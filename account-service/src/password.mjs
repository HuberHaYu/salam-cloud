import {b64, unb64, digest, equal, SECRET} from './core.mjs';
const encoder = new TextEncoder();
export const PASSWORD_SCHEME = 'salam-password-v1';
export const PASSWORD_ITERATIONS = 600000;
export function validatePassword(password) {
  if (typeof password !== 'string' || [...password].length < 8 || [...password].length > 128)
    throw new Error('密码需为 8～128 个字符');
  return password; // Passwords are never trimmed, normalized or silently truncated.
}
async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    {name:'PBKDF2',hash:'SHA-256',salt:unb64(salt),iterations},key,256));
}
async function tag(pepper, id, salt, iterations, derived) {
  if (!SECRET.test(pepper || '')) throw new Error('密码服务密钥未配置');
  return digest(pepper, `${PASSWORD_SCHEME}\n${id}\n${iterations}\n${salt}\n${b64(derived)}`);
}
/** Our versioned storage format, composed of standard PBKDF2 + post-hash HMAC peppering. */
export async function hashPassword(password, id, pepper) {
  validatePassword(password);
  const salt=b64(crypto.getRandomValues(new Uint8Array(32)));
  const derived=await derive(password,salt,PASSWORD_ITERATIONS);
  try { return {scheme:PASSWORD_SCHEME,kdf:'PBKDF2-HMAC-SHA256',iterations:PASSWORD_ITERATIONS,
    salt,tag:await tag(pepper,id,salt,PASSWORD_ITERATIONS,derived)}; }
  finally { derived.fill(0); }
}
export async function verifyPassword(password, id, stored, pepper) {
  if(typeof password!=='string'||[...password].length>128||!stored
    ||stored.scheme!==PASSWORD_SCHEME||stored.kdf!=='PBKDF2-HMAC-SHA256'
    ||!Number.isSafeInteger(stored.iterations)||stored.iterations<PASSWORD_ITERATIONS||stored.iterations>2000000
    ||!SECRET.test(stored.salt||'')||!SECRET.test(stored.tag||''))return false;
  const derived=await derive(password,stored.salt,stored.iterations);
  try {return equal(await tag(pepper,id,stored.salt,stored.iterations,derived),stored.tag);}
  finally {derived.fill(0);}
}
