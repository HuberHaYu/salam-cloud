import {digest, unb64} from './core.mjs';
const encoder=new TextEncoder();
// Match Character.isWhitespace used by the existing Android/Mac order normalization.
const whitespace=/[\u0009-\u000d\u001c-\u0020\u1680\u2000-\u2006\u2008-\u200a\u2028\u2029\u205f\u3000]/g;
export function normalizeOrder(input) {
  if(typeof input!=='string'||input.length>256)throw new Error('请输入完整的主订单编号');
  const order=input.replace(whitespace,'').toUpperCase();
  if(!/^[A-Z0-9_-]{1,64}$/.test(order))throw new Error('请输入完整的主订单编号');
  return order;
}
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
export async function orderId(input, pepper) {
  const hash=unb64(await digest(pepper,'Salam-ID/order/v2\n'+normalizeOrder(input)));
  return 'SL-'+hex(hash.subarray(0,16)).toUpperCase();
}
export async function orderHash(input,kdf) {
  if(kdf?.algorithm!=='PBKDF2-HMAC-SHA256'||!/^(?:[a-fA-F0-9]{2}){8,64}$/.test(kdf?.salt||'')
    ||!Number.isSafeInteger(kdf.iterations)||kdf.iterations<1000||kdf.iterations>2000000
    ||!Number.isSafeInteger(kdf.length)||kdf.length<16||kdf.length>64)throw new Error('订单清单参数无效');
  const key=await crypto.subtle.importKey('raw',encoder.encode(normalizeOrder(input)),'PBKDF2',false,['deriveBits']);
  const salt=Uint8Array.from(kdf.salt.match(/../g),x=>parseInt(x,16));
  return hex(new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:kdf.iterations},key,kdf.length*8)));
}
export function maskOrder(order){return order.length<=8?'••••':order.slice(0,4)+'••••'+order.slice(-4);}
export function username(input) {
  if(typeof input!=='string')throw new Error('请输入用户名');
  const name=input.normalize('NFKC').trim().toLowerCase();
  if(['__proto__','constructor','prototype'].includes(name)||!/^[\p{L}\p{N}_]{3,24}$/u.test(name))throw new Error('用户名需为 3～24 个字母、汉字、数字或下划线');
  return name;
}
export function randomUsername(){return 'salam_'+hex(crypto.getRandomValues(new Uint8Array(8)));}
