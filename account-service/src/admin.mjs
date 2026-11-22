import {b64} from './core.mjs';
// Reuse the owner's configured GitHub credential without transmitting it to the admin endpoint.
// Timestamp, nonce, route and exact canonical JSON body are all bound to the MAC.
export async function adminSignature(token,time,nonce,path,body) {
  const enc=new TextEncoder();
  const key=await crypto.subtle.importKey('raw',enc.encode(token.trim()),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return b64(new Uint8Array(await crypto.subtle.sign('HMAC',key,enc.encode('Salam-ID-admin-v1\n'+time+'\n'+nonce+'\n'+path+'\n'+body))));
}
