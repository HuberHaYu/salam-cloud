import {unb64} from './core.mjs';
// Existing SalamCloud configuration signing key; never use mirror transport for credentials.
const PUBLIC_KEY='MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGjOxaJUesJh+o99uqYiuHYSz9PdhTLcGwGotMmP2WRp5a/H6A04eFUfx7drGKlmcmZwCmy1+Mxz02/bS6hIa6A==';
function rawSignature(der){
  if(der.length<8||der.length>72||der[0]!==0x30||der[1]!==der.length-2)throw new Error('Invalid signature');
  const out=new Uint8Array(64);let p=2;
  for(let i=0;i<2;i++){
    if(der[p++]!==2)throw new Error('Invalid signature');let n=der[p++];
    if(n<1||n>33||p+n>der.length||der[p]&128)throw new Error('Invalid signature');
    if(n>1&&der[p]===0){if(!(der[p+1]&128))throw new Error('Invalid signature');p++;n--;}
    if(n>32)throw new Error('Invalid signature');out.set(der.subarray(p,p+n),(i+1)*32-n);p+=n;
  }
  if(p!==der.length)throw new Error('Invalid signature');return out;
}
export async function verifyControl(bytes,signature,minimumSerial=0,publicKey=PUBLIC_KEY){
  const key=await crypto.subtle.importKey('spki',unb64(publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,rawSignature(unb64(signature.trim())),bytes))throw new Error('Invalid control signature');
  const data=JSON.parse(new TextDecoder().decode(bytes));
  if(!Number.isSafeInteger(data.serial)||data.serial<minimumSerial||data.serial<1)throw new Error('Stale control');
  return data;
}
async function publicBytes(url,max){
  const response=await fetch(url,{redirect:'error',signal:AbortSignal.timeout(5000)});
  if(!response.ok||Number(response.headers.get('content-length')||0)>max)throw new Error('Control unavailable');
  const reader=response.body.getReader(),parts=[];let size=0;
  for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;
    if(size>max){await reader.cancel();throw new Error('Control too large');}parts.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}return bytes;
}
/** Optional public-only routes already used by the Android GitHub accelerator. */
export async function mirroredControl(repository,branch,minimumSerial){
  const path=repository.split('/').map(encodeURIComponent).join('/')+'@'+encodeURIComponent(branch)+'/api/v1/control.json';
  for(const origin of ['https://cdn.jsdmirror.com/gh/','https://cdn.jsdelivr.net/gh/']){
    try{
      const [body,sig]=await Promise.all([publicBytes(origin+path,2000000),publicBytes(origin+path+'.sig',4096)]);
      return await verifyControl(body,new TextDecoder().decode(sig),minimumSerial);
    }catch{/* The next route, then authenticated GitHub API, is attempted without leaking credentials. */}
  }
  throw new Error('Public control unavailable');
}
