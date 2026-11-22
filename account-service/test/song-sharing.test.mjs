import test from 'node:test';
import assert from 'node:assert/strict';
import {AccountService} from '../src/service.mjs';
import {SongSharing, SHARE_TTL, shareTrack, randomShareCode} from '../src/song-sharing.mjs';
import {digest, randomSecret} from '../src/core.mjs';

class Storage {
  constructor(){this.map=new Map();}
  async get(key){return structuredClone(this.map.get(key));}
  async put(key,value){this.map.set(key,structuredClone(value));}
}
const track={name:'夜に駆ける',singer:'YOASOBI',album:'THE BOOK',platform:'wy',songId:'1372060183',hash:'',albumId:'',durationMs:261000,access:0};
async function fixture(options={}){
  const storage=new Storage(),env={AUTH_PEPPER:randomSecret(),PASSWORD_PEPPER:randomSecret(),ARCHIVE_KEY:randomSecret()};
  const id='SL-'+'A'.repeat(32),token=randomSecret(),idB='SL-'+'B'.repeat(32),tokenB=randomSecret();
  const now={value:1700000000000};
  for(const [owner,secret]of [[id,token],[idB,tokenB]])await storage.put('account/'+owner,{id:owner,authVersion:1,
    sessions:{[await digest(env.AUTH_PEPPER,'session:'+secret)]:{expires:now.value+86400000}}});
  const sharing=new SongSharing(storage,env,{now:()=>now.value,...options});
  const request=(token='',ip='192.0.2.1')=>new Request('https://example.test',{headers:{Authorization:'Bearer '+token,'CF-Connecting-IP':ip}});
  const create=(body={},credential=token)=>sharing.handle('/v1/share/create',{id,requestId:crypto.randomUUID(),track,...body},request(credential));
  const receive=(code,ip)=>sharing.handle('/v1/share/receive',{code},request('',ip));
  return{storage,env,id,idB,token,tokenB,now,sharing,create,receive,request};
}
test('song shares contain identity only, do not expose credentials, and guests may receive',async()=>{
  const f=await fixture();const original=JSON.stringify(await f.storage.get('account/'+f.id));
  const created=await f.create({track:{...track,uri:'file:///private/music.flac',url:'https://private.example/?token=secret',password:'secret'}});
  assert.equal(created.status,200);assert.match(created.data.code,/^\d{6}$/);assert.equal(created.data.expiresAt-f.now.value,SHARE_TTL);
  const received=await f.receive(created.data.code);assert.equal(received.status,200);assert.deepEqual(received.data.track,track);
  assert.equal(JSON.stringify(await f.storage.get('account/'+f.id)),original);
  assert.ok(!JSON.stringify(received).includes(f.id));assert.ok(!JSON.stringify(received).includes('secret'));
  assert.ok([...f.storage.map.keys()].every(k=>k.startsWith('account/')||k.startsWith('share/')));
  assert.equal((await f.receive(created.data.code)).status,200);
});
test('sender requires their own valid session; mismatched account, missing token and logout are denied',async()=>{
  const f=await fixture();assert.equal((await f.create({},'')).status,401);
  assert.equal((await f.create({id:f.idB})).status,401);
  assert.equal((await f.create({id:f.idB},f.tokenB)).status,200);
  const a=await f.storage.get('account/'+f.id);a.sessions={};await f.storage.put('account/'+f.id,a);
  assert.equal((await f.create()).status,401);
});
test('leading zeroes and collisions retain the original song',async()=>{
  const codes=['000001','000001','000002'];const f=await fixture({randomCode:()=>codes.shift()});
  const one=await f.create(),two=await f.create({id:f.idB,track:{...track,name:'Another recording'}},f.tokenB);
  assert.equal(one.data.code,'000001');assert.equal(two.data.code,'000002');
  assert.equal((await f.receive(one.data.code)).data.track.name,track.name);
  assert.equal((await f.receive(two.data.code)).data.track.name,'Another recording');
});
test('retry is idempotent, scoped to owner, and cannot silently change the song',async()=>{
  const f=await fixture(),requestId=crypto.randomUUID();const one=await f.create({requestId});
  const retry=await f.create({requestId});assert.equal(retry.data.code,one.data.code);assert.equal(retry.data.expiresAt,one.data.expiresAt);
  assert.equal((await f.create({requestId,track:{...track,name:'Changed'}})).status,409);
  assert.notEqual((await f.create({id:f.idB,requestId},f.tokenB)).data.code,one.data.code);
});
test('expiry uses server time and an expired request may generate a fresh ten-minute code',async()=>{
  const f=await fixture(),requestId=crypto.randomUUID(),one=await f.create({requestId});
  f.now.value+=SHARE_TTL-1;assert.equal((await f.receive(one.data.code)).status,200);
  f.now.value++;assert.equal((await f.receive(one.data.code)).status,404);
  const next=await f.create({requestId});assert.equal(next.status,200);assert.equal(next.data.expiresAt-f.now.value,SHARE_TTL);
});
test('account closure, deletion and password rotation invalidate its existing codes',async()=>{
  for(const change of ['closedAt','deletedAt','deletingAt','authVersion']){
    const f=await fixture(),one=await f.create(),owner=await f.storage.get('account/'+f.id);
    owner[change]=change==='authVersion'?2:f.now.value;await f.storage.put('account/'+f.id,owner);
    assert.equal((await f.receive(one.data.code)).status,404,change);
  }
});
test('guess limits persist, do not affect another receiver, and reset after the window',async()=>{
  const f=await fixture(),one=await f.create();
  for(let i=0;i<6;i++)assert.equal((await f.receive('bad')).status,404);
  assert.equal((await f.receive(one.data.code)).status,429);
  assert.equal((await f.receive(one.data.code,'192.0.2.2')).status,200);
  f.now.value+=60001;assert.equal((await f.receive(one.data.code)).status,200);
});
test('send limits do not reject retries and are isolated between accounts',async()=>{
  const f=await fixture(),requestId=crypto.randomUUID();await f.create({requestId});
  for(let i=1;i<12;i++)assert.equal((await f.create()).status,200);
  assert.equal((await f.create()).status,429);assert.equal((await f.create({requestId})).status,200);
  assert.equal((await f.create({id:f.idB},f.tokenB)).status,200);
});
test('metadata shares preserve versions and strip all non-song fields',()=>{
  const plain=shareTrack({name:'曲名 (Live)',singer:'歌手',album:'现场',file:'/local/path',durationMs:120000});
  assert.equal(plain.platform,'');assert.equal(plain.name,'曲名 (Live)');assert.equal(plain.file,undefined);
  assert.throws(()=>shareTrack({name:'Missing artist'}));assert.throws(()=>shareTrack({...track,songId:'https://example.test/private'}));
  assert.throws(()=>shareTrack({...track,name:'x'.repeat(257)}));
  for(let i=0;i<100;i++)assert.match(randomShareCode(),/^\d{6}$/);
});
test('real account routing keeps share operations away from GitHub and resolves in parallel',async()=>{
  const f=await fixture();for(const id of [f.id,f.idB]){const a=await f.storage.get('account/'+id);for(const s of Object.values(a.sessions))s.expires=Date.now()+86400000;await f.storage.put('account/'+id,a);}
  const hub=new AccountService({storage:f.storage},f.env);
  hub.github=new Proxy({},{get(){throw new Error('Sharing must not call GitHub');}});
  async function call(path,body,token=''){const r=await hub.fetch(new Request('https://example.test'+path,{method:'POST',headers:{Authorization:'Bearer '+token,'CF-Connecting-IP':'192.0.2.3'},body:JSON.stringify(body)}));return{status:r.status,data:await r.json()};}
  const [a,b]=await Promise.all([call('/v1/share/create',{id:f.id,requestId:crypto.randomUUID(),track},f.token),call('/v1/share/create',{id:f.idB,requestId:crypto.randomUUID(),track:{...track,name:'B'}},f.tokenB)]);
  assert.equal(a.status,200);assert.equal(b.status,200);assert.notEqual(a.data.code,b.data.code);
  const replies=await Promise.all(Array.from({length:20},(_,i)=>call('/v1/share/receive',{code:i%2?a.data.code:b.data.code})));
  replies.forEach((r,i)=>{assert.equal(r.status,200);assert.equal(r.data.track.name,i%2?track.name:'B');});
});
