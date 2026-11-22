import test from 'node:test';
import assert from 'node:assert/strict';
import {pbkdf2Sync,generateKeyPairSync,sign} from 'node:crypto';
import {verifyControl} from '../src/public-control.mjs';
import {merge,seal,unseal,randomSecret} from '../src/core.mjs';
import {hashPassword,verifyPassword,PASSWORD_ITERATIONS} from '../src/password.mjs';
import {normalizeOrder,orderId,orderHash,username,usernameKey} from '../src/order.mjs';
import {adminSignature} from '../src/admin.mjs';
import {AccountService} from '../src/service.mjs';
import {GitHubArchive} from '../src/github.mjs';
import {SqliteStorage} from '../src/node-server.mjs';
const orderA='ORDER_12345',orderB='ORDER_67890';
const identityPepper=randomSecret();
const idA=await orderId(orderA,identityPepper),idB=await orderId(orderB,identityPepper),password='A secure passphrase 123!';
const d1='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',d2='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const song=n=>({uri:'salam-online://wy/'+n,rank:0});
const fresh=()=>({id:idA,rev:0,generation:0,records:{},devices:{}});
const op=(key,value,base=0)=>({key,value,base});
const kdf={algorithm:'PBKDF2-HMAC-SHA256',salt:'4f45a32f4ea9d9b37a54dd426b3e1640',iterations:100000,length:32};
const hashes=await Promise.all([orderA,orderB].map(x=>orderHash(x,kdf)));
class Storage {
 constructor(){this.map=new Map();this.alarm=null;}
 async get(k){return structuredClone(this.map.get(k));}async put(k,v){this.map.set(k,structuredClone(v));}
 async delete(keys){for(const k of Array.isArray(keys)?keys:[keys])this.map.delete(k);}
 async list({prefix='',limit=1000,after=''}={}){return new Map([...this.map].filter(([k])=>k.startsWith(prefix)&&k>after).sort(([a],[b])=>a.localeCompare(b)).slice(0,limit).map(([k,v])=>[k,structuredClone(v)]));}
 async transaction(fn){return fn(this);}async getAlarm(){return this.alarm;}async setAlarm(t){this.alarm=t;}async deleteAlarm(){this.alarm=null;}
}
function fixture(){
 const storage=new Storage(),env={AUTH_PEPPER:identityPepper,PASSWORD_PEPPER:randomSecret(),ARCHIVE_KEY:randomSecret(),REGISTRATION_ENABLED:'true',GITHUB_TOKEN:'test-only-owner-token'};
 const hub=new AccountService({storage},env),commits=[],libraries=new Map();let controlReads=0,libraryReads=0,libraryWrites=0;
 hub.github={read:async()=>null,readLibrary:async id=>{libraryReads++;return structuredClone(libraries.get(id)||null);},
 writeLibrary:async(id,envelope,sha)=>{if(libraries.get(id)?.sha!==sha){const e=new Error('CAS conflict');e.status=409;throw e;}libraryWrites++;const next=String(libraryWrites);libraries.set(id,{sha:next,envelope:structuredClone(envelope)});return next;},commit:async f=>commits.push(f),control:async()=>{controlReads++;return {serial:1,order_gate:{kdf,orders:hashes,revoked:[]}};}};
 return {hub,storage,env,commits,libraries,counts:()=>({reads:libraryReads,writes:libraryWrites}),controlReads:()=>controlReads};
}
async function call(hub,path,body,token=''){
 const r=await hub.fetch(new Request('https://account.example'+path,{method:'POST',headers:{'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.1',Authorization:'Bearer '+token},body:JSON.stringify(body)}));
 return {status:r.status,data:await r.json()};
}
async function activate(hub,order=orderA,pwd=password){const r=await call(hub,'/v1/order/activate',{order,password:pwd});assert.equal(r.status,200,JSON.stringify(r.data));return r.data;}

test('same normalized order gets stable ID and matches existing PBKDF2 format',async()=>{
 assert.equal(normalizeOrder(' order_ 12345\n'),orderA);assert.equal(await orderId(' order_ 12345\n',identityPepper),idA);assert.notEqual(idA,idB);assert.notEqual(await orderId(orderA,randomSecret()),idA);
 assert.equal(hashes[0],pbkdf2Sync(orderA,Buffer.from(kdf.salt,'hex'),100000,32,'sha256').toString('hex'));
});
test('password format uses 600k PBKDF2, unique salts, secret pepper and account binding',async()=>{
 const pepper=randomSecret(),a=await hashPassword(password,idA,pepper),b=await hashPassword(password,idA,pepper);
 assert.equal(a.iterations,600000);assert.equal(PASSWORD_ITERATIONS,600000);assert.notEqual(a.salt,b.salt);assert.notEqual(a.tag,b.tag);
 assert.ok(!JSON.stringify(a).includes(password));assert.equal(await verifyPassword(password,idA,a,pepper),true);
 assert.equal(await verifyPassword('wrong password',idA,a,pepper),false);
 assert.equal(await verifyPassword(password,idA,a,randomSecret()),false);assert.equal(await verifyPassword(password,idB,a,pepper),false);
 assert.equal(await verifyPassword(password,idA,{...a,iterations:1000},pepper),false);
});
test('random usernames are stable per account and neither order nor password is stored',async()=>{
 const {hub,storage}=fixture(),a=await activate(hub),b=await activate(hub,orderB);
 assert.match(a.username,/^salam_[a-f0-9]{16}$/);assert.notEqual(a.username,b.username);assert.notEqual(a.id,b.id);
 const retry=await activate(hub);assert.equal(retry.username,a.username);assert.equal(retry.id,a.id);
 const persisted=JSON.stringify([...storage.map]);assert.ok(!persisted.includes(password));assert.ok(!persisted.includes(orderA));assert.ok(!persisted.includes(orderB));
 assert.equal(a.password,undefined);assert.equal(a.orderHash,undefined);assert.equal(a.orderProof,undefined);
});
test('existing order cannot reset its password through activation; both login forms work',async()=>{
 const {hub}=fixture(),a=await activate(hub);
 assert.equal((await call(hub,'/v1/order/activate',{order:orderA,password:'attacker new password'})).status,401);
 assert.equal((await call(hub,'/v1/order/login',{order:orderA,password})).status,200);
 assert.equal((await call(hub,'/v1/username/login',{username:a.username,password})).status,200);
 assert.equal((await call(hub,'/v1/order/login',{order:orderA})).status,401);
 assert.equal((await call(hub,'/v1/order/check',{order:'UNKNOWN_ORDER'})).status,401);
 assert.equal((await call(hub,'/v1/register',{nickname:'anything'})).status,410);
});
test('username rename is unique and old username stops resolving',async()=>{
 const {hub}=fixture(),a=await activate(hub),b=await activate(hub,orderB);
 assert.equal((await call(hub,'/v1/account/username',{id:a.id,username:b.username,currentPassword:password},a.token)).status,409);
 const changed=await call(hub,'/v1/account/username',{id:a.id,username:'我的音乐_01',currentPassword:password},a.token);
 assert.equal(changed.status,200);assert.equal(changed.data.id,a.id);
 assert.equal((await call(hub,'/v1/username/login',{username:a.username,password})).status,401);
 assert.equal((await call(hub,'/v1/username/login',{username:'我的音乐_01',password})).status,200);
});
test('password change checks old password, changes salt, revokes all old device sessions',async()=>{
 const {hub,storage}=fixture(),a=await activate(hub),second=await call(hub,'/v1/order/login',{order:orderA,password});
 const before=(await storage.get('account/'+a.id)).password;
 assert.equal((await call(hub,'/v1/account/password',{id:a.id,currentPassword:'wrong password',newPassword:'another secure password'},a.token)).status,403);
 const changed=await call(hub,'/v1/account/password',{id:a.id,currentPassword:password,newPassword:'another secure password'},a.token);assert.equal(changed.status,200);
 assert.notEqual((await storage.get('account/'+a.id)).password.salt,before.salt);
 assert.equal((await call(hub,'/v1/sync',{id:a.id},a.token)).status,401);
 assert.equal((await call(hub,'/v1/sync',{id:a.id},second.data.token)).status,401);
 assert.equal((await call(hub,'/v1/sync',{id:a.id},changed.data.token)).status,200);
 assert.equal((await call(hub,'/v1/order/login',{order:orderA,password})).status,401);
 assert.equal((await call(hub,'/v1/username/login',{username:a.username,password:'another secure password'})).status,200);
});
test('normal synchronization never queries GitHub for order/password validation',async()=>{
 const f=fixture(),a=await activate(f.hub);for(let i=0;i<15;i++)assert.equal((await call(f.hub,'/v1/sync',{id:a.id},a.token)).status,200);
 assert.equal(f.controlReads(),1);assert.equal((await call(f.hub,'/v1/sync',{id:idB},a.token)).status,401);
});
test('independent device edits merge; duplicates and stale resurrection are rejected',()=>{
 let a=merge(fresh(),{device:d1,seq:1,ops:[op('f:a',song(1))]}).account;
 a=merge(a,{device:d2,seq:1,ops:[op('f:b',song(2))]}).account;
 assert.equal(merge(a,{device:d1,seq:1,ops:[op('f:a',null)]}).duplicate,true);
 a=merge(a,{device:d1,seq:2,ops:[op('f:a',null,2)]}).account;
 const stale=merge(a,{device:d2,seq:2,ops:[op('f:a',song(1),2)]});assert.deepEqual(stale.conflicts,['f:a']);assert.equal(stale.account.records['f:a'].value,null);
});
test('reject local music atomically',()=>{
 const a=fresh();assert.throws(()=>merge(a,{device:d1,seq:1,ops:[op('f:a',song(1)),op('f:b',{uri:'file:///music.mp3',rank:0})]}));assert.equal(a.rev,0);
});
test('public archive is encrypted, authenticated, randomized and account-bound',async()=>{
 const key=randomSecret(),data=fresh(),a=await seal(key,idA,data),b=await seal(key,idA,data);
 assert.notEqual(a.data,b.data);assert.deepEqual(await unseal(key,idA,a),data);await assert.rejects(unseal(key,idB,a));await assert.rejects(unseal(randomSecret(),idA,a));
});
test('archive failure retains dirty data; writes arriving during commit are not cleared',async()=>{
 const {hub,storage}=fixture(),a=await activate(hub);hub.github.commit=async()=>{throw new Error('offline');};await hub.alarm();
 assert.equal((await storage.list({prefix:'dirty/'})).size,1);assert.ok(storage.alarm>Date.now());
 let begin,finish;const started=new Promise(r=>begin=r),release=new Promise(r=>finish=r);
 hub.github.commit=async()=>{begin();await release;};const job=hub.alarm();await started;
 await call(hub,'/v1/account/username',{id:a.id,username:'renamed_during_archive',currentPassword:password},a.token);finish();await job;
 assert.equal((await storage.list({prefix:'dirty/'})).size,1);
});
test('encrypted account and username directory restore; raw secrets and sessions do not',async()=>{
 const f=fixture(),a=await activate(f.hub);await f.hub.alarm();
 const saved=new Map(f.commits.flat().map(x=>[x.id,x.envelope]));assert.ok(saved.has('directory'));assert.ok(saved.has(a.id));
 for(const x of saved.values()){assert.ok(!JSON.stringify(x).includes(password));assert.ok(!JSON.stringify(x).includes(orderA));}
 await f.storage.delete(['directory','account/'+a.id]);f.hub.github.read=async id=>saved.get(id)||null;
 const login=await call(f.hub,'/v1/username/login',{username:a.username,password});assert.equal(login.status,200);
 assert.equal((await call(f.hub,'/v1/sync',{id:a.id},a.token)).status,401);
});
test('Node SQLite adapter rolls back and serializes concurrent transactions',async()=>{
 const db=new SqliteStorage(':memory:');
 try{await db.put('a',1);await assert.rejects(db.transaction(async tx=>{await tx.put('a',2);throw new Error('rollback');}));assert.equal(await db.get('a'),1);
   await Promise.all(Array.from({length:8},()=>db.transaction(async tx=>{const n=await tx.get('a');await tx.put('a',n+1);})));assert.equal(await db.get('a'),9);
   await db.setAlarm(123);assert.equal(await db.getAlarm(),123);await db.deleteAlarm();assert.equal(await db.getAlarm(),undefined);
 }finally{await db.close();}
});

test('public acceleration rejects tampered configuration, wrong signer and serial rollback',async()=>{
 const keys=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const pub=keys.publicKey.export({type:'spki',format:'der'}).toString('base64');
 const bytes=Buffer.from(JSON.stringify({serial:4,order_gate:{}}));
 const signature=sign('sha256',bytes,keys.privateKey).toString('base64');
 assert.equal((await verifyControl(bytes,signature,3,pub)).serial,4);
 await assert.rejects(verifyControl(Buffer.from('{"serial":5}'),signature,3,pub));
 await assert.rejects(verifyControl(bytes,signature,5,pub));
 const other=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({type:'spki',format:'der'}).toString('base64');
 await assert.rejects(verifyControl(bytes,signature,3,other));
});

test('owner-managed repository token works without a GitHub App private key',async()=>{
 const repository=new GitHubArchive({GITHUB_TOKEN:'  test-only-repository-token  '});
 assert.equal(await repository.token(),'test-only-repository-token');
});

test('delta pulls omit unchanged libraries and echo submitted conflict keys even after re-login',async()=>{
 const {hub}=fixture(),a=await activate(hub);
 const first=await call(hub,'/v1/sync',{id:a.id,device:d1,seq:1,since:0,ops:[op('f:a',song(1))]},a.token);
 assert.equal(first.status,200);assert.equal(first.data.delta,true);assert.ok(first.data.records['f:a']);
 const unchanged=await call(hub,'/v1/sync',{id:a.id,since:first.data.rev},a.token);
 assert.deepEqual(unchanged.data.records,{});
 const conflict=await call(hub,'/v1/sync',{id:a.id,device:d2,seq:1,since:first.data.rev,ops:[op('f:a',song(2),0)]},a.token);
 assert.deepEqual(conflict.data.conflicts,['f:a']);assert.equal(conflict.data.records['f:a'].value.uri,song(1).uri);
 const deleted=await call(hub,'/v1/sync',{id:a.id,device:d1,seq:2,since:first.data.rev,ops:[op('f:a',null,first.data.rev)]},a.token);
 assert.equal(deleted.data.records['f:a'].value,null);
});

async function admin(f,path,body={},signatureOverride) {
 const time=String(Date.now()),nonce=crypto.randomUUID().replaceAll('-','');
 const signature=signatureOverride||await adminSignature(f.env.GITHUB_TOKEN,time,nonce,path,JSON.stringify(body));
 const req=new Request('https://account.example'+path,{method:'POST',headers:{Authorization:`SalamAdmin ${time}:${nonce}:${signature}`},body:JSON.stringify(body)});
 const copy=req.clone(),response=await f.hub.fetch(req);
 return {status:response.status,data:await response.json(),replay:copy};
}
test('music only lives in GitHub; unchanged manual pull reads once and makes no commit',async()=>{
 const f=fixture(),a=await activate(f.hub);assert.equal(a.records,undefined);
 await call(f.hub,'/v1/sync',{id:a.id,device:d1,seq:1,ops:[op('f:a',song(99))]},a.token);
 assert.deepEqual(f.counts(),{reads:1,writes:1});
 const sql=JSON.stringify([...f.storage.map]);assert.ok(!sql.includes('salam-online://'));assert.ok(!sql.includes('"records"'));
 const cloud=await unseal(f.env.ARCHIVE_KEY,a.id,f.libraries.get(a.id).envelope);assert.equal(cloud.records['f:a'].value.uri,song(99).uri);
 await call(f.hub,'/v1/sync',{id:a.id,since:cloud.rev},a.token);assert.deepEqual(f.counts(),{reads:2,writes:1});
 const before=f.counts();await call(f.hub,'/v1/username/login',{username:a.username,password});assert.deepEqual(f.counts(),before);
});
test('GitHub compare-and-swap retries preserve simultaneous independent device edits',async()=>{
 const f=fixture(),a=await activate(f.hub);
 const results=await Promise.all([d1,d2].map((device,i)=>call(f.hub,'/v1/sync',{id:a.id,device,seq:1,ops:[op('f:'+i,song(i))]},a.token)));
 assert.ok(results.every(r=>r.status===200));
 const cloud=await unseal(f.env.ARCHIVE_KEY,a.id,f.libraries.get(a.id).envelope);assert.equal(Object.keys(cloud.records).length,2);
});
test('failed GitHub write never acknowledges or stages library data in SQL',async()=>{
 const f=fixture(),a=await activate(f.hub);f.hub.github.writeLibrary=async()=>{throw new Error('offline');};
 assert.equal((await call(f.hub,'/v1/sync',{id:a.id,device:d1,seq:1,ops:[op('f:a',song(9))]},a.token)).status,503);
 assert.ok(!JSON.stringify([...f.storage.map]).includes('salam-online://'));assert.equal(f.libraries.size,0);
});
test('legacy music is removed from SQL only after successful GitHub migration',async()=>{
 const f=fixture(),a=await activate(f.hub);let legacy=await f.storage.get('account/'+a.id);
 delete legacy.libraryVersion;Object.assign(legacy,merge(fresh(),{device:d1,seq:1,ops:[op('f:a',song(3))]}).account);
 await f.storage.put('account/'+a.id,legacy);
 const write=f.hub.github.writeLibrary;f.hub.github.writeLibrary=async()=>{throw new Error('offline');};
 assert.equal((await admin(f,'/admin/migrate')).status,503);assert.ok((await f.storage.get('account/'+a.id)).records);
 f.hub.github.writeLibrary=write;assert.equal((await admin(f,'/admin/migrate')).data.migrated,1);
 assert.equal((await f.storage.get('account/'+a.id)).records,undefined);
 assert.equal((await unseal(f.env.ARCHIVE_KEY,a.id,f.libraries.get(a.id).envelope)).records['f:a'].value.uri,song(3).uri);
});
test('admin requests are signed and single-use; closure revokes sessions without changing orders or music',async()=>{
 const f=fixture(),a=await activate(f.hub);
 await call(f.hub,'/v1/sync',{id:a.id,device:d1,seq:1,ops:[op('f:a',song(5))]},a.token);
 const list=await admin(f,'/admin/accounts');assert.equal(list.status,200);assert.equal(list.data.accounts[0].id,a.id);
 assert.equal((await f.hub.fetch(list.replay)).status,409);
 assert.equal((await admin(f,'/admin/accounts',{},'x'.repeat(43))).status,401);
 const orders=JSON.stringify(await f.storage.get('orderControl')),library=JSON.stringify([...f.libraries]);
 assert.equal((await admin(f,'/admin/close',{id:a.id})).status,200);
 assert.equal((await call(f.hub,'/v1/sync',{id:a.id},a.token)).status,401);
 assert.equal((await call(f.hub,'/v1/order/login',{order:orderA,password})).status,403);
 assert.equal(JSON.stringify(await f.storage.get('orderControl')),orders);assert.equal(JSON.stringify([...f.libraries]),library);
 assert.equal((await admin(f,'/admin/restore',{id:a.id})).status,200);
 assert.equal((await call(f.hub,'/v1/order/login',{order:orderA,password})).status,200);
 assert.equal((await call(f.hub,'/v1/sync',{id:a.id},a.token)).status,401);
});

test('multilingual usernames preserve case, support hyphens, kana and combining letters',()=>{
 for(const name of ['Salam-ID_01','小雨-音楽_AbC','さくら_カナ-A','가나다-A','Cafe\u0301-ID','नमस्ते-ID']) {
   assert.equal(username(name),name.normalize('NFC'));
 }
 assert.equal(usernameKey(username('Ｓａｌａｍ-ID')),usernameKey('salam-id'));
 assert.equal(usernameKey(username('Cafe\u0301-ID')),usernameKey('CAFÉ-id'));
 for(const name of ['ab','x'.repeat(25),'空 格-A','a\nB','a\u200bB','音楽\ufe0f-A','\u0301Ab','__PROTO__'])assert.throws(()=>username(name));
});
test('multilingual display rename keeps ID while case-insensitive login and uniqueness remain stable',async()=>{
 const f=fixture(),a=await activate(f.hub),b=await activate(f.hub,orderB);
 const rename=(account,name)=>call(f.hub,'/v1/account/username',{id:account.id,username:name,currentPassword:password},account.token);
 const changed=await rename(a,'小雨-カナ_AbC');assert.equal(changed.status,200);assert.equal(changed.data.username,'小雨-カナ_AbC');assert.equal(changed.data.id,a.id);
 const login=await call(f.hub,'/v1/username/login',{username:'小雨-カナ_aBc',password});assert.equal(login.status,200);assert.equal(login.data.username,'小雨-カナ_AbC');
 assert.equal((await rename(b,'小雨-カナ_abc')).status,409);
 const caseOnly=await rename(a,'小雨-カナ_ABC');assert.equal(caseOnly.status,200);assert.equal(caseOnly.data.username,'小雨-カナ_ABC');
 assert.equal((await f.storage.get('directory')).users[usernameKey(caseOnly.data.username)],a.id);
 assert.equal((await call(f.hub,'/v1/username/login',{username:a.username,password})).status,401);
 // The legacy lowercase index resolves even when the input is uppercase.
 assert.equal((await call(f.hub,'/v1/username/login',{username:b.username.toUpperCase(),password})).data.id,b.id);
 await f.hub.alarm();const archived=new Map(f.commits.flat().map(x=>[x.id,x.envelope]));
 await f.storage.delete(['directory','account/'+a.id]);f.hub.github.read=async id=>archived.get(id)||null;
 assert.equal((await call(f.hub,'/v1/username/login',{username:'小雨-カナ_abc',password})).data.username,'小雨-カナ_ABC');
});
