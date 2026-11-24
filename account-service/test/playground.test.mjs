import {test} from 'node:test';import assert from 'node:assert/strict';import {Playground,validateGeneration} from '../src/playground.mjs';import {randomSecret,digest} from '../src/core.mjs';
test('generation input is bounded and fixed to one non-live task',()=>{assert.throws(()=>validateGeneration({style:''}));const p=validateGeneration({style:'piano',lyrics:'ignored',music_mode:'instrumental',duration_seconds:30,live:true});assert.equal(p.lyrics,'');assert.equal(p.count,1);assert.equal(p.live,undefined);assert.throws(()=>validateGeneration({...p,duration_seconds:999}));});
test('authenticated idempotent submission, ownership, FIFO lease, measured progress and result access',async()=>{
 const values=new Map(),s={get:async k=>values.get(k),put:async(k,v)=>values.set(k,structuredClone(v)),transaction:async fn=>fn()};let writes=0;const files=new Map();
 const g={root:'/repos/a/b',commit:async items=>{writes++;for(const x of items)files.set(x.path,x.envelope);},send:async path=>({content:btoa(JSON.stringify(files.get(path.split('/contents/')[1])))})};
 const env={AUTH_PEPPER:randomSecret(),ARCHIVE_KEY:randomSecret(),GITHUB_REPOSITORY:'a/b'},token=randomSecret(),id='SL-'+'A'.repeat(32),key=await digest(env.AUTH_PEPPER,'session:'+token);
 values.set('account/'+id,{sessions:{[key]:{expires:Date.now()+60000}}});const service=new Playground(s,env,g);const request=new Request('https://example.test',{headers:{Authorization:'Bearer '+token}});
 const body={id,requestId:crypto.randomUUID(),style:'piano',lyrics:'',music_mode:'instrumental',duration_seconds:30};
 assert.equal((await service.handle('/v1/playground/list',{id},new Request('https://example.test'))).status,401);
 await service.handle('/v1/playground/create',body,request);await service.handle('/v1/playground/create',body,request);assert.equal(writes,1);
 const worker=new Request('https://example.test',{headers:{Authorization:'Bearer '+await digest(env.AUTH_PEPPER,'salam-playground-worker-v1')}});
 const claim=await service.handle('/v1/playground/worker',{action:'claim',ready:true,estimate:2},worker);assert.equal(claim.data.job.request.style,'piano');const job=claim.data.job;
 await service.handle('/v1/playground/worker',{action:'report',jobId:job.id,lease:'wrong',status:'failed'},worker);
 let list=await service.handle('/v1/playground/list',{id},request);assert.equal(list.data.jobs[0].status,'running');assert.equal(list.data.jobs[0].key,undefined);
 await service.handle('/v1/playground/worker',{action:'report',jobId:job.id,lease:job.lease,status:'succeeded',url:'https://github.com/a/b/releases/download/x/music.bin',stage:'完成'},worker);
 assert.equal((await service.handle('/v1/playground/result',{id,jobId:job.id},request)).data.key,job.key);
 values.get('account/'+id).closedAt=Date.now();assert.equal((await service.handle('/v1/playground/list',{id},request)).status,401);
});
