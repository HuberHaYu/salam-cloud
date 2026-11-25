import {ID, SECRET, digest, equal, seal, unseal, randomSecret, unb64} from './core.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const active=j=>['uploading','queued','running','publishing'].includes(j.status);
const REF_MODES=['none','continue','remix'];
const REF_EXTS=['ogg','mp3','wav','flac','m4a'];
const MAX_REF_BYTES=750000;
function decodeStdB64(input){
  const raw=atob(String(input||'').replace(/\s+/g,''));
  const out=new Uint8Array(raw.length);
  for(let i=0;i<raw.length;i++)out[i]=raw.charCodeAt(i);
  return out;
}
async function encryptRefAudio(keyB64Url,jobId,plainBytes){
  const key=await crypto.subtle.importKey('raw',unb64(keyB64Url),'AES-GCM',false,['encrypt']);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const aad=new TextEncoder().encode(jobId+':ref');
  const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},key,plainBytes));
  const out=new Uint8Array(12+ct.length);
  out.set(iv,0);out.set(ct,12);
  return out;
}
export function validateGeneration(b){
  const refMode=b.reference_mode===undefined?'none':b.reference_mode;
  if(!REF_MODES.includes(refMode))throw new Error('参考模式无效');
  const rawStyle=typeof b.style==='string'?b.style.trim():'';
  if((refMode!=='continue'&&!rawStyle)||rawStyle.length>6000)throw new Error('请填写音乐描述（最多 6000 字）');
  const style=rawStyle||'continue smoothly in the same style and timbre';
  if(typeof b.lyrics!=='string'||b.lyrics.length>12000)throw new Error('歌词最多 12000 字');
  const dur=Number(b.duration_seconds);
  const validDur=refMode==='none'?[30,60,120,180].includes(dur):(Number.isInteger(dur)&&dur>=15&&dur<=360);
  if(!['song','instrumental'].includes(b.music_mode)||!validDur)throw new Error('生成选项无效');
  if(b.music_mode==='song'&&!b.lyrics.trim())throw new Error('请填写歌词');
  const out={style,lyrics:b.music_mode==='song'?b.lyrics:'',music_mode:b.music_mode,duration_seconds:b.duration_seconds,count:1,cot:'full',ending_mode:'fade',kv_ram:false};
  if(refMode!=='none'){
    out.reference_mode=refMode;
    if(refMode==='remix'){
      const strength=b.remix_strength===undefined?0.65:Number(b.remix_strength);
      if(!Number.isFinite(strength)||strength<0.1||strength>1.0)throw new Error('Remix 力度无效');
      out.remix_strength=Math.round(strength*100)/100;
      out.keep_melody=b.keep_melody===undefined?true:Boolean(b.keep_melody);
    }
    if(b.source_job_id){
      if(!UUID.test(String(b.source_job_id)))throw new Error('参考作品标识无效');
      out.source_job_id=String(b.source_job_id);
    }else if(typeof b.reference_audio_b64==='string'&&b.reference_audio_b64.trim()){
      const ext=String(b.reference_audio_ext||'ogg').toLowerCase();
      if(!REF_EXTS.includes(ext))throw new Error('参考音频格式不支持');
      out.ref_ext=ext;
    }else{
      throw new Error('请先选择或播放要引用的歌曲');
    }
    if(typeof b.reference_title==='string'&&b.reference_title.trim()){
      out.reference_title=b.reference_title.trim().slice(0,120);
    }
  }
  return out;
}
export class Playground {
 constructor(storage,env,github){this.s=storage;this.e=env;this.g=github;}
 async locked(fn){return this.s.sharingTransaction?this.s.sharingTransaction(fn,'smart-music-queue'):this.s.transaction(fn);}
 async state(){return await this.s.get('playground/queue')||{jobs:[],workerAt:0,estimate:null};}
 async save(q){await this.s.put('playground/queue',q);}
 async handle(path,b,request){
  const token=(request.headers.get('Authorization')||'').replace(/^Bearer /,'');
  if(path==='/v1/playground/worker'){
   if(!equal(token,await digest(this.e.AUTH_PEPPER,'salam-playground-worker-v1')))return {status:401,data:{error:'认证失败'}};
   return {status:200,data:await this.worker(b)};
  }
  const a=ID.test(b.id||'')?await this.s.get('account/'+b.id):null;
  const session=SECRET.test(token)?await digest(this.e.AUTH_PEPPER,'session:'+token):'';
  if(!a||a.closedAt||a.deletingAt||a.deletedAt||!a.sessions?.[session]||a.sessions[session].expires<=Date.now())return {status:401,data:{error:'请先登录 Salam ID'}};
  if(path==='/v1/playground/create'){
   if(!UUID.test(b.requestId||''))return {status:400,data:{error:'提交标识无效'}};
   let payload;try{payload=validateGeneration(b);}catch(e){return {status:400,data:{error:e.message}};}
   let refBytes=null;
   if(payload.ref_ext){
    try{refBytes=decodeStdB64(b.reference_audio_b64);}catch{return {status:400,data:{error:'参考音频编码无效'}};}
    if(refBytes.length<256||refBytes.length>MAX_REF_BYTES)return {status:413,data:{error:'参考音频片段过大'}};
   }
   const fingerprint=await digest(this.e.AUTH_PEPPER,JSON.stringify(payload)+':'+(refBytes?refBytes.length:0));
   const job=await this.locked(async()=>{
    const q=await this.state(),old=q.jobs.find(j=>j.id===b.requestId);
    if(old){if(old.owner!==b.id||old.fingerprint!==fingerprint)throw new Error('请求冲突');return old;}
    if(q.jobs.filter(active).length>=30||q.jobs.some(j=>j.owner===b.id&&active(j)))throw new Error('请等待已有任务完成');
    const j={id:b.requestId,owner:b.id,fingerprint,status:'uploading',stage:'提交中',created:Date.now(),duration:payload.duration_seconds,key:randomSecret(),mode:payload.reference_mode||'none'};
    q.jobs.push(j);await this.save(q);return j;
   });
   if(job.status==='uploading'){
    if(refBytes){
     const encryptedRef=await encryptRefAudio(job.key,job.id,refBytes);
     payload.ref_url=await this.g.uploadReleaseAsset('smart-'+job.id,'ref.bin',encryptedRef);
    }
    const envelope=await seal(this.e.ARCHIVE_KEY,'playground:'+job.id,{id:'playground:'+job.id,request:payload});
    await this.g.commit([{path:'playground/requests/'+job.id+'.json',envelope}]);
    await this.locked(async()=>{const q=await this.state(),j=q.jobs.find(j=>j.id===job.id);if(j?.status==='uploading'){j.status='queued';j.stage='排队中';await this.save(q);}});
   }
   return {status:200,data:{jobId:job.id}};
  }
  if(path==='/v1/playground/list')return {status:200,data:await this.locked(async()=>{
   const q=await this.state();let ahead=0,wait=0,known=Number.isFinite(q.estimate),online=Date.now()-q.workerAt<180000;
   const jobs=q.jobs.map(j=>{
    const running=['running','publishing'].includes(j.status),eta=known?Math.max(0,Math.round(q.estimate*j.duration-(running?(Date.now()-(j.started||Date.now()))/1000:0))):null;
    const out={id:j.id,mine:j.owner===b.id,status:j.status,stage:j.stage,created:j.created,completed:j.completed,total:j.total,duration:j.duration,position:j.status==='queued'?ahead+1:0,waitSeconds:known&&online?Math.round(wait):null,etaSeconds:online?eta:null};
    if(active(j)){ahead++;if(eta===null)known=false;else wait+=eta;}
    return out;
   });return {jobs:jobs.reverse().slice(0,100),online,serverTime:Date.now()};
  })};
  if(path==='/v1/playground/result'){
   const q=await this.state(),j=q.jobs.find(j=>j.id===b.jobId);
   if(!j||j.status!=='succeeded')return {status:404,data:{error:'作品尚未完成'}};
   return {status:200,data:{url:j.url,key:j.key,jobId:j.id}};
  }
  if(path==='/v1/playground/cancel')return {status:200,data:await this.locked(async()=>{const q=await this.state(),j=q.jobs.find(j=>j.id===b.jobId&&j.owner===b.id);if(!j||!['queued','uploading'].includes(j.status))return {error:'只能取消尚未开始的任务'};j.status='cancelled';j.stage='已取消';await this.save(q);return {ok:true};})};
  if(path==='/v1/playground/delete'){
   if(!UUID.test(b.jobId||''))return {status:400,data:{error:'作品标识无效'}};
   const target=await this.locked(async()=>{
    const q=await this.state(),j=q.jobs.find(x=>x.id===b.jobId&&x.owner===b.id);
    if(!j)return {status:404,data:{error:'作品不存在或无权删除'}};
    if(['uploading','running','publishing'].includes(j.status))return {status:409,data:{error:'任务进行中，请稍后再删除'}};
    j.status='deleting';j.stage='删除中';await this.save(q);return {ok:true};
   });
   if(target.status)return target;
   await this.deleteArtifacts(b.jobId);
   await this.locked(async()=>{
    const q=await this.state();
    q.jobs=q.jobs.filter(x=>!(x.id===b.jobId&&x.owner===b.id));
    await this.save(q);
   });
   return {status:200,data:{ok:true,jobId:b.jobId}};
  }
  return {status:404,data:{error:'接口不存在'}};
 }
 async deleteArtifacts(id){
  const tag='smart-'+id;
  try{
   const release=await this.g.send(this.g.root+'/releases/tags/'+encodeURIComponent(tag));
   if(release?.id){
    try{await this.g.send(this.g.root+'/releases/'+release.id,'DELETE');}
    catch(e){if(e.status!==404)throw e;}
   }
  }catch(e){if(e.status!==404)throw e;}
  try{await this.g.send(this.g.root+'/git/refs/tags/'+encodeURIComponent(tag),'DELETE');}
  catch(e){if(e.status!==404&&e.status!==422)throw e;}
  try{await this.g.commit([{path:'playground/requests/'+id+'.json',remove:true}]);}
  catch(e){if(e.status!==404&&e.status!==422)throw e;}
 }
 async worker(b){
  const result=await this.locked(async()=>{
   const q=await this.state();q.workerAt=Date.now();
   if(Number.isFinite(b.estimate)&&b.estimate>0&&b.estimate<1000)q.estimate=b.estimate;
   let j=q.jobs.find(j=>['running','publishing'].includes(j.status));
   if(b.action==='claim'&&!j&&b.ready){j=q.jobs.find(j=>j.status==='queued');if(j){j.status='running';j.stage='准备生成';j.started=Date.now();j.lease=randomSecret();}}
   if(b.action==='report'&&j&&j.id===b.jobId&&equal(j.lease,b.lease||'')){
    if(['running','publishing','failed','succeeded'].includes(b.status)){
     if(b.status==='succeeded'&&!String(b.url||'').startsWith('https://github.com/'+this.e.GITHUB_REPOSITORY+'/releases/download/'))throw new Error('产物地址无效');
     j.status=b.status;j.stage=String(b.stage||'').slice(0,80);j.completed=Number.isFinite(b.completed)?Math.max(0,b.completed):null;j.total=Number.isFinite(b.total)&&b.total>0?b.total:null;
     if(b.status==='succeeded')j.url=b.url;
    }
   }
   await this.save(q);return j&&active(j)?{...j}:null;
  });
  if(result&&b.action==='claim'){
   const f=await this.g.send(this.g.root+'/contents/playground/requests/'+result.id+'.json');
   const payload=await unseal(this.e.ARCHIVE_KEY,'playground:'+result.id,JSON.parse(atob(f.content.replace(/\s/g,''))));
   return {job:{id:result.id,lease:result.lease,key:result.key,request:payload.request}};
  }
  return {ok:true};
 }
}
