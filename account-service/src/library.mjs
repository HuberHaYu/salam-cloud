import {seal,unseal} from './core.mjs';
const enc=new TextEncoder(), TARGET=240000;
const size=x=>enc.encode(JSON.stringify(x)).length;
const bucket=key=>{let h=2166136261;for(let i=0;i<key.length;i++)h=Math.imul(h^key.charCodeAt(i),16777619);return (h>>>0).toString(2).padStart(32,'0');};
export async function blobSha(text){const body=enc.encode(text),head=enc.encode('blob '+body.length+'\0'),data=new Uint8Array(head.length+body.length);data.set(head);data.set(body,head.length);return [...new Uint8Array(await crypto.subtle.digest('SHA-1',data))].map(x=>x.toString(16).padStart(2,'0')).join('');}
/** Account-scoped encrypted index and adaptive record shards. No music is stored in SQL. */
export class LibraryStore {
 constructor(github,env,id){this.github=github;this.key=env.ARCHIVE_KEY;this.id=id;this.cache=new Map();}
 async open(snapshot){
  const file=snapshot?{sha:snapshot,envelope:await this.github.readLibraryBlob(snapshot)}:await this.github.readLibrary(this.id);
  this.sha=file?.sha;this.index=file?await unseal(this.key,this.id,file.envelope):{id:this.id,rev:0,generation:0,records:{},devices:{}};
  if(this.index.storage===2){
   if(!Array.isArray(this.index.shards))throw new Error('Invalid index');
   for(const part of this.index.shards)if(!/^[01]{0,32}$/.test(part.prefix)||!/^([a-f0-9]{40})$/.test(part.sha))throw new Error('Invalid shard');
  }
  return this;
 }
 async part(desc){
  if(this.cache.has(desc.sha))return this.cache.get(desc.sha);
  const payload=await unseal(this.key,this.id,await this.github.readLibraryBlob(desc.sha));
  if(payload.prefix!==desc.prefix||!payload.records)throw new Error('Invalid shard identity');
  for(const k of Object.keys(payload.records))if(!bucket(k).startsWith(desc.prefix))throw new Error('Invalid shard key');
  this.cache.set(desc.sha,payload.records);return payload.records;
 }
 async writable(ops){
  if(this.index.storage!==2)return structuredClone(this.index);
  const wanted=new Set((ops||[]).map(op=>bucket(op.key))),records={};
  for(const part of this.index.shards)if([...wanted].some(hash=>hash.startsWith(part.prefix)))Object.assign(records,await this.part(part));
  return {...this.index,records};
 }
 path(prefix){return 'accounts/library/v2/'+this.id+'/'+(prefix||'root')+'.json';}
 async save(music){
  if(this.index.storage!==2&&size(music)<=TARGET){
   this.sha=await this.github.writeLibrary(this.id,await seal(this.key,this.id,music),this.sha);this.index=music;return;
  }
  const old=this.index,shards=[],files=[];
  const split=async(prefix,records)=>{
   if(size(records)>TARGET&&prefix.length<32){
    const sides=[{},{}];for(const [key,value]of Object.entries(records))sides[bucket(key)[prefix.length]==='1'?1:0][key]=value;
    await split(prefix+'0',sides[0]);await split(prefix+'1',sides[1]);return;
   }
   const envelope=await seal(this.key,this.id,{id:this.id,prefix,records}),content=JSON.stringify(envelope),sha=await blobSha(content);
   files.push({path:this.path(prefix),content});this.cache.set(sha,records);
   shards.push({prefix,sha,rev:Math.max(0,...Object.values(records).map(r=>r.rev))});
  };
  if(old.storage===2){
   for(const part of old.shards){
    // Only shards loaded for this operation can change; untouched references remain byte-identical.
    if(!this.cache.has(part.sha)){shards.push(part);continue;}
    const records={};for(const [k,v]of Object.entries(music.records))if(bucket(k).startsWith(part.prefix))records[k]=v;
    const before=await this.part(part);
    if(JSON.stringify(before)===JSON.stringify(records)){shards.push(part);continue;}
    await split(part.prefix,records);
    if(!shards.some(p=>p.prefix===part.prefix))files.push({path:this.path(part.prefix),remove:true});
   }
  }else await split('',music.records);
  const index={id:this.id,storage:2,rev:music.rev,generation:music.generation,devices:music.devices,shards:shards.sort((a,b)=>a.prefix.localeCompare(b.prefix))};
  const content=JSON.stringify(await seal(this.key,this.id,index));
  files.push({path:'accounts/library/v1/'+this.id+'.json',content});
  await this.github.writeLibraryParts(this.id,files,this.sha);
  this.sha=await blobSha(content);this.index=index;
 }
 async page(body){
  const full=!Number.isSafeInteger(body.since)||body.since<0||body.since>this.index.rev;
  const keys=new Set((body.ops||[]).map(op=>op.key));let records={},nextPage;
  if(body.uploadOnly){
   const current=await this.writable(body.ops);
   for(const key of keys)if(current.records[key])records[key]=current.records[key];
  }else if(this.index.storage===2){
   const selected=this.index.shards.filter(p=>full||p.rev>body.since);
   const start=body.page||0;
   if(!Number.isSafeInteger(start)||start<0||start>selected.length)throw new Error('Invalid page');
   const end=body.paged?Math.min(selected.length,start+1):selected.length;
   for(let i=start;i<end;i++)Object.assign(records,await this.part(selected[i]));
   if(end<selected.length)nextPage=end;
  }else records=this.index.records;
  if(!body.uploadOnly&&keys.size){
   const current=await this.writable(body.ops);for(const key of keys)if(current.records[key])records[key]=current.records[key];
  }
  if(!full){const filtered={};for(const [key,r]of Object.entries(records))if(r.rev>body.since||keys.has(key))filtered[key]=r;records=filtered;}
  return {id:this.id,rev:this.index.rev,committedRev:this.index.rev,records,...(full?{}:{delta:true,baseRev:body.since}),
   ...(nextPage!==undefined?{nextPage,snapshot:this.sha}:{}),deviceSeq:this.index.devices[body.device]||0};
 }
 deletionPaths(){return this.index.storage===2?this.index.shards.map(p=>this.path(p.prefix)):[];}
}
