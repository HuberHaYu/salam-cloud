import {ID, SECRET, digest, equal, randomSecret, merge, seal, unseal} from './core.mjs';
import {hashPassword, verifyPassword, validatePassword} from './password.mjs';
import {normalizeOrder, orderId, orderHash, username, randomUsername} from './order.mjs';
import {GitHubArchive} from './github.mjs';
const TEN_MIN=600000, DAY=86400000;
export const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
export function configured(env){return ['AUTH_PEPPER','PASSWORD_PEPPER','ARCHIVE_KEY'].every(k=>SECRET.test(env[k]||''))
  && new Set([env.AUTH_PEPPER,env.PASSWORD_PEPPER,env.ARCHIVE_KEY]).size===3;}
/** Runtime-independent account service. ctx.storage is durable SQLite (Node or a hosted adapter). */
export class AccountService {
  constructor(ctx,env){this.ctx=ctx;this.env=env;this.github=new GitHubArchive(env);this.tail=Promise.resolve();this.flushing=false;this.activeRequests=0;}
  serial(fn){const p=this.tail.then(fn);this.tail=p.catch(()=>{});return p;}
  async fetch(request){
    if(this.activeRequests>=64)return json({error:'服务繁忙，请稍后重试'},503);
    this.activeRequests++;
    try{return await this.handle(request);}finally{this.activeRequests--;}
  }
  async handle(request){
    const path=new URL(request.url).pathname;
    if(path==='/health')return json({service:'salam-id',version:2});
    if(!configured(this.env))return json({error:'账号服务暂未配置完成'},503);
    if(request.method!=='POST')return json({error:'仅支持 POST'},405);
    try{
      if(Number(request.headers.get('content-length')||0)>1000000)return json({error:'同步数据过大'},413);
      const reader=request.body?.getReader();if(!reader)return json({error:'请求为空'},400);
      const chunks=[];let size=0;
      for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;
        if(size>1000000){await reader.cancel();return json({error:'同步数据过大'},413);}chunks.push(value);}
      const bytes=new Uint8Array(size);let offset=0;for(const part of chunks){bytes.set(part,offset);offset+=part.length;part.fill(0);}
      let body;try{body=JSON.parse(new TextDecoder().decode(bytes));}catch{return json({error:'请求格式不正确'},400);}finally{bytes.fill(0);}
      if(!body||typeof body!=='object'||Array.isArray(body))return json({error:'请求格式不正确'},400);
      return await this.serial(()=>this.route(path,body,request));
    }catch(e){return json({error:e.status===429?'尝试较多，请稍后重试':'请求未完成，请稍后重试'},e.status===429?429:503);}
  }
  async limit(name,max,windowMs){
    const key='limit/'+name,now=Date.now(),old=await this.ctx.storage.get(key);
    const value=!old||old.until<=now?{count:0,until:now+windowMs}:old;
    if(value.count>=max){const e=new Error('rate limited');e.status=429;throw e;}
    value.count++;await this.ctx.storage.put(key,value);
  }
  async authLimit(request,identifier){
    await this.limit(await digest(this.env.AUTH_PEPPER,'ip:'+(request.headers.get('CF-Connecting-IP')||'local')),30,15*60000);
    await this.limit('authentication',1200,3600000);
    await this.limit(await digest(this.env.AUTH_PEPPER,'identity:'+identifier),12,15*60000);
  }
  async control(){
    let cached=await this.ctx.storage.get('orderControl');
    if(!cached||Date.now()-cached.at>3600000){
      const data=await this.github.control(cached?.serial||0);
      if(!Number.isSafeInteger(data.serial)||data.serial<(cached?.serial||0))throw new Error('Stale order control');
      if(!data?.order_gate?.kdf||!Array.isArray(data.order_gate.orders)||!Array.isArray(data.order_gate.revoked))throw new Error('Invalid order control');
      cached={at:Date.now(),serial:data.serial,gate:data.order_gate};await this.ctx.storage.put('orderControl',cached);
    }
    return cached.gate;
  }
  async checkedOrder(input){
    const order=normalizeOrder(input),gate=await this.control(),hash=await orderHash(order,gate.kdf);
    if(!gate.orders.includes(hash)||gate.revoked.includes(hash))return null;
    return {id:await orderId(order,this.env.AUTH_PEPPER),hash,proof:await digest(this.env.AUTH_PEPPER,'order-proof:'+order)};
  }
  async directory(){
    let d=await this.ctx.storage.get('directory');
    if(!d){const archived=await this.github.read('directory');d=archived?await unseal(this.env.ARCHIVE_KEY,'directory',archived):{id:'directory',generation:0,users:{}};
      await this.ctx.storage.put('directory',d);}
    return d;
  }
  async load(id,restore=false){
    let a=await this.ctx.storage.get('account/'+id);
    if(!a&&restore){const archived=await this.github.read(id);if(archived){a=await unseal(this.env.ARCHIVE_KEY,id,archived);a.sessions={};a.committedRev=a.rev;await this.ctx.storage.put('account/'+id,a);}}
    return a;
  }
  async save(a,dirty,directory){
    await this.ctx.storage.transaction(async tx=>{
      await tx.put('account/'+a.id,a);
      if(dirty)await tx.put('dirty/'+a.id,a.generation);
      if(directory){await tx.put('directory',directory);await tx.put('directoryDirty',directory.generation);}
    });
    if(dirty&&!(await this.ctx.storage.getAlarm()))await this.ctx.storage.setAlarm(Date.now()+TEN_MIN);
  }
  async issueSession(a){
    const token=randomSecret(),key=await digest(this.env.AUTH_PEPPER,'session:'+token),now=Date.now();
    for(const [k,s]of Object.entries(a.sessions))if(s.expires<=now)delete a.sessions[k];
    if(Object.keys(a.sessions).length>=32){const oldest=Object.keys(a.sessions).sort((x,y)=>a.sessions[x].expires-a.sessions[y].expires)[0];delete a.sessions[oldest];}
    a.sessions[key]={expires:now+30*DAY};return token;
  }
  response(a,extra={}){return json({id:a.id,username:a.username,nickname:a.username,rev:a.rev,committedRev:a.committedRev||0,records:a.records,...extra});}
  syncResponse(a,b,extra={}){
    if(!Number.isSafeInteger(b.since)||b.since<0||b.since>a.rev)return this.response(a,extra);
    const records={};
    for(const [key,value]of Object.entries(a.records))if(value.rev>b.since)records[key]=value;
    // A retried/rebased in-flight edit may conflict at a revision already seen during login.
    // Echo every submitted key so the client can replace its optimistic local value correctly.
    for(const op of b.ops||[])if(a.records[op.key])records[op.key]=a.records[op.key];
    return json({id:a.id,username:a.username,rev:a.rev,committedRev:a.committedRev||0,
      records,delta:true,baseRev:b.since,...extra});
  }
  async passwordOK(a,password){
    if(!a){
      if(!this.dummy)this.dummy=await hashPassword(randomSecret(),'unknown',this.env.PASSWORD_PEPPER);
      await verifyPassword(password,'unknown',this.dummy,this.env.PASSWORD_PEPPER);return false;
    }
    return verifyPassword(password,a.id,a.password,this.env.PASSWORD_PEPPER);
  }
  async route(path,b,request){
    if(['/v1/order/check','/v1/order/activate','/v1/order/login'].includes(path)){
      let normalized;try{normalized=normalizeOrder(b.order);}catch{return json({error:'请输入完整的主订单编号'},400);}
      await this.authLimit(request,normalized);
      const checked=await this.checkedOrder(normalized);
      if(!checked)return json({error:'当前订单清单中未找到有效订单，请核对编号或稍后重试'},401);
      let a=await this.load(checked.id,true);
      // A collision must never merge two different orders, even with a truncated public ID.
      if(a&&!equal(a.orderProof,checked.proof))return json({error:'账号信息不匹配，请联系客服'},409);
      if(path==='/v1/order/check')return json({requiresSetup:!a});
      if(!a&&path==='/v1/order/activate'){
        try{validatePassword(b.password);}catch(e){return json({error:e.message},400);}
        if(this.env.REGISTRATION_ENABLED!=='true')return json({error:'暂时无法开通新账号'},503);
        await this.limit('registrations',100,DAY);
        const directory=await this.directory();let name;
        do{name=randomUsername();}while(Object.hasOwn(directory.users,name));
        a={id:checked.id,username:name,orderHash:checked.hash,orderProof:checked.proof,
          password:await hashPassword(b.password,checked.id,this.env.PASSWORD_PEPPER),authVersion:1,
          rev:0,committedRev:0,generation:1,records:{},devices:{},sessions:{}};
        directory.users[name]=a.id;directory.generation++;
        const token=await this.issueSession(a);await this.save(a,true,directory);return this.response(a,{token});
      }
      // Repeating activation can log in with the original password; it can NEVER reset it.
      if(!await this.passwordOK(a,b.password))return json({error:'订单号或密码不正确'},401);
      a.orderHash=checked.hash;
      const token=await this.issueSession(a);await this.save(a,false);return this.response(a,{token});
    }
    if(path==='/v1/username/login'){
      let name;try{name=username(b.username);}catch{return json({error:'用户名或密码不正确'},401);}
      await this.authLimit(request,name);
      const d=await this.directory(),id=Object.hasOwn(d.users,name)?d.users[name]:null;
      const a=id?await this.load(id,true):null;
      if(!await this.passwordOK(a,b.password)||a.username!==name)return json({error:'用户名或密码不正确'},401);
      const gate=await this.control();
      if(!gate.orders.includes(a.orderHash)||gate.revoked.includes(a.orderHash))return json({error:'订单信息已更新，请使用订单号登录核对'},401);
      const token=await this.issueSession(a);await this.save(a,false);return this.response(a,{token});
    }
    if(path==='/v1/register'||path==='/v1/login')return json({error:'请使用订单号和密码，或用户名和密码登录'},410);
    if(!ID.test(b.id||''))return json({error:'账号标识不正确'},400);
    const token=(request.headers.get('Authorization')||'').replace(/^Bearer /,'');
    if(!SECRET.test(token))return json({error:'请重新登录'},401);
    const a=await this.load(b.id),sessionKey=await digest(this.env.AUTH_PEPPER,'session:'+token);
    if(!a||!a.sessions[sessionKey]||a.sessions[sessionKey].expires<=Date.now())return json({error:'登录已失效，请重新登录'},401);
    if(path==='/v1/logout'){delete a.sessions[sessionKey];await this.save(a,false);return json({ok:true});}
    if(path==='/v1/account/username'||path==='/v1/account/password'){
      await this.authLimit(request,a.id);
      if(!await this.passwordOK(a,b.currentPassword))return json({error:'当前密码不正确'},403);
      if(path==='/v1/account/username'){
        let name;try{name=username(b.username);}catch(e){return json({error:e.message},400);}
        const d=await this.directory();if(Object.hasOwn(d.users,name)&&d.users[name]!==a.id)return json({error:'该用户名已被使用'},409);
        if(name!==a.username){delete d.users[a.username];d.users[name]=a.id;d.generation++;a.username=name;a.generation++;await this.save(a,true,d);}
        return this.response(a);
      }
      try{validatePassword(b.newPassword);}catch(e){return json({error:e.message},400);}
      a.password=await hashPassword(b.newPassword,a.id,this.env.PASSWORD_PEPPER);a.authVersion++;a.generation++;a.sessions={};
      const fresh=await this.issueSession(a);await this.save(a,true);return this.response(a,{token:fresh});
    }
    if(path==='/v1/sync'){
      if(b.ops?.length){let result;try{result=merge(a,b);}catch{return json({error:'同步内容或版本无效，请保留本机数据后重试'},409);}
        if(!result.duplicate)await this.save(result.account,true);return this.syncResponse(result.account,b,{conflicts:result.conflicts});}
      return this.syncResponse(a,b);
    }
    return json({error:'接口不存在'},404);
  }
  async alarm(){
    if(this.flushing)return;this.flushing=true;let retryAt=Date.now()+TEN_MIN;
    try{
      const snapshot=await this.serial(async()=>{
        const dirty=await this.ctx.storage.list({prefix:'dirty/',limit:20}),accounts=[];
        for(const [key]of dirty){const a=await this.load(key.slice(6));if(a)accounts.push(a);}
        const directory=await this.ctx.storage.get('directoryDirty')?await this.directory():null;
        return {accounts,directory};
      });
      const files=[];let total=0;
      for(const a of snapshot.accounts){const envelope=await seal(this.env.ARCHIVE_KEY,a.id,{...a,sessions:{}}),size=JSON.stringify(envelope).length;
        if(files.length&&total+size>1800000)break;files.push({id:a.id,envelope,generation:a.generation,rev:a.rev});total+=size;}
      if(snapshot.directory)files.push({id:'directory',generation:snapshot.directory.generation,envelope:await seal(this.env.ARCHIVE_KEY,'directory',snapshot.directory)});
      if(files.length){
        await this.github.commit(files);
        await this.serial(async()=>{
          for(const file of files)await this.ctx.storage.transaction(async tx=>{
            if(file.id==='directory'){if(await tx.get('directoryDirty')===file.generation)await tx.delete('directoryDirty');return;}
            const a=await tx.get('account/'+file.id);if(!a)return;
            a.committedRev=Math.max(a.committedRev||0,file.rev);await tx.put('account/'+file.id,a);
            if(a.generation===file.generation)await tx.delete('dirty/'+file.id);
          });
        });retryAt=Date.now()+60000;
      }
      await this.serial(async()=>{const counters=await this.ctx.storage.list({prefix:'limit/',limit:1000});
        const expired=[...counters].filter(([,v])=>v.until<Date.now()).map(([k])=>k);if(expired.length)await this.ctx.storage.delete(expired);});
    }catch(e){const n=(await this.ctx.storage.get('archiveFailures')||0)+1;await this.ctx.storage.put('archiveFailures',n);
      retryAt=Math.max(Date.now()+Math.min(3600000,TEN_MIN*2**Math.min(n-1,3)),e.retryAt||0);
    }finally{this.flushing=false;await this.serial(async()=>{
      if((await this.ctx.storage.list({prefix:'dirty/',limit:1})).size||await this.ctx.storage.get('directoryDirty'))await this.ctx.storage.setAlarm(retryAt);
      else{await this.ctx.storage.delete('archiveFailures');await this.ctx.storage.deleteAlarm();}
    });}
  }
}
