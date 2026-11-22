import postgres from 'postgres';
import {AccountService,json} from '../../../src/service.mjs';
import {PostgresStorage} from '../../../src/postgres-storage.mjs';
import {GitHubArchive} from '../../../src/github.mjs';
import {equal,SECRET} from '../../../src/core.mjs';

const env=Deno.env.toObject();
const sql=postgres(env.SUPABASE_DB_URL,{prepare:false,max:2,idle_timeout:15,connect_timeout:10});
const github=new GitHubArchive(env);
class HostedAccountService extends AccountService {
  serial(fn){return super.serial(()=>this.ctx.storage.locked(fn));}
}
function service(){const hub=new HostedAccountService({storage:new PostgresStorage(sql)},env);hub.github=github;return hub;}

// Durable lease spans the unlocked GitHub commit; concurrent cron/invocation retries cannot flush twice.
async function checkpoint(){
  const hub=service(),due=await hub.ctx.storage.getAlarm();if(!due||due>Date.now())return;
  const holder=crypto.randomUUID();
  const claimed=await sql`UPDATE salam_private.archive_lease SET until_at=now()+interval '3 minutes',holder=${holder}
    WHERE singleton=true AND until_at<now() RETURNING holder`;
  if(!claimed.length)return;
  try{const at=await hub.ctx.storage.getAlarm();if(at&&at<=Date.now())await hub.alarm();}
  finally{await sql`UPDATE salam_private.archive_lease SET until_at='-infinity',holder=NULL WHERE singleton=true AND holder=${holder}`;}
}
Deno.serve(async request=>{
  try{
    const url=new URL(request.url);
    // Supabase forwards /salam-id/...; strip only this function's known mount path.
    url.pathname=url.pathname.replace(/^\/(?:functions\/v1\/)?salam-id(?=\/|$)/,'')||'/';
    if(url.pathname==='/internal/checkpoint'){
      const supplied=request.headers.get('Authorization')?.replace(/^Bearer /,'')||'';
      if(request.method!=='POST'||!SECRET.test(env.CRON_SECRET||'')||!equal(supplied,env.CRON_SECRET))return json({error:'接口不可用'},401);
      await checkpoint();return json({ok:true});
    }
    const headers=new Headers(request.headers);
    // Ignore the client-supplied Cloudflare header. The Supabase gateway owns the forwarded chain.
    const forwarded=request.headers.get('x-forwarded-for')||'';
    headers.set('CF-Connecting-IP',forwarded.split(',').at(-1)?.trim()||'unknown');
    const adjusted=new Request(url,{method:request.method,headers,body:['GET','HEAD'].includes(request.method)?undefined:request.body});
    const response=await service().fetch(adjusted);
    // Cron is the reliable driver. Opportunistic work drains an overdue checkpoint after activity.
    EdgeRuntime.waitUntil(checkpoint().catch(()=>{}));
    return response;
  }catch{return json({error:'服务暂不可用，请稍后重试'},503);}
});
