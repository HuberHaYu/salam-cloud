// Optional Cloudflare adapter. AccountService itself has no Cloudflare API dependency.
import {AccountService, json, configured} from './service.mjs';
export class AccountHub extends AccountService {}
export default {async fetch(request,env){
  if(new URL(request.url).pathname==='/health')return json({service:'salam-id',version:2});
  if(!configured(env))return json({error:'账号服务暂未配置完成'},503);
  return env.ACCOUNTS.get(env.ACCOUNTS.idFromName('salam-id-v1')).fetch(request);
}};
