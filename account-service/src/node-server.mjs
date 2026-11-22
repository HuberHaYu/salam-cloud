import {DatabaseSync} from 'node:sqlite';
import {createServer} from 'node:http';
import {isIP} from 'node:net';
import {Readable} from 'node:stream';
import {mkdirSync,chmodSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {AccountService,configured} from './service.mjs';

/** Single-process SQLite adapter, including serialization across awaited transactions. */
export class SqliteStorage {
  constructor(path){
    if(path!==':memory:'){mkdirSync(dirname(path),{recursive:true,mode:0o700});}
    this.db=new DatabaseSync(path);if(path!==':memory:')chmodSync(path,0o600);
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT NOT NULL)');
    this.tail=Promise.resolve();
    this.raw={
      get:async key=>{const r=this.db.prepare('SELECT value FROM state WHERE key=?').get(key);return r?JSON.parse(r.value):undefined;},
      put:async(key,value)=>{this.db.prepare('INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,JSON.stringify(value));},
      delete:async keys=>{const stmt=this.db.prepare('DELETE FROM state WHERE key=?');for(const key of Array.isArray(keys)?keys:[keys])stmt.run(key);},
      list:async({prefix='',limit=1000,after=''}={})=>new Map(this.db.prepare('SELECT key,value FROM state WHERE key>=? AND key<? AND key>? ORDER BY key LIMIT ?')
        .all(prefix,prefix+'\uffff',after,limit).map(r=>[r.key,JSON.parse(r.value)]))
    };
  }
  serial(fn){const p=this.tail.then(fn);this.tail=p.catch(()=>{});return p;}
  get(k){return this.serial(()=>this.raw.get(k));} put(k,v){return this.serial(()=>this.raw.put(k,v));}
  delete(k){return this.serial(()=>this.raw.delete(k));} list(o){return this.serial(()=>this.raw.list(o));}
  transaction(fn){return this.serial(async()=>{this.db.exec('BEGIN IMMEDIATE');try{const result=await fn(this.raw);this.db.exec('COMMIT');return result;}catch(e){this.db.exec('ROLLBACK');throw e;}});}
  getAlarm(){return this.get('$alarm');}
  async setAlarm(time){await this.put('$alarm',time);this.onAlarmChange?.();}
  async deleteAlarm(){await this.delete('$alarm');this.onAlarmChange?.();}
  close(){return this.serial(()=>this.db.close());}
}
export async function start(env=process.env){
  if(!configured(env))throw new Error('Set distinct AUTH_PEPPER, PASSWORD_PEPPER and ARCHIVE_KEY secrets before starting.');
  const config={GITHUB_REPOSITORY:'HuberHaYu/salam-cloud',GITHUB_BRANCH:'main',REGISTRATION_ENABLED:'true',...env};
  const storage=new SqliteStorage(resolve(env.DATA_FILE||'data/salam-id.sqlite'));
  const service=new AccountService({storage},config);let timer,stopping=false;
  async function arm(){clearTimeout(timer);if(stopping)return;const at=await storage.getAlarm();
    if(stopping)return;clearTimeout(timer);
    if(at)timer=setTimeout(()=>service.alarm().catch(()=>{}).finally(()=>{if(!stopping)void arm();}),Math.min(2147483647,Math.max(1,at-Date.now())));}
  storage.onAlarmChange=()=>{void arm().catch(()=>{});};await arm();
  const server=createServer(async(req,res)=>{
    try{
      const headers=new Headers();for(const [name,value]of Object.entries(req.headers))if(value!==undefined)headers.set(name,Array.isArray(value)?value.join(','):value);
      // Never trust a client-supplied Cloudflare/proxy identity header.
      let peer=req.socket.remoteAddress||'local';
      if(env.TRUST_PROXY_ADDRESS&&peer===env.TRUST_PROXY_ADDRESS&&isIP(String(req.headers['x-real-ip']||'')))peer=String(req.headers['x-real-ip']);
      headers.set('CF-Connecting-IP',peer);
      const method=req.method||'GET';
      const request=new Request('http://localhost'+(req.url||'/'),{method,headers,
        body:['GET','HEAD'].includes(method)?undefined:Readable.toWeb(req),duplex:'half'});
      const response=await service.fetch(request);res.writeHead(response.status,Object.fromEntries(response.headers));res.end(Buffer.from(await response.arrayBuffer()));
    }catch{res.writeHead(503,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end('{"error":"服务暂不可用"}');}
  });
  server.requestTimeout=30000;server.headersTimeout=15000;
  const host=env.BIND_ADDRESS||'127.0.0.1',port=Number(env.PORT||8787);
  await new Promise((ok,fail)=>{server.once('error',fail);server.listen(port,host,ok);});
  const close=async()=>{stopping=true;clearTimeout(timer);await new Promise(r=>server.close(r));await service.tail;await storage.close();};
  return {server,storage,close};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  start().then(({close})=>{console.log('Salam ID listening on configured local address; use a pinned HTTPS reverse proxy for Android.');
    for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{void close().finally(()=>process.exit(0));});
  }).catch(()=>{console.error('Salam ID could not start. Check runtime, protected configuration and data permissions.');process.exitCode=1;});
}
