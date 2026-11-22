import {b64, unb64} from './core.mjs';
import {mirroredControl} from './public-control.mjs';
export class GitHubArchive {
  constructor(env) { this.env=env; this.cached=null; }
  async token() {
    // Owner-managed repository token is an alternative to App installation credentials.
    // The same credential route is used by the existing Mac SalamCloud client.
    if(typeof this.env.GITHUB_TOKEN==='string' && this.env.GITHUB_TOKEN.trim())return this.env.GITHUB_TOKEN.trim();
    if (this.cached && Date.now()<this.cached.until) return this.cached.value;
    const e=this.env, now=Math.floor(Date.now()/1000);
    if (!e.GITHUB_APP_ID || !e.GITHUB_INSTALLATION_ID || !e.GITHUB_PRIVATE_KEY) throw new Error('GitHub App 未配置');
    const enc=new TextEncoder();
    const jwtPart=x=>b64(enc.encode(JSON.stringify(x)));
    const unsigned=jwtPart({alg:'RS256',typ:'JWT'})+'.'+jwtPart({iat:now-60,exp:now+540,iss:e.GITHUB_APP_ID});
    const der=unb64(e.GITHUB_PRIVATE_KEY.replace(/-----[^-]+-----/g,'').replace(/\s/g,''));
    const key=await crypto.subtle.importKey('pkcs8',der,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['sign']);
    const signature=b64(new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key,enc.encode(unsigned))));
    const result=await this.send('/app/installations/'+e.GITHUB_INSTALLATION_ID+'/access_tokens','POST',
      {repositories:[e.GITHUB_REPOSITORY.split('/')[1]],permissions:{contents:'write'}},unsigned+'.'+signature);
    this.cached={value:result.token,until:Date.parse(result.expires_at)-120000};
    return result.token;
  }
  async send(path,method='GET',body,token) {
    const response=await fetch('https://api.github.com'+path, {method,redirect:'error',signal:AbortSignal.timeout(20000),
      headers:{Authorization:'Bearer '+(token||await this.token()),Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Salam-ID','Content-Type':'application/json'},
      body:body===undefined?undefined:JSON.stringify(body)});
    if(!response.ok) { const error=new Error('GitHub '+response.status);error.status=response.status;
      error.retryAt=Date.now()+Math.max(60000,Number(response.headers.get('retry-after')||0)*1000);
      if(response.headers.get('x-ratelimit-remaining')==='0') error.retryAt=Math.max(error.retryAt,Number(response.headers.get('x-ratelimit-reset'))*1000+5000);
      throw error; }
    return response.status===204?{}:response.json();
  }
  get root() { return '/repos/'+this.env.GITHUB_REPOSITORY; }
  async readJson(path, optional=false) {
    try {
      const file=await this.send(this.root+'/contents/'+path+'?ref='+encodeURIComponent(this.env.GITHUB_BRANCH||'main'));
      if(file.encoding!=='base64'||file.size>2500000)throw new Error('云端文件无效');
      return JSON.parse(new TextDecoder().decode(unb64(file.content.replace(/\s/g,''))));
    }catch(e){if(optional&&e.status===404)return null;throw e;}
  }
  async read(id) { return this.readJson('accounts/v1/'+id+'.json',true); }
  async control(minimumSerial=0) {
    if(this.env.GITHUB_PUBLIC_MIRRORS==='true')try{
      return await mirroredControl(this.env.GITHUB_REPOSITORY,this.env.GITHUB_BRANCH||'main',minimumSerial);
    }catch{/* Trusted GitHub API fallback; installation tokens never go to mirrors. */}
    return this.readJson('api/v1/control.json');
  }
  async commit(files) {
    if (!files.length) return;
    const branch=encodeURIComponent(this.env.GITHUB_BRANCH||'main');
    const ref=await this.send(this.root+'/git/ref/heads/'+branch);
    const parent=await this.send(this.root+'/git/commits/'+ref.object.sha);
    const tree=await this.send(this.root+'/git/trees','POST',{base_tree:parent.tree.sha,
      tree:files.map(f=>({path:'accounts/v1/'+f.id+'.json',mode:'100644',type:'blob',content:JSON.stringify(f.envelope)}))});
    const commit=await this.send(this.root+'/git/commits','POST',{message:'Salam ID encrypted checkpoint',tree:tree.sha,parents:[ref.object.sha]});
    // Non-fast-forward is deliberately rejected. A later alarm rebuilds on the latest branch.
    await this.send(this.root+'/git/refs/heads/'+branch,'PATCH',{sha:commit.sha,force:false});
  }
}
