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
  async send(path,method='GET',body,token,accept='application/vnd.github+json') {
    const response=await fetch('https://api.github.com'+path, {method,redirect:'error',signal:AbortSignal.timeout(20000),
      headers:{Authorization:'Bearer '+(token||await this.token()),Accept:accept,'X-GitHub-Api-Version':'2022-11-28','User-Agent':'Salam-ID','Content-Type':'application/json'},
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
  // Contents API reads the current file and its compare-and-swap SHA in one request.
  async readLibrary(id) {
    try {
      const f=await this.send(this.root+'/contents/accounts/library/v1/'+id+'.json?ref='+encodeURIComponent(this.env.GITHUB_BRANCH||'main'),'GET',undefined,undefined,'application/vnd.github.object+json');
      if(!f.sha)throw new Error('Invalid music file');
      return {sha:f.sha,envelope:f.encoding==='base64'?JSON.parse(new TextDecoder().decode(unb64(f.content.replace(/\s/g,'')))):await this.readLibraryBlob(f.sha)};
    }catch(e){if(e.status===404)return null;throw e;}
  }
  async readLibraryBlob(sha) {
    if(!/^[a-f0-9]{40}$/.test(sha))throw new Error('Invalid blob identity');
    const f=await this.send(this.root+'/git/blobs/'+sha);
    if(f.encoding!=='base64'||f.size>16000000)throw new Error('Invalid library blob');
    return JSON.parse(new TextDecoder().decode(unb64(f.content.replace(/\s/g,''))));
  }
  async writeLibraryParts(id,files,expectedSha) {
    const branch=encodeURIComponent(this.env.GITHUB_BRANCH||'main');
    const ref=await this.send(this.root+'/git/ref/heads/'+branch),head=ref.object.sha;
    const parent=await this.send(this.root+'/git/commits/'+head);
    let current;try{current=await this.send(this.root+'/contents/accounts/library/v1/'+id+'.json?ref='+head,'GET',undefined,undefined,'application/vnd.github.object+json');}
    catch(e){if(e.status!==404)throw e;}
    if(current?.sha!==expectedSha){const e=new Error('Library changed');e.status=409;throw e;}
    const tree=await this.send(this.root+'/git/trees','POST',{base_tree:parent.tree.sha,
      tree:files.map(f=>({path:f.path,mode:'100644',type:'blob',...(f.remove?{sha:null}:{content:f.content})}))});
    const commit=await this.send(this.root+'/git/commits','POST',{message:'Salam ID library sync',tree:tree.sha,parents:[head]});
    await this.send(this.root+'/git/refs/heads/'+branch,'PATCH',{sha:commit.sha,force:false});
  }
  async writeLibrary(id,envelope,sha) {
    const bytes=new TextEncoder().encode(JSON.stringify(envelope));let raw='';
    for(let i=0;i<bytes.length;i+=8192)raw+=String.fromCharCode(...bytes.subarray(i,i+8192));
    const result=await this.send(this.root+'/contents/accounts/library/v1/'+id+'.json','PUT',{
      message:'Salam ID manual library sync',branch:this.env.GITHUB_BRANCH||'main',content:btoa(raw),...(sha?{sha}:{})});
    return result.content.sha;
  }
  async control(minimumSerial=0) {
    if(this.env.GITHUB_PUBLIC_MIRRORS==='true')try{
      return await mirroredControl(this.env.GITHUB_REPOSITORY,this.env.GITHUB_BRANCH||'main',minimumSerial);
    }catch{/* Trusted GitHub API fallback; installation tokens never go to mirrors. */}
    return this.readJson('api/v1/control.json');
  }
  async commit(files) {
    if (!files.length) return;
    const branch=encodeURIComponent(this.env.GITHUB_BRANCH||'main');
    const maxAttempts=6;
    for(let attempt=0;attempt<maxAttempts;attempt++){
      const ref=await this.send(this.root+'/git/ref/heads/'+branch);
      const parent=await this.send(this.root+'/git/commits/'+ref.object.sha);
      const tree=await this.send(this.root+'/git/trees','POST',{base_tree:parent.tree.sha,
        tree:files.map(f=>({path:f.path||'accounts/v1/'+f.id+'.json',mode:'100644',type:'blob',
          ...(f.remove?{sha:null}:{content:JSON.stringify(f.envelope)})}))});
      const commit=await this.send(this.root+'/git/commits','POST',{message:'Salam ID encrypted checkpoint',tree:tree.sha,parents:[ref.object.sha]});
      try{
        await this.send(this.root+'/git/refs/heads/'+branch,'PATCH',{sha:commit.sha,force:false});
        return;
      }catch(e){
        if((e?.status===409||e?.status===422)&&attempt<maxAttempts-1){
          await new Promise(r=>setTimeout(r,150+Math.floor(Math.random()*250)*(attempt+1)));
          continue;
        }
        throw e;
      }
    }
  }
  async uploadReleaseAsset(tag,name,bytes) {
    let release;
    try { release=await this.send(this.root+'/releases/tags/'+encodeURIComponent(tag)); }
    catch(e) {
      if(e.status!==404) throw e;
      try {
        release=await this.send(this.root+'/releases','POST',{tag_name:tag,name:tag,body:'Encrypted Salam Smart Music artifact',draft:false,prerelease:true});
      } catch(createErr) {
        if(createErr?.status===422) release=await this.send(this.root+'/releases/tags/'+encodeURIComponent(tag));
        else throw createErr;
      }
    }
    const existing=(release.assets||[]).find(a=>a.name===name);
    if(existing?.browser_download_url) return existing.browser_download_url;
    const uploadBase=String(release.upload_url||'').split('{')[0];
    if(!uploadBase) throw new Error('Release upload URL unavailable');
    const response=await fetch(uploadBase+'?name='+encodeURIComponent(name),{
      method:'POST',redirect:'error',signal:AbortSignal.timeout(30000),
      headers:{Authorization:'Bearer '+await this.token(),Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Salam-ID','Content-Type':'application/octet-stream'},
      body:bytes
    });
    if(!response.ok){const error=new Error('GitHub '+response.status);error.status=response.status;throw error;}
    const asset=await response.json();
    return asset.browser_download_url;
  }
}
