"""Outbound-only Salam playground bridge. Never cancels or reconfigures local YuE2 jobs."""
import base64, fcntl, hashlib, json, os, statistics, time, urllib.request, urllib.error
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ROOT=Path(__file__).resolve().parent
CONFIG=json.loads((ROOT/'config.json').read_text())
LOCAL='http://127.0.0.1:7861'
STATE=ROOT/'flight.json'
JOB_MAP=ROOT/'job_map.json'
REF_DIR=ROOT/'refs'
REF_DIR.mkdir(exist_ok=True)
lock_file=(ROOT/'worker.lock').open('w');fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
def request(url,data=None,token=None,binary=None,method=None):
    headers={'User-Agent':'Salam-Playground','Accept':'application/vnd.github+json'}
    if token: headers['Authorization']='Bearer '+token
    body=binary if binary is not None else json.dumps(data).encode() if data is not None else None
    if body is not None:headers['Content-Type']='application/octet-stream' if binary is not None else 'application/json'
    with urllib.request.urlopen(urllib.request.Request(url,body,headers,method=method),timeout=120) as r:return json.load(r)
def cloud(data):return request(CONFIG['endpoint']+'/v1/playground/worker',data,CONFIG['worker_secret'])
def save(f):
    tmp=STATE.with_suffix('.tmp');tmp.write_text(json.dumps(f));os.chmod(tmp,0o600);tmp.replace(STATE)
def estimate():
    samples=[]
    for p in Path(CONFIG['outputs']).glob('*/job.json'):
        try:
            j=json.loads(p.read_text());d=j['request']['duration_seconds']
            if j['status']=='succeeded' and j.get('model')==status.get('model') and not j['request'].get('live') and j.get('elapsed',0)>0:samples.append(j['elapsed']/d)
        except (KeyError,ValueError,OSError):pass
    return statistics.median(samples[-30:]) if samples else None

def load_job_map():
    try: return json.loads(JOB_MAP.read_text()) if JOB_MAP.exists() else {}
    except (OSError,ValueError): return {}
def save_job_map(cloud_id,local_id):
    m=load_job_map();m[cloud_id]=local_id
    if len(m)>200:
        for k in list(m.keys())[:-200]:m.pop(k,None)
    tmp=JOB_MAP.with_suffix('.tmp');tmp.write_text(json.dumps(m));os.chmod(tmp,0o600);tmp.replace(JOB_MAP)
def download_reference(f):
    ref_url=f['request'].get('ref_url')
    if not ref_url:return None
    ext=''.join(c for c in str(f['request'].get('ref_ext','ogg')).lower() if c.isalnum()) or 'ogg'
    dest=REF_DIR/(f['id']+'.'+ext)
    if dest.exists() and dest.stat().st_size>0:return str(dest)
    with urllib.request.urlopen(urllib.request.Request(ref_url,headers={'User-Agent':'Salam-Playground'}),timeout=120) as r:cipher=r.read()
    key=base64.urlsafe_b64decode(f['key']+'='*(-len(f['key'])%4))
    plain=AESGCM(key).decrypt(cipher[:12],cipher[12:],(f['id']+':ref').encode())
    dest.write_bytes(plain);return str(dest)
def build_local_request(f,seed):
    req={k:v for k,v in f['request'].items() if k not in ('ref_url','ref_ext','reference_title','source_job_id')}
    req['seed']=seed
    src_job=f['request'].get('source_job_id')
    if src_job:
        local_src=load_job_map().get(src_job)
        if local_src:
            src_dir=Path(CONFIG['outputs'])/local_src
            if req.get('reference_mode')=='continue' and (src_dir/'job.json').exists():
                req['continue_from']=local_src;req.pop('reference_mode',None)
            elif (src_dir/'audio.wav').exists():
                req['reference_audio']=str(src_dir/'audio.wav')
            elif (src_dir/'audio.flac').exists():
                req['reference_audio']=str(src_dir/'audio.flac')
    elif f['request'].get('ref_url'):
        req['reference_audio']=download_reference(f)
    return req
def cleanup_reference(job_id):
    for p in REF_DIR.glob(job_id+'.*'):p.unlink(missing_ok=True)

def publish(f):
    repo=CONFIG['repository'];tag='smart-'+f['id'];api='https://api.github.com/repos/'+repo
    token=CONFIG['github_token'];name='music.bin'
    try: release=request(api+'/releases/tags/'+tag,token=token)
    except urllib.error.HTTPError as e:
        if e.code!=404:raise
        release=request(api+'/releases',{'tag_name':tag,'name':tag,'body':'Encrypted Salam Smart Music artifact','draft':False,'prerelease':True},token)
    for a in release.get('assets',[]):
        if a['name']==name:return a['browser_download_url']
    folder=Path(CONFIG['outputs'])/f['local_id'];audio=folder/'audio.flac'
    if not audio.exists():
        import soundfile as sf
        samples,rate=sf.read(folder/'audio.wav',dtype='float32');sf.write(audio,samples,rate,format='FLAC')
    nonce=os.urandom(12);key=base64.urlsafe_b64decode(f['key']+'='*(-len(f['key'])%4))
    cipher=nonce+AESGCM(key).encrypt(nonce,audio.read_bytes(),f['id'].encode())
    a=request(release['upload_url'].split('{')[0]+'?name='+name,token=token,binary=cipher)
    return a['browser_download_url']
while True:
    try:
        status=request(LOCAL+'/api/status');f=json.loads(STATE.read_text()) if STATE.exists() else None
        if not f:
            r=cloud({'action':'claim','ready':status['ready'] and not status['busy'],'estimate':estimate()});f=r.get('job')
            if f:save(f)
        if f:
            if not f.get('local_id'):
                seed=int(hashlib.sha256(f['id'].encode()).hexdigest()[:12],16)
                jobs=request(LOCAL+'/api/jobs');match=next((j for j in jobs if j['request'].get('seed')==seed and j['request'].get('style')==f['request']['style']),None)
                if not match and status['ready'] and not status['busy']:match=request(LOCAL+'/api/jobs',build_local_request(f,seed))
                if match:f['local_id']=match['id'];save(f)
            if f.get('local_id'):
                j=request(LOCAL+'/api/jobs/'+f['local_id']);state=j['status'];data={'action':'report','jobId':f['id'],'lease':f['lease'],'status':'running','stage':j.get('stage','生成中'),'completed':j.get('completed'),'total':j.get('total')}
                if state=='succeeded':
                    cloud(dict(data,status='publishing',stage='保存作品',completed=None,total=None))
                    save_job_map(f['id'],f['local_id'])
                    data.update(status='succeeded',stage='完成',url=publish(f),completed=1,total=1)
                elif state in ('failed','cancelled','interrupted'):data.update(status='failed',stage='生成未完成，请重新提交',completed=None,total=None)
                cloud(data)
                if data['status'] in ('succeeded','failed'):
                    cleanup_reference(f['id'])
                    STATE.unlink(missing_ok=True)
    except Exception as exc:
        # Do not print request bodies, credentials, lyrics, signed URLs or raw HTTP responses.
        print('Bridge retry:',type(exc).__name__,flush=True)
    time.sleep(30)
