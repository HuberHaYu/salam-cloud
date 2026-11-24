"""Outbound-only Salam playground bridge. Never cancels or reconfigures local YuE2 jobs."""
import base64, fcntl, hashlib, json, os, statistics, time, urllib.request, urllib.error
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ROOT=Path(__file__).resolve().parent
CONFIG=json.loads((ROOT/'config.json').read_text())
LOCAL='http://127.0.0.1:7861'
STATE=ROOT/'flight.json'
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
                if not match and status['ready'] and not status['busy']:match=request(LOCAL+'/api/jobs',dict(f['request'],seed=seed))
                if match:f['local_id']=match['id'];save(f)
            if f.get('local_id'):
                j=request(LOCAL+'/api/jobs/'+f['local_id']);state=j['status'];data={'action':'report','jobId':f['id'],'lease':f['lease'],'status':'running','stage':j.get('stage','生成中'),'completed':j.get('completed'),'total':j.get('total')}
                if state=='succeeded':
                    cloud(dict(data,status='publishing',stage='保存作品',completed=None,total=None))
                    data.update(status='succeeded',stage='完成',url=publish(f),completed=1,total=1)
                elif state in ('failed','cancelled','interrupted'):data.update(status='failed',stage='生成未完成，请重新提交',completed=None,total=None)
                cloud(data)
                if data['status'] in ('succeeded','failed'):STATE.unlink(missing_ok=True)
    except Exception as exc:
        # Do not print request bodies, credentials, lyrics, signed URLs or raw HTTP responses.
        print('Bridge retry:',type(exc).__name__,flush=True)
    time.sleep(30)
