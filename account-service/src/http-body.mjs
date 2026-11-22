const MAX_BODY=1000000;
export class BodyError extends Error {
  constructor(status,message){super(message);this.status=status;}
}
async function readBytes(stream,limit){
  if(!stream)throw new BodyError(400,'请求为空');
  const reader=stream.getReader(),chunks=[];let size=0;
  try{
    for(;;){const {value,done}=await reader.read();if(done)break;
      size+=value.length;
      if(size>limit){value.fill(0);await reader.cancel();throw new BodyError(413,'同步数据过大');}
      chunks.push(value);
    }
    const bytes=new Uint8Array(size);let offset=0;
    for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.length;}
    return bytes;
  }finally{for(const chunk of chunks)chunk.fill(0);reader.releaseLock();}
}
export async function readJsonBody(request){
  if(Number(request.headers.get('content-length')||0)>MAX_BODY)throw new BodyError(413,'同步数据过大');
  const encoding=(request.headers.get('content-encoding')||'identity').toLowerCase().trim();
  if(!['identity','gzip'].includes(encoding))throw new BodyError(415,'请求压缩格式不支持');
  const wire=await readBytes(request.body,MAX_BODY);let plain=wire;
  try{
    if(encoding==='gzip'){
      try{plain=await readBytes(new Blob([wire]).stream().pipeThrough(new DecompressionStream('gzip')),MAX_BODY);}
      catch(error){if(error instanceof BodyError)throw error;throw new BodyError(400,'请求压缩内容不完整');}
    }
    let body;try{body=JSON.parse(new TextDecoder().decode(plain));}catch{throw new BodyError(400,'请求格式不正确');}
    if(!body||typeof body!=='object'||Array.isArray(body))throw new BodyError(400,'请求格式不正确');
    return body;
  }finally{wire.fill(0);if(plain!==wire)plain.fill(0);}
}
export async function compressSyncResponse(request,response){
  const accepted=(request.headers.get('accept-encoding')||'').split(',').some(value=>{
    const [name,...parameters]=value.trim().toLowerCase().split(';');
    return name==='gzip'&&!parameters.some(p=>/^\s*q\s*=\s*0(?:\.0*)?\s*$/.test(p));
  });
  if(response.status!==200||!accepted||!new URL(request.url).pathname.endsWith('/v1/sync'))return response;
  const bytes=new Uint8Array(await response.arrayBuffer());
  if(bytes.length<2048)return new Response(bytes,{status:response.status,headers:response.headers});
  const gzip=new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
  const headers=new Headers(response.headers);headers.set('Vary','Accept-Encoding');
  if(gzip.length>=bytes.length)return new Response(bytes,{status:response.status,headers});
  headers.set('Content-Encoding','gzip');headers.set('Content-Length',String(gzip.length));
  bytes.fill(0);return new Response(gzip,{status:response.status,headers});
}
