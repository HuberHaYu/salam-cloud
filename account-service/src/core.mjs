const enc = new TextEncoder();
export const ID = /^SL-[A-F0-9]{32}$/;
export const SECRET = /^[A-Za-z0-9_-]{43}$/;
export const MAX_RECORDS = 6000;
export const MAX_BYTES = 750000;
export function b64(bytes) { return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); }
export function unb64(s) { return Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)); }
export function randomSecret() { return b64(crypto.getRandomValues(new Uint8Array(32))); }
export async function digest(secret, text) {
  const key = await crypto.subtle.importKey('raw', unb64(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  return b64(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(text))));
}
export function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0; for (let i=0;i<a.length;i++) diff |= a.charCodeAt(i)^b.charCodeAt(i);
  return diff === 0;
}
export function nickname(value) {
  if (typeof value !== 'string') throw new Error('请输入昵称');
  const n = value.trim();
  if (!n || [...n].length > 30 || /[\x00-\x1f\x7f]/.test(n)) throw new Error('昵称需为 1～30 个字符');
  return n;
}
export function validRecord(key, value) {
  if (!/^[fcpt]:.{1,240}$/.test(key) || key.includes('\n')) throw new Error('数据标识无效');
  if (value === null) return;
  if (!value || typeof value !== 'object' || Array.isArray(value) || JSON.stringify(value).length > 20000) throw new Error('数据内容无效');
  if (key.startsWith('f:') || key.startsWith('t:')) {
    if (typeof value.uri !== 'string' || !value.uri.startsWith('salam-online://') || value.uri.length > 16000) throw new Error('仅支持在线音乐数据');
    if (!Number.isSafeInteger(value.rank) || value.rank < 0) throw new Error('排序无效');
    if (key.startsWith('t:') && !/^[a-zA-Z0-9-]{1,80}$/.test(value.playlist || '')) throw new Error('歌单标识无效');
  } else if (key.startsWith('p:')) {
    if (typeof value.name !== 'string' || value.name.length > 80 || !value.name.trim()) throw new Error('歌单名称无效');
  } else {
    if (![0,1,2].includes(value.kind) || typeof value.id !== 'string' || value.id.length > 128 || typeof value.platform !== 'string') throw new Error('收藏内容无效');
  }
}
/** Per-record optimistic concurrency. Duplicate device sequences never replay a delete/add. */
export function merge(account, body) {
  if (!/^[a-f0-9-]{36}$/.test(body.device || '') || !Number.isSafeInteger(body.seq) || body.seq < 1 || !Array.isArray(body.ops) || body.ops.length > 500) throw new Error('同步请求无效');
  const previous = account.devices[body.device] || 0;
  if (body.seq <= previous) return {account, conflicts: [], duplicate: true};
  if (body.seq !== previous + 1) throw new Error('设备同步序号不连续');
  if (!previous && Object.keys(account.devices).length >= 32) throw new Error('账号设备数量已达上限');
  const next = structuredClone(account), conflicts = [];
  const unique = new Set();
  for (const op of body.ops) {
    validRecord(op.key, op.value);
    if (unique.has(op.key) || !Number.isSafeInteger(op.base) || op.base < 0 || op.base > account.rev) throw new Error('同步版本无效');
    unique.add(op.key);
    const current = next.records[op.key];
    if (current && current.rev > op.base) { conflicts.push(op.key); continue; }
    if (JSON.stringify(current?.value ?? null) === JSON.stringify(op.value)) continue;
    next.records[op.key] = {value: op.value, rev: ++next.rev};
  }
  next.devices[body.device] = body.seq;
  next.generation++;
  if (Object.keys(next.records).length > MAX_RECORDS || enc.encode(JSON.stringify(next)).length > MAX_BYTES) throw new Error('账号音乐数据已达到当前容量上限');
  return {account:next, conflicts, duplicate:false};
}
/** Random nonce + account-bound AAD; public repository contains ciphertext only. */
export async function seal(keyText, id, data) {
  const key = await crypto.subtle.importKey('raw', unb64(keyText), 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const bytes = enc.encode(JSON.stringify(data));
  const compressed = new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
  const cipher = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:enc.encode('salam-id-v1:'+id)}, key, compressed));
  // Chunk conversion avoids argument-stack overflow on large accounts.
  let raw=''; for(let i=0;i<cipher.length;i+=8192) raw+=String.fromCharCode(...cipher.subarray(i,i+8192));
  return {format:1, iv:b64(iv), data:btoa(raw)};
}
export async function unseal(keyText, id, envelope) {
  if (envelope.format !== 1) throw new Error('归档格式不支持');
  const key = await crypto.subtle.importKey('raw', unb64(keyText), 'AES-GCM', false, ['decrypt']);
  const compressed = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(envelope.iv), additionalData:enc.encode('salam-id-v1:'+id)}, key, unb64(envelope.data));
  const raw = await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  if (raw.length > MAX_BYTES * 2) throw new Error('归档过大');
  const data = JSON.parse(raw);
  if (data.id !== id) throw new Error('归档账号不匹配');
  return data;
}
