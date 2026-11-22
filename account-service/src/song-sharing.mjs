import {ID, SECRET, digest} from './core.mjs';

export const SHARE_TTL = 10 * 60 * 1000;
const REQUEST = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const result = (status, data) => ({status, data});
const unavailable = () => result(404, {error: '分享码不存在或已过期，请向对方获取新分享码'});

/** Whitelist song identity only. Never relay a file URI, playback URL, headers or credentials. */
export function shareTrack(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid track');
  const text = (key, max, required = false) => {
    const value = input[key] ?? '';
    if (typeof value !== 'string' || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new Error('Invalid field');
    const clean = value.trim();
    if (required && !clean) throw new Error('Missing field');
    return clean;
  };
  const track = {name: text('name', 256, true), singer: text('singer', 512), album: text('album', 256),
    platform: text('platform', 32), songId: text('songId', 160), hash: text('hash', 160), albumId: text('albumId', 160)};
  if (track.platform) {
    if (!/^[a-z][a-z0-9_-]{0,31}$/.test(track.platform) || !(track.songId || track.hash)) throw new Error('Invalid identity');
    for (const key of ['songId', 'hash', 'albumId']) if (track[key] && !/^[a-zA-Z0-9._:-]+$/.test(track[key])) throw new Error('Invalid identity');
  } else {
    if (!track.singer) throw new Error('Missing artist');
    track.songId = track.hash = track.albumId = '';
  }
  track.durationMs = Number.isSafeInteger(input.durationMs) && input.durationMs >= 0 && input.durationMs <= 86400000 ? input.durationMs : 0;
  track.access = [0, 1, 2].includes(input.access) ? input.access : 0;
  return track;
}

export function randomShareCode() {
  // Rejection sampling keeps every six-digit code equally likely, including leading zeroes.
  const buffer = new Uint32Array(1), limit = Math.floor(0x100000000 / 1000000) * 1000000;
  do { crypto.getRandomValues(buffer); } while (buffer[0] >= limit);
  return String(buffer[0] % 1000000).padStart(6, '0');
}

/** Creation locks only its sender. Receiving uses atomic counters and indexed reads. */
export class SongSharing {
  constructor(storage, env, {now = Date.now, randomCode = randomShareCode} = {}) {
    this.storage = storage; this.env = env; this.now = now; this.randomCode = randomCode;
  }
  async limit(name, max, window) {
    const key = 'share/limit/' + name, now = this.now();
    if (this.storage.shareLimit) return this.storage.shareLimit(key, max, window, now);
    const old = await this.storage.get(key);
    const entry = !old || old.until <= now ? {count: 0, until: now + window} : old;
    if (entry.count >= max) return false;
    entry.count++; await this.storage.put(key, entry); return true;
  }
  async owner(id) {
    if (await this.storage.get('deleted/' + id)) return null;
    const account = await this.storage.get('account/' + id);
    return account && !account.closedAt && !account.deletingAt && !account.deletedAt ? account : null;
  }
  async handle(path, body, request) {
    if (path === '/v1/share/create') return this.create(body, request);
    if (path === '/v1/share/receive') return this.receive(body, request);
    return result(404, {error: '接口不存在'});
  }
  async create(body, request) {
    const token = (request.headers.get('Authorization') || '').replace(/^Bearer /, '');
    if (!ID.test(body.id || '') || !SECRET.test(token)) return result(401, {error: '请先登录 Salam ID'});
    const account = await this.owner(body.id), sessionKey = await digest(this.env.AUTH_PEPPER, 'session:' + token);
    if (!account?.sessions?.[sessionKey] || account.sessions[sessionKey].expires <= this.now()) return result(401, {error: '请重新登录 Salam ID'});
    if (!REQUEST.test(body.requestId || '')) return result(400, {error: '请重新打开分享窗口'});
    let track;
    try { track = shareTrack(body.track); } catch { return result(400, {error: '歌曲信息不完整，暂时无法分享'}); }
    const requestKey = 'share/request/' + account.id + '/' + body.requestId;
    const previous = await this.storage.get(requestKey), now = this.now();
    if (previous && previous.until > now) {
      const saved = await this.storage.get('share/code/' + previous.code);
      if (saved?.owner === account.id && saved.until > now) {
        if (JSON.stringify(saved.track) !== JSON.stringify(track)) return result(409, {error: '歌曲已变化，请重新打开分享窗口'});
        return result(200, {code: previous.code, expiresAt: saved.until, serverTime: now});
      }
    }
    if (!await this.limit('create/' + account.id, 12, 60000)
        || !await this.limit('daily/' + account.id, 300, 86400000)) return result(429, {error: '分享较频繁，请稍后再试'});
    for (let attempt = 0; attempt < 32; attempt++) {
      const code = this.randomCode(), key = 'share/code/' + code;
      const until = now + SHARE_TTL;
      const value = {owner: account.id, authVersion: account.authVersion, track, until};
      if (this.storage.reserveShare) {
        if (!await this.storage.reserveShare(key, value, now)) continue;
      } else {
        const old = await this.storage.get(key); if (old && old.until > now) continue;
        await this.storage.put(key, value);
      }
      await this.storage.put(requestKey, {code, until});
      return result(200, {code, expiresAt: until, serverTime: now});
    }
    return result(503, {error: '分享较多，请稍后再试'});
  }
  async receive(body, request) {
    const ip = await digest(this.env.AUTH_PEPPER, 'share-ip:' + (request.headers.get('CF-Connecting-IP') || 'unknown'));
    if (!await this.limit('receive/' + ip, 60, 60000)
        || !await this.limit('receive-total', 4000, 60000)) return result(429, {error: '接收较频繁，请稍后再试'});
    const failedKey = 'share/limit/miss/' + ip, failed = await this.storage.get(failedKey), now = this.now();
    if (failed?.until > now && failed.count >= 6) return result(429, {error: '分享码输错次数较多，请一分钟后再试'});
    const saved = typeof body.code === 'string' && /^\d{6}$/.test(body.code) ? await this.storage.get('share/code/' + body.code) : null;
    const account = saved && saved.until > now ? await this.owner(saved.owner) : null;
    if (!account || account.authVersion !== saved.authVersion) {
      await this.limit('miss/' + ip, 6, 60000); return unavailable();
    }
    // Only the sanitized song identity crosses the account boundary. Codes may be used by
    // several friends during the same ten minutes; fetching never changes anyone's library.
    return result(200, {track: saved.track, expiresAt: saved.until, serverTime: now});
  }
}
