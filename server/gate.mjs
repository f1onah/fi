import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFileSync, createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { dirname, join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), 'content');
const files = new Set(JSON.parse(readFileSync(new URL('./manifest.json', import.meta.url))));
const cookieName = '__Host-fi_access';
const ttl = 7 * 24 * 60 * 60;
const digest = value => createHash('sha256').update(value).digest();
const equal = (a, b) => timingSafeEqual(digest(a), digest(b));
const sign = (value, secret) => createHmac('sha256', secret).update(value).digest('base64url');
const html = message => `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>访问验证</title><style>*{box-sizing:border-box}body{margin:0;min-height:100dvh;display:grid;place-items:center;background:#f2f4f7;color:#18212e;font:16px/1.6 system-ui,sans-serif;padding:24px}main{width:100%;max-width:400px;padding:36px;background:white;border:1px solid #e1e5ec;border-radius:20px;box-shadow:0 12px 40px #17202f0a}h1{font-size:26px;margin:0 0 8px}p{color:#596477;margin:0 0 24px}label{display:block;margin-bottom:8px}input,button{font:inherit;width:100%;padding:12px;border-radius:9px}input{border:1px solid #aab4c2}input:focus{outline:3px solid #cedaf3;border-color:#345da7}button{margin-top:18px;border:0;background:#233c68;color:white;cursor:pointer}.error{color:#a32432;margin:16px 0 0;font-size:14px}</style><main><h1>此网站需要密码</h1><p>请输入访问密码，查看网站内容。</p><form action="/_access/login" method="post"><label for="password">访问密码</label><input id="password" name="password" type="password" autocomplete="current-password" required maxlength="256" autofocus><button type="submit">进入网站</button>${message ? `<p class="error" role="alert">${message}</p>` : ''}</form></main></html>`;
function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.statusCode = status; res.setHeader('Content-Type', type); res.end(body);
}
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('CDN-Cache-Control', 'no-store');
  res.setHeader('Vercel-CDN-Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
  res.setHeader('Referrer-Policy', 'no-referrer');
  const password = process.env.SITE_PASSWORD;
  const secret = process.env.SITE_SESSION_SECRET;
  if (!password || !secret || secret.length < 32) return send(res, 503, '访问验证暂不可用，请稍后重试。');
  let path;
  try { path = decodeURIComponent(new URL(req.url, 'https://local.invalid').pathname); }
  catch { return send(res, 400, 'Bad request'); }
  if (path.includes('\\') || path.includes('\0') || path.split('/').includes('..')) return send(res, 400, 'Bad request');
  const sessionKey = sign(password, secret);
  if (path === '/_access/login' && req.method === 'POST') {
    const origin = req.headers.origin;
    if (!origin || origin !== `https://${req.headers.host}`) return send(res, 403, 'Forbidden');
    if (!String(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) return send(res, 415, 'Unsupported media type');
    let body = ''; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 2048) return send(res, 413, 'Request too large'); body += chunk; }
    const entered = new URLSearchParams(body).get('password') || '';
    if (!equal(entered, password)) return send(res, 401, html('密码不正确，请重试。'), 'text/html; charset=utf-8');
    const expires = String(Math.floor(Date.now() / 1000) + ttl);
    res.setHeader('Set-Cookie', `${cookieName}=${expires}.${sign(expires, sessionKey)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${ttl}`);
    res.setHeader('Location', '/'); return send(res, 303, '');
  }
  if (!['GET', 'HEAD'].includes(req.method)) { res.setHeader('Allow', 'GET, HEAD'); return send(res, 405, 'Method not allowed'); }
  const cookie = String(req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(cookieName + '='))?.slice(cookieName.length + 1) || '';
  const [expiry, signature, extra] = cookie.split('.');
  const now = Math.floor(Date.now() / 1000);
  const valid = !extra && /^\d{10}$/.test(expiry || '') && Number(expiry) > now && Number(expiry) <= now + ttl && equal(signature || '', sign(expiry, sessionKey));
  if (!valid) {
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    return send(res, 401, req.method === 'HEAD' ? '' : html(''), 'text/html; charset=utf-8');
  }
  const file = path === '/' ? 'index.html' : path.slice(1);
  if (!files.has(file)) return send(res, 404, 'Not found');
  const location = join(root, file);
  const info = await stat(location);
  const types = { '.html': 'text/html; charset=utf-8', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp', '.pdf': 'application/pdf', '.svg': 'image/svg+xml', '.css': 'text/css', '.js': 'text/javascript' };
  res.setHeader('Content-Type', types[extname(file).toLowerCase()] || 'application/octet-stream');
  res.setHeader('Accept-Ranges', 'bytes');
  let start = 0, end = info.size - 1;
  if (req.headers.range) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range);
    if (!match || (!match[1] && !match[2])) { res.setHeader('Content-Range', `bytes */${info.size}`); return send(res, 416, 'Invalid range'); }
    if (!match[1]) start = Math.max(0, info.size - Number(match[2]));
    else { start = Number(match[1]); if (match[2]) end = Math.min(end, Number(match[2])); }
    if (start > end || start >= info.size) { res.setHeader('Content-Range', `bytes */${info.size}`); return send(res, 416, 'Invalid range'); }
    res.statusCode = 206; res.setHeader('Content-Range', `bytes ${start}-${end}/${info.size}`);
  }
  res.setHeader('Content-Length', end - start + 1);
  if (req.method === 'HEAD') return res.end();
  await pipeline(createReadStream(location, { start, end }), res);
}
