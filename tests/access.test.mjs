import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import handler from '../.vercel/output/functions/protected.func/index.mjs';
process.env.SITE_PASSWORD = 'local-test-password-only';
process.env.SITE_SESSION_SECRET = 'local-test-secret-not-for-production-12345678';
const server = createServer((req, res) => handler(req, res).catch(() => { res.statusCode = 500; res.end(); }));
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const host = `127.0.0.1:${server.address().port}`;
const base = `http://${host}`;
const request = (path, options) => fetch(base + path, { redirect: 'manual', ...options });
const login = password => request('/_access/login', { method: 'POST', headers: { origin: `https://${host}`, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ password }) });
try {
await test('anonymous page, attachments, internal paths and forged cookie never disclose content', async () => {
 for (const path of ['/', '/index.html', '/IMG_8567.JPG', '/' + encodeURIComponent('液冷展会策划案.pdf'), '/protected', '/content/index.html', '/server/gate.mjs', '/.git/config']) {
  const res = await request(path, { headers: { cookie: '__Host-fi_access=9999999999.forged', 'x-middleware-subrequest': 'middleware:middleware:middleware:middleware:middleware' } });
  assert.equal(res.status, 401, path); assert.match(await res.text(), /此网站需要密码/); assert.match(res.headers.get('cache-control'), /no-store/);
 }
});
await test('incorrect password and cross-origin login are rejected', async () => {
 assert.equal((await login('wrong')).status, 401);
 assert.equal((await request('/_access/login', { method: 'POST', body: 'password=x' })).status, 403);
});
let cookie;
await test('correct password creates a signed secure cookie and returns original content', async () => {
 const res = await login(process.env.SITE_PASSWORD); assert.equal(res.status, 303);
 const set = res.headers.get('set-cookie'); assert.match(set, /Secure; HttpOnly; SameSite=Strict/); cookie = set.split(';')[0];
 const page = await request('/', { headers: { cookie } }); assert.equal(page.status, 200);
 assert.equal(await page.text(), readFileSync(new URL('../index.html', import.meta.url), 'utf8'));
 const pdf = await request('/' + encodeURIComponent('液冷展会策划案.pdf'), { headers: { cookie, range: 'bytes=0-9' } });
 assert.equal(pdf.status, 206); assert.match(pdf.headers.get('content-type'), /pdf/); assert.equal((await pdf.arrayBuffer()).byteLength, 10);
 assert.equal((await request('/server/gate.mjs', { headers: { cookie } })).status, 404);
 assert.equal((await request('/%2e%2e%2findex.html', { headers: { cookie } })).status, 400);
});
await test('expired and modified sessions fail; changing password revokes prior sessions', async () => {
 assert.equal((await request('/', { headers: { cookie: cookie + 'x' } })).status, 401);
 const expires = String(Math.floor(Date.now() / 1000) - 1);
 const key = createHmac('sha256', process.env.SITE_SESSION_SECRET).update(process.env.SITE_PASSWORD).digest('base64url');
 const signature = createHmac('sha256', key).update(expires).digest('base64url');
 assert.equal((await request('/', { headers: { cookie: `__Host-fi_access=${expires}.${signature}` } })).status, 401);
 process.env.SITE_PASSWORD = 'changed-test-password';
 assert.equal((await request('/', { headers: { cookie } })).status, 401);
});
await test('missing secret fails closed and build emits no public static directory', async () => {
 delete process.env.SITE_SESSION_SECRET; assert.equal((await request('/')).status, 503);
 assert.equal(existsSync(new URL('../.vercel/output/static', import.meta.url)), false);
});
} finally { server.close(); server.closeAllConnections(); }
