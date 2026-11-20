import { readdir, mkdir, copyFile, writeFile, rm } from 'node:fs/promises';
import { join, extname } from 'node:path';
const output = '.vercel/output';
const destination = join(output, 'functions/protected.func');
await rm(output, { recursive: true, force: true });
await mkdir(join(destination, 'content'), { recursive: true });
const files = [];
const allowed = new Set(['.html', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.svg', '.css', '.js']);
async function collect(directory = '') {
  for (const item of await readdir(directory || '.', { withFileTypes: true })) {
    if (item.name.startsWith('.') || ['server', 'node_modules', 'tests'].includes(item.name)) continue;
    const path = join(directory, item.name);
    if (item.isDirectory()) await collect(path);
    else if (item.isFile() && allowed.has(extname(item.name).toLowerCase())) {
      files.push(path); await mkdir(join(destination, 'content', directory), { recursive: true });
      await copyFile(path, join(destination, 'content', path));
    }
  }
}
await collect();
if (!files.includes('index.html')) throw new Error('Missing homepage');
await copyFile('server/gate.mjs', join(destination, 'index.mjs'));
await writeFile(join(destination, 'manifest.json'), JSON.stringify(files));
await writeFile(join(destination, '.vc-config.json'), JSON.stringify({ runtime: 'nodejs24.x', handler: 'index.mjs', launcherType: 'Nodejs', supportsResponseStreaming: true, maxDuration: 30 }));
await writeFile(join(output, 'config.json'), JSON.stringify({ version: 3, routes: [{ src: '/(.*)', dest: '/protected' }] }));
console.log(`Built password-protected server with ${files.length} private files; no public static files.`);
