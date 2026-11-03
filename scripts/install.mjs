#!/usr/bin/env node
// 安装助手：把生成的油猴脚本通过本地 HTTP 地址提供出去，让 Tampermonkey 拦截安装。
// 用途：Safari 27.x 把 .user.js 文件拖进窗口会触发 WebKit performDragOperation 崩溃，
//       所以不要拖文件，改用本脚本提供的地址（或复制到剪贴板在 Tampermonkey 面板里粘贴）。
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILE = path.join(ROOT, 'userscript', 'cockpit-codex-fill.user.js');
const args = process.argv.slice(2);
const noOpen = args.includes('--no-open');
const minutes = Number((() => { const i = args.indexOf('--minutes'); return i >= 0 ? args[i + 1] : 15; })());

if (!fs.existsSync(FILE)) { console.error('✗ 还没生成脚本，先跑 node scripts/gen-userscript.mjs'); process.exit(1); }
const body = fs.readFileSync(FILE, 'utf8');

const HOST = '127.0.0.1';
let PORT = Number(process.env.COCKPIT_INSTALL_PORT || 18767);

const html = `<!doctype html><meta charset="utf-8"><title>Cockpit 自动填 · 安装</title>
<style>body{font:14px -apple-system,"PingFang SC";max-width:640px;margin:60px auto;line-height:1.7;color:#222}
code{background:#f2f2f2;padding:1px 5px;border-radius:4px}a.btn{display:inline-block;padding:10px 18px;background:#2f6f5a;color:#fff;
text-decoration:none;border-radius:8px;margin:12px 0}</style>
<h2>Cockpit 自动填 · 安装</h2>
<p><a class="btn" href="/cockpit-codex-fill.user.js">点这里安装脚本</a></p>
<p>Tampermonkey 会弹安装页，点「安装」。若没有弹出，说明扩展没拦截，改用下面第 2 种方式。</p>
<hr>
<p><b>方式 2：</b>脚本内容已经复制到剪贴板 —— 打开 Tampermonkey 面板 →「添加新脚本 / +」→ 全选删除 → ⌘V 粘贴 → ⌘S 保存。</p>
<p><b>方式 3（命令行）：</b><code>node scripts/install.mjs --no-open</code> 只起本地地址并复制到剪贴板。</p>`;

function serve(port, tries = 0) {
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/cockpit-codex-fill.user.js')) {
      res.writeHead(200, {
        'content-type': 'text/plain; charset=utf-8',
        'content-disposition': 'inline; filename="cockpit-codex-fill.user.js"',
        'cache-control': 'no-store',
      });
      res.end(body);
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
  });
  server.on('error', (e) => {
    if (e.code === 'EADDRINUSE' && tries < 10) return serve(port + 1, tries + 1);
    console.error('✗ 本地服务启动失败:', e.message); process.exit(1);
  });
  server.listen(port, HOST, () => {
    const url = `http://${HOST}:${port}/cockpit-codex-fill.user.js`;
    // 顺手把脚本放进剪贴板，作为粘贴安装的后备
    try {
      const p = spawn('/usr/bin/pbcopy', [], { stdio: ['pipe', 'ignore', 'ignore'] });
      p.stdin.end(body);
    } catch {}
    console.log(`✓ 安装地址: ${url}`);
    console.log(`  页面:     http://${HOST}:${port}/`);
    console.log(`  脚本内容已复制到剪贴板（备用：Tampermonkey 面板里粘贴）`);
    if (!noOpen) {
      execFile('/usr/bin/open', ['-a', 'Safari', `http://${HOST}:${port}/`], (err) => {
        if (err) console.log(`  （自动打开 Safari 失败：${err.message}，请手动打开上面的地址）`);
        else console.log('  已在 Safari 打开安装页');
      });
    }
    console.log(`  服务 ${minutes} 分钟后自动退出（现在可以安装）`);
    setTimeout(() => { console.log('本地服务已退出'); server.close(); process.exit(0); }, minutes * 60000);
  });
}
serve(PORT);
