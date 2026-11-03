#!/usr/bin/env node
// 从 Cockpit Tools 账号库（只读）生成油猴脚本，把账号列表内嵌进去。
// 用法: node scripts/gen-userscript.mjs [--out 路径]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { listCodexAccounts, COCKPIT_DIR } from './lib/cockpit-store.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };

function die(msg) {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

const embed = args.includes('--embed');
const fixture = args.includes('--fixture');   // 测试用：内嵌一个假账号，不读真实账号库
let accounts = [];
if (fixture) {
  accounts = [
    { id: 'codex_fixture', email: 'demo.user+tag@example.com', password: 'ExamplePass01', mailUrl: '', authMode: 'oauth', plan: 'plus' },
  ];
} else if (embed) {
  try {
    accounts = listCodexAccounts().filter(a => a.authMode === 'oauth' && a.email && !a.email.startsWith('api-key'));
  } catch (e) {
    die(`读取 Cockpit Tools 账号库失败：${e.message}\n  请确认 ${COCKPIT_DIR} 存在且应用至少登录过一次。`);
  }
  if (!accounts.length) {
    die('账号库里没有可用的 OAuth 账号（只有 API Key 账号或都没密码）。先在 Cockpit Tools 里添加一个 Codex 账号。');
  }
}

const payload = accounts.map(a => ({
  email: a.email,
  password: a.password || '',
  codeApi: (a.mailUrl || 'https://2fa.nloop.cc').replace(/\/+$/, '') + '/api/mfa/lookup',
  plan: a.plan || '',
}));

// @connect 按实际取码主机去重生成，不使用通配
const hosts = [...new Set(payload.map(p => {
  try { return new URL(p.codeApi).host; } catch { return null; }
}).filter(Boolean))];
if (!hosts.length) hosts.push('2fa.nloop.cc');   // 没内嵌账号时给默认取码域名
const connectLines = hosts.map(h => `// @connect      ${h}`).join('\n');

const outPath = opt('--out', path.join(ROOT, 'userscript', 'cockpit-codex-fill.user.js'));
const debugBuild = args.includes('--debug');
let template = fs.readFileSync(path.join(ROOT, 'userscript', 'template.user.js'), 'utf8');
if (!debugBuild) {
  if (!template.includes('__DEBUG_HOOK_START__') || !template.includes('__DEBUG_HOOK_END__')) {
    die('模板缺少 __DEBUG_HOOK_START__/__DEBUG_HOOK_END__ 标记，无法剥离调试钩子（拒绝生成含后门的正式产物）');
  }
  // 正式产物里剔除测试调试钩子，避免页面脚本伪造 localStorage 后门
  template = template.replace(/\/\* __DEBUG_HOOK_START__ \*\/[\s\S]*?\/\* __DEBUG_HOOK_END__ \*\//, '// （调试钩子已在正式构建中移除）');
  if (template.includes('__cockpitFill')) die('调试钩子剥离失败：正式产物仍含 __cockpitFill');
}
const out = template
  .replace('__CONNECT_LINES__', connectLines)
  .replace('__ACCOUNTS_JSON__', JSON.stringify(payload, null, 2))
  .replace('__BUILD_TIME__', new Date().toISOString());

// 先写 600 权限临时文件再原子替换，避免出现 644 窗口
const tmp = outPath + '.tmp';
fs.writeFileSync(tmp, out, { mode: 0o600 });
fs.chmodSync(tmp, 0o600);
fs.renameSync(tmp, outPath);
fs.chmodSync(outPath, 0o600);

const noPwd = payload.filter(p => !p.password).map(p => p.email);
console.log(`✓ 已生成 ${outPath}`);
console.log(`  内嵌账号: ${payload.length ? payload.map(p => p.email).join(', ') : '无（默认；用 --embed 可把 Cockpit 账号库内嵌进来）'}`);
console.log(`  @connect: ${hosts.join(', ')}`);
console.log(`  构建: ${debugBuild ? 'DEBUG（含测试钩子，勿分发）' : 'release（无调试钩子）'}`);
if (noPwd.length) console.warn(`  ! 这些账号没存密码，只能代填邮箱/验证码: ${noPwd.join(', ')}`);
