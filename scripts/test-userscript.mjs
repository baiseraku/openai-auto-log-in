// 假登录页 + Playwright 验证油猴脚本：
// 菜单开面板 / 账号识别 / 正路径 / 确认取消 / 自动填不重复 / SPA 换步不重复 / 冷却期手动点击 / 取码失败不刷接口 / 不提交表单
import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEBUG_BUILD = path.join(ROOT, '.cache', 'test', 'debug.user.js');

// 每次测试都重新构建 debug 版（DEBUG 钩子只在 debug 构建里）
fs.mkdirSync(path.dirname(DEBUG_BUILD), { recursive: true });
const gen = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'gen-userscript.mjs'), '--debug', '--fixture', '--out', DEBUG_BUILD], { encoding: 'utf8' });
if (gen.status !== 0) { console.error(gen.stderr || gen.stdout); process.exit(1); }
const DEBUG_EMPTY = path.join(ROOT, '.cache', 'test', 'debug-empty.user.js');
const genEmpty = spawnSync(process.execPath, [path.join(ROOT, 'scripts', 'gen-userscript.mjs'), '--debug', '--out', DEBUG_EMPTY], { encoding: 'utf8' });
if (genEmpty.status !== 0) { console.error(genEmpty.stderr || genEmpty.stdout); process.exit(1); }
const USERSCRIPT = fs.readFileSync(DEBUG_BUILD, 'utf8');
const USERSCRIPT_EMPTY = fs.readFileSync(DEBUG_EMPTY, 'utf8');
const RELEASE = fs.readFileSync(path.join(ROOT, 'userscript', 'cockpit-codex-fill.user.js'), 'utf8');

const form = (inner, prefill = '') => `<!doctype html><html><head><meta charset="utf-8"></head><body>
<h1>login</h1><form>${inner}</form>
<script>
  ${prefill}
  window.__submitCount = 0;
  document.querySelector('form').addEventListener('submit', (e) => { e.preventDefault(); window.__submitCount++; });
</script></body></html>`;

const pages = {
  '/log-in': form(`<input type="email" name="email" placeholder="Email address"><button type="submit">Continue</button>`),
  '/blank': `<!doctype html><html><head><meta charset="utf-8"></head><body><p>没有登录表单</p></body></html>`,
  '/log-in/password': form(`<input type="password" name="password"><button type="submit">Continue</button>`),
  '/mfa': form(`<input autocomplete="one-time-code" inputmode="numeric" name="code" maxlength="6"><button type="submit">Continue</button>`),
  '/mfa-seg': form(`${'<input maxlength="1" inputmode="numeric">'.repeat(6)}<button type="submit">Continue</button>`),
};

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(pages[req.url] || pages['/log-in']);
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch({
  executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  headless: true,
});

const results = [];
const check = (name, pass, detail = '') => results.push({ name, result: pass ? 'OK' : 'FAIL', detail });

const GOOD = 'demo.user+tag@example.com';
const TFA_SECRET = 'JBSWY3DPEHPK3PXP';

/** Node 侧独立实现 TOTP，用来核对脚本里的本地算法 */
function nodeTotp(secret, period = 30, digits = 6) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = secret.toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = chars.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  const counter = Math.floor(Date.now() / 1000 / period);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 4294967296), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const sig = crypto.createHmac('sha1', Buffer.from(out)).update(buf).digest();
  const off = sig[sig.length - 1] & 0x0f;
  const bin = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}
let failMode = false;
let gmCalls = 0;

async function newPage({ path: pagePath = '/log-in', dialogBehavior = 'accept', preset = null, script = USERSCRIPT } = {}) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  let dialogs = 0;
  const dialogMessages = [];
  page.on('dialog', async (d) => {
    dialogs++;
    dialogMessages.push(d.message());
    if (dialogBehavior === 'dismiss' && dialogs === 1) await d.dismiss();
    else await d.accept();
  });
  page.dialogs = () => dialogs;
  page.dialogMessages = () => dialogMessages;

  await page.exposeFunction('__gmFetch', async (url, body) => {
    gmCalls++;
    if (failMode) throw new Error('simulated network failure');
    // 取码接口用固定响应，测试不依赖外网、可复现
    if (String(url).includes('/api/mfa/lookup')) {
      return JSON.stringify({
        ok: true,
        email: JSON.parse(body || '{}').email,
        found: true,
        results: [{ service: 'ChatGPT', code: '123456', remaining: 25, period: 30 }],
      });
    }
    const r = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
    return await r.text();
  });

  await page.addInitScript((presetArg) => {
    try {
      localStorage.setItem('cockpit_fill_debug', '1');
      if (presetArg) {
        if (presetArg.account) localStorage.setItem('cockpit_fill_account', presetArg.account);
        if (presetArg.auto) localStorage.setItem('cockpit_fill_auto', '1');
      }
    } catch {}
    window.__menuCommands = {};
    window.GM_registerMenuCommand = (name, cb) => { window.__menuCommands[name] = cb; };
    window.GM_getValue = (k, d) => {
      try {
        const v = localStorage.getItem('GM_' + k);
        return v === null ? d : v;
      } catch { return d; }
    };
    window.GM_setValue = (k, v) => {
      try { localStorage.setItem('GM_' + k, String(v)); } catch {}
    };
    window.GM_xmlhttpRequest = (opts) => {
      window.__gmFetch(opts.url, opts.data)
        .then((text) => opts.onload && opts.onload({ status: 200, responseText: text }))
        .catch(() => opts.onerror && opts.onerror(new Error('fail')));
    };
  }, preset);

  await page.goto(base + pagePath, { waitUntil: 'domcontentloaded' });
  await page.addScriptTag({ content: script });
  await page.waitForFunction(() => !!window.__cockpitFill, null, { timeout: 5000 });
  return page;
}

const openPanelViaMenu = (page) => page.evaluate(() => {
  const names = Object.keys(window.__menuCommands || {});
  if (!names.length) throw new Error('没有注册菜单命令');
  window.__menuCommands[names[0]]();
});
const val = (page, sel) => page.$eval(sel, el => el.value).catch(() => null);
const submits = (page) => page.evaluate(() => window.__submitCount).catch(() => 0);
const panelVisible = (page) => page.evaluate(() => {
  const h = document.getElementById('cockpit-fill-host');
  return !!h && h.style.display !== 'none';
});

// ---------- 1. 面板默认隐藏，点菜单命令才出现 ----------
{
  const page = await newPage({ preset: { account: GOOD, auto: true } });
  check('面板默认隐藏', (await panelVisible(page)) === false);
  await page.waitForTimeout(1500);
  check('面板隐藏时自动填不生效', (await val(page, 'input[name=email]')) === '' && page.dialogs() === 0);
  check('已注册菜单命令（图标入口）', await page.evaluate(() => Object.keys(window.__menuCommands).length > 0));
  await openPanelViaMenu(page);
  check('点菜单后面板出现', (await panelVisible(page)) === true);
  await openPanelViaMenu(page);
  check('再点菜单面板收起', (await panelVisible(page)) === false);
  await page.context().close();
}

// ---------- 2. 粘贴文本识别账号 ----------
{
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('brand.new@example.com----Pa55w0rd!'));
  const who = await page.evaluate(() => window.__cockpitFill.who());
  check('粘贴识别：email----password', /已识别/.test(who) && who.includes('brand.new@example.com') && /密码/.test(who), who);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(800);
  check('粘贴识别：邮箱填对', (await val(page, 'input[name=email]')) === 'brand.new@example.com');
  const msgs = page.dialogMessages();
  check('确认框带掩码密码便于核对', msgs.some(m => m.includes('密码：') && m.includes('*')), msgs.join(' | ').slice(0, 80));
  await page.context().close();
}
{
  // 密码在前：Pass1234----a@b.com（上一版会把整串当邮箱）
  const page = await newPage({ path: '/log-in/password' });
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('Pass1234----brand.new@example.com'));
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(900);
  check('粘贴识别：密码在前格式', (await val(page, 'input[name=password]')) === 'Pass1234');
  await page.context().close();
}
{
  // 多个邮箱：选「旁边有合法密码」的那个
  const page = await newPage({ path: '/log-in/password' });
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('support@example.com 账号 brand.new@example.com----Pa55w0rd!'));
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(900);
  check('粘贴识别：多邮箱取有密码的那个', (await val(page, 'input[name=password]')) === 'Pa55w0rd!');
  await page.context().close();
}
{
  // 标签在邮箱后面：password:/pass:/pwd:（冒号后带空格）
  const cases = [
    ['brand.new@example.com password: Pa55w0rd', 'Pa55w0rd'],
    ['brand.new@example.com pwd: Pa55w0rd', 'Pa55w0rd'],
    ['brand.new@example.com pass: Pa55w0rd', 'Pa55w0rd'],
    ['brand.new@example.com pass:Pa55w0rd', 'Pa55w0rd'],
    ['brand.new@example.com passwd: Pa55w0rd', 'Pa55w0rd'],
    ['email: brand.new@example.com\npassword: Pa55w0rd', 'Pa55w0rd'],
    ['P@ss----brand.new@example.com', 'P@ss'],
    ['brand.new@example.com----Pass1234----', 'Pass1234'],
    ['brand.new@example.com----Pass:123', 'Pass:123'],
  ];
  for (const [text, want] of cases) {
    const page = await newPage({ path: '/log-in/password' });
    await openPanelViaMenu(page);
    await page.evaluate((t) => window.__cockpitFill.setPaste(t), text);
    await page.evaluate(() => window.__cockpitFill.fill());
    await page.waitForTimeout(900);
    const got = await val(page, 'input[name=password]');
    check(`粘贴识别：${text.replace(/\n/g, '⏎').slice(0, 42)}`, got === want, `得到 ${got}`);
    await page.context().close();
  }
}
{
  // 双密码文本：不能出现带 ---- 的脏值
  const page = await newPage({ path: '/log-in/password' });
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('Pass1234----brand.new@example.com----RealPwd'));
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(900);
  const got = await val(page, 'input[name=password]');
  check('粘贴识别：双密码文本不出脏值', (got === 'Pass1234' || got === 'RealPwd'), `得到 ${got}`);
  await page.context().close();
}
{
  // 干扰文本不能被当密码
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('brand.new@example.com 请勿修改密码'));
  const who = await page.evaluate(() => window.__cockpitFill.who());
  check('粘贴识别：中文干扰文本不当密码', /无密码/.test(who), who);
  await page.evaluate(() => window.__cockpitFill.setPaste('brand.new@example.com----'));
  const who2 = await page.evaluate(() => window.__cockpitFill.who());
  check('粘贴识别：空密码不取分隔符', /无密码/.test(who2), who2);
  await page.context().close();
}
{
  const page = await newPage({ path: '/log-in/password' });
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('账号：brand.new@example.com 密码：Pa55w0rd!'));
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(800);
  check('粘贴识别：中文标签格式', (await val(page, 'input[name=password]')) === 'Pa55w0rd!');
  await page.context().close();
}
{
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('brand.new@example.com'));
  const who = await page.evaluate(() => window.__cockpitFill.who());
  check('粘贴识别：只有邮箱不报有密码', /已识别/.test(who) && /无密码/.test(who), who);
  await page.context().close();
}
{
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('这里没有任何账号信息'));
  const who = await page.evaluate(() => window.__cockpitFill.who());
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(500);
  check('粘贴识别：无邮箱时不误填', /没识别到邮箱/.test(who) && (await val(page, 'input[name=email]')) === '', who);
  await page.context().close();
}
{
  // 同邮箱合并：粘贴库内已存在的邮箱 + 新密码 → 不新建条目，覆盖库内密码
  const page = await newPage({ path: '/log-in/password' });
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.setPaste(`Pa55New1----${e}`), GOOD);
  const who = await page.evaluate(() => window.__cockpitFill.who());
  const selected = await page.evaluate(() => window.__cockpitFill.selected());
  check('同邮箱合并：下拉选中库内账号（不重复）', selected === GOOD, selected);
  check('同邮箱合并：提示已合并并覆盖', /已合并/.test(who) && /覆盖/.test(who), who);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(900);
  check('同邮箱合并：用粘贴的新密码填入', (await val(page, 'input[name=password]')) === 'Pa55New1');
  await page.context().close();
}
{
  // 保存到插件 + 管理区列出 + 删除 + 刷新后仍生效
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('save.me@example.com----SavePwd9'));
  await page.evaluate(() => window.__cockpitFill.save());
  await page.waitForTimeout(400);
  check('保存账号：进入已保存列表', (await page.evaluate(() => window.__cockpitFill.saved())).includes('save.me@example.com'));
  check('保存账号：下拉里出现该账号', (await page.evaluate(() => window.__cockpitFill.accounts())).includes('save.me@example.com'));
  await page.evaluate(() => window.__cockpitFill.mergeOpen());
  await page.waitForTimeout(200);
  check('管理区列出已保存账号', (await page.evaluate(() => window.__cockpitFill.mergeItems())).some(t => t.includes('save.me@example.com')));

  // 刷新页面后应仍在（GM 存储持久）
  await page.goto(base + '/log-in', { waitUntil: 'domcontentloaded' });
  await page.addScriptTag({ content: USERSCRIPT });
  await page.waitForFunction(() => !!window.__cockpitFill, null, { timeout: 5000 });
  check('保存账号：刷新后仍在', (await page.evaluate(() => window.__cockpitFill.saved())).includes('save.me@example.com'));

  // 删除后消失，刷新也不再回来
  await page.evaluate(() => window.__cockpitFill.removeSaved('save.me@example.com'));
  await page.waitForTimeout(300);
  check('删除账号：列表里移除', !(await page.evaluate(() => window.__cockpitFill.saved())).includes('save.me@example.com'));
  await page.goto(base + '/log-in', { waitUntil: 'domcontentloaded' });
  await page.addScriptTag({ content: USERSCRIPT });
  await page.waitForFunction(() => !!window.__cockpitFill, null, { timeout: 5000 });
  check('删除账号：刷新后不会回来', !(await page.evaluate(() => window.__cockpitFill.saved())).includes('save.me@example.com'));
  await page.context().close();
}
{
  // 保存覆盖库内账号的密码，且删除后回退库内密码
  const page = await newPage({ path: '/log-in/password' });
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.setPaste(`NewPwd777----${e}`), GOOD);
  await page.evaluate(() => window.__cockpitFill.save());
  await page.waitForTimeout(300);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(900);
  check('保存覆盖：填的是新密码', (await val(page, 'input[name=password]')) === 'NewPwd777');
  await page.evaluate((e) => window.__cockpitFill.removeSaved(e), GOOD);
  await page.waitForTimeout(300);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(900);
  const back = await val(page, 'input[name=password]');
  check('删除覆盖：回退库内密码', !!back && back !== 'NewPwd777' && back.length >= 8, `密码长度 ${back ? back.length : 0}`);
  await page.context().close();
}
{
  // 删除 / 恢复库内（内嵌）账号
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.mergeOpen());
  await page.waitForTimeout(200);
  const items0 = await page.evaluate(() => window.__cockpitFill.mergeItems());
  check('管理区列出库内账号', items0.some((t) => t.includes(GOOD)), items0.slice(0, 2).join(' | '));

  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate((e) => window.__cockpitFill.hide(e), GOOD);
  await page.waitForTimeout(300);
  check('删除库内账号：从下拉消失', !(await page.evaluate(() => window.__cockpitFill.accounts())).includes(GOOD));
  check('删除库内账号：清空当前选择', (await page.evaluate(() => window.__cockpitFill.selected())) === '');

  await page.goto(base + '/log-in', { waitUntil: 'domcontentloaded' });
  await page.addScriptTag({ content: USERSCRIPT });
  await page.waitForFunction(() => !!window.__cockpitFill, null, { timeout: 5000 });
  check('删除库内账号：刷新后仍隐藏', !(await page.evaluate(() => window.__cockpitFill.accounts())).includes(GOOD));

  await page.evaluate((e) => window.__cockpitFill.restore(e), GOOD);
  await page.waitForTimeout(300);
  check('恢复库内账号：重新出现', (await page.evaluate(() => window.__cockpitFill.accounts())).includes(GOOD));
  await page.context().close();
}
{
  // 右上角不再显示「未识别」
  const page = await newPage({ path: '/blank' });
  await openPanelViaMenu(page);
  check('无输入框页：右上角不显示未识别', (await page.evaluate(() => window.__cockpitFill.badge())) === '');
  await page.goto(base + '/log-in', { waitUntil: 'domcontentloaded' });
  await page.addScriptTag({ content: USERSCRIPT });
  await page.waitForFunction(() => !!window.__cockpitFill, null, { timeout: 5000 });
  await openPanelViaMenu(page);
  check('识别到邮箱页：右上角显示「邮箱」', (await page.evaluate(() => window.__cockpitFill.badge())) === '邮箱');
  await page.context().close();
}
{
  // 粘贴后再从下拉框选库内账号，粘贴状态要清掉
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('brand.new@example.com----Pa55w0rd!'));
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(800);
  check('粘贴后改选账号：以库内账号为准', (await val(page, 'input[name=email]')) === GOOD);
  await page.context().close();
}

// ---------- 3~6 正路径 ----------
{
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(800);
  check('填邮箱', (await val(page, 'input[name=email]')) === GOOD);
  check('填邮箱后未提交表单', (await submits(page)) === 0);
  await page.context().close();
}
{
  const page = await newPage({ path: '/log-in/password' });
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(800);
  check('填密码', ((await val(page, 'input[name=password]')) || '').length >= 6);
  check('填密码后未提交表单', (await submits(page)) === 0);
  await page.context().close();
}
{
  const page = await newPage({ path: '/mfa' });
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(12000); // 取到快过期的码时会自动等下一轮
  check('填验证码（单框）', /^\d{6}$/.test(await val(page, 'input[name=code]') || ''));
  check('填验证码后未提交表单', (await submits(page)) === 0);
  await page.context().close();
}
{
  const page = await newPage({ path: '/mfa-seg' });
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(12000);
  const seg = await page.$$eval('input[maxlength="1"]', els => els.map(e => e.value).join(''));
  check('填验证码（分段）', /^\d{6}$/.test(seg));
  await page.context().close();
}

// ---------- 7. 确认取消：不填、不重复弹 ----------
{
  const page = await newPage({ dialogBehavior: 'dismiss' });
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(2500);
  check('取消后不填值', (await val(page, 'input[name=email]')) === '');
  check('取消后不反复弹窗', page.dialogs() === 1, `弹窗 ${page.dialogs()} 次`);
  await page.context().close();
}

// ---------- 8. 自动填（localStorage 预置，模拟重开登录页） ----------
{
  const page = await newPage({ preset: { account: GOOD, auto: true } });
  await openPanelViaMenu(page);
  await page.waitForTimeout(1800);
  const v1 = await val(page, 'input[name=email]');
  const d1 = page.dialogs();
  await page.waitForTimeout(2600);
  check('自动填：开面板即填', v1 === GOOD);
  check('自动填：只确认一次', d1 === 1, `弹窗 ${d1} 次`);
  check('自动填：不重复触发', (await val(page, 'input[name=email]')) === GOOD && page.dialogs() === 1, `弹窗 ${page.dialogs()} 次`);

  // 换到密码步：已经确认过同一账号，不应再弹确认
  await page.evaluate(() => {
    history.pushState({}, '', '/log-in/password');
    document.querySelector('form').innerHTML = '<input type="password" name="password"><button type="submit">Continue</button>';
  });
  await page.waitForTimeout(2600);
  check('自动填：密码步不再确认', page.dialogs() === 1, `弹窗 ${page.dialogs()} 次`);
  check('自动填：密码步自动填上', ((await val(page, 'input[name=password]')) || '').length >= 6);
  await page.context().close();
}

// ---------- 9. SPA 换步（URL 改变）不重复确认 / 不重复取码 ----------
{
  const page = await newPage({ preset: { account: GOOD, auto: true } });
  await openPanelViaMenu(page);
  await page.waitForTimeout(1500); // 邮箱步自动填完（1 次确认）
  gmCalls = 0;
  await page.evaluate(() => {
    history.pushState({}, '', '/log-in/password');
    document.querySelector('form').innerHTML = '<input type="password" name="password"><button type="submit">Continue</button>';
    const m = new MutationObserver(() => {});
    m.observe(document.body, { childList: true });
  });
  await page.waitForTimeout(2600);
  const dlg = page.dialogs();
  const pwd = await val(page, 'input[name=password]');
  check('SPA 换步不重复确认', dlg === 1, `弹窗 ${dlg} 次`);
  check('SPA 换步填进密码', (pwd || '').length >= 6);
  await page.context().close();
}
{
  // email → 验证码（URL+DOM 同时变），断言只取码一次
  const page = await newPage({ preset: { account: GOOD, auto: true } });
  await openPanelViaMenu(page);
  await page.waitForTimeout(1500);
  gmCalls = 0;
  await page.evaluate(() => {
    history.pushState({}, '', '/mfa');
    document.querySelector('form').innerHTML = '<input autocomplete="one-time-code" inputmode="numeric" name="code" maxlength="6"><button type="submit">Continue</button>';
  });
  await page.waitForTimeout(12000); // 取到快过期的码时脚本会等下一轮
  const codeV = await val(page, 'input[name=code]');
  check('SPA 换到验证码只取码一次', gmCalls >= 1 && gmCalls <= 2, `${gmCalls} 次取码（2 表示过期后重取一次）`);
  check('SPA 换到验证码填对', /^\d{6}$/.test(codeV || ''));
  check('SPA 换到验证码不重复确认', page.dialogs() === 1, `弹窗 ${page.dialogs()} 次`);
  await page.context().close();
}

// ---------- 10. 冷却期内手动点「填入」有反馈且能重试 ----------
{
  failMode = true;
  gmCalls = 0;
  const page = await newPage({ path: '/mfa' });
  await openPanelViaMenu(page);
  await page.evaluate((e) => window.__cockpitFill.select(e), GOOD);
  await page.evaluate(() => window.__cockpitFill.setAuto(true));
  await page.waitForTimeout(2000);
  const failCalls = gmCalls;
  const failStatus = await page.evaluate(() => window.__cockpitFill.status());
  failMode = false;
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(1500);
  const afterStatus = await page.evaluate(() => window.__cockpitFill.status());
  check('取码失败：不刷接口', failCalls <= 2, `${failCalls} 次请求`);
  check('取码失败：有错误提示', /失败|超时|停止/.test(failStatus), failStatus.slice(0, 40));
  check('冷却期内手动点击有反馈/重试', afterStatus !== failStatus, `→ ${afterStatus.slice(0, 40)}`);
  await page.context().close();
}

// ---------- 10.4 2FA（本地 TOTP）与手动编辑 ----------
{
  const page = await newPage();
  await openPanelViaMenu(page);
  const got = await page.evaluate((sec) => window.__cockpitFill.totp(sec), TFA_SECRET);
  const want = nodeTotp(TFA_SECRET);
  check('2FA：本地 TOTP 算法与独立实现一致', got === want, `页面 ${got} / Node ${want}`);
  await page.context().close();
}
{
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate((sec) => window.__cockpitFill.setPaste(`tfa.user@example.com----Pwd123456 2FA: ${sec}`), TFA_SECRET);
  const who = await page.evaluate(() => window.__cockpitFill.who());
  check('2FA：粘贴里能识别出密钥', /2FA 已配置/.test(who), who);
  await page.evaluate(() => window.__cockpitFill.save());
  await page.waitForTimeout(200);
  check('2FA：保存后账号带密钥', (await page.evaluate(() => window.__cockpitFill.twofaOf('tfa.user@example.com'))) === TFA_SECRET);
  await page.context().close();
}
{
  // 有 2FA 的账号在验证码页用本地 TOTP 填码（不走取码接口）
  const page = await newPage({ path: '/mfa' });
  await openPanelViaMenu(page);
  await page.evaluate((sec) => window.__cockpitFill.setPaste(`tfa.user@example.com----Pwd123456 2FA: ${sec}`), TFA_SECRET);
  await page.evaluate(() => window.__cockpitFill.save());
  await page.waitForTimeout(200);
  gmCalls = 0;
  await page.evaluate(() => window.__cockpitFill.fill());
  await page.waitForTimeout(1500);
  const val6 = await val(page, 'input[name=code]');
  const candidates = [nodeTotp(TFA_SECRET)];
  check('2FA：验证码页用本地 TOTP 填对', /^\d{6}$/.test(val6 || '') && candidates.includes(val6), `页面 ${val6} / 期望 ${candidates[0]}`);
  check('2FA：有密钥时不请求取码接口', gmCalls === 0, `${gmCalls} 次请求`);
  await page.context().close();
}
{
  // 手动编辑：账号 / 密码 / 2FA
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('edit.me@example.com----OldPwd123'));
  await page.evaluate(() => window.__cockpitFill.save());
  await page.evaluate((sec) => window.__cockpitFill.updateAccount('edit.me@example.com', {
    email: 'edited.me@example.com', password: 'NewPwd456', twofa: sec,
  }), TFA_SECRET);
  await page.waitForTimeout(300);
  const text = await page.evaluate(() => window.__cockpitFill.exportText());
  check('编辑：账号/密码已更新', text.includes('edited.me@example.com----NewPwd456'), text.slice(0, 80));
  check('编辑：旧记录已替换', !text.includes('edit.me@example.com----OldPwd123'));
  check('编辑：2FA 已写入', (await page.evaluate(() => window.__cockpitFill.twofaOf('edited.me@example.com'))) === TFA_SECRET);
  await page.context().close();
}
{
  // 修改库内账号并改名：旧邮箱隐藏、新邮箱出现
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate((orig) => window.__cockpitFill.updateAccount(orig, {
    email: 'renamed.lib@example.com', password: 'Renamed1',
  }), GOOD);
  await page.waitForTimeout(300);
  const accounts = await page.evaluate(() => window.__cockpitFill.accounts());
  check('编辑库内账号：新邮箱出现', accounts.includes('renamed.lib@example.com'));
  check('编辑库内账号：旧邮箱隐藏', !accounts.includes(GOOD));
  await page.context().close();
}

// ---------- 10.5 批量导出 ----------
{
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.setPaste('exp.one@example.com----ExpPwd123'));
  await page.evaluate(() => window.__cockpitFill.save());
  await page.evaluate(() => window.__cockpitFill.setPaste('exp.two@example.com----ExpPwd456'));
  await page.evaluate(() => window.__cockpitFill.save());
  await page.waitForTimeout(300);
  const text = await page.evaluate(() => window.__cockpitFill.exportText());
  check('导出：包含已保存账号密码', /exp\.one@example\.com----ExpPwd123/.test(text) && /exp\.two@example\.com----ExpPwd456/.test(text), text.slice(0, 80));
  await page.evaluate(() => window.__cockpitFill.export());
  await page.waitForTimeout(300);
  const st = await page.evaluate(() => window.__cockpitFill.status());
  check('导出：有成功提示', /已导出 \d+ 个账号/.test(st), st);
  await page.context().close();
}

// ---------- 10.6 导出带 2FA / 空库内账号不显示分区 ----------
{
  const page = await newPage();
  await openPanelViaMenu(page);
  await page.evaluate((sec) => window.__cockpitFill.setPaste(`exp.tfa@example.com----TfaPwd123 2FA: ${sec}`), TFA_SECRET);
  await page.evaluate(() => window.__cockpitFill.save());
  await page.evaluate(() => window.__cockpitFill.setPaste('exp.plain@example.com----PlainPwd9'));
  await page.evaluate(() => window.__cockpitFill.save());
  await page.waitForTimeout(300);
  const text = await page.evaluate(() => window.__cockpitFill.exportText());
  check('导出：带 2FA 的账号输出密钥', text.includes(`exp.tfa@example.com----TfaPwd123 2FA: ${TFA_SECRET}`), text.slice(0, 120));
  const plainLine = text.split('\n').find((l) => l.startsWith('exp.plain@example.com'));
  check('导出：无 2FA 的账号不带 2FA 字段', plainLine === 'exp.plain@example.com----PlainPwd9', String(plainLine));
  await page.context().close();
}
{
  // 默认构建（不内嵌账号）：「库内账号」「没有可用的库内账号」两行都不出现
  const page = await newPage({ script: USERSCRIPT_EMPTY });
  await openPanelViaMenu(page);
  await page.evaluate(() => window.__cockpitFill.mergeOpen());
  await page.waitForTimeout(300);
  const sections = await page.evaluate(() => window.__cockpitFill.sections());
  const items = await page.evaluate(() => window.__cockpitFill.mergeItems());
  const body = await page.evaluate(() => document.getElementById('cockpit-fill-host') ? '' : '');
  check('空账号库：不出现「库内账号」分组', !sections.some((t) => t.includes('库内账号')), sections.join(' | '));
  check('空账号库：不出现「没有可用的库内账号」', !items.some((t) => t.includes('没有可用的库内账号')), items.join(' | '));
  await page.context().close();
}

// ---------- 11. 正式产物不含调试钩子 ----------
check('release 构建无调试后门', !RELEASE.includes('__cockpitFill'));
check('release 默认不内嵌账号', /const ACCOUNTS = \[\s*\]/.test(RELEASE) && !RELEASE.includes('vanilla_hill04'));
check('release 构建无通配 @connect', !/@connect\s+\*/.test(RELEASE));
check('release 匹配 auth.openai.com 与 wzyp.cn', /@match\s+https:\/\/auth\.openai\.com\/\*/.test(RELEASE) && /@match\s+https:\/\/wzyp\.cn\/\*/.test(RELEASE));

console.log(JSON.stringify(results, null, 1));
const failed = results.filter(r => r.result !== 'OK');
console.log(`\n共 ${results.length} 项断言，` + (failed.length ? `✗ 失败 ${failed.length} 项` : '✓ 全部通过'));
await browser.close();
server.close();
process.exit(failed.length ? 1 : 0);
