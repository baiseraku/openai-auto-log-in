#!/usr/bin/env node
// Codex/ChatGPT 账号自动登录：驱动官方 `codex login` 的 OAuth 流程，在 Chrome 里自动填
// 「邮箱 → 密码 → 一次性验证码」，完成后 auth.json 由 codex 自己写入目标 CODEX_HOME。
//
// 用法:
//   node scripts/login.mjs --email xxx@example.com [--home /tmp/xxx] [--headless] [--debug]
//   node scripts/login.mjs --list
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { findAccount } from './lib/cockpit-store.mjs';
import { fetchCode } from './lib/totp-code.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const CODEX = process.env.CODEX_BIN || '/opt/homebrew/bin/codex';
const CHROME_PROFILE = path.join(ROOT, '.cache', 'chrome-profile');
const LOG_DIR = path.join(ROOT, 'log');
const SHOT_DIR = path.join(ROOT, '.cache', 'shots');

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const opt = (n, d = null) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };

if (flag('--list')) {
  const all = findAccount('');
  console.log('Codex 账号（来自 Cockpit Tools 只读解析）:');
  for (const a of all) console.log(` ${a.email}  plan=${a.plan}  pwd=${a.password ? '有' : '无'}  mail=${a.mailUrl || '-'}`);
  process.exit(0);
}

const emailQuery = opt('--email');
if (!emailQuery) { console.error('缺少 --email，或使用 --list 查看可用账号'); process.exit(2); }
const matches = findAccount(emailQuery);
if (matches.length === 0) { console.error(`账号库里找不到: ${emailQuery}`); process.exit(2); }
if (matches.length > 1) { console.error(`匹配到多个账号，请写完整邮箱:\n  ${matches.map(m => m.email).join('\n  ')}`); process.exit(2); }
const account = matches[0];
if (!account.password) { console.error(`${account.email} 没有存密码，无法自动填密码步`); process.exit(2); }

const HOME = opt('--home') || path.join(ROOT, '.cache', 'homes', account.email.replace(/[^\w.+-]/g, '_'));
const HEADLESS = flag('--headless');
const DEBUG = flag('--debug');
fs.mkdirSync(HOME, { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });
fs.mkdirSync(SHOT_DIR, { recursive: true });

const log = (...a) => console.log(`[${new Date().toLocaleTimeString('zh-CN', { hour12: false })}]`, ...a);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ---------- 1. 启动 codex login，拿到授权 URL ----------
function startCodexLogin() {
  return new Promise((resolve, reject) => {
    const child = spawn(CODEX, ['login'], {
      env: { ...process.env, CODEX_HOME: HOME, BROWSER: '/usr/bin/true', NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let settled = false;
    const onData = (buf) => {
      out += buf.toString();
      const m = out.match(/https:\/\/auth\.openai\.com\/\S+/);
      if (m && !settled) { settled = true; resolve({ child, url: m[0], out: () => out }); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', (code) => {
      if (!settled) { settled = true; reject(new Error(`codex login 提前退出 code=${code}\n${out}`)); }
    });
    child.on('error', reject);
    setTimeout(() => { if (!settled) { settled = true; reject(new Error(`等不到授权 URL\n${out}`)); } }, 20000);
  });
}

// ---------- 2. 页面动作 ----------
const submitSelectors = [
  'button[type=submit]',
  'button:has-text("Continue")',
  'button:has-text("Log in")',
  'button:has-text("Next")',
  'button:has-text("Verify")',
  'button:has-text("Authorize")',
  'button:has-text("Allow")',
  '[role=button]:has-text("Continue")',
];

async function bodyText(page) {
  return (await page.evaluate(() => document.body?.innerText || '').catch(() => '')) || '';
}

async function clickSubmit(page) {
  for (const sel of submitSelectors) {
    const el = page.locator(sel).first();
    if (await el.count().catch(() => 0)) {
      if (await el.isVisible().catch(() => false) && await el.isEnabled().catch(() => false)) {
        await el.click({ timeout: 5000 }).catch(() => {});
        return true;
      }
    }
  }
  return false;
}

/** 找可见的输入框 */
async function visibleInput(page, selectors) {
  for (const sel of selectors) {
    const loc = page.locator(sel);
    const n = await loc.count().catch(() => 0);
    for (let i = 0; i < n; i++) {
      const el = loc.nth(i);
      if (await el.isVisible().catch(() => false)) return el;
    }
  }
  return null;
}

async function fillOtp(page, code) {
  // 情况 A：单个 6 位输入框
  const single = await visibleInput(page, [
    'input[autocomplete="one-time-code"]',
    'input[inputmode="numeric"]',
    'input[name="code"]',
    'input[id*="code" i]',
    'input[placeholder*="code" i]',
  ]);
  const segmented = page.locator('input[maxlength="1"]');
  const segCount = await segmented.count().catch(() => 0);
  if (segCount >= 4) {
    await segmented.first().click();
    await page.keyboard.type(code, { delay: 90 });
    return 'segmented';
  }
  if (single) { await single.click(); await page.keyboard.type(code, { delay: 90 }); return 'single'; }
  return null;
}

// ---------- 3. 主流程 ----------
async function run() {
  log(`账号: ${account.email}  home=${HOME}`);
  const { child, url } = await startCodexLogin();
  log(`已拿到授权 URL: ${url.slice(0, 90)}...`);

  const browser = await chromium.launch({
    executablePath: CHROME,
    headless: HEADLESS,
    args: ['--no-first-run', '--no-default-browser-check', '--window-position=1100,60', '--window-size=980,860'],
  });
  const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 960, height: 820 } });
  const page = await ctx.newPage();

  const done = new Promise((resolve) => child.on('exit', (code) => resolve(code)));
  let ok = false;
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 60000 });
    const deadline = Date.now() + 180000;
    let lastLabel = '';
    while (Date.now() < deadline) {
      await sleep(1200);
      if (page.url().startsWith('http://127.0.0.1') || page.url().startsWith('http://localhost')) { ok = true; break; }
      let text = await bodyText(page);
      if (/Just a moment|security verification/i.test(text)) { lastLabel = 'cloudflare'; continue; }

      // 邮箱
      const emailInput = await visibleInput(page, ['input[type="email"]', 'input[name="email"]', 'input#email', 'input[autocomplete="username"]']);
      if (emailInput && await emailInput.inputValue().catch(() => '') === '') {
        await emailInput.fill(account.email);
        await clickSubmit(page);
        log('已填邮箱，等待下一步'); await sleep(1500); continue;
      }
      // 密码
      const pwdInput = await visibleInput(page, ['input[type="password"]', 'input[name="password"]']);
      if (pwdInput) {
        await pwdInput.fill(account.password);
        await clickSubmit(page);
        log('已填密码，等待下一步'); await sleep(1800); continue;
      }
      // 一次性验证码
      const wantsCode = /verif|code|authenticat|two-factor|2FA|confirm/i.test(text);
      if (wantsCode && /(enter|input|code)/i.test(text)) {
        const { code, remaining } = await fetchCode(account.email);
        const filled = await fillOtp(page, code);
        if (filled) {
          log(`已填验证码（${filled}，剩余 ${remaining}s）`);
          await clickSubmit(page);
          await sleep(2200); continue;
        }
      }
      // 其他确认页（授权/继续）
      if (/continue|allow|authorize|accept/i.test(text)) {
        if (await clickSubmit(page)) { log('点了确认/继续按钮'); await sleep(1500); continue; }
      }
      lastLabel = text.slice(0, 60).replace(/\n/g, ' ');
    }
  } catch (e) {
    log('浏览器流程出错:', e.message);
  }

  // 等 codex 收到回调并退出
  const exitCode = await Promise.race([done, sleep(25000).then(() => 'timeout')]);
  const authFile = path.join(HOME, 'auth.json');
  const hasAuth = fs.existsSync(authFile);
  if (!ok && !hasAuth) {
    await page.screenshot({ path: path.join(SHOT_DIR, `fail-${Date.now()}.png`) }).catch(() => {});
    log('未完成登录，最后页面:', page.url());
    log('页面片段:', (await bodyText(page)).slice(0, 300).replace(/\n/g, ' '));
  }
  await browser.close().catch(() => {});
  if (child.exitCode === null) child.kill();

  if (hasAuth) {
    const auth = JSON.parse(fs.readFileSync(authFile, 'utf8'));
    log(`✅ 登录成功，auth.json 已写入 ${HOME}`);
    log(`   auth_mode=${auth.auth_mode} tokens=${Object.keys(auth.tokens || {}).join(',')}`);
    if (DEBUG) {
      const idt = auth.tokens?.id_token || '';
      const claims = idt.split('.')[1] ? JSON.parse(Buffer.from(idt.split('.')[1], 'base64url').toString()) : {};
      log('   email:', claims.email, ' account_id:', claims['https://api.openai.com/auth']?.chatgpt_account_id);
    }
    process.exit(0);
  }
  log('❌ 登录未完成（codex 退出码 ' + exitCode + '）');
  process.exit(1);
}

run().catch(e => { console.error(e); process.exit(1); });
