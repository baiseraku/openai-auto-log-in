// ==UserScript==
// @name         Cockpit 登录自动填（Codex / ChatGPT）
// @namespace    cockpit-autologin
// @version      2.3.2
// @description  点 Tampermonkey 图标 →「打开面板」，粘贴识别账号、保存到插件、管理删除；填入邮箱 / 密码 / 动态验证码，每次填入前先确认，且不点提交。
// @author       cockpit-autologin
// @match        https://auth.openai.com/*
// @match        https://auth0.openai.com/*
// @match        https://chatgpt.com/*
// @match        https://chat.openai.com/*
// @match        https://platform.openai.com/*
// @match        https://wzyp.cn/*
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @grant        GM_getValue
// @grant        GM_setValue
__CONNECT_LINES__
// @run-at       document-idle
// @noframes
// ==/UserScript==

(function () {
  'use strict';

  const ACCOUNTS = __ACCOUNTS_JSON__;
  const BUILD_TIME = '__BUILD_TIME__';

  if (!ACCOUNTS.length) {
    console.log('[Cockpit 自动填] 未内嵌账号：在面板里粘贴账号密码并「保存账号」即可长期使用。');
  }

  const LS = { account: 'cockpit_fill_account', auto: 'cockpit_fill_auto' };
  const FAIL_COOLDOWN_MS = 5000;
  const FAIL_LIMIT = 3;
  const CODE_RETRY_LIMIT = 3;

  const state = {
    account: '',
    auto: false,
    inFlight: false,
    lastStep: undefined,
    confirmedAccount: '',   // 本次面板会话已确认过的账号（一次登录只确认一次）
    autoDoneMarker: '',
    failCount: new Map(),
    cooldownUntil: new Map(),
    pasted: null,
    debugHost: '',         // 仅调试构建用
    pwOverride: null,   // 粘贴邮箱已在账号库时，用粘贴的密码覆盖库内密码
    twofaOverride: null,// 粘贴带 2FA 密钥时覆盖该账号的 2FA
    codeEmailOverride: null, // 粘贴带辅助邮箱时覆盖取码邮箱
  };
  try {
    state.account = localStorage.getItem(LS.account) || '';
    state.auto = localStorage.getItem(LS.auto) === '1';
  } catch {}
  if (!ACCOUNTS.some(a => a.email === state.account)) state.account = '';

  // ---------- 插件自己保存的账号（Tampermonkey GM 存储） ----------
  const normEmail = (v) => String(v || '').trim().toLowerCase();

  // ---------- 本地 TOTP：有 2FA 密钥的账号自己算码，不依赖第三方网站 ----------
  function base32Decode(input) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = String(input || '').toUpperCase().replace(/[\s\-=]/g, '');
    let bits = 0, value = 0;
    const out = [];
    for (const ch of clean) {
      const idx = chars.indexOf(ch);
      if (idx < 0) continue;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  /** 标准 TOTP（RFC 6238）：SHA-1 / 30s / 6 位，ChatGPT 用的就是这个 */
  async function totpCode(secret, period = 30, digits = 6) {
    const keyBytes = base32Decode(secret);
    if (!keyBytes.length) throw new Error('2FA 密钥无效（base32）');
    const counter = Math.floor(Date.now() / 1000 / period);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 4294967296));
    view.setUint32(4, counter >>> 0);
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
    const off = sig[sig.length - 1] & 0x0f;
    const bin = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
    return String(bin % 10 ** digits).padStart(digits, '0');
  }
  const totpRemaining = (period = 30) => period - (Math.floor(Date.now() / 1000) % period);

  const SAVED_KEY = 'cockpit_saved_accounts';
  function loadSaved() {
    try {
      const raw = typeof GM_getValue === 'function' ? GM_getValue(SAVED_KEY, '[]') : '[]';
      const arr = JSON.parse(raw || '[]');
      return Array.isArray(arr) ? arr.filter((a) => a && a.email) : [];
    } catch { return []; }
  }
  function persistSaved(arr) {
    savedAccounts = arr.slice();
    try { if (typeof GM_setValue === 'function') GM_setValue(SAVED_KEY, JSON.stringify(savedAccounts)); } catch {}
  }
  let savedAccounts = loadSaved();

  // 被用户在面板里删掉的「库内账号」：记成隐藏名单，不写回账号库/生成物
  const HIDDEN_KEY = 'cockpit_hidden_accounts';
  function loadHidden() {
    try {
      const raw = typeof GM_getValue === 'function' ? GM_getValue(HIDDEN_KEY, '[]') : '[]';
      const arr = JSON.parse(raw || '[]');
      return Array.isArray(arr) ? arr.map((x) => normEmail(x)).filter(Boolean) : [];
    } catch { return []; }
  }
  function persistHidden(arr) {
    hiddenAccounts = [...new Set(arr.map((x) => normEmail(x)))];
    try { if (typeof GM_setValue === 'function') GM_setValue(HIDDEN_KEY, JSON.stringify(hiddenAccounts)); } catch {}
  }
  let hiddenAccounts = loadHidden();
  const isHidden = (email) => hiddenAccounts.includes(normEmail(email));

  /** 库内账号 + 插件保存的账号（同邮箱时用保存的密码覆盖） */
  function allAccounts() {
    const map = new Map();
    for (const a of ACCOUNTS) {
      if (isHidden(a.email)) continue;
      map.set(normEmail(a.email), { ...a, source: '库内' });
    }
    for (const s of savedAccounts) {
      const k = normEmail(s.email);
      const base = map.get(k);
      if (base) {
        map.set(k, {
          ...base,
          password: s.password || base.password,
          ...normalizeCode({ email: base.email, twofa: s.twofa || base.twofa || '', codeEmail: s.codeEmail || base.codeEmail || '' }),
          source: '已保存·覆盖',
          saved: true,
        });
      } else {
        map.set(k, {
          email: s.email,
          password: s.password || '',
          ...normalizeCode({ email: s.email, twofa: s.twofa, codeEmail: s.codeEmail }),
          codeApi: s.codeApi || DEFAULT_CODE_API,
          plan: '',
          source: '已保存',
          saved: true,
        });
      }
    }
    return [...map.values()];
  }

  // ---------- 工具 ----------
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));

  function setNativeValue(el, value) {
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function visible(el) {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    return r.width > 1 && r.height > 1 && st.visibility !== 'hidden' && st.display !== 'none' && !el.disabled && !el.readOnly;
  }

  function pickInput(selectors) {
    for (const sel of selectors) {
      for (const el of document.querySelectorAll(sel)) if (visible(el)) return el;
    }
    return null;
  }

  const EMAIL_SELECTORS = ['input[type="email"]', 'input[name="email"]', 'input#email', 'input[autocomplete="username"]'];
  const PWD_SELECTORS = ['input[type="password"]', 'input[name="password"]'];

  function detectStep() {
    const segs = [...document.querySelectorAll('input[maxlength="1"]')].filter(visible);
    if (segs.length >= 4) return 'code';
    if (pickInput(['input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]', 'input[name="code"]', 'input[id*="code" i]'])) return 'code';
    if (pickInput(PWD_SELECTORS)) return 'password';
    if (pickInput(EMAIL_SELECTORS)) return 'email';
    return null;
  }

  const STEP_LABEL = { email: '邮箱', password: '密码', code: '验证码' };
  const markerOf = (step) => location.pathname + '|' + step;
  const currentAccount = () => {
    const base = state.pasted || allAccounts().find(a => normEmail(a.email) === normEmail(state.account)) || null;
    if (!base) return null;
    const same = (o) => o && normEmail(o.email) === normEmail(base.email);
    const merged = { ...base };
    if (same(state.pwOverride)) merged.password = state.pwOverride.password;
    if (same(state.twofaOverride)) merged.twofa = state.twofaOverride.twofa;
    if (same(state.codeEmailOverride)) merged.codeEmail = state.codeEmailOverride.codeEmail;
    return merged;
  };

  // ---------- 从粘贴文本识别账号 ----------
  const DEFAULT_CODE_API = 'https://2fa.nloop.cc/api/mfa/lookup';
  const PASTED_VALUE = '__pasted__';
  // 严格的邮箱边界：local/domain 都不允许连续连字符，避免把 Pass1234----a 或 P@ss----brand.new 整段吞掉
  const EMAIL_LOCAL = '[A-Za-z0-9._%+]+(?:-[A-Za-z0-9._%+]+)*';
  const EMAIL_DOMAIN = '[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?:\\.[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*)*\\.[A-Za-z]{2,}';
  const EMAIL_RE = new RegExp(`${EMAIL_LOCAL}@${EMAIL_DOMAIN}`, 'g');
  const EMAIL_FULL_RE = new RegExp(`^${EMAIL_LOCAL}@${EMAIL_DOMAIN}$`);
  const LABELS = '密码|密碼|password|passwd|pwd|pass|账号|账号信息|账户|email|mail|account';
  const LABEL_ONLY_RE = new RegExp(`^(?:${LABELS})[\\s:：=]*$`, 'i');
  const PWD_LABEL_RE = /(?:^|[\s,;|])(?:密码|密碼|password|passwd|pwd|pass)\s*[:：=]\s*(\S{1,64})/i;

  /** 密码候选必须像密码：ASCII 可见字符、4~64 位、不含 @、不是标签词 */
  function plausiblePassword(v) {
    if (!v) return false;
    const t = cleanPassword(v);
    if (t.length < 4 || t.length > 64) return false;
    if (!/^[\x21-\x7E]+$/.test(t)) return false;
    if (EMAIL_FULL_RE.test(t)) return false;        // 另一个邮箱地址不能当密码
    if (LABEL_ONLY_RE.test(t)) return false;       // 「密码/账号/password:」这类标签词
    if (!/[A-Za-z0-9]/.test(t)) return false;
    return true;
  }
  const cleanPassword = (v) => String(v || '')
    .replace(/^["'“”‘’(（\[]+/, '')
    .replace(/["'“”‘’)\])]+$/, '')
    .replace(/[\s\-|,;:=]+$/, '');

  /** 找出文本里所有合法邮箱（正则本身保证不会被 ---- 串吞掉） */
  function findEmails(text) {
    const out = [];
    for (const m of text.matchAll(EMAIL_RE)) {
      out.push({ email: m[0], start: m.index, end: m.index + m[0].length });
    }
    return out;
  }

  /** 从邮箱两侧取密码候选：优先紧邻其后，其次其前 */
  function passwordAround(text, pos) {
    const tail = text.slice(pos.end);
    const tailM = tail.match(/^[\s\-|,;:=]*([^\s]+)/);
    if (tailM) {
      const cand = cleanPassword(tailM[1]);
      const labelM = cand.match(new RegExp(`^(?:密码|密碼|password|passwd|pwd|pass)\\s*[:：=]\\s*(.+)$`, 'i'));
      if (labelM) {
        if (plausiblePassword(labelM[1])) return cleanPassword(labelM[1]);
        // 标签后面的值不像密码时，退回把整段当密码（如 Pass:123）
        if (plausiblePassword(cand)) return cand;
      }
      else if (plausiblePassword(cand)) return cand;
    }
    const head = text.slice(0, pos.start).replace(/[\s\-|,;:=]+$/, '');
    const headM = head.match(/([^\s]+)$/);
    if (headM) {
      const cand = cleanPassword(headM[1]);
      if (!LABEL_ONLY_RE.test(cand) && plausiblePassword(cand)) return cand;
    }
    return '';
  }

  /**
   * 解析粘贴文本 → { email, password }
   * 支持：a@b.com----Pass1234 / |, :, 空格分隔 / Pass1234----a@b.com /
   *       账号：a@b.com 密码：Pass1234 / password: Pass1234
   */
  const BASE32_RE = /^[A-Z2-7]{16,64}$/;
  const trimSecret = (v) => String(v || '').replace(/[\s\-=]/g, '').toUpperCase();

  /** 邮箱后面的分段：拆出「密码」和「2FA 密钥」（应对 邮箱----密码----密钥 / 邮箱|密码|密钥） */
  function splitAfterEmail(raw, emailEnd, fallbackPwd) {
    const rest = raw.slice(emailEnd);
    const toks = rest.split(/(?:-{2,}|[\s|,;]+)/).map((t) => cleanPassword(t)).filter(Boolean);
    if (!toks.length) return null;
    const first = toks[0];
    const second = toks[1] ? trimSecret(toks[1]) : '';
    const dirty = /-{2,}|[|]/.test(fallbackPwd || '');   // 只在密码被多段格式污染时才纠偏
    if (!plausiblePassword(first)) return null;
    // 只有出现了第三段、且第三段像 base32 时才认定 2FA
    const twofa = second && BASE32_RE.test(second) ? second : '';
    return { password: first, twofa, dirty };
  }

  function parsePasted(text) {
    const raw = String(text || '').trim();
    if (!raw) return null;
    const emails = findEmails(raw);
    if (!emails.length) return { email: null };

    // 1) 带「密码」标签时优先用标签值
    const labeled = raw.match(PWD_LABEL_RE);
    const labelPwd = labeled && plausiblePassword(labeled[1]) ? cleanPassword(labeled[1]) : '';

    // 2) 优先选「旁边就有合法密码」的那个邮箱
    let picked = null;
    let pwd = '';
    for (const e of emails) {
      const p = passwordAround(raw, e);
      if (p) { picked = e; pwd = p; break; }
    }
    if (!picked) picked = emails[0];
    if (!pwd && labelPwd) pwd = labelPwd;

    let twofa = extractTwofa(raw, pwd);
    // 密码被多段格式污染（如「邮箱----密码----2FA密钥」）时，按分段重新取
    const triple = splitAfterEmail(raw, picked.end, pwd);
    if (triple && triple.dirty) {
      pwd = triple.password;
      if (!twofa && triple.twofa) twofa = triple.twofa;
    } else if (!twofa && triple && triple.twofa && pwd === triple.password) {
      twofa = triple.twofa;
    }

    return {
      email: picked.email,
      password: pwd,
      twofa,
      auxEmail: extractAuxEmail(raw, picked.email),
    };
  }

  /** 从粘贴文本里抠 2FA 密钥：otpauth:// 链接 / 「2FA: xxx」/ 「密钥：xxx」/ 独立 base32 串 */
  function extractTwofa(raw, password) {
    const uri = raw.match(/otpauth:\/\/[^\s]+/i);
    if (uri) {
      const m = uri[0].match(/[?&]secret=([A-Za-z2-7]+)/i);
      if (m) return m[1].toUpperCase();
    }
    const labeled = raw.match(/(?:2fa|2-factor|twofa|totp|authenticator|密钥|密鑰|二次验证|二步验证|验证密钥)\s*[:：=]\s*([A-Za-z2-7][A-Za-z2-7\s\-]{14,})/i);
    if (labeled) return labeled[1].replace(/[\s\-]/g, '').toUpperCase();
    const standalone = raw.match(/(?:^|[\s,;|])([A-Z2-7]{16,64})(?=$|[\s,;|])/);
    if (standalone && standalone[1] !== String(password || '').toUpperCase()) return standalone[1];
    return '';
  }

  /** 从粘贴文本里抠辅助邮箱：修改过登录邮箱、但 MFA 仍由原邮箱收码的账号用 */
  function extractAuxEmail(raw, loginEmail) {
    const labeled = raw.match(/(?:辅助邮箱|辅助邮箱地址|原邮箱|旧邮箱|舊邮箱|收码邮箱|取码邮箱|验证码邮箱|mfa\s*邮箱|aux(?:iliary)?(?:\s*(?:email|mail))?|code\s*email|verification\s*email)\s*[:：=]\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})/i);
    if (!labeled) return '';
    const mail = labeled[1].trim();
    if (normEmail(mail) === normEmail(loginEmail)) return '';
    return mail;
  }

  /** 第三个框（取码方式）补齐规则：填了 base32 就是 2FA；否则用取码邮箱，为空时回落到登录邮箱 */
  function normalizeCode(rec) {
    const twofa = String(rec.twofa || '').replace(/[\s\-]/g, '').toUpperCase();
    if (twofa) return { twofa, codeEmail: '' };
    return { twofa: '', codeEmail: String(rec.codeEmail || rec.email || '').trim() };
  }

  /** 2FA 输入框统一解析：填邮箱 → 辅助邮箱；填 base32 → 2FA 密钥（二选一） */
  function parseCodeField(value) {
    let raw = String(value || '').trim();
    if (!raw) return { twofa: '', codeEmail: '' };
    // 允许直接粘「2FA: 密钥」「密钥=密钥」「otpauth://…」
    const uri = raw.match(/[?&]secret=([A-Za-z2-7]+)/i);
    if (uri) return { twofa: uri[1].toUpperCase(), codeEmail: '' };
    raw = raw.replace(/^(?:2fa|mfa|totp|otp|twofa|authenticator|密钥|密鑰|二次验证|二步验证|验证密钥)\s*[:：=]\s*/i, '');
    const mail = raw.match(EMAIL_RE);
    if (mail && mail[0]) return { twofa: '', codeEmail: mail[0] };
    const secret = trimSecret(raw);
    if (BASE32_RE.test(secret)) return { twofa: secret, codeEmail: '' };
    return { twofa: '', codeEmail: '', invalid: true };
  }

  const maskPassword = (v) => {
    if (!v) return '';
    if (v.length <= 3) return '*'.repeat(v.length);
    return v.slice(0, 2) + '*'.repeat(Math.max(1, v.length - 3)) + v.slice(-1);
  };

  // ---------- 取验证码 ----------
  function fetchCode(account) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: 'POST',
        url: account.codeApi,
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ email: account.email }),
        timeout: 15000,
        onload: (res) => {
          try {
            const data = JSON.parse(res.responseText);
            if (!data.ok) return reject(new Error('取码接口返回失败'));
            const item = (data.results || []).find(r => r.code);
            if (!item) return reject(new Error('该邮箱暂无验证码记录'));
            resolve(item);
          } catch (e) { reject(new Error('取码响应解析失败')); }
        },
        onerror: () => reject(new Error('取码请求失败（检查网络/代理）')),
        ontimeout: () => reject(new Error('取码超时')),
      });
    });
  }

  // ---------- 填充（只填，不提交） ----------
  async function fillEmail(account) {
    const el = pickInput(EMAIL_SELECTORS);
    if (!el) throw new Error('没找到邮箱输入框');
    el.focus(); el.click({ bubbles: false });
    setNativeValue(el, account.email);
    return `已填邮箱 ${account.email}`;
  }

  async function fillPassword(account) {
    if (!account.password) throw new Error('这个账号没存密码，请手动输入');
    const el = pickInput(PWD_SELECTORS);
    if (!el) throw new Error('没找到密码输入框');
    el.focus(); el.click({ bubbles: false });
    setNativeValue(el, account.password);
    return '已填密码';
  }

  async function fillCode(account, attempt = 1) {
    if (attempt > CODE_RETRY_LIMIT) throw new Error('连续取到即将过期的验证码，请稍后重试');
    let code;
    let item = { remaining: null };
    if (account.twofa) {
      // 有独立 2FA 密钥：本地算 TOTP，不查第三方
      const left = totpRemaining();
      if (left < 6) {
        await sleep((left + 1) * 1000);
        return fillCode(account, attempt + 1);
      }
      code = await totpCode(account.twofa);
      item = { remaining: totpRemaining() };
    } else {
      const codeEmail = account.codeEmail || account.email;
      item = await fetchCode({ codeApi: account.codeApi, email: codeEmail });
      if (item.remaining != null && item.remaining < 6) {
        await sleep((item.remaining + 1) * 1000);
        return fillCode(account, attempt + 1);
      }
      code = item.code;
    }
    const segs = [...document.querySelectorAll('input[maxlength="1"]')].filter(visible);
    if (segs.length >= 4) {
      segs[0].focus(); segs[0].click({ bubbles: false });
      for (let i = 0; i < Math.min(segs.length, code.length); i++) setNativeValue(segs[i], code[i]);
      return `已填验证码（分段，剩余 ${item.remaining ?? '?'}s）`;
    }
    const el = pickInput(['input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]', 'input[name="code"]', 'input[id*="code" i]']);
    if (!el) throw new Error('没找到验证码输入框');
    el.focus(); el.click({ bubbles: false });
    setNativeValue(el, code);
    return `已填验证码（剩余 ${item.remaining ?? '?'}s）`;
  }

  function fillStep(step, account) {
    if (step === 'email') return fillEmail(account);
    if (step === 'password') return fillPassword(account);
    return fillCode(account);
  }

  // ---------- 面板（closed shadow root，默认隐藏） ----------
  const host = document.createElement('div');
  host.id = 'cockpit-fill-host';
  host.style.display = 'none';
  const shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `
    <style>
      .box {
        font: 13px -apple-system, "PingFang SC", sans-serif;
        position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
        width: 286px; padding: 10px 12px; border-radius: 12px;
        background: rgba(28, 30, 33, .97); color: #ececec;
        box-shadow: 0 10px 30px rgba(0,0,0,.35); border: 1px solid rgba(255,255,255,.09);
      }
      .hd { display:flex; align-items:center; justify-content:space-between; margin-bottom:8px; }
      .tt { font-weight:600; font-size:13px; letter-spacing:.2px; }
      .step { font-size:11px; padding:2px 7px; border-radius:999px; background:#2f6f5a; color:#d6ffe9; }
      .step.none { background:#4a3a1f; color:#ffd9a3; }
      .who { font-size:11px; color:#9aa0a6; margin:-4px 0 8px; min-height:14px; }
      select, button { font: inherit; }
      select { width:100%; padding:6px 8px; border-radius:8px;
               background:#1b1d20; color:#eee; border:1px solid rgba(255,255,255,.13); }
      textarea { width:100%; box-sizing:border-box; margin:6px 0 6px; padding:6px 8px; border-radius:8px;
                 background:#1b1d20; color:#eee; border:1px solid rgba(255,255,255,.13);
                 font:12px -apple-system, "PingFang SC", sans-serif; resize:vertical;
                 -webkit-user-select: text; user-select: text; -webkit-user-modify: read-write-plaintext-only; }
      input[type="text"] { -webkit-user-select: text; user-select: text; }
      .row { display:flex; gap:8px; }
      button { flex:1; padding:7px 10px; border-radius:8px; cursor:pointer; background:#2f6f5a; color:#fff; border:none; }
      button.ghost { background:#2a2d31; color:#cfd2d6; }
      button:disabled { opacity:.45; cursor:default; }
      .auto { display:flex; align-items:center; gap:6px; margin-top:8px; color:#aeb3b9; font-size:12px; }
      .st { margin-top:7px; font-size:12px; line-height:1.4; color:#9be3c3; min-height:16px; word-break:break-all; }
      .st.err { color:#ff9a9a; }
      .row2 { display:flex; gap:8px; margin-top:8px; }
      .row2 button { padding:6px 8px; font-size:12px; }
      #mgmt { display:none; margin-top:8px; border-top:1px solid rgba(255,255,255,.1); padding-top:8px; }
      .mgmt-title { font-size:11px; color:#9aa0a6; margin-bottom:6px; }
      .item { display:flex; align-items:center; justify-content:space-between; gap:6px; font-size:12px;
              padding:3px 0; color:#cfd2d6; word-break:break-all; }
      .item button { flex:0 0 auto; width:22px; height:20px; padding:0; background:#4a2a2a; color:#ffb4b4; font-size:11px; }
      .empty { font-size:12px; color:#8b9096; }
      #edit { margin-top:8px; border-top:1px dashed rgba(255,255,255,.15); padding-top:8px; }
      #edit input { width:100%; box-sizing:border-box; margin-bottom:6px; padding:5px 7px; border-radius:6px;
                    background:#1b1d20; color:#eee; border:1px solid rgba(255,255,255,.16);
                    font:12px -apple-system, "PingFang SC", sans-serif; }
    </style>
    <div class="box">
      <div class="hd">
        <span class="tt">Cockpit 自动填</span>
        <span class="step none" id="step" style="display:none"></span>
      </div>
      <select id="acct"></select>
      <textarea id="paste" rows="2" placeholder="粘贴含账号密码的文字，如 a@b.com----Pass1234"></textarea>
      <div class="who" id="who"></div>
      <div class="row">
        <button id="fill" disabled>填入</button>
        <button id="again" class="ghost">重填</button>
      </div>
      <div class="row2">
        <button id="clip" class="ghost" title="把剪贴板内容读进上面的框">读剪贴板</button>
        <button id="save" class="ghost">保存账号</button>
        <button id="manage" class="ghost">管理</button>
        <button id="export" class="ghost">导出</button>
      </div>
      <div id="mgmt">
        <div class="mgmt-title">账号管理（✎ 改账号/密码/2FA，✕ 删除）</div>
        <div id="mgmt-list"></div>
        <div id="edit" style="display:none">
          <div class="mgmt-title" id="edit-label"></div>
          <input id="edit-email" type="text" placeholder="账号（邮箱）">
          <input id="edit-pwd" type="text" placeholder="密码">
          <input id="edit-2fa" type="text" placeholder="第三个框（必填）：2FA 密钥（base32）或取码邮箱；没有 2FA 就填登录邮箱">
          <div class="row2">
            <button id="edit-save" class="ghost">保存修改</button>
            <button id="edit-cancel" class="ghost">取消</button>
          </div>
        </div>
      </div>
      <label class="auto"><input type="checkbox" id="auto"> 换步后自动填（一次登录只确认一次）</label>
      <div class="st" id="st"></div>
    </div>
  `;
  document.documentElement.appendChild(host);

  const $ = (id) => shadow.getElementById(id);
  const acctSel = $('acct');

  function option(value, text) {
    const o = document.createElement('option');
    o.value = value;
    o.textContent = text;
    return o;
  }

  function rebuildSelect() {
    const keep = acctSel.value;
    acctSel.innerHTML = '';
    acctSel.appendChild(option('', '请选择账号…'));
    if (state.pasted) acctSel.appendChild(option(PASTED_VALUE, `（粘贴识别）${state.pasted.email}`));
    for (const a of allAccounts()) {
      const plan = a.plan && a.plan !== 'free' ? ` · ${a.plan}` : '';
      const src = a.source && a.source !== '库内' ? ` · ${a.source}` : '';
      acctSel.appendChild(option(a.email, `${a.email}${plan}${src}`));
    }
    acctSel.value = keep;
    if (state.account && !allAccounts().some(a => normEmail(a.email) === normEmail(state.account)) && keep === '') {
      acctSel.value = '';
    }
  }

  rebuildSelect();

  $('auto').checked = state.auto;

  function setStatus(text, isErr = false) {
    const st = $('st');
    st.textContent = text;
    st.className = 'st' + (isErr ? ' err' : '');
  }
  function setWho(text) { $('who').textContent = text; }
  function renderWho() {
    const acc = currentAccount();
    if (!acc || (!state.pasted && !state.pwOverride)) { setWho(''); return; }
    const merged = state.pwOverride && normEmail(state.pwOverride.email) === normEmail(acc.email);
    const prefix = merged ? '已合并到库内账号：' : '已识别：';
    const codeSrc = acc.twofa
      ? ' · 取码：2FA'
      : (acc.codeEmail && normEmail(acc.codeEmail) !== normEmail(acc.email)
        ? ` · 取码邮箱 ${acc.codeEmail}`
        : ' · 取码：登录邮箱');
    if (!acc.password) { setWho(`${prefix}${acc.email}（无密码，需手动填）${codeSrc}`); return; }
    const shown = state.showPwd ? acc.password : maskPassword(acc.password);
    const tfa = codeSrc;
    setWho(`${prefix}${acc.email} · 密码 ${shown}${merged ? '（覆盖库内密码）' : ''}${tfa}（点此显示/隐藏）`);
  }

  $('who').addEventListener('click', () => {
    const acc = currentAccount();
    if (!acc || !acc.password) return;
    state.showPwd = !state.showPwd;
    renderWho();
  });

  function refreshStep() {
    const step = detectStep();
    // 只在「切换到另一个非空步骤」时清空确认/自动填标记；
    // 短暂的 null（DOM 重渲染）和同一步骤反复出现都不清，避免重复确认与重复取码。
    if (step) {
      if (step !== state.lastStep) {
        state.autoDoneMarker = '';   // 换步只重置「本步是否已填」，确认状态保留
      }
      state.lastStep = step;
    }
    const stepEl = $('step');
    stepEl.textContent = step ? STEP_LABEL[step] : '';
    stepEl.className = 'step';
    stepEl.style.display = step ? '' : 'none';   // 未识别时不显示右上角标签
    $('fill').disabled = !step || !currentAccount();
  }

  function clearConfirm() {
    state.confirmedAccount = '';
    state.autoDoneMarker = '';
  }

  function applyPaste(text) {
    const parsed = parsePasted(text);
    if (!parsed || !parsed.email) {
      state.pasted = null;
      state.pwOverride = null;
      state.twofaOverride = null;
      state.codeEmailOverride = null;
      rebuildSelect();
      acctSel.value = state.account || '';
      setWho(text && text.trim() ? '没识别到邮箱，检查粘贴内容' : '');
      refreshStep();
      return;
    }
    const known = allAccounts().find(a => normEmail(a.email) === normEmail(parsed.email));
    if (known) {
      // 同邮箱：合并进已有条目（库内或已保存），保留其取码地址，粘贴的密码覆盖原密码
      state.pasted = null;
      state.pwOverride = parsed.password ? { email: known.email, password: parsed.password } : null;
      state.twofaOverride = parsed.twofa ? { email: known.email, twofa: parsed.twofa } : null;
      state.codeEmailOverride = parsed.auxEmail ? { email: known.email, codeEmail: parsed.auxEmail } : null;
      state.account = known.email;
      rebuildSelect();
      acctSel.value = known.email;
      try { localStorage.setItem(LS.account, state.account); } catch {}
    } else {
      // 全新邮箱：用临时粘贴条目
      state.pwOverride = null;
      state.twofaOverride = null;
      state.codeEmailOverride = null;
      state.pasted = {
        email: parsed.email,
        password: parsed.password,
        twofa: parsed.twofa || '',
        codeEmail: parsed.auxEmail || '',
        codeApi: DEFAULT_CODE_API,
        plan: '',
      };
      state.account = '';
      rebuildSelect();
      acctSel.value = PASTED_VALUE;
    }
    state.showPwd = false;
    clearConfirm();
    renderWho();
    refreshStep();
    if (state.auto) scheduleAuto();
  }

  acctSel.addEventListener('change', () => {
    const v = acctSel.value;
    if (v !== PASTED_VALUE) {
      state.pasted = null;
      state.pwOverride = null;
      state.twofaOverride = null;
      state.codeEmailOverride = null;
      state.account = v;
      try { localStorage.setItem(LS.account, state.account); } catch {}
      rebuildSelect();
      acctSel.value = v;
      setWho('');
      setStatus(state.account ? `已选 ${state.account}` : '请选择账号');
    }
    clearConfirm();
    refreshStep();
  });

  let pasteTimer = null;
  $('paste').addEventListener('input', () => {
    clearTimeout(pasteTimer);
    pasteTimer = setTimeout(() => applyPaste($('paste').value), 250);
  });

  // 有些站点会在捕获阶段拦掉 paste 的默认行为，这里自己取剪贴板内容再解析
  $('paste').addEventListener('paste', (e) => {
    let text = '';
    try { text = (e.clipboardData || window.clipboardData).getData('text') || ''; } catch {}
    if (!text) return;                     // 拿不到就让浏览器默认粘贴
    e.preventDefault();
    $('paste').value = text;
    applyPaste(text);
  });

  $('clip').addEventListener('click', async () => {
    try {
      if (!navigator.clipboard || !navigator.clipboard.readText) throw new Error('no clipboard');
      const text = await navigator.clipboard.readText();
      if (!text || !text.trim()) { setStatus('剪贴板是空的', true); return; }
      $('paste').value = text;
      applyPaste(text);
    } catch (e) {
      setStatus('读不到剪贴板：请手动 ⌘V 粘到上面的框，或直接手打', true);
    }
  });

  $('auto').addEventListener('change', (e) => {
    state.auto = e.target.checked;
    try { localStorage.setItem(LS.auto, state.auto ? '1' : '0'); } catch {}
    if (state.auto) scheduleAuto();
  });

  // ---------- 保存 / 管理已保存账号 ----------
  function renderManage() {
    const list = $('mgmt-list');
    list.innerHTML = '';

    const section = (title) => {
      const h = document.createElement('div');
      h.className = 'mgmt-title';
      h.textContent = title;
      list.appendChild(h);
    };
    const empty = (text) => {
      const d = document.createElement('div');
      d.className = 'empty';
      d.textContent = text;
      list.appendChild(d);
    };
    const rowFor = (label, onDelete, deleteTitle, extraButtons = []) => {
      const row = document.createElement('div');
      row.className = 'item';
      const name = document.createElement('span');
      name.textContent = label;
      row.appendChild(name);
      for (const b of extraButtons) row.appendChild(b);
      if (onDelete) {
        const del = document.createElement('button');
        del.textContent = '✕';
        del.title = deleteTitle;
        del.addEventListener('click', onDelete);
        row.appendChild(del);
      }
      list.appendChild(row);
    };
    const editBtn = (email) => {
      const b = document.createElement('button');
      b.textContent = '✎';
      b.title = `修改 ${email}`;
      b.style.background = '#2a3a4a';
      b.style.color = '#bfd8ef';
      b.addEventListener('click', () => openEditForm(email));
      return b;
    };

    const visibleEmbedded = ACCOUNTS.filter((a) => !isHidden(a.email));
    if (visibleEmbedded.length) {
      section('库内账号（来自 Cockpit 账号库）');
      for (const a of visibleEmbedded) {
        rowFor(
          `${a.email}${a.plan && a.plan !== 'free' ? ' · ' + a.plan : ''}${a.twofa ? ' · 2FA' : (a.codeEmail && normEmail(a.codeEmail) !== normEmail(a.email) ? ' · 取码邮箱' : '')}`,
          () => deleteEmbedded(a.email),
          `删除 ${a.email}`,
          [editBtn(a.email)],
        );
      }
    }

    section('已保存到插件');
    if (!savedAccounts.length) empty('还没有保存的账号');
    for (const item of savedAccounts) {
      rowFor(
        `${item.email} · ${item.password ? maskPassword(item.password) : '无密码'}${item.twofa ? ' · 2FA' : (item.codeEmail && normEmail(item.codeEmail) !== normEmail(item.email) ? ' · 取码邮箱' : '')}`,
        () => deleteSaved(item.email),
        `删除 ${item.email}`,
        [editBtn(item.email)],
      );
    }

    if (hiddenAccounts.length) {
      section('已删除的库内账号（可恢复）');
      for (const email of hiddenAccounts) {
        const restore = document.createElement('button');
        restore.textContent = '恢复';
        restore.style.width = 'auto';
        restore.style.background = '#2a4a3a';
        restore.style.color = '#bfe6cf';
        restore.addEventListener('click', () => restoreEmbedded(email));
        rowFor(email, null, '', [restore]);
      }
    }
  }

  function deleteEmbedded(email) {
    if (isHidden(email)) return;
    persistHidden([...hiddenAccounts, email]);
    if (normEmail(state.account) === normEmail(email)) state.account = '';
    rebuildSelect();
    acctSel.value = state.account || '';
    renderManage();
    setStatus(`已删除库内账号 ${email}（可在管理里恢复）`);
    refreshStep();
  }

  function restoreEmbedded(email) {
    persistHidden(hiddenAccounts.filter((x) => x !== normEmail(email)));
    rebuildSelect();
    renderManage();
    setStatus(`已恢复库内账号 ${email}`);
    refreshStep();
  }

  let editingEmail = '';
  function openEditForm(email) {
    const acc = allAccounts().find((a) => normEmail(a.email) === normEmail(email));
    editingEmail = email;
    $('edit-label').textContent = `编辑：${email}`;
    $('edit-email').value = email;
    $('edit-pwd').value = acc ? (acc.password || '') : '';
    $('edit-2fa').value = acc ? (acc.twofa || acc.codeEmail || acc.email || '') : email;
    $('edit').style.display = 'block';
  }
  function closeEditForm() {
    editingEmail = '';
    $('edit').style.display = 'none';
  }

  /** 手动修改账号：账号 / 密码 / 2FA 密钥或辅助邮箱（改库内账号会生成一条「已保存·覆盖」） */
  function updateAccount(origEmail, fields = {}) {
    const newEmail = String(fields.email != null ? fields.email : origEmail).trim();
    if (!newEmail || !EMAIL_FULL_RE.test(newEmail)) { setStatus('邮箱格式不对，未保存', true); return false; }
    const existing = savedAccounts.find((x) => normEmail(x.email) === normEmail(origEmail));
    const wasEmbedded = ACCOUNTS.some((a) => normEmail(a.email) === normEmail(origEmail));
    const current = allAccounts().find((a) => normEmail(a.email) === normEmail(origEmail));
    let twofa = existing ? (existing.twofa || '') : (current ? (current.twofa || '') : '');
    let codeEmail = existing ? (existing.codeEmail || '') : (current ? (current.codeEmail || '') : '');
    if (fields.code != null) {
      const rawCode = String(fields.code).trim();
      if (rawCode) {
        const parsed = parseCodeField(rawCode);
        if (parsed.invalid) { setStatus('第三个框要填 2FA 密钥（base32）或取码邮箱，格式不对', true); return false; }
        twofa = parsed.twofa;
        codeEmail = parsed.codeEmail;
      } else {
        twofa = '';
        codeEmail = '';   // 留空 → 自动用登录邮箱
      }
    } else {
      if (fields.twofa != null) twofa = String(fields.twofa).replace(/[\s\-]/g, '').toUpperCase();
      if (fields.codeEmail != null) codeEmail = String(fields.codeEmail).trim();
    }
    const finalPassword = fields.password != null ? String(fields.password) : (existing ? existing.password : '');
    if (!String(finalPassword).trim()) { setStatus('密码不能为空：三个框都要填满', true); return false; }
    const code = normalizeCode({ email: newEmail, twofa, codeEmail });
    const rec = {
      email: newEmail,
      password: finalPassword,
      twofa: code.twofa,
      codeEmail: code.codeEmail,
      codeApi: (existing && existing.codeApi) || DEFAULT_CODE_API,
      savedAt: Date.now(),
    };
    savedAccounts = savedAccounts.filter((x) => normEmail(x.email) !== normEmail(origEmail));
    savedAccounts.push(rec);
    persistSaved(savedAccounts);
    if (wasEmbedded && normEmail(newEmail) !== normEmail(origEmail) && !isHidden(origEmail)) {
      persistHidden([...hiddenAccounts, normEmail(origEmail)]);
    }
    state.account = newEmail;
    state.pasted = null;
    state.pwOverride = null;
    state.twofaOverride = null;
    state.codeEmailOverride = null;
    rebuildSelect();
    acctSel.value = newEmail;
    closeEditForm();
    renderManage();
    const tag = rec.twofa ? '（2FA 取码）' : `（邮箱取码：${rec.codeEmail}）`;
    setStatus(`已更新 ${newEmail}${tag}`);
    refreshStep();
    return true;
  }

  $('edit-save').addEventListener('click', () => {
    if (!editingEmail) return;
    updateAccount(editingEmail, {
      email: $('edit-email').value,
      password: $('edit-pwd').value,
      code: $('edit-2fa').value,
    });
  });
  $('edit-cancel').addEventListener('click', closeEditForm);

  function saveCurrent() {
    const acc = currentAccount();
    if (!acc || !acc.email) { setStatus('没有可保存的账号，先粘贴识别或选一个', true); return; }
    if (!String(acc.password || '').trim()) { setStatus('密码为空：三个框都要填满，先到「管理 → ✎」补上密码', true); return; }
    const code = normalizeCode({ email: acc.email, twofa: acc.twofa, codeEmail: acc.codeEmail });
    const rec = {
      email: acc.email,
      password: acc.password,
      twofa: code.twofa,
      codeEmail: code.codeEmail,
      codeApi: acc.codeApi || DEFAULT_CODE_API,
      savedAt: Date.now(),
    };
    const idx = savedAccounts.findIndex((x) => normEmail(x.email) === normEmail(acc.email));
    if (idx >= 0) savedAccounts[idx] = rec; else savedAccounts.push(rec);
    persistSaved(savedAccounts);
    state.account = acc.email;
    state.pasted = null;
    state.pwOverride = null;
    rebuildSelect();
    acctSel.value = acc.email;
    renderManage();
    setStatus(`已保存 ${acc.email} 到插件（共 ${savedAccounts.length} 个）`);
    refreshStep();
  }

  function deleteSaved(email) {
    const before = savedAccounts.length;
    savedAccounts = savedAccounts.filter((x) => normEmail(x.email) !== normEmail(email));
    if (savedAccounts.length === before) return;
    persistSaved(savedAccounts);
    if (normEmail(state.account) === normEmail(email) && !ACCOUNTS.some((a) => normEmail(a.email) === normEmail(email))) {
      state.account = '';
    }
    rebuildSelect();
    if (state.account) acctSel.value = state.account;
    else if (acctSel.value !== PASTED_VALUE) acctSel.value = '';
    renderManage();
    setStatus(`已删除 ${email}（剩 ${savedAccounts.length} 个已保存）`);
    refreshStep();
  }

  // ---------- 批量导出账号密码 ----------
  function buildExportText() {
    const seen = new Set();
    const lines = [];
    for (const a of allAccounts()) {
      const k = normEmail(a.email);
      if (seen.has(k)) continue;
      seen.add(k);
      const code = normalizeCode(a);
      const codeTag = code.twofa
        ? ` 2FA: ${code.twofa}`
        : (code.codeEmail && normEmail(code.codeEmail) !== normEmail(a.email) ? ` AUX: ${code.codeEmail}` : '');
      lines.push(`${a.email}----${a.password || ''}${codeTag}`);
    }
    return lines.join('\n');
  }

  function copyText(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
        return;
      }
    } catch {}
    fallbackCopy(text);
  }
  function fallbackCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    } catch {}
  }

  function exportAccounts() {
    const text = buildExportText();
    if (!text) { setStatus('没有可导出的账号', true); return; }
    const count = text.split('\n').length;
    copyText(text);
    try {
      const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cockpit-accounts-${new Date().toISOString().slice(0, 10)}.txt`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch {}
    setStatus(`已导出 ${count} 个账号：已复制到剪贴板并下载 txt`);
  }

  $('export').addEventListener('click', exportAccounts);
  $('save').addEventListener('click', saveCurrent);
  $('manage').addEventListener('click', () => {
    const box = $('mgmt');
    const open = box.style.display !== 'block';
    box.style.display = open ? 'block' : 'none';
    if (open) renderManage();
    else closeEditForm();
  });

  $('fill').addEventListener('click', () => doFill({ manual: true }));
  $('again').addEventListener('click', () => {
    if (detectStep() !== 'code') { setStatus('「重填」只用于验证码步骤', true); return; }
    doFill({ manual: true });
  });

  async function doFill({ manual = false } = {}) {
    if (state.inFlight) return;
    const step = detectStep();
    if (!step) { setStatus('当前页面没有识别到输入框', true); refreshStep(); return; }
    const account = currentAccount();
    if (!account) { setStatus('请先在上方选择账号', true); return; }

    const marker = markerOf(step);
    const cooling = state.cooldownUntil.get(marker) || 0;
    if (cooling > Date.now()) {
      if (manual) {
        // 手动点击不受冷却限制，但要给反馈
        setStatus('刚失败过，正在重试…');
      } else {
        return;
      }
    }

    // 一次登录只确认一次：确认前绝不碰输入框；确认后同账号的后续步骤不再问
    if (state.confirmedAccount !== account.email) {
      const pwdLine = account.password ? `\n密码：${maskPassword(account.password)}` : '';
      const ok = window.confirm(`本次填入使用账号：\n${account.email}${pwdLine}\n\n确定吗？`);
      if (!ok) {
        state.autoDoneMarker = marker;
        state.cooldownUntil.set(marker, Date.now() + FAIL_COOLDOWN_MS);
        setStatus('已取消（本次不再自动重试，可手动点填入）', true);
        return;
      }
      state.confirmedAccount = account.email;
    }

    state.inFlight = true;
    try {
      if (detectStep() !== step) return;
      const msg = await fillStep(step, account);
      if (state.lastStep !== step) return;
      state.autoDoneMarker = marker;
      state.failCount.delete(marker);
      state.cooldownUntil.delete(marker);
      setStatus(msg);
    } catch (e) {
      const n = (state.failCount.get(marker) || 0) + 1;
      state.failCount.set(marker, n);
      state.cooldownUntil.set(marker, Date.now() + FAIL_COOLDOWN_MS);
      state.autoDoneMarker = marker;
      setStatus(`${e.message}${n >= FAIL_LIMIT ? '（自动填已停止，请手动处理）' : ''}`, true);
    } finally {
      state.inFlight = false;
      refreshStep();
    }
  }

  function maybeAutoFill() {
    if (!state.auto || state.inFlight) return;
    if (host.style.display === 'none') return;
    const step = detectStep();
    if (!step) return;
    const marker = markerOf(step);
    if (state.autoDoneMarker === marker) return;
    if ((state.cooldownUntil.get(marker) || 0) > Date.now()) return;
    if ((state.failCount.get(marker) || 0) >= FAIL_LIMIT) return;
    doFill({ manual: false });
  }

  let autoTimer = null;
  function scheduleAuto() {
    if (autoTimer) return;
    autoTimer = setTimeout(() => { autoTimer = null; maybeAutoFill(); }, 400);
  }

  let moTimer = null;
  new MutationObserver(() => {
    if (moTimer) return;
    moTimer = setTimeout(() => { moTimer = null; refreshStep(); maybeAutoFill(); }, 300);
  }).observe(document.documentElement, { childList: true, subtree: true });

  let lastUrl = location.href;
  function onUrlChange() {
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    // 不清标记：步骤变化由 refreshStep() 统一判定，避免重复确认/重复取码
    refreshStep();
    maybeAutoFill();
  }
  window.addEventListener('popstate', onUrlChange);
  window.addEventListener('hashchange', onUrlChange);
  setInterval(onUrlChange, 1000);

  // ---------- 面板开关：点 Tampermonkey 图标 → 菜单项 ----------
  let panelOpen = false;
  function setPanelOpen(v) {
    panelOpen = !!v;
    host.style.display = panelOpen ? '' : 'none';
    if (panelOpen) {
      const pasted = ($('paste') && $('paste').value || '').trim();
      if (pasted) applyPaste(pasted);
      refreshStep();
      if (!acctSel.value) setStatus('请选择要代填的账号', true);
      else if (!detectStep()) setStatus('当前页面没有识别到输入框', true);
      if (state.auto) scheduleAuto();
    }
  }
  function togglePanel() {
    panelOpen = !panelOpen;
    setPanelOpen(panelOpen);
  }
  try {
    if (typeof GM_registerMenuCommand === 'function') {
      GM_registerMenuCommand('Cockpit 自动填：打开/关闭面板', togglePanel);
    }
  } catch {}

  refreshStep();
  setStatus(ACCOUNTS.length
    ? `内嵌账号 ${ACCOUNTS.length} 个 · 选账号后点「填入」`
    : '把账号密码粘贴到上面的输入框，点「保存账号」即可长期使用');
  if (state.auto) scheduleAuto();
  if (typeof GM_registerMenuCommand !== 'function') {
    console.warn('[Cockpit 自动填] 当前环境不支持 GM_registerMenuCommand，面板将无法通过图标打开');
  }

    /* __DEBUG_HOOK_START__ */
  try {
    if (localStorage.getItem('cockpit_fill_debug') === '1') {
      window.__cockpitFill = {
        show() { setPanelOpen(true); },
        hide() { setPanelOpen(false); },
        select(email) { acctSel.value = email; acctSel.dispatchEvent(new Event('change')); },
        setPaste(text) { $('paste').value = text; applyPaste(text); },
        pasteValue: () => $('paste').value,
        parse: (text) => parsePasted(text),
        codeField: (v) => parseCodeField(v),
        who: () => $('who').textContent,
        setAuto(v) { $('auto').checked = !!v; $('auto').dispatchEvent(new Event('change')); },
        fill() { return doFill({ manual: true }); },
        step: () => detectStep(),
        badge: () => {
          const el = $('step');
          return el.style.display === 'none' ? '' : el.textContent;
        },
        selected: () => acctSel.value,
        save: () => saveCurrent(),
        saved: () => savedAccounts.map((x) => x.email),
        removeSaved: (email) => deleteSaved(email),
        hide: (email) => deleteEmbedded(email),
        hidden: () => hiddenAccounts.slice(),
        restore: (email) => restoreEmbedded(email),
        exportText: () => buildExportText(),
        pasteValue: () => $('paste').value,
        pasteInto(text) {
          const dt = new DataTransfer();
          dt.setData('text/plain', text);
          $('paste').dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
        },
        clip: () => $('clip').click(),
        sections: () => [...$('mgmt-list').querySelectorAll('.mgmt-title')].map((e) => e.textContent),
        confirmedAccount: () => state.confirmedAccount,
        updateAccount: (orig, fields) => updateAccount(orig, fields),
        twofaOf: (email) => {
          const a = allAccounts().find((x) => normEmail(x.email) === normEmail(email));
          return a ? (a.twofa || '') : '';
        },
        codeEmailOf: (email) => {
          const a = allAccounts().find((x) => normEmail(x.email) === normEmail(email));
          return a ? (a.codeEmail || '') : '';
        },
        totp: (secret) => totpCode(secret),
        export: () => exportAccounts(),
        mergeOpen: () => { $('manage').click(); },
        mergeItems: () => [...$('mgmt-list').querySelectorAll('.item span')].map((e) => e.textContent),
        status: () => $('st').textContent,
        accounts: () => allAccounts().map(a => a.email),
        panelOpen: () => panelOpen,
      };
    }
  } catch {}
  /* __DEBUG_HOOK_END__ */
})();
