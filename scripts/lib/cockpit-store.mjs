// 只读访问 Cockpit Tools 的账号库（AES-256-GCM），仅用于取出邮箱/密码/取码链接。
// 不会写入任何 Cockpit Tools 文件。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

export const COCKPIT_DIR = path.join(os.homedir(), '.cockpit_tools');

function readKey() {
  const raw = fs.readFileSync(path.join(COCKPIT_DIR, 'secure-account-storage.key'), 'utf8').trim();
  return Buffer.from(raw, 'base64');
}

function decrypt(filePath, key) {
  const d = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!d.nonce || !d.ciphertext) throw new Error('不是加密账号文件');
  const nonce = Buffer.from(d.nonce, 'base64');
  const ct = Buffer.from(d.ciphertext, 'base64');
  const tag = ct.subarray(ct.length - 16);
  const body = ct.subarray(0, ct.length - 16);
  const dec = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  dec.setAuthTag(tag);
  return JSON.parse(Buffer.concat([dec.update(body), dec.final()]).toString('utf8'));
}

/** 列出所有 codex 账号（只读） */
export function listCodexAccounts() {
  const key = readKey();
  const dir = path.join(COCKPIT_DIR, 'codex_accounts');
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.json') || f.endsWith('.bak')) continue;
    try {
      const o = decrypt(path.join(dir, f), key);
      out.push({
        id: o.id,
        email: o.email,
        password: o.account_password || '',
        mailUrl: o.mail_url || '',
        authMode: o.auth_mode || '',
        plan: o.plan_type || '',
        file: f,
      });
    } catch { /* 跳过无法解密的文件 */ }
  }
  return out.sort((a, b) => a.email.localeCompare(b.email));
}

/** 按邮箱查账号，支持前缀/模糊匹配 */
export function findAccount(query) {
  const all = listCodexAccounts();
  const q = String(query || '').toLowerCase().trim();
  if (!q) return all;
  return all.filter(a =>
    a.email.toLowerCase() === q ||
    a.email.toLowerCase().startsWith(q) ||
    a.email.toLowerCase().includes(q));
}
