// 从 2fa.nloop.cc 取指定邮箱当前的 ChatGPT 动态验证码（只读查询接口）
const ENDPOINT = 'https://2fa.nloop.cc/api/mfa/lookup';

export async function fetchCode(email, { minRemaining = 8 } = {}) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': 'cockpit-autologin/1.0' },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) throw new Error(`取码接口 HTTP ${res.status}`);
    const data = await res.json();
    if (!data.ok) throw new Error(`取码接口返回失败: ${JSON.stringify(data).slice(0, 200)}`);
    const item = (data.results || []).find(r => r.code);
    if (!item) throw new Error(`该邮箱没有可用的验证码记录: ${email}`);
    // 剩余秒数太少就等一下取下一轮，避免提交时刚好过期
    if (item.remaining != null && item.remaining < minRemaining && attempt < 2) {
      await new Promise(r => setTimeout(r, (item.remaining + 1) * 1000));
      continue;
    }
    return { code: item.code, remaining: item.remaining, period: item.period, email: item.email };
  }
  throw new Error('取码重试次数用尽');
}
