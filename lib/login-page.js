// dsh-login-gate — 登录页（内嵌 HTML，移动端友好，零外部依赖/零外链）
export function renderLogin({ error = '', next = '/', usersConfigured = true, title = 'DSH 登录', sessionDays = 30 } = {}) {
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))
  const nextVal = String(next).startsWith('/') && !String(next).startsWith('//') ? String(next) : '/'
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
<title>${esc(title)}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
         background:#0f1115; color:#e8eaed; }
  .card { width:min(92vw,360px); background:#181b22; border:1px solid #2a2e38; border-radius:14px;
          padding:28px 24px; box-shadow:0 8px 30px rgba(0,0,0,.35); }
  h1 { margin:0 0 4px; font-size:20px; font-weight:600; }
  .sub { margin:0 0 20px; font-size:13px; color:#9aa0aa; }
  label { display:block; font-size:13px; color:#9aa0aa; margin:14px 0 6px; }
  input { width:100%; padding:11px 12px; border-radius:9px; border:1px solid #343a46;
          background:#0f1115; color:#e8eaed; font-size:15px; outline:none; }
  input:focus { border-color:#4c8dff; }
  button { width:100%; margin-top:22px; padding:12px; border-radius:9px; border:none;
           background:#2f6feb; color:#fff; font-size:15px; font-weight:600; cursor:pointer; }
  button:active { opacity:.85; }
  .err { margin-top:14px; padding:10px 12px; border-radius:8px; background:#3a1d22;
         border:1px solid #6b2c33; color:#ff9ba3; font-size:13px; }
  .warn { margin-top:14px; padding:10px 12px; border-radius:8px; background:#3a331d;
          border:1px solid #6b5f2c; color:#e8d48a; font-size:13px; }
  .foot { margin-top:18px; font-size:11px; color:#6b7280; text-align:center; }
</style>
</head>
<body>
  <div class="card">
    <h1>${esc(title)}</h1>
    <p class="sub">DeepSeek Harness · 登录后进入网页端</p>
    ${usersConfigured ? '' : '<div class="warn">尚未配置登录用户：请在 DSH 设置或 users.json 中配置账号后重试（fail-closed：未配置时任何人都无法进入）。</div>'}
    ${error ? `<div class="err">${esc(error)}</div>` : ''}
    <form method="POST" action="/__gate/login" autocomplete="on">
      <input type="hidden" name="next" value="${esc(nextVal)}">
      <label for="u">用户名</label>
      <input id="u" name="u" type="text" autocomplete="username" autocapitalize="none" required ${usersConfigured ? '' : 'disabled'}>
      <label for="p">密码</label>
      <input id="p" name="p" type="password" autocomplete="current-password" required ${usersConfigured ? '' : 'disabled'}>
      <button type="submit" ${usersConfigured ? '' : 'disabled'}>登 录</button>
    </form>
    <div class="foot">dsh-login-gate · 表单登录 · 登录后约 ${Number(sessionDays) || 30} 天内免登录</div>
  </div>
</body>
</html>`
}
