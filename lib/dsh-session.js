// dsh-login-gate — 原生 DSH 会话获取（转发层免 401 的关键）
// 版本实测记录（2026-09-21，dsh 0.1.5-rc.2 实机验证）：
//   - dsh web 的浏览器会话 = `GET /?token=<启动token>` → 303 + Set-Cookie
//     `dsh-auth-<b64url(sha256(authority))>=v1.<b64url(JSON{version,authority,issuedAt,expiresAt})>.<HMAC>`
//     （形状与 Aztech-Lab/dsh-3301 lib/dsh-session.js 描述一致；authority = 上游 host:port）
//   - ⚠️ 用 $DSH_HOME/.credentials.yaml 的 browser-session secret 自行铸造 HMAC 在该版本不被认可
//     （secret 选取或签名规范化与新版存在差异）→ 自铸降级为末位兜底
//   - ✅ token 兑换实测有效：真实 cookie 直连 GUI 200；门禁会话+注入该 cookie 经门禁转发亦 200
//   - token 由 ~/.dsh/start-dsh.sh 每次重启捕获并写入 $DSH_HOME/web-url.txt（600），
//     dsh-web.log 中亦有 `?token=` 行——两处实时读取，dsh 重启后自动跟随新 token
// 获取优先级（版本兼容链）：
//   B. token 兑换（本版本实测 ✅，优先）
//   A. 进程内官方 API ctx.connection.authenticatedUrl()（版本支持时）
//   C. credentials.yaml 自铸（dsh-3301 公式，兜底）
//   D. 均不可用 → 不注入 + 告警一次
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import http from 'node:http'

const RECORD_KEY = 'client-connection/browser-session'
const SECRET_BYTES = 32
const TTL_MS = 6 * 60 * 60 * 1000 // 注入 cookie 的内部刷新周期（真实 cookie 本身 30 天有效）

const b64url = (buf) => Buffer.from(buf).toString('base64url')

export function resolveDshHome() {
  return process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
}

export function resolveCredentialsFile() {
  return process.env.DSH_LOGIN_GATE_CREDENTIALS || path.join(resolveDshHome(), '.credentials.yaml')
}

function decodeSecret(value) {
  if (typeof value !== 'string') return undefined
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/')
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4)
  const buf = Buffer.from(padded, 'base64')
  return buf.length === SECRET_BYTES ? buf : undefined
}

/** 从凭据文件读取 browser-session 签名 secret（只读，兜底铸造模式用）。 */
export function readSigningSecret(file = resolveCredentialsFile()) {
  let text
  try { text = fs.readFileSync(file, 'utf8') } catch { return undefined }
  const at = text.indexOf(RECORD_KEY)
  if (at < 0) return undefined
  const m = /^\s*secret:\s*['"]?([A-Za-z0-9_-]{40,})['"]?\s*$/m.exec(text.slice(at))
  return m ? decodeSecret(m[1]) : undefined
}

/** 从文本中提取 dsh 启动 token（web-url.txt 或 dsh-web.log 的 ?token= 行） */
export function extractToken(text) {
  const m = /token=([A-Za-z0-9_-]{20,})/.exec(String(text ?? ''))
  return m ? m[1] : undefined
}

/** 内部请求：GET url 捕获首个 Set-Cookie */
function httpGetCookie(url) {
  return new Promise((resolve) => {
    let settled = false
    const done = (v) => { if (!settled) { settled = true; resolve(v) } }
    try {
      const req = http.get(url, { timeout: 5000 }, (res) => {
        const setCookie = res.headers['set-cookie']
        res.resume()
        if (!setCookie || !setCookie.length) return done(null)
        const first = String(setCookie[0]).split(';')[0]
        const eq = first.indexOf('=')
        if (eq <= 0) return done(null)
        done({ name: first.slice(0, eq).trim(), value: first.slice(eq + 1).trim() })
      })
      req.on('error', () => done(null))
      req.on('timeout', () => { req.destroy(); done(null) })
    } catch { done(null) }
  })
}

/**
 * 创建会话供给器。
 * @returns {{ ensure(): Promise<string|null>, invalidate(): void, mode(): string, authority: string }}
 *   ensure() 返回可直接追加到 Cookie 头的 "name=value"，无会话时 null。
 */
export function createDshSession({ ctx, upstreamPort, log }) {
  const authority = `127.0.0.1:${upstreamPort}`
  const dshHome = resolveDshHome()
  const tokenSources = [
    path.join(dshHome, 'web-url.txt'), // start-dsh.sh 每次重启更新（600）
    path.join(dshHome, 'dsh-web.log'),  // 兜底：日志中的 ?token= 行
  ]
  let name = null
  let value = null
  let refreshAt = 0
  let mode = 'D'
  let warned = false

  // —— 模式 B：token 兑换（dsh 0.1.5-rc.2 实测 ✅，优先） ——
  async function tryModeToken() {
    for (const file of tokenSources) {
      let token
      try { token = extractToken(fs.readFileSync(file, 'utf8')) } catch { continue }
      if (!token) continue
      const got = await httpGetCookie(`http://${authority}/?token=${token}`)
      if (got && got.value) {
        name = got.name
        value = got.value
        refreshAt = Date.now() + TTL_MS
        mode = 'B'
        return true
      }
    }
    return false
  }

  // —— 模式 A：官方 API 换取真实会话（版本支持时） ——
  async function tryModeApi() {
    try {
      if (typeof ctx?.connection?.authenticatedUrl !== 'function') return false
      const url = ctx.connection.authenticatedUrl()
      if (!url || typeof url !== 'string') return false
      const got = await httpGetCookie(url)
      if (!got || !got.value) return false
      name = got.name
      value = got.value
      refreshAt = Date.now() + TTL_MS
      mode = 'A'
      return true
    } catch { return false }
  }

  // —— 模式 C：credentials.yaml 自铸（dsh-3301 公式；该版本实测不被认可，仅兜底） ——
  function tryModeMint() {
    const secret = readSigningSecret()
    if (!secret) return false
    const body = JSON.stringify({ version: 1, authority, issuedAt: Date.now(), expiresAt: Date.now() + TTL_MS })
    name = 'dsh-auth-' + b64url(crypto.createHash('sha256').update(authority).digest())
    value = `v1.${b64url(Buffer.from(body, 'utf8'))}.${b64url(crypto.createHmac('sha256', secret).update(body).digest())}`
    refreshAt = Date.now() + TTL_MS * 0.5
    mode = 'C'
    return true
  }

  async function ensure() {
    if (name && value && Date.now() < refreshAt) return `${name}=${value}`
    name = null
    value = null
    const ok = (await tryModeToken()) || (await tryModeApi()) || tryModeMint()
    if (!ok) {
      mode = 'D'
      if (!warned) {
        warned = true
        log?.('未获取到原生 DSH 会话（token 兑换/官方API/自铸均失败）；GUI 请求可能 401。检查 $DSH_HOME/web-url.txt 是否存在且 dsh web 正在运行')
      }
      return null
    }
    return `${name}=${value}`
  }

  /** 上游 401 时调用：作废缓存，下次重新获取（dsh 重启换 token 后自愈） */
  function invalidate() {
    refreshAt = 0
    name = null
    value = null
  }

  return { ensure, invalidate, mode: () => mode, authority }
}
