// dsh-login-gate — 原生 DSH 会话获取（转发层免 401 的关键）
// 机制来源：Aztech-Lab/dsh-3301 lib/dsh-session.js 与 lib/plugin.js
//   "DSH 1.2+ 用签名且绑定 authority 的 cookie 认证每个 GUI 请求；仅改写 Host/Origin 的
//    反代转发的流量会被 DSH 以 401 拒绝——代理必须持有自己的真实会话。"
//   cookie 形状（dsh-client-connection 自身签发的形状）：
//     name  = "dsh-auth-" + base64url(sha256(authority))
//     value = "v1." + base64url(JSON{version,authority,issuedAt,expiresAt})
//                 + "." + base64url(HMAC-SHA256(secret, body))
//   secret 存于 $DSH_HOME/.credentials.yaml 的 client-connection/browser-session 记录。
// 三级获取策略（版本兼容优先）：
//   A. 进程内官方 API ctx.connection.authenticatedUrl() → 内部换取真实 Set-Cookie
//   B. 读凭据文件按上述形状自铸 loopback authority 会话
//   C. 均不可用 → 不注入（旧版 dsh 对 loopback 来源可能免鉴权），并告警一次
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import http from 'node:http'

const RECORD_KEY = 'client-connection/browser-session'
const SECRET_BYTES = 32
const TTL_MS = 6 * 60 * 60 * 1000 // 6h 会话，半周期刷新

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

/**
 * 从凭据文件读取 browser-session 签名 secret。
 * 只读取 client-connection/browser-session 记录之后的第一条 secret: 行，
 * 不触碰其他凭据条目；删除/轮换该记录会使已铸会话立即失效。
 */
export function readSigningSecret(file = resolveCredentialsFile()) {
  let text
  try { text = fs.readFileSync(file, 'utf8') } catch { return undefined }
  const at = text.indexOf(RECORD_KEY)
  if (at < 0) return undefined
  const m = /^\s*secret:\s*['"]?([A-Za-z0-9_-]{40,})['"]?\s*$/m.exec(text.slice(at))
  return m ? decodeSecret(m[1]) : undefined
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
 * @returns {{ ensure(): Promise<string|null>, mode(): string, authority: string }}
 *   ensure() 返回可直接追加到 Cookie 头的 "name=value"，无会话时 null。
 */
export function createDshSession({ ctx, upstreamPort, log }) {
  const authority = `127.0.0.1:${upstreamPort}`
  let name = null
  let value = null
  let refreshAt = 0
  let mode = 'C'
  let warned = false

  // —— 模式 B：凭据文件自铸（同步、零依赖，作为主路径） ——
  function tryModeB() {
    const secret = readSigningSecret()
    if (!secret) return false
    const body = JSON.stringify({ version: 1, authority, issuedAt: Date.now(), expiresAt: Date.now() + TTL_MS })
    name = 'dsh-auth-' + b64url(crypto.createHash('sha256').update(authority).digest())
    value = `v1.${b64url(Buffer.from(body, 'utf8'))}.${b64url(crypto.createHmac('sha256', secret).update(body).digest())}`
    refreshAt = Date.now() + TTL_MS * 0.5
    mode = 'B'
    return true
  }

  // —— 模式 A：官方 API 换取真实会话（版本支持时优先） ——
  async function tryModeA() {
    try {
      if (typeof ctx?.connection?.authenticatedUrl !== 'function') return false
      const url = ctx.connection.authenticatedUrl()
      if (!url || typeof url !== 'string') return false
      const got = await httpGetCookie(url)
      if (!got || !got.value) return false
      name = got.name
      value = got.value
      refreshAt = Date.now() + TTL_MS * 0.5
      mode = 'A'
      return true
    } catch { return false }
  }

  async function ensure() {
    if (name && value && Date.now() < refreshAt) return `${name}=${value}`
    name = null
    value = null
    const ok = (await tryModeA()) || tryModeB()
    if (!ok) {
      mode = 'C'
      if (!warned) {
        warned = true
        log?.('[login-gate] 未获取到原生 DSH 会话凭证（ctx.connection API 与 .credentials.yaml 均不可用），按无注入模式转发；若 GUI 请求出现 401，请检查 dsh 版本与 $DSH_HOME/.credentials.yaml')
      }
      return null
    }
    return `${name}=${value}`
  }

  return { ensure, mode: () => mode, authority }
}
