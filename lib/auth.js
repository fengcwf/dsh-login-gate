// dsh-login-gate — 密码学基础：scrypt 密码哈希（自描述格式，兼容 dsh-gateway）+ HMAC 会话令牌
// 机制来源：clarknu/dsh-gateway lib/auth.js（scrypt$N$r$p$salt$hash + HMAC cookie）
//          Aztech-Lab/dsh-3301 lib/gate-auth.js（scrypt 参数与 fail-closed 校验）
import { createHash, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

export const SCRYPT_PREFIX = 'scrypt$'
// ~16MiB 工作集，显著高于交互式登录成本（dsh-3301 同款参数）
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 }

export const sha256 = (s) => createHash('sha256').update(String(s), 'utf8').digest()

const safeEqual = (a, b) => a.length === b.length && timingSafeEqual(a, b)

/** 把密码哈希为自描述 scrypt 字符串：scrypt$N$r$p$saltB64url$hashB64url */
export function hashPassword(password, params = {}) {
  const { N, r, p, keylen, maxmem } = { ...SCRYPT_PARAMS, ...params }
  const salt = randomBytes(16)
  const hash = scryptSync(String(password), salt, keylen, { N, r, p, maxmem })
  return `${SCRYPT_PREFIX}${N}$${r}$${p}$${salt.toString('base64url')}$${hash.toString('base64url')}`
}

/**
 * 恒时校验密码。stored 为 scrypt$... 哈希；明文值按 legacy 兼容（sha256 恒时比较，
 * 与 dsh-gateway 的迁移路径一致）；任何畸形输入一律 fail-closed 返回 false。
 */
export function verifyPassword(password, stored) {
  const s = String(stored ?? '')
  if (!s) return false
  if (s.startsWith(SCRYPT_PREFIX)) {
    const parts = s.slice(SCRYPT_PREFIX.length).split('$')
    if (parts.length !== 5) return false
    const [N, r, p, saltB64, hashB64] = parts
    const Nn = Number(N), rn = Number(r), pn = Number(p)
    if (!Number.isInteger(Nn) || Nn <= 0) return false
    if (!Number.isInteger(rn) || rn <= 0) return false
    if (!Number.isInteger(pn) || pn <= 0) return false
    let salt, expected
    try {
      salt = Buffer.from(saltB64, 'base64url')
      expected = Buffer.from(hashB64, 'base64url')
    } catch { return false }
    if (!salt.length || !expected.length) return false
    try {
      const derived = scryptSync(String(password), salt, expected.length, { N: Nn, r: rn, p: pn, maxmem: SCRYPT_PARAMS.maxmem })
      return safeEqual(derived, expected)
    } catch { return false } // 超大成本参数/maxmem 超限 → fail closed
  }
  return safeEqual(sha256(password), sha256(s))
}

const b64url = (buf) => Buffer.from(buf).toString('base64url')

/**
 * 会话管理器：HMAC-SHA256 签名令牌，payload={u,iat,exp}。
 * getSecret 每次签名/验签时实时读取——轮换 secret（logout-all）立即作废全部已发会话，
 * 无需重启监听（dsh-gateway 同款设计）。
 */
export function createSessionManager({ getSecret, cookieName = 'dlg_sid' }) {
  const sign = (payload) => createHmac('sha256', getSecret()).update(payload).digest()

  /** 签发会话令牌（ttlSeconds 秒有效） */
  function issue(username, ttlSeconds) {
    const payload = JSON.stringify({ u: username, iat: Date.now(), exp: Date.now() + ttlSeconds * 1000 })
    return `${b64url(Buffer.from(payload, 'utf8'))}.${b64url(sign(payload))}`
  }

  /** 校验 Cookie 头中的会话令牌；有效返回 payload({u,iat,exp})，否则 null */
  function verifyToken(token) {
    if (!token) return null
    const dot = token.indexOf('.')
    if (dot <= 0) return null
    let payloadBuf, sig
    try {
      payloadBuf = Buffer.from(token.slice(0, dot), 'base64url')
      sig = Buffer.from(token.slice(dot + 1), 'base64url')
    } catch { return null }
    if (!safeEqual(sig, sign(payloadBuf))) return null
    let payload
    try { payload = JSON.parse(payloadBuf.toString('utf8')) } catch { return null }
    if (!payload || typeof payload.u !== 'string' || typeof payload.exp !== 'number') return null
    if (Date.now() > payload.exp) return null
    return payload
  }

  /** 从 Cookie 请求头解析并校验本门禁会话 */
  function verifyCookie(cookieHeader) {
    if (!cookieHeader) return null
    const part = cookieHeader.split(';').map((p) => p.trim()).find((p) => p.startsWith(`${cookieName}=`))
    if (!part) return null
    return verifyToken(part.slice(cookieName.length + 1))
  }

  return { cookieName, issue, verifyToken, verifyCookie }
}
