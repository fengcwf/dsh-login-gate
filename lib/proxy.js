// dsh-login-gate — 认证反代：HTTP 转发 + WebSocket 隧道
// 机制来源：mobile-remote lib/proxy.js（Host/Origin 改写、WS 裸流隧道、gzip 直通、
//          hop-by-hop 头清理）+ dsh-gateway lib/proxy.js（网关在前的转发姿态）
// 与参考实现的差异：认证层是「表单 + Cookie 会话」而非 Basic Auth——
//   浏览器/WebView 的 WS 握手会自动携带 Cookie，因此无需 mobile-remote 的
//   /__dsh_ws_token 种 cookie 技巧（那是 Basic Auth 不随 WS 发送的补偿方案）。
import { request as httpRequest } from 'node:http'
import { connect as netConnect } from 'node:net'
import { createGzip } from 'node:zlib'

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])

/**
 * 构造转发请求头。
 * @param {boolean} upgrade  升级请求（WS 握手）时必须 true：
 *   完整保留原始头（含 connection/upgrade/sec-websocket-*）——RFC 6455 握手依赖
 *   `Connection: Upgrade` + `Upgrade: websocket`，剥离后上游按普通 GET 处理 →
 *   404 → 前端连接恢复机制无限退避重连（"自动重连"常驻）。
 * 普通转发时剥离静态 hop-by-hop 头 + RFC 7230 §6.1：Connection 头动态列出的名字。
 */
function buildHeaders(req, { upstreamHost, upstreamPort, rewriteHost, nativeCookie, stripCookieNames, upgrade = false }) {
  const connListed = new Set()
  if (!upgrade) {
    for (const part of String(req.headers.connection ?? '').split(',')) {
      const name = part.trim().toLowerCase()
      if (name && !HOP_BY_HOP.has(name)) connListed.add(name)
    }
  }
  const out = {}
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase()
    if (!upgrade && (HOP_BY_HOP.has(key) || connListed.has(key))) continue
    out[k] = v
  }
  if (rewriteHost) {
    out.host = `${upstreamHost}:${upstreamPort}`
    if (out.origin) out.origin = `http://${upstreamHost}:${upstreamPort}`
    if (out.referer) {
      try {
        const u = new URL(out.referer)
        out.referer = `http://${upstreamHost}:${upstreamPort}${u.pathname}${u.search}`
      } catch { /* referer 非法时保持原值 */ }
    }
  }
  // Cookie 处理：剔除本门禁的会话 cookie（不外泄给上游）+ 追加原生 DSH 会话
  const raw = req.headers.cookie
  const parts = String(raw ?? '').split(';').map((p) => p.trim()).filter(Boolean)
    .filter((p) => {
      const eq = p.indexOf('=')
      if (eq <= 0) return true
      return !stripCookieNames.has(p.slice(0, eq).trim())
    })
  if (nativeCookie) parts.push(nativeCookie)
  if (parts.length) out.cookie = parts.join('; ')
  else delete out.cookie
  return out
}

/**
 * 创建转发器。
 * @param {object} opts
 * @param {string} opts.upstreamHost  上游主机（127.0.0.1）
 * @param {number} opts.upstreamPort  上游端口（3080）
 * @param {boolean} opts.rewriteHost  Host/Origin 改写为 loopback
 * @param {boolean} opts.gzipPass     大 JSON/文本透明 gzip
 * @param {string[]} opts.wsAllow     WS 放行正则；['any'] 表示全部放行
 * @param {() => Promise<string|null>} opts.getNativeCookie  原生 DSH 会话注入
 * @param {Set<string>} opts.stripCookieNames  不转发给上游的 cookie 名
 */
export function createForwarder(opts) {
  const {
    upstreamHost = '127.0.0.1',
    upstreamPort = 3080,
    rewriteHost = true,
    gzipPass = true,
    wsAllow = ['^/api/'],
    getNativeCookie = async () => null,
    stripCookieNames = new Set(),
    onUpstreamUnauthorized = null,
  } = opts

  const wsAllowAll = wsAllow.includes('any')
  const wsRules = wsAllowAll ? [] : wsAllow.map((s) => new RegExp(s))
  const wsPermitted = (url) => wsAllowAll || wsRules.some((re) => re.test(url))

  // 上游绝对 Location 改写：防止 `http://127.0.0.1:3080/...` 这类 loopback 地址漏给浏览器
  const rewriteLocation = (loc) => {
    if (typeof loc !== 'string') return loc
    const clean = loc.replace(/[\r\n]/g, '')
    try {
      const u = new URL(clean)
      if (u.host === `${upstreamHost}:${upstreamPort}` || u.host === upstreamHost) {
        return `${u.pathname}${u.search}${u.hash}`
      }
      return clean
    } catch { return clean }
  }
  const fixRespHeaders = (h) => {
    if (h.location) {
      h.location = Array.isArray(h.location) ? h.location.map(rewriteLocation) : rewriteLocation(h.location)
    }
    return h
  }

  /** HTTP 转发（req/res 来自门禁层，已通过认证） */
  async function forward(req, res) {
    const nativeCookie = await getNativeCookie()
    const headers = buildHeaders(req, { upstreamHost, upstreamPort, rewriteHost, nativeCookie, stripCookieNames, upgrade: false })
    const proxy = httpRequest(
      { host: upstreamHost, port: upstreamPort, path: req.url, method: req.method, headers, timeout: 0 },
      (up) => {
        // 上游 401 自愈：dsh 重启换 token 后，作废缓存的注入会话并用新会话重试一次（仅幂等请求）
        if (up.statusCode === 401 && !req.__dlgRetried &&
            (req.method === 'GET' || req.method === 'HEAD') && typeof onUpstreamUnauthorized === 'function') {
          req.__dlgRetried = true
          up.resume()
          onUpstreamUnauthorized()
          forward(req, res)
          return
        }
        const upCtype = String(up.headers['content-type'] ?? '')
        const acceptGzip = /gzip/i.test(req.headers['accept-encoding'] ?? '')
        const upCompressed = Boolean(up.headers['content-encoding'])
        const compress = gzipPass && acceptGzip && !upCompressed &&
          /json|text|javascript|xml/.test(upCtype) && up.statusCode !== 204 && up.statusCode < 300
        if (compress) {
          const h = fixRespHeaders({ ...up.headers })
          delete h['content-length']
          h['content-encoding'] = 'gzip'
          res.writeHead(up.statusCode, h)
          up.pipe(createGzip()).pipe(res)
        } else {
          res.writeHead(up.statusCode, fixRespHeaders({ ...up.headers }))
          up.pipe(res)
        }
      }
    )
    proxy.on('error', (e) => {
      if (!res.headersSent) { res.writeHead(502); res.end('bad gateway: ' + e.message) }
      else res.destroy()
    })
    proxy.on('timeout', () => proxy.destroy(new Error('upstream timeout')))
    req.pipe(proxy)
  }

  /** WebSocket 隧道（upgrade 事件；调用方已完成会话校验） */
  async function forwardUpgrade(req, socket, head) {
    if (!wsPermitted(req.url)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n')
      socket.destroy()
      return
    }
    const nativeCookie = await getNativeCookie()
    // upgrade:true → 完整保留 connection/upgrade/sec-websocket-* 原始头（WS 握手必需）；
    // 下方的兜底赋值在正常情况下是等值覆写，异常情况下保证握手头存在。
    const headers = buildHeaders(req, { upstreamHost, upstreamPort, rewriteHost, nativeCookie, stripCookieNames, upgrade: true })
    headers['connection'] = 'Upgrade'
    headers['upgrade'] = req.headers.upgrade || 'websocket'
    const tunnel = netConnect({ port: upstreamPort, host: upstreamHost, timeout: 5000 }, () => {
      const headLines = [
        `${req.method} ${req.url} HTTP/1.1`,
        ...Object.entries(headers).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`),
        '',
        '',
      ].join('\r\n')
      tunnel.write(headLines)
      if (head && head.length) tunnel.write(head)
    })
    tunnel.on('timeout', () => tunnel.destroy(new Error('ws tunnel connect timeout')))
    const teardown = () => { socket.destroy(); tunnel.destroy() }
    tunnel.on('error', teardown)
    socket.on('error', teardown)
    socket.on('close', teardown)
    tunnel.on('close', teardown)
    socket.pipe(tunnel)
    tunnel.pipe(socket)
  }

  return { forward, forwardUpgrade, wsPermitted }
}
