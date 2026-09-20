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

/** 清理逐跳头 + 改写 Host/Origin + 合并/注入 Cookie */
function buildHeaders(req, { upstreamHost, upstreamPort, rewriteHost, nativeCookie, stripCookieNames }) {
  const out = {}
  for (const [k, v] of Object.entries(req.headers)) {
    if (HOP_BY_HOP.has(k.toLowerCase())) continue
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
  } = opts

  const wsAllowAll = wsAllow.includes('any')
  const wsRules = wsAllowAll ? [] : wsAllow.map((s) => new RegExp(s))
  const wsPermitted = (url) => wsAllowAll || wsRules.some((re) => re.test(url))

  /** HTTP 转发（req/res 来自门禁层，已通过认证） */
  async function forward(req, res) {
    const nativeCookie = await getNativeCookie()
    const headers = buildHeaders(req, { upstreamHost, upstreamPort, rewriteHost, nativeCookie, stripCookieNames })
    const proxy = httpRequest(
      { host: upstreamHost, port: upstreamPort, path: req.url, method: req.method, headers, timeout: 0 },
      (up) => {
        const upCtype = String(up.headers['content-type'] ?? '')
        const acceptGzip = /gzip/i.test(req.headers['accept-encoding'] ?? '')
        const upCompressed = Boolean(up.headers['content-encoding'])
        const compress = gzipPass && acceptGzip && !upCompressed &&
          /json|text|javascript|xml/.test(upCtype) && up.statusCode !== 204 && up.statusCode < 300
        if (compress) {
          const h = { ...up.headers }
          delete h['content-length']
          h['content-encoding'] = 'gzip'
          res.writeHead(up.statusCode, h)
          up.pipe(createGzip()).pipe(res)
        } else {
          res.writeHead(up.statusCode, up.headers)
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
    const headers = buildHeaders(req, { upstreamHost, upstreamPort, rewriteHost, nativeCookie, stripCookieNames })
    const tunnel = netConnect(upstreamPort, upstreamHost, () => {
      const headLines = [
        `${req.method} ${req.url} HTTP/1.1`,
        ...Object.entries(headers).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`),
        '',
        '',
      ].join('\r\n')
      tunnel.write(headLines)
      if (head && head.length) tunnel.write(head)
    })
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
