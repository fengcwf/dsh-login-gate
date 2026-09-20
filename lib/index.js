// dsh-login-gate — DeepSeek Harness 登录门禁插件（入口）
// 设计来源（源码分析见 README「致谢与机制来源」）：
//   clarknu/dsh-gateway    — scrypt 自描述哈希、HMAC 会话、secret 实时轮换、fail-closed
//   Aztech-Lab/dsh-3301    — 原生 DSH 会话获取（credentials.yaml 铸造 + authenticatedUrl API）、
//                             表单登录（密码每次登录只过线一次）、scrypt 参数、权限收紧
//   534119219/chicheng-gate— 门禁与 DSH 端口分层（网关端口 → 3080）、明文禁存
//   hongshuxifan321/dsh-mobile-app server/plugin — Cordis 插件生命周期（apply + ctx.effect）、
//                             Host/Origin loopback 改写、WS 隧道与逐跳头清理
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import { createSessionManager } from './auth.js'
import { createRateLimiter } from './ratelimit.js'
import { loadUsers, createUserProvider } from './users.js'
import { createDshSession } from './dsh-session.js'
import { createForwarder } from './proxy.js'
import { createGateServer } from './gate.js'

export const name = 'login-gate'
export const inject = [] // 不依赖宿主服务 API：任何 dsh 版本均可加载（会话注入走 A/B/C 兼容链）

export const Config = z.object({
  enabled: z.boolean().default(true),
  listenHost: z.string().default('127.0.0.1'),
  port: z.number().min(1).max(65535).default(3500),
  upstreamPort: z.number().min(1).max(65535).default(3080),
  rewriteHost: z.boolean().default(true),
  sessionDays: z.number().min(1).max(3650).default(30),
  maxFailures: z.number().min(1).default(5),
  secureCookie: z.boolean().default(true),
  wsAllow: z.array(z.string()).default(['^/api/']),
  gzipPass: z.boolean().default(true),
  users: z.record(z.string(), z.string()).default({}),
  usersFile: z.string().optional(),
})

function gateDir() {
  return join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'login-gate')
}
function secretFile() {
  return join(gateDir(), 'secret')
}

/** 读取或创建会话签名 secret（0600） */
function loadOrCreateSecret() {
  const f = secretFile()
  try {
    if (existsSync(f)) {
      const v = readFileSync(f, 'utf8').trim()
      if (v) return v
    }
  } catch { /* fallthrough: 重新生成 */ }
  const secret = randomBytes(32).toString('base64')
  try {
    mkdirSync(gateDir(), { recursive: true })
    writeFileSync(f, secret, { mode: 0o600 })
  } catch { /* 只读文件系统等：退回内存 secret（重启后会话失效，不影响可用性） */ }
  return secret
}

/** 防御性归一化：宿主未做 schema 校验时也能工作 */
function normalize(raw) {
  const c = raw ?? {}
  return {
    enabled: c.enabled !== false,
    listenHost: typeof c.listenHost === 'string' && c.listenHost ? c.listenHost : '127.0.0.1',
    port: Number.isInteger(c.port) && c.port > 0 ? c.port : 3500,
    upstreamPort: Number.isInteger(c.upstreamPort) && c.upstreamPort > 0 ? c.upstreamPort : 3080,
    rewriteHost: c.rewriteHost !== false,
    sessionDays: Number.isInteger(c.sessionDays) && c.sessionDays > 0 ? c.sessionDays : 30,
    maxFailures: Number.isInteger(c.maxFailures) && c.maxFailures > 0 ? c.maxFailures : 5,
    secureCookie: c.secureCookie !== false,
    wsAllow: Array.isArray(c.wsAllow) && c.wsAllow.length ? c.wsAllow.map(String) : ['^/api/'],
    gzipPass: c.gzipPass !== false,
    users: c.users && typeof c.users === 'object' ? c.users : {},
    usersFile: typeof c.usersFile === 'string' && c.usersFile ? c.usersFile : undefined,
  }
}

export function apply(ctx, rawConfig) {
  const cfg = normalize(rawConfig)
  if (!cfg.enabled) return

  const log = (...args) => {
    const line = args.join(' ')
    try { ctx.logger?.info?.(line) } catch { /* logger 不可用时仅控制台 */ }
    console.log('[login-gate] ' + line)
  }

  const { users, warnings, usersFile } = loadUsers({ users: cfg.users, usersFile: cfg.usersFile })
  warnings.forEach((w) => log('⚠️ ' + w))
  // 热加载账号表：usersFile 变更（hash-password.mjs --write）无需重启
  const getUsers = createUserProvider({ users: cfg.users, usersFile: cfg.usersFile })

  // secret 持有器：logout-all 时轮换并持久化 → 全部已发会话立即作废（dsh-gateway 机制）
  const holder = { secret: loadOrCreateSecret() }
  const rotateSecret = () => {
    holder.secret = randomBytes(32).toString('base64')
    try { writeFileSync(secretFile(), holder.secret, { mode: 0o600 }) } catch { /* 内存态轮换 */ }
  }

  const sessions = createSessionManager({ getSecret: () => holder.secret })
  const limiter = createRateLimiter({ maxFailures: cfg.maxFailures })
  const dshSession = createDshSession({ ctx, upstreamPort: cfg.upstreamPort, log })
  const strip = new Set([sessions.cookieName]) // 门禁会话 cookie 不转发给上游
  const forwarder = createForwarder({
    upstreamHost: '127.0.0.1',
    upstreamPort: cfg.upstreamPort,
    rewriteHost: cfg.rewriteHost,
    gzipPass: cfg.gzipPass,
    wsAllow: cfg.wsAllow,
    getNativeCookie: () => dshSession.ensure(),
    stripCookieNames: strip,
    onUpstreamUnauthorized: () => dshSession.invalidate(),
  })

  const userCount = Object.keys(users).length
  if (userCount === 0) {
    log(`⚠️ 未配置任何登录用户（fail-closed）：所有人将看到配置提示页。配置方式：`)
    log(`   1) usersFile（推荐）：node tools/hash-password.mjs --write <用户名>   生成并写入 ${usersFile}`)
    log(`   2) 或在 settings.yaml 的 login-gate 配置里填写 users（值为 scrypt$... 哈希）`)
  }

  ctx.effect(() => {
    const server = createGateServer({
      users,
      getUsers,
      sessions,
      limiter,
      forwarder,
      onLogoutAll: rotateSecret,
      sessionMode: () => dshSession.mode(),
      secureCookie: cfg.secureCookie,
      sessionDays: cfg.sessionDays,
      log,
    })
    server.on('error', (e) => log(`门禁监听失败：${e.message}（检查端口 ${cfg.port} 是否被占用/监听地址是否可用）`))
    try {
      server.listen(cfg.port, cfg.listenHost, () => {
        log(`登录门禁已启动：http://${cfg.listenHost}:${cfg.port} → 127.0.0.1:${cfg.upstreamPort}`)
        log(`账号数：${userCount}（usersFile: ${usersFile}）；会话 ${cfg.sessionDays} 天；失败锁定：连续 ${cfg.maxFailures} 次后指数退避`)
        log(`反代姿态：Host/Origin 改写=${cfg.rewriteHost ? '开（loopback 形式，安全边界=本门禁登录）' : '关（需自行配置 dsh trustedHosts）'}；WS 放行：${cfg.wsAllow.join(', ')}`)
      })
    } catch (e) {
      log(`门禁启动异常：${e.message}`)
    }
    return () => {
      try { server.close() } catch { /* 已关闭 */ }
      log('已停止（登录门禁已关闭）')
    }
  }, 'login-gate: 表单登录门禁与认证反代')
}
