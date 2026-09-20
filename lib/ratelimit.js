// dsh-login-gate — 每 IP 登录失败锁定：连续失败达阈值后指数退避
// 机制来源：mobile-remote proxy.js（fail bucket + 退避）、dsh-gateway auth.js（fail buckets）、
//          dsh-3301（maxFailures/lockoutMinutes 配置化）

export function createRateLimiter({ maxFailures = 5, baseLockMs = 30_000, maxLockMs = 300_000 } = {}) {
  const buckets = new Map() // ip -> { fails, lockedUntil }
  const now = () => Date.now()

  /** 检查 IP 是否被锁定；{ ok } 或 { ok:false, retryAfter(秒) } */
  function check(ip) {
    const b = buckets.get(ip)
    if (!b || !b.lockedUntil) return { ok: true }
    if (b.lockedUntil > now()) return { ok: false, retryAfter: Math.max(1, Math.ceil((b.lockedUntil - now()) / 1000)) }
    return { ok: true }
  }

  /** 记录一次失败；达到阈值后按 30s * 2^(超出次数) 退避，上限 maxLockMs */
  function recordFailure(ip) {
    const b = buckets.get(ip) ?? { fails: 0, lockedUntil: 0 }
    b.fails += 1
    if (b.fails >= maxFailures) {
      const over = b.fails - maxFailures
      b.lockedUntil = now() + Math.min(baseLockMs * 2 ** over, maxLockMs)
    }
    buckets.set(ip, b)
    prune()
  }

  /** 登录成功：清除该 IP 记录 */
  function recordSuccess(ip) {
    buckets.delete(ip)
  }

  /** 防内存膨胀：清理过期且未锁定的桶 */
  function prune() {
    if (buckets.size <= 4096) return
    const cutoff = now() - maxLockMs
    for (const [ip, b] of buckets) {
      if (b.lockedUntil < cutoff && b.fails < maxFailures) buckets.delete(ip)
    }
  }

  return { check, recordFailure, recordSuccess }
}
