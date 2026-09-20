// dsh-login-gate — 用户账号加载：config.users ∪ usersFile（文件优先）
// 文件缺省 $DSH_HOME/login-gate/users.json（0600），JSON 格式 {"用户名": "scrypt$..."}
import { existsSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { SCRYPT_PREFIX } from './auth.js'

export function defaultUsersFile() {
  return join(process.env.DSH_HOME || join(homedir(), '.dsh'), 'login-gate', 'users.json')
}

/**
 * 合并账号表。返回 { users: {name: stored}, warnings: [] }
 * - usersFile 里的条目覆盖 config.users 同名项
 * - 明文密码仍可校验（legacy 兼容），但产生迁移警告
 * - 空用户名/空值条目跳过
 */
export function loadUsers({ users = {}, usersFile } = {}) {
  const out = {}
  const warnings = []
  const file = usersFile && String(usersFile).trim() ? String(usersFile).replace(/^~(?=\/)/, homedir()) : defaultUsersFile()

  for (const [k, v] of Object.entries(users ?? {})) {
    const name = String(k ?? '').trim()
    if (!name || !v) continue
    out[name] = String(v)
  }

  if (file && existsSync(file)) {
    try {
      const data = JSON.parse(readFileSync(file, 'utf8'))
      for (const [k, v] of Object.entries(data)) {
        const name = String(k ?? '').trim()
        if (!name || !v) continue
        out[name] = String(v)
      }
    } catch (e) {
      warnings.push(`usersFile 解析失败（${file}）：${e.message}`)
    }
  }

  for (const [name, stored] of Object.entries(out)) {
    if (!String(stored).startsWith(SCRYPT_PREFIX)) {
      warnings.push(`用户「${name}」的密码为明文存储，建议执行 node tools/hash-password.mjs 迁移为 scrypt$... 格式`)
    }
  }

  return { users: out, warnings, usersFile: file }
}

/**
 * 账号表供给器（热加载）：每次登录时按 usersFile 的 mtime 决定是否重新读取合并，
 * 因此 tools/hash-password.mjs --write 写入新用户后无需重启 dsh（dsh-gateway"配置热生效"同款体验）。
 * @returns {() => Record<string,string>} 返回当前账号表
 */
export function createUserProvider({ users = {}, usersFile } = {}) {
  const file = usersFile && String(usersFile).trim() ? String(usersFile).replace(/^~(?=\/)/, homedir()) : defaultUsersFile()
  let cached = null
  let cachedMtime = -1
  return () => {
    let mtime = -1
    try { mtime = existsSync(file) ? statSync(file).mtimeMs : -1 } catch { mtime = -1 }
    if (cached && mtime === cachedMtime) return cached
    const { users: merged } = loadUsers({ users, usersFile: file })
    cached = merged
    cachedMtime = mtime
    return cached
  }
}
