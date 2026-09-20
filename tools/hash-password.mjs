#!/usr/bin/env node
// dsh-login-gate — 密码哈希工具（scrypt 自描述格式，兼容 dsh-gateway）
//
// 用法：
//   node tools/hash-password.mjs <密码>                  # 打印 scrypt$... 哈希
//   node tools/hash-password.mjs --write <用户名>        # 交互/参数生成并写入默认 users.json
//   node tools/hash-password.mjs --write <用户名> <密码> # 同上（密码作为第二个参数）
//   node tools/hash-password.mjs --write <用户名> --file /path/users.json [密码]
//
// users.json 格式：{ "用户名": "scrypt$16384$8$1$salt$hash" }
// 写入后执行：dsh plugin 对应配置生效无需重启（读取时每次从文件合并）；文件权限建议 0600。
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs'
import { dirname } from 'node:path'
import { createInterface } from 'node:readline/promises'
import { hashPassword } from '../lib/auth.js'
import { defaultUsersFile } from '../lib/users.js'

function usageExit(msg) {
  if (msg) console.error(msg)
  console.error('用法: node tools/hash-password.mjs <密码> | --write <用户名> [<密码>] [--file <users.json>]')
  process.exit(1)
}

async function promptPassword(username) {
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true })
  try {
    const pw = await rl.question(`为用户「${username}」设置密码: `)
    const again = await rl.question('再次输入确认: ')
    if (!pw || pw !== again) usageExit('两次输入不一致或为空')
    return pw
  } finally {
    rl.close()
  }
}

async function main() {
  const argv = process.argv.slice(2)
  if (!argv.length) usageExit()

  if (argv[0] === '--write') {
    const username = (argv[1] ?? '').trim()
    if (!username) usageExit('缺少用户名')
    let file = null
    let pwArg = null
    for (let i = 2; i < argv.length; i++) {
      if (argv[i] === '--file') { file = argv[++i] }
      else if (!pwArg) { pwArg = argv[i] }
    }
    file = file ?? defaultUsersFile()
    const password = pwArg ?? await promptPassword(username)
    const hash = hashPassword(password)

    let data = {}
    if (existsSync(file)) {
      try { data = JSON.parse(readFileSync(file, 'utf8')) } catch { console.error(`⚠️ ${file} 已存在但解析失败，将覆盖`) }
    }
    data[username] = hash
    mkdirSync(dirname(file), { recursive: true })
    writeFileSync(file, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 })
    try { chmodSync(file, 0o600) } catch { /* Windows 等平台忽略 */ }
    console.log(`已写入 ${file}`)
    console.log(`  ${username}: ${hash.slice(0, 24)}…（共 ${Object.keys(data).length} 个用户）`)
    console.log('提示：无需重启 dsh——门禁每次登录时从文件读取合并账号表。')
    return
  }

  const password = argv[0]
  if (!password || password.startsWith('--')) usageExit()
  console.log(hashPassword(password))
}

main().catch((e) => { console.error(e); process.exit(1) })
