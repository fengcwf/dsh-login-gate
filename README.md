# dsh-login-gate

DeepSeek Harness（DSH）**表单登录门禁插件**：为 `dsh web` 网页端提供「用户名 + 密码」登录入口，配合 Lucky / Nginx 反向代理实现外网 HTTPS 安全访问。多用户、多会话、每 IP 锁定、fail-closed，**不使用 HTTP Basic Auth**。

```
手机 APK / 浏览器
   │ HTTPS https://dsh.fengcwf.cn（Lucky：ACME 证书 + 反代，Host 模式「使用请求Host」）
   ▼ http://127.0.0.1:3500
dsh-login-gate（dsh 进程内插件）
   表单登录（scrypt 校验 + 每 IP 指数退避锁定）→ HMAC 签名会话 Cookie（HttpOnly）
   ▼ 认证反代（Host/Origin 改写为 loopback + 原生 DSH 会话注入 + WS 透传）
dsh web 127.0.0.1:3080（保持仅回环监听，官方安全模型不变）
```

## 功能

- **表单登录**：密码每次登录只过线一次，之后为签名会话 Cookie（默认 30 天）——区别于 Basic Auth 每请求携带
- **多用户**：`users.json` 账号表（推荐）或配置文件 `users`；**热加载**——写入新账号无需重启
- **密码存储**：scrypt 自描述哈希 `scrypt$16384$8$1$salt$hash`（与 dsh-gateway 格式兼容），恒时比较，畸形输入 fail-closed；明文仅 legacy 兼容并告警
- **会话管理**：HMAC-SHA256 签名令牌；**logout-all 轮换签名 secret，一键作废全部已登录设备**
- **爆破防护**：每 IP 连续失败 ≥5 次后指数退避锁定（30s 起、上限 300s）；用户名未命中时执行等耗时哑校验，防用户名枚举
- **认证反代**：Host/Origin 改写为 loopback 形式（设置面板远程完整可用）；**原生 DSH 会话注入**（三级兼容链，见下）；WebSocket 透传（会话 Cookie 随握手自动携带，无 Basic Auth 的 WS 缺失问题）；大体积 JSON/文本透明 gzip
- **fail-closed**：未配置任何用户时，所有人只能看到配置提示页
- **安全默认**：监听 `127.0.0.1`（公网入口交给 Lucky）；门禁会话 Cookie 不转发给上游；`__gate` 端点外的一切路径均需登录

## 原生 DSH 会话注入（为什么需要）

dsh-3301 项目实证：新版 DSH 用**签名且绑定 authority 的 cookie** 认证每个 GUI 请求，仅改写 Host 的外部反代会被 401 拒绝——网关必须持有自己的真实会话。本插件按版本兼容性依次尝试：

| 模式 | 机制 | 来源 |
|---|---|---|
| A | 进程内官方 API `ctx.connection.authenticatedUrl()` 内部换取真实 Set-Cookie | dsh-3301 plugin.js |
| B | 读 `$DSH_HOME/.credentials.yaml` 的 `client-connection/browser-session` secret，按 `dsh-auth-<b64url(sha256(authority))> = v1.<b64url(JSON)>.<b64url(HMAC)>` 铸造 loopback 会话（6h 半周期刷新） | dsh-3301 dsh-session.js |
| C | 均不可用 → 不注入并告警一次（旧版 dsh 对 loopback 来源可能免鉴权） | 兜底 |

查看当前模式：`curl http://127.0.0.1:3500/__gate/health` → `{"ok":true,"users":N,"mode":"A|B|C"}`

## 安装

```sh
dsh plugin --profile web add github:fengcwf/dsh-login-gate
```

重启 dsh web 后，插件按 `cordis.patch.yml` 自动挂载（`login-gate` 配置段可在 settings.yaml 中修改）。

### 配置账号（推荐 usersFile 方式）

```sh
node <插件目录>/tools/hash-password.mjs --write alice
node <插件目录>/tools/hash-password.mjs --write bob
# 写入 $DSH_HOME/login-gate/users.json（0600），格式 {"alice":"scrypt$...","bob":"scrypt$..."}
# 热加载：无需重启
```

### Lucky 反向代理配置

1. Web 服务 → 新增反代规则：域名 `dsh.fengcwf.cn` → 目标 `http://127.0.0.1:3500`；
2. **Host 自定义模式选「使用请求Host」**（Lucky 官方 Web 模块要求，核对非默认端口无丢失）；
3. WebSocket：默认开启，无需额外开关；
4. HTTPS/证书：Lucky ACME 给该子域签发；
5. **不要**在 Lucky 上再配置 BasicAuth（认证由本插件承担，双层只会双重登录）。

> Lucky 与 DSH 不在同一台机器时：把插件 `listenHost` 改为可信私网 IP，并用防火墙限制来源为 Lucky 的私网地址。

## 端点

| 端点 | 说明 |
|---|---|
| `GET /__gate/login` | 登录页（已登录自动跳回 next） |
| `POST /__gate/login` | 校验账号密码 → Set-Cookie → 跳回原地址 |
| `POST /__gate/logout` | 注销当前会话 |
| `POST /__gate/logout-all` | 轮换 secret，作废**全部**已登录设备（需已登录） |
| `GET /__gate/health` | 健康检查（无认证）：`{ok, users, mode}` |
| `GET /__gate/status` | 当前会话信息（需登录） |

## 安全模型

- **本门禁（表单登录）是唯一认证边界**：Host/Origin 改写为 loopback 后，DSH 视所有通过门禁的请求为本机来源（设置面板因此在远程完整可用）——与 dsh-gateway / dsh-3301 / dsh-mobile-app 认证代理同构；
- **多用户 = 多账号共享同一 DSH 实例**：登录后所有账号看到同一套会话/工作区/文件/终端（DSH 为单用户设计）。需要数据隔离时，请为每用户部署独立 dsh 实例 + 反代按子域路由；
- 会话 secret 存 `$DSH_HOME/login-gate/secret`（0600）；凭据文件 `$DSH_HOME/.credentials.yaml` 仅被**读取**用于铸造会话，删除该记录会使注入会话立即失效；
- Lucky 层建议叠加：强密码（≥16 位随机）+（可选）访问 IP 限制；`secureCookie` 在 HTTPS 部署下保持 `true`。

## 与 Android 壳（dsh-mobile-app 等 WebView APK）的配合

WebView 壳打开 `https://dsh.fengcwf.cn` → 显示本插件登录页（标准网页表单）→ 登录后 `dlg_sid` Cookie（HttpOnly）由 WebView 持久化，之后打开即进。壳的 HttpAuth 自动登录逻辑在此模式下不再使用（可从 fork 中移除）；WebSocket 握手自动携带 Cookie，实时事件无需额外处理。

## 已验证（本仓库开发环境实测）

- scrypt 哈希往返 / 错误密码拒绝 / 畸形哈希 fail-closed
- 会话签发-校验 / secret 轮换立即作废全部会话
- 每 IP 锁定（429 + Retry-After）/ 其他 IP 不受影响
- usersFile 热加载（mtime 缓存）
- 端到端：未登录 302 → 登录页；登录成功 Set-Cookie 跳转；带会话转发时 **Host/Origin 改写 ✓ 门禁 Cookie 剥离 ✓ 原生会话注入 ✓**

## 致谢与机制来源

本插件是对以下开源项目的机制综合（详见各文件头注释）：

- [clarknu/dsh-gateway](https://github.com/clarknu/dsh-gateway)：scrypt 自描述哈希、HMAC 会话、secret 实时轮换、fail-closed 姿态
- [Aztech-Lab/dsh-3301](https://github.com/Aztech-Lab/dsh-3301)：原生 DSH 会话获取（credentials.yaml 铸造 + authenticatedUrl API）、表单登录理念、scrypt 参数与存储权限收紧
- [534119219/chicheng-gate](https://github.com/534119219/chicheng-gate)：门禁端口与 DSH 端口分层、明文禁存
- [hongshuxifan321/dsh-mobile-app](https://github.com/hongshuxifan321/dsh-mobile-app)（server/plugin）：Cordis 插件生命周期、Host/Origin loopback 改写、WS 隧道与逐跳头清理

## Roadmap

- DSH 设置页内的可视化账号管理卡片（当前经 settings.yaml / users.json 配置）
- 可选的登录页品牌自定义（标题/Logo）
- 按用户的会话配额与审计日志

## License

MIT © 2026 fengcwf
