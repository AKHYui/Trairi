# Trairi

[English](README.md) | **简体中文**

[![CI](https://github.com/AKHYui/Trairi/actions/workflows/ci.yml/badge.svg)](https://github.com/AKHYui/Trairi/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

一个用 Rust 写的内网穿透与异地组网工具。

> **只有一个可执行文件，没有独立的客户端/服务端二进制。**
> 靠配置文件里的 `mode` 或命令行子命令决定这次当服务端还是客户端。

```bash
trairi server -c server.yaml     # 当服务端
trairi client -c client.yaml     # 当客户端
trairi run    -c any.yaml        # 由配置里的 mode 决定
trairi validate -c any.yaml      # 只校验配置
trairi version
```

> 配置文件统一用 **YAML**（`.yaml` / `.yml`）。因为 YAML 是 JSON 的超集，
> 直接把 JSON 丢进去也能解析。

---

## 1. 快速开始

服务端（公网机器）：

```yaml
# server.yaml
mode: server

server:
  bind_port: 7000
  vhost_http_port: 8080
  token: 换成你自己的长随机串
  # 允许客户端申请的端口范围；为空时禁止申请固定端口
  allow_ports: "7001-7200"
  # 公网服务端建议强制加密
  force_encryption: true

dashboard:
  # 面板默认只绑本机；要看请用 SSH 隧道，不要直接暴露公网
  bind_addr: 127.0.0.1
  port: 7500
  user: admin
  password: 换成至少 8 位的强密码
```

```bash
trairi server -c server.yaml
```

客户端（内网机器）：

```yaml
# client.yaml
mode: client

client:
  server_addr: 你的公网IP
  server_port: 7000
  token: 和服务端一致的 token
  use_encryption: true

proxies:
  - name: ssh
    type: tcp
    local_addr: 127.0.0.1:22
    remote_port: 7001
```

```bash
trairi client -c client.yaml
# 之后 ssh -p 7001 你的公网IP 就能进内网机器
```

看面板（推荐 SSH 隧道，不要把 7500 直接开到公网）：

```bash
ssh -L 7500:127.0.0.1:7500 你的服务器
# 然后本机打开 http://127.0.0.1:7500
```

---

## 2. 功能一览

| 功能 | 状态 | 说明 |
|---|---|---|
| TCP 代理 | ✅ | `type = "tcp"` |
| UDP 代理 | ✅ | `type = "udp"` |
| HTTP 虚拟主机（按域名） | ✅ | `type = "http"` + `custom_domains` / `subdomain` |
| HTTPS 虚拟主机（按 SNI） | ✅ | `type = "https"`，**TLS 端到端不终止** |
| 密钥访问 TCP | ✅ | `type = "stcp"`；服务端不监听端口，靠 `sk` 鉴权 |
| 代理 P2P | ✅ | `type = "p2p"`；owner/visitor 之间直连 KCP + smux，失败回退中继 |
| 访问者 visitor | ✅ | `visitors` 列表 |
| SOCKS5 插件 | ✅ | `type = "socks5"`，内置实现 |
| HTTP 代理插件 | ✅ | `type = "http_proxy"`（支持 CONNECT 隧道） |
| 静态文件插件 | ✅ | `type = "static_file"`，内置静态站 + Basic Auth |
| 多路复用（smux） | ✅ | 一条连接跑所有代理 |
| 传输协议 tcp/tls/ws/wss/kcp | ✅ | TCP 在 `bind_port` 上自动嗅探；KCP 使用同一端口的 UDP |
| 连接加密（AEAD） | ✅ | ChaCha20-Poly1305 + HKDF 派生密钥 |
| 流压缩 | ✅ | snappy |
| token 认证 | ✅ | HMAC-SHA256 覆盖完整 Hello，带重放保护 |
| 心跳 / 超时剔除 | ✅ | 双向心跳 |
| 代理健康检查 | ✅ | `health_check_type = tcp/http`，状态回传服务端 |
| 负载均衡（group） | ✅ | 同 `group` + `group_key` + `remote_port`，服务端轮询健康成员 |
| 带宽限制 | ✅ | `bandwidth_limit = "5MB"`，可指定 server/client 侧生效 |
| PROXY protocol v1/v2 | ✅ | `proxy_protocol_version = "v1"` |
| 端口白名单 | ✅ | `allow_ports = "7001-7200"` |
| 面板 + JSON API | ✅ | 内置，无前端构建依赖 |
| 客户端管理 API（reload/stop） | ✅ | `webServer` |

暂未实现：QUIC、smux 之外的通用 TCP 多路复用、Prometheus 指标。
面板 JSON API 可以直接接入自有监控。

KCP 是可靠 UDP 传输，不是加密层；请保持 `force_encryption` / `use_encryption`
开启，让 Trairi 的 token 认证和 ChaCha20-Poly1305 记录层继续保护数据。
`server.kcp` 默认关闭，因为它会和 overlay 数据面共用 UDP `bind_port`。

---

## 3. 架构

```
   ┌──────────── 客户端（内网）────────────┐        ┌──────── 服务端（公网）────────┐
   │                                       │        │                              │
   │  local:22 ─┐                          │        │   :7001  ──┐                 │
   │  local:80 ─┼─ 代理运行时 ─ smux 会话 ───┼── TCP ─┼─ :8080(vhost) ── 路由 ── 监听 │
   │  plugin:xx ┘   （加密/压缩）           │  TLS   │   :8443(vhost)               │
   │                                       │  WS    │                              │
   └───────────────────────────────────────┘  WSS   └──────────────────────────────┘
```

### 建立过程

1. **传输层**：客户端连服务端 `bind_port`。TCP/TLS/WS 自动嗅探；KCP 使用同一端口的 UDP。
   嗅探在每连接 task 内完成，首字节和 TLS/WS 握手都有 5 秒超时，单个慢连接不会卡住 accept 循环。
2. **明文握手（协议 v2）**：客户端发 `HelloRequest{salt, timestamp, HMAC(token, 完整握手字段), 是否加密/压缩}`；
   服务端校验时间窗 + HMAC + `(salt,timestamp)` 重放缓存。
3. **派生密钥**：`HKDF-SHA256(token, salt)`，之后整条连接走 ChaCha20-Poly1305 记录帧；
   两个方向使用不同的 nonce 方向前缀，避免同 key + 同 nonce 的双向复用。
4. **多路复用**：在记录层之上起 `smux` 会话，第一条流是**控制流**。
5. **登录**：控制流上 `Login{run_id, hostname, os, arch}` → `LoginResp`。
6. **注册代理**：控制流上 `NewProxy` → `NewProxyResp{remote_addr}`。
7. **转发**：
   - 服务端收到外部连接 → 控制流发 `ReqWorkConn`
   - 客户端新开一条 smux 流，先发 `StreamHeader::Work{proxy_name}`，再连本地服务
   - 两端字节对拷（服务端可附加 PROXY protocol 头）

控制消息用「4 字节大端长度 + JSON」的帧，便于调试；数据面全是零拷贝的字节流转发。

---

## 4. 配置参考

配置是 YAML，顶层键如下（下面各表里的字段就是对应的嵌套键）：

```yaml
mode: client        # 或 server
log: { ... }
server: { ... }     # 服务端参数
client: { ... }     # 客户端参数
dashboard: { ... }  # 服务端面板
webServer: { ... }  # 客户端管理 API
proxies:            # 代理列表
  - name: ...
visitors:           # 访问者列表
  - name: ...
```

### 顶层

| 字段 | 说明 |
|---|---|
| `mode` | `"server"` 或 `"client"`；也可用命令行覆盖 |
| `log` | `level`（trace/debug/info/warn/error）、`file`（空=仅控制台，填路径按天滚动）、`max_days`（保留天数） |
| `server` | 服务端参数 |
| `client` | 客户端参数 |
| `dashboard` | 服务端面板 |
| `webServer` | 客户端管理 API |
| `proxies` 列表 | 代理定义（客户端生效） |
| `visitors` 列表 | 访问者定义（客户端生效） |

### `server`

| 字段 | 默认 | 说明 |
|---|---|---|
| `bind_addr` | `0.0.0.0` | 监听地址 |
| `bind_port` | — | 客户端接入端口（必填）；KCP 使用同一端口的 UDP |
| `kcp` | `false` | 在 `bind_port` 上启用 KCP（可靠 UDP）；不能与 `overlay.udp_port` 冲突 |
| `p2p_port` | `0` | P2P UDP 会合端口；0 = 关闭 P2P |
| `vhost_http_port` | `0` | HTTP 虚拟主机端口，0 关闭 |
| `vhost_https_port` | `0` | HTTPS 虚拟主机端口（SNI 路由），0 关闭 |
| `subdomain_host` | `""` | 泛域名后缀，如 `example.com` |
| `allow_ports` | `""` | 允许申请的端口，如 `"7001-7200,8000"`；为空时禁止申请固定端口 |
| `max_ports_per_client` | `64` | 每个客户端端口配额，0 不限 |
| `authentication_timeout` | `10` | 认证超时（秒） |
| `heartbeat_timeout` | `90` | 心跳超时（秒） |
| `max_clients` | `1024` | 客户端数量上限，0 不限 |
| `token` | `""` | 认证口令；**服务端模式必填**，否则启动失败 |
| `force_encryption` | `true` | 强制加密 |
| `tls_cert_file` / `tls_key_file` | `""` | 服务端 TLS 证书（PEM） |
| `proxy_protocol_version` | `""` | 代理的默认 PROXY protocol 版本（per-proxy 可覆盖） |

### `client`

| 字段 | 默认 | 说明 |
|---|---|---|
| `server_addr` / `server_port` | — | 服务端地址（必填） |
| `token` | `""` | 与服务端一致 |
| `run_id` | 自动 | 客户端标识，同 ID 重连会踢掉旧连接 |
| `user` | `""` | 备注用 |
| `protocol` | `tcp` | `tcp` / `tls` / `ws` / `wss` / `kcp` |
| `tls_enable` | `false` | 等价于 `protocol = "tls"` |
| `tls_server_name` | `server_addr` | TLS 校验用名字 |
| `tls_cert_file` | `""` | 自定义 CA |
| `tls_insecure` | `false` | 跳过证书校验 |
| `ws_path` | `/~!trairi` | WebSocket 路径 |
| `use_encryption` | `true` | 是否加密（需要 token） |
| `use_compression` | `false` | 是否 snappy 压缩 |
| `heartbeat_interval` | `30` | 心跳间隔（秒；0 = 使用服务端建议值） |
| `p2p_udp_port` | `0` | P2P 本地 UDP 绑定端口；0 = 随机 |
| `heartbeat_timeout` | `90` | 心跳超时（秒） |
| `dial_timeout` | `10` | 连接本地服务/服务端超时（秒） |
| `proxy_protocol_version` | `""` | 默认 PROXY protocol 版本 |
| `bandwidth_limit` | `""` | 全局限速（作为代理默认值） |
| `start` | `[]` | 只启动列表中的代理 |

### `proxies` 列表

| 字段 | 说明 |
|---|---|
| `name` | 必填，全局唯一 |
| `type` | `tcp` / `udp` / `http` / `https` / `stcp` / `socks5` / `http_proxy` / `static_file` |
| `local_addr` | 本地服务地址 `IP:PORT`（插件类型可留空，会自动分配） |
| `local_path` | `static_file` 的根目录 |
| `remote_port` | tcp/udp 对外端口；0 表示由服务端从 `allow_ports` 分配 |
| `custom_domains` | http/https 的域名列表 |
| `subdomain` | 配合服务端 `subdomain_host` |
| `sk` | `stcp` / `p2p` 的共享密钥 |
| `group` / `group_key` | 负载均衡分组（同组同端口共享监听） |
| `weight` | 分组负载均衡权重（1–1000，默认 1） |
| `bandwidth_limit` | 如 `"5MB"`、`"512KB"`；空=不限 |
| `bandwidth_limit_mode` | `server`（默认）或 `client` |
| `proxy_protocol_version` | `""` / `v1` / `v2` |
| `http_user` / `http_pwd` | `static_file` 的 Basic Auth |
| `health_check_type` | `tcp` / `http`，空=不检查 |
| `health_check_path` | http 检查的路径，默认 `/` |
| `health_check_interval` / `_timeout` / `_max_failed` | 检查间隔、超时、连续失败阈值 |

### `visitors` 列表

| 字段 | 说明 |
|---|---|
| `name` | 必填 |
| `type` | `stcp` 或 `p2p` |
| `server_name` | 目标代理名 |
| `sk` | 与目标代理一致的密钥 |
| `bind_addr` / `bind_port` | 本地监听地址 |
| `p2p_fallback` | `true`（默认）：P2P 直连失败时回退服务器中继 |

### P2P 代理

服务端需要单独的 UDP 会合端口：

```yaml
server:
  p2p_port: 7001       # 放行 UDP 7001；0 = 关闭
```

owner 客户端：

```yaml
proxies:
  - name: p2p-ssh
    type: p2p
    local_addr: 127.0.0.1:22
    sk: a-shared-secret
```

visitor 客户端（本机也跑 Trairi，并监听本地端口）：

```yaml
visitors:
  - name: p2p-ssh-visitor
    type: p2p
    server_name: p2p-ssh
    sk: a-shared-secret
    bind_addr: 127.0.0.1
    bind_port: 2222
    p2p_fallback: true
```

服务端只交换双方 UDP endpoint；owner/visitor 打洞成功后走 KCP + smux 直连，
同一局域网内会优先尝试对方的私网 endpoint，再尝试公网 endpoint；失败则回退普通
服务器中继。`sk` 同时用于 HMAC 认证和派生 P2P 记录层密钥。

P2P 在至少一端有公网/可达 UDP endpoint 时效果最好；对称 NAT 或 UDP 被封会
回退中继。一个 KCP 会话通过 smux 承载 visitor 侧的多条 TCP 连接。

---

## 5. 面板与管理 API

**服务端面板** `http://host:7500/`：客户端/代理列表、连接数、上下行流量，2 秒自动刷新。
JSON：`GET /api/overview`，健康检查：`GET /healthz`。支持 Basic Auth。

**客户端管理 API**（`webServer`）：

| 接口 | 作用 |
|---|---|
| `GET /api/status` | 连接状态、已注册代理、对外地址 |
| `GET /api/reload` | 重新读取配置文件并重连 |
| `GET /api/stop` | 退出进程 |

---

## 6. 编译

需要 Rust 工具链；交叉编译 Linux 静态包建议用 `cargo-zigbuild` + Zig。

```bash
# Windows 版
cargo build --release

# Linux x86_64 静态（可直接拷到任何 Linux 跑）
cargo zigbuild --release --target x86_64-unknown-linux-musl

# Linux x86_64 glibc ≥ 2.17
cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.17

# Linux ARM64
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

产物在 `target/<target>/release/trairi`（Windows 下是 `trairi.exe`）。

---

## 7. 测试

```bash
cargo test
cargo clippy --all-targets
```

当前测试规模：76 个单元测试、17 个端口转发端到端测试、8 个 overlay 集成测试。

集成测试会在同一进程里起真实的 server + client，覆盖：

- TCP 转发、加密通道、WebSocket 传输
- HTTP 虚拟主机路由、未匹配域名的 404
- UDP 转发
- 内置 SOCKS5
- 密钥访问 TCP + visitor、错误 sk 被拒绝
- PROXY protocol v1 落到后端
- 面板 `/api/overview`（带认证）
- 分组负载均衡轮询
- 错误 token 被拒绝、Hello 重放被拒绝、慢连接不阻塞新连接

---

## 8. 安全建议

### 8.1 代码级安全默认（当前版本已内置）

1. **服务端必须配置 `server.token`**，否则 `trairi server` 启动时配置校验直接失败。
2. `Hello` 的 HMAC 覆盖完整握手字段（版本、salt、时间戳、加密/压缩开关、client 标识），
   服务端还有 `(salt,timestamp)` 重放缓存；`force_encryption` 默认 `true`。
3. 记录层两个方向使用不同的 AEAD nonce 方向前缀，不再出现同 key + 同 nonce 的双向复用。
4. `allow_ports` 对显式 `remote_port` 同样生效；为空时禁止申请固定端口。
   默认 `max_clients = 1024`、`max_ports_per_client = 64`、`authentication_timeout = 10`。
5. 中继认证有 10 秒超时、连接数上限；中继只接受已在 overlay 控制面登记的公钥。
6. 面板默认绑 `127.0.0.1`；开启面板必须配置 `user` / `password`（至少 8 位）。
7. 单连接嗅探/TLS/WS 握手都在独立 task 中完成，并带 5 秒超时，慢连接不会卡死 accept 循环。

> 协议已升级到 **v2**：旧版客户端（v1）会因协议版本不一致被拒绝，需要一起升级。

### 8.2 公网部署运维加固（运维项，不是程序漏洞）

下面这些属于**部署/运维层面的加固**；程序无法替你做，但公网生产环境应当逐项确认：

1. **轮换 secrets**：`server.token`、`overlay.network_secret` 用 32 字节以上随机值；
   不要提交到 git，不要写在脚本里。`token`/`network_secret` 一旦泄露，等于把信令和 overlay 交出去。
2. **不要用 root 跑纯信令/中继**：用独立用户 + 高位端口；需要 TUN 时用 systemd
   `User=trairi` + `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`，不要整机 root。
3. **防火墙/安全组只放行必要端口**：`bind_port`、`relay_listen` 尽量限制来源 IP；
   overlay 的 UDP 端口只对需要的节点开放；面板端口不要对公网开放。
4. **面板走 SSH 隧道或 TLS 反代**：面板本身是 HTTP Basic auth，明文 HTTP 下密码可被嗅探。
5. **日志限级 + 轮转**：生产用 `log.level: info`，不要让 `debug` 长期写满磁盘；
   用 logrotate 或 `log.file` 按天滚动，并监控磁盘。
6. **公网建议加 TLS**：`protocol: tls` / `wss` + 有效证书，作为传输层保护；
   `force_encryption` 保护的是 Trairi 记录层，不替代 TLS。
7. **SSH 自身也要加固**：密钥登录、禁用密码登录、fail2ban/来源限制；服务器被 SSH 爆破和 Trairi 无关，但同样会导致整机失守。
8. **定期升级依赖**：`cargo audit` 目前只有 `rustls-pemfile` 的 unmaintained 警告，无已知 CVE；
   仍建议每次发版重跑，并关注 RustSec。
9. **最小化 overlay ACL**：默认 ACL 为空表示全放行；如果网络里有不完全可信的成员，
   用 `overlay.acl` 限制节点间访问。
10. **保留回滚包和配置**：升级协议 v2 前先备份旧二进制/配置，确认所有节点都能同步升级。

完整的安全策略与漏洞报告方式见：[SECURITY.md](SECURITY.md)。

---

## 9. 已知限制

- **没有 QUIC**：KCP 已支持可靠 UDP 传输；QUIC 暂未实现。
- **P2P 是尽力而为**：对称 NAT、CGNAT 或 UDP 被封时会回退服务器中继；P2P 要求 owner 和 visitor 都运行 Trairi。
- **HTTP 虚拟主机是连接级路由**：按首个请求的 Host 选后端，同一连接内的后续请求不再重新匹配（这样 keep-alive 和 WebSocket 都能正常工作）。
- **`http_proxy` 插件只支持 CONNECT**（HTTPS 隧道），普通 `GET http://...` 明文代理未实现。
- **加密/压缩是连接级开关**：在 `client.use_encryption` / `client.use_compression` 设置，没有 per-proxy 开关。
- **服务端不支持热重载**：改完配置重启进程；客户端支持 `/api/reload`。
- **协议 v2 不向下兼容**：v1 客户端会因协议版本不一致被拒绝，升级服务端时所有客户端需要一起升级。
- **面板开启后必须配置认证**：`dashboard.port > 0` 时 `user`/`password` 必填，且默认只绑 `127.0.0.1`。

---

## 10. 目录结构

```
src/
├─ main.rs / lib.rs     入口（单二进制，mode 决定角色）
├─ cli.rs               命令行（run/server/client/validate/version）
├─ config.rs            配置模型与校验
├─ protocol.rs          控制消息、流头、帧编解码
├─ crypto.rs            HMAC 认证 + HKDF + ChaCha20-Poly1305
├─ stream.rs            压缩/加密记录层，统一流类型
├─ transport.rs         tcp/tls/ws/wss 拨号与单端口嗅探
├─ util.rs              限速、PROXY protocol、双向拷贝、SNI/Host 解析
├─ server/
│  ├─ mod.rs            状态、代理注册、端口分配、分组
│  ├─ control.rs        握手、登录、控制循环、work 连接分发
│  ├─ proxy.rs          tcp/udp/vhost-http/vhost-https 转发
│  └─ dashboard.rs      面板与 JSON API
├─ client/
│  ├─ mod.rs            连接、登录、注册、控制循环、管理 API
│  └─ proxy.rs          本地转发、访问者、健康检查
└─ plugin/mod.rs        socks5 / http_proxy / static_file
tests/integration.rs    端到端测试
examples/               服务端 / 客户端 YAML 配置示例
scripts/                network namespace 与 NAT 测试辅助脚本
```

---

## 11. 异地组网（overlay）

Trairi 内置异地组网能力：把多台机器组成一个虚拟局域网，
每台机器分到一个 `10.144.144.x` 的虚拟 IP，互相直接 `ping` 通，
不需要改路由器、不需要公网 IP。

### 架构

```
   应用 / 内核协议栈
         │  10.144.144.x 的 IP 包
         ▼
   TUN 虚拟网卡（Windows: wintun；Linux: /dev/net/tun）
         │
         ▼
   WireGuard（boringtun 实现：加密、握手、重放保护、保活）
         │  UDP
         ▼
   对端节点  ── 端点信息由 Trairi 服务端协调下发
         ▲
         │  控制面（复用现有登录/token/心跳通道）
   Trairi 服务端：分配虚拟 IP、登记公钥、分发节点表
```

- **数据面**用标准 WireGuard；当前版本**没有官方 WG 入口**，overlay 节点仍需运行 Trairi；
- **控制面**复用 Trairi 现有服务端，不引入第二套进程；
- 路由是**中心分配 + 本机 /32 路由**，没有 OSPF，行为和排错都简单。

### 用法

服务端（公网机器，需要能被客户端 TCP 连上）：

```yaml
mode: server
server:
  bind_port: 7000
  token: 你的token
overlay:
  enable: true
  network_name: my-home-net
  network_secret: 很长的随机串
  ipv4_pool: 10.144.144.0/24
  udp_port: 11013
  stun_port: 0
  node_port: 0
```

Overlay 端口布局：`udp_port` 是数据面；`stun_port` 默认 `udp_port + 1`；
`relay_listen` 默认 TCP `udp_port + 2`；`node_port` 在服务端自己也成为节点时
默认 `udp_port + 3`。三个都可以显式配置。`relay_listen` 填 `0.0.0.0:0` 可关闭
TCP 中继。

客户端（**必须以 root / 管理员运行**，因为要建虚拟网卡）：

```yaml
mode: client
client:
  server_addr: 1.2.3.4
  server_port: 7000
  token: 你的token
overlay:
  enable: true
  network_name: my-home-net
  network_secret: 很长的随机串
  ipv4: 10.144.144.2      # 可留空，由服务端分配
  interface: trairi0
```

两边都起来后：

```bash
ping 10.144.144.3        # 直接 ping 对方虚拟 IP
```

### 当前实现状态

| 能力 | 状态 |
|---|---|
| 虚拟网卡（Linux `/dev/net/tun`、Windows wintun） | ✅ |
| WireGuard 数据面（握手/加密/保活/重放保护） | ✅ |
| 服务端协调：虚拟 IP 分配、公钥登记、节点表分发 | ✅ |
| 端点学习（服务端观测客户端公网地址并分发） | ✅ |
| 本机路由自动配置与退出清理 | ✅ |
| 全 mesh 直连（至少一方可达时） | ✅ |
| **TCP 中继兜底**（直连打不通时自动切换，断线退避重连） | ✅ |
| CLI：`trairi overlay status` / `trairi overlay cleanup` | ✅ |
| **服务端自身作为组网节点**（`overlay.node_ipv4`） | ✅ |
| **STUN（NAT 映射探测）** | ✅ |
| **UDP 打洞（主动探测 + 地址学习）** | ✅ 逻辑已验证，真实 NAT 环境待联调 |
| **子网路由**（共享内网给其它节点，proxy_networks） | ✅ |
| **ACL**（overlay.acl，发送端生效） | ✅ |
| **MagicDNS**（节点主机名写进 hosts） | ✅ |

路径选择规则（双路径发送 + 归属锁定）：

- 还没判定归属时，**直连和中继同时发**，避免「入向通、出向不通」的单向 NAT 把包吞掉；
- 收到对端的**中继**报文（中继 TCP 双向、服务端按公钥鉴权）→ 立即锁定中继；
- 只有收到对端的**直连握手响应/cookie 回复**（证明我们发出的握手真的到了对端）才锁定直连；
- 直连锁定后如果发过业务数据、15 秒没有回包，自动回退双路径，让中继接管；
- `overlay.direct: false` 可以强制只走中继。

### 命令行工具

```bash
trairi overlay status -c client.yaml     # 看 overlay 配置摘要
trairi overlay cleanup --interface trairi0   # 进程被强杀后清理残留网卡
```

### P2（STUN + 打洞）的实现与验证边界

- `src/overlay/stun.rs`：RFC 5389 最小实现（Binding Request/Response + XOR-MAPPED-ADDRESS），
  服务端在 overlay UDP 端口上直接应答，因此**不需要外部 STUN 服务器**；
  另开 `udp_port + 1` 作为第二个端口，用于对比端口映射行为。
- 打洞：握手 2 秒未建立时，每 500ms 向对端（服务端观测到的）公网地址发探测包；
  收到探测包的一方会**学习对方的真实地址**并回包；路径是否可用按上节的「归属锁定」判断，
  不再按固定时间硬切中继。
- 已用**单元/集成测试**精确验证：定时器确实会发探测包、收到探测包会纠正过期地址。
- 本机也用 netns + iptables 搭了「两个客户端各自在 NAT 后」的实验室（`scripts/overlay-nat-test.sh`）：
  **中继路径通过**；但直连打洞在该实验室失败——抓包显示打洞包已到达对端 NAT 的公网口，
  是 Linux MASQUERADE 在跨目的地址时更换源端口（端点相关映射）导致被丢弃，
  这与真实家用路由「保端口 / 全锥形」的行为不同，**该实验室无法忠实复现打洞场景**。
  结论：打洞逻辑已实现并有测试覆盖，但**真实 NAT 下的成功率还需要在公网环境联调**。
- **公网实测（已用腾讯云 Ubuntu 服务器完成）**：
  - 服务端部署在公网，客户端（WSL 里 root 跑、真 TUN）跨公网登录/建卡/连中继全部正常；
  - STUN 在真实网络下正确探测出家里 NAT 的公网映射（`198.51.100.20:xxxxx`），
    且多次探测端口一致 → **端点无关映射（EIM）**；
  - 从公网服务器主动向该映射地址发打洞包：**若客户端没主动发过，0/5 收到**（端口限制）；
    **若客户端先向该对端地址发过，5/5 收到** → 家里是**端口限制型锥形 NAT**，
    正是「双方同时发包即可打洞」的典型场景，与我们的实现策略一致。
  - 结论：**打洞机制在真实 NAT 上成立**。
- **跨公网完整验证（腾讯云 VPS + 家用网络，已完成）**：
  - 在公网 VPS 上运行服务端并开启 `overlay.node_ipv4: 10.144.144.1`，
    自动创建虚拟网卡 `trairi0-srv`，并额外监听 UDP 56005 作为节点数据面；
  - 家用网络里的客户端（WSL、真 TUN、10.144.144.2）跨公网接入；
  - **双向 ping 全通**：`CLIENT_TO_SERVER_OK` + `SERVER_TO_CLIENT_OK`；
  - 双方日志都能看到互相打洞探测包（`203.0.113.10:56005` ↔ `198.51.100.20:xxxxx`），
    说明公网节点与 NAT 后节点是经打洞直连的，不是走中继。
  - 复现脚本：`scripts/overlay-nat-test.sh` / `scripts/overlay-netns-test.sh`（通用 netns 实验，
    不包含任何私有部署信息）。

### 验证情况

- 单元/集成测试：`cargo test`（70 单元 + 14 端口转发集成 + 8 overlay 集成）；
- overlay 集成测试用「内存网卡 + 本机 UDP」跑通了两节点 WireGuard 握手与双向 IP 包转发；
- 新增回归测试 `relay_rescues_when_direct_path_is_dead`：双方 endpoint 都指向黑洞、只有中继可用时，
  双路径发送仍能把握手拉起来，并断言两端都锁定中继；
- **真实环境验证**：在 WSL 里用两个 network namespace 各起一个客户端（真实 TUN、真实路由），
  两个节点双向 `ping` 全部成功（3/3 包，RTT 1~8ms）。
- **真实跨公网验证（腾讯云 VPS + Debian + 异地 Windows）**：
  - Debian `10.144.144.3` ↔ 异地 Windows `10.144.144.4` 双向 `ping` 5/5、0% 丢包（约 31ms），
    服务端同时能看到两端 116 字节业务帧的中继转发；
  - 临时节点 `10.144.144.5`（WSL 新版）↔ `.3`、`.5` ↔ `.4` 同样 0% 丢包；
  - 此前「两端都注册中继、却从不发中继帧」的根因是：`prefer_relay()` 用 `rx_bytes > 0`
    把「收到过对端报文」当成直连可用，单向 NAT 下会永远误判；该函数已被双路径 + 归属锁定取代。

### 注意事项

- 需要 **root / 管理员** 权限，否则创建虚拟网卡会失败并给出明确提示；
- Windows 需要 exe 同目录或系统路径里有 `wintun.dll`（也可以用 `TRAIRI_WINTUN_DLL` 环境变量指定）；
- 退出时会删除自己加的 `/32` 路由；如果进程被强杀，可用系统命令清理，
  虚拟网卡本身会随进程退出自动销毁；
- 虚拟网段不要和本地真实网段冲突（默认 `10.144.144.0/24`，可通过 `ipv4_pool` 改）。

### P3（子网路由 / ACL / MagicDNS）

> 三项都属于**可选的增强功能**。Trairi 的核心用途仍然是：
> 「多台机器注册到公网信令服务器后，彼此能用虚拟 IP 互通」，不依赖这里的任何配置。

- **子网路由**：在节点上配 `overlay.proxy_networks: [192.168.1.0/24]`，
  该网段会被广播给全网；其它节点自动把这段流量接到虚拟网卡并送到该节点。
  承接方需要开启内核转发（`net.ipv4.ip_forward=1`），如果希望内网设备把回包发回来，
  还要做 SNAT（如 `iptables -t nat -A POSTROUTING -o <内网网卡> -s 10.144.144.0/24 -j MASQUERADE`），
  这一步没做自动化，按需手动配置。
- **ACL**：服务端 `overlay.acl` 下发全网，节点在**发送端**按顺序匹配、第一条命中生效，默认放行。
  ⚠️ 这是「协作式」控制，不是安全边界——被攻陷的节点可以无视规则。
- **MagicDNS**：把节点主机名（`<hostname>` 和 `<hostname>.trairi`）写进系统 hosts 的托管块
  （`# >>> trairi magic dns >>>` … `# <<< trairi magic dns <<<`），每次节点表变化整体替换。
  不是真正的 DNS 服务器，也不需要改系统 resolver；写 hosts 需要管理员/root 权限，失败只告警。

---

## 12. 版本记录

- **0.3.1**（2026-11-12）：修复 overlay 端口默认值。
  - `server.kcp` 改为默认 `false`，避免它悄悄占用 UDP `bind_port` 与
    `overlay.udp_port` 冲突；
  - `overlay.relay_listen` 默认留空，自动使用 `overlay.udp_port + 2`；
  - `overlay.stun_port` / `overlay.node_port` 可显式覆盖默认的 `+1` / `+3` 端口；
  - 显式配置仍然优先，避免再出现写死的 `11012`。
- **0.3.0**（2026-11-12）：KCP + P2P + Android 桥接。
  - KCP 可靠 UDP 传输（`protocol: kcp`）；
  - P2P 代理：私网 endpoint 优先、公网打洞、KCP + smux，失败回退中继；
  - 中继自动重连、分组加权、全局默认值、日志保留、面板用户字段；
  - Rust Android VpnService TUN 桥接，供 Flutter 客户端使用。
- **0.2.0**（2026-11-10）：安全加固版。
  - 协议 v2：Hello HMAC 覆盖完整字段 + 服务端重放缓存；记录层按方向分离 AEAD nonce；
  - 接入循环改为每连接 task，TLS/WS/首字节均有 5 秒超时；
  - 中继认证 10 秒超时 + 连接上限 + overlay 公钥白名单 + 活跃公钥不可顶替；
  - `allow_ports` 对显式端口强制生效；默认 `authentication_timeout=10`、`max_clients=1024`、`max_ports_per_client=64`；
  - 面板默认 `127.0.0.1`、开启必须认证、前端转义 + CSP；
  - 解压上限 4 MiB；服务端 token 必填、`force_encryption` 默认 true。
  - ⚠️ 旧 v1 客户端不兼容，需要客户端/服务端一起升级。

---

## 13. License

MIT，见 [LICENSE](LICENSE)。

欢迎提交贡献，见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞请按
[SECURITY.md](SECURITY.md) 私下报告，不要开公开 issue。