# Trairi 增加「异地组网」能力的可行性调研

> 调研对象：[EasyTier](https://github.com/EasyTier/EasyTier)（Rust + Tokio 的去中心化虚拟局域网）
> 目标：在 Trairi 里实现一套类似的异地组网（overlay VPN / SD-WAN）功能
> 调研方式：阅读 EasyTier 源码结构、依赖清单与协议定义（`easytier-core` 279 个文件，
> 源码约 4.3 MB），对照 Trairi 现有代码评估复用度；并在本机验证 TUN / 权限等前置条件。

---

## 0. 结论先说

| 问题 | 结论 |
|---|---|
| 技术上可行吗？ | **可行**。Trairi 已经具备加密、传输、配置、面板这些外围能力，缺的是「虚拟网卡 + L3 转发 + P2P 连接管理 + 路由同步」四块。 |
| 工作量多大？ | 核心可用版本（**P0+P1**：TUN + 节点互通 + UDP 直连打洞 + 中转兜底）约 **2 周**、3~5k 行；完整对标 EasyTier（含子网代理、多跳路由、WireGuard 入口、Web 管理）**6~8 周**。EasyTier 自己是一万行级别以上的独立项目，不可能几天做完。 |
| 会不会和现有功能冲突？ | 架构上是**并行新增一个 `overlay` 子系统**，不影响现有的端口转发。但**不能用现在的 smux/TCP 通道跑 L3 流量**，必须独立走 UDP 数据面。 |
| 最硬的门槛是什么？ | 不是写代码，而是 ① Windows 必须**管理员权限** + `wintun.dll`；② 打洞成功率要在真实 NAT 环境里反复调（实验室测不出来）；③ 多跳路由收敛。 |
| 建议 | 先做 **P0（经服务端中转的 hub-spoke overlay）**，一周内能用起来；再迭代 P1 的 P2P 打洞。不建议一上来就追 EasyTier 的全部特性。 |

---

## 1. EasyTier 到底做了什么

它把自己定位成「简单、安全、去中心化的虚拟私有网络」，本质是**在 UDP 上跑一个 L3 overlay**：

```
应用 → 内核协议栈 → 虚拟网卡(TUN, 如 10.144.144.2)
                        │ 读原始 IP 包
                        ▼
                  packet 处理（MTU/分片/ACL）
                        │ 查路由表：目的 IP → 哪个 peer
                        ▼
                  tunnel（Noise 加密后的 UDP/TCP/WS/WG 封装）
                        │
                        ▼
                    对方 peer → 写入它的 TUN → 对方内核协议栈
```

### 1.1 它的模块划分（读源码得到）

`easytier-core/src/` 下的一级模块，正好对应我们要补的四块能力：

| 模块 | 职责 | 我们的对应工作量 |
|---|---|---|
| `peers/` | peer 管理、**OSPF 式路由**（`peer_ospf_route.rs` 单文件 229 KB）、ACL | 大 |
| `connectivity/` | `stun`（NAT 类型探测）、`hole_punch`（UDP 打洞，含服务端协调）、`direct`、`manual`、`transport` | 大 |
| `tunnel/` | 数据面封装：UDP / TCP / WS / WS-S / WireGuard | 中 |
| `gateway/` | `smoltcp`（用户态协议栈）、`dhcp`、`magic_dns`、`socks5`、`port_forward`、`vpn_portal`（WG 入口） | 大 |
| `config/` | 配置（TOML/命令行/API）、DHCP、加密、网关配置 | 小（已有） |
| `socket/` / `packet/` | 零拷贝收发、分片 | 中 |
| `rpc/` + `easytier-proto/*.proto` | peer 间 RPC（prost + protobuf），路由/邻居信息交换 | 中 |

### 1.2 关键依赖（说明它靠什么撑起来）

```
tun = "tun-easytier"（fork 的 rust-tun）   ← 虚拟网卡，Windows 下走 wintun-bindings
smoltcp 0.14                              ← 用户态 TCP/IP 栈（子网代理/网关用）
snow 0.10 (25519_ChaChaPoly_SHA256)       ← Noise 握手
x25519-dalek / aes-gcm / chacha20poly1305 ← 密钥交换与数据加密
stun_codec 0.4                            ← STUN 打洞
quinn 0.11                                ← QUIC 传输
tokio-websockets 0.13                     ← WS/WSS 传输（便于过 CDN/反代）
zerocopy / async-ringbuf                  ← 零拷贝、批处理
prost / prost-types                       ← peer 间 protobuf RPC
```

### 1.3 默认端口（可作参考）

`11010/TCP+UDP`（主连接）、`11011` WS、`11012` WSS、`11013` WireGuard。

---

## 2. Trairi 现状：能复用多少

| 能力 | 现状 | 组网时可复用？ |
|---|---|---|
| 配置体系（YAML + 校验） | 已有 | ✅ 直接加 `overlay:` 段 |
| 加密原语（HKDF + ChaCha20-Poly1305 + HMAC） | 已有 | ⚠️ 可复用密码学底座，但 peer 间握手建议换成 **Noise（snow）**，因为要做基于网络名的双向认证和可 rotection 的前向保密 |
| 传输抽象（tcp/tls/ws/wss + 嗅探） | 已有 | ⚠️ 只对**控制面**有用；数据面必须新写 UDP（+可选 KCP/QUIC） |
| smux 多路复用 | 已有 | ❌ 不适合 L3：IP 包是数据报语义，塞进字节流会被队头阻塞，延迟和丢包表现都很差 |
| token 认证 / 心跳 | 已有 | ✅ 控制面可沿用思路 |
| 面板 / JSON API | 已有 | ✅ 加几个 overlay 页面即可 |
| 带宽限速（令牌桶） | 已有 | ✅ 直接用在转发表 |
| PROXY protocol / 端口转发 | 已有 | ✅ 与 overlay 无关，并行存在 |
| **虚拟网卡 / IP 转发 / 路由表操作 / NAT 穿透 / 邻居发现** | **无** | ❌ 全部要新写 |

一句话：**外围齐了，内核全缺。**

---

## 3. 关键技术点与门槛

### 3.1 虚拟网卡（TUN）

| 平台 | 实现方式 | 门槛 |
|---|---|---|
| Windows | `tun`(rust-tun) 走 `wintun-bindings`，运行时需要 `wintun.dll` | **必须管理员权限**；需要随包分发 wintun.dll（你机器上 `D:\easytier-gui\wintun.dll` 就是 EasyTier 带的那个）；首次创建网卡会触发 Windows 防火墙询问 |
| Linux | `/dev/net/tun` + `ip link`/netlink | 需要 `CAP_NET_ADMIN` 或 root |
| macOS | `utun` | 需要 root 授权 |

**本机验证结果**：
- Windows：当前用户**在管理员组**，但进程未提权 → 运行 overlay 模式必须「以管理员身份运行」，这是产品层面的硬约束，必须写进文档。
- WSL Ubuntu：`/dev/net/tun` 存在、`iproute2 6.1.0` 可用 → **Linux 侧可以立刻做原型和自动化测试**，不用等真机。
- 你机器上已有 Hyper-V 虚拟网卡和 EasyTier 装的 wintun，多个 TUN 网卡共存没问题，但要注意**路由优先级**和网卡跃点。

### 3.2 路由表（让系统把包交给我们的网卡）

创建 TUN 只是第一步，还得让内核把 `10.144.144.0/24` 的流量交给它：
- Windows：`route add` / IP Helper API（`CreateIpForwardEntry2`），或直接给网卡配 `10.144.144.x/24` 让系统自动生成直连路由（简单可靠，推荐）。
- Linux：`ip addr add` + `ip route add`（或用 netlink）。
- **退出时要清理**：网卡、路由、DNS，否则用户机器上会残留不可用的路由，导致断网——这是这类工具最常见的投诉点。

### 3.3 NAT 穿透（最难、最不可控）

EasyTier 的连接建立优先级大致是：**直连（公网 IP / IPv6）→ UDP 打洞 → 中继（经其它节点）**。

需要的能力：
1. **STUN 探测**：判断自己处于 FullCone / Restricted / PortRestricted / Symmetric 哪类 NAT。
2. **协调打洞**：双方同时向对方公网端点发包（`hole_punch/udp/server.rs` 那套信令）。
3. **失败兜底**：走中继节点转发（带宽受中继限制）。
4. **IPv6**：有 IPv6 时成功率最高，值得优先支持。

现实预期（业内通用经验）：
- 一方有公网 IP → 直连成功率接近 100%；
- 双方都是 FullCone/PortRestricted → 打洞成功率 80%+；
- 双方都是 **Symmetric NAT（部分移动网络/企业网）** → 打洞基本失败，只能中继。

⚠️ 这一块**没法在单机实验室里验证充分**，必须有至少 3 种真实网络环境（家庭宽带、手机热点、云主机）来调。

### 3.4 路由与邻居发现

小规模（<10 节点）可以用最简单的方式：每个节点维护「虚拟 IP → peer」的全量表，靠控制面广播同步。
规模上去（几十上百节点、多跳中继）才需要 EasyTier 那种 OSPF 式的**基于延迟和丢包的动态选路**——这部分是它代码量的最大头（单文件 229 KB），我们**第一版不要碰**。

### 3.5 性能与 MTU

- 建议虚拟网卡 MTU = **1280**（IPv6 最小 MTU，避免分片），overlay 头再加 ~60 字节。
- 数据面要走「一次性批量收发 + 零拷贝」，不要每包一次 `send().await`，否则千兆网都跑不满。
- 加密用 ChaCha20-Poly1305（纯 Rust，`ring` 也可），单核 1~2 Gbps 量级，够用。

### 3.6 加密与认证

建议对标 EasyTier 用 **Noise IK/XX（snow crate，25519_ChaChaPoly_SHA256）**：
- 用 `network_name + network_secret` 派生静态密钥，握手时互相认证；
- 每条连接独立会话密钥，支持重放保护；
- 我们现有的 HKDF+AEAD 记录层可以保留给控制面，但 peer 间数据面不要复用（没有身份绑定，容易做错）。

---

## 4. 三条落地路线

### 路线 A：自研 overlay（推荐）

在 Trairi 里新增 `overlay` 子系统，独立数据面（UDP），与现有端口转发并行。

```
src/overlay/
├─ tun.rs          虚拟网卡抽象（windows: wintun / linux: /dev/net/tun）
├─ device.rs       读写 IP 包、批量收发
├─ packet.rs       IP 头解析、路由查找、TTL、分片
├─ peer.rs         peer 状态机、连接建立/保活/断线重连
├─ connectivity/   stun.rs / hole_punch.rs / direct.rs / relay.rs
├─ route.rs        虚拟 IP 路由表 + 邻居/路由同步（先做全量广播，不做 OSPF）
├─ crypto.rs       Noise 握手 + 会话密钥
├─ tunnel/         udp.rs（主）/ tcp.rs / ws.rs（兜底）
└─ host.rs         路由表/网卡配置与清理（平台相关）
```

**优点**：完全可控、和 Trairi 的配置/日志/面板统一，不引入 LGPL 代码。
**缺点**：工作量大，NAT 和路由要长期调优。

### 路线 B：集成 `easytier-core` 作为子进程

不自己实现，Trairi 只做「编排 + 管理面」：启动 `easytier-core` 子进程，透传配置、收集状态、在面板里展示。

**优点**：一周内就有完整能力，NAT 穿透、多跳路由都是现成的。
**缺点**：
- EasyTier 是 **LGPL-3.0**，作为独立子进程调用是合规的（不静态链接），但要随包分发它的二进制、要接受它的行为与升级节奏；
- 两套工具的运行状态割裂（用户要装两个东西的感觉）；
- 你机器上已经装了 EasyTier GUI，等于重复建设。

### 路线 C：只做「简化版组网」——hub-and-spoke

所有流量强制经 Trairi 服务端中转，不做 P2P 打洞：

```
节点A ──┐
节点B ──┼──(UDP, 加密)── Trairi 服务端（TUN 网关）── 内网/其它节点
节点C ──┘
```

**优点**：一周内能做出来、行为确定、调试简单；不需要 STUN、不需要打洞、不需要动态路由；服务器带宽就是总带宽。
**缺点**：延迟和带宽都受服务器限制，不是真正的「P2P 异地组网」。

> **推荐组合**：先做 **C 作为 P0**（保证有能用的东西），再演进到 **A 的 P1/P2**（P2P 打洞、动态路由）。
> 路线 B 只在「只想快速要有组网能力、不在乎自研」时才考虑。

---

## 5. 分阶段实施计划

以「AI 辅助开发、单人推进」估算：

### P0：hub-and-spoke overlay（1~1.5 周）

| 项 | 内容 |
|---|---|
| 交付 | `trairi server --overlay` 起网关；客户端 `overlay:` 配置虚拟 IP 和 peers；节点间互 ping、访问服务端所连内网 |
| 代码 | `tun.rs`、`device.rs`、`packet.rs`（IPv4 转发 + ICMP 透传）、`peer.rs`（UDP 单跳）、Noise 握手、`host.rs`（Windows/Linux 路由配置与清理） |
| 规模 | ~2.5~3.5k 行 |
| 验收 | 两台机器（Windows + Linux）经服务端中转后互相 `ping` 通；能访问服务端背后的 `192.168.x.x`；退出后路由/网卡清理干净 |

### P1：UDP 直连 + 打洞（1~1.5 周）

| 项 | 内容 |
|---|---|
| 交付 | 同 NAT 后/公网节点之间自动直连，失败自动回到中继 |
| 代码 | `connectivity/stun.rs`（NAT 类型探测）、`hole_punch.rs`（双方协调打洞，含服务端信令）、`peer.rs` 多连接择优、保活与切换 |
| 规模 | ~2~3k 行 |
| 验收 | 家庭宽带 ↔ 云主机、家庭宽带 ↔ 手机热点 两类场景能直连；Symmetric NAT 下自动回落到中继且不卡死 |

### P2：路由与网关能力（2~3 周）

| 项 | 内容 |
|---|---|
| 交付 | 多跳中继、子网代理（`10.1.1.0/24` 共享）、简单 DHCP 分配虚拟 IP、magic DNS |
| 代码 | `route.rs` 全量同步 → 增量化；net-to-net 转发；smoltcp 接入（子网代理做 NAT） |
| 规模 | ~3~4k 行 |
| 验收 | 三节点链式拓扑（A-B-C）可通信；B 把内网网段共享给 A/C |

### P3：生态对接（1~2 周，可选）

WireGuard 入口端口（手机直接连）、Web 管理页、多平台打包、系统服务注册。

---

## 6. 主要风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| Windows 需要管理员权限 | 用户可能直接放弃 | 文档前置说明；提供「非管理员只做端口转发」的降级路径；安装脚本一键提权 |
| wintun.dll 分发与签名 | 被杀软误杀/加载失败 | 从 WireGuard 官方构建取签名 DLL 随包分发，校验签名（`verify_binary_signature` feature 已支持） |
| NAT 穿透成功率不可控 | 用户「组网不通」 | 永远保留中继兜底；面板上明确显示当前连接类型（直连/中继/失败原因） |
| 路由残留导致用户断网 | 严重投诉 | 退出/崩溃时注册清理（Windows 用服务或 `Drop`+信号处理；Linux 用 netlink 删除）；提供 `trairi overlay cleanup --iface xx` |
| 与 Hyper-V / 其它 VPN 网卡冲突 | 路由优先级错乱 | 只添加目标网段的精确路由，不设默认路由；避免劫持全局流量 |
| 与 EasyTier 同时运行 | 虚拟 IP 段/网卡名冲突 | 自定义网段与网卡名，启动时检测冲突并提示 |
| 规模与性能 | 大流量下掉速 | 批量收发 + 零拷贝；限速用现有令牌桶；MTU 1280 |
| LGPL 合规（若参考 EasyTier 实现） | 法律风险 | 自研实现不复制其代码；只有走路线 B 才涉及，且子进程调用是合规的 |

---

## 7. 如果要做，配置会长什么样（YAML）

沿用现有的单二进制 + YAML 体系，新增一个 `overlay` 段，与 `proxies` 完全并行：

```yaml
mode: server          # 服务端兼做组网网关/中继

overlay:
  enable: true
  network_name: my-home-net
  network_secret: 一个很长的随机串
  # 本节点的虚拟 IP
  ipv4: 10.144.144.1/24
  # 数据面监听
  listen:
    - udp://0.0.0.0:11010
    - tcp://0.0.0.0:11010
  # 允许客户端直连打洞 / 也允许作为中继
  relay: true
  mtu: 1280
```

```yaml
mode: client

overlay:
  enable: true
  network_name: my-home-net
  network_secret: 一个很长的随机串
  ipv4: 10.144.144.2/24
  peers:
    - udp://1.2.3.4:11010
  # 想共享内网网段时（子网代理，P2）
  proxy_networks:
    - 192.168.1.0/24
```

```bash
trairi overlay status      # 看 peers / 连接类型 / 延迟 / 丢包
trairi overlay cleanup     # 清理虚拟网卡与路由
```

这样用户拿到的是**一个程序、两种能力**：既做端口转发，也能组网，和 EasyTier 的定位类似但不重复。

---

## 8. 最终建议

1. **先做 P0（hub-spoke）**，它能在 1 周内给出「异地两台机器互通」的可用结果，且不依赖 NAT 穿透这种玄学。
2. **P1 打洞**必须配真实网络环境验证，建议同时用 WSL 的 netns 搭 NAT 模拟做回归（本机已验证 WSL 有 `/dev/net/tun` 和 `iproute2`，可以直接跑）。
3. **不要第一版就做 OSPF 式动态路由**，先全量路由同步，规模不够再说。
4. 如果只是「需要一个能用的组网」，**路线 B（子进程集成 easytier-core）** 是最省事的，但要接受 LGPL 和双进程形态。

> 结论：**值得做，且技术路径清晰**；难点集中在 Windows 权限/驱动、NAT 穿透实测、以及退出时的网络清理，而不是 Rust 本身。

---

## 9. 参考资料

- EasyTier 仓库：<https://github.com/EasyTier/EasyTier>（LGPL-3.0）
- 文档站：<https://easytier.cn/>
- 本调研抓取的原始材料：`docs/research/`（README、Cargo 依赖清单、proto 定义、源码树）
- 相关 crate：`tun`(rust-tun) / `tun-rs` / `wintun` / `smoltcp` / `snow` / `stun_codec` / `quinn`
- 对照项目：WireGuard、Tailscale、ZeroTier
