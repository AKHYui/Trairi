# 组网架构选型：参考 Tailscale 是否合理

> 前置说明：上一份《[EasyTier 可行性调研](easytier-overlay-feasibility.md)》里列的
> 「Windows 要管理员权限、wintun.dll、NAT 打洞不可控、退出要清路由」是**这类 overlay VPN 的固有约束**，
> 不是 EasyTier 的缺陷或漏洞。我没审计过它的安全性，也不做这种判断。
> 换任何方案（包括 Tailscale 式）这些约束一个都不会消失。

---

## 1. 结论

| 问题 | 回答 |
|---|---|
| 参考 Tailscale 合理吗？ | **架构层面：合理，而且比照抄 EasyTier 更合适。** |
| 可行性如何？ | 可行。核心工作量在「控制面 + TUN + 中继」，**加密和握手这两块最难最容易写错的，可以直接用现成的 WireGuard 实现**。 |
| 能做成协议级兼容 Tailscale 吗？ | **不建议、也不现实。** 控制协议未公开、服务端闭源，跟着它演进是无底洞。 |
| 那「参考」具体指什么？ | 借它的**架构**：WireGuard 数据面 + 中心化协调 + 中继兜底 + 打洞直连。协议自研。 |
| 工作量对比 | 与 EasyTier 路线**总体相当或略少**（5~6.5 周 vs 6~8 周），但**风险显著更低**。 |

---

## 2. Tailscale 到底是什么

拆开看它只有四块：

```
┌────────────── 数据面（开源，BSD-3）──────────────┐
│  TUN 网卡  ←→  WireGuard（加密/握手/重放保护）    │
└───────────────┬──────────────────────────────────┘
                │ UDP（直连时）
                ▼
┌────────────── 打洞（disco）──────────────────────┐
│  STUN 探测 + 双方探测包 + 端点漂移学习            │
└───────────────┬──────────────────────────────────┘
                │ 打洞失败
                ▼
┌────────────── 中继 DERP（协议简单，源码可读）────┐
│  TCP 长连接 + 帧协议，按 curve25519 公钥寻址      │
└───────────────┬──────────────────────────────────┘
                │
┌────────────── 控制面（闭源，托管服务）───────────┐
│  谁在线、公钥是什么、虚拟 IP、ACL、子网路由       │
│  （Headscale 是社区对它的开源重写）               │
└──────────────────────────────────────────────────┘
```

**开源边界（已核实）**：

- 客户端 `tailscaled` + CLI：**BSD-3-Clause**（`tailscale/tailscale` 仓库 README 明确写了「包含大部分开源代码」）；
- 控制服务器（coordination）：**闭源**，Tailscale 提供的是托管服务；
- DERP 中继协议：**源码里有正式说明**（`derp/derp.go` 头注释：用 curve25519 公钥做地址、TCP 帧、`DERP🔑` magic、64KB 包上限、60s keepalive），协议很简单，完全可以自己实现；
- 移动端 GUI 不在开源仓库里。

**关键点：Tailscale 自己不发明加密协议，数据面就是标准 WireGuard。** 这是它和 EasyTier 最本质的区别。

---

## 3. 三条路线对比

| 维度 | **EasyTier 式**（自研协议） | **Tailscale 式**（WireGuard 数据面） | **纯 hub-spoke**（全走服务器） |
|---|---|---|---|
| 加密/握手 | 自研 Noise（snow）+ 自研隧道封装 | **标准 WireGuard**（`boringtun` / `defguard_wireguard_rs`） | 同左或自研 |
| 路由模型 | OSPF 式动态选路（它代码量最大的部分，单文件 229 KB） | **中心分配路由表**，客户端只查表 | 服务端一张表 |
| 控制面 | peer 之间 gossip + protobuf RPC | **中心化**：谁在哪、公钥、虚拟 IP、ACL | 中心化 |
| NAT 穿透 | 自研打洞 | STUN + disco（业界最成熟的一类做法） | 不需要 |
| 与标准客户端互通 | ❌（自研协议；只有它自己的 WG portal 能接 WG 客户端） | ✅ **官方 WireGuard 客户端可直接接入**（手机/路由器/别的设备零成本入网） | ❌ |
| 代码量/风险 | 大；加密与动态路由都要自己保证正确 | 中；加密交给成熟件，路由是查表 | 小 |
| 许可证 | LGPL-3.0（参考实现要小心） | BSD-3-Clause（可放心参考甚至借鉴代码） | — |
| 失效兜底 | 经其它 peer 中继 | DERP 中继（简单 TCP，易实现易运维） | 本来就是中继 |

### 为什么「Tailscale 式」更适合 Trairi

1. **省掉最危险的 1~1.5k 行**：握手、密钥协商、重放窗口、密钥轮换，这些自己写最容易出事。WireGuard 是经过大规模审计的标准协议，Rust 侧有现成实现。
2. **省掉 OSPF**：EasyTier 那套动态选路是为了「多跳 mesh」；而大多数家用/小团队场景只需要「中心分配 + 直连优先 + 中继兜底」，一张表就够。
3. **能和标准客户端互通**：这是 EasyTier 自研协议给不了的。做完之后手机装个官方 WG 客户端填个配置就能进网，用户爽感完全不同。
4. **许可证更宽松**：BSD-3 允许我们参考它的实现思路甚至片段；LGPL 的 EasyTier 只能看架构不能抄代码。
5. **和 Trairi 现有代码天然契合**：Tailscale 式需要「中心化协调」，而 Trairi 本来就有 server、登录、token、心跳、面板、配置——这些直接变成协调面，不需要另起一套 peer 协议。

---

## 4. 「参考 Tailscale」不成立的三件事

1. **不要做协议级兼容**。它的控制协议是私有 protobuf + Noise over HTTPS，服务端闭源且持续演进；Headscale 能对上是因为它逆向维护，属于长期高成本路线。我们要的是"像它一样工作"，不是"能连进它的网络"。
2. **不能移植代码**。Tailscale 是 Go，我们是 Rust。只能借架构，不能借实现（`boringtun` 是独立项目，不是 Tailscale 的代码）。
3. **中心化不是免费的**。你要自己写协调服务：虚拟 IP 分配、公钥登记与轮换、端点更新、ACL、以及 DERP 中继服务器。这一块 EasyTier 是靠去中心化 gossip 省掉的，我们换成了「必须有一个靠谱的中心」。

---

## 5. 在 Trairi 里怎么落

### 5.1 复用现有控制面

Trairi 已经有：登录 / `run_id` / token / 心跳 / 控制消息 / 面板。做法是把它们扩展成协调面：

```
客户端                                 Trairi 服务端
  │  Login（已有）                        │
  │  OverlayRegister{                        │
  │     wg_pubkey, desired_ip, hostname }  →  分配 10.144.144.x
  │  ← OverlayAssign{ip, peers[], derp}    │  把虚拟网段与公钥登记
  │                                        │
  │  OverlayPeers 拉取/推送（谁在线、       │  端点变化时广播
  │  公钥、最近观测到的公网端点）           │
  ▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔
  │  UDP 11013：WireGuard 数据面（直连）
  │  TCP 11012：DERP 式中继（直连不通时）
```

控制消息走**现有的 smux 通道 + 加密记录层**，一行不用重写；面板加一个 overlay 页展示 peer、连接类型（直连/中继）、延迟、流量。

### 5.2 新增模块

```
src/overlay/
├─ mod.rs          overlay 运行时（与现有 server/client 并行）
├─ tun.rs          虚拟网卡（windows: wintun / linux: /dev/net/tun）
├─ host.rs         地址与路由配置、退出清理（最关键，最容易留坑）
├─ wg.rs           boringtun 封装：喂 IP 包 → 出 UDP 报文，反之亦然
├─ coord.rs        协调消息（复用现控制面）
├─ direct.rs       UDP 直连 + STUN 探测 + 端点学习
├─ relay.rs        DERP 式中继客户端/服务端
└─ route.rs        虚拟网段 → peer 的查表与下发
```

### 5.3 配置形态（YAML）

```yaml
mode: server
overlay:
  enable: true
  network_name: my-home-net
  network_secret: 很长的随机串
  ipv4_pool: 10.144.144.0/24
  wg_listen: udp://0.0.0.0:11013        # 数据面
  relay_listen: tcp://0.0.0.0:11012     # 中继
  # 服务器自己也可以是一个节点
  node_ipv4: 10.144.144.1
```

```yaml
mode: client
overlay:
  enable: true
  network_name: my-home-net
  network_secret: 很长的随机串
  # 不填则由服务端分配
  # ipv4: 10.144.144.2
  proxy_networks:            # 想共享内网网段时
    - 192.168.1.0/24
```

```bash
trairi overlay status        # peers / 连接类型 / 延迟
trairi overlay cleanup       # 清理网卡与路由
```

---

## 6. 工作量（AI 辅助、单人估算）

| 阶段 | 内容 | Tailscale 式 | EasyTier 式（对比） |
|---|---|---|---|
| **P0** | TUN + host 路由 + 协调面 + WireGuard 直连（至少一方公网/同网） | 1.5~2 周 | 1~1.5 周 |
| **P1** | DERP 式中继兜底（保证「任何网络都能连上」） | ~1 周 | ~1 周 |
| **P2** | 打洞（STUN + 探测 + 端点漂移） | 2~3 周 | 1.5~2 周 |
| **P3** | 子网路由、MagicDNS、ACL、Web 页 | 1~1.5 周 | 2~3 周（还要 OSPF） |
| **合计** | | **约 5~6.5 周** | 约 6~8 周 |

差异的来源：**Tailscale 式把「加密」和「动态路由」两块硬骨头换成了成熟件 + 中心查表**；
代价是多了中心协调服务和中继服务器的运维，以及 P0 阶段要多接一个 WireGuard 状态机。

---

## 7. 风险与对策

| 风险 | 说明 | 对策 |
|---|---|---|
| `boringtun` 维护节奏 | Cloudflare 的项目更新不算快（当前 0.7.1） | 备选 `defguard_wireguard_rs`（0.12.5，更活跃）做对比；两者都是 WG 兼容，接口层抽象掉即可 |
| 用户态 WG 的性能 | 用户态转发比内核 WG 慢 | 批量收发 + 多队列；先保证千兆够用，后续可接系统 WG（Linux kernel / Windows 官方驱动） |
| 与官方 WireGuard 客户端共存 | 同一台机器装两个 WG 可能抢 11013/网卡 | 端口与网段可配，启动检测冲突 |
| Windows 服务化/提权 | 必须管理员；开机自启要注册服务 | 参考 EasyTier 的 install.ps1 思路，提供 `trairi overlay install-service` |
| 中心故障即全网不通 | 中心化架构的固有代价 | 协调面只负责「谁在哪」；已建立的直连不会因中心挂掉而断（类似 Tailscale 的 DERP/控制分离） |
| 密钥管理 | 私钥落盘、轮换、注销设备 | 私钥只存本地、登录时登记公钥、面板可踢设备 |

---

## 8. 建议

1. **采用 Tailscale 式架构**：WireGuard 数据面 + Trairi 现有控制面做协调 + DERP 式中继。
2. **分两段交付**：P0（直连）+ P1（中继）先做出「一定能连上」的版本；打洞（P2）作为体验优化后置。
3. **优先保证「互通官方 WireGuard 客户端」**：这是这条路线最大的差异化卖点，工程上也顺路。
4. 不要试图兼容 Tailscale/Headscale 协议；也不要第一版上 OSPF。
5. 无论选哪条路线，**Windows 管理员权限 + wintun.dll + 路由清理**这三件事都要面对，先把它做扎实。

---

## 9. 参考

- Tailscale 仓库（BSD-3）：<https://github.com/tailscale/tailscale>
- DERP 协议实现：`tailscale/derp/derp.go`（本目录 `research/tailscale_derp.txt` 存了协议头注释）
- headscale（控制面开源重写，仅供理解协议用）：<https://github.com/juanfont/headscale>
- `boringtun`（Cloudflare 的 Rust WireGuard）：crates.io 0.7.1
- `defguard_wireguard_rs`：crates.io 0.12.5
- 对照：[EasyTier 可行性调研](easytier-overlay-feasibility.md)
