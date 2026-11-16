//! 客户端 overlay 运行时：建网卡、注册、装 peer 表、发包探测公网地址。

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use boringtun::x25519::StaticSecret;
use tokio::net::UdpSocket;

use crate::config::OverlayConfig;
use crate::config::parse_ipv4_prefix;
use crate::overlay::node::{self, NodeHandle, PeerSpec};
use crate::overlay::tunplat;
use crate::overlay::{key_from_b64, key_to_b64, secret_hash};
use crate::protocol::{OverlayAssign, OverlayPeerInfo, OverlayRegister};

/// 客户端侧的 overlay 实例。
pub struct OverlayClient {
    pub node: NodeHandle,
    pub ifname: String,
    pub ip: Ipv4Addr,
    private: StaticSecret,
    peers: tokio::sync::RwLock<Vec<Ipv4Addr>>,
    direct: bool,
    server_addr: String,
    server_node_port: u16,
    magic_dns: bool,
}

impl OverlayClient {
    /// 用服务端下发的节点表刷新本地表，并同步 /32 路由。
    pub async fn apply_peers(&self, peers: &[OverlayPeerInfo]) {
        let mut specs = Vec::new();
        for p in peers {
            let Ok(ip) = p.ip.parse::<Ipv4Addr>() else {
                continue;
            };
            let Ok(pk) = key_from_b64(&p.pubkey) else {
                tracing::warn!("节点 {} 的公钥非法，跳过", p.run_id);
                continue;
            };
            // direct = false 时忽略 endpoint，强制走中继
            let endpoint = if !self.direct {
                None
            } else if p.is_server {
                // 服务端节点：客户端用自己连服务端用的地址去凑（服务端不知道自己的公网 IP）
                if self.server_node_port > 0 {
                    format!("{}:{}", self.server_addr, self.server_node_port)
                        .parse()
                        .ok()
                } else {
                    None
                }
            } else {
                match node::parse_endpoint(&p.endpoint) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!("节点 {} 的 endpoint 非法: {e}", p.run_id);
                        None
                    }
                }
            };
            specs.push(PeerSpec {
                ip,
                pubkey: pk,
                endpoint,
                endpoints: p.endpoints.iter().filter_map(|s| node::parse_endpoint(s).ok().flatten()).collect(),
                tcp_endpoint: p.tcp_endpoint.parse().ok(),
                relay_allowed: !p.is_server,
            });
        }
        let ips: Vec<Ipv4Addr> = specs.iter().map(|s| s.ip).collect();
        let routes: Vec<(ipnet::Ipv4Net, Ipv4Addr)> = peers
            .iter()
            .filter_map(|p| {
                let ip = p.ip.parse::<Ipv4Addr>().ok()?;
                Some((ip, p.proxy_networks.clone()))
            })
            .flat_map(|(ip, cidrs)| {
                cidrs
                    .into_iter()
                    .filter_map(move |c| c.parse::<ipnet::Ipv4Net>().ok().map(|n| (n, ip)))
            })
            .collect();
        self.node
            .update_peers_with_routes(specs, routes.clone(), &self.private)
            .await;
        if !routes.is_empty() {
            let cidrs: Vec<ipnet::Ipv4Net> = routes.iter().map(|(n, _)| *n).collect();
            crate::overlay::host::ensure_cidr_routes(&self.ifname, &cidrs);
        }

        // MagicDNS：主机名变化时同步 hosts
        if self.magic_dns {
            let entries: Vec<(String, Ipv4Addr)> = peers
                .iter()
                .filter_map(|p| Some((p.hostname.clone(), p.ip.parse::<Ipv4Addr>().ok()?)))
                .filter(|(n, _)| !n.is_empty())
                .collect();
            crate::overlay::hosts::sync(&entries);
        }

        // 给新出现的对端补路由
        let mut known = self.peers.write().await;
        let new: Vec<Ipv4Addr> = ips
            .iter()
            .copied()
            .filter(|ip| !known.contains(ip))
            .collect();
        if !new.is_empty() {
            crate::overlay::host::ensure_peer_routes(&self.ifname, &new);
            known.extend(new);
        }
    }

    /// 当前的表内对端 IP（退出时清路由用）
    pub async fn ips(&self) -> Vec<Ipv4Addr> {
        self.peers.read().await.clone()
    }

    /// 供面板/日志展示
    pub async fn status(&self) -> (usize, (u64, u64)) {
        (self.node.peer_count().await, self.node.bytes())
    }
}

/// 建立 overlay 客户端。
///
/// 调用方负责：生成密钥、绑定 UDP socket、发送注册消息、拿到分配结果，
/// 然后把同一个密钥和 socket 交进来。
pub async fn setup(
    cfg: &OverlayConfig,
    server_addr: &str,
    assign: OverlayAssign,
    private: StaticSecret,
    socket: Arc<UdpSocket>,
) -> Result<OverlayClient> {
    if !assign.ok {
        bail!("服务端拒绝了 overlay 登记: {}", assign.error);
    }

    // 域名必须走 A 记录。否则 DNS 的 IPv6 结果会让控制面连上，
    // 但 overlay UDP/relay/server-node 全部不可达。
    let server_ip = crate::transport::resolve_server_addr(
        server_addr,
        assign.server_udp_port.max(1),
    )
    .await?;
    let server_host = server_ip.ip().to_string();

    let ip: Ipv4Addr = assign
        .ip
        .parse()
        .with_context(|| format!("服务端分配的 IP 非法: {}", assign.ip))?;
    let cidr = parse_ipv4_prefix(&assign.cidr)
        .with_context(|| format!("服务端下发的网段非法: {}", assign.cidr))?;
    let prefix = cidr.prefix_len();

    let mut tun_cfg = cfg.clone();
    tun_cfg.mtu = assign.mtu.max(576);

    let device = tunplat::create_tun(&tun_cfg, ip, prefix)?;

    // Best-effort automatic router mapping. This is what makes symmetric NAT
    // usable without asking the user to open a port by hand. Failure is not
    // fatal: relay fallback remains.
    #[cfg(not(target_os = "android"))]
    {
        let mapped = match crate::overlay::upnp::try_map(socket.as_ref()).await {
            Ok(port) => Some(port),
            Err(e) => {
                tracing::info!("UPnP 自动端口映射不可用: {e:#}");
                match crate::overlay::natpmp::try_map(socket.local_addr()?.port()).await {
                    Ok(port) => Some(port),
                    Err(e) => {
                        tracing::info!("NAT-PMP 自动端口映射不可用: {e:#}");
                        None
                    }
                }
            }
        };
        if let Some(port) = mapped {
            tracing::debug!("自动端口映射外部端口 {port}");
        }
    }

    // 探测自己的公网地址
    if assign.server_udp_port > 0 {
        let target = format!("{server_host}:{}", assign.server_udp_port);
        match tokio::net::lookup_host(&target).await {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    let probe = crate::server::overlay::build_probe(
                        &boringtun::x25519::PublicKey::from(&private).to_bytes(),
                    );
                    if let Err(e) = socket.send_to(&probe, addr).await {
                        tracing::warn!("发送 overlay 探测包失败: {e}");
                    }
                }
            }
            Err(e) => tracing::warn!("解析服务端 overlay 地址 {target} 失败: {e}"),
        }
    }

    let mut specs = Vec::new();
    let mut ips = Vec::new();
    for p in &assign.peers {
        if let (Ok(ip), Ok(pk)) = (p.ip.parse::<Ipv4Addr>(), key_from_b64(&p.pubkey)) {
            let endpoint = if !cfg.direct {
                None
            } else if p.is_server {
                if assign.server_node_port > 0 {
                    format!("{server_host}:{}", assign.server_node_port)
                        .parse()
                        .ok()
                } else {
                    None
                }
            } else {
                node::parse_endpoint(&p.endpoint).unwrap_or(None)
            };
            specs.push(PeerSpec {
                ip,
                pubkey: pk,
                endpoint,
                endpoints: p.endpoints.iter().filter_map(|s| node::parse_endpoint(s).ok().flatten()).collect(),
                tcp_endpoint: p.tcp_endpoint.parse().ok(),
                relay_allowed: !p.is_server,
            });
            ips.push(ip);
        }
    }

    // 配置服务端中继（直连不通时兜底）；连接与断线重连由 RelayLink 后台维护。
    let relay = if cfg.relay && assign.server_relay_port > 0 {
        let addr = format!("{server_host}:{}", assign.server_relay_port);
        let hash = secret_hash(&cfg.network_secret);
        let public = boringtun::x25519::PublicKey::from(&private).to_bytes();
        tracing::info!("overlay 中继已配置 {addr}（断线自动重连）");
        Some(crate::overlay::relay::RelayLink::new(
            addr,
            cfg.network_name.clone(),
            hash,
            public,
        ))
    } else {
        None
    };

    // NAT 探测：必须用同一个 UDP socket（保证 NAT 映射一致），且在启动数据面之前
    if assign.server_udp_port > 0 {
        let a = format!("{server_host}:{}", assign.server_udp_port);
        let addr_a = tokio::net::lookup_host(&a)
            .await
            .ok()
            .and_then(|mut it| it.next());

        // 判断映射行为要求「对端 IP 不同」：优先用配置里的外部 STUN，
        // 否则退化成同 IP 不同端口（结论较弱，只作参考）。
        let mut addr_b: Option<std::net::SocketAddr> = None;
        let mut strong = false;
        let default_stun: &[&str] = &["stun.qq.com:3478", "stun.miwifi.com:3478"];
        let stun_hosts: Vec<String> = if cfg.stun_servers.is_empty() {
            default_stun.iter().map(|s| (*s).to_string()).collect()
        } else {
            cfg.stun_servers.clone()
        };
        for host in stun_hosts {
            if let Ok(it) = tokio::net::lookup_host(host.clone()).await {
                if let Some(a) = it.filter(|a| a.is_ipv4()).next() {
                    addr_b = Some(a);
                    strong = true;
                    break;
                }
            }
        }

        if let Some(addr_a) = addr_a {
            let probe = match addr_b {
                Some(bb) => crate::overlay::stun::probe_mapping(&socket, addr_a, bb).await,
                None => crate::overlay::stun::binding(&socket, addr_a)
                    .await
                    .map(|m| (m, crate::overlay::stun::MappingBehavior::Unknown)),
            };
            match probe {
                Ok((mapped, behavior)) => {
                    tracing::info!(
                        "overlay NAT：本机公网映射 {mapped}，端口映射行为 {}{}",
                        behavior.as_str(),
                        if strong {
                            ""
                        } else {
                            "（仅同 IP 不同端口对比，结果仅供参考；可在 overlay.stun_servers 里配一个不同 IP 的 STUN 服务器）"
                        }
                    );
                }
                Err(e) => tracing::debug!("overlay NAT 探测失败: {e:#}"),
            }
        }
    }

    let node = node::start_node(
        device,
        socket,
        private.clone(),
        ip,
        tun_cfg.mtu,
        specs.clone(),
        relay,
    )
    .await?;

    if !ips.is_empty() {
        crate::overlay::host::ensure_peer_routes(&cfg.interface, &ips);
    }

    // 共享子网路由：把对端声明的内网网段接到虚拟网卡上
    let routes: Vec<(ipnet::Ipv4Net, Ipv4Addr)> = assign
        .peers
        .iter()
        .filter_map(|p| Some((p.ip.parse::<Ipv4Addr>().ok()?, p.proxy_networks.clone())))
        .flat_map(|(peer_ip, cidrs)| {
            cidrs
                .into_iter()
                .filter_map(move |c| c.parse::<ipnet::Ipv4Net>().ok().map(|n| (n, peer_ip)))
        })
        .collect();
    if !routes.is_empty() {
        let cidrs: Vec<ipnet::Ipv4Net> = routes.iter().map(|(n, _)| *n).collect();
        crate::overlay::host::ensure_cidr_routes(&cfg.interface, &cidrs);
        node.update_peers_with_routes(specs, routes, &private).await;
        tracing::info!("已接入 {} 个共享子网", cidrs.len());
    }

    // 服务端下发的 ACL
    node.set_acl(&assign.acl).await;
    if !assign.acl.is_empty() {
        tracing::info!("已应用 {} 条 ACL 规则", assign.acl.len());
    }

    // MagicDNS：把节点主机名写进 hosts
    if cfg.magic_dns {
        let entries: Vec<(String, Ipv4Addr)> = assign
            .peers
            .iter()
            .filter_map(|p| Some((p.hostname.clone(), p.ip.parse::<Ipv4Addr>().ok()?)))
            .filter(|(n, _)| !n.is_empty())
            .collect();
        crate::overlay::hosts::sync(&entries);
    }

    tracing::info!(
        "overlay 已启动：本机 {ip}/{}，网卡 {}，{} 个对端",
        prefix,
        cfg.interface,
        ips.len()
    );

    Ok(OverlayClient {
        node,
        ifname: cfg.interface.clone(),
        ip,
        private,
        peers: tokio::sync::RwLock::new(ips),
        direct: cfg.direct,
        server_addr: server_host,
        server_node_port: assign.server_node_port,
        magic_dns: cfg.magic_dns,
    })
}

/// 生成一对密钥，返回 (私钥, 公钥 base64)。
pub fn generate_keypair() -> (StaticSecret, String) {
    let private = node::generate_private();
    let public = boringtun::x25519::PublicKey::from(&private).to_bytes();
    (private, key_to_b64(&public))
}

/// 构造注册消息。
pub fn register_msg(
    cfg: &OverlayConfig,
    public_b64: &str,
    udp_port: u16,
    ipv6: &str,
) -> OverlayRegister {
    OverlayRegister {
        network: cfg.network_name.clone(),
        secret_hash: secret_hash(&cfg.network_secret),
        pubkey: public_b64.to_string(),
        udp_port,
        ipv6: ipv6.to_string(),
        // 只发 IP 部分，掩码由服务端按地址池决定
        hostname: crate::client::hostname_static(),
        proxy_networks: cfg.proxy_networks.clone(),
        want_ip: cfg
            .ipv4
            .split('/')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

/// 等待分配结果的超时。
pub const ASSIGN_TIMEOUT: Duration = Duration::from_secs(15);

/// Parse a 32-hex-character address from /proc/net/if_inet6.
#[cfg(target_os = "linux")]
fn hex_ipv6(s: &str) -> Result<std::net::Ipv6Addr> {
    if s.len() != 32 {
        anyhow::bail!("IPv6 hex length");
    }
    let mut octets = [0u8; 16];
    for (i, byte) in octets.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(std::net::Ipv6Addr::from(octets))
}

/// Best-effort global/local IPv6 address for dual-stack P2P signaling.
pub async fn local_ipv6() -> Option<std::net::Ipv6Addr> {    #[cfg(target_os = "linux")]
    {
        // Prefer a global address with a normal prefix. The WSL/VM bridge can
        // expose a /128 `...::1` address that is not routable from the peer.
        if let Ok(text) = std::fs::read_to_string("/proc/net/if_inet6") {
            let mut best = None;
            for line in text.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 6 {
                    continue;
                }
                let scope = u32::from_str_radix(cols[3], 16).unwrap_or(0);
                let plen = u32::from_str_radix(cols[2], 16).unwrap_or(128);
                if scope != 0 || plen >= 128 {
                    continue;
                }
                let Ok(addr) = hex_ipv6(cols[0]) else {
                    continue;
                };
                if addr.is_loopback() || addr.is_unspecified() {
                    continue;
                }
                if best.is_none() {
                    best = Some(addr);
                }
            }
            if best.is_some() {
                return best;
            }
        }
    }

    let sock = tokio::net::UdpSocket::bind("[::]:0").await.ok()?;
    sock.connect("[2001:4860:4860::8888]:80").await.ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V6(v) if !v.is_unspecified() && !v.is_loopback() => Some(v),
        _ => None,
    }
}
