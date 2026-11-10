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

    // 探测自己的公网地址
    if assign.server_udp_port > 0 {
        let target = format!("{server_addr}:{}", assign.server_udp_port);
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
                    format!("{server_addr}:{}", assign.server_node_port)
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
            });
            ips.push(ip);
        }
    }

    // 连上服务端中继（直连不通时兜底）
    let relay = if cfg.relay && assign.server_relay_port > 0 {
        let addr = format!("{server_addr}:{}", assign.server_relay_port);
        let hash = secret_hash(&cfg.network_secret);
        let public = boringtun::x25519::PublicKey::from(&private).to_bytes();
        match crate::overlay::relay::RelayClient::connect(&addr, &cfg.network_name, &hash, public)
            .await
        {
            Ok(r) => {
                tracing::info!("overlay 中继已连接 {addr}");
                Some(r)
            }
            Err(e) => {
                tracing::warn!("连接 overlay 中继 {addr} 失败: {e:#}");
                None
            }
        }
    } else {
        None
    };

    // NAT 探测：必须用同一个 UDP socket（保证 NAT 映射一致），且在启动数据面之前
    if assign.server_udp_port > 0 {
        let a = format!("{server_addr}:{}", assign.server_udp_port);
        let addr_a = tokio::net::lookup_host(&a)
            .await
            .ok()
            .and_then(|mut it| it.next());

        // 判断映射行为要求「对端 IP 不同」：优先用配置里的外部 STUN，
        // 否则退化成同 IP 不同端口（结论较弱，只作参考）。
        let mut addr_b: Option<std::net::SocketAddr> = None;
        let mut strong = false;
        if let Some(host) = cfg.stun_servers.first() {
            if let Ok(mut it) = tokio::net::lookup_host(host.clone()).await {
                addr_b = it.next();
            }
            strong = true;
        } else if assign.server_stun_port > 0 {
            let b = format!("{server_addr}:{}", assign.server_stun_port);
            addr_b = tokio::net::lookup_host(&b)
                .await
                .ok()
                .and_then(|mut it| it.next());
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
        Box::new(device),
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
        server_addr: server_addr.to_string(),
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
pub fn register_msg(cfg: &OverlayConfig, public_b64: &str, udp_port: u16) -> OverlayRegister {
    OverlayRegister {
        network: cfg.network_name.clone(),
        secret_hash: secret_hash(&cfg.network_secret),
        pubkey: public_b64.to_string(),
        udp_port,
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
