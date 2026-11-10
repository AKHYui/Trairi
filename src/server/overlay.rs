//! 服务端 overlay 协调：节点登记、虚拟 IP 分配、公钥与端点分发。

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};

use crate::config::OverlayConfig;
use crate::overlay::{key_from_b64, key_to_b64, usable_hosts};
use crate::protocol::{ControlMsg, OverlayAssign, OverlayPeerInfo, OverlayPeers, OverlayRegister};

/// 服务端自身作为组网节点时使用的 run_id
pub const SERVER_NODE_ID: &str = "__server__";

/// 服务端自身的组网节点（共享同一个公网 IP，独立 UDP 端口）
pub struct ServerNode {
    pub handle: crate::overlay::node::NodeHandle,
    pub private: boringtun::x25519::StaticSecret,
    pub ip: std::net::Ipv4Addr,
    pub pubkey: [u8; 32],
    pub node_port: u16,
    pub ifname: String,
}

impl ServerNode {
    async fn start(cfg: &OverlayConfig) -> Result<Self> {
        let ip: std::net::Ipv4Addr = cfg
            .node_ipv4
            .parse()
            .with_context(|| format!("overlay.node_ipv4 非法: {}", cfg.node_ipv4))?;
        let node_port = cfg.udp_port + 3;

        let pool: ipnet::Ipv4Net = cfg.ipv4_pool.parse()?;
        let mut tun_cfg = cfg.clone();
        tun_cfg.interface = if cfg.interface.is_empty() {
            "trairi-srv".to_string()
        } else {
            format!("{}-srv", cfg.interface)
        };
        let device = crate::overlay::tunplat::create_tun(&tun_cfg, ip, pool.prefix_len())?;

        let sock = tokio::net::UdpSocket::bind(("0.0.0.0", node_port))
            .await
            .with_context(|| format!("服务端节点 UDP {node_port} 绑定失败"))?;
        let private = crate::overlay::node::generate_private();
        let pubkey = boringtun::x25519::PublicKey::from(&private).to_bytes();
        let handle = crate::overlay::node::start_node(
            Box::new(device),
            std::sync::Arc::new(sock),
            private.clone(),
            ip,
            cfg.mtu,
            Vec::new(),
            None,
        )
        .await?;

        tracing::info!("服务端自身作为组网节点：{ip}，UDP 端口 {node_port}");
        Ok(Self {
            handle,
            private,
            ip,
            pubkey,
            node_port,
            ifname: tun_cfg.interface.clone(),
        })
    }
}

/// 服务端探测客户端公网地址用的 UDP 报文魔数
pub const PROBE_MAGIC: &[u8; 8] = b"TRIRUD01";

/// 网络里的一个成员
pub struct Member {
    pub run_id: String,
    pub pubkey: [u8; 32],
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub endpoint: Option<SocketAddr>,
    pub last_seen: Instant,
    pub hostname: String,
    pub proxy_networks: Vec<String>,
}

/// 一个虚拟网络
pub struct Network {
    pub name: String,
    pub secret_hash: String,
    pub pool: ipnet::Ipv4Net,
    members: RwLock<HashMap<String, Member>>,
}

impl Network {
    async fn snapshot(&self, exclude: Option<&str>) -> Vec<OverlayPeerInfo> {
        let members = self.members.read().await;
        members
            .values()
            .filter(|m| Some(m.run_id.as_str()) != exclude)
            .map(|m| OverlayPeerInfo {
                run_id: m.run_id.clone(),
                pubkey: key_to_b64(&m.pubkey),
                ip: m.ip.to_string(),
                endpoint: m.endpoint.map(|e| e.to_string()).unwrap_or_default(),
                is_server: m.run_id == SERVER_NODE_ID,
                hostname: m.hostname.clone(),
                proxy_networks: m.proxy_networks.clone(),
            })
            .collect()
    }

    async fn assign_ip(&self, want: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        let used: HashSet<Ipv4Addr> = {
            let members = self.members.read().await;
            members.values().map(|m| m.ip).collect()
        };
        if let Some(ip) = want {
            if self.pool.contains(&ip) && !used.contains(&ip) {
                return Some(ip);
            }
        }
        for ip in usable_hosts(&self.pool) {
            if !used.contains(&ip) {
                return Some(ip);
            }
        }
        None
    }
}

/// overlay 协调器
pub struct OverlayCoordinator {
    pub networks: RwLock<HashMap<String, Arc<Network>>>,
    pub udp_port: u16,
    pub relay_port: u16,
    pub stun_port: u16,
    /// 服务端自身作为组网节点（未启用为 None）
    pub node: Option<Arc<ServerNode>>,
    /// 下发给所有节点的 ACL 规则
    pub acl: Vec<String>,
    pub mtu: u16,
    /// 已在控制面登记的公钥（中继只允许这些公钥接入）
    pub pubkeys: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// run_id -> 控制消息发送端（用于主动推送 peer 列表）
    senders: RwLock<HashMap<String, mpsc::Sender<ControlMsg>>>,
}

impl OverlayCoordinator {
    pub async fn new(cfg: &OverlayConfig) -> Result<Arc<Self>> {
        let pool: ipnet::Ipv4Net = cfg
            .ipv4_pool
            .parse()
            .with_context(|| format!("overlay.ipv4_pool 非法: {}", cfg.ipv4_pool))?;

        let udp = UdpSocket::bind(("0.0.0.0", cfg.udp_port))
            .await
            .with_context(|| format!("overlay UDP 端口 {} 绑定失败", cfg.udp_port))?;
        let udp_port = udp.local_addr()?.port();
        let socket = Arc::new(udp);

        // 中继端口：relay_listen 形如 "0.0.0.0:11012"；留空或端口 0 表示关闭
        let relay_port = cfg
            .relay_listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(0);

        // 第二个 STUN 端口（udp_port + 1），用于探测客户端 NAT 映射行为
        let stun_sock = if cfg.udp_port > 0 {
            tokio::net::UdpSocket::bind(("0.0.0.0", cfg.udp_port + 1))
                .await
                .ok()
                .map(Arc::new)
        } else {
            None
        };
        let stun_port = stun_sock
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);

        // 服务端自身作为组网节点（需要 root/管理员建 TUN）
        let node = if cfg.node_ipv4.trim().is_empty() {
            None
        } else {
            match ServerNode::start(cfg).await {
                Ok(n) => Some(Arc::new(n)),
                Err(e) => {
                    tracing::error!("服务端节点启动失败（将只做协调/中继）: {e:#}");
                    None
                }
            }
        };

        let pubkeys = Arc::new(RwLock::new(HashSet::new()));
        let coord = Arc::new(Self {
            networks: RwLock::new(HashMap::new()),
            udp_port,
            relay_port,
            stun_port,
            mtu: cfg.mtu,
            senders: RwLock::new(HashMap::new()),
            node: node.clone(),
            acl: cfg.acl.clone(),
            pubkeys,
        });

        {
            let mut nets = coord.networks.write().await;
            nets.insert(
                cfg.network_name.clone(),
                Arc::new(Network {
                    name: cfg.network_name.clone(),
                    secret_hash: crate::overlay::secret_hash(&cfg.network_secret),
                    pool,
                    members: RwLock::new(HashMap::new()),
                }),
            );
        }

        // 把服务端节点自己登记进网络
        if let Some(n) = &node {
            let nets = coord.networks.read().await;
            if let Some(net) = nets.get(&cfg.network_name) {
                net.members.write().await.insert(
                    SERVER_NODE_ID.to_string(),
                    Member {
                        run_id: SERVER_NODE_ID.to_string(),
                        pubkey: n.pubkey,
                        ip: n.ip,
                        udp_port: n.node_port,
                        endpoint: None,
                        last_seen: Instant::now(),
                        hostname: "server".to_string(),
                        proxy_networks: Vec::new(),
                    },
                );
            }
        }

        // UDP 监听：学习客户端公网 endpoint + 应答 STUN 绑定请求
        let me = coord.clone();
        let sock = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                // STUN 绑定请求
                if crate::overlay::stun::is_stun(&buf[..n]) {
                    if let Some(resp) = crate::overlay::stun::build_binding_response(&buf[..n], src)
                    {
                        let _ = sock.send_to(&resp, src).await;
                    }
                    continue;
                }
                if n < PROBE_MAGIC.len() + 32 {
                    continue;
                }
                if &buf[..PROBE_MAGIC.len()] != PROBE_MAGIC {
                    continue;
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&buf[PROBE_MAGIC.len()..PROBE_MAGIC.len() + 32]);
                if me.learn_endpoint(&pk, src).await {
                    tracing::debug!("overlay 学习到 endpoint: {src}");
                }
            }
        });

        // 第二个 STUN 端口：只做绑定应答
        if let Some(stun) = stun_sock.clone() {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let Ok((n, src)) = stun.recv_from(&mut buf).await else {
                        continue;
                    };
                    if !crate::overlay::stun::is_stun(&buf[..n]) {
                        continue;
                    }
                    if let Some(resp) = crate::overlay::stun::build_binding_response(&buf[..n], src)
                    {
                        let _ = stun.send_to(&resp, src).await;
                    }
                }
            });
            tracing::info!("overlay STUN 端口 {stun_port}（用于 NAT 映射探测）");
        }

        // TCP 中继（直连不通时兜底）
        if relay_port > 0 {
            let listener = tokio::net::TcpListener::bind(&cfg.relay_listen)
                .await
                .with_context(|| format!("overlay.relay_listen 绑定失败: {}", cfg.relay_listen))?;
            let real_port = crate::overlay::relay::spawn_relay_server(
                listener,
                cfg.network_name.clone(),
                crate::overlay::secret_hash(&cfg.network_secret),
                Some(coord.pubkeys.clone()),
            )
            .await?;
            tracing::info!("overlay 中继端口 {real_port}");
        }

        tracing::info!(
            "overlay 已启用：网络 {}，地址池 {}，UDP 端口 {}",
            cfg.network_name,
            cfg.ipv4_pool,
            udp_port
        );
        Ok(coord)
    }

    pub async fn add_sender(&self, run_id: &str, tx: mpsc::Sender<ControlMsg>) {
        self.senders.write().await.insert(run_id.to_string(), tx);
    }

    pub async fn remove_sender(&self, run_id: &str) {
        self.senders.write().await.remove(run_id);
        let nets = self.networks.read().await;
        for net in nets.values() {
            net.members.write().await.remove(run_id);
        }
        // 重建中继公钥白名单，避免已下线节点的 pubkey 永久有效
        let mut live = HashSet::new();
        for net in nets.values() {
            for m in net.members.read().await.values() {
                live.insert(m.pubkey);
            }
        }
        *self.pubkeys.write().await = live;
    }

    /// 客户端登记，返回分配结果；成功后广播给同网其它节点。
    pub async fn register(
        &self,
        run_id: &str,
        req: &OverlayRegister,
    ) -> Result<OverlayAssign, String> {
        let net = {
            let nets = self.networks.read().await;
            nets.get(&req.network).cloned()
        };
        let Some(net) = net else {
            return Err(format!("未知网络: {}", req.network));
        };
        if net.secret_hash != req.secret_hash {
            return Err("网络密钥不正确".to_string());
        }
        let pubkey = key_from_b64(&req.pubkey).map_err(|e| format!("公钥非法: {e}"))?;

        // 兼容 "10.144.144.2" 和 "10.144.144.2/32" 两种写法
        let want = if req.want_ip.trim().is_empty() {
            None
        } else {
            crate::config::parse_ipv4_prefix(req.want_ip.trim())
                .ok()
                .map(|n| n.addr())
        };

        // 同一个 run_id 重复登记：沿用原 IP
        let existing_ip = {
            let members = net.members.read().await;
            members.get(run_id).map(|m| m.ip)
        };

        let ip = match existing_ip {
            Some(ip) => ip,
            None => net
                .assign_ip(want)
                .await
                .ok_or_else(|| "地址池已耗尽".to_string())?,
        };

        {
            let mut members = net.members.write().await;
            let old_endpoint = members.get(run_id).and_then(|m| m.endpoint);
            members.insert(
                run_id.to_string(),
                Member {
                    run_id: run_id.to_string(),
                    pubkey,
                    ip,
                    udp_port: req.udp_port,
                    endpoint: old_endpoint,
                    last_seen: Instant::now(),
                    hostname: req.hostname.clone(),
                    proxy_networks: req.proxy_networks.clone(),
                },
            );
        }

        // 中继只接受已经通过控制面登记的公钥
        self.pubkeys.write().await.insert(pubkey);

        let peers = net.snapshot(Some(run_id)).await;
        tracing::info!(
            "overlay 节点 {run_id} 加入网络 {}，分配 {ip}，当前 {} 个对端",
            net.name,
            peers.len()
        );

        // 通知其它节点
        self.broadcast_peers(&net.name).await;

        Ok(OverlayAssign {
            ok: true,
            error: String::new(),
            ip: ip.to_string(),
            cidr: net.pool.to_string(),
            mtu: self.mtu,
            server_udp_port: self.udp_port,
            server_relay_port: self.relay_port,
            server_stun_port: self.stun_port,
            server_node_port: self.node.as_ref().map(|n| n.node_port).unwrap_or(0),
            acl: self.acl.clone(),
            peers,
        })
    }

    /// 学习到某个公钥对应的公网 endpoint。
    async fn learn_endpoint(&self, pubkey: &[u8; 32], src: SocketAddr) -> bool {
        let nets: Vec<Arc<Network>> = self.networks.read().await.values().cloned().collect();
        for net in nets {
            let mut changed = false;
            {
                let mut members = net.members.write().await;
                for m in members.values_mut() {
                    if &m.pubkey == pubkey && m.endpoint != Some(src) {
                        m.endpoint = Some(src);
                        m.last_seen = Instant::now();
                        changed = true;
                    }
                }
            }
            if changed {
                let name = net.name.clone();
                self.broadcast_peers(&name).await;
                return true;
            }
        }
        false
    }

    /// 把某个网络的最新节点列表推给所有成员。
    pub async fn broadcast_peers(&self, network: &str) {
        let net = {
            let nets = self.networks.read().await;
            nets.get(network).cloned()
        };
        let Some(net) = net else { return };

        let members: Vec<String> = { net.members.read().await.keys().cloned().collect() };
        let senders = self.senders.read().await;

        for run_id in members {
            let peers = net.snapshot(Some(&run_id)).await;
            if let Some(tx) = senders.get(&run_id) {
                let _ = tx
                    .send(ControlMsg::OverlayPeers(OverlayPeers { peers }))
                    .await;
            }
        }
        drop(senders);

        // 服务端节点自己也要更新对端表
        if let Some(node) = &self.node {
            let entries = net.snapshot(Some(SERVER_NODE_ID)).await;
            let mut specs = Vec::new();
            let mut ips = Vec::new();
            for p in entries {
                let Ok(ip) = p.ip.parse::<Ipv4Addr>() else {
                    continue;
                };
                let Ok(pk) = crate::overlay::key_from_b64(&p.pubkey) else {
                    continue;
                };
                specs.push(crate::overlay::node::PeerSpec {
                    ip,
                    pubkey: pk,
                    endpoint: crate::overlay::node::parse_endpoint(&p.endpoint).unwrap_or(None),
                });
                ips.push(ip);
            }
            node.handle.update_peers(specs, &node.private).await;
            if !ips.is_empty() {
                crate::overlay::host::ensure_peer_routes(&node.ifname, &ips);
            }
        }
    }

    /// 面板用：当前所有网络的节点信息。
    pub async fn snapshot_all(&self) -> Vec<(String, Vec<OverlayPeerInfo>)> {
        let nets = self.networks.read().await;
        let mut out = Vec::new();
        for net in nets.values() {
            out.push((net.name.clone(), net.snapshot(None).await));
        }
        out
    }
}

/// 客户端用来告诉服务端「我在这里」的探测包。
pub fn build_probe(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(PROBE_MAGIC.len() + 32);
    v.extend_from_slice(PROBE_MAGIC);
    v.extend_from_slice(pubkey);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_format() {
        let pk = [1u8; 32];
        let p = build_probe(&pk);
        assert_eq!(p.len(), 40);
        assert_eq!(&p[..8], PROBE_MAGIC);
        assert_eq!(&p[8..], &pk);
    }
}
