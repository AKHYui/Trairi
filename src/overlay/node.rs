//! overlay 运行时：把 TUN、WireGuard 状态机、UDP socket、TCP 中继串起来。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Mutex, RwLock, mpsc};

use crate::overlay::device::IpDevice;
use crate::overlay::relay::RelayLink;
use crate::overlay::wg::{Path, SendPaths, WgAction, WgPeer, wg_message_type};
use crate::overlay::{ipv4_dst, key_to_b64};

/// 打洞探测包的魔数（8 字节魔数 + 32 字节公钥）
pub const PUNCH_MAGIC: &[u8; 8] = b"TRIRPN01";

/// 构造一个打洞探测包。
pub fn build_punch(public_key: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(PUNCH_MAGIC.len() + 32);
    v.extend_from_slice(PUNCH_MAGIC);
    v.extend_from_slice(public_key);
    v
}

/// 是不是打洞探测包。
pub fn is_punch(buf: &[u8]) -> bool {
    buf.len() == PUNCH_MAGIC.len() + 32 && &buf[..PUNCH_MAGIC.len()] == PUNCH_MAGIC
}

#[derive(Debug, Clone)]
pub struct PeerSpec {
    pub ip: Ipv4Addr,
    pub pubkey: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    /// Additional endpoints learned from STUN/punches/IPv6 signaling.
    pub endpoints: Vec<SocketAddr>,
    /// Optional TCP direct endpoint (same numeric port as UDP by default).
    pub tcp_endpoint: Option<SocketAddr>,
    /// Whether this peer can be reached via the server's TCP relay.
    /// The server-node peer is direct-only.
    pub relay_allowed: bool,
}

type PeerMap = Arc<RwLock<HashMap<Ipv4Addr, Arc<Mutex<WgPeer>>>>>;

/// 对外暴露的节点句柄。
pub struct NodeHandle {
    pub public_key: [u8; 32],
    pub ip: Ipv4Addr,
    peers: PeerMap,
    endpoints: Arc<RwLock<HashMap<SocketAddr, Ipv4Addr>>>,
    stats_tx: Arc<AtomicU64>,
    stats_rx: Arc<AtomicU64>,
    relay_active: Arc<std::sync::atomic::AtomicBool>,
    routes: Arc<RwLock<Vec<(ipnet::Ipv4Net, Ipv4Addr)>>>,
    acl: Arc<RwLock<crate::overlay::acl::Acl>>,
}

impl NodeHandle {
    pub fn public_key_b64(&self) -> String {
        key_to_b64(&self.public_key)
    }

    pub async fn peer_endpoints(&self) -> Vec<(Ipv4Addr, Option<SocketAddr>)> {
        let peers = self.peers.read().await;
        let mut out = Vec::new();
        for (ip, p) in peers.iter() {
            let ep = p.lock().await.endpoint;
            out.push((*ip, ep));
        }
        out
    }

    /// 有多少对端已经锁定走中继。
    pub async fn relayed_peers(&self) -> usize {
        let peers = self.peers.read().await;
        let mut n = 0;
        for p in peers.values() {
            if p.lock().await.is_relay_locked() {
                n += 1;
            }
        }
        n
    }

    pub fn relay_active(&self) -> bool {
        self.relay_active.load(Ordering::Relaxed)
    }

    pub fn bytes(&self) -> (u64, u64) {
        (
            self.stats_tx.load(Ordering::Relaxed),
            self.stats_rx.load(Ordering::Relaxed),
        )
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// 设置 ACL（空表示全部放行）。
    pub async fn set_acl(&self, rules: &[String]) {
        let parsed = crate::overlay::acl::Acl::parse(rules);
        *self.acl.write().await = parsed;
    }

    /// 全量替换对端表，同时更新共享子网路由表。
    pub async fn update_peers_with_routes(
        &self,
        specs: Vec<PeerSpec>,
        routes: Vec<(ipnet::Ipv4Net, Ipv4Addr)>,
        private: &StaticSecret,
    ) {
        *self.routes.write().await = routes;
        self.update_peers(specs, private).await;
    }

    /// 当前的共享子网路由表。
    pub async fn routes(&self) -> Vec<(ipnet::Ipv4Net, Ipv4Addr)> {
        self.routes.read().await.clone()
    }

    /// 全量替换对端表（公钥不变的保留会话，只更新 endpoint）。
    pub async fn update_peers(&self, specs: Vec<PeerSpec>, private: &StaticSecret) {
        let current = { self.peers.read().await.clone() };
        let mut map = HashMap::new();
        let mut eps = HashMap::new();

        for (idx, spec) in specs.into_iter().enumerate() {
            let peer = match current.get(&spec.ip) {
                Some(p) => {
                    let same_key = {
                        let g = p.lock().await;
                        g.pubkey == spec.pubkey
                    };
                    if same_key {
                        p.clone()
                    } else {
                        Arc::new(Mutex::new(WgPeer::new(
                            private,
                            spec.pubkey,
                            spec.ip,
                            idx as u32,
                            None,
                        )))
                    }
                }
                None => Arc::new(Mutex::new(WgPeer::new(
                    private,
                    spec.pubkey,
                    spec.ip,
                    idx as u32,
                    None,
                ))),
            };
            {
                let mut g = peer.lock().await;
                if let Some(ep) = spec.endpoint {
                    g.learn_candidate(ep);
                    g.endpoint = Some(ep);
                }
                for ep in &spec.endpoints {
                    g.learn_candidate(*ep);
                }
                g.relay_allowed = spec.relay_allowed;
                g.tcp_endpoint = spec.tcp_endpoint;
            }
            if let Some(ep) = spec.endpoint {
                eps.insert(ep, spec.ip);
            }
            for ep in spec.endpoints {
                eps.insert(ep, spec.ip);
            }
            map.insert(spec.ip, peer);
        }

        let n = map.len();
        // 诊断：把对端表打出来（ip / endpoint），排查互通问题用
        for (ip, p) in map.iter() {
            let g = p.lock().await;
            tracing::info!("对端表: ip={ip} endpoint={:?}", g.endpoint);
        }
        *self.peers.write().await = map;
        *self.endpoints.write().await = eps;
        tracing::info!("overlay 节点表已更新，共 {n} 个对端");
    }
}

/// 创建一个 overlay 节点并启动后台任务。
pub async fn start_node(
    device: Box<dyn IpDevice>,
    socket: Arc<UdpSocket>,
    private: StaticSecret,
    my_ip: Ipv4Addr,
    mtu: u16,
    initial_peers: Vec<PeerSpec>,
    relay: Option<RelayLink>,
) -> Result<NodeHandle> {
    let public_key = PublicKey::from(&private).to_bytes();

    let peers: PeerMap = Arc::new(RwLock::new(HashMap::new()));
    let endpoints: Arc<RwLock<HashMap<SocketAddr, Ipv4Addr>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let stats_tx = Arc::new(AtomicU64::new(0));
    let stats_rx = Arc::new(AtomicU64::new(0));
    let relay_active = Arc::new(std::sync::atomic::AtomicBool::new(relay.is_some()));
    let routes: Arc<RwLock<Vec<(ipnet::Ipv4Net, Ipv4Addr)>>> = Arc::new(RwLock::new(Vec::new()));
    let acl: Arc<RwLock<crate::overlay::acl::Acl>> =
        Arc::new(RwLock::new(crate::overlay::acl::Acl::default()));

    {
        let mut map = HashMap::new();
        let mut eps = HashMap::new();
        for (idx, spec) in initial_peers.into_iter().enumerate() {
            let peer = Arc::new(Mutex::new(WgPeer::new(
                &private,
                spec.pubkey,
                spec.ip,
                idx as u32,
                None,
            )));
            {
                let mut g = peer.lock().await;
                if let Some(ep) = spec.endpoint {
                    g.learn_candidate(ep);
                    g.endpoint = Some(ep);
                }
                for ep in &spec.endpoints {
                    g.learn_candidate(*ep);
                }
                g.relay_allowed = spec.relay_allowed;
                g.tcp_endpoint = spec.tcp_endpoint;
            }
            if let Some(ep) = spec.endpoint {
                eps.insert(ep, spec.ip);
            }
            for ep in spec.endpoints {
                eps.insert(ep, spec.ip);
            }
            map.insert(spec.ip, peer);
        }
        *peers.write().await = map;
        *endpoints.write().await = eps;
    }

    let handle = NodeHandle {
        public_key,
        ip: my_ip,
        peers: peers.clone(),
        endpoints: endpoints.clone(),
        stats_tx: stats_tx.clone(),
        stats_rx: stats_rx.clone(),
        relay_active: relay_active.clone(),
        routes: routes.clone(),
        acl: acl.clone(),
    };

    let (to_dev_tx, to_dev_rx) = mpsc::channel::<Vec<u8>>(512);
    if let Ok(local) = socket.local_addr() {
        spawn_tcp_manager(
            peers.clone(),
            to_dev_tx.clone(),
            public_key,
            local.port(),
        );
    }

    spawn_udp_receiver(
        socket.clone(),
        peers.clone(),
        endpoints.clone(),
        to_dev_tx.clone(),
        stats_rx.clone(),
        public_key,
        acl.clone(),
        relay.clone(),
    );
    if let Some(rc) = relay.clone() {
        spawn_relay_receiver(rc, peers.clone(), to_dev_tx, socket.clone());
    }
    spawn_timer(
        peers.clone(),
        socket.clone(),
        stats_tx.clone(),
        relay.clone(),
        public_key,
    );
    spawn_device_loop(
        device,
        socket,
        peers,
        mtu as usize,
        to_dev_rx,
        relay,
        routes.clone(),
        acl.clone(),
        my_ip,
    );

    Ok(handle)
}

fn relay_path_available(relay: &Option<RelayLink>) -> bool {
    relay.as_ref().is_some_and(|r| r.is_connected())
}

/// 按路径归属把一批 WireGuard 报文发出去。
///
/// 未锁定时会同时发直连和中继：只发直连会被单向 NAT 吞掉，
/// 只发中继又会让本来可直连的场景白白绕路。
async fn send_out(
    socket: &UdpSocket,
    relay: Option<&RelayLink>,
    peer_pubkey: [u8; 32],
    endpoints: &[SocketAddr],
    tcp: Option<&tokio::sync::mpsc::Sender<Vec<u8>>>,
    paths: SendPaths,
    packets: &[Vec<u8>],
) {
    if packets.is_empty() || (paths.is_empty() && tcp.is_none()) {
        return;
    }
    if let Some(tx) = tcp {
        for p in packets {
            let _ = tx.send(p.clone()).await;
        }
    }
    // 先直连：延迟更低，也让对端优先看到直连路径。
    if paths.direct {
        for ep in endpoints {
            for p in packets {
                let _ = socket.send_to(p, ep).await;
            }
        }
    }
    if paths.relay
        && let Some(r) = relay
    {
        for p in packets {
            r.send_to(peer_pubkey, p).await;
        }
    }
}

fn spawn_device_loop(
    mut device: Box<dyn IpDevice>,
    socket: Arc<UdpSocket>,
    peers: PeerMap,
    mtu: usize,
    mut to_dev_rx: mpsc::Receiver<Vec<u8>>,
    relay: Option<RelayLink>,
    routes: Arc<RwLock<Vec<(ipnet::Ipv4Net, Ipv4Addr)>>>,
    acl: Arc<RwLock<crate::overlay::acl::Acl>>,
    my_ip: Ipv4Addr,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; mtu + 128];
        loop {
            tokio::select! {
                r = device.read_packet(&mut buf) => {
                    match r {
                        Ok(0) => break,
                        Ok(n) => {
                            let pkt = &buf[..n];
                            let Some(dst) = ipv4_dst(pkt) else { continue };
                            if !acl.read().await.allows(my_ip, dst) {
                                tracing::debug!("ACL 拒绝 {my_ip} -> {dst}");
                                continue;
                            }
                            // 先按虚拟 IP 精确匹配，再查共享子网路由
                            let mut peer = { peers.read().await.get(&dst).cloned() };
                            if peer.is_none() {
                                let target = {
                                    let r = routes.read().await;
                                    r.iter()
                                        .find(|(net, _)| net.contains(&dst))
                                        .map(|(_, ip)| *ip)
                                };
                                if let Some(ip) = target {
                                    peer = peers.read().await.get(&ip).cloned();
                                }
                            }
                            let Some(peer) = peer else {
                                tracing::trace!("没有到 {dst} 的对端或子网，丢弃");
                                continue;
                            };
                            let mut g = peer.lock().await;
                            let endpoints = g.direct_addrs();
                            let tcp = g.tcp_tx.clone();
                            let pubkey = g.pubkey;
                            let paths = g.send_paths(relay_path_available(&relay));
                            let action: WgAction = g.encapsulate(pkt);
                            drop(g);
                            send_out(&socket, relay.as_ref(), pubkey, &endpoints, tcp.as_ref(), paths, &action.to_net).await;
                        }
                        Err(e) => {
                            tracing::debug!("TUN 读取结束: {e}");
                            break;
                        }
                    }
                }
                Some(pkt) = to_dev_rx.recv() => {
                    if device.write_packet(&pkt).await.is_err() {
                        break;
                    }
                }
            }
        }
        tracing::debug!("overlay 设备循环退出");
    });
}

fn spawn_udp_receiver(
    socket: Arc<UdpSocket>,
    peers: PeerMap,
    endpoints: Arc<RwLock<HashMap<SocketAddr, Ipv4Addr>>>,
    to_dev: mpsc::Sender<Vec<u8>>,
    stats_rx: Arc<AtomicU64>,
    my_pubkey: [u8; 32],
    _acl: Arc<RwLock<crate::overlay::acl::Acl>>,
    relay: Option<RelayLink>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let my_probe = build_punch(&my_pubkey);
        loop {
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("overlay UDP 接收失败: {e}");
                    // A persistent socket error (for example ICMP port
                    // unreachable) must not turn this into a busy loop.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let src = crate::overlay::normalize_addr(src);
            let datagram = &buf[..n];
            stats_rx.fetch_add(n as u64, Ordering::Relaxed);

            // The server-node UDP port also answers STUN. This gives clients a
            // second source port for mapping classification without exposing
            // an additional port.
            if crate::overlay::stun::is_stun(datagram) {
                if let Some(resp) = crate::overlay::stun::build_binding_response(datagram, src) {
                    let _ = socket.send_to(&resp, src).await;
                }
                continue;
            }

            // 打洞探测：学习对端真实公网地址，并在地址变化时回一发。
            if is_punch(datagram) {
                tracing::debug!("overlay 收到打洞探测包，来自 {src}");
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&datagram[PUNCH_MAGIC.len()..]);
                let all: Vec<(Ipv4Addr, Arc<Mutex<WgPeer>>)> = {
                    let guard = peers.read().await;
                    guard.iter().map(|(ip, p)| (*ip, p.clone())).collect()
                };
                for (ip, peer) in all {
                    let (matched, changed) = {
                        let mut g = peer.lock().await;
                        if g.pubkey == pk {
                            let changed = g.endpoint != Some(src);
                            if changed {
                                tracing::info!("overlay 打洞：{ip} 的地址更新为 {src}");
                            }
                            g.endpoint = Some(src);
                            // 探测包只证明入向可达；不能当作直连出向也可用的证据。
                            // established 只用于停止继续打洞。
                            g.established = true;
                            (true, changed)
                        } else {
                            (false, false)
                        }
                    };
                    if matched {
                        endpoints.write().await.insert(src, ip);
                        // 只在对端地址刚变化时回一发，避免两边互相回声形成风暴。
                        if changed {
                            let _ = socket.send_to(&my_probe, src).await;
                        }
                        break;
                    }
                }
                continue;
            }

            let known_ip = { endpoints.read().await.get(&src).copied() };

            if let Some(ip) = known_ip {
                let peer = { peers.read().await.get(&ip).cloned() };
                if let Some(peer) = peer {
                    let (action, paths, pubkey, tcp) = {
                        let mut g = peer.lock().await;
                        let action = g.decapsulate(Some(src.ip()), datagram);
                        if action.authenticated {
                            g.note_inbound(Path::Direct, wg_message_type(datagram));
                        }
                        let paths = g.send_paths(relay_path_available(&relay));
                        (action, paths, g.pubkey, g.tcp_tx.clone())
                    };
                    send_out(
                        &socket,
                        relay.as_ref(),
                        pubkey,
                        &[src],
                        tcp.as_ref(),
                        paths,
                        &action.to_net,
                    )
                    .await;
                    for p in action.to_tun {
                        let _ = to_dev.send(p).await;
                    }
                    continue;
                }
            }

            let all: Vec<(Ipv4Addr, Arc<Mutex<WgPeer>>)> = {
                let guard = peers.read().await;
                guard.iter().map(|(ip, p)| (*ip, p.clone())).collect()
            };
            let mut learned = false;
            for (ip, peer) in all {
                let found = {
                    let mut g = peer.lock().await;
                    let act = g.decapsulate(Some(src.ip()), datagram);
                    if act.authenticated {
                        g.note_inbound(Path::Direct, wg_message_type(datagram));
                        g.endpoint = Some(src);
                        let paths = g.send_paths(relay_path_available(&relay));
                        Some((act, paths, g.pubkey, g.tcp_tx.clone()))
                    } else {
                        None
                    }
                };
                if let Some((action, paths, pubkey, tcp)) = found {
                    endpoints.write().await.insert(src, ip);
                    send_out(
                        &socket,
                        relay.as_ref(),
                        pubkey,
                        &[src],
                        tcp.as_ref(),
                        paths,
                        &action.to_net,
                    )
                    .await;
                    for p in action.to_tun {
                        let _ = to_dev.send(p).await;
                    }
                    learned = true;
                    break;
                }
            }
            if !learned {
                tracing::trace!("丢弃无法识别的 overlay 报文，来自 {src}");
            }
        }
    });
}

/// 中继收到对端报文 -> 解封装 -> 写 TUN；需要回应的握手包仍走中继回去。
fn spawn_relay_receiver(
    relay: RelayLink,
    peers: PeerMap,
    to_dev: mpsc::Sender<Vec<u8>>,
    socket: Arc<UdpSocket>,
) {
    tokio::spawn(async move {
        let Some(mut rx) = relay.take_incoming().await else {
            return;
        };
        while let Some((src_pubkey, data)) = rx.recv().await {
            let all: Vec<Arc<Mutex<WgPeer>>> = {
                let guard = peers.read().await;
                guard.values().cloned().collect()
            };
            for peer in all {
                let msg_type = wg_message_type(&data);
                let action = {
                    let mut g = peer.lock().await;
                    if g.pubkey != src_pubkey {
                        continue;
                    }
                    // 对端是通过中继把包送来的：中继是双向 TCP，服务端又按公钥鉴权，
                    // 收到就说明这条端到端路径可用，直接把归属锁定到中继。
                    g.note_inbound(Path::Relay, msg_type);
                    g.decapsulate(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), &data)
                };
                // 握手回包也通过中继回去
                for b in action.to_net {
                    relay.send_to(src_pubkey, &b).await;
                }
                for p in action.to_tun {
                    let _ = to_dev.send(p).await;
                }
                // 中继收到的流量说明对端可达，顺手记录一下统计
                let _ = &socket;
                break;
            }
        }
    });
}

fn spawn_timer(
    peers: PeerMap,
    socket: Arc<UdpSocket>,
    stats_tx: Arc<AtomicU64>,
    relay: Option<RelayLink>,
    my_pubkey: [u8; 32],
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(250));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let my_probe = build_punch(&my_pubkey);
        let mut probe_round = false;
        loop {
            ticker.tick().await;
            probe_round = !probe_round;
            let all: Vec<Arc<Mutex<WgPeer>>> = {
                let guard = peers.read().await;
                guard.values().cloned().collect()
            };
            for peer in all {
                let mut g = peer.lock().await;
                let endpoints = g.direct_addrs();
                let tcp = g.tcp_tx.clone();
                let pubkey = g.pubkey;
                let paths = g.send_paths(relay_path_available(&relay));
                let punch_due = g.punch_due();
                let scan_targets = g.scan_targets();
                let action = g.tick();
                drop(g);
                // 打洞探测：每 500ms 朝服务端观测到的地址打一发
                if punch_due && probe_round {
                    for ep in &endpoints {
                        let _ = socket.send_to(&my_probe, *ep).await;
                    }
                    for ep in &scan_targets {
                        let _ = socket.send_to(&my_probe, *ep).await;
                    }
                }
                if action.to_net.is_empty() {
                    continue;
                }
                let bytes: usize = action.to_net.iter().map(|b| b.len()).sum();
                stats_tx.fetch_add(bytes as u64, Ordering::Relaxed);
                send_out(
                    &socket,
                    relay.as_ref(),
                    pubkey,
                    &endpoints,
                    tcp.as_ref(),
                    paths,
                    &action.to_net,
                )
                .await;
            }
        }
    });
}

/// 生成一个 WireGuard 私钥。
pub fn generate_private() -> StaticSecret {
    StaticSecret::random_from_rng(rand::thread_rng())
}

/// 解析 endpoint 字符串。
pub fn parse_endpoint(s: &str) -> Result<Option<SocketAddr>> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    match s.parse::<SocketAddr>() {
        Ok(a) => Ok(Some(a)),
        Err(e) => bail!("非法 endpoint {s}: {e}"),
    }
}

/// 只接受 IPv4。
pub fn as_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(_) => None,
    }
}

const TCP_MAGIC: &[u8; 8] = b"TRIRTCP1";

fn spawn_tcp_manager(
    peers: PeerMap,
    to_dev: mpsc::Sender<Vec<u8>>,
    my_pubkey: [u8; 32],
    listen_port: u16,
) {
    tokio::spawn(async move {
        let listener = match TcpListener::bind(("0.0.0.0", listen_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::debug!("TCP 直连监听端口 {listen_port} 不可用: {e}");
                return;
            }
        };
        tracing::info!("overlay TCP 直连监听 :{listen_port}");
        let p = peers.clone();
        let d = to_dev.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let p = p.clone();
                        let d = d.clone();
                        tokio::spawn(async move {
                            tracing::debug!("overlay TCP 入站连接 {addr}");
                            if let Err(e) = handle_tcp_stream(stream, p, d, my_pubkey).await {
                                tracing::debug!("overlay TCP 入站结束 {addr}: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        tracing::debug!("overlay TCP accept: {e}");
                    }
                }
            }
        });

        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let candidates: Vec<(Ipv4Addr, SocketAddr)> = {
                let guard = peers.read().await;
                let mut out = Vec::new();
                for (ip, p) in guard.iter() {
                    let g = p.lock().await;
                    if g.tcp_tx.is_none() {
                        if let Some(ep) = g.tcp_endpoint {
                            out.push((*ip, ep));
                        }
                    }
                }
                out
            };
            for (_ip, ep) in candidates {
                let p = peers.clone();
                let d = to_dev.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(3), connect_tcp_direct(ep, listen_port)).await {
                        Ok(Ok(stream)) => {
                            tracing::debug!("overlay TCP 出站连接 {ep}");
                            if let Err(e) = handle_tcp_stream(stream, p, d, my_pubkey).await {
                                tracing::debug!("overlay TCP 出站结束 {ep}: {e:#}");
                            }
                        }
                        _ => {}
                    }
                });
            }
        }
    });
}

async fn handle_tcp_stream(
    stream: TcpStream,
    peers: PeerMap,
    to_dev: mpsc::Sender<Vec<u8>>,
    my_pubkey: [u8; 32],
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (mut r, mut w) = stream.into_split();

    let mut hello = Vec::with_capacity(40);
    hello.extend_from_slice(TCP_MAGIC);
    hello.extend_from_slice(&my_pubkey);
    w.write_all(&hello).await?;
    w.flush().await?;

    let mut head = [0u8; 40];
    read_exact_timeout(&mut r, &mut head, 3).await?;
    if &head[..8] != TCP_MAGIC {
        bail!("TCP 握手魔数错误");
    }
    let mut peer_key = [0u8; 32];
    peer_key.copy_from_slice(&head[8..]);

    let (peer_ip, peer) = {
        let guard = peers.read().await;
        let mut found = None;
        for (ip, p) in guard.iter() {
            let g = p.lock().await;
            if g.pubkey == peer_key {
                found = Some((*ip, p.clone()));
                break;
            }
        }
        found.ok_or_else(|| anyhow::anyhow!("TCP 对端公钥不在本节点表中"))?
    };

    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
    {
        let mut g = peer.lock().await;
        if g.tcp_tx.is_some() {
            bail!("TCP 对端已有直连链路");
        }
        g.tcp_tx = Some(tx.clone());
        tracing::info!("overlay TCP 直连已建立: {peer_ip}");
    }

    let writer = tokio::spawn(async move {
        let mut rx = rx;
        while let Some(p) = rx.recv().await {
            if p.len() > 65535 {
                continue;
            }
            if w.write_all(&(p.len() as u32).to_be_bytes()).await.is_err() {
                break;
            }
            if w.write_all(&p).await.is_err() {
                break;
            }
            let _ = w.flush().await;
        }
    });

    let peers_for_read = peers.clone();
    let to_dev_for_read = to_dev.clone();
    let tx_for_read = tx.clone();
    let read_task = tokio::spawn(async move {
        loop {
            let mut len = [0u8; 4];
            if read_exact_timeout(&mut r, &mut len, 30).await.is_err() {
                break;
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > 65535 {
                break;
            }
            let mut data = vec![0u8; n];
            if read_exact_timeout(&mut r, &mut data, 30).await.is_err() {
                break;
            }
            let target = {
                let guard = peers_for_read.read().await;
                guard.get(&peer_ip).cloned()
            };
            let Some(target) = target else { break };
            let (action, paths) = {
                let mut g = target.lock().await;
                let action = g.decapsulate(Some(std::net::IpAddr::V4(peer_ip)), &data);
                if action.authenticated {
                    g.note_inbound(Path::Direct, wg_message_type(&data));
                    g.established = true;
                }
                let paths = g.send_paths(true);
                (action, paths)
            };
            for p in action.to_tun {
                let _ = to_dev_for_read.send(p).await;
            }
            for p in action.to_net {
                let _ = tx_for_read.send(p).await;
            }
            let _ = paths;
        }
        tracing::debug!("overlay TCP 读循环退出: {peer_ip}");
    });

    tokio::time::timeout(Duration::from_secs(3600), writer).await.ok();
    read_task.abort();
    let mut g = peer.lock().await;
    g.tcp_tx = None;
    tracing::info!("overlay TCP 直连已断开: {peer_ip}");
    Ok(())
}

async fn connect_tcp_direct(ep: SocketAddr, local_port: u16) -> Result<TcpStream> {
    // TCP simultaneous-open attempt: use the listener's numeric source port
    // so both NATs can create a predictable mapping. Fall back to an
    // ephemeral source when the platform refuses to reuse the port.
    if let Ok(sock) = TcpSocket::new_v4() {
        if sock.set_reuseaddr(true).is_ok()
            && sock.bind(SocketAddr::from(([0, 0, 0, 0], local_port))).is_ok()
        {
            if let Ok(stream) = sock.connect(ep).await {
                return Ok(stream);
            }
        }
    }
    let _ = local_port;
    TcpStream::connect(ep).await.map_err(Into::into)
}

async fn read_exact_timeout<R: AsyncReadExt + Unpin>(
    r: &mut R,
    buf: &mut [u8],
    secs: u64,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(secs), r.read_exact(buf))
        .await
        .map_err(|_| anyhow::anyhow!("TCP 读取超时"))??;
    Ok(())
}
