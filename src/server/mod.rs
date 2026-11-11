//! 服务端运行时：监听、客户端管理、代理注册、vhost 路由、面板。

pub mod control;
pub mod dashboard;
pub mod overlay;
pub mod proxy;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use tokio::net::TcpListener;
use tokio::sync::{Notify, RwLock, mpsc};
use tokio::task::JoinHandle;

use crate::config::{Config, ServerConfig, WireKind};
use crate::protocol::{ControlMsg, NewProxyRequest};
use crate::stream::AnyStream;
use crate::util::parse_port_ranges;

/// 服务端接受的 WebSocket 路径（与客户端默认值一致）
pub const WS_PATH: &str = "/~!trairi";

/// 待分配的 work 连接
pub struct WorkConn {
    pub stream: AnyStream,
    pub src: Option<std::net::SocketAddr>,
    pub dst: Option<std::net::SocketAddr>,
}

/// 每个代理一个 wait/notify 队列，服务端拿到外部连接后来这里取一条 work 连接。
pub struct WorkQueue {
    q: StdMutex<VecDeque<WorkConn>>,
    notify: Notify,
}

impl Default for WorkQueue {
    fn default() -> Self {
        Self {
            q: StdMutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }
}

impl WorkQueue {
    pub fn push(&self, conn: WorkConn) {
        self.q.lock().unwrap().push_back(conn);
        self.notify.notify_one();
    }

    pub fn len(&self) -> usize {
        self.q.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 等待一条 work 连接（带超时）。
    pub async fn pop(&self, dur: Duration) -> Option<WorkConn> {
        let deadline = tokio::time::Instant::now() + dur;
        loop {
            if let Some(c) = self.q.lock().unwrap().pop_front() {
                return Some(c);
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // 注册 notifier 之后再检查一次，避免丢唤醒
            if let Some(c) = self.q.lock().unwrap().pop_front() {
                return Some(c);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }
}

/// 统计计数
#[derive(Default)]
pub struct Stats {
    pub conns: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}
impl Stats {
    pub fn add(&self, up: u64, down: u64) {
        self.bytes_in.fetch_add(up, Ordering::Relaxed);
        self.bytes_out.fetch_add(down, Ordering::Relaxed);
    }
}

/// 负载均衡分组：同 group + group_key + 端口的多个代理共享一个监听。
pub struct GroupMembers {
    pub group: String,
    pub group_key: String,
    pub port: u16,
    pub members: StdMutex<Vec<Arc<ProxyRuntime>>>,
    rr: AtomicU64,
}

impl GroupMembers {
    fn new(group: &str, group_key: &str, port: u16) -> Self {
        Self {
            group: group.to_string(),
            group_key: group_key.to_string(),
            port,
            members: StdMutex::new(Vec::new()),
            rr: AtomicU64::new(0),
        }
    }

    fn add(&self, proxy: Arc<ProxyRuntime>) {
        self.members.lock().unwrap().push(proxy);
    }

    /// 按健康状态和权重轮流挑一个成员。
    pub fn pick(&self) -> Option<Arc<ProxyRuntime>> {
        let members = self.members.lock().unwrap().clone();
        if members.is_empty() {
            return None;
        }
        let healthy: Vec<Arc<ProxyRuntime>> = members
            .iter()
            .filter(|m| m.healthy.load(Ordering::Relaxed))
            .cloned()
            .collect();
        let pool = if healthy.is_empty() { members } else { healthy };
        let total: u64 = pool.iter().map(|m| m.weight.max(1) as u64).sum();
        if total == 0 {
            return None;
        }
        let slot = self.rr.fetch_add(1, Ordering::Relaxed) % total;
        let mut acc = 0u64;
        for member in pool {
            acc += member.weight.max(1) as u64;
            if slot < acc {
                return Some(member);
            }
        }
        None
    }
}

/// 服务端视角的一个客户端
pub struct ClientHandle {
    pub run_id: String,
    pub remote_addr: String,
    pub hostname: String,
    pub user: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub connected_at: Instant,
    pub connected_at_wall: SystemTime,
    pub tx: mpsc::Sender<ControlMsg>,
    pub proxies: StdMutex<Vec<String>>,
    pub transport: String,
}

impl ClientHandle {
    pub async fn send(&self, msg: ControlMsg) -> bool {
        self.tx.send(msg).await.is_ok()
    }
}

/// 服务端视角的一个代理
pub struct ProxyRuntime {
    pub name: String,
    pub kind: WireKind,
    pub client: Arc<ClientHandle>,
    pub remote_port: u16,
    pub domains: Vec<String>,
    pub subdomain: String,
    pub sk: String,
    pub group: String,
    pub weight: u32,
    pub bandwidth_limit: u64,
    pub proxy_protocol: String,
    pub healthy: AtomicBool,
    pub work: WorkQueue,
    pub stats: Stats,
    pub created_at: Instant,
    pub listener: StdMutex<Option<JoinHandle<()>>>,
    /// 所属负载均衡分组（如果有）
    pub group_handle: StdMutex<Option<Arc<GroupMembers>>>,
}

impl ProxyRuntime {
    pub fn new(
        req: &NewProxyRequest,
        client: Arc<ClientHandle>,
        remote_port: u16,
        default_proxy_protocol: &str,
    ) -> Self {
        Self {
            name: req.name.clone(),
            kind: req.kind.wire(),
            client,
            remote_port,
            domains: req.custom_domains.clone(),
            subdomain: req.subdomain.clone(),
            sk: req.sk.clone(),
            group: req.group.clone(),
            weight: req.weight.clamp(1, 1000),
            bandwidth_limit: req.bandwidth_limit,
            proxy_protocol: if req.proxy_protocol.is_empty() {
                default_proxy_protocol.to_string()
            } else {
                req.proxy_protocol.clone()
            },
            healthy: AtomicBool::new(true),
            work: WorkQueue::default(),
            stats: Stats::default(),
            created_at: Instant::now(),
            listener: StdMutex::new(None),
            group_handle: StdMutex::new(None),
        }
    }
}

/// 服务端全局状态
pub struct ServerState {
    pub cfg: ServerConfig,
    pub started_at: Instant,
    pub started_at_wall: SystemTime,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub allow_ports: Vec<(u16, u16)>,
    pub clients: RwLock<HashMap<String, Arc<ClientHandle>>>,
    pub proxies: RwLock<HashMap<String, Arc<ProxyRuntime>>>,
    pub vhost: RwLock<HashMap<String, Arc<ProxyRuntime>>>,
    /// 负载均衡分组
    pub groups: RwLock<HashMap<String, Arc<GroupMembers>>>,
    pub used_ports: StdMutex<HashSet<u16>>,
    pub http_port: AtomicU64,
    pub https_port: AtomicU64,
    /// 组网协调器（未启用为 None）
    pub overlay: Option<std::sync::Arc<overlay::OverlayCoordinator>>,
    pub server_id: String,
    /// 已成功使用过的 Hello (salt|timestamp)，用于防重放
    pub replay: StdMutex<HashMap<String, Instant>>,
}

impl ServerState {
    pub fn new(
        cfg: ServerConfig,
        tls: Option<Arc<rustls::ServerConfig>>,
        overlay: Option<std::sync::Arc<overlay::OverlayCoordinator>>,
    ) -> Result<Arc<Self>> {
        let allow_ports = if cfg.allow_ports.trim().is_empty() {
            Vec::new()
        } else {
            parse_port_ranges(&cfg.allow_ports).context("解析 allow_ports 失败")?
        };
        Ok(Arc::new(Self {
            cfg,
            started_at: Instant::now(),
            started_at_wall: SystemTime::now(),
            tls,
            allow_ports,
            clients: RwLock::new(HashMap::new()),
            proxies: RwLock::new(HashMap::new()),
            vhost: RwLock::new(HashMap::new()),
            groups: RwLock::new(HashMap::new()),
            used_ports: StdMutex::new(HashSet::new()),
            http_port: AtomicU64::new(0),
            https_port: AtomicU64::new(0),
            overlay,
            server_id: crate::util::random_hex(8),
            replay: StdMutex::new(HashMap::new()),
        }))
    }

    /// 记录一次成功的 Hello；同一 salt+timestamp 在 5 分钟窗口内只允许一次。
    ///
    /// 返回 false 表示重放/缓存已满。
    pub fn accept_hello(&self, salt: &str, timestamp: i64) -> bool {
        const WINDOW: Duration = Duration::from_secs(300);
        const MAX_ENTRIES: usize = 100_000;
        let now = Instant::now();
        let mut map = self.replay.lock().unwrap();
        map.retain(|_, t| now.duration_since(*t) < WINDOW);
        let key = format!("{salt}|{timestamp}");
        if map.contains_key(&key) {
            return false;
        }
        if map.len() >= MAX_ENTRIES {
            return false;
        }
        map.insert(key, now);
        true
    }

    /// 注册一个代理，失败时返回错误信息（会回传给客户端）。
    pub async fn register_proxy(
        self: &Arc<Self>,
        req: &NewProxyRequest,
        client: &Arc<ClientHandle>,
    ) -> Result<Arc<ProxyRuntime>, String> {
        if req.name.is_empty() {
            return Err("代理名不能为空".into());
        }
        {
            let proxies = self.proxies.read().await;
            if proxies.contains_key(&req.name) {
                return Err(format!("代理名已被占用: {}", req.name));
            }
        }
        if self.cfg.max_clients > 0 {
            let n = self.clients.read().await.len() as u32;
            if n >= self.cfg.max_clients {
                return Err(format!("客户端数量超过上限 {}", self.cfg.max_clients));
            }
        }

        let kind = req.kind.wire();
        let mut remote_port = 0u16;

        // 分组：同 group + group_key + 端口的成员共享一个监听
        let group_key_full = if req.group.is_empty() {
            None
        } else {
            Some(format!(
                "{}|{}|{}",
                req.group, req.group_key, req.remote_port
            ))
        };
        let mut group_handle: Option<Arc<GroupMembers>> = None;
        let mut already_bound = false;
        if let Some(key) = &group_key_full {
            let groups = self.groups.read().await;
            if let Some(g) = groups.get(key) {
                group_handle = Some(g.clone());
                remote_port = g.port;
                already_bound = true;
            }
        }

        match kind {
            WireKind::Tcp | WireKind::Udp => {
                if !already_bound {
                    if self.cfg.max_ports_per_client > 0 {
                        let used = client.proxies.lock().unwrap().len() as u32;
                        if used >= self.cfg.max_ports_per_client {
                            return Err(format!(
                                "每个客户端最多申请 {} 个端口",
                                self.cfg.max_ports_per_client
                            ));
                        }
                    }
                    let want = if req.remote_port > 0 {
                        u16::try_from(req.remote_port)
                            .map_err(|_| "remote_port 非法".to_string())?
                    } else {
                        0
                    };
                    remote_port = self
                        .allocate_port(want, kind == WireKind::Udp)
                        .map_err(|e| format!("分配端口失败: {e}"))?;
                }
            }
            WireKind::Http | WireKind::Https => {
                let port = if kind == WireKind::Http {
                    self.cfg.vhost_http_port
                } else {
                    self.cfg.vhost_https_port
                };
                if port == 0 {
                    return Err(format!(
                        "服务端没有开启 {} 端口（vhost_{}_port = 0）",
                        kind.as_str(),
                        kind.as_str()
                    ));
                }
            }
            WireKind::Stcp => {
                if req.sk.is_empty() {
                    return Err("stcp 代理需要 sk".into());
                }
            }
        }

        // 域名
        let mut domains: Vec<String> = Vec::new();
        for d in &req.custom_domains {
            domains.push(d.to_ascii_lowercase());
        }
        let mut subdomain = String::new();
        if !req.subdomain.is_empty() {
            if self.cfg.subdomain_host.is_empty() {
                return Err("服务端没有配置 subdomain_host，无法使用 subdomain".into());
            }
            let sub = req.subdomain.to_ascii_lowercase();
            subdomain = sub.clone();
            domains.push(format!(
                "{}.{}",
                sub,
                self.cfg.subdomain_host.to_ascii_lowercase()
            ));
        }
        // subdomain 字段保留在 proxy 上，方便面板展示
        let _ = &subdomain;

        if matches!(kind, WireKind::Http | WireKind::Https) && domains.is_empty() {
            return Err("http/https 代理需要 custom_domains 或 subdomain".into());
        }

        {
            let vhost = self.vhost.read().await;
            for d in &domains {
                if vhost.contains_key(d) {
                    return Err(format!("域名已被其他代理占用: {d}"));
                }
            }
        }

        let proxy = Arc::new(ProxyRuntime::new(
            req,
            client.clone(),
            remote_port,
            &self.cfg.proxy_protocol_version,
        ));

        {
            let mut proxies = self.proxies.write().await;
            proxies.insert(proxy.name.clone(), proxy.clone());
        }
        {
            let mut vhost = self.vhost.write().await;
            for d in &domains {
                vhost.insert(d.clone(), proxy.clone());
            }
        }
        client.proxies.lock().unwrap().push(proxy.name.clone());

        // 加入分组
        if let Some(key) = &group_key_full {
            let handle = match group_handle {
                Some(g) => g,
                None => {
                    let g = Arc::new(GroupMembers::new(&req.group, &req.group_key, remote_port));
                    self.groups.write().await.insert(key.clone(), g.clone());
                    g
                }
            };
            handle.add(proxy.clone());
            *proxy.group_handle.lock().unwrap() = Some(handle);
        }

        tracing::info!(
            "代理 [{}] 已注册 type={} client={} {}",
            proxy.name,
            kind.as_str(),
            client.run_id,
            if remote_port > 0 {
                format!("remote_port={remote_port}")
            } else if !domains.is_empty() {
                format!("domains={}", domains.join(","))
            } else {
                String::new()
            }
        );

        if !already_bound {
            match kind {
                WireKind::Tcp => proxy::start_tcp_listener(self.clone(), proxy.clone()).await?,
                WireKind::Udp => proxy::start_udp_listener(self.clone(), proxy.clone()).await?,
                _ => {}
            }
        }

        Ok(proxy)
    }

    /// 分配一个对外端口。
    ///
    /// 安全约束：显式端口也必须命中 `allow_ports`；`allow_ports` 为空时，
    /// 不允许客户端申请任何固定端口（避免已认证客户端占用任意端口）。
    fn allocate_port(&self, want: u16, udp: bool) -> Result<u16, String> {
        let mut used = self.used_ports.lock().unwrap();
        if want > 0 {
            if self.allow_ports.is_empty() {
                return Err("服务端未配置 allow_ports，禁止申请固定端口".to_string());
            }
            if !crate::util::port_in_ranges(&self.allow_ports, want) {
                return Err(format!("端口 {want} 不在 allow_ports 允许范围内"));
            }
            if used.contains(&want) {
                return Err(format!("端口 {want} 已被占用"));
            }
            if port_is_busy(want, udp) {
                return Err(format!("端口 {want} 已被系统占用"));
            }
            used.insert(want);
            return Ok(want);
        }
        if self.allow_ports.is_empty() {
            return Err("没有指定 remote_port，且服务端没有配置 allow_ports".to_string());
        }
        for (a, b) in &self.allow_ports {
            for p in *a..=*b {
                if !used.contains(&p) && !port_is_busy(p, udp) {
                    used.insert(p);
                    return Ok(p);
                }
            }
        }
        Err("allow_ports 范围内没有空闲端口".to_string())
    }

    /// 注销一个代理（释放端口、域名、监听）。
    pub async fn unregister_proxy(&self, name: &str) {
        let proxy = {
            let mut proxies = self.proxies.write().await;
            proxies.remove(name)
        };
        let Some(proxy) = proxy else { return };

        if proxy.remote_port > 0 {
            self.used_ports.lock().unwrap().remove(&proxy.remote_port);
        }
        {
            let mut vhost = self.vhost.write().await;
            for d in &proxy.domains {
                if let Some(p) = vhost.get(d) {
                    if p.name == proxy.name {
                        vhost.remove(d);
                    }
                }
            }
        }
        if let Some(handle) = proxy.listener.lock().unwrap().take() {
            handle.abort();
        }
        proxy.client.proxies.lock().unwrap().retain(|n| n != name);
        tracing::info!("代理 [{}] 已注销", name);
    }

    /// 客户端断开时清理其全部代理。
    pub async fn remove_client(&self, run_id: &str) {
        let client = {
            let mut clients = self.clients.write().await;
            clients.remove(run_id)
        };
        let Some(client) = client else { return };
        let names = client.proxies.lock().unwrap().clone();
        let count = names.len();
        for n in names {
            self.unregister_proxy(&n).await;
        }
        if let Some(ov) = &self.overlay {
            ov.remove_sender(run_id).await;
        }
        tracing::info!("客户端 {run_id} 已断开，清理 {count} 个代理");
    }

    /// 按域名找代理。
    pub async fn find_vhost(&self, host: &str) -> Option<Arc<ProxyRuntime>> {
        let host = host.to_ascii_lowercase();
        let vhost = self.vhost.read().await;
        if let Some(p) = vhost.get(&host) {
            return Some(p.clone());
        }
        // 泛域名：subdomain_host 下的第一级子域
        if !self.cfg.subdomain_host.is_empty() {
            if let Some(sub) = host.strip_suffix(&format!(
                ".{}",
                self.cfg.subdomain_host.to_ascii_lowercase()
            )) {
                if !sub.contains('.') {
                    return vhost.get(&host).cloned();
                }
            }
        }
        None
    }
}

fn port_is_busy(port: u16, udp: bool) -> bool {
    if udp {
        std::net::UdpSocket::bind(("0.0.0.0", port)).is_err()
    } else {
        std::net::TcpListener::bind(("0.0.0.0", port)).is_err()
    }
}

async fn serve_kcp(mut listener: tokio_kcp::KcpListener, state: Arc<ServerState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let accepted = crate::transport::Accepted {
                    stream: Box::new(stream),
                    peer,
                    transport: "kcp",
                };
                let st = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = control::handle_connection(st, accepted).await {
                        tracing::debug!("KCP 连接处理结束: {e:#}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!("KCP accept 失败: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 启动
// ---------------------------------------------------------------------------

pub async fn run(cfg: Config) -> Result<()> {
    crate::transport::ensure_crypto_provider();

    let server_cfg = cfg.server.clone();
    if server_cfg.bind_port == 0 {
        bail!("[server].bind_port 必须大于 0");
    }
    let tls = crate::transport::server_tls_config(&server_cfg)?;

    // 组网协调器（可选）
    let overlay = if cfg.overlay.enable {
        Some(overlay::OverlayCoordinator::new(&cfg.overlay).await?)
    } else {
        None
    };

    let state = ServerState::new(server_cfg.clone(), tls.clone(), overlay)?;

    let bind_addr = format!("{}:{}", server_cfg.bind_addr, server_cfg.bind_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("监听 {bind_addr} 失败"))?;
    tracing::info!("服务端监听 {bind_addr}（自动嗅探 tcp/tls/ws/wss）");

    if server_cfg.kcp {
        match tokio_kcp::KcpListener::bind(crate::transport::kcp_config(), &bind_addr).await {
            Ok(kcp) => {
                tracing::info!("服务端 KCP UDP 监听 {bind_addr}");
                let st = state.clone();
                tokio::spawn(async move { serve_kcp(kcp, st).await });
            }
            Err(e) => {
                // KCP 是可选传输；UDP 端口不可用时不要让 TCP 服务一起启动失败。
                tracing::error!("KCP UDP 监听 {bind_addr} 失败，KCP 不可用: {e}");
            }
        }
    }

    if server_cfg.vhost_http_port > 0 {
        let addr = format!("{}:{}", server_cfg.bind_addr, server_cfg.vhost_http_port);
        let l = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("监听 vhost_http_port {addr} 失败"))?;
        state
            .http_port
            .store(server_cfg.vhost_http_port as u64, Ordering::Relaxed);
        tracing::info!("HTTP 虚拟主机监听 {addr}");
        let st = state.clone();
        tokio::spawn(async move { proxy::serve_vhost_http(st, l).await });
    }

    if server_cfg.vhost_https_port > 0 {
        let addr = format!("{}:{}", server_cfg.bind_addr, server_cfg.vhost_https_port);
        let l = TcpListener::bind(&addr)
            .await
            .with_context(|| format!("监听 vhost_https_port {addr} 失败"))?;
        state
            .https_port
            .store(server_cfg.vhost_https_port as u64, Ordering::Relaxed);
        tracing::info!("HTTPS 虚拟主机(SNI 路由)监听 {addr}");
        let st = state.clone();
        tokio::spawn(async move { proxy::serve_vhost_https(st, l).await });
    }

    if cfg.dashboard.port > 0 {
        let st = state.clone();
        let dash = cfg.dashboard.clone();
        tokio::spawn(async move {
            if let Err(e) = dashboard::serve(st, dash).await {
                tracing::error!("面板启动失败: {e:#}");
            }
        });
    }

    loop {
        match crate::transport::accept_pending(&listener).await {
            Ok((sock, peer)) => {
                let st = state.clone();
                let tls = tls.clone();
                let ws_path = WS_PATH.to_string();
                tokio::spawn(async move {
                    match crate::transport::handshake(sock, peer, tls, &ws_path).await {
                        Ok(accepted) => {
                            if let Err(e) = control::handle_connection(st, accepted).await {
                                tracing::debug!("连接处理结束: {e:#}");
                            }
                        }
                        Err(e) => tracing::debug!("连接 {peer} 握手失败: {e:#}"),
                    }
                });
            }
            Err(e) => {
                tracing::warn!("accept 失败: {e:#}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_replay_cache_rejects_duplicate() {
        let st = ServerState::new(ServerConfig::default(), None, None).unwrap();
        assert!(st.accept_hello("salt-a", 100));
        assert!(!st.accept_hello("salt-a", 100), "同一 salt+ts 必须被拒绝");
        assert!(st.accept_hello("salt-a", 101));
        assert!(st.accept_hello("salt-b", 100));
    }

    #[test]
    fn fixed_port_requires_allow_list() {
        let st = ServerState::new(ServerConfig::default(), None, None).unwrap();
        assert!(
            st.allocate_port(12345, false).is_err(),
            "allow_ports 为空时不得分配固定端口"
        );
    }

    #[test]
    fn group_weighted_round_robin() {
        let (tx, _rx) = mpsc::channel(4);
        let client = Arc::new(ClientHandle {
            run_id: "test".into(),
            remote_addr: "127.0.0.1:1".into(),
            hostname: "test".into(),
            user: String::new(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "0.0.0".into(),
            connected_at: Instant::now(),
            connected_at_wall: SystemTime::now(),
            tx,
            proxies: StdMutex::new(Vec::new()),
            transport: "tcp".into(),
        });
        let group = GroupMembers::new("g", "k", 1234);
        for (name, weight) in [("a", 1), ("b", 3)] {
            let req = NewProxyRequest {
                name: name.into(),
                kind: crate::config::ProxyKind::Tcp,
                remote_port: 1234,
                custom_domains: Vec::new(),
                subdomain: String::new(),
                sk: String::new(),
                group: "g".into(),
                group_key: "k".into(),
                weight,
                bandwidth_limit: 0,
                proxy_protocol: String::new(),
            };
            group.add(Arc::new(ProxyRuntime::new(&req, client.clone(), 1234, "")));
        }

        let mut a = 0;
        let mut b = 0;
        for _ in 0..8 {
            match group.pick().unwrap().name.as_str() {
                "a" => a += 1,
                "b" => b += 1,
                other => panic!("unexpected member {other}"),
            }
        }
        assert_eq!((a, b), (2, 6), "权重 1:3 应按 2:6 分配");
    }
}
