//! 客户端运行时：连接服务端、登录、注册代理、处理 work 连接、访问者与健康检查。

pub mod overlay;
pub mod p2p;
pub mod proxy;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use smux::{Config as SmuxConfig, Session};
use tokio::sync::{mpsc, oneshot, watch};

use crate::config::{ClientConfig, Config, ProxyConfig, ProxyKind};
use crate::crypto;
use crate::protocol::{
    ControlMsg, HelloRequest, HelloResponse, LoginRequest, LoginResponse, NewProxyRequest,
    NewProxyResponse, PROTOCOL_VERSION, StreamHeader, read_msg, write_msg,
};
use crate::stream::AnyStream;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 供 overlay 模块使用的主机名。
pub fn hostname_static() -> String {
    hostname()
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// 客户端运行期状态（管理 API 会读取）
pub struct ClientInfo {
    pub run_id: StdMutex<String>,
    pub connected: AtomicBool,
    pub server: String,
    pub proxies: StdMutex<Vec<ProxyStatus>>,
}

#[derive(Clone, serde::Serialize)]
pub struct ProxyStatus {
    pub name: String,
    pub kind: String,
    pub remote: String,
    pub error: String,
}

/// 管理 API 的共享标志
#[derive(Default)]
pub struct AdminFlags {
    pub reload: AtomicBool,
    pub stop: AtomicBool,
}

/// 客户端入口：带自动重连。
pub async fn run(cfg: Config) -> Result<()> {
    crate::transport::ensure_crypto_provider();

    let admin = Arc::new(AdminFlags::default());
    let info = Arc::new(ClientInfo {
        run_id: StdMutex::new(String::new()),
        connected: AtomicBool::new(false),
        server: format!("{}:{}", cfg.client.server_addr, cfg.client.server_port),
        proxies: StdMutex::new(Vec::new()),
    });

    if cfg.web_server.port > 0 {
        let ws = cfg.web_server.clone();
        let admin2 = admin.clone();
        let info2 = info.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_admin(ws, admin2, info2).await {
                tracing::error!("管理 API 启动失败: {e:#}");
            }
        });
    }

    let mut current = cfg;
    loop {
        let outcome = connect_once(current.clone(), info.clone()).await;

        if admin.stop.load(Ordering::Relaxed) {
            tracing::info!("收到停止指令，退出");
            return Ok(());
        }

        if admin.reload.swap(false, Ordering::Relaxed) {
            tracing::info!("收到重载指令，重新读取配置");
            if let Some(path) = crate::config_path() {
                match Config::load(&path) {
                    Ok(new_cfg) => current = new_cfg,
                    Err(e) => tracing::error!("重载配置失败，沿用旧配置: {e:#}"),
                }
            }
        }

        match outcome {
            Ok(()) => tracing::warn!("与 {} 的连接已断开，3 秒后重连", info.server),
            Err(e) => tracing::warn!("连接 {} 异常: {e:#}，3 秒后重连", info.server),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// 将客户端级默认值落到单个代理上；per-proxy 非空值优先。
fn apply_client_defaults(cc: &ClientConfig, mut pc: ProxyConfig) -> ProxyConfig {
    if pc.bandwidth_limit.is_empty() {
        pc.bandwidth_limit = cc.bandwidth_limit.clone();
    }
    if pc.proxy_protocol_version.is_empty() {
        pc.proxy_protocol_version = cc.proxy_protocol_version.clone();
    }
    pc
}

/// 客户端心跳间隔：配置 > 0 时优先，否则用服务端建议值，最小 5 秒。
fn effective_heartbeat(client_interval: u64, server_interval: u64) -> u64 {
    if client_interval > 0 {
        client_interval
    } else {
        server_interval
    }
    .max(5)
}

/// 建立一次完整连接并运行到断开。
async fn connect_once(cfg: Config, info: Arc<ClientInfo>) -> Result<()> {
    let cc = &cfg.client;

    // ---- 1. 传输层 ----
    let mut raw = crate::transport::dial(cc).await?;

    // ---- 2. 明文握手 ----
    let salt = crate::util::random_hex(8);
    let timestamp = now_secs();
    let use_encryption = cc.use_encryption && !cc.token.is_empty();
    let client_name = format!("trairi/{} {}", env!("CARGO_PKG_VERSION"), hostname());
    let hello = HelloRequest {
        version: PROTOCOL_VERSION,
        salt: salt.clone(),
        timestamp,
        signature: if cc.token.is_empty() {
            String::new()
        } else {
            crypto::sign(
                &cc.token,
                &salt,
                timestamp,
                PROTOCOL_VERSION,
                use_encryption,
                cc.use_compression,
                &client_name,
            )
        },
        use_encryption,
        use_compression: cc.use_compression,
        client: client_name,
    };
    write_msg(&mut raw, &hello)
        .await
        .context("发送握手包失败")?;
    let resp: HelloResponse = read_msg(&mut raw).await.context("读取握手响应失败")?;
    if !resp.ok {
        bail!("服务端拒绝连接: {}", resp.error);
    }

    // ---- 3. 记录层（加密 / 压缩） ----
    let key = if use_encryption {
        Some(crypto::derive_key(&cc.token, &salt)?)
    } else {
        None
    };
    let stream =
        crate::stream::wrap_stream(raw, key, cc.use_compression, crate::stream::Side::Client)?;

    // ---- 4. smux 会话 ----
    let session = Arc::new(
        Session::client(stream, SmuxConfig::default())
            .await
            .context("创建 smux 会话失败")?,
    );

    // ---- 5. 控制流 + 登录 ----
    let ctrl = session.open_stream().await.context("打开控制流失败")?;
    let (mut ctrl_r, mut ctrl_w) = tokio::io::split(ctrl);

    let run_id = if cc.run_id.is_empty() {
        format!("{}-{}", hostname(), crate::util::random_hex(4))
    } else {
        cc.run_id.clone()
    };
    let login = LoginRequest {
        run_id: run_id.clone(),
        user: cc.user.clone(),
        hostname: hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: now_secs(),
        metas: Default::default(),
    };
    write_msg(&mut ctrl_w, &ControlMsg::Login(login))
        .await
        .context("发送登录请求失败")?;
    let (sid, server_heartbeat, server_p2p_port) = match read_msg::<_, ControlMsg>(&mut ctrl_r)
        .await
        .context("读取登录响应失败")?
    {
        ControlMsg::LoginResp(LoginResponse {
            ok: true,
            run_id: sid,
            heartbeat_interval,
            p2p_port,
            ..
        }) => {
            tracing::info!("已登录服务端 {sid}");
            *info.run_id.lock().unwrap() = sid.clone();
            (sid, heartbeat_interval, p2p_port)
        }
        ControlMsg::LoginResp(LoginResponse {
            ok: false, error, ..
        }) => {
            bail!("登录被拒绝: {error}");
        }
        other => bail!("登录响应异常: {other:?}"),
    };
    // 客户端配置优先；0 表示沿用服务端建议值。
    let heartbeat_secs = effective_heartbeat(cc.heartbeat_interval, server_heartbeat);
    info.connected.store(true, Ordering::Relaxed);

    let (tx, mut rx) = mpsc::channel::<ControlMsg>(256);
    let (close_tx, close_rx) = oneshot::channel::<()>();
    let (stop_tx, stop_rx) = watch::channel(false);

    // P2P 需要 owner/visitor 至少各有一端配置了 p2p 代理/访问者。
    let wants_p2p = cfg
        .proxies
        .iter()
        .any(|p| p.kind == crate::config::ProxyKind::P2p)
        || cfg
            .visitors
            .iter()
            .any(|v| v.kind == crate::config::ProxyKind::P2p);
    let p2p_node: Option<Arc<p2p::P2pNode>> = if wants_p2p && server_p2p_port > 0 {
        match p2p::P2pNode::start(&cfg, cc, sid.clone(), server_p2p_port, tx.clone()).await {
            Ok(node) => Some(node),
            Err(e) => {
                tracing::error!("P2P 节点启动失败，将只能使用服务器中继: {e:#}");
                None
            }
        }
    } else if wants_p2p {
        tracing::warn!("配置了 P2P，但服务端 p2p_port=0，P2P 不可用");
        None
    } else {
        None
    };

    // ---- 6. 写任务 ----
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_msg(&mut ctrl_w, &msg).await.is_err() {
                break;
            }
        }
    });

    // ---- 7. 心跳 ----
    {
        let tx = tx.clone();
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(heartbeat_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if tx.send(ControlMsg::Ping { ts: now_secs() }).await.is_err() {
                            break;
                        }
                    }
                    _ = stop.changed() => break,
                }
            }
        });
    }

    // ---- 8. 控制循环 ----
    let pending: Arc<StdMutex<HashMap<String, oneshot::Sender<NewProxyResponse>>>> =
        Arc::new(StdMutex::new(HashMap::new()));
    let proxies: Arc<StdMutex<HashMap<String, Arc<ProxyConfig>>>> =
        Arc::new(StdMutex::new(HashMap::new()));
    // overlay：分配结果的一次性回执 + 已建立的节点
    let overlay_assign: Arc<StdMutex<Option<oneshot::Sender<crate::protocol::OverlayAssign>>>> =
        Arc::new(StdMutex::new(None));
    let overlay_client: Arc<tokio::sync::Mutex<Option<Arc<overlay::OverlayClient>>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    // 节点表可能在 overlay 客户端还没建好时就推过来了，先存着，建好后补应用
    let overlay_pending: Arc<StdMutex<Option<Vec<crate::protocol::OverlayPeerInfo>>>> =
        Arc::new(StdMutex::new(None));

    {
        let session = session.clone();
        let overlay_assign = overlay_assign.clone();
        let overlay_client = overlay_client.clone();
        let overlay_pending = overlay_pending.clone();
        let tx = tx.clone();
        let pending = pending.clone();
        let proxies = proxies.clone();
        let info = info.clone();
        let p2p_node = p2p_node.clone();
        let dial_timeout = cc.dial_timeout;
        let heartbeat_timeout = Duration::from_secs(cc.heartbeat_timeout.max(10));
        tokio::spawn(async move {
            let mut ctrl_r = ctrl_r;
            loop {
                let msg = match tokio::time::timeout(
                    heartbeat_timeout,
                    read_msg::<_, ControlMsg>(&mut ctrl_r),
                )
                .await
                {
                    Ok(Ok(m)) => m,
                    Ok(Err(e)) => {
                        tracing::debug!("控制流结束: {e}");
                        break;
                    }
                    Err(_) => {
                        tracing::warn!("心跳超时，准备重连");
                        break;
                    }
                };
                match msg {
                    ControlMsg::NewProxyResp(resp) => {
                        let waiter = pending.lock().unwrap().remove(&resp.name);
                        if let Some(w) = waiter {
                            let _ = w.send(resp);
                        }
                    }
                    ControlMsg::ReqWorkConn(req) => {
                        let proxy = proxies.lock().unwrap().get(&req.proxy_name).cloned();
                        let Some(proxy) = proxy else {
                            tracing::warn!("服务端请求了未知代理 [{}] 的连接", req.proxy_name);
                            continue;
                        };
                        let session = session.clone();
                        tokio::spawn(async move {
                            if let Err(e) = run_work_conn(session, proxy, dial_timeout).await {
                                tracing::warn!("处理 work 连接失败: {e:#}");
                            }
                        });
                    }
                    ControlMsg::Ping { ts } => {
                        let _ = tx.send(ControlMsg::Pong { ts }).await;
                    }
                    ControlMsg::Pong { .. } => {}
                    ControlMsg::OverlayAssign(a) => {
                        let waiter = overlay_assign.lock().unwrap().take();
                        if let Some(w) = waiter {
                            let _ = w.send(a);
                        }
                    }
                    ControlMsg::OverlayPeers(p) => {
                        *overlay_pending.lock().unwrap() = Some(p.peers.clone());
                        let node = overlay_client.lock().await.clone();
                        if let Some(node) = node {
                            node.apply_peers(&p.peers).await;
                        }
                    }
                    ControlMsg::CloseProxy(n) => {
                        tracing::info!("服务端关闭代理 [{}]: {}", n.name, n.error);
                        proxies.lock().unwrap().remove(&n.name);
                    }
                    ControlMsg::P2pInfo {
                        ok,
                        error,
                        proxy_name,
                        peer_endpoint,
                    } => {
                        if ok {
                            if let Ok(ep) = peer_endpoint.parse() {
                                if let Some(node) = &p2p_node {
                                    node.set_peer(&proxy_name, ep).await;
                                }
                            }
                        } else {
                            tracing::debug!("P2P 会合 [{proxy_name}] 失败: {error}");
                        }
                    }
                    ControlMsg::P2pPeer {
                        proxy_name,
                        peer_endpoint,
                    } => {
                        if let Ok(ep) = peer_endpoint.parse() {
                            if let Some(node) = &p2p_node {
                                node.set_peer(&proxy_name, ep).await;
                            }
                        }
                    }
                    ControlMsg::P2pRequest { .. } => {}
                    ControlMsg::Stop => {
                        tracing::info!("服务端要求断开连接");
                        break;
                    }
                    ControlMsg::LoginResp(_) => {}
                    other => tracing::debug!("客户端忽略消息: {other:?}"),
                }
            }
            info.connected.store(false, Ordering::Relaxed);
            let _ = close_tx.send(());
        });
    }

    // ---- 8.5 启动 overlay（如果启用） ----
    if cfg.overlay.enable {
        match start_overlay(&cfg, cc, &tx, &overlay_assign, &overlay_client).await {
            Ok(()) => {
                // 补应用在初始化期间已经推过来的节点表
                let pending = overlay_pending.lock().unwrap().take();
                if let Some(peers) = pending {
                    let node = overlay_client.lock().await.clone();
                    if let Some(node) = node {
                        node.apply_peers(&peers).await;
                    }
                }
            }
            Err(e) => tracing::error!("overlay 启动失败: {e:#}"),
        }
    }

    // ---- 9. 启动本地服务并注册代理 ----
    let mut started_plugins = Vec::new();
    let mut status_list = Vec::new();
    for pc in cfg.proxies.iter() {
        if !cc.start.is_empty() && !cc.start.contains(&pc.name) {
            tracing::info!("代理 [{}] 不在 start 列表中，跳过", pc.name);
            continue;
        }
        let mut pc = apply_client_defaults(cc, pc.clone());

        match proxy::prepare_local(&pc).await {
            Ok(Some(svc)) => {
                if pc.local_addr.is_empty() {
                    pc.local_addr = svc.local_addr();
                }
                started_plugins.push(svc);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!("代理 [{}] 本地服务启动失败: {e:#}", pc.name);
                status_list.push(ProxyStatus {
                    name: pc.name.clone(),
                    kind: pc.kind.as_str().to_string(),
                    remote: String::new(),
                    error: format!("{e:#}"),
                });
                continue;
            }
        }

        let pc = Arc::new(pc);
        proxies.lock().unwrap().insert(pc.name.clone(), pc.clone());

        let req = NewProxyRequest {
            name: pc.name.clone(),
            kind: pc.kind,
            remote_port: pc.remote_port,
            custom_domains: pc.custom_domains.clone(),
            subdomain: pc.subdomain.clone(),
            sk: pc.sk.clone(),
            group: pc.group.clone(),
            group_key: pc.group_key.clone(),
            weight: pc.weight.max(1),
            // 客户端侧限速时告知服务端不要再限一次
            bandwidth_limit: if pc.limit_on_client() {
                0
            } else {
                pc.bandwidth_bytes()
            },
            proxy_protocol: pc.proxy_protocol_version.clone(),
        };

        let (wtx, wrx) = oneshot::channel();
        pending.lock().unwrap().insert(pc.name.clone(), wtx);
        if tx.send(ControlMsg::NewProxy(req)).await.is_err() {
            bail!("控制连接已断开");
        }

        match tokio::time::timeout(Duration::from_secs(15), wrx).await {
            Ok(Ok(resp)) if resp.error.is_empty() => {
                tracing::info!(
                    "代理 [{}] 注册成功{}",
                    pc.name,
                    if resp.remote_addr.is_empty() {
                        String::new()
                    } else {
                        format!("，对外地址 {}", resp.remote_addr)
                    }
                );
                status_list.push(ProxyStatus {
                    name: pc.name.clone(),
                    kind: pc.kind.as_str().to_string(),
                    remote: resp.remote_addr.clone(),
                    error: String::new(),
                });
            }
            Ok(Ok(resp)) => {
                tracing::error!("代理 [{}] 注册失败: {}", pc.name, resp.error);
                status_list.push(ProxyStatus {
                    name: pc.name.clone(),
                    kind: pc.kind.as_str().to_string(),
                    remote: String::new(),
                    error: resp.error,
                });
            }
            Ok(Err(_)) => tracing::warn!("代理 [{}] 注册等待被取消", pc.name),
            Err(_) => tracing::warn!("代理 [{}] 注册超时", pc.name),
        }

        if !pc.health_check_type.is_empty() {
            tokio::spawn(proxy::health_check_loop(
                (*pc).clone(),
                tx.clone(),
                stop_rx.clone(),
            ));
        }
    }

    *info.proxies.lock().unwrap() = status_list;

    // ---- 10. 访问者 ----
    for v in cfg.visitors.iter().cloned() {
        match proxy::start_visitor(
            v.clone(),
            session.clone(),
            cc.dial_timeout,
            p2p_node.clone(),
        )
        .await
        {
            Ok(_) => tracing::info!("访问者 [{}] 已启动", v.name),
            Err(e) => tracing::error!("访问者 [{}] 启动失败: {e:#}", v.name),
        }
    }

    // ---- 11. 等待断开 ----
    let _ = close_rx.await;
    let _ = stop_tx.send(true);

    // 清理 overlay 路由（网卡随设备释放一起消失）
    {
        let mut slot = overlay_client.lock().await;
        if let Some(oc) = slot.take() {
            crate::overlay::host::remove_peer_routes(&oc.ifname, &oc.ips().await);
        }
    }
    for svc in started_plugins {
        svc.handle.abort();
    }
    Ok(())
}

async fn run_work_conn(
    session: Arc<Session>,
    proxy: Arc<ProxyConfig>,
    dial_timeout: u64,
) -> Result<()> {
    let mut stream = session.open_stream().await.context("打开 work 流失败")?;
    let header = StreamHeader::Work {
        proxy_name: proxy.name.clone(),
        src_addr: String::new(),
        dst_addr: String::new(),
    };
    write_msg(&mut stream, &header)
        .await
        .context("写 work 头失败")?;
    let any: AnyStream = Box::new(stream);

    if proxy.kind == ProxyKind::Udp {
        proxy::run_udp_work_conn(proxy, any, dial_timeout).await
    } else {
        proxy::run_work_conn(proxy, any, dial_timeout).await
    }
}

/// 建立 overlay 连接：绑定 UDP、注册、等分配、建网卡、启动数据面。
async fn start_overlay(
    cfg: &Config,
    cc: &ClientConfig,
    tx: &mpsc::Sender<ControlMsg>,
    assign_slot: &Arc<StdMutex<Option<oneshot::Sender<crate::protocol::OverlayAssign>>>>,
    client_slot: &Arc<tokio::sync::Mutex<Option<Arc<overlay::OverlayClient>>>>,
) -> Result<()> {
    let (private, pubkey_b64) = overlay::generate_keypair();

    let bind = format!("0.0.0.0:{}", cfg.overlay.udp_port);
    let socket = Arc::new(
        tokio::net::UdpSocket::bind(&bind)
            .await
            .with_context(|| format!("overlay UDP 绑定 {bind} 失败"))?,
    );
    let port = socket.local_addr()?.port();

    let (tx_a, rx_a) = oneshot::channel();
    *assign_slot.lock().unwrap() = Some(tx_a);

    tx.send(ControlMsg::OverlayRegister(overlay::register_msg(
        &cfg.overlay,
        &pubkey_b64,
        port,
    )))
    .await
    .map_err(|_| anyhow::anyhow!("控制连接已断开"))?;

    let assign = tokio::time::timeout(overlay::ASSIGN_TIMEOUT, rx_a)
        .await
        .map_err(|_| anyhow::anyhow!("等待 overlay 分配超时"))?
        .map_err(|_| anyhow::anyhow!("overlay 分配被取消"))?;

    let oc = overlay::setup(&cfg.overlay, &cc.server_addr, assign, private, socket).await?;
    *client_slot.lock().await = Some(Arc::new(oc));
    Ok(())
}

async fn serve_admin(
    cfg: crate::config::WebServerConfig,
    admin: Arc<AdminFlags>,
    info: Arc<ClientInfo>,
) -> Result<()> {
    use tiny_http::{Header, Method, Response, Server};

    let addr = format!("{}:{}", cfg.addr, cfg.port);
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("监听 {addr} 失败: {e}"))?;
    tracing::info!("客户端管理 API 已启动 http://{addr}");

    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let path = request.url().to_string();
            let path = path.split('?').next().unwrap_or("/").to_string();
            let (code, body): (u16, String) = match (&request.method(), path.as_str()) {
                (Method::Get, "/api/status") | (Method::Post, "/api/status") => {
                    let payload = serde_json::json!({
                        "run_id": *info.run_id.lock().unwrap(),
                        "connected": info.connected.load(Ordering::Relaxed),
                        "server": info.server,
                        "proxies": info.proxies.lock().unwrap().clone(),
                    });
                    (200, payload.to_string())
                }
                (Method::Get, "/api/reload") | (Method::Post, "/api/reload") => {
                    admin.reload.store(true, Ordering::Relaxed);
                    (200, r#"{"ok":true,"msg":"已触发重载"}"#.to_string())
                }
                (Method::Get, "/api/stop") | (Method::Post, "/api/stop") => {
                    admin.stop.store(true, Ordering::Relaxed);
                    std::thread::spawn(|| {
                        std::thread::sleep(Duration::from_millis(300));
                        std::process::exit(0);
                    });
                    (200, r#"{"ok":true,"msg":"已停止"}"#.to_string())
                }
                _ => (404, r#"{"ok":false,"msg":"not found"}"#.to_string()),
            };
            let resp = Response::from_string(body)
                .with_status_code(code)
                .with_header(
                    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                );
            let _ = request.respond(resp);
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_defaults_apply_to_proxy() {
        let cc = ClientConfig {
            bandwidth_limit: "5MB".into(),
            proxy_protocol_version: "v2".into(),
            ..Default::default()
        };
        let pc = ProxyConfig {
            name: "p".into(),
            ..Default::default()
        };
        let out = apply_client_defaults(&cc, pc);
        assert_eq!(out.bandwidth_limit, "5MB");
        assert_eq!(out.proxy_protocol_version, "v2");

        let pc = ProxyConfig {
            name: "p".into(),
            bandwidth_limit: "1MB".into(),
            proxy_protocol_version: "v1".into(),
            ..Default::default()
        };
        let out = apply_client_defaults(&cc, pc);
        assert_eq!(out.bandwidth_limit, "1MB", "per-proxy 应优先");
        assert_eq!(out.proxy_protocol_version, "v1");
    }

    #[test]
    fn heartbeat_precedence() {
        assert_eq!(effective_heartbeat(0, 30), 30);
        assert_eq!(effective_heartbeat(60, 30), 60);
        assert_eq!(effective_heartbeat(1, 30), 5, "最小 5 秒");
    }
}
