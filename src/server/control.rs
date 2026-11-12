//! 服务端连接处理：握手 → 加密记录层 → smux → 登录 → 控制循环 → work 连接分发。

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use smux::{Config as SmuxConfig, Session};
use tokio::sync::mpsc;

use crate::config::{ProxyKind, WireKind};
use crate::crypto;
use crate::protocol::{
    ControlMsg, HelloRequest, HelloResponse, LoginRequest, LoginResponse, NewProxyResponse,
    PROTOCOL_VERSION, StreamHeader, read_msg, write_msg,
};
use crate::server::{ClientHandle, ProxyRuntime, ServerState, WorkConn};
use crate::stream::AnyStream;
use crate::transport::Accepted;

/// 允许的最大时钟偏差
const MAX_CLOCK_SKEW_SECS: i64 = 300;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 处理一条来自客户端的连接。
pub async fn handle_connection(state: Arc<ServerState>, accepted: Accepted) -> Result<()> {
    let peer = accepted.peer;
    let transport = accepted.transport;
    let mut raw = accepted.stream;

    // ---- 1. 明文 Hello ----
    let auth_timeout = Duration::from_secs(state.cfg.authentication_timeout.max(5));
    let hello: HelloRequest = tokio::time::timeout(auth_timeout, read_msg(&mut raw))
        .await
        .map_err(|_| anyhow::anyhow!("等待客户端握手超时"))?
        .context("读取客户端握手包失败")?;

    if hello.version != PROTOCOL_VERSION {
        let _ = send_hello(
            &mut raw,
            false,
            "协议版本不一致，请升级 Trairi",
            &state.server_id,
        )
        .await;
        bail!("协议版本不一致: {} != {}", hello.version, PROTOCOL_VERSION);
    }
    let skew = (now_secs() - hello.timestamp).abs();
    if skew > MAX_CLOCK_SKEW_SECS {
        let _ = send_hello(
            &mut raw,
            false,
            "客户端与服务端时间偏差过大",
            &state.server_id,
        )
        .await;
        bail!("时间偏差 {skew}s，超出允许范围");
    }

    let token = &state.cfg.token;
    // 限制握手字段长度，避免 1 MiB salt/client 做无谓的 HMAC/分配
    if hello.salt.len() < 8 || hello.salt.len() > 128 {
        let _ = send_hello(&mut raw, false, "salt 长度非法", &state.server_id).await;
        bail!("salt 长度非法（{}）", hello.salt.len());
    }
    if hello.client.len() > 128 {
        let _ = send_hello(&mut raw, false, "client 标识过长", &state.server_id).await;
        bail!("client 标识过长（{}）", hello.client.len());
    }
    if !token.is_empty()
        && !crypto::verify_sign(
            token,
            &hello.salt,
            hello.timestamp,
            hello.version,
            hello.use_encryption,
            hello.use_compression,
            &hello.client,
            &hello.signature,
        )
    {
        let _ = send_hello(&mut raw, false, "token 校验失败", &state.server_id).await;
        bail!("token 校验失败（来自 {peer}）");
    }
    // 同一 salt+timestamp 只能成功握手一次；时间窗内重放直接拒绝。
    if !token.is_empty() && !state.accept_hello(&hello.salt, hello.timestamp) {
        let _ = send_hello(&mut raw, false, "握手重放或过于频繁", &state.server_id).await;
        bail!("握手重放被拒绝（来自 {peer}）");
    }
    if state.cfg.force_encryption && !hello.use_encryption {
        let _ = send_hello(&mut raw, false, "服务端强制加密", &state.server_id).await;
        bail!("服务端强制加密，但客户端未开启 use_encryption");
    }

    // ---- 2. 是否加密 ----
    let want_encryption = hello.use_encryption || state.cfg.force_encryption;
    let key = if want_encryption {
        if token.is_empty() {
            let _ = send_hello(
                &mut raw,
                false,
                "服务端要求加密但未配置 token",
                &state.server_id,
            )
            .await;
            bail!("客户端要求加密，但服务端没有配置 token");
        }
        Some(crypto::derive_key(token, &hello.salt)?)
    } else {
        None
    };

    // ---- 3. 先回明文握手响应，再从下一条字节开始加密 ----
    send_hello(&mut raw, true, "", &state.server_id).await?;
    let stream =
        crate::stream::wrap_stream(raw, key, hello.use_compression, crate::stream::Side::Server)?;

    tracing::info!(
        "客户端 {} 已接入 {peer} transport={transport} 加密={} 压缩={}",
        hello.client,
        key.is_some(),
        hello.use_compression
    );

    // ---- 5. smux ----
    let session = Session::server(stream, SmuxConfig::default())
        .await
        .context("创建 smux 会话失败")?;
    let session = Arc::new(session);

    let mut ctrl = session.accept_stream().await.context("等待控制流失败")?;

    // ---- 6. 登录 ----
    let login: LoginRequest = tokio::time::timeout(auth_timeout, read_msg(&mut ctrl))
        .await
        .map_err(|_| anyhow::anyhow!("等待登录包超时"))?
        .context("读取登录包失败")?;

    let run_id = if login.run_id.is_empty() {
        format!("{}-{}", crate::util::random_hex(4), login.hostname)
    } else {
        login.run_id.clone()
    };

    let (tx, mut rx) = mpsc::channel::<ControlMsg>(256);
    let client = Arc::new(ClientHandle {
        run_id: run_id.clone(),
        remote_addr: peer.to_string(),
        hostname: login.hostname.clone(),
        user: login.user.clone(),
        os: login.os.clone(),
        arch: login.arch.clone(),
        version: login.client_version.clone(),
        connected_at: std::time::Instant::now(),
        connected_at_wall: SystemTime::now(),
        tx,
        proxies: std::sync::Mutex::new(Vec::new()),
        transport: transport.to_string(),
    });

    // 同名客户端：踢掉旧的；同时限制登录连接数
    let full = {
        let clients = state.clients.read().await;
        !clients.contains_key(&run_id)
            && state.cfg.max_clients > 0
            && clients.len() >= state.cfg.max_clients as usize
    };
    if full {
        let resp = LoginResponse {
            ok: false,
            error: format!("服务端客户端数量已达上限 {}", state.cfg.max_clients),
            run_id: run_id.clone(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            heartbeat_interval: 30,
            p2p_port: state.cfg.p2p_port,
        };
        write_msg(&mut ctrl, &ControlMsg::LoginResp(resp)).await?;
        bail!("客户端数量达到上限 {}", state.cfg.max_clients);
    }
    let old = {
        let mut clients = state.clients.write().await;
        clients.insert(run_id.clone(), client.clone())
    };
    if let Some(old) = old {
        tracing::warn!("客户端 {run_id} 重复登录，旧连接将被关闭");
        old.send(ControlMsg::Stop).await;
    }

    // 把控制通道交给组网协调器（用于推送 peer 列表）
    if let Some(ov) = &state.overlay {
        ov.add_sender(&run_id, client.tx.clone()).await;
    }

    // 登录响应
    let resp = LoginResponse {
        ok: true,
        error: String::new(),
        run_id: run_id.clone(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        heartbeat_interval: 30,
        p2p_port: state.cfg.p2p_port,
    };
    write_msg(&mut ctrl, &ControlMsg::LoginResp(resp)).await?;

    // ---- 7. 读写分离 ----
    let (mut ctrl_r, mut ctrl_w) = tokio::io::split(ctrl);
    {
        let session_for_accept = session.clone();
        let state_for_accept = state.clone();
        let client_for_accept = client.clone();

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let stop = matches!(msg, ControlMsg::Stop);
                if write_msg(&mut ctrl_w, &msg).await.is_err() {
                    break;
                }
                if stop {
                    break;
                }
            }
        });

        // ---- 8. 接收 work 连接 ----
        tokio::spawn(async move {
            accept_streams(state_for_accept, session_for_accept, client_for_accept).await;
        });
    }

    // ---- 9. 控制循环 ----
    let result = control_loop(&state, &client, &mut ctrl_r).await;

    state.remove_client(&run_id).await;
    result
}

async fn send_hello(
    stream: &mut crate::stream::Stream,
    ok: bool,
    error: &str,
    server_id: &str,
) -> Result<()> {
    let resp = HelloResponse {
        version: PROTOCOL_VERSION,
        ok,
        error: error.to_string(),
        server_id: server_id.to_string(),
    };
    write_msg(stream, &resp).await.context("写握手响应失败")
}

/// 控制消息循环。
async fn control_loop(
    state: &Arc<ServerState>,
    client: &Arc<ClientHandle>,
    ctrl: &mut tokio::io::ReadHalf<smux::Stream>,
) -> Result<()> {
    let heartbeat_timeout = Duration::from_secs(state.cfg.heartbeat_timeout.max(10));
    loop {
        let msg =
            match tokio::time::timeout(heartbeat_timeout, read_msg::<_, ControlMsg>(ctrl)).await {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    tracing::debug!("控制流结束: {e}");
                    break;
                }
                Err(_) => {
                    tracing::warn!("客户端 {} 心跳超时", client.run_id);
                    break;
                }
            };

        match msg {
            ControlMsg::Ping { ts } => {
                let _ = client.send(ControlMsg::Pong { ts }).await;
            }
            ControlMsg::NewProxy(req) => {
                let resp = match state.register_proxy(&req, client).await {
                    Ok(p) => NewProxyResponse {
                        name: req.name.clone(),
                        error: String::new(),
                        remote_addr: if p.kind == WireKind::Tcp || p.kind == WireKind::Udp {
                            format!("{}:{}", state.cfg.bind_addr, p.remote_port)
                        } else {
                            p.domains.first().cloned().unwrap_or_default()
                        },
                    },
                    Err(e) => {
                        tracing::warn!("代理 [{}] 注册被拒: {e}", req.name);
                        NewProxyResponse {
                            name: req.name.clone(),
                            error: e,
                            remote_addr: String::new(),
                        }
                    }
                };
                let _ = client.send(ControlMsg::NewProxyResp(resp)).await;
            }
            ControlMsg::ProxyHealth(report) => {
                let proxies = state.proxies.read().await;
                if let Some(p) = proxies.get(&report.name) {
                    p.healthy
                        .store(report.healthy, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!(
                        "代理 [{}] 健康状态: {}",
                        report.name,
                        if report.healthy { "健康" } else { "异常" }
                    );
                }
            }
            ControlMsg::CloseProxy(n) => {
                state.unregister_proxy(&n.name).await;
            }
            ControlMsg::P2pRequest { proxy_name } => {
                if let Err(e) = handle_p2p_request(state, client, proxy_name.as_str()).await {
                    let _ = client
                        .send(ControlMsg::P2pInfo {
                            ok: false,
                            error: e.to_string(),
                            proxy_name,
                            peer_endpoint: String::new(),
                            peer_local_endpoint: String::new(),
                        })
                        .await;
                }
            }
            ControlMsg::Pong { .. } => {}
            ControlMsg::OverlayRegister(req) => {
                let assign = match &state.overlay {
                    Some(ov) => match ov.register(&client.run_id, &req).await {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::warn!("overlay 登记失败: {e}");
                            crate::protocol::OverlayAssign {
                                ok: false,
                                error: e,
                                ip: String::new(),
                                cidr: String::new(),
                                mtu: 0,
                                server_udp_port: 0,
                                server_relay_port: 0,
                                server_stun_port: 0,
                                server_node_port: 0,
                                acl: Vec::new(),
                                peers: Vec::new(),
                            }
                        }
                    },
                    None => crate::protocol::OverlayAssign {
                        ok: false,
                        error: "服务端未启用 overlay".into(),
                        ip: String::new(),
                        cidr: String::new(),
                        mtu: 0,
                        server_udp_port: 0,
                        server_relay_port: 0,
                        server_stun_port: 0,
                        server_node_port: 0,
                        acl: Vec::new(),
                        peers: Vec::new(),
                    },
                };
                let _ = client.send(ControlMsg::OverlayAssign(assign)).await;
            }
            other => {
                tracing::debug!("服务端忽略消息: {other:?}");
            }
        }
    }
    Ok(())
}

/// 处理所有新开的子流（work 连接 / 访问者连接）。
async fn accept_streams(state: Arc<ServerState>, session: Arc<Session>, client: Arc<ClientHandle>) {
    loop {
        let mut stream = match session.accept_stream().await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("会话结束: {e}");
                break;
            }
        };

        let header: StreamHeader =
            match tokio::time::timeout(Duration::from_secs(10), read_msg(&mut stream)).await {
                Ok(Ok(h)) => h,
                _ => {
                    tracing::debug!("子流缺少头信息，已丢弃");
                    continue;
                }
            };

        match header {
            StreamHeader::Work {
                proxy_name,
                src_addr,
                dst_addr,
            } => {
                let proxy = {
                    let proxies = state.proxies.read().await;
                    proxies.get(&proxy_name).cloned()
                };
                let Some(proxy) = proxy else {
                    tracing::warn!("收到未知代理 [{proxy_name}] 的 work 连接，已丢弃");
                    continue;
                };
                if proxy.client.run_id != client.run_id {
                    tracing::warn!("代理 [{proxy_name}] 的 work 连接来自错误的客户端，已丢弃");
                    continue;
                }
                let conn = WorkConn {
                    stream: Box::new(stream) as AnyStream,
                    src: src_addr.parse().ok(),
                    dst: dst_addr.parse().ok(),
                };
                proxy.work.push(conn);
            }
            StreamHeader::Visitor {
                proxy_name,
                sk,
                src_addr,
                dst_addr,
                ..
            } => {
                let st = state.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_visitor(st, stream, proxy_name, sk, src_addr, dst_addr).await
                    {
                        tracing::warn!("访问者连接失败: {e:#}");
                    }
                });
            }
        }
    }
}

/// 处理访问者的 P2P 会合请求：把双方 UDP endpoint 互相交换。
async fn handle_p2p_request(
    state: &Arc<ServerState>,
    visitor: &Arc<ClientHandle>,
    proxy_name: &str,
) -> Result<()> {
    let proxy = {
        let proxies = state.proxies.read().await;
        proxies
            .get(proxy_name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("不存在代理 [{proxy_name}]"))?
    };
    if !proxy.p2p {
        bail!("代理 [{proxy_name}] 不是 P2P 类型");
    }
    let rendezvous = {
        let guard = state.p2p.lock().unwrap();
        guard
            .clone()
            .ok_or_else(|| anyhow::anyhow!("服务端未启用 P2P（p2p_port=0）"))?
    };
    let owner_ep = rendezvous
        .endpoint(&proxy.client.run_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("代理持有者还没有 P2P UDP endpoint"))?;
    let visitor_ep = rendezvous
        .endpoint(&visitor.run_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("访问者还没有 P2P UDP endpoint"))?;
    let owner_local = owner_ep.local.map(|a| a.to_string()).unwrap_or_default();
    let visitor_local = visitor_ep.local.map(|a| a.to_string()).unwrap_or_default();

    visitor
        .send(ControlMsg::P2pInfo {
            ok: true,
            error: String::new(),
            proxy_name: proxy_name.to_string(),
            peer_endpoint: owner_ep.public.to_string(),
            peer_local_endpoint: owner_local.clone(),
        })
        .await;
    if !proxy
        .client
        .send(ControlMsg::P2pPeer {
            proxy_name: proxy_name.to_string(),
            peer_endpoint: visitor_ep.public.to_string(),
            peer_local_endpoint: visitor_local.clone(),
        })
        .await
    {
        bail!("无法通知代理持有者");
    }
    tracing::info!(
        "P2P 会合 [{proxy_name}]: owner={} ({owner_local}) visitor={} ({visitor_local})",
        owner_ep.public,
        visitor_ep.public
    );
    Ok(())
}

/// stcp 访问者连接：校验 sk 后，向代理持有者要一条 work 连接并桥接。
async fn handle_visitor(
    state: Arc<ServerState>,
    visitor_stream: smux::Stream,
    proxy_name: String,
    sk: String,
    src_addr: String,
    dst_addr: String,
) -> Result<()> {
    let proxy: Arc<ProxyRuntime> = {
        let proxies = state.proxies.read().await;
        match proxies.get(&proxy_name) {
            Some(p) => p.clone(),
            None => bail!("不存在代理 [{proxy_name}]"),
        }
    };
    if proxy.kind != WireKind::Stcp {
        bail!("代理 [{proxy_name}] 不是 stcp 类型");
    }
    if proxy.sk != sk {
        bail!("代理 [{proxy_name}] 的 sk 校验失败");
    }
    if !proxy.healthy.load(std::sync::atomic::Ordering::Relaxed) {
        bail!("代理 [{proxy_name}] 当前不可用");
    }

    // 向持有者请求一条 work 连接
    let req = crate::protocol::RequestWorkConn {
        proxy_name: proxy_name.clone(),
        src_addr: src_addr.clone(),
        dst_addr: dst_addr.clone(),
        proxy_protocol: String::new(),
    };
    if !proxy.client.send(ControlMsg::ReqWorkConn(req)).await {
        bail!("无法联系代理持有者");
    }
    let Some(work) = proxy.work.pop(Duration::from_secs(15)).await else {
        bail!("等待 work 连接超时");
    };

    proxy
        .stats
        .conns
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (up, down) =
        crate::util::pipe_bidirectional(Box::new(visitor_stream), work.stream, None, None).await;
    proxy.stats.add(up, down);
    Ok(())
}

/// 判断一个 proxy 类型是否需要在服务端监听端口。
pub fn kind_needs_listener(kind: ProxyKind) -> bool {
    matches!(kind.wire(), WireKind::Tcp | WireKind::Udp)
}
