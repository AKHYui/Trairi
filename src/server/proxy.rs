//! 服务端各类代理的监听与转发：tcp / udp / vhost http / vhost https。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use crate::protocol::{ControlMsg, RequestWorkConn, parse_pp};
use crate::server::{ProxyRuntime, ServerState, WorkConn};
use crate::util::{Throttle, build_proxy_protocol};

/// 等待客户端提供 work 连接的超时
const WORK_TIMEOUT: Duration = Duration::from_secs(15);
/// UDP 会话空闲超时
const UDP_IDLE: Duration = Duration::from_secs(60);
/// HTTP 请求头最大长度
const MAX_HEAD: usize = 16 * 1024;

/// 向客户端索要一条 work 连接。
async fn request_work(
    proxy: &Arc<ProxyRuntime>,
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Result<WorkConn> {
    if !proxy.healthy.load(Ordering::Relaxed) {
        bail!("代理 [{}] 当前不健康", proxy.name);
    }
    let req = RequestWorkConn {
        proxy_name: proxy.name.clone(),
        src_addr: src.map(|s| s.to_string()).unwrap_or_default(),
        dst_addr: dst.map(|s| s.to_string()).unwrap_or_default(),
        proxy_protocol: proxy.proxy_protocol.clone(),
    };
    if !proxy.client.send(ControlMsg::ReqWorkConn(req)).await {
        bail!("客户端 {} 已断开", proxy.client.run_id);
    }
    proxy
        .work
        .pop(WORK_TIMEOUT)
        .await
        .ok_or_else(|| anyhow::anyhow!("等待 work 连接超时"))
}

fn make_throttles(proxy: &ProxyRuntime) -> (Option<Arc<Throttle>>, Option<Arc<Throttle>>) {
    if proxy.bandwidth_limit == 0 {
        (None, None)
    } else {
        (
            Some(Throttle::new(proxy.bandwidth_limit)),
            Some(Throttle::new(proxy.bandwidth_limit)),
        )
    }
}

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

/// 启动 TCP 代理的对外监听。
pub async fn start_tcp_listener(
    state: Arc<ServerState>,
    proxy: Arc<ProxyRuntime>,
) -> Result<(), String> {
    let addr = format!("{}:{}", state.cfg.bind_addr, proxy.remote_port);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("监听 {addr} 失败: {e}"))?;
    let local_addr: SocketAddr = addr
        .parse()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    tracing::info!("代理 [{}] TCP 监听 {addr}", proxy.name);

    let (tin, tout) = make_throttles(&proxy);
    let group = proxy.group_handle.lock().unwrap().clone();
    let weak = Arc::downgrade(&proxy);
    let handle = tokio::spawn(async move {
        loop {
            let Some(proxy) = weak.upgrade() else { break };
            let (conn, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("TCP accept 失败: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = conn.set_nodelay(true);
            // 分组场景下轮询挑选一个健康成员
            let p = match group.as_ref().and_then(|g| g.pick()) {
                Some(m) => m,
                None => proxy.clone(),
            };
            let tin = tin.clone();
            let tout = tout.clone();
            tokio::spawn(async move {
                let wc = match request_work(&p, Some(peer), Some(local_addr)).await {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::warn!("代理 [{}] 获取 work 连接失败: {e:#}", p.name);
                        return;
                    }
                };
                p.stats.conns.fetch_add(1, Ordering::Relaxed);
                let mut ws = wc.stream;
                let pp = build_proxy_protocol(
                    parse_pp(&p.proxy_protocol),
                    wc.src.or(Some(peer)),
                    wc.dst.or(Some(local_addr)),
                );
                if !pp.is_empty() && ws.write_all(&pp).await.is_err() {
                    return;
                }
                let (up, down) = crate::util::pipe_bidirectional(conn, ws, tin, tout).await;
                p.stats.add(up, down);
                tracing::debug!("代理 [{}] 连接结束 {peer}: 上行 {up} 下行 {down}", p.name);
            });
        }
    });

    *proxy.listener.lock().unwrap() = Some(handle);
    Ok(())
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 启动 UDP 代理的对外监听。
pub async fn start_udp_listener(
    state: Arc<ServerState>,
    proxy: Arc<ProxyRuntime>,
) -> Result<(), String> {
    let addr = format!("{}:{}", state.cfg.bind_addr, proxy.remote_port);
    let socket = UdpSocket::bind(&addr)
        .await
        .map_err(|e| format!("监听 UDP {addr} 失败: {e}"))?;
    let socket = Arc::new(socket);
    let local_addr: SocketAddr = addr
        .parse()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    tracing::info!("代理 [{}] UDP 监听 {addr}", proxy.name);

    let group = proxy.group_handle.lock().unwrap().clone();
    let weak = Arc::downgrade(&proxy);
    let handle = tokio::spawn(async move {
        let mut sessions: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let Some(proxy) = weak.upgrade() else { break };
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("UDP 接收失败: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let data = buf[..n].to_vec();

            if let Some(tx) = sessions.get(&src) {
                if tx.send(data.clone()).await.is_ok() {
                    continue;
                }
                sessions.remove(&src);
            }

            // 新会话
            let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
            sessions.insert(src, tx.clone());
            let _ = tx.send(data).await;

            let p = match group.as_ref().and_then(|g| g.pick()) {
                Some(m) => m,
                None => proxy.clone(),
            };
            let sock = socket.clone();
            tokio::spawn(async move {
                match request_work(&p, Some(src), Some(local_addr)).await {
                    Ok(wc) => {
                        p.stats.conns.fetch_add(1, Ordering::Relaxed);
                        udp_session(sock, src, wc, rx, p.clone()).await;
                    }
                    Err(e) => tracing::warn!("UDP 会话建立失败: {e:#}"),
                }
            });
        }
    });

    *proxy.listener.lock().unwrap() = Some(handle);
    Ok(())
}

async fn udp_session(
    socket: Arc<UdpSocket>,
    src: SocketAddr,
    wc: WorkConn,
    rx: mpsc::Receiver<Vec<u8>>,
    proxy: Arc<ProxyRuntime>,
) {
    let last = Arc::new(AtomicU64::new(now_ms()));
    let stream = wc.stream;
    let (mut rd, mut wr) = tokio::io::split(stream);

    // 上行：本地数据报 -> work 连接
    let last_tx = last.clone();
    let mut rx = rx;
    let up = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            last_tx.store(now_ms(), Ordering::Relaxed);
            if data.len() > u16::MAX as usize {
                continue;
            }
            let mut frame = Vec::with_capacity(2 + data.len());
            frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
            frame.extend_from_slice(&data);
            if wr.write_all(&frame).await.is_err() {
                break;
            }
            let _ = wr.flush().await;
        }
        let _ = wr.shutdown().await;
    });

    // 下行：work 连接 -> 本地数据报
    let last_rx = last.clone();
    let sock = socket.clone();
    let down = tokio::spawn(async move {
        let mut len_buf = [0u8; 2];
        loop {
            if crate::util::read_full(&mut rd, &mut len_buf)
                .await
                .unwrap_or(0)
                != 2
            {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut data = vec![0u8; len];
            if crate::util::read_full(&mut rd, &mut data)
                .await
                .unwrap_or(0)
                != len
            {
                break;
            }
            last_rx.store(now_ms(), Ordering::Relaxed);
            let _ = sock.send_to(&data, src).await;
        }
    });

    // 空闲回收
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if up.is_finished() || down.is_finished() {
            break;
        }
        if now_ms().saturating_sub(last.load(Ordering::Relaxed)) > UDP_IDLE.as_millis() as u64 {
            break;
        }
    }
    up.abort();
    down.abort();
    proxy.stats.conns.fetch_sub(1, Ordering::Relaxed);
    tracing::debug!("UDP 会话结束 {src}");
}

// ---------------------------------------------------------------------------
// vhost HTTP
// ---------------------------------------------------------------------------

/// 在共享端口上按 Host 分发 HTTP 请求。
pub async fn serve_vhost_http(state: Arc<ServerState>, listener: TcpListener) {
    loop {
        let (conn, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("HTTP vhost accept 失败: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = conn.set_nodelay(true);
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_vhost_http(st, conn, peer).await {
                tracing::debug!("HTTP vhost 连接 {peer} 结束: {e:#}");
            }
        });
    }
}

async fn handle_vhost_http(
    state: Arc<ServerState>,
    mut conn: tokio::net::TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    // 读请求头
    let mut head = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            bail!("请求头过大");
        }
        let n = tokio::time::timeout_at(deadline, conn.read(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("读取请求头超时"))?
            .context("读取请求头失败")?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }

    let host =
        crate::util::parse_http_host(&head).ok_or_else(|| anyhow::anyhow!("请求缺少 Host 头"))?;
    let Some(proxy) = state.find_vhost(&host).await else {
        let body = format!("Trairi: 没有匹配的代理来处理 host = {host}\n");
        let resp = crate::util::http_response(404, "Not Found", &body);
        let _ = conn.write_all(&resp).await;
        return Ok(());
    };

    let dst = SocketAddr::from(([0, 0, 0, 0], state.http_port.load(Ordering::Relaxed) as u16));
    let wc = request_work(&proxy, Some(peer), Some(dst)).await?;
    proxy.stats.conns.fetch_add(1, Ordering::Relaxed);

    let (tin, tout) = make_throttles(&proxy);
    let mut ws = wc.stream;
    ws.write_all(&head).await.context("转发请求头失败")?;

    // 头部已经在上面转发过了，这里直接对接剩余的字节流
    let (up, down) = crate::util::pipe_bidirectional(conn, ws, tout, tin).await;
    proxy.stats.add(up, down);
    Ok(())
}

// ---------------------------------------------------------------------------
// vhost HTTPS（按 SNI 路由，不终止 TLS）
// ---------------------------------------------------------------------------

/// 在共享端口上按 SNI 分发 HTTPS 连接。
pub async fn serve_vhost_https(state: Arc<ServerState>, listener: TcpListener) {
    loop {
        let (conn, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("HTTPS vhost accept 失败: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let _ = conn.set_nodelay(true);
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_vhost_https(st, conn, peer).await {
                tracing::debug!("HTTPS vhost 连接 {peer} 结束: {e:#}");
            }
        });
    }
}

async fn handle_vhost_https(
    state: Arc<ServerState>,
    mut conn: tokio::net::TcpStream,
    peer: SocketAddr,
) -> Result<()> {
    // 读第一条 TLS 记录（ClientHello）
    let mut head = vec![0u8; 5];
    if crate::util::read_full(&mut conn, &mut head).await? != 5 {
        return Ok(());
    }
    if head[0] != 0x16 {
        bail!("不是 TLS 握手");
    }
    let record_len = u16::from_be_bytes([head[3], head[4]]) as usize;
    if record_len == 0 || record_len > 64 * 1024 {
        bail!("非法的 TLS 记录长度 {record_len}");
    }
    let mut body = vec![0u8; record_len];
    if crate::util::read_full(&mut conn, &mut body).await? != record_len {
        return Ok(());
    }
    let mut hello = head.clone();
    hello.extend_from_slice(&body);

    let sni =
        crate::util::peek_sni(&hello).ok_or_else(|| anyhow::anyhow!("ClientHello 里没有 SNI"))?;
    let Some(proxy) = state.find_vhost(&sni).await else {
        tracing::debug!("没有匹配 {sni} 的 https 代理");
        return Ok(());
    };

    let dst = SocketAddr::from((
        [0, 0, 0, 0],
        state.https_port.load(Ordering::Relaxed) as u16,
    ));
    let wc = request_work(&proxy, Some(peer), Some(dst)).await?;
    proxy.stats.conns.fetch_add(1, Ordering::Relaxed);

    let (tin, tout) = make_throttles(&proxy);
    let mut ws = wc.stream;
    ws.write_all(&hello)
        .await
        .context("转发 ClientHello 失败")?;

    let (up, down) = crate::util::pipe_bidirectional(conn, ws, tout, tin).await;
    proxy.stats.add(up, down);
    Ok(())
}

/// 记录一次连接开始的日志（供外部调用）。
pub fn log_new_conn(proxy: &ProxyRuntime, peer: SocketAddr) {
    tracing::debug!("代理 [{}] 新连接 {peer}", proxy.name);
    let _ = Instant::now();
}
