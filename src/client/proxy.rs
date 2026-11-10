//! 客户端侧的本地转发：work 连接 → 本地服务，以及访问者监听、健康检查。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use smux::Session;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::config::{ProxyConfig, VisitorConfig};
use crate::plugin;
use crate::protocol::{ControlMsg, ProxyHealthReport, StreamHeader, write_msg};
use crate::stream::AnyStream;
use crate::util::Throttle;

/// 根据代理配置准备本地服务（插件类型会现起一个本地服务）。
pub async fn prepare_local(proxy: &ProxyConfig) -> Result<Option<plugin::PluginService>> {
    let svc = match proxy.kind {
        crate::config::ProxyKind::Socks5 => Some(plugin::start_socks5().await?),
        crate::config::ProxyKind::HttpProxy => Some(plugin::start_http_proxy().await?),
        crate::config::ProxyKind::StaticFile => Some(
            plugin::start_static_file(
                std::path::PathBuf::from(&proxy.local_path),
                proxy.http_user.clone(),
                proxy.http_pwd.clone(),
            )
            .await?,
        ),
        _ => None,
    };
    Ok(svc)
}

fn throttle_of(proxy: &ProxyConfig) -> (Option<Arc<Throttle>>, Option<Arc<Throttle>>) {
    let limit = proxy.bandwidth_bytes();
    if limit > 0 && proxy.limit_on_client() {
        (Some(Throttle::new(limit)), Some(Throttle::new(limit)))
    } else {
        (None, None)
    }
}

/// 处理一条 work 连接：连上本地服务后双向转发。
pub async fn run_work_conn(
    proxy: Arc<ProxyConfig>,
    stream: AnyStream,
    dial_timeout: u64,
) -> Result<()> {
    let addr = proxy.local_addr.clone();
    if addr.is_empty() {
        bail!("代理 {} 没有配置 local_addr", proxy.name);
    }

    let conn = tokio::time::timeout(
        Duration::from_secs(dial_timeout.max(1)),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("连接本地服务 {addr} 超时"))?
    .with_context(|| format!("连接本地服务 {addr} 失败"))?;
    let _ = conn.set_nodelay(true);

    let (tin, tout) = throttle_of(&proxy);
    let (up, down) = crate::util::pipe_bidirectional(conn, stream, tout, tin).await;
    tracing::debug!(
        "代理 [{}] 本地转发结束 {}: 上行 {up} 下行 {down}",
        proxy.name,
        addr
    );
    Ok(())
}

/// 处理一条 UDP work 连接。
pub async fn run_udp_work_conn(
    proxy: Arc<ProxyConfig>,
    stream: AnyStream,
    dial_timeout: u64,
) -> Result<()> {
    let addr = proxy.local_addr.clone();
    if addr.is_empty() {
        bail!("UDP 代理 {} 没有配置 local_addr", proxy.name);
    }
    let remote: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("UDP 代理 {} 的 local_addr 必须是 IP:PORT", proxy.name))?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("绑定本地 UDP 失败")?;
    socket
        .connect(remote)
        .await
        .context("连接本地 UDP 服务失败")?;
    let socket = Arc::new(socket);
    let _ = dial_timeout;

    let (mut rd, mut wr) = tokio::io::split(stream);

    // 下行：work 连接 -> 本地 UDP
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
            if sock.send(&data).await.is_err() {
                break;
            }
        }
    });

    // 上行：本地 UDP -> work 连接
    let (tin, _) = throttle_of(&proxy);
    let mut buf = vec![0u8; 65536];
    loop {
        let n = match socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(_) => break,
        };
        if let Some(t) = tin.as_ref() {
            t.consume(n).await;
        }
        let mut frame = Vec::with_capacity(2 + n);
        frame.extend_from_slice(&(n as u16).to_be_bytes());
        frame.extend_from_slice(&buf[..n]);
        if wr.write_all(&frame).await.is_err() {
            break;
        }
        let _ = wr.flush().await;
    }
    let _ = wr.shutdown().await;
    let _ = down.await;
    Ok(())
}

/// 启动一个 stcp 访问者：本地监听，连上后向服务端开一条访问者流。
pub async fn start_visitor(
    visitor: VisitorConfig,
    session: Arc<Session>,
    dial_timeout: u64,
) -> Result<tokio::task::JoinHandle<()>> {
    let addr = format!("{}:{}", visitor.bind_addr, visitor.bind_port);
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("访问者 {} 监听 {addr} 失败", visitor.name))?;
    tracing::info!(
        "访问者 [{}] 已监听 {addr} → stcp 代理 [{}]",
        visitor.name,
        visitor.server_name
    );

    let handle = tokio::spawn(async move {
        loop {
            let (conn, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("访问者 accept 失败: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = conn.set_nodelay(true);
            let session = session.clone();
            let v = visitor.clone();
            tokio::spawn(async move {
                match open_visitor_stream(&session, &v, peer, dial_timeout).await {
                    Ok(stream) => {
                        crate::util::pipe_bidirectional(conn, stream, None, None).await;
                    }
                    Err(e) => tracing::warn!("访问者 [{}] 建立隧道失败: {e:#}", v.name),
                }
            });
        }
    });

    Ok(handle)
}

async fn open_visitor_stream(
    session: &Arc<Session>,
    visitor: &VisitorConfig,
    peer: std::net::SocketAddr,
    dial_timeout: u64,
) -> Result<AnyStream> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(dial_timeout.max(1)),
        session.open_stream(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("打开访问者流超时"))?
    .context("打开访问者流失败")?;
    let header = StreamHeader::Visitor {
        proxy_name: visitor.server_name.clone(),
        sk: visitor.sk.clone(),
        src_addr: peer.to_string(),
        dst_addr: String::new(),
        proxy_protocol: String::new(),
    };
    write_msg(&mut stream, &header)
        .await
        .context("写访问者头失败")?;
    Ok(Box::new(stream))
}

/// 健康检查循环：状态变化时上报服务端。
pub async fn health_check_loop(
    proxy: ProxyConfig,
    tx: mpsc::Sender<ControlMsg>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let kind = proxy.health_check_type.to_ascii_lowercase();
    if kind.is_empty() {
        return;
    }
    let interval = Duration::from_secs(proxy.health_check_interval.max(1));
    let timeout = Duration::from_secs(proxy.health_check_timeout.max(1));
    let max_failed = proxy.health_check_max_failed.max(1);
    let mut failed = 0u32;
    let mut healthy = true;
    let mut ticker = tokio::time::interval(interval);

    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = stop.changed() => break,
        }

        let ok = match kind.as_str() {
            "tcp" => matches!(
                tokio::time::timeout(timeout, TcpStream::connect(&proxy.local_addr)).await,
                Ok(Ok(_))
            ),
            "http" => check_http(&proxy.local_addr, &proxy.health_check_path, timeout).await,
            other => {
                tracing::warn!("代理 [{}] 未知的健康检查类型: {other}", proxy.name);
                return;
            }
        };

        if ok {
            failed = 0;
            if !healthy {
                healthy = true;
                tracing::info!("代理 [{}] 恢复健康", proxy.name);
                let _ = tx
                    .send(ControlMsg::ProxyHealth(ProxyHealthReport {
                        name: proxy.name.clone(),
                        healthy: true,
                    }))
                    .await;
            }
        } else {
            failed += 1;
            if healthy && failed >= max_failed {
                healthy = false;
                tracing::warn!("代理 [{}] 健康检查连续失败 {failed} 次", proxy.name);
                let _ = tx
                    .send(ControlMsg::ProxyHealth(ProxyHealthReport {
                        name: proxy.name.clone(),
                        healthy: false,
                    }))
                    .await;
            }
        }
    }
}

async fn check_http(addr: &str, path: &str, timeout: Duration) -> bool {
    let Ok(Ok(mut conn)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await else {
        return false;
    };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: trairi-health\r\nConnection: close\r\n\r\n",
        if path.is_empty() { "/" } else { path },
        addr
    );
    if conn.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    match tokio::time::timeout(timeout, conn.read(&mut buf)).await {
        Ok(Ok(n)) if n > 12 => {
            let line = String::from_utf8_lossy(&buf[..n]);
            line.starts_with("HTTP/1.1 2") || line.starts_with("HTTP/1.1 3")
        }
        _ => false,
    }
}
