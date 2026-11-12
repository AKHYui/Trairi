//! 客户端 P2P 数据面。
//!
//! 设计要点：
//! - owner/visitor 各自在一个预先绑定的 UDP socket 上起 `KcpListener`；
//! - 服务端只交换双方公网 UDP endpoint，不转发业务数据；
//! - visitor 用一条手工构造的 KCP PUSH 包发起会话（同一个 socket 打洞）；
//! - 会话建立后先做 `sk` HMAC 认证，再接入本地服务；
//! - 失败由 visitor 回退到服务端中继。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use smux::{Config as SmuxConfig, Session as SmuxSession};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, RwLock, mpsc, oneshot};
use tokio_kcp::{KcpListener, KcpStream};

use crate::config::{ClientConfig, Config, ProxyConfig, ProxyKind};
use crate::p2p::{auth_mac, probe_packet, punch_packet, verify_auth_mac};
use crate::protocol::ControlMsg;
use crate::stream::{AnyStream, Side};
const P2P_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const P2P_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const P2P_MAX_FRAME: usize = 64 * 1024;

type PendingSender = oneshot::Sender<Result<(KcpStream, String, i64), String>>;

struct Pending {
    peer: SocketAddr,
    tx: PendingSender,
}

#[derive(Debug, Clone, Copy)]
struct PeerAddrs {
    public: SocketAddr,
    local: Option<SocketAddr>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum P2pFrame {
    Challenge {
        nonce: String,
        timestamp: i64,
    },
    Auth {
        proxy_name: String,
        conv: u32,
        mac: String,
    },
    AuthResp {
        conv: u32,
        ok: bool,
        #[serde(default)]
        error: String,
    },
}

/// 客户端 P2P 节点：owner 和 visitor 共用。
pub struct P2pNode {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
    peers: Arc<RwLock<HashMap<String, PeerAddrs>>>,
    pending: Arc<Mutex<Option<Pending>>>,
    sessions: Arc<Mutex<HashMap<String, Arc<SmuxSession>>>>,
    establish_lock: Arc<Mutex<()>>,
    shutdown: Arc<Notify>,
    proxies: Arc<HashMap<String, ProxyConfig>>,
    control_tx: mpsc::Sender<ControlMsg>,
}

impl P2pNode {
    pub async fn start(
        cfg: &Config,
        cc: &ClientConfig,
        run_id: String,
        server_p2p_port: u16,
        control_tx: mpsc::Sender<ControlMsg>,
    ) -> Result<Arc<Self>> {
        let std_socket = std::net::UdpSocket::bind(("0.0.0.0", cc.p2p_udp_port))
            .with_context(|| format!("P2P UDP 绑定 0.0.0.0:{} 失败", cc.p2p_udp_port))?;
        std_socket.set_nonblocking(true)?;
        let send_std = std_socket.try_clone()?;
        let listener_socket = UdpSocket::from_std(std_socket)?;
        let socket = Arc::new(UdpSocket::from_std(send_std)?);
        let local = socket.local_addr()?;
        let listener = KcpListener::from_socket(crate::transport::kcp_config(), listener_socket)
            .await
            .map_err(|e| anyhow::anyhow!("P2P KCP listener 启动失败: {e}"))?;

        let proxies: Arc<HashMap<String, ProxyConfig>> = Arc::new(
            cfg.proxies
                .iter()
                .filter(|p| p.kind == ProxyKind::P2p)
                .map(|p| (p.name.clone(), p.clone()))
                .collect(),
        );
        let node = Arc::new(Self {
            socket: socket.clone(),
            local,
            peers: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(Mutex::new(None)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            establish_lock: Arc::new(Mutex::new(())),
            shutdown: Arc::new(Notify::new()),
            proxies: proxies.clone(),
            control_tx,
        });

        {
            let pending = node.pending.clone();
            let proxies = proxies.clone();
            let local = node.local;
            let shutdown = node.shutdown.clone();
            tokio::spawn(async move {
                accept_loop(listener, pending, proxies, local, shutdown).await;
            });
        }

        // 解析会合服务端地址，启动周期性探针。
        let server = format!("{}:{}", cc.server_addr, server_p2p_port);
        let probe_addr = crate::transport::resolve_server_addr(&cc.server_addr, server_p2p_port)
            .await
            .with_context(|| format!("解析 P2P 会合地址 {server} 失败"))?;

        // 通过一条临时 UDP socket 查看到会合服务端所使用的本机出口 IP。
        let local_endpoint = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(route) => match route.connect(probe_addr).await {
                Ok(()) => match route.local_addr() {
                    Ok(a) if a.is_ipv4() => Some(SocketAddr::new(a.ip(), local.port())),
                    _ => None,
                },
                Err(_) => None,
            },
            Err(_) => None,
        };
        if let Some(ep) = local_endpoint {
            tracing::info!("P2P 本机 endpoint: {ep}");
        }

        {
            let socket = socket.clone();
            let token = cc.token.clone();
            let probe = probe_addr;
            let shutdown = node.shutdown.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(10));
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let pkt = probe_packet(&token, &run_id, now_secs(), local_endpoint);
                            let _ = socket.send_to(&pkt, probe).await;
                        }
                        _ = shutdown.notified() => break,
                    }
                }
            });
        }

        tracing::info!("P2P UDP 已监听 {local}，会合服务端 {probe_addr}");
        Ok(node)
    }

    /// 控制面收到 P2pInfo/P2pPeer 后更新对端 endpoint。
    pub async fn set_peer(&self, proxy_name: &str, public: SocketAddr, local: Option<SocketAddr>) {
        self.peers
            .write()
            .await
            .insert(proxy_name.to_string(), PeerAddrs { public, local });
        // owner 主动向 visitor 发短打洞包，打开自己的 NAT 映射。
        if self.proxies.contains_key(proxy_name) {
            let socket = self.socket.clone();
            let targets: Vec<SocketAddr> = local.into_iter().chain([public]).collect();
            tokio::spawn(async move {
                for _ in 0..3 {
                    for target in &targets {
                        let _ = socket.send_to(punch_packet(), target).await;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }
    }

    /// visitor 发起一条到 owner 的 P2P 连接。
    pub async fn connect(&self, proxy_name: &str, sk: &str) -> Result<AnyStream> {
        let _guard = self.establish_lock.lock().await;
        if let Some(session) = self.sessions.lock().await.get(proxy_name).cloned()
            && !session.is_closed()
        {
            let stream = session
                .open_stream()
                .await
                .context("打开 P2P smux 流失败")?;
            return Ok(Box::new(stream));
        }
        self.sessions.lock().await.remove(proxy_name);

        let stream = self.establish(proxy_name, sk).await?;
        let session = Arc::new(
            SmuxSession::client(stream, SmuxConfig::default())
                .await
                .context("创建 P2P smux 会话失败")?,
        );
        self.sessions
            .lock()
            .await
            .insert(proxy_name.to_string(), session.clone());
        let stream = session
            .open_stream()
            .await
            .context("打开 P2P smux 流失败")?;
        Ok(Box::new(stream))
    }

    async fn establish(&self, proxy_name: &str, sk: &str) -> Result<crate::stream::Stream> {
        let peer = self
            .wait_peer(proxy_name, Duration::from_millis(2500))
            .await?;
        let mut candidates = Vec::new();
        if let Some(local) = peer.local
            && local != peer.public
        {
            candidates.push((local, Duration::from_millis(1500)));
        }
        candidates.push((peer.public, P2P_CONNECT_TIMEOUT));

        let mut last_err = None;
        for (endpoint, timeout) in candidates {
            match self.establish_to(proxy_name, sk, endpoint, timeout).await {
                Ok(stream) => return Ok(stream),
                Err(e) => {
                    tracing::debug!("P2P 尝试 {endpoint} 失败: {e:#}");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("没有可用的 P2P endpoint")))
    }

    async fn establish_to(
        &self,
        proxy_name: &str,
        sk: &str,
        peer: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<crate::stream::Stream> {
        let conv = random_conv();
        tracing::info!("P2P[{}] establish {proxy_name} -> {peer}", self.local);
        let (tx, rx) = oneshot::channel();
        {
            let mut slot = self.pending.lock().await;
            if slot.is_some() {
                bail!("已有一条 P2P 会话正在建立");
            }
            *slot = Some(Pending { peer, tx });
        }

        // WASK 只是建立 KCP session，不携带业务数据；认证由 owner 发起 challenge。
        let wask = build_wask(conv);
        for _ in 0..3 {
            self.socket.send_to(&wask, peer).await?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let (mut stream, nonce, timestamp) = match tokio::time::timeout(connect_timeout, rx).await {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => {
                *self.pending.lock().await = None;
                bail!("P2P 会话失败: {e}");
            }
            Ok(Err(_)) => {
                *self.pending.lock().await = None;
                bail!("P2P 会话被取消");
            }
            Err(_) => {
                *self.pending.lock().await = None;
                bail!("P2P 连接 {peer} 超时");
            }
        };

        *self.pending.lock().await = None;
        let auth = P2pFrame::Auth {
            proxy_name: proxy_name.to_string(),
            conv,
            mac: auth_mac(sk, proxy_name, conv, &nonce, timestamp),
        };
        write_frame(&mut stream, &auth).await?;
        match tokio::time::timeout(P2P_AUTH_TIMEOUT, read_frame(&mut stream)).await {
            Ok(Ok(P2pFrame::AuthResp { ok: true, .. })) => {
                let key = crate::crypto::derive_key(sk, "p2p-v1")?;
                crate::stream::wrap_stream(stream, Some(key), false, Side::Client)
            }
            Ok(Ok(P2pFrame::AuthResp { error, .. })) => bail!("P2P 认证失败: {error}"),
            Ok(Ok(_)) => bail!("P2P 认证响应异常"),
            Ok(Err(e)) => bail!("P2P 认证读取失败: {e}"),
            Err(_) => bail!("P2P 认证超时"),
        }
    }

    async fn wait_peer(&self, proxy_name: &str, timeout: Duration) -> Result<PeerAddrs> {
        if let Some(peer) = self.peers.read().await.get(proxy_name).copied() {
            return Ok(peer);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let _ = self
                .control_tx
                .send(ControlMsg::P2pRequest {
                    proxy_name: proxy_name.to_string(),
                })
                .await;
            if let Some(peer) = self.peers.read().await.get(proxy_name).copied() {
                return Ok(peer);
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("没有拿到 P2P 代理 [{proxy_name}] 的 endpoint");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

impl Drop for P2pNode {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
    }
}

async fn accept_loop(
    mut listener: KcpListener,
    pending: Arc<Mutex<Option<Pending>>>,
    proxies: Arc<HashMap<String, ProxyConfig>>,
    local: SocketAddr,
    shutdown: Arc<Notify>,
) {
    let owner = !proxies.is_empty();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.notified() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((mut stream, peer)) => {
                tracing::debug!("P2P[{local}] KCP accept stream from {peer}");
                let pending = pending.clone();
                let proxies = proxies.clone();
                tokio::spawn(async move {
                    if owner {
                        let nonce = crate::util::random_hex(16);
                        let timestamp = now_secs();
                        let challenge = P2pFrame::Challenge {
                            nonce: nonce.clone(),
                            timestamp,
                        };
                        if write_frame(&mut stream, &challenge).await.is_err() {
                            return;
                        }
                        let frame =
                            match tokio::time::timeout(P2P_AUTH_TIMEOUT, read_frame(&mut stream))
                                .await
                            {
                                Ok(Ok(f)) => f,
                                _ => {
                                    tracing::debug!(
                                        "P2P[{local}] 会话 {peer} 没有认证响应，已丢弃"
                                    );
                                    return;
                                }
                            };
                        if let P2pFrame::Auth {
                            proxy_name,
                            conv,
                            mac,
                        } = frame
                        {
                            handle_owner_auth(
                                stream, peer, proxy_name, conv, nonce, timestamp, mac, proxies,
                            )
                            .await;
                        }
                    } else {
                        let frame =
                            match tokio::time::timeout(P2P_AUTH_TIMEOUT, read_frame(&mut stream))
                                .await
                            {
                                Ok(Ok(f)) => f,
                                _ => {
                                    tracing::debug!(
                                        "P2P[{local}] 会话 {peer} 没有 challenge，已丢弃"
                                    );
                                    return;
                                }
                            };
                        if let P2pFrame::Challenge { nonce, timestamp } = frame {
                            let mut slot = pending.lock().await;
                            if let Some(p) = slot.take() {
                                if p.peer == peer {
                                    let _ = p.tx.send(Ok((stream, nonce, timestamp)));
                                } else {
                                    *slot = Some(p);
                                }
                            }
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!("P2P KCP accept 失败: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_owner_auth(
    mut stream: KcpStream,
    peer: SocketAddr,
    proxy_name: String,
    conv: u32,
    nonce: String,
    timestamp: i64,
    mac: String,
    proxies: Arc<HashMap<String, ProxyConfig>>,
) {
    let Some(proxy) = proxies.get(&proxy_name) else {
        let _ = write_frame(
            &mut stream,
            &P2pFrame::AuthResp {
                conv,
                ok: false,
                error: "未知 P2P 代理".into(),
            },
        )
        .await;
        return;
    };
    if !verify_auth_mac(
        &proxy.sk,
        &proxy_name,
        conv,
        &nonce,
        timestamp,
        &mac,
        now_secs(),
    ) {
        let _ = write_frame(
            &mut stream,
            &P2pFrame::AuthResp {
                conv,
                ok: false,
                error: "sk 校验失败".into(),
            },
        )
        .await;
        return;
    }

    if write_frame(
        &mut stream,
        &P2pFrame::AuthResp {
            conv,
            ok: true,
            error: String::new(),
        },
    )
    .await
    .is_err()
    {
        return;
    }
    let session = match crate::crypto::derive_key(&proxy.sk, "p2p-v1")
        .and_then(|key| crate::stream::wrap_stream(stream, Some(key), false, Side::Server))
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("P2P 记录层创建失败: {e:#}");
            return;
        }
    };
    let session = match SmuxSession::server(session, SmuxConfig::default()).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("P2P smux 会话创建失败: {e}");
            return;
        }
    };
    tracing::info!("P2P 直连 [{proxy_name}] 来自 {peer}");
    let proxy = proxy.clone();
    loop {
        let stream = match session.accept_stream().await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("P2P smux 会话结束: {e}");
                break;
            }
        };
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let local = match TcpStream::connect(&proxy.local_addr).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("P2P 连接本地服务失败: {e}");
                    return;
                }
            };
            let _ = crate::util::pipe_bidirectional(stream, local, None, None).await;
        });
    }
}

fn encode_frame(frame: &P2pFrame) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(frame)?;
    if body.len() > P2P_MAX_FRAME {
        bail!("P2P 帧过大");
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<P2pFrame> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > P2P_MAX_FRAME {
        bail!("P2P 帧长度非法: {len}");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &P2pFrame) -> Result<()> {
    let data = encode_frame(frame)?;
    w.write_all(&data).await?;
    w.flush().await?;
    Ok(())
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_conv() -> u32 {
    loop {
        let v = rand::random::<u32>();
        if v != 0 {
            return v;
        }
    }
}

/// 构造一条合法的 KCP WASK：只用于让对端创建 session，不携带数据。
/// 这样后续的 Auth 帧会从双方 KCP 的 sn=0 开始，不会和 WASK 的数据序列冲突。
fn build_wask(conv: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&conv.to_le_bytes());
    out.push(83); // KCP_CMD_WASK
    out.push(0); // frg
    out.extend_from_slice(&128u16.to_le_bytes()); // wnd
    out.extend_from_slice(&now_millis().to_le_bytes()); // ts
    out.extend_from_slice(&0u32.to_le_bytes()); // sn
    out.extend_from_slice(&0u32.to_le_bytes()); // una
    out.extend_from_slice(&0u32.to_le_bytes()); // len
    out
}

fn now_millis() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u32)
        .unwrap_or(0)
}
