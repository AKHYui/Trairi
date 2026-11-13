//! TCP 中继：直连不通时，两端把 WireGuard 报文交给服务端转发。
//!
//! 协议（长度前缀帧，跑在一条长连接上）：
//! ```text
//! 客户端 -> 服务端   AUTH   {network, secret_hash, pubkey}
//! 服务端 -> 客户端   AUTH_RESP {ok, error}
//! 客户端 -> 服务端   SEND   [32B 目标公钥][WireGuard 报文]
//! 服务端 -> 客户端   RECV   [32B 来源公钥][WireGuard 报文]
//! 双向                PING / PONG
//! ```
//! 中继只搬运密文，不持有任何密钥。

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};

use crate::overlay::{key_from_b64, key_to_b64};

pub const FRAME_AUTH: u8 = 1;
pub const FRAME_AUTH_RESP: u8 = 2;
pub const FRAME_SEND: u8 = 3;
pub const FRAME_RECV: u8 = 4;
pub const FRAME_PING: u8 = 5;
pub const FRAME_PONG: u8 = 6;

const MAX_FRAME: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub network: String,
    pub secret_hash: String,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: String,
}

/// 把一个帧编码成字节。
pub fn encode_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 读一个帧，返回 (kind, payload)。
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 5];
    if crate::util::read_full(r, &mut head).await? != 5 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "中继连接已关闭",
        ));
    }
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "帧过大",
        ));
    }
    let mut payload = vec![0u8; len];
    if crate::util::read_full(r, &mut payload).await? != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "帧不完整",
        ));
    }
    Ok((head[0], payload))
}

// ---------------------------------------------------------------------------
// 服务端
// ---------------------------------------------------------------------------

type Registry = Arc<RwLock<HashMap<[u8; 32], mpsc::Sender<Vec<u8>>>>>;
type AllowedPubkeys = Arc<RwLock<HashSet<[u8; 32]>>>;

/// 未认证连接最多等这么久
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
/// 中继连接上限（防止 fd/内存被无限占用）
const MAX_RELAY_CONNS: usize = 4096;

/// 在给定监听器上启动中继服务，返回实际端口。
///
/// `allowed` 不为 None 时，只接受已通过 overlay 控制面登记的公钥，
/// 避免任何知道 `secret_hash` 的人拿任意 pubkey 注册中继身份。
pub async fn spawn_relay_server(
    listener: TcpListener,
    network: String,
    secret_hash: String,
    allowed: Option<AllowedPubkeys>,
) -> Result<u16> {
    let port = listener.local_addr()?.port();
    let registry: Registry = Arc::new(RwLock::new(HashMap::new()));
    let slots = Arc::new(Semaphore::new(MAX_RELAY_CONNS));

    tokio::spawn(async move {
        loop {
            let (conn, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("中继 accept 失败: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                tracing::warn!("中继连接数已达上限 {MAX_RELAY_CONNS}，拒绝 {peer}");
                drop(conn);
                continue;
            };
            let _ = conn.set_nodelay(true);
            let registry = registry.clone();
            let network = network.clone();
            let secret_hash = secret_hash.clone();
            let allowed = allowed.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = serve_conn(conn, registry, network, secret_hash, allowed).await {
                    tracing::debug!("中继连接 {peer} 结束: {e:#}");
                }
            });
        }
    });

    tracing::info!("overlay TCP 中继已监听 :{port}");
    Ok(port)
}

async fn serve_conn(
    conn: tokio::net::TcpStream,
    registry: Registry,
    network: String,
    secret_hash: String,
    allowed: Option<AllowedPubkeys>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(conn);

    // 认证：必须在有限时间内完成，不能无限占用一个 task/fd
    let read = tokio::time::timeout(AUTH_TIMEOUT, read_frame(&mut rd)).await;
    let (kind, payload) = match read {
        Ok(v) => v.context("读取认证帧失败")?,
        Err(_) => bail!("等待中继认证超时"),
    };
    if kind != FRAME_AUTH {
        bail!("第一帧必须是认证");
    }
    let auth: AuthRequest = serde_json::from_slice(&payload).context("认证帧解析失败")?;
    if auth.network.len() > 128 || auth.secret_hash.len() != 64 {
        bail!("中继认证字段长度非法");
    }
    if auth.network != network || auth.secret_hash != secret_hash {
        let resp = AuthResponse {
            ok: false,
            error: "网络或密钥不正确".into(),
        };
        wr.write_all(&encode_frame(FRAME_AUTH_RESP, &serde_json::to_vec(&resp)?))
            .await
            .ok();
        bail!("中继认证失败");
    }
    let pubkey = key_from_b64(&auth.pubkey).context("公钥非法")?;
    if let Some(allowed) = &allowed
        && !allowed.read().await.contains(&pubkey)
    {
        let resp = AuthResponse {
            ok: false,
            error: "该公钥未在 overlay 控制面登记".into(),
        };
        wr.write_all(&encode_frame(FRAME_AUTH_RESP, &serde_json::to_vec(&resp)?))
            .await
            .ok();
        bail!("中继公钥未登记");
    }
    // 同一公钥已有活跃连接时拒绝顶替；只有旧连接已关闭才允许重连。
    if let Some(old) = registry.read().await.get(&pubkey).cloned()
        && !old.is_closed()
    {
        let resp = AuthResponse {
            ok: false,
            error: "该公钥已有活跃中继连接".into(),
        };
        wr.write_all(&encode_frame(FRAME_AUTH_RESP, &serde_json::to_vec(&resp)?))
            .await
            .ok();
        bail!("中继公钥已在线");
    }
    let resp = AuthResponse {
        ok: true,
        error: String::new(),
    };
    wr.write_all(&encode_frame(FRAME_AUTH_RESP, &serde_json::to_vec(&resp)?))
        .await?;

    // 写任务
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    let writer = tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            if wr.write_all(&buf).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    registry.write().await.insert(pubkey, tx.clone());
    tracing::info!("中继节点 {:.8} 已接入", key_to_b64(&pubkey));

    // 读循环
    let mut last_seen = std::time::Instant::now();
    loop {
        let read = tokio::time::timeout(Duration::from_secs(90), read_frame(&mut rd)).await;
        let (kind, payload) = match read {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => break,
            Err(_) => {
                tracing::debug!("中继连接空闲超时");
                break;
            }
        };
        last_seen = std::time::Instant::now();
        match kind {
            FRAME_SEND => {
                if payload.len() < 32 {
                    continue;
                }
                let mut dst = [0u8; 32];
                dst.copy_from_slice(&payload[..32]);
                let body = &payload[32..];
                let target = { registry.read().await.get(&dst).cloned() };
                if let Some(sender) = target {
                    let mut frame = Vec::with_capacity(5 + 32 + body.len());
                    frame.extend_from_slice(&encode_frame(
                        FRAME_RECV,
                        &[&pubkey[..], body].concat(),
                    ));
                    tracing::debug!("中继转发 {} 字节 -> {:.8}", body.len(), key_to_b64(&dst));
                    let _ = sender.send(frame).await;
                } else {
                    tracing::trace!("中继目标 {:.8} 不在线", key_to_b64(&dst));
                }
            }
            FRAME_PING => {
                let _ = tx.send(encode_frame(FRAME_PONG, &[])).await;
            }
            _ => {}
        }
    }

    {
        let mut reg = registry.write().await;
        // 只有当前 registry 里还是自己这条连接时才删除，避免旧连接退出时
        // 把刚重连上来的新连接删掉。
        let is_current = reg
            .get(&pubkey)
            .map(|s| s.same_channel(&tx))
            .unwrap_or(false);
        if is_current {
            reg.remove(&pubkey);
        }
    }
    tracing::info!(
        "中继节点 {:.8} 已断开（在线 {:?}）",
        key_to_b64(&pubkey),
        last_seen.elapsed()
    );
    writer.abort();
    Ok(())
}

// ---------------------------------------------------------------------------
// 客户端
// ---------------------------------------------------------------------------

/// 中继客户端句柄。
#[derive(Clone)]
pub struct RelayClient {
    tx: mpsc::Sender<Vec<u8>>,
    incoming: Arc<Mutex<Option<mpsc::Receiver<([u8; 32], Vec<u8>)>>>>,
    _tasks: Arc<RelayTasks>,
}

/// 持有中继连接的后台任务；最后一个 RelayClient 被丢弃时中止它们，
/// 这样 RelayLink 丢掉旧连接后可以立刻重新认证，而不是等心跳超时。
struct RelayTasks {
    handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl RelayTasks {
    fn new(handles: Vec<tokio::task::JoinHandle<()>>) -> Self {
        Self {
            handles: std::sync::Mutex::new(handles),
        }
    }
}

impl Drop for RelayTasks {
    fn drop(&mut self) {
        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
    }
}

impl RelayClient {
    /// 连接中继并完成认证，返回客户端句柄与「收到对端报文」的通道。
    pub async fn connect(
        addr: &str,
        network: &str,
        secret_hash: &str,
        pubkey: [u8; 32],
    ) -> Result<Self> {
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map_err(|_| anyhow::anyhow!("连接中继 {addr} 超时"))?
        .with_context(|| format!("连接中继 {addr} 失败"))?;
        let _ = conn.set_nodelay(true);
        let (mut rd, mut wr) = tokio::io::split(conn);

        let auth = AuthRequest {
            network: network.to_string(),
            secret_hash: secret_hash.to_string(),
            pubkey: key_to_b64(&pubkey),
        };
        wr.write_all(&encode_frame(FRAME_AUTH, &serde_json::to_vec(&auth)?))
            .await?;

        let (kind, payload) = read_frame(&mut rd).await.context("读取中继认证响应失败")?;
        if kind != FRAME_AUTH_RESP {
            bail!("中继认证响应异常");
        }
        let resp: AuthResponse = serde_json::from_slice(&payload)?;
        if !resp.ok {
            bail!("中继认证被拒绝: {}", resp.error);
        }

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        let (in_tx, in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(1024);

        // 写任务
        let writer = tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                if wr.write_all(&buf).await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        });

        // 读任务
        let reader = tokio::spawn(async move {
            let mut rd = rd;
            loop {
                match read_frame(&mut rd).await {
                    Ok((kind, payload)) => match kind {
                        FRAME_RECV if payload.len() > 32 => {
                            let mut src = [0u8; 32];
                            src.copy_from_slice(&payload[..32]);
                            let _ = in_tx.send((src, payload[32..].to_vec())).await;
                        }
                        FRAME_PING => {}
                        _ => {}
                    },
                    Err(_) => break,
                }
            }
            tracing::debug!("中继读循环结束");
        });

        // 心跳
        let heartbeat = {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(20));
                loop {
                    ticker.tick().await;
                    if tx.send(encode_frame(FRAME_PING, &[])).await.is_err() {
                        break;
                    }
                }
            })
        };

        Ok(Self {
            tx,
            incoming: Arc::new(Mutex::new(Some(in_rx))),
            _tasks: Arc::new(RelayTasks::new(vec![writer, reader, heartbeat])),
        })
    }

    /// 取出「收到对端报文」的接收端（只能取一次）。
    pub async fn take_incoming(&self) -> Option<mpsc::Receiver<([u8; 32], Vec<u8>)>> {
        self.incoming.lock().await.take()
    }

    /// 通过中继发给某个公钥对应的节点。
    ///
    /// 返回 false 表示写通道已经关闭（连接已断）。
    pub async fn send_to(&self, dst: [u8; 32], payload: &[u8]) -> bool {
        let mut body = Vec::with_capacity(32 + payload.len());
        body.extend_from_slice(&dst);
        body.extend_from_slice(payload);
        self.tx.send(encode_frame(FRAME_SEND, &body)).await.is_ok()
    }

    /// 写通道是否已经关闭。
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

struct RelayLinkInner {
    addr: String,
    network: String,
    secret_hash: String,
    pubkey: [u8; 32],
    current: RwLock<Option<RelayClient>>,
    incoming_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
    incoming: Mutex<Option<mpsc::Receiver<([u8; 32], Vec<u8>)>>>,
    connected: AtomicBool,
    generation: AtomicU64,
}

/// 带自动重连的中继链路。
///
/// 对上层暴露稳定的收包通道；底层 `RelayClient` 断开后由后台任务按
/// 1s/2s/5s/10s/30s 退避重连，旧连接退出不会误删新连接。
#[derive(Clone)]
pub struct RelayLink {
    inner: Arc<RelayLinkInner>,
}

impl RelayLink {
    pub fn new(addr: String, network: String, secret_hash: String, pubkey: [u8; 32]) -> Self {
        let (in_tx, in_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(1024);
        let inner = Arc::new(RelayLinkInner {
            addr,
            network,
            secret_hash,
            pubkey,
            current: RwLock::new(None),
            incoming_tx: in_tx,
            incoming: Mutex::new(Some(in_rx)),
            connected: AtomicBool::new(false),
            generation: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move { relay_reconnect_loop(weak).await });
        Self { inner }
    }

    /// 取出稳定的「收到对端报文」接收端（只能取一次）。
    pub async fn take_incoming(&self) -> Option<mpsc::Receiver<([u8; 32], Vec<u8>)>> {
        self.inner.incoming.lock().await.take()
    }

    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::Relaxed)
    }

    pub async fn send_to(&self, dst: [u8; 32], payload: &[u8]) {
        let client = self.inner.current.read().await.clone();
        if let Some(client) = client
            && !client.send_to(dst, payload).await
        {
            // 写通道关闭时尽早让路径选择回退，后台任务会负责重连。
            self.inner.connected.store(false, Ordering::Relaxed);
        }
    }
}

async fn relay_reconnect_loop(weak: Weak<RelayLinkInner>) {
    let mut backoff = 1u64;
    loop {
        let Some(inner) = weak.upgrade() else {
            return;
        };

        if inner.connected.load(Ordering::Relaxed) {
            let closed = inner
                .current
                .read()
                .await
                .as_ref()
                .map(|c| c.is_closed())
                .unwrap_or(true);
            if closed {
                inner.connected.store(false, Ordering::Relaxed);
            }
        }

        if !inner.connected.load(Ordering::Relaxed) {
            match RelayClient::connect(
                &inner.addr,
                &inner.network,
                &inner.secret_hash,
                inner.pubkey,
            )
            .await
            {
                Ok(client) => {
                    let Some(mut rx) = client.take_incoming().await else {
                        drop(inner);
                        tokio::time::sleep(Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(30);
                        continue;
                    };
                    let generation = inner.generation.fetch_add(1, Ordering::Relaxed) + 1;
                    *inner.current.write().await = Some(client);
                    inner.connected.store(true, Ordering::Relaxed);
                    tracing::info!("overlay 中继已连接 {}", inner.addr);
                    backoff = 1;

                    let weak_reader = weak.clone();
                    tokio::spawn(async move {
                        while let Some(item) = rx.recv().await {
                            let Some(inner) = weak_reader.upgrade() else {
                                break;
                            };
                            if inner.generation.load(Ordering::Relaxed) != generation {
                                break;
                            }
                            if inner.incoming_tx.send(item).await.is_err() {
                                break;
                            }
                        }
                        if let Some(inner) = weak_reader.upgrade()
                            && inner.generation.load(Ordering::Relaxed) == generation
                        {
                            inner.connected.store(false, Ordering::Relaxed);
                            *inner.current.write().await = None;
                            tracing::warn!("overlay 中继连接断开，准备重连");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("overlay 中继连接失败: {e:#}，{} 秒后重试", backoff);
                }
            }
        }

        let connected = inner.connected.load(Ordering::Relaxed);
        drop(inner);
        if connected {
            // 连接正常时只做轻量存活检查，不累积退避时间。
            tokio::time::sleep(Duration::from_secs(1)).await;
        } else {
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    }
}

/// 供测试与内部使用：启动一个本地中继并返回端口。
pub async fn test_pair(network: &str, secret: &str) -> Result<(RelayClient, u16)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let hash = crate::overlay::secret_hash(secret);
    let _ = spawn_relay_server(listener, network.to_string(), hash.clone(), None).await?;
    let key = [9u8; 32];
    let client = RelayClient::connect(&format!("127.0.0.1:{port}"), network, &hash, key).await?;
    Ok((client, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let f = encode_frame(FRAME_SEND, b"hello");
        assert_eq!(f[0], FRAME_SEND);
        assert_eq!(u32::from_be_bytes([f[1], f[2], f[3], f[4]]) as usize, 5);
        assert_eq!(&f[5..], b"hello");
    }

    #[tokio::test]
    async fn relay_forwards_between_two_nodes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hash = crate::overlay::secret_hash("secret");
        spawn_relay_server(listener, "net".into(), hash.clone(), None)
            .await
            .unwrap();

        let addr = format!("127.0.0.1:{port}");
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];

        let client_a = RelayClient::connect(&addr, "net", &hash, key_a)
            .await
            .unwrap();
        let client_b = RelayClient::connect(&addr, "net", &hash, key_b)
            .await
            .unwrap();
        let mut rx_a = client_a.take_incoming().await.unwrap();
        let mut rx_b = client_b.take_incoming().await.unwrap();

        // 等两端都完成注册
        tokio::time::sleep(Duration::from_millis(200)).await;

        client_a.send_to(key_b, b"ping-from-a").await;
        let (src, data) = tokio::time::timeout(Duration::from_secs(3), rx_b.recv())
            .await
            .expect("B 没收到")
            .unwrap();
        assert_eq!(src, key_a);
        assert_eq!(data, b"ping-from-a");

        client_b.send_to(key_a, b"pong-from-b").await;
        let (src, data) = tokio::time::timeout(Duration::from_secs(3), rx_a.recv())
            .await
            .expect("A 没收到")
            .unwrap();
        assert_eq!(src, key_b);
        assert_eq!(data, b"pong-from-b");
    }

    #[tokio::test]
    async fn relay_rejects_wrong_secret() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hash = crate::overlay::secret_hash("right");
        spawn_relay_server(listener, "net".into(), hash, None)
            .await
            .unwrap();

        let addr = format!("127.0.0.1:{port}");
        let bad = crate::overlay::secret_hash("wrong");
        let r = RelayClient::connect(&addr, "net", &bad, [3u8; 32]).await;
        assert!(r.is_err(), "错误密钥不应通过认证");
    }

    #[tokio::test]
    async fn relay_rejects_unregistered_pubkey() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hash = crate::overlay::secret_hash("secret");
        let allowed = Arc::new(RwLock::new(HashSet::new()));
        spawn_relay_server(listener, "net".into(), hash.clone(), Some(allowed))
            .await
            .unwrap();

        let addr = format!("127.0.0.1:{port}");
        let r = RelayClient::connect(&addr, "net", &hash, [4u8; 32]).await;
        assert!(r.is_err(), "未登记的 pubkey 不应接入中继");
    }

    #[tokio::test]
    async fn relay_link_reconnects_after_drop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hash = crate::overlay::secret_hash("secret");
        spawn_relay_server(listener, "net".into(), hash.clone(), None)
            .await
            .unwrap();

        let link = RelayLink::new(format!("127.0.0.1:{port}"), "net".into(), hash, [7u8; 32]);
        let mut connected = false;
        for _ in 0..50 {
            if link.is_connected() {
                connected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(connected, "RelayLink 首次连接失败");

        // 模拟底层连接断开：丢掉当前 client，后台应重新建立连接。
        link.inner.connected.store(false, Ordering::Relaxed);
        *link.inner.current.write().await = None;

        let mut reconnected = false;
        for _ in 0..100 {
            if link.is_connected() {
                reconnected = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(reconnected, "RelayLink 断开后没有自动重连");
    }
}
