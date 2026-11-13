//! 服务端 P2P 会合：记录客户端 UDP 探针的公网 endpoint，供控制面交换。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::p2p::parse_probe;

const ENDPOINT_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy)]
pub struct PeerEndpoint {
    pub public: SocketAddr,
    pub local: Option<SocketAddr>,
}

pub struct P2pRendezvous {
    endpoints: RwLock<HashMap<String, (PeerEndpoint, Instant)>>,
    token: String,
}

impl P2pRendezvous {
    pub async fn start(bind_addr: &str, port: u16, token: String) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(format!("{bind_addr}:{port}"))
            .await
            .with_context(|| format!("P2P 会合 UDP 监听 {bind_addr}:{port} 失败"))?;
        let this = Arc::new(Self {
            endpoints: RwLock::new(HashMap::new()),
            token,
        });
        let me = this.clone();
        tokio::spawn(async move {
            me.run(socket).await;
        });
        Ok(this)
    }

    pub async fn endpoint(&self, run_id: &str) -> Option<PeerEndpoint> {
        self.endpoints
            .read()
            .await
            .get(run_id)
            .map(|(addr, _)| *addr)
    }

    async fn run(&self, socket: UdpSocket) {
        let mut buf = [0u8; 2048];
        loop {
            let (n, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("P2P 会合接收失败: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let now = now_secs();
            let Some((run_id, local)) = parse_probe(&self.token, &buf[..n], now) else {
                continue;
            };
            {
                let mut map = self.endpoints.write().await;
                map.retain(|_, (_, t)| t.elapsed() < ENDPOINT_TTL);
                map.insert(
                    run_id,
                    (PeerEndpoint { public: src, local }, Instant::now()),
                );
            }
            tracing::debug!("P2P 会合: {src}");
        }
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
