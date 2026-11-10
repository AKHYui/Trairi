//! 传输层：TCP / TLS / WebSocket / WSS 的拨号与监听。
//!
//! 服务端只监听一个端口，通过首字节嗅探自动识别客户端用的是
//! 裸 TCP、TLS、WS 还是 WSS，因此客户端可以自由选择协议而不需要服务端改配置。

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;

use crate::config::{ClientConfig, ServerConfig, TransportProtocol};
use crate::stream::{AsyncStream, Stream};

/// 等待客户端发来首字节的超时
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// TLS / WebSocket 握手超时
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// 安装 rustls 的 crypto provider（进程内只能成功一次，重复调用无副作用）。
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ---------------------------------------------------------------------------
// 可回放前置字节的流
// ---------------------------------------------------------------------------

/// 把先前读出来的几个字节「塞回去」，使得上层读到完整数据。
pub struct PrependStream<S> {
    inner: S,
    head: Vec<u8>,
    pos: usize,
}

impl<S> PrependStream<S> {
    pub fn new(inner: S, head: Vec<u8>) -> Self {
        Self {
            inner,
            head,
            pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrependStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.head.len() {
            let remaining = &self.head[self.pos..];
            let n = remaining.len().min(buf.remaining());
            let (start, end) = (self.pos, self.pos + n);
            buf.put_slice(&self.head[start..end]);
            self.pos = end;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrependStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 读若干字节用于嗅探（读不到就超时）。
async fn probe<S: AsyncRead + Unpin>(stream: &mut S, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let filled = tokio::time::timeout(PROBE_TIMEOUT, async {
        let mut got = 0;
        while got < n {
            let read = stream.read(&mut buf[got..]).await?;
            if read == 0 {
                break;
            }
            got += read;
        }
        Ok::<usize, std::io::Error>(got)
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "等待客户端数据超时"))??;
    buf.truncate(filled);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// TLS 配置
// ---------------------------------------------------------------------------

/// 不校验证书的握手校验器（仅在 `tls_insecure = true` 时使用）。
#[derive(Debug)]
struct InsecureVerifier(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 构造客户端 TLS 配置。
pub fn client_tls_config(cfg: &ClientConfig) -> Result<Arc<rustls::ClientConfig>> {
    ensure_crypto_provider();
    let provider = rustls::crypto::ring::default_provider();

    if cfg.tls_insecure {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier(Arc::new(provider))))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if !cfg.tls_cert_file.is_empty() {
        let mut reader = BufReader::new(
            File::open(&cfg.tls_cert_file)
                .with_context(|| format!("打开 CA 文件失败: {}", cfg.tls_cert_file))?,
        );
        let mut added = 0usize;
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.context("解析 CA 证书失败")?;
            roots.add(cert).context("加入 CA 证书失败")?;
            added += 1;
        }
        if added == 0 {
            bail!("CA 文件里没有可用的证书: {}", cfg.tls_cert_file);
        }
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// 构造服务端 TLS 配置；没有配置证书时返回 None。
pub fn server_tls_config(cfg: &ServerConfig) -> Result<Option<Arc<rustls::ServerConfig>>> {
    if cfg.tls_cert_file.is_empty() || cfg.tls_key_file.is_empty() {
        return Ok(None);
    }
    ensure_crypto_provider();

    let mut cert_reader = BufReader::new(
        File::open(&cfg.tls_cert_file)
            .with_context(|| format!("打开证书失败: {}", cfg.tls_cert_file))?,
    );
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<_, _>>()
        .context("解析服务端证书失败")?;
    if certs.is_empty() {
        bail!("证书文件为空: {}", cfg.tls_cert_file);
    }

    let mut key_reader = BufReader::new(
        File::open(&cfg.tls_key_file)
            .with_context(|| format!("打开私钥失败: {}", cfg.tls_key_file))?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .context("解析私钥失败")?
        .context("私钥文件里没有找到私钥")?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("构造 TLS 服务端配置失败")?;
    Ok(Some(Arc::new(config)))
}

async fn tls_connect<S>(stream: S, cfg: &ClientConfig) -> Result<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let tls_cfg = client_tls_config(cfg)?;
    let server_name = if cfg.tls_server_name.is_empty() {
        cfg.server_addr.clone()
    } else {
        cfg.tls_server_name.clone()
    };
    let name = ServerName::try_from(server_name.clone())
        .map_err(|_| anyhow::anyhow!("非法的 TLS server name: {server_name}"))?;
    let connector = tokio_rustls::TlsConnector::from(tls_cfg);
    connector
        .connect(name, stream)
        .await
        .with_context(|| format!("TLS 握手失败，目标 {server_name}"))
}

// ---------------------------------------------------------------------------
// 客户端拨号
// ---------------------------------------------------------------------------

/// 建立到服务端的原始连接（已完成 TLS / WS 握手，但还没有做 Trairi 握手）。
pub async fn dial(cfg: &ClientConfig) -> Result<Stream> {
    let proto = cfg.effective_protocol();
    let addr = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let timeout = Duration::from_secs(cfg.dial_timeout.max(1));

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("连接 {addr} 超时"))?
        .with_context(|| format!("连接 {addr} 失败"))?;
    let _ = tcp.set_nodelay(true);

    match proto {
        TransportProtocol::Tcp => Ok(Box::new(tcp)),
        TransportProtocol::Tls => {
            let tls = tls_connect(tcp, cfg).await?;
            Ok(Box::new(tls))
        }
        TransportProtocol::Ws => {
            let ws = ws_connect(tcp, cfg, false).await?;
            Ok(ws_to_bytestream(ws))
        }
        TransportProtocol::Wss => {
            let tls = tls_connect(tcp, cfg).await?;
            let ws = ws_connect(tls, cfg, true).await?;
            Ok(ws_to_bytestream(ws))
        }
    }
}

/// 把 WebSocket 的「消息流」适配成「字节流」。
///
/// tokio-tungstenite 只实现了 `Stream + Sink<Message>`，这里用两个后台任务
/// （加密记录层同样的做法）把它桥接成 `AsyncRead + AsyncWrite`。
fn ws_to_bytestream<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> Stream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut source) = ws.split();
    let (user, peer) = tokio::io::duplex(64 * 1024);
    let (mut peer_r, mut peer_w) = tokio::io::split(peer);

    // 收：WS 消息 -> 字节流
    tokio::spawn(async move {
        while let Some(item) = source.next().await {
            match item {
                Ok(Message::Binary(_)) | Ok(Message::Text(_)) => {
                    let data = item.unwrap().into_data();
                    if peer_w.write_all(&data).await.is_err() {
                        break;
                    }
                    if peer_w.flush().await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        let _ = peer_w.shutdown().await;
    });

    // 发：字节流 -> WS 消息
    tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match peer_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let msg = Message::Binary(
                        tokio_tungstenite::tungstenite::Bytes::copy_from_slice(&buf[..n]),
                    );
                    if sink.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sink.close().await;
    });

    Box::new(user)
}

async fn ws_connect<S>(
    stream: S,
    cfg: &ClientConfig,
    secure: bool,
) -> Result<tokio_tungstenite::WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let scheme = if secure { "wss" } else { "ws" };
    let host = format!("{}:{}", cfg.server_addr, cfg.server_port);
    let path = if cfg.ws_path.starts_with('/') {
        cfg.ws_path.clone()
    } else {
        format!("/{}", cfg.ws_path)
    };
    let url = format!("{scheme}://{host}{path}");
    let mut request = url
        .as_str()
        .into_client_request()
        .with_context(|| format!("构造 WebSocket 请求失败: {url}"))?;
    request.headers_mut().insert(
        "Host",
        HeaderValue::from_str(&host).context("构造 Host 头失败")?,
    );

    let (ws, _resp) = tokio_tungstenite::client_async(request, stream)
        .await
        .context("WebSocket 握手失败")?;
    Ok(ws)
}

// ---------------------------------------------------------------------------
// 服务端接受连接
// ---------------------------------------------------------------------------

/// 服务端接受的原始连接。
pub struct Accepted {
    pub stream: Stream,
    pub peer: std::net::SocketAddr,
    /// 实际使用的传输方式，仅用于日志
    pub transport: &'static str,
}

/// 只接受 TCP 连接，不在 accept 循环里做任何会等待客户端数据的操作。
pub async fn accept_pending(listener: &TcpListener) -> Result<(TcpStream, std::net::SocketAddr)> {
    let (sock, peer) = listener.accept().await.context("accept 失败")?;
    let _ = sock.set_nodelay(true);
    Ok((sock, peer))
}

/// 对一条已 accept 的连接做 TLS / WS 嗅探。
///
/// 这个函数必须在每连接 task 里调用；所有等待客户端数据的阶段都有超时，
/// 否则一个发 `GET ` 后挂起的连接就能卡死整个服务端的 accept 循环。
pub async fn handshake(
    sock: TcpStream,
    peer: std::net::SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    ws_path: &str,
) -> Result<Accepted> {
    let mut stream: Box<dyn AsyncStream> = Box::new(sock);
    let mut transport = "tcp";

    // 第一次嗅探：TLS 还是明文
    let head = probe(&mut stream, 4)
        .await
        .context("读取客户端首字节失败")?;
    if head.is_empty() {
        bail!("连接 {peer} 在握手前就关闭了");
    }

    if head[0] == 0x16 {
        let Some(tls_cfg) = tls else {
            bail!("客户端 {peer} 使用了 TLS，但服务端没有配置 tls_cert_file / tls_key_file");
        };
        let acceptor = TlsAcceptor::from(tls_cfg);
        let tls_stream = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            acceptor.accept(Box::new(PrependStream::new(stream, head))),
        )
        .await
        .map_err(|_| anyhow::anyhow!("TLS 握手超时"))?
        .context("TLS 握手失败")?;
        stream = Box::new(tls_stream);
        transport = "tls";
    } else {
        stream = Box::new(PrependStream::new(stream, head));
    }

    // 第二次嗅探：是不是 WebSocket
    let head2 = probe(&mut stream, 4).await.context("读取 WS 首字节失败")?;
    if head2.starts_with(b"GET ") {
        let expected = ws_path.to_string();
        let ws = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            tokio_tungstenite::accept_hdr_async(
                PrependStream::new(stream, head2),
                move |req: &Request,
                      resp: Response|
                      -> std::result::Result<Response, ErrorResponse> {
                    let path = req.uri().path();
                    if !expected.is_empty() && path != expected {
                        let mut err = ErrorResponse::new(Some("未知的 WebSocket 路径".to_string()));
                        *err.status_mut() =
                            tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
                        return Err(err);
                    }
                    Ok(resp)
                },
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("WebSocket 握手超时"))?
        .context("WebSocket 握手失败")?;
        stream = ws_to_bytestream(ws);
        transport = if transport == "tls" { "wss" } else { "ws" };
    } else {
        stream = Box::new(PrependStream::new(stream, head2));
    }

    Ok(Accepted {
        stream,
        peer,
        transport,
    })
}

/// 判断一个字节串看起来像不像 TLS ClientHello。
pub fn looks_like_tls(head: &[u8]) -> bool {
    head.first() == Some(&0x16)
}

/// 主动关闭一条流（尽量优雅）。
pub async fn shutdown<S: AsyncWrite + Unpin>(stream: &mut S) {
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prepend_stream_replays_bytes() {
        let (a, mut b) = tokio::io::duplex(1024);
        let mut upstream = PrependStream::new(a, b"HEAD".to_vec());
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 8];
            upstream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"HEADBODY");
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        b.write_all(b"BODY").await.unwrap();
        handle.await.unwrap();
    }

    #[test]
    fn tls_sniffing() {
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x00]));
        assert!(!looks_like_tls(b"GET "));
        assert!(!looks_like_tls(b""));
    }

    /// 用真实的 TLS 客户端验证 SNI 解析（https 虚拟主机的路由依据）。
    #[tokio::test]
    async fn sni_extracted_from_real_client_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut total = conn.read(&mut buf).await.unwrap();
            if total < 5 {
                return None;
            }
            let need = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
            while total < need {
                let n = conn.read(&mut buf[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
            }
            crate::util::peek_sni(&buf[..total])
        });

        let mut cfg = crate::config::ClientConfig::default();
        cfg.server_addr = "127.0.0.1".into();
        cfg.tls_insecure = true;
        let tls = client_tls_config(&cfg).unwrap();
        let connector = tokio_rustls::TlsConnector::from(tls);
        let name = ServerName::try_from("test.example".to_string()).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        // 对端不会回 ServerHello，握手必然失败，但 ClientHello 已经发出去了
        let _ = connector.connect(name, tcp).await;

        let sni = server.await.unwrap();
        assert_eq!(sni.as_deref(), Some("test.example"));
    }
}
