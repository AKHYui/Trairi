//! 端到端集成测试：在同一个进程里起服务端 + 客户端，走真实的 TCP 链路。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use trairi::config::{
    ClientConfig, Config, Mode, ProxyConfig, ProxyKind, ServerConfig, TransportProtocol,
    VisitorConfig,
};
use trairi::protocol::{HelloRequest, HelloResponse, PROTOCOL_VERSION, read_msg, write_msg};

const TEST_TOKEN: &str = "test-token";

// ---------------------------------------------------------------------------
// 测试用本地服务
// ---------------------------------------------------------------------------

/// 起一个 TCP echo 服务，返回端口
async fn spawn_tcp_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = conn.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// 起一个 UDP echo 服务，返回端口
async fn spawn_udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    port
}

/// 起一个 HTTP 服务，回显 Host 头，返回端口
async fn spawn_http_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                let host = trairi::util::parse_http_host(buf[..n].as_ref()).unwrap_or_default();
                let body = format!("local-http host={host} path={}", first_line(&text));
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = conn.write_all(resp.as_bytes()).await;
                let _ = conn.shutdown().await;
            });
        }
    });
    port
}

fn first_line(request: &str) -> String {
    request.lines().next().unwrap_or_default().to_string()
}

// ---------------------------------------------------------------------------
// 启动服务端 / 客户端
// ---------------------------------------------------------------------------

fn free_port() -> u16 {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let used = USED.get_or_init(|| Mutex::new(HashSet::new()));

    // KCP 会在同一个端口号上监听 UDP，所以分配测试端口时要同时确认 TCP/UDP 都空闲；
    // 同时把端口记下来，避免 Linux 立刻复用刚释放的临时端口造成测试互相干扰。
    loop {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        let mut set = used.lock().unwrap();
        if set.insert(port) {
            return port;
        }
    }
}

struct Harness {
    handles: Vec<tokio::task::JoinHandle<()>>,
    pub server_port: u16,
    pub vhost_http_port: u16,
}

impl Harness {
    fn shutdown(&self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

/// 构建并启动一套 server + client。
async fn start(
    proxies: Vec<ProxyConfig>,
    token: &str,
    protocol: TransportProtocol,
    with_vhost: bool,
) -> Harness {
    // 安全默认值要求服务端必须有 token；空值测试统一用测试 token。
    let token = if token.is_empty() {
        "test-token"
    } else {
        token
    };
    let vhost_http_port = if with_vhost { free_port() } else { 0 };
    // 避免控制端口和代理对外端口复用同一个数字：Linux 会很快复用刚释放的临时端口。
    let server_port = loop {
        let p = free_port();
        let conflicts =
            p == vhost_http_port || proxies.iter().any(|proxy| proxy.remote_port == p as i64);
        if !conflicts {
            break p;
        }
    };

    let server_cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: server_port,
            kcp: true,
            vhost_http_port,
            allow_ports: "1-65535".into(),
            token: token.to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let client_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: token.to_string(),
            protocol,
            use_encryption: !token.is_empty(),
            use_compression: token == "compress-me",
            dial_timeout: 5,
            ..Default::default()
        },
        proxies,
        ..Default::default()
    };

    let h1 = tokio::spawn(async move {
        let _ = trairi::server::run(server_cfg).await;
    });
    // 等服务端开始监听
    wait_port(server_port, Duration::from_secs(5)).await;

    let h2 = tokio::spawn(async move {
        let _ = trairi::client::run(client_cfg).await;
    });

    Harness {
        handles: vec![h1, h2],
        server_port,
        vhost_http_port,
    }
}

async fn wait_port(port: u16, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("端口 {port} 在超时内没有就绪");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// 发送一个合法 Hello，返回服务端响应。
async fn send_hello(port: u16, hello: &HelloRequest) -> HelloResponse {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    write_msg(&mut conn, hello).await.unwrap();
    read_msg(&mut conn).await.unwrap()
}

/// 轮询直到某个端口可以连上
async fn wait_proxy(port: u16) {
    wait_port(port, Duration::from_secs(10)).await;
    // 再等一小会儿让注册完全生效
    tokio::time::sleep(Duration::from_millis(200)).await;
}

fn tcp_proxy(name: &str, local_port: u16, remote_port: u16) -> ProxyConfig {
    ProxyConfig {
        name: name.into(),
        kind: ProxyKind::Tcp,
        local_addr: format!("127.0.0.1:{local_port}"),
        remote_port: remote_port as i64,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_proxy_plain() {
    let echo = spawn_tcp_echo().await;
    let remote = free_port();
    let h = start(
        vec![tcp_proxy("echo", echo, remote)],
        "",
        TransportProtocol::Tcp,
        false,
    )
    .await;
    wait_proxy(remote).await;

    let mut conn = TcpStream::connect(("127.0.0.1", remote)).await.unwrap();
    conn.write_all(b"hello trairi").await.unwrap();
    let mut buf = [0u8; 12];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello trairi");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_proxy_over_kcp() {
    let echo = spawn_tcp_echo().await;
    let remote = free_port();
    let h = start(
        vec![tcp_proxy("kcp-echo", echo, remote)],
        TEST_TOKEN,
        TransportProtocol::Kcp,
        false,
    )
    .await;
    wait_proxy(remote).await;

    let mut conn = TcpStream::connect(("127.0.0.1", remote)).await.unwrap();
    conn.write_all(b"hello over kcp").await.unwrap();
    let mut buf = [0u8; 14];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello over kcp");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_proxy_with_encryption() {
    let echo = spawn_tcp_echo().await;
    let remote = free_port();
    let h = start(
        vec![tcp_proxy("secure-echo", echo, remote)],
        "s3cret-token",
        TransportProtocol::Tcp,
        false,
    )
    .await;
    wait_proxy(remote).await;

    let mut conn = TcpStream::connect(("127.0.0.1", remote)).await.unwrap();
    let payload = b"encrypted payload".repeat(100);
    conn.write_all(&payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_proxy_with_ws_transport() {
    let echo = spawn_tcp_echo().await;
    let remote = free_port();
    let h = start(
        vec![tcp_proxy("ws-echo", echo, remote)],
        "",
        TransportProtocol::Ws,
        false,
    )
    .await;
    wait_proxy(remote).await;

    let mut conn = TcpStream::connect(("127.0.0.1", remote)).await.unwrap();
    conn.write_all(b"over websocket").await.unwrap();
    let mut buf = [0u8; 14];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"over websocket");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_vhost_routing() {
    let web = spawn_http_echo().await;
    let h = start(
        vec![ProxyConfig {
            name: "site".into(),
            kind: ProxyKind::Http,
            local_addr: format!("127.0.0.1:{web}"),
            custom_domains: vec!["a.test".into()],
            ..Default::default()
        }],
        "",
        TransportProtocol::Tcp,
        true,
    )
    .await;

    // 等代理注册
    tokio::time::sleep(Duration::from_millis(800)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", h.vhost_http_port))
        .await
        .unwrap();
    conn.write_all(b"GET /x HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    conn.read_to_string(&mut resp).await.unwrap();
    assert!(resp.contains("200 OK"), "响应: {resp}");
    assert!(resp.contains("host=a.test"), "响应: {resp}");
    assert!(resp.contains("GET /x"), "响应: {resp}");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_unknown_host_gets_404() {
    let web = spawn_http_echo().await;
    let h = start(
        vec![ProxyConfig {
            name: "site".into(),
            kind: ProxyKind::Http,
            local_addr: format!("127.0.0.1:{web}"),
            custom_domains: vec!["a.test".into()],
            ..Default::default()
        }],
        "",
        TransportProtocol::Tcp,
        true,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", h.vhost_http_port))
        .await
        .unwrap();
    conn.write_all(b"GET / HTTP/1.1\r\nHost: nope.test\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    conn.read_to_string(&mut resp).await.unwrap();
    assert!(resp.contains("404"), "响应: {resp}");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_proxy() {
    let echo = spawn_udp_echo().await;
    let remote = free_port();
    let h = start(
        vec![ProxyConfig {
            name: "udp-echo".into(),
            kind: ProxyKind::Udp,
            local_addr: format!("127.0.0.1:{echo}"),
            remote_port: remote as i64,
            ..Default::default()
        }],
        "",
        TransportProtocol::Tcp,
        false,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(900)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"udp datagram", ("127.0.0.1", remote))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
        .await
        .expect("UDP 回包超时")
        .unwrap();
    assert_eq!(&buf[..n], b"udp datagram");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_plugin() {
    let echo = spawn_tcp_echo().await;
    let remote = free_port();
    let h = start(
        vec![ProxyConfig {
            name: "socks".into(),
            kind: ProxyKind::Socks5,
            remote_port: remote as i64,
            ..Default::default()
        }],
        "",
        TransportProtocol::Tcp,
        false,
    )
    .await;
    wait_proxy(remote).await;

    let mut conn = TcpStream::connect(("127.0.0.1", remote)).await.unwrap();
    // 问候：无认证
    conn.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    conn.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // CONNECT 127.0.0.1:echo
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&echo.to_be_bytes());
    conn.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    conn.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "SOCKS5 连接失败: {rep:?}");

    conn.write_all(b"through socks5").await.unwrap();
    let mut buf = [0u8; 14];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"through socks5");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_proxy_direct() {
    let echo = spawn_tcp_echo().await;
    let server_port = free_port();
    let p2p_port = free_port();
    let visitor_port = free_port();
    let token = "p2p-token";

    let server_cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: server_port,
            p2p_port,
            token: token.into(),
            allow_ports: "1-65535".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let owner_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: token.into(),
            ..Default::default()
        },
        proxies: vec![ProxyConfig {
            name: "p2p-echo".into(),
            kind: ProxyKind::P2p,
            local_addr: format!("127.0.0.1:{echo}"),
            sk: "p2p-sk".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let visitor_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: token.into(),
            ..Default::default()
        },
        visitors: vec![VisitorConfig {
            name: "p2p-visitor".into(),
            kind: ProxyKind::P2p,
            server_name: "p2p-echo".into(),
            sk: "p2p-sk".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port,
            p2p_fallback: false,
        }],
        ..Default::default()
    };

    let hs = tokio::spawn(async move {
        let _ = trairi::server::run(server_cfg).await;
    });
    wait_port(server_port, Duration::from_secs(5)).await;
    let ho = tokio::spawn(async move {
        let _ = trairi::client::run(owner_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let hv = tokio::spawn(async move {
        let _ = trairi::client::run(visitor_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(800)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", visitor_port))
        .await
        .unwrap();
    conn.write_all(b"p2p hello").await.unwrap();
    let mut buf = [0u8; 9];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"p2p hello");

    // 同一个 P2P KCP/smux 会话上复用多条本地连接。
    for i in 0..3 {
        let mut c = TcpStream::connect(("127.0.0.1", visitor_port))
            .await
            .unwrap();
        let msg = format!("p2p-{i}");
        c.write_all(msg.as_bytes()).await.unwrap();
        let mut b = vec![0u8; msg.len()];
        c.read_exact(&mut b).await.unwrap();
        assert_eq!(b, msg.as_bytes());
    }

    hs.abort();
    ho.abort();
    hv.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_fallback_relay() {
    let echo = spawn_tcp_echo().await;
    let server_port = free_port();
    let visitor_port = free_port();
    let token = "p2p-token";

    let server_cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: server_port,
            p2p_port: 0,
            token: token.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let owner_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: token.into(),
            ..Default::default()
        },
        proxies: vec![ProxyConfig {
            name: "p2p-relay-echo".into(),
            kind: ProxyKind::P2p,
            local_addr: format!("127.0.0.1:{echo}"),
            sk: "p2p-sk".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let visitor_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: token.into(),
            ..Default::default()
        },
        visitors: vec![VisitorConfig {
            name: "p2p-relay-visitor".into(),
            kind: ProxyKind::P2p,
            server_name: "p2p-relay-echo".into(),
            sk: "p2p-sk".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port,
            p2p_fallback: true,
        }],
        ..Default::default()
    };

    let hs = tokio::spawn(async move {
        let _ = trairi::server::run(server_cfg).await;
    });
    wait_port(server_port, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let ho = tokio::spawn(async move {
        let _ = trairi::client::run(owner_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let hv = tokio::spawn(async move {
        let _ = trairi::client::run(visitor_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", visitor_port))
        .await
        .unwrap();
    conn.write_all(b"relay").await.unwrap();
    let mut buf = [0u8; 5];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"relay");

    hs.abort();
    ho.abort();
    hv.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_token_is_rejected() {
    let echo = spawn_tcp_echo().await;
    let remote = free_port();
    let server_port = free_port();

    let server_cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: server_port,
            token: "server-token".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let client_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: "wrong-token".into(),
            use_encryption: true,
            ..Default::default()
        },
        proxies: vec![tcp_proxy("x", echo, remote)],
        ..Default::default()
    };

    let h1 = tokio::spawn(async move {
        let _ = trairi::server::run(server_cfg).await;
    });
    wait_port(server_port, Duration::from_secs(5)).await;
    let h2 = tokio::spawn(async move {
        let _ = trairi::client::run(client_cfg).await;
    });

    // 等一段时间，代理不应该被注册成功
    tokio::time::sleep(Duration::from_secs(2)).await;
    let registered = TcpStream::connect(("127.0.0.1", remote)).await.is_ok();
    assert!(!registered, "错误 token 竟然注册成功了");

    h1.abort();
    h2.abort();
}

// ---------------------------------------------------------------------------
// 追加测试：stcp 访问者 / PROXY protocol / 面板 API / 分组负载均衡
// ---------------------------------------------------------------------------

/// 起一个「先读一段、再原样回显」的服务，返回端口
async fn spawn_read_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                if n > 0 {
                    let _ = conn.write_all(&buf[..n]).await;
                }
                let _ = conn.shutdown().await;
            });
        }
    });
    port
}

/// 起一个带标识的 echo 服务，返回 (端口, 标识)
async fn spawn_id_echo(id: &'static str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                let n = conn.read(&mut buf).await.unwrap_or(0);
                if n > 0 {
                    let reply = format!("{id}:{}", String::from_utf8_lossy(&buf[..n]));
                    let _ = conn.write_all(reply.as_bytes()).await;
                }
                let _ = conn.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stcp_with_visitor() {
    let echo = spawn_tcp_echo().await;
    let server_port = free_port();
    let visitor_port = free_port();

    let server_cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: server_port,
            token: TEST_TOKEN.into(),
            allow_ports: "1-65535".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    // 持有 stcp 代理的一端
    let owner_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: TEST_TOKEN.into(),
            run_id: "owner".into(),
            ..Default::default()
        },
        proxies: vec![ProxyConfig {
            name: "secret-echo".into(),
            kind: ProxyKind::Stcp,
            local_addr: format!("127.0.0.1:{echo}"),
            sk: "shared-secret".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    // 访问者
    let visitor_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: TEST_TOKEN.into(),
            run_id: "visitor".into(),
            ..Default::default()
        },
        visitors: vec![trairi::config::VisitorConfig {
            name: "v1".into(),
            kind: ProxyKind::Stcp,
            server_name: "secret-echo".into(),
            sk: "shared-secret".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port,
            p2p_fallback: true,
        }],
        ..Default::default()
    };

    let h0 = tokio::spawn(async move {
        let _ = trairi::server::run(server_cfg).await;
    });
    wait_port(server_port, Duration::from_secs(5)).await;

    let h1 = tokio::spawn(async move {
        let _ = trairi::client::run(owner_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let h2 = tokio::spawn(async move {
        let _ = trairi::client::run(visitor_cfg).await;
    });
    wait_port(visitor_port, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", visitor_port))
        .await
        .unwrap();
    conn.write_all(b"via stcp").await.unwrap();
    let mut buf = [0u8; 8];
    conn.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"via stcp");

    h0.abort();
    h1.abort();
    h2.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stcp_wrong_sk_is_rejected() {
    let echo = spawn_tcp_echo().await;
    let server_port = free_port();
    let visitor_port = free_port();

    let server_cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: server_port,
            token: TEST_TOKEN.into(),
            allow_ports: "1-65535".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let owner_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: TEST_TOKEN.into(),
            run_id: "owner2".into(),
            ..Default::default()
        },
        proxies: vec![ProxyConfig {
            name: "secret-echo2".into(),
            kind: ProxyKind::Stcp,
            local_addr: format!("127.0.0.1:{echo}"),
            sk: "right-secret".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let visitor_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: TEST_TOKEN.into(),
            run_id: "visitor2".into(),
            ..Default::default()
        },
        visitors: vec![trairi::config::VisitorConfig {
            name: "v2".into(),
            kind: ProxyKind::Stcp,
            server_name: "secret-echo2".into(),
            sk: "wrong-secret".into(),
            bind_addr: "127.0.0.1".into(),
            bind_port: visitor_port,
            p2p_fallback: true,
        }],
        ..Default::default()
    };

    let h0 = tokio::spawn(async move {
        let _ = trairi::server::run(server_cfg).await;
    });
    wait_port(server_port, Duration::from_secs(5)).await;
    let h1 = tokio::spawn(async move {
        let _ = trairi::client::run(owner_cfg).await;
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    let h2 = tokio::spawn(async move {
        let _ = trairi::client::run(visitor_cfg).await;
    });
    wait_port(visitor_port, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", visitor_port))
        .await
        .unwrap();
    conn.write_all(b"should not arrive").await.unwrap();
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf)).await;
    // 应该是超时或读到 0（连接被关闭），不应该是回显
    match r {
        Ok(Ok(n)) => assert_eq!(n, 0, "错误的 sk 竟然拿到了回显: {:?}", &buf[..n]),
        Ok(Err(_)) => {}
        Err(_) => {}
    }

    h0.abort();
    h1.abort();
    h2.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_protocol_v1_forwarded() {
    let backend = spawn_read_echo().await;
    let remote = free_port();
    let h = start(
        vec![ProxyConfig {
            name: "pp".into(),
            kind: ProxyKind::Tcp,
            local_addr: format!("127.0.0.1:{backend}"),
            remote_port: remote as i64,
            proxy_protocol_version: "v1".into(),
            ..Default::default()
        }],
        "",
        TransportProtocol::Tcp,
        false,
    )
    .await;
    wait_proxy(remote).await;

    let mut conn = TcpStream::connect(("127.0.0.1", remote)).await.unwrap();
    conn.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf))
        .await
        .expect("后端没有回数据")
        .unwrap();
    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(text.starts_with("PROXY TCP4 "), "后端收到: {text}");

    h.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_handshake_does_not_block_and_replay_is_rejected() {
    let port = free_port();
    let cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: port,
            token: TEST_TOKEN.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let h = tokio::spawn(async move {
        let _ = trairi::server::run(cfg).await;
    });
    wait_port(port, Duration::from_secs(5)).await;

    // 一个只发 "GET " 就挂起的连接，不应阻塞后面的合法握手。
    let mut slow = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    slow.write_all(b"GET ").await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let salt = "0123456789abcdef";
    let client = "trairi/test test";
    let hello = HelloRequest {
        version: PROTOCOL_VERSION,
        salt: salt.into(),
        timestamp: ts,
        signature: trairi::crypto::sign(
            TEST_TOKEN,
            salt,
            ts,
            PROTOCOL_VERSION,
            true,
            false,
            client,
        ),
        use_encryption: true,
        use_compression: false,
        client: client.into(),
    };

    let resp = tokio::time::timeout(Duration::from_secs(2), send_hello(port, &hello))
        .await
        .expect("慢连接阻塞了新连接");
    assert!(resp.ok, "合法握手被拒: {}", resp.error);

    // 完全相同的 Hello 第二次必须被 replay cache 拒绝。
    let replay = tokio::time::timeout(Duration::from_secs(2), send_hello(port, &hello))
        .await
        .expect("重放请求超时");
    assert!(!replay.ok, "重放竟然被接受");

    h.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_overview_api() {
    let dash_port = free_port();
    let server_port = free_port();
    let echo = spawn_tcp_echo().await;
    let remote = free_port();

    let server_cfg = Config {
        mode: Some(Mode::Server),
        server: ServerConfig {
            bind_addr: "127.0.0.1".into(),
            bind_port: server_port,
            token: TEST_TOKEN.into(),
            allow_ports: "1-65535".into(),
            ..Default::default()
        },
        dashboard: trairi::config::DashboardConfig {
            bind_addr: "127.0.0.1".into(),
            port: dash_port,
            user: "admin".into(),
            password: "test-password".into(),
        },
        ..Default::default()
    };
    let client_cfg = Config {
        mode: Some(Mode::Client),
        client: ClientConfig {
            server_addr: "127.0.0.1".into(),
            server_port,
            token: TEST_TOKEN.into(),
            user: "alice".into(),
            ..Default::default()
        },
        proxies: vec![tcp_proxy("dash-echo", echo, remote)],
        ..Default::default()
    };

    let h0 = tokio::spawn(async move {
        let _ = trairi::server::run(server_cfg).await;
    });
    wait_port(server_port, Duration::from_secs(5)).await;
    let h1 = tokio::spawn(async move {
        let _ = trairi::client::run(client_cfg).await;
    });
    wait_proxy(remote).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut conn = TcpStream::connect(("127.0.0.1", dash_port)).await.unwrap();
    conn.write_all(
        b"GET /api/overview HTTP/1.1\r\nHost: x\r\nAuthorization: Basic YWRtaW46dGVzdC1wYXNzd29yZA==\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut resp = String::new();
    conn.read_to_string(&mut resp).await.unwrap();
    assert!(resp.contains("200 OK"), "响应: {resp}");
    assert!(resp.contains("\"proxies\""), "响应: {resp}");
    assert!(resp.contains("dash-echo"), "响应: {resp}");
    assert!(
        resp.contains("\"user\":\"alice\""),
        "用户字段未出现在面板: {resp}"
    );

    h0.abort();
    h1.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_load_balancing() {
    let a = spawn_id_echo("A").await;
    let b = spawn_id_echo("B").await;
    let remote = free_port();

    let mk = |name: &str, port: u16| ProxyConfig {
        name: name.into(),
        kind: ProxyKind::Tcp,
        local_addr: format!("127.0.0.1:{port}"),
        remote_port: remote as i64,
        group: "web".into(),
        group_key: "gk".into(),
        ..Default::default()
    };

    let h = start(
        vec![mk("web-1", a), mk("web-2", b)],
        "",
        TransportProtocol::Tcp,
        false,
    )
    .await;
    wait_proxy(remote).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let mut seen = Vec::new();
    for _ in 0..4 {
        let mut conn = TcpStream::connect(("127.0.0.1", remote)).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf))
            .await
            .expect("没有回包")
            .unwrap();
        seen.push(
            String::from_utf8_lossy(&buf[..n])
                .chars()
                .next()
                .unwrap_or('?'),
        );
    }
    assert!(seen.contains(&'A'), "没有打到 A: {seen:?}");
    assert!(seen.contains(&'B'), "没有打到 B: {seen:?}");

    h.shutdown();
}
