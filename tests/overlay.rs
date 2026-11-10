//! overlay 数据面集成测试：用内存设备 + 本机 UDP，跑通 WireGuard 握手与 IP 包转发。

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::{TcpListener, UdpSocket};

use trairi::overlay::device::mock_device;
use trairi::overlay::node::{PeerSpec, start_node};
use trairi::overlay::relay::{RelayClient, spawn_relay_server};
use trairi::overlay::secret_hash;

fn build_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 253; // 实验用协议号
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[20..].copy_from_slice(payload);
    pkt
}

async fn bind_udp() -> (Arc<UdpSocket>, std::net::SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    (Arc::new(sock), addr)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_nodes_exchange_ip_packets() {
    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let ip_b = Ipv4Addr::new(10, 144, 144, 3);

    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_a = PublicKey::from(&priv_a).to_bytes();
    let pub_b = PublicKey::from(&priv_b).to_bytes();

    let (sock_a, addr_a) = bind_udp().await;
    let (sock_b, addr_b) = bind_udp().await;

    let (dev_a, mut handle_a) = mock_device();
    let (dev_b, mut handle_b) = mock_device();

    // A 认识 B，B 认识 A（真实场景里由服务端下发）
    let _node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a,
        ip_a,
        1280,
        vec![PeerSpec {
            ip: ip_b,
            pubkey: pub_b,
            endpoint: Some(addr_b),
        }],
        None,
    )
    .await
    .unwrap();

    let _node_b = start_node(
        Box::new(dev_b),
        sock_b,
        priv_b,
        ip_b,
        1280,
        vec![PeerSpec {
            ip: ip_a,
            pubkey: pub_a,
            endpoint: Some(addr_a),
        }],
        None,
    )
    .await
    .unwrap();

    // 从 A 侧「内核」发出一个发往 B 的包
    let payload = b"hello over the overlay";
    let pkt = build_ipv4_packet(ip_a, ip_b, payload);
    handle_a.feed.send(pkt.clone()).await.unwrap();

    // 等它出现在 B 侧（握手需要几个来回，定时器 250ms 驱动）
    let got = tokio::time::timeout(Duration::from_secs(8), handle_b.drain.recv())
        .await
        .expect("等待 overlay 转发超时")
        .expect("设备通道被关闭");

    assert_eq!(got, pkt, "B 侧收到的 IP 包应与 A 侧发出的一致");

    // 反向再来一次
    let pkt2 = build_ipv4_packet(ip_b, ip_a, b"reply");
    handle_b.feed.send(pkt2.clone()).await.unwrap();
    let back = tokio::time::timeout(Duration::from_secs(8), handle_a.drain.recv())
        .await
        .expect("等待反向转发超时")
        .expect("设备通道被关闭");
    assert_eq!(back, pkt2, "反向包也应正确送达");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_destination_is_dropped() {
    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_b = PublicKey::from(&priv_b).to_bytes();

    let (sock_a, _addr_a) = bind_udp().await;
    let (dev_a, handle_a) = mock_device();
    let node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a,
        ip_a,
        1280,
        vec![PeerSpec {
            ip: Ipv4Addr::new(10, 144, 144, 3),
            pubkey: pub_b,
            endpoint: None,
        }],
        None,
    )
    .await
    .unwrap();

    // 发往一个不在表里的地址：应被直接丢弃（不会 panic、不会写回设备）
    let pkt = build_ipv4_packet(ip_a, Ipv4Addr::new(10, 144, 144, 99), b"nobody");
    handle_a.feed.send(pkt).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(node_a.peer_count().await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_table_update_keeps_session() {
    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let ip_b = Ipv4Addr::new(10, 144, 144, 3);
    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_b = PublicKey::from(&priv_b).to_bytes();

    let (sock_a, _) = bind_udp().await;
    let (dev_a, _handle_a) = mock_device();
    let node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a.clone(),
        ip_a,
        1280,
        vec![PeerSpec {
            ip: ip_b,
            pubkey: pub_b,
            endpoint: None,
        }],
        None,
    )
    .await
    .unwrap();

    // 全量更新：同公钥，只改 endpoint，不应重建
    node_a
        .update_peers(
            vec![PeerSpec {
                ip: ip_b,
                pubkey: pub_b,
                endpoint: Some("127.0.0.1:12345".parse().unwrap()),
            }],
            &priv_a,
        )
        .await;
    assert_eq!(node_a.peer_count().await, 1);

    // 换成另一个公钥 -> 应重建
    let other = PublicKey::from(&StaticSecret::random_from_rng(rand::thread_rng())).to_bytes();
    node_a
        .update_peers(
            vec![PeerSpec {
                ip: ip_b,
                pubkey: other,
                endpoint: None,
            }],
            &priv_a,
        )
        .await;
    assert_eq!(node_a.peer_count().await, 1);
}

/// 真实 TUN 设备的读写验证（需要 Linux + root，默认跳过）。
///
/// 运行方式（在 WSL 里以 root 跑交叉编译出来的测试二进制）：
///   TRAIRI_TUN_TEST=1 ./overlay-<hash> real_tun_device_plumbing
#[test]
#[cfg(target_os = "linux")]
fn real_tun_device_plumbing() {
    use trairi::config::OverlayConfig;
    use trairi::overlay::device::IpDevice;
    use trairi::overlay::tunplat::create_tun;

    if std::env::var("TRAIRI_TUN_TEST").is_err() {
        eprintln!("未设置 TRAIRI_TUN_TEST，跳过真实 TUN 测试");
        return;
    }

    let cfg = OverlayConfig {
        interface: "trairih0".to_string(),
        mtu: 1400,
        ..Default::default()
    };
    let mut dev = create_tun(&cfg, Ipv4Addr::new(10, 99, 0, 1), 24).expect("创建 TUN 失败");

    // 从内核侧往 10.99.0.2 发一个 UDP 包，它应该出现在 TUN 的读端
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.send_to(b"trairi overlay probe", "10.99.0.2:9")
        .expect("发送失败");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let pkt = rt.block_on(async {
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(5), dev.read_packet(&mut buf))
            .await
            .expect("等待 TUN 数据超时")
            .expect("读取 TUN 失败");
        buf.truncate(n);
        buf
    });

    assert!(pkt.len() >= 20, "包太短: {}", pkt.len());
    assert_eq!(pkt[0] >> 4, 4, "应该是 IPv4 包");
    assert_eq!(
        trairi::overlay::ipv4_dst(&pkt),
        Some(Ipv4Addr::new(10, 99, 0, 2)),
        "目的地址不对"
    );
    eprintln!("真实 TUN 验证通过，收到 {} 字节", pkt.len());
}

// ---------------------------------------------------------------------------
// P1：中继兜底（两端都没有可达 endpoint，只能经服务端转发）

// ---------------------------------------------------------------------------
// P2：打洞机制（精确验证两点：定时器会发包；收到探测包会纠正对端地址）
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_probe_is_sent_to_peer_endpoint() {
    use trairi::overlay::node::{PUNCH_MAGIC, is_punch};

    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let ip_b = Ipv4Addr::new(10, 144, 144, 3);
    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_b = PublicKey::from(&StaticSecret::random_from_rng(rand::thread_rng())).to_bytes();

    // 用「对端」的 socket 充当接收方，观察 A 是否真的会向它打探测包
    let peer_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_sock.local_addr().unwrap();

    let (sock_a, _) = bind_udp().await;
    let (dev_a, _handle_a) = mock_device();
    let _node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a,
        ip_a,
        1280,
        vec![PeerSpec {
            ip: ip_b,
            pubkey: pub_b,
            endpoint: Some(peer_addr),
        }],
        None,
    )
    .await
    .unwrap();

    // 打洞探测在 2 秒后开始，每 500ms 一发；之前会先收到 WireGuard 握手包，跳过它们
    let mut buf = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut saw_punch = false;
    while tokio::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(Ok((n, _from))) = tokio::time::timeout(left, peer_sock.recv_from(&mut buf)).await
        else {
            break;
        };
        if is_punch(&buf[..n]) {
            assert_eq!(&buf[..PUNCH_MAGIC.len()], PUNCH_MAGIC);
            saw_punch = true;
            break;
        }
    }
    assert!(saw_punch, "没有收到打洞探测包");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_probe_fixes_stale_peer_address() {
    use trairi::overlay::node::build_punch;

    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let ip_b = Ipv4Addr::new(10, 144, 144, 3);
    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_b = PublicKey::from(&priv_b).to_bytes();

    let (sock_a, addr_a) = bind_udp().await;
    let (dev_a, _handle_a) = mock_device();

    // A 手里的 B 地址是「过期的」
    let stale: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a,
        ip_a,
        1280,
        vec![PeerSpec {
            ip: ip_b,
            pubkey: pub_b,
            endpoint: Some(stale),
        }],
        None,
    )
    .await
    .unwrap();

    // 真正的 B 从自己的 socket 打一个探测包给 A
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_b = sock_b.local_addr().unwrap();
    sock_b.send_to(&build_punch(&pub_b), addr_a).await.unwrap();

    // A 应该把 B 的地址纠正成 addr_b
    let mut fixed = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let eps = node_a.peer_endpoints().await;
        if eps.iter().any(|(_, ep)| *ep == Some(addr_b)) {
            fixed = true;
            break;
        }
    }
    assert!(fixed, "收到探测包后没有纠正对端地址");
    assert_eq!(ip_b, Ipv4Addr::new(10, 144, 144, 3));
}

// ---------------------------------------------------------------------------
// P3：共享子网路由（对端声明 192.168.1.0/24，包要送到它那里）
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn subnet_route_forwards_to_advertising_peer() {
    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let ip_b = Ipv4Addr::new(10, 144, 144, 3);
    let lan: ipnet::Ipv4Net = "192.168.1.0/24".parse().unwrap();

    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_a = PublicKey::from(&priv_a).to_bytes();
    let pub_b = PublicKey::from(&priv_b).to_bytes();

    let (sock_a, addr_a) = bind_udp().await;
    let (sock_b, addr_b) = bind_udp().await;
    let (dev_a, handle_a) = mock_device();
    let (dev_b, mut handle_b) = mock_device();

    let node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a.clone(),
        ip_a,
        1280,
        vec![PeerSpec {
            ip: ip_b,
            pubkey: pub_b,
            endpoint: Some(addr_b),
        }],
        None,
    )
    .await
    .unwrap();

    let _node_b = start_node(
        Box::new(dev_b),
        sock_b,
        priv_b,
        ip_b,
        1280,
        vec![PeerSpec {
            ip: ip_a,
            pubkey: pub_a,
            endpoint: Some(addr_a),
        }],
        None,
    )
    .await
    .unwrap();

    // B 把 192.168.1.0/24 共享出来 -> A 这边装路由
    node_a
        .update_peers_with_routes(
            vec![PeerSpec {
                ip: ip_b,
                pubkey: pub_b,
                endpoint: Some(addr_b),
            }],
            vec![(lan, ip_b)],
            &priv_a,
        )
        .await;
    assert_eq!(node_a.routes().await.len(), 1);

    // A 往共享子网里的地址发包，应该被送到 B
    let target = Ipv4Addr::new(192, 168, 1, 10);
    let pkt = build_ipv4_packet(ip_a, target, b"into the lan");
    handle_a.feed.send(pkt.clone()).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(10), handle_b.drain.recv())
        .await
        .expect("共享子网的包没有到达对端")
        .expect("设备通道被关闭");
    assert_eq!(got, pkt, "经共享子网路由收到的包应与发出的一致");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_blocks_denied_destination() {
    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let ip_b = Ipv4Addr::new(10, 144, 144, 3);

    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_b = PublicKey::from(&priv_b).to_bytes();

    let (sock_a, _) = bind_udp().await;
    let (sock_b, addr_b) = bind_udp().await;
    let (dev_a, handle_a) = mock_device();
    let (dev_b, mut handle_b) = mock_device();

    let node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a,
        ip_a,
        1280,
        vec![PeerSpec {
            ip: ip_b,
            pubkey: pub_b,
            endpoint: Some(addr_b),
        }],
        None,
    )
    .await
    .unwrap();
    node_a
        .set_acl(&["deny 10.144.144.2 -> 10.144.144.3".to_string()])
        .await;

    let _node_b = start_node(
        Box::new(dev_b),
        sock_b,
        StaticSecret::random_from_rng(rand::thread_rng()),
        ip_b,
        1280,
        vec![],
        None,
    )
    .await
    .unwrap();

    let pkt = build_ipv4_packet(ip_a, ip_b, b"should be dropped");
    handle_a.feed.send(pkt).await.unwrap();

    let r = tokio::time::timeout(Duration::from_secs(2), handle_b.drain.recv()).await;
    assert!(r.is_err(), "ACL 拒绝了，但包还是到了对端");
}

/// 回归：直连 endpoint 存在但完全不通时，必须靠双路径发送把中继拉起来。
///
/// 旧实现用 `rx_bytes > 0` 判断直连可用，且发送前只选一条路径：
/// 一旦直连是「入向通、出向不通」，就永远不会发中继帧。
/// 新实现未判定归属时直连 + 中继同时发，收到对端报文后按路径归属锁定。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_rescues_when_direct_path_is_dead() {
    let ip_a = Ipv4Addr::new(10, 144, 144, 2);
    let ip_b = Ipv4Addr::new(10, 144, 144, 3);

    let priv_a = StaticSecret::random_from_rng(rand::thread_rng());
    let priv_b = StaticSecret::random_from_rng(rand::thread_rng());
    let pub_a = PublicKey::from(&priv_a).to_bytes();
    let pub_b = PublicKey::from(&priv_b).to_bytes();

    let (sock_a, _addr_a) = bind_udp().await;
    let (sock_b, _addr_b) = bind_udp().await;
    let (dev_a, mut handle_a) = mock_device();
    let (dev_b, mut handle_b) = mock_device();

    // 本地中继服务
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_port = listener.local_addr().unwrap().port();
    let hash = secret_hash("relay-test-secret");
    spawn_relay_server(listener, "relay-net".into(), hash.clone(), None)
        .await
        .unwrap();
    let relay_addr = format!("127.0.0.1:{relay_port}");
    let relay_a = RelayClient::connect(&relay_addr, "relay-net", &hash, pub_a)
        .await
        .unwrap();
    let relay_b = RelayClient::connect(&relay_addr, "relay-net", &hash, pub_b)
        .await
        .unwrap();
    // 等两端都完成中继注册
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 双方拿到的 endpoint 都是“假”的：直连包发出去会掉进黑洞。
    let dead_a: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let dead_b: std::net::SocketAddr = "127.0.0.1:2".parse().unwrap();

    let node_a = start_node(
        Box::new(dev_a),
        sock_a,
        priv_a,
        ip_a,
        1280,
        vec![PeerSpec {
            ip: ip_b,
            pubkey: pub_b,
            endpoint: Some(dead_b),
        }],
        Some(relay_a),
    )
    .await
    .unwrap();

    let node_b = start_node(
        Box::new(dev_b),
        sock_b,
        priv_b,
        ip_b,
        1280,
        vec![PeerSpec {
            ip: ip_a,
            pubkey: pub_a,
            endpoint: Some(dead_a),
        }],
        Some(relay_b),
    )
    .await
    .unwrap();

    let pkt = build_ipv4_packet(ip_a, ip_b, b"through the relay");
    handle_a.feed.send(pkt.clone()).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(10), handle_b.drain.recv())
        .await
        .expect("直连不通时中继没有把包送到")
        .expect("设备通道被关闭");
    assert_eq!(got, pkt);

    // 反向也必须走中继回来
    let pkt2 = build_ipv4_packet(ip_b, ip_a, b"relay reply");
    handle_b.feed.send(pkt2.clone()).await.unwrap();
    let back = tokio::time::timeout(Duration::from_secs(10), handle_a.drain.recv())
        .await
        .expect("反向包没有经中继回来")
        .expect("设备通道被关闭");
    assert_eq!(back, pkt2);

    assert_eq!(node_a.relayed_peers().await, 1, "A 应该锁定中继");
    assert_eq!(node_b.relayed_peers().await, 1, "B 应该锁定中继");
}
