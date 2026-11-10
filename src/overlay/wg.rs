//! WireGuard 单 peer 封装（基于 boringtun）。
//!
//! 注意 boringtun 的约定：拿到 `WriteToNetwork` 之后要用**空包**继续调用，
//! 直到返回 `Done`，否则排队的数据包（握手期间缓存的）不会被发出去。
//! 这里统一封装成 `WgAction`，调用方只需按结果发包/写 TUN。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// 一条可用的出站路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// 直连：UDP 直接发到对端 endpoint。
    Direct,
    /// 中继：把 WireGuard 密文交给服务端 TCP 中继转发。
    Relay,
}

impl Path {
    pub fn as_str(self) -> &'static str {
        match self {
            Path::Direct => "直连",
            Path::Relay => "中继",
        }
    }
}

/// 一条报文应该发往哪些路径。
///
/// 未锁定时 `direct` 和 `relay` 同时为真（双路径发送），
/// 锁定后只会有一条路径为真。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendPaths {
    pub direct: bool,
    pub relay: bool,
}

impl SendPaths {
    pub fn is_empty(self) -> bool {
        !self.direct && !self.relay
    }
}

/// 单次操作的产出
#[derive(Default)]
pub struct WgAction {
    /// 需要发到对端的字节（可能有多条：握手包 + 排队的业务包）
    pub to_net: Vec<Vec<u8>>,
    /// 需要写进 TUN 的 IP 包
    pub to_tun: Vec<Vec<u8>>,
    /// 这次调用是否真的解开了一条对端报文（重放/非法包为 false）。
    /// 只有认证通过的报文才能作为「这条路径通」的证据。
    pub authenticated: bool,
}

impl WgAction {
    fn push_net(&mut self, buf: &mut [u8], len: usize) {
        self.to_net.push(buf[..len].to_vec());
    }
}

/// 取 WireGuard 报文类型：1=握手发起，2=握手响应，3=cookie，4=数据。
///
/// 头部是 `[type:1][reserved:3][sender_index:4]`，reserved 必须为 0。
pub fn wg_message_type(datagram: &[u8]) -> Option<u8> {
    if datagram.len() < 8 || datagram[1..4] != [0, 0, 0] {
        return None;
    }
    match datagram[0] {
        t @ 1..=4 => Some(t),
        _ => None,
    }
}

/// 直连锁定后的回退条件：发过业务数据，但这么久没收到对端的认证回包，
/// 才退回双路径让中继接管。不能只看“多久没收到包”——空闲对端本来就不发包，
/// 误回退会让双路径的重复保活把对端也带到中继上。
const DIRECT_LOCK_IDLE: Duration = Duration::from_secs(15);

/// 一个 WireGuard 对端。
pub struct WgPeer {
    pub ip: Ipv4Addr,
    pub pubkey: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    tunn: Tunn,
    pub established: bool,
    /// 路径归属：None 表示还没判定，所有报文双路径发送。
    owner: Option<Path>,
    /// 最近一次从各路径收到通过认证的报文。
    direct_rx_at: Option<Instant>,
    relay_rx_at: Option<Instant>,
    /// 最近一次真正发出业务数据（非保活/握手）的时间。
    data_tx_at: Option<Instant>,
    created: std::time::Instant,
}

impl WgPeer {
    pub fn new(
        private: &StaticSecret,
        peer_public: [u8; 32],
        ip: Ipv4Addr,
        index: u32,
        preshared: Option<[u8; 32]>,
    ) -> Self {
        let tunn = Tunn::new(
            private.clone(),
            PublicKey::from(peer_public),
            preshared,
            Some(25), // 25 秒 persistent keepalive，用来穿透 NAT
            index,
            None,
        );
        Self {
            ip,
            pubkey: peer_public,
            endpoint: None,
            tunn,
            established: false,
            owner: None,
            direct_rx_at: None,
            relay_rx_at: None,
            data_tx_at: None,
            created: Instant::now(),
        }
    }

    /// 把 IP 包封装成 WireGuard 报文（必要时先发起握手）。
    pub fn encapsulate(&mut self, packet: &[u8]) -> WgAction {
        if !packet.is_empty() {
            self.data_tx_at = Some(Instant::now());
        }
        let mut action = WgAction::default();
        let mut out = vec![0u8; packet.len() + 256];

        if let TunnResult::WriteToNetwork(b) = self.tunn.encapsulate(packet, &mut out) {
            let len = b.len();
            action.push_net(&mut out, len);
        }

        // 继续冲刷排队的包
        self.flush(&mut action);
        action
    }

    /// 驱动握手重传与 keepalive 定时器。
    ///
    /// 必须用 boringtun 的 `update_timers`，不能用 `encapsulate(&[])`：
    /// 后者只要会话存在就会立刻吐一个 keepalive，250ms 一次的 tick 会变成
    /// 每秒 4 个保活包（走中继时尤其浪费）。
    pub fn tick(&mut self) -> WgAction {
        let mut action = WgAction::default();
        let mut out = vec![0u8; 256];
        match self.tunn.update_timers(&mut out) {
            TunnResult::WriteToNetwork(b) => {
                let len = b.len();
                action.push_net(&mut out, len);
            }
            TunnResult::Err(e) => {
                tracing::debug!("WireGuard 定时器/会话过期: {e:?}");
                self.established = false;
            }
            _ => {}
        }
        self.flush(&mut action);
        action
    }

    /// 解封装一条收到的 WireGuard 报文。
    pub fn decapsulate(&mut self, src: Option<IpAddr>, datagram: &[u8]) -> WgAction {
        let mut action = WgAction::default();
        let mut out = vec![0u8; datagram.len().max(1500) + 512];
        self.handle_datagram(src, datagram, &mut out, &mut action);
        self.flush(&mut action);
        if action.authenticated {
            // 能解开握手响应 / 数据包，说明会话真的在向前推进；
            // 不再只看 to_tun 是否非空（否则中继握手成功后会一直打洞）。
            self.established = true;
        }
        action
    }

    fn handle_datagram(
        &mut self,
        src: Option<IpAddr>,
        datagram: &[u8],
        out: &mut [u8],
        action: &mut WgAction,
    ) {
        match self.tunn.decapsulate(src, datagram, out) {
            TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                action.authenticated = true;
                // 空的 IP 包是 keepalive，不能写进 TUN
                if !b.is_empty() {
                    action.to_tun.push(b.to_vec());
                }
            }
            TunnResult::WriteToNetwork(b) => {
                action.authenticated = true;
                let len = b.len();
                action.push_net(out, len);
            }
            TunnResult::Err(e) => tracing::debug!("WireGuard 解封装失败: {e:?}"),
            TunnResult::Done => {}
        }
    }

    /// 用空包反复调用，把排队的数据包吐出来。
    fn flush(&mut self, action: &mut WgAction) {
        for _ in 0..16 {
            let mut out = vec![0u8; 65536];
            match self.tunn.decapsulate(None, &[], &mut out) {
                TunnResult::WriteToNetwork(b) => {
                    let len = b.len();
                    action.push_net(&mut out, len);
                }
                TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                    if !b.is_empty() {
                        action.to_tun.push(b.to_vec());
                    }
                }
                _ => break,
            }
        }
    }

    /// 选出这条报文要发往的路径。
    ///
    /// - 还没判定归属：直连（若有 endpoint）+ 中继（若有）同时发；
    /// - 已锁定直连/中继：只发归属路径。
    ///
    /// 双路径发送是关键：`rx_bytes > 0` 只能证明**入向**有包，
    /// 不能证明我们的出向包能到对端（端口限制型 NAT 的单向通路）。
    /// 在判定清楚之前两条路都发，谁先带回对端的认证报文，就锁定谁。
    pub fn send_paths(&mut self, relay_available: bool) -> SendPaths {
        self.expire_direct_lock();
        match self.owner {
            Some(Path::Direct) if self.endpoint.is_some() => SendPaths {
                direct: true,
                relay: false,
            },
            Some(Path::Direct) => SendPaths {
                direct: false,
                relay: relay_available,
            },
            Some(Path::Relay) if relay_available => SendPaths {
                direct: false,
                relay: true,
            },
            // 中继断了：退回直连（如果还有 endpoint），不要在死路上卡住。
            Some(Path::Relay) => SendPaths {
                direct: self.endpoint.is_some(),
                relay: false,
            },
            None => SendPaths {
                direct: self.endpoint.is_some(),
                relay: relay_available,
            },
        }
    }

    /// 记录从某条路径收到了对端报文。
    ///
    /// 判定规则围绕「出向是否真的能到对端」：
    /// - **中继**：TCP 长连接是双向的，而且服务端按公钥鉴权转发。
    ///   只要从对端收到任意 WG 报文（包括重放包），就说明这条端到端路径可用，
    ///   立即锁定中继；中继优先级高于直连（对端既然走中继，回包也必须走中继）。
    /// - **直连**：收到数据包只能证明入向通；只有收到 **握手响应(2)** 或
    ///   **cookie 回复(3)** 才能证明我们发出的握手真的到了对端（出向也通）。
    ///   所以直连只在类型 2/3 且尚未锁定时才锁定。
    pub fn note_inbound(&mut self, path: Path, msg_type: Option<u8>) {
        let now = Instant::now();
        match path {
            Path::Relay => {
                self.relay_rx_at = Some(now);
                if msg_type.is_some() {
                    self.set_owner(Path::Relay, "中继收到对端报文");
                }
            }
            Path::Direct => {
                self.direct_rx_at = Some(now);
                if self.owner.is_none() && matches!(msg_type, Some(2) | Some(3)) {
                    self.set_owner(Path::Direct, "直连收到对端握手响应");
                }
            }
        }
    }

    fn set_owner(&mut self, path: Path, why: &str) {
        if self.owner != Some(path) {
            tracing::info!("overlay 路径归属 {} -> {}（{why}）", self.ip, path.as_str());
            self.owner = Some(path);
        }
    }

    /// 直连锁定后发过业务数据却长时间收不到对端认证回包：退回双路径，让中继接管。
    fn expire_direct_lock(&mut self) {
        if self.owner != Some(Path::Direct) {
            return;
        }
        let (Some(rx), Some(tx)) = (self.direct_rx_at, self.data_tx_at) else {
            return;
        };
        // 只有“发出数据之后再也没有收到过直连回包”才说明直连可能已经断了。
        // 空闲对端不发业务数据，不能因为长时间没包就切中继。
        if tx > rx && tx.elapsed() > DIRECT_LOCK_IDLE {
            self.owner = None;
            tracing::info!(
                "overlay 路径归属 {}: 直连 {} 秒没有回包（期间发过业务数据），恢复双路径发送",
                self.ip,
                DIRECT_LOCK_IDLE.as_secs()
            );
        }
    }

    /// 当前是否锁定了中继。
    pub fn is_relay_locked(&self) -> bool {
        self.owner == Some(Path::Relay)
    }

    /// 当前归属路径（调试/测试用）。
    pub fn owner(&self) -> Option<Path> {
        self.owner
    }

    /// 某条路径最近一次收到认证报文的时间（调试用）。
    pub fn last_rx(&self, path: Path) -> Option<Instant> {
        match path {
            Path::Direct => self.direct_rx_at,
            Path::Relay => self.relay_rx_at,
        }
    }

    /// 从对端收到的总字节数（boringtun 统计）。
    pub fn rx_bytes(&self) -> usize {
        self.tunn.stats().2
    }

    /// 强制这个对端走中继（显式配置或对端只能经中继到达时调用）。
    pub fn force_relay(&mut self) {
        self.relay_rx_at = Some(Instant::now());
        self.set_owner(Path::Relay, "强制走中继");
    }

    /// 是否该开始向对端打洞探测（握手 2 秒还没建立）
    pub fn punch_due(&self) -> bool {
        self.endpoint.is_some()
            && !self.established
            && self.created.elapsed() > std::time::Duration::from_secs(2)
    }

    pub fn is_expired(&self) -> bool {
        self.tunn.is_expired()
    }

    /// (RTT, 发送字节, 接收字节)
    pub fn stats(&self) -> (Option<std::time::Duration>, usize, usize) {
        let (rtt, tx, rx, _, _) = self.tunn.stats();
        (rtt, tx, rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(endpoint: Option<SocketAddr>) -> WgPeer {
        let private = StaticSecret::random_from_rng(rand::thread_rng());
        let remote = StaticSecret::random_from_rng(rand::thread_rng());
        let pubkey = PublicKey::from(&remote).to_bytes();
        let mut p = WgPeer::new(&private, pubkey, Ipv4Addr::new(10, 144, 144, 2), 1, None);
        p.endpoint = endpoint;
        p
    }

    fn ep(port: u16) -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    #[test]
    fn wg_message_type_parses_header() {
        let mut init = [0u8; 148];
        init[0] = 1;
        assert_eq!(wg_message_type(&init), Some(1));

        let mut data = [0u8; 32];
        data[0] = 4;
        assert_eq!(wg_message_type(&data), Some(4));

        // reserved 必须为 0
        data[1] = 1;
        assert_eq!(wg_message_type(&data), None);
        assert_eq!(wg_message_type(&[1, 0, 0, 0]), None);
        assert_eq!(wg_message_type(&[]), None);
    }

    #[test]
    fn unowned_peer_sends_both_paths() {
        let mut p = test_peer(ep(5000));
        assert_eq!(p.owner(), None);
        let paths = p.send_paths(true);
        assert!(paths.direct && paths.relay);
    }

    #[test]
    fn no_endpoint_means_relay_only() {
        let mut p = test_peer(None);
        let paths = p.send_paths(true);
        assert!(!paths.direct && paths.relay);
        // 没有中继可用时没有任何出路
        assert!(p.send_paths(false).is_empty());
    }

    #[test]
    fn direct_data_is_not_proof_of_outbound() {
        // 收到对端直连数据只能证明入向通；旧实现正是把 rx_bytes>0 当成了
        // 直连可用的证据，导致“入向通、出向不通”时永远不走中继。
        let mut p = test_peer(ep(5000));
        p.note_inbound(Path::Direct, Some(4));
        assert_eq!(p.owner(), None);
        let paths = p.send_paths(true);
        assert!(paths.direct && paths.relay, "未证明出向时应继续双路径发送");
    }

    #[test]
    fn direct_handshake_response_locks_direct() {
        let mut p = test_peer(ep(5000));
        p.note_inbound(Path::Direct, Some(2));
        assert_eq!(p.owner(), Some(Path::Direct));
        let paths = p.send_paths(true);
        assert!(paths.direct && !paths.relay);
    }

    #[test]
    fn relay_packet_locks_relay_and_overrides_direct() {
        let mut p = test_peer(ep(5000));
        p.note_inbound(Path::Direct, Some(2));
        assert_eq!(p.owner(), Some(Path::Direct));

        // 对端改走中继 -> 我们的回包必须跟着走中继
        p.note_inbound(Path::Relay, Some(1));
        assert_eq!(p.owner(), Some(Path::Relay));
        let paths = p.send_paths(true);
        assert!(!paths.direct && paths.relay);
        assert!(p.is_relay_locked());
    }

    #[test]
    fn relay_message_without_wg_header_does_not_lock() {
        let mut p = test_peer(ep(5000));
        p.note_inbound(Path::Relay, None);
        assert_eq!(p.owner(), None);
    }

    #[test]
    fn force_relay_is_sticky() {
        let mut p = test_peer(ep(5000));
        p.force_relay();
        assert!(p.is_relay_locked());
        assert!(!p.send_paths(true).direct);
    }
}
