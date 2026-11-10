//! 异地组网（overlay）：WireGuard 数据面 + 中心化协调。
//!
//! 分层：
//! ```text
//!  TUN 虚拟网卡（wintun / /dev/net/tun）
//!        │ 原始 IP 包
//!        ▼
//!  WgPeer（boringtun 的 WireGuard 状态机）
//!        │ WireGuard 数据报
//!        ▼
//!  UDP socket  ──►  对端 endpoint
//! ```

pub mod acl;
pub mod device;
pub mod host;
pub mod hosts;
pub mod node;
pub mod relay;
pub mod stun;
pub mod tunplat;
pub mod wg;

use std::net::Ipv4Addr;

use anyhow::{Result, bail};
use base64::Engine;
use sha2::{Digest, Sha256};

/// 由网络名+密钥派生一个稳定的标识（用于服务端比对）。
pub fn secret_hash(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"trairi-overlay-v1:");
    h.update(secret.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// WireGuard 公钥编码成 base64。
pub fn key_to_b64(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// base64 解码 WireGuard 公钥。
pub fn key_from_b64(s: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow::anyhow!("公钥 base64 解码失败: {e}"))?;
    if raw.len() != 32 {
        bail!("公钥长度必须是 32 字节，实际 {}", raw.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// 取 IPv4 包的目的地址。
pub fn ipv4_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

/// 取 IPv4 包的源地址。
pub fn ipv4_src(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
}

/// 前缀长度转点分掩码。
pub fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    Ipv4Addr::from(bits)
}

/// 服务端分配地址时跳过网络地址 / 广播地址 / 已占用地址。
pub fn usable_hosts(pool: &ipnet::Ipv4Net) -> impl Iterator<Item = Ipv4Addr> + '_ {
    let prefix = pool.prefix_len();
    pool.hosts().filter(move |h| {
        // /31、/32 没有网络/广播地址的概念
        if prefix >= 31 {
            return true;
        }
        *h != pool.network() && *h != pool.broadcast()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hash_is_stable() {
        let a = secret_hash("abc");
        assert_eq!(a, secret_hash("abc"));
        assert_ne!(a, secret_hash("abd"));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn key_roundtrip() {
        let key = [7u8; 32];
        let b64 = key_to_b64(&key);
        assert_eq!(key_from_b64(&b64).unwrap(), key);
        assert!(key_from_b64("not-base64!!").is_err());
    }

    #[test]
    fn packet_addresses() {
        // 最小 IPv4 头：version/ihl=0x45，源 1.2.3.4，目的 5.6.7.8
        let mut pkt = vec![0u8; 20];
        pkt[0] = 0x45;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        assert_eq!(ipv4_src(&pkt), Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(ipv4_dst(&pkt), Some(Ipv4Addr::new(5, 6, 7, 8)));

        // IPv6 / 太短的包
        let mut v6 = pkt.clone();
        v6[0] = 0x60;
        assert_eq!(ipv4_dst(&v6), None);
        assert_eq!(ipv4_dst(&[0u8; 10]), None);
    }

    #[test]
    fn prefix_masks() {
        assert_eq!(prefix_to_mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_mask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_mask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_mask(0), Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn usable_hosts_skips_network_and_broadcast() {
        let pool: ipnet::Ipv4Net = "10.144.144.0/24".parse().unwrap();
        let hosts: Vec<_> = usable_hosts(&pool).collect();
        assert_eq!(hosts.first(), Some(&Ipv4Addr::new(10, 144, 144, 1)));
        assert_eq!(hosts.last(), Some(&Ipv4Addr::new(10, 144, 144, 254)));
        assert!(!hosts.contains(&Ipv4Addr::new(10, 144, 144, 0)));
        assert!(!hosts.contains(&Ipv4Addr::new(10, 144, 144, 255)));
    }
}
