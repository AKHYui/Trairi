//! P2P 会合与认证的轻量线协议。
//!
//! 这里只放不依赖 TCP/控制流的小工具：UDP 会合探针、打洞包、
//! 以及 owner/visitor 之间的 HMAC 计算。真正的数据面在
//! `client::p2p`，服务端会合在 `server::p2p`。

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const PROBE_MAGIC: &[u8; 8] = b"TRIRP2P1";
pub const PUNCH_MAGIC: &[u8; 8] = b"TRIRPCH1";
const PROBE_DOMAIN: &[u8] = b"trairi-p2p-probe-v1\0";
const AUTH_DOMAIN: &[u8] = b"trairi-p2p-auth-v1\0";
const MAX_RUN_ID: usize = 128;
const MAX_SKEW_SECS: i64 = 300;

fn hmac_hex(key: &[u8], parts: &[&[u8]]) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac 接受任意长度密钥");
    for part in parts {
        mac.update(part);
    }
    let out = mac.finalize().into_bytes();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// 生成服务端会合探针。
pub fn probe_packet(token: &str, run_id: &str, timestamp: i64) -> Vec<u8> {
    let mac = hmac_hex(
        token.as_bytes(),
        &[PROBE_DOMAIN, run_id.as_bytes(), &timestamp.to_be_bytes()],
    );
    let mut out = Vec::with_capacity(8 + 8 + 2 + run_id.len() + 64);
    out.extend_from_slice(PROBE_MAGIC);
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&(run_id.len() as u16).to_be_bytes());
    out.extend_from_slice(run_id.as_bytes());
    out.extend_from_slice(mac.as_bytes());
    out
}

/// 校验会合探针，返回 run_id。
pub fn parse_probe(token: &str, data: &[u8], now: i64) -> Option<String> {
    if data.len() < 8 + 8 + 2 + 64 || &data[..8] != PROBE_MAGIC {
        return None;
    }
    let mut off = 8;
    let ts = i64::from_be_bytes(data[off..off + 8].try_into().ok()?);
    off += 8;
    let len = u16::from_be_bytes(data[off..off + 2].try_into().ok()?) as usize;
    off += 2;
    if len == 0 || len > MAX_RUN_ID || data.len() != off + len + 64 {
        return None;
    }
    if (now - ts).abs() > MAX_SKEW_SECS {
        return None;
    }
    let run_id = std::str::from_utf8(&data[off..off + len]).ok()?;
    off += len;
    let got = &data[off..off + 64];
    let expect = hmac_hex(
        token.as_bytes(),
        &[PROBE_DOMAIN, run_id.as_bytes(), &ts.to_be_bytes()],
    );
    if expect.as_bytes().ct_eq(got).unwrap_u8() != 1 {
        return None;
    }
    Some(run_id.to_string())
}

/// 打洞包故意短于 KCP 头（24 字节），避免被 KCP listener 当成会话。
pub fn punch_packet() -> &'static [u8] {
    PUNCH_MAGIC
}

pub fn is_punch(data: &[u8]) -> bool {
    data == PUNCH_MAGIC
}

/// owner/visitor 的认证 HMAC。
pub fn auth_mac(sk: &str, proxy_name: &str, conv: u32, nonce: &str, timestamp: i64) -> String {
    hmac_hex(
        sk.as_bytes(),
        &[
            AUTH_DOMAIN,
            proxy_name.as_bytes(),
            &conv.to_be_bytes(),
            nonce.as_bytes(),
            &timestamp.to_be_bytes(),
        ],
    )
}

pub fn verify_auth_mac(
    sk: &str,
    proxy_name: &str,
    conv: u32,
    nonce: &str,
    timestamp: i64,
    got: &str,
    now: i64,
) -> bool {
    if (now - timestamp).abs() > MAX_SKEW_SECS {
        return false;
    }
    let expect = auth_mac(sk, proxy_name, conv, nonce, timestamp);
    expect.as_bytes().ct_eq(got.as_bytes()).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_roundtrip_and_tamper() {
        let pkt = probe_packet("token", "run-1", 1000);
        assert_eq!(parse_probe("token", &pkt, 1000).as_deref(), Some("run-1"));
        assert!(parse_probe("wrong", &pkt, 1000).is_none());
        assert!(parse_probe("token", &pkt, 2000).is_none());
        let mut bad = pkt;
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(parse_probe("token", &bad, 1000).is_none());
    }

    #[test]
    fn auth_mac_roundtrip() {
        let mac = auth_mac("sk", "proxy", 42, "nonce", 1000);
        assert!(verify_auth_mac(
            "sk", "proxy", 42, "nonce", 1000, &mac, 1000
        ));
        assert!(!verify_auth_mac(
            "sk", "proxy", 43, "nonce", 1000, &mac, 1000
        ));
        assert!(!verify_auth_mac(
            "sk", "proxy", 42, "nonce", 1000, &mac, 2000
        ));
    }
}
