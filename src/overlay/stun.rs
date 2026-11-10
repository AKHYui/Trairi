//! 最小可用的 STUN 实现（RFC 5389）：用来发现自己的公网映射地址，
//! 并判断 NAT 的映射行为（是否为「端点无关映射」——打洞能否成功的关键）。
//!
//! 只实现了 Binding Request / Binding Success + XOR-MAPPED-ADDRESS，
//! 足够支撑 overlay 的 NAT 探测；不做 ICE、认证、TCP 等。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::UdpSocket;

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// NAT 端口映射行为
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingBehavior {
    /// 端点无关映射（cone 型）——打洞成功率高
    EndpointIndependent,
    /// 地址/端口相关映射（symmetric 型）——基本只能中继
    AddressDependent,
    /// 没测出来
    Unknown,
}

impl MappingBehavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            MappingBehavior::EndpointIndependent => "cone（端点无关映射，可打洞）",
            MappingBehavior::AddressDependent => "symmetric（端口相关映射，建议中继）",
            MappingBehavior::Unknown => "未知",
        }
    }
}

/// 生成一个随机事务 ID。
pub fn random_txid() -> [u8; 12] {
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut [0u8; 12]);
    let mut id = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
    id
}

/// 构造 Binding Request。
pub fn build_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // 无属性
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txid);
    buf
}

/// 是不是 STUN 报文（看 magic cookie）。
pub fn is_stun(buf: &[u8]) -> bool {
    buf.len() >= 20
        && buf[4..8] == MAGIC_COOKIE.to_be_bytes()
        && u16::from_be_bytes([buf[2], buf[3]]) as usize + 20 <= buf.len()
}

/// 解析 Binding Success，取出映射地址。
pub fn parse_binding_response(buf: &[u8]) -> Option<SocketAddr> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_SUCCESS {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let txid = &buf[8..20];
    let body = buf.get(20..20 + len)?;

    let mut p = 0;
    while p + 4 <= body.len() {
        let attr = u16::from_be_bytes([body[p], body[p + 1]]);
        let alen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let val = body.get(p + 4..p + 4 + alen)?;
        if attr == ATTR_XOR_MAPPED_ADDRESS {
            return decode_xor_addr(val, txid);
        }
        // 属性按 4 字节对齐
        p += 4 + ((alen + 3) & !3);
    }
    None
}

fn decode_xor_addr(val: &[u8], txid: &[u8]) -> Option<SocketAddr> {
    if val.len() < 4 {
        return None;
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    match family {
        0x01 => {
            if val.len() < 8 {
                return None;
            }
            let ip = Ipv4Addr::new(
                val[4] ^ cookie[0],
                val[5] ^ cookie[1],
                val[6] ^ cookie[2],
                val[7] ^ cookie[3],
            );
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            if val.len() < 20 {
                return None;
            }
            let mut raw = [0u8; 16];
            for i in 0..16 {
                raw[i] = val[4 + i] ^ if i < 4 { cookie[i] } else { txid[i - 4] };
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(raw)), port))
        }
        _ => None,
    }
}

/// 构造 Binding Success 响应（服务端用）。
pub fn build_binding_response(request: &[u8], mapped: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20 {
        return None;
    }
    let txid = &request[8..20];
    let mut attr = Vec::with_capacity(12);
    match mapped {
        SocketAddr::V4(a) => {
            attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            attr.extend_from_slice(&8u16.to_be_bytes());
            attr.push(0);
            attr.push(0x01);
            let port = mapped.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            attr.extend_from_slice(&port.to_be_bytes());
            let c = MAGIC_COOKIE.to_be_bytes();
            let oct = a.ip().octets();
            attr.extend_from_slice(&[oct[0] ^ c[0], oct[1] ^ c[1], oct[2] ^ c[2], oct[3] ^ c[3]]);
            let _ = a;
        }
        SocketAddr::V6(a) => {
            attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            attr.extend_from_slice(&20u16.to_be_bytes());
            attr.push(0);
            attr.push(0x02);
            let port = mapped.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            attr.extend_from_slice(&port.to_be_bytes());
            let c = MAGIC_COOKIE.to_be_bytes();
            let oct = a.ip().octets();
            for i in 0..16 {
                attr.push(oct[i] ^ if i < 4 { c[i] } else { txid[i - 4] });
            }
        }
    }

    let mut buf = Vec::with_capacity(20 + attr.len());
    buf.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    buf.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txid);
    buf.extend_from_slice(&attr);
    Some(buf)
}

/// 向一个 STUN 服务端发绑定请求，拿回自己的公网映射地址。
pub async fn binding(socket: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    let txid = random_txid();
    let req = build_binding_request(&txid);
    socket
        .send_to(&req, server)
        .await
        .with_context(|| format!("向 STUN {server} 发送失败"))?;

    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            bail!("STUN {server} 超时");
        }
        let (n, from) = tokio::time::timeout(left, socket.recv_from(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("STUN {server} 超时"))??;
        // 只认这个服务端回来的
        if from.ip() != server.ip() {
            continue;
        }
        if let Some(addr) = parse_binding_response(&buf[..n]) {
            return Ok(addr);
        }
    }
}

/// 用同一 socket 向两个不同服务端端口探测，判断 NAT 映射行为。
pub async fn probe_mapping(
    socket: &UdpSocket,
    server_a: SocketAddr,
    server_b: SocketAddr,
) -> Result<(SocketAddr, MappingBehavior)> {
    let mapped_a = binding(socket, server_a).await?;
    let mapped_b = match binding(socket, server_b).await {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!("第二个 STUN 端口探测失败: {e:#}");
            return Ok((mapped_a, MappingBehavior::Unknown));
        }
    };
    let behavior = if mapped_a == mapped_b {
        MappingBehavior::EndpointIndependent
    } else {
        MappingBehavior::AddressDependent
    };
    Ok((mapped_a, behavior))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape() {
        let txid = [7u8; 12];
        let req = build_binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        assert_eq!(&req[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert!(is_stun(&req));
    }

    #[test]
    fn response_roundtrip_v4() {
        let txid = [1u8; 12];
        let mut req = build_binding_request(&txid);
        req[8..20].copy_from_slice(&txid);
        let mapped: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let resp = build_binding_response(&req, mapped).unwrap();
        assert!(is_stun(&resp));
        assert_eq!(parse_binding_response(&resp), Some(mapped));
    }

    #[test]
    fn response_roundtrip_v6() {
        let txid = [2u8; 12];
        let req = build_binding_request(&txid);
        let mapped: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        let resp = build_binding_response(&req, mapped).unwrap();
        assert_eq!(parse_binding_response(&resp), Some(mapped));
    }

    #[test]
    fn garbage_is_not_stun() {
        assert!(!is_stun(b"hello"));
        assert!(!is_stun(&[0u8; 20]));
        assert_eq!(parse_binding_response(&[0u8; 20]), None);
    }

    #[tokio::test]
    async fn binding_against_local_server() {
        // 起一个本地「STUN 服务端」，验证编解码与收发闭环
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let Ok((n, src)) = server.recv_from(&mut buf).await else {
                    break;
                };
                if let Some(resp) = build_binding_response(&buf[..n], src) {
                    let _ = server.send_to(&resp, src).await;
                }
            }
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mapped = binding(&client, server_addr).await.unwrap();
        // 同一个 socket，映射地址应该就是自己
        assert_eq!(mapped, client.local_addr().unwrap());
    }
}
