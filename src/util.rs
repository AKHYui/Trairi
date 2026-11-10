//! 通用工具：限速、代理协议、双向拷贝、TLS SNI / HTTP Host 解析等。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

/// 每个读取块的大小
pub const BUF_SIZE: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// 基础格式
// ---------------------------------------------------------------------------

/// 解析流量/带宽字符串，例如 `1MB`、`512KB`、`1048576`（纯数字视为字节）。
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("空的容量字符串");
    }
    let upper = s.to_uppercase();
    let (num_part, mult) = if let Some(v) = upper.strip_suffix("GB") {
        (v, 1024u64 * 1024 * 1024)
    } else if let Some(v) = upper.strip_suffix("MB") {
        (v, 1024u64 * 1024)
    } else if let Some(v) = upper.strip_suffix("KB") {
        (v, 1024u64)
    } else if let Some(v) = upper.strip_suffix('B') {
        (v, 1u64)
    } else {
        (upper.as_str(), 1u64)
    };
    let n: f64 = num_part.trim().parse()?;
    if n < 0.0 {
        bail!("容量不能为负数: {s}");
    }
    Ok((n * mult as f64) as u64)
}

/// 把字节数格式化成人类可读形式。
pub fn fmt_bytes(mut n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut i = 0;
    let mut f = n as f64;
    while f >= 1024.0 && i < units.len() - 1 {
        f /= 1024.0;
        i += 1;
        if i == 0 {
            n = 0;
        }
    }
    if i == 0 {
        format!("{n} {}", units[0])
    } else {
        format!("{f:.2} {}", units[i])
    }
}

/// 生成随机十六进制字符串（用于盐、run_id 等）。
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// 解析端口区间描述，例如 `1000-2000,3000,4000-4001`。
pub fn parse_port_ranges(spec: &str) -> Result<Vec<(u16, u16)>> {
    let mut out = Vec::new();
    for part in spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.trim().parse()?;
            let end: u16 = b.trim().parse()?;
            if start == 0 || end < start {
                bail!("非法端口区间: {part}");
            }
            out.push((start, end));
        } else {
            let p: u16 = part.parse()?;
            if p == 0 {
                bail!("非法端口: {part}");
            }
            out.push((p, p));
        }
    }
    Ok(out)
}

/// 端口是否落在允许区间内。
pub fn port_in_ranges(ranges: &[(u16, u16)], port: u16) -> bool {
    ranges.iter().any(|(a, b)| port >= *a && port <= *b)
}

/// 从区间里挑一个未被占用的端口。
pub fn pick_free_port(ranges: &[(u16, u16)], used: &[u16]) -> Option<u16> {
    for (a, b) in ranges {
        for p in *a..=*b {
            if !used.contains(&p) {
                return Some(p);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 限速（令牌桶）
// ---------------------------------------------------------------------------

/// 以字节/秒为单位的简单令牌桶限速器。
pub struct Throttle {
    rate: f64,
    state: Mutex<(f64, Instant)>,
}

impl Throttle {
    pub fn new(bytes_per_sec: u64) -> Arc<Self> {
        Arc::new(Self {
            rate: bytes_per_sec as f64,
            state: Mutex::new((bytes_per_sec as f64, Instant::now())),
        })
    }

    /// 消耗 `n` 字节的额度，不足时阻塞等待。
    pub async fn consume(&self, n: usize) {
        if self.rate <= 0.0 {
            return;
        }
        {
            let mut st = self.state.lock().await;
            let now = Instant::now();
            let elapsed = now.duration_since(st.1).as_secs_f64();
            st.0 = (st.0 + elapsed * self.rate).min(self.rate);
            st.1 = now;
            st.0 -= n as f64;
            if st.0 >= 0.0 {
                return;
            }
            let wait = Duration::from_secs_f64((-st.0 / self.rate).min(1.0));
            st.1 = now + wait;
            st.0 = 0.0;
            drop(st);
            tokio::time::sleep(wait).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Proxy Protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    None,
    V1,
    V2,
}

impl ProxyProtocolVersion {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "none" => Ok(Self::None),
            "v1" => Ok(Self::V1),
            "v2" => Ok(Self::V2),
            other => bail!("不支持的 proxy_protocol 版本: {other}（可选 v1 / v2）"),
        }
    }
}

/// 生成 PROXY protocol 头，`src` 是真实客户端，`dst` 是对外监听地址。
pub fn build_proxy_protocol(
    version: ProxyProtocolVersion,
    src: Option<SocketAddr>,
    dst: Option<SocketAddr>,
) -> Vec<u8> {
    let (Some(src), Some(dst)) = (src, dst) else {
        return Vec::new();
    };
    match version {
        ProxyProtocolVersion::None => Vec::new(),
        ProxyProtocolVersion::V1 => {
            let fam = if src.is_ipv4() { "TCP4" } else { "TCP6" };
            if src.is_ipv4() != dst.is_ipv4() {
                return b"PROXY UNKNOWN\r\n".to_vec();
            }
            format!(
                "PROXY {fam} {} {} {} {}\r\n",
                src.ip(),
                dst.ip(),
                src.port(),
                dst.port()
            )
            .into_bytes()
        }
        ProxyProtocolVersion::V2 => {
            let mut buf = Vec::with_capacity(52);
            buf.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
            buf.push(0x21); // version 2, PROXY
            match (src, dst) {
                (SocketAddr::V4(s), SocketAddr::V4(d)) => {
                    buf.push(0x11); // AF_INET + STREAM
                    buf.extend_from_slice(&16u16.to_be_bytes());
                    buf.extend_from_slice(&s.ip().octets());
                    buf.extend_from_slice(&d.ip().octets());
                    buf.extend_from_slice(&s.port().to_be_bytes());
                    buf.extend_from_slice(&d.port().to_be_bytes());
                }
                (SocketAddr::V6(s), SocketAddr::V6(d)) => {
                    buf.push(0x21); // AF_INET6 + STREAM
                    buf.extend_from_slice(&36u16.to_be_bytes());
                    buf.extend_from_slice(&s.ip().octets());
                    buf.extend_from_slice(&d.ip().octets());
                    buf.extend_from_slice(&s.port().to_be_bytes());
                    buf.extend_from_slice(&d.port().to_be_bytes());
                }
                _ => {
                    buf.push(0x00); // UNSPEC
                    buf.extend_from_slice(&0u16.to_be_bytes());
                }
            }
            buf
        }
    }
}

// ---------------------------------------------------------------------------
// 双向管道
// ---------------------------------------------------------------------------

/// 带限速的双向转发，返回 (a→b 字节数, b→a 字节数)。
pub async fn pipe_bidirectional<A, B>(
    a: A,
    b: B,
    ab_throttle: Option<Arc<Throttle>>,
    ba_throttle: Option<Arc<Throttle>>,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let up = async move {
        let n = copy_throttled(&mut ar, &mut bw, ab_throttle).await;
        let _ = bw.shutdown().await;
        n
    };
    let down = async move {
        let n = copy_throttled(&mut br, &mut aw, ba_throttle).await;
        let _ = aw.shutdown().await;
        n
    };

    let (up_n, down_n) = tokio::join!(up, down);
    (up_n, down_n)
}

async fn copy_throttled<R, W>(r: &mut R, w: &mut W, throttle: Option<Arc<Throttle>>) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        if let Some(t) = throttle.as_ref() {
            t.consume(n).await;
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        if w.flush().await.is_err() {
            break;
        }
        total += n as u64;
    }
    total
}

// ---------------------------------------------------------------------------
// TLS SNI / HTTP Host 解析
// ---------------------------------------------------------------------------

/// 从 TLS ClientHello 中提取 SNI 主机名（不完整时返回 None）。
pub fn peek_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }
    let hs = &buf[5..5 + record_len];
    parse_client_hello_sni(hs)
}

fn parse_client_hello_sni(hs: &[u8]) -> Option<String> {
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let body = hs.get(4..4 + body_len)?;
    if body.len() < 34 {
        return None;
    }
    let mut p = 34; // version(2) + random(32)
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs_len;
    let comp_len = *body.get(p)? as usize;
    p += 1 + comp_len;
    if p + 2 > body.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let end = (p + ext_len).min(body.len());
    while p + 4 <= end {
        let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
        let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + ext_len > end {
            return None;
        }
        if ext_type == 0x0000 {
            let data = &body[p..p + ext_len];
            if data.len() < 5 {
                return None;
            }
            let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
            let name = data.get(5..5 + name_len)?;
            return String::from_utf8(name.to_vec()).ok();
        }
        p += ext_len;
    }
    None
}

/// 从 HTTP 请求头中提取 Host（去掉端口、转小写）。
pub fn parse_http_host(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("host") {
                let host = v.trim();
                let host = match host.rsplit_once(':') {
                    Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
                    _ => host,
                };
                return Some(
                    host.trim_matches('[')
                        .trim_matches(']')
                        .to_ascii_lowercase(),
                );
            }
        }
    }
    None
}

/// 读满 `n` 字节，返回实际读到的长度（读到 EOF 提前返回）。
pub async fn read_full<R: AsyncRead + Unpin>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// 给出一个简单的 HTTP 响应字节流。
pub fn http_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("512KB").unwrap(), 512 * 1024);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1.5MB").unwrap(), 1572864);
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn port_ranges() {
        let r = parse_port_ranges("1000-1002,2000").unwrap();
        assert_eq!(r, vec![(1000, 1002), (2000, 2000)]);
        assert!(port_in_ranges(&r, 1001));
        assert!(!port_in_ranges(&r, 1500));
        assert_eq!(pick_free_port(&r, &[1000, 1001]), Some(1002));
    }

    #[test]
    fn host_parsing() {
        let head = b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n";
        assert_eq!(parse_http_host(head).as_deref(), Some("example.com"));
        let head = b"GET / HTTP/1.1\r\nhost: a.b.c\r\n\r\n";
        assert_eq!(parse_http_host(head).as_deref(), Some("a.b.c"));
        assert_eq!(parse_http_host(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn proxy_protocol_v1() {
        let src: SocketAddr = "1.2.3.4:5555".parse().unwrap();
        let dst: SocketAddr = "5.6.7.8:80".parse().unwrap();
        let h = build_proxy_protocol(ProxyProtocolVersion::V1, Some(src), Some(dst));
        assert_eq!(
            String::from_utf8(h).unwrap(),
            "PROXY TCP4 1.2.3.4 5.6.7.8 5555 80\r\n"
        );
    }

    #[test]
    fn proxy_protocol_v2_header() {
        let src: SocketAddr = "1.2.3.4:5555".parse().unwrap();
        let dst: SocketAddr = "5.6.7.8:80".parse().unwrap();
        let h = build_proxy_protocol(ProxyProtocolVersion::V2, Some(src), Some(dst));
        assert_eq!(&h[..12], b"\r\n\r\n\x00\r\nQUIT\n");
        assert_eq!(h[12], 0x21);
        assert_eq!(h[13], 0x11);
        assert_eq!(&h[14..16], &16u16.to_be_bytes());
        assert_eq!(h.len(), 16 + 12);
    }

    #[tokio::test]
    async fn throttle_limits_rate() {
        let t = Throttle::new(1024);
        let start = Instant::now();
        for _ in 0..3 {
            t.consume(1024).await;
        }
        assert!(start.elapsed() >= Duration::from_millis(1500));
    }
}
