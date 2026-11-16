//! Minimal NAT-PMP client (RFC 6886) for automatic UDP port mapping.
//!
//! This complements UPnP: many routers expose one, the other, or both. We only
//! need a best-effort mapping for the overlay UDP port.

use anyhow::{Context, Result, bail};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

const PORT: u16 = 5351;

/// Ask the default gateway for a UDP mapping. Returns the external port.
pub async fn try_map(local_port: u16) -> Result<u16> {
    try_map_inner(local_port, 0).await
}

/// Map TCP on the same numeric port (NAT-PMP opcode 1).
pub async fn try_map_tcp(local_port: u16) -> Result<u16> {
    try_map_inner(local_port, 1).await
}

async fn try_map_inner(local_port: u16, opcode: u8) -> Result<u16> {
    let gateway = default_gateway()?;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((gateway, PORT)).await?;

    // version 0, opcode (UDP/TCP), reserved, internal port, suggested
    // external, lifetime 3600 seconds.
    let mut req = [0u8; 12];
    req[1] = opcode;
    req[4..6].copy_from_slice(&local_port.to_be_bytes());
    req[6..8].copy_from_slice(&local_port.to_be_bytes());
    req[8..12].copy_from_slice(&3600u32.to_be_bytes());
    sock.send(&req).await?;

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .context("NAT-PMP 响应超时")??;
    if n < 12 || buf[0] != 0 || buf[1] != 128 {
        bail!("NAT-PMP 响应格式非法");
    }
    let result = u16::from_be_bytes([buf[2], buf[3]]);
    if result != 0 {
        bail!("NAT-PMP 映射被拒绝，result={result}");
    }
    let external = u16::from_be_bytes([buf[10], buf[11]]);
    if external == 0 {
        bail!("NAT-PMP 返回外部端口 0");
    }
    tracing::info!("NAT-PMP：已自动映射 UDP {external} -> 本机:{local_port}");
    Ok(external)
}

fn default_gateway() -> Result<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string("/proc/net/route").context("读取 /proc/net/route")?;
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 3 || cols[1] != "00000000" {
                continue;
            }
            let raw = u32::from_str_radix(cols[2], 16).context("解析网关地址")?;
            return Ok(Ipv4Addr::from(raw.to_le_bytes()));
        }
        bail!("没有找到 IPv4 默认网关");
    }
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("route")
            .args(["print", "0.0.0.0"])
            .output()
            .context("执行 route print")?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
                if let Ok(ip) = cols[2].parse::<Ipv4Addr>() {
                    return Ok(ip);
                }
            }
        }
        bail!("没有找到 IPv4 默认网关");
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        bail!("当前平台不支持 NAT-PMP 网关发现")
    }
}
