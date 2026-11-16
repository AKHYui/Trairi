//! Best-effort UPnP IGD port mapping for the overlay UDP socket.
//!
//! Many home routers already have UPnP enabled. Asking the user to open a port
//! by hand is not acceptable for a "start and it works" overlay, so we try to
//! create the mapping ourselves. Failure is non-fatal and simply leaves relay
//! fallback in place.

use anyhow::{Context, Result, bail};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const SSDP_ADDR: &str = "239.255.255.250:1900";
const SERVICE_TYPES: [&str; 4] = [
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:2",
];

/// Try to create a stable UDP port mapping for `socket`.
///
/// Returns the external port when the router accepted the mapping.
pub async fn try_map(socket: &UdpSocket) -> Result<u16> {
    let local_port = socket.local_addr().context("读取 overlay UDP 本地端口")?.port();
    let local_ip = local_ip().await?;
    let location = discover().await?;
    let root = http_get(&location).await?;
    let (service, control_url) = find_wan_service(&root, &location)?;

    // Prefer the same external port. If another application already owns it,
    // try a short range; the server learns the actual mapping through STUN.
    let last = local_port.saturating_add(10);
    let mut last_err = None;
    for external in local_port..=last {
        match add_mapping(
            &control_url,
            &service,
            external,
            local_port,
            local_ip,
            "UDP",
        )
        .await
        {
            Ok(()) => {
                tracing::info!(
                    "UPnP：已自动映射 UDP {external} -> {local_ip}:{local_port}（无需手动配置路由器）"
                );
                return Ok(external);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("路由器未接受 UPnP 端口映射")))
}

async fn local_ip() -> Result<IpAddr> {
    // Connecting a UDP socket does not send packets; it only asks the OS which
    // source address it would use for the default route.
    let probe = UdpSocket::bind("0.0.0.0:0").await?;
    probe.connect("8.8.8.8:80").await?;
    Ok(probe.local_addr()?.ip())
}

async fn discover() -> Result<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.set_multicast_ttl_v4(2).ok();
    let search = |st: &str| {
        format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDR}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n"
        )
    };
    for st in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "ssdp:all",
    ] {
        let _ = sock.send_to(search(st).as_bytes(), SSDP_ADDR).await;
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("UPnP 未发现 IGD 网关");
        }
        let mut buf = [0u8; 4096];
        let (n, _) = match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e).context("接收 SSDP 响应"),
            Err(_) => bail!("UPnP 未发现 IGD 网关"),
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        if let Some(loc) = header(&text, "location") {
            return Ok(loc.trim().to_string());
        }
    }
}

fn header(text: &str, name: &str) -> Option<String> {
    let prefix = format!("{name}:");
    text.lines().find_map(|line| {
        let line = line.trim();
        if line
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(&prefix))
        {
            Some(line[prefix.len()..].trim().to_string())
        } else {
            None
        }
    })
}

async fn http_get(url: &str) -> Result<String> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("连接 UPnP 描述地址 {host}:{port}"))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nUser-Agent: Trairi\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut buf))
        .await
        .context("读取 UPnP 描述超时")??;
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    if !head.lines().next().unwrap_or("").contains(" 200 ") {
        bail!("UPnP 描述请求失败: {}", head.lines().next().unwrap_or(""));
    }
    Ok(body.to_string())
}

fn find_wan_service(root: &str, location: &str) -> Result<(String, String)> {
    for service in SERVICE_TYPES {
        let tag = format!("{service}</serviceType>");
        let Some(pos) = root.find(&tag) else { continue };
        let rest = &root[pos..];
        let end = rest.find("</service>").unwrap_or(rest.len());
        let block = &rest[..end];
        let Some(control) = extract_tag(block, "controlURL") else {
            continue;
        };
        let control = resolve_url(location, control.trim())?;
        return Ok((service.to_string(), control));
    }
    bail!("UPnP 网关没有 WANIPConnection/WANPPPConnection 服务")
}

fn extract_tag<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let a = text.find(&start)? + start.len();
    let b = text[a..].find(&end)? + a;
    Some(&text[a..b])
}

fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .with_context(|| format!("UPnP 只支持 HTTP 描述: {url}"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse::<u16>()?),
        _ => (authority.to_string(), 80),
    };
    if host.is_empty() {
        bail!("UPnP 描述地址没有主机名: {url}");
    }
    Ok((host, port, path))
}

fn resolve_url(base: &str, rel: &str) -> Result<String> {
    if rel.starts_with("http://") {
        return Ok(rel.to_string());
    }
    let rest = base
        .strip_prefix("http://")
        .with_context(|| format!("UPnP 描述不是 HTTP URL: {base}"))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if rel.starts_with('/') {
        Ok(format!("http://{authority}{rel}"))
    } else {
        let dir = base.rsplit_once('/').map(|(d, _)| d).unwrap_or(base);
        Ok(format!("{dir}/{rel}"))
    }
}

async fn add_mapping(
    control_url: &str,
    service: &str,
    external_port: u16,
    internal_port: u16,
    local_ip: IpAddr,
    protocol: &str,
) -> Result<()> {
    let (host, port, path) = parse_http_url(control_url)?;
    let body = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="{service}">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{external_port}</NewExternalPort>
<NewProtocol>{protocol}</NewProtocol>
<NewInternalPort>{internal_port}</NewInternalPort>
<NewInternalClient>{local_ip}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Trairi</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"#
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service}#AddPortMapping\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("连接 UPnP 控制地址 {host}:{port}"))?;
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(4), stream.read_to_end(&mut buf))
        .await
        .context("读取 UPnP 映射响应超时")??;
    let text = String::from_utf8_lossy(&buf);
    let status = text.lines().next().unwrap_or("");
    if status.contains(" 200 ") {
        Ok(())
    } else {
        bail!("UPnP AddPortMapping 返回 {status}")
    }
}
