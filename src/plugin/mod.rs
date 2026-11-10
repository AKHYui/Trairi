//! 内置本地服务插件：socks5 / http_proxy / static_file。
//!
//! 客户端启动代理时，如果是插件类型，就在本机 127.0.0.1 上起一个服务，
//! 然后把这个地址当作 `local_addr` 使用——这样对服务端完全透明。

use std::io::Read;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// 插件实例：监听地址 + 后台任务句柄
pub struct PluginService {
    pub addr: SocketAddr,
    pub handle: tokio::task::JoinHandle<()>,
}

impl PluginService {
    pub fn local_addr(&self) -> String {
        self.addr.to_string()
    }
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

/// 启动一个 SOCKS5 服务（无认证，支持 CONNECT）。
pub async fn start_socks5() -> Result<PluginService> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("启动内置 socks5 失败")?;
    let addr = listener.local_addr()?;
    tracing::info!("内置 SOCKS5 已监听 {addr}");

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((conn, peer)) => {
                    tokio::spawn(async move {
                        if let Err(e) = socks5_conn(conn).await {
                            tracing::debug!("socks5 连接 {peer} 结束: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("socks5 accept 失败: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(PluginService { addr, handle })
}

async fn socks5_conn(mut conn: TcpStream) -> Result<()> {
    // 1. 问候
    let mut head = [0u8; 2];
    conn.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        bail!("不是 SOCKS5 请求");
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    conn.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        conn.write_all(&[0x05, 0xff]).await?;
        bail!("客户端不支持无认证方式");
    }
    conn.write_all(&[0x05, 0x00]).await?;

    // 2. 请求
    let mut req = [0u8; 4];
    conn.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("SOCKS5 版本错误");
    }
    if req[1] != 0x01 {
        // 只支持 CONNECT
        conn.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        bail!("不支持的 SOCKS5 命令: {}", req[1]);
    }
    let target = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            conn.read_exact(&mut b).await?;
            let ip = std::net::Ipv4Addr::from(b);
            let mut p = [0u8; 2];
            conn.read_exact(&mut p).await?;
            format!("{ip}:{}", u16::from_be_bytes(p))
        }
        0x03 => {
            let mut l = [0u8; 1];
            conn.read_exact(&mut l).await?;
            let mut host = vec![0u8; l[0] as usize];
            conn.read_exact(&mut host).await?;
            let mut p = [0u8; 2];
            conn.read_exact(&mut p).await?;
            format!(
                "{}:{}",
                String::from_utf8_lossy(&host),
                u16::from_be_bytes(p)
            )
        }
        0x04 => {
            let mut b = [0u8; 16];
            conn.read_exact(&mut b).await?;
            let ip = std::net::Ipv6Addr::from(b);
            let mut p = [0u8; 2];
            conn.read_exact(&mut p).await?;
            format!("[{ip}]:{}", u16::from_be_bytes(p))
        }
        other => {
            conn.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("不支持的地址类型: {other}");
        }
    };

    // 3. 连接
    let remote = match TcpStream::connect(&target).await {
        Ok(r) => r,
        Err(e) => {
            conn.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("连接 {target} 失败: {e}");
        }
    };
    let _ = remote.set_nodelay(true);
    conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    crate::util::pipe_bidirectional(conn, remote, None, None).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP CONNECT 代理
// ---------------------------------------------------------------------------

/// 启动一个只支持 CONNECT 的 HTTP 代理。
pub async fn start_http_proxy() -> Result<PluginService> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("启动内置 http_proxy 失败")?;
    let addr = listener.local_addr()?;
    tracing::info!("内置 HTTP 代理已监听 {addr}");

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((conn, peer)) => {
                    tokio::spawn(async move {
                        if let Err(e) = http_proxy_conn(conn).await {
                            tracing::debug!("http_proxy 连接 {peer} 结束: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("http_proxy accept 失败: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(PluginService { addr, handle })
}

async fn http_proxy_conn(mut conn: TcpStream) -> Result<()> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            bail!("请求头过大");
        }
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }

    let text = String::from_utf8_lossy(&head);
    let first = text.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    if !method.eq_ignore_ascii_case("CONNECT") {
        let body = "Trairi 内置 HTTP 代理只支持 CONNECT（HTTPS 隧道）\n";
        let resp = format!(
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        conn.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let remote = match TcpStream::connect(target).await {
        Ok(r) => r,
        Err(e) => {
            let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            conn.write_all(resp.as_bytes()).await?;
            bail!("连接 {target} 失败: {e}");
        }
    };
    let _ = remote.set_nodelay(true);

    // 头部里可能已经带了隧道内的数据（极少），一并转发
    let rest_len = head.len() - text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(head.len());
    let rest = if rest_len > 0 && rest_len <= head.len() {
        head[head.len() - rest_len..].to_vec()
    } else {
        Vec::new()
    };

    conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let mut remote = remote;
    if !rest.is_empty() {
        remote.write_all(&rest).await?;
    }
    crate::util::pipe_bidirectional(conn, remote, None, None).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// 静态文件服务
// ---------------------------------------------------------------------------

/// 启动一个静态文件服务。
pub async fn start_static_file(root: PathBuf, user: String, pwd: String) -> Result<PluginService> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("启动内置 static_file 失败")?;
    let addr = listener.local_addr()?;
    if !root.exists() {
        bail!("静态目录不存在: {}", root.display());
    }
    let root = std::fs::canonicalize(&root)?;
    tracing::info!("内置静态文件服务已监听 {addr}，根目录 {}", root.display());

    let root = Arc::new(root);
    let auth = if user.is_empty() && pwd.is_empty() {
        None
    } else {
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pwd}"))
        ))
    };

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((conn, peer)) => {
                    let root = root.clone();
                    let auth = auth.clone();
                    tokio::spawn(async move {
                        if let Err(e) = static_conn(conn, root, auth).await {
                            tracing::debug!("static_file 连接 {peer} 结束: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("static_file accept 失败: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(PluginService { addr, handle })
}

async fn static_conn(mut conn: TcpStream, root: Arc<PathBuf>, auth: Option<String>) -> Result<()> {
    let mut head = Vec::with_capacity(2048);
    let mut buf = [0u8; 2048];
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > 32 * 1024 {
            bail!("请求头过大");
        }
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.lines();
    let first = lines.next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_uppercase();
    let raw_path = parts.next().unwrap_or("/");

    if method != "GET" && method != "HEAD" {
        respond(
            &mut conn,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        )
        .await?;
        return Ok(());
    }

    if let Some(expected) = auth {
        let got = lines.find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("authorization") {
                Some(v.trim().to_string())
            } else {
                None
            }
        });
        if got.as_deref() != Some(expected.as_str()) {
            let body = b"unauthorized";
            let resp = format!(
                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"trairi\"\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            conn.write_all(resp.as_bytes()).await?;
            conn.write_all(body).await?;
            return Ok(());
        }
    }

    let rel = raw_path.split('?').next().unwrap_or("/");
    let rel = percent_decode(rel);
    let safe = sanitize_path(&rel);
    let mut full = root.as_ref().join(&safe);
    if full.is_dir() {
        full = full.join("index.html");
    }

    match std::fs::File::open(&full) {
        Ok(mut f) => {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            let ctype = content_type(&full);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
            );
            conn.write_all(head.as_bytes()).await?;
            if method == "GET" {
                let mut data = Vec::new();
                f.read_to_end(&mut data)?;
                conn.write_all(&data).await?;
            }
        }
        Err(_) => {
            respond(
                &mut conn,
                404,
                "text/plain; charset=utf-8",
                b"file not found",
            )
            .await?;
        }
    }
    let _ = conn.shutdown().await;
    Ok(())
}

async fn respond(conn: &mut TcpStream, code: u16, ctype: &str, body: &[u8]) -> Result<()> {
    let reason = match code {
        404 => "Not Found",
        405 => "Method Not Allowed",
        403 => "Forbidden",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    conn.write_all(head.as_bytes()).await?;
    conn.write_all(body).await?;
    Ok(())
}

/// 去掉 `..` 之类的路径穿越。
fn sanitize_path(raw: &str) -> PathBuf {
    let p = Path::new(raw);
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => {}
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "txt" | "md" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_traversal_is_stripped() {
        assert_eq!(
            sanitize_path("/../../etc/passwd"),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(sanitize_path("/a/b/c.txt"), PathBuf::from("a/b/c.txt"));
        assert_eq!(sanitize_path("/"), PathBuf::new());
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("/a%20b"), "/a b");
        assert_eq!(percent_decode("/%E4%B8%AD"), "/中");
        assert_eq!(percent_decode("/plain"), "/plain");
    }

    #[test]
    fn mime_types() {
        assert_eq!(
            content_type(Path::new("a.html")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type(Path::new("a.PNG")), "image/png");
        assert_eq!(content_type(Path::new("a.bin")), "application/octet-stream");
    }
}
