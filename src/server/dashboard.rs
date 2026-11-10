//! 服务端面板：一个极简的 HTTP 服务，提供 HTML 页面和 JSON API。

use std::sync::Arc;
use std::time::UNIX_EPOCH;

use anyhow::Result;
use base64::Engine;
use serde::Serialize;
use subtle::ConstantTimeEq;
use tiny_http::{Header, Method, Request, Response, Server};

use crate::config::DashboardConfig;
use crate::server::ServerState;

#[derive(Serialize)]
struct ClientView {
    run_id: String,
    remote_addr: String,
    hostname: String,
    os: String,
    arch: String,
    version: String,
    transport: String,
    connected_secs: u64,
    proxies: Vec<String>,
}

#[derive(Serialize)]
struct ProxyView {
    name: String,
    kind: String,
    client: String,
    remote_port: u16,
    domains: Vec<String>,
    healthy: bool,
    conns: u64,
    bytes_in: u64,
    bytes_out: u64,
    created_secs: u64,
}

#[derive(Serialize)]
struct Overview {
    version: &'static str,
    server_id: String,
    start_time: u64,
    uptime_secs: u64,
    bind_port: u16,
    vhost_http_port: u16,
    vhost_https_port: u16,
    clients: Vec<ClientView>,
    proxies: Vec<ProxyView>,
    total_conns: u64,
    total_bytes_in: u64,
    total_bytes_out: u64,
}

async fn overview(state: &Arc<ServerState>) -> Overview {
    let clients = state.clients.read().await;
    let proxies = state.proxies.read().await;

    let client_views: Vec<ClientView> = clients
        .values()
        .map(|c| ClientView {
            run_id: c.run_id.clone(),
            remote_addr: c.remote_addr.clone(),
            hostname: c.hostname.clone(),
            os: c.os.clone(),
            arch: c.arch.clone(),
            version: c.version.clone(),
            transport: c.transport.clone(),
            connected_secs: c.connected_at.elapsed().as_secs(),
            proxies: c.proxies.lock().unwrap().clone(),
        })
        .collect();

    let proxy_views: Vec<ProxyView> = proxies
        .values()
        .map(|p| ProxyView {
            name: p.name.clone(),
            kind: p.kind.as_str().to_string(),
            client: p.client.run_id.clone(),
            remote_port: p.remote_port,
            domains: p.domains.clone(),
            healthy: p.healthy.load(std::sync::atomic::Ordering::Relaxed),
            conns: p.stats.conns.load(std::sync::atomic::Ordering::Relaxed),
            bytes_in: p.stats.bytes_in.load(std::sync::atomic::Ordering::Relaxed),
            bytes_out: p.stats.bytes_out.load(std::sync::atomic::Ordering::Relaxed),
            created_secs: p.created_at.elapsed().as_secs(),
        })
        .collect();

    Overview {
        version: env!("CARGO_PKG_VERSION"),
        server_id: state.server_id.clone(),
        start_time: state
            .started_at_wall
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        uptime_secs: state.started_at.elapsed().as_secs(),
        bind_port: state.cfg.bind_port,
        vhost_http_port: state.cfg.vhost_http_port,
        vhost_https_port: state.cfg.vhost_https_port,
        total_conns: proxy_views.iter().map(|p| p.conns).sum(),
        total_bytes_in: proxy_views.iter().map(|p| p.bytes_in).sum(),
        total_bytes_out: proxy_views.iter().map(|p| p.bytes_out).sum(),
        clients: client_views,
        proxies: proxy_views,
    }
}

/// 启动面板（阻塞在独立线程里）。
pub async fn serve(state: Arc<ServerState>, cfg: DashboardConfig) -> Result<()> {
    let handle = tokio::runtime::Handle::current();
    let addr = format!("{}:{}", cfg.bind_addr, cfg.port);
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("监听面板 {addr} 失败: {e}"))?;
    tracing::info!("面板已启动 http://{addr}");

    let expected_auth = if cfg.user.is_empty() && cfg.password.is_empty() {
        None
    } else {
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", cfg.user, cfg.password))
        ))
    };

    let st = state.clone();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let response = handle_request(&st, &handle, &expected_auth, request);
            if let Err(e) = response {
                tracing::debug!("面板请求处理失败: {e:#}");
            }
        }
    });

    Ok(())
}

fn handle_request(
    state: &Arc<ServerState>,
    handle: &tokio::runtime::Handle,
    expected_auth: &Option<String>,
    request: Request,
) -> Result<()> {
    // 鉴权
    if let Some(expected) = expected_auth {
        let ok = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| {
                h.value
                    .as_str()
                    .as_bytes()
                    .ct_eq(expected.as_bytes())
                    .unwrap_u8()
                    == 1
            })
            .unwrap_or(false);
        if !ok {
            let mut resp = Response::from_string("需要认证").with_status_code(401);
            resp.add_header(
                Header::from_bytes(&b"WWW-Authenticate"[..], &b"Basic realm=\"trairi\""[..])
                    .unwrap(),
            );
            let _ = request.respond(resp);
            return Ok(());
        }
    }

    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();

    match (&request.method(), path.as_str()) {
        (Method::Get, "/") => {
            let body = INDEX_HTML.replace("{{VERSION}}", env!("CARGO_PKG_VERSION"));
            let resp =
                Response::from_string(body).with_header(json_header("text/html; charset=utf-8"));
            let _ = request.respond(resp);
        }
        (Method::Get, "/api/overview") => {
            let data = handle.block_on(overview(state));
            let body = serde_json::to_string(&data).unwrap_or_else(|_| "{}".into());
            let resp = Response::from_string(body).with_header(json_header("application/json"));
            let _ = request.respond(resp);
        }
        (Method::Get, "/healthz") => {
            let resp = Response::from_string("ok");
            let _ = request.respond(resp);
        }
        _ => {
            let resp = Response::from_string("not found").with_status_code(404);
            let _ = request.respond(resp);
        }
    }
    Ok(())
}

fn json_header(content_type: &str) -> Header {
    Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes()).unwrap()
}

/// 静态页面（不引入前端构建，单文件够用）
const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'">
<meta name="referrer" content="no-referrer">
<title>Trairi 面板</title>
<style>
  :root { --bg:#0f1115; --card:#171a21; --line:#242936; --fg:#e6e8ee; --dim:#8b93a7; --ok:#3ecf8e; --bad:#f2545b; --acc:#4d9fff; }
  * { box-sizing: border-box; }
  body { margin:0; font: 14px/1.6 system-ui, -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:18px 24px; border-bottom:1px solid var(--line); display:flex; align-items:baseline; gap:16px; }
  h1 { font-size:18px; margin:0; letter-spacing:.5px; }
  .dim { color:var(--dim); }
  main { padding:24px; display:grid; gap:20px; grid-template-columns: 1fr; }
  .cards { display:grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr)); gap:14px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
  .card .k { color:var(--dim); font-size:12px; }
  .card .v { font-size:22px; font-weight:600; margin-top:4px; }
  section { background:var(--card); border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  section h2 { font-size:14px; margin:0; padding:12px 16px; border-bottom:1px solid var(--line); color:var(--dim); font-weight:500; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:8px 16px; border-bottom:1px solid var(--line); white-space:nowrap; }
  th { color:var(--dim); font-weight:500; }
  tr:last-child td { border-bottom:none; }
  .ok { color:var(--ok); } .bad { color:var(--bad); }
  code { background:#0b0d12; padding:2px 6px; border-radius:4px; color:var(--acc); }
  .empty { padding:16px; color:var(--dim); }
</style>
</head>
<body>
<header>
  <h1>Trairi</h1>
  <span class="dim">v{{VERSION}}</span>
  <span class="dim" id="uptime"></span>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="k">客户端</div><div class="v" id="n-clients">-</div></div>
    <div class="card"><div class="k">代理</div><div class="v" id="n-proxies">-</div></div>
    <div class="card"><div class="k">累计连接</div><div class="v" id="n-conns">-</div></div>
    <div class="card"><div class="k">上行流量</div><div class="v" id="bytes-in">-</div></div>
    <div class="card"><div class="k">下行流量</div><div class="v" id="bytes-out">-</div></div>
  </div>

  <section>
    <h2>代理</h2>
    <table id="tbl-proxies">
      <thead><tr><th>名字</th><th>类型</th><th>地址/域名</th><th>状态</th><th>连接</th><th>上行</th><th>下行</th></tr></thead>
      <tbody></tbody>
    </table>
  </section>

  <section>
    <h2>客户端</h2>
    <table id="tbl-clients">
      <thead><tr><th>Run ID</th><th>主机名</th><th>系统</th><th>版本</th><th>传输</th><th>在线</th></tr></thead>
      <tbody></tbody>
    </table>
  </section>
</main>
<script>
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtBytes(n) {
  const u = ['B','KB','MB','GB','TB']; let i = 0; let f = n;
  while (f >= 1024 && i < u.length - 1) { f /= 1024; i++; }
  return (i === 0 ? f : f.toFixed(2)) + ' ' + u[i];
}
function fmtDur(s) {
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
  if (d) return d + '天' + h + '小时';
  if (h) return h + '小时' + m + '分';
  return m + '分' + (s%60) + '秒';
}
async function tick() {
  try {
    const r = await fetch('api/overview');
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    document.getElementById('uptime').textContent = '已运行 ' + fmtDur(d.uptime_secs);
    document.getElementById('n-clients').textContent = d.clients.length;
    document.getElementById('n-proxies').textContent = d.proxies.length;
    document.getElementById('n-conns').textContent = d.total_conns;
    document.getElementById('bytes-in').textContent = fmtBytes(d.total_bytes_in);
    document.getElementById('bytes-out').textContent = fmtBytes(d.total_bytes_out);

    const pb = document.querySelector('#tbl-proxies tbody');
    pb.innerHTML = d.proxies.length ? d.proxies.map(p => `<tr>
      <td><code>${esc(p.name)}</code></td><td>${esc(p.kind)}</td>
      <td>${p.domains.length ? esc(p.domains.join(', ')) : ':' + p.remote_port}</td>
      <td class="${p.healthy ? 'ok' : 'bad'}">${p.healthy ? '正常' : '异常'}</td>
      <td>${p.conns}</td><td>${fmtBytes(p.bytes_in)}</td><td>${fmtBytes(p.bytes_out)}</td></tr>`).join('')
      : '<tr><td colspan="7" class="empty">暂无代理</td></tr>';

    const cb = document.querySelector('#tbl-clients tbody');
    cb.innerHTML = d.clients.length ? d.clients.map(c => `<tr>
      <td><code>${esc(c.run_id)}</code></td><td>${esc(c.hostname)}</td>
      <td>${esc(c.os)}/${esc(c.arch)}</td><td>${esc(c.version)}</td><td>${esc(c.transport)}</td>
      <td>${fmtDur(c.connected_secs)}</td></tr>`).join('')
      : '<tr><td colspan="6" class="empty">暂无客户端</td></tr>';
  } catch (e) {
    document.getElementById('uptime').textContent = '面板连接失败: ' + e;
  }
}
tick(); setInterval(tick, 2000);
</script>
</body>
</html>"#;
