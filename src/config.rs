//! 配置模型：server / client 合一，靠 `mode` 或命令行参数决定角色。

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 枚举
// ---------------------------------------------------------------------------

/// 运行模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Server => write!(f, "server"),
            Mode::Client => write!(f, "client"),
        }
    }
}

/// 代理类型（用户可写的类型）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Tcp,
    Udp,
    Http,
    Https,
    Stcp,
    Socks5,
    #[serde(rename = "http_proxy")]
    HttpProxy,
    #[serde(rename = "static_file")]
    StaticFile,
}

impl ProxyKind {
    /// 服务端只认识这几种「对外监听」类型。
    pub fn wire(self) -> WireKind {
        match self {
            ProxyKind::Tcp | ProxyKind::Socks5 | ProxyKind::HttpProxy => WireKind::Tcp,
            ProxyKind::Udp => WireKind::Udp,
            ProxyKind::Http | ProxyKind::StaticFile => WireKind::Http,
            ProxyKind::Https => WireKind::Https,
            ProxyKind::Stcp => WireKind::Stcp,
        }
    }

    /// 是否由客户端内置插件提供本地服务。
    pub fn is_plugin(self) -> bool {
        matches!(
            self,
            ProxyKind::Socks5 | ProxyKind::HttpProxy | ProxyKind::StaticFile
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ProxyKind::Tcp => "tcp",
            ProxyKind::Udp => "udp",
            ProxyKind::Http => "http",
            ProxyKind::Https => "https",
            ProxyKind::Stcp => "stcp",
            ProxyKind::Socks5 => "socks5",
            ProxyKind::HttpProxy => "http_proxy",
            ProxyKind::StaticFile => "static_file",
        }
    }
}

/// 线上协议使用的类型（服务端视角）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WireKind {
    Tcp,
    Udp,
    Http,
    Https,
    Stcp,
}

impl WireKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WireKind::Tcp => "tcp",
            WireKind::Udp => "udp",
            WireKind::Http => "http",
            WireKind::Https => "https",
            WireKind::Stcp => "stcp",
        }
    }
}

/// 传输层协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Tls,
    Ws,
    Wss,
}

impl TransportProtocol {
    pub fn is_tls(self) -> bool {
        matches!(self, TransportProtocol::Tls | TransportProtocol::Wss)
    }
    pub fn is_ws(self) -> bool {
        matches!(self, TransportProtocol::Ws | TransportProtocol::Wss)
    }
}

// ---------------------------------------------------------------------------
// 顶层配置
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub mode: Option<Mode>,
    pub log: LogConfig,
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub dashboard: DashboardConfig,
    #[serde(rename = "webServer")]
    pub web_server: WebServerConfig,
    /// 异地组网（overlay）
    pub overlay: OverlayConfig,
    /// 代理定义（客户端生效）
    pub proxies: Vec<ProxyConfig>,
    /// 访问者定义（客户端生效，用于 stcp）
    pub visitors: Vec<VisitorConfig>,
}

impl Config {
    /// 从 YAML 文件加载配置。
    ///
    /// YAML 是 JSON 的超集，所以 .yaml / .yml / .json 都用同一个解析器；
    /// 只有 .json 扩展名时额外走严格 JSON 解析，报错信息更精确。
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("读取配置文件失败: {}", path.display()))?;
        let cfg = Self::from_yaml(&text)
            .with_context(|| format!("解析配置文件失败: {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// 直接从 YAML 文本解析（测试与内嵌场景用）。
    pub fn from_yaml(text: &str) -> Result<Self> {
        // Windows 上的记事本 / PowerShell / 部分编辑器会写 UTF-8 BOM，
        // 而 std::fs::read_to_string 不会去掉它，libyaml 会因此解析失败。
        let text = text.trim_start_matches('\u{feff}');
        serde_norway::from_str(text).map_err(|e| anyhow::anyhow!("YAML 解析错误: {e}"))
    }

    /// 决定本次以哪种角色运行。
    pub fn resolve_mode(&self, cli_mode: Option<Mode>) -> Result<Mode> {
        if let Some(m) = cli_mode {
            return Ok(m);
        }
        if let Some(m) = self.mode {
            return Ok(m);
        }
        let has_server = self.server.bind_port != 0;
        let has_client = !self.client.server_addr.is_empty();
        match (has_server, has_client) {
            (true, false) => Ok(Mode::Server),
            (false, true) => Ok(Mode::Client),
            (true, true) => bail!(
                "配置里同时有 [server] 和 [client] 内容，请显式设置 `mode = \"server\"` 或 `mode = \"client\"`"
            ),
            (false, false) => bail!("配置里没有 mode，也没有 [server]/[client] 内容"),
        }
    }

    /// 校验配置，失败时给出人类可读的错误。
    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        if let Some(m) = self.mode {
            match m {
                Mode::Server => {
                    if self.server.bind_port == 0 {
                        errors.push("[server].bind_port 必须大于 0".to_string());
                    }
                    if self.server.token.is_empty() {
                        errors.push(
                            "[server].token 不能为空（公网服务端必须配置认证 token）".to_string(),
                        );
                    }
                }
                Mode::Client => {
                    if self.client.server_addr.is_empty() {
                        errors.push("[client].server_addr 不能为空".to_string());
                    }
                    if self.client.server_port == 0 {
                        errors.push("[client].server_port 必须大于 0".to_string());
                    }
                }
            }
        }

        // 面板：只要开启就必须有认证，避免再次出现“公网 0.0.0.0 + 空密码”
        if self.dashboard.port > 0 {
            if self.dashboard.user.is_empty() || self.dashboard.password.is_empty() {
                errors.push(
                    "[dashboard] 开启面板时必须配置 user / password（建议绑 127.0.0.1）"
                        .to_string(),
                );
            } else if self.dashboard.password.len() < 8 {
                errors.push("[dashboard].password 至少 8 个字符".to_string());
            }
        }

        // 代理
        let mut names = HashSet::new();
        for p in &self.proxies {
            if p.name.is_empty() {
                errors.push("proxy.name 不能为空".to_string());
                continue;
            }
            if !names.insert(p.name.clone()) {
                errors.push(format!("proxy 名字重复: {}", p.name));
            }
            match p.kind {
                ProxyKind::Tcp | ProxyKind::Udp | ProxyKind::Socks5 | ProxyKind::HttpProxy => {
                    if p.remote_port <= 0 || p.remote_port > 65535 {
                        errors.push(format!(
                            "proxy {} ({}) 需要 1..=65535 的 remote_port",
                            p.name,
                            p.kind.as_str()
                        ));
                    }
                    if !p.kind.is_plugin() && p.local_addr.is_empty() {
                        errors.push(format!("proxy {} 需要 local_addr", p.name));
                    }
                }
                ProxyKind::Http | ProxyKind::Https => {
                    if p.custom_domains.is_empty() && p.subdomain.is_empty() {
                        errors.push(format!(
                            "proxy {} ({}) 需要 custom_domains 或 subdomain",
                            p.name,
                            p.kind.as_str()
                        ));
                    }
                    if p.local_addr.is_empty() {
                        errors.push(format!("proxy {} 需要 local_addr", p.name));
                    }
                }
                ProxyKind::StaticFile => {
                    if p.custom_domains.is_empty() && p.subdomain.is_empty() {
                        errors.push(format!("proxy {} 需要 custom_domains 或 subdomain", p.name));
                    }
                    if p.local_path.is_empty() {
                        errors.push(format!("proxy {} 需要 local_path", p.name));
                    } else if !Path::new(&p.local_path).exists() {
                        errors.push(format!(
                            "proxy {} 的 local_path 不存在: {}",
                            p.name, p.local_path
                        ));
                    }
                }
                ProxyKind::Stcp => {
                    if p.sk.is_empty() {
                        errors.push(format!("proxy {} (stcp) 需要 sk", p.name));
                    }
                    if p.local_addr.is_empty() {
                        errors.push(format!("proxy {} 需要 local_addr", p.name));
                    }
                }
            }
            if !p.group.is_empty() && p.group_key.is_empty() {
                errors.push(format!("proxy {} 属于 group 但缺少 group_key", p.name));
            }
            if !p.bandwidth_limit.is_empty() && crate::util::parse_size(&p.bandwidth_limit).is_err()
            {
                errors.push(format!(
                    "proxy {} 的 bandwidth_limit 无法解析: {}",
                    p.name, p.bandwidth_limit
                ));
            }
            if let Err(e) = crate::util::ProxyProtocolVersion::parse(&p.proxy_protocol_version) {
                errors.push(format!("proxy {}: {e}", p.name));
            }
        }

        // 访问者
        for v in &self.visitors {
            if v.name.is_empty() {
                errors.push("visitor.name 不能为空".to_string());
            }
            if v.server_name.is_empty() {
                errors.push(format!("visitor {} 需要 server_name", v.name));
            }
            if v.sk.is_empty() {
                errors.push(format!("visitor {} 需要 sk", v.name));
            }
            if v.bind_port == 0 {
                errors.push(format!("visitor {} 需要 bind_port", v.name));
            }
        }

        if self.overlay.enable {
            if self.overlay.network_name.is_empty() {
                errors.push("overlay.network_name 不能为空".to_string());
            }
            if self.overlay.network_secret.is_empty() {
                errors.push("overlay.network_secret 不能为空".to_string());
            }
            if self.overlay.mtu < 576 {
                errors.push(format!("overlay.mtu 太小: {}", self.overlay.mtu));
            }
            if !self.overlay.ipv4.is_empty() && self.overlay.parse_ipv4().is_err() {
                errors.push(format!("overlay.ipv4 非法: {}", self.overlay.ipv4));
            }
            if !self.overlay.ipv4_pool.is_empty()
                && self.overlay.ipv4_pool.parse::<ipnet::Ipv4Net>().is_err()
            {
                errors.push(format!(
                    "overlay.ipv4_pool 非法: {}",
                    self.overlay.ipv4_pool
                ));
            }
            if self.mode == Some(Mode::Server)
                && self.overlay.ipv4_pool.is_empty()
                && self.overlay.node_ipv4.is_empty()
            {
                errors.push("服务端启用 overlay 时必须配置 overlay.ipv4_pool".to_string());
            }
            if !self.overlay.node_ipv4.is_empty()
                && self
                    .overlay
                    .node_ipv4
                    .parse::<std::net::Ipv4Addr>()
                    .is_err()
            {
                errors.push(format!(
                    "overlay.node_ipv4 非法: {}",
                    self.overlay.node_ipv4
                ));
            }
        }

        if let Some(m) = self.mode {
            if m == Mode::Client
                && self.proxies.is_empty()
                && self.visitors.is_empty()
                && !self.overlay.enable
            {
                errors.push("客户端模式下 proxies、visitors、overlay 至少要有一个".to_string());
            }
        }

        if !errors.is_empty() {
            bail!("配置校验失败:\n  - {}", errors.join("\n  - "));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 各段配置
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LogConfig {
    pub level: String,
    pub file: String,
    pub max_days: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            file: String::new(),
            max_days: 7,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub bind_port: u16,
    pub vhost_http_port: u16,
    pub vhost_https_port: u16,
    pub subdomain_host: String,
    /// 允许客户端申请的端口，如 "1000-2000,3000"；为空表示不限制
    pub allow_ports: String,
    pub max_ports_per_client: u32,
    /// 服务端等待客户端认证的秒数
    pub authentication_timeout: u64,
    /// 心跳超时秒数
    pub heartbeat_timeout: u64,
    pub max_clients: u32,
    pub token: String,
    /// 强制要求加密
    pub force_encryption: bool,
    pub tls_cert_file: String,
    pub tls_key_file: String,
    /// 服务端统一要求客户端使用 proxy protocol（可被代理级配置覆盖）
    pub proxy_protocol_version: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".into(),
            bind_port: 0,
            vhost_http_port: 0,
            vhost_https_port: 0,
            subdomain_host: String::new(),
            allow_ports: String::new(),
            max_ports_per_client: 64,
            authentication_timeout: 10,
            heartbeat_timeout: 90,
            max_clients: 1024,
            token: String::new(),
            force_encryption: true,
            tls_cert_file: String::new(),
            tls_key_file: String::new(),
            proxy_protocol_version: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DashboardConfig {
    pub bind_addr: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1".into(),
            port: 0,
            user: "admin".into(),
            password: "admin".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct WebServerConfig {
    pub addr: String,
    pub port: u16,
    pub user: String,
    pub password: String,
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1".into(),
            port: 0,
            user: "admin".into(),
            password: "admin".into(),
        }
    }
}

/// 异地组网（overlay）配置段。
///
/// 架构：WireGuard 数据面 + Trairi 服务端做协调（分配虚拟 IP、登记公钥、分发端点）。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OverlayConfig {
    /// 是否启用组网
    pub enable: bool,
    /// 网络名（同一个虚拟局域网的节点必须一致）
    pub network_name: String,
    /// 网络密钥（同网节点必须一致，同时用作 WireGuard 预共享密钥）
    pub network_secret: String,
    /// 本节点虚拟 IP；客户端留空则由服务端分配
    pub ipv4: String,
    /// 服务端：虚拟 IP 地址池，如 10.144.144.0/24
    pub ipv4_pool: String,
    /// 数据面 UDP 监听端口（0 表示随机）
    pub udp_port: u16,
    /// 虚拟网卡名
    pub interface: String,
    /// 虚拟网卡 MTU
    pub mtu: u16,
    /// 服务端是否自己也作为组网节点（填它的虚拟 IP，留空表示只做协调）
    pub node_ipv4: String,
    /// 服务端 TCP 中继监听地址；留空或端口 0 表示关闭中继
    pub relay_listen: String,
    /// 客户端是否允许经由服务端中继（直连不通时兜底）
    pub relay: bool,
    /// 是否尝试直连；false 表示一律走中继
    pub direct: bool,
    /// 共享给其它节点访问的内网网段，如 192.168.1.0/24（本机必须在那个网段里）
    pub proxy_networks: Vec<String>,
    /// 访问控制规则，如 "allow * -> *"、"deny 10.144.144.0/24 -> 192.168.1.0/24"
    pub acl: Vec<String>,
    /// MagicDNS：把节点主机名写进系统 hosts（需要管理员/root）
    pub magic_dns: bool,
    /// 额外的 STUN 服务器（形如 1.2.3.4:3478）。
    /// 用来判断「端口映射行为」——需要和对端不同 IP 的服务器对比较，结果才准确。
    pub stun_servers: Vec<String>,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            enable: false,
            network_name: String::new(),
            network_secret: String::new(),
            ipv4: String::new(),
            ipv4_pool: String::new(),
            udp_port: 11013,
            interface: if cfg!(windows) {
                "Trairi".into()
            } else {
                "trairi0".into()
            },
            mtu: 1280,
            node_ipv4: String::new(),
            relay_listen: "0.0.0.0:11012".into(),
            relay: true,
            direct: true,
            stun_servers: Vec::new(),
            magic_dns: true,
            proxy_networks: Vec::new(),
            acl: Vec::new(),
        }
    }
}

impl OverlayConfig {
    /// 解析本节点要用的地址（可带前缀）。
    pub fn parse_ipv4(&self) -> Result<ipnet::Ipv4Net> {
        parse_ipv4_prefix(&self.ipv4)
    }
}

/// 解析 `10.144.144.2` 或 `10.144.144.2/24`（缺省前缀按 /32 处理）。
pub fn parse_ipv4_prefix(s: &str) -> Result<ipnet::Ipv4Net> {
    let s = s.trim();
    if s.is_empty() {
        bail!("空的 IPv4 地址");
    }
    if s.contains('/') {
        s.parse::<ipnet::Ipv4Net>()
            .map_err(|e| anyhow::anyhow!("非法 IPv4 网段 {s}: {e}"))
    } else {
        let addr: std::net::Ipv4Addr = s
            .parse()
            .map_err(|e| anyhow::anyhow!("非法 IPv4 地址 {s}: {e}"))?;
        Ok(ipnet::Ipv4Net::new(addr, 32).expect("32 位前缀合法"))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_port: u16,
    pub token: String,
    pub run_id: String,
    pub user: String,
    /// tcp / tls / ws / wss
    pub protocol: TransportProtocol,
    /// 兼容写法：为 true 且 protocol=tcp 时自动升级成 tls
    pub tls_enable: bool,
    /// 校验服务端证书用的名字（默认等于 server_addr）
    pub tls_server_name: String,
    /// 自定义 CA 文件
    pub tls_cert_file: String,
    /// 跳过服务端证书校验（不推荐）
    pub tls_insecure: bool,
    pub ws_path: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    pub heartbeat_interval: u64,
    pub heartbeat_timeout: u64,
    pub dial_timeout: u64,
    pub proxy_protocol_version: String,
    pub bandwidth_limit: String,
    /// 只启动列表里的代理（按名字）
    pub start: Vec<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_addr: String::new(),
            server_port: 0,
            token: String::new(),
            run_id: String::new(),
            user: String::new(),
            protocol: TransportProtocol::Tcp,
            tls_enable: false,
            tls_server_name: String::new(),
            tls_cert_file: String::new(),
            tls_insecure: false,
            ws_path: "/~!trairi".into(),
            use_encryption: true,
            use_compression: false,
            heartbeat_interval: 30,
            heartbeat_timeout: 90,
            dial_timeout: 10,
            proxy_protocol_version: String::new(),
            bandwidth_limit: String::new(),
            start: Vec::new(),
        }
    }
}

impl ClientConfig {
    /// 实际使用的传输协议（把 `tls_enable` 兼容进来）。
    pub fn effective_protocol(&self) -> TransportProtocol {
        if self.tls_enable && self.protocol == TransportProtocol::Tcp {
            TransportProtocol::Tls
        } else {
            self.protocol
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ProxyKind,
    /// 本地服务地址，如 127.0.0.1:22
    pub local_addr: String,
    /// static_file 的根目录
    pub local_path: String,
    /// tcp/udp 对外端口
    pub remote_port: i64,
    pub custom_domains: Vec<String>,
    pub subdomain: String,
    /// stcp 的密钥
    pub sk: String,
    /// 负载均衡分组
    pub group: String,
    pub group_key: String,
    pub weight: u32,
    /// 如 "1MB"、"512KB"，空表示不限
    pub bandwidth_limit: String,
    /// server（默认）或 client
    pub bandwidth_limit_mode: String,
    pub proxy_protocol_version: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    /// static_file 的 basic auth
    pub http_user: String,
    pub http_pwd: String,
    // 健康检查
    pub health_check_type: String,
    pub health_check_timeout: u64,
    pub health_check_interval: u64,
    pub health_check_max_failed: u32,
    pub health_check_path: String,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: ProxyKind::Tcp,
            local_addr: String::new(),
            local_path: String::new(),
            remote_port: 0,
            custom_domains: Vec::new(),
            subdomain: String::new(),
            sk: String::new(),
            group: String::new(),
            group_key: String::new(),
            weight: 1,
            bandwidth_limit: String::new(),
            bandwidth_limit_mode: "server".into(),
            proxy_protocol_version: String::new(),
            use_encryption: false,
            use_compression: false,
            http_user: String::new(),
            http_pwd: String::new(),
            health_check_type: String::new(),
            health_check_timeout: 3,
            health_check_interval: 10,
            health_check_max_failed: 1,
            health_check_path: "/".into(),
        }
    }
}

impl ProxyConfig {
    pub fn bandwidth_bytes(&self) -> u64 {
        if self.bandwidth_limit.is_empty() {
            0
        } else {
            crate::util::parse_size(&self.bandwidth_limit).unwrap_or(0)
        }
    }

    pub fn limit_on_client(&self) -> bool {
        self.bandwidth_limit_mode.eq_ignore_ascii_case("client")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct VisitorConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ProxyKind,
    /// 要访问的 stcp 代理名
    pub server_name: String,
    pub sk: String,
    pub bind_addr: String,
    pub bind_port: u16,
}

impl Default for VisitorConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: ProxyKind::Stcp,
            server_name: String::new(),
            sk: String::new(),
            bind_addr: "127.0.0.1".into(),
            bind_port: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_YAML: &str = r#"
mode: client

client:
  server_addr: 127.0.0.1
  server_port: 7000
  token: abc

proxies:
  - name: ssh
    type: tcp
    local_addr: 127.0.0.1:22
    remote_port: 6000
  - name: web
    type: http
    local_addr: 127.0.0.1:8080
    custom_domains:
      - a.example.com
"#;

    #[test]
    fn parse_client_config() {
        let cfg = Config::from_yaml(CLIENT_YAML).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.resolve_mode(None).unwrap(), Mode::Client);
        assert_eq!(cfg.proxies.len(), 2);
        assert_eq!(cfg.proxies[0].kind.wire(), WireKind::Tcp);
        assert_eq!(cfg.proxies[1].kind.wire(), WireKind::Http);
        assert_eq!(cfg.client.token, "abc");
        assert_eq!(cfg.proxies[1].custom_domains, vec!["a.example.com"]);
    }

    #[test]
    fn yaml_parses_json_too() {
        // YAML 是 JSON 的超集
        let text = r#"{"mode":"server","server":{"bind_port":7000}}"#;
        let cfg = Config::from_yaml(text).unwrap();
        assert_eq!(cfg.resolve_mode(None).unwrap(), Mode::Server);
    }

    #[test]
    fn yaml_tolerates_utf8_bom() {
        // Windows 编辑器常带 BOM，必须能吃下去
        let text = "\u{feff}mode: server\nserver:\n  bind_port: 7000\n";
        let cfg = Config::from_yaml(text).unwrap();
        assert_eq!(cfg.resolve_mode(None).unwrap(), Mode::Server);
    }

    #[test]
    fn mode_from_sections() {
        let cfg = Config::from_yaml("server:\n  bind_port: 7000\n").unwrap();
        assert_eq!(cfg.resolve_mode(None).unwrap(), Mode::Server);

        let cfg =
            Config::from_yaml("client:\n  server_addr: 1.1.1.1\n  server_port: 7000\n").unwrap();
        assert_eq!(cfg.resolve_mode(None).unwrap(), Mode::Client);

        let cfg = Config::from_yaml(
            "server:\n  bind_port: 7000\nclient:\n  server_addr: 1.1.1.1\n  server_port: 1\n",
        )
        .unwrap();
        assert!(cfg.resolve_mode(None).is_err());

        // 命令行优先
        let cfg = Config::from_yaml("server:\n  bind_port: 7000\n").unwrap();
        assert_eq!(cfg.resolve_mode(Some(Mode::Client)).unwrap(), Mode::Client);
    }

    #[test]
    fn validation_catches_mistakes() {
        let mut cfg = Config::default();
        cfg.mode = Some(Mode::Client);
        cfg.client.server_addr = "127.0.0.1".into();
        cfg.client.server_port = 7000;
        // 缺 remote_port
        cfg.proxies.push(ProxyConfig {
            name: "a".into(),
            kind: ProxyKind::Tcp,
            local_addr: "127.0.0.1:22".into(),
            ..Default::default()
        });
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("remote_port"), "{err}");

        // 重名
        let mut cfg = Config::default();
        cfg.mode = Some(Mode::Client);
        cfg.client.server_addr = "127.0.0.1".into();
        cfg.client.server_port = 7000;
        for _ in 0..2 {
            cfg.proxies.push(ProxyConfig {
                name: "dup".into(),
                kind: ProxyKind::Tcp,
                local_addr: "127.0.0.1:22".into(),
                remote_port: 6000,
                ..Default::default()
            });
        }
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("重复"), "{err}");
    }

    #[test]
    fn tls_enable_compat() {
        let mut c = ClientConfig::default();
        assert_eq!(c.effective_protocol(), TransportProtocol::Tcp);
        c.tls_enable = true;
        assert_eq!(c.effective_protocol(), TransportProtocol::Tls);
        c.protocol = TransportProtocol::Ws;
        assert_eq!(c.effective_protocol(), TransportProtocol::Ws);
    }

    #[test]
    fn plugin_wire_types() {
        assert_eq!(ProxyKind::Socks5.wire(), WireKind::Tcp);
        assert_eq!(ProxyKind::StaticFile.wire(), WireKind::Http);
        assert_eq!(ProxyKind::HttpProxy.wire(), WireKind::Tcp);
        assert!(ProxyKind::Socks5.is_plugin());
        assert!(!ProxyKind::Tcp.is_plugin());
    }
}
