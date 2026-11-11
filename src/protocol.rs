//! Trairi 控制协议：长度前缀 + JSON 的消息帧。

use std::net::SocketAddr;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::config::ProxyKind;
use crate::util::ProxyProtocolVersion;

/// 控制消息最大长度（1 MiB，足够放下任何一条控制消息）
pub const MAX_MSG_LEN: usize = 1024 * 1024;

/// 协议版本号
///
/// v2：Hello 签名覆盖完整字段；记录层按方向分离 AEAD nonce。
pub const PROTOCOL_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// 握手（明文，在 smux 会话建立之前）
// ---------------------------------------------------------------------------

/// 客户端 -> 服务端的第一帧，始终明文。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloRequest {
    pub version: u32,
    /// 本次连接的随机盐，用于派生加密密钥
    pub salt: String,
    /// 客户端 Unix 时间戳（秒），服务端用于防重放
    pub timestamp: i64,
    /// HMAC-SHA256(token, salt || timestamp)，token 为空时为空串
    pub signature: String,
    pub use_encryption: bool,
    pub use_compression: bool,
    /// 客户端标识，便于服务端日志
    pub client: String,
}

/// 服务端 -> 客户端的第一帧（若启用加密，则这帧本身已加密）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub version: u32,
    pub ok: bool,
    #[serde(default)]
    pub error: String,
    /// 服务端生成，便于客户端日志
    pub server_id: String,
}

// ---------------------------------------------------------------------------
// 控制消息
// ---------------------------------------------------------------------------

/// 客户端登录请求（跑在 smux 的第一条流上）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub run_id: String,
    #[serde(default)]
    pub user: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub client_version: String,
    pub timestamp: i64,
    #[serde(default)]
    pub metas: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: String,
    pub run_id: String,
    pub server_version: String,
    /// 服务端建议的心跳间隔（秒）
    pub heartbeat_interval: u64,
    /// P2P 会合 UDP 端口；0 = 未启用
    #[serde(default)]
    pub p2p_port: u16,
}

/// 注册一个代理。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProxyRequest {
    pub name: String,
    pub kind: ProxyKind,
    #[serde(default)]
    pub remote_port: i64,
    #[serde(default)]
    pub custom_domains: Vec<String>,
    #[serde(default)]
    pub subdomain: String,
    #[serde(default)]
    pub sk: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub group_key: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 服务端限速（字节/秒），0 表示不限
    #[serde(default)]
    pub bandwidth_limit: u64,
    /// 传给本地服务的 PROXY protocol 版本（" / v1 / v2）
    #[serde(default)]
    pub proxy_protocol: String,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewProxyResponse {
    pub name: String,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub remote_addr: String,
}

/// 服务端通知客户端：开一条 work 连接给我。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestWorkConn {
    pub proxy_name: String,
    #[serde(default)]
    pub src_addr: String,
    #[serde(default)]
    pub dst_addr: String,
    #[serde(default)]
    pub proxy_protocol: String,
}

/// 客户端健康状态上报。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyHealthReport {
    pub name: String,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloseProxyNotice {
    pub name: String,
    #[serde(default)]
    pub error: String,
}

// ---------------------------------------------------------------------------
// 异地组网（overlay）协调消息
// ---------------------------------------------------------------------------

/// 客户端加入虚拟网络。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayRegister {
    pub network: String,
    /// sha256(network_secret) 的十六进制
    pub secret_hash: String,
    /// WireGuard 公钥（base64）
    pub pubkey: String,
    /// 数据面 UDP 监听端口
    pub udp_port: u16,
    /// 期望的虚拟 IP（可空，由服务端分配）
    #[serde(default)]
    pub want_ip: String,
    /// 主机名（MagicDNS 用）
    #[serde(default)]
    pub hostname: String,
    /// 本节点共享给其它节点的内网网段
    #[serde(default)]
    pub proxy_networks: Vec<String>,
}

/// 网络里的一个节点。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayPeerInfo {
    pub run_id: String,
    pub pubkey: String,
    pub ip: String,
    /// 服务端观测到的公网 endpoint（可能为空）
    #[serde(default)]
    pub endpoint: String,
    /// 这是服务端自己所在的节点（endpoint 由客户端用 server_addr 补齐）
    #[serde(default)]
    pub is_server: bool,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub proxy_networks: Vec<String>,
}

/// 服务端下发的分配结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayAssign {
    pub ok: bool,
    #[serde(default)]
    pub error: String,
    /// 本节点虚拟 IP
    pub ip: String,
    /// 虚拟网段（用于配置网卡掩码）
    pub cidr: String,
    pub mtu: u16,
    /// 服务端 overlay UDP 端口（客户端向它打探自己公网 endpoint）
    pub server_udp_port: u16,
    /// 服务端 TCP 中继端口（0 表示不可用）
    #[serde(default)]
    pub server_relay_port: u16,
    /// 服务端第二个 STUN 端口（用于探测 NAT 映射行为，0 表示不可用）
    #[serde(default)]
    pub server_stun_port: u16,
    /// 服务端自身的组网节点 UDP 端口（0 表示服务端不是节点）
    #[serde(default)]
    pub server_node_port: u16,
    /// 服务端下发的 ACL 规则
    #[serde(default)]
    pub acl: Vec<String>,
    /// 同网其它节点
    pub peers: Vec<OverlayPeerInfo>,
}

/// 节点列表变更通知。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayPeers {
    pub peers: Vec<OverlayPeerInfo>,
}

/// 控制流上的所有消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ControlMsg {
    Login(LoginRequest),
    LoginResp(LoginResponse),
    NewProxy(NewProxyRequest),
    NewProxyResp(NewProxyResponse),
    ReqWorkConn(RequestWorkConn),
    ProxyHealth(ProxyHealthReport),
    CloseProxy(CloseProxyNotice),
    Ping { ts: i64 },
    Pong { ts: i64 },
    Stop,
    // ---- overlay ----
    OverlayRegister(OverlayRegister),
    OverlayAssign(OverlayAssign),
    OverlayPeers(OverlayPeers),
    // ---- P2P ----
    P2pRequest {
        proxy_name: String,
    },
    P2pInfo {
        ok: bool,
        #[serde(default)]
        error: String,
        proxy_name: String,
        #[serde(default)]
        peer_endpoint: String,
    },
    P2pPeer {
        proxy_name: String,
        peer_endpoint: String,
    },
}

// ---------------------------------------------------------------------------
// 每条新流开头的头信息（区分用途）
// ---------------------------------------------------------------------------

/// 客户端新开一条流时，第一帧说明这条流是给谁用的。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum StreamHeader {
    /// 一条 work 连接，用于承载某个代理的真实流量。
    Work {
        proxy_name: String,
        #[serde(default)]
        src_addr: String,
        #[serde(default)]
        dst_addr: String,
    },
    /// stcp 访问者连接，需要 sk 校验。
    Visitor {
        proxy_name: String,
        sk: String,
        #[serde(default)]
        src_addr: String,
        #[serde(default)]
        dst_addr: String,
        #[serde(default)]
        proxy_protocol: String,
    },
}

impl StreamHeader {
    pub fn proxy_name(&self) -> &str {
        match self {
            StreamHeader::Work { proxy_name, .. } => proxy_name,
            StreamHeader::Visitor { proxy_name, .. } => proxy_name,
        }
    }
}

// ---------------------------------------------------------------------------
// 帧编解码
// ---------------------------------------------------------------------------

/// 写一条消息：4 字节大端长度 + JSON。
pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if body.len() > MAX_MSG_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "消息过长",
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

/// 读一条消息。
pub async fn read_msg<R, T>(r: &mut R) -> std::io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    let n = crate::util::read_full(r, &mut len_buf).await?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "连接已关闭",
        ));
    }
    if n < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "长度字段不完整",
        ));
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_MSG_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("非法消息长度: {len}"),
        ));
    }
    let mut body = vec![0u8; len];
    if crate::util::read_full(r, &mut body).await? != len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "消息体不完整",
        ));
    }
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// 用于日志显示的远端描述。
pub fn addr_desc(addr: &Option<SocketAddr>) -> String {
    addr.map(|a| a.to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// 把字符串形式的 proxy protocol 版本转换过来。
pub fn parse_pp(v: &str) -> ProxyProtocolVersion {
    ProxyProtocolVersion::parse(v).unwrap_or(ProxyProtocolVersion::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn msg_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let msg = ControlMsg::ReqWorkConn(RequestWorkConn {
            proxy_name: "ssh".into(),
            src_addr: "1.2.3.4:5".into(),
            dst_addr: "6.7.8.9:10".into(),
            proxy_protocol: "v1".into(),
        });
        write_msg(&mut a, &msg).await.unwrap();
        let got: ControlMsg = read_msg(&mut b).await.unwrap();
        match got {
            ControlMsg::ReqWorkConn(w) => assert_eq!(w.proxy_name, "ssh"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn stream_header_tag() {
        let h = StreamHeader::Work {
            proxy_name: "a".into(),
            src_addr: "".into(),
            dst_addr: "".into(),
        };
        let s = serde_json::to_string(&h).unwrap();
        assert!(s.contains("\"t\":\"work\""));
        let back: StreamHeader = serde_json::from_str(&s).unwrap();
        assert_eq!(back.proxy_name(), "a");
    }
}
