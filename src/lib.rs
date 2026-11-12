//! Trairi —— 单二进制的内网穿透工具（server / client 二合一）。
//!
//! 同一个二进制，靠配置文件里的 `mode` 或命令行子命令决定本次以服务端还是客户端运行。
//!
//! 模块划分：
//! - [`config`] 配置模型与校验
//! - [`protocol`] 控制协议与流头
//! - [`crypto`] 认证与 AEAD 原语
//! - [`stream`] 压缩/加密记录层，统一的流类型
//! - [`transport`] tcp / tls / ws / wss 拨号与监听
//! - [`server`] 服务端运行时
//! - [`client`] 客户端运行时
//! - [`plugin`] 内置本地服务（socks5 / http_proxy / static_file）
//! - [`dashboard`] 服务端面板与客户端管理 API

pub mod cli;
#[cfg(target_os = "android")]
pub mod android;
pub mod client;
pub mod config;
pub mod crypto;
pub mod logging;
pub mod overlay;
pub mod p2p;
pub mod plugin;
pub mod protocol;
pub mod server;
pub mod stream;
pub mod transport;
pub mod util;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use cli::{Cli, Command};
use config::{Config, Mode};

/// 本次生效的配置文件路径（供客户端热重载使用）
static CONFIG_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// 取回配置文件路径。
pub fn config_path() -> Option<PathBuf> {
    CONFIG_PATH.get().cloned()
}

/// 打印版本信息。
pub fn print_version() {
    println!("trairi {}", env!("CARGO_PKG_VERSION"));
    println!("  协议版本 : {}", protocol::PROTOCOL_VERSION);
    println!(
        "  编译目标 : {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!(
        "  profile  : {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
}

/// 解析配置并返回 (配置, 运行模式)。
pub fn load_and_resolve(cli: &Cli) -> Result<(Config, Mode)> {
    let path = cli
        .config_path()
        .cloned()
        .context("缺少配置文件，请用 -c/--config 指定（例如 -c trairi.yaml）")?;
    let cfg = Config::load(&path)?;
    let mode = cfg.resolve_mode(cli.explicit_mode())?;
    let _ = CONFIG_PATH.set(path);
    Ok((cfg, mode))
}

/// 在已有的 tokio 运行时里按模式运行。
pub async fn run_mode(cfg: Config, mode: Mode) -> Result<()> {
    match mode {
        Mode::Server => server::run(cfg).await,
        Mode::Client => client::run(cfg).await,
    }
}

/// 程序入口逻辑（被 `main.rs` 调用，也方便集成测试）。
pub fn entry() -> Result<()> {
    let cli = Cli::parse();

    if matches!(cli.command, Some(Command::Version)) {
        print_version();
        return Ok(());
    }

    // 组网工具子命令：不进入正常运行流程
    if let Some(Command::Overlay { action }) = &cli.command {
        return run_overlay_tool(&cli, action);
    }

    // `trairi up`：不读配置文件，直接用命令行参数组网
    if let Some(Command::Up {
        server,
        token,
        ip,
        network,
        secret,
        interface,
    }) = &cli.command
    {
        let cfg = build_up_config(server, token, ip, network, secret, interface)?;
        logging::init(&cfg.log)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("trairi")
            .build()
            .context("创建 tokio 运行时失败")?;
        return rt.block_on(async move { client::run(cfg).await });
    }

    let (cfg, mode) = load_and_resolve(&cli)?;

    if matches!(cli.command, Some(Command::Validate { .. })) {
        println!("配置校验通过（mode = {mode}）");
        return Ok(());
    }

    logging::init(&cfg.log)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("trairi")
        .build()
        .context("创建 tokio 运行时失败")?;

    runtime.block_on(async move {
        tracing::info!("Trairi {} 以 {} 模式启动", env!("CARGO_PKG_VERSION"), mode);
        tokio::select! {
            r = run_mode(cfg, mode) => r,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("收到退出信号，正在关闭…");
                Ok(())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_string_contains_name() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}

/// 处理 `trairi overlay ...` 子命令。
fn run_overlay_tool(cli: &Cli, action: &cli::OverlayAction) -> Result<()> {
    use cli::OverlayAction;

    // 清理：可以直接给网卡名，不强制要配置文件
    if let OverlayAction::Cleanup { interface, .. } = action {
        if let Some(name) = interface {
            return match crate::overlay::host::cleanup_interface(name) {
                Ok(()) => {
                    println!("已清理虚拟网卡 {name}");
                    Ok(())
                }
                Err(e) => Err(anyhow::anyhow!("清理 {name} 失败: {e}")),
            };
        }
    }

    let path = cli
        .config_path()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("需要 -c 指定配置文件（或用 --interface 直接给网卡名）"))?;
    let cfg = Config::load(&path)?;
    let o = &cfg.overlay;

    match action {
        OverlayAction::Status { .. } => {
            println!("overlay 配置（{}）", path.display());
            println!("  启用        : {}", o.enable);
            if o.enable {
                println!("  网络名      : {}", o.network_name);
                println!(
                    "  本机虚拟 IP : {}",
                    if o.ipv4.is_empty() {
                        "（由服务端分配）"
                    } else {
                        &o.ipv4
                    }
                );
                println!("  地址池      : {}", o.ipv4_pool);
                println!("  UDP 数据面  : {}", o.udp_port);
                println!(
                    "  STUN        : {}",
                    o.effective_stun_port()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "关闭".into())
                );
                println!(
                    "  中继监听    : {}",
                    if o.effective_relay_listen().is_empty() {
                        "关闭".to_string()
                    } else {
                        o.effective_relay_listen()
                    }
                );
                println!(
                    "  节点端口    : {}",
                    if o.node_ipv4.is_empty() {
                        "（未启用服务端节点）".to_string()
                    } else {
                        o.effective_node_port()
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "无法推导".into())
                    }
                );
                println!("  允许中继    : {}", o.relay);
                println!("  允许直连    : {}", o.direct);
                println!("  网卡名      : {}", o.interface);
                println!("  MTU         : {}", o.mtu);
            } else {
                println!(
                    "  （未启用，把 overlay.enable 设为 true 并配置 network_name / network_secret）"
                );
            }
            Ok(())
        }
        OverlayAction::Cleanup { .. } => {
            let ifname = if o.interface.is_empty() {
                return Err(anyhow::anyhow!("需要 --interface 指定网卡名"));
            } else {
                o.interface.clone()
            };
            match crate::overlay::host::cleanup_interface(&ifname) {
                Ok(()) => {
                    println!("已清理虚拟网卡 {ifname}");
                    Ok(())
                }
                Err(e) => Err(anyhow::anyhow!("清理 {ifname} 失败: {e}")),
            }
        }
    }
}

/// 用命令行参数拼一个最小的客户端配置（`trairi up` 用）。
pub fn build_up_config(
    server: &str,
    token: &str,
    ip: &str,
    network: &str,
    secret: &str,
    interface: &str,
) -> Result<Config> {
    let (host, port) = server
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("--server 需要 host:port 形式，例如 1.2.3.4:56000"))?;
    let port: u16 = port
        .parse()
        .map_err(|e| anyhow::anyhow!("--server 端口非法: {e}"))?;
    if host.is_empty() {
        anyhow::bail!("--server 缺少主机名");
    }

    let mut cfg = Config::default();
    cfg.mode = Some(Mode::Client);
    cfg.client.server_addr = host.to_string();
    cfg.client.server_port = port;
    cfg.client.token = token.to_string();
    cfg.overlay.enable = true;
    cfg.overlay.network_name = network.to_string();
    // 密钥默认沿用 token，省得用户填两遍
    cfg.overlay.network_secret = if secret.is_empty() {
        token.to_string()
    } else {
        secret.to_string()
    };
    cfg.overlay.ipv4 = ip.to_string();
    if !interface.is_empty() {
        cfg.overlay.interface = interface.to_string();
    }
    cfg.validate()?;
    Ok(cfg)
}