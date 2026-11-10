//! 创建真实 TUN 设备（Windows 走 wintun，Linux 走 /dev/net/tun）。

use std::net::Ipv4Addr;

use anyhow::{Context, Result};

use crate::config::OverlayConfig;
use crate::overlay::device::TunDevice;
use crate::overlay::prefix_to_mask;

/// 创建并配置虚拟网卡。
///
/// - Windows：需要管理员权限，且 exe 同目录或系统路径里要有 `wintun.dll`；
/// - Linux：需要 root 或 `CAP_NET_ADMIN`。
pub fn create_tun(cfg: &OverlayConfig, ip: Ipv4Addr, prefix: u8) -> Result<TunDevice> {
    check_privileges()?;

    let mut conf = tun::Configuration::default();
    conf.address(ip)
        .netmask(prefix_to_mask(prefix))
        .mtu(cfg.mtu)
        .up();

    if !cfg.interface.is_empty() {
        conf.tun_name(&cfg.interface);
    }

    #[cfg(target_os = "windows")]
    {
        // 允许通过环境变量指定 wintun.dll 路径
        if let Ok(path) = std::env::var("TRAIRI_WINTUN_DLL") {
            conf.platform_config(|p| {
                p.wintun_file(path);
            });
        }
    }

    let dev = tun::create_as_async(&conf).with_context(|| {
        format!(
            "创建虚拟网卡 {} 失败（Windows 需以管理员运行并准备 wintun.dll；Linux 需 root）",
            cfg.interface
        )
    })?;

    tracing::info!(
        "虚拟网卡 {} 已就绪：{ip}/{}，MTU {}",
        cfg.interface,
        prefix,
        cfg.mtu
    );
    Ok(TunDevice::new(dev))
}

/// 提前给出更友好的权限提示。
pub fn check_privileges() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        // 试写系统目录来粗判是否有管理员权限
        let probe = std::env::temp_dir().join(".trairi_priv_probe");
        let _ = std::fs::remove_file(&probe);
        // 用 `net session` 判断（非管理员会返回非 0）
        let out = std::process::Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if let Ok(st) = out {
            if !st.success() {
                anyhow::bail!("创建虚拟网卡需要管理员权限，请右键「以管理员身份运行」Trairi");
            }
        }
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc_geteuid() };
        if uid != 0 {
            anyhow::bail!("创建虚拟网卡需要 root 权限（或用 CAP_NET_ADMIN 运行）");
        }
    }
    Ok(())
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    // 避免为了一个 geteuid 引入 libc 依赖
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}
