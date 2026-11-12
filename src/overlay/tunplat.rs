//! 创建真实 TUN 设备：Windows 走 wintun，Linux 走 /dev/net/tun，
//! Android 走 VpnService 传入的 TUN fd。
use std::net::Ipv4Addr;

use anyhow::{Context, Result};

use crate::config::OverlayConfig;
use crate::overlay::device::IpDevice;

#[cfg(not(target_os = "android"))]
use crate::overlay::device::TunDevice;
#[cfg(not(target_os = "android"))]
use crate::overlay::prefix_to_mask;

/// 创建并配置虚拟网卡。
///
/// - Windows：需要管理员权限，且 exe 同目录或系统路径里要有 `wintun.dll`；
/// - Linux：需要 root 或 `CAP_NET_ADMIN`；
/// - Android：由 `VpnService` 建立 TUN 并通过 JNI 传入 fd，不在这里提权。
pub fn create_tun(cfg: &OverlayConfig, ip: Ipv4Addr, prefix: u8) -> Result<Box<dyn IpDevice>> {
    #[cfg(target_os = "android")]
    {
        let _ = (cfg, ip, prefix);
        let fd = crate::android::tun_fd().context(
            "Android TUN fd 未就绪（需要先通过 VpnService 建立 VPN 并传入 fd）",
        )?;
        let dev = AndroidTun::new(fd)?;
        tracing::info!("Android TUN fd={fd} 已接入 overlay");
        return Ok(Box::new(dev));
    }

    #[cfg(not(target_os = "android"))]
    {
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
        Ok(Box::new(TunDevice::new(dev)))
    }
}

#[cfg(target_os = "android")]
struct AndroidFd(std::os::fd::RawFd);

#[cfg(target_os = "android")]
impl std::os::fd::AsRawFd for AndroidFd {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}

#[cfg(target_os = "android")]
struct AndroidTun {
    fd: tokio::io::unix::AsyncFd<AndroidFd>,
}

#[cfg(target_os = "android")]
impl AndroidTun {
    fn new(fd: std::os::fd::RawFd) -> std::io::Result<Self> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(Self {
            fd: tokio::io::unix::AsyncFd::new(AndroidFd(fd))?,
        })
    }
}

#[cfg(target_os = "android")]
#[async_trait::async_trait]
impl IpDevice for AndroidTun {
    async fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().0,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> std::io::Result<()> {
        let mut off = 0;
        while off < pkt.len() {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.get_ref().0,
                        pkt[off..].as_ptr() as *const libc::c_void,
                        pkt.len() - off,
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => off += n,
                Ok(Err(e)) => return Err(e),
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

/// 提前给出更友好的权限提示（Android 由 VpnService 授权，不需要 root）。
pub fn check_privileges() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("net")
            .arg("session")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if let Ok(st) = out {
            if !st.success() {
                anyhow::bail!("创建虚拟网卡需要管理员权限，请右键「以管理员身份运行 trairi");
            }
        }
    }
    #[cfg(all(unix, not(target_os = "android")))]
    {
        let uid = unsafe { libc_geteuid() };
        if uid != 0 {
            anyhow::bail!("创建虚拟网卡需要 root 权限（或用 CAP_NET_ADMIN 运行）");
        }
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "android")))]
unsafe fn libc_geteuid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}
