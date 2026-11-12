//! Android 平台与 VpnService 的交接点：Service 建立 TUN 后把 fd 存进来，
//! overlay 的 Android TUN 实现从这里取 fd。JNI 入口在 APP 仓库的
//! `rust-jni` crate 中，避免把 Android 运行时依赖塞进桌面库。

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

static TUN_FD: AtomicI32 = AtomicI32::new(-1);

pub fn set_tun_fd(fd: i32) -> anyhow::Result<()> {
    if fd < 0 {
        anyhow::bail!("TUN fd 非法: {fd}");
    }
    TUN_FD.store(fd, Ordering::Release);
    Ok(())
}

pub fn clear_tun_fd() {
    TUN_FD.store(-1, Ordering::Release);
}

pub fn tun_fd() -> Option<RawFd> {
    let fd = TUN_FD.load(Ordering::Acquire);
    (fd >= 0).then_some(fd)
}
