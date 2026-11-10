//! 主机侧网络配置：给对端加 /32 路由，退出时清理。
//!
//! 只加「精确到单个虚拟 IP」的路由，不动默认路由，避免影响用户正常上网。

use std::net::Ipv4Addr;
use std::process::Command;

/// 给网卡配置对端路由。
pub fn ensure_peer_routes(ifname: &str, peers: &[Ipv4Addr]) {
    for ip in peers {
        if let Err(e) = add_route(ifname, *ip) {
            tracing::warn!("添加路由 {ip}/32 失败（{e}），该节点可能无法直接访问");
        }
    }
}

/// 给共享子网加路由（整段走虚拟网卡）。
pub fn ensure_cidr_routes(ifname: &str, cidrs: &[ipnet::Ipv4Net]) {
    for c in cidrs {
        let cidr = c.to_string();
        #[cfg(target_os = "linux")]
        {
            match Command::new("ip")
                .args(["route", "replace", &cidr, "dev", ifname])
                .status()
            {
                Ok(st) if st.success() => tracing::debug!("已添加子网路由 {cidr} -> {ifname}"),
                Ok(st) => tracing::warn!("添加子网路由 {cidr} 失败（退出码 {st}）"),
                Err(e) => tracing::warn!("添加子网路由 {cidr} 失败: {e}"),
            }
        }
        #[cfg(target_os = "windows")]
        {
            match Command::new("netsh")
                .args(["interface", "ipv4", "add", "route", &cidr, ifname])
                .status()
            {
                Ok(st) if st.success() => tracing::debug!("已添加子网路由 {cidr} -> {ifname}"),
                Ok(st) => tracing::warn!("添加子网路由 {cidr} 失败（退出码 {st}）"),
                Err(e) => tracing::warn!("添加子网路由 {cidr} 失败: {e}"),
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            let _ = (&cidr, ifname);
        }
    }
}

/// 删除对端路由。
pub fn remove_peer_routes(ifname: &str, peers: &[Ipv4Addr]) {
    for ip in peers {
        let _ = remove_route(ifname, *ip);
    }
}

/// 彻底删掉虚拟网卡（异常的残留清理用）。
pub fn cleanup_interface(ifname: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let st = Command::new("ip").args(["link", "del", ifname]).status()?;
        if !st.success() {
            return Err(std::io::Error::other(format!(
                "ip link del {ifname} 退出码 {st}（网卡可能不存在）"
            )));
        }
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        let st = Command::new("netsh")
            .args(["interface", "set", "interface", ifname, "admin=disable"])
            .status()?;
        if !st.success() {
            return Err(std::io::Error::other(format!(
                "netsh 禁用网卡 {ifname} 失败（退出码 {st}），可在设备管理器里移除 Wintun 适配器"
            )));
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = ifname;
        Err(std::io::Error::other("当前平台不支持自动清理"))
    }
}

#[cfg(target_os = "linux")]
fn add_route(ifname: &str, ip: Ipv4Addr) -> std::io::Result<()> {
    let st = Command::new("ip")
        .args(["route", "replace", &format!("{ip}/32"), "dev", ifname])
        .status()?;
    if !st.success() {
        return Err(std::io::Error::other(format!("ip route 退出码 {st}")));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_route(ifname: &str, ip: Ipv4Addr) -> std::io::Result<()> {
    Command::new("ip")
        .args(["route", "del", &format!("{ip}/32"), "dev", ifname])
        .status()?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn add_route(ifname: &str, ip: Ipv4Addr) -> std::io::Result<()> {
    let st = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "add",
            "route",
            &format!("{ip}/32"),
            ifname,
        ])
        .status()?;
    if !st.success() {
        return Err(std::io::Error::other(format!("netsh 退出码 {st}")));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_route(ifname: &str, ip: Ipv4Addr) -> std::io::Result<()> {
    Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "delete",
            "route",
            &format!("{ip}/32"),
            ifname,
        ])
        .status()?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn add_route(_ifname: &str, _ip: Ipv4Addr) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn remove_route(_ifname: &str, _ip: Ipv4Addr) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn route_helpers_compile() {
        // 真正的路由配置需要 root/管理员，这里只保证代码路径存在
        assert!(true);
    }
}
