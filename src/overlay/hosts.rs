//! MagicDNS（v1）：把节点的主机名写进系统 hosts 的「托管块」。
//!
//! 没有引入 DNS 服务器（那需要额外改系统 resolver 配置、跨平台差异大），
//! 而是维护一段带标记的 hosts 记录：
//!
//! ```text
//! # >>> trairi magic dns >>>
//! 10.144.144.3    my-laptop
//! 10.144.144.3    my-laptop.trairi
//! # <<< trairi magic dns <<<
//! ```
//!
//! 每次节点表变化时整体替换这一段，用户自己的 hosts 内容不受影响。

use std::net::Ipv4Addr;

const BEGIN: &str = "# >>> trairi magic dns >>>";
const END: &str = "# <<< trairi magic dns <<<";

/// 生成托管块文本（不含首尾标记之外的内容）。
pub fn render_block(entries: &[(String, Ipv4Addr)]) -> String {
    let mut out = String::from(BEGIN);
    out.push('\n');
    for (name, ip) in entries {
        let name = sanitize(name);
        if name.is_empty() {
            continue;
        }
        out.push_str(&format!("{ip}\t{name}\n"));
        out.push_str(&format!("{ip}\t{name}.trairi\n"));
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// 把新块替换进原有 hosts 内容。
pub fn merge_hosts(existing: &str, entries: &[(String, Ipv4Addr)]) -> String {
    let block = render_block(entries);
    if let (Some(start), Some(end)) = (existing.find(BEGIN), existing.find(END)) {
        let end = end + END.len();
        // 连同后面的换行一起去掉
        let tail = existing[end..].trim_start_matches('\n');
        let mut out = String::new();
        out.push_str(&existing[..start]);
        out.push_str(&block);
        out.push_str(tail);
        out
    } else {
        let mut out = existing.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&block);
        out
    }
}

/// 主机名里只保留安全字符。
fn sanitize(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .take(63)
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase()
}

/// hosts 文件路径
pub fn hosts_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::path::PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::path::PathBuf::from("/etc/hosts")
    }
}

/// 实际写入（失败只告警：通常是没有管理员/root 权限）。
pub fn sync(entries: &[(String, Ipv4Addr)]) {
    if entries.is_empty() {
        return;
    }
    let path = hosts_path();
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("MagicDNS：读不了 {}（{e}）", path.display());
            return;
        }
    };
    let merged = merge_hosts(&existing, entries);
    if merged == existing {
        return;
    }
    match std::fs::write(&path, merged) {
        Ok(()) => tracing::info!("MagicDNS：已写入 {} 条 hosts 记录", entries.len()),
        Err(e) => tracing::warn!(
            "MagicDNS：写 {} 失败（{e}），需要管理员/root 权限",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, ip: &str) -> (String, Ipv4Addr) {
        (name.to_string(), ip.parse().unwrap())
    }

    #[test]
    fn renders_managed_block() {
        let block = render_block(&[entry("laptop", "10.144.144.3")]);
        assert!(block.starts_with(BEGIN));
        assert!(block.contains("10.144.144.3\tlaptop\n"));
        assert!(block.contains("10.144.144.3\tlaptop.trairi\n"));
        assert!(block.trim_end().ends_with(END));
    }

    #[test]
    fn appends_when_no_block() {
        let merged = merge_hosts("127.0.0.1 localhost\n", &[entry("a", "10.0.0.2")]);
        assert!(merged.starts_with("127.0.0.1 localhost\n"));
        assert!(merged.contains(BEGIN));
        assert!(merged.contains("10.0.0.2\ta\n"));
    }

    #[test]
    fn replaces_existing_block_without_touching_others() {
        let existing =
            format!("127.0.0.1 localhost\n{BEGIN}\n10.0.0.9\told\n{END}\n10.9.9.9 custom\n");
        let merged = merge_hosts(&existing, &[entry("new", "10.0.0.3")]);
        assert!(merged.contains("127.0.0.1 localhost"));
        assert!(merged.contains("10.9.9.9 custom"));
        assert!(merged.contains("10.0.0.3\tnew"));
        assert!(!merged.contains("10.0.0.9\told"), "旧记录应被替换掉");
        // 只应存在一个托管块
        assert_eq!(merged.matches(BEGIN).count(), 1);
    }

    #[test]
    fn sanitizes_names() {
        let block = render_block(&[entry("My PC!", "10.0.0.4")]);
        assert!(
            block.contains("10.0.0.4\tmypc\n"),
            "非法字符应被过滤: {block}"
        );
    }
}
