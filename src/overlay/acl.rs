//! 简单的 overlay 访问控制（ACL）。
//!
//! 规则写法：`allow|deny <src> -> <dst>`，src/dst 可以是 `*`、单个 IP 或 CIDR。
//! 按顺序匹配，**第一条命中的规则生效**；都不命中时默认放行。
//!
//! 例如：
//! ```text
//! deny  10.144.144.3 -> 10.144.144.2      # 禁止某个节点访问另一个节点
//! allow *            -> 192.168.1.0/24    # 允许访问共享子网
//! deny  *            -> 192.168.2.0/24    # 禁止访问另一个共享子网
//! ```

use std::net::Ipv4Addr;

/// 一个地址匹配器
#[derive(Debug, Clone)]
enum AddrMatch {
    Any,
    Net(ipnet::Ipv4Net),
}

impl AddrMatch {
    fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s == "*" {
            return Ok(AddrMatch::Any);
        }
        if s.contains('/') {
            s.parse::<ipnet::Ipv4Net>()
                .map(AddrMatch::Net)
                .map_err(|e| format!("非法 CIDR {s}: {e}"))
        } else {
            let ip: Ipv4Addr = s.parse().map_err(|e| format!("非法 IP {s}: {e}"))?;
            Ok(AddrMatch::Net(
                ipnet::Ipv4Net::new(ip, 32).expect("32 位前缀合法"),
            ))
        }
    }

    fn matches(&self, ip: Ipv4Addr) -> bool {
        match self {
            AddrMatch::Any => true,
            AddrMatch::Net(n) => n.contains(&ip),
        }
    }
}

#[derive(Debug, Clone)]
struct Rule {
    allow: bool,
    src: AddrMatch,
    dst: AddrMatch,
}

/// 一组 ACL 规则
#[derive(Debug, Clone, Default)]
pub struct Acl {
    rules: Vec<Rule>,
}

impl Acl {
    /// 从字符串解析；非法规则会被丢弃并记日志。
    pub fn parse(lines: &[String]) -> Self {
        let mut rules = Vec::new();
        for line in lines {
            let raw = line.trim();
            if raw.is_empty() || raw.starts_with('#') {
                continue;
            }
            match Self::parse_one(raw) {
                Ok(r) => rules.push(r),
                Err(e) => tracing::warn!("ACL 规则非法，已忽略: {raw}（{e}）"),
            }
        }
        Self { rules }
    }

    fn parse_one(raw: &str) -> Result<Rule, String> {
        let (action, rest) = raw
            .split_once(char::is_whitespace)
            .ok_or_else(|| "缺少动作".to_string())?;
        let allow = match action.trim().to_ascii_lowercase().as_str() {
            "allow" => true,
            "deny" => false,
            other => return Err(format!("未知动作 {other}")),
        };
        let (src, dst) = rest.split_once("->").ok_or_else(|| "缺少 ->".to_string())?;
        Ok(Rule {
            allow,
            src: AddrMatch::parse(src)?,
            dst: AddrMatch::parse(dst)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 是否允许一条从 src 到 dst 的流量。
    pub fn allows(&self, src: Ipv4Addr, dst: Ipv4Addr) -> bool {
        for r in &self.rules {
            if r.src.matches(src) && r.dst.matches(dst) {
                return r.allow;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_acl_allows_everything() {
        let acl = Acl::default();
        assert!(acl.allows(ip("10.0.0.1"), ip("10.0.0.2")));
        assert!(acl.is_empty());
    }

    #[test]
    fn deny_single_pair() {
        let acl = Acl::parse(&["deny 10.144.144.3 -> 10.144.144.2".into()]);
        assert!(!acl.allows(ip("10.144.144.3"), ip("10.144.144.2")));
        // 反向不受影响
        assert!(acl.allows(ip("10.144.144.2"), ip("10.144.144.3")));
        // 无关地址不受影响
        assert!(acl.allows(ip("10.144.144.3"), ip("10.144.144.9")));
    }

    #[test]
    fn subnet_rules_and_order() {
        let acl = Acl::parse(&[
            "allow * -> 192.168.1.0/24".into(),
            "deny * -> 192.168.2.0/24".into(),
        ]);
        assert!(acl.allows(ip("10.144.144.2"), ip("192.168.1.10")));
        assert!(!acl.allows(ip("10.144.144.2"), ip("192.168.2.10")));
        assert!(acl.allows(ip("10.144.144.2"), ip("10.144.144.9")));
    }

    #[test]
    fn first_match_wins() {
        let acl = Acl::parse(&[
            "deny 10.144.144.2 -> 10.144.144.3".into(),
            "allow * -> *".into(),
        ]);
        assert!(!acl.allows(ip("10.144.144.2"), ip("10.144.144.3")));
        assert!(acl.allows(ip("10.144.144.4"), ip("10.144.144.3")));
    }

    #[test]
    fn invalid_rules_are_ignored() {
        let acl = Acl::parse(&["garbage".into(), "deny x -> y".into(), "# 注释".into()]);
        assert!(acl.is_empty());
        assert!(acl.allows(ip("1.1.1.1"), ip("2.2.2.2")));
    }
}
