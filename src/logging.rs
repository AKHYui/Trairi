//! 日志初始化：控制台 + 可选的文件（按天滚动）。

use std::path::Path;

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogConfig;

/// 初始化全局日志。重复调用不会 panic。
pub fn init(cfg: &LogConfig) -> Result<()> {
    let level = if cfg.level.is_empty() {
        "info".to_string()
    } else {
        cfg.level.clone()
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let console = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(true);

    if cfg.file.is_empty() {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(console)
            .try_init();
        return Ok(());
    }

    let path = Path::new(&cfg.file);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let prefix = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "trairi.log".to_string());
    std::fs::create_dir_all(dir).with_context(|| format!("创建日志目录失败: {}", dir.display()))?;

    let appender = tracing_appender::rolling::daily(dir, prefix);
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);
    // 让后台写线程常驻
    Box::leak(Box::new(guard));

    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(console)
        .with(file_layer)
        .try_init();
    Ok(())
}
