//! 命令行接口：`trairi run -c cfg.yaml`、`trairi server -c ...`、`trairi client -c ...`

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Mode;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeArg {
    Server,
    Client,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Server => Mode::Server,
            ModeArg::Client => Mode::Client,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "trairi",
    version,
    about = "Trairi —— 单二进制内网穿透工具（server/client 二合一，配置决定角色）",
    long_about = None,
)]
pub struct Cli {
    /// 配置文件路径（.yaml / .yml，也兼容 .json）
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// 覆盖配置文件里的 mode
    #[arg(long, global = true, value_enum, value_name = "MODE")]
    pub mode: Option<ModeArg>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 按配置文件里的 mode 运行
    Run {
        /// 配置文件
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// 以服务端身份运行
    Server {
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// 以客户端身份运行
    Client {
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// 只校验配置文件
    Validate {
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// 打印版本信息
    Version,
    /// 一条命令加入组网（不需要配置文件）
    ///
    /// 例：trairi up --server 1.2.3.4:56000 --token xxx --ip 10.144.144.2
    Up {
        /// 服务端地址 host:port
        #[arg(long, value_name = "HOST:PORT")]
        server: String,
        /// 与服务端一致的 token
        #[arg(long, default_value = "", value_name = "TOKEN")]
        token: String,
        /// 本机虚拟 IP（留空由服务端分配）
        #[arg(long, default_value = "", value_name = "IP")]
        ip: String,
        /// 网络名（默认 trairi）
        #[arg(long, default_value = "trairi", value_name = "NAME")]
        network: String,
        /// 网络密钥（默认与 token 相同）
        #[arg(long, default_value = "", value_name = "SECRET")]
        secret: String,
        /// 虚拟网卡名（留空用默认）
        #[arg(long, default_value = "", value_name = "IFACE")]
        interface: String,
    },
    /// 组网工具（查看状态 / 清理残留网卡）
    Overlay {
        #[command(subcommand)]
        action: OverlayAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum OverlayAction {
    /// 显示 overlay 配置摘要
    Status {
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// 清理残留的虚拟网卡（连同它上面的路由）
    Cleanup {
        /// 网卡名，默认取配置文件里的 overlay.interface
        #[arg(short, long, value_name = "IFACE")]
        interface: Option<String>,
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
}

impl Cli {
    /// 取出这次要用到的配置文件路径。
    pub fn config_path(&self) -> Option<&PathBuf> {
        match &self.command {
            Some(Command::Run { config })
            | Some(Command::Server { config })
            | Some(Command::Client { config })
            | Some(Command::Validate { config }) => config.as_ref().or(self.config.as_ref()),
            Some(Command::Overlay { action }) => match action {
                OverlayAction::Status { config } | OverlayAction::Cleanup { config, .. } => {
                    config.as_ref().or(self.config.as_ref())
                }
            },
            _ => self.config.as_ref(),
        }
    }

    /// 子命令隐含的 mode。
    pub fn mode_from_command(&self) -> Option<Mode> {
        match &self.command {
            Some(Command::Server { .. }) => Some(Mode::Server),
            Some(Command::Client { .. }) => Some(Mode::Client),
            _ => self.mode.map(Mode::from),
        }
    }

    /// 命令行 mode 的优先级：子命令 > --mode。
    pub fn explicit_mode(&self) -> Option<Mode> {
        match &self.command {
            Some(Command::Server { .. }) => Some(Mode::Server),
            Some(Command::Client { .. }) => Some(Mode::Client),
            _ => self.mode.map(Mode::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_server_subcommand() {
        let cli = Cli::parse_from(["trairi", "server", "-c", "s.yaml"]);
        assert_eq!(cli.explicit_mode(), Some(Mode::Server));
        assert_eq!(cli.config_path().unwrap().to_str().unwrap(), "s.yaml");
    }

    #[test]
    fn parse_global_mode() {
        let cli = Cli::parse_from(["trairi", "run", "-c", "c.yaml", "--mode", "client"]);
        assert_eq!(cli.explicit_mode(), Some(Mode::Client));
    }

    #[test]
    fn config_falls_back_to_global() {
        let cli = Cli::parse_from(["trairi", "-c", "x.yaml", "client"]);
        assert_eq!(cli.explicit_mode(), Some(Mode::Client));
        assert_eq!(cli.config_path().unwrap().to_str().unwrap(), "x.yaml");
    }
}
