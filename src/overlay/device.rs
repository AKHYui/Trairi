//! 抽象出「IP 包收发设备」，方便用假设备做测试。

use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// 承载 IP 包的设备（真实 TUN 或测试用的内存设备）。
#[async_trait]
pub trait IpDevice: Send {
    /// 读一个完整的 IP 包，返回长度。
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// 写一个完整的 IP 包。
    async fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()>;
}

/// 真实的 TUN 虚拟网卡。
pub struct TunDevice {
    dev: tun::AsyncDevice,
}

impl TunDevice {
    pub fn new(dev: tun::AsyncDevice) -> Self {
        Self { dev }
    }
}

#[async_trait]
impl IpDevice for TunDevice {
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.read(buf).await
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        self.dev.write_all(pkt).await?;
        self.dev.flush().await
    }
}

/// 测试用的内存设备：外部把「内核发出的包」喂进来，也能观察「要写回内核的包」。
pub struct MockDevice {
    inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
}

/// 测试侧的操作柄。
pub struct MockHandle {
    /// 往虚拟网卡里塞一个包（模拟内核发出）
    pub feed: mpsc::Sender<Vec<u8>>,
    /// 从虚拟网卡里取一个包（模拟内核收到）
    pub drain: mpsc::Receiver<Vec<u8>>,
}

/// 创建一对 MockDevice / MockHandle。
pub fn mock_device() -> (MockDevice, MockHandle) {
    let (feed_tx, feed_rx) = mpsc::channel(64);
    let (drain_tx, drain_rx) = mpsc::channel(64);
    (
        MockDevice {
            inbound: feed_rx,
            outbound: drain_tx,
        },
        MockHandle {
            feed: feed_tx,
            drain: drain_rx,
        },
    )
}

#[async_trait]
impl IpDevice for MockDevice {
    async fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inbound.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        let _ = self.outbound.send(pkt.to_vec()).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_device_roundtrip() {
        let (mut dev, h) = mock_device();
        h.feed.send(vec![1, 2, 3]).await.unwrap();
        let mut buf = [0u8; 16];
        let n = dev.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3]);

        dev.write_packet(&[9, 9]).await.unwrap();
        drop(dev);
        let mut drain = h.drain;
        assert_eq!(drain.recv().await.unwrap(), vec![9, 9]);
    }
}
