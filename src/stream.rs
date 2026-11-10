//! 统一的流类型，以及可选的「压缩 + 加密」记录层。
//!
//! 分层顺序（自下而上）：
//! `TCP -> TLS -> WebSocket -> [压缩+AEAD 记录层] -> smux -> 业务流`
//!
//! 记录层用两个后台任务把「明文流」和「加密流」桥接起来，
//! 这样上层（smux）拿到的就是一个普通的 `AsyncRead + AsyncWrite`。

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::FrameCipher;

/// 记录层单块明文大小
const CHUNK: usize = 32 * 1024;
/// 单帧解压后允许的最大字节数（防压缩炸弹）
const MAX_DECOMPRESSED: usize = 4 * 1024 * 1024;

/// 当前端在连接中的角色，用来给 AEAD nonce 加方向前缀。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

impl Side {
    fn out_direction(self) -> u8 {
        match self {
            Side::Client => 0,
            Side::Server => 1,
        }
    }

    fn in_direction(self) -> u8 {
        1 - self.out_direction()
    }
}

/// 我们需要的流能力。
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// 装箱后的流（用于交给 smux，要求 `Sync`）。
pub type Stream = Box<dyn AsyncStream>;

/// 双向流的最小要求（用于 smux 产出的子流，不要求 `Sync`）。
pub trait AsyncStreamAny: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T> AsyncStreamAny for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// 装箱后的子流。
pub type AnyStream = Box<dyn AsyncStreamAny>;

/// 记录层参数。
#[derive(Debug, Clone, Copy, Default)]
pub struct RecordOptions {
    /// 是否启用 AEAD 加密（密钥已派生好时才有意义）
    pub encryption: bool,
    /// 是否启用 snappy 压缩
    pub compression: bool,
}

impl RecordOptions {
    pub fn enabled(&self) -> bool {
        self.encryption || self.compression
    }
}

/// 给底层连接套上记录层。
///
/// - `key == None` 表示不加密；
/// - `compression` 独立于加密生效。
pub fn wrap_stream<S>(
    inner: S,
    key: Option<[u8; 32]>,
    compression: bool,
    side: Side,
) -> Result<Stream>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let opts = RecordOptions {
        encryption: key.is_some(),
        compression,
    };
    if !opts.enabled() {
        return Ok(Box::new(inner));
    }

    let (user_side, crypto_side) = tokio::io::duplex(2 * CHUNK);
    let (mut crypto_r, mut crypto_w) = tokio::io::split(crypto_side);
    let (mut inner_r, mut inner_w) = tokio::io::split(inner);

    let cipher_out = key.map(|k| FrameCipher::new(k, side.out_direction()));
    let cipher_in = key.map(|k| FrameCipher::new(k, side.in_direction()));

    // 明文 -> (压缩) -> (加密) -> 底层
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        let mut cipher = cipher_out;
        loop {
            let n = match crypto_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &buf[..n];
            let payload = if compression {
                match snap::raw::Encoder::new().compress_vec(chunk) {
                    Ok(v) => v,
                    Err(_) => break,
                }
            } else {
                chunk.to_vec()
            };
            let payload = match cipher.as_mut() {
                Some(c) => match c.seal(&payload) {
                    Ok(v) => v,
                    Err(_) => break,
                },
                None => payload,
            };
            let mut frame = Vec::with_capacity(4 + payload.len());
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&payload);
            if inner_w.write_all(&frame).await.is_err() {
                break;
            }
            if inner_w.flush().await.is_err() {
                break;
            }
        }
        let _ = inner_w.shutdown().await;
    });

    // 底层 -> (解密) -> (解压) -> 明文
    tokio::spawn(async move {
        let mut cipher = cipher_in;
        let mut len_buf = [0u8; 4];
        loop {
            if crate::util::read_full(&mut inner_r, &mut len_buf)
                .await
                .unwrap_or(0)
                != 4
            {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len == 0 || len > crate::crypto::MAX_FRAME {
                break;
            }
            let mut payload = vec![0u8; len];
            if crate::util::read_full(&mut inner_r, &mut payload)
                .await
                .unwrap_or(0)
                != len
            {
                break;
            }
            let payload = match cipher.as_mut() {
                Some(c) => match c.open(&payload) {
                    Ok(v) => v,
                    Err(_) => break,
                },
                None => payload,
            };
            let data = if compression {
                // 先看声明的解压长度，避免小帧解压成几百 MB/几 GB。
                match snap::raw::decompress_len(&payload) {
                    Ok(n) if n <= MAX_DECOMPRESSED => {}
                    _ => break,
                }
                match snap::raw::Decoder::new().decompress_vec(&payload) {
                    Ok(v) => v,
                    Err(_) => break,
                }
            } else {
                payload
            };
            if crypto_w.write_all(&data).await.is_err() {
                break;
            }
            if crypto_w.flush().await.is_err() {
                break;
            }
        }
        let _ = crypto_w.shutdown().await;
    });

    Ok(Box::new(user_side))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_key;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn roundtrip(encrypt: bool, compress: bool) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let key = if encrypt {
            Some(derive_key("token", "salt").unwrap())
        } else {
            None
        };
        let mut sa = wrap_stream(a, key, compress, Side::Client).unwrap();
        let mut sb = wrap_stream(b, key, compress, Side::Server).unwrap();

        let payload = b"trairi record layer test payload".repeat(1000);
        let p2 = payload.clone();
        let writer = tokio::spawn(async move {
            sa.write_all(&p2).await.unwrap();
            sa.flush().await.unwrap();
            sa.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        sb.read_to_end(&mut got).await.unwrap();
        writer.await.unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn plain_passthrough() {
        roundtrip(false, false).await;
    }

    #[tokio::test]
    async fn encrypted_only() {
        roundtrip(true, false).await;
    }

    #[tokio::test]
    async fn compressed_only() {
        roundtrip(false, true).await;
    }

    #[tokio::test]
    async fn encrypted_and_compressed() {
        roundtrip(true, true).await;
    }
}
