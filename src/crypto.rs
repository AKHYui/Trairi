//! 连接加密与认证原语。
//!
//! 设计：
//! 1. 客户端先发一帧明文 `HelloRequest`，带随机盐和 HMAC 签名；
//! 2. 双方用 `HKDF-SHA256(token, salt, "trairi/1 aead")` 派生 32 字节密钥；
//! 3. 之后所有字节都以 ChaCha20-Poly1305 记录帧传输。

use anyhow::{Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// 单帧明文上限（也是读取时的上限校验）
pub const MAX_FRAME: usize = 64 * 1024;

const HKDF_INFO: &[u8] = b"trairi/1 aead";

/// 计算 HelloRequest 的 HMAC-SHA256，十六进制小写。
///
/// 覆盖完整握手字段，避免攻击者只改 `use_encryption` / `use_compression`
/// 等字段而签名仍然有效（降级攻击）。
pub fn sign(
    token: &str,
    salt: &str,
    timestamp: i64,
    version: u32,
    use_encryption: bool,
    use_compression: bool,
    client: &str,
) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(token.as_bytes()).expect("hmac 接受任意长度密钥");
    mac.update(b"trairi-hello-v2\0");
    mac.update(&version.to_be_bytes());
    mac.update(&(salt.len() as u32).to_be_bytes());
    mac.update(salt.as_bytes());
    mac.update(&timestamp.to_be_bytes());
    mac.update(&[use_encryption as u8, use_compression as u8]);
    mac.update(&(client.len() as u32).to_be_bytes());
    mac.update(client.as_bytes());
    let out = mac.finalize().into_bytes();
    out.iter().map(|b| format!("{b:02x}")).collect()
}

/// 常量时间校验签名。
#[allow(clippy::too_many_arguments)]
pub fn verify_sign(
    token: &str,
    salt: &str,
    timestamp: i64,
    version: u32,
    use_encryption: bool,
    use_compression: bool,
    client: &str,
    got: &str,
) -> bool {
    let expect = sign(
        token,
        salt,
        timestamp,
        version,
        use_encryption,
        use_compression,
        client,
    );
    let a = expect.as_bytes();
    let b = got.as_bytes();
    a.len() == b.len() && a.ct_eq(b).unwrap_u8() == 1
}

/// 由 token 与盐派生 AEAD 密钥。
pub fn derive_key(token: &str, salt: &str) -> Result<[u8; 32]> {
    if token.is_empty() {
        bail!("启用加密时必须配置 token");
    }
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), token.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| anyhow::anyhow!("密钥派生失败: {e}"))?;
    Ok(okm)
}

/// 一个方向上的计数器，用于生成不重复的 nonce。
///
/// 第 0 字节是方向前缀（0=客户端->服务端，1=服务端->客户端）。
/// 两个方向使用同一把 key 时，前缀保证 nonce 空间不相交。
fn nonce_of(counter: u64, direction: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = direction;
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// AEAD 记录帧的加解密器（调用方负责帧头长度）。
pub struct FrameCipher {
    cipher: ChaCha20Poly1305,
    direction: u8,
    send_counter: u64,
    recv_counter: u64,
}

impl FrameCipher {
    pub fn new(key: [u8; 32], direction: u8) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            direction,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_of(self.send_counter, self.direction);
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("加密计数器溢出"))?;
        self.cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| anyhow::anyhow!("加密失败: {e}"))
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = nonce_of(self.recv_counter, self.direction);
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("解密计数器溢出"))?;
        self.cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("解密失败（token 不一致或数据被篡改）"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_stable_and_verified() {
        let s = sign("secret", "abc", 1700000000, 2, true, false, "client");
        assert_eq!(s.len(), 64);
        assert!(verify_sign(
            "secret", "abc", 1700000000, 2, true, false, "client", &s
        ));
        assert!(!verify_sign(
            "secret2", "abc", 1700000000, 2, true, false, "client", &s
        ));
        assert!(!verify_sign(
            "secret", "abc", 1700000001, 2, true, false, "client", &s
        ));
        // 任意握手字段被改都必须失败
        assert!(!verify_sign(
            "secret", "abc", 1700000000, 2, false, false, "client", &s
        ));
        assert!(!verify_sign(
            "secret", "abc", 1700000000, 2, true, true, "client", &s
        ));
        assert!(!verify_sign(
            "secret", "abc", 1700000000, 2, true, false, "other", &s
        ));
    }

    #[test]
    fn key_derivation_requires_token() {
        assert!(derive_key("", "salt").is_err());
        let a = derive_key("t", "salt").unwrap();
        let b = derive_key("t", "salt").unwrap();
        let c = derive_key("t", "salt2").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn aead_roundtrip_and_tamper_detect() {
        let key = derive_key("token", "salt").unwrap();
        let mut enc = FrameCipher::new(key, 0);
        let mut dec = FrameCipher::new(key, 0);
        let msg = b"hello trairi";
        let ct = enc.seal(msg).unwrap();
        assert_ne!(&ct[..], &msg[..]);
        assert_eq!(dec.open(&ct).unwrap(), msg);

        // 计数器推进，nonce 不复用
        let ct2 = enc.seal(msg).unwrap();
        assert_eq!(dec.open(&ct2).unwrap(), msg);

        // 篡改一定失败
        let mut bad = ct.clone();
        bad[0] ^= 0xff;
        assert!(dec.open(&bad).is_err());
    }

    #[test]
    fn counter_and_direction_are_part_of_nonce() {
        assert_eq!(nonce_of(1, 0)[0], 0);
        assert_eq!(nonce_of(1, 1)[0], 1);
        assert_eq!(nonce_of(1, 0)[11], 1);
        assert_eq!(nonce_of(256, 0)[10], 1);
        assert_eq!(&nonce_of(1, 0)[..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn opposite_directions_do_not_reuse_nonce() {
        let key = derive_key("token", "salt").unwrap();
        let mut c2s = FrameCipher::new(key, 0);
        let mut s2c = FrameCipher::new(key, 1);
        // 相同的明文、相同的计数器 0，但因为方向前缀不同，密文必须不同。
        let a = c2s.seal(b"same plaintext").unwrap();
        let b = s2c.seal(b"same plaintext").unwrap();
        assert_ne!(a, b);

        // 用错误方向的 cipher 解不开
        let mut wrong = FrameCipher::new(key, 0);
        assert!(wrong.open(&b).is_err());
    }
}
