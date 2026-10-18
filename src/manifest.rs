//! 更新清单与 Ed25519 验签
//!
//! 签名对象是 **manifest.json 的原始字节**，签名单独放 `manifest.sig`（128 个 hex 字符）。
//! 这样不需要任何"规范化 JSON"约定，Python 侧写出的字节是什么，就签什么。

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// 容器内条目名（如 boss1-h.html）
    pub name: String,
    /// 明文长度
    pub size: u64,
    /// 明文的 SHA-256（hex）
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Unsupported {
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: u32,
    #[serde(default)]
    pub container: String,
    pub version: String,
    #[serde(default)]
    pub created: Option<String>,
    #[serde(default)]
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub unsupported: Option<Unsupported>,
}

impl Manifest {
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(raw).map_err(|e| format!("manifest 解析失败: {}", e))
    }
}

pub fn parse_public_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes = hex_to_bytes(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!("公钥长度应为 32 字节，实际 {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("公钥非法: {}", e))
}

/// 用公钥验证 `raw_manifest`（原始字节）上的签名
pub fn verify(raw_manifest: &[u8], sig_hex: &str, pk: &VerifyingKey) -> Result<(), String> {
    let sig_bytes = hex_to_bytes(sig_hex.trim())?;
    if sig_bytes.len() != 64 {
        return Err(format!("签名长度应为 64 字节，实际 {}", sig_bytes.len()));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&arr);
    pk.verify(raw_manifest, &signature)
        .map_err(|_| "清单签名校验失败（可能被篡改）".to_string())
}

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex 长度必须为偶数".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or("hex 含非法字符")? as u8;
        let lo = (b[i + 1] as char).to_digit(16).ok_or("hex 含非法字符")? as u8;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn verify_roundtrip() {
        let (sk, vk) = keypair();
        let raw = br#"{"schema":1,"version":"v1","entries":[]}"#;
        let sig = sk.sign(raw);
        assert!(verify(raw, &bytes_to_hex(&sig.to_bytes()), &vk).is_ok());
    }

    #[test]
    fn reject_tampered() {
        let (sk, vk) = keypair();
        let raw = br#"{"schema":1,"version":"v1","entries":[]}"#;
        let sig = sk.sign(raw);
        let mut bad = raw.to_vec();
        bad[10] ^= 0x01;
        assert!(verify(&bad, &bytes_to_hex(&sig.to_bytes()), &vk).is_err());
    }

    #[test]
    fn parse_manifest() {
        let raw = br#"{"schema":1,"container":"Text","version":"2026101901",
            "entries":[{"name":"a.html","size":5,"sha256":"aa"}]}"#;
        let m = Manifest::parse(raw).unwrap();
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].name, "a.html");
    }
}
