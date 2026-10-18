//! 与 Python 版逐字节对拍：decode / encode 必须与 vectors.json 完全一致

use base64::Engine;
use l1pak::cipher;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    vectors: std::vec::Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    size: usize,
    cipher_only: bool,
    cipher_sha256: String,
    #[serde(default)]
    plain_sha256: Option<String>,
    #[serde(default)]
    cipher_b64: Option<String>,
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn vectors_match_python() {
    let raw = include_str!("vectors.json");
    let doc: Vectors = serde_json::from_str(raw).expect("vectors.json 解析失败");

    let mut checked = 0;
    let mut skipped = 0;
    for v in &doc.vectors {
        let Some(b64) = &v.cipher_b64 else {
            skipped += 1;
            continue;
        };
        let cipher_bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("base64 解码失败");
        assert_eq!(cipher_bytes.len(), v.size, "{}: 长度不符", v.name);
        assert_eq!(
            sha256_hex(&cipher_bytes),
            v.cipher_sha256,
            "{}: 密文指纹不符",
            v.name
        );

        let plain = cipher::decode(&cipher_bytes);
        if let Some(ph) = &v.plain_sha256 {
            assert_eq!(sha256_hex(&plain), *ph, "{}: 明文指纹不符", v.name);
        }
        let re_enc = cipher::encode(&plain);
        assert_eq!(re_enc, cipher_bytes, "{}: 重编码未逐字节复现", v.name);

        checked += 1;
    }

    println!("对拍通过 {} 条，跳过 {} 条（无样本）", checked, skipped);
    assert!(checked >= 15, "有效样本太少：{}", checked);
}

#[test]
fn roundtrip_arbitrary_lengths() {
    // 覆盖 0..=64 全部长度，重点验证 len%8 的余数处理
    for len in 0..=64usize {
        let data: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) & 0xFF) as u8).collect();
        let enc = cipher::encode(&data);
        assert_eq!(enc.len(), data.len(), "长度变化 len={}", len);
        let dec = cipher::decode(&enc);
        assert_eq!(dec, data, "回环失败 len={}", len);
    }
}

#[test]
fn block_independence() {
    // 单块改动不得影响其它块（原地写的地基）
    let data: Vec<u8> = (0..72).map(|i| (i as u8) ^ 0x5A).collect();
    let enc1 = cipher::encode(&data);
    let mut data2 = data.clone();
    data2[17] ^= 0x01; // 落在第 2 块
    let enc2 = cipher::encode(&data2);
    let diff: Vec<usize> = (0..enc1.len()).filter(|&i| enc1[i] != enc2[i]).collect();
    assert!(diff.iter().all(|&i| i / 8 == 17 / 8), "改动越块: {:?}", diff);
    assert!(diff.len() <= 8, "单字节改动影响超过 1 块: {:?}", diff);
}
