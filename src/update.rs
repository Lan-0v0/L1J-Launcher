//! 更新逻辑：拉清单 → 验签 → 比对 → 只下差异 → 校验 → 合并 → 写版本

use crate::http;
use crate::manifest::{self, Entry, Manifest};
use l1pak::Container;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const MAX_MANIFEST: usize = 2 * 1024 * 1024;
pub const MAX_ENTRY: usize = 8 * 1024 * 1024;
pub const VERSION_FILE: &str = "L1J_Update.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalVersion {
    pub version: String,
    #[serde(default)]
    pub applied_at: String,
    #[serde(default)]
    pub entries: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub version: String,
    pub to_download: Vec<Entry>,
    pub skipped: usize,
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn read_local_version(client: &Path) -> Option<LocalVersion> {
    let p = client.join(VERSION_FILE);
    let txt = std::fs::read_to_string(p).ok()?;
    serde_json::from_str(&txt).ok()
}

pub fn write_local_version(client: &Path, version: &str, entries: &[String]) -> Result<(), String> {
    let v = LocalVersion {
        version: version.to_string(),
        applied_at: now_string(),
        entries: entries.to_vec(),
    };
    let p = client.join(VERSION_FILE);
    std::fs::write(&p, serde_json::to_string_pretty(&v).unwrap())
        .map_err(|e| format!("写版本文件失败 {}: {}", p.display(), e))
}

fn now_string() -> String {
    // 不引第三方时间库：用系统时间的 unix 秒，够用
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{}", d.as_secs()),
        Err(_) => String::new(),
    }
}

/// 拉取 manifest.json + manifest.sig 并验签
pub fn fetch_and_verify(base: &str, public_key_hex: &str) -> Result<Manifest, String> {
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{}/", base)
    };
    let raw = http::get(&format!("{}manifest.json", base), MAX_MANIFEST)?;
    let sig = http::get(&format!("{}manifest.sig", base), 4096)?;
    let sig_txt = String::from_utf8(sig).map_err(|_| "manifest.sig 不是文本".to_string())?;

    let pk = manifest::parse_public_key(public_key_hex)?;
    manifest::verify(&raw, &sig_txt, &pk)?;
    Manifest::parse(&raw)
}

/// 比对本地容器与清单，算出要下载哪些
pub fn plan(m: &Manifest, c: &Container) -> Plan {
    // 注意：清单里存的是**明文** SHA-256，容器里拿到的是密文，
    // 所以必须解出该条目再比（只解清单里列到的条目，几十 KB 级别，可忽略）
    let mut to_download = Vec::new();
    let mut skipped = 0usize;
    for e in &m.entries {
        let same = match c.plain_of(&e.name) {
            Some(p) => p.len() as u64 == e.size && sha256_hex(&p) == e.sha256,
            None => false,
        };
        if same {
            skipped += 1;
        } else {
            to_download.push(e.clone());
        }
    }
    Plan {
        version: m.version.clone(),
        to_download,
        skipped,
    }
}

/// 下载 + 校验 + 合并 + 保存。progress(描述, 已完成, 总数)
pub fn apply(
    base: &str,
    client: &Path,
    c: &mut Container,
    plan: &Plan,
    progress: &mut dyn FnMut(&str, usize, usize),
) -> Result<l1pak::Report, String> {
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{}/", base)
    };

    let mut patches: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let total = plan.to_download.len();
    for (i, e) in plan.to_download.iter().enumerate() {
        progress(&format!("下载 {}", e.name), i, total);
        let url = format!("{}text/{}", base, url_encode(&e.name));
        let data = http::get(&url, MAX_ENTRY)?;
        if data.len() as u64 != e.size {
            return Err(format!(
                "条目大小不符 {}: 期望 {} 实际 {}",
                e.name,
                e.size,
                data.len()
            ));
        }
        let h = sha256_hex(&data);
        if h != e.sha256 {
            return Err(format!("条目哈希不符 {}", e.name));
        }
        if !c.index_of(&e.name).is_some() {
            return Err(format!("客户端容器里没有条目 {}", e.name));
        }
        patches.insert(e.name.clone(), data);
    }

    progress("合并到 Text.pak", total, total);
    let rep = c.replace(&patches)?;
    c.save(client)
        .map_err(|e| format!("保存容器失败: {}", e))?;
    Ok(rep)
}

/// 条目名一般只含 ASCII，但稳妥起见做最小转义
fn url_encode(name: &str) -> String {
    let mut out = String::new();
    for b in name.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_basic() {
        assert_eq!(url_encode("boss1-h.html"), "boss1-h.html");
        assert_eq!(url_encode("a b.html"), "a%20b.html");
    }

    #[test]
    fn plan_detects_changes() {
        let dir = std::env::temp_dir().join("l1launcher_plan_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 构造一个只有一条目的容器
        let data = b"hello";
        let enc = l1pak::cipher::encode(data);
        let mut pak = enc.clone();
        let mut body = Vec::new();
        let mut rec = [0u8; 28];
        rec[0..4].copy_from_slice(&0i32.to_le_bytes());
        rec[4..4 + 9].copy_from_slice(b"a.html\0\0\0");
        rec[24..28].copy_from_slice(&(enc.len() as i32).to_le_bytes());
        body.extend_from_slice(&rec);
        let mut idx = (1u32).to_le_bytes().to_vec();
        idx.extend_from_slice(&l1pak::cipher::encode(&body));
        pak.truncate(enc.len());
        let c = Container::from_parts(idx, pak).unwrap();

        let m = Manifest {
            schema: 1,
            container: "Text".into(),
            version: "v1".into(),
            created: None,
            entries: vec![
                Entry {
                    name: "a.html".into(),
                    size: 5,
                    sha256: sha256_hex(data),
                },
                Entry {
                    name: "b.html".into(),
                    size: 3,
                    sha256: "00".into(),
                },
            ],
            unsupported: None,
        };
        let p = plan(&m, &c);
        assert_eq!(p.skipped, 1, "a.html 应命中本地");
        assert_eq!(p.to_download.len(), 1);
        assert_eq!(p.to_download[0].name, "b.html");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
