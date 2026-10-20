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

/// 下载 + 校验 + 合并 + 保存。progress(描述, 已完成条目数, 总条目数, 当前条目下载进度 0..1)
pub fn apply(
    base: &str,
    client: &Path,
    c: &mut Container,
    plan: &Plan,
    progress: &mut dyn FnMut(&str, usize, usize, f32),
) -> Result<l1pak::Report, String> {
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{}/", base)
    };

    let mut patches: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut additions: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let total = plan.to_download.len();
    for (i, e) in plan.to_download.iter().enumerate() {
        progress(&format!("下载 {}", e.name), i, total, 0.0);
        let url = format!("{}text/{}", base, url_encode(&e.name));
        let desc = format!("下载 {}", e.name);
        let data = http::get_with_progress(&url, MAX_ENTRY, Some(&mut |got: usize, t: usize| {
            let frac = if t > 0 {
                (got as f32 / t as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            progress(&desc, i, total, frac);
        }))?;
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
        if e.is_add() {
            if c.index_of(&e.name).is_some() {
                // 幂等：重跑时条目已在，内容一致就跳过，不一致按替换处理
                patches.insert(e.name.clone(), data);
            } else {
                additions.insert(e.name.clone(), data);
            }
            continue;
        }
        if c.index_of(&e.name).is_none() {
            return Err(format!("客户端容器里没有条目 {}", e.name));
        }
        patches.insert(e.name.clone(), data);
    }

    // 合并前备份上一版容器（单槽，失败可回滚）
    let bdir = client.join("backup_l1j");
    let _ = std::fs::create_dir_all(&bdir);
    let _ = std::fs::copy(client.join("Text.pak"), bdir.join("Text.pak.bak"));
    let _ = std::fs::copy(client.join("Text.idx"), bdir.join("Text.idx.bak"));

    progress("合并到 Text.pak", total, total, 1.0);
    let mut rep = c.replace(&patches)?;
    if !additions.is_empty() {
        let rep2 = c.add(&additions)?;
        rep.added = rep2.added;
        rep.pak_new = rep2.pak_new;
        rep.bytes_appended += rep2.bytes_appended;
        rep.idx_changed = true;
    }
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

/// 回滚到上一次更新的容器（backup_l1j/）
pub fn rollback(client: &Path) -> Result<(), String> {
    let bdir = client.join("backup_l1j");
    for n in ["Text.pak", "Text.idx"] {
        let src = bdir.join(format!("{}.bak", n));
        if !src.is_file() {
            return Err(format!("没有备份：{}", src.display()));
        }
        std::fs::copy(&src, client.join(n)).map_err(|e| format!("回滚 {} 失败: {}", n, e))?;
    }
    Ok(())
}

/// 容器完整性检查（首次启动 / 排查 QQ 传输损坏）
pub fn verify_container(c: &Container) -> Result<usize, String> {
    let mut bad = 0usize;
    for e in &c.entries {
        if e.off < 0 || (e.off as usize).saturating_add(e.size.max(0) as usize) > c.pak.len() {
            bad += 1;
        }
    }
    if bad > 0 {
        Err(format!("容器有 {} 个条目越界，可能文件损坏", bad))
    } else {
        Ok(c.entries.len())
    }
}
