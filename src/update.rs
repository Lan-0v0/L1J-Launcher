//! 更新逻辑：拉清单 → 验签 → 比对 → 只下差异 → 校验 → 合并 → 写版本

use crate::http;
use crate::manifest::{self, Entry, FileEntry, Files, Manifest};
use l1pak::Container;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MAX_MANIFEST: usize = 2 * 1024 * 1024;
pub const MAX_ENTRY: usize = 8 * 1024 * 1024;
/// 文件通道单文件上限（反外挂组件 / 补丁 DLL 通常几 MB）
pub const MAX_FILE: usize = 64 * 1024 * 1024;
pub const VERSION_FILE: &str = "L1J_Update.json";
/// 文件备份根目录（相对客户端目录）
pub const BACKUP_DIR: &str = "backup_l1j";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalVersion {
    pub version: String,
    #[serde(default)]
    pub applied_at: String,
    #[serde(default)]
    pub entries: Vec<String>,
    /// 本次写入/删除的普通文件（相对路径）
    #[serde(default)]
    pub files: Vec<String>,
}

/// 文件通道的下载/删除计划
#[derive(Debug, Clone, Default)]
pub struct FilePlan {
    pub to_download: Vec<FileEntry>,
    pub to_delete: Vec<String>,
    pub skipped: usize,
}

impl FilePlan {
    pub fn is_empty(&self) -> bool {
        self.to_download.is_empty() && self.to_delete.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub version: String,
    pub to_download: Vec<Entry>,
    pub skipped: usize,
    pub files: FilePlan,
    /// 要从 Text.pak 里删掉的条目名
    pub to_remove: Vec<String>,
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

pub fn write_local_version(
    client: &Path,
    version: &str,
    entries: &[String],
    files: &[String],
) -> Result<(), String> {
    let v = LocalVersion {
        version: version.to_string(),
        applied_at: now_string(),
        entries: entries.to_vec(),
        files: files.to_vec(),
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

/// 比对本地容器 + 本地文件与清单，算出要下载/删除哪些
///
/// `c` 只在清单含 Text 条目时才需要（纯文件更新可以不加载容器）
pub fn plan(m: &Manifest, c: Option<&Container>, client: &Path) -> Result<Plan, String> {
    // 注意：清单里存的是**明文** SHA-256，容器里拿到的是密文，
    // 所以必须解出该条目再比（只解清单里列到的条目，几十 KB 级别，可忽略）
    let mut to_download = Vec::new();
    let mut skipped = 0usize;
    if !m.entries.is_empty() {
        let c = c.ok_or("清单含 Text 条目，但没有加载容器")?;
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
    }

    let f = m.files.clone().unwrap_or_default();
    let mut files = FilePlan::default();
    for e in &f.entries {
        let rel = safe_rel_path(&e.path)?;
        let dest = client.join(&rel);
        let same = match sha256_file(&dest) {
            Some((sz, h)) => sz == e.size && h == e.sha256,
            None => false,
        };
        if same {
            files.skipped += 1;
        } else {
            files.to_download.push(e.clone());
        }
    }
    for d in &f.deletes {
        let rel = safe_rel_path(d)?;
        if client.join(&rel).exists() {
            files.to_delete.push(d.clone());
        }
    }

    // Text 条目删除：只有本地确实存在才需要动手（删不到的忽略，保证幂等）
    let mut to_remove: Vec<String> = Vec::new();
    if !m.text_deletes.is_empty() {
        let c = c.ok_or("清单含 text_deletes，但没有加载容器")?;
        for name in &m.text_deletes {
            if c.index_of(name).is_some() {
                to_remove.push(name.clone());
            }
        }
    }

    Ok(Plan {
        version: m.version.clone(),
        to_download,
        skipped,
        files,
        to_remove,
    })
}

/// 相对路径白名单：只允许客户端目录内的普通相对路径
///
/// 拒绝：绝对路径、盘符、`..`、Windows 保留设备名、通配字符、结尾的点/空格、ADS(`:`)
pub fn safe_rel_path(raw: &str) -> Result<PathBuf, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("文件路径为空".into());
    }
    if raw.len() > 240 {
        return Err(format!("文件路径过长（>240）：{}", raw));
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(format!("不允许绝对路径：{}", raw));
    }
    if raw.contains(':') {
        return Err(format!("路径不允许含冒号（盘符/ADS）：{}", raw));
    }
    let mut out = PathBuf::new();
    for seg in raw.split(|c| c == '/' || c == '\\') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(format!("路径不允许上跳：{}", raw));
        }
        if seg.chars().any(|c| matches!(c, '*' | '?' | '"' | '<' | '>' | '|')) {
            return Err(format!("路径含非法字符：{}", raw));
        }
        if seg.ends_with('.') || seg.ends_with(' ') {
            return Err(format!("路径片段不允许以点/空格结尾：{}", raw));
        }
        let stem = seg.split('.').next().unwrap_or("");
        const RESERVED: [&str; 22] = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
            return Err(format!("路径含 Windows 保留名：{}", raw));
        }
        out.push(seg);
    }
    if out.as_os_str().is_empty() {
        return Err(format!("规范化后路径为空：{}", raw));
    }
    Ok(out)
}

/// 流式计算文件 (大小, sha256)；文件不存在/读不到返回 None
pub fn sha256_file(p: &Path) -> Option<(u64, String)> {
    let mut f = std::fs::File::open(p).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Some((total, h.finalize().iter().map(|b| format!("{:02x}", b)).collect()))
}

/// 目标文件是否被别的进程占用（独占打开一次，失败即视为占用）
#[cfg(windows)]
pub fn is_locked(p: &Path) -> bool {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *mut c_void,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    if !p.exists() {
        return false;
    }
    let w: Vec<u16> = p
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            0x8000_0000, // GENERIC_READ
            0,            // 不允许任何共享 → 有别的句柄就打不开
            std::ptr::null_mut(),
            3, // OPEN_EXISTING
            0x80,
            std::ptr::null_mut(),
        )
    };
    if h as isize == -1 {
        return true;
    }
    unsafe {
        CloseHandle(h);
    }
    false
}

#[cfg(not(windows))]
pub fn is_locked(_p: &Path) -> bool {
    false
}

/// 原子替换：先写临时文件，再用 MoveFileEx(REPLACE_EXISTING) 覆盖
fn replace_file(tmp: &Path, dest: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(existing: *const u16, newname: *const u16, flags: u32) -> i32;
        }
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
        let a: Vec<u16> = tmp
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let b: Vec<u16> = dest
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let ok = unsafe {
            MoveFileExW(
                a.as_ptr(),
                b.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            let _ = std::fs::remove_file(tmp);
            return Err(format!(
                "替换文件失败 {}: {}",
                dest.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(tmp, dest).map_err(|e| format!("替换文件失败 {}: {}", dest.display(), e))
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

    // 合并前备份上一版容器：只在本次更新窗口内存在。
    // 失败（下面的 `?` 提前返回）时备份留着可供人工救援；
    // 成功则立刻删掉 —— 玩家机器上不该常年压着 17MB。
    let bdir = client.join(BACKUP_DIR);
    let _ = std::fs::create_dir_all(&bdir);
    let _ = std::fs::copy(client.join("Text.pak"), bdir.join("Text.pak.bak"));
    let _ = std::fs::copy(client.join("Text.idx"), bdir.join("Text.idx.bak"));

    progress("合并到 Text.pak", total, total, 1.0);
    // 没有 replace 补丁时别白 clone 一遍 pak（几十 MB）
    let mut rep = if patches.is_empty() {
        l1pak::Report {
            pak_old: c.pak.len(),
            pak_new: c.pak.len(),
            ..Default::default()
        }
    } else {
        c.replace(&patches)?
    };
    if !additions.is_empty() {
        let rep2 = c.add(&additions)?;
        rep.added = rep2.added;
        rep.pak_new = rep2.pak_new;
        rep.bytes_appended += rep2.bytes_appended;
        rep.idx_changed = true;
    }
    if !plan.to_remove.is_empty() {
        let rep3 = c.remove(&plan.to_remove)?;
        rep.removed = rep3.removed;
        rep.idx_changed = true;
    }
    if let Err(e) = c.save(client) {
        // 半截 .tmp_new 由 save() 自己清。这里再判断容器到底有没有被改动：
        // 没改动的话备份没有任何救援价值，留着就是 17MB 垃圾（游戏占用时必然走到这条）。
        if container_unchanged(client, &bdir) {
            let _ = std::fs::remove_file(bdir.join("Text.pak.bak"));
            let _ = std::fs::remove_file(bdir.join("Text.idx.bak"));
            let _ = std::fs::remove_dir(&bdir);
        }
        return Err(format!("保存容器失败: {}", e));
    }

    let _ = std::fs::remove_file(bdir.join("Text.pak.bak"));
    let _ = std::fs::remove_file(bdir.join("Text.idx.bak"));
    let _ = std::fs::remove_dir(&bdir); // 目录空了才成功，非空忽略
    Ok(rep)
}

/// 保存失败后判断容器是否真的没被改动（决定备份还有没有保留价值）
///
/// rename 是原子的，所以正常情况下失败发生在改名之前，原文件一个字节没动；
/// 只有「pak 改名成功、idx 改名失败」这一种极端情况才会真的改到容器，
/// 那时必须把备份留给玩家手工还原。
fn container_unchanged(client: &Path, bdir: &Path) -> bool {
    for name in ["Text.pak", "Text.idx"] {
        let cur = match std::fs::read(client.join(name)) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let bak = match std::fs::read(bdir.join(format!("{}.bak", name))) {
            Ok(v) => v,
            Err(_) => return false, // 备份不完整，别乱删
        };
        if l1pak::Container::sha256_hex(&cur) != l1pak::Container::sha256_hex(&bak) {
            return false;
        }
    }
    true
}

/// 清理更新遗留的备份目录
///
/// 只在「本地已经和清单一致」时调用 —— 那种状态下上次更新必然是成功的，
/// 备份没有任何存在价值，整个 `backup_l1j/` 直接删掉。
/// 这样即使某个玩家的更新中途失败留下了残留，下次成功启动也会自动扫干净。
pub fn cleanup_backup(client: &Path) {
    let root = client.join(BACKUP_DIR);
    if !root.is_dir() {
        return;
    }
    let _ = std::fs::remove_dir_all(&root);
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
                    op: None,
                },
                Entry {
                    name: "b.html".into(),
                    size: 3,
                    sha256: "00".into(),
                    op: None,
                },
            ],
            files: None,
            launcher: None,
            text_deletes: vec![],
            unsupported: None,
        };
        let p = plan(&m, Some(&c), &dir).unwrap();
        assert_eq!(p.skipped, 1, "a.html 应命中本地");
        assert_eq!(p.to_download.len(), 1);
        assert_eq!(p.to_download[0].name, "b.html");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 造一个最小容器（条目按传入顺序写，不做名称排序）
    fn tiny_container(items: &[(&str, &[u8])]) -> Container {
        let mut pak = Vec::new();
        let mut body = Vec::new();
        for (name, data) in items {
            let off = pak.len() as i32;
            let enc = l1pak::cipher::encode(data);
            pak.extend_from_slice(&enc);
            let mut rec = [0u8; 28];
            rec[0..4].copy_from_slice(&off.to_le_bytes());
            rec[4..4 + name.len()].copy_from_slice(name.as_bytes());
            rec[24..28].copy_from_slice(&(enc.len() as i32).to_le_bytes());
            body.extend_from_slice(&rec);
        }
        let mut idx = Vec::new();
        idx.extend_from_slice(&(items.len() as u32).to_le_bytes());
        idx.extend_from_slice(&l1pak::cipher::encode(&body));
        Container::from_parts(idx, pak).expect("造容器失败")
    }

    #[test]
    fn plan_marks_text_deletes_only_when_present() {
        let dir = std::env::temp_dir().join("l1launcher_textdel_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let c = tiny_container(&[("keep.html", b"K"), ("gone.html", b"G")]);
        let m = Manifest {
            schema: 1,
            container: "Text".into(),
            version: "vdel".into(),
            created: None,
            entries: vec![],
            files: None,
            launcher: None,
            text_deletes: vec!["gone.html".into(), "never.html".into()],
            unsupported: None,
        };

        let p = plan(&m, Some(&c), &dir).unwrap();
        // 只有本地存在的才进待删列表；删不到的忽略，保证重复发同一份清单不报错
        assert_eq!(p.to_remove, vec!["gone.html".to_string()]);
        assert!(p.to_download.is_empty());
        assert!(!p.to_remove.iter().any(|n| n == "keep.html"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_backup_removes_whole_dir() {
        let dir = std::env::temp_dir().join("l1launcher_cleanup_backup_test");
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.join(BACKUP_DIR);
        std::fs::create_dir_all(root.join("files").join("v1")).unwrap();
        std::fs::create_dir_all(root.join("files").join("v2")).unwrap();
        std::fs::write(root.join("Text.pak.bak"), b"x").unwrap();
        std::fs::write(root.join("Text.idx.bak"), b"y").unwrap();
        std::fs::write(root.join("files").join("v1/a.txt"), b"1").unwrap();
        std::fs::write(root.join("files").join("v2/a.txt"), b"2").unwrap();

        cleanup_backup(&dir);

        assert!(!root.exists(), "backup_l1j 整个目录都应被删掉");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_files_restores_and_removes() {
        let dir = std::env::temp_dir().join("l1launcher_rollback_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"new").unwrap();
        std::fs::write(dir.join("sub/b.txt"), b"created").unwrap();

        let vdir = dir.join(BACKUP_DIR).join("files").join("v1");
        std::fs::create_dir_all(vdir.join("sub")).unwrap();
        std::fs::write(vdir.join("a.txt"), b"old").unwrap();
        let meta = serde_json::json!({"version":"v1","items":[
            {"path":"a.txt","existed":true},
            {"path":"sub/b.txt","existed":false}
        ]});
        std::fs::write(
            vdir.join("_files.json"),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();

        let n = rollback_files(&dir).unwrap();
        assert_eq!(n, 2, "应处理两条备份记录");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"old");
        assert!(!dir.join("sub/b.txt").exists(), "更新时新建的文件应被删掉");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_path_rejects_escapes() {
        for bad in [
            "",
            "/etc/passwd",
            "\\windows\\system32",
            "../outside.txt",
            "a/../../b.txt",
            "C:/win.ini",
            "file.txt:ads",
            "con.txt",
            "a/*.dll",
            "dir./x.txt",
            "x /y.txt",
        ] {
            assert!(safe_rel_path(bad).is_err(), "应拒绝: {:?}", bad);
        }
        for ok in [
            "antibot/ac.dll",
            "sub/dir/readme.txt",
            "./a.bin",
            "TW13032701.bin",
            "配置/说明.txt",
        ] {
            assert!(safe_rel_path(ok).is_ok(), "应接受: {:?}", ok);
        }
        assert_eq!(
            safe_rel_path("a/./b//c.txt").unwrap(),
            PathBuf::from("a/b/c.txt")
        );
    }

    #[test]
    fn plan_files_detects_create_replace_delete() {
        let dir = std::env::temp_dir().join("l1launcher_fileplan_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("same.dll"), b"same").unwrap();
        std::fs::write(dir.join("old.dll"), b"v1").unwrap();
        std::fs::write(dir.join("gone.txt"), b"bye").unwrap();

        let files = Files {
            base: None,
            entries: vec![
                FileEntry {
                    path: "same.dll".into(),
                    size: 4,
                    sha256: sha256_hex(b"same"),
                },
                FileEntry {
                    path: "old.dll".into(),
                    size: 2,
                    sha256: sha256_hex(b"v2"),
                },
                FileEntry {
                    path: "sub/new.dll".into(),
                    size: 3,
                    sha256: sha256_hex(b"new"),
                },
            ],
            deletes: vec!["gone.txt".into(), "not-there.txt".into()],
        };
        let m = Manifest {
            schema: 2,
            container: "Text".into(),
            version: "vtest".into(),
            created: None,
            entries: vec![],
            files: Some(files),
            launcher: None,
            text_deletes: vec![],
            unsupported: None,
        };
        // 空容器：只要 entry 列表为空即可
        let mut pak = Vec::new();
        let mut body = Vec::new();
        let enc = l1pak::cipher::encode(b"x");
        pak.extend_from_slice(&enc);
        let mut rec = [0u8; 28];
        rec[0..4].copy_from_slice(&0i32.to_le_bytes());
        rec[4..13].copy_from_slice(b"x.html\0\0\0");
        rec[24..28].copy_from_slice(&(enc.len() as i32).to_le_bytes());
        body.extend_from_slice(&rec);
        let mut idx = (1u32).to_le_bytes().to_vec();
        idx.extend_from_slice(&l1pak::cipher::encode(&body));
        let c = Container::from_parts(idx, pak).unwrap();

        let p = plan(&m, Some(&c), &dir).unwrap();
        assert_eq!(p.files.skipped, 1, "same.dll 应命中本地");
        assert_eq!(p.files.to_download.len(), 2, "old.dll + sub/new.dll");
        assert_eq!(p.files.to_delete, vec!["gone.txt".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_files_writes_backs_up_and_deletes() {
        let dir = std::env::temp_dir().join("l1launcher_fileapply_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("keep.dll"), b"old-content").unwrap();
        std::fs::write(dir.join("kill.txt"), b"to-delete").unwrap();

        // 本地起一个最小 HTTP 服务太麻烦：这里直接走 file:// 不支持，
        // 所以把 apply_files 的下载部分交给 e2e 测试，这里只测备份/替换/删除的落盘逻辑，
        // 通过 manual 方式模拟已下载数据（复用 replace_file 与备份分支）。
        let bdir = dir.join(BACKUP_DIR).join("files").join("vtest");
        std::fs::create_dir_all(&bdir).unwrap();
        std::fs::copy(dir.join("keep.dll"), bdir.join("keep.dll")).unwrap();
        let mut tmp_os = dir.join("keep.dll").into_os_string();
        tmp_os.push(".l1jtmp");
        let tmp = PathBuf::from(tmp_os);
        std::fs::write(&tmp, b"new-content").unwrap();
        replace_file(&tmp, &dir.join("keep.dll")).unwrap();
        assert_eq!(std::fs::read(dir.join("keep.dll")).unwrap(), b"new-content");
        assert_eq!(std::fs::read(bdir.join("keep.dll")).unwrap(), b"old-content");
        assert!(!tmp.exists(), "临时文件应已被移走");

        std::fs::copy(dir.join("kill.txt"), bdir.join("kill.txt")).unwrap();
        std::fs::remove_file(dir.join("kill.txt")).unwrap();
        assert!(!dir.join("kill.txt").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// 文件通道执行结果
#[derive(Debug, Clone, Default)]
pub struct FileReport {
    pub written: usize,
    pub deleted: usize,
    pub backup: Option<String>,
}

/// 版本号里只允许安全字符，避免备份目录被版本串带偏
fn sanitize_version(v: &str) -> String {
    let s: String = v
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' })
        .collect();
    if s.is_empty() {
        "unknown".to_string()
    } else {
        s
    }
}

/// 写文件通道：下载 → 校验 → 占用检测 → 备份 → 原子替换；再处理删除
pub fn apply_files(
    base: &str,
    client: &Path,
    files: &Files,
    plan: &FilePlan,
    version: &str,
    progress: &mut dyn FnMut(&str, usize, usize, f32),
) -> Result<FileReport, String> {
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{}/", base)
    };
    let total = plan.to_download.len() + plan.to_delete.len();
    let mut report = FileReport::default();
    if total == 0 {
        return Ok(report);
    }

    let bdir = client
        .join(BACKUP_DIR)
        .join("files")
        .join(sanitize_version(version));
    std::fs::create_dir_all(&bdir)
        .map_err(|e| format!("建备份目录失败 {}: {}", bdir.display(), e))?;
    let mut records: Vec<(String, bool)> = Vec::new();

    for (i, e) in plan.to_download.iter().enumerate() {
        let rel = safe_rel_path(&e.path)?;
        let dest = client.join(&rel);
        let desc = format!("下载 {}", e.path);
        progress(&desc, i, total, 0.0);
        let url = format!("{}{}{}", base, files.base_dir(), e.sha256);
        let data = http::get_with_progress(&url, MAX_FILE, Some(&mut |got: usize, t: usize| {
            let frac = if t > 0 {
                (got as f32 / t as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            progress(&desc, i, total, frac);
        }))?;
        if data.len() as u64 != e.size {
            return Err(format!(
                "文件大小不符 {}: 期望 {} 实际 {}",
                e.path,
                e.size,
                data.len()
            ));
        }
        if sha256_hex(&data) != e.sha256 {
            return Err(format!("文件哈希不符 {}", e.path));
        }
        if is_locked(&dest) {
            return Err(format!(
                "文件被占用，请先关闭游戏/登录器再更新：{}",
                e.path
            ));
        }

        let existed = dest.is_file();
        if existed {
            let b = bdir.join(&rel);
            if let Some(p) = b.parent() {
                std::fs::create_dir_all(p)
                    .map_err(|err| format!("建备份子目录失败 {}: {}", p.display(), err))?;
            }
            std::fs::copy(&dest, &b)
                .map_err(|err| format!("备份失败 {}: {}", e.path, err))?;
        }
        records.push((e.path.clone(), existed));

        if let Some(p) = dest.parent() {
            std::fs::create_dir_all(p)
                .map_err(|err| format!("建目录失败 {}: {}", p.display(), err))?;
        }
        let mut tmp_os = dest.clone().into_os_string();
        tmp_os.push(".l1jtmp");
        let tmp = PathBuf::from(tmp_os);
        std::fs::write(&tmp, &data).map_err(|err| format!("写入临时文件失败 {}: {}", e.path, err))?;
        replace_file(&tmp, &dest)?;
        report.written += 1;
        progress(&desc, i, total, 1.0);
    }

    for (k, raw) in plan.to_delete.iter().enumerate() {
        let rel = safe_rel_path(raw)?;
        let dest = client.join(&rel);
        progress(
            &format!("删除 {}", raw),
            plan.to_download.len() + k,
            total,
            1.0,
        );
        if !dest.is_file() {
            continue;
        }
        if is_locked(&dest) {
            return Err(format!(
                "文件被占用，请先关闭游戏/登录器再更新：{}",
                raw
            ));
        }
        let b = bdir.join(&rel);
        if let Some(p) = b.parent() {
            std::fs::create_dir_all(p)
                .map_err(|err| format!("建备份子目录失败 {}: {}", p.display(), err))?;
        }
        std::fs::copy(&dest, &b).map_err(|err| format!("备份失败 {}: {}", raw, err))?;
        records.push((raw.clone(), true));
        std::fs::remove_file(&dest).map_err(|err| format!("删除失败 {}: {}", raw, err))?;
        report.deleted += 1;
    }

    let items: Vec<serde_json::Value> = records
        .iter()
        .map(|(p, existed)| serde_json::json!({"path": p, "existed": existed}))
        .collect();
    let meta = serde_json::json!({"version": version, "items": items});
    let _ = std::fs::write(
        bdir.join("_files.json"),
        serde_json::to_string_pretty(&meta).unwrap_or_default(),
    );
    report.backup = Some(bdir.to_string_lossy().to_string());
    // 与容器备份一致：成功即清，游戏目录里不留任何备份。
    // 失败路径都在上面的 `?` / `return Err` 提前返回，走不到这里，备份会留着救人。
    let _ = std::fs::remove_dir_all(&bdir);
    let ffiles = client.join(BACKUP_DIR).join("files");
    let _ = std::fs::remove_dir(&ffiles);
    let _ = std::fs::remove_dir(&client.join(BACKUP_DIR));
    Ok(report)
}

/// 回滚到上一次更新的容器（backup_l1j/）
/// 回滚文件通道：取最新的版本备份目录回放（existed=true 拷回，false 删掉）
///
/// 返回实际处理的条目数；没有备份时返回 0（不算错误）。
pub fn rollback_files(client: &Path) -> Result<usize, String> {
    let froot = client.join(BACKUP_DIR).join("files");
    if !froot.is_dir() {
        return Ok(0);
    }
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&froot)
        .map_err(|e| format!("读备份目录失败 {}: {}", froot.display(), e))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    let last = match dirs.last() {
        Some(d) => d,
        None => return Ok(0),
    };
    let txt = match std::fs::read_to_string(last.join("_files.json")) {
        Ok(t) => t,
        Err(_) => return Ok(0),
    };
    let v: serde_json::Value =
        serde_json::from_str(&txt).map_err(|e| format!("备份清单解析失败: {}", e))?;
    let mut n = 0usize;
    for item in v["items"].as_array().cloned().unwrap_or_default() {
        let raw = item["path"].as_str().unwrap_or("");
        if raw.is_empty() {
            continue;
        }
        let existed = item["existed"].as_bool().unwrap_or(true);
        let rel = safe_rel_path(raw)?;
        let dest = client.join(&rel);
        if existed {
            let src = last.join(&rel);
            if src.is_file() {
                if let Some(p) = dest.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                std::fs::copy(&src, &dest).map_err(|e| format!("回滚文件 {} 失败: {}", raw, e))?;
                n += 1;
            }
        } else {
            let _ = std::fs::remove_file(&dest);
            n += 1;
        }
    }
    Ok(n)
}

/// 回滚到上一次更新（容器 + 文件）
pub fn rollback(client: &Path) -> Result<(), String> {
    let bdir = client.join(BACKUP_DIR);

    // 1) 文件通道
    rollback_files(client)?;

    // 2) 容器
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
