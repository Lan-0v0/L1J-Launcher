//! 登录器自更新：改名腾位（rename-then-replace）
//!
//! # 为什么不能复用 `update::apply_files`
//!
//! 那条路径对 `is_locked()` 命中是**直接返回错误**，而正在运行的自身 exe
//! 永远处于 locked 状态 ⇒ 把 exe 塞进 `files` 通道会让整单更新失败。
//! 自更新必须是独立分支，跳过占用检测、改用改名。
//!
//! # 为什么判定不用版本号
//!
//! 版本号靠人维护，早晚会忘（本仓库 `Cargo.toml` 就一直停在 0.1.0）。
//! 改成比对**自身 exe 的 sha256**：相等即最新，不等即需要更新。
//! 副作用是玩家手改 exe 也会被自动修复回官方版本，算加分项。
//!
//! # Windows 的文件锁边界
//!
//! 运行中的 exe 被锁的是**映像节**，不是**目录项**，所以
//! **可以改名、不能覆盖或删除**。顺序必须是：
//!
//! ```text
//! 自身 exe  →  自身 exe.old      （腾出原名）
//! 自身 exe.new  →  自身 exe      （就位）
//! ```
//!
//! 两步都在同一目录（同卷）做 rename，第二步失败立刻反向改名回滚。
//! 这是 Squirrel.Windows / Velopack / iw4x 登录器共用的机制。
//!
//! `.old` 只是改名的副产品，不是长期备份：新版本成功启动后会自动删掉
//! （见 [`cleanup_old`]），所以客户端目录里不会积累垃圾。

use crate::http;
use crate::manifest::Launcher;
use crate::update::{self, MAX_FILE};
use std::path::{Path, PathBuf};

/// 自更新结局
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 清单没有 launcher 段 / 已是最新 / 本轮被抑制
    UpToDate,
    /// 已改名就位，调用方应尽快重启（此刻旧进程仍在跑，用的还是旧代码）
    Replaced { version: String },
    /// 失败；**不得阻断启动**
    Failed(String),
}

/// 上一版留档后缀（同时是二期自动回滚的回滚点）
const OLD_SUFFIX: &str = ".old";
/// 下载中的临时后缀
const NEW_SUFFIX: &str = ".new";
/// 改名重试次数：杀软扫描会短暂占用目录项，重试即可
const RENAME_RETRIES: u32 = 3;
/// 每次重试间隔
const RETRY_DELAY_MS: u64 = 200;

/// 取自身 exe 路径
///
/// 注意：**不要**用 `canonicalize`（会加 `\\?\` 前缀），也不要拼配置里的固定名字，
/// 玩家随时可能把 `Login.exe` 改名。
pub fn own_exe() -> Result<PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("取自身路径失败: {}", e))
}

/// 清理上一版留档（`<exe>.old`）
///
/// **为什么可以删**：能调用到这里，说明当前 exe 已经成功加载并跑起来了；
/// 而新文件落地前已经过 size + sha256 + PE 三重校验，坏文件根本写不进去。
/// 所以 `.old` 没有救场价值，留着只是白占 2.8MB。
///
/// 真要回滚，走清单更可靠：把 `launcher.sha256` 指回旧版，玩家下次启动就换回去了。
///
/// 删不掉不算错误：旧进程可能还没完全退出（文件仍被映射），下次启动会再试。
pub fn cleanup_old(exe: &Path) -> bool {
    let mut name = match exe.file_name() {
        Some(s) => s.to_os_string(),
        None => return false,
    };
    name.push(OLD_SUFFIX);
    let old = match exe.parent() {
        Some(d) => d.join(name),
        None => return false,
    };
    if !old.is_file() {
        return false;
    }
    std::fs::remove_file(&old).is_ok()
}

/// 自身是否需要更新（先比大小，快速路径；大小一致再算 sha256）
fn needs_update(exe: &Path, want: &Launcher) -> Result<bool, String> {
    let meta = std::fs::metadata(exe).map_err(|e| format!("读自身属性失败: {}", e))?;
    if meta.len() != want.size {
        return Ok(true);
    }
    let data = std::fs::read(exe).map_err(|e| format!("读自身失败: {}", e))?;
    Ok(update::sha256_hex(&data) != want.sha256.trim().to_ascii_lowercase())
}

/// 自更新主流程
///
/// - `suppressed`：本次启动带 `--self-updated`（刚更新过），一律不再碰，
///   这是防死循环的关键——即使改名被回滚也只在每次启动尝试一次。
/// - `progress`：下载进度 0..1。
///
/// 任何失败都只返回 `Failed`，**由调用方忽略并继续启动**（fail-open）。
pub fn run(
    base: &str,
    launcher: Option<&Launcher>,
    suppressed: bool,
    progress: &mut dyn FnMut(f32),
) -> Outcome {
    // 能执行到这里，就说明当前 exe 是活的、能加载 —— 上一版的留档没用了，顺手清掉。
    // 新版本若真的起不来，进程根本走不到这一行，`.old` 会留着当救命文件。
    if let Ok(exe) = own_exe() {
        let _ = cleanup_old(&exe);
    }

    let want = match launcher {
        Some(v) => v,
        None => return Outcome::UpToDate,
    };
    if want.sha256.trim().is_empty() || want.size == 0 {
        return Outcome::UpToDate;
    }
    if suppressed {
        return Outcome::UpToDate;
    }

    let exe = match own_exe() {
        Ok(p) => p,
        Err(e) => return Outcome::Failed(e),
    };
    match needs_update(&exe, want) {
        Ok(false) => return Outcome::UpToDate,
        Ok(true) => {}
        Err(e) => return Outcome::Failed(e),
    }

    let dir = match exe.parent() {
        Some(d) => d.to_path_buf(),
        None => return Outcome::Failed("取自身目录失败".into()),
    };
    let stem = match exe.file_name() {
        Some(s) => s.to_os_string(),
        None => return Outcome::Failed("取自身文件名失败".into()),
    };

    // ---- 下载（复用内容寻址约定：files/<sha256>）----
    let base = if base.ends_with('/') {
        base.to_string()
    } else {
        format!("{}/", base)
    };
    let sha = want.sha256.trim().to_ascii_lowercase();
    let url = format!("{}files/{}", base, sha);
    let data = {
        let p = progress;
        let mut cb = |got: usize, total: usize| {
            let frac = if total > 0 {
                (got as f32 / total as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            p(frac);
        };
        match http::get_with_progress(&url, MAX_FILE, Some(&mut cb)) {
            Ok(d) => d,
            Err(e) => return Outcome::Failed(format!("下载新版失败: {}", e)),
        }
    };

    // ---- 三重校验：大小 → sha256 → PE 头 ----
    if data.len() as u64 != want.size {
        return Outcome::Failed(format!(
            "新版大小不符：期望 {} 实际 {}",
            want.size,
            data.len()
        ));
    }
    if update::sha256_hex(&data) != sha {
        return Outcome::Failed("新版哈希不符".into());
    }
    if !is_pe(&data) {
        return Outcome::Failed("下载到的不是有效 exe（PE 头校验失败）".into());
    }

    // ---- 落到同目录的 .new（必须同卷，否则 rename 会跨卷失败）----
    let mut new_name = stem.clone();
    new_name.push(NEW_SUFFIX);
    let new_path = dir.join(new_name);
    if let Err(e) = std::fs::write(&new_path, &data) {
        let _ = std::fs::remove_file(&new_path);
        return Outcome::Failed(format!("写临时文件失败: {}", e));
    }

    // ---- 三步改名 ----
    let mut old_name = stem.clone();
    old_name.push(OLD_SUFFIX);
    let old_path = dir.join(old_name);
    if let Err(e) = swap(&exe, &new_path, &old_path) {
        let _ = std::fs::remove_file(&new_path);
        return Outcome::Failed(e);
    }

    Outcome::Replaced {
        version: if want.version.trim().is_empty() {
            sha.chars().take(12).collect()
        } else {
            want.version.trim().to_string()
        },
    }
}

/// 改名腾位 + 就位；第二步失败则立刻把 `.old` 改回去
fn swap(exe: &Path, new: &Path, old: &Path) -> Result<(), String> {
    move_retry(exe, old).map_err(|e| format!("腾位失败（自身可能被安全软件占用）: {}", e))?;
    if let Err(e) = move_retry(new, exe) {
        return match move_retry(old, exe) {
            // 回滚成功：登录器仍可正常打开，这次更新作废
            Ok(()) => Err(format!("新文件就位失败，已回滚到旧版: {}", e)),
            // 回滚也失败：只能靠玩家重新下载，但先把原因写清楚
            Err(e2) => Err(format!(
                "新文件就位失败({})，回滚也失败({})：请重新下载登录器",
                e, e2
            )),
        };
    }
    Ok(())
}

/// 带重试的 rename（同卷、可覆盖目标）
fn move_retry(from: &Path, to: &Path) -> Result<(), String> {
    let mut last = String::new();
    for i in 0..RENAME_RETRIES {
        match move_file(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = e;
                if i + 1 < RENAME_RETRIES {
                    std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
                }
            }
        }
    }
    Err(last)
}

#[cfg(windows)]
fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, newname: *const u16, flags: u32) -> i32;
    }
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    let a: Vec<u16> = from
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let b: Vec<u16> = to
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
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

#[cfg(not(windows))]
fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::rename(from, to).map_err(|e| e.to_string())
}

/// 极简 PE 校验：挡住「下到 HTML 错误页 / 半截文件」这类脏数据
fn is_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }
    let off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    off + 4 <= data.len() && &data[off..off + 4] == b"PE\0\0"
}

/// 重启自己，带上 `--self-updated` 标记（下次启动不再自更新）
///
/// 用 `std::process::Command` 而不是手写 `CreateProcessW`：
/// 标准库已经处理好参数转义（路径含空格/中文都安全），也不会和 `launch`
/// 模块里那份 extern 声明撞名（同名不同签名会触发 redeclared 警告）。
#[cfg(windows)]
pub fn restart_self() -> Result<(), String> {
    let exe = own_exe()?;
    let dir = exe
        .parent()
        .map(Path::to_path_buf)
        .ok_or("取自身目录失败")?;
    // 当前进程已提权，子进程直接继承令牌 ⇒ 不会再弹一次 UAC
    std::process::Command::new(&exe)
        .arg("--self-updated")
        .current_dir(&dir)
        .spawn()
        .map_err(|e| format!("启动新版失败: {}", e))?;
    Ok(())
}

#[cfg(not(windows))]
pub fn restart_self() -> Result<(), String> {
    Err("仅 Windows 支持自更新重启".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pe_header_detection() {
        let mut good = vec![0u8; 0x80];
        good[0] = b'M';
        good[1] = b'Z';
        good[0x3c] = 0x40; // e_lfanew = 0x40
        good[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert!(is_pe(&good));

        // 少了 PE 签名
        let mut bad = good.clone();
        bad[0x40] = b'X';
        assert!(!is_pe(&bad));

        // 典型的「下到 HTML 错误页」
        let html = b"<!DOCTYPE html><html><body>404</body></html>";
        assert!(!is_pe(html));

        // 半截文件
        assert!(!is_pe(&[b'M', b'Z']));
    }

    #[test]
    fn cleanup_old_removes_only_the_archive() {
        let dir = std::env::temp_dir().join("l1j_selfupdate_cleanup_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let exe = dir.join("Login.exe");
        let old = dir.join("Login.exe.old");
        std::fs::write(&exe, b"MZ-exe").unwrap();
        std::fs::write(&old, b"old-version").unwrap();

        assert!(cleanup_old(&exe), "存在 .old 时应删掉");
        assert!(!old.exists(), ".old 应被删除");
        assert!(exe.exists(), "本体绝不能被删");

        // 没有 .old 时返回 false，不报错也不动本体
        assert!(!cleanup_old(&exe));
        assert!(exe.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
