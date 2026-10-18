//! 启动游戏
//!
//! 实测：`TW13032701.bin` / `Lin.bin` / `login.exe` 三个清单都是 `requireAdministrator`，
//! 非提权进程用 CreateProcess 直接起会得到 WinError 740。
//! 所以这里用 ShellExecuteW + "runas"，让 UAC 提示出现在厂商程序上
//! （我们自己的 exe 保持 asInvoker，不申请管理员）。

use std::path::Path;

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::path::Path;

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn run(client: &Path, exe_name: &str, args: &str) -> Result<(), String> {
        let exe = client.join(exe_name);
        if !exe.is_file() {
            return Err(format!("找不到游戏程序: {}", exe.display()));
        }
        let op = wide("runas");
        let file = wide(&exe.to_string_lossy());
        let params = wide(args);
        let dir = wide(&client.to_string_lossy());
        unsafe {
            let r = ShellExecuteW(
                std::ptr::null_mut(),
                op.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                dir.as_ptr(),
                1,
            );
            // ShellExecuteW 返回值 > 32 表示成功
            if r as usize <= 32 {
                return Err(format!("启动失败（ShellExecute 返回 {}）", r));
            }
        }
        Ok(())
    }
}

pub fn launch_game(client: &Path, exe_name: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        imp::run(client, exe_name, "")
    }
    #[cfg(not(windows))]
    {
        let _ = (client, exe_name);
        Err("仅支持 Windows".into())
    }
}

/// 直接拉起游戏主程序（带服务器 IP 十进制整数参数），供将来免登录器方案使用
pub fn launch_game_with_ip(client: &Path, exe_name: &str, ip: &str) -> Result<(), String> {
    let arg = ip_to_int(ip).ok_or_else(|| format!("IP 格式非法: {}", ip))?;
    #[cfg(windows)]
    {
        imp::run(client, exe_name, &arg.to_string())
    }
    #[cfg(not(windows))]
    {
        let _ = (client, exe_name);
        Err("仅支持 Windows".into())
    }
}

/// IPv4 -> 十进制整数（与登录器一致：a*16777216 + b*65536 + c*256 + d）
pub fn ip_to_int(ip: &str) -> Option<u32> {
    let parts: Vec<u32> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 || parts.iter().any(|v| *v > 255) {
        return None;
    }
    Some(parts[0] * 16_777_216 + parts[1] * 65_536 + parts[2] * 256 + parts[3])
}

#[cfg(test)]
mod tests {
    use super::ip_to_int;

    #[test]
    fn ip_int_matches_launcher() {
        // 审计日志里实测：登录器传的是 2130706433 = 127.0.0.1
        assert_eq!(ip_to_int("127.0.0.1"), Some(2_130_706_433));
        assert_eq!(ip_to_int("124.222.172.24"), Some(2_094_967_832));
        assert_eq!(ip_to_int("1.2.3.4"), Some(16_909_060));
        assert_eq!(ip_to_int("256.1.1.1"), None);
        assert_eq!(ip_to_int("abc"), None);
    }
}
