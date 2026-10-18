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

    #[repr(C)]
    struct STARTUPINFOW {
        cb: u32,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: *mut c_void,
        h_std_output: *mut c_void,
        h_std_error: *mut c_void,
    }

    #[repr(C)]
    struct PROCESS_INFORMATION {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
        fn ReadProcessMemory(p: *mut c_void, addr: *const c_void, buf: *mut c_void, n: usize, got: *mut usize) -> i32;
        fn WriteProcessMemory(p: *mut c_void, addr: *mut c_void, buf: *const c_void, n: usize, written: *mut usize) -> i32;
        fn VirtualProtectEx(p: *mut c_void, addr: *mut c_void, n: usize, newp: u32, old: *mut u32) -> i32;
        fn Sleep(ms: u32);
        fn CreateProcessW(
            app: *const u16,
            cmdline: *mut u16,
            sa: *mut c_void,
            ta: *mut c_void,
            inherit: i32,
            flags: u32,
            env: *mut c_void,
            cwd: *const u16,
            si: *const STARTUPINFOW,
            pi: *mut PROCESS_INFORMATION,
        ) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    const PATCH_VA: usize = 0x004D_5AF2;

    /// 等壳把代码解密后，把 `0F 85` 改成 `90 E9`（与厂商登录器行为一致）
    unsafe fn apply_runtime_patch(proc: *mut c_void) {
        let want = [0x0Fu8, 0x85u8];
        let repl = [0x90u8, 0xE9u8];
        for _ in 0..400 {
            let mut buf = [0u8; 2];
            let mut got = 0usize;
            let ok = ReadProcessMemory(
                proc,
                PATCH_VA as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                2,
                &mut got,
            );
            if ok != 0 && got == 2 && buf == want {
                let mut old = 0u32;
                let _ = VirtualProtectEx(proc, PATCH_VA as *mut c_void, 2, 0x40, &mut old); // PAGE_EXECUTE_READWRITE
                let mut written = 0usize;
                let _ = WriteProcessMemory(
                    proc,
                    PATCH_VA as *mut c_void,
                    repl.as_ptr() as *const c_void,
                    2,
                    &mut written,
                );
                let _ = VirtualProtectEx(proc, PATCH_VA as *mut c_void, 2, old, &mut old);
                return;
            }
            Sleep(5);
        }
    }

    /// 直接 CreateProcess：启动器自身已提权，子进程继承管理员令牌。
    /// 不能用 ShellExecute("runas")——`.bin` 没有文件关联，会报“没有应用程序与该文件有关联”。
    pub fn run(client: &Path, exe_name: &str, args: &str) -> Result<(), String> {
        let exe = client.join(exe_name);
        if !exe.is_file() {
            return Err(format!("找不到游戏程序: {}", exe.display()));
        }
        let app = wide(&exe.to_string_lossy());
        let mut cmd = wide(&format!("\"{}\" {}", exe.display(), args));
        let cwd = wide(&client.to_string_lossy());
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lp_reserved: std::ptr::null_mut(),
            lp_desktop: std::ptr::null_mut(),
            lp_title: std::ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 1,
            cb_reserved2: 0,
            lp_reserved2: std::ptr::null_mut(),
            h_std_input: std::ptr::null_mut(),
            h_std_output: std::ptr::null_mut(),
            h_std_error: std::ptr::null_mut(),
        };
        let mut pi = PROCESS_INFORMATION {
            h_process: std::ptr::null_mut(),
            h_thread: std::ptr::null_mut(),
            dw_process_id: 0,
            dw_thread_id: 0,
        };
        unsafe {
            let ok = CreateProcessW(
                app.as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null_mut(),
                cwd.as_ptr(),
                &si,
                &mut pi,
            );
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                return Err(format!("启动失败（{}）cmd={}", e, String::from_utf16_lossy(&cmd[..cmd.len()-1])));
            }
            // ★ 关键补丁：与厂商 login.exe 完全一致
            // 失败现场： 0F 85 97 00 00 00  (jne 0x4D5B8F  -> 跳去 RunTime Expired)
            // 成功现场： 90 E9 97 00 00 00  (nop + jmp   -> 永远跳过报错)
            // 逐字节对比两次 dump 得到，非猜测。
            apply_runtime_patch(pi.h_process);

            WaitForSingleObject(pi.h_process, 0xFFFF_FFFF);
            CloseHandle(pi.h_thread);
            CloseHandle(pi.h_process);
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
