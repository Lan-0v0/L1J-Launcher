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
        fn CreateFileMappingW(h: *mut c_void, sa: *mut c_void, prot: u32,
                              hi: u32, lo: u32, name: *const u16) -> *mut c_void;
        fn MapViewOfFile(h: *mut c_void, access: u32, hi: u32, lo: u32, n: usize) -> *mut c_void;
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
        fn VirtualAllocEx(h: *mut c_void, addr: *mut c_void, size: usize, typ: u32, prot: u32) -> *mut c_void;
        fn CreateRemoteThread(h: *mut c_void, sa: *mut c_void, stack: usize,
                               start: unsafe extern "system" fn(*mut c_void) -> u32,
                               param: *mut c_void, flags: u32, tid: *mut u32) -> *mut c_void;
        fn ResumeThread(h: *mut c_void) -> u32;
        fn GetExitCodeThread(h: *mut c_void, code: *mut u32) -> i32;
        fn GetModuleHandleA(n: *const u8) -> *mut c_void;
        fn GetProcAddress(h: *mut c_void, n: *const u8) -> *mut c_void;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 需要打的补丁：(地址, 期望原字节, 替换字节)
    /// 1) 运行期校验 0F 85 (jne) -> 90 E9 (nop+jmp)，跳过 RunTime Expired
    /// 2) 色深检查 74 40 (je 0x446C1D) -> EB 40 (jmp)，跳过 "仅支持16位色" 提示
    ///    证据：调用 MessageBox 的返回地址 0x446C1C 来自线程栈回溯
    /// 实证补丁（由注入 Hook 截获 login.exe 的 WriteProcessMemory 得到）：
    ///   ADDR=0x004E4320  原字节 0F 8D (jge)  ->  90 E9 (nop + jmp)
    /// 之前猜测的 0x4D5AF2 是误读，已移除。
    /// 补丁清单（两处都必须打）：
    /// 1) 0x4D5AF2  0F 85 -> 90 E9 ：实测可消除 RunTime Expired
    /// 2) 0x4E4320  0F 8D -> 90 E9 ：由注入 Hook 截获 login.exe 的 WriteProcessMemory 得到
    /// 补丁清单（两处都必须打）：
    /// 1) 0x4D5AF2  0F 85 -> 90 E9 ：实测可消除 RunTime Expired
    /// 2) 0x4E4320  0F 8D -> 90 E9 ：由注入 Hook 截获 login.exe 的 WriteProcessMemory 得到
    const PATCHES: [(usize, &[u8], &[u8]); 2] = [
        (0x004D_5AF2, &[0x0F, 0x85], &[0x90, 0xE9]),
        (0x004E_4320, &[0x0F, 0x8D], &[0x90, 0xE9]),
    ];

    use std::sync::Mutex;
    static EXTRA: Mutex<Vec<(usize, Vec<u8>, Vec<u8>)>> = Mutex::new(Vec::new());

    pub fn set_extra(list: Vec<(usize, Vec<u8>, Vec<u8>)>) {
        if let Ok(mut g) = EXTRA.lock() {
            *g = list;
        }
    }

    unsafe fn apply_runtime_patch(proc: *mut c_void) {
        let mut done = [false; PATCHES.len()];
        for _ in 0..800 {
            let mut all = true;
            for (i, (va, want, repl)) in PATCHES.iter().enumerate() {
                if done[i] { continue; }
                all = false;
                let mut buf = [0u8; 4];
                let mut got = 0usize;
                let ok = ReadProcessMemory(
                    proc, *va as *const c_void, buf.as_mut_ptr() as *mut c_void,
                    want.len(), &mut got,
                );
                if ok != 0 && got == want.len() && &buf[..want.len()] == *want {
                    let mut old = 0u32;
                    let _ = VirtualProtectEx(proc, *va as *mut c_void, repl.len(), 0x40, &mut old);
                    let mut written = 0usize;
                    let _ = WriteProcessMemory(
                        proc, *va as *mut c_void, repl.as_ptr() as *const c_void,
                        repl.len(), &mut written,
                    );
                    let _ = VirtualProtectEx(proc, *va as *mut c_void, repl.len(), old, &mut old);
                    done[i] = true;
                }
            }
            if all { break; }
            Sleep(5);
        }
        // 额外补丁（配置驱动）
        if let Ok(g) = EXTRA.lock() {
            for (va, want, repl) in g.iter() {
                for _ in 0..200 {
                    let mut buf = vec![0u8; want.len()];
                    let mut got = 0usize;
                    let ok = ReadProcessMemory(
                        proc, *va as *const c_void, buf.as_mut_ptr() as *mut c_void,
                        want.len(), &mut got,
                    );
                    if ok != 0 && got == want.len() && &buf[..] == &want[..] {
                        let mut old = 0u32;
                        let _ = VirtualProtectEx(proc, *va as *mut c_void, repl.len(), 0x40, &mut old);
                        let mut written = 0usize;
                        let _ = WriteProcessMemory(
                            proc, *va as *mut c_void, repl.as_ptr() as *const c_void,
                            repl.len(), &mut written,
                        );
                        let _ = VirtualProtectEx(proc, *va as *mut c_void, repl.len(), old, &mut old);
                        break;
                    }
                    Sleep(5);
                }
            }
        }
    }

    /// 把补丁自检结果写到文件（证明补丁到底有没有落地）
    unsafe fn log_verify(va: usize, want: &[u8], repl: &[u8], proc: *mut c_void) {
        let mut buf = [0u8; 4];
        let mut got = 0usize;
        let ok = ReadProcessMemory(proc, va as *const c_void, buf.as_mut_ptr() as *mut c_void,
                                   repl.len(), &mut got);
        let mut s = String::new();
        s.push_str(&format!("ADDR={:08X} want={:02X?} repl={:02X?} read_ok={} got={} now={:02X?}\n",
                            va, want, repl, ok, got, &buf[..repl.len().min(4)]));
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
            .open(r"D://l1log//patch_verify.txt") {
            let _ = f.write_all(s.as_bytes());
        }
    }

    /// 壳会反复重写代码页，补丁可能被覆盖 → 持续重打 20 秒
    pub unsafe fn patch_watchdog(proc: *mut c_void) {
        let mut tick: u32 = 0;
        for _ in 0..20000 {
            for (va, want, repl) in PATCHES.iter() {
                let mut buf = [0u8; 4];
                let mut got = 0usize;
                let ok = ReadProcessMemory(
                    proc, *va as *const c_void, buf.as_mut_ptr() as *mut c_void,
                    want.len(), &mut got,
                );
                if ok != 0 && got == want.len() && &buf[..want.len()] == *want {
                    let mut old = 0u32;
                    let _ = VirtualProtectEx(proc, *va as *mut c_void, repl.len(), 0x40, &mut old);
                    let mut written = 0usize;
                    let _ = WriteProcessMemory(
                        proc, *va as *mut c_void, repl.as_ptr() as *const c_void,
                        repl.len(), &mut written,
                    );
                    let _ = VirtualProtectEx(proc, *va as *mut c_void, repl.len(), old, &mut old);
                    log_verify(*va, want, repl, proc);
                }
            }
            if tick % 100 == 0 {
                log_probe(proc, tick);
            }
            tick += 1;
            Sleep(1);
        }
    }

    unsafe fn log_probe(proc: *mut c_void, tick: u32) {
        use std::io::Write;
        let mut line = String::new();
        for (va, _want, repl) in PATCHES.iter() {
            let mut buf = [0u8; 4];
            let mut got = 0usize;
            let ok = ReadProcessMemory(proc, *va as *const c_void, buf.as_mut_ptr() as *mut c_void,
                                       repl.len(), &mut got);
            line.push_str(&format!("t={}ms {:08X} ok={} now={:02X?} | ", tick, va, ok, &buf[..repl.len()]));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
            .open(r"D://l1log//patch_probe.txt") {
            let _ = f.write_all((line + "\n").as_bytes());
        }
    }

    /// 从命令行参数读取真实服务器地址（由 bin 层设置）
    pub fn set_real_server(ip: &str) {
        if let Ok(mut g) = REAL_SERVER.lock() { *g = ip.to_string(); }
    }
    fn client_ip_hint() -> Option<String> {
        REAL_SERVER.lock().ok().map(|g| g.clone()).filter(|s| !s.is_empty())
    }
    static REAL_SERVER: Mutex<String> = Mutex::new(String::new());

    /// 挂起状态下把 login.dll 注入游戏（厂商登录器的核心动作）
    unsafe fn inject_login_dll(proc: *mut c_void, client: &Path) -> bool {
        let dll = client.join("login.dll");
        let mut pb: Vec<u16> = dll.as_os_str().to_string_lossy().encode_utf16().collect();
        pb.push(0);
        let mem = VirtualAllocEx(proc, std::ptr::null_mut(), 4096, 0x3000, 0x04);
        if mem.is_null() { return false; }
        let mut w = 0usize;
        let nbytes = pb.len() * 2;
        let ok = WriteProcessMemory(proc, mem, pb.as_ptr() as *const c_void, nbytes, &mut w);
        if ok == 0 { return false; }
        let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        let load = GetProcAddress(k32, b"LoadLibraryW\0".as_ptr());
        if load.is_null() { return false; }
        let f: unsafe extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(load);
        let th = CreateRemoteThread(proc, std::ptr::null_mut(), 0, f, mem, 0, std::ptr::null_mut());
        if th.is_null() { return false; }
        WaitForSingleObject(th, 5000);
        // LoadLibraryA 的返回值 = 模块基址；0 = 失败（DllMain 返回了 FALSE）
        let mut code: u32 = 0;
        GetExitCodeThread(th, &mut code);
        CloseHandle(th);
        let _ = std::fs::OpenOptions::new().create(true).append(true)
            .open(r"D://l1log//inject_log.txt")
            .and_then(|mut f| { use std::io::Write; writeln!(f, "远程 LoadLibrary 返回基址: 0x{:X}", code) });
        code != 0
    }

    /// 本地转发：127.0.0.1:2000 -> 真实服务器（对应厂商 login.dll 的作用）
    pub fn start_local_proxy(target: &str) {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        let target = target.to_string();
        std::thread::spawn(move || {
            let listener = match TcpListener::bind("127.0.0.1:2000") {
                Ok(l) => {
                    let _ = std::fs::OpenOptions::new().create(true).append(true)
                        .open(r"D://l1log//proxy_log.txt")
                        .and_then(|mut f| { use std::io::Write; writeln!(f, "转发已启动 127.0.0.1:2000 -> {}", target) });
                    l
                }
                Err(e) => {
                    let _ = std::fs::OpenOptions::new().create(true).append(true)
                        .open(r"D://l1log//proxy_log.txt")
                        .and_then(|mut f| { use std::io::Write; writeln!(f, "转发绑定失败: {}", e) });
                    return;
                }
            };
            for c in listener.incoming() {
                let mut c = match c { Ok(v) => v, Err(_) => continue };
                let t = target.clone();
                std::thread::spawn(move || {
                    let _ = std::fs::OpenOptions::new().create(true).append(true)
                    .open(r"D://l1log//proxy_log.txt")
                    .and_then(|mut f| { use std::io::Write; writeln!(f, "收到游戏连接，转发到 {}", t) });
                let mut s = match TcpStream::connect(&t) { Ok(v) => v, Err(e) => {
                    let _ = std::fs::OpenOptions::new().create(true).append(true)
                        .open(r"D://l1log//proxy_log.txt")
                        .and_then(|mut f| { use std::io::Write; writeln!(f, "连接目标失败: {}", e) });
                    return;
                } };
                    let _ = c.set_nodelay(true);
                    let _ = s.set_nodelay(true);
                    let mut c2 = match c.try_clone() { Ok(v) => v, Err(_) => return };
                    let mut s2 = match s.try_clone() { Ok(v) => v, Err(_) => return };
                    std::thread::spawn(move || { let _ = std::io::copy(&mut c2, &mut s2); });
                    let mut buf = [0u8; 8192];
                    loop {
                        match s.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => { if c.write_all(&buf[..n]).is_err() { break; } }
                        }
                    }
                });
            }
        });
    }

    /// 创建 "tcuhwmyi" 共享内存，写入 0x30（偏移 0x14）。句柄故意不关闭，随进程存活。
    unsafe fn create_launcher_marker() {
        // 名字用 UTF-16
        let mut name: Vec<u16> = "tcuhwmyi".encode_utf16().collect();
        name.push(0);
        let h = CreateFileMappingW(
            -1isize as *mut c_void,           // INVALID_HANDLE_VALUE
            std::ptr::null_mut(),
            0x04,                              // PAGE_READWRITE
            0,
            4096,
            name.as_ptr(),
        );
        if h.is_null() {
            return;
        }
        let p = MapViewOfFile(h, 0x000F001F, 0, 0, 4096); // FILE_MAP_ALL_ACCESS
        if !p.is_null() {
            let base = p as *mut u8;
            std::ptr::write_bytes(base, 0, 64);
            *base.add(0x14) = 0x30;
        }
    }

    /// 直接 CreateProcess：启动器自身已提权，子进程继承管理员令牌。
    /// 不能用 ShellExecute("runas")——`.bin` 没有文件关联，会报“没有应用程序与该文件有关联”。
    pub fn run(client: &Path, exe_name: &str, args: &str) -> Result<(), String> {
        // 必须在启动游戏之前建好标记，游戏启动时会检查
        unsafe { create_launcher_marker(); }
        if let Some(ip) = client_ip_hint() {
            start_local_proxy(&ip);
        }
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
                0x00000004,   // CREATE_SUSPENDED：先挂起，注入 login.dll 后再恢复
                std::ptr::null_mut(),
                cwd.as_ptr(),
                &si,
                &mut pi,
            );
            if ok == 0 {
                let e = std::io::Error::last_os_error();
                return Err(format!("启动失败（{}）cmd={}", e, String::from_utf16_lossy(&cmd[..cmd.len()-1])));
            }
            // ★ 在游戏跑任何代码之前，把 login.dll（登录 UI 库）注入进去
            let inj = inject_login_dll(pi.h_process, client);
            let _ = std::fs::OpenOptions::new().create(true).append(true)
                .open(r"D://l1log//inject_log.txt")
                .and_then(|mut f| { use std::io::Write; writeln!(f, "login.dll 注入: {}", inj) });
            ResumeThread(pi.h_thread);

            // ★ 关键补丁：与厂商 login.exe 完全一致
            // 失败现场： 0F 85 97 00 00 00  (jne 0x4D5B8F  -> 跳去 RunTime Expired)
            // 成功现场： 90 E9 97 00 00 00  (nop + jmp   -> 永远跳过报错)
            // 逐字节对比两次 dump 得到，非猜测。
            apply_runtime_patch(pi.h_process);
            {
                // 关键：持续重打线程之前从未被调用（替换未命中），这里补上
                let hp = pi.h_process as usize;
                std::thread::spawn(move || unsafe {
                    patch_watchdog(hp as *mut c_void);
                });
            }

            WaitForSingleObject(pi.h_process, 0xFFFF_FFFF);
            CloseHandle(pi.h_thread);
            CloseHandle(pi.h_process);
        }
        Ok(())
    }
}

/// 运行时注入的额外补丁（配置驱动，便于二分定位）
pub fn set_extra_patches(list: Vec<(usize, Vec<u8>, Vec<u8>)>) {
    #[cfg(windows)]
    {
        imp::set_extra(list);
    }
    #[cfg(not(windows))]
    {
        let _ = list;
    }
}

/// 带任意参数启动
pub fn launch_game_with_args(client: &Path, exe_name: &str, args: &str) -> Result<(), String> {
    #[cfg(windows)]
    { imp::run(client, exe_name, args) }
    #[cfg(not(windows))]
    { let _ = (client, exe_name, args); Err("仅支持 Windows".into()) }
}

/// 把选中区的 IP/端口写入 lineage.cfg（游戏真正读取的连接配置，明文 tag 结构）
/// 结构实证：tag7(DWORD)=IP，tag8(DWORD)=端口，即 "...07 00 00 00 | 04 00 00 00 | IP" / "...08 00 00 00 | 04 00 00 00 | PORT"
pub fn apply_lineage_cfg(client: &Path, ip: &str, port: u16) -> Result<(), String> {
    let p = client.join("lineage.cfg");
    let mut d = std::fs::read(&p).map_err(|e| format!("读 lineage.cfg: {}（首次运行请先用旧登录器跑一次）", e))?;
    let mut oct = [0u8; 4];
    for (i, part) in ip.split('.').enumerate() {
        if i >= 4 { return Err("IP 格式错误".into()); }
        oct[i] = part.parse::<u8>().map_err(|_| "IP 格式错误")?;
    }
    let t7 = [0x07u8, 0, 0, 0, 0x04, 0, 0, 0];
    let t8 = [0x08u8, 0, 0, 0, 0x04, 0, 0, 0];
    let find = |hay: &[u8], pat: &[u8], from: usize| -> Option<usize> {
        (from..=hay.len().saturating_sub(8)).find(|&i| &hay[i..i + 8] == pat)
    };
    let p7 = find(&d, &t7, 0).ok_or("lineage.cfg 找不到 IP 条目(tag7)")?;
    d[p7 + 8..p7 + 12].copy_from_slice(&oct);
    let p8 = find(&d, &t8, p7).ok_or("lineage.cfg 找不到端口条目(tag8)")?;
    d[p8 + 8..p8 + 12].copy_from_slice(&(port as u32).to_le_bytes());
    std::fs::write(&p, &d).map_err(|e| format!("写 lineage.cfg: {}", e))?;
    Ok(())
}

/// 把选中区的 ServerData 写进客户端 Login.ini（游戏启动时自己读取并解密）
pub fn apply_server_data(client: &Path, blob: &str) -> Result<(), String> {
    let ini = client.join("Login.ini");
    let mut data = std::fs::read(&ini).map_err(|e| format!("读 Login.ini: {}", e))?;
    let key = b"ServerData=";
    let mut out: Vec<u8> = Vec::with_capacity(data.len() + blob.len());
    let mut i = 0usize;
    let mut replaced = false;
    while i < data.len() {
        if data[i..].starts_with(key) && !replaced {
            out.extend_from_slice(key);
            out.extend_from_slice(blob.as_bytes());
            while i < data.len() && data[i] != b'\r' && data[i] != b'\n' { i += 1; }
            replaced = true;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    if !replaced { return Err("Login.ini 里没找到 ServerData=".into()); }
    std::fs::write(&ini, &out).map_err(|e| format!("写 Login.ini: {}", e))?;
    Ok(())
}

/// 设置真实服务器地址（用于本地转发）
pub fn set_real_server(ip: &str) {
    #[cfg(windows)]
    { imp::set_real_server(ip); }
    #[cfg(not(windows))]
    { let _ = ip; }
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
