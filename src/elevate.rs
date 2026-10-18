//! 自提权
//!
//! 依据：客户端 `TW13032701.bin` / `Lin.bin` / 厂商登录器 三个清单都是
//! `requireAdministrator`；其他私服的登录器（骷髅天堂[盾].exe、LineageClientLogin.exe、
//! LineageLogin[盾].exe…）同样如此。所以本程序也申请管理员：
//!   · 只弹一次 UAC（启动时），之后拉游戏不再二次弹
//!   · 行为与行业惯例一致，不额外增加误报特征

#[cfg(windows)]
pub fn ensure_admin() {
    if is_elevated() {
        return;
    }
    relaunch_as_admin();
}

#[cfg(not(windows))]
pub fn ensure_admin() {}

#[cfg(windows)]
fn is_elevated() -> bool {
    use std::ffi::c_void;
    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn GetTokenInformation(
            token: *mut c_void,
            class: u32,
            info: *mut c_void,
            len: u32,
            ret_len: *mut u32,
        ) -> i32;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION: u32 = 20;
    unsafe {
        let mut token: *mut c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TokenElevation { token_is_elevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TOKEN_ELEVATION,
            &mut elev as *mut _ as *mut c_void,
            std::mem::size_of::<TokenElevation>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elev.token_is_elevated != 0
    }
}

#[cfg(windows)]
fn relaunch_as_admin() {
    use std::ffi::c_void;
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            op: *const u16,
            file: *const u16,
            params: *const u16,
            dir: *const u16,
            show: i32,
        ) -> isize;
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let params = args.join(" ");
    let op = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let par = wide(&params);
    unsafe {
        let r = ShellExecuteW(
            std::ptr::null_mut(),
            op.as_ptr(),
            file.as_ptr(),
            par.as_ptr(),
            std::ptr::null(),
            1,
        );
        if r as usize > 32 {
            std::process::exit(0);
        }
    }
}
