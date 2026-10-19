//! 极简 HTTPS GET（直接调用 WinHTTP，不依赖 `windows` crate）
//!
//! 为什么手写 FFI：`windows` crate 的构建脚本需要 `dlltool` 生成导入库，
//! 在本机 gnu 工具链下总失败；而 MinGW 自带的 `libwinhttp.a` 已经够用，
//! 手写 8 个函数声明即可，还能少几 MB 依赖。

use std::ffi::c_void;

pub const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
pub const WINHTTP_FLAG_SECURE: u32 = 0x0080_0000;
pub const WINHTTP_QUERY_STATUS_CODE: u32 = 19;
pub const WINHTTP_QUERY_CONTENT_LENGTH: u32 = 5;
pub const WINHTTP_QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

/// 联网超时（毫秒）：解析 3s / 连接 3s / 发送 5s / 接收 5s
/// 没有它，服务器不可达时 WinHTTP 会按系统默认超时干等（几十秒），界面卡在「正在檢查更新…」
const T_RESOLVE: i32 = 3000;
const T_CONNECT: i32 = 3000;
const T_SEND: i32 = 5000;
const T_RECEIVE: i32 = 5000;

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpOpen(
        psz_agent_w: *const u16,
        dw_access_type: u32,
        psz_proxy_w: *const u16,
        psz_proxy_bypass_w: *const u16,
        dw_flags: u32,
    ) -> *mut c_void;
    fn WinHttpConnect(
        h_session: *mut c_void,
        pswz_server_name: *const u16,
        n_server_port: u16,
        dw_reserved: u32,
    ) -> *mut c_void;
    fn WinHttpOpenRequest(
        h_connect: *mut c_void,
        pwsz_verb: *const u16,
        pwsz_object_name: *const u16,
        pwsz_version: *const u16,
        pwsz_referrer: *const u16,
        ppwsz_accept_types: *const *const u16,
        dw_flags: u32,
    ) -> *mut c_void;
    fn WinHttpSendRequest(
        h_request: *mut c_void,
        lpsz_headers: *const u16,
        dw_headers_length: u32,
        lp_optional: *const c_void,
        dw_optional_length: u32,
        dw_total_length: u32,
        dw_context: usize,
    ) -> i32;
    fn WinHttpReceiveResponse(h_request: *mut c_void, lp_reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(
        h_request: *mut c_void,
        dw_info_level: u32,
        pwsz_name: *const u16,
        lp_buffer: *mut c_void,
        lpdw_buffer_length: *mut u32,
        lpdw_index: *mut u32,
    ) -> i32;
    fn WinHttpReadData(
        h_request: *mut c_void,
        lp_buffer: *mut c_void,
        dw_number_of_bytes_to_read: u32,
        lpdw_number_of_bytes_read: *mut u32,
    ) -> i32;
    fn WinHttpCloseHandle(h_internet: *mut c_void) -> i32;
    /// 超时（毫秒）：解析域名 / 建立连接 / 发送请求 / 接收响应
    fn WinHttpSetTimeouts(
        h_internet: *mut c_void,
        resolve_timeout: i32,
        connect_timeout: i32,
        send_timeout: i32,
        receive_timeout: i32,
    ) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn split_url(url: &str) -> Result<(bool, String, u16, String), String> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("URL 必须以 http(s):// 开头: {}", url));
    };
    let (host_port, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rfind(':') {
        Some(i) => (
            host_port[..i].to_string(),
            host_port[i + 1..]
                .parse::<u16>()
                .map_err(|_| format!("端口非法: {}", host_port))?,
        ),
        None => (host_port.to_string(), if secure { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err("URL 缺少主机名".into());
    }
    Ok((secure, host, port, path.to_string()))
}

/// 最后一个 Win32 错误
fn last_error(ctx: &str) -> String {
    let code = unsafe { GetLastError() };
    format!("{}（Win32 错误 {}）", ctx, code)
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

/// 便捷版：只要数据，不要进度
pub fn get(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    get_with_progress(url, max_bytes, None::<&mut dyn FnMut(usize, usize)>)
}

/// 带进度回调的下载：`progress(已收字节, 总字节)`，总字节未知时为 0
pub fn get_with_progress(
    url: &str,
    max_bytes: usize,
    mut progress: Option<&mut dyn FnMut(usize, usize)>,
) -> Result<Vec<u8>, String> {
    let (secure, host, port, path) = split_url(url)?;
    let agent = wide("l1j-launcher/0.1");
    let host_w = wide(&host);
    let path_w = wide(&path);
    let verb = wide("GET");
    let flags = if secure { WINHTTP_FLAG_SECURE } else { 0 };

    unsafe {
        let session = WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        if session.is_null() {
            return Err(last_error("WinHttpOpen 失败"));
        }
        // 必须显式设超时：否则服务器不可达时会无限期等待（界面假死）
        if WinHttpSetTimeouts(session, T_RESOLVE, T_CONNECT, T_SEND, T_RECEIVE) == 0 {
            // 设超时失败不致命，继续（只是退回系统默认）
            let _ = GetLastError();
        }

        let mut conn: *mut c_void = std::ptr::null_mut();
        let mut req: *mut c_void = std::ptr::null_mut();

        let result = (|| -> Result<Vec<u8>, String> {
            conn = WinHttpConnect(session, host_w.as_ptr(), port, 0);
            if conn.is_null() {
                return Err(last_error(&format!("连接失败 {}:{}", host, port)));
            }
            req = WinHttpOpenRequest(
                conn,
                verb.as_ptr(),
                path_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                flags,
            );
            if req.is_null() {
                return Err(last_error("WinHttpOpenRequest 失败"));
            }
            if WinHttpSendRequest(
                req,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                0,
                0,
            ) == 0
            {
                return Err(last_error("发送请求失败"));
            }
            if WinHttpReceiveResponse(req, std::ptr::null_mut()) == 0 {
                return Err(last_error("等待响应失败"));
            }

            let mut status: u32 = 0;
            let mut len = std::mem::size_of::<u32>() as u32;
            if WinHttpQueryHeaders(
                req,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                std::ptr::null(),
                &mut status as *mut _ as *mut c_void,
                &mut len,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(last_error("读状态码失败"));
            }
            if status != 200 {
                return Err(format!("HTTP {} : {}", status, url));
            }

            // 总长度（可能没有 Content-Length，此时为 0 → 回调拿到 0 表示未知）
            let mut total: u32 = 0;
            let mut tlen = std::mem::size_of::<u32>() as u32;
            if WinHttpQueryHeaders(
                req,
                WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                std::ptr::null(),
                &mut total as *mut _ as *mut c_void,
                &mut tlen,
                std::ptr::null_mut(),
            ) == 0
            {
                total = 0;
            }

            let mut out: Vec<u8> = Vec::new();
            let mut buf = vec![0u8; 64 * 1024];
            if let Some(cb) = progress.as_deref_mut() {
                cb(0, total as usize);
            }
            loop {
                let mut read: u32 = 0;
                if WinHttpReadData(
                    req,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                    &mut read,
                ) == 0
                {
                    return Err(last_error("读数据失败"));
                }
                if read == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..read as usize]);
                if out.len() > max_bytes {
                    return Err(format!("响应超过上限 {} 字节", max_bytes));
                }
                if let Some(cb) = progress.as_deref_mut() {
                    cb(out.len(), total as usize);
                }
            }
            if let Some(cb) = progress.as_deref_mut() {
                cb(out.len(), total as usize);
            }
            Ok(out)
        })();

        if !req.is_null() {
            WinHttpCloseHandle(req);
        }
        if !conn.is_null() {
            WinHttpCloseHandle(conn);
        }
        WinHttpCloseHandle(session);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::split_url;

    #[test]
    fn url_parse() {
        let (s, h, p, path) = split_url("https://example.com/a/b.json").unwrap();
        assert!(s);
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
        assert_eq!(path, "/a/b.json");

        let (s, h, p, _) = split_url("http://127.0.0.1:8080/manifest.json").unwrap();
        assert!(!s);
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8080);
    }

    #[test]
    fn url_reject() {
        assert!(split_url("ftp://x/y").is_err());
        assert!(split_url("https:///path").is_err());
    }
}
