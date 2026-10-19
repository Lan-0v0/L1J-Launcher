//! 区服选择窗口（原生皮肤：`skin\Serverlist.bmp` + `skin\Button.bmp`）
//!
//! 布局由原生截图逐像素量出：
//!   单个区服时：板宽 153×31，水平居中，垂直居中于列表区（y≈150）
//!   多区服时：2 列网格，列 x=155/345，行 y=118 起、行距 47
//!   状态圆点：直径 12px，贴在板的左侧（右列贴右侧）

#![cfg(windows)]
use std::ffi::c_void;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub const W: i32 = 692;
pub const H: i32 = 460;

#[derive(Clone, Debug)]
pub struct Server {
    pub name: String,
    pub ip: String,
    pub enabled: bool,
    /// 真实 ping 用的端口（缺省 2000）
    pub port: Option<u16>,
}

const PLATE_W: i32 = 153;
const PLATE_H: i32 = 31;

#[repr(C)]
struct MSG {
    hwnd: *mut c_void,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt_x: i32,
    pt_y: i32,
    l_private: u32,
}

#[repr(C)]
struct PAINTSTRUCT {
    hdc: *mut c_void,
    f_erase: i32,
    rc_paint: [i32; 4],
    f_restore: i32,
    f_inc_update: i32,
    rgb_reserved: [u8; 32],
}

#[repr(C)]
struct RECT {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct BITMAPINFOHEADER {
    bi_size: u32,
    bi_width: i32,
    bi_height: i32,
    bi_planes: u16,
    bi_bit_count: u16,
    bi_compression: u32,
    bi_size_image: u32,
    bi_x_pels: i32,
    bi_y_pels: i32,
    bi_clr_used: u32,
    bi_clr_important: u32,
}

#[repr(C)]
struct WNDCLASSEXW {
    cb_size: u32,
    style: u32,
    lpfn_wnd_proc: Option<unsafe extern "system" fn(*mut c_void, u32, usize, isize) -> isize>,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: *mut c_void,
    h_icon: *mut c_void,
    h_cursor: *mut c_void,
    hbr_background: *mut c_void,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
    h_icon_sm: *mut c_void,
}

#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(c: *const WNDCLASSEXW) -> u16;
    fn CreateWindowExW(ex: u32, class: *const u16, title: *const u16, style: u32,
                       x: i32, y: i32, w: i32, h: i32, parent: *mut c_void,
                       menu: *mut c_void, inst: *mut c_void, param: *mut c_void) -> *mut c_void;
    fn DefWindowProcW(h: *mut c_void, m: u32, w: usize, l: isize) -> isize;
    fn ShowWindow(h: *mut c_void, cmd: i32) -> i32;
    fn UpdateWindow(h: *mut c_void) -> i32;
    fn GetMessageW(msg: *mut MSG, h: *mut c_void, min: u32, max: u32) -> i32;
    fn TranslateMessage(msg: *const MSG) -> i32;
    fn DispatchMessageW(msg: *const MSG) -> isize;
    fn PostQuitMessage(code: i32);
    fn DestroyWindow(h: *mut c_void) -> i32;
    fn BeginPaint(h: *mut c_void, ps: *mut PAINTSTRUCT) -> *mut c_void;
    fn EndPaint(h: *mut c_void, ps: *const PAINTSTRUCT) -> i32;
    fn GetSystemMetrics(idx: i32) -> i32;
    fn LoadCursorW(inst: *mut c_void, name: *const u16) -> *mut c_void;
    fn SetCapture(h: *mut c_void) -> *mut c_void;
    fn ReleaseCapture() -> i32;
    fn SendMessageW(h: *mut c_void, m: u32, w: usize, l: isize) -> isize;
    fn DrawTextW(dc: *mut c_void, text: *const u16, len: i32, rc: *mut RECT, fmt: u32) -> i32;
    fn PostMessageW(h: *mut c_void, m: u32, w: usize, l: isize) -> i32;
    fn InvalidateRect(h: *mut c_void, rc: *const RECT, erase: i32) -> i32;
    fn FrameRect(dc: *mut c_void, rc: *const RECT, brush: *mut c_void) -> i32;
}

#[link(name = "gdi32")]
extern "system" {
    fn CreateSolidBrush(color: u32) -> *mut c_void;
    fn SelectObject(dc: *mut c_void, obj: *mut c_void) -> *mut c_void;
    fn DeleteObject(obj: *mut c_void) -> i32;
    fn CreateFontW(h: i32, w: i32, esc: i32, orient: i32, weight: i32, italic: u32,
                   underline: u32, strike: u32, charset: u32, out_prec: u32, clip: u32,
                   quality: u32, pitch: u32, face: *const u16) -> *mut c_void;
    fn SetTextColor(dc: *mut c_void, c: u32) -> u32;
    fn SetBkMode(dc: *mut c_void, m: i32) -> i32;
    fn StretchDIBits(dc: *mut c_void, xd: i32, yd: i32, wd: i32, hd: i32,
                     xs: i32, ys: i32, ws: i32, hs: i32,
                     bits: *const c_void, bi: *const BITMAPINFOHEADER, usage: u32, rop: u32) -> i32;
    fn Ellipse(dc: *mut c_void, l: i32, t: i32, r: i32, b: i32) -> i32;
    fn GetStockObject(obj: i32) -> *mut c_void;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_NCLBUTTONDOWN: u32 = 0x00A1;
const HTCAPTION: usize = 2;const WS_POPUP: u32 = 0x8000_0000;
const SW_SHOW: i32 = 5;
const CS_HREDRAW: u32 = 0x0002;
const CS_VREDRAW: u32 = 0x0001;
const DT_CENTER: u32 = 0x0001;
const DT_VCENTER: u32 = 0x0004;
const DT_SINGLELINE: u32 = 0x0020;
const DT_NOPREFIX: u32 = 0x0800;
const SRCCOPY: u32 = 0x00CC_0020;
const BI_RGB: u32 = 0;
const DIB_RGB_COLORS: u32 = 0;

static BG_BMP: &[u8] = include_bytes!("../assets/serverlist.bmp");
static BTN_BMP: &[u8] = include_bytes!("../assets/button.bmp");

// ---- 功能按钮：命中矩形（外观是底图原像素，绝不另画贴图）----
// 实测 serverlist.bmp 原图烧死像素：Recover 207..299×415..444、取消 400..492×415..444
const BTN_RECOVER: (i32, i32, i32, i32) = (207, 415, 300, 445); // 93x30
const BTN_CANCEL: (i32, i32, i32, i32) = (400, 415, 493, 445);  // 93x30
// 右上角 X 是底图自带的浮雕方块（周围是纯黑带，重画反而更差），保留原像素，只加热区
const BTN_CLOSE: (i32, i32, i32, i32) = (662, 2, 692, 28);

// hover 目标编码：0..n-1 = 区服 i；1000+ = 功能按钮
const HOV_RECOVER: usize = 1000;
const HOV_CANCEL: usize = 1001;
const HOV_CLOSE: usize = 1002;
const HOV_COLOR: u32 = rgb(255, 226, 130);

static QUIT: AtomicBool = AtomicBool::new(false);

/// X 按钮是否被点击过（真·退出启动器，区别于「取消回加载界面」）
pub fn quit_requested() -> bool {
    QUIT.load(Ordering::Relaxed)
}

fn in_rect(r: (i32, i32, i32, i32), x: i32, y: i32) -> bool {
    x >= r.0 && x < r.2 && y >= r.1 && y < r.3
}

// ---- 真实 Ping ----
// 后台线程对每个 enabled 区做 TCP connect，结果写入原子数组后 PostMessage 触发重绘。
const WM_APP_PING: u32 = 0x8000 + 1; // w_param = 区索引
const PING_CHECKING: u8 = 0;
const PING_OK: u8 = 1;
const PING_FAIL: u8 = 2;
const PING_TIMEOUT_MS: u64 = 800;
const MAX_SRV: usize = 8;

#[allow(clippy::declare_interior_mutable_const)]
const A8_ZERO: AtomicU8 = AtomicU8::new(PING_CHECKING);
#[allow(clippy::declare_interior_mutable_const)]
const A32_ZERO: AtomicU32 = AtomicU32::new(0);
static PINGS: [AtomicU8; MAX_SRV] = [A8_ZERO; MAX_SRV];
static PING_MS: [AtomicU32; MAX_SRV] = [A32_ZERO; MAX_SRV];

fn ping_state(i: usize) -> (u8, u32) {
    if i >= MAX_SRV {
        return (PING_CHECKING, 0);
    }
    (PINGS[i].load(Ordering::Relaxed), PING_MS[i].load(Ordering::Relaxed))
}

/// 逐区一个线程并行探测；完成后 PostMessage 让主线程重绘
/// （hwnd 以 usize 传递：*mut c_void 不能直接跨线程）
fn spawn_pings(hwnd: usize, targets: Vec<(usize, String, Option<u16>)>) {
    for (idx, ip, port) in targets {
        std::thread::spawn(move || unsafe {
            let hwnd = hwnd as *mut c_void;
            let addr: SocketAddr = match format!("{}:{}", ip, port.unwrap_or(2000)).parse() {
                Ok(a) => a,
                Err(_) => {
                    if idx < MAX_SRV {
                        PINGS[idx].store(PING_FAIL, Ordering::Relaxed);
                        PostMessageW(hwnd, WM_APP_PING, idx, 0);
                    }
                    return;
                }
            };
            let t0 = Instant::now();
            let ok = TcpStream::connect_timeout(&addr, Duration::from_millis(PING_TIMEOUT_MS)).is_ok();
            let ms = t0.elapsed().as_millis() as u32;
            if idx < MAX_SRV {
                PINGS[idx].store(if ok { PING_OK } else { PING_FAIL }, Ordering::Relaxed);
                PING_MS[idx].store(ms, Ordering::Relaxed);
                PostMessageW(hwnd, WM_APP_PING, idx, 0);
            }
        });
    }
}

struct Img {
    w: i32,
    h: i32,
    bits: Vec<u8>,
}

fn parse_bmp(d: &[u8]) -> Img {
    let off = u32::from_le_bytes([d[10], d[11], d[12], d[13]]) as usize;
    let w = i32::from_le_bytes([d[18], d[19], d[20], d[21]]);
    let h = i32::from_le_bytes([d[22], d[23], d[24], d[25]]).abs();
    let stride = ((w as usize * 3 + 3) / 4) * 4;
    let mut bits = vec![0u8; (w * h * 4) as usize];
    for y in 0..h as usize {
        let sy = h as usize - 1 - y;
        for x in 0..w as usize {
            let s = off + sy * stride + x * 3;
            let dst = (y * w as usize + x) * 4;
            bits[dst] = d[s];
            bits[dst + 1] = d[s + 1];
            bits[dst + 2] = d[s + 2];
            bits[dst + 3] = 255;
        }
    }
    Img { w, h, bits }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

struct SelectState {
    servers: Vec<Server>,
    picked: Option<usize>,
    hover: Option<usize>,
}

static mut STATE: Option<SelectState> = None;

fn plate_rect(i: usize, n: usize) -> (i32, i32) {
    if n <= 1 {
        ((W - PLATE_W) / 2, 150)
    } else {
        let col = (i % 2) as i32;
        let row = (i / 2) as i32;
        (155 + col * 190, 118 + row * 47)
    }
}

unsafe fn draw_img(hdc: *mut c_void, img: &Img, x: i32, y: i32) {
    let bi = BITMAPINFOHEADER {
        bi_size: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        bi_width: img.w,
        bi_height: -img.h,
        bi_planes: 1,
        bi_bit_count: 32,
        bi_compression: BI_RGB,
        bi_size_image: 0,
        bi_x_pels: 0,
        bi_y_pels: 0,
        bi_clr_used: 0,
        bi_clr_important: 0,
    };
    StretchDIBits(hdc, x, y, img.w, img.h, 0, 0, img.w, img.h,
                  img.bits.as_ptr() as *const c_void, &bi, DIB_RGB_COLORS, SRCCOPY);
}

/// hover 高亮边框
unsafe fn frame(hdc: *mut c_void, r: (i32, i32, i32, i32), color: u32) {
    let br = CreateSolidBrush(color);
    let rc = RECT { left: r.0, top: r.1, right: r.2, bottom: r.3 };
    FrameRect(hdc, &rc, br);
    DeleteObject(br);
}

/// 命中测试：返回 hover/点击目标编码
fn hit_test(st: Option<&SelectState>, x: i32, y: i32) -> Option<usize> {
    if in_rect(BTN_CLOSE, x, y) {
        return Some(HOV_CLOSE);
    }
    if in_rect(BTN_CANCEL, x, y) {
        return Some(HOV_CANCEL);
    }
    if in_rect(BTN_RECOVER, x, y) {
        return Some(HOV_RECOVER);
    }
    if let Some(s) = st {
        let n = s.servers.len();
        for i in 0..n {
            let (px, py) = plate_rect(i, n);
            if x >= px && x < px + PLATE_W && y >= py && y < py + PLATE_H {
                return Some(i);
            }
        }
    }
    None
}

unsafe fn fill_circle(hdc: *mut c_void, cx: i32, cy: i32, r: i32, color: u32) {
    let br = CreateSolidBrush(color);
    let old_b = SelectObject(hdc, br);
    let null_pen = GetStockObject(8); // NULL_PEN
    let old_p = SelectObject(hdc, null_pen);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, old_p);
    SelectObject(hdc, old_b);
    DeleteObject(br);
}

/// 状态圆点三态+探测中：暗边 -> 亮色主体 -> 左上高光（直径 16px，真正的圆形）
unsafe fn dot(hdc: *mut c_void, cx: i32, cy: i32, color: u32) {
    fill_circle(hdc, cx, cy, 8, rgb(24, 24, 22));
    fill_circle(hdc, cx, cy, 7, color);
    fill_circle(hdc, cx - 2, cy - 2, 2, rgb(224, 255, 214));
}

const DOT_GREEN: u32 = rgb(74, 226, 96);   // 通，快
const DOT_YELLOW: u32 = rgb(232, 200, 60); // 通，慢
const DOT_RED: u32 = rgb(230, 80, 70);     // 超时/拒绝
const DOT_CHECK: u32 = rgb(120, 130, 145); // 探测中
const DOT_GRAY: u32 = rgb(132, 128, 122);  // enabled=false

/// 根据枚举与 ping 结果返回（圆点颜色，名字后缀）
fn dot_and_suffix(enabled: bool, i: usize) -> (u32, String) {
    if !enabled {
        return (DOT_GRAY, String::new());
    }
    let (st, ms) = ping_state(i);
    match st {
        PING_OK => {
            let c = if ms < 150 { DOT_GREEN } else { DOT_YELLOW };
            (c, format!(" ({}ms)", ms))
        }
        PING_FAIL => (DOT_RED, " (超时)".to_string()),
        _ => (DOT_CHECK, String::new()),
    }
}

unsafe extern "system" fn wndproc(h: *mut c_void, msg: u32, wp: usize, lp: isize) -> isize {
    let st = &mut *std::ptr::addr_of_mut!(STATE);
    match msg {
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(h, &mut ps);
            let bg = parse_bmp(BG_BMP);
            let btn = parse_bmp(BTN_BMP);
            draw_img(hdc, &bg, 0, 0);
            let font = CreateFontW(-15, 0, 0, 0, 400, 0, 0, 0, 134, 0, 0, 5, 0,
                                   wide("Microsoft YaHei").as_ptr());
            SetBkMode(hdc, 1);
            if let Some(s) = st.as_ref() {
                let n = s.servers.len();
                for (i, srv) in s.servers.iter().enumerate() {
                    let (x, y) = plate_rect(i, n);
                    draw_img(hdc, &btn, x, y);
                    let mut rc = RECT { left: x, top: y, right: x + PLATE_W, bottom: y + PLATE_H };
                    let (dot_c, suffix) = dot_and_suffix(srv.enabled, i);
                    let label = format!("{}{}", srv.name, suffix);
                    let mut name: Vec<u16> = label.encode_utf16().collect();
                    name.push(0);
                    SelectObject(hdc, font);
                    SetTextColor(hdc, rgb(12, 9, 6));
                    let mut sh = RECT { left: rc.left + 1, top: rc.top + 1, right: rc.right + 1, bottom: rc.bottom + 1 };
                    DrawTextW(hdc, name.as_ptr(), (name.len() - 1) as i32, &mut sh,
                              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    SetTextColor(hdc, if srv.enabled { rgb(255, 252, 238) } else { rgb(168, 162, 150) });
                    DrawTextW(hdc, name.as_ptr(), (name.len() - 1) as i32, &mut rc,
                              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                    let cx = if n <= 1 { x - 16 } else if i % 2 == 0 { x - 16 } else { x + PLATE_W + 16 };
                    dot(hdc, cx, y + PLATE_H / 2, dot_c);
                }
            }
            // ---- 底部功能按钮：外观完全沿用底图原像素（严禁自造贴图）----
            // 这里只叠 hover 提示框；按钮本体就是 serverlist.bmp 里烧死的原图
            if let Some(hv) = st.as_ref().and_then(|s| s.hover) {
                match hv {
                    HOV_RECOVER => frame(hdc, BTN_RECOVER, HOV_COLOR),
                    HOV_CANCEL => frame(hdc, BTN_CANCEL, HOV_COLOR),
                    HOV_CLOSE => frame(hdc, BTN_CLOSE, HOV_COLOR),
                    _ => {}
                }
            }
            DeleteObject(font);
            EndPaint(h, &ps);
            0
        }
        WM_MOUSEMOVE => {
            let x = (lp & 0xFFFF) as i32;
            let y = ((lp >> 16) & 0xFFFF) as i32;
            let hov = hit_test(st.as_ref(), x, y);
            if st.as_ref().and_then(|s| s.hover) != hov {
                if let Some(s) = st.as_mut() {
                    s.hover = hov;
                }
                InvalidateRect(h, std::ptr::null(), 0);
            }
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lp & 0xFFFF) as i32;
            let y = ((lp >> 16) & 0xFFFF) as i32;
            match hit_test(st.as_ref(), x, y) {
                Some(HOV_CLOSE) => {
                    // 右上角 X：关闭整个启动器
                    QUIT.store(true, Ordering::Relaxed);
                    DestroyWindow(h);
                    PostQuitMessage(0);
                }
                Some(HOV_CANCEL) => {
                    // 取消：关闭选区窗，回到加载界面（picked 保持 None）
                    DestroyWindow(h);
                    PostQuitMessage(0);
                }
                Some(HOV_RECOVER) => {
                    // Recover 暂未绑定功能（占位）
                }
                Some(i) => {
                    let ok = st.as_ref().map(|s| s.servers[i].enabled).unwrap_or(false);
                    if ok {
                        if let Some(s) = st.as_mut() {
                            s.picked = Some(i);
                        }
                        DestroyWindow(h);
                        PostQuitMessage(0);
                    }
                }
                None => {
                    ReleaseCapture();
                    SendMessageW(h, WM_NCLBUTTONDOWN, HTCAPTION, 0);
                }
            }
            0
        }
        WM_APP_PING => {
            // 某个区的 ping 结果回来了：整窗重绘（窗口小，代价可忽略）
            InvalidateRect(h, std::ptr::null(), 0);
            0
        }
        WM_CLOSE => {
            // 系统关闭（Alt+F4 等）视同 X：退出启动器
            QUIT.store(true, Ordering::Relaxed);
            DestroyWindow(h);
            PostQuitMessage(0);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(h, msg, wp, lp),
    }
}

/// 显示区服选择窗口，返回被选中的索引
pub fn select(servers: Vec<Server>) -> Option<usize> {
    if servers.is_empty() {
        return None;
    }
    unsafe { run(servers) }
}

unsafe fn run(servers: Vec<Server>) -> Option<usize> {
    let st = &mut *std::ptr::addr_of_mut!(STATE);
    *st = Some(SelectState { servers, picked: None, hover: None });
    QUIT.store(false, Ordering::Relaxed);

    let inst = GetModuleHandleW(std::ptr::null());
    let cls = wide("L1JServerSelect");
    let title = wide("Lineage: Select Server");
    let wc = WNDCLASSEXW {
        cb_size: std::mem::size_of::<WNDCLASSEXW>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfn_wnd_proc: Some(wndproc),
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: inst,
        h_icon: std::ptr::null_mut(),
        h_cursor: LoadCursorW(std::ptr::null_mut(), 32512 as *const u16),
        hbr_background: std::ptr::null_mut(),
        lpsz_menu_name: std::ptr::null(),
        lpsz_class_name: cls.as_ptr(),
        h_icon_sm: std::ptr::null_mut(),
    };
    RegisterClassExW(&wc);
    let sw = GetSystemMetrics(0);
    let sh = GetSystemMetrics(1);
    let hwnd = CreateWindowExW(0, cls.as_ptr(), title.as_ptr(), WS_POPUP,
                               (sw - W) / 2, (sh - H) / 2, W, H,
                               std::ptr::null_mut(), std::ptr::null_mut(), inst,
                               std::ptr::null_mut());
    if hwnd.is_null() {
        return Some(0);
    }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // 后台真实 ping：enabled 的区逐区一线程，探测完 PostMessage 重绘
    let targets: Vec<(usize, String, Option<u16>)> = st
        .as_ref()
        .unwrap()
        .servers
        .iter()
        .enumerate()
        .filter(|(_, s)| s.enabled)
        .map(|(i, s)| (i, s.ip.clone(), s.port))
        .collect();
    spawn_pings(hwnd as usize, targets);

    let mut msg: MSG = std::mem::zeroed();
    while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    st.as_ref().and_then(|s| s.picked)
}
