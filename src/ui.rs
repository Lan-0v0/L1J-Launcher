//! 原生更新窗口（GDI 绘制，无第三方 UI 库）
//!
//! 底图 = 客户端 `skin\Bulletin.bmp` 的预处理版（洋红透明键已填、进度条已擦空）
//! 布局实测（692×460）：
//!   蓝条「目前進度」 x=105..470 y=407..414
//!   红条「總進度」   x=105..470 y=424..431
//!   状态文字区       x=106..472 y=386..404（进度条正上方，公告栏不动）
//!   開始按钮         x=569..666 y=366..413
//!   取消按钮         x=569..666 y=414..447

#![cfg(windows)]
use std::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};

pub const W: i32 = 692;
pub const H: i32 = 460;

const BAR_X: i32 = 105;
const BAR_W: i32 = 366;
const BAR1_Y: i32 = 407;
const BAR2_Y: i32 = 424;
const STATUS_RECT: (i32, i32, i32, i32) = (176, 386, 560, 404);
const BTN_START: (i32, i32, i32, i32) = (569, 366, 666, 413);
const BTN_CANCEL: (i32, i32, i32, i32) = (569, 414, 666, 447);
const BTN_CLOSE: (i32, i32, i32, i32) = (670, 2, 692, 24); // 皮肤右上角那个小 X

const BLUE: [(u8, u8, u8); 8] = [
    (165, 215, 239), (107, 162, 231), (107, 162, 231), (49, 109, 198),
    (24, 77, 156), (16, 60, 132), (16, 52, 123), (8, 44, 115),
];
const RED: [(u8, u8, u8); 8] = [
    (222, 134, 148), (222, 105, 82), (222, 105, 82), (189, 65, 33),
    (148, 40, 8), (123, 36, 0), (115, 36, 0), (110, 34, 0),
];

#[derive(Clone, Copy, PartialEq)]
pub enum Phase {
    Working,
    Done,
    Failed,
}

#[derive(Clone)]
pub struct UiState {
    pub phase: Phase,
    pub current: f32, // 目前進度 0..1
    pub overall: f32, // 總進度 0..1
    pub status: String,
    pub version: String,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            phase: Phase::Working,
            current: 0.0,
            overall: 0.0,
            status: "正在檢查更新…".into(),
            version: String::new(),
        }
    }
}

pub type Shared = Arc<Mutex<UiState>>;

static HWND_G: OnceLock<usize> = OnceLock::new();

/// 工作线程调用：通知 UI 重绘
pub fn notify() {
    if let Some(&h) = HWND_G.get() {
        unsafe {
            InvalidateRect(h as *mut c_void, std::ptr::null(), 0);
        }
    }
}

use std::sync::atomic::{AtomicBool, Ordering};
static CANCELED: AtomicBool = AtomicBool::new(false);
static START_CLICKED: AtomicBool = AtomicBool::new(false);

pub fn canceled() -> bool {
    CANCELED.load(Ordering::Relaxed)
}
pub fn start_clicked() -> bool {
    START_CLICKED.load(Ordering::Relaxed)
}

pub fn run(state: Shared) -> i32 {
    unsafe { imp::run(state) }
}

// ---------------- FFI ----------------
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
    fn GetDC(h: *mut c_void) -> *mut c_void;
    fn ReleaseDC(h: *mut c_void, dc: *mut c_void) -> i32;
    fn GetSystemMetrics(idx: i32) -> i32;
    fn InvalidateRect(h: *mut c_void, r: *const c_void, erase: i32) -> i32;
    fn LoadCursorW(inst: *mut c_void, name: *const u16) -> *mut c_void;
    fn SetCapture(h: *mut c_void) -> *mut c_void;
    fn ReleaseCapture() -> i32;
    fn SendMessageW(h: *mut c_void, m: u32, w: usize, l: isize) -> isize;
    fn DrawTextW(dc: *mut c_void, text: *const u16, len: i32, rc: *mut RECT, fmt: u32) -> i32;
    fn FillRect(dc: *mut c_void, rc: *const RECT, brush: *mut c_void) -> i32;
    fn GetClientRect(h: *mut c_void, rc: *mut RECT) -> i32;
}

#[link(name = "gdi32")]
extern "system" {
    fn CreateCompatibleDC(dc: *mut c_void) -> *mut c_void;
    fn DeleteDC(dc: *mut c_void) -> i32;
    fn SelectObject(dc: *mut c_void, obj: *mut c_void) -> *mut c_void;
    fn DeleteObject(obj: *mut c_void) -> i32;
    fn CreateSolidBrush(color: u32) -> *mut c_void;
    fn CreateFontW(h: i32, w: i32, esc: i32, orient: i32, weight: i32, italic: u32,
                   underline: u32, strike: u32, charset: u32, out_prec: u32, clip: u32,
                   quality: u32, pitch: u32, face: *const u16) -> *mut c_void;
    fn SetTextColor(dc: *mut c_void, color: u32) -> u32;
    fn SetBkMode(dc: *mut c_void, mode: i32) -> i32;
    fn StretchDIBits(dc: *mut c_void, xd: i32, yd: i32, wd: i32, hd: i32,
                     xs: i32, ys: i32, ws: i32, hs: i32,
                     bits: *const c_void, bi: *const BITMAPINFOHEADER, usage: u32, rop: u32) -> i32;
    fn CreateBitmap(w: i32, h: i32, planes: u32, bits: u32, data: *const c_void) -> *mut c_void;
    fn CreatePatternBrush(bmp: *mut c_void) -> *mut c_void;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
}

const WM_DESTROY: u32 = 0x0002;
const WM_PAINT: u32 = 0x000F;
const WM_CLOSE: u32 = 0x0010;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_NCLBUTTONDOWN: u32 = 0x00A1;
const HTCAPTION: usize = 2;
const WS_POPUP: u32 = 0x8000_0000;
const WS_SYSMENU: u32 = 0x0008_0000;
const SW_SHOW: i32 = 5;
const CS_HREDRAW: u32 = 0x0002;
const CS_VREDRAW: u32 = 0x0001;
const DT_LEFT: u32 = 0x0000;
const DT_VCENTER: u32 = 0x0004;
const DT_SINGLELINE: u32 = 0x0020;
const DT_NOPREFIX: u32 = 0x0800;
const SRCCOPY: u32 = 0x00CC_0020;
const BI_RGB: u32 = 0;
const DIB_RGB_COLORS: u32 = 0;

mod imp {
    use super::*;

    // 底图（BMP，24bpp，54 字节头）
    static BG_BMP: &[u8] = include_bytes!("../assets/bulletin.bmp");

    pub struct Bg {
        pub w: i32,
        pub h: i32,
        pub bits: Vec<u8>, // BGRA，自顶向下
        pub dim: Vec<u8>,  // 50% 暗化副本（禁用态）
    }

    pub fn parse_bg() -> Bg {
        let d = BG_BMP;
        let off = u32::from_le_bytes([d[10], d[11], d[12], d[13]]) as usize;
        let w = i32::from_le_bytes([d[18], d[19], d[20], d[21]]);
        let h = i32::from_le_bytes([d[22], d[23], d[24], d[25]]).abs();
        let bpp = u16::from_le_bytes([d[28], d[29]]) as usize;
        assert_eq!(bpp, 24, "底图必须是 24bpp");
        let stride = ((w as usize * 3 + 3) / 4) * 4;
        let mut bits = vec![0u8; (w * h * 4) as usize];
        for y in 0..h as usize {
            let src_y = h as usize - 1 - y;
            for x in 0..w as usize {
                let s = off + src_y * stride + x * 3;
                let dst = (y * w as usize + x) * 4;
                bits[dst] = d[s];         // B
                bits[dst + 1] = d[s + 1]; // G
                bits[dst + 2] = d[s + 2]; // R
                bits[dst + 3] = 255;
            }
        }
        let dim = bits
            .iter()
            .map(|v| (v / 2) as u8)
            .collect::<Vec<u8>>();
        let _ = &mut bits;
        Bg { w, h, bits, dim }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn rgb(r: u8, g: u8, b: u8) -> u32 {
        (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
    }

    unsafe fn fill(hdc: *mut c_void, x: i32, y: i32, w: i32, h: i32, color: u32) {
        let br = CreateSolidBrush(color);
        let rc = RECT { left: x, top: y, right: x + w, bottom: y + h };
        FillRect(hdc, &rc, br);
        DeleteObject(br);
    }

    unsafe fn draw_bg(hdc: *mut c_void, bg: &Bg) {
        let bi = BITMAPINFOHEADER {
            bi_size: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            bi_width: bg.w,
            bi_height: -bg.h, // 负数 = 自顶向下
            bi_planes: 1,
            bi_bit_count: 32,
            bi_compression: BI_RGB,
            bi_size_image: 0,
            bi_x_pels: 0,
            bi_y_pels: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        };
        StretchDIBits(hdc, 0, 0, bg.w, bg.h, 0, 0, bg.w, bg.h,
                      bg.bits.as_ptr() as *const c_void, &bi, DIB_RGB_COLORS, SRCCOPY);
    }

    unsafe fn draw_bar(hdc: *mut c_void, y: i32, pct: f32, pal: &[(u8, u8, u8); 8], dim: bool) {
        let p = pct.clamp(0.0, 1.0);
        let end = BAR_X + (BAR_W as f32 * p) as i32;
        if end <= BAR_X {
            return;
        }
        for (i, c) in pal.iter().enumerate() {
            let (mut r, mut g, mut b) = *c;
            if dim {
                r = (r as u32 * 6 / 10) as u8;
                g = (g as u32 * 6 / 10) as u8;
                b = (b as u32 * 6 / 10) as u8;
            }
            fill(hdc, BAR_X, y + i as i32, end - BAR_X, 1, rgb(r, g, b));
        }
    }

    unsafe fn draw_status(hdc: *mut c_void, text: &str, color: u32, font: *mut c_void) {
        let (l, t, r, b) = STATUS_RECT;
        let mut rc = RECT { left: l, top: t, right: r, bottom: b };
        let mut w: Vec<u16> = text.encode_utf16().collect();
        w.push(0);
        SelectObject(hdc, font);
        SetBkMode(hdc, 1); // TRANSPARENT
        SetTextColor(hdc, color);
        DrawTextW(hdc, w.as_ptr(), (w.len() - 1) as i32, &mut rc,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }

    unsafe fn dim_rect(hdc: *mut c_void, bg: &Bg, r: (i32, i32, i32, i32)) {
        let (l, t, rr, b) = r;
        let bi = BITMAPINFOHEADER {
            bi_size: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            bi_width: bg.w,
            bi_height: -bg.h,
            bi_planes: 1,
            bi_bit_count: 32,
            bi_compression: BI_RGB,
            bi_size_image: 0,
            bi_x_pels: 0,
            bi_y_pels: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        };
        StretchDIBits(hdc, l, t, rr - l, b - t, l, t, rr - l, b - t,
                      bg.dim.as_ptr() as *const c_void, &bi, DIB_RGB_COLORS, SRCCOPY);
    }

    unsafe extern "system" fn wndproc(h: *mut c_void, msg: u32, wp: usize, lp: isize) -> isize {
        match msg {
            WM_PAINT => {
                let mut ps: PAINTSTRUCT = std::mem::zeroed();
                let hdc = BeginPaint(h, &mut ps);
                let bg = parse_bg();
                draw_bg(hdc, &bg);

                let st = crate::ui::STATE.get().map(|s| s.lock().unwrap().clone()).unwrap_or_default();
                let dim = !matches!(st.phase, Phase::Done | Phase::Failed);
                draw_bar(hdc, BAR1_Y, st.current, &BLUE, false);
                draw_bar(hdc, BAR2_Y, st.overall, &RED, false);
                let _ = dim; // 方案B：不动「開始」的图，只在逻辑上禁用点击

                let font = CreateFontW(-12, 0, 0, 0, 400, 0, 0, 0, 134, 0, 0, 5, 0,
                                       wide("Microsoft YaHei").as_ptr());
                let color = if matches!(st.phase, Phase::Failed) { rgb(232, 120, 108) } else { rgb(216, 185, 106) };
                draw_status(hdc, &st.status, color, font);
                DeleteObject(font);
                EndPaint(h, &ps);
                0
            }
            WM_LBUTTONDOWN => {
                let x = (lp & 0xFFFF) as i32;
                let y = ((lp >> 16) & 0xFFFF) as i32;
                if hit(BTN_CLOSE, x, y) {
                    CANCELED.store(true, Ordering::Relaxed);
                    DestroyWindow(h);
                    PostQuitMessage(0);
                } else if hit(BTN_CANCEL, x, y) {
                    CANCELED.store(true, Ordering::Relaxed);
                    DestroyWindow(h);
                    PostQuitMessage(0);
                } else if hit(BTN_START, x, y) {
                    let st = crate::ui::STATE.get().map(|s| s.lock().unwrap().clone()).unwrap_or_default();
                    if matches!(st.phase, Phase::Done | Phase::Failed) {
                        START_CLICKED.store(true, Ordering::Relaxed);
                        DestroyWindow(h);
                        PostQuitMessage(0);
                    }
                } else {
                    // 拖动窗口
                    ReleaseCapture();
                    SendMessageW(h, WM_NCLBUTTONDOWN, HTCAPTION, 0);
                }
                0
            }
            WM_CLOSE => {
                CANCELED.store(true, Ordering::Relaxed);
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

    fn hit(r: (i32, i32, i32, i32), x: i32, y: i32) -> bool {
        x >= r.0 && x < r.2 && y >= r.1 && y < r.3
    }

    pub unsafe fn run(state: Shared) -> i32 {
        let _ = crate::ui::STATE.set(state);
        let inst = GetModuleHandleW(std::ptr::null());
        let cls = wide("L1JLauncherWnd");
        let title = wide("Lineage: Auto-Updater");

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
        let x = (sw - W) / 2;
        let y = (sh - H) / 2;

        let hwnd = CreateWindowExW(0, cls.as_ptr(), title.as_ptr(), WS_POPUP,
                                   x, y, W, H, std::ptr::null_mut(), std::ptr::null_mut(),
                                   inst, std::ptr::null_mut());
        if hwnd.is_null() {
            return 1;
        }
        let _ = crate::ui::HWND_G.set(hwnd as usize);
        ShowWindow(hwnd, SW_SHOW);
        UpdateWindow(hwnd);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        0
    }
}

static STATE: OnceLock<Shared> = OnceLock::new();
