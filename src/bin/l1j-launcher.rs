#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! l1j-launcher —— 客户端更新器
//!
//! 默认：原生更新窗口（与客户端 `skin\Bulletin.bmp` 同款）
//! `--console`：控制台模式（自测/排错）

use l1j_launcher::{config::Config, launch, update};
#[cfg(windows)]
use l1j_launcher::ui::{self, Phase, UiState};
use l1pak::Container;
use std::path::{Path, PathBuf};

fn main() {
    // 决策：与同行一致——启动即提权，只弹一次 UAC（后续如要改回最小权限，删掉这行即可）
    l1j_launcher::elevate::ensure_admin();
    let exe = std::env::current_exe().unwrap_or_else(|e| {
        eprintln!("取程序路径失败: {}", e);
        std::process::exit(1)
    });
    let dir = exe
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let cfg_path = dir.join("launcher.json");
    if !cfg_path.exists() {
        let _ = l1j_launcher::config::write_example(&cfg_path);
        eprintln!("未找到 launcher.json，已生成示例：{}", cfg_path.display());
        std::process::exit(2);
    }
    let cfg = Config::load(&cfg_path).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(2)
    });
    let client = cfg.client_path(&dir);

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--console") {
        console_flow(&cfg, &client);
        return;
    }

    #[cfg(windows)]
    {
        let state: ui::Shared = std::sync::Arc::new(std::sync::Mutex::new(UiState::default()));
        let st = state.clone();
        let cfg2 = cfg.clone();
        let client2 = client.clone();
        std::thread::spawn(move || worker(cfg2, client2, st));
        // 主循环：加载窗 → 开始 → 选区窗；选区点「取消」回到加载窗，X / 启动成功则退出
        loop {
            ui::reset_flags();
            let rc = ui::run(state.clone());
            if !ui::start_clicked() {
                std::process::exit(rc);
            }
            match do_launch(&cfg, &client) {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    if l1j_launcher::select::quit_requested() || e != "未选择区服" {
                        std::process::exit(1);
                    }
                    // 「取消」→ 继续循环，重新弹出加载界面
                }
            }
        }
    }
    #[cfg(not(windows))]
    console_flow(&cfg, &client);
}

#[cfg(windows)]
fn worker(cfg: Config, client: PathBuf, state: ui::Shared) {
    // 只设「目标值」，绘制值由 ui 的 33ms 定时器缓动追上去（这就是进度条动画）
    let set = |phase: Phase, cur: f32, ovr: f32, msg: String| {
        {
            let mut s = state.lock().unwrap();
            s.phase = phase;
            s.target_current = cur;
            s.target_overall = ovr;
            s.status = msg;
        }
        ui::notify();
    };

    set(Phase::Working, 0.0, 0.0, "正在檢查更新…".into());
    if ui::canceled() {
        return;
    }

    let manifest = match update::fetch_and_verify(&cfg.update_base, &cfg.public_key) {
        Ok(m) => m,
        Err(e) => {
            set(Phase::Failed, 0.0, 0.0, format!("更新失敗：{}", trim(&e, 32)));
            return;
        }
    };
    let files_cfg = manifest.files.clone().unwrap_or_default();
    let has_text = !manifest.entries.is_empty();
    let has_files = !files_cfg.is_empty();
    if !has_text && !has_files {
        set(Phase::Done, 1.0, 1.0, "已是最新版本".into());
        return;
    }

    // 只有存在 Text 条目时才需要容器；纯文件更新不依赖 Text.pak
    let mut container = if has_text {
        match Container::load(&client) {
            Ok(c) => {
                if let Err(e) = update::verify_container(&c) {
                    set(Phase::Failed, 0.0, 0.0, format!("客戶端校驗失敗：{}", trim(&e, 24)));
                    return;
                }
                Some(c)
            }
            Err(e) => {
                set(Phase::Failed, 0.0, 0.0, format!("讀取客戶端失敗：{}", trim(&e, 26)));
                return;
            }
        }
    } else {
        None
    };

    let plan = match update::plan(&manifest, container.as_ref(), &client) {
        Ok(p) => p,
        Err(e) => {
            set(Phase::Failed, 0.0, 0.0, format!("更新失敗：{}", trim(&e, 32)));
            return;
        }
    };
    if plan.to_download.is_empty() && plan.files.is_empty() {
        let _ = update::write_local_version(&client, &plan.version, &[], &[]);
        set(Phase::Done, 1.0, 1.0, format!("已是最新（{}）", plan.version));
        return;
    }

    let n_text = plan.to_download.len();
    let n_files = plan.files.to_download.len() + plan.files.to_delete.len();
    let total = n_text + n_files;
    let mut applied_text: Vec<String> = Vec::new();
    let mut applied_files: Vec<String> = Vec::new();

    // ---- Text 通道 ----
    if n_text > 0 {
        let mut prog = |desc: &str, i: usize, _n: usize, frac: f32| {
            let ovr = if total == 0 {
                0.0
            } else {
                ((i as f32) + frac) / (total as f32)
            };
            set(
                Phase::Working,
                frac,
                ovr,
                (if desc.is_empty() {
                    "正在下載更新…".to_string()
                } else {
                    format!("正在下載更新… {}", desc)
                }),
            );
        };
        match update::apply(
            &cfg.update_base,
            &client,
            container.as_mut().unwrap(),
            &plan,
            &mut prog,
        ) {
            Ok(_) => {
                applied_text = plan.to_download.iter().map(|e| e.name.clone()).collect()
            }
            Err(e) => {
                set(Phase::Failed, 0.0, 0.0, format!("更新失敗：{}", trim(&e, 32)));
                return;
            }
        }
    }

    // ---- 文件通道 ----
    if n_files > 0 {
        let mut prog = |desc: &str, i: usize, _n: usize, frac: f32| {
            let done = (n_text + i) as f32 + frac;
            let ovr = if total == 0 { 0.0 } else { done / (total as f32) };
            set(
                Phase::Working,
                frac,
                ovr,
                (if desc.is_empty() {
                    "正在下載更新…".to_string()
                } else {
                    format!("正在下載更新… {}", desc)
                }),
            );
        };
        match update::apply_files(
            &cfg.update_base,
            &client,
            &files_cfg,
            &plan.files,
            &plan.version,
            &mut prog,
        ) {
            Ok(_) => {
                applied_files = plan
                    .files
                    .to_download
                    .iter()
                    .map(|e| e.path.clone())
                    .chain(plan.files.to_delete.iter().cloned())
                    .collect();
            }
            Err(e) => {
                set(Phase::Failed, 0.0, 0.0, format!("更新失敗：{}", trim(&e, 32)));
                return;
            }
        }
    }

    let _ = update::write_local_version(&client, &plan.version, &applied_text, &applied_files);
    set(Phase::Done, 1.0, 1.0, format!("更新完成（{}）", plan.version));
}

/// 解析 "地址:原字节HEX:新字节HEX"
fn parse_patches(list: &[String]) -> Vec<(usize, Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for item in list {
        let parts: Vec<&str> = item.split(':').collect();
        if parts.len() != 3 {
            continue;
        }
        let addr = match usize::from_str_radix(parts[0].trim_start_matches("0x"), 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let old = (0..parts[1].len() / 2)
            .filter_map(|i| u8::from_str_radix(&parts[1][i * 2..i * 2 + 2], 16).ok())
            .collect::<Vec<u8>>();
        let new = (0..parts[2].len() / 2)
            .filter_map(|i| u8::from_str_radix(&parts[2][i * 2..i * 2 + 2], 16).ok())
            .collect::<Vec<u8>>();
        if !old.is_empty() && old.len() == new.len() {
            out.push((addr, old, new));
        }
    }
    out
}

/// 启动：先选服（>=2 个时才弹窗），再按 IP 十进制参数拉起游戏
fn do_launch(cfg: &Config, client: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        l1j_launcher::launch::set_extra_patches(parse_patches(&cfg.extra_patches));
        if cfg.use_vendor_dialog && !cfg.game_exe.to_lowercase().ends_with(".bin") {
            let ini = format!("{}.ini",
                std::path::Path::new(&cfg.game_exe)
                    .file_stem().map(|v| v.to_string_lossy().to_string()).unwrap_or_default());
            let src = client.join("servers.ini");
            if src.is_file() {
                match std::fs::copy(&src, client.join(&ini)) {
                    Ok(_) => sel_log(&format!("已写 {}（来自 servers.ini）", ini)),
                    Err(e) => sel_log(&format!("复制 servers.ini 失败: {}", e)),
                }
            } else {
                sel_log("缺少 servers.ini");
            }
            return launch::launch_game(client, &cfg.game_exe);
        }
        if cfg.dev_skip_select {
            let pick = cfg.servers.iter().position(|x| x.enabled).unwrap_or(0);
            let sv = &cfg.servers[pick];
            sel_log(&format!("选中: {} ip={} port={:?}", sv.name, sv.ip, sv.port));

            l1j_launcher::launch::set_real_server(&format!("{}:{}", sv.ip, sv.port.unwrap_or(2000)));
            if let Some(blob) = sv.server_data.as_deref() {
                let ini = if cfg.game_exe.to_lowercase().ends_with(".bin") {
                    "Login.ini".to_string()
                } else {
                    format!("{}.ini", std::path::Path::new(&cfg.game_exe).file_stem().map(|v| v.to_string_lossy().to_string()).unwrap_or_default())
                };
                sel_log(&format!("写 {}: {:?}", ini, l1j_launcher::launch::write_server_data(client, &ini, blob)));
            }
            return match cfg.launch_arg.as_deref() {
                Some(a) if !a.trim().is_empty() => {
                    l1j_launcher::launch::launch_game_with_args(client, &cfg.game_exe, a.trim())
                }
                _ => l1j_launcher::launch::launch_game_with_ip(
                    client, &cfg.game_exe, &cfg.servers[pick].ip),
            };
        }
        if !cfg.servers.is_empty() {
            let list: Vec<l1j_launcher::select::Server> = cfg
                .servers
                .iter()
                .map(|s| l1j_launcher::select::Server {
                    name: s.name.clone(),
                    ip: s.ip.clone(),
                    enabled: s.enabled,
                    port: s.port,
                })
                .collect();
            return match l1j_launcher::select::select(list) {
                Some(i) => {
                    let sv = &cfg.servers[i];
                    sel_log(&format!("选中: {} ip={} port={:?}", sv.name, sv.ip, sv.port));
                    launch::set_click_index(i);
                    {
                        let ini = if cfg.game_exe.to_lowercase().ends_with(".bin") { "Login.ini".to_string() }
                                  else { format!("{}.ini", std::path::Path::new(&cfg.game_exe).file_stem().map(|v| v.to_string_lossy().to_string()).unwrap_or_default()) };
                        if let Ok(tpl) = std::fs::read(client.join("servers.ini")) {
                            // 按字节切块（区名是 GBK，绝不能转 UTF-8），只写被选中的那一块
                            let key = b"[Server";
                            let mut starts: Vec<usize> = Vec::new();
                            let mut k = 0usize;
                            while k + key.len() <= tpl.len() {
                                if &tpl[k..k + key.len()] == key { starts.push(k); k += key.len(); }
                                else { k += 1; }
                            }
                            if let Some(&st) = starts.get(i) {
                                let end = starts.get(i + 1).copied().unwrap_or(tpl.len());
                                let _ = std::fs::write(client.join(&ini), &tpl[st..end]);
                                sel_log(&format!("已写 {}（仅第 {} 区）", ini, i + 1));
                            }
                        }
                    }

                    launch::set_real_server(&format!("{}:{}", sv.ip, sv.port.unwrap_or(2000)));
                    if let Some(blob) = sv.server_data.as_deref() {
                        let ini = if cfg.game_exe.to_lowercase().ends_with(".bin") {
                    "Login.ini".to_string()
                } else {
                    format!("{}.ini", std::path::Path::new(&cfg.game_exe).file_stem().map(|v| v.to_string_lossy().to_string()).unwrap_or_default())
                };
                        sel_log(&format!("写 {}: {:?}", ini, launch::write_server_data(client, &ini, blob)));
                    }
                    launch::launch_game_with_ip(client, &cfg.game_exe, &sv.ip)
                }
                None => Err("未选择区服".into()),
            };
        }
    }
    match cfg.server_ip.as_deref() {
        Some(ip) if !ip.trim().is_empty() => {
            launch::launch_game_with_ip(client, &cfg.game_exe, ip.trim())
        }
        _ => launch::launch_game(client, &cfg.game_exe),
    }
}

/// 选区写入日志（GUI 程序 eprintln 不可见，必须落盘）
fn sel_log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true)
        .open("D://l1log//sel_log.txt") {
        let _ = writeln!(f, "[{}] {}", chrono_now(), msg);
    }
}
fn chrono_now() -> String {
    // 简易时间戳（秒级）
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "?".into())
}

fn trim(s: &str, n: usize) -> String {
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i >= n {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out.replace('\n', " ")
}

fn console_flow(cfg: &Config, client: &Path) {
    use std::io::Write as _;
    let manifest = match update::fetch_and_verify(&cfg.update_base, &cfg.public_key) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[更新] 取清单失败: {}", e);
            if cfg.launch_on_error {
                let _ = do_launch(cfg, client);
            }
            return;
        }
    };
    println!(
        "本地版本: {:?}   远端: {}",
        update::read_local_version(client).map(|v| v.version),
        manifest.version
    );
    let files_cfg = manifest.files.clone().unwrap_or_default();
    let has_text = !manifest.entries.is_empty();
    let has_files = !files_cfg.is_empty();
    if !has_text && !has_files {
        println!("清单为空，已是最新。");
        return;
    }

    let mut c = if has_text {
        match Container::load(client) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("{}", e);
                return;
            }
        }
    } else {
        None
    };
    let plan = match update::plan(&manifest, c.as_ref(), client) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("生成更新计划失败: {}", e);
            return;
        }
    };
    println!(
        "Text 条目 {}：需下载 {}，已是最新 {} | 文件 {}：需下载 {}，删除 {}，已是最新 {}",
        manifest.entries.len(),
        plan.to_download.len(),
        plan.skipped,
        files_cfg.entries.len(),
        plan.files.to_download.len(),
        plan.files.to_delete.len(),
        plan.files.skipped
    );

    let mut applied_text: Vec<String> = Vec::new();
    let mut applied_files: Vec<String> = Vec::new();

    if !plan.to_download.is_empty() {
        match update::apply(&cfg.update_base, client, c.as_mut().unwrap(), &plan, &mut |d, i, n, frac| {
            if frac <= 0.0 || frac >= 1.0 {
                println!("  [{}/{}] {}", i + 1, n, d)
            } else {
                print!("\r  [{}/{}] {} {:.0}%   ", i + 1, n, d, frac * 100.0);
                let _ = std::io::stdout().flush();
            }
        }) {
            Ok(rep) => {
                println!(
                    "合并完成：原地写 {} 条，追加 {} 条；pak {} → {} B",
                    rep.inplace.len(),
                    rep.appended.len(),
                    rep.pak_old,
                    rep.pak_new
                );
                applied_text = plan.to_download.iter().map(|e| e.name.clone()).collect();
            }
            Err(e) => {
                eprintln!("更新失败: {}", e);
                return;
            }
        }
    }

    if plan.files.is_empty() {
        println!("文件通道：无变更");
    } else {
        match update::apply_files(
            &cfg.update_base,
            client,
            &files_cfg,
            &plan.files,
            &plan.version,
            &mut |d, i, n, frac| {
                if frac <= 0.0 || frac >= 1.0 {
                    println!("  [文件 {}/{}] {}", i + 1, n, d)
                } else {
                    print!("\r  [文件 {}/{}] {} {:.0}%   ", i + 1, n, d, frac * 100.0);
                    let _ = std::io::stdout().flush();
                }
            },
        ) {
            Ok(rep) => {
                println!(
                    "文件通道完成：写入 {} 个，删除 {} 个，备份 {}",
                    rep.written,
                    rep.deleted,
                    rep.backup.unwrap_or_else(|| "-".into())
                );
                applied_files = plan
                    .files
                    .to_download
                    .iter()
                    .map(|e| e.path.clone())
                    .chain(plan.files.to_delete.iter().cloned())
                    .collect();
            }
            Err(e) => {
                eprintln!("文件通道失败: {}", e);
                return;
            }
        }
    }

    let _ = update::write_local_version(client, &plan.version, &applied_text, &applied_files);
    if applied_text.is_empty() && applied_files.is_empty() {
        println!("已是最新。");
    }
}
