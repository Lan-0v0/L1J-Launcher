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
        let rc = ui::run(state);
        if ui::start_clicked() {
            let _ = do_launch(&cfg, &client);
        }
        std::process::exit(rc);
    }
    #[cfg(not(windows))]
    console_flow(&cfg, &client);
}

#[cfg(windows)]
fn worker(cfg: Config, client: PathBuf, state: ui::Shared) {
    let set = |phase: Phase, cur: f32, ovr: f32, msg: String| {
        {
            let mut s = state.lock().unwrap();
            s.phase = phase;
            s.current = cur;
            s.overall = ovr;
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
    if manifest.entries.is_empty() {
        set(Phase::Done, 1.0, 1.0, "已是最新版本".into());
        return;
    }

    let mut container = match Container::load(&client) {
        Ok(c) => c,
        Err(e) => {
            set(Phase::Failed, 0.0, 0.0, format!("讀取客戶端失敗：{}", trim(&e, 26)));
            return;
        }
    };
    if let Err(e) = update::verify_container(&container) {
        set(Phase::Failed, 0.0, 0.0, format!("客戶端校驗失敗：{}", trim(&e, 24)));
        return;
    }
    let plan = update::plan(&manifest, &container);
    if plan.to_download.is_empty() {
        let _ = update::write_local_version(&client, &plan.version, &[]);
        set(Phase::Done, 1.0, 1.0, format!("已是最新（{}）", plan.version));
        return;
    }

    let res = update::apply(
        &cfg.update_base,
        &client,
        &mut container,
        &plan,
        &mut |_desc, i, n| {
            let p = if n == 0 { 0.0 } else { (i as f32) / (n as f32) };
            set(Phase::Working, 0.0, p, "正在下載更新…".into());
        },
    );

    match res {
        Ok(_) => {
            let names: Vec<String> = plan.to_download.iter().map(|e| e.name.clone()).collect();
            let _ = update::write_local_version(&client, &plan.version, &names);
            set(Phase::Done, 1.0, 1.0, format!("更新完成（{}）", plan.version));
        }
        Err(e) => set(Phase::Failed, 0.0, 0.0, format!("更新失敗：{}", trim(&e, 32))),
    }
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
        // 用第一个可用区的 IP 作为转发目标
        if let Some(sv) = cfg.servers.iter().find(|x| x.enabled) {
            l1j_launcher::launch::set_real_server(&sv.ip);
        }
        if cfg.dev_skip_select {
            let pick = cfg.servers.iter().position(|x| x.enabled).unwrap_or(0);
            let _ = pick;
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
                })
                .collect();
            return match l1j_launcher::select::select(list) {
                Some(i) => launch::launch_game_with_ip(client, &cfg.game_exe, &cfg.servers[i].ip),
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
    let mut c = match Container::load(client) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };
    let plan = update::plan(&manifest, &c);
    println!(
        "条目 {} 条：需下载 {}，已是最新 {}",
        manifest.entries.len(),
        plan.to_download.len(),
        plan.skipped
    );
    if plan.to_download.is_empty() {
        let _ = update::write_local_version(client, &plan.version, &[]);
        println!("已是最新。");
        return;
    }
    match update::apply(&cfg.update_base, client, &mut c, &plan, &mut |d, i, n| {
        println!("  [{}/{}] {}", i + 1, n, d)
    }) {
        Ok(rep) => {
            println!(
                "合并完成：原地写 {} 条，追加 {} 条；pak {} → {} B",
                rep.inplace.len(),
                rep.appended.len(),
                rep.pak_old,
                rep.pak_new
            );
            let names: Vec<String> = plan.to_download.iter().map(|e| e.name.clone()).collect();
            let _ = update::write_local_version(client, &plan.version, &names);
        }
        Err(e) => eprintln!("更新失败: {}", e),
    }
}
