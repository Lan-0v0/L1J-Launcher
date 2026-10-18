//! l1j-launcher（控制台版）—— 先跑通流程，之后再套 UI
//!
//! 用法：
//!   l1j-launcher.exe                 检查更新 → 合并 → 启动游戏
//!   l1j-launcher.exe --no-launch     只更新，不启动（自测用）
//!   l1j-launcher.exe --force         忽略版本号，强制比对（默认就会比对，本参数仅保留语义）

use l1j_launcher::{config::Config, launch, update};
use l1pak::Container;

fn main() {
    if let Err(e) = run() {
        eprintln!("[错误] {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("取程序路径失败: {}", e))?;
    let dir = exe
        .parent()
        .ok_or("无法确定程序所在目录")?
        .to_path_buf();

    let cfg_path = dir.join("launcher.json");
    if !cfg_path.exists() {
        l1j_launcher::config::write_example(&cfg_path).map_err(|e| format!("写示例配置失败: {}", e))?;
        return Err(format!(
            "未找到 launcher.json，已生成示例：{}\n请填写 update_base 与 public_key 后重试",
            cfg_path.display()
        ));
    }
    let cfg = Config::load(&cfg_path)?;
    let client = cfg.client_path(&dir);
    if !client.exists() {
        return Err(format!("客户端目录不存在: {}", client.display()));
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let no_launch = args.iter().any(|a| a == "--no-launch");

    // 1) 拉清单 + 验签
    let manifest = match update::fetch_and_verify(&cfg.update_base, &cfg.public_key) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[更新] 取清单失败: {}", e);
            if cfg.launch_on_error {
                eprintln!("[更新] 按配置跳过更新，直接启动游戏");
                return launch::launch_game(&client, &cfg.game_exe);
            }
            return Err(e);
        }
    };

    let local_ver = update::read_local_version(&client)
        .map(|v| v.version)
        .unwrap_or_else(|| "(无)".to_string());
    println!("客户端: {}", client.display());
    println!("本地版本: {}   远端版本: {}", local_ver, manifest.version);
    if manifest.entries.is_empty() {
        println!("清单里没有条目，跳过。");
        return if no_launch {
            Ok(())
        } else {
            launch::launch_game(&client, &cfg.game_exe)
        };
    }

    // 2) 比对
    let mut container = Container::load(&client)?;
    let plan = update::plan(&manifest, &container);
    println!(
        "条目 {} 条：需下载 {}，已是最新 {}",
        manifest.entries.len(),
        plan.to_download.len(),
        plan.skipped
    );

    if plan.to_download.is_empty() {
        update::write_local_version(&client, &plan.version, &[])?;
        println!("已是最新，无需更新。");
    } else {
        // 3) 下载 + 校验 + 合并
        let report = update::apply(
            &cfg.update_base,
            &client,
            &mut container,
            &plan,
            &mut |desc, i, n| {
                if i < n {
                    println!("  [{}/{}] {}", i + 1, n, desc)
                } else {
                    println!("  {}", desc)
                }
            },
        )?;
        println!(
            "合并完成：原地写 {} 条，尾部追加 {} 条；pak {} → {} B（+{}），index {}",
            report.inplace.len(),
            report.appended.len(),
            report.pak_old,
            report.pak_new,
            report.bytes_appended,
            if report.idx_changed { "已更新" } else { "未变" }
        );
        let names: Vec<String> = plan.to_download.iter().map(|e| e.name.clone()).collect();
        update::write_local_version(&client, &plan.version, &names)?;
    }

    if no_launch {
        println!("--no-launch：不启动游戏。");
        return Ok(());
    }
    println!("启动 {} ...", cfg.game_exe);
    launch::launch_game(&client, &cfg.game_exe)
}
