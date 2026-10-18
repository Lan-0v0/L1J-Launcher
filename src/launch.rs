//! 启动游戏（普通 CreateProcess，无注入）

use std::path::Path;
use std::process::Command;

pub fn launch_game(client: &Path, exe_name: &str) -> Result<(), String> {
    let exe = client.join(exe_name);
    if !exe.is_file() {
        return Err(format!("找不到游戏程序: {}", exe.display()));
    }
    Command::new(&exe)
        .current_dir(client)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("启动失败 {}: {}", exe.display(), e))
}
