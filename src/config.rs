//! 启动器配置（`launcher.json`，与 exe 同目录）

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCfg {
    pub name: String,
    pub ip: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Encode 预生成的 ServerData（Base64）。仅供旧厂商登录器链路，自研链路不用
    #[serde(default)]
    pub server_data: Option<String>,
    /// 游戏端口（默认 2000）。启动前写入 lineage.cfg（游戏从这里读连接地址，明文）
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 用厂商登录器自带的选区弹窗当唯一选区界面（骷髅同款结构）
    #[serde(default)]
    pub use_vendor_dialog: bool,
    /// 更新站根地址，必须以 / 结尾，例如 "https://example.com/l1update/"
    pub update_base: String,
    /// 更新完成后要启动的程序（相对客户端目录）
    pub game_exe: String,
    /// 游戏服务器 IPv4；填了就按登录器的方式传十进制整数给游戏（路线乙）
    #[serde(default)]
    pub server_ip: Option<String>,
    /// 客户端目录（相对 exe 所在目录；"." 表示同目录）
    #[serde(default = "default_client_dir")]
    pub client_dir: String,
    /// Ed25519 公钥（32 字节 hex，64 个字符）
    pub public_key: String,
    /// 额外运行期补丁，格式 "地址:原字节HEX:新字节HEX"（如 "4173DD:75:90"）
    #[serde(default)]
    pub extra_patches: Vec<String>,
    /// 传给游戏主程序的参数（厂商实测为 2130706433）
    #[serde(default)]
    pub launch_arg: Option<String>,
    /// 仅测试用：true 时自动选第一个可用区，不弹选区窗口（不影响 UI 配置）
    #[serde(default)]
    pub dev_skip_select: bool,
    /// 区服列表（>=2 个时启动前弹选区窗口）
    #[serde(default)]
    pub servers: Vec<ServerCfg>,
    /// 拉不到清单时是否仍然直接启动游戏（默认 true，避免服务器挂了玩家进不去）
    #[serde(default = "default_true")]
    pub launch_on_error: bool,
}

fn default_client_dir() -> String {
    ".".to_string()
}

fn default_true() -> bool {
    true
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let txt = std::fs::read_to_string(path)
            .map_err(|e| format!("读配置失败 {}: {}", path.display(), e))?;
        serde_json::from_str(&txt).map_err(|e| format!("配置格式错误: {}", e))
    }

    pub fn client_path(&self, exe_dir: &Path) -> PathBuf {
        exe_dir.join(&self.client_dir)
    }
}

/// 写入示例配置（首次运行时放置）
pub fn write_example(path: &Path) -> std::io::Result<()> {
    let sample = Config {
        use_vendor_dialog: false,
        update_base: "https://your-domain/l1update/".into(),
        game_exe: "login.exe".into(),
        server_ip: None,
        client_dir: ".".into(),
        public_key: "00".repeat(32),
        servers: vec![
            ServerCfg {
                name: "龙潭天堂·一区".into(),
                ip: "124.222.172.24".into(),
                enabled: false, // 维护中
                server_data: None,
                port: None,
            },
            ServerCfg {
                name: "龙潭天堂·测试服".into(),
                ip: "124.222.172.24".into(),
                enabled: true,
                server_data: None,
                port: None,
            },
        ],
        launch_arg: Some("2130706433".into()),
        dev_skip_select: false,
        launch_on_error: true,
        extra_patches: Vec::new(),
    };
    std::fs::write(path, serde_json::to_string_pretty(&sample).unwrap())
}
