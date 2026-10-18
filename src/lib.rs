//! l1j-launcher —— 客户端更新器核心库
//!
//! 流程：读配置 → 拉 manifest + 签名 → 验签 → 比对本地容器 → 只下差异条目
//!       → 校验 SHA-256 → 合并进 Text.pak → 写版本 → 启动游戏
//!
//! 设计约束（与项目约定一致）：
//!   1. 只做本地文件读写 + 一个 HTTPS 下载点，不注入、不 hook、不写注册表
//!   2. 合并走 `l1pak` 的原地写/尾部追加，绝不紧凑重建
//!   3. 清单用 Ed25519 签名，防更新服务器被篡改

pub mod config;
pub mod elevate;
pub mod http;
pub mod launch;
pub mod manifest;
pub mod update;
#[cfg(windows)]
pub mod ui;

pub use config::Config;
pub use manifest::{Entry, Manifest};
