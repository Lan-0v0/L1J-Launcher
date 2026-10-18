//! l1pak — 天堂1 客户端 Text 容器读写（纯 Rust）
//!
//! 与 `L1J-eat-CN` 的 Python 实现（`lib/pakcore.py` + `lib/paktools.py`）逐字节等价，
//! 由 `tests/vectors.rs` 的 golden vectors 对拍保证。

pub mod cipher;
pub mod container;
mod tables;

pub use container::{Container, Entry, Report, NAME_LEN, REC_SIZE};
