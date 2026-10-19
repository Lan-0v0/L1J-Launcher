// 用 windres 把 icon.rc 编译成 COFF 并链接进 exe（图标在资源 id=1）
// 链接器路径问题：本仓库必须在纯 ASCII 路径下构建（如 D:/l1log/build/l1j-launcher）
use std::path::PathBuf;
use std::process::Command;

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    println!("cargo:rerun-if-changed=icon.rc");
    println!("cargo:rerun-if-changed=assets/app.ico");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc = out.join("icon.rc");
    let obj = out.join("icon.o");
    std::fs::write(&rc, "1 ICON \"assets/app.ico\"\n").unwrap();

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let windres = std::env::var("WINDRES").unwrap_or_else(|_| "windres.exe".into());
    let status = Command::new(&windres)
        .current_dir(&manifest) // 相对路径 assets/app.ico 以 manifest 为基准
        .arg(&rc)
        .arg(&obj)
        .status()
        .unwrap_or_else(|e| panic!("windres ({}) 启动失败: {}（需要 MinGW binutils 在 PATH，或设 WINDRES 环境变量）", windres, e));
    assert!(status.success(), "windres 编译 icon.rc 失败");
    println!("cargo:rustc-link-arg={}", obj.display());
}
