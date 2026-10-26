//! 调试工具：把一份文件内容覆盖进 Text.pak 的指定条目（仅用于本地测试）
//! 用法：put_entry <客户端目录> <条目名> <内容文件>

use std::path::Path;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 3 {
        eprintln!("用法: put_entry <客户端目录> <条目名> <内容文件>");
        std::process::exit(2);
    }
    let dir = Path::new(&a[0]);
    let name = &a[1];
    let data = std::fs::read(&a[2]).expect("读内容文件失败");

    let mut c = l1pak::Container::load(dir).expect("加载容器失败");
    if c.index_of(name).is_none() {
        eprintln!("容器里没有条目: {}", name);
        std::process::exit(1);
    }
    let mut patches = std::collections::BTreeMap::new();
    patches.insert(name.clone(), data.clone());
    let rep = c.replace(&patches).expect("替换失败");
    c.save(dir).expect("保存失败");
    println!(
        "已写入 {} ({} 字节)  原地写 {} 条  追加 {} 条  pak {} -> {}",
        name,
        data.len(),
        rep.inplace.len(),
        rep.appended.len(),
        rep.pak_old,
        rep.pak_new
    );
}
