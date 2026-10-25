//! 调试工具：对真实 Text 容器执行一次「条目删除」，并做结构自检
//!
//! 用法：
//!   cargo run --example remove_entry -- <客户端目录> --list <关键字>
//!   cargo run --example remove_entry -- <客户端目录> <条目名> [更多条目...]
//!
//! 只在**副本**上跑，别对着正在用的客户端目录操作。

use l1pak::Container;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("用法: remove_entry <客户端目录> --list <关键字>");
        eprintln!("      remove_entry <客户端目录> <条目名>...");
        std::process::exit(2);
    }
    let dir = Path::new(&args[0]);
    let c = Container::load(dir).expect("加载容器失败");
    println!(
        "加载成功：{} 条，pak {} 字节，idx {} 字节",
        c.entries.len(),
        c.pak.len(),
        c.idx_raw.len()
    );

    if args[1] == "--list" {
        if args.len() < 3 {
            eprintln!("--list 需要一个关键字");
            std::process::exit(2);
        }
        let key = args[2].to_ascii_lowercase();
        let mut n = 0;
        for e in &c.entries {
            if e.name.to_ascii_lowercase().contains(&key) {
                println!("  {}  off={} size={}", e.name, e.off, e.size);
                n += 1;
            }
        }
        println!("命中 {} 条", n);
        return;
    }

    let names: Vec<String> = args[1..].to_vec();
    for n in &names {
        if c.index_of(n).is_none() {
            eprintln!("条目不存在，无法删除：{}", n);
            std::process::exit(1);
        }
    }

    let pak_sha_before = Container::sha256_hex(&c.pak);
    let idx_len_before = c.idx_raw.len();
    let count_before = c.entries.len();

    let mut c = c;
    let rep = c.remove(&names).expect("删除失败");
    println!("删除 {} 条：", rep.removed.len());
    for (name, size, off) in &rep.removed {
        println!("  {}  size={} off={}", name, size, off);
    }

    assert_eq!(
        Container::sha256_hex(&c.pak),
        pak_sha_before,
        "!! Text.pak 被改动了"
    );
    println!("✓ Text.pak 一个字节都没变");
    assert_eq!(c.entries.len(), count_before - names.len(), "条目数不对");
    assert_eq!(
        c.idx_raw.len(),
        idx_len_before - 28 * names.len(),
        "idx 长度不对"
    );
    println!(
        "✓ idx {} → {} 字节（-{}），条目 {} → {}",
        idx_len_before,
        c.idx_raw.len(),
        28 * names.len(),
        count_before,
        c.entries.len()
    );

    c.save(dir).expect("保存失败");
    let back = Container::load(dir).expect("回读失败");
    assert_eq!(back.entries.len(), count_before - names.len());
    for n in &names {
        assert!(back.plain_of(n).is_none(), "{} 删除后仍可读", n);
    }
    println!("✓ 落盘后回读正常，被删条目确认不可读");

    // 抽查首尾各 2 条，确认其余条目仍能解密读出
    let mut checked = 0;
    for e in back.entries.iter().take(2).chain(back.entries.iter().rev().take(2)) {
        let data = back.plain_of(&e.name).expect("保留条目读不出来");
        println!("  抽查 {} → {} 字节", e.name, data.len());
        checked += 1;
    }
    println!("✓ 抽查 {} 条保留条目可读", checked);
}
