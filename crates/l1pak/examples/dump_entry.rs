//! 调试工具：列出 / 导出 Text.pak 条目
//!
//! 用法：
//!   dump_entry <客户端目录> --list <关键字>
//!   dump_entry <客户端目录> <条目名> [输出文件]

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("用法:");
        eprintln!("  dump_entry <客户端目录> --list <关键字>");
        eprintln!("  dump_entry <客户端目录> <条目名> [输出文件]");
        std::process::exit(2);
    }
    let dir = Path::new(&args[0]);
    let c = match l1pak::Container::load(dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("加载容器失败: {}", e);
            std::process::exit(1);
        }
    };
    println!("条目总数: {}", c.entries.len());

    if args[1] == "--list" {
        let key = args.get(2).map(|s| s.to_ascii_lowercase()).unwrap_or_default();
        let mut hit = 0;
        for e in &c.entries {
            if key.is_empty() || e.name.to_ascii_lowercase().contains(&key) {
                hit += 1;
                println!("  {:>10}  {}", e.size, e.name);
            }
        }
        println!("命中 {} 条", hit);
        return;
    }

    // 按原始字节（十六进制）在所有条目正文里搜索，编码无关
    if args[1] == "--grep-hex" {
        let hx = args.get(2).expect("缺少十六进制串");
        let needle: Vec<u8> = (0..hx.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hx[i..i + 2], 16).expect("非法十六进制"))
            .collect();
        let mut hit = 0;
        for e in &c.entries {
            if let Some(data) = c.plain_of(&e.name) {
                if let Some(pos) = data.windows(needle.len()).position(|w| w == &needle[..]) {
                    hit += 1;
                    println!("  {:>8}  {:<40} @{}", e.size, e.name, pos);
                }
            }
        }
        println!("命中 {} 条（搜索 {} 字节）", hit, needle.len());
        return;
    }

    let name = &args[1];
    match c.plain_of(name) {
        Some(data) => {
            println!("条目 {} : {} 字节", name, data.len());
            if let Some(out) = args.get(2) {
                if let Err(e) = std::fs::write(out, &data) {
                    eprintln!("写文件失败: {}", e);
                    std::process::exit(1);
                }
                println!("已写入 {}", out);
            } else {
                println!("--- 内容开始 ---");
                print!("{}", String::from_utf8_lossy(&data));
                println!("\n--- 内容结束 ---");
            }
        }
        None => {
            println!("找不到条目: {}", name);
            std::process::exit(1);
        }
    }
}
