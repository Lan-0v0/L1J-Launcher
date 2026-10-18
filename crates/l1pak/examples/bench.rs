//! 性能基线：全量解密 / 指纹计算
//! 用法：cargo run --release --example bench -- <客户端目录>

use l1pak::Container;
use std::time::Instant;

fn main() {
    let dir = std::env::args().nth(1).expect("用法: bench <客户端目录>");
    let t0 = Instant::now();
    let c = Container::load(std::path::Path::new(&dir)).expect("加载失败");
    let t_load = t0.elapsed();

    let total: usize = c.entries.iter().map(|e| e.size.max(0) as usize).sum();

    let t1 = Instant::now();
    let fp = c.fingerprint();
    let t_fp = t1.elapsed();

    let t2 = Instant::now();
    let mut bytes = 0usize;
    for e in &c.entries {
        if e.size > 0 && e.off >= 0 {
            let p = c.plain_of(&e.name).unwrap();
            bytes += p.len();
        }
    }
    let t_dec = t2.elapsed();

    println!("条目数        : {}", c.entries.len());
    println!("数据总量      : {} B ({:.2} MB)", total, total as f64 / 1048576.0);
    println!("加载(idx解密) : {:?}", t_load);
    println!("指纹(全量sha) : {:?}  ({} 条)", t_fp, fp.len());
    println!("全量解密      : {:?}  ({} B)", t_dec, bytes);
    println!(
        "解密吞吐      : {:.1} MB/s",
        bytes as f64 / 1048576.0 / t_dec.as_secs_f64()
    );
}
