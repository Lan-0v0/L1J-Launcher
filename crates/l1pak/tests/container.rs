//! 容器级行为：合成一个小容器，验证原地写 / 尾部追加

use l1pak::cipher;
use l1pak::Container;
use std::collections::BTreeMap;

/// 用明文条目构造一个合成容器（pak + 加密 idx）
fn build_container(items: &[(&str, &[u8])]) -> Container {
    let mut pak = Vec::new();
    let mut body = Vec::new();
    for (name, data) in items {
        let off = pak.len() as i32;
        let enc = cipher::encode(data);
        pak.extend_from_slice(&enc);
        let mut rec = [0u8; 28];
        rec[0..4].copy_from_slice(&off.to_le_bytes());
        let nb = name.as_bytes();
        rec[4..4 + nb.len()].copy_from_slice(nb);
        rec[24..28].copy_from_slice(&(enc.len() as i32).to_le_bytes());
        body.extend_from_slice(&rec);
    }
    let mut idx = Vec::new();
    idx.extend_from_slice(&(items.len() as u32).to_le_bytes());
    idx.extend_from_slice(&cipher::encode(&body));
    Container::from_parts(idx, pak).expect("合成容器失败")
}

#[test]
fn inplace_write_changes_only_that_block() {
    let a = b"<html>AAAA</html>";
    let b = b"<html>BBBB</html>";
    let mut c = build_container(&[("a.html", a), ("b.html", b)]);
    let before_pak = c.pak.clone();
    let before_idx = c.idx_raw.clone();

    let mut patches = BTreeMap::new();
    let mut new_a = a.to_vec();
    new_a[6] ^= 0x01; // 同长度
    patches.insert("a.html".to_string(), new_a.clone());

    let rep = c.replace(&patches).expect("替换失败");
    assert_eq!(c.pak.len(), before_pak.len(), "同长度不应改变 pak 大小");
    assert_eq!(c.idx_raw, before_idx, "同长度不应改 idx");
    assert_eq!(c.plain_of("a.html").unwrap(), new_a, "回读不一致");
    // 改动必须落在 a.html 区间内
    let e = c.entries.iter().find(|e| e.name == "a.html").unwrap();
    for i in 0..before_pak.len() {
        if before_pak[i] != c.pak[i] {
            assert!(
                i >= e.off as usize && i < (e.off + e.size) as usize,
                "越界改动 offset={}",
                i
            );
        }
    }
}

#[test]
fn append_when_length_differs() {
    let a = b"<html>orig</html>";
    let mut c = build_container(&[("a.html", a), ("b.html", b"keep")]);
    let before_pak = c.pak.clone();
    let before_idx_len = c.idx_raw.len();

    let mut patches = BTreeMap::new();
    let longer = b"<html>orig-plus-extra</html>".to_vec();
    patches.insert("a.html".to_string(), longer.clone());

    let rep = c.replace(&patches).expect("追加失败");
    assert_eq!(rep.appended.len(), 1, "应走追加分支");
    assert!(rep.idx_changed, "追加必须改 idx");
    assert_eq!(c.idx_raw.len(), before_idx_len, "idx 长度不应变化");
    // 原有 pak 字节必须一字节不动
    assert_eq!(&c.pak[..before_pak.len()], &before_pak[..], "原有数据被改动");
    assert_eq!(c.plain_of("a.html").unwrap(), longer, "回读不一致");
    assert_eq!(c.plain_of("b.html").unwrap(), b"keep".to_vec());
}

#[test]
fn rejects_unknown_entry() {
    let mut c = build_container(&[("a.html", b"x")]);
    let mut patches = BTreeMap::new();
    patches.insert("nope.html".to_string(), b"y".to_vec());
    assert!(c.replace(&patches).is_err(), "未知条目应当报错");
}

#[test]
fn save_and_reload() {
    let dir = std::env::temp_dir().join("l1pak_test_reload");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut c = build_container(&[("a.html", b"0123456789"), ("b.html", b"abc")]);
    c.save(&dir).unwrap();
    let reloaded = Container::load(&dir).unwrap();
    assert_eq!(reloaded.entries.len(), 2);
    assert_eq!(reloaded.plain_of("a.html").unwrap(), b"0123456789".to_vec());
    assert_eq!(reloaded.plain_of("b.html").unwrap(), b"abc".to_vec());
    let _ = std::fs::remove_dir_all(&dir);
}
