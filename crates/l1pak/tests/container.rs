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

#[test]
fn remove_drops_record_only_and_keeps_data_area() {
    let a = b"<html>AAAA</html>";
    let b = b"<html>BBBB</html>";
    let d = b"<html>DDDD</html>";
    let mut c = build_container(&[("a.html", a), ("b.html", b), ("d.html", d)]);

    let before_pak = c.pak.clone();
    let before_idx_len = c.idx_raw.len();

    let rep = c.remove(&["b.html".to_string()]).expect("删除失败");

    assert_eq!(rep.removed.len(), 1);
    assert_eq!(rep.removed[0].0, "b.html");
    // 关键：数据区一个字节都不能动（被删条目只留空洞，不搬移）
    assert_eq!(c.pak, before_pak, "删除不应改动 Text.pak");
    // idx 正好少一条记录
    assert_eq!(c.idx_raw.len(), before_idx_len - 28, "idx 应少 28 字节");
    assert_eq!(c.entries.len(), 2);
    // 被删读不到，其余原样
    assert!(c.plain_of("b.html").is_none(), "被删条目仍可读");
    assert_eq!(c.plain_of("a.html").unwrap(), a);
    assert_eq!(c.plain_of("d.html").unwrap(), d);

    // 落盘结构自洽：用新 idx 重新解析仍成立
    let reload = Container::from_parts(c.idx_raw.clone(), c.pak.clone()).expect("重新解析失败");
    assert_eq!(reload.entries.len(), 2);
    assert!(reload.plain_of("b.html").is_none());
    assert_eq!(reload.plain_of("a.html").unwrap(), a);
}

#[test]
fn remove_multiple_first_and_last() {
    let mut c = build_container(&[
        ("a.html", b"aaa"),
        ("b.html", b"bbb"),
        ("c.html", b"ccc"),
        ("d.html", b"ddd"),
    ]);
    let rep = c
        .remove(&["a.html".to_string(), "d.html".to_string()])
        .expect("批量删除失败");

    assert_eq!(rep.removed.len(), 2);
    assert_eq!(c.entries.len(), 2);
    assert_eq!(c.idx_raw.len(), 4 + 2 * 28, "idx 应剩两条记录");
    assert!(c.plain_of("a.html").is_none());
    assert!(c.plain_of("d.html").is_none());
    assert_eq!(c.plain_of("b.html").unwrap(), b"bbb");
    assert_eq!(c.plain_of("c.html").unwrap(), b"ccc");
}

#[test]
fn remove_rejects_unknown_entry() {
    let mut c = build_container(&[("a.html", b"aaa")]);
    assert!(
        c.remove(&["nope.html".to_string()]).is_err(),
        "不存在的条目应当报错"
    );
    // 报错后容器状态不能被破坏
    assert_eq!(c.entries.len(), 1);
    assert_eq!(c.plain_of("a.html").unwrap(), b"aaa");
}

#[test]
fn remove_then_add_keeps_container_consistent() {
    let mut c = build_container(&[("a.html", b"AAA"), ("b.html", b"BBB")]);
    c.remove(&["a.html".to_string()]).unwrap();

    let mut add = BTreeMap::new();
    add.insert("c.html".to_string(), b"CCC".to_vec());
    c.add(&add).unwrap();

    assert_eq!(c.entries.len(), 2);
    assert!(c.plain_of("a.html").is_none());
    assert_eq!(c.plain_of("b.html").unwrap(), b"BBB");
    assert_eq!(c.plain_of("c.html").unwrap(), b"CCC");
    assert_eq!(c.idx_raw.len(), 4 + 2 * 28);
}
