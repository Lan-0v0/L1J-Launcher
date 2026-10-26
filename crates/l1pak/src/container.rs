//! Text 容器读写：原地写 / 尾部追加（禁止紧凑重建）
//!
//! 行为必须与 Python 版 `lib/pakcore.py` 完全一致。

use crate::cipher;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

pub const REC_SIZE: usize = 28;
pub const NAME_LEN: usize = 20;

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub off: i32,
    pub size: i32,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    /// (name, off, size)
    pub inplace: Vec<(String, i32, i32)>,
    /// (name, old_size, new_size, new_off)
    pub appended: Vec<(String, i32, i32, i32)>,
    /// 本次新增的条目：(name, size, off)
    pub added: Vec<(String, i32, i32)>,
    /// 本次删除的条目：(name, size, off)
    pub removed: Vec<(String, i32, i32)>,
    pub pak_old: usize,
    pub pak_new: usize,
    /// 原有数据区里被改动的字节数
    pub bytes_changed: usize,
    /// 追加到末尾的字节数
    pub bytes_appended: usize,
    pub idx_changed: bool,
}

pub struct Container {
    pub idx_raw: Vec<u8>,
    pub pak: Vec<u8>,
    pub body: Vec<u8>,
    pub entries: Vec<Entry>,
    index: HashMap<String, usize>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    out.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Container {
    pub fn from_parts(idx_raw: Vec<u8>, pak: Vec<u8>) -> Result<Self, String> {
        if idx_raw.len() < 4 {
            return Err("idx 文件过短".into());
        }
        let n = u32::from_le_bytes([idx_raw[0], idx_raw[1], idx_raw[2], idx_raw[3]]) as usize;
        let body = cipher::decode(&idx_raw[4..]);
        if body.len() != n * REC_SIZE {
            return Err(format!(
                "idx 结构异常：声明 {} 条，正文 {} 字节（应 {}）",
                n,
                body.len(),
                n * REC_SIZE
            ));
        }
        let mut entries = Vec::with_capacity(n);
        let mut index = HashMap::with_capacity(n);
        for i in 0..n {
            let s = i * REC_SIZE;
            let off = i32::from_le_bytes([body[s], body[s + 1], body[s + 2], body[s + 3]]);
            let raw = &body[s + 4..s + 4 + NAME_LEN];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(NAME_LEN);
            let name = String::from_utf8_lossy(&raw[..end]).to_string();
            let size =
                i32::from_le_bytes([body[s + 24], body[s + 25], body[s + 26], body[s + 27]]);
            index.insert(name.clone(), i);
            entries.push(Entry { name, off, size });
        }
        Ok(Container {
            idx_raw,
            pak,
            body,
            entries,
            index,
        })
    }

    pub fn load(client_dir: &Path) -> Result<Self, String> {
        let idx_path = client_dir.join("Text.idx");
        let pak_path = client_dir.join("Text.pak");
        let idx_raw = fs::read(&idx_path).map_err(|e| format!("读 {} 失败: {}", idx_path.display(), e))?;
        let pak = fs::read(&pak_path).map_err(|e| format!("读 {} 失败: {}", pak_path.display(), e))?;
        Self::from_parts(idx_raw, pak)
    }

    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.index.get(name).copied()
    }

    pub fn cipher_of(&self, name: &str) -> Option<&[u8]> {
        let i = self.index_of(name)?;
        let e = &self.entries[i];
        if e.off < 0 || (e.off as usize + e.size as usize) > self.pak.len() {
            return None;
        }
        Some(&self.pak[e.off as usize..e.off as usize + e.size as usize])
    }

    pub fn plain_of(&self, name: &str) -> Option<Vec<u8>> {
        self.cipher_of(name).map(|c| cipher::decode(c))
    }

    /// 不解密，返回 name -> (size, cipher_sha256)
    pub fn fingerprint(&self) -> HashMap<String, (i32, String)> {
        let mut m = HashMap::with_capacity(self.entries.len());
        for e in &self.entries {
            if e.off >= 0 && (e.off as usize + e.size as usize) <= self.pak.len() {
                let seg = &self.pak[e.off as usize..e.off as usize + e.size as usize];
                m.insert(e.name.clone(), (e.size, sha256_hex(seg)));
            }
        }
        m
    }

    fn encode_idx(&self, body: &[u8], blocks: Option<&[usize]>) -> Vec<u8> {
        let mut out = self.idx_raw.clone();
        let total = body.len();
        let all: Vec<usize> = (0..(total + 7) / 8).collect();
        let list = blocks.unwrap_or(&all);
        for &b in list {
            let s = b * 8;
            if s + 8 > total {
                continue; // 末尾余数原样
            }
            let mut blk = [0u8; 8];
            blk.copy_from_slice(&body[s..s + 8]);
            let enc = cipher::encode_block(&blk);
            out[4 + s..4 + s + 8].copy_from_slice(&enc);
        }
        out
    }

    /// 写入补丁：同长度 → 原地写；不同长度 → 尾部追加 + 改 1 条 idx 记录
    pub fn replace(&mut self, patches: &BTreeMap<String, Vec<u8>>) -> Result<Report, String> {
        for name in patches.keys() {
            if !self.index.contains_key(name) {
                return Err(format!("条目不在容器中（不支持新增）：{}", name));
            }
        }

        let mut pak = self.pak.clone();
        let mut body = self.body.clone();
        let mut report = Report {
            pak_old: self.pak.len(),
            ..Default::default()
        };
        let mut changed_blocks: Vec<usize> = Vec::new();
        let mut new_offsets: HashMap<String, (i32, i32)> = HashMap::new();

        for (name, data) in patches {
            let i = self.index[name];
            let (off, size) = (self.entries[i].off, self.entries[i].size);
            let enc = cipher::encode(data);
            if enc.len() == size as usize {
                let s = off as usize;
                for k in 0..enc.len() {
                    if pak[s + k] != enc[k] {
                        report.bytes_changed += 1;
                        pak[s + k] = enc[k];
                    }
                }
                report.inplace.push((name.clone(), off, size));
                new_offsets.insert(name.clone(), (off, size));
            } else {
                let new_off = pak.len() as i32;
                let new_size = enc.len() as i32;
                pak.extend_from_slice(&enc);
                let rs = i * REC_SIZE;
                body[rs..rs + 4].copy_from_slice(&new_off.to_le_bytes());
                body[rs + 24..rs + 28].copy_from_slice(&new_size.to_le_bytes());
                let b0 = rs / 8;
                let b1 = (rs + REC_SIZE - 1) / 8;
                for b in b0..=b1 {
                    if !changed_blocks.contains(&b) {
                        changed_blocks.push(b);
                    }
                }
                report
                    .appended
                    .push((name.clone(), size, new_size, new_off));
                new_offsets.insert(name.clone(), (new_off, new_size));
            }
        }

        let idx_out = if changed_blocks.is_empty() {
            self.idx_raw.clone()
        } else {
            changed_blocks.sort_unstable();
            let v = self.encode_idx(&body, Some(&changed_blocks));
            if v.len() != self.idx_raw.len() {
                return Err("自检失败：idx 大小变化".into());
            }
            v
        };

        // 自检：逐条回读
        for (name, data) in patches {
            let (off, size) = new_offsets[name];
            let seg = &pak[off as usize..off as usize + size as usize];
            let back = cipher::decode(seg);
            if &back != data {
                return Err(format!("自检失败：回读内容不一致 {}", name));
            }
        }

        report.pak_new = pak.len();
        report.bytes_appended = pak.len() - self.pak.len();
        report.idx_changed = !changed_blocks.is_empty();

        self.pak = pak;
        self.body = body;
        self.idx_raw = idx_out;
        let mut entries = Vec::with_capacity(self.entries.len());
        let mut index = HashMap::with_capacity(self.entries.len());
        for i in 0..self.entries.len() {
            let s = i * REC_SIZE;
            let off = i32::from_le_bytes([
                self.body[s],
                self.body[s + 1],
                self.body[s + 2],
                self.body[s + 3],
            ]);
            let size = i32::from_le_bytes([
                self.body[s + 24],
                self.body[s + 25],
                self.body[s + 26],
                self.body[s + 27],
            ]);
            let name = self.entries[i].name.clone();
            index.insert(name.clone(), i);
            entries.push(Entry { name, off, size });
        }
        self.entries = entries;
        self.index = index;

        Ok(report)
    }

    /// 新增条目：数据追加到 pak 末尾，idx 尾部追加 28B 记录并把记录数 +1。
    ///
    /// 与 `replace` 的区别：
    /// * 只允许**不存在**的条目名（已存在则报错，避免覆盖误用）；
    /// * idx 正文变长 28 字节，不再是 8 的整数倍，因此必须**整段重新加密**
    ///   （`cipher::encode` 对末尾余数原样保留，与原始 idx 的写法一致）；
    /// * 写盘前用 `from_parts` 重新解析自检，逐条回读新增内容。
    pub fn add(&mut self, additions: &BTreeMap<String, Vec<u8>>) -> Result<Report, String> {
        if additions.is_empty() {
            return Ok(Report {
                pak_old: self.pak.len(),
                pak_new: self.pak.len(),
                ..Default::default()
            });
        }
        for name in additions.keys() {
            if self.index.contains_key(name) {
                return Err(format!("条目已存在，不能新增：{}", name));
            }
            if name.is_empty() || name.len() > NAME_LEN {
                return Err(format!("条目名长度必须 1..={} 字节：{}", NAME_LEN, name));
            }
            if name.as_bytes().iter().any(|&b| b == 0) {
                return Err(format!("条目名不能含 0 字节：{}", name));
            }
        }

        let mut pak = self.pak.clone();
        let mut body = self.body.clone();
        let mut report = Report {
            pak_old: self.pak.len(),
            ..Default::default()
        };

        // ★idx 必须保持“按名称小写序”——客户端用二分查找，追加到末尾会直接查不到。
        // 所以新记录插到“第一个小写序比它大的记录”之前（现有记录的相对顺序不动）。
        let mut order: Vec<String> = self.entries.iter().map(|e| e.name.clone()).collect();
        let mut sorted: Vec<(&String, &Vec<u8>)> = additions.iter().collect();
        sorted.sort_by(|a, b| a.0.to_ascii_lowercase().cmp(&b.0.to_ascii_lowercase()));

        for (name, data) in sorted {
            let enc = cipher::encode(data);
            let new_off = pak.len() as i32;
            let new_size = enc.len() as i32;
            pak.extend_from_slice(&enc);

            let mut rec = [0u8; REC_SIZE];
            rec[0..4].copy_from_slice(&new_off.to_le_bytes());
            rec[4..4 + name.len()].copy_from_slice(name.as_bytes());
            rec[24..28].copy_from_slice(&new_size.to_le_bytes());

            let key = name.to_ascii_lowercase();
            let pos = order
                .iter()
                .position(|n| n.to_ascii_lowercase() > key)
                .unwrap_or(order.len());
            let at = pos * REC_SIZE;
            body.splice(at..at, rec.iter().copied());
            order.insert(pos, name.clone());

            report.added.push((name.clone(), new_size, new_off));
        }

        let n = self.entries.len() + additions.len();
        let mut idx_out = Vec::with_capacity(4 + body.len());
        idx_out.extend_from_slice(&(n as u32).to_le_bytes());
        idx_out.extend_from_slice(&cipher::encode(&body));

        // 自检：用新 idx + 新 pak 重新构造，确认条目数与内容都能读回来
        let probe = Container::from_parts(idx_out.clone(), pak.clone())?;
        if probe.entries.len() != n {
            return Err(format!(
                "自检失败：条目数 {}，应为 {}",
                probe.entries.len(),
                n
            ));
        }
        for (name, data) in additions {
            let back = probe
                .plain_of(name)
                .ok_or_else(|| format!("自检失败：新增条目不可读 {}", name))?;
            if &back != data {
                return Err(format!("自检失败：新增条目回读不一致 {}", name));
            }
        }

        report.pak_new = pak.len();
        report.bytes_appended = pak.len() - self.pak.len();
        report.idx_changed = true;

        self.pak = pak;
        self.body = probe.body;
        self.idx_raw = idx_out;
        self.entries = probe.entries;
        self.index = probe.index;

        Ok(report)
    }

    /// 删除条目：只从 idx 摘掉记录并把条目数 -1，**数据区一个字节都不动**。
    ///
    /// 与 `add` 完全对称：idx 正文变短 28 字节，同样不是 8 的整数倍，所以必须
    /// **整段重新加密**（`cipher::encode` 会把末尾 4 字节余数原样保留）。
    ///
    /// 被删条目的旧数据留在 `Text.pak` 里成为空洞，不回收也不搬移 —— 这样其余
    /// 条目的 `off` 全部保持不变，是风险最小的做法（与 `replace` 换长度时尾部
    /// 追加、旧数据不搬移的策略一致）。
    pub fn remove(&mut self, names: &[String]) -> Result<Report, String> {
        if names.is_empty() {
            return Ok(Report {
                pak_old: self.pak.len(),
                pak_new: self.pak.len(),
                ..Default::default()
            });
        }

        let mut positions: Vec<usize> = Vec::new();
        for name in names {
            match self.index.get(name) {
                Some(&i) => {
                    if !positions.contains(&i) {
                        positions.push(i);
                    }
                }
                None => return Err(format!("条目不在容器中，不能删除：{}", name)),
            }
        }
        // 从后往前摘，避免前面的删除让后面的下标整体前移
        positions.sort_unstable();

        let mut body = self.body.clone();
        let mut removed: Vec<(String, i32, i32)> = Vec::new();
        for &i in positions.iter().rev() {
            let at = i * REC_SIZE;
            let e = &self.entries[i];
            removed.push((e.name.clone(), e.size, e.off));
            body.drain(at..at + REC_SIZE);
        }
        removed.reverse(); // 恢复成名称序，日志更好读

        let n = self.entries.len() - positions.len();
        let mut idx_out = Vec::with_capacity(4 + body.len());
        idx_out.extend_from_slice(&(n as u32).to_le_bytes());
        idx_out.extend_from_slice(&cipher::encode(&body));

        // 自检：新 idx 必须能解析、条目数对得上、被删的确实读不到。
        // 其余条目不需要逐条回读 —— 它们的 off/size 是从旧 idx 原样搬过来的，
        // 数据区没动，结构对了就一定能读（全量解密要几秒，不值得）。
        let probe = Container::from_parts(idx_out.clone(), self.pak.clone())?;
        if probe.entries.len() != n {
            return Err(format!(
                "自检失败：删除后条目数 {}，应为 {}",
                probe.entries.len(),
                n
            ));
        }
        for (name, _, _) in &removed {
            if probe.plain_of(name).is_some() {
                return Err(format!("自检失败：{} 删除后仍可读到", name));
            }
        }

        let report = Report {
            removed,
            pak_old: self.pak.len(),
            pak_new: self.pak.len(),
            idx_changed: true,
            ..Default::default()
        };

        self.body = probe.body;
        self.idx_raw = idx_out;
        self.entries = probe.entries;
        self.index = probe.index;

        Ok(report)
    }

    /// 原子写回（先写 .tmp 再 rename）
    ///
    /// 任何一步失败都要把半截的 `.tmp_new` 清掉：客户端目录一旦被游戏占用，
    /// 写盘几乎必然失败，而一个 Text.pak.tmp_new 就是 17MB 垃圾。
    pub fn save(&self, client_dir: &Path) -> std::io::Result<()> {
        let pak_path: PathBuf = client_dir.join("Text.pak");
        let idx_path: PathBuf = client_dir.join("Text.idx");
        let tmp_pak = pak_path.with_extension("pak.tmp_new");
        let tmp_idx = idx_path.with_extension("idx.tmp_new");
        let res = (|| -> std::io::Result<()> {
            fs::write(&tmp_pak, &self.pak)?;
            fs::write(&tmp_idx, &self.idx_raw)?;
            fs::rename(&tmp_pak, &pak_path)?;
            fs::rename(&tmp_idx, &idx_path)?;
            Ok(())
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp_pak);
            let _ = fs::remove_file(&tmp_idx);
        }
        res
    }

    pub fn sha256_hex(data: &[u8]) -> String {
        sha256_hex(data)
    }
}
