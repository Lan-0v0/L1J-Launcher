//! 天堂1 客户端 Text 容器的分组加密（8 字节块，块间独立）
//!
//! 移植自 `L1J-eat-CN/lib/paktools.py`（其源头是 l1j-en Launcher 的 PakTools.cs）。
//! 语义必须与 Python 版逐字节一致，由 `tests/vectors.rs` 的 golden vectors 保证。

use crate::tables::{MAP1, MAP2, MAP3, MAP4, MAP5};

#[inline]
fn sub_4032e0(a1: &[u8; 8], a2: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let mut num = 0usize;
    let mut num1 = 0usize;
    while num1 < 16 {
        let b = a1[num];
        let hi = (b >> 4) as usize;
        let lo = (b & 0x0f) as usize;
        for i in 0..8 {
            let num5 = num1 * 128 + i;
            out[i] |= a2[num5 + hi * 8] | a2[num5 + (16 + lo) * 8];
        }
        num1 += 2;
        num += 1;
    }
    out
}

#[inline]
fn sub_403450(a1: &[u8]) -> [u8; 6] {
    let (b0, b1, b2, b3) = (
        a1[0] as u32,
        a1[1] as u32,
        a1[2] as u32,
        a1[3] as u32,
    );
    [
        ((b3 << 7) | (((b0 & 249) | ((b0 >> 2) & 6)) >> 1)) as u8,
        ((((b0 & 1) | (b0 << 2)) << 3) | (((b1 >> 2) | (b1 & 135)) >> 3)) as u8,
        (((b2 >> 7) | (((b1 & 31) | ((b1 & 248) << 2)) << 1)) & 0xFF) as u8,
        (((b1 << 7) | (((b2 & 249) | ((b2 >> 2) & 6)) >> 1)) & 0xFF) as u8,
        ((((b2 & 1) | (b2 << 2)) << 3) | (((b3 >> 2) | (b3 & 135)) >> 3)) as u8,
        (((b0 >> 7) | (((b3 & 31) | ((b3 & 248) << 2)) << 1)) & 0xFF) as u8,
    ]
}

#[inline]
fn sub_403520(a1: &[u8; 6]) -> [u8; 4] {
    let b = [
        a1[0] as usize,
        a1[1] as usize,
        a1[2] as usize,
        a1[3] as usize,
        a1[4] as usize,
        a1[5] as usize,
    ];
    [
        MAP4[b[0] * 16 | b[1] >> 4],
        MAP4[4096 + (b[2] | (b[1] % 16) * 256)],
        MAP4[8192 + (b[3] * 16 | b[4] >> 4)],
        MAP4[12288 + (b[5] | (b[4] % 16) * 256)],
    ]
}

#[inline]
fn sub_4035a0(a1: &[u8; 4]) -> [u8; 4] {
    let mut out = [0u8; 4];
    for i in 0..4 {
        let num = (i * 256 + a1[i] as usize) * 4;
        out[0] |= MAP3[num];
        out[1] |= MAP3[num + 1];
        out[2] |= MAP3[num + 2];
        out[3] |= MAP3[num + 3];
    }
    out
}

#[inline]
fn sub_4033b0(a1: &[u8], round: usize) -> [u8; 4] {
    let arr = sub_403450(a1);
    let num = round * 6;
    let mut m5 = [0u8; 6];
    for i in 0..6 {
        m5[i] = arr[i] ^ MAP5[num + i];
    }
    sub_4035a0(&sub_403520(&m5))
}

#[inline]
fn sub_403340(round: usize, a2: &[u8; 8]) -> [u8; 8] {
    let r = sub_4033b0(&a2[4..8], round);
    [
        a2[4],
        a2[5],
        a2[6],
        a2[7],
        r[0] ^ a2[0],
        r[1] ^ a2[1],
        r[2] ^ a2[2],
        r[3] ^ a2[3],
    ]
}

/// 解密一个 8 字节块
pub fn decode_block(block: &[u8; 8]) -> [u8; 8] {
    let mut cur = sub_4032e0(block, &MAP1);
    for round in (0..16).rev() {
        cur = sub_403340(round, &cur);
    }
    let sw = [cur[4], cur[5], cur[6], cur[7], cur[0], cur[1], cur[2], cur[3]];
    sub_4032e0(&sw, &MAP2)
}

/// 加密一个 8 字节块
pub fn encode_block(block: &[u8; 8]) -> [u8; 8] {
    let mut cur = sub_4032e0(block, &MAP1);
    for round in 0..16 {
        cur = sub_403340(round, &cur);
    }
    let sw = [cur[4], cur[5], cur[6], cur[7], cur[0], cur[1], cur[2], cur[3]];
    sub_4032e0(&sw, &MAP2)
}

fn coder(src: &[u8], encode: bool) -> Vec<u8> {
    let mut out = src.to_vec();
    let blocks = src.len() / 8;
    for i in 0..blocks {
        let s = i * 8;
        let mut blk = [0u8; 8];
        blk.copy_from_slice(&src[s..s + 8]);
        let r = if encode { encode_block(&blk) } else { decode_block(&blk) };
        out[s..s + 8].copy_from_slice(&r);
    }
    // 末尾余数（len % 8）原样保留
    out
}

/// 解密整段（从第 0 字节起按 8 字节分组）
pub fn decode(src: &[u8]) -> Vec<u8> {
    coder(src, false)
}

/// 加密整段（从第 0 字节起按 8 字节分组）
pub fn encode(src: &[u8]) -> Vec<u8> {
    coder(src, true)
}
