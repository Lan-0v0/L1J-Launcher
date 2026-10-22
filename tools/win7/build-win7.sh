#!/usr/bin/env bash
# 构建 Win7 兼容版 Login.exe（i686-win7-windows-gnu）
#
# 为什么必须用这个 target：
#   Rust 1.78 起，默认的 i686-pc-windows-gnu 最低系统要求被抬到 Windows 10，
#   会产生 5 个 Win7 根本不存在的静态导入：
#     api-ms-win-core-synch-l1-2-0!WaitOnAddress / WakeByAddressAll / WakeByAddressSingle
#     bcryptprimitives!ProcessPrng              （Win10 1709+）
#     KERNEL32!GetSystemTimePreciseAsFileTime   （Win8+）
#   Win7 加载器解析不了这些 API Set forwarder，进程直接 0xc0000005，
#   且不会提示“缺少 xxx.dll”，极难排查。
#
# 两个硬性前提（都是踩过的坑）：
#   1. 构建目录必须是纯 ASCII 路径 —— -Z build-std 要现编 std，中文路径会失败
#   2. 宿主必须是 nightly-x86_64-pc-windows-gnu —— 普通 nightly 是 msvc 宿主，
#      交叉链接 gnu 目标时找不到 x86_64 的 gcc
#
# 用法：tools/win7/build-win7.sh [输出目录]
set -euo pipefail

MINGW="${MINGW:-D:/l1log/tc/mingw32/bin}"
OUTDIR="${1:-dist-win7}"
TC="nightly-x86_64-pc-windows-gnu"

export PATH="$MINGW:$HOME/.cargo/bin:$PATH"
export CARGO_TARGET_I686_WIN7_WINDOWS_GNU_LINKER="$MINGW/gcc.exe"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "$ROOT" in
  *[![:ascii:]]*) echo "!! 构建路径含非 ASCII 字符，-Z build-std 会失败：$ROOT" >&2
                  echo "   请把工程复制到 /d/l1win7build/l1j-launcher 这类纯英文路径再跑" >&2
                  exit 1;;
esac

cd "$ROOT"
rustup component add rust-src --toolchain "$TC" >/dev/null 2>&1 || true

echo "== 编译 l1j-launcher / l1sign ($TC -> i686-win7-windows-gnu)"
cargo "+$TC" build --release --target i686-win7-windows-gnu -Z build-std=std

T="target/i686-win7-windows-gnu/release"
mkdir -p "$OUTDIR"
cp "$T/l1j-launcher.exe" "$T/l1sign.exe" "$OUTDIR/"

echo "== 导入表校验（出现 Win8+ API 直接失败）"
python "${ROOT}/tools/win7/check_pe_imports.py" "$OUTDIR/l1j-launcher.exe" "$OUTDIR/l1sign.exe"

echo "== 完成：$OUTDIR"
ls -l "$OUTDIR"
