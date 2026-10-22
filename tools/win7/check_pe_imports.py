#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""PE 导入表守卫：发现 Windows 7 不存在的 API 就报错退出。

背景：Rust 默认 target（i686-pc-windows-gnu）从 1.78 起最低要求 Windows 10，
会把 WaitOnAddress / ProcessPrng / GetSystemTimePreciseAsFileTime 等
Win8+ API 静态导入进来；Win7 上表现为进程启动即 0xc0000005，
且**不会**提示缺少 DLL，排查成本极高。打包前跑一遍这个脚本即可拦住。

用法：
    python check_pe_imports.py a.exe b.dll ...
退出码：0 = 全部干净；1 = 有 Win8+ 导入；2 = 文件不是 PE
"""
import struct
import sys

BAD = {
    'WaitOnAddress', 'WakeByAddressAll', 'WakeByAddressSingle',      # Win8, api-ms-win-core-synch-l1-2-0
    'GetSystemTimePreciseAsFileTime',                                # Win8, kernel32
    'ProcessPrng',                                                   # Win10 1709, bcryptprimitives
    'GetHostNameW',                                                  # Win8, ws2_32
    'SetThreadDescription', 'GetThreadDescription',                   # Win10 1607
    'GetDpiForWindow', 'SetProcessDpiAwarenessContext',               # Win10 1607
    'RoInitialize', 'RoUninitialize',                                 # Win8
}


def sections_and_dirs(d):
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e + 4] != b'PE\0\0':
        return None
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from('<H', d, opt)[0]
    dd = opt + (96 if magic == 0x10b else 112)
    sec = opt + optsz
    secs = []
    for i in range(nsec):
        o = sec + i * 40
        vsz, va, rsz, rp = struct.unpack_from('<IIII', d, o + 8)
        secs.append((va, max(vsz, rsz), rp))
    return dd, secs


def rva2off(secs, r):
    for va, sz, raw in secs:
        if va <= r < va + sz:
            return raw + (r - va)
    return None


def imports(fn):
    d = open(fn, 'rb').read()
    got = sections_and_dirs(d)
    if got is None:
        return None
    dd, secs = got
    imp = struct.unpack_from('<I', d, dd + 8)[0]
    out = {}
    if not imp:
        return out
    off = rva2off(secs, imp)
    while off is not None:
        oft, _ts, _fc, nr, ft = struct.unpack_from('<IIIII', d, off)
        if nr == 0:
            break
        o = rva2off(secs, nr)
        dll = d[o:].split(b'\0')[0].decode('latin1') if o is not None else '?'
        th = rva2off(secs, oft) if oft else rva2off(secs, ft)
        flags = []
        while th is not None:
            v = struct.unpack_from('<I', d, th)[0]
            if v == 0:
                break
            if not (v & 0x80000000):
                o2 = rva2off(secs, v)
                if o2 is not None:
                    nm = d[o2 + 2:].split(b'\0')[0].decode('latin1')
                    if nm in BAD:
                        flags.append((dll, nm))
            th += 4
        out[dll] = flags
        off += 20
    return out


def main(paths):
    rc = 0
    for fn in paths:
        imps = imports(fn)
        if imps is None:
            print('!! %s 不是 PE 文件' % fn)
            rc = max(rc, 2)
            continue
        bad = [(dll, nm) for dll, fl in imps.items() for (dll, nm) in fl]
        total = sum(len(v) for v in imps.values())
        if bad:
            rc = max(rc, 1)
            print('✗ %s  发现 %d 个 Win8+ 导入（共 %d DLL）:' % (fn, len(bad), len(imps)))
            for dll, nm in bad:
                print('    %s!%s' % (dll, nm))
        else:
            print('✓ %s  Win8+ 导入: 无（%d 个 DLL，命中 %d）' % (fn, len(imps), total))
    if rc == 1:
        print('\n构建目标选错了：请用 --target i686-win7-windows-gnu -Z build-std=std（见 tools/win7/build-win7.sh）')
    return rc


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
