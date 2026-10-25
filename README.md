# L1J-Launcher

天堂1 客户端**一体化启动器**：检查更新 → 选区 → 启动游戏。

界面是 Win32 原生窗口（GDI 自绘，底图取自客户端 `skin\`），**不用 Electron / WebView**，单文件、无运行时依赖。

> ⚠️ 它只做这几件事：拉清单、验签、下载差异、写自己目录、起游戏。
> 没有进程注入、没有内存补丁、不写注册表、不装驱动、不 hook API。
> 这不是功能缺失，是刻意设计：二进制一次装好、之后不再自我更新，避免杀软把每次更新当成新样本。

---

## 三条更新通道

| 通道 | 目标 | 能力 |
|---|---|---|
| **Text** | `Text.pak` 内部条目（NPC 对话页、字符串表） | 改已有条目、**新增条目**（新记录按名称小写序插入 idx，保持客户端二分查找可用） |
| **文件** | 客户端目录内**任意文件**（反外挂组件、补丁 DLL、配置） | 新建 / 覆盖 / 删除；内容寻址下载、路径白名单、占用检测、原子替换、备份回滚 |
| **登录器自身** | 正在运行的这个 exe | 改名腾位替换（见「登录器自更新」）；失败一律放行，不影响进游戏 |

清单为 `schema 2`。**老清单没有 `files` / `launcher` 段时，行为与旧版完全一致**（已实测）。

### 清单结构

```json
{
  "schema": 2,
  "container": "Text",
  "version": "v20261020_xxx",
  "created": "2026-10-20T09:53:01+0800",
  "entries": [ { "name": "maker1-h.html", "size": 257, "sha256": "...", "op": "add" } ],
  "files": {
    "base": "files/",
    "entries": [ { "path": "antibot/ac.dll", "size": 12345, "sha256": "..." } ],
    "deletes": [ "antibot/old.dll" ]
  },
  "launcher": { "version": "20261025.1840", "size": 2800640, "sha256": "..." },
  "unsupported": { "added": [], "removed": [] }
}
```

- `entries[].op`：缺省 = 覆盖已有条目，`add` = 新增（客户端容器里没有时走 add 分支）
- `files[].path`：**相对客户端目录**的路径，正斜杠
- 文件下载地址 = `<update_base><files.base><sha256>`（内容寻址，与路径无关，天然去重）
- `launcher`：登录器自身，**故意不含文件名**（玩家会把 exe 改名），更新目标一律取 `current_exe()`；
  是否更新**只比 `sha256`**，`version` 仅用于日志和界面提示

---

## 更新流程

```
拉 manifest.json + manifest.sig → Ed25519 验签 →
比对本地（容器条目 / 文件 sha256）→ 只下差异 →
逐条校验 size + sha256 → 合并容器 / 写文件 → 写 L1J_Update.json
```

**文件通道的写入顺序**（`update::apply_files`）：

1. 校验 `size` + `sha256`，不符立即中止（不落盘）
2. 占用检测：`CreateFileW(share=0)` 独占打开一次，被占用就提示关闭游戏
3. 旧文件备份到 `backup_l1j/files/<版本>/<相对路径>`，并写 `_files.json` 记录「原本是否存在」
4. 写 `<目标>.l1jtmp` → `MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH)` 原子替换
5. 删除项同样先备份再删

**路径白名单**：拒绝绝对路径、盘符、`..`、ADS（`:`）、Windows 保留设备名（CON/NUL/COM1…）、
通配符、片段结尾的点或空格。恶意清单在**计划阶段**就被拒绝，不会产生任何写入。

**回滚**：`rollback_files()` 取最新版本备份目录按 `_files.json` 回放（原本存在的拷回，本次新建的删掉）；
容器仍走 `backup_l1j/Text.pak.bak` / `Text.idx.bak`。

---

## 登录器自更新

Windows 只锁运行中 exe 的**映像节**，不锁**目录项**：可以改名，但不能覆盖或删除。
所以自更新用「改名腾位」，与 Squirrel.Windows / Velopack / iw4x 登录器同一套机制：

```
下载 files/<sha256> → 校验 size + sha256 + PE 头 → 写同目录 <exe>.new
  → <exe> 改名为 <exe>.old   （腾出原名）
  → <exe>.new 改名为 <exe>   （就位；这一步失败立刻把 .old 改回）
  → 重启自己，带 --self-updated
```

**为什么不复用文件通道**：`apply_files` 对 `is_locked()` 命中是直接报错，而正在运行的自己永远被锁，
会把整单更新拖失败。自更新必须是独立分支（`src/selfupdate.rs`）。

**五条防护**

| 防护 | 做法 |
|---|---|
| 防重复 | 比 `sha256`，相等即跳过（顺带自愈被玩家改过的 exe） |
| 防死循环 | 重启带 `--self-updated`，本次启动一律不再碰 exe；即使被回滚也只尝试一次 |
| 防脏数据 | size + sha256 + `MZ` / `PE\0\0` 双头校验，全过才写 `.new` |
| 防半途失败 | 第二步失败立刻反向改名回滚，`.old` 始终是可直接运行的完整上一版 |
| 防阻断 | 任何异常只记日志，**继续正常更新与启动**（fail-open） |

`.old` 不自动删：它是手工回滚点（`copy /y Login.exe.old Login.exe` 即可回到上一版），
下次更新时被新的 `.old` 覆盖。

---

## 启动流程

```
更新（失败可跳过，直接进游戏）→ 选区窗口（真实 ping，绿/黄/红/灰）→
按选区把 `servers.ini` 里对应的那一段**按字节**切出来写进 `login_old.ini`（只写选中的那一条）→
把选中区 IP 转成十进制整数作为**启动参数** → CreateProcess 拉起厂商登录器 →
注入 quiet.dll 隐藏其选区弹窗 → 客户端连服

> ⚠️ 真正决定连到哪台服务器的是 **`ServerData` 密文**（Encode 生成、含 IP+端口，游戏启动时自己解密）。
> 启动参数里的十进制 IP 是冗余的：`Encode/README.md` 记录 2026-10-19 实测「命令行参数与此无关」。
> `apply_lineage_cfg()`（写 `lineage.cfg`）是**死代码**，全仓库没有调用点。
> ⇒ **换服务器 IP 时，必须用 Encode 重新生成 `servers.ini` 的 ServerData**，只改 `launcher.json` 不够。
```

- 厂商登录器 **ini 有多条时永远只用第一条**，所以只写选中的那一块（按字节切 GBK，不转码）
- `quiet.dll` 用 `SetWinEventHook(EVENT_OBJECT_SHOW)` 拦住厂商选区窗，再用 `BM_CLICK` 点「进入游戏」

---

## 客户端目录布局

```
龙潭天堂\
  Login.exe            ← 唯一入口
  launcher.json        ← 配置（更新地址 / 公钥 / 区服列表）
  Login.ico            ← 图标源（编译期已内嵌，运行时不需要它）
  skin\                ← 厂商皮肤源（登录器底图从这里取，必须保留）
  login_old.exe        ← 原厂商登录器（改名后保留）
  login_old.ini / login_old.cfg
  Text.pak / Text.idx  ← 要被更新的容器
  backup_l1j\          ← 自动备份（容器 + 每次文件更新的旧版本）
  L1J_Update.json      ← 本地版本记录（由本程序写）
```

> 原 `login.exe` 改名 `login_old.exe` 时，`Login.ini` / `Login.cfg` **必须一起改名**
> （配置名跟着 exe 基名走，不改名会导致区服列表空白）。

## `launcher.json`

```json
{
  "update_base": "http://<host>:1999/",
  "game_exe": "login_old.exe",
  "client_dir": ".",
  "public_key": "c74b4736...（64 个 hex 字符）",
  "launch_on_error": true,
  "servers": [
    { "name": "龙潭天堂·测试", "ip": "<host>", "enabled": true, "port": 2000 },
    { "name": "龙潭天堂·合区", "ip": "<host>", "enabled": true, "port": 2001 },
    { "name": "龙潭天堂·三区", "ip": "<host>", "enabled": false, "port": 2002 }
  ]
}
```

- `launch_on_error`：拉不到清单 / 验签失败时是否仍直接进游戏（默认 `true`）
- `servers[].ip`：**可填 IPv4（`1.2.3.4`），也可填域名 / DDNS 主机名**；域名会在启动前解析成 IPv4
  （用于选区 ping 和启动参数。真正的游戏连接地址仍由 `ServerData` 决定）
- `servers` ≥ 2 时启动前弹选区窗口；`enabled: false` 的点显示为灰点且不可选

---

## 服务端静态目录（不需要任何程序）

```
l1update/
  manifest.json      ← l1eat text diff / file pack 产出
  manifest.sig       ← l1sign 产出（对 manifest.json 原始字节签名）
  text/              ← 只放本次变更的容器条目
  files/<sha256>     ← 文件通道内容（按哈希命名）
```

部署方式：`python3 -m http.server 1999 --directory /opt/l1j/update` + systemd（`l1update.service`）。

---

## 发版

```bat
:: ① 容器条目：比对两版客户端
l1eat text diff --base 线上客户端 --target 改过的客户端 --out release\vXXX --version vXXX

:: ② 普通文件：把目录打进同一个 release（可反复执行，按路径去重）
l1eat file pack --src 要发布的目录 --release release\vXXX [--prefix antibot] [--delete old/x.dll]

:: ③ 签名（私钥只留本机）
l1sign sign release\vXXX\manifest.json priv.hex

:: ④ 上传 manifest.json / manifest.sig / text\ / files\
```

要顺带更新**登录器本身**时，把新 exe 放到 `files/<它的 sha256>`，并在清单里加：

```json
"launcher": { "version": "20261025.1840", "size": 2800640, "sha256": "<与上面的文件名一致>" }
```

玩家下次启动就会自己换掉，旧版留成 `Login.exe.old`，可手工回滚。

## 命令行

```bat
Login.exe                 直接进图形界面（更新 → 选区 → 游戏）
Login.exe --console       控制台模式：只跑更新并打印明细（自测/排错；不提权、不重启）
Login.exe --self-updated  内部使用：刚自更新完，本次不再碰 exe（防死循环）
l1sign keygen priv.hex pub.hex
l1sign sign   manifest.json priv.hex
l1sign verify manifest.json pub.hex
```

---

## 构建

Rust + MinGW（机器无需 MSVC）。**必须用 `i686-win7-windows-gnu`**，不能用默认的 `i686-pc-windows-gnu`：

```bash
export PATH="/d/l1log/tc/mingw32/bin:/c/Users/<user>/.cargo/bin:$PATH"
cd /d/l1win7build/l1j-launcher       # ★必须在纯 ASCII 路径下构建
tools/win7/build-win7.sh             # 内含 build-std 与导入表校验
```

### ★ 为什么不能用默认 target（2026-10-22 线上事故）

Rust 1.78 起，`i686-pc-windows-gnu` 的最低系统要求被抬到 **Windows 10**，会静态导入 5 个
Win7 根本不存在的 API：

| DLL | 函数 | 起始版本 |
|---|---|---|
| `api-ms-win-core-synch-l1-2-0` | `WaitOnAddress` / `WakeByAddressAll` / `WakeByAddressSingle` | Win8 |
| `bcryptprimitives` | `ProcessPrng` | Win10 1709 |
| `KERNEL32` | `GetSystemTimePreciseAsFileTime` | Win8 |

Win7 加载器解析这些 API Set forwarder 时**直接抛访问违例**，表现为
「应用程序无法正常启动 (0xc0000005)」，**且不会提示缺少 DLL**，极难排查。
`quiet.dll` 同理（旧版还多一个 `WS2_32!GetHostNameW`）。

正确 target 是 `i686-win7-windows-gnu`（Tier 3，`target_vendor="win7"`，无预编译 std）：

- 宿主必须用 **`nightly-x86_64-pc-windows-gnu`**（普通 `nightly` 是 msvc 宿主，交叉链 gnu 目标会失败）
- 需要 `rust-src` 组件 + `-Z build-std=std`（cdylib 再加 `,panic_abort`）
- 构建目录必须是纯 ASCII 路径（`-Z build-std` 要现编 std，中文路径会失败）

**打包前必须过导入表守卫**（`build-win7.sh` 已自动调用）：

```bash
python tools/win7/check_pe_imports.py dist-win7/l1j-launcher.exe quiet.dll
# 退出码 0 = 干净；1 = 有 Win8+ 导入，禁止发布
```

**三个坑**（换机器必看）：

1. **源码放在含中文的路径下，MinGW 的 `ld` 会失败**（找不到 `*.rcgu.o`）→ 构建目录必须是纯 ASCII
2. `windres` 只有 `windres.exe`，**不要**设 `WINDRES=i686-w64-mingw32-windres.exe`（会启动失败）
3. `cargo` 在 `C:\Users\<user>\.cargo\bin`，**不要**把 `CARGO_HOME` 指到别处（会 command not found）

图标由 `icon.rc` + `build.rs` 在编译期嵌入（`assets/app.ico` 换成新图后重编译即可）。

产物：`l1j-launcher.exe` ≈ **2.7 MB**（含 5 档图标）、`l1sign.exe` ≈ **488 KB**，均为单文件、无运行时依赖。

---

## 依赖

- `crates/l1pak` —— 内置的容器读写库（与 `L1J-eat-CN/rust/l1pak` 同一份代码，上游改动后同步过来，不要在这里直接改）
- `ed25519-dalek` —— 验签
- `serde` / `serde_json` / `sha2`

## 当前状态

- [x] 清单 + Ed25519 验签（对原始字节签名）
- [x] 只下差异 + SHA-256 校验
- [x] 容器：原地写 / 尾部追加 / **新增条目**（按名称小写序插入 idx）
- [x] 文件通道：任意文件新建 / 覆盖 / 删除（白名单 + 占用检测 + 原子替换 + 备份）
- [x] 幂等（已是最新则跳过）
- [x] 失败可跳过更新直接进游戏
- [x] GUI（加载窗 + 选区窗、双进度条缓动动画、等待态流动块）
- [x] 真实 ping（圆点：绿 <150ms / 黄 / 红 / 灰=禁用）
- [x] 首次全量校验（`verify_container`）
- [x] 回滚实现（容器 + 文件）
- [x] 联网超时（WinHTTP 解析 3s / 连接 3s / 发送 5s / 接收 5s）
- [ ] 「Recover」按钮接线到 `rollback()`（函数已就绪，按钮仍是占位）
- [ ] 清单全量语义（`export_changes` 只写本次变更，玩家跳版本可能漏更）
