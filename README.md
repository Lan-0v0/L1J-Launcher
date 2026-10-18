# L1J-Launcher

天堂1 客户端**更新器**：检查更新 → 只下载差异条目 → 合并进 `Text.pak` → 启动游戏。

> ⚠️ 它**只做**这几件事。没有进程注入、没有内存补丁、不写注册表、不装驱动、不 hook API。
> 这不是功能缺失，是刻意设计：二进制要一次装好、之后永不更新，才能避免杀软把每次更新当成新样本。

---

## 它解决的问题

传统私服用 `eat.exe` 吃档：每次更新把补丁打成 zip，玩家端解压后调 `eat.exe` 把散装文件塞进容器。
问题是：`eat.exe` 带毒（Sality 感染体）、要联网下载再执行、每次都是"陌生 exe 干高危操作"。

本项目的做法：

1. **发版端**（你的电脑）用 `L1J-eat-CN` 的 `l1eat text diff` 产出**条目级补丁**（几百字节）
2. 用 `l1sign` 给 `manifest.json` 做 **Ed25519 签名**
3. 玩家端登录器：拉清单 → **验签** → 比对本地容器 → **只下缺的那几个条目** → 校验 SHA-256 → 合并 → 启动

全程客户端**不执行任何下载来的可执行文件**，只写自己目录里的 `Text.pak`。

---

## 客户端目录布局

```
龙潭天堂\
  l1j-launcher.exe     ← 唯一的入口（玩家的桌面快捷方式指向它）
  launcher.json        ← 配置（更新地址 + 公钥）
  login_old.exe        ← 原厂商登录器（改名后保留区服选择界面）
  login_old.ini / login_old.cfg
  Text.pak / Text.idx  ← 要被更新的容器
  L1J_Update.json      ← 本地版本记录（由本程序写）
```

> 原 `login.exe` 改名 `login_old.exe` 时，**`Login.ini` / `Login.cfg` 必须一起改名**
> （实测：配置名跟着 exe 基名走，不改名会导致区服列表空白）。

## `launcher.json`

```json
{
  "update_base": "https://your-domain/l1update/",
  "game_exe": "login_old.exe",
  "client_dir": ".",
  "public_key": "c74b4736...（64 个 hex 字符）",
  "launch_on_error": true
}
```

- `launch_on_error`：拉不到清单 / 验签失败时，是否仍然直接进游戏（默认 `true`，避免服务器挂了玩家进不去）

---

## 服务端目录（静态文件，不需要任何程序）

```
l1update/
  manifest.json     ← 由 l1eat text diff 产出
  manifest.sig      ← 由 l1sign 产出（对 manifest.json 的**原始字节**签名）
  text/
    boss1-h.html    ← 只放本次变更的条目
```

---

## 发版三步

```bat
:: 1) 比对两版客户端，产出 release
l1eat text diff --base 线上版客户端 --target 改过的客户端 --out release\v2026101901 --version 2026101901

:: 2) 签名（私钥只留本机）
l1sign sign release\v2026101901\manifest.json priv.hex

:: 3) 上传 manifest.json / manifest.sig / text\ 到 l1update/
```

## 命令行

```bat
l1j-launcher.exe              检查更新 → 合并 → 启动游戏
l1j-launcher.exe --no-launch  只更新不启动（自测用）
l1sign keygen priv.hex pub.hex
l1sign sign   manifest.json priv.hex
l1sign verify manifest.json pub.hex
```

---

## 构建

需要 Rust（本项目在 `x86_64-pc-windows-gnu` 下开发，机器无需 MSVC）：

```bash
export CARGO_HOME=E:/Rust/cargo RUSTUP_HOME=E:/Rust/rustup
export PATH=$PATH:/e/Rust/cargo/bin
cargo build --release
```

**两个本机坑**（换机器时注意）：

1. 源码在含中文的路径下时，MinGW 的 `ld` 会报 `cannot find *.rcgu.o` → 必须把构建产物放到纯英文目录
   （已在 `E:\Rust\cargo\config.toml` 设 `[build] target-dir = "E:/Rust/target"`）
2. 早期版本依赖 `windows` crate，其构建脚本需要 `dlltool.exe`；现已**手写 WinHTTP FFI** 去掉该依赖，
   只需要 MinGW 自带的 `libwinhttp.a`。

产物：`l1j-launcher.exe` 约 **553 KB**，`l1sign.exe` 约 388 KB，均为单文件、无运行时依赖。

---

## 依赖

- `crates/l1pak` —— 从 `L1J-eat-CN/rust/l1pak` 内置的容器读写库（与 Python 版逐字节等价，靠 golden vectors 对拍）
  - 上游更新后用脚本同步，不要在这里直接改
- `ed25519-dalek` —— 验签
- `serde` / `serde_json` / `sha2`

## 当前状态

- [x] 清单 + Ed25519 验签
- [x] 只下差异条目 + SHA-256 校验
- [x] 原地写 / 尾部追加（不紧凑重建）
- [x] 幂等（已是最新则跳过）
- [x] 失败可跳过更新直接进游戏
- [ ] GUI（进度条窗口）
- [ ] 首次全量校验
- [ ] 回滚（保留上一版容器）
