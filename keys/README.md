# keys/ —— 签名密钥（私钥不进 git）

## 文件

| 文件 | 是否入库 | 说明 |
|---|---|---|
| `ed25519-signing.key` | **否**（被 .gitignore 排除） | 私钥，32 字节随机种子的 hex（64 字符） |
| `ed25519-signing.pub` | 是 | 公钥 hex，内置在每个玩家的 `launcher.json` 的 `public_key` |
| `README.md` | 是 | 本文件 |

## 公钥指纹

```
c74b4736487feb5dc600252ca6b65ff761bd27b06e36cc2ab0b1c8b1e3578cf0
```

## 用途

给热更清单签名：

```bash
# 签名（需要私钥）
l1sign sign manifest.json keys/ed25519-signing.key

# 验签（只需要公钥）
l1sign verify manifest.json keys/ed25519-signing.pub
```

产出的 `manifest.sig` 和 `manifest.json` 一起放到云端 `/opt/l1j/update/`，
客户端用内置公钥验签，通过才更新。

## 为什么私钥不提交

git 历史不可变——一旦提交，即使之后删除，`.git` 里仍然保留，任何克隆过仓库的人都能翻出来。
私钥泄露 = 别人可以伪造 manifest + 签名，让所有客户端主动下载并安装任意文件。

## 公钥 / 私钥的正确理解

- **公钥丢了**：不要紧，可从私钥重新推导（seed → SHA512 → clamp → 标量乘基点）。
  验证脚本见 `D:\l1log\sec\derive_pub.py`。
- **私钥丢了**：不可找回。只能生成新密钥对 → 换公钥 → 重签 → **所有客户端的
  `launcher.json` 都要更新**（公钥是写死在客户端的，这一步不能走热更，只能走整包更新）。

## 备份要求

私钥必须离线备份 ≥2 份（U 盘 / 加密压缩包 / 纸质二维码均可），
且**不要**放在任何会被同步到云端的目录里。
