//! l1sign —— 清单签名小工具（发版机专用，不随客户端发布）
//!
//! 用法：
//!   l1sign keygen <priv.hex> <pub.hex>        生成一对密钥（私钥留本机，公钥填进 launcher.json）
//!   l1sign sign   <manifest.json> <priv.hex>  生成 manifest.sig（放在 manifest.json 同目录）
//!   l1sign verify <manifest.json> <pub.hex>   本地自检签名

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::process::exit;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        usage();
    }
    let rc = match args[0].as_str() {
        "keygen" => {
            if args.len() != 3 {
                usage();
            }
            keygen(&args[1], &args[2])
        }
        "sign" => {
            if args.len() != 3 {
                usage();
            }
            sign(&args[1], &args[2])
        }
        "verify" => {
            if args.len() != 3 {
                usage();
            }
            verify(&args[1], &args[2])
        }
        _ => usage(),
    };
    if let Err(e) = rc {
        eprintln!("[错误] {}", e);
        exit(1);
    }
}

fn usage() -> ! {
    eprintln!(
        "l1sign —— 清单签名\n\
         \n  l1sign keygen <priv.hex> <pub.hex>\n\
         \n  l1sign sign   <manifest.json> <priv.hex>\n\
         \n  l1sign verify <manifest.json> <pub.hex>"
    );
    exit(2);
}

fn read_hex32(path: &str) -> Result<[u8; 32], String> {
    let txt = std::fs::read_to_string(path).map_err(|e| format!("读 {} 失败: {}", path, e))?;
    let hex = txt.trim();
    if hex.len() != 64 {
        return Err(format!("{} 应为 64 个 hex 字符（32 字节），实际 {}", path, hex.len()));
    }
    let mut out = [0u8; 32];
    let b = hex.as_bytes();
    for i in 0..32 {
        let hi = (b[i * 2] as char).to_digit(16).ok_or("hex 非法")? as u8;
        let lo = (b[i * 2 + 1] as char).to_digit(16).ok_or("hex 非法")? as u8;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn keygen(priv_path: &str, pub_path: &str) -> Result<(), String> {
    let sk = SigningKey::generate(&mut OsRng);
    std::fs::write(priv_path, hex(&sk.to_bytes()) + "\n").map_err(|e| e.to_string())?;
    std::fs::write(pub_path, hex(sk.verifying_key().as_bytes()) + "\n").map_err(|e| e.to_string())?;
    println!("私钥 -> {}（只留在本机，绝不要发给玩家）", priv_path);
    println!("公钥 -> {}（填进 launcher.json 的 public_key）", pub_path);
    Ok(())
}

fn sig_path_for(manifest_path: &str) -> String {
    if let Some(stem) = manifest_path.strip_suffix(".json") {
        format!("{}.sig", stem)
    } else {
        format!("{}.sig", manifest_path)
    }
}

fn sign(manifest_path: &str, priv_path: &str) -> Result<(), String> {
    let seed = read_hex32(priv_path)?;
    let sk = SigningKey::from_bytes(&seed);
    let raw = std::fs::read(manifest_path).map_err(|e| format!("读清单失败: {}", e))?;
    let sig = sk.sign(&raw);
    let out = sig_path_for(manifest_path);
    std::fs::write(&out, hex(&sig.to_bytes()) + "\n").map_err(|e| e.to_string())?;
    println!("清单 {} 字节，签名 -> {}", raw.len(), out);
    Ok(())
}

fn verify(manifest_path: &str, pub_path: &str) -> Result<(), String> {
    let pk_bytes = read_hex32(pub_path)?;
    let pk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("公钥非法: {}", e))?;
    let raw = std::fs::read(manifest_path).map_err(|e| format!("读清单失败: {}", e))?;
    let sig_path = sig_path_for(manifest_path);
    let sig_txt = std::fs::read_to_string(&sig_path)
        .map_err(|e| format!("读签名失败 {}: {}", sig_path, e))?;
    let sig_txt = sig_txt.trim();
    if sig_txt.len() != 128 {
        return Err(format!("签名应为 128 个 hex 字符，实际 {}", sig_txt.len()));
    }
    let mut sig_bytes = [0u8; 64];
    let b = sig_txt.as_bytes();
    for i in 0..64 {
        let hi = (b[i * 2] as char).to_digit(16).ok_or("签名 hex 非法")? as u8;
        let lo = (b[i * 2 + 1] as char).to_digit(16).ok_or("签名 hex 非法")? as u8;
        sig_bytes[i] = (hi << 4) | lo;
    }
    let signature = Signature::from_bytes(&sig_bytes);
    pk.verify(&raw, &signature)
        .map_err(|_| "验签失败".to_string())?;
    println!("验签通过（{} 字节清单）", raw.len());
    Ok(())
}
