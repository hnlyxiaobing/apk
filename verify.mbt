///|
/// 真验签通道：`Apk::verify_signatures`（W6 公钥验签，M6-RSA-a/b）。
///
/// 与 `signature_checks()`（历史契约）不同：本入口对签名**值**做 RSA PKCS#1 v1.5 公钥
/// 验签。`crypto_verified` 为 true 仅当签名值在模幂后填充正确且 DigestInfo 一致。
///
/// 语义防火墙（本包最重要的设计决策，硬性）：
/// - `signature_checks()` 与 `SignatureCheck.signature_verified` **恒 false 永不改变**；
/// - 验签结论只走本模块的新类型 `SignatureVerification`；
/// - 不支持/未实现算法（ECDSA、DSA、RSA-PSS、v1 未接入分支）一律 fail-closed：
///   `crypto_verified` 恒 false，`detail` 说明原因，绝不误判为通过。
///
/// 范围（W6 已裁决 2026-11-18：仅 RSA 降级立项）：v2/v3/v3.1 的 RSA PKCS#1 v1.5
/// 签名值验证（M6-RSA-a）；v1 CMS SignedData 接入（M6-RSA-b）。

///|
/// 单个签名方案的验签结论（新类型，纯加法 API；旧类型语义不变）。
pub(all) struct SignatureVerification {
  scheme : SignatureScheme
  /// 签名结构是否可解析（v2/v3/v3.1：signer 序列结构合法；v1：PKCS#7/MANIFEST/.SF 齐全）。
  structure_ok : Bool
  /// 本地可验证的摘要是否一致（v2/v3/v3.1：APK 内容分块摘要；v1：清单条目 + .SF 摘要）。
  digest_ok : Bool
  /// **公钥验签**是否通过。仅 RSA PKCS#1 v1.5 可实现；ECDSA/DSA/未知恒 false（fail-closed）。
  crypto_verified : Bool
  /// 实际执行的算法标识（如 `"SHA256withRSA"` / `"SHA512withRSA"` / `"unsupported"`）。
  algo : String
  /// 人类可读结论 / 失败原因（诊断用，不参与判定）。
  detail : String
}

///|
/// 对每个已识别签名方案做**签名值**验签，返回新类型 `SignatureVerification` 列表。
///
/// 顺序与 `signature_checks()` 一致（v1 优先，v2/v3/v3.1 按块内顺序、按方案排序）。
/// 不抛错即表示结构可解析；单个方案验签失败记录在该方案 `crypto_verified=false` 中，
/// 不中断整体遍历。
pub fn Apk::verify_signatures(
  self : Apk,
) -> Array[SignatureVerification] raise ApkError {
  let out : Array[SignatureVerification] = []
  for rec in self.collect_signature_records() {
    match rec.scheme {
      SignatureScheme::V1 => out.push(self.verify_v1_crypto(rec))
      SignatureScheme::V2 | SignatureScheme::V3 | SignatureScheme::V31 =>
        out.push(self.verify_v2_crypto(rec))
    }
  }
  out
}

///|
/// v1 CMS signerInfo 验签（M6-RSA-b）。结构与摘要沿用 `verify_v1` 的既有结论；
/// 签名值走 `verify_v1_signer_info`（RSA PKCS#1 v1.5 over signedAttrs 或 content）。
fn Apk::verify_v1_crypto(self : Apk, rec : SigRecord) -> SignatureVerification {
  let base = self.verify_v1(rec)
  let sf_bytes = match rec.v1_sf {
    Some(n) => self.safe_entry(n)
    None => None
  }
  let pkcs7 = match rec.v1_block {
    Some(n) => self.safe_entry(n)
    None => None
  }
  let (crypto_verified, algo, detail) = match (sf_bytes, pkcs7) {
    (Some(sf), Some(der)) => verify_v1_signer_info(rec.certs, sf, der)
    _ =>
      (false, "unsupported", "v1 signerInfo: .SF or PKCS#7 block unavailable")
  }
  {
    scheme: rec.scheme,
    structure_ok: base.structure_ok,
    digest_ok: base.digest_ok,
    crypto_verified,
    algo,
    detail,
  }
}

///|
/// v2/v3/v3.1 签名值验签（RSA PKCS#1 v1.5 / PSS 与 ECDSA）。
///
/// 签名覆盖的原始数据 = signer 的 **signed-data 内容字节**（digests + certificates +
/// [min/maxSDK] + attributes 的长度前缀序列化，不含其自身长度前缀），即 apksigner
/// 口径的 `dataToSign`。对每个 signature 记录按算法 ID 决定摘要算法并验签。
fn Apk::verify_v2_crypto(self : Apk, rec : SigRecord) -> SignatureVerification {
  let signers = self.try_extract_scheme_verify(rec)
  if signers is None {
    return {
      scheme: rec.scheme,
      structure_ok: false,
      digest_ok: false,
      crypto_verified: false,
      algo: "unsupported",
      detail: "signer structure could not be parsed for signature-value verification",
    }
  }
  let signers = signers.unwrap()
  // 摘要：沿用既有内容分块摘要判定。
  let digest_ok = match rec.digests {
    [] => false
    _ => {
      let mut ok = false
      for d in rec.digests {
        let name = content_digest_algorithm_name(d.algorithm)
        if name != "SHA-256" && name != "SHA-512" {
          continue
        }
        match self.content_digest(name) {
          Some(c) => if c == d.digest { ok = true }
          None => ()
        }
      }
      ok
    }
  }
  // 结构合法 = 至少一个 signer，且签名记录与公钥字段齐全。
  let structure_ok = signers.length() > 0
  // 逐个 signer 尝试 RSA / ECDSA 验签；任一签名通过即 crypto_verified=true。
  let (crypto_verified, algo, detail) = verify_v2_signers(signers)
  {
    scheme: rec.scheme,
    structure_ok,
    digest_ok,
    crypto_verified,
    algo,
    detail,
  }
}

///|
/// 对一组 signer 做签名值验签：先按 RSA SPKI 解析，失败再按 EC SPKI 解析。
///
/// RSA：算法 ID 0x0101/0x0102 = RSA-PSS(SHA-256/512)，0x0103/0x0104 = PKCS#1 v1.5。
/// ECDSA：0x0201 = SHA256withECDSA、0x0202 = SHA512withECDSA（无 PSS 变体），
/// 签名值为 DER `SEQUENCE{INTEGER r, INTEGER s}`。两者都无法识别时 fail-closed。
fn verify_v2_signers(
  signers : Array[SignerVerifyData],
) -> (Bool, String, String) {
  let mut crypto_verified = false
  let mut algo = "unsupported"
  let mut detail = "no verifiable RSA signature"
  for s in signers {
    match rsa_public_key_from_spki(s.public_key) {
      Some(k) =>
        if rsa_key_too_large(k) {
          // 模数超 8192 位：fail-closed，且不进入模幂（DoS 面收敛）。
          detail = "key too large"
        } else {
          for (alg_id, sig_bytes) in s.signatures {
            // Android 签名算法 ID：0x0101/0x0102 = RSA-PSS(SHA-256/512)，
            // 0x0103/0x0104 = RSA-PKCS#1 v1.5(SHA-256/512)；其余不支持。
            let (hash_name, digest, pss) = match alg_id {
              0x0101U => ("SHA-256", sha256(s.signed_data), true)
              0x0102U => ("SHA-512", sha512(s.signed_data), true)
              0x0103U => ("SHA-256", sha256(s.signed_data), false)
              0x0104U => ("SHA-512", sha512(s.signed_data), false)
              _ => ("", b"", false)
            }
            let verified = if hash_name == "" {
              false
            } else if pss {
              rsa_verify_pss(k, sig_bytes, digest, hash_name)
            } else {
              rsa_verify_pkcs1(k, sig_bytes, digest, hash_name)
            }
            if verified {
              crypto_verified = true
              algo = if pss {
                if hash_name == "SHA-256" {
                  "SHA256withRSA/PSS"
                } else {
                  "SHA512withRSA/PSS"
                }
              } else if hash_name == "SHA-256" {
                "SHA256withRSA"
              } else {
                "SHA512withRSA"
              }
              detail = if pss {
                "RSA PSS signature verified over signed data"
              } else {
                "RSA PKCS#1 v1.5 signature verified over signed data"
              }
            } else {
              detail = "signature failed verification or unsupported algorithm"
            }
          }
        }
      None =>
        match ec_public_key_from_spki(s.public_key) {
          None => detail = "public key is not a parseable RSA or EC SPKI"
          Some((curve, qx, qy)) =>
            match ec_params(curve) {
              None => detail = "unsupported EC curve"
              Some(params) =>
                for (alg_id, sig_bytes) in s.signatures {
                  // ECDSA 无 PSS 版本：0x0201 只对应 SHA-256、0x0202 只对应 SHA-512。
                  let (hash_name, digest) = match alg_id {
                    0x0201U => ("SHA-256", sha256(s.signed_data))
                    0x0202U => ("SHA-512", sha512(s.signed_data))
                    _ => ("", b"")
                  }
                  if hash_name == "" {
                    detail = "signature failed verification or unsupported algorithm"
                    continue
                  }
                  match ec_sig_from_der(sig_bytes) {
                    None => detail = "ECDSA signature value is not valid DER"
                    Some((r, sig_s)) =>
                      if ec_ecdsa_verify(
                          params,
                          qx,
                          qy,
                          big_from_be_bytes(digest),
                          r,
                          sig_s,
                        ) {
                        crypto_verified = true
                        algo = if hash_name == "SHA-256" {
                          "SHA256withECDSA"
                        } else {
                          "SHA512withECDSA"
                        }
                        detail = "ECDSA signature verified over signed data"
                      } else {
                        detail = "ECDSA signature failed verification"
                      }
                  }
                }
            }
        }
    }
  }
  (crypto_verified, algo, detail)
}

///|
/// 提取签名方案的各 signer 验签数据；结构异常（raise）时返回 None（fail-closed）。
fn Apk::try_extract_scheme_verify(
  self : Apk,
  rec : SigRecord,
) -> Array[SignerVerifyData]? {
  let mut out : Array[SignerVerifyData]? = None
  try {
    out = Some(
      extract_scheme_verify(
        self.source,
        rec.value_off,
        rec.value_len,
        rec.value_off,
        rec.scheme,
      ),
    )
  } catch {
    _ => ()
  } noraise {
    _ => ()
  }
  out
}

///|
/// 单个 signer 的验签所需数据。
priv struct SignerVerifyData {
  signed_data : Bytes
  signatures : Array[(UInt32, Bytes)]
  public_key : Bytes
}

///|
/// 从签名方案 value 中提取每个 signer 的 signed-data 原始字节、签名记录与公钥 SPKI。
///
/// 布局与 `extract_signer_data` 相同，但额外取：
///   v2  signer = signed_data(长度前缀) + signatures(长度前缀序列) + public_key(长度前缀)。
///   v3/3.1 signer = signed_data + uint32 minSdk + uint32 maxSdk + signatures + public_key。
/// signatures = u32 序列长 { u32 记录长 u32 算法ID u32 签名长 签名 }*。
/// signed-data 内容字节即签名覆盖对象（不含其自身长度前缀）。
fn extract_scheme_verify(
  source : Bytes,
  value_off : Int32,
  value_len : Int32,
  pair_off : Int32,
  scheme : SignatureScheme,
) -> Array[SignerVerifyData] raise ApkError {
  let out : Array[SignerVerifyData] = []
  let end = value_off + value_len
  let mut pos = value_off
  guard pos + 4 <= end else {
    raise ApkError::BadSigningBlock(pair_off, "signer sequence length missing")
  }
  let seq_len = le_u32(source, pos)
  guard seq_len <= (end - pos - 4).reinterpret_as_uint() else {
    raise ApkError::BadSigningBlock(
      pair_off, "signer sequence overruns signature scheme value",
    )
  }
  let seq_end = pos + 4 + seq_len.reinterpret_as_int()
  pos = pos + 4
  while pos < seq_end {
    guard pos + 4 <= seq_end else {
      raise ApkError::BadSigningBlock(pair_off, "signer length missing")
    }
    let signer_len = le_u32(source, pos)
    guard signer_len <= (seq_end - pos - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(
        pair_off, "signer overruns signer sequence",
      )
    }
    let signer_end = pos + 4 + signer_len.reinterpret_as_int()
    let mut sp = pos + 4
    // signed_data
    guard sp + 4 <= signer_end else {
      raise ApkError::BadSigningBlock(pair_off, "signed data length missing")
    }
    let sd_len = le_u32(source, sp)
    guard sd_len <= (signer_end - sp - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(pair_off, "signed data overruns signer")
    }
    let sd_content = sp + 4
    let sd_end = sd_content + sd_len.reinterpret_as_int()
    let signed_data = source[sd_content:sd_end].to_owned()
    sp = sd_end
    // v3 / v3.1：signed_data 之后是 minSdk / maxSdk 两个裸 uint32。
    if scheme is SignatureScheme::V3 || scheme is SignatureScheme::V31 {
      guard sp + 8 <= signer_end else {
        raise ApkError::BadSigningBlock(pair_off, "v3 min/max SDK missing")
      }
      sp = sp + 8
    }
    // signatures（长度前缀序列）
    guard sp + 4 <= signer_end else {
      raise ApkError::BadSigningBlock(pair_off, "signatures length missing")
    }
    let sigs_len = le_u32(source, sp)
    guard sigs_len <= (signer_end - sp - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(pair_off, "signatures overrun signer")
    }
    let sigs_end = sp + 4 + sigs_len.reinterpret_as_int()
    sp = sp + 4
    let signatures : Array[(UInt32, Bytes)] = []
    while sp < sigs_end {
      guard sp + 4 <= sigs_end else {
        raise ApkError::BadSigningBlock(
          pair_off, "signature record length missing",
        )
      }
      let rec_len = le_u32(source, sp)
      guard rec_len >= 8 && rec_len <= (sigs_end - sp - 4).reinterpret_as_uint() else {
        raise ApkError::BadSigningBlock(
          pair_off, "signature record overruns signatures",
        )
      }
      let alg_id = le_u32(source, sp + 4)
      let sig_len = le_u32(source, sp + 8)
      guard sig_len <= rec_len - 8 else {
        raise ApkError::BadSigningBlock(pair_off, "signature overruns record")
      }
      signatures.push(
        (
          alg_id,
          source[sp + 12:sp + 12 + sig_len.reinterpret_as_int()].to_owned(),
        ),
      )
      sp = sp + 4 + rec_len.reinterpret_as_int()
    }
    sp = sigs_end
    // public_key（长度前缀）
    guard sp + 4 <= signer_end else {
      raise ApkError::BadSigningBlock(pair_off, "public key length missing")
    }
    let pk_len = le_u32(source, sp)
    guard pk_len <= (signer_end - sp - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(pair_off, "public key overruns signer")
    }
    let public_key = source[sp + 4:sp + 4 + pk_len.reinterpret_as_int()].to_owned()
    sp = sp + 4 + pk_len.reinterpret_as_int()
    out.push({ signed_data, signatures, public_key, })
    pos = signer_end
  }
  out
}
