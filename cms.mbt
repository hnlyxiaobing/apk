///|
/// v1（JAR 签名）CMS SignedData 的 signerInfo 签名值验证（W6 / M6-RSA-b + ECDSA）。
///
/// 覆盖范围：PKCS#7 `SignedData` 中每个 `SignerInfo` 的 RSA PKCS#1 v1.5 / ECDSA 签名值。
/// 验签对象口径（与 apksigner / jarsigner 一致）：
/// - 若 signerInfo 带 `authenticatedAttributes`（[0] IMPLICIT SET OF Attribute），
///   签名覆盖的是把这些属性**重新编码为 SET OF（tag 0x31）**的 DER 字节，
///   且其中 `messageDigest` 属性值必须等于 `.SF` 文件的摘要；
/// - 若不 signedAttrs，签名直接覆盖 `.SF` 内容。
///
/// DSA/未知算法一律 fail-closed（返回 false）。
/// 不新增 `ApkError` 变体；解析失败一律返回 false（不抛错）。

///|
/// signerInfo 的验签所需数据。
priv struct CmsSignerInfo {
  /// 摘要算法名（"SHA-256" / "SHA-512" / "" 表示不支持）。
  digest_alg : String
  /// 签名算法名（"RSA" / "ECDSA" / "unsupported"）。
  sig_alg : String
  /// `authenticatedAttributes` 原始 DER（含 0xA0 tag）；None 表示无签名属性。
  signed_attrs : Bytes?
  /// 签名值（encryptedDigest）。
  signature : Bytes
  /// signedAttrs 中 `messageDigest` 属性值；无 signedAttrs 时为 None。
  message_digest : Bytes?
}

///|
/// v1 signerInfo 验签结论（crypto 是否通过 + 算法名 + 诊断）。
fn verify_v1_signer_info(
  certs : Array[Bytes],
  sf_bytes : Bytes,
  pkcs7_der : Bytes,
) -> (Bool, String, String) {
  if certs.length() == 0 {
    return (false, "unsupported", "v1 signerInfo: no certificate available")
  }
  let spki = match x509_spki(certs[0]) {
    Some(s) => s
    None =>
      return (
        false, "unsupported", "v1 signerInfo: certificate SPKI unreadable",
      )
  }
  let rsa_key = rsa_public_key_from_spki(spki)
  let ec_key = match rsa_key {
    Some(_) => None
    None => ec_public_key_from_spki(spki)
  }
  match (rsa_key, ec_key) {
    (None, None) =>
      return (
        false, "unsupported", "v1 signerInfo: certificate key is not a parseable RSA or EC SPKI",
      )
    _ => ()
  }
  if rsa_key is Some(key) {
    if rsa_key_too_large(key) {
      return (false, "unsupported", "v1 signerInfo: key too large")
    }
  }
  let signers = match cms_signer_infos(pkcs7_der) {
    Some(s) => s
    None =>
      return (false, "unsupported", "v1 signerInfo: CMS SignedData unreadable")
  }
  let mut algo = "unsupported"
  let mut detail = "v1 signerInfo: no verifiable RSA or ECDSA signature"
  for si in signers {
    if si.digest_alg == "" {
      detail = "v1 signerInfo: unsupported algorithm"
      continue
    }
    if si.sig_alg == "RSA" {
      let key = match rsa_key {
        Some(k) => k
        None => {
          detail = "v1 signerInfo: certificate key is not RSA"
          continue
        }
      }
      algo = if si.digest_alg == "SHA-256" {
        "SHA256withRSA"
      } else {
        "SHA512withRSA"
      }
      match si.signed_attrs {
        Some(attrs) => {
          // 1) messageDigest 属性必须等于 .SF 摘要。
          let md_ok = match si.message_digest {
            Some(md) => cms_digest_eq(si.digest_alg, sf_bytes, md)
            None => false
          }
          if !md_ok {
            detail = "v1 signerInfo: messageDigest attribute mismatch or missing"
            continue
          }
          // 2) 签名覆盖重新编码为 SET OF（0x31）的属性字节。
          let signed_bytes = cms_attrs_as_set(attrs)
          let digest = cms_hash(si.digest_alg, signed_bytes)
          if rsa_verify_pkcs1(key, si.signature, digest, si.digest_alg) {
            return (
              true, algo, "v1 signerInfo: RSA signature verified over signed attributes",
            )
          }
          detail = "v1 signerInfo: signature over signed attributes failed verification"
        }
        None => {
          let digest = cms_hash(si.digest_alg, sf_bytes)
          if rsa_verify_pkcs1(key, si.signature, digest, si.digest_alg) {
            return (
              true, algo, "v1 signerInfo: RSA signature verified over .SF content",
            )
          }
          detail = "v1 signerInfo: signature over content failed verification"
        }
      }
    } else if si.sig_alg == "ECDSA" {
      let (curve, qx, qy) = match ec_key {
        Some(v) => v
        None => {
          detail = "v1 signerInfo: certificate key is not EC"
          continue
        }
      }
      let params = match ec_params(curve) {
        Some(p) => p
        None => {
          detail = "v1 signerInfo: unsupported EC curve"
          continue
        }
      }
      algo = if si.digest_alg == "SHA-256" {
        "SHA256withECDSA"
      } else {
        "SHA512withECDSA"
      }
      match si.signed_attrs {
        Some(attrs) => {
          // 1) messageDigest 属性必须等于 .SF 摘要（与 RSA 路径一致）。
          let md_ok = match si.message_digest {
            Some(md) => cms_digest_eq(si.digest_alg, sf_bytes, md)
            None => false
          }
          if !md_ok {
            detail = "v1 signerInfo: messageDigest attribute mismatch or missing"
            continue
          }
          // 2) 签名覆盖重新编码为 SET OF（0x31）的属性字节。
          let signed_bytes = cms_attrs_as_set(attrs)
          let digest = cms_hash(si.digest_alg, signed_bytes)
          let (ok, why) = cms_ecdsa_verify(
            params,
            qx,
            qy,
            si.signature,
            ec_hash_to_e(digest, params.n),
            si.digest_alg,
          )
          if ok {
            return (
              true, algo, "v1 signerInfo: ECDSA signature verified over signed attributes",
            )
          }
          detail = why
        }
        None => {
          let digest = cms_hash(si.digest_alg, sf_bytes)
          let (ok, why) = cms_ecdsa_verify(
            params,
            qx,
            qy,
            si.signature,
            ec_hash_to_e(digest, params.n),
            si.digest_alg,
          )
          if ok {
            return (
              true, algo, "v1 signerInfo: ECDSA signature verified over .SF content",
            )
          }
          detail = why
        }
      }
    } else {
      detail = "v1 signerInfo: unsupported algorithm"
    }
  }
  (false, algo, detail)
}

///|
/// v1 CMS ECDSA 签名值验签：DER 解码 `SEQUENCE{INTEGER r, INTEGER s}` 后调
/// `ec_ecdsa_verify`（r/s 越界、曲线不匹配、公钥非法均由其内部 fail-closed）。
fn cms_ecdsa_verify(
  params : EcParams,
  qx : BigInt,
  qy : BigInt,
  sig_der : Bytes,
  e : BigInt,
  hash_name : String,
) -> (Bool, String) {
  match ec_sig_from_der(sig_der) {
    None => (false, "v1 signerInfo: ECDSA signature value is not valid DER")
    Some((r, s)) =>
      if ec_ecdsa_verify(params, qx, qy, e, r, s) {
        (true, "")
      } else {
        (
          false,
          "v1 signerInfo: ECDSA " + hash_name + " signature failed verification",
        )
      }
  }
}

///|
/// 按算法名计算摘要；不支持返回空 Bytes。
fn cms_hash(alg : String, data : Bytes) -> Bytes {
  if alg == "SHA-256" {
    sha256(data)
  } else if alg == "SHA-512" {
    sha512(data)
  } else {
    b""
  }
}

///|
/// 比较摘要与期望值。
fn cms_digest_eq(alg : String, data : Bytes, expected : Bytes) -> Bool {
  let actual = cms_hash(alg, data)
  if actual.length() == 0 {
    return false
  }
  if actual.length() != expected.length() {
    return false
  }
  for i = 0; i < actual.length(); i = i + 1 {
    if actual[i] != expected[i] {
      return false
    }
  }
  true
}

///|
/// 把 `authenticatedAttributes`（[0] IMPLICIT，tag 0xA0）重新编码为 SET OF（tag 0x31），
/// 即 jarsigner 签名时使用的 DER 字节；长度编码原样保留。
fn cms_attrs_as_set(attrs : Bytes) -> Bytes {
  let out : Array[Byte] = []
  if attrs.length() == 0 {
    return b""
  }
  out.push(b'\x31')
  for i = 1; i < attrs.length(); i = i + 1 {
    out.push(attrs[i])
  }
  Bytes::from_array(out[:])
}

///|
/// 解析 CMS SignedData 的 signerInfos；结构异常返回 None。
fn cms_signer_infos(der : Bytes) -> Array[CmsSignerInfo]? {
  let len = der.length()
  let ci = match der_read(der, 0, len) {
    Some(t) => t
    None => return None
  }
  if ci.tag != 0x30 {
    return None
  }
  // ContentInfo.contentType 必须为 signedData (1.2.840.113549.1.7.2)
  let oid = match der_read(der, ci.body, ci.end) {
    Some(t) => t
    None => return None
  }
  if oid.tag != 0x06 || !der_oid_is(der, oid.body, oid.end, oid_signed_data) {
    return None
  }
  let ctx = match der_read(der, oid.end, ci.end) {
    Some(t) => t
    None => return None
  }
  if ctx.tag != 0xA0 {
    return None
  }
  let sd = match der_read(der, ctx.body, ctx.end) {
    Some(t) => t
    None => return None
  }
  if sd.tag != 0x30 {
    return None
  }
  // SignedData: version INTEGER, digestAlgorithms SET, contentInfo SEQ,
  //             [0] certs?, [1] crls?, signerInfos SET
  let mut p = sd.body
  // version
  let version = match der_read(der, p, sd.end) {
    Some(t) => t
    None => return None
  }
  if version.tag != 0x02 {
    return None
  }
  p = version.end
  // digestAlgorithms
  let dig_algs = match der_read(der, p, sd.end) {
    Some(t) => t
    None => return None
  }
  if dig_algs.tag != 0x31 {
    return None
  }
  p = dig_algs.end
  // encapContentInfo
  let encap = match der_read(der, p, sd.end) {
    Some(t) => t
    None => return None
  }
  if encap.tag != 0x30 {
    return None
  }
  p = encap.end
  // 可选 [0] certs / [1] crls
  while p < sd.end {
    let c = match der_read(der, p, sd.end) {
      Some(t) => t
      None => return None
    }
    if c.tag == 0xA0 || c.tag == 0xA1 {
      p = c.end
      continue
    }
    break
  }
  // signerInfos SET OF SignerInfo
  let infos = match der_read(der, p, sd.end) {
    Some(t) => t
    None => return None
  }
  if infos.tag != 0x31 {
    return None
  }
  let out : Array[CmsSignerInfo] = []
  let mut q = infos.body
  while q < infos.end {
    let si = match der_read(der, q, infos.end) {
      Some(t) => t
      None => return None
    }
    if si.tag != 0x30 {
      return None
    }
    match cms_parse_signer_info(der, si) {
      Some(v) => out.push(v)
      None => return None
    }
    q = si.end
  }
  Some(out)
}

///|
/// 解析单个 SignerInfo SEQUENCE。
fn cms_parse_signer_info(der : Bytes, si : DerTlv) -> CmsSignerInfo? {
  let mut p = si.body
  // version INTEGER
  let version = match der_read(der, p, si.end) {
    Some(t) => t
    None => return None
  }
  if version.tag != 0x02 {
    return None
  }
  p = version.end
  // issuerAndSerialNumber SEQUENCE
  let ias = match der_read(der, p, si.end) {
    Some(t) => t
    None => return None
  }
  if ias.tag != 0x30 {
    return None
  }
  p = ias.end
  // digestAlgorithm AlgorithmIdentifier
  let dig = match der_read(der, p, si.end) {
    Some(t) => t
    None => return None
  }
  if dig.tag != 0x30 {
    return None
  }
  let digest_alg = cms_digest_alg_name(der, dig)
  p = dig.end
  // authenticatedAttributes [0] IMPLICIT OPTIONAL
  let mut signed_attrs : Bytes? = None
  let mut message_digest : Bytes? = None
  let maybe_attrs = match der_read(der, p, si.end) {
    Some(t) => t
    None => return None
  }
  if maybe_attrs.tag == 0xA0 {
    let raw = der[maybe_attrs.start:maybe_attrs.end].to_owned()
    signed_attrs = Some(raw)
    message_digest = cms_find_message_digest(der, maybe_attrs)
    p = maybe_attrs.end
  }
  // digestEncryptionAlgorithm AlgorithmIdentifier
  let sigalg = match der_read(der, p, si.end) {
    Some(t) => t
    None => return None
  }
  if sigalg.tag != 0x30 {
    return None
  }
  let sig_alg = cms_sig_alg_name(der, sigalg)
  p = sigalg.end
  // encryptedDigest OCTET STRING
  let sig = match der_read(der, p, si.end) {
    Some(t) => t
    None => return None
  }
  if sig.tag != 0x04 {
    return None
  }
  let signature = der[sig.body:sig.end].to_owned()
  Some({ digest_alg, sig_alg, signed_attrs, signature, message_digest, })
}

///|
/// 在 attributes SET 中查找 `messageDigest`（1.2.840.113549.1.9.4）属性值。
fn cms_find_message_digest(der : Bytes, attrs : DerTlv) -> Bytes? {
  let mut p = attrs.body
  while p < attrs.end {
    let attr = match der_read(der, p, attrs.end) {
      Some(t) => t
      None => return None
    }
    if attr.tag != 0x30 {
      return None
    }
    let oid = match der_read(der, attr.body, attr.end) {
      Some(t) => t
      None => return None
    }
    if oid.tag == 0x06 && der_oid_is(der, oid.body, oid.end, oid_message_digest) {
      let values = match der_read(der, oid.end, attr.end) {
        Some(t) => t
        None => return None
      }
      if values.tag != 0x31 {
        return None
      }
      let octet = match der_read(der, values.body, values.end) {
        Some(t) => t
        None => return None
      }
      if octet.tag != 0x04 {
        return None
      }
      return Some(der[octet.body:octet.end].to_owned())
    }
    p = attr.end
  }
  None
}

///|
/// AlgorithmIdentifier → 摘要算法名（仅 SHA-256 / SHA-512，其余为空串）。
fn cms_digest_alg_name(der : Bytes, alg : DerTlv) -> String {
  let oid = match der_read(der, alg.body, alg.end) {
    Some(t) => t
    None => return ""
  }
  if oid.tag != 0x06 {
    return ""
  }
  if der_oid_is(der, oid.body, oid.end, oid_sha256) {
    "SHA-256"
  } else if der_oid_is(der, oid.body, oid.end, oid_sha512) {
    "SHA-512"
  } else {
    ""
  }
}

///|
/// AlgorithmIdentifier → 签名算法名（RSA / ECDSA 系列，其余 "unsupported"）。
fn cms_sig_alg_name(der : Bytes, alg : DerTlv) -> String {
  let oid = match der_read(der, alg.body, alg.end) {
    Some(t) => t
    None => return "unsupported"
  }
  if oid.tag != 0x06 {
    return "unsupported"
  }
  if der_oid_is(der, oid.body, oid.end, oid_sha256_with_rsa) ||
    der_oid_is(der, oid.body, oid.end, oid_sha512_with_rsa) ||
    der_oid_is(der, oid.body, oid.end, oid_rsa_encryption) {
    "RSA"
  } else if der_oid_is(der, oid.body, oid.end, oid_ecdsa_with_sha256) ||
    der_oid_is(der, oid.body, oid.end, oid_ecdsa_with_sha512) ||
    der_oid_is(der, oid.body, oid.end, oid_ecdsa_with_sha1) ||
    der_oid_is(der, oid.body, oid.end, oid_ecdsa_secp521r1) {
    // 具体摘要以 signerInfo 的 digestAlgorithm 为准（ECDSA 无 PSS 变体）。
    "ECDSA"
  } else {
    "unsupported"
  }
}

///|
/// 从 X.509 证书 DER 提取 SubjectPublicKeyInfo（SPKI）。
///
/// Certificate = SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }；
/// tbsCertificate 的子项顺序（version 可选）：serial, sigAlg, issuer, validity,
/// subject, SPKI, ...，故 SPKI 为第 base+5 个子项。
fn x509_spki(cert : Bytes) -> Bytes? {
  let len = cert.length()
  let c = match der_read(cert, 0, len) {
    Some(t) => t
    None => return None
  }
  if c.tag != 0x30 {
    return None
  }
  let tbs = match der_read(cert, c.body, c.end) {
    Some(t) => t
    None => return None
  }
  if tbs.tag != 0x30 {
    return None
  }
  let kids : Array[DerTlv] = []
  let mut p = tbs.body
  while p < tbs.end {
    let k = match der_read(cert, p, tbs.end) {
      Some(t) => t
      None => return None
    }
    kids.push(k)
    p = k.end
  }
  let base = if kids.length() > 0 && kids[0].tag == 0xA0 { 1 } else { 0 }
  let idx = base + 5
  if idx >= kids.length() {
    return None
  }
  let spki = kids[idx]
  if spki.tag != 0x30 {
    return None
  }
  Some(cert[spki.start:spki.end].to_owned())
}

///|
/// OID 内容字节比较。
fn der_oid_is(b : Bytes, start : Int32, end : Int32, expected : Bytes) -> Bool {
  if end - start != expected.length() {
    return false
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if b[start + i] != expected[i] {
      return false
    }
  }
  true
}

///|
/// OID 1.2.840.113549.1.7.2（signedData）。
let oid_signed_data : Bytes = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"

///|
/// OID 1.2.840.113549.1.9.4（messageDigest）。
let oid_message_digest : Bytes = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"

///|
/// OID 1.2.840.113549.1.1.1（rsaEncryption）。
let oid_rsa_encryption : Bytes = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"

///|
/// OID 1.2.840.113549.1.1.11（sha256WithRSAEncryption）。
let oid_sha256_with_rsa : Bytes = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"

///|
/// OID 1.2.840.113549.1.1.13（sha512WithRSAEncryption）。
let oid_sha512_with_rsa : Bytes = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d"

///|
/// OID 2.16.840.1.101.3.4.2.1（sha256）。
let oid_sha256 : Bytes = b"\x60\x86\x48\x01\x65\x03\x04\x02\x01"

///|
/// OID 2.16.840.1.101.3.4.2.3（sha512）。
let oid_sha512 : Bytes = b"\x60\x86\x48\x01\x65\x03\x04\x02\x03"

///|
/// OID 1.2.840.10045.4.3.2（ecdsa-with-SHA256）。
let oid_ecdsa_with_sha256 : Bytes = b"\x2a\x86\x48\xce\x3d\x04\x03\x02"

///|
/// OID 1.2.840.10045.4.3.3（ecdsa-with-SHA512）。
let oid_ecdsa_with_sha512 : Bytes = b"\x2a\x86\x48\xce\x3d\x04\x03\x03"

///|
/// OID 1.2.840.10045.4.1（ecdsa-with-SHA1；部分工具使用的通配签名算法 OID）。
let oid_ecdsa_with_sha1 : Bytes = b"\x2a\x86\x48\xce\x3d\x04\x01"

///|
/// OID 1.3.132.0.35（secp521r1；部分工具用作 ECDSA 签名算法别名）。
let oid_ecdsa_secp521r1 : Bytes = b"\x2b\x81\x04\x00\x23"
