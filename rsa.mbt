///|
/// RSA 公钥验签原语（M6-RSA-a，W6 公钥验签·仅 RSA）。
///
/// 仅实现 RSA **验签**（公钥操作），不实现签名/密钥生成/私钥。范围严格限于：
///   1. RSA 公钥验签原语：`sig^e mod n`，PKCS#1 v1.5 填充校验 + DigestInfo 比对；
///   2. 从 X.509 证书 SPKI 提取 RSA 公钥（模数 n、指数 e）。
///
/// 依赖：本包 `bigint.mbt` 的无符号大数模幂。算法仅 RSA（ECDSA 由 W6 裁决排除，
/// fail-closed）。SHA-256 / SHA-512 摘要由 `crypto.mbt` 提供。
///
/// 语义：验签成功 = 签名值在模幂后以 PKCS#1 v1.5 正确填充且 DigestInfo（含 OID 与
/// 摘要）逐字节一致。**不**做 CRT/私钥/侧信道（离线分析工具，非实时验签服务）。
/// 边界：模数长度上限即大数 limb 规模（2048/4096 位可承载，分析工具口径）。

///|
/// RSA 公钥：模数 n（大数）+ 指数 e（大数）。仅验签用途。
priv struct RsaPublicKey {
  n : BigInt
  e : BigInt
}

///|
/// 从 X.509 SPKI（SubjectPublicKeyInfo）DER 提取 RSA 公钥；非 RSA 或解析失败返回 None。
///
/// 结构：SEQUENCE { SEQUENCE{ OID, NULL } , BIT STRING{ 00, SEQUENCE{ INTEGER n, INTEGER e } } }。
fn rsa_public_key_from_spki(spki : Bytes) -> RsaPublicKey? {
  let len = spki.length()
  if len < 8 {
    return None
  }
  let outer = match der_read(spki, 0, len) {
    Some(t) => t
    None => return None
  }
  if outer.tag != 0x30 {
    return None
  }
  // AlgorithmIdentifier
  let alg = match der_read(spki, outer.body, outer.end) {
    Some(t) => t
    None => return None
  }
  if alg.tag != 0x30 {
    return None
  }
  // 定位 BIT STRING（alg 之后）
  let bit = match der_read(spki, alg.end, outer.end) {
    Some(t) => t
    None => return None
  }
  if bit.tag != 0x03 {
    return None
  }
  // BIT STRING 内容：首字节为未用位数（通常 0x00），其后为 DER 编码的 RSAPublicKey。
  if bit.body >= bit.end {
    return None
  }
  let rsa_seq = match der_read(spki, bit.body + 1, bit.end) {
    Some(t) => t
    None => return None
  }
  if rsa_seq.tag != 0x30 {
    return None
  }
  let n_tlv = match der_read(spki, rsa_seq.body, rsa_seq.end) {
    Some(t) => t
    None => return None
  }
  if n_tlv.tag != 0x02 {
    return None
  }
  let e_tlv = match der_read(spki, n_tlv.end, rsa_seq.end) {
    Some(t) => t
    None => return None
  }
  if e_tlv.tag != 0x02 {
    return None
  }
  let n = big_from_der_integer(spki, n_tlv.body, n_tlv.end)
  let e = big_from_der_integer(spki, e_tlv.body, e_tlv.end)
  if big_is_zero(n) || big_is_zero(e) {
    return None
  }
  Some({ n, e, })
}

///|
/// DER INTEGER（可能带一个前导 0x00 填充位）→ BigInt。
fn big_from_der_integer(b : Bytes, start : Int32, end : Int32) -> BigInt {
  let mut s = start
  // 正数补位：去掉单个前导 0x00（非零值时）。
  if end - s > 1 && b[s] == b'\x00' {
    s = s + 1
  }
  let arr : Array[Byte] = []
  for i = s; i < end; i = i + 1 {
    arr.push(b[i])
  }
  big_from_be_bytes(Bytes::from_array(arr[:]))
}

///|
/// PKCS#1 v1.5 验签：`signature` 为等长模数的签名字节；`digest` 为摘要；`hash_name`
/// 为 `"SHA-256"` 或 `"SHA-512"`。返回公钥验签是否通过。
fn rsa_verify_pkcs1(
  key : RsaPublicKey,
  signature : Bytes,
  digest : Bytes,
  hash_name : String,
) -> Bool {
  if big_is_zero(key.n) || big_is_zero(key.e) {
    return false
  }
  let modulus_bytes = big_to_be_bytes(key.n)
  let nbytes = modulus_bytes.length()
  // 签名必须正好等于模数长度（PKCS#1 要求）。
  if signature.length() != nbytes {
    return false
  }
  let sig_int = big_from_be_bytes(signature)
  if big_cmp(sig_int, key.n) >= 0 {
    return false
  }
  let m = big_mod_pow(sig_int, key.e, key.n)
  // EM = m 补齐为 k 字节大端。
  let m_bytes = big_to_be_bytes(m)
  let em = if m_bytes.length() < nbytes {
    let arr = Array::make(nbytes, b'\x00')
    let dst = nbytes - m_bytes.length()
    for i = 0; i < m_bytes.length(); i = i + 1 {
      arr[dst + i] = m_bytes[i]
    }
    Bytes::from_array(arr[:])
  } else {
    m_bytes
  }
  // DigestInfo 期望前缀（SHA-256 / SHA-512），含 OID 与 NULL 与长度字节。
  let prefix : Bytes = if hash_name == "SHA-256" {
    // 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
  } else if hash_name == "SHA-512" {
    // 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
    b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
  } else {
    return false
  }
  // 期望的 EM 尾部：prefix || digest，并前置固定头。
  let expected_len = 2 + prefix.length() + digest.length()
  if nbytes < expected_len + 1 {
    // 至少要有 00 01 FF* 00 与 DigestInfo
    return false
  }
  // 校验填充：EM[0]=00, EM[1]=01, 若干 0xFF, 00, 然后 prefix||digest。
  if em[0] != b'\x00' || em[1] != b'\x01' {
    return false
  }
  // 从 index 2 找 0x00 分隔符（0xFF 至少一个）。
  let mut sep = -1
  for i = 2; i < nbytes; i = i + 1 {
    if em[i] == b'\x00' {
      sep = i
      break
    }
    if em[i] != b'\xff' {
      // 分隔符前必须是全 0xFF
      return false
    }
  }
  if sep < 2 {
    return false
  }
  let body_start = sep + 1
  let body_len = nbytes - body_start
  if body_len != prefix.length() + digest.length() {
    return false
  }
  // 比对 prefix
  for i = 0; i < prefix.length(); i = i + 1 {
    if em[body_start + i] != prefix[i] {
      return false
    }
  }
  // 比对 digest
  for i = 0; i < digest.length(); i = i + 1 {
    if em[body_start + prefix.length() + i] != digest[i] {
      return false
    }
  }
  true
}
