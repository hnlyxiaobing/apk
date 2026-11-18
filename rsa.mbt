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
/// 边界：模数 bit 长硬上限 8192（见 `rsa_max_modulus_bits`）；超限一律 fail-closed，
/// 不进入模幂，避免攻击者可控的超大模数放大计算量（对齐 W2 内存有界口径）。

///|
/// RSA 公钥：模数 n（大数）+ 指数 e（大数）。仅验签用途。
priv struct RsaPublicKey {
  n : BigInt
  e : BigInt
}

///|
/// 模数 bit 长硬上限（对齐 W2 内存有界口径）：2048/4096/8192 位均可用，超过 8192
/// 位则 fail-closed，不执行模幂。
let rsa_max_modulus_bits : Int32 = 8192

///|
/// 模数是否超过硬上限；超限时验签直接判失败（值化返回，不抛错）。
fn rsa_key_too_large(key : RsaPublicKey) -> Bool {
  big_bit_length(key.n) > rsa_max_modulus_bits
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
  if rsa_key_too_large(key) {
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

///|
/// RSA 验签（PSS，RFC 8017 §9.1.2 / EMSA-PSS-VERIFY），salt 长度 = 摘要长度。
///
/// 用于 Android APK Signature Scheme 的 0x0101（PSS+SHA-256）/ 0x0102（PSS+SHA-512）
/// 签名算法 ID。`msg_digest` 为待验数据的摘要（`H(M)`），而非消息本身。
fn rsa_verify_pss(
  key : RsaPublicKey,
  signature : Bytes,
  msg_digest : Bytes,
  hash_name : String,
) -> Bool {
  if big_is_zero(key.n) || big_is_zero(key.e) {
    return false
  }
  if rsa_key_too_large(key) {
    return false
  }
  let h_len = msg_digest.length()
  if h_len == 0 {
    return false
  }
  let salt_len = h_len
  let modulus_bytes = big_to_be_bytes(key.n)
  let nbytes = modulus_bytes.length()
  if signature.length() != nbytes {
    return false
  }
  let sig_int = big_from_be_bytes(signature)
  if big_cmp(sig_int, key.n) >= 0 {
    return false
  }
  let m = big_mod_pow(sig_int, key.e, key.n)
  let m_bytes = big_to_be_bytes(m)
  // emBits = modBits - 1；emLen = ceil(emBits / 8)
  let mod_bits = big_bit_length(key.n)
  let em_bits = mod_bits - 1
  if em_bits <= 0 {
    return false
  }
  let em_len = (em_bits + 7) / 8
  if m_bytes.length() > em_len {
    return false
  }
  // EM = m 右对齐补齐为 emLen 字节（大端）。
  let em : Array[Byte] = Array::make(em_len, b'\x00')
  let dst = em_len - m_bytes.length()
  for i = 0; i < m_bytes.length(); i = i + 1 {
    em[dst + i] = m_bytes[i]
  }
  if em_len < h_len + salt_len + 2 {
    return false
  }
  if em[em_len - 1] != b'\xbc' {
    return false
  }
  let db_len = em_len - h_len - 1
  // maskedDB 最高位必须为 0（8*emLen - emBits 位）。
  let unused_bits = 8 * em_len - em_bits
  if unused_bits > 0 {
    let mask = (1 << (8 - unused_bits)) - 1
    if (em[0].to_int() & (0xFF - mask)) != 0 {
      return false
    }
  }
  // H = EM 中 maskedDB 之后的 hLen 字节（EM = maskedDB || H || 0xbc）
  let h : Array[Byte] = []
  for i = db_len; i < em_len - 1; i = i + 1 {
    h.push(em[i])
  }
  let h_bytes = Bytes::from_array(h[:])
  // dbMask = MGF1(H, dbLen)
  let db_mask = mgf1(h_bytes, db_len, hash_name)
  if db_mask.length() != db_len {
    return false
  }
  // DB = maskedDB XOR dbMask
  let db : Array[Byte] = []
  for i = 0; i < db_len; i = i + 1 {
    db.push((em[i].to_int() ^ db_mask[i].to_int()).to_byte())
  }
  if unused_bits > 0 {
    let mask = (1 << (8 - unused_bits)) - 1
    db[0] = (db[0].to_int() & mask).to_byte()
  }
  // DB = PS(全 0) || 0x01 || salt
  let ps_len = db_len - salt_len - 1
  if ps_len < 0 {
    return false
  }
  for i = 0; i < ps_len; i = i + 1 {
    if db[i] != b'\x00' {
      return false
    }
  }
  if db[ps_len] != b'\x01' {
    return false
  }
  // salt = DB 尾部 saltLen 字节
  let salt : Array[Byte] = []
  for i = ps_len + 1; i < db_len; i = i + 1 {
    salt.push(db[i])
  }
  // H' = Hash(0x00 * 8 || mHash || salt)
  let mp : Array[Byte] = []
  for i = 0; i < 8; i = i + 1 {
    mp.push(b'\x00')
  }
  for b in msg_digest {
    mp.push(b)
  }
  for b in salt {
    mp.push(b)
  }
  let hp = if hash_name == "SHA-256" {
    sha256(Bytes::from_array(mp[:]))
  } else if hash_name == "SHA-512" {
    sha512(Bytes::from_array(mp[:]))
  } else {
    return false
  }
  if hp.length() != h_len {
    return false
  }
  for i = 0; i < h_len; i = i + 1 {
    if hp[i] != h_bytes[i] {
      return false
    }
  }
  true
}

///|
/// MGF1 掩码生成（RFC 8017 附录 B.2.1）：T = Hash(seed || I2OSP(counter, 4)) 拼接至 mask_len。
fn mgf1(seed : Bytes, mask_len : Int32, hash_name : String) -> Bytes {
  let out : Array[Byte] = []
  let mut counter = 0U
  while out.length() < mask_len {
    let block : Array[Byte] = []
    for b in seed {
      block.push(b)
    }
    block.push(((counter >> 24) & 0xFF).to_byte())
    block.push(((counter >> 16) & 0xFF).to_byte())
    block.push(((counter >> 8) & 0xFF).to_byte())
    block.push((counter & 0xFF).to_byte())
    let d = if hash_name == "SHA-256" {
      sha256(Bytes::from_array(block[:]))
    } else if hash_name == "SHA-512" {
      sha512(Bytes::from_array(block[:]))
    } else {
      b""
    }
    if d.length() == 0 {
      return b""
    }
    for b in d {
      if out.length() >= mask_len {
        break
      }
      out.push(b)
    }
    counter = counter + 1
  }
  Bytes::from_array(out[:])
}
