///|
/// 最小 X.509 证书结构解析（W3）。
///
/// 目标：把 `SignatureInfo.certificates` 的 DER 字节变成可合规初筛的结构事实。
/// **边界**：只解结构，不验签、不验证书链、不判信任；未知扩展一律跳过不报错。
///
/// 错误模型：畸形 DER / 关键结构缺失一律 `ApkError::BadSigningBlock(off, reason)`
/// （复用既有变体，不新增错误变体）；`off` 为证书 DER 内偏移；不 panic、不越界。
///
/// 时间归一化：UTCTime 两位年按 X.509 规则（>=50 -> 19xx，<50 -> 20xx）输出
/// `"YYYY-MM-DDTHH:MM:SSZ"`；GeneralizedTime 直接按 4 位年解析。

///|
/// 单个 X.509 证书的结构事实（不含信任结论）。
pub(all) struct CertificateInfo {
  /// X.509 version 原始编码值：v1=0 / v2=1 / v3=2。
  version : Int32
  /// 序列号十六进制（小写，无前缀）。
  serial_hex : String
  /// RFC 4514 风格颁发者 DN（顺序与 DER 一致，如 `CN=Test CA,O=Example,C=US`）。
  issuer : String
  /// RFC 4514 风格主体 DN。
  subject : String
  /// 有效期起始（`"YYYY-MM-DDTHH:MM:SSZ"`）。
  not_before : String
  /// 有效期结束（同格式）。
  not_after : String
  /// 证书内签名算法 OID（点分十进制，如 `1.2.840.113549.1.1.11`）。
  signature_algo_oid : String
  /// 主体公钥算法 OID（如 `1.2.840.113549.1.1.1` = RSA）。
  public_key_algo_oid : String
  /// RSA 模长（位）/ EC 曲线估算位长；无法判定为 -1。
  public_key_bits : Int32
  /// 整份证书 DER 的 SHA-256 指纹（小写 hex）。
  sha256_fingerprint_hex : String
}

///|
/// 解析单个 X.509 证书 DER 字节；结构非法 raise `BadSigningBlock`。
pub fn parse_certificate(der : Bytes) -> CertificateInfo raise ApkError {
  let len = der.length()
  let outer = cert_tlv(der, 0, len, "certificate outer SEQUENCE")
  guard outer.tag == 0x30 else {
    raise ApkError::BadSigningBlock(0, "certificate outer tag is not SEQUENCE")
  }
  let tbs = cert_tlv(der, outer.body, outer.end, "tbsCertificate SEQUENCE")
  guard tbs.tag == 0x30 else {
    raise ApkError::BadSigningBlock(
      tbs.start,
      "tbsCertificate tag is not SEQUENCE",
    )
  }
  // TBS 子字段顺序：[0] version OPTIONAL / serialNumber / signature / issuer /
  // validity / subject / subjectPublicKeyInfo。
  let mut p = tbs.body
  let version_t = cert_tlv(der, p, tbs.end, "version")
  let mut version = 0
  if version_t.tag == 0xA0 {
    let v_int = cert_tlv(der, version_t.body, version_t.end, "version INTEGER")
    version = cert_int_value(der, v_int)
    p = version_t.end
  }
  let serial_t = cert_tlv(der, p, tbs.end, "serialNumber INTEGER")
  guard serial_t.tag == 0x02 else {
    raise ApkError::BadSigningBlock(
      serial_t.start,
      "serialNumber is not INTEGER",
    )
  }
  let serial_hex = cert_hex(der[serial_t.body:serial_t.end].to_owned())
  p = serial_t.end
  let sig_algo_t = cert_tlv(der, p, tbs.end, "signature AlgorithmIdentifier")
  guard sig_algo_t.tag == 0x30 else {
    raise ApkError::BadSigningBlock(
      sig_algo_t.start,
      "signature algo not SEQUENCE",
    )
  }
  let signature_algo_oid = cert_first_oid(der, sig_algo_t)
  p = sig_algo_t.end
  let issuer_t = cert_tlv(der, p, tbs.end, "issuer Name")
  guard issuer_t.tag == 0x30 else {
    raise ApkError::BadSigningBlock(issuer_t.start, "issuer not SEQUENCE")
  }
  let issuer = cert_dn(der, issuer_t)
  p = issuer_t.end
  let validity_t = cert_tlv(der, p, tbs.end, "validity SEQUENCE")
  guard validity_t.tag == 0x30 else {
    raise ApkError::BadSigningBlock(validity_t.start, "validity not SEQUENCE")
  }
  let not_before_t = cert_tlv(der, validity_t.body, validity_t.end, "notBefore")
  let not_after_t = cert_tlv(der, not_before_t.end, validity_t.end, "notAfter")
  let not_before = cert_time(der, not_before_t)
  let not_after = cert_time(der, not_after_t)
  p = validity_t.end
  let subject_t = cert_tlv(der, p, tbs.end, "subject Name")
  guard subject_t.tag == 0x30 else {
    raise ApkError::BadSigningBlock(subject_t.start, "subject not SEQUENCE")
  }
  let subject = cert_dn(der, subject_t)
  p = subject_t.end
  let spki_t = cert_tlv(der, p, tbs.end, "subjectPublicKeyInfo SEQUENCE")
  guard spki_t.tag == 0x30 else {
    raise ApkError::BadSigningBlock(spki_t.start, "SPKI not SEQUENCE")
  }
  let algo_t = cert_tlv(der, spki_t.body, spki_t.end, "SPKI algorithm")
  guard algo_t.tag == 0x30 else {
    raise ApkError::BadSigningBlock(algo_t.start, "SPKI algo not SEQUENCE")
  }
  let public_key_algo_oid = cert_first_oid(der, algo_t)
  let public_key_bits = cert_public_key_bits(
    der, spki_t, algo_t, public_key_algo_oid,
  )
  {
    version,
    serial_hex,
    issuer,
    subject,
    not_before,
    not_after,
    signature_algo_oid,
    public_key_algo_oid,
    public_key_bits,
    sha256_fingerprint_hex: cert_sha256_hex(der),
  }
}

///|
/// 聚合 APK 中全部证书 DER（v1 PKCS#7 + v2/v3/v3.1 signer）并按 DER 字节去重。
pub fn Apk::certificate_infos(
  self : Apk,
) -> Array[CertificateInfo] raise ApkError {
  let seen : Array[Bytes] = []
  let out : Array[CertificateInfo] = []
  for s in self.signatures() {
    for cert in s.certificates {
      let mut dup = false
      for x in seen {
        if x == cert {
          dup = true
        }
      }
      if !dup {
        seen.push(cert)
        out.push(parse_certificate(cert))
      }
    }
  }
  out
}

///|
/// 从 SPKI 估算公钥位长。RSA：解析 RSAPublicKey.modulus 字节数 x 8；
/// EC：按曲线 OID 映射位长（P-256/P-384/P-521）；其余返回 -1。
fn cert_public_key_bits(
  der : Bytes,
  spki : CertTlv,
  algo : CertTlv,
  oid : String,
) -> Int32 {
  // subjectPublicKey BIT STRING 是 AlgorithmIdentifier 之后的下一个 TLV。
  let bitstr = match cert_tlv_opt(der, algo.end, spki.end) {
    Some(t) => t
    None => return -1
  }
  if bitstr.tag != 0x03 {
    return -1
  }
  // BIT STRING body 首字节为 unused-bits；其后是位串内容。
  if bitstr.body >= bitstr.end {
    return -1
  }
  let content = der[bitstr.body + 1:bitstr.end].to_owned()
  if oid == "1.2.840.113549.1.1.1" {
    // RSA RSAPublicKey：SEQUENCE { modulus INTEGER, publicExponent INTEGER }。
    let seq = match cert_tlv_opt(content, 0, content.length()) {
      Some(t) => t
      None => return -1
    }
    if seq.tag != 0x30 {
      return -1
    }
    let mod_int = match cert_tlv_opt(content, seq.body, seq.end) {
      Some(t) => t
      None => return -1
    }
    if mod_int.tag != 0x02 {
      return -1
    }
    let n = mod_int.end - mod_int.body
    // 整数位长：若首字节为 0x00 则是 DER 符号位填充，减 8；否则即 n*8。
    let mut bits = n * 8
    if n > 0 && content[mod_int.body].to_int() == 0 {
      bits = bits - 8
    }
    if bits < 0 {
      bits = 0
    }
    return bits
  }
  // EC 曲线 OID -> 位长。
  match oid {
    "1.2.840.10045.3.1.7" => 256
    "1.3.132.840.10045.3.1" => 384
    "1.3.132.840.10045.3.2" => 521
    _ => -1
  }
}

///|
/// DER TLV 结果（start/body/end 均为字节内偏移）。
priv struct CertTlv {
  tag : Int32
  start : Int32
  body : Int32
  end : Int32
}

///|
/// 读取一个 DER TLV；失败 raise `BadSigningBlock`（带上下文 reason）。
fn cert_tlv(
  der : Bytes,
  off : Int32,
  limit : Int32,
  reason : String,
) -> CertTlv raise ApkError {
  match cert_tlv_opt(der, off, limit) {
    Some(t) => t
    None =>
      raise ApkError::BadSigningBlock(
        cert_clamp(der, off),
        "DER TLV truncated: " + reason,
      )
  }
}

///|
/// 读取一个 DER TLV；越界/坏长度返回 None。短/长格式长度均支持（长度字节数上限 4）。
fn cert_tlv_opt(der : Bytes, off : Int32, limit : Int32) -> CertTlv? {
  if off < 0 || off + 2 > limit {
    return None
  }
  let tag = der[off].to_int()
  let l0 = der[off + 1].to_int()
  if l0 < 0x80 {
    let body = off + 2
    let end = body + l0
    if end > limit {
      return None
    }
    return Some({ tag, start: off, body, end, })
  }
  let n = l0 & 0x7F
  if n == 0 || n > 4 || off + 2 + n > limit {
    return None
  }
  let mut len = 0
  for i = 0; i < n; i = i + 1 {
    len = (len << 8) | der[off + 2 + i].to_int()
  }
  let body = off + 2 + n
  let end = body + len
  if end > limit || end < body {
    return None
  }
  Some({ tag, start: off, body, end, })
}

///|
/// 把偏移夹到 `[0, der.length()]`。
fn cert_clamp(der : Bytes, off : Int32) -> Int32 {
  if off < 0 {
    0
  } else if off > der.length() {
    der.length()
  } else {
    off
  }
}

///|
/// 读取整数 TLV 的值（大端；超 4 字节时只取低 4 字节）。
fn cert_int_value(der : Bytes, t : CertTlv) -> Int32 {
  let mut v = 0
  let n = t.end - t.body
  let start = if n > 4 { t.end - 4 } else { t.body }
  for i = start; i < t.end; i = i + 1 {
    v = (v << 8) | der[i].to_int()
  }
  v
}

///|
/// 取 SEQUENCE 内第一个 OID TLV 的点分十进制字符串。
fn cert_first_oid(der : Bytes, seq : CertTlv) -> String {
  let oid = match cert_tlv_opt(der, seq.body, seq.end) {
    Some(t) => t
    None => return ""
  }
  if oid.tag != 0x06 {
    return ""
  }
  cert_oid_dotted(der[oid.body:oid.end].to_owned())
}

///|
/// 把 OID 内容字节解码为点分十进制。
fn cert_oid_dotted(b : Bytes) -> String {
  if b.length() == 0 {
    return ""
  }
  let parts : Array[String] = []
  let first = b[0].to_int()
  parts.push((first / 40).to_string())
  parts.push((first % 40).to_string())
  let mut value = 0
  let mut started = false
  for i = 1; i < b.length(); i = i + 1 {
    let x = b[i].to_int()
    value = (value << 7) | (x & 0x7F)
    started = true
    if x < 0x80 {
      parts.push(value.to_string())
      value = 0
      started = false
    }
  }
  if started {
    parts.push(value.to_string())
  }
  let mut out = ""
  for i = 0; i < parts.length(); i = i + 1 {
    if i > 0 {
      out = out + "."
    }
    out = out + parts[i]
  }
  out
}

///|
/// 把 Name SEQUENCE 解码为 RFC 4514 风格 DN（多值按 DER 顺序拼接，逗号分隔）。
fn cert_dn(der : Bytes, name : CertTlv) -> String {
  let mut out = ""
  let mut rdn = name.body
  while rdn < name.end {
    let set = match cert_tlv_opt(der, rdn, name.end) {
      Some(t) => t
      None => break
    }
    if set.tag != 0x31 {
      break
    }
    let attr = match cert_tlv_opt(der, set.body, set.end) {
      Some(t) => t
      None => break
    }
    if attr.tag != 0x30 {
      break
    }
    let oid_t = match cert_tlv_opt(der, attr.body, attr.end) {
      Some(t) => t
      None => break
    }
    let val_t = match cert_tlv_opt(der, oid_t.end, attr.end) {
      Some(t) => t
      None => break
    }
    let key = match oid_t.tag {
      0x06 =>
        cert_oid_key(cert_oid_dotted(der[oid_t.body:oid_t.end].to_owned()))
      _ => "OID"
    }
    let val = cert_dn_value(der, val_t)
    if out != "" {
      out = out + ","
    }
    out = out + key + "=" + val
    rdn = set.end
  }
  out
}

///|
/// 常见 DN OID -> 短键；未知返回 `OID.<dotted>`。
fn cert_oid_key(dotted : String) -> String {
  match dotted {
    "2.5.4.3" => "CN"
    "2.5.4.10" => "O"
    "2.5.4.11" => "OU"
    "2.5.4.6" => "C"
    "2.5.4.8" => "ST"
    "2.5.4.7" => "L"
    _ => "OID." + dotted
  }
}

///|
/// 取 RDN AttributeValue 的可打印字符串（UTF8String/PrintableString/IA5String 等）。
fn cert_dn_value(der : Bytes, t : CertTlv) -> String {
  @encoding/utf8.decode(der[t.body:t.end].to_owned()) catch {
    _ => ""
  }
}

///|
/// 解析 UTCTime / GeneralizedTime 为归一化 `YYYY-MM-DDTHH:MM:SSZ`。
fn cert_time(der : Bytes, t : CertTlv) -> String raise ApkError {
  let raw = @encoding/utf8.decode(der[t.body:t.end].to_owned()) catch {
    _ => ""
  }
  let sv = raw.trim()
  // UTCTime: "YYMMDDHHMMSSZ"；GeneralizedTime: "YYYYMMDDHHMMSSZ"。
  let (year_off, year_len) = if t.tag == 0x18 { (0, 4) } else { (0, 2) }
  guard sv.length() >= year_len + 10 else {
    raise ApkError::BadSigningBlock(t.start, "invalid time string")
  }
  let mut year = cert_digit(sv, year_off, year_len)
  if year_len == 2 {
    year = if year >= 50 { 1900 + year } else { 2000 + year }
  }
  let month = cert_digit(sv, year_off + year_len, 2)
  let day = cert_digit(sv, year_off + year_len + 2, 2)
  let hour = cert_digit(sv, year_off + year_len + 4, 2)
  let minute = cert_digit(sv, year_off + year_len + 6, 2)
  let second = cert_digit(sv, year_off + year_len + 8, 2)
  cert_pad4(year) +
  "-" +
  cert_pad2(month) +
  "-" +
  cert_pad2(day) +
  "T" +
  cert_pad2(hour) +
  ":" +
  cert_pad2(minute) +
  ":" +
  cert_pad2(second) +
  "Z"
}

///|
/// 从字符串视图取两位数字（0..99）；非数字返回 0（fail-closed，配合上游 raise）。
fn cert_digit(sv : StringView, off : Int32, len : Int32) -> Int32 {
  let mut v = 0
  let mut i = off
  while i < off + len {
    let c = sv[i].to_int()
    if c < 48 || c > 57 {
      return 0
    }
    v = v * 10 + (c - 48)
    i = i + 1
  }
  v
}

///|
fn cert_pad2(v : Int32) -> String {
  if v < 10 {
    "0" + v.to_string()
  } else {
    v.to_string()
  }
}

///|
fn cert_pad4(v : Int32) -> String {
  if v < 10 {
    "000" + v.to_string()
  } else if v < 100 {
    "00" + v.to_string()
  } else if v < 1000 {
    "0" + v.to_string()
  } else {
    v.to_string()
  }
}

///|
/// 字节串转小写 hex。
fn cert_hex(b : Bytes) -> String {
  let mut out = ""
  for x in b {
    let hi = (x.to_int() >> 4) & 0xF
    let lo = x.to_int() & 0xF
    out = out + cert_hex_nibble(hi) + cert_hex_nibble(lo)
  }
  out
}

///|
fn cert_hex_nibble(v : Int32) -> String {
  if v < 10 {
    v.to_string()
  } else {
    match v {
      10 => "a"
      11 => "b"
      12 => "c"
      13 => "d"
      14 => "e"
      _ => "f"
    }
  }
}

///|
/// 整份证书 DER 的 SHA-256 小写 hex。
fn cert_sha256_hex(der : Bytes) -> String {
  cert_hex(sha256(der))
}
