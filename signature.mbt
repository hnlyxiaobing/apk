///|
/// APK 签名**结构 + 摘要**校验（v1 JAR / v2 / v3 / v3.1）。
///
/// 边界（硬性）：
/// - 本模块能做：解析签名块结构、解析 v1 JAR 的 `MANIFEST.MF` / `.SF` / PKCS#7 封装、
///   校验 v1 条目摘要与清单摘要、校验 v2/v3/v3.1 的 APK 内容分块摘要（SHA-256）。
/// - 本模块**不能做**：RSA / ECDSA / DSA 公钥验签（MoonBit 无密码学 stdlib，本库也未
///   实现大数公钥运算）。因此 `verified == true` 的语义是「结构合法且摘要一致」，
///   **不等于签名有效**；`SignatureCheck.signature_verified` 恒为 `false`。
///
/// 摘要对象（AOSP APK Signature Scheme v2/v3 规范）：
///   section1 = ZIP 条目区 [0, signing_block_start)
///   section2 = 中央目录区
///   section3 = EOCD（其「中央目录偏移」字段改写为 signing block 起始偏移）
///   每个 section 按 1 MiB 切片，chunk digest = SHA-256(0xa5 || chunk_len_u32le || chunk)；
///   内容摘要 = SHA-256(0x5a || chunk_count_u32le || concat(chunk_digests))。
///   该口径已用 apksigner 自产样本（fx-multidex-v2v3 / tvshell-debug）实测对齐。

///|
/// 签名者的一条摘要记录（v2/v3/v3.1 signed data 的 digests 序列项）。
priv struct SignerDigest {
  algorithm : UInt32
  digest : Bytes
}

///|
/// 签名者结构：DER 证书 + 摘要记录（v1 的摘要来自 JAR 清单，不在本结构）。
priv struct SignerData {
  certs : Array[Bytes]
  digests : Array[SignerDigest]
}

///|
/// 一个已识别的签名方案记录（内部）。
priv struct SigRecord {
  scheme : SignatureScheme
  block_id : UInt32
  certs : Array[Bytes]
  digests : Array[SignerDigest]
  pkcs7_ok : Bool
  v1_sf : String?
  v1_manifest : String?
}

///|
/// 签名校验结论（结构 + 摘要，**不含**公钥验签）。
pub(all) struct SignatureCheck {
  scheme : SignatureScheme
  /// 结构解析是否通过（v1：PKCS#7/MANIFEST/.SF 齐全且可解析；v2/v3：signer 证书与摘要记录可解析）。
  structure_ok : Bool
  /// 本地可验证的摘要是否全部一致（v1 条目摘要 + 清单摘要；v2/v3 内容分块摘要）。
  digest_ok : Bool
  /// 摘要算法名（`"SHA-256"` / `"SHA-512"` / `"unknown"`；空串表示未识别）。
  digest_algorithm : String
  /// v1：校验过的 MANIFEST 条目数；v2/v3：0。
  entries_checked : Int32
  /// v1：摘要不一致或条目缺失的条目数；v2/v3：0。
  entries_failed : Int32
  /// 公钥验签是否通过。本库未实现 RSA/ECDSA 验签，**恒为 false**。
  signature_verified : Bool
  /// 人类可读结论 / 失败原因（用于诊断，不参与判定）。
  detail : String
}

///|
/// 返回每个已识别签名方案的结构 + 摘要校验结论。
///
/// 与 `Apk::signatures()` 使用同一套结构解析；`SignatureCheck.signature_verified`
/// 恒为 false（未做公钥验签），`digest_ok` 只代表摘要一致。
pub fn Apk::signature_checks(
  self : Apk,
) -> Array[SignatureCheck] raise ApkError {
  let out : Array[SignatureCheck] = []
  for rec in self.collect_signature_records() {
    out.push(self.verify_signature_record(rec))
  }
  out
}

///|
/// 收集已识别签名方案记录（v1 优先，v2/v3/v3.1 按块内顺序），按方案排序。
fn Apk::collect_signature_records(
  self : Apk,
) -> Array[SigRecord] raise ApkError {
  let out : Array[SigRecord] = []
  // v1：META-INF/*.RSA|*.DSA|*.EC 存在即识别；证书从 PKCS#7 提取。
  let mut v1_block : String? = None
  for e in self.entries {
    if v1_block is None &&
      e.name.has_prefix("META-INF/") &&
      (
        e.name.has_suffix(".RSA") ||
        e.name.has_suffix(".DSA") ||
        e.name.has_suffix(".EC")
      ) {
      v1_block = Some(e.name)
    }
  }
  match v1_block {
    Some(block_name) => {
      let block_bytes = self.safe_entry(block_name).unwrap_or(b"")
      let certs = pkcs7_certificates(block_bytes)
      let pkcs7_ok = certs.length() > 0
      let stem = block_name[:block_name.length() - 4].to_owned()
      let sf_name = stem + ".SF"
      let manifest_name = "META-INF/MANIFEST.MF"
      out.push({
        scheme: SignatureScheme::V1,
        block_id: 0,
        certs,
        digests: [],
        pkcs7_ok,
        v1_sf: Some(sf_name),
        v1_manifest: Some(manifest_name),
      })
    }
    None => ()
  }
  match self.signing_block_off {
    None => ()
    Some(sb) => {
      let block_start = sb.to_int()
      let size = le_u64(self.source, block_start)
      let pairs_start = block_start + 8
      let pairs_end = block_start + size.to_int() - 16
      let mut pos = pairs_start
      let mut recognized = 0
      while pos < pairs_end {
        guard pos + 8 <= pairs_end else {
          raise ApkError::BadSigningBlock(
            pos, "truncated ID-value pair length in APK Signing Block",
          )
        }
        let pair_len = le_u64(self.source, pos)
        guard pair_len >= 4 && pair_len - 4 <= (pairs_end - pos - 8).to_uint64() else {
          raise ApkError::BadSigningBlock(
            pos, "ID-value pair overruns APK Signing Block",
          )
        }
        let id = le_u32(self.source, pos + 8)
        let value_off = pos + 12
        let value_len = pair_len.to_int() - 4
        if id == SIG_ID_V2 || id == SIG_ID_V3 || id == SIG_ID_V31 {
          let sch = if id == SIG_ID_V2 {
            SignatureScheme::V2
          } else if id == SIG_ID_V3 {
            SignatureScheme::V3
          } else {
            SignatureScheme::V31
          }
          let data = extract_signer_data(
            self.source,
            sch,
            value_off,
            value_len,
            pos,
          )
          out.push({
            scheme: sch,
            block_id: id,
            certs: data.certs,
            digests: data.digests,
            pkcs7_ok: true,
            v1_sf: None,
            v1_manifest: None,
          })
          recognized = recognized + 1
        }
        pos = pos + 8 + pair_len.to_int()
      }
      if recognized == 0 {
        raise ApkError::UnsupportedSignatureScheme(
          "APK Signing Block at offset " +
          block_start.to_string() +
          " contains no v2/v3/v3.1 signature scheme",
        )
      }
    }
  }
  out.sort_by(fn(a, b) { scheme_rank(a.scheme) - scheme_rank(b.scheme) })
  out
}

///|
/// 对单条记录做结构 + 摘要校验。
fn Apk::verify_signature_record(self : Apk, rec : SigRecord) -> SignatureCheck {
  match rec.scheme {
    SignatureScheme::V1 => self.verify_v1(rec)
    _ => self.verify_v2(rec)
  }
}

///|
/// 失败时的统一结论构造。
fn failed_check(
  scheme : SignatureScheme,
  algorithm : String,
  detail : String,
) -> SignatureCheck {
  {
    scheme,
    structure_ok: false,
    digest_ok: false,
    digest_algorithm: algorithm,
    entries_checked: 0,
    entries_failed: 0,
    signature_verified: false,
    detail,
  }
}

///|
/// v1 JAR 签名校验：MANIFEST.MF 条目摘要 + `.SF` 对 MANIFEST 的摘要。
fn Apk::verify_v1(self : Apk, rec : SigRecord) -> SignatureCheck {
  let manifest = match rec.v1_manifest {
    Some(n) => self.safe_entry(n)
    None => None
  }
  let sf = match rec.v1_sf {
    Some(n) => self.safe_entry(n)
    None => None
  }
  let structure_ok = rec.pkcs7_ok && manifest is Some(_) && sf is Some(_)
  if !structure_ok {
    let mut detail = "v1 structure incomplete"
    if !rec.pkcs7_ok {
      detail = "v1 PKCS#7 signature block could not be parsed"
    } else if manifest is None {
      detail = "v1 META-INF/MANIFEST.MF is missing or unreadable"
    } else if sf is None {
      detail = "v1 META-INF/*.SF is missing or unreadable"
    }
    return failed_check(SignatureScheme::V1, "", detail)
  }
  let mf_bytes = manifest.unwrap()
  let sf_bytes = sf.unwrap()
  let mf_text = @encoding/utf8.decode(mf_bytes) catch { _ => "" }
  let sf_text = @encoding/utf8.decode(sf_bytes) catch { _ => "" }
  let sections = parse_manifest_sections(mf_text)
  let mut entries_checked = 0
  let mut entries_failed = 0
  let mut unsupported = 0
  let mut algorithm = ""
  for section in sections {
    match attr_value(section, "Name") {
      None => ()
      Some(name) =>
        match entry_digest_attr(section) {
          None => ()
          Some((alg, expected_b64)) => {
            algorithm = alg
            if alg == "SHA-256" {
              match self.safe_entry(name) {
                Some(data) =>
                  if digest_matches(sha256(data), expected_b64) {
                    entries_checked = entries_checked + 1
                  } else {
                    entries_checked = entries_checked + 1
                    entries_failed = entries_failed + 1
                  }
                None => {
                  entries_checked = entries_checked + 1
                  entries_failed = entries_failed + 1
                }
              }
            } else {
              unsupported = unsupported + 1
            }
          }
        }
    }
  }
  // `.SF` 对整份 MANIFEST.MF 的摘要。
  let sf_sections = parse_manifest_sections(sf_text)
  let manifest_digest_attr = if sf_sections.length() > 0 {
    attr_value(sf_sections[0], "SHA-256-Digest-Manifest")
  } else {
    None
  }
  let mut manifest_ok = false
  match manifest_digest_attr {
    Some(expected) => manifest_ok = digest_matches(sha256(mf_bytes), expected)
    None => ()
  }
  let digest_ok = manifest_ok &&
    entries_checked > 0 &&
    entries_failed == 0 &&
    unsupported == 0
  let detail = if digest_ok {
    "v1 digests verified (" +
    entries_checked.to_string() +
    " entries + MANIFEST.MF); signature NOT verified"
  } else if !manifest_ok {
    "v1 MANIFEST.MF digest mismatch or unavailable; signature NOT verified"
  } else if entries_failed > 0 {
    "v1 entry digest mismatch x" +
    entries_failed.to_string() +
    "; signature NOT verified"
  } else if unsupported > 0 {
    "v1 digest algorithm unsupported x" +
    unsupported.to_string() +
    "; signature NOT verified"
  } else {
    "v1 MANIFEST.MF has no verifiable entry digests; signature NOT verified"
  }
  if algorithm == "" {
    algorithm = "SHA-256"
  }
  {
    scheme: SignatureScheme::V1,
    structure_ok: true,
    digest_ok,
    digest_algorithm: algorithm,
    entries_checked,
    entries_failed,
    signature_verified: false,
    detail,
  }
}

///|
/// v2/v3/v3.1 校验：比较 signed data 中的内容摘要与本地重算的 APK 内容分块摘要。
fn Apk::verify_v2(self : Apk, rec : SigRecord) -> SignatureCheck {
  let structure_ok = rec.certs.length() > 0 && rec.digests.length() > 0
  if !structure_ok {
    return failed_check(
      rec.scheme,
      "",
      "signer has no certificate or no digest record",
    )
  }
  let mut digest_ok = false
  let mut algorithm = ""
  let mut computed_some = false
  for d in rec.digests {
    let name = content_digest_algorithm_name(d.algorithm)
    if algorithm == "" {
      algorithm = name
    }
    if name != "SHA-256" && name != "SHA-512" {
      continue
    }
    match self.content_digest(name) {
      Some(c) => {
        computed_some = true
        if d.digest == c {
          digest_ok = true
        }
      }
      None => ()
    }
  }
  let detail = if digest_ok {
    "content digest (" + algorithm + ") matched; signature NOT verified"
  } else if computed_some {
    "content digest mismatch or unsupported algorithm (" +
    algorithm +
    "); signature NOT verified"
  } else {
    "APK content digest could not be computed; signature NOT verified"
  }
  {
    scheme: rec.scheme,
    structure_ok,
    digest_ok,
    digest_algorithm: algorithm,
    entries_checked: 0,
    entries_failed: 0,
    signature_verified: false,
    detail,
  }
}

///|
/// v2/v3 内容摘要算法 ID → 摘要算法名。
/// 只认 AOSP `CONTENT_DIGEST_*` ID（0x0101/0x0103/0x0104=SHA-256；0x0102/0x0105=SHA-512）；
/// 0x0201/0x0301 等是签名算法 ID，不参与内容摘要聚合。
fn content_digest_algorithm_name(id : UInt32) -> String {
  match id {
    0x0101U | 0x0103U | 0x0104U => "SHA-256"
    0x0102U | 0x0105U => "SHA-512"
    _ => "unknown"
  }
}

///|
/// 计算 v2/v3 规范的 APK 内容分块摘要。`algorithm` 为 "SHA-256" 或 "SHA-512"；
/// 只在存在 APK Signing Block 时有意义；EOCD 的中央目录偏移字段改写为块起始偏移。
fn Apk::content_digest(self : Apk, algorithm : String) -> Bytes? {
  let hash_fn = match algorithm {
    "SHA-256" => sha256
    "SHA-512" => sha512
    _ => return None
  }
  let sb = match self.signing_block_off {
    Some(v) => v.to_int()
    None => return None
  }
  let eocd = match find_eocd(self.source) {
    Some(o) => o
    None => return None
  }
  let source = self.source
  let cd_off = le_u32(source, eocd + 16).reinterpret_as_int()
  let cd_size = le_u32(source, eocd + 12).reinterpret_as_int()
  if cd_off < 0 || cd_size < 0 || cd_off + cd_size > eocd {
    return None
  }
  let comment_len = le_u16(source, eocd + 20)
  let eocd_len = 22 + comment_len
  if eocd + eocd_len > source.length() {
    return None
  }
  let chunk_digests : Array[Bytes] = []
  chunk_append(source, 0, sb, chunk_digests, hash_fn)
  chunk_append(source, cd_off, cd_off + cd_size, chunk_digests, hash_fn)
  // EOCD 副本：中央目录偏移（+16）改写为 signing block 起始偏移。
  let eocd_buf : Array[Byte] = []
  for i = 0; i < eocd_len; i = i + 1 {
    eocd_buf.push(source[eocd + i])
  }
  let sb_u = sb.reinterpret_as_uint()
  eocd_buf[16] = (sb_u & 0xFFU).reinterpret_as_int().to_byte()
  eocd_buf[17] = ((sb_u >> 8) & 0xFFU).reinterpret_as_int().to_byte()
  eocd_buf[18] = ((sb_u >> 16) & 0xFFU).reinterpret_as_int().to_byte()
  eocd_buf[19] = ((sb_u >> 24) & 0xFFU).reinterpret_as_int().to_byte()
  chunk_digests.push(chunk_digest_of(Bytes::from_array(eocd_buf[:]), hash_fn))
  // 外层：0x5a || chunk_count(u32le) || chunk digests
  let outer : Array[Byte] = []
  outer.push(b'\x5a')
  push_u32_le(outer, chunk_digests.length())
  for d in chunk_digests {
    for x in d {
      outer.push(x)
    }
  }
  Some(hash_fn(Bytes::from_array(outer[:])))
}

///|
/// 按 1 MiB 切片 `source[start:end]`，追加每片摘要到 `out`。
fn chunk_append(
  source : Bytes,
  start : Int32,
  end : Int32,
  out : Array[Bytes],
  hash_fn : (Bytes) -> Bytes,
) -> Unit {
  let chunk_size = 1048576
  let mut pos = start
  while pos < end {
    let take = if end - pos > chunk_size { chunk_size } else { end - pos }
    let buf : Array[Byte] = []
    for i = pos; i < pos + take; i = i + 1 {
      buf.push(source[i])
    }
    out.push(chunk_digest_of(Bytes::from_array(buf[:]), hash_fn))
    pos = pos + take
  }
}

///|
/// 单片摘要：algorithm(0xa5 || chunk_len_u32le || chunk)。
fn chunk_digest_of(chunk : Bytes, hash_fn : (Bytes) -> Bytes) -> Bytes {
  let buf : Array[Byte] = []
  buf.push(b'\xa5')
  push_u32_le(buf, chunk.length())
  for x in chunk {
    buf.push(x)
  }
  hash_fn(Bytes::from_array(buf[:]))
}

///|
/// 小端 u32 写入字节数组。
fn push_u32_le(a : Array[Byte], v : Int32) -> Unit {
  a.push((v & 0xFF).to_byte())
  a.push(((v >> 8) & 0xFF).to_byte())
  a.push(((v >> 16) & 0xFF).to_byte())
  a.push(((v >> 24) & 0xFF).to_byte())
}

///|
/// 包内安全取条目（失败返回 None，供校验路径记录失败而非抛出）。
fn Apk::safe_entry(self : Apk, name : String) -> Bytes? {
  let mut out : Bytes? = None
  try {
    out = Some(extract_entry(self.source, self.entries, name))
  } catch {
    _ => ()
  } noraise {
    _ => ()
  }
  out
}

///|
/// base64 摘要比较（解码失败视为不一致）。
fn digest_matches(actual : Bytes, expected_b64 : String) -> Bool {
  let expected = @base64.decode(expected_b64) catch { _ => return false }
  actual == expected
}

///|
/// 从 JAR 清单 section 中取摘要属性：优先 SHA-256，其次 SHA-1/SHA-512（后者不支持校验）。
fn entry_digest_attr(section : Array[(String, String)]) -> (String, String)? {
  match attr_value(section, "SHA-256-Digest") {
    Some(v) => Some(("SHA-256", v))
    None =>
      match attr_value(section, "SHA-1-Digest") {
        Some(v) => Some(("SHA-1", v))
        None =>
          match attr_value(section, "SHA-512-Digest") {
            Some(v) => Some(("SHA-512", v))
            None => None
          }
      }
  }
}

///|
/// 取 section 的属性值。
fn attr_value(section : Array[(String, String)], key : String) -> String? {
  for (k, v) in section {
    if k == key {
      return Some(v)
    }
  }
  None
}

///|
/// 解析 JAR 清单文本为 section 数组（每个 section 是属性键值对数组）。
///
/// 处理 CRLF/LF、续行（行首单个空格）与空行分节；首 section 为主属性。
fn parse_manifest_sections(text : String) -> Array[Array[(String, String)]] {
  let logical : Array[String] = []
  for raw in text.split("\n") {
    let mut line = raw.to_owned()
    if line.has_suffix("\r") {
      line = line[:line.length() - 1].to_owned()
    }
    if line.has_prefix(" ") && logical.length() > 0 {
      let last = logical.length() - 1
      logical[last] = logical[last] + line[1:].to_owned()
    } else if line == "" {
      logical.push("")
    } else {
      logical.push(line)
    }
  }
  let sections : Array[Array[(String, String)]] = []
  let mut cur : Array[(String, String)] = []
  for line in logical {
    if line == "" {
      if cur.length() > 0 {
        sections.push(cur)
        cur = []
      }
    } else {
      match line.find(":") {
        Some(colon) => {
          let mut value = line[colon + 1:].to_owned()
          if value.has_prefix(" ") {
            value = value[1:].to_owned()
          }
          cur.push((trim_spaces(line[:colon].to_owned()), trim_spaces(value)))
        }
        None => ()
      }
    }
  }
  if cur.length() > 0 {
    sections.push(cur)
  }
  sections
}

///|
/// 去掉首尾空格（JAR 属性值/键名的规范化）。
fn trim_spaces(s : String) -> String {
  let mut start = 0
  let mut end = s.length()
  while start < end && s[start:start + 1] == " " {
    start = start + 1
  }
  while end > start && s[end - 1:end] == " " {
    end = end - 1
  }
  s[start:end].to_owned()
}

///|
/// 从 PKCS#7（DER）中提取证书 DER 原始字节；结构非法返回空数组（不抛错）。
///
/// 只做最外层结构定位：ContentInfo → signedData → [0] certificates → Certificate。
/// **不验证** SignedData 的签名值，也不校验证书链。
fn pkcs7_certificates(der : Bytes) -> Array[Bytes] {
  let certs : Array[Bytes] = []
  let len = der.length()
  if len < 4 {
    return certs
  }
  let ci = match der_read(der, 0, len) {
    Some(t) => t
    None => return certs
  }
  if ci.tag != 0x30 {
    return certs
  }
  let oid = match der_read(der, ci.body, ci.end) {
    Some(t) => t
    None => return certs
  }
  if oid.tag != 0x06 || !der_oid_is_signed_data(der, oid.body, oid.end) {
    return certs
  }
  let ctx = match der_read(der, oid.end, ci.end) {
    Some(t) => t
    None => return certs
  }
  if ctx.tag != 0xA0 {
    return certs
  }
  let sd = match der_read(der, ctx.body, ctx.end) {
    Some(t) => t
    None => return certs
  }
  if sd.tag != 0x30 {
    return certs
  }
  let mut p = sd.body
  while p < sd.end {
    let child = match der_read(der, p, sd.end) {
      Some(t) => t
      None => return certs
    }
    if child.tag == 0xA0 {
      let mut c = child.body
      while c < child.end {
        let cert = match der_read(der, c, child.end) {
          Some(t) => t
          None => return certs
        }
        if cert.tag == 0x30 {
          certs.push(der[cert.start:cert.end].to_owned())
        }
        c = cert.end
      }
    }
    p = child.end
  }
  certs
}

///|
/// 判断 OID 内容是否为 `1.2.840.113549.1.7.2`（signedData）。
fn der_oid_is_signed_data(b : Bytes, start : Int32, end : Int32) -> Bool {
  let expected = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
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
/// DER TLV 读取结果（`start` 为 tag 起始、`body` 为内容起始、`end` 为 TLV 结束）。
priv struct DerTlv {
  tag : Int32
  start : Int32
  body : Int32
  end : Int32
}

///|
/// 读取一个 DER TLV；短/长格式长度均支持（长度字节数上限 4），越界返回 None。
fn der_read(b : Bytes, off : Int32, limit : Int32) -> DerTlv? {
  if off < 0 || off + 2 > limit {
    return None
  }
  let tag = b[off].to_int()
  let l0 = b[off + 1].to_int()
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
    len = (len << 8) | b[off + 2 + i].to_int()
  }
  let body = off + 2 + n
  let end = body + len
  if end > limit || end < body {
    return None
  }
  Some({ tag, start: off, body, end, })
}
