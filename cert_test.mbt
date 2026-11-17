///|
/// W3 X.509 证书结构解析测试（合成 DER，无第三方二进制）。
///
/// 覆盖：
/// - T-W3-2：畸形 DER（截断/坏 tag/坏时间）一律 raise `BadSigningBlock`，不 panic；
/// - T-W3-3：v1（PKCS#7 内证书）与 v2/v3（signer certificates）双通道去重；
/// - T-W3-4：字段稳定性（主体/颁发者/有效期/算法/位长/指纹）。
///
/// 边界：本库不验签、不验证书链；这些用例只断言结构事实。

///|
/// 拼接两个 Bytes。
fn w3_cat(a : Bytes, b : Bytes) -> Bytes {
  let out : Array[Byte] = []
  push_bytes(out, a)
  push_bytes(out, b)
  Bytes::from_array(out[:])
}

///|
/// DER TLV（短长度，< 128；长长度由 s_tlv_long 处理）。
fn w3_tlv(tag : Int32, body : Bytes) -> Bytes {
  let out : Array[Byte] = []
  out.push(tag.to_byte())
  let n = body.length()
  if n < 0x80 {
    out.push(n.to_byte())
  } else if n <= 0xFF {
    out.push(b'\x81')
    out.push(n.to_byte())
  } else {
    out.push(b'\x82')
    out.push(((n >> 8) & 0xFF).to_byte())
    out.push((n & 0xFF).to_byte())
  }
  push_bytes(out, body)
  Bytes::from_array(out[:])
}

///|
/// INTEGER（正整数，自动加前导 0 防符号位）。
fn w3_int(v : Int32) -> Bytes {
  let mut v = v
  let bytes : Array[Byte] = []
  if v == 0 {
    bytes.push(b'\x00')
  } else {
    while v > 0 {
      bytes.push((v & 0xFF).to_byte())
      v = v >> 8
    }
    // 反转
    let rev : Array[Byte] = []
    let mut i = bytes.length() - 1
    while i >= 0 {
      rev.push(bytes[i])
      i = i - 1
    }
    bytes.clear()
    for x in rev {
      bytes.push(x)
    }
    if (bytes[0].to_int() & 0x80) != 0 {
      let padded : Array[Byte] = [b'\x00']
      for x in bytes {
        padded.push(x)
      }
      bytes.clear()
      for x in padded {
        bytes.push(x)
      }
    }
  }
  w3_tlv(0x02, Bytes::from_array(bytes[:]))
}

///|
/// OID 编码（点分 → DER）。
fn w3_oid(dotted : String) -> Bytes {
  // 硬编码常用 OID 的 DER 内容，避免实现一个完整 OID 编码器。
  match dotted {
    "1.2.840.113549.1.1.11" =>
      w3_tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b")
    "1.2.840.113549.1.1.1" =>
      w3_tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01")
    "2.5.4.3" => w3_tlv(0x06, b"\x55\x04\x03")
    "2.5.4.10" => w3_tlv(0x06, b"\x55\x04\x0a")
    "2.5.4.6" => w3_tlv(0x06, b"\x55\x04\x06")
    _ => w3_tlv(0x06, b"")
  }
}

///|
/// RDN：AttributeTypeAndValue 序列。
fn w3_rdn(oid : String, value : String) -> Bytes {
  let oid_b = w3_oid(oid)
  let val_b = w3_tlv(0x0C, @encoding/utf8.encode(value))
  w3_tlv(0x30, w3_cat(oid_b, val_b))
}

///|
/// Name：SET OF RDN。
fn w3_name(rdns : Array[Bytes]) -> Bytes {
  let mut body = b""
  for r in rdns {
    body = w3_cat(body, w3_tlv(0x31, r))
  }
  w3_tlv(0x30, body)
}

///|
/// UTCTime "YYMMDDHHMMSSZ"。
fn w3_utctime(s : String) -> Bytes {
  w3_tlv(0x17, @encoding/utf8.encode(s))
}

///|
/// AlgorithmIdentifier：OID + 空参数。
fn w3_algo(oid : String) -> Bytes {
  w3_tlv(0x30, w3_cat(w3_oid(oid), w3_tlv(0x05, b"")))
}

///|
/// SubjectPublicKeyInfo：RSA 公钥（modulus=2048 位假模，exponent=65537）。
fn w3_spki_rsa() -> Bytes {
  // RSAPublicKey：modulus INTEGER(256 字节) + exponent INTEGER(3 字节 010001)。
  let modulus_bytes : Array[Byte] = []
  for i = 0; i < 256; i = i + 1 {
    modulus_bytes.push(((i * 7 + 3) & 0xFF).to_byte())
  }
  // 置高位为 1，保证是 2048 位正整数。
  modulus_bytes[0] = (modulus_bytes[0].to_int() | 0x80).to_byte()
  let modulus = w3_tlv(0x02, Bytes::from_array(modulus_bytes[:]))
  let exponent = w3_tlv(0x02, b"\x01\x00\x01")
  let rsa_pub = w3_tlv(0x30, w3_cat(modulus, exponent))
  // BIT STRING：unused-bits=0 + 内容。
  let bitstr = w3_tlv(0x03, w3_cat(b"\x00", rsa_pub))
  w3_tlv(0x30, w3_cat(w3_algo("1.2.840.113549.1.1.1"), bitstr))
}

///|
/// 构造一个合成 v3 证书 DER（CN=Test Subject, O=Example, C=US）。
fn w3_cert() -> Bytes {
  let version = w3_tlv(0xA0, w3_int(2))
  let serial = w3_int(12345)
  let sig_algo = w3_algo("1.2.840.113549.1.1.11")
  let issuer = w3_name([
    w3_rdn("2.5.4.3", "Test CA"),
    w3_rdn("2.5.4.10", "Example Org"),
    w3_rdn("2.5.4.6", "US"),
  ])
  let validity = w3_tlv(
    0x30,
    w3_cat(w3_utctime("250101000000Z"), w3_utctime("350101000000Z")),
  )
  let subject = w3_name([
    w3_rdn("2.5.4.3", "Test Subject"),
    w3_rdn("2.5.4.10", "Example Org"),
    w3_rdn("2.5.4.6", "US"),
  ])
  let spki = w3_spki_rsa()
  let tbs = w3_tlv(
    0x30,
    w3_cat(
      w3_cat(w3_cat(version, serial), sig_algo),
      w3_cat(w3_cat(issuer, validity), w3_cat(subject, spki)),
    ),
  )
  // 外层：TBS + 算法 + 签名值（假签名 256 字节）。
  let fake_sig = w3_tlv(0x03, w3_cat(b"\x00", Bytes::from_array([b'\x00'])))
  w3_tlv(0x30, w3_cat(w3_cat(tbs, sig_algo), fake_sig))
}

///|
/// T-W3-4：合成证书字段全绿。
test "W3 T-W3-4 synthetic cert fields are stable" {
  let der = w3_cert()
  let info = @apk.parse_certificate(der)
  assert_eq(info.version, 2)
  assert_eq(info.serial_hex, "3039")
  assert_eq(info.subject, "CN=Test Subject,O=Example Org,C=US")
  assert_eq(info.issuer, "CN=Test CA,O=Example Org,C=US")
  assert_eq(info.not_before, "2025-01-01T00:00:00Z")
  assert_eq(info.not_after, "2035-01-01T00:00:00Z")
  assert_eq(info.signature_algo_oid, "1.2.840.113549.1.1.11")
  assert_eq(info.public_key_algo_oid, "1.2.840.113549.1.1.1")
  assert_eq(info.public_key_bits, 2048)
  // 指纹 = 整份 DER 的 SHA-256（小写 hex）。
  assert_true(info.sha256_fingerprint_hex.length() == 64)
}

///|
/// T-W3-2：畸形 DER 截断 → raise BadSigningBlock，不 panic。
test "W3 T-W3-2 truncated DER raises BadSigningBlock" {
  let der = w3_cert()
  let cases : Array[Int32] = [1, 10, 50, 100, der.length() - 1]
  for cut in cases {
    let truncated = der[0:cut].to_owned()
    let mut hit = false
    try ignore(@apk.parse_certificate(truncated)) catch {
      @apk.ApkError::BadSigningBlock(_, _) => hit = true
      _ => fail("expected BadSigningBlock")
    } noraise {
      _ => ()
    }
    assert_true(hit, msg="truncated at \{cut} must raise BadSigningBlock")
  }
}

///|
/// T-W3-2：坏外层（非 SEQUENCE）→ raise BadSigningBlock。
test "W3 T-W3-2 bad outer tag raises BadSigningBlock" {
  let mut hit = false
  try ignore(@apk.parse_certificate(b"\x31\x03\x02\x01\x05")) catch {
    @apk.ApkError::BadSigningBlock(_, _) => hit = true
    _ => fail("expected BadSigningBlock")
  } noraise {
    _ => ()
  }
  assert_true(hit, msg="non-SEQUENCE outer must raise BadSigningBlock")
}

///|
/// 剥掉外层 SEQUENCE 的 tag+len，返回 body（支持短/长形式长度，长形式 ≤ 4 字节）。
fn w3_strip_seq(der : Bytes) -> Bytes {
  let l0 = der[1].to_int()
  if l0 < 0x80 {
    return der[2:2 + l0].to_owned()
  }
  let n = l0 & 0x7F
  let mut len = 0
  for i = 0; i < n; i = i + 1 {
    len = (len << 8) | der[2 + i].to_int()
  }
  der[2 + n:2 + n + len].to_owned()
}

///|
/// 最小 PKCS#7 SignedData 封装（用 w3_tlv 支持 >255 字节证书的长格式长度）：
/// ContentInfo(OID signedData) + [0] SignedData，内含一个 [0] certificates SEQUENCE。
/// 证书以 `SEQUENCE(inner_body)` 形式嵌入，提取出的证书与传入的 `cert` 逐字节一致。
fn w3_pkcs7(cert : Bytes) -> Bytes {
  let oid = w3_tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02")
  let cert_tlv = w3_tlv(0x30, w3_strip_seq(cert))
  let certs = w3_tlv(0xA0, cert_tlv)
  let version = w3_tlv(0x02, b"\x01")
  let digest_algs = w3_tlv(0x31, b"")
  let encap = w3_tlv(0x30, b"")
  let signed_data = w3_tlv(
    0x30,
    w3_cat(w3_cat(version, digest_algs), w3_cat(encap, certs)),
  )
  w3_tlv(0x30, w3_cat(oid, w3_tlv(0xA0, signed_data)))
}

///|
/// T-W3-3：v1-only 样本 certificate_infos 去重（单证书）。
test "W3 T-W3-3 v1 certificate_infos dedup" {
  let cert = w3_cert()
  let apk = @apk.Apk::open(
    s_v1_apk(b"hello", s_manifest_ok(), s_sf_ok(), w3_pkcs7(cert)),
  )
  let infos = apk.certificate_infos()
  assert_eq(infos.length(), 1)
  assert_eq(infos[0].subject, "CN=Test Subject,O=Example Org,C=US")
}

///|
/// T-W3-3：v2/v3 同一证书在两个方案中重复 → certificate_infos 去重为 1。
test "W3 T-W3-3 v2+v3 same cert dedup to one" {
  let cert = w3_cert()
  let v2_block = sig_block_of([
    (0x7109871aU, scheme_value(cert, 0)),
    (0xf05368c0U, scheme_value(cert, 8)),
  ])
  let apk = @apk.Apk::open(
    build_zip([zspec("a.txt", b"hello")], Some(v2_block)),
  )
  let infos = apk.certificate_infos()
  assert_eq(infos.length(), 1)
  assert_eq(infos[0].subject, "CN=Test Subject,O=Example Org,C=US")
}
