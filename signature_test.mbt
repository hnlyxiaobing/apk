// 合成 v1 JAR 签名样本：全部字节在测试内构造（无第三方二进制），
// 覆盖 结构+摘要 校验的真/假两条路径，以及 PKCS#7 结构错误的降级路径。
//
// 边界：本库不做 RSA/ECDSA 验签；这些用例只断言「结构 + 摘要」，
// `SignatureCheck.signature_verified` 必须恒为 false。

///|
/// 拼接两个 Bytes。
fn s_cat(a : Bytes, b : Bytes) -> Bytes {
  let out : Array[Byte] = []
  push_bytes(out, a)
  push_bytes(out, b)
  Bytes::from_array(out[:])
}

///|
/// DER TLV 编码（长度 < 256 用短格式，其余用 1 字节长格式；测试样本足够小）。
fn s_tlv(tag : Int32, body : Bytes) -> Bytes {
  let out : Array[Byte] = []
  out.push(tag.to_byte())
  let n = body.length()
  if n < 0x80 {
    out.push(n.to_byte())
  } else {
    out.push(b'\x81')
    out.push(n.to_byte())
  }
  push_bytes(out, body)
  Bytes::from_array(out[:])
}

///|
/// 最小 PKCS#7 SignedData 封装：ContentInfo(OID signedData) + [0] SignedData，
/// SignedData 内只有一个 [0] certificates SEQUENCE（内容由参数给定）。
fn s_pkcs7(cert_body : Bytes) -> Bytes {
  let oid = s_tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02")
  let cert = s_tlv(0x30, cert_body)
  let certs = s_tlv(0xA0, cert)
  let version = s_tlv(0x02, b"\x01")
  let digest_algs = s_tlv(0x31, b"")
  let encap = s_tlv(0x30, b"")
  let signed_data = s_tlv(
    0x30,
    s_cat(s_cat(version, digest_algs), s_cat(encap, certs)),
  )
  s_tlv(0x30, s_cat(oid, s_tlv(0xA0, signed_data)))
}

///|
/// 合成 v1 签名的固定 MANIFEST.MF（条目 a.txt 的内容摘要 = SHA-256("hello")）。
fn s_manifest_ok() -> Bytes {
  @encoding/utf8.encode(
    "Manifest-Version: 1.0\n\nName: a.txt\nSHA-256-Digest: LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=\n\n",
  )
}

///|
/// 合成 v1 签名的 `.SF`：SHA-256-Digest-Manifest = SHA-256(上面 MANIFEST.MF)。
fn s_sf_ok() -> Bytes {
  @encoding/utf8.encode(
    "Signature-Version: 1.0\nSHA-256-Digest-Manifest: yRNoz2zwAjSHD5DEd85JIOFsdIgTjQcXVPi2ByINCZs=\n\n",
  )
}

///|
/// 构造完整 v1 APK：a.txt + MANIFEST.MF + TEST.SF + TEST.RSA。
fn s_v1_apk(
  entry_data : Bytes,
  manifest : Bytes,
  sf : Bytes,
  block : Bytes,
) -> Bytes {
  build_zip(
    [
      zspec("a.txt", entry_data),
      zspec("META-INF/MANIFEST.MF", manifest),
      zspec("META-INF/TEST.SF", sf),
      zspec("META-INF/TEST.RSA", block),
    ],
    None,
  )
}

///|
/// 合成 v1：结构 + 摘要全部通过；证书从 PKCS#7 提取。
test "synthetic v1 signature verifies structure and digests" {
  let cert_body = b"\x02\x01\x02fake-cert"
  let apk = @apk.Apk::open(
    s_v1_apk(b"hello", s_manifest_ok(), s_sf_ok(), s_pkcs7(cert_body)),
  )
  let sigs = apk.signatures()
  assert_eq(sigs.length(), 1)
  assert_eq(sigs[0].block_id, 0)
  assert_eq(sigs[0].certificates.length(), 1)
  assert_true(sigs[0].certificates[0] == s_tlv(0x30, cert_body))
  assert_true(sigs[0].verified)
  let checks = apk.signature_checks()
  assert_eq(checks.length(), 1)
  assert_true(checks[0].structure_ok)
  assert_true(checks[0].digest_ok, msg=checks[0].detail)
  assert_eq(checks[0].entries_checked, 1)
  assert_eq(checks[0].entries_failed, 0)
  assert_eq(checks[0].digest_algorithm, "SHA-256")
  assert_true(!checks[0].signature_verified)
}

///|
/// 合成 v1：条目内容被换掉（摘要仍对应 "hello"）→ digest_ok=false、verified=false。
test "synthetic v1 entry digest mismatch is reported not raised" {
  let apk = @apk.Apk::open(
    s_v1_apk(b"HELLO", s_manifest_ok(), s_sf_ok(), s_pkcs7(b"cert")),
  )
  assert_true(!apk.signatures()[0].verified)
  let c = apk.signature_checks()[0]
  assert_true(c.structure_ok)
  assert_true(!c.digest_ok)
  assert_eq(c.entries_checked, 1)
  assert_eq(c.entries_failed, 1)
  assert_true(c.detail.contains("mismatch"))
}

///|
/// 合成 v1：`.SF` 的 MANIFEST 摘要错误 → 清单摘要校验失败。
test "synthetic v1 wrong manifest digest fails" {
  let bad_sf = @encoding/utf8.encode(
    "Signature-Version: 1.0\nSHA-256-Digest-Manifest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n",
  )
  let apk = @apk.Apk::open(
    s_v1_apk(b"hello", s_manifest_ok(), bad_sf, s_pkcs7(b"cert")),
  )
  let c = apk.signature_checks()[0]
  assert_true(c.structure_ok)
  assert_true(!c.digest_ok)
  assert_true(!apk.signatures()[0].verified)
}

///|
/// 合成 v1：PKCS#7 结构非法 → structure_ok=false（不 panic、不抛错）。
test "synthetic v1 malformed PKCS#7 degrades to structure_ok=false" {
  let apk = @apk.Apk::open(
    s_v1_apk(b"hello", s_manifest_ok(), s_sf_ok(), b"not-a-der-pkcs7"),
  )
  let sigs = apk.signatures()
  assert_eq(sigs.length(), 1)
  assert_eq(sigs[0].certificates.length(), 0)
  assert_true(!sigs[0].verified)
  let c = apk.signature_checks()[0]
  assert_true(!c.structure_ok)
  assert_true(!c.digest_ok)
  assert_true(c.detail.contains("PKCS#7"))
}

///|
/// 合成 v1：缺 `.SF` → structure_ok=false。
test "synthetic v1 missing SF degrades to structure_ok=false" {
  let zip = build_zip(
    [
      zspec("a.txt", b"hello"),
      zspec("META-INF/MANIFEST.MF", s_manifest_ok()),
      zspec("META-INF/TEST.RSA", s_pkcs7(b"cert")),
    ],
    None,
  )
  let apk = @apk.Apk::open(zip)
  let c = apk.signature_checks()[0]
  assert_true(!c.structure_ok)
  assert_true(!c.digest_ok)
  assert_true(!apk.signatures()[0].verified)
}

///|
/// ---------- W4 v1 SHA-512 摘要支持 ----------
/// T-W4-1：纯 SHA-512（MANIFEST 条目 + .SF 清单摘要均用 SHA-512）。
/// T-W4-2：SHA-256 与 SHA-512 混合 MANIFEST → digest_ok=true 且 detail 含 "mixed"。
/// T-W4-3：SHA-1 条目 → unsupported++，fail-closed。
/// T-W4-4：`entry_digest_attr` 对仅有 SHA-512-Digest 的 section 返回 ("SHA-512", ...)。

///|
/// 纯 SHA-512 MANIFEST（SHA-512("hello") 的 base64）。
fn s_manifest_sha512() -> Bytes {
  @encoding/utf8.encode(
    "Manifest-Version: 1.0\n\nName: a.txt\nSHA-512-Digest: m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==\n\n",
  )
}

///|
/// .SF：SHA-512-Digest-Manifest = SHA-512(Manifest-Version: 1.0\n\nName:...==\n\n)。
fn s_sf_sha512() -> Bytes {
  @encoding/utf8.encode(
    "Signature-Version: 1.0\nSHA-512-Digest-Manifest: 4alQAH9yPIuNA2VeBL8T+kauZS7g6T+5GiMbxohnq3rloqSxIlUU351DHl+h8rdCiYX70xwZnJUBtnbEEpV/+w==\n\n",
  )
}

///|
/// 混合 MANIFEST：a.txt 用 SHA-256，b.txt 用 SHA-512（同含 "hello"）。
fn s_manifest_mixed() -> Bytes {
  @encoding/utf8.encode(
    "Manifest-Version: 1.0\n\nName: a.txt\nSHA-256-Digest: LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=\n\nName: b.txt\nSHA-512-Digest: m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==\n\n",
  )
}

///|
/// 混合 .SF：同时包含 SHA-256-Digest-Manifest 与 SHA-512-Digest-Manifest。
fn s_sf_mixed() -> Bytes {
  @encoding/utf8.encode(
    "Signature-Version: 1.0\nSHA-256-Digest-Manifest: K8LPlmqQIfgyvo/ChFT6sP5TllIe8P2EYKTYxXtxmiU=\nSHA-512-Digest-Manifest: rh2yRBnK2GtRaNrvT7kfPFjviynCg0IdbHiSx3gvLzBfGyG74rvcCGJVqd0x7ZBlceUzwuvyUb3OOQlOj0DNTQ==\n\n",
  )
}

///|
/// 构造混合 v1 APK（两条目：a.txt + b.txt + META-INF）。
fn s_v1_mixed_apk(
  entry_a : Bytes,
  entry_b : Bytes,
  manifest : Bytes,
  sf : Bytes,
  block : Bytes,
) -> Bytes {
  build_zip(
    [
      zspec("a.txt", entry_a),
      zspec("b.txt", entry_b),
      zspec("META-INF/MANIFEST.MF", manifest),
      zspec("META-INF/TEST.SF", sf),
      zspec("META-INF/TEST.RSA", block),
    ],
    None,
  )
}

///|
/// T-W4-1：纯 SHA-512 v1 签名 → digest_ok=true。
test "W4 T-W4-1 pure SHA-512 v1 signature verifies digests" {
  let apk = @apk.Apk::open(
    s_v1_apk(b"hello", s_manifest_sha512(), s_sf_sha512(), s_pkcs7(b"cert")),
  )
  let c = apk.signature_checks()[0]
  assert_true(c.structure_ok)
  assert_true(c.digest_ok, msg=c.detail)
  assert_eq(c.entries_checked, 1)
  assert_eq(c.entries_failed, 0)
  assert_eq(c.digest_algorithm, "SHA-512")
  assert_true(!c.signature_verified)
}

///|
/// T-W4-2：混合 SHA-256 + SHA-512 v1 → digest_ok=true，detail 含 "(mixed algorithms)"。
test "W4 T-W4-2 mixed SHA-256 and SHA-512 v1 signature verifies with mixed note" {
  let apk = @apk.Apk::open(
    s_v1_mixed_apk(
      b"hello",
      b"hello",
      s_manifest_mixed(),
      s_sf_mixed(),
      s_pkcs7(b"cert"),
    ),
  )
  let c = apk.signature_checks()[0]
  assert_true(c.structure_ok)
  assert_true(c.digest_ok, msg=c.detail)
  assert_eq(c.entries_checked, 2)
  assert_eq(c.entries_failed, 0)
  assert_eq(c.digest_algorithm, "SHA-256")
  assert_true(
    c.detail.contains("mixed"),
    msg="expected mixed note: " + c.detail,
  )
  assert_true(!c.signature_verified)
}

///|
/// T-W4-3 .SF：SHA-256-Digest-Manifest = SHA-256(SHA-1-only manifest)。
fn s_sf_sha1_mf() -> Bytes {
  @encoding/utf8.encode(
    "Signature-Version: 1.0\nSHA-256-Digest-Manifest: Af77eMM8tiiPN0p+IFQD4QD2NDZJmeLKgqeE7X16HEM=\n\n",
  )
}

///|
/// T-W4-3：SHA-1 条目 → unsupported，fail-closed（digest_ok=false）。
test "W4 T-W4-3 SHA-1 entry is unsupported fail-closed" {
  let mf_sha1 = @encoding/utf8.encode(
    "Manifest-Version: 1.0\n\nName: a.txt\nSHA-1-Digest: qvTGHdzF6KLavt4PO0gs2a6pQ00=\n\n",
  )
  let apk = @apk.Apk::open(
    s_v1_apk(b"hello", mf_sha1, s_sf_sha1_mf(), s_pkcs7(b"cert")),
  )
  let c = apk.signature_checks()[0]
  assert_true(c.structure_ok)
  assert_true(!c.digest_ok)
  assert_true(c.detail.contains("unsupported"))
}

///|
/// T-W4-4 .SF：SHA-512-Digest-Manifest = SHA-512(two-entry pure-SHA-512 manifest)。
fn s_sf_sha512_two() -> Bytes {
  @encoding/utf8.encode(
    "Signature-Version: 1.0\nSHA-512-Digest-Manifest: asdMCdf05jhtxOUNsBManw6S6dnGZuqAYFjre2HUoqtYJwQw16t855LV4nYgYDvEyuheO0ER6xlKzIosziSbVQ==\n\n",
  )
}

///|
/// T-W4-4：双条目均用 SHA-512（不同姓名）→ digest_ok=true，digest_algorithm="SHA-512"。
test "W4 T-W4-4 two-entry pure SHA-512 v1 both ok" {
  let mf_two = @encoding/utf8.encode(
    "Manifest-Version: 1.0\n\nName: a.txt\nSHA-512-Digest: m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==\n\nName: b.txt\nSHA-512-Digest: m3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==\n\n",
  )
  let apk = @apk.Apk::open(
    s_v1_mixed_apk(
      b"hello",
      b"hello",
      mf_two,
      s_sf_sha512_two(),
      s_pkcs7(b"cert"),
    ),
  )
  let c = apk.signature_checks()[0]
  assert_true(c.digest_ok, msg=c.detail)
  assert_eq(c.entries_checked, 2)
  assert_eq(c.entries_failed, 0)
  assert_eq(c.digest_algorithm, "SHA-512")
}
