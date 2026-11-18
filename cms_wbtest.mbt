///|
/// 测试用 DER TLV 编码（内容长度 < 256，支持短格式与 0x81 长格式）。
fn cms_test_tlv(tag : Int32, content : Bytes) -> Bytes {
  let out : Array[Byte] = [tag.to_byte()]
  let n = content.length()
  if n < 0x80 {
    out.push(n.to_byte())
  } else {
    out.push(b'\x81')
    out.push(n.to_byte())
  }
  for b in content {
    out.push(b)
  }
  Bytes::from_array(out[:])
}

///|
/// 顺序拼接多段字节。
fn cms_test_concat(parts : Array[Bytes]) -> Bytes {
  let out : Array[Byte] = []
  for p in parts {
    for b in p {
      out.push(b)
    }
  }
  Bytes::from_array(out[:])
}

///|
/// 构造一个携带指定 SPKI 的最小 X.509 证书（tbsCertificate 七个子项，便于 x509_spki 定位）。
fn cms_test_cert_with_spki(spki : Bytes) -> Bytes {
  let tbs_body = cms_test_concat([
    b"\xa0\x03\x02\x01\x02", // [0] version = 2
     b"\x02\x01\x01", // serialNumber
     b"\x30\x00", // signature
     b"\x30\x00", // issuer
     b"\x30\x00", // validity
     b"\x30\x00", // subject
     spki, // subjectPublicKeyInfo
  ])
  let tbs = cms_test_tlv(0x30, tbs_body)
  cms_test_tlv(0x30, cms_test_concat([tbs, b"\x30\x00", b"\x03\x00"]))
}

///|
/// 构造最小 PKCS#7 SignedData（ECDSA/SHA-256、无 signedAttrs、签名覆盖 .SF 内容）。
fn cms_test_pkcs7_ecdsa(sig_der : Bytes) -> Bytes {
  let digest_alg = cms_test_tlv(
    0x30,
    cms_test_tlv(0x06, b"\x60\x86\x48\x01\x65\x03\x04\x02\x01"), // sha256
  )
  let sig_alg = cms_test_tlv(
    0x30,
    cms_test_tlv(0x06, b"\x2a\x86\x48\xce\x3d\x04\x03\x02"), // ecdsa-with-SHA256
  )
  let signer_info = cms_test_tlv(
    0x30,
    cms_test_concat([
      b"\x02\x01\x01", // version
      b"\x30\x00", // issuerAndSerialNumber
      digest_alg,
      sig_alg,
      cms_test_tlv(0x04, sig_der), // encryptedDigest
    ]),
  )
  let signed_data = cms_test_tlv(
    0x30,
    cms_test_concat([
      b"\x02\x01\x01", // version
      b"\x31\x00", // digestAlgorithms
      b"\x30\x00", // encapContentInfo
      cms_test_tlv(0x31, signer_info), // signerInfos
    ]),
  )
  cms_test_tlv(
    0x30,
    cms_test_concat([
      cms_test_tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"), // signedData
      cms_test_tlv(0xA0, signed_data),
    ]),
  )
}

///|
/// P-384 EC SPKI（把 RFC 6979 A.2.5 的 P-256 坐标零扩展到 48 字节，用于曲线不匹配用例）。
fn cms_test_spki_p384_mismatch() -> Bytes {
  bytes_from_hex(
    "3076301006072a8648ce3d020106052b81040022036200040000000000000000000000000000000060fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6000000000000000000000000000000007903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
}

///|
/// 非 RSA 也非 EC 的 SPKI（OID 1.2.840.10040.4.1，DSA）。
fn cms_test_spki_dsa() -> Bytes {
  bytes_from_hex("300f300906072a8648ce38040103020000")
}

///|
test "T-W6-EC-c: RFC 6979 向量走 v1 CMS 调度链 crypto_verified=true" {
  // signedAttrs 缺失 → 签名覆盖 .SF 内容；sf_bytes 取 "sample" 使 e = sha256("sample")。
  let cert = cms_test_cert_with_spki(ec_test_spki_p256())
  let pkcs7 = cms_test_pkcs7_ecdsa(ec_test_sig_der())
  match cms_signer_infos(pkcs7) {
    Some(infos) => {
      assert_eq(infos.length(), 1)
      assert_eq(infos[0].sig_alg, "ECDSA")
      assert_eq(infos[0].digest_alg, "SHA-256")
      assert_true(infos[0].signed_attrs is None, msg="no signedAttrs")
    }
    None => fail("minimal PKCS#7 should parse")
  }
  let (ok, algo, detail) = verify_v1_signer_info([cert], b"sample", pkcs7)
  assert_true(ok, msg="ECDSA v1 signerInfo verifies over .SF content")
  assert_eq(algo, "SHA256withECDSA")
  assert_true(detail.contains("ECDSA"), msg="detail reports ECDSA")
}

///|
test "T-W6-EC-c: 非 RSA/EC SPKI、截断签名、曲线不匹配一律 fail-closed" {
  // 1) DSA SPKI：RSA 与 EC 解析都失败 → 直接 fail。
  let dsa_cert = cms_test_cert_with_spki(cms_test_spki_dsa())
  let pkcs7 = cms_test_pkcs7_ecdsa(ec_test_sig_der())
  let (ok0, _, detail0) = verify_v1_signer_info([dsa_cert], b"sample", pkcs7)
  assert_true(!ok0, msg="DSA SPKI 必须 fail-closed")
  assert_true(detail0.contains("SPKI"), msg="detail reports unparseable SPKI")
  // 2) RSA SPKI 但签名算法声明 ECDSA → 证书密钥不是 EC。
  let rsa_spki = bytes_from_hex("3013300d06092a864886f70d010101050003020000")
  let rsa_cert = cms_test_cert_with_spki(rsa_spki)
  let (ok1, _, detail1) = verify_v1_signer_info([rsa_cert], b"sample", pkcs7)
  assert_true(!ok1, msg="RSA 密钥配 ECDSA 签名必须 fail-closed")
  assert_true(detail1.contains("EC"), msg="detail reports non-EC key")
  // 3) 签名值 DER 截断。
  let der = ec_test_sig_der()
  let truncated = cms_test_pkcs7_ecdsa(der[0:20].to_owned())
  let cert = cms_test_cert_with_spki(ec_test_spki_p256())
  let (ok2, _, detail2) = verify_v1_signer_info([cert], b"sample", truncated)
  assert_true(!ok2, msg="截断签名必须 fail-closed")
  assert_true(detail2.contains("DER"), msg="detail reports bad DER")
  // 4) 曲线不匹配：P-384 SPKI + P-256 签名。
  let p384_cert = cms_test_cert_with_spki(cms_test_spki_p384_mismatch())
  let (ok3, _, _) = verify_v1_signer_info([p384_cert], b"sample", pkcs7)
  assert_true(!ok3, msg="曲线不匹配必须 fail-closed")
}
