///|
/// W6-后续 里程碑 a：曲线原语白盒已知向量测试（RFC 6979 A.2.5 / A.2.6，权威标准值）。
///
/// 覆盖：域参数合法性（p/n 位长）、点乘正确性（`x·G == 公钥 U`，RFC 6979 官方密钥对）、
/// 点在曲线判定、模逆、以及 ECDSA 验签原语（真签名通过 / 篡改 r 或 s 失败）。
///
/// 向量来源：RFC 6979 附录 A.2.5（P-256）与 A.2.6（P-384）官方标准密钥对与签名。
/// 消息哈希 `e` 取该消息（"sample"）的 SHA-256/SHA-384 值（FIPS 180-4 标准输出，经
/// .NET SHA256/SHA384 独立核算），位长与曲线阶一致且 < n，故 `e` 直接用哈希值。

///|
/// 点相等（仿射坐标，逐坐标比较）。
fn ec_point_eq(p1 : EcPoint?, p2 : EcPoint?) -> Bool {
  match (p1, p2) {
    (None, None) => true
    (Some(a), Some(b)) => big_cmp(a.x, b.x) == 0 && big_cmp(a.y, b.y) == 0
    _ => false
  }
}

///|
test "T-W6-EC-params: P-256 p/n 位长为 256，P-384 为 384（SEC 2 域参数）" {
  assert_eq(big_bit_length(p256_p), 256)
  assert_eq(big_bit_length(p256_n), 256)
  assert_eq(big_bit_length(p384_p), 384)
  assert_eq(big_bit_length(p384_n), 384)
}

///|
test "T-W6-EC-oncurve: 基点 G 与 RFC6979 公钥均在曲线上" {
  // P-256 G
  assert_true(ec_on_curve({ x: p256_gx, y: p256_gy, }, p256_params))
  // P-384 G
  assert_true(ec_on_curve({ x: p384_gx, y: p384_gy, }, p384_params))
  // RFC 6979 A.2.5 P-256 公钥 U
  assert_true(
    ec_on_curve(
      {
        x: big_from_hex(
          "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        ),
        y: big_from_hex(
          "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ),
      },
      p256_params,
    ),
  )
  // RFC 6979 A.2.6 P-384 公钥 U
  assert_true(
    ec_on_curve(
      {
        x: big_from_hex(
          "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
        ),
        y: big_from_hex(
          "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
        ),
      },
      p384_params,
    ),
  )
  // 非曲线点（坐标略改）应判 false（fail-closed）
  assert_true(
    !ec_on_curve(
      {
        x: big_from_hex(
          "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb7",
        ),
        y: big_from_hex(
          "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        ),
      },
      p256_params,
    ),
  )
}

///|
test "T-W6-EC-scalarmul: P-256 x·G == 公钥 U（RFC 6979 A.2.5 官方密钥对）" {
  let x = big_from_hex(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
  )
  let got = ec_jac_to_affine(
    ec_jac_scalar_mul(x, ec_jac_of({ x: p256_gx, y: p256_gy, }), p256_params),
    p256_params,
  )
  let want = Some({
    x: big_from_hex(
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
    ),
    y: big_from_hex(
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
    ),
  })
  assert_true(ec_point_eq(got, want))
}

///|
test "T-W6-EC-scalarmul: P-384 x·G == 公钥 U（RFC 6979 A.2.6 官方密钥对）" {
  let x = big_from_hex(
    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
  )
  let got = ec_jac_to_affine(
    ec_jac_scalar_mul(x, ec_jac_of({ x: p384_gx, y: p384_gy, }), p384_params),
    p384_params,
  )
  let want = Some({
    x: big_from_hex(
      "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
    ),
    y: big_from_hex(
      "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
    ),
  })
  assert_true(ec_point_eq(got, want))
}

///|
test "T-W6-EC-scalarmul: P-256 1·G == G；0·G == 无穷远点" {
  let g = { x: p256_gx, y: p256_gy, }
  let one = big_from_hex("1")
  assert_true(
    ec_point_eq(
      ec_jac_to_affine(
        ec_jac_scalar_mul(one, ec_jac_of(g), p256_params),
        p256_params,
      ),
      Some(g),
    ),
  )
  // 0·G 应为无穷远点
  assert_true(
    ec_jac_to_affine(
      ec_jac_scalar_mul(big_from_hex("0"), ec_jac_of(g), p256_params),
      p256_params,
    )
    is None,
  )
}

///|
test "T-W6-EC-modinv: 模逆自反性（a · a^-1 ≡ 1 mod p）" {
  let a = big_from_hex("deadbeef1234")
  let inv = ec_modinv(a, p256_p)
  let one = big_from_hex("1")
  assert_eq(big_to_hex(ec_mul_mod(a, inv, p256_p)), big_to_hex(one))
}

///|
test "T-W6-EC-verify: P-256 SHA-256(\"sample\") 真签名验签通过（RFC 6979 A.2.5）" {
  let qx = big_from_hex(
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
  )
  let qy = big_from_hex(
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
  // e = SHA-256("sample")
  let e = big_from_hex(
    "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
  )
  let r = big_from_hex(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
  )
  let s = big_from_hex(
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
  )
  assert_true(ec_ecdsa_verify(p256_params, qx, qy, e, r, s))
}

///|
test "T-W6-EC-verify: P-384 SHA-384(\"sample\") 真签名验签通过（RFC 6979 A.2.6）" {
  let qx = big_from_hex(
    "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
  )
  let qy = big_from_hex(
    "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
  )
  // e = SHA-384("sample")
  let e = big_from_hex(
    "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe",
  )
  let r = big_from_hex(
    "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
  )
  let s = big_from_hex(
    "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
  )
  assert_true(ec_ecdsa_verify(p384_params, qx, qy, e, r, s))
}

///|
test "T-W6-EC-verify: 篡改 r 验签失败（fail-closed）" {
  let qx = big_from_hex(
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
  )
  let qy = big_from_hex(
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
  let e = big_from_hex(
    "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
  )
  // 把 r 改 1 位
  let r_bad = big_from_hex(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3717",
  )
  let s = big_from_hex(
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
  )
  assert_true(!ec_ecdsa_verify(p256_params, qx, qy, e, r_bad, s))
}

///|
test "T-W6-EC-verify: 篡改 s 验签失败（fail-closed）" {
  let qx = big_from_hex(
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
  )
  let qy = big_from_hex(
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
  let e = big_from_hex(
    "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
  )
  let r = big_from_hex(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
  )
  let s_bad = big_from_hex(
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda9",
  )
  assert_true(!ec_ecdsa_verify(p256_params, qx, qy, e, r, s_bad))
}

///|
test "T-W6-EC-verify: r/s 越界与非法公钥一律 fail-closed" {
  let qx = big_from_hex(
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
  )
  let qy = big_from_hex(
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
  let e = big_from_hex(
    "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
  )
  let r = big_from_hex(
    "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
  )
  let s = big_from_hex(
    "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
  )
  // r = 0
  assert_true(!ec_ecdsa_verify(p256_params, qx, qy, e, big_from_hex("0"), s))
  // r = n（越上界）
  assert_true(!ec_ecdsa_verify(p256_params, qx, qy, e, p256_n, s))
  // s = 0
  assert_true(!ec_ecdsa_verify(p256_params, qx, qy, e, r, big_from_hex("0")))
  // 非法公钥（x 改 1 位 → 不在曲线上）
  let qx_bad = big_from_hex(
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb7",
  )
  assert_true(!ec_ecdsa_verify(p256_params, qx_bad, qy, e, r, s))
}

// ---------------------------------------------------------------------------
// 里程碑 b：EC SPKI / DER 签名解析 + v2 调度链白盒端到端（RFC 6979 A.2.5）
// ---------------------------------------------------------------------------

///|
/// P-256 EC SPKI（RFC 6979 A.2.5 公钥 U，未压缩点）。
fn ec_test_spki_p256() -> Bytes {
  bytes_from_hex(
    "3059301306072a8648ce3d020106082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
}

///|
/// RFC 6979 A.2.5 签名的 DER 编码 `SEQUENCE{INTEGER r, INTEGER s}`（均带 0x00 符号填充）。
fn ec_test_sig_der() -> Bytes {
  bytes_from_hex(
    "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
  )
}

///|
/// 构造单个 v2 signer 验签数据（白盒测试辅助）。
fn ec_test_signer(
  public_key : Bytes,
  alg_id : UInt32,
  sig : Bytes,
) -> SignerVerifyData {
  { signed_data: b"sample", signatures: [(alg_id, sig)], public_key, }
}

///|
test "T-W6-EC-b-spki: P-256 SPKI 解析出 P256 与公钥坐标" {
  match ec_public_key_from_spki(ec_test_spki_p256()) {
    Some((curve, qx, qy)) => {
      assert_true(curve is EcCurve::P256, msg="curve is P-256")
      assert_eq(
        big_to_hex(qx),
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
      )
      assert_eq(
        big_to_hex(qy),
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      )
    }
    None => fail("P-256 SPKI should parse")
  }
}

///|
test "T-W6-EC-b-spki: P-384 SPKI 解析出 P384 与公钥坐标" {
  let spki = bytes_from_hex(
    "3076301006072a8648ce3d020106052b8104002203620004ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
  )
  match ec_public_key_from_spki(spki) {
    Some((curve, qx, qy)) => {
      assert_true(curve is EcCurve::P384, msg="curve is P-384")
      assert_eq(
        big_to_hex(qx),
        "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
      )
      assert_eq(
        big_to_hex(qy),
        "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      )
    }
    None => fail("P-384 SPKI should parse")
  }
}

///|
test "T-W6-EC-b-spki: 坏 OID / 非 EC OID / BIT STRING 截断一律 None" {
  // ecPublicKey OID 末字节篡改（…02 01 → …02 02）。
  let bad_oid = bytes_from_hex(
    "3059301306072a8648ce3d020206082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
  assert_true(ec_public_key_from_spki(bad_oid) is None, msg="坏 OID")
  // 非 EC：RSA SPKI（OID 1.2.840.113549.1.1.1）。
  let rsa_spki = bytes_from_hex("3013300d06092a864886f70d010101050003020000")
  assert_true(ec_public_key_from_spki(rsa_spki) is None, msg="非 EC OID")
  // BIT STRING 长度改为 0x40（少 2 字节）：点长度不符。
  let bad_bit = bytes_from_hex(
    "3059301306072a8648ce3d020106082a8648ce3d0301070340000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
  )
  assert_true(ec_public_key_from_spki(bad_bit) is None, msg="BIT STRING 截断")
  // 外层非 SEQUENCE。
  assert_true(
    ec_public_key_from_spki(bytes_from_hex("03020000")) is None,
    msg="非 SEQUENCE",
  )
  assert_true(ec_public_key_from_spki(b"") is None, msg="空输入")
}

///|
test "T-W6-EC-b-der: 正确 DER 签名解析出 (r,s)" {
  match ec_sig_from_der(ec_test_sig_der()) {
    Some((r, s)) => {
      assert_eq(
        big_to_hex(r),
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
      )
      assert_eq(
        big_to_hex(s),
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
      )
    }
    None => fail("valid DER signature should parse")
  }
}

///|
test "T-W6-EC-b-der: 截断 / 非 SEQUENCE / 缺 INTEGER 一律 None" {
  let der = ec_test_sig_der()
  assert_true(ec_sig_from_der(der[0:20].to_owned()) is None, msg="截断")
  assert_true(ec_sig_from_der(b"\x02\x01\x01") is None, msg="非 SEQUENCE")
  // 只有 r，没有 s。
  assert_true(
    ec_sig_from_der(bytes_from_hex("3003020101")) is None,
    msg="缺 s",
  )
  assert_true(ec_sig_from_der(b"") is None, msg="空输入")
}

///|
test "T-W6-EC-b-v2: RFC 6979 向量走 v2 调度链 crypto_verified=true" {
  let signer = ec_test_signer(ec_test_spki_p256(), 0x0201U, ec_test_sig_der())
  let (ok, algo, detail) = verify_v2_signers([signer])
  assert_true(ok, msg="ECDSA signature verifies over signed data")
  assert_eq(algo, "SHA256withECDSA")
  assert_true(detail.contains("ECDSA"), msg="detail reports ECDSA")
}

///|
test "T-W6-EC-b-v2: 非 EC SPKI / 截断签名 / 篡改 r 一律 fail-closed" {
  // RSA SPKI + ECDSA 算法 ID：两条公钥解析路径都不适用 → false。
  let rsa_spki = bytes_from_hex("3013300d06092a864886f70d010101050003020000")
  let (ok0, _, detail0) = verify_v2_signers([
    ec_test_signer(rsa_spki, 0x0201U, ec_test_sig_der()),
  ])
  assert_true(!ok0, msg="非 EC SPKI 必须 fail-closed")
  assert_true(detail0.contains("SPKI"), msg="detail reports unparseable SPKI")
  // 签名 DER 截断。
  let der = ec_test_sig_der()
  let (ok1, _, _) = verify_v2_signers([
    ec_test_signer(ec_test_spki_p256(), 0x0201U, der[0:20].to_owned()),
  ])
  assert_true(!ok1, msg="截断签名必须 fail-closed")
  // 篡改 r（末字节 0x16 → 0x17）。
  let bad_r = bytes_from_hex(
    "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3717022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
  )
  let (ok2, _, _) = verify_v2_signers([
    ec_test_signer(ec_test_spki_p256(), 0x0201U, bad_r),
  ])
  assert_true(!ok2, msg="篡改 r 必须 fail-closed")
}

///|
test "T-W6-EC-trunc: SHA-512 摘要按曲线阶位长左截断" {
  // 64 字节摘要：前 32 字节任意，后 32 字节为 RFC 6979 A.2.5 的 e。
  let e_hex = "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
  let prefix = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  let digest = bytes_from_hex(prefix + e_hex)
  // P-256：左截断 256 位 → 后 32 字节。
  assert_eq(big_to_hex(ec_hash_to_e(digest, p256_params.n)), e_hex)
  // P-384：左截断 384 位 → 丢弃前 16 字节，保留后 48 字节。
  let expected_384 = big_to_hex(
    big_from_be_bytes(
      bytes_from_hex("00112233445566778899aabbccddeeff" + e_hex),
    ),
  )
  assert_eq(big_to_hex(ec_hash_to_e(digest, p384_params.n)), expected_384)
  // 前导零字节：截断量由哈希字节长度决定，不受整数实际位长影响。
  let e_bytes = bytes_from_hex(e_hex)
  let lz : Array[Byte] = []
  for b in bytes_from_hex(prefix) {
    lz.push(b)
  }
  lz.push(b'\x00')
  for i = 0; i < 31; i = i + 1 {
    lz.push(e_bytes[i])
  }
  let leading_zero = Bytes::from_array(lz[:])
  let expected_lz = big_to_hex(
    big_from_be_bytes(leading_zero[32:64].to_owned()),
  )
  assert_eq(big_to_hex(ec_hash_to_e(leading_zero, p256_params.n)), expected_lz)
  // 哈希位长不超过 n 位时不截断（SHA-256 + P-384）。
  let short = bytes_from_hex(e_hex)
  assert_eq(big_to_hex(ec_hash_to_e(short, p384_params.n)), e_hex)
}
