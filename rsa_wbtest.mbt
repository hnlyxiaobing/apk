///|
/// M6-RSA-a：RSA PKCS#1 v1.5 验签原语已知向量测试。
///
/// 向量由 Python `cryptography`（openssl）生成的 RSA-1024 密钥签名产生（见开发会话记录），
/// 覆盖 SHA-256 / SHA-512、篡改签名、错配摘要。期望：真签名验签通过，篡改/错配 fail-closed。

///|
/// 十六进制字符串 → Bytes（白盒测试辅助）。
fn bytes_from_hex(s : String) -> Bytes {
  let out : Array[Byte] = []
  for i = 0; i + 1 < s.length(); i = i + 2 {
    let hi = hex_val(s[i].to_int())
    let lo = hex_val(s[i + 1].to_int())
    out.push(((hi << 4) | lo).to_byte())
  }
  Bytes::from_array(out[:])
}

///|
/// 十六进制字符值 → Int32。
fn hex_val(v : Int32) -> Int32 {
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    0
  }
}

///|
/// 构造 RSA 公钥（仅服务白盒测试；生产构造走 `rsa_public_key_from_spki`）。
fn rsa_key(n : BigInt, e : BigInt) -> RsaPublicKey {
  { n, e, }
}

///|
test "T-W6-RSA-pkcs1: SHA-256 valid signature verifies" {
  let n = big_from_hex(
    "bdb9b10875ef349fd79af60d8f28bc4625a2afa41591cf7cfd0d246785eaa64b809005eca281447b28cd66142f07ba4e19691e4f52ea86021f470c3e0f613ca84b8465c3c652548d02e87357bf648115267f4433364e1ceee47a665efd7b91d54ac8fb2f06d1c8b95f4d8dca68718c47b548a1cfb6d4ab63c0adace0de4f29ad",
  )
  let e = big_from_hex("10001")
  let key = rsa_key(n, e)
  let digest = bytes_from_hex(
    "933c6d9895b9114f71805f661c2e567039a03f13827a35c723a23a1936b2da61",
  )
  let sig = bytes_from_hex(
    "b44984b9ad32b912c40389330efe906bbc7a030efd32150856e81cb60a54b3f4702426f95c0d0a6cb838df4e2027b9bdf88f0de2c00b8e7d14ef8cc03f24fa0e43be6f5e4959081717dbcf98491b1963aaedfc4d5a5f44999534ada98e468698d574bb992daa157ec91061bca2e853259f55f7fbdd37762ca9d0c35eed179446",
  )
  assert_true(rsa_verify_pkcs1(key, sig, digest, "SHA-256"))
}

///|
test "T-W6-RSA-pkcs1: SHA-512 valid signature verifies" {
  let n = big_from_hex(
    "bdb9b10875ef349fd79af60d8f28bc4625a2afa41591cf7cfd0d246785eaa64b809005eca281447b28cd66142f07ba4e19691e4f52ea86021f470c3e0f613ca84b8465c3c652548d02e87357bf648115267f4433364e1ceee47a665efd7b91d54ac8fb2f06d1c8b95f4d8dca68718c47b548a1cfb6d4ab63c0adace0de4f29ad",
  )
  let e = big_from_hex("10001")
  let key = rsa_key(n, e)
  let digest = bytes_from_hex(
    "32759acfd82c45d3d4a924e85d307c7dce021051c34d3ad63c2fcb569c1c35314d89e736fb5010cde98030249506ab170f703716c4854f97054da382197de714",
  )
  let sig = bytes_from_hex(
    "3598530661e3e5712ecf60530710f272375b23dc9e64c9aad621ec3890ffae50b55496e43610faedc3b8396779eded535f92a3714634d318b4e0d1459df93f863c2e4570e301d64844889df62b5fa4e0c7b4c3f347f11e7b81e52e3a4049f0642af5cfb19290477639fd597d2a4fee9b5c18955310f8f99c15ce6c844f323129",
  )
  assert_true(rsa_verify_pkcs1(key, sig, digest, "SHA-512"))
}

///|
test "T-W6-RSA-pkcs1: tampered signature fails" {
  let n = big_from_hex(
    "bdb9b10875ef349fd79af60d8f28bc4625a2afa41591cf7cfd0d246785eaa64b809005eca281447b28cd66142f07ba4e19691e4f52ea86021f470c3e0f613ca84b8465c3c652548d02e87357bf648115267f4433364e1ceee47a665efd7b91d54ac8fb2f06d1c8b95f4d8dca68718c47b548a1cfb6d4ab63c0adace0de4f29ad",
  )
  let e = big_from_hex("10001")
  let key = rsa_key(n, e)
  let digest = bytes_from_hex(
    "933c6d9895b9114f71805f661c2e567039a03f13827a35c723a23a1936b2da61",
  )
  let sig = bytes_from_hex(
    "b44984b9ad32b912c40388330efe906bbc7a030efd32150856e81cb60a54b3f4702426f95c0d0a6cb838df4e2027b9bdf88f0de2c00b8e7d14ef8cc03f24fa0e43be6f5e4959081717dbcf98491b1963aaedfc4d5a5f44999534ada98e468698d574bb992daa157ec91061bca2e853259f55f7fbdd37762ca9d0c35eed179446",
  )
  assert_true(!rsa_verify_pkcs1(key, sig, digest, "SHA-256"))
}

///|
test "T-W6-RSA-pkcs1: wrong digest fails (fail-closed)" {
  let n = big_from_hex(
    "bdb9b10875ef349fd79af60d8f28bc4625a2afa41591cf7cfd0d246785eaa64b809005eca281447b28cd66142f07ba4e19691e4f52ea86021f470c3e0f613ca84b8465c3c652548d02e87357bf648115267f4433364e1ceee47a665efd7b91d54ac8fb2f06d1c8b95f4d8dca68718c47b548a1cfb6d4ab63c0adace0de4f29ad",
  )
  let e = big_from_hex("10001")
  let key = rsa_key(n, e)
  let digest = bytes_from_hex(
    "d9298a10d1b0735837dc4bd85dac641b0f3cef27a47e5d53a54f2f3f5b2fcffa",
  )
  let sig = bytes_from_hex(
    "b44984b9ad32b912c40389330efe906bbc7a030efd32150856e81cb60a54b3f4702426f95c0d0a6cb838df4e2027b9bdf88f0de2c00b8e7d14ef8cc03f24fa0e43be6f5e4959081717dbcf98491b1963aaedfc4d5a5f44999534ada98e468698d574bb992daa157ec91061bca2e853259f55f7fbdd37762ca9d0c35eed179446",
  )
  assert_true(!rsa_verify_pkcs1(key, sig, digest, "SHA-256"))
}

///|
test "T-W6-RSA-pkcs1: wrong-length signature fails" {
  let n = big_from_hex(
    "bdb9b10875ef349fd79af60d8f28bc4625a2afa41591cf7cfd0d246785eaa64b809005eca281447b28cd66142f07ba4e19691e4f52ea86021f470c3e0f613ca84b8465c3c652548d02e87357bf648115267f4433364e1ceee47a665efd7b91d54ac8fb2f06d1c8b95f4d8dca68718c47b548a1cfb6d4ab63c0adace0de4f29ad",
  )
  let e = big_from_hex("10001")
  let key = rsa_key(n, e)
  let digest = bytes_from_hex(
    "933c6d9895b9114f71805f661c2e567039a03f13827a35c723a23a1936b2da61",
  )
  // 截短一个字节的签名
  let sig = bytes_from_hex(
    "b44984b9ad32b912c40389330efe906bbc7a030efd32150856e81cb60a54b3f4702426f95c0d0a6cb838df4e2027b9bdf88f0de2c00b8e7d14ef8cc03f24fa0e43be6f5e4959081717dbcf98491b1963aaedfc4d5a5f44999534ada98e468698d574bb992daa157ec91061bca2e853259f55f7fbdd37762ca9d0c35eed17944",
  )
  assert_true(!rsa_verify_pkcs1(key, sig, digest, "SHA-256"))
}

///|
test "T-W6-RSA-pkcs1: unsupported hash name fails (fail-closed)" {
  let n = big_from_hex(
    "bdb9b10875ef349fd79af60d8f28bc4625a2afa41591cf7cfd0d246785eaa64b809005eca281447b28cd66142f07ba4e19691e4f52ea86021f470c3e0f613ca84b8465c3c652548d02e87357bf648115267f4433364e1ceee47a665efd7b91d54ac8fb2f06d1c8b95f4d8dca68718c47b548a1cfb6d4ab63c0adace0de4f29ad",
  )
  let e = big_from_hex("10001")
  let key = rsa_key(n, e)
  let digest = bytes_from_hex(
    "933c6d9895b9114f71805f661c2e567039a03f13827a35c723a23a1936b2da61",
  )
  let sig = bytes_from_hex(
    "b44984b9ad32b912c40389330efe906bbc7a030efd32150856e81cb60a54b3f4702426f95c0d0a6cb838df4e2027b9bdf88f0de2c00b8e7d14ef8cc03f24fa0e43be6f5e4959081717dbcf98491b1963aaedfc4d5a5f44999534ada98e468698d574bb992daa157ec91061bca2e853259f55f7fbdd37762ca9d0c35eed179446",
  )
  assert_true(!rsa_verify_pkcs1(key, sig, digest, "SHA-1"))
}

///|
test "T-W6-RSA-pss: known vector (EMSA-PSS-VERIFY)" {
  let key = match
    rsa_public_key_from_spki(
      bytes_from_hex(
        "30819f300d06092a864886f70d010101050003818d0030818902818100cabfbdcec805d6844ee428427e5aade60695a99d58d0a9c0d4c8acc224c1e594b7565f638f227f5a990bd7ffacad35d236c6918195eecc7bf17dd4ed5e7e693da3f2c7f0e117c281a0709f907921ff9d90be75751d09b5ac00dfbb8d755b1da5b338948209789756ef4535cd0e3b405ee7b9ca8e92fb907b0409140d38cc726f0203010001",
      ),
    ) {
    Some(k) => k
    None => fail("spki parse failed")
  }
  let sig = bytes_from_hex(
    "30c19d0c54e4a559b008b4b45242575d00530530b42ff47c8ef5835759356cd968336a48d2dcf50d99773bda03427be4c4daf0cb87c903bf04d5e26763cafe3b217b4e74c80e7aa56294a4b915b35f0180893f6384b7295df6564c5274442d6d5c37777d78cd85d535abd8245d2b145a3c7acfc01af2e165afd7ef2fbc8b698b",
  )
  let dg = bytes_from_hex(
    "5d1961d33b1b26035f275173addb3ed49f4f1912bf9b8ea2bcb6df88480c5057",
  )
  assert_true(
    rsa_verify_pss(key, sig, dg, "SHA-256"),
    msg="PSS known vector verifies",
  )
  // 篡改签名的最后一位必须失败（fail-closed）。
  let bad : Array[Byte] = []
  for b in sig {
    bad.push(b)
  }
  bad[bad.length() - 1] = (bad[bad.length() - 1].to_int() ^ 0x01).to_byte()
  assert_true(
    !rsa_verify_pss(key, Bytes::from_array(bad[:]), dg, "SHA-256"),
    msg="tampered PSS fails",
  )
  // 错配摘要必须失败。
  let wrong = bytes_from_hex(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_true(
    !rsa_verify_pss(key, sig, wrong, "SHA-256"),
    msg="wrong digest fails",
  )
}

///|
/// 测试辅助：构造 n 个重复字节。
fn rsa_t_repeat(b : Byte, n : Int32) -> Array[Byte] {
  let out : Array[Byte] = []
  for i = 0; i < n; i = i + 1 {
    out.push(b)
  }
  out
}

///|
/// 测试辅助：拼接字节段。
fn rsa_t_cat(parts : Array[Array[Byte]]) -> Bytes {
  let out : Array[Byte] = []
  for p in parts {
    for b in p {
      out.push(b)
    }
  }
  Bytes::from_array(out[:])
}

///|
/// W6 覆盖率巡检：RSA 验签入口的零密钥 / 零指数 fail-closed 返回。
/// 这些分支在正常样本下不可达（SPKI 解析已拒绝零值），属防御性返回，直接构造密钥钉住。
test "W6 hardening: RSA 验签零模数/零指数 fail-closed" {
  let zero = big_zero()
  let one = big_from_hex("1")
  let sig = rsa_t_cat([rsa_t_repeat(0x00, 127), [0x01]])
  let digest = rsa_t_cat([rsa_t_repeat(0x11, 32)])
  assert_true(!rsa_verify_pkcs1(rsa_key(zero, one), sig, digest, "SHA-256"))
  assert_true(
    !rsa_verify_pkcs1(rsa_key(big_from_hex("ff"), zero), sig, digest, "SHA-256"),
  )
  assert_true(!rsa_verify_pss(rsa_key(zero, one), sig, digest, "SHA-256"))
  assert_true(
    !rsa_verify_pss(rsa_key(big_from_hex("ff"), zero), sig, digest, "SHA-256"),
  )
}

///|
/// W6 覆盖率巡检：PKCS#1 v1.5 填充畸形分支（EM[1]!=01、非 FF、无分隔符、
/// DigestInfo 长度/前缀不符、模数过小）。用 e=1 的测试公钥使 `m = EM`，从而可直接
/// 构造任意编码块——这些分支对攻击者可控的签名值真实可达，全部必须返回 false。
test "W6 hardening: PKCS#1 v1.5 填充畸形一律 fail-closed" {
  let key = rsa_key(
    big_from_be_bytes(Bytes::from_array(rsa_t_repeat(0xff, 128)[:])),
    big_from_hex("1"),
  )
  let digest = rsa_t_cat([rsa_t_repeat(0x11, 32)])
  // sep 前出现非 FF（0x02）。
  let em_nonff = rsa_t_cat([[0x00, 0x01, 0x02], rsa_t_repeat(0xff, 125)])
  assert_true(!rsa_verify_pkcs1(key, em_nonff, digest, "SHA-256"))
  // 无 0x00 分隔符。
  let em_nosep = rsa_t_cat([[0x00, 0x01], rsa_t_repeat(0xff, 126)])
  assert_true(!rsa_verify_pkcs1(key, em_nosep, digest, "SHA-256"))
  // DigestInfo 长度不符。
  let em_badlen = rsa_t_cat([
    [0x00, 0x01],
    rsa_t_repeat(0xff, 100),
    [0x00],
    rsa_t_repeat(0xaa, 25),
  ])
  assert_true(!rsa_verify_pkcs1(key, em_badlen, digest, "SHA-256"))
  // DigestInfo 前缀不符。
  let em_badprefix = rsa_t_cat([
    [0x00, 0x01],
    rsa_t_repeat(0xff, 74),
    [0x00],
    rsa_t_repeat(0xaa, 51),
  ])
  assert_true(!rsa_verify_pkcs1(key, em_badprefix, digest, "SHA-256"))
  // 不支持摘要名。
  let em_ok = rsa_t_cat([[0x00, 0x01], rsa_t_repeat(0xff, 74), [0x00]])
  assert_true(!rsa_verify_pkcs1(key, em_ok, digest, "SHA-1"))
  // 模数太小，容纳不下 DigestInfo。
  assert_true(
    !rsa_verify_pkcs1(
      rsa_key(big_from_hex("c5"), big_from_hex("1")),
      bytes_from_hex("01"),
      digest,
      "SHA-256",
    ),
  )
}

///|
/// W6 覆盖率巡检：PSS 验证的结构性失败返回（空摘要、emLen 不足、尾字节非 0xbc、
/// 未用高位非 0、MGF1 不可用、PS 非全 0、分隔符非 0x01、H' 长度不符）。
/// 均用 e=1 测试公钥直接构造 EM；任意一条都必须 fail-closed。
test "W6 hardening: PSS 结构畸形与非常规摘要长度一律 fail-closed" {
  let n128 = big_from_be_bytes(Bytes::from_array(rsa_t_repeat(0xff, 128)[:]))
  let key = rsa_key(n128, big_from_hex("1"))
  let dg32 = rsa_t_cat([rsa_t_repeat(0x11, 32)])
  // 空摘要。
  assert_true(
    !rsa_verify_pss(
      key,
      rsa_t_cat([[0x01], rsa_t_repeat(0x00, 127)]),
      b"",
      "SHA-256",
    ),
  )
  // emLen < hLen + saltLen + 2（512 位模数 + SHA-256）。
  let n512 = big_from_be_bytes(Bytes::from_array(rsa_t_repeat(0xff, 64)[:]))
  assert_true(
    !rsa_verify_pss(
      rsa_key(n512, big_from_hex("1")),
      rsa_t_cat([rsa_t_repeat(0x00, 63), [0x01]]),
      dg32,
      "SHA-256",
    ),
  )
  // EM 尾字节非 0xbc。
  assert_true(
    !rsa_verify_pss(
      key,
      rsa_t_cat([rsa_t_repeat(0x00, 127), [0x01]]),
      dg32,
      "SHA-256",
    ),
  )
  // 未用最高位非 0（emBits=1023）。
  assert_true(
    !rsa_verify_pss(
      key,
      rsa_t_cat([[0x80], rsa_t_repeat(0x00, 126), [0xbc]]),
      dg32,
      "SHA-256",
    ),
  )
  // MGF1 不支持的摘要名（20 字节摘要 + SHA-1）。
  assert_true(
    !rsa_verify_pss(
      key,
      rsa_t_cat([[0x00], rsa_t_repeat(0x00, 126), [0xbc]]),
      rsa_t_cat([rsa_t_repeat(0x11, 20)]),
      "SHA-1",
    ),
  )
  // PS 非全 0。
  let dg20 = rsa_t_cat([rsa_t_repeat(0x11, 20)])
  let em_ps_nonzero = bytes_from_hex(
    "74311a65e5a3f56d1eafe2cc786a2618d0967c37d42250566275f9569f8cc65931c02c34aea06163f7cf71373b773c0fb314b87916e10143d84583a1d24dcf41480e5b62a94a2c7064c7f2548cdf6866b7969d454f694a24189967121e5938852e9b29495b6d913feed50f3333333333333333333333333333333333333333bc",
  )
  assert_true(!rsa_verify_pss(key, em_ps_nonzero, dg20, "SHA-256"))
  // DB 分隔符非 0x01。
  let em_bad_sep = bytes_from_hex(
    "75311a65e5a3f56d1eafe2cc786a2618d0967c37d42250566275f9569f8cc65931c02c34aea06163f7cf71373b773c0fb314b87916e10143d84583a1d24dcf41480e5b62a94a2c7064c7f2548cdf6866b7969d454f694b04189967121e5938852e9b29495b6d913feed50f3333333333333333333333333333333333333333bc",
  )
  assert_true(!rsa_verify_pss(key, em_bad_sep, dg20, "SHA-256"))
  // 结构合法但摘要长度与 SHA-256 不符（H' 长度检查）。
  let em_hp_len = bytes_from_hex(
    "75311a65e5a3f56d1eafe2cc786a2618d0967c37d42250566275f9569f8cc65931c02c34aea06163f7cf71373b773c0fb314b87916e10143d84583a1d24dcf41480e5b62a94a2c7064c7f2548cdf6866b7969d454f694a24189967121e5938852e9b29495b6d913feed50f3333333333333333333333333333333333333333bc",
  )
  assert_true(!rsa_verify_pss(key, em_hp_len, dg20, "SHA-256"))
  // 模数过小导致 emBits<=0（n=1，s=0）。
  assert_true(
    !rsa_verify_pss(
      rsa_key(big_from_hex("1"), big_from_hex("1")),
      bytes_from_hex("00"),
      dg32,
      "SHA-256",
    ),
  )
  // m 的大端字节数超过 emLen（n=2^504+1，s=2^504，emLen=63）。
  let n_504 = big_from_be_bytes(
    rsa_t_cat([[0x01], rsa_t_repeat(0x00, 62), [0x01]]),
  )
  let sig_504 = rsa_t_cat([[0x01], rsa_t_repeat(0x00, 63)])
  assert_true(
    !rsa_verify_pss(rsa_key(n_504, big_from_hex("1")), sig_504, dg32, "SHA-256"),
  )
}

///|
/// 测试辅助：Option 是否为 None（RsaPublicKey 未派生 Eq）。
fn rsa_t_is_none(o : RsaPublicKey?) -> Bool {
  match o {
    None => true
    Some(_) => false
  }
}

///|
/// W6 覆盖率巡检：SPKI 解析的空 BIT STRING / 零模数 / 零指数拒绝分支。
test "W6 hardening: SPKI 空 BIT STRING 与零值 RSA 公钥一律拒绝" {
  // 合法 rsaEncryption 算法标识 + 空 BIT STRING。
  assert_true(
    rsa_t_is_none(
      rsa_public_key_from_spki(
        bytes_from_hex("3011300d06092a864886f70d01010105000300"),
      ),
    ),
    msg="空 BIT STRING",
  )
  // n = 0。
  assert_true(
    rsa_t_is_none(
      rsa_public_key_from_spki(
        bytes_from_hex(
          "301c300d06092a864886f70d0101010500030b0030080201000203010001",
        ),
      ),
    ),
    msg="零模数",
  )
  // e = 0。
  assert_true(
    rsa_t_is_none(
      rsa_public_key_from_spki(
        bytes_from_hex(
          "301c300d06092a864886f70d0101010500030b0030080203010001020100",
        ),
      ),
    ),
    msg="零指数",
  )
}
