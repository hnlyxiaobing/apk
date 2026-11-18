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
