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
