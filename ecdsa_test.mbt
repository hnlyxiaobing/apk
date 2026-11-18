///|
/// W6-后续 里程碑 a：ECDSA 验签公开入口黑盒测试（RFC 6979 权威向量）。
///
/// 经 `ecdsa_verify_raw`（纯加法公开 API）验证：真签名验签通过、篡改 r/s 失败、
/// 畸形/越界输入 fail-closed（不 panic）、未知曲线拒绝。向量来自 RFC 6979
/// 附录 A.2.5（P-256）与 A.2.6（P-384）；`e` 为该消息 SHA-256/SHA-384 标准值。

///|
test "T-W6-EC-pub: P-256 SHA-256(\"sample\") 真签名验签通过" {
  assert_true(
    @apk.ecdsa_verify_raw(
      @apk.EcCurve::P256,
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ),
  )
}

///|
test "T-W6-EC-pub: P-384 SHA-384(\"sample\") 真签名验签通过" {
  assert_true(
    @apk.ecdsa_verify_raw(
      @apk.EcCurve::P384,
      "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
      "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe",
      "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
      "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
    ),
  )
}

///|
test "T-W6-EC-pub: 篡改 r 验签失败（fail-closed）" {
  assert_true(
    !@apk.ecdsa_verify_raw(
      @apk.EcCurve::P256,
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3717",
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ),
  )
}

///|
test "T-W6-EC-pub: 篡改 s 验签失败（fail-closed）" {
  assert_true(
    !@apk.ecdsa_verify_raw(
      @apk.EcCurve::P384,
      "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13",
      "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      "9a9083505bc92276aec4be312696ef7bf3bf603f4bbd381196a029f340585312313bca4a9b5b890efee42c77b1ee25fe",
      "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46",
      "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac9",
    ),
  )
}

///|
test "T-W6-EC-pub: 未知曲线拒绝（fail-closed）" {
  assert_true(
    !@apk.ecdsa_verify_raw(
      @apk.EcCurve::Unknown,
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ),
  )
}

///|
test "T-W6-EC-pub: 畸形十六进制 / 空串一律 false 不 panic" {
  // 公钥 x 非法字符
  assert_true(
    !@apk.ecdsa_verify_raw(
      @apk.EcCurve::P256,
      "zzzzfed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ),
  )
  // 签名 s 为空串
  assert_true(
    !@apk.ecdsa_verify_raw(
      @apk.EcCurve::P256,
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
      "",
    ),
  )
  // 全部为空串
  assert_true(!@apk.ecdsa_verify_raw(@apk.EcCurve::P256, "", "", "", "", ""))
}

///|
test "T-W6-EC-pub: r 越界（r=n）与非法公钥拒绝（fail-closed）" {
  let n_p256 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
  // r = n（越上界）
  assert_true(
    !@apk.ecdsa_verify_raw(
      @apk.EcCurve::P256,
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
      n_p256,
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ),
  )
  // 公钥 x 改 1 位 → 不在曲线上
  assert_true(
    !@apk.ecdsa_verify_raw(
      @apk.EcCurve::P256,
      "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb7",
      "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
      "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
      "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ),
  )
}
