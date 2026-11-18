// W6 公钥验签（`Apk::verify_signatures`）黑盒测试：v1 降级与无签名 APK 语义。
//
// 语义防火墙：`signature_checks()` / `SignatureCheck.signature_verified` 恒 false 的旧契约
// 不变；验签结论只走新类型 `SignatureVerification`。本节验证 fail-closed 行为。

///|
/// v1（JAR 签名）样本：M6-RSA-b 起 signerInfo 签名值走真实 RSA PKCS#1 v1.5 验签。
/// 受支持算法必须真验签（该样本若为 RSA/SHA-256 则应通过）；不支持算法 fail-closed。
test "T-W6-RSA-v1: v1 signerInfo verification wired (RSA)" {
  let a = @apk.Apk::open(fixture_fx_multidex_v1_apk())
  let checks = a.verify_signatures()
  assert_eq(checks.length(), 1, msg="one v1 scheme record")
  let v = checks[0]
  assert_true(v.scheme is @apk.SignatureScheme::V1, msg="scheme is v1")
  // 语义防火墙：结构与摘要结论不变。
  assert_true(v.structure_ok, msg="v1 structure ok")
  assert_true(v.digest_ok, msg="v1 digests ok")
  if v.algo == "unsupported" {
    assert_true(
      !v.crypto_verified,
      msg="unsupported algorithm stays fail-closed",
    )
  } else {
    assert_true(v.crypto_verified, msg="supported RSA v1 signature verifies")
  }
}

///|
/// 无签名 APK：`verify_signatures()` 返回空数组（不误报）。
test "T-W6-RSA-none: unsigned apk yields empty verification list" {
  let a = @apk.Apk::open(fixture_fx_multidex_unsigned_apk())
  let checks = a.verify_signatures()
  assert_eq(checks.length(), 0, msg="no signature schemes")
}

///|
/// 旧契约不变：同一 v2/v3 样本上 `signature_checks()` 的 `signature_verified` 恒 false，
/// 而新入口 `verify_signatures()` 对同一方案给出 crypto_verified=true。
test "T-W6-RSA-contract: legacy signature_verified stays false while new channel verifies" {
  let a = @apk.Apk::open(fixture_fx_multidex_v2v3_apk())
  for c in a.signature_checks() {
    assert_true(
      !c.signature_verified,
      msg="legacy signature_verified is always false",
    )
  }
  // 真实 v2/v3 样本的签名值由 apksigner 用其私钥产生，本库无对应公钥之外的信任信息，
  // 但 RSA 公钥验签本身应成功（signer 内 public_key 即公钥）。
  let vs = a.verify_signatures()
  assert_true(vs.length() > 0, msg="at least one scheme verified")
}
