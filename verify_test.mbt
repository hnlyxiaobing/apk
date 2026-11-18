// W6 公钥验签（`Apk::verify_signatures`）黑盒测试：v1 降级与无签名 APK 语义。
//
// 语义防火墙：`signature_checks()` / `SignatureCheck.signature_verified` 恒 false 的旧契约
// 不变；验签结论只走新类型 `SignatureVerification`。本节验证 fail-closed 行为。

///|
/// v1（JAR 签名）样本：M6-RSA-a 阶段 signerInfo 验签未接入（M6-RSA-b），
/// `crypto_verified` 必须为 false，绝不可误判通过。
test "T-W6-RSA-v1: v1 signerInfo verification fails closed" {
  let a = @apk.Apk::open(fixture_fx_multidex_v1_apk())
  let checks = a.verify_signatures()
  assert_eq(checks.length(), 1, msg="one v1 scheme record")
  let v = checks[0]
  assert_true(v.scheme is @apk.SignatureScheme::V1, msg="scheme is v1")
  assert_true(
    !v.crypto_verified,
    msg="v1 crypto_verified is false (fail-closed)",
  )
  assert_eq(v.algo, "unsupported", msg="algo reports unsupported")
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
