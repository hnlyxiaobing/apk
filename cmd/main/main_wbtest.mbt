///|
/// `apk-cli extract` 限额常量回归：CLI 以 `max_extract_bytes`（256 MiB）作为 `entry_capped`
/// 的限额传给库（W2 内存防线）。该常量必须为正且落在 Int32 可表示范围内，保证
/// `entry_capped(name, max_extract_bytes.to_int64())` 的限额恒为合法正值。
test "extract cap constant is positive in-range Int32" {
  assert_true(max_extract_bytes > 0)
  // 256 MiB = 268435456，小于 Int32 上限 2147483647。
  assert_eq(max_extract_bytes, 268435456)
}

///|
/// `verify` 判定口径回归：必须是 structure_ok && digest_ok && crypto_verified 三者同时成立。
/// 反例来自真实 apksigner oracle：v1 清单摘要被篡改时 signerInfo 签名值仍有效，
/// 但 apksigner 判未通过——CLI 不能只看 crypto_verified。
test "verify verdict requires structure+digest+crypto" {
  let mk = fn(
    structure_ok : Bool,
    digest_ok : Bool,
    crypto_verified : Bool,
  ) -> @apk.SignatureVerification {
    {
      scheme: @apk.SignatureScheme::V1,
      structure_ok,
      digest_ok,
      crypto_verified,
      algo: "SHA256withRSA",
      detail: "",
    }
  }
  assert_true(verification_passed(mk(true, true, true)))
  assert_true(!verification_passed(mk(true, false, true)))
  assert_true(!verification_passed(mk(false, true, true)))
  assert_true(!verification_passed(mk(true, true, false)))
}
