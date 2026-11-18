///|
/// W5-后续 verity 树重算黑盒测试（公开 API `Apk::verity_tree_check`）。
///
/// 测试工具（build_zip / sig_block_of / zspec / scheme_value / scheme_value_with_verity_digest /
/// push_u32 / push_u64_small）来自同测试包的 apk_test.mbt。
///
/// 黑盒无法调用私有 `verity_root`，故端到端「真实根比对为 true」的用例放在白盒
/// `verity_tree_wbtest.mbt`；此处覆盖：普通 v2 无 verity 摘要 → None，以及声明根被篡改
/// （非真实重算根）→ `tree_recomputed_ok == false`（fail-closed）。

///|
/// 40 字节伪造 verity 摘要（root 置乱 + source_len=0），非真实重算根。
fn bogus_verity_digest() -> Bytes {
  let a : Array[Byte] = []
  for i = 0; i < 32; i = i + 1 {
    a.push(b'\xaa')
  }
  push_u64_small(a, 0)
  Bytes::from_array(a[:])
}

///|
/// 普通 v2 APK（digests=0，无 verity 摘要）→ `verity_tree_check()` 返回 None。
test "W5-后续 verity_tree_check: ordinary v2 returns None" {
  let v2_block = sig_block_of([(0x7109871aU, scheme_value(b"cert", 0))])
  let apk = @apk.Apk::open(
    build_zip([zspec("foo.txt", b"hello")], Some(v2_block)),
  )
  assert_true(apk.verity_tree_check() is None)
}

///|
/// 声明 verity 摘要存在但 root 被篡改（非真实重算根）→ Some，`tree_recomputed_ok == false`。
test "W5-后续 verity_tree_check: tampered declared root => false" {
  let digest = bogus_verity_digest()
  let v2_block = sig_block_of([
    (0x7109871aU, scheme_value_with_verity_digest(b"cert", digest, 0)),
  ])
  let apk = @apk.Apk::open(
    build_zip([zspec("foo.txt", b"hello")], Some(v2_block)),
  )
  let c = apk.verity_tree_check()
  guard c is Some(info) else { fail("expected Some(VerityTreeCheck)") }
  assert_eq(info.block_id, 0x42726577U)
  assert_eq(info.hash_algorithm, "SHA-256")
  assert_eq(info.block_size, 4096)
  assert_eq(info.salt_hex, "0000000000000000")
  assert_eq(info.source_len, 0UL)
  assert_true(!info.tree_recomputed_ok, msg="篡改声明根必须 fail-closed")
  assert_eq(
    info.declared_root_hash_hex,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  )
}
