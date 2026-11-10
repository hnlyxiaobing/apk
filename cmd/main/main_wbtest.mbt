///|
/// `apk-cli extract` 输出大小上限回归测试。
test "extract output size cap boundary" {
  assert_true(is_extract_size_allowed(0))
  assert_true(is_extract_size_allowed(max_extract_bytes))
  assert_eq(is_extract_size_allowed(max_extract_bytes + 1), false)
}
