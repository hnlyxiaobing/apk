///|
/// `apk-cli extract` 限额常量回归：CLI 以 `max_extract_bytes`（256 MiB）作为 `entry_capped`
/// 的限额传给库（W2 内存防线）。该常量必须为正且落在 Int32 可表示范围内，保证
/// `entry_capped(name, max_extract_bytes.to_int64())` 的限额恒为合法正值。
test "extract cap constant is positive in-range Int32" {
  assert_true(max_extract_bytes > 0)
  // 256 MiB = 268435456，小于 Int32 上限 2147483647。
  assert_eq(max_extract_bytes, 268435456)
}
