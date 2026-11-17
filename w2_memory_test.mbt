// W2 解压炸弹内存防线测试（docs/2026-11-16-container-trust-dev-plan.md W2；
// docs/2026-11-16-test-system-design.md §4.1 P7 内存上界律、§6.1 F13 限额提取）。
//
// 覆盖验收：T-W2-1 伪造声明尺寸 / 膨胀比样本返回 None（预检即拒，不 panic、不 raise）；
// T-W2-2 边界 ±1 字节；T-W2-4 正常样本 `entry_capped` 与 `entry` 输出逐字节一致；
// T-W2-3 CLI 退出码 / 错误文案回归由 CLI 二进制在门禁阶段手工验证（记录见 CHANGELOG M2）。
//
// 复用 apk_test.mbt 的 fixture 辅助：ZSpec / zspec / zspec_deflated / zspec_override /
// build_zip / deflate_stored / t_crc32。

///|
/// 构造一个 `declared_size` 伪造为 `decl`（stored 条目，压缩尺寸用实际值）。
/// 用于 T-W2-1a / T-W2-2 声明尺寸预检。
fn stored_decl(name : String, data : Bytes, decl : Int32) -> ZSpec {
  {
    name,
    comp_method: 0,
    data,
    extra_pad: 0,
    cd_extra: b"",
    bad_crc: false,
    declared_size: Some(decl),
    compressed_size: None,
  }
}

///|
/// 重复 `b` 共 `n` 字节。
fn rep_bytes(b : Byte, n : Int32) -> Bytes {
  let out : Array[Byte] = []
  for i = 0; i < n; i = i + 1 {
    out.push(b)
  }
  Bytes::from_array(out[:])
}

///|
/// T-W2-1a：伪造声明尺寸超限（stored，declared = limit+1）。
/// `entry` 若被调用会 raise "stored entry has mismatched sizes"；但 `entry_capped`
/// 的声明尺寸预检（step 1）在触碰解压前直接返回 None——证明「预检即拒」。
test "W2 T-W2-1a declared size pre-check rejects without extracting" {
  let limit : Int64 = 100000L
  let spec = stored_decl("a.txt", b"abc", 100001)
  let apk = @apk.Apk::open(build_zip([spec], None))
  // 对照：未限额的 entry 对「声明尺寸与实际压缩尺寸不符」的 stored 条目会 raise。
  let entry_raises = try {
    ignore(apk.entry("a.txt"))
    false
  } catch {
    _ => true
  } noraise {
    _ => false
  }
  assert_true(entry_raises, msg="对照条目应因尺寸不符而 raise")
  // entry_capped：声明尺寸预检直接拒绝，返回 None 而非 raise。
  assert_true(apk.entry_capped("a.txt", limit) is None)
}

///|
/// T-W2-1b：膨胀比预检（step 2）——compressed_size > limit/1032 即拒绝。
/// 该条目其实可正常解压（`entry` 返回 92 字节），但 sound 上界预检在 inflate 前就拒绝，
/// 证明伪造巨大 deflate 流无法先耗尽内存。
test "W2 T-W2-1b ratio pre-check rejects oversized deflate stream" {
  let limit : Int64 = 100000L
  // limit/1032 = 96（整除向下取整）；92 字节 payload 的 stored 块压缩后 ≈ 97 字节 > 96。
  let data = rep_bytes(b'a', 92)
  let spec = zspec_deflated("big.bin", data)
  let apk = @apk.Apk::open(build_zip([spec], None))
  // 对照：该 deflate 流合法且只有 92 字节，未限额 entry 成功解压。
  assert_true(
    apk.entry("big.bin") == data,
    msg="对照 deflate 条目应可正常解压",
  )
  // 限额下因膨胀比超限在 inflate 前拒绝。
  assert_true(apk.entry_capped("big.bin", limit) is None)
}

///|
/// T-W2-2：声明尺寸边界 ±1 字节（stored，limit 内成功、超 1 字节即拒绝）。
test "W2 T-W2-2 declared size boundary plus-minus 1 byte" {
  let limit : Int64 = 4096L
  // 恰好等于 limit → Some（边界含）。
  let at = stored_decl("at.txt", rep_bytes(b'x', 4096), 4096)
  let apk_at = @apk.Apk::open(build_zip([at], None))
  let got_at = apk_at.entry_capped("at.txt", limit)
  assert_true(got_at is Some(_), msg="size==limit 应允许")
  assert_true(got_at.unwrap().length() == 4096)
  // 超过 1 字节 → None。
  let over = stored_decl("over.txt", rep_bytes(b'y', 4097), 4097)
  let apk_over = @apk.Apk::open(build_zip([over], None))
  assert_true(apk_over.entry_capped("over.txt", limit) is None)
}

///|
/// T-W2-4：正常样本 `entry_capped` 与 `entry` 输出逐字节一致（stored + deflate 双通道）。
test "W2 T-W2-4 capped matches uncapped for in-limit entries" {
  let limit : Int64 = 1000000L
  let apk = @apk.Apk::open(
    build_zip(
      [zspec("ok.txt", b"hello"), zspec_deflated("d.txt", b"deflate-payload")],
      None,
    ),
  )
  let a = apk.entry_capped("ok.txt", limit)
  let b = apk.entry_capped("d.txt", limit)
  assert_true(a is Some(_) && b is Some(_), msg="限额内条目应返回 Some")
  assert_true(a.unwrap() == apk.entry("ok.txt"))
  assert_true(b.unwrap() == apk.entry("d.txt"))
}

///|
/// API 契约：`limit <= 0` 视为用法错误，按既有变体 `BadCentralDirectory(0, "invalid limit")` 报告。
test "W2 entry_capped invalid limit reports BadCentralDirectory" {
  let apk = @apk.Apk::open(build_zip([zspec("a.txt", b"x")], None))
  try ignore(apk.entry_capped("a.txt", 0L)) catch {
    @apk.ApkError::BadCentralDirectory(off, detail) => {
      assert_eq(off, 0)
      assert_eq(detail, "invalid limit")
    }
    _ => fail("expected BadCentralDirectory for invalid limit")
  } noraise {
    _ => fail("expected BadCentralDirectory for invalid limit")
  }
}

///|
/// API 契约：条目不存在仍 raise `EntryNotFound`（解析错误，与 `entry` 一致）。
test "W2 entry_capped raises EntryNotFound for missing entry" {
  let apk = @apk.Apk::open(build_zip([zspec("a.txt", b"x")], None))
  try ignore(apk.entry_capped("nope.txt", 1000L)) catch {
    @apk.ApkError::EntryNotFound(_) => ()
    _ => fail("expected EntryNotFound")
  } noraise {
    _ => fail("expected EntryNotFound")
  }
}
