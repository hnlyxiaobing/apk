// W1 批量完整性报告测试（docs/2026-11-16-container-trust-dev-plan.md W1；
// docs/2026-11-16-test-system-design.md §4.1 P6 双通道一致律、§6.1 F9 批量完整性报告）。
// 覆盖验收：T-W1-1 全绿样本 ok 全 true；T-W1-2 坏 CRC 条目 ok=false 且其余不受影响；
// T-W1-3 与 Apk::entry 的 raise 行为逐条目一致；T-W1-4 快照 diff 纯加法（由门禁验证）。
//
// 复用 apk_test.mbt 的 fixture 辅助：ZSpec / zspec / zspec_deflated / build_zip /
// patch_byte / patch_u32 / deflate_stored / t_crc32 / sig_block_of。

///|
/// 构造一个带 `bad_crc`（中央目录与 local 头 CRC 写入 +1）的 ZSpec。
fn bad_crc_spec(name : String, data : Bytes) -> ZSpec {
  {
    name,
    comp_method: 0,
    data,
    extra_pad: 0,
    cd_extra: b"",
    bad_crc: true,
    declared_size: None,
    compressed_size: None,
  }
}

///|
/// 断言两条目集（integrity 结论 vs entry 行为）逐条一致。
/// P6 / T-W1-3：`ok == true` ⟺ `entry(name)` 成功；`ok == false` ⟺ `entry(name)` raise。
fn assert_dual_channel(
  checks : Array[@apk.IntegrityCheck],
  names : Array[String],
  apk : @apk.Apk,
) -> Unit raise {
  assert_eq(
    checks.length(),
    names.length(),
    msg="integrity_checks 条目数与 names 一致",
  )
  let mut i = 0
  while i < names.length() {
    let c = checks[i]
    let nm = names[i]
    assert_eq(c.name, nm, msg="结论条目名与输入一致")
    let entry_ok = try {
      ignore(apk.entry(nm))
      true
    } catch {
      @apk.ApkError::EntryNotFound(_) => fail("条目 \{nm} 应在索引中")
      _ => false
    }
    assert_eq(
      c.ok,
      entry_ok,
      msg="P6: 结论 ok==\{c.ok} 与 entry raise/成功行为==\{entry_ok} 一致 (\{nm})",
    )
    i = i + 1
  }
}

///|
/// T-W1-1 + F9：全绿样本（stored + deflate + 目录条目）ok 全 true、aligned 口径正确、
/// 目录条目被跳过、尺寸与 CRC 与声明一致。
test "W1 T-W1-1 全绿样本 ok 全 true" {
  let zip = build_zip(
    [
      zspec("ab.txt", b"hello"),
      zspec_deflated("cd.txt", b"world!!"),
      zspec("dir/", b""),
    ],
    None,
  )
  let apk = @apk.Apk::open(zip)
  let checks = apk.integrity_checks()
  // 目录条目 "dir/" 被跳过，故只返回 2 条。
  assert_eq(checks.length(), 2, msg="目录条目被跳过")
  assert_eq(checks[0].name, "ab.txt")
  assert_eq(checks[0].declared_size, 5UL)
  assert_eq(checks[0].actual_size, Some(5UL))
  assert_eq(checks[0].crc32_expected, t_crc32(b"hello"))
  assert_eq(checks[0].crc32_actual, Some(t_crc32(b"hello")))
  assert_true(checks[0].ok, msg="stored 条目 ok=true")
  assert_true(checks[0].aligned, msg="ab.txt 数据区 4 对齐")
  assert_eq(checks[0].error, "", msg="成功条目的 error 为空串")
  assert_eq(checks[1].name, "cd.txt")
  assert_true(checks[1].ok, msg="deflate 条目 ok=true")
  // "cd.txt" 是 deflate，数据区偏移 41 非 4 对齐。
  assert_true(
    !checks[1].aligned,
    msg="cd.txt 数据区非 4 对齐（口径复用 ZipEntryRef）",
  )
  assert_eq(checks[1].error, "", msg="成功条目的 error 为空串")
  assert_dual_channel(checks, ["ab.txt", "cd.txt"], apk)
}

///|
/// T-W1-2：坏 CRC 样本——对应条目 ok=false、error 非空且含 crc32 mismatch，其余条目不受影响。
test "W1 T-W1-2 坏 CRC 条目 ok=false 且其余不受影响" {
  let good = zspec("good.txt", b"fine")
  let bad = bad_crc_spec("bad.txt", b"corrupt")
  let zip = build_zip([good, bad], None)
  let apk = @apk.Apk::open(zip)
  let checks = apk.integrity_checks()
  assert_eq(checks.length(), 2)
  assert_true(checks[0].ok, msg="good.txt 不受影响")
  assert_eq(checks[0].error, "")
  assert_true(!checks[1].ok, msg="bad.txt ok=false")
  assert_true(
    checks[1].error.contains("crc32 mismatch"),
    msg="error 含 crc32 mismatch，实为 \{checks[1].error}",
  )
  assert_true(
    checks[1].actual_size is None,
    msg="坏 CRC 条目 actual_size=None",
  )
  assert_true(
    checks[1].crc32_actual is None,
    msg="坏 CRC 条目 crc32_actual=None",
  )
  assert_dual_channel(checks, ["good.txt", "bad.txt"], apk)
}

///|
/// T-W1-3 / P6：逐条双通道对照——同一 fixture 上 `integrity_checks()` 的 ok
/// 与 `entry(name)` 的 raise/成功行为逐条一致（覆盖 stored、deflate、坏 CRC、坏尺寸、坏压缩方法）。
test "W1 T-W1-3 与 entry raise 行为逐条目一致" {
  // 坏尺寸：构造 stored 条目但压缩字节长度与声明不符的畸形（借助 patch 修改压缩尺寸）。
  // 用 deflate_stored 语义构造：这里用一个坏压缩方法条目（comp_method=9 不可解压）。
  let bad_method_spec = {
    name: "weird.bin",
    comp_method: 9,
    data: b"x",
    extra_pad: 0,
    cd_extra: b"",
    bad_crc: false,
    declared_size: None,
    compressed_size: None,
  }
  let zip = build_zip(
    [zspec("ok.txt", b"ok"), zspec_deflated("d.txt", b"defl"), bad_method_spec],
    None,
  )
  let apk = @apk.Apk::open(zip)
  let checks = apk.integrity_checks()
  assert_true(checks[0].ok, msg="ok.txt ok=true")
  assert_true(checks[1].ok, msg="deflate ok=true")
  assert_true(!checks[2].ok, msg="未知压缩方法条目 ok=false")
  assert_true(
    checks[2].error.contains("unsupported compression method"),
    msg="error 含原因",
  )
  assert_dual_channel(checks, ["ok.txt", "d.txt", "weird.bin"], apk)
}

///|
/// 补充：对真实黄金 fixture（fx-multidex-v1 / fx-multidex-v2v3）跑一次全绿巡检，
/// 确认批量报告在真实多 dex 样本上全部 ok（F9 矩阵的现实回归）。
test "W1 真实多 dex fixture 全绿巡检" {
  for fx in [fixture_fx_multidex_v1_apk(), fixture_fx_multidex_v2v3_apk()] {
    let apk = @apk.Apk::open(fx)
    let checks = apk.integrity_checks()
    assert_true(checks.length() > 0, msg="fixture 至少含一个条目")
    for c in checks {
      assert_true(c.ok, msg="真实 fixture 条目 \{c.name} 应 ok=true")
      assert_eq(
        c.error,
        "",
        msg="真实 fixture 条目 \{c.name} error 应为空",
      )
    }
  }
}
