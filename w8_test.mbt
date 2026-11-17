///|
/// W8 Dart 符号定位测试（T-W8-1..4）。
/// W7 轨 A 的合成 ELF/APK fixture（w7_test.mbt）用于 T-W8-1 偏移对账。

///|
test "T-W8-1: W7 fixture dart snapshot refs offsets match generator values" {
  // W7 轨 A 生成器在 dynsym 中写入了 2 个 _kDart* marker：
  //   _kDartVmSnapshotInstructions (st_value=0x2000)
  //   _kDartIsolateSnapshotData    (st_value=0x3000)
  let apk = @apk.Apk::open(w7_apk())
  let libs = apk.native_libs(None)
  guard libs.length() > 0 else { fail("expected native libs in w7 fixture") }
  let lib = libs[0]
  let refs = lib.dart_snapshot_refs()
  guard refs.length() == 2 else {
    fail("expected 2 dart snapshot refs, got " + refs.length().to_string())
  }
  // 按 marker 预设顺序
  assert_eq(refs[0].marker, "_kDartVmSnapshotInstructions")
  assert_eq(refs[1].marker, "_kDartIsolateSnapshotData")
  // st_value = 0x2000 = 8192
  assert_eq(refs[0].offset, 0x2000UL)
  // st_value = 0x3000 = 12288
  assert_eq(refs[1].offset, 0x3000UL)
  // 无 section header table（e_shoff=0），in_section 为空
  assert_eq(refs[0].in_section, "")
  assert_eq(refs[1].in_section, "")
}

///|
test "T-W8-2: stripped section header table does not panic" {
  // W7 fixture 无 section header table（e_shoff=0），验证不 panic。
  let apk = @apk.Apk::open(w7_apk())
  let libs = apk.native_libs(None)
  let lib = libs[0]
  let refs = lib.dart_snapshot_refs()
  // 不 panic 即通过；in_section 应为空（无 section headers）
  for r in refs {
    assert_eq(r.in_section, "")
  }
}

///|
test "T-W8-3: no Dart symbols returns empty array" {
  // fx-multidex-v1.apk 不含 native 库（或库中无 Dart 符号）。
  let apk = @apk.Apk::open(fixture_fx_multidex_v1_apk())
  let libs = apk.native_libs(None)
  if libs.length() == 0 {
    // 无 native 库 → 自然无 Dart 符号
    return
  }
  for lib in libs {
    let refs = lib.dart_snapshot_refs()
    assert_eq(refs.length(), 0)
  }
}

///|
/// T-W8-4: 快照 diff 纯加法 —— 由 moon info gate 5 承载，不在测试内重复。
test "T-W8-4: snapshot diff pure addition (gate 5)" {
  // 由 moon info + git diff 门禁承载，不作内联测试。
}
