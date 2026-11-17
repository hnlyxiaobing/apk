// L1 性质/变异测试（docs/2026-11-16-test-system-design.md §4）。
// 零风险：只测既有公共 API（`@apk.`），不改库源码。
// 覆盖：
//   §4.1 变形律 P1–P5（P5 按文档标记 #skip，原因见下）
//   §4.3 截断扫描（A4，全局不变量「任意前缀不 panic」）
//   §6.2 错误变体簿记（10 个 ApkError 变体各 ≥1 显式触发）
//
// 复用 apk_test.mbt 的 fixture 辅助（同包根目录、同一测试模块）：
//   ZSpec / zspec / build_zip / sig_block_of / patch_byte / patch_u32 / scheme_value

///|
/// P1：local 头 extra 区追加 1–3 B 零填充，`entries()` 名称与 `entry()` 字节不变。
/// 用容器纯数据条目（"a.txt"）避免 AXML 语义依赖，保持 container-only。

///|
/// 构造给定 extra_pad 的 "a.txt" 条目 spec（ZSpec 为可变记录，逐字段构造）。
fn pad_spec(data : Bytes, pad : Int32) -> ZSpec {
  {
    name: "a.txt",
    comp_method: 0,
    data,
    extra_pad: pad,
    cd_extra: b"",
    bad_crc: false,
  }
}

///|
test "P1 bare-padding invariance" {
  let data = b"payload-bytes-for-padding-test"
  let plain = build_zip([pad_spec(data, 0)], None)
  let apk0 = @apk.Apk::open(plain)
  assert_true(
    apk0.entry("a.txt") == data,
    msg="extra_pad=0 提取字节应等于原数据",
  )
  let pad1 = build_zip([pad_spec(data, 1)], None)
  let pad2 = build_zip([pad_spec(data, 2)], None)
  let pad3 = build_zip([pad_spec(data, 3)], None)
  for padded in [pad1, pad2, pad3] {
    let a = @apk.Apk::open(padded)
    assert_true(
      a.entry("a.txt") == data,
      msg="padding 后提取字节应等于原数据",
    )
    assert_eq(a.entries().length(), 1, msg="padding 后 entries 数量不变")
    assert_eq(a.entries()[0].name, "a.txt", msg="padding 后条目名不变")
  }
}

///|
/// P2：相同条目集、中央目录顺序重排后，按名提取字节不变。
/// build_zip 同时用 specs 数组顺序排布 local 头与 CD 并重算偏移，
/// 因此仅重排数组即可构造「不同 CD 顺序」的合法 ZIP。
test "P2 entry-reorder invariance" {
  let names = [
    zspec("a.txt", b"alpha"),
    zspec_deflated("b.txt", b"beta-bytes"),
    zspec("c.txt", b"gamma"),
    zspec_deflated("d.txt", b"delta!"),
  ]
  let order1 = build_zip([names[0], names[1], names[2], names[3]], None)
  let order2 = build_zip([names[3], names[0], names[2], names[1]], None)
  let a1 = @apk.Apk::open(order1)
  let a2 = @apk.Apk::open(order2)
  for nm in ["a.txt", "b.txt", "c.txt", "d.txt"] {
    assert_true(
      a1.entry(nm) == a2.entry(nm),
      msg="重排后按名提取 \{nm} 字节应一致",
    )
  }
  assert_eq(a1.entries().length(), 4, msg="两序条目数一致")
  assert_eq(a2.entries().length(), 4, msg="两序条目数一致")
}

///|
/// P3：追加无关条目后，dex_files / native_libs 结论不变（位置式定位，无需 AXML）。
/// 文档 §4.1 P3 提及 manifest；本用例保持 container-only，改断言位置式结论。
test "P3 unrelated-entry append invariance" {
  let base = [
    zspec("classes.dex", b"dex1"),
    zspec("lib/arm64-v8a/liba.so", b"so-a"),
  ]
  let before = @apk.Apk::open(build_zip(base, None))
  let b_dex = before.dex_files()
  let b_lib = before.native_libs(None)
  assert_eq(b_dex.length(), 1, msg="base dex_files 计数")
  assert_eq(b_lib.length(), 1, msg="base native_libs 计数")

  let appended = base + [zspec("res/values/strings.xml", b"<strings>")]
  let after = @apk.Apk::open(build_zip(appended, None))
  let a_dex = after.dex_files()
  let a_lib = after.native_libs(None)
  assert_eq(a_dex.length(), 1, msg="追加后 dex_files 计数不变")
  assert_eq(a_lib.length(), 1, msg="追加后 native_libs 计数不变")
  assert_true(a_dex[0].name == b_dex[0].name, msg="dex 条目名不变")
  assert_true(a_dex[0].bytes == b_dex[0].bytes, msg="dex 字节不变")
  assert_true(a_lib[0].path == b_lib[0].path, msg="lib 路径不变")
  assert_true(a_lib[0].bytes == b_lib[0].bytes, msg="lib 字节不变")
}

///|
/// P4：同一 Bytes 两次 `open` + 全量查询，所有输出逐字节相等（纯函数性）；
/// 同一 Apk 上重复 `entry(name)` 确定性一致。
test "P4 idempotence" {
  let zip = build_zip(
    [zspec("a.txt", b"alpha"), zspec_deflated("b.txt", b"beta-bytes")],
    None,
  )
  let a1 = @apk.Apk::open(zip)
  let a2 = @apk.Apk::open(zip)
  let e1 = a1.entries()
  let e2 = a2.entries()
  assert_eq(e1.length(), e2.length(), msg="两次 open entries 数量一致")
  for i = 0; i < e1.length(); i = i + 1 {
    assert_eq(e1[i].name, e2[i].name, msg="entries 名称逐项一致")
    assert_true(e1[i].crc32 == e2[i].crc32, msg="entries CRC 逐项一致")
  }
  for nm in ["a.txt", "b.txt"] {
    assert_true(a1.entry(nm) == a2.entry(nm), msg="跨 open 提取字节一致")
    assert_true(
      a1.entry(nm) == a1.entry(nm),
      msg="同 open 重复提取确定性一致",
    )
  }
}

///|
/// P5：签名块位移不变性。**#skip**——verity 布局（W5）尚未落地，签名块平移需
/// 内容区随动重算摘要的样本族，M2 阶段随 W5 实现后再补（见 docs §4.1 P5）。
#skip
test "P5 signing-block shift invariance [SKIPPED: W5 verity layout unresolved; deferred to M2]" {
  println("SKIPPED: P5 signing-block shift deferred to M2 (W5 verity layout)")
}

///|
/// §4.3 截断扫描（A4）：对受控小 ZIP 遍历所有前缀 `0..len`，
/// 逐一 `open` 只允许 `ApkError`，任何 panic / 其它异常即测试失败。
test "A4 truncation scan: no panic for every prefix" {
  let zip = build_zip(
    [zspec("a.txt", b"alpha"), zspec_deflated("b.txt", b"beta-bytes")],
    None,
  )
  assert_true(
    zip.length() < 512,
    msg="截断扫描用几百字节的小 ZIP 控制循环上界",
  )
  for n in 0..<zip.length() {
    let cut = zip[0:n].to_owned()
    try ignore(@apk.Apk::open(cut)) catch {
      _ => ()
    } noraise {
      _ => ()
    }
  }
}

///|
/// §6.2 错误变体簿记：10 个 `ApkError` 变体各 ≥1 显式触发（断言变体名）。
/// 全部通过公共 API 触发；BadElf / BadResourceTable 亦给出容器内触发路径。
test "A5 error-variant ledger: all 10 ApkError variants explicitly triggered" {
  // 1) NotAZip：无关字节。
  try ignore(@apk.Apk::open(b"definitely not a zip archive")) catch {
    @apk.ApkError::NotAZip(_) => ()
    _ => fail("expected NotAZip")
  } noraise {
    _ => fail("expected NotAZip")
  }

  // 2) Zip64Unsupported：EOCD cd_size 置为 ZIP64 哨兵 0xFFFFFFFF。
  let z64_zip = build_zip([zspec("a.txt", b"hello")], None)
  let z64_eocd = z64_zip.length() - 22
  try ignore(@apk.Apk::open(patch_u32(z64_zip, z64_eocd + 12, -1))) catch {
    @apk.ApkError::Zip64Unsupported(_) => ()
    _ => fail("expected Zip64Unsupported")
  } noraise {
    _ => fail("expected Zip64Unsupported")
  }

  // 3) BadCentralDirectory：翻转中央目录签名首字节。
  // 单条目 "a.txt"(5B 名 + 5B 数据)：local 头 30 + 名 5 + 数据 5 = CD 起点 40。
  let cd_zip = build_zip([zspec("a.txt", b"hello")], None)
  try ignore(@apk.Apk::open(patch_byte(cd_zip, 40, 0x51))) catch {
    @apk.ApkError::BadCentralDirectory(off, detail) => {
      assert_eq(off, 40, msg="CD 签名污染偏移")
      assert_true(detail.contains("signature"), msg="detail 含 signature")
    }
    _ => fail("expected BadCentralDirectory")
  } noraise {
    _ => fail("expected BadCentralDirectory")
  }

  // 4) EntryNotFound：按名提取缺失条目。
  let en_apk = @apk.Apk::open(build_zip([zspec("a.txt", b"hello")], None))
  try ignore(en_apk.entry("nope.bin")) catch {
    @apk.ApkError::EntryNotFound(n) => assert_eq(n, "nope.bin")
    _ => fail("expected EntryNotFound")
  } noraise {
    _ => fail("expected EntryNotFound")
  }

  // 5) UnexpectedEof：截断归档尾部（既有 L0 触发方式的容器化）。
  let eof_zip = build_zip(
    [zspec("a.txt", b"hello"), zspec_deflated("b.txt", b"world!!")],
    None,
  )
  let eof_cut = eof_zip[0:eof_zip.length() - 30].to_owned()
  try ignore(@apk.Apk::open(eof_cut)) catch {
    @apk.ApkError::UnexpectedEof(_) => ()
    _ => fail("expected UnexpectedEof")
  } noraise {
    _ => fail("expected UnexpectedEof")
  }

  // 6) BadSigningBlock：签名块 size 字段污染（"a.txt" 数据止于 40 = 块首字节）。
  let sb_pairs : Array[(UInt32, Bytes)] = []
  sb_pairs.push((0x7109871a, scheme_value(b"cert2", 0)))
  let sb_zip = build_zip(
    [zspec("a.txt", b"hello")],
    Some(sig_block_of(sb_pairs)),
  )
  try
    ignore(@apk.Apk::open(patch_byte(sb_zip, 40, sb_zip[40].to_int() + 1)))
  catch {
    @apk.ApkError::BadSigningBlock(off, _) =>
      assert_eq(off, 40, msg="签名块 size 污染偏移")
    _ => fail("expected BadSigningBlock")
  } noraise {
    _ => fail("expected BadSigningBlock")
  }

  // 7) UnsupportedSignatureScheme：签名块含未知方案 ID。
  let us_pairs : Array[(UInt32, Bytes)] = []
  us_pairs.push((0xdeadbeef, b"mystery"))
  let us_apk = @apk.Apk::open(
    build_zip([zspec("a.txt", b"hello")], Some(sig_block_of(us_pairs))),
  )
  try ignore(us_apk.signatures()) catch {
    @apk.ApkError::UnsupportedSignatureScheme(_) => ()
    _ => fail("expected UnsupportedSignatureScheme")
  } noraise {
    _ => fail("expected UnsupportedSignatureScheme")
  }

  // 8) BadAlignment：resources.arsc 全局字符串池 chunk 未对齐。
  let al_arsc = build_arsc(30)
  let al_apk = @apk.Apk::open(
    build_zip([zspec("resources.arsc", al_arsc)], None),
  )
  try ignore(al_apk.resource_table()) catch {
    @apk.ApkError::BadAlignment(name, off) => {
      assert_eq(name, "resources.arsc")
      assert_eq(off, 12, msg="未对齐 chunk 偏移")
    }
    _ => fail("expected BadAlignment")
  } noraise {
    _ => fail("expected BadAlignment")
  }

  // 9) BadResourceTable：resources.arsc 顶层 chunk 类型非法，经 resource_table_full() 触发。
  let bad_arsc = b"\x03\x00\x0c\x00\x0c\x00\x00\x00\x00\x00\x00\x00"
  let rt_apk = @apk.Apk::open(
    build_zip([zspec("resources.arsc", bad_arsc)], None),
  )
  try ignore(rt_apk.resource_table_full()) catch {
    @apk.ApkError::BadResourceTable(0, _) => ()
    _ => fail("expected BadResourceTable")
  } noraise {
    _ => fail("expected BadResourceTable")
  }

  // 10) BadElf：lib/<abi>/*.so 条目字节缺 ELF magic（经 NativeLib::elf_abi 触发）。
  let bad_so = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  let elf_apk = @apk.Apk::open(
    build_zip([zspec("lib/arm64-v8a/liba.so", bad_so)], None),
  )
  let libs = elf_apk.native_libs(None)
  assert_eq(libs.length(), 1, msg="native_libs 识别到 liba.so")
  try ignore(libs[0].elf_abi()) catch {
    @apk.ApkError::BadElf(off, detail) => {
      assert_eq(off, 0, msg="ELF magic 缺失偏移")
      assert_true(detail.contains("ELF magic"), msg="detail 含 ELF magic")
    }
    _ => fail("expected BadElf")
  } noraise {
    _ => fail("expected BadElf")
  }
}
