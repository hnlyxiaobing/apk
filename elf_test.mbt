// 非空 .so ABI 解析侧测试：**受控自建合成 ELF fixture**（测试内构造最小 ELF 头，
// 不引入任何第三方二进制）。
//
// 覆盖：
// - `Apk::native_libs` 的 `lib/<abi>/*.so` 路径解析与 ABI 归类（arm64-v8a /
//   armeabi-v7a / x86 / x86_64 / 未知 riscv64）；
// - `NativeLib::elf_abi()` 内容侧 ABI 交叉校验（ELF magic / class / data / e_machine）；
// - 目录 ABI 与 ELF 头 ABI 不一致时的可观察差异（错标库）；
// - 坏 ELF 头报 `BadElf` 而非 panic。
//
// 真实第三方 .so 的解析侧黄金差分：**仍未执行**（样本许可不明/未入库），
// 以 `#skip` 显式标注，见文件末尾。

///|
/// 最小 ELF64 头（64 字节）：ET_DYN + 指定 e_machine + 小端。
fn e_elf64(machine : Int32) -> Bytes {
  let out : Array[Byte] = []
  out.push(b'\x7f')
  out.push(b'\x45')
  out.push(b'\x4c')
  out.push(b'\x46')
  out.push(b'\x02')
  out.push(b'\x01')
  out.push(b'\x01')
  out.push(b'\x00')
  for i = 0; i < 8; i = i + 1 {
    out.push(b'\x00')
  }
  push_u16(out, 3)
  push_u16(out, machine)
  push_u32(out, 1)
  while out.length() < 64 {
    out.push(b'\x00')
  }
  Bytes::from_array(out[:])
}

///|
/// 最小 ELF32 头（52 字节）：ET_DYN + 指定 e_machine + 小端。
fn e_elf32(machine : Int32) -> Bytes {
  let out : Array[Byte] = []
  out.push(b'\x7f')
  out.push(b'\x45')
  out.push(b'\x4c')
  out.push(b'\x46')
  out.push(b'\x01')
  out.push(b'\x01')
  out.push(b'\x01')
  out.push(b'\x00')
  for i = 0; i < 8; i = i + 1 {
    out.push(b'\x00')
  }
  push_u16(out, 3)
  push_u16(out, machine)
  push_u32(out, 1)
  while out.length() < 52 {
    out.push(b'\x00')
  }
  Bytes::from_array(out[:])
}

///|
/// 测试侧独立读取 ELF e_machine（与库内 `elf_abi` 实现无关的交叉基准）。
fn e_read_machine(b : Bytes) -> Int32 {
  b[18].to_int() | (b[19].to_int() << 8)
}

///|
/// 合成 ELF APK：5 个 ABI 目录各一个非空 .so。
fn e_elf_apk() -> Bytes {
  build_zip(
    [
      zspec("AndroidManifest.xml", b"\x03\x00\x02\x00fake-axml"),
      zspec("lib/arm64-v8a/libnative.so", e_elf64(183)),
      zspec("lib/armeabi-v7a/libnative.so", e_elf32(40)),
      zspec("lib/x86_64/libnative.so", e_elf64(62)),
      zspec("lib/x86/libnative.so", e_elf32(3)),
      zspec("lib/riscv64/libnative.so", e_elf64(243)),
    ],
    None,
  )
}

///|
/// ABI 黄金：合成 ELF 的目录 ABI / ELF 头 ABI / 路径 / 字节数。
fn golden_elf_apk() -> String {
  "ENTR|AndroidManifest.xml|13|13\nENTR|lib/arm64-v8a/libnative.so|64|64\nENTR|lib/armeabi-v7a/libnative.so|52|52\nENTR|lib/x86_64/libnative.so|64|64\nENTR|lib/x86/libnative.so|52|52\nENTR|lib/riscv64/libnative.so|64|64\nLIB|Arm64V8a|Arm64V8a|lib/arm64-v8a/libnative.so|64\nLIB|ArmeabiV7a|ArmeabiV7a|lib/armeabi-v7a/libnative.so|52\nLIB|X86_64|X86_64|lib/x86_64/libnative.so|64\nLIB|X86|X86|lib/x86/libnative.so|52\nLIB|Unknown(riscv64)|Unknown(riscv64)|lib/riscv64/libnative.so|64\nMANI|13\n"
}

///|
/// 非空 .so：路径解析 + ABI 归类 + 字节完整性 + 过滤。
test "native_libs resolves non-empty synthetic ELF fixtures" {
  let apk = @apk.Apk::open(e_elf_apk())
  let all = apk.native_libs(None)
  assert_eq(all.length(), 5)
  assert_eq(abi_str(all[0].abi), "Arm64V8a")
  assert_eq(all[0].path, "lib/arm64-v8a/libnative.so")
  assert_true(all[0].bytes == e_elf64(183), msg="arm64 bytes intact")
  assert_eq(abi_str(all[1].abi), "ArmeabiV7a")
  assert_eq(all[1].path, "lib/armeabi-v7a/libnative.so")
  assert_true(all[1].bytes == e_elf32(40))
  assert_eq(abi_str(all[2].abi), "X86_64")
  assert_eq(abi_str(all[3].abi), "X86")
  assert_eq(abi_str(all[4].abi), "Unknown(riscv64)")
  assert_true(all[2].bytes == e_elf64(62))
  // 过滤：只取 arm64 / x86_64。
  let arm64 = apk.native_libs(Some(@apk.Abi::Arm64V8a))
  assert_eq(arm64.length(), 1)
  assert_eq(arm64[0].path, "lib/arm64-v8a/libnative.so")
  let x64 = apk.native_libs(Some(@apk.Abi::X86_64))
  assert_eq(x64.length(), 1)
  assert_eq(apk.native_libs(Some(@apk.Abi::Unknown("mips"))).length(), 0)
}

///|
/// 内容侧 ABI（ELF 头）与目录 ABI 一致：验证 ABI 识别不是只靠路径字符串。
test "synthetic ELF headers agree with classified ABI" {
  let apk = @apk.Apk::open(e_elf_apk())
  let expected : Array[(String, Int32)] = [
    ("Arm64V8a", 183),
    ("ArmeabiV7a", 40),
    ("X86_64", 62),
    ("X86", 3),
    ("Unknown(riscv64)", 243),
  ]
  let libs = apk.native_libs(None)
  let mut i = 0
  for l in libs {
    assert_eq(abi_str(l.elf_abi()), expected[i].0, msg=l.path)
    assert_eq(e_read_machine(l.bytes), expected[i].1, msg=l.path)
    assert_true(
      abi_str(l.abi) == abi_str(l.elf_abi()),
      msg="dir ABI == ELF ABI: \{l.path}",
    )
    i = i + 1
  }
}

///|
/// 错标库：ELF 头是 arm64，但放在 lib/x86_64/ 下 —— 目录归类为 X86_64，
/// `elf_abi()` 报 Arm64V8a，调用方可据此发现不一致（不静默改写目录 ABI）。
test "mismatched ELF header is observable but does not rewrite dir ABI" {
  let apk = @apk.Apk::open(
    build_zip(
      [
        zspec("AndroidManifest.xml", b"\x03\x00\x02\x00fake-axml"),
        zspec("lib/x86_64/libwrong.so", e_elf64(183)),
      ],
      None,
    ),
  )
  let libs = apk.native_libs(Some(@apk.Abi::X86_64))
  assert_eq(libs.length(), 1)
  assert_eq(abi_str(libs[0].abi), "X86_64")
  assert_eq(abi_str(libs[0].elf_abi()), "Arm64V8a")
  assert_true(abi_str(libs[0].abi) != abi_str(libs[0].elf_abi()))
}

///|
/// 坏 ELF 头：magic/class/data/长度异常均报 `BadElf`，不 panic。
test "bad ELF headers raise BadElf" {
  let cases : Array[(Bytes, Int32)] = [
    (b"not an elf at all!!!!", 0),
    (b"\x7fELF", 4),
    (patch_byte(e_elf64(183), 4, 3), 4),
    (patch_byte(e_elf64(183), 5, 2), 5),
  ]
  for (bytes, want_off) in cases {
    let lib : @apk.NativeLib = {
      abi: @apk.Abi::X86,
      path: "lib/x86/libbad.so",
      bytes,
    }
    let mut hit = false
    try ignore(lib.elf_abi()) catch {
      @apk.ApkError::BadElf(off, _) => {
        assert_eq(off, want_off)
        hit = true
      }
      _ => fail("expected BadElf")
    } noraise {
      _ => ()
    }
    assert_true(hit, msg="bad ELF must raise BadElf")
  }
}

///|
/// 黄金差分：容器规范化（ENTR/DEX/LIB/MANI）与内嵌黄金一致。
test "golden apk synthetic ELF ABI" {
  let apk = @apk.Apk::open(e_elf_apk())
  assert_eq(fx_canon_apk(apk), golden_elf_apk())
}

///|
/// 真实第三方 .so 的解析侧 ABI 黄金差分：仍未执行。
/// 既有内嵌样本均无 .so（open-questions §2.1 缺口 4）；本文件用合成 ELF 补齐
/// 解析侧结构路径，但**不能替代**真实 `.so` 差分。`#skip` 显式标注，绝不冒充通过。
#skip
test "native_libs real third-party .so differential [SKIPPED: 真实 .so 未入库]" {
  println(
    "SKIPPED: 真实第三方 .so 样本许可不明/未入库；合成 ELF fixture 仅覆盖结构路径，真实差分 [仍需实测]",
  )
}
