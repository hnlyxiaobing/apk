// ELF 只读侦察（加法性子能力）测试：**测试内合成最小合法 ELF32/ELF64 小端 .so**，
// 不入库任何真实 .so / APK / 第三方二进制。
//
// 合成 fixture 设计要点（详见各 ///| 分块）：
// - 装载基址 er_base = 0x10000（非零）：DT_STRTAB / DT_SYMTAB / DT_HASH 的 d_val 是
//   **虚拟地址**，必须经 PT_LOAD 的 [p_vaddr, p_vaddr + p_filesz) 映射才能得到文件偏移；
//   若实现错误地假设 vaddr == offset，本 fixture 会直接读到越界 / 错值而失败。
// - 2 个 PT_LOAD 连续拼接覆盖整个文件（全局恒有 vaddr = er_base + 文件偏移），
//   再加 1 个 PT_DYNAMIC（e_phnum = 3）。
// - DT_HASH(SysV) 的 nchain 是**精确动态符号数**（= 3），覆盖 elf_dynsym_count 的
//   DT_HASH 精确路径；nchain 受 (len - sym_off) / syment 上界与 elf_max_dynsym 双重夹取。
// - DT_NEEDED 的 d_val 是 strtab 内索引（不是 vaddr），与 DT_STRTAB 的 d_val 语义不同。
// - strtab 内故意乱序 + 重复放入 5 个 Dart AOT marker，验证 dart_markers 命中、
//   按预设顺序输出、去重（字节模式命中，非快照解析）。
//
// 错误路径：截断 / 坏 magic / EI_CLASS=3 / 缺 PT_DYNAMIC / 缺 DT_STRTAB /
// DT_STRTAB 越界，一律断言 ApkError::BadElf(_, _)，不 panic、不静默成功。
// 复用 apk_test.mbt 的 push_u16 / push_u32 / push_u64_small / push_bytes /
// patch_byte / patch_u32 与 fixtures_malformed_test.mbt 的 fx_cut
//（黑盒测试文件共享顶层作用域）。

///|
/// 装载基址：让所有 DT_* 虚拟地址与文件偏移相差 er_base，强制走 PT_LOAD 映射。
let er_base : Int32 = 0x10000

///|
/// 构造 strtab：首字节 NUL（索引 0 空串），随后逐个 NUL 结尾串；返回 (字节, 各串起始索引)。
fn er_strtab(names : Array[String]) -> (Bytes, Array[Int32]) {
  let buf : Array[Byte] = []
  let offsets : Array[Int32] = []
  buf.push(b'\x00')
  for n in names {
    offsets.push(buf.length())
    push_bytes(buf, @encoding/utf8.encode(n))
    buf.push(b'\x00')
  }
  (Bytes::from_array(buf[:]), offsets)
}

///|
/// 3 个动态符号：Java_ 导出(已定义 st_shndx=1) / memcpy(UNDEF 导入 st_shndx=0) /
/// Java_ 导出(已定义)。Elf64_Sym = 24B(st_shndx@6) / Elf32_Sym = 16B(st_shndx@14)。
fn er_dynsym(is64 : Bool, offs : Array[Int32]) -> Bytes {
  let buf : Array[Byte] = []
  let specs : Array[(Int32, Int32)] = [(offs[2], 1), (offs[3], 0), (offs[4], 1)]
  for (name_idx, shndx) in specs {
    push_u32(buf, name_idx) // st_name：strtab 内索引
    if is64 {
      buf.push(b'\x00') // st_info
      buf.push(b'\x00') // st_other
      push_u16(buf, shndx) // st_shndx @6：!= 0 即 defined
      push_u32(buf, 0) // st_value
      push_u32(buf, 0)
      push_u32(buf, 0) // st_size
      push_u32(buf, 0)
    } else {
      push_u32(buf, 0) // st_value
      push_u32(buf, 0) // st_size
      buf.push(b'\x00') // st_info
      buf.push(b'\x00') // st_other
      push_u16(buf, shndx) // st_shndx @14
    }
  }
  Bytes::from_array(buf[:])
}

///|
/// SysV DT_HASH：nbucket=1、nchain=3(= 动态符号数)、bucket[0]、chain[3]。
/// elf_dynsym_count 只读 hash 头第 2 个 u32(nchain) 作为精确符号数。
fn er_hash() -> Bytes {
  let buf : Array[Byte] = []
  push_u32(buf, 1) // nbucket
  push_u32(buf, 3) // nchain = 符号数
  push_u32(buf, 1) // bucket[0]
  push_u32(buf, 0) // chain[0]
  push_u32(buf, 0) // chain[1]
  push_u32(buf, 0) // chain[2]
  Bytes::from_array(buf[:])
}

///|
/// 7 条 DT_*：NEEDED×2 / STRTAB / SYMTAB / SYMENT / HASH / NULL。
/// DT_NEEDED 的 d_val 是 strtab 索引；STRTAB / SYMTAB / HASH 的 d_val 是虚拟地址
/// (= er_base + 文件偏移)。Elf64_Dyn = 16B / Elf32_Dyn = 8B。
fn er_dynamic(
  is64 : Bool,
  offs : Array[Int32],
  str_off : Int32,
  sym_off : Int32,
  hash_off : Int32,
) -> Bytes {
  let syment = if is64 { 24 } else { 16 }
  let entries : Array[(Int32, Int32)] = [
    (1, offs[0]), // DT_NEEDED → libc.so
    (1, offs[1]), // DT_NEEDED → libdl.so
    (5, er_base + str_off), // DT_STRTAB (vaddr)
    (6, er_base + sym_off), // DT_SYMTAB (vaddr)
    (11, syment), // DT_SYMENT
    (4, er_base + hash_off), // DT_HASH (vaddr)
    (0, 0), // DT_NULL（解析到此 break）
  ]
  let buf : Array[Byte] = []
  for (tag, val) in entries {
    if is64 {
      push_u64_small(buf, tag) // Elf64_Sxword d_tag
      push_u64_small(buf, val) // Elf64_Xword d_val
    } else {
      push_u32(buf, tag) // Elf32_Sword d_tag
      push_u32(buf, val) // Elf32_Word d_val
    }
  }
  Bytes::from_array(buf[:])
}

///|
/// 单个 program header：Elf64_Phdr = 56B / Elf32_Phdr = 32B。
/// 字段偏移：p_type@0、p_offset@8(64)/4(32)、p_vaddr@16(64)/8(32)、
/// p_filesz@32(64)/16(32)。
fn er_phdr(
  is64 : Bool,
  ptype : Int32,
  offset : Int32,
  vaddr : Int32,
  filesz : Int32,
) -> Bytes {
  let buf : Array[Byte] = []
  if is64 {
    push_u32(buf, ptype) // p_type
    push_u32(buf, 4) // p_flags
    push_u64_small(buf, offset) // p_offset
    push_u64_small(buf, vaddr) // p_vaddr
    push_u64_small(buf, 0) // p_paddr
    push_u64_small(buf, filesz) // p_filesz
    push_u64_small(buf, filesz) // p_memsz
    push_u64_small(buf, 0x1000) // p_align
  } else {
    push_u32(buf, ptype) // p_type
    push_u32(buf, offset) // p_offset
    push_u32(buf, vaddr) // p_vaddr
    push_u32(buf, 0) // p_paddr
    push_u32(buf, filesz) // p_filesz
    push_u32(buf, filesz) // p_memsz
    push_u32(buf, 4) // p_flags
    push_u32(buf, 0x1000) // p_align
  }
  Bytes::from_array(buf[:])
}

///|
/// ELF 头：EI_CLASS = 2/1、EI_DATA = 1(小端)、e_phoff 紧跟头、
/// e_phentsize = 56/32、e_phnum = 3。e_machine@18、e_phoff@32(64)/28(32)、
/// e_phentsize@54(64)/42(32)、e_phnum@56(64)/44(32)。
fn er_ehdr(is64 : Bool, machine : Int32) -> Bytes {
  let ehsize = if is64 { 64 } else { 52 }
  let phentsize = if is64 { 56 } else { 32 }
  let buf : Array[Byte] = []
  buf.push(b'\x7f')
  buf.push(b'\x45')
  buf.push(b'\x4c')
  buf.push(b'\x46')
  buf.push(if is64 { b'\x02' } else { b'\x01' }) // EI_CLASS
  buf.push(b'\x01') // EI_DATA = LSB
  buf.push(b'\x01') // EI_VERSION
  buf.push(b'\x00') // EI_OSABI
  push_u32(buf, 0) // e_ident pad (8B)
  push_u32(buf, 0)
  push_u16(buf, 3) // e_type = ET_DYN
  push_u16(buf, machine) // e_machine
  push_u32(buf, 1) // e_version
  if is64 {
    push_u64_small(buf, 0) // e_entry
    push_u64_small(buf, ehsize) // e_phoff = 64
    push_u64_small(buf, 0) // e_shoff
    push_u32(buf, 0) // e_flags
    push_u16(buf, ehsize) // e_ehsize
    push_u16(buf, phentsize) // e_phentsize
    push_u16(buf, 3) // e_phnum
    push_u16(buf, 0) // e_shentsize
    push_u16(buf, 0) // e_shnum
    push_u16(buf, 0) // e_shstrndx
  } else {
    push_u32(buf, 0) // e_entry
    push_u32(buf, ehsize) // e_phoff = 52
    push_u32(buf, 0) // e_shoff
    push_u32(buf, 0) // e_flags
    push_u16(buf, ehsize) // e_ehsize
    push_u16(buf, phentsize) // e_phentsize
    push_u16(buf, 3) // e_phnum
    push_u16(buf, 0) // e_shentsize
    push_u16(buf, 0) // e_shnum
    push_u16(buf, 0) // e_shstrndx
  }
  Bytes::from_array(buf[:])
}

///|
/// 合成结果与关键字段偏移（供畸形派生用例定点 patch）。
struct ErBuilt {
  bytes : Bytes
  dynamic_ph_type_off : Int32
  strtab_tag_off : Int32
  strtab_val_off : Int32
}

///|
/// 构造最小合法 ELF（32/64 位小端，带非零装载基址）：2×PT_LOAD + 1×PT_DYNAMIC。
/// 全局恒有 vaddr = er_base + 文件偏移（两段 PT_LOAD 连续拼接覆盖全文件）。
fn er_build(is64 : Bool, machine : Int32) -> ErBuilt {
  let names : Array[String] = [
    "libc.so", "libdl.so", "Java_com_example_App_stringFromJNI", "memcpy", "Java_com_example_App_init",
    "CodeSourceMap", // Dart marker（预设第 5）
     "_kDartIsolateSnapshotData", // 预设第 3
     "KernelProgramInfo", // 预设第 4
     "_kDartVmSnapshotInstructions", // 预设第 1
     "_kDartIsolateSnapshotInstructions", // 预设第 2
     "CodeSourceMap", // 重复，验证去重
  ]
  let (strtab, offs) = er_strtab(names)
  let dynsym = er_dynsym(is64, offs)
  let hash = er_hash()
  let ehsize = if is64 { 64 } else { 52 }
  let phentsize = if is64 { 56 } else { 32 }
  let dyn_ent = if is64 { 16 } else { 8 }
  let dyn_count = 7
  let dyn_off = ehsize + 3 * phentsize
  let str_off = dyn_off + dyn_count * dyn_ent
  let sym_off = str_off + strtab.length()
  let hash_off = sym_off + dynsym.length()
  let total = hash_off + hash.length()

  let ehdr = er_ehdr(is64, machine)
  let dynamic = er_dynamic(is64, offs, str_off, sym_off, hash_off)
  let ph0 = er_phdr(is64, 1, 0, er_base, dyn_off) // PT_LOAD：[0, dyn_off)
  let ph1 = er_phdr(is64, 1, dyn_off, er_base + dyn_off, total - dyn_off) // PT_LOAD：[dyn_off, total)
  let ph2 = er_phdr(is64, 2, dyn_off, er_base + dyn_off, dyn_count * dyn_ent) // PT_DYNAMIC

  let out : Array[Byte] = []
  push_bytes(out, ehdr)
  push_bytes(out, ph0)
  push_bytes(out, ph1)
  push_bytes(out, ph2)
  push_bytes(out, dynamic)
  push_bytes(out, strtab)
  push_bytes(out, dynsym)
  push_bytes(out, hash)
  {
    bytes: Bytes::from_array(out[:]),
    dynamic_ph_type_off: ehsize + 2 * phentsize, // phdr[2].p_type
    strtab_tag_off: dyn_off + 2 * dyn_ent, // DT_STRTAB 是第 3 条(index 2)
    strtab_val_off: dyn_off + 2 * dyn_ent + (if is64 { 8 } else { 4 }), // d_val 紧跟 d_tag
  }
}

///|
/// 把合成字节包成 NativeLib（abi / path 仅占位；elf_info 只读 bytes）。
fn er_lib(bytes : Bytes) -> @apk.NativeLib {
  { abi: @apk.Abi::Arm64V8a, path: "lib/arm64-v8a/librecon.so", bytes, }
}

///|
/// ElfClass 无 Eq / Show 派生，测试侧转 String 断言（与 abi_str 同构）。
fn er_class_str(c : @apk.ElfClass) -> String {
  match c {
    @apk.ElfClass::Elf64 => "Elf64"
    @apk.ElfClass::Elf32 => "Elf32"
  }
}

///|
/// 畸形 ELF：elf_info 是否按预期抛 BadElf。其它 ApkError 变体、panic 或静默成功
/// 都返回 false，由调用方在 test 块内 assert_true 判定（普通 fn 不能用 assert/fail）。
fn er_is_bad(bytes : Bytes) -> Bool {
  let lib = er_lib(bytes)
  let mut hit = false
  try ignore(lib.elf_info()) catch {
    @apk.ApkError::BadElf(_, _) => hit = true
    _ => ()
  } noraise {
    _ => ()
  }
  hit
}

///|
/// ELF64 小端：elf_info 全字段 + 便利函数与 elf_info 一致。
test "elf_info ELF64 合成 .so：全字段与便利函数一致" {
  let built = er_build(true, 183) // 0xB7 AArch64
  let lib = er_lib(built.bytes)
  let info = lib.elf_info()
  assert_eq(er_class_str(info.elf_class), "Elf64")
  assert_eq(info.machine, 183)
  assert_eq(info.needed.length(), 2)
  assert_eq(info.needed[0], "libc.so")
  assert_eq(info.needed[1], "libdl.so")
  assert_eq(info.dynamic_symbols.length(), 3)
  assert_eq(info.dynamic_symbols[0].name, "Java_com_example_App_stringFromJNI")
  assert_eq(info.dynamic_symbols[0].defined, true)
  assert_eq(info.dynamic_symbols[1].name, "memcpy")
  assert_eq(info.dynamic_symbols[1].defined, false) // UNDEF 导入
  assert_eq(info.dynamic_symbols[2].name, "Java_com_example_App_init")
  assert_eq(info.dynamic_symbols[2].defined, true)
  assert_eq(info.jni_exports.length(), 2)
  assert_eq(info.jni_exports[0], "Java_com_example_App_stringFromJNI")
  assert_eq(info.jni_exports[1], "Java_com_example_App_init")
  // 便利函数内部委托 elf_info，结果必须逐项一致。
  let nl = lib.needed_libraries()
  assert_eq(nl.length(), info.needed.length())
  for i = 0; i < nl.length(); i = i + 1 {
    assert_eq(nl[i], info.needed[i])
  }
  let je = lib.jni_exports()
  assert_eq(je.length(), info.jni_exports.length())
  for i = 0; i < je.length(); i = i + 1 {
    assert_eq(je[i], info.jni_exports[i])
  }
}

///|
/// ELF32 小端：ElfClass::Elf32 与同样字段；Elf32_Sym = 16B、DT_SYMENT = 16。
test "elf_info ELF32 合成 .so：Elf32 与同样字段" {
  let built = er_build(false, 40) // 0x28 ARM
  let lib = er_lib(built.bytes)
  let info = lib.elf_info()
  assert_eq(er_class_str(info.elf_class), "Elf32")
  assert_eq(info.machine, 40)
  assert_eq(info.needed.length(), 2)
  assert_eq(info.needed[0], "libc.so")
  assert_eq(info.needed[1], "libdl.so")
  assert_eq(info.dynamic_symbols.length(), 3)
  assert_eq(info.dynamic_symbols[0].name, "Java_com_example_App_stringFromJNI")
  assert_eq(info.dynamic_symbols[0].defined, true)
  assert_eq(info.dynamic_symbols[1].name, "memcpy")
  assert_eq(info.dynamic_symbols[1].defined, false)
  assert_eq(info.dynamic_symbols[2].name, "Java_com_example_App_init")
  assert_eq(info.dynamic_symbols[2].defined, true)
  assert_eq(info.jni_exports.length(), 2)
  assert_eq(info.jni_exports[0], "Java_com_example_App_stringFromJNI")
  assert_eq(info.jni_exports[1], "Java_com_example_App_init")
  let nl = lib.needed_libraries()
  assert_eq(nl.length(), info.needed.length())
  for i = 0; i < nl.length(); i = i + 1 {
    assert_eq(nl[i], info.needed[i])
  }
  let je = lib.jni_exports()
  assert_eq(je.length(), info.jni_exports.length())
  for i = 0; i < je.length(); i = i + 1 {
    assert_eq(je[i], info.jni_exports[i])
  }
}

///|
/// Dart AOT marker：命中、按预设顺序、去重（strtab 内故意乱序 + 重复放入 5 个 marker）。
test "dart_markers 命中按预设顺序且去重" {
  for is64 in [true, false] {
    let built = er_build(is64, 183)
    let lib = er_lib(built.bytes)
    let info = lib.elf_info()
    let m = info.dart_markers
    assert_eq(m.length(), 5)
    assert_eq(m[0], "_kDartVmSnapshotInstructions")
    assert_eq(m[1], "_kDartIsolateSnapshotInstructions")
    assert_eq(m[2], "_kDartIsolateSnapshotData")
    assert_eq(m[3], "KernelProgramInfo")
    assert_eq(m[4], "CodeSourceMap")
  }
}

///|
/// 错误路径：截断 / 坏 magic / EI_CLASS=3 / 缺 PT_DYNAMIC / 缺 DT_STRTAB /
/// DT_STRTAB 越界 —— 两种位宽一律抛 BadElf，不 panic、不静默成功。
test "畸形 ELF 一律抛 BadElf、不 panic、不静默成功" {
  for is64 in [true, false] {
    let built = er_build(is64, 183)
    let b = built.bytes
    // 截断：覆盖 ident / 头 / program header 表 / dynamic 段多处边界。
    for n in [0, 4, 20, 100] {
      assert_true(
        er_is_bad(fx_cut(b, n)),
        msg="截断到 \{n} 字节必须抛 BadElf",
      )
    }
    // 坏 magic。
    assert_true(
      er_is_bad(patch_byte(b, 0, 0x00)),
      msg="坏 magic 必须抛 BadElf",
    )
    // EI_CLASS = 3（既非 ELF32 也非 ELF64）。
    assert_true(
      er_is_bad(patch_byte(b, 4, 3)),
      msg="EI_CLASS=3 必须抛 BadElf",
    )
    // 缺 PT_DYNAMIC：把第 3 个 phdr 的 p_type 改成 PT_NULL(0)。
    assert_true(
      er_is_bad(patch_u32(b, built.dynamic_ph_type_off, 0)),
      msg="缺 PT_DYNAMIC 必须抛 BadElf",
    )
    // 缺 DT_STRTAB：把该条 d_tag 改成未知 tag（不再是 DT_STRTAB=5）。
    assert_true(
      er_is_bad(patch_u32(b, built.strtab_tag_off, 0x7777)),
      msg="缺 DT_STRTAB 必须抛 BadElf",
    )
    // DT_STRTAB 越界：d_val 改成不属于任何 PT_LOAD 的虚拟地址。
    assert_true(
      er_is_bad(patch_u32(b, built.strtab_val_off, 0x7FFFFFF0)),
      msg="DT_STRTAB 越界必须抛 BadElf",
    )
  }
}
