///|
/// ELF 只读结构化侦察（P2 加法性子能力，容器条目自身的只读元数据）。
///
/// 契约边界（见 docs/DECISIONS.md §8）：本能力只读 `NativeLib.bytes` 内的 ELF 结构，
/// 产出 apk 自有值类型（`ElfInfo` / `ElfSymbol` / `ElfClass`），不返回 `axml` / `dex`
/// 等任何下游解析类型、不编排下游解析、不新增跨模块依赖；与 R4 已有的
/// `NativeLib::elf_abi()` 的 ELF 头部解析同构，是「容器条目自身元数据」索引的加深，
/// 不把 `apk` 变成中心节点（ADR-0003 的容器层边界不变）。
///
/// 只读范围：ELF32/ELF64 头（EI_CLASS / EI_DATA / `e_machine` / program headers）、
/// `PT_DYNAMIC` 的 `DT_*` 条目、`DT_NEEDED` 依赖库名、动态符号表（name / defined）、
/// 以及一次线性字节扫描命中的 Dart AOT marker 名。
/// **不做** 反汇编 / 符号执行 / 重定位展开 / ELF 装载；**不做** Dart AOT 快照格式解析
/// —— `dart_markers` 仅是「字节模式命中」，对象图 / 指令表 / 快照版本语义 [仍需实测]，
/// 不得据命中项断言任何 Dart 语义。
///
/// 错误模型：所有越界 / 截断 / 坏 magic / 坏 EI_CLASS / 坏 EI_DATA / 坏 PT_DYNAMIC /
/// 虚拟地址未落在 `PT_LOAD` / 坏 `DT_STRTAB` / 坏 `DT_HASH` 一律
/// `ApkError::BadElf(offset, reason)`（复用既有构造，不新增错误变体），
/// 不 panic、不返回带部分结果的静默成功；`offset` 为 `NativeLib.bytes` 内偏移。
/// 名字解码：从 strtab 读 NUL 结尾串，按 UTF-8 解码并要求可打印；空名 / 非 UTF-8 /
/// 截断 / 含控制字符一律**跳过该名字**（不是结构错误），取舍理由见 `elf_cstring`。

///|
/// ELF 位宽（`EI_CLASS`：1 → `Elf32`，2 → `Elf64`）。
pub(all) enum ElfClass {
  Elf32
  Elf64
}

///|
/// 动态符号表中的一条符号。`name` 来自 `DT_STRTAB`；
/// `defined` = `st_shndx != SHN_UNDEF(0)`（未定义即导入符号）。
pub(all) struct ElfSymbol {
  name : String
  defined : Bool
}

///|
/// `NativeLib::elf_info()` 的只读结构化结果（全部是 apk 自有值类型与 `String`）。
/// - `jni_exports`：`dynamic_symbols` 中 `defined == true` 且名字以 `Java_` 开头者，
///   按 dynsym 顺序；
/// - `dart_markers`：命中的预设 marker 名，去重、按预设顺序（字节模式命中，非快照解析）。
pub(all) struct ElfInfo {
  elf_class : ElfClass
  machine : Int32
  needed : Array[String]
  dynamic_symbols : Array[ElfSymbol]
  jni_exports : Array[String]
  dart_markers : Array[String]
}

///|
/// program header 类型常量。
let elf_pt_load : Int32 = 1

///|
let elf_pt_dynamic : Int32 = 2

///|
/// dynamic 段 `d_tag` 常量（`Elf64_Sxword` / `Elf32_Sword` 均按无符号比较）。
let elf_dt_null : UInt64 = 0UL

///|
let elf_dt_needed : UInt64 = 1UL

///|
let elf_dt_hash : UInt64 = 4UL

///|
let elf_dt_strtab : UInt64 = 5UL

///|
let elf_dt_symtab : UInt64 = 6UL

///|
let elf_dt_syment : UInt64 = 11UL

///|
/// `DT_GNU_HASH` = 0x6ffffef5。
let elf_dt_gnu_hash : UInt64 = 1879047925UL

///|
/// dynsym 条目数绝对上限：防止畸形 `DT_HASH.nchain` / 距离上界导致放大或越界。
let elf_max_dynsym : Int32 = 65536

///|
/// Dart AOT 线索 marker（预设顺序；输出按此顺序、去重）。
/// 这是字节模式命中集合，**不是** Dart AOT 快照格式解析；对象图 / 指令表语义 [仍需实测]。
let elf_dart_marker_names : Array[String] = [
  "_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions", "_kDartIsolateSnapshotData",
  "KernelProgramInfo", "CodeSourceMap",
]

///|
/// 一个 program header 的只读索引（vaddr / filesz 保留为 `UInt64` 便于越界判定）。
priv struct ElfSegment {
  p_type : Int32
  p_offset : Int32
  p_vaddr : UInt64
  p_filesz : UInt64
}

///|
/// ELF 头 + program headers 的只读解析结果。
priv struct ElfLayout {
  is64 : Bool
  little : Bool
  machine : Int32
  segments : Array[ElfSegment]
}

///|
/// `PT_DYNAMIC` 中我们关心的 `DT_*` 值（`d_val` 原样保留为虚拟地址 / strtab 索引 / 尺寸）。
priv struct ElfDyn {
  needed : Array[UInt64]
  strtab : UInt64?
  symtab : UInt64?
  syment : UInt64?
  hash : UInt64?
  has_gnu_hash : Bool
}

///|
/// 把错误偏移夹到 `[0, len]`，保证 `BadElf` 的 `offset` 始终是可用值。
fn elf_clamp(b : Bytes, off : Int32) -> Int32 {
  if off < 0 {
    0
  } else if off > b.length() {
    b.length()
  } else {
    off
  }
}

///|
/// 定宽 u16 读取（按 `EI_DATA` 字节序）；越界一律 `BadElf`。
fn elf_r16(b : Bytes, off : Int32, little : Bool) -> Int32 raise ApkError {
  guard off >= 0 && off + 2 <= b.length() else {
    raise ApkError::BadElf(elf_clamp(b, off), "ELF u16 read out of bounds")
  }
  let b0 = b[off].to_int()
  let b1 = b[off + 1].to_int()
  if little {
    b0 | (b1 << 8)
  } else {
    (b0 << 8) | b1
  }
}

///|
/// 定宽 u32 读取（按 `EI_DATA` 字节序）；越界一律 `BadElf`。
fn elf_r32(b : Bytes, off : Int32, little : Bool) -> UInt32 raise ApkError {
  guard off >= 0 && off + 4 <= b.length() else {
    raise ApkError::BadElf(elf_clamp(b, off), "ELF u32 read out of bounds")
  }
  let b0 = b[off].to_uint()
  let b1 = b[off + 1].to_uint()
  let b2 = b[off + 2].to_uint()
  let b3 = b[off + 3].to_uint()
  if little {
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
  } else {
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  }
}

///|
/// 定宽 u64 读取（`Elf64_Addr` / `Elf64_Xword` / `d_tag`），按 `EI_DATA` 组装高低字。
fn elf_r64(b : Bytes, off : Int32, little : Bool) -> UInt64 raise ApkError {
  let w0 = elf_r32(b, off, little).to_uint64()
  let w1 = elf_r32(b, off + 4, little).to_uint64()
  if little {
    w0 | (w1 << 32)
  } else {
    (w0 << 32) | w1
  }
}

///|
/// 地址宽度字段（`Elf32_Addr` = u32 / `Elf64_Addr` = u64）。
fn elf_addr(
  b : Bytes,
  off : Int32,
  is64 : Bool,
  little : Bool,
) -> UInt64 raise ApkError {
  if is64 {
    elf_r64(b, off, little)
  } else {
    elf_r32(b, off, little).to_uint64()
  }
}

///|
/// 把虚拟地址 / 尺寸转成可用的文件偏移：必须 `<= len`，否则 `BadElf`。
/// 64 位值若超出文件长度说明结构畸形（本机 `Bytes.length()` 为 `Int32`），直接拒绝。
fn elf_off_of(b : Bytes, v : UInt64) -> Int32 raise ApkError {
  guard v <= b.length().to_uint64() else {
    raise ApkError::BadElf(b.length(), "ELF file offset out of bounds")
  }
  v.to_int()
}

///|
/// 解析 ELF 头与 program headers。`EI_DATA` 支持 1=小端 / 2=大端，其余报 `BadElf`；
/// `EI_CLASS` 只支持 1 / 2。所有表边界用 `UInt64` 计算，避免 `Int32` 溢出。
fn elf_parse_header(b : Bytes) -> ElfLayout raise ApkError {
  let len = b.length()
  if len < 16 {
    raise ApkError::BadElf(len, "ELF identification truncated (< 16 bytes)")
  }
  if b[0].to_int() != 0x7F ||
    b[1].to_int() != 0x45 ||
    b[2].to_int() != 0x4C ||
    b[3].to_int() != 0x46 {
    raise ApkError::BadElf(0, "missing ELF magic")
  }
  let ei_class = b[4].to_int()
  let is64 = if ei_class == 2 {
    true
  } else if ei_class == 1 {
    false
  } else {
    raise ApkError::BadElf(4, "unsupported EI_CLASS (not ELF32/ELF64)")
  }
  let ei_data = b[5].to_int()
  let little = if ei_data == 1 {
    true
  } else if ei_data == 2 {
    false
  } else {
    raise ApkError::BadElf(5, "unsupported EI_DATA (not LSB/MSB)")
  }
  let ehsize = if is64 { 64 } else { 52 }
  if len < ehsize {
    raise ApkError::BadElf(len, "ELF header truncated")
  }
  let machine = elf_r16(b, 18, little)
  let phoff_off = if is64 { 32 } else { 28 }
  let phentsize_off = if is64 { 54 } else { 42 }
  let phnum_off = if is64 { 56 } else { 44 }
  let phoff = elf_off_of(b, elf_addr(b, phoff_off, is64, little))
  let phentsize = elf_r16(b, phentsize_off, little)
  let phnum = elf_r16(b, phnum_off, little)
  let min_ph = if is64 { 56 } else { 32 }
  if phentsize < min_ph {
    raise ApkError::BadElf(
      phentsize_off, "e_phentsize smaller than a program header",
    )
  }
  let table_end = phoff.to_uint64() + phnum.to_uint64() * phentsize.to_uint64()
  guard table_end <= len.to_uint64() else {
    raise ApkError::BadElf(
      elf_clamp(b, phoff),
      "program header table out of bounds",
    )
  }
  let segments : Array[ElfSegment] = []
  for i = 0; i < phnum; i = i + 1 {
    let p = phoff + i * phentsize
    let p_type = elf_r32(b, p, little).reinterpret_as_int()
    let off_field = if is64 { p + 8 } else { p + 4 }
    let vaddr_field = if is64 { p + 16 } else { p + 8 }
    let filesz_field = if is64 { p + 32 } else { p + 16 }
    let p_offset = elf_off_of(b, elf_addr(b, off_field, is64, little))
    let p_vaddr = elf_addr(b, vaddr_field, is64, little)
    let p_filesz = elf_addr(b, filesz_field, is64, little)
    segments.push({ p_type, p_offset, p_vaddr, p_filesz, })
  }
  { is64, little, machine, segments, }
}

///|
/// 虚拟地址 → 文件偏移：只经 `PT_LOAD` 的 `[p_vaddr, p_vaddr + p_filesz)` 映射，
/// **不假设 vaddr == offset**（真实 `.so` 普遍带装载基址）。用 `delta < p_filesz`
/// 判定而非 `vaddr < p_vaddr + p_filesz`，避免 `UInt64` 加法回绕。
fn elf_vaddr_to_off(
  b : Bytes,
  segments : Array[ElfSegment],
  vaddr : UInt64,
) -> Int32 raise ApkError {
  for s in segments {
    if s.p_type == elf_pt_load && vaddr >= s.p_vaddr {
      let delta = vaddr - s.p_vaddr
      if delta < s.p_filesz {
        let off64 = s.p_offset.to_uint64() + delta
        guard off64 <= b.length().to_uint64() else {
          raise ApkError::BadElf(
            b.length(),
            "PT_LOAD mapping lands past end of file",
          )
        }
        return off64.to_int()
      }
    }
  }
  raise ApkError::BadElf(
    0, "virtual address is not covered by any PT_LOAD segment",
  )
}

///|
/// 解析 `PT_DYNAMIC` 的 `DT_*` 条目；缺失 `PT_DYNAMIC` / 段越界一律 `BadElf`。
/// `DT_GNU_HASH` 只记录「存在」：其头部不直接给符号总数，条目数由
/// `elf_dynsym_count` 走 symtab→strtab 距离上界推断（见该节注释）。
fn elf_parse_dynamic(b : Bytes, layout : ElfLayout) -> ElfDyn raise ApkError {
  let mut dyn_off : Int32? = None
  let mut dyn_size : UInt64 = 0UL
  for s in layout.segments {
    if s.p_type == elf_pt_dynamic {
      dyn_off = Some(s.p_offset)
      dyn_size = s.p_filesz
    }
  }
  let off = match dyn_off {
    Some(o) => o
    None => raise ApkError::BadElf(0, "missing PT_DYNAMIC segment")
  }
  let entsize = if layout.is64 { 16 } else { 8 }
  let size = elf_off_of(b, dyn_size)
  let end = off + size
  guard off >= 0 && size >= entsize && end <= b.length() else {
    raise ApkError::BadElf(elf_clamp(b, off), "PT_DYNAMIC table out of bounds")
  }
  let needed : Array[UInt64] = []
  let mut strtab : UInt64? = None
  let mut symtab : UInt64? = None
  let mut syment : UInt64? = None
  let mut hash : UInt64? = None
  let mut has_gnu_hash = false
  let mut pos = off
  while pos + entsize <= end {
    let tag = if layout.is64 {
      elf_r64(b, pos, layout.little)
    } else {
      elf_r32(b, pos, layout.little).to_uint64()
    }
    let val = if layout.is64 {
      elf_r64(b, pos + 8, layout.little)
    } else {
      elf_r32(b, pos + 4, layout.little).to_uint64()
    }
    if tag == elf_dt_null {
      break
    }
    if tag == elf_dt_needed {
      needed.push(val)
    } else if tag == elf_dt_hash {
      hash = Some(val)
    } else if tag == elf_dt_gnu_hash {
      has_gnu_hash = true
    } else if tag == elf_dt_strtab {
      strtab = Some(val)
    } else if tag == elf_dt_symtab {
      symtab = Some(val)
    } else if tag == elf_dt_syment {
      syment = Some(val)
    }
    pos = pos + entsize
  }
  { needed, strtab, symtab, syment, hash, has_gnu_hash, }
}

///|
/// 从 strtab 读一条 NUL 结尾名字，解码为 UTF-8 可打印串。
/// 取舍：**跳过**（返回 `None`）而非报错的情形——空名（含索引 0 的 null 符号）、
/// 非 UTF-8、到 EOF 仍无 NUL（截断）、含控制字符 / DEL / C1 控制字符。
/// 理由：这些是「名字内容不可用」，不是 ELF 结构损坏；跳过可让单个坏名字不掩盖
/// 其它符号。结构性的 strtab 越界由 `elf_vaddr_to_off` / `elf_needed` 报 `BadElf`。
fn elf_cstring(b : Bytes, start : Int32) -> String? {
  if start < 0 || start >= b.length() {
    return None
  }
  let mut end = start
  while end < b.length() && b[end].to_int() != 0 {
    end = end + 1
  }
  if end >= b.length() || end == start {
    return None
  }
  let s = @encoding/utf8.decode(b[start:end]) catch { _ => "" }
  if s == "" {
    return None
  }
  for c in s.iter() {
    let v = c.to_int()
    if v < 0x20 || v == 0x7F || (v >= 0x80 && v <= 0x9F) {
      return None
    }
  }
  Some(s)
}

///|
/// 解析 `DT_NEEDED`：`d_val` 是 strtab 内偏移（不是虚拟地址），
/// 经 strtab 文件偏移取值；名字不可用则跳过，偏移越界则 `BadElf`。
fn elf_needed(
  b : Bytes,
  needed : Array[UInt64],
  strtab_off : Int32,
) -> Array[String] raise ApkError {
  let out : Array[String] = []
  for idx in needed {
    let abs = strtab_off.to_uint64() + idx
    guard abs < b.length().to_uint64() else {
      raise ApkError::BadElf(strtab_off, "DT_NEEDED offset out of bounds")
    }
    match elf_cstring(b, abs.to_int()) {
      Some(n) => out.push(n)
      None => ()
    }
  }
  out
}

///|
/// 确定 dynsym 条目数：
/// - 有 `DT_HASH`(SysV)：读 hash 头第 2 个 u32 `nchain` 作为**精确**符号数；
///   若超出文件可容纳量或绝对上限，视为畸形并报 `BadElf`（不静默截断）。
/// - 否则：`DT_GNU_HASH` 头不直接给总数，用 `(strtab_off - symtab_off) / syment`
///   作**上界**保守推断，再夹到「文件可容纳量」与 `elf_max_dynsym`；
///   若连 `DT_GNU_HASH` 都没有，则没有可用哈希线索，不猜测、返回 0（保守空）。
/// 两种路径都 clamping 到上限，防止畸形输入把循环放大 / 越界。
fn elf_dynsym_count(
  b : Bytes,
  layout : ElfLayout,
  dy : ElfDyn,
  sym_off : Int32,
  str_off : Int32,
  syment : Int32,
) -> Int32 raise ApkError {
  guard syment > 0 else {
    raise ApkError::BadElf(sym_off, "invalid DT_SYMENT (zero or negative)")
  }
  let by_file = (b.length() - sym_off) / syment
  match dy.hash {
    Some(hv) => {
      let hoff = elf_vaddr_to_off(b, layout.segments, hv)
      let nchain = elf_r32(b, hoff + 4, layout.little).reinterpret_as_int()
      guard nchain >= 0 && nchain <= by_file && nchain <= elf_max_dynsym else {
        raise ApkError::BadElf(
          hoff, "DT_HASH nchain exceeds file bounds / symbol cap",
        )
      }
      nchain
    }
    None =>
      if !dy.has_gnu_hash {
        0
      } else {
        guard str_off > sym_off else {
          raise ApkError::BadElf(
            sym_off, "DT_GNU_HASH: symtab/strtab order cannot yield a dynsym upper bound",
          )
        }
        let mut upper = (str_off - sym_off) / syment
        if upper > by_file {
          upper = by_file
        }
        if upper > elf_max_dynsym {
          upper = elf_max_dynsym
        }
        upper
      }
  }
}

///|
/// 遍历 dynsym：解析 `st_name` / `st_shndx`，产出顺序与 dynsym 一致；
/// 名字不可用的条目跳过（含索引 0 的 null 符号）。`Elf64_Sym` = 24 B、
/// `Elf32_Sym` = 16 B，`st_shndx` 偏移分别为 6 / 14。
fn elf_dynsymbols(
  b : Bytes,
  little : Bool,
  is64 : Bool,
  sym_off : Int32,
  str_off : Int32,
  syment : Int32,
  count : Int32,
) -> Array[ElfSymbol] raise ApkError {
  let out : Array[ElfSymbol] = []
  for i = 0; i < count; i = i + 1 {
    let so = sym_off + i * syment
    guard so >= 0 && so + syment <= b.length() else {
      raise ApkError::BadElf(
        elf_clamp(b, so),
        "dynamic symbol table entry out of bounds",
      )
    }
    let st_name = elf_r32(b, so, little)
    let shndx_off = if is64 { so + 6 } else { so + 14 }
    let st_shndx = elf_r16(b, shndx_off, little)
    let defined = st_shndx != 0
    let abs = str_off.to_uint64() + st_name.to_uint64()
    if abs < b.length().to_uint64() {
      match elf_cstring(b, abs.to_int()) {
        Some(name) => out.push({ name, defined, })
        None => ()
      }
    }
  }
  out
}

///|
/// JNI 导出名：dynsym 中已定义且名字以 `Java_` 开头者，按 dynsym 顺序。
fn elf_jni(symbols : Array[ElfSymbol]) -> Array[String] {
  let out : Array[String] = []
  for s in symbols {
    if s.defined && s.name.has_prefix("Java_") {
      out.push(s.name)
    }
  }
  out
}

///|
/// 一个可打印 run 内是否出现 marker 字节序列（marker 集合为常量，比较次数受控）。
fn elf_run_contains(b : Bytes, start : Int32, end : Int32, mb : Bytes) -> Bool {
  let ml = mb.length()
  if end - start < ml {
    return false
  }
  let mut i = start
  while i + ml <= end {
    let mut k = 0
    while k < ml {
      if b[i + k].to_int() != mb[k].to_int() {
        break
      }
      k = k + 1
    }
    if k == ml {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// Dart AOT 线索：一次线性扫描 `bytes`，提取长度 ≥ 6 的 ASCII 可打印 run，
/// 与预设 marker 集合比对，返回命中的 marker 名（去重、按预设顺序）。
/// 只维护 run 起点与命中布尔位，**不把任何字符串存入数组**（内存友好，只保留命中项）；
/// 整体 O(N)：每字节只判定一次是否属于 run，run 结束时与固定 5 个 marker 做常数次
/// 字节比较。这是**字节模式命中**，不是 Dart AOT 快照格式解析；对象图 / 指令表语义
/// [仍需实测]，不得据命中项断言语义。
fn elf_dart_markers(b : Bytes) -> Array[String] {
  let names = elf_dart_marker_names
  let mbs : Array[Bytes] = []
  let hit : Array[Bool] = []
  for k = 0; k < names.length(); k = k + 1 {
    mbs.push(@encoding/utf8.encode(names[k]))
    hit.push(false)
  }
  let n = b.length()
  let mut run_start = -1
  let mut i = 0
  while i <= n {
    let mut printable = false
    if i < n {
      let c = b[i].to_int()
      printable = c >= 0x20 && c <= 0x7E
    }
    if printable {
      if run_start < 0 {
        run_start = i
      }
    } else {
      if run_start >= 0 {
        if i - run_start >= 6 {
          for j = 0; j < names.length(); j = j + 1 {
            if !hit[j] && elf_run_contains(b, run_start, i, mbs[j]) {
              hit[j] = true
            }
          }
        }
      }
      run_start = -1
    }
    i = i + 1
  }
  let out : Array[String] = []
  for j = 0; j < names.length(); j = j + 1 {
    if hit[j] {
      out.push(names[j])
    }
  }
  out
}

///|
/// ELF 只读结构化侦察：解析 ELF 头 / program headers / `PT_DYNAMIC`，
/// 产出依赖库名、动态符号表、JNI 导出名与 Dart AOT 字节 marker。
/// 全部入参只读（`self.bytes`），无状态、可并发；越界 / 截断 / 坏结构一律
/// `ApkError::BadElf(offset, reason)`，不 panic、不返回部分结果的静默成功。
pub fn NativeLib::elf_info(self : NativeLib) -> ElfInfo raise ApkError {
  let b = self.bytes
  let layout = elf_parse_header(b)
  let dy = elf_parse_dynamic(b, layout)
  let strtab_vaddr = match dy.strtab {
    Some(v) => v
    None => raise ApkError::BadElf(0, "missing DT_STRTAB")
  }
  let str_off = elf_vaddr_to_off(b, layout.segments, strtab_vaddr)
  let symtab_vaddr = match dy.symtab {
    Some(v) => v
    None => raise ApkError::BadElf(0, "missing DT_SYMTAB")
  }
  let sym_off = elf_vaddr_to_off(b, layout.segments, symtab_vaddr)
  let syment = match dy.syment {
    Some(v) => {
      guard v > 0UL && v <= 64UL else {
        raise ApkError::BadElf(sym_off, "invalid DT_SYMENT value")
      }
      v.to_int()
    }
    None => if layout.is64 { 24 } else { 16 }
  }
  let needed = elf_needed(b, dy.needed, str_off)
  let count = elf_dynsym_count(b, layout, dy, sym_off, str_off, syment)
  let symbols = elf_dynsymbols(
    b,
    layout.little,
    layout.is64,
    sym_off,
    str_off,
    syment,
    count,
  )
  let jni = elf_jni(symbols)
  let markers = elf_dart_markers(b)
  let elf_class = if layout.is64 { ElfClass::Elf64 } else { ElfClass::Elf32 }
  {
    elf_class,
    machine: layout.machine,
    needed,
    dynamic_symbols: symbols,
    jni_exports: jni,
    dart_markers: markers,
  }
}

///|
/// 便利函数：`DT_NEEDED` 依赖库名。内部委托 `elf_info()`，不重复解析逻辑。
pub fn NativeLib::needed_libraries(
  self : NativeLib,
) -> Array[String] raise ApkError {
  let info = self.elf_info()
  info.needed
}

///|
/// 便利函数：JNI 导出名。内部委托 `elf_info()`，不重复解析逻辑。
pub fn NativeLib::jni_exports(self : NativeLib) -> Array[String] raise ApkError {
  let info = self.elf_info()
  info.jni_exports
}
