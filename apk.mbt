///|
/// APK 容器层解析库：ZIP 中央目录索引 + Android 专有结构定位。
///
/// 契约决策（见 DECISIONS.md §1）：本库是「ZIP 目录 + 索引」，只产出原始字节与位置信息，
/// 不编排 `axml` / `dex` 的解析结果。这样 `apk` 对下游格式零知识，逆向入参可任意组合。
/// 不解析 AXML / DEX 语义、不做签名校验、不打包、不修改 ZIP。
///
/// ZIP 读取实现：EOCD / 中央目录 / local header 由本包解析（所有错误携带目录偏移或条目名），
/// DEFLATE 解压复用文档授权依赖 `bobzhang/zip/deflate`（Apache-2.0，审计见 DECISIONS.md §3）。
/// ZIP64 一律拒绝（`Zip64Unsupported`），符合 `ApkError` 契约。

///|
/// Android ABI 分类。
pub(all) enum Abi {
  ArmeabiV7a
  Arm64V8a
  X86
  X86_64
  Unknown(String)
}

///|
/// APK 签名方案（v1 = JAR 签名；v2/v3/v3.1 = APK Signing Block）。
pub(all) enum SignatureScheme {
  V1
  V2
  V3
  V31
}

///|
/// ZIP 中央目录条目的最小索引。偏移为条目结构在原 `Bytes` 内的位置。
/// `local_header_off` 为 local file header 偏移；数据区偏移 = local_header_off + 30 +
/// local 文件名长 + local 扩展域长。`is_aligned` 表示数据区偏移是否 4 字节对齐（zipalign 约定）。
pub(all) struct ZipEntryRef {
  name : String
  compressed_size : UInt64
  uncompressed_size : UInt64
  crc32 : UInt32
  compression_method : Int32
  local_header_off : UInt64
  is_aligned : Bool
}

///|
/// DEX 条目：只给名字与原始字节，不调用 `dex` 库。
pub(all) struct DexEntry {
  name : String
  bytes : Bytes
}

///|
/// native 库条目：按 ABI 归类后的路径与原始字节。
pub(all) struct NativeLib {
  abi : Abi
  path : String
  bytes : Bytes
}

///|
/// Manifest 引用：只给二进制 AXML 原始字节，由调用方交给 `axml::parse`。
pub(all) struct ManifestRef {
  entry_name : String
  raw : Bytes
}

///|
/// 签名块摘要。`certificates` 保存 DER 原始字节，不做证书链校验。
/// v2/v3/v3.1 的证书从签名块 signer 结构中按长度前缀定位提取；
/// v1（JAR 签名）的证书从 `META-INF/*.RSA|*.DSA|*.EC` 的 PKCS#7 封装中提取。
///
/// `verified` 语义（**重要**）：为 `true` 当且仅当「签名结构解析通过 **且** 本地可验证的
/// 摘要全部一致」——v1 为 MANIFEST 条目摘要 + `.SF` 对 MANIFEST 的摘要；v2/v3/v3.1 为
/// APK 内容分块摘要（SHA-256）。它**不表示签名有效**：本库没有 RSA/ECDSA 公钥验签能力，
/// 不校验证书链，也不做签名值验证。需要逐项判定时用 `Apk::signature_checks()`，
/// 其中 `signature_verified` 恒为 `false`。
pub(all) struct SignatureInfo {
  scheme : SignatureScheme
  block_id : UInt32
  certificates : Array[Bytes]
  verified : Bool
}

///|
/// `resources.arsc` 引用：第一阶段只读全局字符串池，不展开包/类型/配置项。
/// `global_string_pool` 为 arsc 中全局字符串池 chunk 的完整原始字节（含 chunk 头）。
pub(all) struct ResourceTableRef {
  entry_name : String
  raw : Bytes
  global_string_pool : Bytes
}

///|
/// APK 容器视图。持有原始 `Bytes` 与索引；纯值，无外部句柄、无需释放。
pub(all) struct Apk {
  source : Bytes
  entries : Array[ZipEntryRef]
  signing_block_off : UInt64?
}

///|
/// APK 错误模型。
#derive(Debug)
pub suberror ApkError {
  UnexpectedEof(Int32)
  NotAZip(String)
  BadCentralDirectory(Int32, String)
  Zip64Unsupported(String)
  EntryNotFound(String)
  BadSigningBlock(Int32, String)
  UnsupportedSignatureScheme(String)
  BadAlignment(String, Int32)
  /// `resources.arsc` 完整展开时的结构错误（offset = arsc 内绝对偏移）。
  BadResourceTable(Int32, String)
  /// ELF 头结构错误（offset = ELF 字节内偏移）。
  BadElf(Int32, String)
}

///|
pub extend ApkError with Debug::{to_repr}

///|
/// 条目名（ZIP 内以 `/` 分隔的相对路径）。
pub type EntryName = String

///|
/// 容器只读索引契约；实现方必须保证 `entry` 不做任何解压以外的语义解释。
pub trait ContainerIndex {
  fn entry(Self, EntryName) -> Bytes raise ApkError
  fn entries(Self) -> Array[ZipEntryRef]
}

///|
/// 打开一个 APK 字节流并构建中央目录索引。
///
/// - 参数：`source` 为完整 APK 字节；所有权由调用方保留，`Apk` 只做只读引用。
/// - 返回：`Apk` 纯值索引；不解压业务条目（惰性，见 `Apk::entry`）。
/// - 错误：EOCD / 中央目录 / ZIP64 / 签名块 / 结构截断均以 `ApkError` 传播（带偏移）。
/// - 线程：无可变全局状态，索引只读，可并发查询。
/// - 非目标：不反编译、不签名、不打包、不修改 ZIP、不做证书链验证。
/// - 实现要点：定位 EOCD（拒绝 ZIP64 标记与 ZIP64 locator）、解析中央目录、
///   校验每个 local file header 并计算数据区 4 字节对齐标志、定位 APK Signing Block。
pub fn Apk::open(source : Bytes) -> Apk raise ApkError {
  let len = source.length()
  let eocd_off = match find_eocd(source) {
    Some(o) => o
    None =>
      if looks_like_zip(source) {
        raise ApkError::UnexpectedEof(len)
      } else if len < 22 {
        raise ApkError::NotAZip(
          "file too small to contain a ZIP end-of-central-directory record",
        )
      } else {
        raise ApkError::NotAZip("missing ZIP end-of-central-directory record")
      }
  }
  let disk = le_u16(source, eocd_off + 4)
  let cd_disk = le_u16(source, eocd_off + 6)
  let entries_disk = le_u16(source, eocd_off + 8)
  let entries_total = le_u16(source, eocd_off + 10)
  let cd_size_v = le_u32(source, eocd_off + 12)
  let cd_off_v = le_u32(source, eocd_off + 16)
  if entries_total == 0xFFFF ||
    cd_size_v == 0xFFFFFFFF ||
    cd_off_v == 0xFFFFFFFF {
    raise ApkError::Zip64Unsupported(
      "ZIP64 sentinel values in the end-of-central-directory record",
    )
  }
  if eocd_off >= 20 && le_u32(source, eocd_off - 20) == ZIP64_EOCD_LOCATOR_SIG {
    raise ApkError::Zip64Unsupported(
      "ZIP64 end-of-central-directory locator present",
    )
  }
  if disk != 0 || cd_disk != 0 {
    raise ApkError::BadCentralDirectory(
      eocd_off, "multi-disk archives are not supported",
    )
  }
  if entries_disk != entries_total {
    raise ApkError::BadCentralDirectory(
      eocd_off, "inconsistent entry counts in the end-of-central-directory record",
    )
  }
  let cd_off64 = cd_off_v.to_uint64()
  let cd_size64 = cd_size_v.to_uint64()
  if cd_off64 + cd_size64 > len.to_uint64() {
    raise ApkError::BadCentralDirectory(
      clamp_off(cd_off64, len),
      "central directory extends past end of file",
    )
  }
  if cd_off64 + cd_size64 != eocd_off.to_uint64() {
    raise ApkError::BadCentralDirectory(
      clamp_off(cd_off64, len),
      "central directory does not end at the end-of-central-directory record",
    )
  }
  let cd_off = cd_off64.to_int()
  let cd_end = cd_off + cd_size64.to_int()
  let entries : Array[ZipEntryRef] = []
  let mut pos = cd_off
  for i = 0; i < entries_total; i = i + 1 {
    guard pos + 46 <= cd_end else {
      raise ApkError::BadCentralDirectory(
        pos, "central directory entry exceeds the directory region",
      )
    }
    guard le_u32(source, pos) == ZIP_CENTRAL_SIG else {
      raise ApkError::BadCentralDirectory(
        pos, "bad central directory entry signature",
      )
    }
    let comp_method = le_u16(source, pos + 10)
    let crc = le_u32(source, pos + 16)
    let comp_size = le_u32(source, pos + 20)
    let uncomp_size = le_u32(source, pos + 24)
    let name_len = le_u16(source, pos + 28)
    let extra_len = le_u16(source, pos + 30)
    let comment_len = le_u16(source, pos + 32)
    let local_off = le_u32(source, pos + 42)
    let rec_end = pos + 46 + name_len + extra_len + comment_len
    guard rec_end <= cd_end else {
      raise ApkError::BadCentralDirectory(
        pos, "central directory entry exceeds the directory region",
      )
    }
    let name = decode_entry_name(source, pos + 46, pos + 46 + name_len, pos)
    if comp_size == 0xFFFFFFFF ||
      uncomp_size == 0xFFFFFFFF ||
      local_off == 0xFFFFFFFF {
      raise ApkError::Zip64Unsupported(
        "entry '" + name + "' uses ZIP64 sizes or offsets",
      )
    }
    let extra_start = pos + 46 + name_len
    if extra_field_has_id(
        source[extra_start:extra_start + extra_len],
        ZIP64_EXTRA_ID,
      ) {
      raise ApkError::Zip64Unsupported(
        "entry '" + name + "' carries a ZIP64 extra field",
      )
    }
    let lo64 = local_off.to_uint64()
    if lo64 + 30 > len.to_uint64() {
      raise ApkError::UnexpectedEof(clamp_off(lo64, len))
    }
    let lo = lo64.to_int()
    if le_u32(source, lo) != ZIP_LOCAL_SIG {
      raise ApkError::BadCentralDirectory(
        lo,
        "entry '" + name + "': local file header signature mismatch",
      )
    }
    let l_name_len = le_u16(source, lo + 26)
    let l_extra_len = le_u16(source, lo + 28)
    let data_off64 = lo64 +
      30 +
      l_name_len.to_uint64() +
      l_extra_len.to_uint64()
    if data_off64 + comp_size.to_uint64() > len.to_uint64() {
      raise ApkError::UnexpectedEof(clamp_off(data_off64, len))
    }
    let data_off = data_off64.to_int()
    entries.push({
      name,
      compressed_size: comp_size.to_uint64(),
      uncompressed_size: uncomp_size.to_uint64(),
      crc32: crc,
      compression_method: comp_method,
      local_header_off: lo64,
      is_aligned: data_off % 4 == 0,
    })
    pos = rec_end
  }
  if pos != cd_end {
    raise ApkError::BadCentralDirectory(
      pos, "central directory size does not match its entry count",
    )
  }
  let mut signing_block_off : UInt64? = None
  if cd_off >= 24 && is_apk_sig_block_magic(source, cd_off - 16) {
    let size_off = cd_off - 24
    let size2 = le_u64(source, size_off)
    if size2 < 24 || size2 > cd_off.to_uint64() - 8 {
      raise ApkError::BadSigningBlock(
        size_off, "APK Signing Block size is out of range",
      )
    }
    let block_start = (cd_off.to_uint64() - size2 - 8).to_int()
    let size1 = le_u64(source, block_start)
    if size1 != size2 {
      raise ApkError::BadSigningBlock(
        block_start, "mismatched APK Signing Block size fields",
      )
    }
    signing_block_off = Some(block_start.to_uint64())
  }
  { source, entries, signing_block_off, }
}

///|
/// 返回全部 ZIP 条目索引（中央目录顺序）。
pub fn Apk::entries(self : Apk) -> Array[ZipEntryRef] {
  self.entries.copy()
}

///|
/// 返回 `AndroidManifest.xml` 的原始 AXML 字节（供 `axml::parse` 消费）。
pub fn Apk::manifest(self : Apk) -> ManifestRef raise ApkError {
  {
    entry_name: "AndroidManifest.xml",
    raw: extract_entry(self.source, self.entries, "AndroidManifest.xml"),
  }
}

///|
/// 返回 `classes*.dex` 列表（按名字典序排序，只给字节，不解析 DEX）。
pub fn Apk::dex_files(self : Apk) -> Array[DexEntry] raise ApkError {
  let out : Array[DexEntry] = []
  for e in self.entries {
    if is_dex_name(e.name) {
      out.push({ name: e.name, bytes: extract_data(self.source, e), })
    }
  }
  out.sort_by(fn(a, b) { name_compare(a.name, b.name) })
  out
}

///|
/// 返回指定 ABI 的 `lib/<abi>/*.so` 列表；`abi = None` 返回全部并各自标注 ABI。
///
/// ABI 归类**只依据 `lib/<abi>/` 目录名**（与 aapt2 `native-code` 口径一致），不解析
/// ELF 内容；内容侧交叉校验用 `NativeLib::elf_abi()`。
pub fn Apk::native_libs(
  self : Apk,
  abi : Abi?,
) -> Array[NativeLib] raise ApkError {
  let out : Array[NativeLib] = []
  for e in self.entries {
    match lib_abi_of(e.name) {
      Some(a) => {
        let wanted = match abi {
          Some(w) => abi_eq(w, a)
          None => true
        }
        if wanted {
          out.push({
            abi: a,
            path: e.name,
            bytes: extract_data(self.source, e),
          })
        }
      }
      None => ()
    }
  }
  out
}

///|
/// 从 ELF 头读取内容侧 ABI（交叉校验用，不替代 `NativeLib.abi` 的目录归类）。
///
/// 只读 ELF 头：magic `\x7fELF`、EI_CLASS（1=32/2=64）、EI_DATA（必须 1=小端）、
/// `e_machine`（18..19 小端）。返回：
/// - `EM_ARM(40)` → `ArmeabiV7a`；`EM_AARCH64(183)` → `Arm64V8a`；
/// - `EM_386(3)` → `X86`；`EM_X86_64(62)` → `X86_64`；
/// - `EM_RISCV(243)` / `EM_MIPS(8)` / 其他 → `Unknown(...)`（保留机器类型）。
///
/// 非法 ELF（magic/class/data 异常、头截断）报 `BadElf(offset, detail)`，不 panic。
/// 典型用途：发现「目录写 x86_64、内容其实是 arm64」的错标 APK。
pub fn NativeLib::elf_abi(self : NativeLib) -> Abi raise ApkError {
  let b = self.bytes
  let len = b.length()
  if len < 20 {
    raise ApkError::BadElf(len, "ELF header truncated (< 20 bytes)")
  }
  if b[0].to_int() != 0x7F ||
    b[1].to_int() != 0x45 ||
    b[2].to_int() != 0x4C ||
    b[3].to_int() != 0x46 {
    raise ApkError::BadElf(0, "missing ELF magic")
  }
  let ei_class = b[4].to_int()
  if ei_class != 1 && ei_class != 2 {
    raise ApkError::BadElf(4, "unsupported ELF class")
  }
  let ei_data = b[5].to_int()
  if ei_data != 1 {
    raise ApkError::BadElf(
      5, "unsupported ELF data encoding (only little-endian)",
    )
  }
  let machine = b[18].to_int() | (b[19].to_int() << 8)
  match machine {
    40 => Abi::ArmeabiV7a
    183 => Abi::Arm64V8a
    3 => Abi::X86
    62 => Abi::X86_64
    243 => Abi::Unknown("riscv64")
    8 => Abi::Unknown("mips")
    _ => Abi::Unknown("elf-machine-" + machine.to_string())
  }
}

///|
/// 返回已识别的签名方案摘要。
///
/// - v1：`META-INF/*.RSA|*.DSA|*.EC` 存在即识别；证书从 PKCS#7 提取（解析失败时为空），
///   `block_id` 为 0。`verified` 需 MANIFEST 条目摘要与 `.SF` 清单摘要全部一致。
/// - v2/v3/v3.1：解析 APK Signing Block 的 ID-value 对（0x7109871a / 0xf05368c0 /
///   0x1b93ad61），从 signer 结构按长度前缀提取 DER 证书与摘要记录；`verified` 需
///   APK 内容分块摘要（SHA-256）与签名块中的摘要一致。
/// - 未知 ID-value 对（如 verity padding）跳过；块内没有任何受支持方案时报
///   `UnsupportedSignatureScheme`；块结构异常报 `BadSigningBlock`。
///
/// **边界**：`verified` = 结构 + 摘要校验通过，**≠ 签名有效**（无 RSA/ECDSA 验签）。
/// 逐项结论见 `Apk::signature_checks()`。
pub fn Apk::signatures(self : Apk) -> Array[SignatureInfo] raise ApkError {
  let out : Array[SignatureInfo] = []
  for rec in self.collect_signature_records() {
    let check = self.verify_signature_record(rec)
    out.push({
      scheme: rec.scheme,
      block_id: rec.block_id,
      certificates: rec.certs,
      verified: check.structure_ok && check.digest_ok,
    })
  }
  out
}

///|
/// 返回 `resources.arsc` 引用（仅全局字符串池）；无该条目返回 `None`。
///
/// 这是**轻量索引**路径（只切出全局字符串池 chunk，不展开包/类型）。完整展开用
/// `Apk::resource_table_full()`。
pub fn Apk::resource_table(self : Apk) -> ResourceTableRef? raise ApkError {
  for e in self.entries {
    if e.name == "resources.arsc" {
      let raw = extract_data(self.source, e)
      return Some({
        entry_name: "resources.arsc",
        raw,
        global_string_pool: arsc_global_string_pool(raw),
      })
    }
  }
  None
}

///|
/// 返回 `resources.arsc` 的**完整展开**结果（全局字符串池 + package/typeSpec/
/// type 条目/复杂 bag）；无该条目返回 `None`。
///
/// 解析规则见 `arsc.mbt` 顶部文档；畸形结构报 `BadResourceTable` /
/// `UnexpectedEof`（带 arsc 内绝对偏移），不 panic。
pub fn Apk::resource_table_full(self : Apk) -> ResTable? raise ApkError {
  for e in self.entries {
    if e.name == "resources.arsc" {
      return Some(parse_resources_arsc(extract_data(self.source, e)))
    }
  }
  None
}

///|
/// 按条目名返回解压后的原始字节；未命中返回 `EntryNotFound`。
pub fn Apk::entry(self : Apk, name : EntryName) -> Bytes raise ApkError {
  extract_entry(self.source, self.entries, name)
}

///|
/// `ContainerIndex` 只读索引契约的实现（语义与 `Apk::entry` / `Apk::entries` 一致）。
pub impl ContainerIndex for Apk with fn entry(self : Apk, name : EntryName) -> Bytes raise ApkError {
  extract_entry(self.source, self.entries, name)
}

///|
pub impl ContainerIndex for Apk with fn entries(self : Apk) -> Array[
  ZipEntryRef,
] {
  self.entries.copy()
}

///|
/// ZIP 结构魔数（小端常量）。
const ZIP_LOCAL_SIG : UInt32 = 0x04034b50

///|
const ZIP_CENTRAL_SIG : UInt32 = 0x02014b50

///|
const ZIP_EOCD_SIG : UInt32 = 0x06054b50

///|
const ZIP64_EOCD_LOCATOR_SIG : UInt32 = 0x07064b50

///|
const ZIP64_EXTRA_ID : Int32 = 0x0001

///|
/// APK Signing Block 方案 ID。
const SIG_ID_V2 : UInt32 = 0x7109871a

///|
const SIG_ID_V3 : UInt32 = 0xf05368c0

///|
const SIG_ID_V31 : UInt32 = 0x1b93ad61

///|
/// APK Signing Block 魔数 "APK Sig Block 42"（16 字节）。
let apk_sig_block_magic : Bytes = @encoding/utf8.encode("APK Sig Block 42")

///|
/// 小端读取工具。越界由调用方先行校验，因此不抛错。
fn le_u16(b : Bytes, off : Int32) -> Int32 {
  b[off].to_int() | (b[off + 1].to_int() << 8)
}

///|
fn le_u32(b : Bytes, off : Int32) -> UInt32 {
  b[off].to_uint() |
  (b[off + 1].to_uint() << 8) |
  (b[off + 2].to_uint() << 16) |
  (b[off + 3].to_uint() << 24)
}

///|
fn le_u64(b : Bytes, off : Int32) -> UInt64 {
  le_u32(b, off).to_uint64() | (le_u32(b, off + 4).to_uint64() << 32)
}

///|
/// 把超出文件长度的偏移夹到 `len`，保证错误里的偏移始终可用。
fn clamp_off(v : UInt64, len : Int32) -> Int32 {
  if v > len.to_uint64() {
    len
  } else {
    v.to_int()
  }
}

///|
/// CRC-32（IEEE 多项式 0xEDB88320，初值 0xFFFFFFFF）。
fn crc32_of(data : Bytes) -> UInt32 {
  let mut crc : UInt32 = 0xFFFFFFFF
  for i = 0; i < data.length(); i = i + 1 {
    let mut c = (crc ^ data[i].to_uint()) & 0xFF
    for j = 0; j < 8; j = j + 1 {
      c = if (c & 1) == 1 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 }
    }
    crc = (crc >> 8) ^ c
  }
  crc ^ 0xFFFFFFFF
}

///|
/// 判断字节流是否以 ZIP 系列魔数开头（用于区分「截断的 ZIP」与「根本不是 ZIP」）。
fn looks_like_zip(data : Bytes) -> Bool {
  if data.length() < 4 {
    return false
  }
  let sig = le_u32(data, 0)
  sig == ZIP_LOCAL_SIG || sig == ZIP_CENTRAL_SIG || sig == ZIP_EOCD_SIG
}

///|
/// 定位 EOCD（end of central directory）记录偏移。
///
/// 从文件尾部向前扫描；只有当 `comment_len` 恰好使记录收尾于 EOF 时才接受该候选，
/// 从而跳过条目数据/注释中伪造的 EOCD 签名。找不到返回 `None`。
fn find_eocd(data : Bytes) -> Int32? {
  let len = data.length()
  if len < 22 {
    return None
  }
  let search_start = if len > 65557 { len - 65557 } else { 0 }
  for i = len - 22; i >= search_start; i = i - 1 {
    if le_u32(data, i) == ZIP_EOCD_SIG {
      let comment_len = le_u16(data, i + 20)
      if i + 22 + comment_len == len {
        return Some(i)
      }
    }
  }
  None
}

///|
/// 判断偏移处是否为 APK Signing Block 魔数。
fn is_apk_sig_block_magic(data : Bytes, off : Int32) -> Bool {
  data.length() >= off + 16 &&
  data[off:off + 16].equal_to_bytes(apk_sig_block_magic)
}

///|
/// 解码中央目录条目名（严格 UTF-8，非法编码按目录损坏处理）。
fn decode_entry_name(
  source : Bytes,
  start : Int32,
  end : Int32,
  rec_off : Int32,
) -> String raise ApkError {
  @encoding/utf8.decode(source[start:end]) catch {
    _ =>
      raise ApkError::BadCentralDirectory(
        rec_off, "entry name is not valid UTF-8",
      )
  }
}

///|
/// 扫描 ZIP 扩展域中是否包含指定 ID（用于识别 ZIP64 扩展域 0x0001）。
fn extra_field_has_id(extra : BytesView, target : Int32) -> Bool {
  let total = extra.length()
  let mut pos = 0
  while pos + 4 <= total {
    let id = extra[pos].to_int() | (extra[pos + 1].to_int() << 8)
    let size = extra[pos + 2].to_int() | (extra[pos + 3].to_int() << 8)
    if id == target {
      return true
    }
    pos = pos + 4 + size
  }
  false
}

///|
/// 按条目名取回解压后的原始字节（惰性，每次独立分配输出缓冲）。
fn extract_entry(
  source : Bytes,
  index : Array[ZipEntryRef],
  name : String,
) -> Bytes raise ApkError {
  for e in index {
    if e.name == name {
      return extract_data(source, e)
    }
  }
  raise ApkError::EntryNotFound(name)
}

///|
/// 解压单个条目：stored 直接切片、deflate 走 `bobzhang/zip/deflate`；
/// 压缩方法 / CRC-32 / 尺寸一致性都在这里校验。
fn extract_data(source : Bytes, e : ZipEntryRef) -> Bytes raise ApkError {
  let len64 = source.length().to_uint64()
  let lo64 = e.local_header_off
  if lo64 + 30 > len64 {
    raise ApkError::UnexpectedEof(clamp_off(lo64, source.length()))
  }
  let lo = lo64.to_int()
  if le_u32(source, lo) != ZIP_LOCAL_SIG {
    raise ApkError::BadCentralDirectory(
      lo,
      "entry '" + e.name + "': local file header signature mismatch",
    )
  }
  let gp = le_u16(source, lo + 6)
  if (gp & 1) == 1 {
    raise ApkError::BadCentralDirectory(
      lo,
      "entry '" + e.name + "': encrypted entries are not supported",
    )
  }
  let l_name_len = le_u16(source, lo + 26)
  let l_extra_len = le_u16(source, lo + 28)
  let data_off64 = lo64 + 30 + l_name_len.to_uint64() + l_extra_len.to_uint64()
  if data_off64 + e.compressed_size > len64 {
    raise ApkError::UnexpectedEof(clamp_off(data_off64, source.length()))
  }
  let data_off = data_off64.to_int()
  let comp_len = e.compressed_size.to_int()
  let out = if e.compression_method == 0 {
    if e.compressed_size != e.uncompressed_size {
      raise ApkError::BadCentralDirectory(
        data_off,
        "entry '" + e.name + "': stored entry has mismatched sizes",
      )
    }
    source[data_off:data_off + comp_len].to_owned()
  } else if e.compression_method == 8 {
    let inflated = @deflate.inflate(source[data_off:data_off + comp_len]) catch {
      _ =>
        raise ApkError::BadCentralDirectory(
          data_off,
          "entry '" + e.name + "': deflate stream is invalid",
        )
    }
    if inflated.length().to_uint64() != e.uncompressed_size {
      raise ApkError::BadCentralDirectory(
        data_off,
        "entry '" + e.name + "': uncompressed size mismatch",
      )
    }
    inflated
  } else {
    raise ApkError::BadCentralDirectory(
      data_off,
      "entry '" +
      e.name +
      "': unsupported compression method " +
      e.compression_method.to_string(),
    )
  }
  if crc32_of(out) != e.crc32 {
    raise ApkError::BadCentralDirectory(
      data_off,
      "entry '" + e.name + "': crc32 mismatch",
    )
  }
  out
}

///|
/// 签名方案排序权重（v1 < v2 < v3 < v3.1）。
fn scheme_rank(s : SignatureScheme) -> Int32 {
  match s {
    SignatureScheme::V1 => 0
    SignatureScheme::V2 => 1
    SignatureScheme::V3 => 2
    SignatureScheme::V31 => 3
  }
}

///|
/// 从签名方案值（signer 序列）中提取 DER 证书与摘要记录。
///
/// 布局（APK Signature Scheme v2/v3/v3.1）：
/// value = u32 序列长 { u32 signer 长 signer }*；
/// signer = signed_data(长度前缀) + signatures(长度前缀序列) + public_key(长度前缀)；
/// signed_data = digests(长度前缀序列) + certificates(长度前缀序列)
///          + [v3/v3.1: minSDK(u32) + maxSDK(u32)] + additional_attributes。
/// digests = u32 序列长 { u32 记录长 u32 算法ID u32 摘要长 摘要 }*。
/// 即 v2/v3/v3.1 的 signer 顶层布局一致（sd_prefix = 0）；v3/v3.1 的
/// min/max SDK（v3.1 另有 rotationMinSDK，位于 additional_attributes）在
/// signed_data 内部、certificates 之后，不在 signer 顶层。
/// 结构不合法一律 `BadSigningBlock`（不做任何静默降级）。
fn extract_signer_data(
  source : Bytes,
  sch : SignatureScheme,
  value_off : Int32,
  value_len : Int32,
  pair_off : Int32,
) -> SignerData raise ApkError {
  let certs : Array[Bytes] = []
  let digests : Array[SignerDigest] = []
  let end = value_off + value_len
  let mut pos = value_off
  guard pos + 4 <= end else {
    raise ApkError::BadSigningBlock(pair_off, "signer sequence length missing")
  }
  let seq_len = le_u32(source, pos)
  guard seq_len <= (end - pos - 4).reinterpret_as_uint() else {
    raise ApkError::BadSigningBlock(
      pair_off, "signer sequence overruns signature scheme value",
    )
  }
  let seq_end = pos + 4 + seq_len.reinterpret_as_int()
  pos = pos + 4
  let sd_prefix = match sch {
    SignatureScheme::V2 => 0
    SignatureScheme::V3 => 0
    SignatureScheme::V31 => 0
    SignatureScheme::V1 => 0
  }
  while pos < seq_end {
    guard pos + 4 <= seq_end else {
      raise ApkError::BadSigningBlock(pair_off, "signer length missing")
    }
    let signer_len = le_u32(source, pos)
    guard signer_len <= (seq_end - pos - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(
        pair_off, "signer overruns signer sequence",
      )
    }
    let signer_end = pos + 4 + signer_len.reinterpret_as_int()
    let mut sp = pos + 4 + sd_prefix
    guard sp + 4 <= signer_end else {
      raise ApkError::BadSigningBlock(
        pair_off, "signed data length missing in signer",
      )
    }
    let sd_len = le_u32(source, sp)
    guard sd_len <= (signer_end - sp - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(pair_off, "signed data overruns signer")
    }
    let sd_end = sp + 4 + sd_len.reinterpret_as_int()
    sp = sp + 4
    guard sp + 4 <= sd_end else {
      raise ApkError::BadSigningBlock(
        pair_off, "digests length missing in signed data",
      )
    }
    let digests_len = le_u32(source, sp)
    guard digests_len <= (sd_end - sp - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(pair_off, "digests overrun signed data")
    }
    let digests_end = sp + 4 + digests_len.reinterpret_as_int()
    sp = sp + 4
    while sp < digests_end {
      guard sp + 4 <= digests_end else {
        raise ApkError::BadSigningBlock(
          pair_off, "digest record length missing",
        )
      }
      let rec_len = le_u32(source, sp)
      guard rec_len >= 8 &&
        rec_len <= (digests_end - sp - 4).reinterpret_as_uint() else {
        raise ApkError::BadSigningBlock(
          pair_off, "digest record overruns digests",
        )
      }
      let rec_end = sp + 4 + rec_len.reinterpret_as_int()
      let algorithm = le_u32(source, sp + 4)
      let digest_len = le_u32(source, sp + 8)
      guard digest_len <= rec_len - 8 else {
        raise ApkError::BadSigningBlock(
          pair_off, "digest overruns digest record",
        )
      }
      digests.push({
        algorithm,
        digest: source[sp + 12:sp + 12 + digest_len.reinterpret_as_int()].to_owned(),
      })
      sp = rec_end
    }
    guard sp + 4 <= sd_end else {
      raise ApkError::BadSigningBlock(
        pair_off, "certificates length missing in signed data",
      )
    }
    let certs_len = le_u32(source, sp)
    guard certs_len <= (sd_end - sp - 4).reinterpret_as_uint() else {
      raise ApkError::BadSigningBlock(
        pair_off, "certificates overrun signed data",
      )
    }
    let certs_end = sp + 4 + certs_len.reinterpret_as_int()
    sp = sp + 4
    while sp < certs_end {
      guard sp + 4 <= certs_end else {
        raise ApkError::BadSigningBlock(pair_off, "certificate length missing")
      }
      let cert_len = le_u32(source, sp)
      guard cert_len <= (certs_end - sp - 4).reinterpret_as_uint() else {
        raise ApkError::BadSigningBlock(
          pair_off, "certificate overruns certificate sequence",
        )
      }
      certs.push(
        source[sp + 4:sp + 4 + cert_len.reinterpret_as_int()].to_owned(),
      )
      sp = sp + 4 + cert_len.reinterpret_as_int()
    }
    pos = signer_end
  }
  { certs, digests, }
}

///|
/// 从 `resources.arsc` 原始字节中切出全局字符串池 chunk（含 chunk 头）。
///
/// `resources.arsc` 的 chunk 链按规范 4 字节对齐；类型 / 头长 / 尺寸异常一律
/// `BadAlignment`（name = 条目名、offset = chunk 偏移），截断报 `UnexpectedEof`。
fn arsc_global_string_pool(raw : Bytes) -> Bytes raise ApkError {
  let len = raw.length()
  guard len >= 8 else { raise ApkError::UnexpectedEof(len) }
  let table_type = le_u16(raw, 0)
  let header_size = le_u16(raw, 2)
  let table_size = le_u32(raw, 4)
  if table_type != 0x0002 || header_size != 12 || (table_size & 3) != 0 {
    raise ApkError::BadAlignment("resources.arsc", 0)
  }
  let table_size64 = table_size.to_uint64()
  if table_size64 > len.to_uint64() {
    raise ApkError::UnexpectedEof(len)
  }
  guard len >= 20 else { raise ApkError::UnexpectedEof(len) }
  let pool_type = le_u16(raw, 12)
  let pool_header_size = le_u16(raw, 14)
  let pool_size = le_u32(raw, 16)
  if pool_type != 0x0001 ||
    pool_header_size != 28 ||
    pool_size < 28 ||
    (pool_size & 3) != 0 {
    raise ApkError::BadAlignment("resources.arsc", 12)
  }
  let pool_end64 = pool_size.to_uint64() + 12
  if pool_end64 > table_size64 || pool_end64 > len.to_uint64() {
    raise ApkError::BadAlignment("resources.arsc", 12)
  }
  raw[12:12 + pool_size.reinterpret_as_int()].to_owned()
}

///|
/// 条目名字典序比较（UTF-8 字节序，等价于码点序）。
/// 不用 `String::compare`：其排序语义并非字典序，而 dex 列表要求「按名」确定性字典序。
fn name_compare(x : String, y : String) -> Int32 {
  let bx = @encoding/utf8.encode(x)
  let by = @encoding/utf8.encode(y)
  let n = if bx.length() < by.length() { bx.length() } else { by.length() }
  for i = 0; i < n; i = i + 1 {
    let c = bx[i].to_int() - by[i].to_int()
    if c != 0 {
      return c
    }
  }
  bx.length() - by.length()
}

///|
/// `classes*.dex`（根目录）判定：`classes` 前缀 + `.dex` 后缀、无子目录。
fn is_dex_name(name : String) -> Bool {
  name.has_prefix("classes") &&
  name.has_suffix(".dex") &&
  !name.contains_char('/')
}

///|
/// `lib/<abi>/<file>.so` 归类：恰好三段路径、末段以 `.so` 结尾且不止扩展名。
fn lib_abi_of(name : String) -> Abi? {
  guard name.has_prefix("lib/") && name.has_suffix(".so") else { return None }
  let segs : Array[StringView] = []
  for part in name.split("/") {
    segs.push(part)
  }
  guard segs.length() == 3 && segs[1].length() > 0 && segs[2].length() > 3 else {
    return None
  }
  Some(abi_of_dir(segs[1].to_owned()))
}

///|
/// ABI 目录名 → `Abi`；未知值保留为 `Unknown(String)`。
fn abi_of_dir(s : String) -> Abi {
  if s == "armeabi-v7a" {
    Abi::ArmeabiV7a
  } else if s == "arm64-v8a" {
    Abi::Arm64V8a
  } else if s == "x86" {
    Abi::X86
  } else if s == "x86_64" {
    Abi::X86_64
  } else {
    Abi::Unknown(s)
  }
}

///|
/// `Abi` 结构相等（不给公开类型加 `derive`，避免改动导出接口）。
fn abi_eq(a : Abi, b : Abi) -> Bool {
  match (a, b) {
    (Abi::ArmeabiV7a, Abi::ArmeabiV7a) => true
    (Abi::Arm64V8a, Abi::Arm64V8a) => true
    (Abi::X86, Abi::X86) => true
    (Abi::X86_64, Abi::X86_64) => true
    (Abi::Unknown(x), Abi::Unknown(y)) => x == y
    _ => false
  }
}
