///|
/// `resources.arsc` 完整展开（apk 自有字节解析，**不 import axml**）。
///
/// 语义与 `axml` 的资源表解析器对齐（AOSP `ResourceTypes.h` / `LoadedArsc.cpp`）：
/// - 顶层 `RES_TABLE_TYPE`（0x0002）+ 全局字符串池 + `RES_TABLE_PACKAGE_TYPE`（0x0200）；
/// - 包内 `RES_TABLE_TYPE_SPEC_TYPE`（0x0202）与 `RES_TABLE_TYPE_TYPE`（0x0201）；
/// - entry offsets 三种编码：dense u32、FLAG_OFFSET16、FLAG_SPARSE；
/// - `ResTable_entry` simple / complex（bag：parent + ResTable_map[]）/ compact（FLAG_COMPACT）；
/// - `ResTable_config` 常用 qualifier + 原始 config 字节；
/// - 未知 chunk（overlayable / staged alias 等）按 headerSize/size 跳过（降级，不报错）。
///
/// 与 `axml` 的差异（边界）：apk 侧只保留「名字 + 值 + 结构」，
/// 不提供 aapt2 风格的值渲染 / 主题求值 / bag 压平 / library 动态包改写；
/// 类型与条目查询为最小集合（`lookup` / `find_id`），供容器层消费者做索引。
/// 错误统一走 `ApkError`（`BadResourceTable` / `UnexpectedEof`），畸形输入不 panic。

///|
/// `Res_value.dataType`（AOSP `Res_value::TYPE_*` 全集）；未知值保留原始字节。
pub(all) enum ResDataType {
  Null
  Reference
  Attribute
  String
  Float
  Dimension
  Fraction
  DynamicReference
  DynamicAttribute
  IntDec
  IntHex
  IntBoolean
  IntColorArgb8
  IntColorRgb8
  IntColorArgb4
  IntColorRgb4
  Unknown(Int32)
}

///|
/// 单个 `Res_value`（32 位数据 + 类型）。
pub(all) struct ResValue {
  data_type : ResDataType
  data : UInt32
}

///|
/// bag 内的一对 name/value（AOSP `ResTable_map`）。
pub(all) struct ResMap {
  name : UInt32
  value : ResValue
}

///|
/// 复杂条目（bag）：父资源 id + 映射数组（AOSP `ResTable_map_entry`）。
pub(all) struct ResBag {
  parent : UInt32
  maps : Array[ResMap]
}

///|
/// 条目取值：简单值（含 compact 编码）或复杂 bag。
pub(all) enum ResEntryValue {
  Simple(ResValue)
  Complex(ResBag)
}

///|
/// 单个资源条目（AOSP `ResTable_entry`）。
/// `flags` 保留 FLAG_COMPLEX(0x0001)/FLAG_PUBLIC(0x0002)/FLAG_WEAK(0x0004)/FLAG_COMPACT(0x0008)。
pub(all) struct ResEntry {
  key : Int32
  key_name : String
  flags : Int32
  value : ResEntryValue
}

///|
/// 一个资源配置（AOSP `ResTable_config`）；未覆盖字段完整保留在 `raw`。
pub(all) struct ResConfig {
  size : Int32
  mcc : Int32
  mnc : Int32
  language : String
  country : String
  orientation : Int32
  touchscreen : Int32
  density : Int32
  keyboard : Int32
  navigation : Int32
  input_flags : Int32
  screen_width : Int32
  screen_height : Int32
  sdk_version : Int32
  screen_layout : Int32
  ui_mode : Int32
  smallest_screen_width_dp : Int32
  screen_width_dp : Int32
  screen_height_dp : Int32
  locale_script : String
  color_mode : Int32
  raw : Bytes
}

///|
/// 一个（类型, 配置）资源组（AOSP `ResTable_type`）。
/// `entries` 下标即 entry index，`None` 表示该配置下此条目不存在（NO_ENTRY）。
pub(all) struct ResTypeConfig {
  id : Int32
  flags : Int32
  config : ResConfig
  entries : Array[ResEntry?]
}

///|
/// 一个资源类型（`RES_TABLE_TYPE_SPEC_TYPE` + 其全部配置变体）。
pub(all) struct ResTypeSpec {
  id : Int32
  types_count : Int32
  entry_count : Int32
  spec_flags : Array[UInt32]
  configs : Array[ResTypeConfig]
}

///|
/// 一个资源包（AOSP `ResTable_package`）。
pub(all) struct ResPackage {
  id : Int32
  name : String
  type_id_offset : Int32
  type_strings : Array[String]
  key_strings : Array[String]
  types : Array[ResTypeSpec]
}

///|
/// resources.arsc 完整解析结果：全局值字符串池 + 包数组。
pub(all) struct ResTable {
  global_strings : Array[String]
  packages : Array[ResPackage]
  package_count : Int32
}

///|
/// 资源 id 查询命中：包/类型/条目名 + 最优配置与该配置下的条目。
pub(all) struct ResLookup {
  package_name : String
  type_name : String
  entry_name : String
  type_id : Int32
  entry_id : Int32
  config : ResConfig
  entry : ResEntry
}

///|
/// 解析一段完整 resources.arsc 字节流（含 `RES_TABLE_TYPE` 头，不含 ZIP 封装）。
///
/// - 参数：`data` 只读，调用方持有；不转移、不缓存。
/// - 返回：`ResTable` 纯值；无句柄、可跨线程共享。
/// - 错误：`UnexpectedEof(offset)` / `BadResourceTable(offset, detail)`，均为绝对字节偏移。
/// - 降级：未知 chunk 跳过；未知 `ResDataType` 保留在 `Unknown`；字符串池下标越界在
///   `key_name` 中以占位文本呈现（与 axml 语义对齐），结构越界仍报错。
pub fn parse_resources_arsc(data : Bytes) -> ResTable raise ApkError {
  arsc_parse_table(data)
}

///|
/// 该配置是否为默认配置（全部 qualifier 字段为 0 / 空）。
pub fn ResConfig::is_default(self : ResConfig) -> Bool {
  self.mcc == 0 &&
  self.mnc == 0 &&
  self.language == "" &&
  self.country == "" &&
  self.orientation == 0 &&
  self.touchscreen == 0 &&
  self.density == 0 &&
  self.keyboard == 0 &&
  self.navigation == 0 &&
  self.input_flags == 0 &&
  self.screen_width == 0 &&
  self.screen_height == 0 &&
  self.sdk_version == 0 &&
  self.screen_layout == 0 &&
  self.ui_mode == 0 &&
  self.smallest_screen_width_dp == 0 &&
  self.screen_width_dp == 0 &&
  self.screen_height_dp == 0 &&
  self.locale_script == "" &&
  self.color_mode == 0
}

///|
/// 按包 id 查找包。
pub fn ResTable::package_by_id(self : ResTable, id : Int32) -> ResPackage? {
  for p in self.packages {
    if p.id == id {
      return Some(p)
    }
  }
  None
}

///|
/// 资源 id（0xPPTTNNNN）→ (包, 类型, 条目, 最优值) 查询。
///
/// 选择策略：**默认配置优先**（同一资源存在多个配置变体时返回 qualifier 全零的配置）；
/// 无默认配置时返回 chunk 顺序中的第一个命中。未命中返回 `None`。
pub fn ResTable::lookup(self : ResTable, id : UInt32) -> ResLookup? {
  let hits = self.collect_hits(id)
  if hits.is_empty() {
    return None
  }
  let mut best = hits.at(0)
  for hit in hits {
    if hit.config.is_default() {
      best = hit
      break
    }
  }
  Some(best)
}

///|
/// 资源 id 的全部配置命中（按 chunk 顺序）。
pub fn ResTable::lookup_all(self : ResTable, id : UInt32) -> Array[ResLookup] {
  self.collect_hits(id)
}

///|
/// 按名字查资源 id：(类型名, 条目名) → id；未命中返回 `None`。
pub fn ResTable::find_id(
  self : ResTable,
  type_name : String,
  entry_name : String,
) -> UInt32? {
  for p in self.packages {
    for spec in p.types {
      let idx = spec.id - p.type_id_offset - 1
      if arsc_pool_string(p.type_strings, idx) == type_name {
        for cfg in spec.configs {
          let mut i = 0
          while i < cfg.entries.length() {
            match cfg.entries.at(i) {
              Some(entry) =>
                if entry.key_name == entry_name {
                  let id = ((p.id.reinterpret_as_uint() & 255U) << 24) |
                    (
                      (
                        (spec.id + p.type_id_offset).reinterpret_as_uint() &
                        255U
                      ) <<
                      16
                    ) |
                    (i.reinterpret_as_uint() & 65535U)
                  return Some(id)
                }
              None => ()
            }
            i = i + 1
          }
        }
      }
    }
  }
  None
}

///|
/// 收集某 id 在所有配置中的命中（chunk 顺序）。
fn ResTable::collect_hits(self : ResTable, id : UInt32) -> Array[ResLookup] {
  let out : Array[ResLookup] = []
  let pkg_id = ((id >> 24) & 255U).reinterpret_as_int()
  let type_id = ((id >> 16) & 255U).reinterpret_as_int()
  let entry_id = (id & 65535U).reinterpret_as_int()
  for p in self.packages {
    if p.id != pkg_id {
      continue
    }
    for spec in p.types {
      if spec.id + p.type_id_offset != type_id {
        continue
      }
      let type_name = arsc_pool_string(
        p.type_strings,
        spec.id - p.type_id_offset - 1,
      )
      for cfg in spec.configs {
        if entry_id < cfg.entries.length() {
          match cfg.entries.at(entry_id) {
            Some(entry) =>
              out.push({
                package_name: p.name,
                type_name,
                entry_name: entry.key_name,
                type_id,
                entry_id,
                config: cfg.config,
                entry,
              })
            None => ()
          }
        }
      }
    }
  }
  out
}

///|
/// 字符串池取值：越界返回占位文本（与 axml 查询路径一致，不报错）。
fn arsc_pool_string(pool : Array[String], index : Int32) -> String {
  if index < 0 || index >= pool.length() {
    return "(invalid string index \{index})"
  }
  pool.at(index)
}

///|
/// 定宽小端读取（越界报 `UnexpectedEof(offset)`）。
fn arsc_u8(data : Bytes, off : Int32, limit : Int32) -> Int32 raise ApkError {
  if off < 0 || off + 1 > limit || off + 1 > data.length() {
    raise ApkError::UnexpectedEof(off)
  }
  data.at(off).to_int()
}

///|
fn arsc_u16(data : Bytes, off : Int32, limit : Int32) -> Int32 raise ApkError {
  if off < 0 || off + 2 > limit || off + 2 > data.length() {
    raise ApkError::UnexpectedEof(off)
  }
  data.at(off).to_int() | (data.at(off + 1).to_int() << 8)
}

///|
fn arsc_u32(data : Bytes, off : Int32, limit : Int32) -> Int32 raise ApkError {
  if off < 0 || off + 4 > limit || off + 4 > data.length() {
    raise ApkError::UnexpectedEof(off)
  }
  data.at(off).to_int() |
  (data.at(off + 1).to_int() << 8) |
  (data.at(off + 2).to_int() << 16) |
  (data.at(off + 3).to_int() << 24)
}

///|
fn arsc_u32u(data : Bytes, off : Int32, limit : Int32) -> UInt32 raise ApkError {
  arsc_u32(data, off, limit).reinterpret_as_uint()
}

///|
/// chunk 头读取 + 基本校验：返回 (type, headerSize, size)。
fn arsc_chunk_header(
  data : Bytes,
  off : Int32,
  limit : Int32,
) -> (Int32, Int32, Int32) raise ApkError {
  let ty = arsc_u16(data, off, limit)
  let hs = arsc_u16(data, off + 2, limit)
  let sz = arsc_u32(data, off + 4, limit)
  if sz < 8 {
    raise ApkError::BadResourceTable(off, "chunk size < 8")
  }
  if hs < 8 || hs > sz {
    raise ApkError::BadResourceTable(off, "chunk headerSize out of range")
  }
  (ty, hs, sz)
}

///|
/// 解析顶层 `resources.arsc`。
fn arsc_parse_table(data : Bytes) -> ResTable raise ApkError {
  let len = data.length()
  if len < 12 {
    raise ApkError::UnexpectedEof(len)
  }
  let table_type = arsc_u16(data, 0, len)
  if table_type != 0x0002 {
    raise ApkError::BadResourceTable(0, "not a RES_TABLE_TYPE chunk")
  }
  let header_size = arsc_u16(data, 2, len)
  if header_size != 12 {
    raise ApkError::BadResourceTable(0, "RES_TABLE_TYPE headerSize must be 12")
  }
  let size = arsc_u32(data, 4, len)
  if size < 12 {
    raise ApkError::BadResourceTable(4, "RES_TABLE_TYPE size < header")
  }
  if size > len {
    raise ApkError::UnexpectedEof(len)
  }
  if size < len {
    raise ApkError::BadResourceTable(4, "trailing bytes after RES_TABLE_TYPE")
  }
  let package_count = arsc_u32(data, 8, len)
  if package_count < 0 {
    raise ApkError::BadResourceTable(8, "packageCount is negative")
  }
  let mut global_strings : Array[String]? = None
  let packages : Array[ResPackage] = []
  let mut off = 12
  while off < size {
    let (ty, hs, sz) = arsc_chunk_header(data, off, size)
    if off + sz > size {
      raise ApkError::UnexpectedEof(off)
    }
    if ty == 0x0001 {
      if global_strings is None {
        if hs != 28 {
          raise ApkError::BadResourceTable(
            off, "string pool headerSize must be 28",
          )
        }
        global_strings = Some(arsc_string_pool(data, off, sz))
      }
    } else if ty == 0x0200 {
      if packages.length() >= package_count {
        raise ApkError::BadResourceTable(
          off, "more package chunks than packageCount",
        )
      }
      packages.push(arsc_parse_package(data, off, sz))
    } else {
      // 顶层未知 chunk：跳过（降级）。
      ()
    }
    off = off + sz
  }
  let global_strings = match global_strings {
    Some(p) => p
    None =>
      raise ApkError::BadResourceTable(12, "missing global string pool chunk")
  }
  { global_strings, packages, package_count, }
}

///|
/// 解析字符串池 chunk（`off` 为 chunk 起点，`csize` 为 chunk 大小）。
fn arsc_string_pool(
  data : Bytes,
  off : Int32,
  csize : Int32,
) -> Array[String] raise ApkError {
  let limit = off + csize
  let string_count = arsc_u32(data, off + 8, limit)
  let style_count = arsc_u32(data, off + 12, limit)
  let flags = arsc_u32(data, off + 16, limit)
  let strings_start = arsc_u32(data, off + 20, limit)
  let styles_start = arsc_u32(data, off + 24, limit)
  if string_count < 0 || style_count < 0 {
    raise ApkError::BadResourceTable(off, "negative string/style count")
  }
  if flags < 0 || flags > 0x101 || (flags & 0x101) != flags {
    raise ApkError::BadResourceTable(off, "unknown string pool flags")
  }
  let utf8 = (flags & 0x100) != 0
  if csize < 28 || string_count > (csize - 28) / 4 {
    raise ApkError::BadResourceTable(off, "string count exceeds chunk")
  }
  if style_count > (csize - 28 - 4 * string_count) / 4 {
    raise ApkError::BadResourceTable(off, "style count exceeds chunk")
  }
  let table_end = 28 + 4 * (string_count + style_count)
  if strings_start < table_end || strings_start > csize {
    raise ApkError::BadResourceTable(off, "stringsStart outside string pool")
  }
  if style_count == 0 {
    if styles_start != 0 {
      raise ApkError::BadResourceTable(off, "stylesStart set without styles")
    }
  } else if styles_start < strings_start || styles_start > csize {
    raise ApkError::BadResourceTable(off, "stylesStart outside string pool")
  }
  let strings : Array[String] = []
  let mut i = 0
  while i < string_count {
    let table_off = off + 28 + 4 * i
    let rel = arsc_u32(data, table_off, limit)
    if rel < 0 || rel >= csize - strings_start {
      raise ApkError::BadResourceTable(table_off, "string offset out of range")
    }
    let entry = off + strings_start + rel
    let s = if utf8 {
      arsc_utf8_entry(data, entry, limit)
    } else {
      arsc_utf16_entry(data, entry, limit)
    }
    strings.push(s)
    i = i + 1
  }
  strings
}

///|
/// 长度前缀（8 位形式）：返回 (值, 下一位置)。
fn arsc_len8(
  data : Bytes,
  pos : Int32,
  limit : Int32,
) -> (Int32, Int32) raise ApkError {
  let b = arsc_u8(data, pos, limit)
  if (b & 0x80) == 0 {
    return (b, pos + 1)
  }
  let b2 = arsc_u8(data, pos + 1, limit)
  (((b & 0x7F) << 8) | b2, pos + 2)
}

///|
/// 长度前缀（16 位形式）：返回 (值, 下一位置)。
fn arsc_len16(
  data : Bytes,
  pos : Int32,
  limit : Int32,
) -> (Int32, Int32) raise ApkError {
  let u = arsc_u16(data, pos, limit)
  if (u & 0x8000) == 0 {
    return (u, pos + 2)
  }
  let u2 = arsc_u16(data, pos + 2, limit)
  (((u & 0x7FFF) << 16) | u2, pos + 4)
}

///|
/// UTF-8 字符串池条目：字符数前缀 + 字节数前缀 + 载荷 + NUL。
fn arsc_utf8_entry(
  data : Bytes,
  entry : Int32,
  limit : Int32,
) -> String raise ApkError {
  let (_, p1) = arsc_len8(data, entry, limit)
  let (byte_len, p2) = arsc_len8(data, p1, limit)
  if byte_len < 0 || p2 + byte_len + 1 > limit {
    raise ApkError::BadResourceTable(entry, "UTF-8 string exceeds pool chunk")
  }
  let s = @encoding/utf8.decode(data[p2:p2 + byte_len]) catch {
    _ => raise ApkError::BadResourceTable(p2, "invalid UTF-8 string")
  }
  if data.at(p2 + byte_len).to_int() != 0 {
    raise ApkError::BadResourceTable(p2 + byte_len, "missing NUL terminator")
  }
  s
}

///|
/// UTF-16 字符串池条目：unit 数前缀 + 载荷 + 16 位 NUL。
fn arsc_utf16_entry(
  data : Bytes,
  entry : Int32,
  limit : Int32,
) -> String raise ApkError {
  let (units, p1) = arsc_len16(data, entry, limit)
  if units < 0 || p1 + 2 > limit || units > (limit - p1 - 2) / 2 {
    raise ApkError::BadResourceTable(entry, "UTF-16 string exceeds pool chunk")
  }
  let s = arsc_decode_utf16(data, p1, units, limit)
  if data.at(p1 + 2 * units).to_int() != 0 ||
    data.at(p1 + 2 * units + 1).to_int() != 0 {
    raise ApkError::BadResourceTable(p1 + 2 * units, "missing UTF-16 NUL")
  }
  s
}

///|
/// UTF-16LE 解码（合并代理对；孤立代理报错）。
fn arsc_decode_utf16(
  data : Bytes,
  off : Int32,
  units : Int32,
  limit : Int32,
) -> String raise ApkError {
  if off < 0 || units < 0 || off > limit || units > (limit - off) / 2 {
    raise ApkError::UnexpectedEof(off)
  }
  let b = StringBuilder(size_hint=units)
  let mut i = 0
  while i < units {
    let base = off + 2 * i
    let u = arsc_u16(data, base, limit)
    if u >= 0xD800 && u <= 0xDBFF {
      if i + 1 >= units {
        raise ApkError::BadResourceTable(base, "unpaired UTF-16 high surrogate")
      }
      let next = off + 2 * (i + 1)
      let lo = arsc_u16(data, next, limit)
      if lo < 0xDC00 || lo > 0xDFFF {
        raise ApkError::BadResourceTable(next, "unpaired UTF-16 high surrogate")
      }
      let cp = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
      b.write_char(arsc_scalar(cp, base))
      i = i + 2
    } else if u >= 0xDC00 && u <= 0xDFFF {
      raise ApkError::BadResourceTable(base, "unpaired UTF-16 low surrogate")
    } else {
      b.write_char(arsc_scalar(u, base))
      i = i + 1
    }
  }
  b.to_string()
}

///|
/// Unicode 标量值 → Char；非法值报错（不 panic）。
fn arsc_scalar(cp : Int32, at : Int32) -> Char raise ApkError {
  match cp.to_char() {
    Some(c) => c
    None => raise ApkError::BadResourceTable(at, "invalid Unicode scalar value")
  }
}

///|
/// 包名/库名：UTF-16 NUL 结尾，最多 `max_units` 个 code unit。
fn arsc_utf16z(
  data : Bytes,
  off : Int32,
  max_units : Int32,
  limit : Int32,
) -> String raise ApkError {
  let mut n = 0
  while n < max_units {
    let u = arsc_u16(data, off + 2 * n, limit)
    if u == 0 {
      break
    }
    n = n + 1
  }
  arsc_decode_utf16(data, off, n, limit)
}

///|
/// 解析 `RES_TABLE_PACKAGE_TYPE` chunk。
fn arsc_parse_package(
  data : Bytes,
  off : Int32,
  csize : Int32,
) -> ResPackage raise ApkError {
  let limit = off + csize
  let header_size = arsc_u16(data, off + 2, limit)
  if header_size < 284 || header_size > csize {
    raise ApkError::BadResourceTable(off, "package headerSize out of range")
  }
  let id = arsc_u32(data, off + 8, limit)
  let name = arsc_utf16z(data, off + 12, 128, limit)
  let type_strings_off = arsc_u32(data, off + 268, limit)
  let key_strings_off = arsc_u32(data, off + 276, limit)
  let type_id_offset = if header_size >= 288 {
    arsc_u32(data, off + 284, limit)
  } else {
    0
  }
  if type_id_offset < 0 || type_id_offset > 255 {
    raise ApkError::BadResourceTable(off + 284, "typeIdOffset out of range")
  }
  if type_strings_off <= 0 || key_strings_off <= 0 {
    raise ApkError::BadResourceTable(
      off, "inheriting package (typeStrings/keyStrings == 0) unsupported",
    )
  }
  let type_pool_at = off + type_strings_off
  let key_pool_at = off + key_strings_off
  if type_pool_at < off + header_size || type_pool_at + 28 > limit {
    raise ApkError::BadResourceTable(
      off + 268,
      "typeStrings offset out of chunk",
    )
  }
  if key_pool_at < off + header_size || key_pool_at + 28 > limit {
    raise ApkError::BadResourceTable(
      off + 276,
      "keyStrings offset out of chunk",
    )
  }
  if arsc_u16(data, type_pool_at, limit) != 0x0001 {
    raise ApkError::BadResourceTable(
      type_pool_at, "typeStrings is not a string pool",
    )
  }
  if arsc_u16(data, key_pool_at, limit) != 0x0001 {
    raise ApkError::BadResourceTable(
      key_pool_at, "keyStrings is not a string pool",
    )
  }
  let type_pool_size = arsc_u32(data, type_pool_at + 4, limit)
  let key_pool_size = arsc_u32(data, key_pool_at + 4, limit)
  if type_pool_size < 28 || type_pool_at + type_pool_size > limit {
    raise ApkError::UnexpectedEof(type_pool_at)
  }
  if key_pool_size < 28 || key_pool_at + key_pool_size > limit {
    raise ApkError::UnexpectedEof(key_pool_at)
  }
  let type_strings = arsc_string_pool(data, type_pool_at, type_pool_size)
  let key_strings = arsc_string_pool(data, key_pool_at, key_pool_size)
  let types : Array[ResTypeSpec] = []
  let mut p = off + header_size
  while p < limit {
    let (ty, hs, sz) = arsc_chunk_header(data, p, limit)
    if p + sz > limit {
      raise ApkError::UnexpectedEof(p)
    }
    if p == type_pool_at || p == key_pool_at {
      ()
    } else if ty == 0x0001 {
      // 多余字符串池：忽略（AOSP 记警告后跳过）。
      ()
    } else if ty == 0x0202 {
      let spec = arsc_parse_typespec(data, p, sz, hs)
      let mut seen = false
      for t in types {
        if t.id == spec.id {
          seen = true
        }
      }
      if !seen {
        types.push(spec)
      }
    } else if ty == 0x0201 {
      arsc_parse_type_into(data, p, sz, hs, types, key_strings)
    } else {
      // 0x0203 library / 0x0204 overlayable / 未知 chunk：跳过（降级）。
      ()
    }
    p = p + sz
  }
  { id, name, type_id_offset, type_strings, key_strings, types, }
}

///|
/// 解析 `RES_TABLE_TYPE_SPEC_TYPE`（0x0202）。
fn arsc_parse_typespec(
  data : Bytes,
  off : Int32,
  csize : Int32,
  header_size : Int32,
) -> ResTypeSpec raise ApkError {
  let limit = off + csize
  if header_size < 16 {
    raise ApkError::BadResourceTable(off, "typeSpec headerSize < 16")
  }
  let id = arsc_u8(data, off + 8, limit)
  if id == 0 {
    raise ApkError::BadResourceTable(off + 8, "typeSpec id 0")
  }
  let types_count = arsc_u16(data, off + 10, limit)
  let entry_count = arsc_u32(data, off + 12, limit)
  if entry_count < 0 || entry_count > 0xFFFF {
    raise ApkError::BadResourceTable(
      off + 12,
      "typeSpec entryCount out of range",
    )
  }
  if entry_count * 4 > csize - header_size {
    raise ApkError::BadResourceTable(off, "typeSpec too small for flags")
  }
  let spec_flags : Array[UInt32] = []
  let mut i = 0
  while i < entry_count {
    spec_flags.push(arsc_u32u(data, off + header_size + 4 * i, limit))
    i = i + 1
  }
  { id, types_count, entry_count, spec_flags, configs: [], }
}

///|
/// 解析 `RES_TABLE_TYPE_TYPE`（0x0201）并挂到同 id 的 typeSpec。
fn arsc_parse_type_into(
  data : Bytes,
  off : Int32,
  csize : Int32,
  header_size : Int32,
  types : Array[ResTypeSpec],
  key_pool : Array[String],
) -> Unit raise ApkError {
  let limit = off + csize
  if header_size < 24 {
    raise ApkError::BadResourceTable(off, "type headerSize < 24")
  }
  let id = arsc_u8(data, off + 8, limit)
  if id == 0 {
    raise ApkError::BadResourceTable(off + 8, "type id 0")
  }
  let flags = arsc_u8(data, off + 9, limit)
  let entry_count = arsc_u32(data, off + 12, limit)
  let entries_start = arsc_u32(data, off + 16, limit)
  if entry_count < 0 || entry_count > 0xFFFF {
    raise ApkError::BadResourceTable(off + 12, "type entryCount out of range")
  }
  let offset16 = (flags & 0x02) != 0
  let offsets_len = if offset16 { entry_count * 2 } else { entry_count * 4 }
  if (entries_start & 3) != 0 {
    raise ApkError::BadResourceTable(
      off + 16,
      "entriesStart not 4-byte aligned",
    )
  }
  if entries_start < header_size || entries_start > csize {
    raise ApkError::BadResourceTable(
      off + 16,
      "entriesStart outside type chunk",
    )
  }
  if entries_start - header_size < offsets_len {
    raise ApkError::BadResourceTable(off, "entry offsets overlap entry data")
  }
  let config = arsc_parse_config(data, off + 20, off + header_size)
  let entries = arsc_parse_entries(
    data, off, csize, header_size, flags, entry_count, entries_start, limit, key_pool,
  )
  let cfg : ResTypeConfig = { id, flags, config, entries, }
  let mut i = 0
  while i < types.length() {
    if types.at(i).id == id {
      types.at(i).configs.push(cfg)
      return
    }
    i = i + 1
  }
  raise ApkError::BadResourceTable(off, "type chunk without preceding typeSpec")
}

///|
/// 解析 entry offsets（dense u32 / FLAG_OFFSET16 u16 / FLAG_SPARSE）与条目数据。
fn arsc_parse_entries(
  data : Bytes,
  off : Int32,
  csize : Int32,
  header_size : Int32,
  flags : Int32,
  entry_count : Int32,
  entries_start : Int32,
  limit : Int32,
  key_pool : Array[String],
) -> Array[ResEntry?] raise ApkError {
  let entries : Array[ResEntry?] = []
  let sparse = (flags & 0x01) != 0
  let offset16 = (flags & 0x02) != 0
  if sparse {
    let mut max_idx = -1
    let mut i = 0
    while i < entry_count {
      let slot = off + header_size + 4 * i
      let idx = arsc_u16(data, slot, limit)
      if idx > max_idx {
        max_idx = idx
      }
      i = i + 1
    }
    let total = if max_idx + 1 > entry_count {
      max_idx + 1
    } else {
      entry_count
    }
    let mut j = 0
    while j < total {
      entries.push(None)
      j = j + 1
    }
    i = 0
    while i < entry_count {
      let slot = off + header_size + 4 * i
      let idx = arsc_u16(data, slot, limit)
      let raw = arsc_u16(data, slot + 2, limit)
      let entry = arsc_parse_entry(
        data,
        off,
        csize,
        entries_start,
        raw * 4,
        limit,
        key_pool,
      )
      if idx >= 0 && idx < entries.length() {
        entries[idx] = Some(entry)
      }
      i = i + 1
    }
  } else {
    let mut i = 0
    while i < entry_count {
      let raw = if offset16 {
        arsc_u16(data, off + header_size + 2 * i, limit)
      } else {
        arsc_u32(data, off + header_size + 4 * i, limit)
      }
      if offset16 && raw == 0xFFFF {
        entries.push(None)
        i = i + 1
        continue
      }
      if !offset16 && raw == -1 {
        entries.push(None)
        i = i + 1
        continue
      }
      if raw < 0 {
        raise ApkError::BadResourceTable(
          off + header_size + (if offset16 { 2 * i } else { 4 * i }),
          "negative entry offset",
        )
      }
      let entry_off = if offset16 { raw * 4 } else { raw }
      let entry = arsc_parse_entry(
        data, off, csize, entries_start, entry_off, limit, key_pool,
      )
      entries.push(Some(entry))
      i = i + 1
    }
  }
  entries
}

///|
/// 解析单个 `ResTable_entry`（相对 type chunk 的 `entry_off`）。
fn arsc_parse_entry(
  data : Bytes,
  off : Int32,
  csize : Int32,
  entries_start : Int32,
  entry_off : Int32,
  limit : Int32,
  key_pool : Array[String],
) -> ResEntry raise ApkError {
  if (entry_off & 3) != 0 {
    raise ApkError::BadResourceTable(off, "entry offset not 4-byte aligned")
  }
  if entry_off > csize - 8 {
    raise ApkError::BadResourceTable(off, "entry offset beyond type chunk")
  }
  let e = off + entries_start + entry_off
  if e + 8 > limit {
    raise ApkError::UnexpectedEof(e)
  }
  let size = arsc_u16(data, e, limit)
  let flags = arsc_u16(data, e + 2, limit)
  if (flags & 0x0008) != 0 {
    // Compact entry：整项 8 字节，key/flags/dataType/data 内联。
    let key = size
    let data_type = flags >> 8
    let value_data = arsc_u32u(data, e + 4, limit)
    return {
      key,
      key_name: arsc_pool_string(key_pool, key),
      flags,
      value: Simple({ data_type: arsc_data_type(data_type), data: value_data, }),
    }
  }
  if size < 8 {
    raise ApkError::BadResourceTable(e, "entry size < 8")
  }
  if entry_off > csize - size {
    raise ApkError::BadResourceTable(e, "entry size beyond type chunk")
  }
  let key = arsc_u32(data, e + 4, limit)
  if (flags & 0x0001) != 0 {
    if size < 16 {
      raise ApkError::BadResourceTable(e, "bag entry size < 16")
    }
    let parent = arsc_u32u(data, e + 8, limit)
    let count = arsc_u32(data, e + 12, limit)
    if count < 0 || count > (csize - entry_off - size) / 12 {
      raise ApkError::BadResourceTable(e + 12, "bag map count exceeds chunk")
    }
    let maps : Array[ResMap] = []
    let mut i = 0
    while i < count {
      let m = e + size + 12 * i
      let name = arsc_u32u(data, m, limit)
      let value = arsc_parse_value(data, m + 4, limit)
      maps.push({ name, value, })
      i = i + 1
    }
    return {
      key,
      key_name: arsc_pool_string(key_pool, key),
      flags,
      value: Complex({ parent, maps, }),
    }
  }
  if entry_off > csize - size - 8 {
    raise ApkError::BadResourceTable(e, "no room for Res_value after entry")
  }
  let value = arsc_parse_value(data, e + size, limit)
  {
    key,
    key_name: arsc_pool_string(key_pool, key),
    flags,
    value: Simple(value),
  }
}

///|
/// 解析 `Res_value`（size u16, res0 u8, dataType u8, data u32）。
fn arsc_parse_value(
  data : Bytes,
  off : Int32,
  limit : Int32,
) -> ResValue raise ApkError {
  let size = arsc_u16(data, off, limit)
  if size < 8 {
    raise ApkError::BadResourceTable(off, "Res_value size < 8")
  }
  let data_type = arsc_u8(data, off + 3, limit)
  let raw = arsc_u32u(data, off + 4, limit)
  { data_type: arsc_data_type(data_type), data: raw, }
}

///|
/// `Res_value.dataType` 字节 → `ResDataType`（未知值原样保留）。
fn arsc_data_type(v : Int32) -> ResDataType {
  match v {
    0x00 => Null
    0x01 => Reference
    0x02 => Attribute
    0x03 => String
    0x04 => Float
    0x05 => Dimension
    0x06 => Fraction
    0x07 => DynamicReference
    0x08 => DynamicAttribute
    0x10 => IntDec
    0x11 => IntHex
    0x12 => IntBoolean
    0x1c => IntColorArgb8
    0x1d => IntColorRgb8
    0x1e => IntColorArgb4
    0x1f => IntColorRgb4
    _ => Unknown(v)
  }
}

///|
/// 解析 `ResTable_config`（`off` 为 config 起点，`limit` 为 type chunk 头部末尾）。
fn arsc_parse_config(
  data : Bytes,
  off : Int32,
  limit : Int32,
) -> ResConfig raise ApkError {
  let size = arsc_u32(data, off, limit)
  if size < 4 || off + size > limit {
    raise ApkError::BadResourceTable(off, "config size out of range")
  }
  let end = off + size
  let mcc = if size >= 6 { arsc_u16(data, off + 4, end) } else { 0 }
  let mnc = if size >= 8 { arsc_u16(data, off + 6, end) } else { 0 }
  let language = if size >= 10 {
    arsc_unpack_locale(data, off + 8, end, false)
  } else {
    ""
  }
  let country = if size >= 12 {
    arsc_unpack_locale(data, off + 10, end, true)
  } else {
    ""
  }
  let orientation = if size >= 13 { arsc_u8(data, off + 12, end) } else { 0 }
  let touchscreen = if size >= 14 { arsc_u8(data, off + 13, end) } else { 0 }
  let density = if size >= 16 { arsc_u16(data, off + 14, end) } else { 0 }
  let keyboard = if size >= 17 { arsc_u8(data, off + 16, end) } else { 0 }
  let navigation = if size >= 18 { arsc_u8(data, off + 17, end) } else { 0 }
  let input_flags = if size >= 19 { arsc_u8(data, off + 18, end) } else { 0 }
  let screen_width = if size >= 22 { arsc_u16(data, off + 20, end) } else { 0 }
  let screen_height = if size >= 24 { arsc_u16(data, off + 22, end) } else { 0 }
  let sdk_version = if size >= 26 { arsc_u16(data, off + 24, end) } else { 0 }
  let screen_layout = if size >= 29 { arsc_u8(data, off + 28, end) } else { 0 }
  let ui_mode = if size >= 30 { arsc_u8(data, off + 29, end) } else { 0 }
  let smallest_screen_width_dp = if size >= 32 {
    arsc_u16(data, off + 30, end)
  } else {
    0
  }
  let screen_width_dp = if size >= 34 {
    arsc_u16(data, off + 32, end)
  } else {
    0
  }
  let screen_height_dp = if size >= 36 {
    arsc_u16(data, off + 34, end)
  } else {
    0
  }
  let locale_script = if size >= 40 {
    arsc_ascii4(data, off + 36, end)
  } else {
    ""
  }
  let color_mode = if size >= 50 { arsc_u8(data, off + 49, end) } else { 0 }
  let raw = data[off:end].to_owned()
  {
    size,
    mcc,
    mnc,
    language,
    country,
    orientation,
    touchscreen,
    density,
    keyboard,
    navigation,
    input_flags,
    screen_width,
    screen_height,
    sdk_version,
    screen_layout,
    ui_mode,
    smallest_screen_width_dp,
    screen_width_dp,
    screen_height_dp,
    locale_script,
    color_mode,
    raw,
  }
}

///|
/// AOSP `unpackLanguageOrRegion`：两位 ASCII 或 15 位压缩三字母码。
fn arsc_unpack_locale(
  data : Bytes,
  off : Int32,
  limit : Int32,
  is_region : Bool,
) -> String raise ApkError {
  let high = arsc_u8(data, off, limit)
  let low = arsc_u8(data, off + 1, limit)
  if (high & 0x80) == 0 {
    let b = StringBuilder(size_hint=2)
    if high != 0 {
      b.write_char(arsc_scalar(high, off))
      if low != 0 {
        b.write_char(arsc_scalar(low, off + 1))
      }
    }
    return b.to_string()
  }
  let base = if is_region { 48 } else { 97 }
  let first = (low & 0x1F) + base - 1
  let second = (((low >> 5) | ((high & 0x03) << 3)) & 0x1F) + base - 1
  let third = ((high >> 2) & 0x1F) + base - 1
  let b = StringBuilder(size_hint=3)
  b.write_char(arsc_scalar(first, off))
  b.write_char(arsc_scalar(second, off))
  b.write_char(arsc_scalar(third, off))
  b.to_string()
}

///|
/// 4 字节 ASCII 串（localeScript），遇 NUL 截断。
fn arsc_ascii4(
  data : Bytes,
  off : Int32,
  limit : Int32,
) -> String raise ApkError {
  let b = StringBuilder(size_hint=4)
  let mut i = 0
  while i < 4 {
    let c = arsc_u8(data, off + i, limit)
    if c == 0 {
      break
    }
    b.write_char(arsc_scalar(c, off + i))
    i = i + 1
  }
  b.to_string()
}
