///|
/// Verity 签名块结构解析（W5 — 块识别 + 原始字节 + 声明字段）。
///
/// 边界：APK Signing Block 中 ID 0x42726577 的块在 AOSP 中用作对齐填充（padding），
/// 不承载结构化 verity 参数（fs-verity Merkle 树参数在 v4 .idsig 文件中）。
/// 本模块按开发文档 W5 方针实现：块识别 + 原始字节保存 + 尽力解析声明字段；
/// 树重算挂 `#skip` 显式缺口。
///
/// 非目标：不做 Merkle 树重算、不做 v4 .idsig 解析、不做安装语义。

///|
#derive(Debug)
/// Verity 签名块信息（APK Signing Block ID 0x42726577）。
pub(all) struct VerityInfo {
  /// block_id = 0x42726577
  block_id : UInt32
  /// 块内声明的版本号（解析失败时为 0）。
  version : Int32
  /// 块内声明的哈希算法名称；unknown = 未识别 / 算法不在支持列表。
  hash_algorithm : String
  /// 块内声明的数据分块大小（字节）；0 = 未声明。
  block_size : Int32
  /// 块内声明的盐值（小写 hex）；空 = 未声明。
  salt_hex : String
  /// 块内声明的根哈希（小写 hex）；空 = 未声明。
  root_hash_hex : String
  /// 块内声明的树尺寸（字节）；0 = 未声明。
  tree_size : UInt64
  /// 是否已重算 Merkle 树并与声明一致。
  /// 本模块不做树重算，恒为 false（#skip 缺口）。
  tree_recomputed_ok : Bool
}

///|
pub extend VerityInfo with Debug::{to_repr}

///|
/// 读取 verity 签名块（ID 0x42726577）的结构信息；无该块返回 None。
///
/// 遍历 APK Signing Block 的 ID-value 对，找到 verity 块后尽力解析声明字段；
/// 所有解析失败以缺省值表示（不 raise、不 panic），由调用方决定如何使用。
/// 树重算恒不执行，`tree_recomputed_ok` 恒为 false。
pub fn Apk::verity(self : Apk) -> VerityInfo? raise ApkError {
  let sb = match self.signing_block_off {
    Some(o) => o.to_int()
    None => return None
  }
  let size = le_u64(self.source, sb)
  let pairs_start = sb + 8
  let pairs_end = sb + size.to_int() - 16
  let mut pos = pairs_start
  while pos < pairs_end {
    guard pos + 8 <= pairs_end else {
      raise ApkError::BadSigningBlock(
        pos, "truncated ID-value pair length in APK Signing Block",
      )
    }
    let pair_len = le_u64(self.source, pos)
    guard pair_len >= 4 && pair_len - 4 <= (pairs_end - pos - 8).to_uint64() else {
      raise ApkError::BadSigningBlock(
        pos, "ID-value pair overruns APK Signing Block",
      )
    }
    let id = le_u32(self.source, pos + 8)
    let value_off = pos + 12
    let value_len = pair_len.to_int() - 4
    if id == VERITY_BLOCK_ID {
      let raw = self.source[value_off:value_off + value_len].to_owned()
      return Some(parse_verity_value(id, raw))
    }
    pos = pos + 8 + pair_len.to_int()
  }
  None
}

///|
/// Verity 块 ID（AOSP ApkSigningBlockUtils.VERITY_PADDING_BLOCK_ID）。
const VERITY_BLOCK_ID : UInt32 = 0x42726577

///|
/// 从 verity 块原始字节尽力解析声明字段；解析失败以缺省值表示。
fn parse_verity_value(block_id : UInt32, raw : Bytes) -> VerityInfo {
  let len = raw.length()
  let mut version = 0
  let mut hash_algorithm = "unknown"
  let mut block_size = 0
  let mut salt_hex = ""
  let mut root_hash_hex = ""
  let mut tree_size : UInt64 = 0UL
  // 尝试按简单顺序格式解析：
  // u32 version | u32 hash_algo | u32 block_size | u32 salt_len | salt |
  // u32 root_hash_len | root_hash | u64 tree_size
  if len >= 4 {
    version = le_u32(raw, 0).reinterpret_as_int()
  }
  if len >= 8 {
    let algo_id = le_u32(raw, 4)
    hash_algorithm = if algo_id == 1U {
      "SHA-256"
    } else if algo_id == 2U {
      "SHA-512"
    } else {
      "unknown"
    }
  }
  if len >= 12 {
    block_size = le_u32(raw, 8).reinterpret_as_int()
  }
  let mut pos = 12
  if pos + 4 <= len {
    let salt_len = le_u32(raw, pos).reinterpret_as_int()
    pos = pos + 4
    if salt_len > 0 && salt_len <= 64 && pos + salt_len <= len {
      salt_hex = bytes_to_hex(raw[pos:pos + salt_len])
      pos = pos + salt_len
    }
  }
  if pos + 4 <= len {
    let rh_len = le_u32(raw, pos).reinterpret_as_int()
    pos = pos + 4
    if rh_len > 0 && rh_len <= 64 && pos + rh_len <= len {
      root_hash_hex = bytes_to_hex(raw[pos:pos + rh_len])
      pos = pos + rh_len
    }
  }
  if pos + 8 <= len {
    tree_size = le_u64(raw, pos)
  }
  {
    block_id,
    version,
    hash_algorithm,
    block_size,
    salt_hex,
    root_hash_hex,
    tree_size,
    tree_recomputed_ok: false,
  }
}

///|
/// 字节切片 → 小写 hex 字符串。
fn bytes_to_hex(b : BytesView) -> String {
  let out = StringBuilder(capacity=b.length() * 2)
  for byte in b {
    let v = byte.to_int()
    let hi = (v >> 4) & 0xF
    let lo = v & 0xF
    let c_hi = if hi < 10 {
      (48 + hi).unsafe_to_char()
    } else {
      (87 + hi).unsafe_to_char()
    }
    let c_lo = if lo < 10 {
      (48 + lo).unsafe_to_char()
    } else {
      (87 + lo).unsafe_to_char()
    }
    out.write_char(c_hi)
    out.write_char(c_lo)
  }
  out.to_string()
}
