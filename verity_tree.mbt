///|
/// fs-verity Merkle 根重算与 v2/v3/v3.1 声明摘要比对（W5-后续）。
///
/// 背景（已联网核实 AOSP）：APK Signing Block 中 ID `0x42726577`（`VERITY_PADDING_BLOCK_ID`）
/// 仅作对齐填充，**不承载** root hash 或任何 verity 参数——故既有 `VerityInfo` 从该块读到的
/// `root_hash_hex` 恒为空、`tree_recomputed_ok` 恒 false 是正确的，该块无法承载比对。
/// 真实 fs-verity Merkle 根位于 v2/v3/v3.1 **signed data 的 verity 内容摘要**中：
/// 摘要算法 ID `0x0421`(RSA)/`0x0423`(ECDSA)/`0x0425`(DSA) 均映射到
/// `CONTENT_DIGEST_VERITY_CHUNKED_SHA256`，值为 40 字节 = root_hash[32] || source_len(int64 小端)。
///
/// 本模块新增加法 API：`Apk::verity_tree_check`（新 struct `VerityTreeCheck`），对 fs-verity
/// Merkle 根做真重算并与 v2/v3/v3.1 声明的 verity 摘要根比对。属纯加法，不动既有
/// `VerityInfo`/`Apk::verity`，不新增 `ApkError` 变体，不引入依赖。
///
/// 非目标：不做 v4 `.idsig` 解析、不做安装语义、不修改 APK。

///|
/// fs-verity Merkle 根重算结论（与 v2/v3/v3.1 声明摘要比对）。
///
/// `block_id` 恒为 0x42726577（标识这是 verity 能力，尽管该块本身不承载 root hash）。
/// `tree_recomputed_ok` 为 true 仅当「声明了 verity 摘要」且「重算根 == 声明根」；否则 false
/// （fail-closed）。`verity_tree_check()` 返回 `None` 表示该 APK 的 v2/v3/v3.1 中无 verity 摘要。
pub(all) struct VerityTreeCheck {
  /// 恒 0x42726577（标识 verity 能力）。
  block_id : UInt32
  /// "SHA-256"（fs-verity 固定）；声明存在但算法无法识别时为 "unknown"。
  hash_algorithm : String
  /// fs-verity 块大小，恒 4096。
  block_size : Int32
  /// 盐值 hex（fs-verity 固定 8 字节全零）：恒 "0000000000000000"。
  salt_hex : String
  /// v2/v3/v3.1 声明 verity 摘要中提取的 32 字节根（小写 hex）。
  declared_root_hash_hex : String
  /// 对 fs-verity 源数据重算出的 32 字节根（小写 hex）；重算失败时为空串。
  recomputed_root_hash_hex : String
  /// 重算根 == 声明根。有声明且比对一致才为 true，否则 false（fail-closed）。
  tree_recomputed_ok : Bool
  /// v2/v3/v3.1 verity 摘要中声明的 source_len。
  source_len : UInt64
}

///|
/// 收集 v2/v3/v3.1 signer 的 verity 摘要记录。
///
/// 遍历 APK Signing Block 的 ID-value 对，对每个 v2/v3/v3.1 方案尝试解析 signer 的 digests 序列，
/// 挑出算法 ID 为 0x0421/0x0423/0x0425 且值为 40 字节的记录。单个 signer 解析失败跳过（值化），
/// 但结构性截断（pair 长度越界）仍按既有 `BadSigningBlock` 语义 raise（与 `Apk::verity` 一致）。
/// 返回顺序不保证（调用方只取第一个合法记录）。
fn Apk::collect_verity_digests(
  self : Apk,
) -> Array[SignerDigest] raise ApkError {
  let out : Array[SignerDigest] = []
  let sb = match self.signing_block_off {
    Some(o) => o.to_int()
    None => return out
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
    if id == SIG_ID_V2 || id == SIG_ID_V3 || id == SIG_ID_V31 {
      let value_off = pos + 12
      let value_len = pair_len.to_int() - 4
      let sch = if id == SIG_ID_V2 {
        SignatureScheme::V2
      } else if id == SIG_ID_V3 {
        SignatureScheme::V3
      } else {
        SignatureScheme::V31
      }
      let data : SignerData? = Some(
        extract_signer_data(self.source, sch, value_off, value_len, pos),
      ) catch {
        // 单个 signer 解析失败值化为 None（跳过该 signer），与 W5「解析失败一律值化」一致；
        // 结构性 pair 越界仍由上方 guard 按既有 BadSigningBlock 语义 raise。
        _ => None
      }
      match data {
        Some(d) =>
          for dd in d.digests {
            if is_verity_digest_algorithm(dd.algorithm) &&
              dd.digest.length() == 40 {
              out.push(dd)
            }
          }
        None => ()
      }
    }
    pos = pos + 8 + pair_len.to_int()
  }
  out
}

///|
/// 判断摘要算法 ID 是否对应 fs-verity 内容摘要（AOSP `CONTENT_DIGEST_VERITY_CHUNKED_SHA256`）。
/// 注：这是「签名算法 ID 映射到 verity 内容摘要」的 ID（RSA/ECDSA/DSA 三档）。
fn is_verity_digest_algorithm(id : UInt32) -> Bool {
  id == 0x0421U || id == 0x0423U || id == 0x0425U
}

///|
/// 构造 fs-verity 源数据：APK 全部字节扣除签名块区间 `[signingBlockOff, centralDirOffset)`，
/// 且 EOCD 的中央目录偏移字段（EOCD 内偏移 +16，4 字节小端）改写为 `signingBlockOff`。
/// 与 `content_digest` 的分块摘要不同（这是 Merkle 树的整源），不可复用错。
/// 源数据不可构造（无签名块 / 无 EOCD / 目录越界）返回 None。
fn Apk::verity_source_bytes(self : Apk) -> Bytes? {
  let sb = match self.signing_block_off {
    Some(v) => v.to_int()
    None => return None
  }
  let eocd = match find_eocd(self.source) {
    Some(o) => o
    None => return None
  }
  let source = self.source
  let cd_off = le_u32(source, eocd + 16).reinterpret_as_int()
  let cd_size = le_u32(source, eocd + 12).reinterpret_as_int()
  if cd_off < 0 || cd_size < 0 || cd_off + cd_size > eocd {
    return None
  }
  let comment_len = le_u16(source, eocd + 20)
  let eocd_len = 22 + comment_len
  if eocd + eocd_len > source.length() {
    return None
  }
  let buf : Array[Byte] = []
  // 1) 签名块前的条目区 [0, sb)
  for i = 0; i < sb; i = i + 1 {
    buf.push(source[i])
  }
  // 2) 中央目录区 [cd_off, cd_off + cd_size)
  for i = cd_off; i < cd_off + cd_size; i = i + 1 {
    buf.push(source[i])
  }
  // 3) EOCD 副本，中央目录偏移字段改写为 sb
  for i = 0; i < eocd_len; i = i + 1 {
    buf.push(source[eocd + i])
  }
  let sb_u = sb.reinterpret_as_uint()
  let base = buf.length() - eocd_len
  buf[base + 16] = (sb_u & 0xFFU).reinterpret_as_int().to_byte()
  buf[base + 17] = ((sb_u >> 8) & 0xFFU).reinterpret_as_int().to_byte()
  buf[base + 18] = ((sb_u >> 16) & 0xFFU).reinterpret_as_int().to_byte()
  buf[base + 19] = ((sb_u >> 24) & 0xFFU).reinterpret_as_int().to_byte()
  Some(Bytes::from_array(buf[:]))
}

///|
/// fs-verity Merkle 根（apk-verity 变体，AOSP `VerityBuilder.generateApkVerityTree`）。
///
/// - 盐 = 8 字节全零，SHA-256，块大小 4096。
/// - 叶子层：源按 4096 分块，每块 `sha256(盐 || 零填充至4096的块)`；不满补零。
/// - 内部层：上一层 32 字节摘要串接后按 4096 分块，每块 `sha256(盐 || 零填充至4096)`；逐层向上直到该层 ≤4096 字节。
/// - 根：对最顶层（首个 ≤4096 字节的层）做 `sha256(盐 || 该层零填充块)`。
fn verity_root(source : Bytes, salt : Bytes, block_size : Int32) -> Bytes {
  // 叶子层
  let mut level : Array[Bytes] = []
  let n = source.length()
  let mut off = 0
  while off < n {
    let take = if n - off > block_size { block_size } else { n - off }
    let block = zero_pad(source[off:off + take].to_owned(), block_size)
    level.push(sha256(concat_salt(salt, block)))
    off = off + block_size
  }
  // 内部层：直到当前层串接尺寸 ≤ block_size
  while level.length() * 32 > block_size {
    let concat = concat_bytes(level)
    let m = concat.length()
    let next : Array[Bytes] = []
    let mut o = 0
    while o < m {
      let take = if m - o > block_size { block_size } else { m - o }
      let block = zero_pad(concat[o:o + take].to_owned(), block_size)
      next.push(sha256(concat_salt(salt, block)))
      o = o + block_size
    }
    level = next
  }
  // 根：最顶层串接零填充
  let top = zero_pad(concat_bytes(level), block_size)
  sha256(concat_salt(salt, top))
}

///|
/// 对字节流做 fs-verity 根重算并与 v2/v3/v3.1 声明的 verity 摘要根比对。
///
/// - 收集 v2/v3/v3.1 signer 的 digests，找到 algorithm 为 0x0421/0x0423/0x0425 且值 40 字节的
///   摘要（提取声明根与 source_len）；无则返回 `None`。
/// - 有声明时构造 fs-verity 源并重算根，比对一致 `tree_recomputed_ok=true`。
/// - 解析失败一律值化（`tree_recomputed_ok=false`、字段缺省），不 panic、不新增错误变体。
pub fn Apk::verity_tree_check(self : Apk) -> VerityTreeCheck? raise ApkError {
  let digests = self.collect_verity_digests()
  let mut declared : (Bytes, UInt64)? = None
  for d in digests {
    if d.digest.length() == 40 {
      declared = Some((d.digest[0:32].to_owned(), le_u64(d.digest, 32)))
      break
    }
  }
  match declared {
    None => return None
    Some((root_hash, source_len)) => {
      let recomputed : Bytes? = match self.verity_source_bytes() {
        Some(src) =>
          Some(verity_root(src, b"\x00\x00\x00\x00\x00\x00\x00\x00", 4096))
        None => None
      }
      let ok = match recomputed {
        Some(r) => r == root_hash
        None => false
      }
      Some({
        block_id: VERITY_BLOCK_ID,
        hash_algorithm: "SHA-256",
        block_size: 4096,
        salt_hex: "0000000000000000",
        declared_root_hash_hex: bytes_to_hex(root_hash),
        recomputed_root_hash_hex: match recomputed {
          Some(r) => bytes_to_hex(r)
          None => ""
        },
        tree_recomputed_ok: ok,
        source_len,
      })
    }
  }
}

///|
/// 盐 || 数据。
fn concat_salt(salt : Bytes, data : Bytes) -> Bytes {
  let out : Array[Byte] = []
  for x in salt {
    out.push(x)
  }
  for x in data {
    out.push(x)
  }
  Bytes::from_array(out[:])
}

///|
/// 零填充到 block_size（不足补零；已满原样返回）。
fn zero_pad(b : Bytes, block_size : Int32) -> Bytes {
  if b.length() == block_size {
    return b
  }
  let out : Array[Byte] = []
  for x in b {
    out.push(x)
  }
  while out.length() < block_size {
    out.push(b'\x00')
  }
  Bytes::from_array(out[:])
}

///|
/// 串接一层摘要。
fn concat_bytes(level : Array[Bytes]) -> Bytes {
  let out : Array[Byte] = []
  for d in level {
    for x in d {
      out.push(x)
    }
  }
  Bytes::from_array(out[:])
}
