///|
/// W5-后续 verity 树重算白盒测试。
///
/// 白盒可访问私有 `verity_root` / `verity_source_bytes` / `sha256`，从而能构造
/// **含真实重算根**的 v2 verity 摘要样本，端到端证明 `tree_recomputed_ok=true` 成立
/// （不再是既有 `VerityInfo` 的恒 false）。同时覆盖单块根独立核对与篡改 fail-closed。
///
/// 复用 `apk_wbtest.mbt` 的 `w_push_u16`/`w_push_u32` 与包内 `crc32_of` 等私有工具。
/// fixture 构造：单 stored 条目 "foo.txt" + v2 签名块（digests 含一个 0x0421 verity 摘要）。

///|
fn w_push_u64_small(a : Array[Byte], v : Int32) -> Unit {
  w_push_u32(a, v)
  w_push_u32(a, 0)
}

///|
fn w_push_bytes(a : Array[Byte], b : Bytes) -> Unit {
  for x in b {
    a.push(x)
  }
}

///|
/// 40 字节全零（占位 verity 摘要）。
fn w_zeros40() -> Bytes {
  let a : Array[Byte] = []
  for i = 0; i < 40; i = i + 1 {
    a.push(b'\x00')
  }
  Bytes::from_array(a[:])
}

///|
/// 签名方案值（fixture，白盒版）：digests 含一个 0x0421 verity 摘要（40 字节）。
fn w_scheme_value_with_verity(verity_digest : Bytes, sdk_tail : Int32) -> Bytes {
  let ds : Array[Byte] = []
  w_push_u32(ds, verity_digest.length() + 8)
  w_push_u32(ds, 0x0421)
  w_push_u32(ds, verity_digest.length())
  w_push_bytes(ds, verity_digest)
  let ds_b = Bytes::from_array(ds[:])
  let cert = b"cert"
  let cs : Array[Byte] = []
  w_push_u32(cs, cert.length())
  w_push_bytes(cs, cert)
  let cs_b = Bytes::from_array(cs[:])
  let sd : Array[Byte] = []
  w_push_u32(sd, ds_b.length())
  w_push_bytes(sd, ds_b)
  w_push_u32(sd, cs_b.length())
  w_push_bytes(sd, cs_b)
  for i = 0; i < sdk_tail; i = i + 1 {
    sd.push(b'\x00')
  }
  w_push_u32(sd, 0)
  let sd_b = Bytes::from_array(sd[:])
  let signer : Array[Byte] = []
  w_push_u32(signer, sd_b.length())
  w_push_bytes(signer, sd_b)
  w_push_u32(signer, 0)
  w_push_u32(signer, 0)
  let signer_b = Bytes::from_array(signer[:])
  let value : Array[Byte] = []
  w_push_u32(value, signer_b.length() + 4)
  w_push_u32(value, signer_b.length())
  w_push_bytes(value, signer_b)
  Bytes::from_array(value[:])
}

///|
/// APK Signing Block（fixture，白盒版）。
fn w_sig_block_of(pairs : Array[(UInt32, Bytes)]) -> Bytes {
  let pb : Array[Byte] = []
  for (id, value) in pairs {
    w_push_u64_small(pb, value.length() + 4)
    w_push_u32(pb, id.reinterpret_as_int())
    w_push_bytes(pb, value)
  }
  let out : Array[Byte] = []
  w_push_u64_small(out, pb.length() + 24)
  w_push_bytes(out, Bytes::from_array(pb[:]))
  w_push_u64_small(out, pb.length() + 24)
  w_push_bytes(out, b"APK Sig Block 42")
  Bytes::from_array(out[:])
}

///|
/// 构造单条目（stored "foo.txt"）+ v2 verity 签名块 + 中央目录 + EOCD 的完整 APK 字节。
/// 返回 `(bytes, signingBlockOff)`（白盒测试据此手工装配 `Apk`，不依赖 `Apk::open` 完整校验）。
fn w_build_zip_with_verity(
  content : Bytes,
  verity_digest : Bytes,
  sdk_tail : Int32,
) -> (Bytes, Int32) {
  let name_b = @encoding/utf8.encode("foo.txt")
  let out : Array[Byte] = []
  let cd : Array[Byte] = []
  // local file header（stored）
  w_push_u32(out, 0x04034b50)
  w_push_u16(out, 20)
  w_push_u16(out, 0)
  w_push_u16(out, 0)
  w_push_u16(out, 0)
  w_push_u16(out, 0)
  w_push_u32(out, crc32_of(content).reinterpret_as_int())
  w_push_u32(out, content.length())
  w_push_u32(out, content.length())
  w_push_u16(out, name_b.length())
  w_push_u16(out, 0)
  w_push_bytes(out, name_b)
  w_push_bytes(out, content)
  // APK Signing Block（含 v2 verity 摘要）
  let sb = w_sig_block_of([
    (SIG_ID_V2, w_scheme_value_with_verity(verity_digest, sdk_tail)),
  ])
  let sb_off = out.length()
  w_push_bytes(out, sb)
  // 中央目录（单条目）
  let cd_off = out.length()
  w_push_u32(cd, 0x02014b50)
  w_push_u16(cd, 20)
  w_push_u16(cd, 20)
  w_push_u16(cd, 0)
  w_push_u16(cd, 0)
  w_push_u16(cd, 0)
  w_push_u16(cd, 0)
  w_push_u32(cd, crc32_of(content).reinterpret_as_int())
  w_push_u32(cd, content.length())
  w_push_u32(cd, content.length())
  w_push_u16(cd, name_b.length())
  w_push_u16(cd, 0)
  w_push_u16(cd, 0)
  w_push_u16(cd, 0)
  w_push_u16(cd, 0)
  w_push_u32(cd, 0)
  w_push_u32(cd, 0)
  w_push_bytes(cd, name_b)
  let cd_b = Bytes::from_array(cd[:])
  w_push_bytes(out, cd_b)
  // EOCD
  w_push_u32(out, 0x06054b50)
  w_push_u16(out, 0)
  w_push_u16(out, 0)
  w_push_u16(out, 1)
  w_push_u16(out, 1)
  w_push_u32(out, cd_b.length())
  w_push_u32(out, cd_off)
  w_push_u16(out, 0)
  (Bytes::from_array(out[:]), sb_off)
}

///|
/// 零填充（测试独立复刻，仅用于单块根的手工核对）。
fn w_zero_pad(b : Bytes, block_size : Int32) -> Bytes {
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
/// 盐 || 数据（测试独立复刻，用于单块根的手工核对）。
fn w_concat_salt(salt : Bytes, data : Bytes) -> Bytes {
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
/// 单块源（≤4096 字节）：fs-verity 根 == sha256(盐 || 零填充至4096的叶子摘要)。
/// 单块时叶子层即最顶层，故根 = sha256(盐 || zero_pad(sha256(盐 || zero_pad(source))))。
test "verity_root: single-block source root matches independent sha256" {
  let source = b"hello verity tree"
  let salt = b"\x00\x00\x00\x00\x00\x00\x00\x00"
  let root = verity_root(source, salt, 4096)
  let leaf = sha256(w_concat_salt(salt, w_zero_pad(source, 4096)))
  let expected = sha256(w_concat_salt(salt, w_zero_pad(leaf, 4096)))
  assert_true(
    root == expected,
    msg="单块 fs-verity 根应等于 sha256(盐||叶子摘要零填充)",
  )
  assert_eq(root.length(), 32)
}

///|
/// 多块源（>4096 字节）：确认 `verity_root` 走内部层路径且稳定可复算。
test "verity_root: multi-block source is deterministic and 32 bytes" {
  let a : Array[Byte] = []
  for i = 0; i < 9000; i = i + 1 {
    a.push((i % 251).to_byte())
  }
  let source = Bytes::from_array(a[:])
  let salt = b"\x00\x00\x00\x00\x00\x00\x00\x00"
  let r1 = verity_root(source, salt, 4096)
  let r2 = verity_root(source, salt, 4096)
  assert_eq(r1.length(), 32)
  assert_true(r1 == r2, msg="重算应确定")
  assert_true(
    r1 != verity_root(b"different", salt, 4096),
    msg="内容变化根应变化",
  )
}

///|
/// 端到端：构造含**真实重算根**的 v2 verity 摘要 APK，`verity_tree_check().tree_recomputed_ok`
/// 必须为 true（证明不再是恒 false）。
test "W5-后续 verity_tree_check end-to-end: tree_recomputed_ok == true" {
  let content = b"the quick brown fox jumps over the lazy dog"
  let salt = b"\x00\x00\x00\x00\x00\x00\x00\x00"
  // 第一遍：占位 verity 摘要（40 字节零）定布局 → 求 fs-verity 源与真实根。
  let placeholder = w_zeros40()
  let (bytes1, sb1) = w_build_zip_with_verity(content, placeholder, 0)
  let apk1 : Apk = {
    source: bytes1,
    entries: [],
    signing_block_off: Some(sb1.to_uint64()),
  }
  let src = apk1.verity_source_bytes().unwrap()
  let root = verity_root(src, salt, 4096)
  let source_len = src.length().to_uint64()
  // 40 字节 verity 摘要 = root[32] || source_len(int64 小端)
  let vd : Array[Byte] = []
  for x in root {
    vd.push(x)
  }
  w_push_u64_small(vd, source_len.to_int())
  let digest = Bytes::from_array(vd[:])
  // 第二遍：用真实根重排签名块（value 长度不变，sb 偏移不变）→ 终版 APK。
  let (bytes, sb) = w_build_zip_with_verity(content, digest, 0)
  assert_eq(sb, sb1, msg="签名块偏移应不变")
  let apk : Apk = {
    source: bytes,
    entries: [],
    signing_block_off: Some(sb.to_uint64()),
  }
  let c = apk.verity_tree_check()
  guard c is Some(info) else { fail("expected Some(VerityTreeCheck)") }
  assert_eq(info.block_id, 0x42726577U)
  assert_eq(info.hash_algorithm, "SHA-256")
  assert_eq(info.block_size, 4096)
  assert_eq(info.salt_hex, "0000000000000000")
  assert_eq(info.source_len, source_len)
  assert_eq(info.declared_root_hash_hex, w_hex(root))
  assert_eq(info.recomputed_root_hash_hex, w_hex(root))
  assert_true(
    info.tree_recomputed_ok,
    msg="端到端：真实根比对必须为 true",
  )
}

///|
/// 篡改内容区 1 字节 → 重算根变化 → `tree_recomputed_ok == false`（fail-closed）。
test "W5-后续 verity_tree_check tamper content: tree_recomputed_ok == false" {
  let content = b"the quick brown fox jumps over the lazy dog"
  let salt = b"\x00\x00\x00\x00\x00\x00\x00\x00"
  let placeholder = w_zeros40()
  let (bytes1, sb1) = w_build_zip_with_verity(content, placeholder, 0)
  let apk1 : Apk = {
    source: bytes1,
    entries: [],
    signing_block_off: Some(sb1.to_uint64()),
  }
  let src = apk1.verity_source_bytes().unwrap()
  let root = verity_root(src, salt, 4096)
  let source_len = src.length().to_uint64()
  let vd : Array[Byte] = []
  for x in root {
    vd.push(x)
  }
  w_push_u64_small(vd, source_len.to_int())
  let digest = Bytes::from_array(vd[:])
  // 用真实根构造终版 APK，然后翻转内容区 1 字节（内容区起始 = 30 头 + "foo.txt" 7 = 37）。
  let (bytes, sb) = w_build_zip_with_verity(content, digest, 0)
  let arr = bytes.to_array()
  let flip_at = 37
  let old = arr[flip_at].to_int()
  arr[flip_at] = (if old == 0x41 { 0x42 } else { 0x41 }).to_byte()
  let tampered = Bytes::from_array(arr[:])
  let apk : Apk = {
    source: tampered,
    entries: [],
    signing_block_off: Some(sb.to_uint64()),
  }
  let c = apk.verity_tree_check()
  guard c is Some(info) else { fail("expected Some(VerityTreeCheck)") }
  assert_true(!info.tree_recomputed_ok, msg="内容篡改必须 fail-closed")
  assert_true(info.declared_root_hash_hex != info.recomputed_root_hash_hex)
}
