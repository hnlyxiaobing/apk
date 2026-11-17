///|
/// W5 verity 签名块测试（T-W5-1 / T-W5-4；T-W5-2/3 #skip —— 树重算未实现）。
/// 测试工具（build_zip / sig_block_of / zspec / push_u32 / push_u64_small）来自同
/// 测试包的 apk_test.mbt；fixture 加载来自 fixtures_test.mbt。

///|
test "T-W5-1: no verity block returns None" {
  let apk = @apk.Apk::open(fixture_fx_multidex_v1_apk())
  let v = apk.verity()
  assert_true(v is None)
}

///|
test "T-W5-4a: verity block recognition (zero-padding style)" {
  // 构造带 verity padding 块的 APK：ID 0x42726577，value = 零填充（对齐）。
  let verity_value : Bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  let sb = sig_block_of([(0x42726577U, verity_value)])
  let zip = build_zip([zspec("foo.txt", b"hello")], Some(sb))
  let apk = @apk.Apk::open(zip)
  let v = apk.verity()
  guard v is Some(info) else { fail("expected Some(VerityInfo)") }
  assert_eq(info.block_id, 0x42726577U)
  assert_eq(info.tree_recomputed_ok, false)
  assert_eq(info.hash_algorithm, "unknown")
  assert_eq(info.salt_hex, "")
  assert_eq(info.root_hash_hex, "")
}

///|
test "T-W5-4b: verity block with structured data (parse attempt)" {
  // 构造带结构化 verity 值的 APK：
  // u32 version=2 | u32 hash_algo=1(SHA256) | u32 block_size=4096 |
  // u32 salt_len=4 | salt=b"NaCl" | u32 root_hash_len=4 | root_hash=b"rhsh" | u64 tree_size=0
  let val : Array[Byte] = []
  push_u32(val, 2)
  push_u32(val, 1)
  push_u32(val, 4096)
  push_u32(val, 4)
  for x in b"NaCl" {
    val.push(x)
  }
  push_u32(val, 4)
  for x in b"rhsh" {
    val.push(x)
  }
  push_u64_small(val, 0)
  let verity_value = Bytes::from_array(val[:])
  let sb = sig_block_of([(0x42726577U, verity_value)])
  let zip = build_zip([zspec("foo.txt", b"hello")], Some(sb))
  let apk = @apk.Apk::open(zip)
  let v = apk.verity()
  guard v is Some(info) else { fail("expected Some(VerityInfo)") }
  assert_eq(info.block_id, 0x42726577U)
  assert_eq(info.version, 2)
  assert_eq(info.hash_algorithm, "SHA-256")
  assert_eq(info.block_size, 4096)
  assert_eq(info.salt_hex, "4e61436c")
  assert_eq(info.root_hash_hex, "72687368")
  assert_eq(info.tree_size, 0UL)
  assert_eq(info.tree_recomputed_ok, false)
}

///|
/// T-W5-2: #skip —— 树重算未实现（需 AOSP 布局核实 + fs-verity Merkle 树实现）。
test "T-W5-2 tree recomputation (skip: not implemented)" {
  // #skip: 树重算依赖 AOSP fs-verity Merkle 树布局核实，本模块只交付块识别。
}

///|
/// T-W5-3: #skip —— 树重算未实现。
test "T-W5-3 tampered content detection (skip: not implemented)" {
  // #skip: 同上，树重算未实现。
}
