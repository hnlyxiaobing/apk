// WP-G / Q1 畸形派生用例（R2 准备轮新增文件）：从**真实** tvshell-debug.apk 派生，
// 覆盖截断 / 偏移污染（EOCD、中央目录）/ 错误 CRC / 未知压缩方法。
// 断言目标：报 `ApkError` 而非 panic。样本来源见 fixtures/golden/ASSETS.md。

///|
/// 字节级变异：拷贝后把 `offset` 处改成 `value`。
fn fx_mut(src : Bytes, offset : Int32, value : Byte) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<src.length() {
    arr.push(src[i])
  }
  if offset >= 0 && offset < arr.length() {
    arr[offset] = value
  }
  Bytes::from_array(arr)
}

///|
/// 异或变异（用于 CRC 字段）。
fn fx_xor(src : Bytes, offset : Int32, mask : Byte) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<src.length() {
    arr.push(src[i])
  }
  if offset >= 0 && offset < arr.length() {
    arr[offset] = (arr[offset].to_int() ^ mask.to_int()).to_byte()
  }
  Bytes::from_array(arr)
}

///|
/// 截断到前 `n` 字节。
fn fx_cut(src : Bytes, n : Int32) -> Bytes {
  let arr : Array[Byte] = []
  let mut i = 0
  while i < n && i < src.length() {
    arr.push(src[i])
    i = i + 1
  }
  Bytes::from_array(arr)
}

///|
/// 写小端 u32（拷贝后写入）。
fn fx_set_u32(src : Bytes, off : Int32, v : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for i in 0..<src.length() {
    arr.push(src[i])
  }
  arr[off] = (v & 0xFF).to_byte()
  arr[off + 1] = ((v >> 8) & 0xFF).to_byte()
  arr[off + 2] = ((v >> 16) & 0xFF).to_byte()
  arr[off + 3] = ((v >> 24) & 0xFF).to_byte()
  Bytes::from_array(arr)
}

///|
/// 从尾部向前找 EOCD 签名 `PK\x05\x06`，返回偏移；找不到返回 -1。
fn fx_find_eocd(b : Bytes) -> Int32 {
  let mut found = -1
  let mut i = b.length() - 4
  while i >= 0 && found < 0 {
    if b[i] == b'\x50' &&
      b[i + 1] == b'\x4b' &&
      b[i + 2] == b'\x05' &&
      b[i + 3] == b'\x06' {
      found = i
    }
    i = i - 1
  }
  found
}

///|
/// 找 ASCII 模式（如 "classes.dex"）首次出现的偏移；从 `start` 开始找；找不到返回 -1。
fn fx_find_pattern_from(b : Bytes, pat : Array[Int32], start : Int32) -> Int32 {
  let mut found = -1
  let mut i = if start > 0 { start } else { 0 }
  while i + pat.length() <= b.length() && found < 0 {
    let mut hit = true
    let mut k = 0
    while k < pat.length() {
      if b[i + k].to_int() != pat[k] {
        hit = false
        k = pat.length()
      }
      k = k + 1
    }
    if hit {
      found = i
    }
    i = i + 1
  }
  found
}

///|
/// 读小端 u32。
fn fx_u32(src : Bytes, off : Int32) -> Int32 {
  src[off].to_int() +
  (src[off + 1].to_int() << 8) +
  (src[off + 2].to_int() << 16) +
  (src[off + 3].to_int() << 24)
}

///|
/// 中央目录区里 `classes.dex` 的文件名偏移（EOCD+16 = CD 起始）。
fn fx_cd_classes_dex_off(src : Bytes) -> Int32 {
  let eocd = fx_find_eocd(src)
  if eocd < 0 {
    -1
  } else {
    let cd = fx_u32(src, eocd + 16)
    fx_find_pattern_from(src, fx_classes_dex_pat(), cd)
  }
}

///|
/// "classes.dex" 的 ASCII 码。
fn fx_classes_dex_pat() -> Array[Int32] {
  [0x63, 0x6c, 0x61, 0x73, 0x73, 0x65, 0x73, 0x2e, 0x64, 0x65, 0x78]
}

///|
/// 打开是否以 `ApkError` 结束。
fn fx_open_raises(b : Bytes) -> Bool {
  let mut raised = false
  try ignore(@apk.Apk::open(b)) catch {
    _ => raised = true
  } noraise {
    _ => ()
  }
  raised
}

///|
test "apk malformed: 截断真实 APK 报错且不 panic" {
  let src = fixture_tvshell_apk()
  for cut in [0, 100, 10000, 21207] {
    assert_true(
      fx_open_raises(fx_cut(src, cut)),
      msg="截断到 \{cut} 字节应报 ApkError",
    )
  }
}

///|
test "apk malformed: EOCD 签名污染报 NotAZip" {
  let src = fixture_tvshell_apk()
  let eocd = fx_find_eocd(src)
  assert_true(eocd > 0, msg="能找到 EOCD")
  assert_true(
    fx_open_raises(fx_mut(src, eocd, b'\x00')),
    msg="EOCD 签名污染应报 NotAZip",
  )
}

///|
test "apk malformed: 中央目录偏移污染报错" {
  let src = fixture_tvshell_apk()
  let eocd = fx_find_eocd(src)
  // EOCD +16 = 中央目录起始偏移
  let bad = fx_set_u32(src, eocd + 16, 0x00FFFFFF)
  assert_true(
    fx_open_raises(bad),
    msg="CD 偏移越界应报 BadCentralDirectory",
  )
}

///|
test "apk malformed: 条目 CRC 污染在解压时报错" {
  let src = fixture_tvshell_apk()
  let name_off = fx_cd_classes_dex_off(src)
  assert_true(name_off > 0, msg="中央目录含 classes.dex")
  // 中央目录项：签名4 版本2 需要2 标志2 方法2 时间2 日期2 CRC4 ...  文件名从 +46 开始
  let crc_off = name_off - 46 + 16
  let bad = fx_xor(src, crc_off, b'\xff')
  let mut raised = false
  try {
    let a = @apk.Apk::open(bad)
    ignore(a.entry("classes.dex"))
  } catch {
    _ => raised = true
  } noraise {
    _ => ()
  }
  assert_true(raised, msg="CRC 污染应在解压校验时报 ApkError")
}

///|
test "apk malformed: 未知压缩方法报错" {
  let src = fixture_tvshell_apk()
  let name_off = fx_cd_classes_dex_off(src)
  // 中央目录项：方法字段在 +10（文件名前 36 字节）
  let mut bad = fx_set_u32(src, name_off - 46 + 10, 99)
  // 上面按4 字节写会覆盖方法(2)+时间(2)，这里改为精确写 2 字节
  let arr : Array[Byte] = []
  for i in 0..<src.length() {
    arr.push(src[i])
  }
  arr[name_off - 46 + 10] = 99
  arr[name_off - 46 + 11] = 0
  bad = Bytes::from_array(arr)
  let mut raised = false
  try {
    let a = @apk.Apk::open(bad)
    ignore(a.entry("classes.dex"))
  } catch {
    _ => raised = true
  } noraise {
    _ => ()
  }
  assert_true(raised, msg="未知压缩方法应报 ApkError")
}

///|
/// ZIP 没有 AXML 那样的 chunk 概念；“未知 chunk 跳过”的等价用例见
/// axml/fixtures_malformed_test.mbt；DEX 的“未知 opcode”见 dex 链。
#skip
test "apk malformed: 未知 chunk [SKIPPED: ZIP 无 chunk 概念]" {
  println("SKIPPED: ZIP 无 chunk；未知压缩方法用例见上")
}
