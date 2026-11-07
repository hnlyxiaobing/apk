// Whitebox tests run within the package scope.
// Use them to validate internal helpers or invariants.
// Keep them focused; public behavior belongs in `_test.mbt`.
//
// 这里覆盖内部小端读取、CRC-32 已知向量、EOCD 定位（含伪造 EOCD）、ABI/路径归类。

///|
fn w_push_u16(a : Array[Byte], v : Int32) -> Unit {
  a.push((v & 0xFF).to_byte())
  a.push(((v >> 8) & 0xFF).to_byte())
}

///|
fn w_push_u32(a : Array[Byte], v : Int32) -> Unit {
  w_push_u16(a, v & 0xFFFF)
  w_push_u16(a, (v >> 16) & 0xFFFF)
}

///|
test "little endian readers" {
  let b = b"\x78\x56\x34\x12\x9a\xbc\xde\xf0"
  assert_eq(le_u16(b, 0), 0x5678)
  assert_eq(le_u16(b, 2), 0x1234)
  assert_eq(le_u32(b, 0), 0x12345678)
  assert_eq(le_u32(b, 4), 0xf0debc9a)
  assert_eq(le_u64(b, 0), 0xf0debc9a12345678)
}

///|
test "crc32 known vectors" {
  assert_eq(crc32_of(b""), 0)
  assert_eq(crc32_of(b"a"), 0xE8B7BE43)
  assert_eq(crc32_of(b"123456789"), 0xCBF43926)
}

///|
test "find_eocd skips forged records and honors comment length" {
  let a : Array[Byte] = []
  // 伪造 EOCD：comment_len=5，不会收尾于 EOF
  w_push_u32(a, 0x06054b50)
  w_push_u16(a, 0)
  w_push_u16(a, 0)
  w_push_u16(a, 0)
  w_push_u16(a, 0)
  w_push_u32(a, 0)
  w_push_u32(a, 0)
  w_push_u16(a, 5)
  for i = 0; i < 5; i = i + 1 {
    a.push(i.to_byte())
  }
  // 真 EOCD：comment_len=0，恰好收尾于 EOF
  w_push_u32(a, 0x06054b50)
  w_push_u16(a, 0)
  w_push_u16(a, 0)
  w_push_u16(a, 0)
  w_push_u16(a, 0)
  w_push_u32(a, 0)
  w_push_u32(a, 0)
  w_push_u16(a, 0)
  let b = Bytes::from_array(a[:])
  assert_true(find_eocd(b) == Some(27))
  assert_true(find_eocd(b"short") is None)
}

///|
test "abi and path classifiers" {
  assert_true(abi_of_dir("armeabi-v7a") is Abi::ArmeabiV7a)
  assert_true(abi_of_dir("arm64-v8a") is Abi::Arm64V8a)
  assert_true(abi_of_dir("x86") is Abi::X86)
  assert_true(abi_of_dir("x86_64") is Abi::X86_64)
  assert_true(abi_of_dir("mips") is Abi::Unknown("mips"))
  assert_true(lib_abi_of("lib/arm64-v8a/liba.so") is Some(Abi::Arm64V8a))
  assert_true(lib_abi_of("lib/mips/liba.so") is Some(Abi::Unknown("mips")))
  assert_true(lib_abi_of("lib/arm64-v8a/deep/x.so") is None)
  assert_true(lib_abi_of("lib/arm64-v8a/nosuffix") is None)
  assert_true(lib_abi_of("res/liba.so") is None)
  assert_true(lib_abi_of("lib/x86/.so") is None)
  assert_true(is_dex_name("classes.dex"))
  assert_true(is_dex_name("classes12.dex"))
  assert_true(!is_dex_name("myclasses.dex"))
  assert_true(!is_dex_name("classes.txt"))
  assert_true(!is_dex_name("docs/classes.dex"))
}

///|
test "abi_eq is structural" {
  assert_true(abi_eq(Abi::Arm64V8a, Abi::Arm64V8a))
  assert_true(!abi_eq(Abi::Arm64V8a, Abi::ArmeabiV7a))
  assert_true(abi_eq(Abi::Unknown("mips"), Abi::Unknown("mips")))
  assert_true(!abi_eq(Abi::Unknown("mips"), Abi::Unknown("riscv")))
}

///|
test "name_compare is deterministic lexicographic order" {
  assert_true(name_compare("classes10.dex", "classes2.dex") < 0)
  assert_true(name_compare("classes2.dex", "classes10.dex") > 0)
  assert_true(name_compare("classes.dex", "classes10.dex") < 0)
  assert_true(name_compare("a", "a") == 0)
  assert_true(name_compare("a", "ab") < 0)
}

///|
test "extra_field_has_id scans id-value pairs" {
  let a : Array[Byte] = []
  w_push_u16(a, 0xd935)
  w_push_u16(a, 2)
  w_push_u16(a, 0x1234)
  let ok = Bytes::from_array(a[:])
  assert_true(extra_field_has_id(ok[:], 0xd935))
  assert_true(!extra_field_has_id(ok[:], 0x0001))
  let b : Array[Byte] = []
  w_push_u16(b, 0x0001)
  w_push_u16(b, 8)
  for i = 0; i < 8; i = i + 1 {
    b.push(b'\x00')
  }
  assert_true(extra_field_has_id(Bytes::from_array(b[:])[:], 0x0001))
}
