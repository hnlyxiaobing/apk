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

///|
/// 字节 → 小写十六进制（白盒测试辅助）。
fn w_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let mut s = ""
  for x in b {
    let v = x.to_int()
    let hi = (v >> 4) & 15
    let lo = v & 15
    s = s + digits[hi:hi + 1].to_owned()
    s = s + digits[lo:lo + 1].to_owned()
  }
  s
}

///|
/// SHA-256 已知向量（FIPS 180-4 / NIST 标准测试向量），白盒校验纯 MoonBit 实现。
test "sha256 known vectors" {
  assert_eq(
    w_hex(sha256(b"")),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  )
  assert_eq(
    w_hex(sha256(b"abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  )
  assert_eq(
    w_hex(sha256(b"123456789")),
    "15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
  )
  // 56 字节输入触发「0x80 + 8 字节位长」跨块边界。
  assert_eq(
    w_hex(sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  )
}

///|
/// SHA-256 输出长度与确定性。
test "sha256 length and determinism" {
  let a = sha256(b"apk")
  assert_eq(a.length(), 32)
  assert_true(a == sha256(b"apk"))
  assert_true(a != sha256(b"apk!"))
}

///|
/// 白盒错误路径：坏 arsc typeSpec / 截断 DER / 坏签名块 signer / 坏 ELF 头
/// —— 全部报 `ApkError`（或 DER 解析返回 None），不 panic。
test "whitebox error paths: arsc DER signing block ELF" {
  // arsc：typeSpec id=0 → BadResourceTable(off+8)。
  let spec : Array[Byte] = []
  w_push_u16(spec, 0x0202)
  w_push_u16(spec, 16)
  w_push_u32(spec, 16)
  spec.push(b'\x00')
  spec.push(b'\x00')
  w_push_u16(spec, 1)
  w_push_u32(spec, 0)
  let spec_b = Bytes::from_array(spec[:])
  let mut arsc_hit = false
  try ignore(arsc_parse_typespec(spec_b, 0, 16, 16)) catch {
    ApkError::BadResourceTable(8, _) => arsc_hit = true
    _ => ()
  } noraise {
    _ => ()
  }
  assert_true(arsc_hit, msg="bad typeSpec must raise BadResourceTable")
  // DER：只有 tag 没有长度 → None；非 DER 的 PKCS#7 → 空证书。
  assert_true(der_read(b"\x30", 0, 1) is None)
  assert_eq(pkcs7_certificates(b"not-a-der-pkcs7").length(), 0)
  // 签名块：signer 序列长度越界 → BadSigningBlock(0)。
  let mut sb_hit = false
  try
    ignore(
      extract_signer_data(b"\xff\xff\xff\xff", SignatureScheme::V2, 0, 4, 0),
    )
  catch {
    ApkError::BadSigningBlock(0, _) => sb_hit = true
    _ => ()
  } noraise {
    _ => ()
  }
  assert_true(sb_hit, msg="bad signing block must raise BadSigningBlock")
  // ELF：bad magic → BadElf。
  let lib : NativeLib = {
    abi: Abi::X86,
    path: "lib/x86/libbad.so",
    bytes: b"not-elf",
  }
  let mut elf_hit = false
  try ignore(lib.elf_abi()) catch {
    ApkError::BadElf(_, _) => elf_hit = true
    _ => ()
  } noraise {
    _ => ()
  }
  assert_true(elf_hit, msg="bad ELF must raise BadElf")
}
