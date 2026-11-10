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

///|
/// UInt64 移位、循环右移与大端读取（SHA-512 前置检查）。
test "uint64 shifts rotr and be_u64" {
  assert_eq(0x0123456789abcdefUL << 4, 0x123456789abcdef0UL)
  assert_eq(0x0123456789abcdefUL >> 4, 0x00123456789abcdeUL)
  assert_eq(rotr64(0x0123456789abcdefUL, 4), 0xf0123456789abcdeUL)
  assert_eq(
    be_u64(b"\x01\x23\x45\x67\x89\xab\xcd\xef", 0),
    0x0123456789abcdefUL,
  )
  assert_eq(
    be_u64(b"\xff\xff\xff\xff\xff\xff\xff\xff", 0),
    0xFFFFFFFFFFFFFFFFUL,
  )
  assert_eq(0xFFFFFFFFFFFFFFFEUL + 2UL, 0UL)
  assert_eq(0x0000000100000000UL + 1UL, 0x0000000100000001UL)
  // 验证 sha512 字节提取方式（高 bit 不丢失）。
  let x = 0xcf83e1357eefb8bdUL
  let b0 = ((x >> 56) & 0xFF).to_int().to_byte()
  let b1 = ((x >> 48) & 0xFF).to_int().to_byte()
  assert_eq(b0.to_int(), 0xcf)
  assert_eq(b1.to_int(), 0x83)
  // MoonBit `UInt64 >> n` 在 n>=64 时按模 64 回绕；sha512 长度编码已手动规避。
  assert_eq(24UL >> 64, 24UL)
  assert_eq(24UL >> 120, 0UL)
  assert_eq(0x0F0F0F0F0F0F0F0FUL ^ 0xF0F0F0F0F0F0F0F0UL, 0xFFFFFFFFFFFFFFFFUL)
  assert_eq(0x0F0F0F0F0F0F0F0FUL & 0xF0F0F0F0F0F0F0F0UL, 0UL)
  // SHA-512 实际用到的旋转量（与正确值逐项对账）。
  let y = 0x0123456789abcdefUL
  assert_eq(rotr64(y, 1), 0x8091a2b3c4d5e6f7UL)
  assert_eq(rotr64(y, 8), 0xef0123456789abcdUL)
  assert_eq(rotr64(y, 7), 0xde02468acf13579bUL)
  assert_eq(rotr64(y, 19), 0x79bde02468acf135UL)
  assert_eq(rotr64(y, 61), 0x091a2b3c4d5e6f78UL)
  assert_eq(rotr64(y, 14), 0x37bc048d159e26afUL)
  assert_eq(rotr64(y, 18), 0xf37bc048d159e26aUL)
  assert_eq(rotr64(y, 41), 0xb3c4d5e6f78091a2UL)
  assert_eq(rotr64(y, 28), 0x9abcdef012345678UL)
  assert_eq(rotr64(y, 34), 0xe26af37bc048d159UL)
  assert_eq(rotr64(y, 39), 0xcf13579bde02468aUL)
  // 拆解 n=7 的两个移位，定位 rotr64 错误来源。
  assert_eq(y >> 7, 0x0002468acf13579bUL)
  assert_eq(y << 57, 0xde00000000000000UL)
}

///|
/// 校验 SHA-512 常量数组未被截断或错位。
test "sha512 constants integrity" {
  assert_eq(sha512_iv.length(), 8)
  assert_eq(sha512_iv[0], 0x6a09e667f3bcc908UL)
  assert_eq(sha512_iv[7], 0x5be0cd19137e2179UL)
  assert_eq(sha512_k.length(), 80)
  assert_eq(sha512_k[0], 0x428a2f98d728ae22UL)
  assert_eq(sha512_k[79], 0x6c44198c4a475817UL)
}

///|
/// SHA-512 已知向量（FIPS 180-4）。
test "sha512 known vector empty" {
  assert_eq(
    w_hex(sha512(b"")),
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
  )
}

///|
test "sha512 known vector abc" {
  assert_eq(
    w_hex(sha512(b"abc")),
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
  )
}

///|
test "sha512 known vector a" {
  assert_eq(
    w_hex(sha512(b"a")),
    "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
  )
}

///|
test "sha512 128 zero bytes" {
  let zeros : Array[Byte] = []
  for i = 0; i < 128; i = i + 1 {
    zeros.push(b'\x00')
  }
  assert_eq(
    w_hex(sha512(Bytes::from_array(zeros[:]))),
    "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11",
  )
}

///|
/// 构造最小 APK 字节：section1 + 签名块 + 中央目录 + EOCD；
/// 只供 `content_digest` 白盒测试使用（不经过 `Apk::open` 完整校验）。
fn w_dummy_apk(_sb : Int32, cd_off : Int32, cd_size : Int32) -> Bytes {
  let eocd = cd_off + cd_size
  let buf : Array[Byte] = []
  for i = 0; i < eocd; i = i + 1 {
    buf.push((i % 256).to_byte())
  }
  // EOCD
  w_push_u32(buf, 0x06054b50)
  w_push_u16(buf, 0)
  w_push_u16(buf, 0)
  w_push_u16(buf, 1)
  w_push_u16(buf, 1)
  w_push_u32(buf, cd_size)
  w_push_u32(buf, cd_off)
  w_push_u16(buf, 0)
  Bytes::from_array(buf[:])
}

///|
/// v2/v3 内容摘要算法 ID 映射：只认 AOSP `CONTENT_DIGEST_*`，
/// 签名算法 ID（0x0201/0x0301）不再被误映射为 SHA-256。
test "whitebox: content digest algorithm id mapping" {
  assert_eq(content_digest_algorithm_name(0x0101U), "SHA-256")
  assert_eq(content_digest_algorithm_name(0x0103U), "SHA-256")
  assert_eq(content_digest_algorithm_name(0x0104U), "SHA-256")
  assert_eq(content_digest_algorithm_name(0x0102U), "SHA-512")
  assert_eq(content_digest_algorithm_name(0x0105U), "SHA-512")
  assert_eq(content_digest_algorithm_name(0x0201U), "unknown")
  assert_eq(content_digest_algorithm_name(0x0301U), "unknown")
}

///|
/// v2 内容摘要聚合语义：按记录算法分别计算 SHA-256/SHA-512，并与 signer digest 比对。
test "whitebox: v2 content digest aggregation" {
  let sb = 32
  let cd_off = 64
  let cd_size = 48
  let source = w_dummy_apk(sb, cd_off, cd_size)
  let apk : Apk = {
    source,
    entries: [],
    signing_block_off: Some(sb.to_uint64()),
  }
  let d256 = apk.content_digest("SHA-256").unwrap()
  assert_eq(d256.length(), 32, msg="SHA-256 内容摘要长度")
  let d512 = apk.content_digest("SHA-512").unwrap()
  assert_eq(d512.length(), 64, msg="SHA-512 内容摘要长度")
  let rec256 : SigRecord = {
    scheme: SignatureScheme::V2,
    block_id: 0x7109871aU,
    certs: [b"cert"],
    digests: [{ algorithm: 0x0101U, digest: d256, }],
    pkcs7_ok: true,
    v1_sf: None,
    v1_manifest: None,
  }
  let check256 = apk.verify_v2(rec256)
  assert_true(check256.structure_ok, msg="结构完整")
  assert_true(check256.digest_ok, msg="SHA-256 内容摘要一致")
  let rec512 : SigRecord = {
    scheme: SignatureScheme::V2,
    block_id: 0x7109871aU,
    certs: [b"cert"],
    digests: [{ algorithm: 0x0102U, digest: d512, }],
    pkcs7_ok: true,
    v1_sf: None,
    v1_manifest: None,
  }
  let check512 = apk.verify_v2(rec512)
  assert_true(check512.digest_ok, msg="SHA-512 内容摘要一致")
  // 签名算法 ID 0x0201 不应被当作 SHA-256，digest_ok 保持 false。
  let rec_bad : SigRecord = {
    scheme: SignatureScheme::V2,
    block_id: 0x7109871aU,
    certs: [b"cert"],
    digests: [{ algorithm: 0x0201U, digest: d256, }],
    pkcs7_ok: true,
    v1_sf: None,
    v1_manifest: None,
  }
  let check_bad = apk.verify_v2(rec_bad)
  assert_true(
    !check_bad.digest_ok,
    msg="签名算法 ID 不参与内容摘要聚合",
  )
}
