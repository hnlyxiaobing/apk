// Blackbox tests run against the package's public API. Use `@apk` to import.
// Prefer high-level behaviors over implementation details.
// Run `moon test` to execute and `moon test --update` to refresh snapshots.
//
// 测试策略（见 DESIGN.md §10）：工作区无真实 APK 资产（docs/open-questions.md Q1），
// 所有 ZIP/APK 样本在测试代码中以编程方式构造：stored / deflate 条目、classes*.dex 列表、
// lib/<abi>/*.so 目录、APK Signing Block 魔数用例、畸形中央目录用例、ZIP64 拒绝用例。

///|
/// 测试侧小端写入工具。
fn push_u16(a : Array[Byte], v : Int32) -> Unit {
  a.push((v & 0xFF).to_byte())
  a.push(((v >> 8) & 0xFF).to_byte())
}

///|
fn push_u32(a : Array[Byte], v : Int32) -> Unit {
  push_u16(a, v & 0xFFFF)
  push_u16(a, (v >> 16) & 0xFFFF)
}

///|
fn push_u64_small(a : Array[Byte], v : Int32) -> Unit {
  push_u32(a, v)
  push_u32(a, 0)
}

///|
fn push_bytes(a : Array[Byte], b : Bytes) -> Unit {
  for x in b {
    a.push(x)
  }
}

///|
/// 测试侧 CRC-32（与实现同算法，用于 fixture 的目录字段）。
fn t_crc32(data : Bytes) -> UInt32 {
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
/// 手工构造的 deflate 流：单个 stored 块（BFINAL=1, BTYPE=00），合法 RFC 1951。
fn deflate_stored(data : Bytes) -> Bytes {
  let out : Array[Byte] = []
  out.push(b'\x01')
  push_u16(out, data.length())
  push_u16(out, 0xFFFF - data.length())
  push_bytes(out, data)
  Bytes::from_array(out[:])
}

///|
/// ZIP 条目描述（fixture 用）。
struct ZSpec {
  name : String
  comp_method : Int32
  data : Bytes
  extra_pad : Int32
  cd_extra : Bytes
  bad_crc : Bool
}

///|
fn zspec(name : String, data : Bytes) -> ZSpec {
  { name, comp_method: 0, data, extra_pad: 0, cd_extra: b"", bad_crc: false, }
}

///|
fn zspec_deflated(name : String, data : Bytes) -> ZSpec {
  { name, comp_method: 8, data, extra_pad: 0, cd_extra: b"", bad_crc: false, }
}

///|
/// 构造一个完整 ZIP：local headers + 数据 +（可选）APK Signing Block + 中央目录 + EOCD。
fn build_zip(specs : Array[ZSpec], sig_block : Bytes?) -> Bytes {
  let out : Array[Byte] = []
  let cd : Array[Byte] = []
  for s in specs {
    let comp = if s.comp_method == 8 { deflate_stored(s.data) } else { s.data }
    let crc = t_crc32(s.data)
    let name_b = @encoding/utf8.encode(s.name)
    let local_off = out.length()
    push_u32(out, 0x04034b50)
    push_u16(out, 20)
    push_u16(out, 0)
    push_u16(out, s.comp_method)
    push_u16(out, 0)
    push_u16(out, 0)
    push_u32(out, (if s.bad_crc { crc + 1 } else { crc }).reinterpret_as_int())
    push_u32(out, comp.length())
    push_u32(out, s.data.length())
    push_u16(out, name_b.length())
    push_u16(out, s.extra_pad)
    push_bytes(out, name_b)
    for i = 0; i < s.extra_pad; i = i + 1 {
      out.push(b'\x00')
    }
    push_bytes(out, comp)
    push_u32(cd, 0x02014b50)
    push_u16(cd, 20)
    push_u16(cd, 20)
    push_u16(cd, 0)
    push_u16(cd, s.comp_method)
    push_u16(cd, 0)
    push_u16(cd, 0)
    push_u32(cd, (if s.bad_crc { crc + 1 } else { crc }).reinterpret_as_int())
    push_u32(cd, comp.length())
    push_u32(cd, s.data.length())
    push_u16(cd, name_b.length())
    push_u16(cd, s.cd_extra.length())
    push_u16(cd, 0)
    push_u16(cd, 0)
    push_u16(cd, 0)
    push_u32(cd, 0)
    push_u32(cd, local_off)
    push_bytes(cd, name_b)
    push_bytes(cd, s.cd_extra)
  }
  match sig_block {
    Some(sb) => push_bytes(out, sb)
    None => ()
  }
  let cd_off = out.length()
  let cd_bytes = Bytes::from_array(cd[:])
  push_bytes(out, cd_bytes)
  let n = specs.length()
  push_u32(out, 0x06054b50)
  push_u16(out, 0)
  push_u16(out, 0)
  push_u16(out, n)
  push_u16(out, n)
  push_u32(out, cd_bytes.length())
  push_u32(out, cd_off)
  push_u16(out, 0)
  Bytes::from_array(out[:])
}

///|
/// APK Signing Block：u64 size + ID-value 对 + u64 size + "APK Sig Block 42"。
fn sig_block_of(pairs : Array[(UInt32, Bytes)]) -> Bytes {
  let pb : Array[Byte] = []
  for (id, value) in pairs {
    push_u64_small(pb, value.length() + 4)
    push_u32(pb, id.reinterpret_as_int())
    push_bytes(pb, value)
  }
  let out : Array[Byte] = []
  push_u64_small(out, pb.length() + 24)
  push_bytes(out, Bytes::from_array(pb[:]))
  push_u64_small(out, pb.length() + 24)
  push_bytes(out, b"APK Sig Block 42")
  Bytes::from_array(out[:])
}

///|
/// 签名方案值（fixture）：signer 序列，cert 挂在 signed_data 的 certificates 下。
/// 布局对齐真实 APK Signing Block（v2/v3/v3.1 signer 顶层一致，与 apksigner 产物
/// 同构）：signed_data = digests(=0) + certificates + minSDK/maxSDK 尾区(`sdk_tail`
/// 字节) + additional_attributes(=0)。`sdk_tail`：v2 = 0、v3 = 8、v3.1 = 8
/// （min/max SDK 在 signed_data 内部、certificates 之后；v3.1 的 rotationMinSDK
/// 位于 additional_attributes，本 fixture attrs 为空）。
fn scheme_value(cert : Bytes, sdk_tail : Int32) -> Bytes {
  let cs : Array[Byte] = []
  push_u32(cs, cert.length())
  push_bytes(cs, cert)
  let cs_b = Bytes::from_array(cs[:])
  let sd : Array[Byte] = []
  push_u32(sd, 0)
  push_u32(sd, cs_b.length())
  push_bytes(sd, cs_b)
  for i = 0; i < sdk_tail; i = i + 1 {
    sd.push(b'\x00')
  }
  push_u32(sd, 0)
  let sd_b = Bytes::from_array(sd[:])
  let signer : Array[Byte] = []
  push_u32(signer, sd_b.length())
  push_bytes(signer, sd_b)
  push_u32(signer, 0)
  push_u32(signer, 0)
  let signer_b = Bytes::from_array(signer[:])
  let value : Array[Byte] = []
  push_u32(value, signer_b.length() + 4)
  push_u32(value, signer_b.length())
  push_bytes(value, signer_b)
  Bytes::from_array(value[:])
}

///|
/// 最小 `resources.arsc`：ResTable 头 + 全局字符串池 chunk（chunk 尺寸可注入畸形，
/// 文件本身始终 4 字节对齐，确保畸形被定位到 chunk 而不是文件级截断）。
fn build_arsc(pool_size : Int32) -> Bytes {
  let padded = (pool_size + 3) / 4 * 4
  let out : Array[Byte] = []
  push_u16(out, 0x0002)
  push_u16(out, 12)
  push_u32(out, 12 + padded)
  push_u32(out, 1)
  push_u16(out, 0x0001)
  push_u16(out, 28)
  push_u32(out, pool_size)
  push_u32(out, 2)
  push_u32(out, 0)
  push_u32(out, 0)
  push_u32(out, 28)
  push_u32(out, 0)
  for i = 28; i < padded; i = i + 1 {
    out.push(i.to_byte())
  }
  Bytes::from_array(out[:])
}

///|
fn patch_byte(b : Bytes, off : Int32, v : Int32) -> Bytes {
  let arr = b.to_array()
  arr[off] = v.to_byte()
  Bytes::from_array(arr[:])
}

///|
fn patch_u32(b : Bytes, off : Int32, v : Int32) -> Bytes {
  let arr = b.to_array()
  arr[off] = (v & 0xFF).to_byte()
  arr[off + 1] = ((v >> 8) & 0xFF).to_byte()
  arr[off + 2] = ((v >> 16) & 0xFF).to_byte()
  arr[off + 3] = ((v >> 24) & 0xFF).to_byte()
  Bytes::from_array(arr[:])
}

///|
fn scheme_str(s : @apk.SignatureScheme) -> String {
  match s {
    @apk.SignatureScheme::V1 => "V1"
    @apk.SignatureScheme::V2 => "V2"
    @apk.SignatureScheme::V3 => "V3"
    @apk.SignatureScheme::V31 => "V31"
  }
}

///|
fn abi_str(a : @apk.Abi) -> String {
  match a {
    @apk.Abi::ArmeabiV7a => "ArmeabiV7a"
    @apk.Abi::Arm64V8a => "Arm64V8a"
    @apk.Abi::X86 => "X86"
    @apk.Abi::X86_64 => "X86_64"
    @apk.Abi::Unknown(s) => "Unknown(" + s + ")"
  }
}

///|
test "open indexes central directory entries in order" {
  let zip = build_zip(
    [zspec("ab.txt", b"hello"), zspec_deflated("cd.txt", b"world!!")],
    None,
  )
  let apk = @apk.Apk::open(zip)
  let es = apk.entries()
  assert_eq(es.length(), 2)
  assert_eq(es[0].name, "ab.txt")
  assert_eq(es[0].crc32, t_crc32(b"hello"))
  assert_eq(es[0].compression_method, 0)
  assert_eq(es[0].compressed_size, 5UL)
  assert_eq(es[0].uncompressed_size, 5UL)
  assert_eq(es[0].local_header_off, 0UL)
  assert_true(es[0].is_aligned)
  assert_eq(es[1].name, "cd.txt")
  assert_eq(es[1].compression_method, 8)
  assert_eq(es[1].uncompressed_size, 7UL)
  assert_eq(
    es[1].compressed_size,
    deflate_stored(b"world!!").length().to_uint64(),
  )
  assert_eq(es[1].local_header_off, 41UL)
  assert_true(!es[1].is_aligned)
}

///|
test "entry extracts stored and deflate payloads" {
  let zip = build_zip(
    [zspec("ab.txt", b"hello"), zspec_deflated("cd.txt", b"world!!")],
    None,
  )
  let apk = @apk.Apk::open(zip)
  assert_true(apk.entry("ab.txt") == b"hello")
  assert_true(apk.entry("cd.txt") == b"world!!")
}

///|
test "entry raises EntryNotFound for missing names" {
  let apk = @apk.Apk::open(build_zip([zspec("ab.txt", b"hello")], None))
  try ignore(apk.entry("nope.bin")) catch {
    @apk.ApkError::EntryNotFound(n) => assert_eq(n, "nope.bin")
    _ => fail("expected EntryNotFound")
  } noraise {
    _ => fail("expected EntryNotFound")
  }
}

///|
test "entry raises on unsupported compression method" {
  let s = {
    name: "ab.txt",
    comp_method: 12,
    data: b"hello",
    extra_pad: 0,
    cd_extra: b"",
    bad_crc: false,
  }
  let apk = @apk.Apk::open(build_zip([s], None))
  try ignore(apk.entry("ab.txt")) catch {
    @apk.ApkError::BadCentralDirectory(off, detail) => {
      assert_eq(off, 36)
      assert_true(detail.contains("compression method"))
    }
    _ => fail("expected BadCentralDirectory")
  } noraise {
    _ => fail("expected BadCentralDirectory")
  }
}

///|
test "entry raises on crc32 mismatch" {
  let s = {
    name: "ab.txt",
    comp_method: 0,
    data: b"hello",
    extra_pad: 0,
    cd_extra: b"",
    bad_crc: true,
  }
  let apk = @apk.Apk::open(build_zip([s], None))
  try ignore(apk.entry("ab.txt")) catch {
    @apk.ApkError::BadCentralDirectory(_, detail) =>
      assert_true(detail.contains("crc32"))
    _ => fail("expected BadCentralDirectory")
  } noraise {
    _ => fail("expected BadCentralDirectory")
  }
}

///|
test "manifest returns raw axml bytes and raises when missing" {
  let axml = b"\x03\x00\x02\x00fake-axml-payload"
  let apk = @apk.Apk::open(
    build_zip([zspec("AndroidManifest.xml", axml)], None),
  )
  let m = apk.manifest()
  assert_eq(m.entry_name, "AndroidManifest.xml")
  assert_true(m.raw == axml)
  let empty_apk = @apk.Apk::open(build_zip([zspec("ab.txt", b"hello")], None))
  try ignore(empty_apk.manifest()) catch {
    @apk.ApkError::EntryNotFound(n) => assert_eq(n, "AndroidManifest.xml")
    _ => fail("expected EntryNotFound")
  } noraise {
    _ => fail("expected EntryNotFound")
  }
}

///|
test "dex_files lists root classes*.dex sorted by name" {
  let apk = @apk.Apk::open(
    build_zip(
      [
        zspec("classes10.dex", b"dex10"),
        zspec("classes2.dex", b"dex2"),
        zspec("classes.dex", b"dex1"),
        zspec("docs/notes.dex", b"nested"),
        zspec("myclasses.dex", b"prefix"),
        zspec("classes.txt", b"notdex"),
      ],
      None,
    ),
  )
  let ds = apk.dex_files()
  assert_eq(ds.length(), 3)
  assert_eq(ds[0].name, "classes.dex")
  assert_true(ds[0].bytes == b"dex1")
  assert_eq(ds[1].name, "classes10.dex")
  assert_true(ds[1].bytes == b"dex10")
  assert_eq(ds[2].name, "classes2.dex")
  assert_true(ds[2].bytes == b"dex2")
}

///|
test "native_libs classifies ABIs and filters" {
  let apk = @apk.Apk::open(
    build_zip(
      [
        zspec("lib/arm64-v8a/liba.so", b"so-a"),
        zspec("lib/armeabi-v7a/libb.so", b"so-b"),
        zspec("lib/x86/libc.so", b"so-c"),
        zspec("lib/x86_64/libd.so", b"so-d"),
        zspec("lib/mips/libe.so", b"so-e"),
        zspec("lib/arm64-v8a/readme.txt", b"txt"),
        zspec("res/libfake.so", b"fake"),
        zspec("lib/arm64-v8a/deep/x.so", b"deep"),
      ],
      None,
    ),
  )
  let all = apk.native_libs(None)
  assert_eq(all.length(), 5)
  assert_eq(abi_str(all[0].abi), "Arm64V8a")
  assert_eq(all[0].path, "lib/arm64-v8a/liba.so")
  assert_true(all[0].bytes == b"so-a")
  assert_eq(abi_str(all[1].abi), "ArmeabiV7a")
  assert_eq(abi_str(all[2].abi), "X86")
  assert_eq(abi_str(all[3].abi), "X86_64")
  assert_eq(abi_str(all[4].abi), "Unknown(mips)")
  let only_arm64 = apk.native_libs(Some(@apk.Abi::Arm64V8a))
  assert_eq(only_arm64.length(), 1)
  assert_eq(only_arm64[0].path, "lib/arm64-v8a/liba.so")
  let none = apk.native_libs(Some(@apk.Abi::Unknown("riscv64")))
  assert_eq(none.length(), 0)
}

///|
test "signatures identifies v2 v3 v31 schemes with certificates" {
  let pairs : Array[(UInt32, Bytes)] = []
  pairs.push((0x42726577, b"padding"))
  pairs.push((0x7109871a, scheme_value(b"cert2", 0)))
  pairs.push((0xf05368c0, scheme_value(b"cert3", 8)))
  pairs.push((0x1b93ad61, scheme_value(b"cert31", 8)))
  let apk = @apk.Apk::open(
    build_zip([zspec("ab.txt", b"hello")], Some(sig_block_of(pairs))),
  )
  assert_true(apk.signing_block_off is Some(_))
  let sigs = apk.signatures()
  assert_eq(sigs.length(), 3)
  assert_eq(scheme_str(sigs[0].scheme), "V2")
  assert_eq(sigs[0].block_id, 0x7109871a)
  assert_true(
    sigs[0].certificates.length() == 1 && sigs[0].certificates[0] == b"cert2",
  )
  assert_true(!sigs[0].verified)
  assert_eq(scheme_str(sigs[1].scheme), "V3")
  assert_eq(sigs[1].block_id, 0xf05368c0)
  assert_true(
    sigs[1].certificates.length() == 1 && sigs[1].certificates[0] == b"cert3",
  )
  assert_eq(scheme_str(sigs[2].scheme), "V31")
  assert_eq(sigs[2].block_id, 0x1b93ad61)
  assert_true(
    sigs[2].certificates.length() == 1 && sigs[2].certificates[0] == b"cert31",
  )
  assert_true(!sigs[2].verified)
}

///|
test "signatures detects v1 from META-INF signature entries" {
  let apk = @apk.Apk::open(
    build_zip(
      [zspec("META-INF/CERT.RSA", b"pkcs7"), zspec("classes.dex", b"dex")],
      None,
    ),
  )
  let sigs = apk.signatures()
  assert_eq(sigs.length(), 1)
  assert_eq(scheme_str(sigs[0].scheme), "V1")
  assert_eq(sigs[0].block_id, 0)
  assert_eq(sigs[0].certificates.length(), 0)
  assert_true(!sigs[0].verified)
}

///|
test "signatures returns empty without signing block" {
  let apk = @apk.Apk::open(build_zip([zspec("ab.txt", b"hello")], None))
  assert_true(apk.signing_block_off is None)
  assert_eq(apk.signatures().length(), 0)
}

///|
test "signatures raises UnsupportedSignatureScheme for unknown schemes" {
  let pairs : Array[(UInt32, Bytes)] = []
  pairs.push((0xdeadbeef, b"mystery"))
  let apk = @apk.Apk::open(
    build_zip([zspec("ab.txt", b"hello")], Some(sig_block_of(pairs))),
  )
  try ignore(apk.signatures()) catch {
    @apk.ApkError::UnsupportedSignatureScheme(_) => ()
    _ => fail("expected UnsupportedSignatureScheme")
  } noraise {
    _ => fail("expected UnsupportedSignatureScheme")
  }
}

///|
test "signatures raises BadSigningBlock on overrunning pair" {
  let pb : Array[Byte] = []
  push_u64_small(pb, 1000)
  push_u32(pb, 0x7109871a)
  push_bytes(pb, b"x")
  let out : Array[Byte] = []
  push_u64_small(out, pb.length() + 24)
  push_bytes(out, Bytes::from_array(pb[:]))
  push_u64_small(out, pb.length() + 24)
  push_bytes(out, b"APK Sig Block 42")
  let apk = @apk.Apk::open(
    build_zip([zspec("ab.txt", b"hello")], Some(Bytes::from_array(out[:]))),
  )
  try ignore(apk.signatures()) catch {
    @apk.ApkError::BadSigningBlock(_, _) => ()
    _ => fail("expected BadSigningBlock")
  } noraise {
    _ => fail("expected BadSigningBlock")
  }
}

///|
test "open raises BadSigningBlock on mismatched block sizes" {
  let pairs : Array[(UInt32, Bytes)] = []
  pairs.push((0x7109871a, scheme_value(b"cert2", 0)))
  let zip = build_zip([zspec("ab.txt", b"hello")], Some(sig_block_of(pairs)))
  // 签名块紧跟在唯一条目数据之后：偏移 41 是 size 字段首字节
  let patched = patch_byte(zip, 41, zip[41].to_int() + 1)
  try ignore(@apk.Apk::open(patched)) catch {
    @apk.ApkError::BadSigningBlock(off, _) => assert_eq(off, 41)
    _ => fail("expected BadSigningBlock")
  } noraise {
    _ => fail("expected BadSigningBlock")
  }
}

///|
test "resource_table returns global string pool" {
  let arsc = build_arsc(32)
  let apk = @apk.Apk::open(build_zip([zspec("resources.arsc", arsc)], None))
  let res = match apk.resource_table() {
    Some(r) => r
    None => fail("expected resources.arsc")
  }
  assert_eq(res.entry_name, "resources.arsc")
  assert_true(res.raw == arsc)
  assert_eq(res.global_string_pool.length(), 32)
  assert_eq(res.global_string_pool[0].to_int(), 0x01)
  assert_eq(res.global_string_pool[2].to_int(), 0x1C)
}

///|
test "resource_table returns None without resources.arsc" {
  let apk = @apk.Apk::open(build_zip([zspec("ab.txt", b"hello")], None))
  assert_true(apk.resource_table() is None)
}

///|
test "resource_table raises BadAlignment on misaligned chunk" {
  let arsc = build_arsc(30)
  let apk = @apk.Apk::open(build_zip([zspec("resources.arsc", arsc)], None))
  try ignore(apk.resource_table()) catch {
    @apk.ApkError::BadAlignment(name, off) => {
      assert_eq(name, "resources.arsc")
      assert_eq(off, 12)
    }
    _ => fail("expected BadAlignment")
  } noraise {
    _ => fail("expected BadAlignment")
  }
}

///|
test "open raises NotAZip on unrelated bytes" {
  try ignore(@apk.Apk::open(b"this is definitely not a zip archive")) catch {
    @apk.ApkError::NotAZip(_) => ()
    _ => fail("expected NotAZip")
  } noraise {
    _ => fail("expected NotAZip")
  }
  try ignore(@apk.Apk::open(b"tiny")) catch {
    @apk.ApkError::NotAZip(_) => ()
    _ => fail("expected NotAZip")
  } noraise {
    _ => fail("expected NotAZip")
  }
}

///|
test "open raises UnexpectedEof on truncated archive" {
  let zip = build_zip(
    [zspec("ab.txt", b"hello"), zspec_deflated("cd.txt", b"world!!")],
    None,
  )
  let truncated = zip[0:zip.length() - 30].to_owned()
  try ignore(@apk.Apk::open(truncated)) catch {
    @apk.ApkError::UnexpectedEof(_) => ()
    _ => fail("expected UnexpectedEof")
  } noraise {
    _ => fail("expected UnexpectedEof")
  }
}

///|
test "open raises BadCentralDirectory on corrupt directory" {
  let zip = build_zip([zspec("ab.txt", b"hello")], None)
  // 单条目 "ab.txt"(5B 数据)：中央目录从偏移 41 开始，翻转签名首字节
  let patched = patch_byte(zip, 41, 0x51)
  try ignore(@apk.Apk::open(patched)) catch {
    @apk.ApkError::BadCentralDirectory(off, detail) => {
      assert_eq(off, 41)
      assert_true(detail.contains("signature"))
    }
    _ => fail("expected BadCentralDirectory")
  } noraise {
    _ => fail("expected BadCentralDirectory")
  }
}

///|
test "open rejects ZIP64 sentinel values in EOCD" {
  let zip = build_zip([zspec("ab.txt", b"hello")], None)
  let eocd = zip.length() - 22
  let patched = patch_u32(zip, eocd + 12, -1)
  try ignore(@apk.Apk::open(patched)) catch {
    @apk.ApkError::Zip64Unsupported(_) => ()
    _ => fail("expected Zip64Unsupported")
  } noraise {
    _ => fail("expected Zip64Unsupported")
  }
}

///|
test "open rejects ZIP64 end-of-central-directory locator" {
  let out : Array[Byte] = []
  for i = 0; i < 24; i = i + 1 {
    out.push(b'\x00')
  }
  push_u32(out, 0x07064b50)
  push_u32(out, 0)
  push_u64_small(out, 0)
  push_u32(out, 1)
  push_u32(out, 0x06054b50)
  push_u16(out, 0)
  push_u16(out, 0)
  push_u16(out, 0)
  push_u16(out, 0)
  push_u32(out, 0)
  push_u32(out, 0)
  push_u16(out, 0)
  try ignore(@apk.Apk::open(Bytes::from_array(out[:]))) catch {
    @apk.ApkError::Zip64Unsupported(_) => ()
    _ => fail("expected Zip64Unsupported")
  } noraise {
    _ => fail("expected Zip64Unsupported")
  }
}

///|
test "open rejects ZIP64 extra field on entries" {
  let extra : Array[Byte] = []
  push_u16(extra, 0x0001)
  push_u16(extra, 8)
  for i = 0; i < 8; i = i + 1 {
    extra.push(b'\x00')
  }
  let s = {
    name: "ab.txt",
    comp_method: 0,
    data: b"hello",
    extra_pad: 0,
    cd_extra: Bytes::from_array(extra[:]),
    bad_crc: false,
  }
  try ignore(@apk.Apk::open(build_zip([s], None))) catch {
    @apk.ApkError::Zip64Unsupported(_) => ()
    _ => fail("expected Zip64Unsupported")
  } noraise {
    _ => fail("expected Zip64Unsupported")
  }
}

///|
test "is_aligned reflects 4-byte data alignment" {
  // "x.txt"(5)：local 头 30 + 名 5 = 数据偏移 35（未对齐）；补 1 字节 local extra 后 36（对齐）
  let mis = zspec("x.txt", b"abc")
  let zip1 = build_zip([mis], None)
  let apk1 = @apk.Apk::open(zip1)
  assert_true(!apk1.entries()[0].is_aligned)
  let ok = {
    name: "x.txt",
    comp_method: 0,
    data: b"abc",
    extra_pad: 1,
    cd_extra: b"",
    bad_crc: false,
  }
  let apk2 = @apk.Apk::open(build_zip([ok], None))
  assert_true(apk2.entries()[0].is_aligned)
  assert_true(apk2.entry("x.txt") == b"abc")
}

///|
test "container index trait mirrors inherent methods" {
  let apk = @apk.Apk::open(build_zip([zspec("ab.txt", b"hello")], None))
  assert_true(@apk.ContainerIndex::entry(apk, "ab.txt") == b"hello")
  assert_eq(@apk.ContainerIndex::entries(apk).length(), 1)
}

///|
test "empty archive yields empty index" {
  let apk = @apk.Apk::open(build_zip([], None))
  assert_eq(apk.entries().length(), 0)
  assert_eq(apk.dex_files().length(), 0)
  assert_eq(apk.native_libs(None).length(), 0)
  assert_eq(apk.signatures().length(), 0)
  assert_true(apk.resource_table() is None)
}
