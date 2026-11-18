// 畸形派生用例：从**真实** tvshell-debug.apk 派生，
// 覆盖截断 / 偏移污染（EOCD、中央目录）/ 错误 CRC / 未知压缩方法。
// 断言目标：报 `ApkError` 而非 panic。样本来源见 tests/ASSETS.md。

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
/// ZIP 没有 AXML 那样的 chunk 概念；“未知 chunk 跳过”的等价用例见 axml 库的对应畸形测试；
/// DEX 的“未知 opcode”见 dex 库的对应测试。
#skip
test "apk malformed: 未知 chunk [SKIPPED: ZIP 无 chunk 概念]" {
  println("SKIPPED: ZIP 无 chunk；未知压缩方法用例见上")
}

///|
/// 受控构建多 dex APK（v2/v3 变体）派生：截断 / EOCD 签名污染 /
/// 中央目录偏移污染，同样只报 `ApkError` 而非 panic。样本性质：受控自产
///（aapt2/d8/apksigner 构建），见 tests/ASSETS.md。
test "apk malformed: 多 dex APK 截断与目录污染报错且不 panic" {
  let src = fixture_fx_multidex_v2v3_apk()
  for cut in [0, 100, 6000, 12549] {
    assert_true(
      fx_open_raises(fx_cut(src, cut)),
      msg="截断到 \{cut} 字节应报 ApkError",
    )
  }
  let eocd = fx_find_eocd(src)
  assert_true(eocd > 0, msg="能找到 EOCD")
  assert_true(
    fx_open_raises(fx_mut(src, eocd, b'\x00')),
    msg="EOCD 签名污染应报 NotAZip",
  )
  let bad = fx_set_u32(src, eocd + 16, 0x00FFFFFF)
  assert_true(
    fx_open_raises(bad),
    msg="CD 偏移越界应报 BadCentralDirectory",
  )
}

// ---------------------------------------------------------------------------
// W6 加固：APK Signing Block / v1 CMS 块畸形语料（真实样本一线）。
// 断言口径：`verify_signatures()` 只能抛 ApkError 或 crypto_verified=false；
// 未变异基线必须验签通过（防止「全 false 假绿」）。
// ---------------------------------------------------------------------------

///|
/// 签名块范围：返回 (block_start, pairs_end)；解析不出返回 (-1, -1)。
fn w6_blk_span(src : Bytes) -> (Int32, Int32) {
  let eocd = fx_find_eocd(src)
  if eocd < 0 {
    return (-1, -1)
  }
  let cd = fx_u32(src, eocd + 16)
  if cd < 24 {
    return (-1, -1)
  }
  let size = fx_u32(src, cd - 24)
  (cd - size - 8, cd - 24)
}

///|
/// 按 ID 查签名块 value：返回 (value_off, value_len)；找不到 (-1, -1)。
fn w6_blk_find(src : Bytes, id : Int32) -> (Int32, Int32) {
  let span = w6_blk_span(src)
  let mut pos = span.0 + 8
  let mut found : (Int32, Int32) = (-1, -1)
  while span.0 >= 0 && pos + 12 <= span.1 && found.0 < 0 {
    let len = fx_u32(src, pos)
    if fx_u32(src, pos + 8) == id {
      found = (pos + 12, len - 4)
    }
    pos = pos + 8 + len
  }
  found
}

///|
/// `verify_signatures()` 是否 fail-closed（抛 ApkError 或 crypto 全 false）。
fn w6_verify_fail_closed(src : Bytes) -> Bool {
  let mut ok = true
  try {
    let apk = @apk.Apk::open(src)
    for c in apk.verify_signatures() {
      if c.crypto_verified {
        ok = false
      }
    }
  } catch {
    _ => ()
  } noraise {
    _ => ()
  }
  ok
}

///|
/// 方案枚举相等（枚举未派生 Eq，此处显式匹配）。
fn w6_same_scheme(a : @apk.SignatureScheme, b : @apk.SignatureScheme) -> Bool {
  match (a, b) {
    (@apk.SignatureScheme::V1, @apk.SignatureScheme::V1) => true
    (@apk.SignatureScheme::V2, @apk.SignatureScheme::V2) => true
    (@apk.SignatureScheme::V3, @apk.SignatureScheme::V3) => true
    (@apk.SignatureScheme::V31, @apk.SignatureScheme::V31) => true
    _ => false
  }
}

///|
/// 指定方案是否 fail-closed（抛 ApkError / 缺该方案 / 该方案 crypto=false）。
/// 多方案样本中只变异某一方案时，其他方案仍可验签，故按方案断言。
fn w6_verify_scheme_fail_closed(
  src : Bytes,
  scheme : @apk.SignatureScheme,
) -> Bool {
  let mut ok = true
  try {
    let apk = @apk.Apk::open(src)
    for c in apk.verify_signatures() {
      if w6_same_scheme(c.scheme, scheme) && c.crypto_verified {
        ok = false
      }
    }
  } catch {
    _ => ()
  } noraise {
    _ => ()
  }
  ok
}

///|
test "apk malformed: v2/v3 签名块长度字段污染与截断 fail-closed（真实样本）" {
  let src = fixture_fx_multidex_v2v3_apk()
  // 基线校准：未变异样本必须可验签，否则「全 false」断言无意义。
  let base = @apk.Apk::open(src).verify_signatures()
  assert_true(base.length() > 0, msg="基线含签名方案")
  assert_true(base[0].crypto_verified, msg="基线验签通过")
  for
    entry in [
      (0x7109871a, @apk.SignatureScheme::V2),
      (0xf05368c0, @apk.SignatureScheme::V3),
    ] {
    let (id, scheme) = entry
    let value = w6_blk_find(src, id)
    assert_true(value.0 > 0, msg="找到签名方案 \{id}")
    let vo = value.0
    // seq_len / signer_len / sd_len 越界污染（只影响该方案）。
    for delta in [0, 4, 8] {
      for bad in [-1, 0x7FFFFFFF] {
        assert_true(
          w6_verify_scheme_fail_closed(fx_set_u32(src, vo + delta, bad), scheme),
          msg="value+\{delta} 置 0x\{bad} 应 fail-closed",
        )
      }
    }
    // value 头部采样位翻转（长度字段/签名载荷密集区）。
    for i in 0..<24 {
      assert_true(
        w6_verify_scheme_fail_closed(fx_xor(src, vo + i, b'\x01'), scheme),
        msg="value+\{i} 位翻转应 fail-closed",
      )
    }
    // 签名块内截断（影响整个容器，全部方案 fail-closed）。
    let span = w6_blk_span(src)
    for cut in [span.0 + 8, vo + 1, vo + 3] {
      if cut > 0 && cut < src.length() {
        assert_true(
          w6_verify_fail_closed(fx_cut(src, cut)),
          msg="截断到 \{cut} 字节应 fail-closed",
        )
      }
    }
  }
}

///|
/// 重建含指定 `.RSA` 块的 v1 APK（其余条目字节不变，保持摘要链）。
fn w6_v1_with_rsa(base : Array[ZSpec], der : Bytes) -> Bytes {
  let specs : Array[ZSpec] = []
  for s in base {
    specs.push(s)
  }
  specs.push(zspec("META-INF/FXKEY.RSA", der))
  build_zip(specs, None)
}

///|
test "apk malformed: v1 CMS 块截断/长度污染/位翻转 fail-closed（真实样本重建）" {
  let apk = @apk.Apk::open(fixture_fx_multidex_v1_apk())
  let base : Array[ZSpec] = []
  for
    n in [
      "AndroidManifest.xml", "resources.arsc", "classes.dex", "classes2.dex", "META-INF/MANIFEST.MF",
      "META-INF/FXKEY.SF",
    ] {
    base.push(zspec(n, apk.entry(n)))
  }
  let der = apk.entry("META-INF/FXKEY.RSA")
  // 基线校准：重建后的 APK 必须仍可验签（只替换同一 .RSA 字节）。
  let rebuilt = w6_v1_with_rsa(base, der)
  let checks = @apk.Apk::open(rebuilt).verify_signatures()
  assert_true(checks.length() > 0, msg="重建样本含 v1 方案")
  assert_true(checks[0].crypto_verified, msg="重建基线验签通过")
  // 截断。
  for cut in [0, 1, 4, 10, 100, der.length() / 2, der.length() - 1] {
    if cut >= 0 && cut < der.length() {
      assert_true(
        w6_verify_fail_closed(w6_v1_with_rsa(base, fx_cut(der, cut))),
        msg="CMS 截断到 \{cut} 应 fail-closed",
      )
    }
  }
  // DER 长长度字段（30 82 xx xx）污染。
  let mut hits = 0
  for i in 0..<(der.length() - 2) {
    if der[i] == b'\x30' && der[i + 1] == b'\x82' && hits < 6 {
      assert_true(
        w6_verify_fail_closed(w6_v1_with_rsa(base, fx_mut(der, i + 2, b'\xff'))),
        msg="DER 长度 @\{i + 2} 污染应 fail-closed",
      )
      hits = hits + 1
    }
  }
  assert_true(hits > 0, msg="样本含 30 82 长长度字段")
  // DER 头部采样位翻转：证书区/算法标识不参与 signerInfo 签名，只断言不 panic。
  for i in 0..<48 {
    ignore(w6_verify_fail_closed(w6_v1_with_rsa(base, fx_xor(der, i, b'\x01'))))
  }
  // 末尾 encryptedDigest 区位翻转：CMS 签名值必须验证失败。
  for i in (der.length() - 32)..<der.length() {
    assert_true(
      w6_verify_fail_closed(w6_v1_with_rsa(base, fx_xor(der, i, b'\x01'))),
      msg="CMS 签名区 @\{i} 位翻转应 fail-closed",
    )
  }
}

// ---------------------------------------------------------------------------
// W6 加固：模数规模上限（≤ 8192 位）——攻击者可控超大模数的 DoS 面收敛。
// ---------------------------------------------------------------------------

///|
/// DER TLV（长度编码支持 0x80..0xFFFFFF）。
fn w6_der(tag : Int32, content : Bytes) -> Bytes {
  let out : Array[Byte] = [tag.to_byte()]
  let n = content.length()
  if n < 0x80 {
    out.push(n.to_byte())
  } else if n <= 0xFF {
    out.push(b'\x81')
    out.push(n.to_byte())
  } else if n <= 0xFFFF {
    out.push(b'\x82')
    out.push((n >> 8).to_byte())
    out.push((n & 0xFF).to_byte())
  } else {
    out.push(b'\x83')
    out.push((n >> 16).to_byte())
    out.push(((n >> 8) & 0xFF).to_byte())
    out.push((n & 0xFF).to_byte())
  }
  push_bytes(out, content)
  Bytes::from_array(out[:])
}

///|
/// 以给定模数内容构造 RSA SPKI（e = 65537）。
fn w6_rsa_spki(modulus : Bytes) -> Bytes {
  let rsa : Array[Byte] = []
  push_bytes(rsa, w6_der(0x02, modulus))
  push_bytes(rsa, w6_der(0x02, b"\x01\x00\x01"))
  let bits : Array[Byte] = [b'\x00']
  push_bytes(bits, w6_der(0x30, Bytes::from_array(rsa[:])))
  let body : Array[Byte] = []
  push_bytes(
    body, b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00",
  )
  push_bytes(body, w6_der(0x03, Bytes::from_array(bits[:])))
  w6_der(0x30, Bytes::from_array(body[:]))
}

///|
/// v2 方案值：空摘要/空证书 + 一条 RSA PKCS#1(SHA-256) 签名记录（1 字节占位）+ 公钥。
fn w6_v2_value(pk : Bytes) -> Bytes {
  let sd : Array[Byte] = []
  push_u32(sd, 0)
  push_u32(sd, 0)
  push_u32(sd, 0)
  let sigrec : Array[Byte] = []
  push_u32(sigrec, 9)
  push_u32(sigrec, 0x0103)
  push_u32(sigrec, 1)
  push_bytes(sigrec, b"\x00")
  let signer : Array[Byte] = []
  push_u32(signer, sd.length())
  push_bytes(signer, Bytes::from_array(sd[:]))
  push_u32(signer, sigrec.length())
  push_bytes(signer, Bytes::from_array(sigrec[:]))
  push_u32(signer, pk.length())
  push_bytes(signer, pk)
  let value : Array[Byte] = []
  push_u32(value, signer.length() + 4)
  push_u32(value, signer.length())
  push_bytes(value, Bytes::from_array(signer[:]))
  Bytes::from_array(value[:])
}

///|
test "apk hardening: 超大模数 fail-closed 且 detail=key too large" {
  // 65544 位模数（8193 字节全 0xFF）；若无上限，模幂不可完成。
  let mod : Array[Byte] = []
  for i = 0; i < 8193; i = i + 1 {
    mod.push(b'\xff')
  }
  let pk = w6_rsa_spki(Bytes::from_array(mod[:]))
  let value = w6_v2_value(pk)
  let apk_bytes = build_zip(
    [zspec("AndroidManifest.xml", b"\x03\x00\x08\x00")],
    Some(sig_block_of([(0x7109871aU, value)])),
  )
  let apk = @apk.Apk::open(apk_bytes)
  let checks = apk.verify_signatures()
  assert_eq(checks.length(), 1)
  assert_true(checks[0].scheme is @apk.SignatureScheme::V2)
  assert_true(checks[0].structure_ok, msg="signer 结构可解析")
  assert_true(!checks[0].crypto_verified, msg="超限模数必须 fail-closed")
  assert_eq(checks[0].detail, "key too large")
}
