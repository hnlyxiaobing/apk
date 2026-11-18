///|
/// M6-1 无符号大数已知向量测试（FIPS/已知值）。
///
/// 覆盖：add / sub / mul / mod / mod_pow / 十六进制与字节往返 / 边界（0、1、模幂指数 0）。
/// 期望值经 Python 大整数计算核验（见开发会话记录）。
/// 注意：`big_mod_pow` 的 `exp` 为 `BigInt`，指数 0 与 1 用 `big_from_u32` 构造。

///|
test "T-M6-1-add: carry-across-limbs add" {
  let a = big_from_hex("ffffffffffffffffffffffffffffffff")
  let b = big_from_hex("1")
  let s = big_add(a, b)
  assert_eq(big_to_hex(s), "100000000000000000000000000000000")
}

///|
test "T-M6-1-sub: borrow-across-limbs sub" {
  let a = big_from_hex("ffffffffffffffffffffffffffffffff")
  let b = big_from_hex("1")
  let d = big_sub(a, b)
  assert_eq(big_to_hex(d), "fffffffffffffffffffffffffffffffe")
}

///|
test "T-M6-1-mul: 64-bit multiply" {
  let a = big_from_hex("ffffffffffffffff")
  let b = big_from_hex("ffffffffffffffff")
  let p = big_mul(a, b)
  assert_eq(big_to_hex(p), "fffffffffffffffe0000000000000001")
}

///|
test "T-M6-1-mul2: distinct operands" {
  let a = big_from_hex("deadbeef")
  let b = big_from_hex("cafebabe")
  let p = big_mul(a, b)
  assert_eq(big_to_hex(p), "b092ab7b88cf5b62")
}

///|
test "T-M6-1-mod: reduce to remainder" {
  let a = big_from_hex("ffffffffffffffffffffffffffffffff")
  let m = big_from_hex("3b9aca07")
  let r = big_mod(a, m)
  assert_eq(big_to_hex(r), "10aad994")
}

///|
test "T-M6-1-mod-pow: exponent 0 and base 0" {
  // base^0 = 1
  let b0 = big_from_u32(99)
  let e0 = big_from_u32(0)
  let m0 = big_from_u32(1000)
  let r0 = big_mod_pow(b0, e0, m0)
  assert_eq(big_to_hex(r0), "1")
  // 0^5 = 0
  let r1 = big_mod_pow(big_from_u32(0), big_from_u32(5), big_from_u32(100))
  assert_eq(big_to_hex(r1), "0")
}

///|
test "T-M6-1-mod-pow: known vector 5^77 mod 97" {
  let r = big_mod_pow(big_from_u32(5), big_from_u32(77), big_from_u32(97))
  assert_eq(big_to_hex(r), "17")
}

///|
test "T-M6-1-mod-pow: 3^1024 mod 1e9+7 (multi-limb)" {
  let r = big_mod_pow(
    big_from_u32(3),
    big_from_hex("400"),
    big_from_u32(1000000007),
  )
  assert_eq(big_to_hex(r), "2d7f7514")
}

///|
test "T-M6-1-mod-pow: large exponent 0x1234^0x5678 mod 0xabcdef" {
  let r = big_mod_pow(
    big_from_hex("1234"),
    big_from_hex("5678"),
    big_from_hex("abcdef"),
  )
  assert_eq(big_to_hex(r), "a89c10")
}

///|
test "T-M6-1-parse-roundtrip: hex and be-bytes round-trip" {
  let v = "deadbeefcafebabe0123456789abcdef"
  let a = big_from_hex(v)
  assert_eq(big_to_hex(a), v)
  let bytes = big_to_be_bytes(a)
  let b = big_from_be_bytes(bytes)
  assert_eq(big_to_hex(b), v)
}

///|
test "T-M6-1-byte-roundtrip: 2^128-1 is 16 bytes" {
  let a = big_from_hex("ffffffffffffffffffffffffffffffff")
  let bytes = big_to_be_bytes(a)
  assert_eq(bytes.length(), 16)
  let b = big_from_be_bytes(bytes)
  assert_eq(big_to_hex(b), "ffffffffffffffffffffffffffffffff")
}

///|
test "T-M6-1-zero-and-one normalization" {
  assert_eq(big_to_hex(big_from_u32(0)), "0")
  assert_eq(big_to_hex(big_one()), "1")
  assert_eq(big_to_be_bytes(big_from_u32(0)), b"\x00")
  assert_true(big_is_zero(big_from_u32(0)))
  assert_true(!big_is_zero(big_one()))
}

///|
test "T-M6-1-cmp ordering" {
  let a = big_from_hex("10")
  let b = big_from_hex("0f")
  let c = big_from_hex("10")
  assert_eq(big_cmp(a, b), 1)
  assert_eq(big_cmp(b, a), -1)
  assert_eq(big_cmp(a, c), 0)
  assert_eq(big_cmp(big_from_u32(0), big_from_u32(1)), -1)
}

///|
/// 以下三个十六进制 / u32 构造器仅服务白盒测试（非生产消费方），故置于 `_wbtest` 文件，
/// 避免被 `moon check --deny-warn` 当作「仅测试引用的未用函数」。生产解析走
/// `big_from_be_bytes` / `big_from_der_integer`。

///|
/// 从单个 UInt32 构造（0 → 空数组）。
fn big_from_u32(v : UInt32) -> BigInt {
  if v == 0U {
    big_zero()
  } else {
    { limbs: [v], }
  }
}

///|
/// 从十六进制字符串构造（允许前导 "0x"/"0X"；非法字符忽略）。
fn big_from_hex(s : String) -> BigInt {
  let mut start = 0
  if s.length() >= 2 &&
    s[0].to_int() == 48 &&
    (s[1].to_int() == 120 || s[1].to_int() == 88) {
    start = 2
  }
  let nib : Array[Int32] = []
  for i = start; i < s.length(); i = i + 1 {
    let c = s[i].to_int()
    let val = if c >= 48 && c <= 57 {
      c - 48
    } else if c >= 97 && c <= 102 {
      c - 87
    } else if c >= 65 && c <= 70 {
      c - 55
    } else {
      continue
    }
    nib.push(val)
  }
  if nib.length() == 0 {
    return big_zero()
  }
  let even = nib.length() % 2 == 0
  let bytes : Array[Byte] = []
  if !even {
    bytes.push(nib[0].to_byte())
  }
  let mut p = if even { 0 } else { 1 }
  while p + 1 < nib.length() {
    let hi = nib[p]
    let lo = nib[p + 1]
    bytes.push(((hi << 4) | lo).to_byte())
    p = p + 2
  }
  big_from_be_bytes(Bytes::from_array(bytes[:]))
}

///|
/// 转十六进制字符串（小写，无前导 0；0 → "0"）。
fn big_to_hex(a : BigInt) -> String {
  if big_is_zero(a) {
    return "0"
  }
  let bytes = big_to_be_bytes(a)
  let sb = StringBuilder()
  let mut first = true
  for x in bytes {
    let v = x.to_int()
    let hi = (v >> 4) & 0xF
    let lo = v & 0xF
    if first && hi == 0 {
      first = false
      sb.write_char((48 + lo).unsafe_to_char())
      continue
    }
    first = false
    sb.write_char(
      if hi < 10 {
        (48 + hi).unsafe_to_char()
      } else {
        (87 + hi).unsafe_to_char()
      },
    )
    sb.write_char(
      if lo < 10 {
        (48 + lo).unsafe_to_char()
      } else {
        (87 + lo).unsafe_to_char()
      },
    )
  }
  sb.to_string()
}
