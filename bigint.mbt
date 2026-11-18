///|
/// 纯 MoonBit 无符号大数（M6-1，W6 公钥验签·仅 RSA）。
///
/// 内部原语：以 `Array[UInt32]` 为 limb（**小端**：limb[0] 为最低位），每个 limb 32 位，
/// 归一化（最高位 limb 不为 0；空数组代表值 0）。提供加 / 减 / 乘 / 模 / 模幂。
///
/// 用途：RSA PKCS#1 v1.5 验签原语（M6-2）的底层；后续接入 v1/v2/v3/v3.1 签名值验证。
/// 本模块**不进入公开 API**（内部原语），公开入口在 M6-4/M6-5 的 `verify_signatures`。
///
/// 实现口径：纯值、无外部依赖、无全局状态；输入只读。`big_mod` 用二进制长除法
/// （移位-减），`big_mod_pow` 用右到左二进制模幂——对离线分析工具的 APK 级输入可接受；
/// 大 RSA 模数的模运算复杂度 O(bitlen·limbs)，属分析工具可接受的非实时口径。
///
/// 语义防火墙：本模块只做无符号整数运算，**不做**符号/小数/负数；调用方保证
/// `big_sub` 的 a≥b、`big_mod`/`big_mod_pow` 的模数非 0 且为奇（RSA 模数天然满足）。
/// 密码学正确性由 M6-1 已知向量测试承载（见 `bigint_test.mbt`）。

///|
/// 大数：小端 UInt32 limb 数组（空数组 = 0，无前导 0 limb）。
priv struct BigInt {
  limbs : Array[UInt32]
}

///|
/// 值 0。
fn big_zero() -> BigInt {
  { limbs: [], }
}

///|
/// 值 1。
fn big_one() -> BigInt {
  { limbs: [1], }
}

///|
/// 判断是否为 0。
fn big_is_zero(a : BigInt) -> Bool {
  a.limbs.length() == 0
}

///|
/// 比较 a 与 b：a<b → -1；a==b → 0；a>b → 1。
fn big_cmp(a : BigInt, b : BigInt) -> Int32 {
  let la = a.limbs.length()
  let lb = b.limbs.length()
  if la != lb {
    if la < lb {
      -1
    } else {
      1
    }
  } else {
    for i = la - 1; i >= 0; i = i - 1 {
      if a.limbs[i] != b.limbs[i] {
        return if a.limbs[i] < b.limbs[i] { -1 } else { 1 }
      }
    }
    0
  }
}

///|
/// 位长（最高置位位下标 + 1；0 返回 0）。
fn big_bit_length(a : BigInt) -> Int32 {
  let n = a.limbs.length()
  if n == 0 {
    return 0
  }
  let top = a.limbs[n - 1]
  (n - 1) * 32 + (32 - top.clz())
}

///|
/// 取第 `i` 位（LSB 为位 0）。
fn big_bit_at(a : BigInt, i : Int32) -> Bool {
  let limb = a.limbs[i / 32]
  ((limb >> (i % 32)) & 1U) != 0U
}

///|
/// 左移 1 位。
fn big_shl1(a : BigInt) -> BigInt {
  let out : Array[UInt32] = []
  let mut carry : UInt32 = 0U
  for limb in a.limbs {
    out.push((limb << 1) | carry)
    carry = limb >> 31
  }
  if carry != 0U {
    out.push(carry)
  }
  { limbs: out, }
}

///|
/// 归一化：去掉最高位的 0 limb（空数组 = 0）。
fn big_normalize(limbs : Array[UInt32]) -> BigInt {
  let mut n = limbs.length()
  while n > 0 && limbs[n - 1] == 0U {
    n = n - 1
  }
  let out : Array[UInt32] = []
  for i = 0; i < n; i = i + 1 {
    out.push(limbs[i])
  }
  { limbs: out, }
}

///|
/// 加：a + b。
fn big_add(a : BigInt, b : BigInt) -> BigInt {
  let na = a.limbs.length()
  let nb = b.limbs.length()
  let n = if na > nb { na } else { nb }
  let out : Array[UInt32] = []
  let mut carry : UInt64 = 0UL
  for i = 0; i < n; i = i + 1 {
    let ai = if i < na { a.limbs[i].to_uint64() } else { 0UL }
    let bi = if i < nb { b.limbs[i].to_uint64() } else { 0UL }
    let s = ai + bi + carry
    out.push(s.to_uint())
    carry = s >> 32
  }
  if carry != 0UL {
    out.push(carry.to_uint())
  }
  big_normalize(out)
}

///|
/// 减：a - b（要求 a ≥ b）。
fn big_sub(a : BigInt, b : BigInt) -> BigInt {
  let na = a.limbs.length()
  let nb = b.limbs.length()
  let n = if na > nb { na } else { nb }
  let out : Array[UInt32] = []
  let mut borrow : UInt64 = 0UL
  for i = 0; i < n; i = i + 1 {
    let ai = if i < na { a.limbs[i].to_uint64() } else { 0UL }
    let bi = if i < nb { b.limbs[i].to_uint64() } else { 0UL }
    let diff = ai + 4294967296UL - borrow - bi
    out.push(diff.to_uint())
    borrow = if ai < bi + borrow { 1UL } else { 0UL }
  }
  big_normalize(out)
}

///|
/// 乘：a * b（教科书逐位乘，limb 中间用 UInt64 承接）。
fn big_mul(a : BigInt, b : BigInt) -> BigInt {
  if big_is_zero(a) || big_is_zero(b) {
    return big_zero()
  }
  let na = a.limbs.length()
  let nb = b.limbs.length()
  let res = Array::make(na + nb, 0U)
  for i = 0; i < na; i = i + 1 {
    let mut carry : UInt64 = 0UL
    let ai = a.limbs[i].to_uint64()
    for j = 0; j < nb; j = j + 1 {
      let cur = res[i + j].to_uint64() + ai * b.limbs[j].to_uint64() + carry
      res[i + j] = cur.to_uint()
      carry = cur >> 32
    }
    res[i + nb] = carry.to_uint()
  }
  big_normalize(res)
}

///|
/// 模：a mod m（二进制长除法，m ≠ 0；结果 < m）。
fn big_mod(a : BigInt, m : BigInt) -> BigInt {
  if big_is_zero(a) {
    return big_zero()
  }
  if big_cmp(a, m) < 0 {
    return a
  }
  let mut r = big_zero()
  let bit_len = big_bit_length(a)
  for i = bit_len - 1; i >= 0; i = i - 1 {
    r = big_shl1(r)
    if big_bit_at(a, i) {
      r = big_add(r, big_one())
    }
    if big_cmp(r, m) >= 0 {
      r = big_sub(r, m)
    }
  }
  r
}

///|
/// 模幂：base^exp mod m（右到左二进制模幂；exp ≥ 0，m ≠ 0）。
fn big_mod_pow(base : BigInt, exp : BigInt, m : BigInt) -> BigInt {
  let mut result = big_one()
  let mut b = big_mod(base, m)
  let bit_len = big_bit_length(exp)
  for i = 0; i < bit_len; i = i + 1 {
    if big_bit_at(exp, i) {
      result = big_mod(big_mul(result, b), m)
    }
    b = big_mod(big_mul(b, b), m)
  }
  result
}

///|
/// 从大端字节构造（b[0] 为最高位字节）。空/全零 → 0。
fn big_from_be_bytes(b : Bytes) -> BigInt {
  let len = b.length()
  if len == 0 {
    return big_zero()
  }
  let nlimbs = (len + 3) / 4
  let out : Array[UInt32] = []
  for i = 0; i < nlimbs; i = i + 1 {
    let mut v : UInt32 = 0U
    // 每个 limb 覆盖大端字节 [len-4i-4, len-4i-1)；k=0 为该 limb 的最高字节。
    for k = 0; k < 4; k = k + 1 {
      let byte_idx = len - 4 * i - 4 + k
      if byte_idx >= 0 && byte_idx < len {
        v = (v << 8) | b[byte_idx].to_uint()
      }
    }
    out.push(v)
  }
  big_normalize(out)
}

///|
/// 转大端字节（最小字节数；0 → 单字节 0x00）。
fn big_to_be_bytes(a : BigInt) -> Bytes {
  if big_is_zero(a) {
    return b"\x00"
  }
  let bytes : Array[Byte] = []
  for i = a.limbs.length() - 1; i >= 0; i = i - 1 {
    let limb = a.limbs[i]
    bytes.push(((limb >> 24) & 0xFFU).to_byte())
    bytes.push(((limb >> 16) & 0xFFU).to_byte())
    bytes.push(((limb >> 8) & 0xFFU).to_byte())
    bytes.push((limb & 0xFFU).to_byte())
  }
  let mut start = 0
  while start < bytes.length() - 1 && bytes[start] == b'\x00' {
    start = start + 1
  }
  let out : Array[Byte] = []
  for i = start; i < bytes.length(); i = i + 1 {
    out.push(bytes[i])
  }
  Bytes::from_array(out[:])
}
