///|
/// W6-后续：ECDSA 真验签（里程碑 a：曲线原语 + NIST/RFC 向量，不接 v2/v3/v3.1 与 v1）。
///
/// 范围（本里程碑只做原语与向量，不接 b/c）：
///   - secp256r1 (P-256) 与 secp384r1 (P-384) 域参数：p、n（曲线阶）、G=(Gx,Gy)、a、b；
///   - 大数域运算（复用 `bigint.mbt` 的 `BigInt`/`big_*` 原语）：模逆（费马小定理，
///     利用既有 `big_mod_pow`）、模加/模减/模乘（在域 p 下）；
///   - 椭圆曲线：仿射坐标点加、点双倍、标量点乘（double-and-add）；
///   - ECDSA 验签原语：`r,s ∈ [1,n-1]`、`w=s^-1 mod n`、`u1=e·w`、`u2=r·w`、
///     `(x1,y1)=u1·G+u2·Q`、`v=x1 mod n`、`v==r`。
///
/// 门禁现实（dev-plan §5）：纯内部原语无法独立过 `moon check --deny-warn` 的
/// `unused_value`（白盒测试不计入未用分析）。因此本里程碑自带一个**合法的非测试公开
/// 入口** `ecdsa_verify_raw`——它是纯加法 pub 声明，本身就是内部原语的消费方，从而
/// 让所有曲线原语被公开引用、通过门禁。里程碑 b/c（接入 v2/v3/v3.1 与 v1）留空。
///
/// 语义防火墙（对齐 W6）：本模块**只提供独立验签原语**，不触碰 `verify_signatures()` /
/// `SignatureCheck.signature_verified`（恒 false 永不改变）；不新增 `ApkError` 变体；
/// 畸形输入一律值化返回 `false`，不 panic。侧信道不在威胁模型内（离线分析工具）。

///|
/// 支持的椭圆曲线（纯加法公开枚举）。
pub(all) enum EcCurve {
  /// secp256r1 (NIST P-256)。
  P256
  /// secp384r1 (NIST P-384)。
  P384
  /// 未知/未支持曲线。
  Unknown
}

///|
/// 曲线域参数（仿射坐标）。
priv struct EcParams {
  p : BigInt // 域素数
  n : BigInt // 基点阶（曲线阶）
  a : BigInt // 曲线系数 a
  b : BigInt // 曲线系数 b
  gx : BigInt // 基点 G 的 x 坐标
  gy : BigInt // 基点 G 的 y 坐标
}

///|
/// 仿射坐标椭圆曲线点。
priv struct EcPoint {
  x : BigInt
  y : BigInt
}

///|
/// 小整数常量（避免重复解析）。
fn big_two() -> BigInt {
  big_add(big_one(), big_one())
}

///|
fn big_three() -> BigInt {
  big_add(big_two(), big_one())
}

///|
/// 域参数常量专用解析：从合法十六进制构造（常量串固定合法，绝不返回 None）。
fn big_from_hex_const(s : String) -> BigInt {
  match ec_big_from_hex(s) {
    Some(v) => v
    None => big_zero()
  }
}

// ---------------------------------------------------------------------------
// 域参数（权威值见 NIST FIPS 186-4 / SEC 2，转写为 16 进制）
// ---------------------------------------------------------------------------

///|
/// P-256 域素数 p（NIST FIPS 186-4 / SEC 2）。
let p256_p : BigInt = big_from_hex_const(
  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
)

///|
/// P-256 曲线阶 n（NIST FIPS 186-4 / SEC 2）。
let p256_n : BigInt = big_from_hex_const(
  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
)

///|
/// P-256 曲线系数 a。
let p256_a : BigInt = big_from_hex_const(
  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
)

///|
/// P-256 曲线系数 b。
let p256_b : BigInt = big_from_hex_const(
  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
)

///|
/// P-256 基点 Gx。
let p256_gx : BigInt = big_from_hex_const(
  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
)

///|
/// P-256 基点 Gy。
let p256_gy : BigInt = big_from_hex_const(
  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
)

///|
/// P-256 完整域参数。
let p256_params : EcParams = {
  p: p256_p,
  n: p256_n,
  a: p256_a,
  b: p256_b,
  gx: p256_gx,
  gy: p256_gy,
}

///|
/// P-384 域素数 p（NIST FIPS 186-4 / SEC 2）。
let p384_p : BigInt = big_from_hex_const(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
)

///|
/// P-384 曲线阶 n（NIST FIPS 186-4 / SEC 2）。
let p384_n : BigInt = big_from_hex_const(
  "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
)

///|
/// P-384 曲线系数 a（NIST FIPS 186-4 / SEC 2）。
let p384_a : BigInt = big_from_hex_const(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
)

///|
/// P-384 曲线系数 b（NIST FIPS 186-4 / SEC 2）。
let p384_b : BigInt = big_from_hex_const(
  "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
)

///|
/// P-384 基点 Gx（NIST FIPS 186-4 / SEC 2）。
let p384_gx : BigInt = big_from_hex_const(
  "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
)

///|
/// P-384 基点 Gy（NIST FIPS 186-4 / SEC 2）。
let p384_gy : BigInt = big_from_hex_const(
  "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
)

///|
/// P-384 完整域参数。
let p384_params : EcParams = {
  p: p384_p,
  n: p384_n,
  a: p384_a,
  b: p384_b,
  gx: p384_gx,
  gy: p384_gy,
}

///|
/// 曲线 → 域参数；未知曲线返回 None（fail-closed）。
fn ec_params(curve : EcCurve) -> EcParams? {
  match curve {
    EcCurve::P256 => Some(p256_params)
    EcCurve::P384 => Some(p384_params)
    EcCurve::Unknown => None
  }
}

// ---------------------------------------------------------------------------
// 大数域运算（在模 m 下；m 为素数，本模块用于域 p 与曲线阶 n）
// ---------------------------------------------------------------------------

///|
/// 模逆（费马小定理）：`a^(m-2) mod m`，要求 m 为素数、a 不可被 m 整除。复用既有
/// `big_mod_pow`（右到左二进制模幂）。P-256/P-384 的 p 与 n 均为素数。
fn ec_modinv(a : BigInt, m : BigInt) -> BigInt {
  big_mod_pow(a, big_sub(m, big_two()), m)
}

///|
/// 模加：(a + b) mod m（假定 a,b < m；结果 < m）。
fn ec_add_mod(a : BigInt, b : BigInt, m : BigInt) -> BigInt {
  let s = big_add(a, b)
  if big_cmp(s, m) >= 0 {
    big_sub(s, m)
  } else {
    s
  }
}

///|
/// 模减：(a - b) mod m（假定 a,b < m；结果 < m）。
fn ec_sub_mod(a : BigInt, b : BigInt, m : BigInt) -> BigInt {
  if big_cmp(a, b) >= 0 {
    big_sub(a, b)
  } else {
    // (a - b) mod m = m - (b - a)，且 b-a ∈ [1,m-1] 故结果 ∈ [1,m-1]
    big_sub(m, big_sub(b, a))
  }
}

///|
/// 模乘：(a * b) mod m。
fn ec_mul_mod(a : BigInt, b : BigInt, m : BigInt) -> BigInt {
  big_mod(big_mul(a, b), m)
}

// ---------------------------------------------------------------------------
// 椭圆曲线点运算（Jacobian 坐标）
//
// 仿射坐标每次点加/点双倍都要一次模逆（费马：O(bitlen) 次模乘），标量点乘需
// O(bitlen) 次点运算，代价高达 O(bitlen²) 次模逆。Jacobian 坐标 (X,Y,Z) 表示
// 仿射点 (X/Z², Y/Z³)，把模逆推迟到标量点乘末尾一次——标量点乘只需 1 次模逆。
// 无穷远点以 Z=0 表示。
// ---------------------------------------------------------------------------

///|
/// 点是否在曲线上（仿射）：x,y ∈ [0,p-1] 且 `y² == x³ + a·x + b (mod p)`。
fn ec_on_curve(pt : EcPoint, params : EcParams) -> Bool {
  if big_cmp(pt.x, params.p) >= 0 || big_cmp(pt.y, params.p) >= 0 {
    return false
  }
  let lhs = ec_mul_mod(pt.y, pt.y, params.p)
  let x2 = ec_mul_mod(pt.x, pt.x, params.p)
  let x3 = ec_mul_mod(x2, pt.x, params.p)
  let ax = ec_mul_mod(params.a, pt.x, params.p)
  let rhs = ec_add_mod(ec_add_mod(x3, ax, params.p), params.b, params.p)
  big_cmp(lhs, rhs) == 0
}

///|
/// Jacobian 坐标椭圆曲线点（`(X/Z², Y/Z³)`；`Z == 0` 表无穷远点）。
priv struct EcJacobian {
  x : BigInt
  y : BigInt
  z : BigInt
}

///|
fn big_four() -> BigInt {
  big_add(big_two(), big_two())
}

///|
fn big_eight() -> BigInt {
  big_add(big_four(), big_four())
}

///|
/// 由仿射点构造 Jacobian 点（Z=1）。
fn ec_jac_of(pt : EcPoint) -> EcJacobian {
  { x: pt.x, y: pt.y, z: big_one(), }
}

///|
/// 无穷远点（Z=0）。
fn ec_jac_infinity() -> EcJacobian {
  { x: big_one(), y: big_one(), z: big_zero(), }
}

///|
/// 是否为无穷远点。
fn ec_jac_is_infinity(pt : EcJacobian) -> Bool {
  big_is_zero(pt.z)
}

///|
/// Jacobian 点双倍（通用 a）：`S = 4·X·Y²`、`M = 3·X² + a·Z⁴`、
/// `X' = M² - 2S`、`Y' = M(S - X') - 8·Y⁴`、`Z' = 2·Y·Z`。Y==0 或 Z==0 → 无穷远点。
fn ec_jac_double(pt : EcJacobian, params : EcParams) -> EcJacobian {
  let p = params.p
  if big_is_zero(pt.z) || big_is_zero(pt.y) {
    return ec_jac_infinity()
  }
  let yy = ec_mul_mod(pt.y, pt.y, p)
  let s = ec_mul_mod(big_four(), ec_mul_mod(pt.x, yy, p), p)
  let xx = ec_mul_mod(pt.x, pt.x, p)
  let zz = ec_mul_mod(pt.z, pt.z, p)
  let zzzz = ec_mul_mod(zz, zz, p)
  let m = ec_add_mod(
    ec_mul_mod(big_three(), xx, p),
    ec_mul_mod(params.a, zzzz, p),
    p,
  )
  let x3 = ec_sub_mod(ec_mul_mod(m, m, p), ec_mul_mod(big_two(), s, p), p)
  let y3 = ec_sub_mod(
    ec_mul_mod(m, ec_sub_mod(s, x3, p), p),
    ec_mul_mod(big_eight(), ec_mul_mod(yy, yy, p), p),
    p,
  )
  let z3 = ec_mul_mod(big_two(), ec_mul_mod(pt.y, pt.z, p), p)
  { x: x3, y: y3, z: z3, }
}

///|
/// Jacobian 点加（通用）：处理无穷远点、同点（转双倍）与互反点（无穷远）。
fn ec_jac_add(
  p1 : EcJacobian,
  p2 : EcJacobian,
  params : EcParams,
) -> EcJacobian {
  if ec_jac_is_infinity(p1) {
    return p2
  }
  if ec_jac_is_infinity(p2) {
    return p1
  }
  let p = params.p
  let z1z1 = ec_mul_mod(p1.z, p1.z, p)
  let z2z2 = ec_mul_mod(p2.z, p2.z, p)
  let u1 = ec_mul_mod(p1.x, z2z2, p)
  let u2 = ec_mul_mod(p2.x, z1z1, p)
  let s1 = ec_mul_mod(p1.y, ec_mul_mod(p2.z, z2z2, p), p)
  let s2 = ec_mul_mod(p2.y, ec_mul_mod(p1.z, z1z1, p), p)
  if big_cmp(u1, u2) == 0 {
    if big_cmp(s1, s2) == 0 {
      return ec_jac_double(p1, params)
    }
    return ec_jac_infinity()
  }
  let h = ec_sub_mod(u2, u1, p)
  let r = ec_sub_mod(s2, s1, p)
  let hh = ec_mul_mod(h, h, p)
  let hhh = ec_mul_mod(h, hh, p)
  let v = ec_mul_mod(u1, hh, p)
  let x3 = ec_sub_mod(
    ec_sub_mod(ec_mul_mod(r, r, p), hhh, p),
    ec_mul_mod(big_two(), v, p),
    p,
  )
  let y3 = ec_sub_mod(
    ec_mul_mod(r, ec_sub_mod(v, x3, p), p),
    ec_mul_mod(s1, hhh, p),
    p,
  )
  let z3 = ec_mul_mod(ec_mul_mod(p1.z, p2.z, p), h, p)
  { x: x3, y: y3, z: z3, }
}

///|
/// 标量点乘（double-and-add，LSB→MSB）；scalar 为 0 → 无穷远点。
fn ec_jac_scalar_mul(
  scalar : BigInt,
  pt : EcJacobian,
  params : EcParams,
) -> EcJacobian {
  let mut result = ec_jac_infinity()
  let mut addend = pt
  let bits = big_bit_length(scalar)
  for i = 0; i < bits; i = i + 1 {
    if big_bit_at(scalar, i) {
      result = ec_jac_add(result, addend, params)
    }
    addend = ec_jac_double(addend, params)
  }
  result
}

///|
/// Jacobian → 仿射（一次模逆）；无穷远点返回 None。
fn ec_jac_to_affine(pt : EcJacobian, params : EcParams) -> EcPoint? {
  if ec_jac_is_infinity(pt) {
    return None
  }
  let p = params.p
  let zinv = ec_modinv(pt.z, p)
  let zinv2 = ec_mul_mod(zinv, zinv, p)
  let x = ec_mul_mod(pt.x, zinv2, p)
  let y = ec_mul_mod(pt.y, ec_mul_mod(zinv2, zinv, p), p)
  Some({ x, y, })
}

// ---------------------------------------------------------------------------
// ECDSA 验签原语
// ---------------------------------------------------------------------------

///|
/// ECDSA 验签原语：给定公钥点 (qx,qy)、消息哈希 e、签名 (r,s)，判验签是否通过。
///
/// 步骤：`r,s ∈ [1,n-1]`（否则 false）；公钥点需在曲线上；`w = s^-1 mod n`；
/// `u1 = e·w mod n`；`u2 = r·w mod n`；`(x1,y1) = u1·G + u2·Q`；
/// `v = x1 mod n`；`v == r`。任一畸形输入均值化返回 false，不 panic。
fn ec_ecdsa_verify(
  params : EcParams,
  qx : BigInt,
  qy : BigInt,
  e : BigInt,
  r : BigInt,
  s : BigInt,
) -> Bool {
  // r, s ∈ [1, n-1]
  if big_is_zero(r) || big_cmp(r, params.n) >= 0 {
    return false
  }
  if big_is_zero(s) || big_cmp(s, params.n) >= 0 {
    return false
  }
  let q = { x: qx, y: qy, }
  if !ec_on_curve(q, params) {
    return false
  }
  let w = ec_modinv(s, params.n)
  let u1 = ec_mul_mod(e, w, params.n)
  let u2 = ec_mul_mod(r, w, params.n)
  let g = ec_jac_of({ x: params.gx, y: params.gy, })
  let qj = ec_jac_of(q)
  let p1 = ec_jac_scalar_mul(u1, g, params)
  let p2 = ec_jac_scalar_mul(u2, qj, params)
  let pt = ec_jac_add(p1, p2, params)
  match ec_jac_to_affine(pt, params) {
    None => false
    Some(p) => {
      let v = big_mod(p.x, params.n)
      big_cmp(v, r) == 0
    }
  }
}

// ---------------------------------------------------------------------------
// 公开入口（里程碑 a 自带的合法非测试消费方，承载上述全部内部原语）
// ---------------------------------------------------------------------------

///|
/// 生产用十六进制解析：→ BigInt；非法字符 / 空串返回 None（fail-closed）。
fn ec_big_from_hex(s : String) -> BigInt? {
  let nib : Array[Int32] = []
  for i = 0; i < s.length(); i = i + 1 {
    let c = s[i].to_int()
    if c >= 48 && c <= 57 {
      nib.push(c - 48)
    } else if c >= 97 && c <= 102 {
      nib.push(c - 87)
    } else if c >= 65 && c <= 70 {
      nib.push(c - 55)
    } else {
      return None
    }
  }
  if nib.length() == 0 {
    return None
  }
  let even = nib.length() % 2 == 0
  let bytes : Array[Byte] = []
  if !even {
    bytes.push(nib[0].to_byte())
  }
  let mut p = if even { 0 } else { 1 }
  while p + 1 < nib.length() {
    bytes.push(((nib[p] << 4) | nib[p + 1]).to_byte())
    p = p + 2
  }
  Some(big_from_be_bytes(Bytes::from_array(bytes[:])))
}

///|
/// ECDSA 验签公开入口（纯加法 API，里程碑 a 的门禁承载点）。
///
/// 各参数为无前缀十六进制字符串。任一畸形/越界输入均值化返回 `false`（fail-closed，
/// 不 panic）。不接入 v2/v3/v3.1 与 v1（里程碑 b/c 留空）。
///
/// # Example
/// ```mbt nocheck
/// test {
///   // P-256 / SHA-256("sample")，RFC 6979 A.2.5 标准向量（真签名验签通过）。
///   assert_true(
///     ecdsa_verify_raw(
///       EcCurve::P256,
///       "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
///       "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
///       "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf",
///       "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
///       "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
///     ),
///   )
/// }
/// ```
pub fn ecdsa_verify_raw(
  curve : EcCurve,
  pubkey_x_hex : String,
  pubkey_y_hex : String,
  msg_hash_hex : String,
  sig_r_hex : String,
  sig_s_hex : String,
) -> Bool {
  let params = match ec_params(curve) {
    Some(p) => p
    None => return false
  }
  let qx = ec_big_from_hex(pubkey_x_hex)
  let qy = ec_big_from_hex(pubkey_y_hex)
  let e = ec_big_from_hex(msg_hash_hex)
  let r = ec_big_from_hex(sig_r_hex)
  let s = ec_big_from_hex(sig_s_hex)
  match (qx, qy, e, r, s) {
    (Some(qx), Some(qy), Some(e), Some(r), Some(s)) =>
      ec_ecdsa_verify(params, qx, qy, e, r, s)
    _ => false
  }
}
