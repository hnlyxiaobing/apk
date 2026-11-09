///|
/// 纯 MoonBit SHA-256 实现（FIPS 180-4）。
///
/// 用途：APK 签名**摘要**校验（v1 JAR MANIFEST 条目摘要、v2/v3 内容分块摘要）。
/// 本模块**不做 RSA/ECDSA 验签**：没有密码学 stdlib，也没有实现公钥运算；
/// 摘要通过不等于签名有效（边界见 `SignatureInfo` 文档与 `DECISIONS.md` §5）。
///
/// 实现约束：纯值、无外部依赖、无全局状态；输入只读；输出 32 字节。
/// 性能按测试/分析工具口径实现（逐块处理，不做 SIMD），APK 级输入可接受。

///|
/// SHA-256 初始哈希值（H0..H7）。
let sha256_iv : Array[UInt32] = [
  0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU,
  0x5be0cd19U,
]

///|
/// SHA-256 轮常量（K0..K63）。
let sha256_k : Array[UInt32] = [
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
  0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
  0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
  0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
  0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
  0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
  0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
  0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
  0xc67178f2U,
]

///|
/// 32 位循环右移（`n` 取 1..31）。
fn rotr32(x : UInt32, n : Int32) -> UInt32 {
  (x >> n) | (x << (32 - n))
}

///|
/// 大端读取 4 字节为 `UInt`（块内消息字）。
fn be_u32(b : Bytes, off : Int32) -> UInt32 {
  (b[off].to_uint() << 24) |
  (b[off + 1].to_uint() << 16) |
  (b[off + 2].to_uint() << 8) |
  b[off + 3].to_uint()
}

///|
/// 计算 SHA-256 摘要（32 字节）。包内使用；不进入公开 API。
fn sha256(data : Bytes) -> Bytes {
  let h : Array[UInt32] = []
  for x in sha256_iv {
    h.push(x)
  }
  let len = data.length()
  // 填充：0x80 + 若干 0x00 + 8 字节大端位长，总长 64 字节对齐。
  let total = ((len + 8) / 64 + 1) * 64
  let buf : Array[Byte] = []
  for i = 0; i < len; i = i + 1 {
    buf.push(data[i])
  }
  buf.push(b'\x80')
  while buf.length() < total - 8 {
    buf.push(b'\x00')
  }
  let bit_len = len.to_uint64() * 8UL
  for i = 0; i < 8; i = i + 1 {
    let shift = (7 - i) * 8
    buf.push(((bit_len >> shift).to_int() & 0xFF).to_byte())
  }
  let padded = Bytes::from_array(buf[:])
  let mut off = 0
  while off < total {
    let w : Array[UInt32] = []
    for i = 0; i < 16; i = i + 1 {
      w.push(be_u32(padded, off + 4 * i))
    }
    for i = 16; i < 64; i = i + 1 {
      let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
      let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
      w.push(w[i - 16] + s0 + w[i - 7] + s1)
    }
    let mut a = h[0]
    let mut b = h[1]
    let mut c = h[2]
    let mut d = h[3]
    let mut e = h[4]
    let mut f = h[5]
    let mut g = h[6]
    let mut hh = h[7]
    for i = 0; i < 64; i = i + 1 {
      let s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
      let ch = (e & f) ^ ((e ^ 0xFFFFFFFFU) & g)
      let t1 = hh + s1 + ch + sha256_k[i] + w[i]
      let s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = s0 + maj
      hh = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
    }
    h[0] = h[0] + a
    h[1] = h[1] + b
    h[2] = h[2] + c
    h[3] = h[3] + d
    h[4] = h[4] + e
    h[5] = h[5] + f
    h[6] = h[6] + g
    h[7] = h[7] + hh
    off = off + 64
  }
  let out : Array[Byte] = []
  for x in h {
    out.push(((x >> 24) & 0xFF).reinterpret_as_int().to_byte())
    out.push(((x >> 16) & 0xFF).reinterpret_as_int().to_byte())
    out.push(((x >> 8) & 0xFF).reinterpret_as_int().to_byte())
    out.push((x & 0xFF).reinterpret_as_int().to_byte())
  }
  Bytes::from_array(out[:])
}
