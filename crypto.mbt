///|
/// 纯 MoonBit SHA-256 实现（FIPS 180-4）。
///
/// 用途：APK 签名**摘要**校验（v1 JAR MANIFEST 条目摘要、v2/v3 内容分块摘要）。
/// 本模块**不做 RSA/ECDSA 验签**：没有密码学 stdlib，也没有实现公钥运算；
/// 摘要通过不等于签名有效（边界见 `SignatureInfo` 文档与 `docs/DECISIONS.md` §5）。
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

///|
/// 64 位循环右移（`n` 取 1..63）。
fn rotr64(x : UInt64, n : Int32) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// 大端读取 8 字节为 `UInt64`（SHA-512 消息字）。
fn be_u64(b : Bytes, off : Int32) -> UInt64 {
  (b[off].to_uint64() << 56) |
  (b[off + 1].to_uint64() << 48) |
  (b[off + 2].to_uint64() << 40) |
  (b[off + 3].to_uint64() << 32) |
  (b[off + 4].to_uint64() << 24) |
  (b[off + 5].to_uint64() << 16) |
  (b[off + 6].to_uint64() << 8) |
  b[off + 7].to_uint64()
}

///|
/// SHA-512 初始哈希值（H0..H7）。
let sha512_iv : Array[UInt64] = [
  0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
  0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL,
]

///|
/// SHA-512 轮常量（K0..K79）。
let sha512_k : Array[UInt64] = [
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL,
]

///|
/// 计算 SHA-512 摘要（64 字节）。包内使用；不进入公开 API。
fn sha512(data : Bytes) -> Bytes {
  let h : Array[UInt64] = []
  for x in sha512_iv {
    h.push(x)
  }
  let len = data.length()
  // 填充：0x80 + 若干 0x00 + 16 字节大端位长，总长 128 字节对齐。
  let total = ((len + 16) / 128 + 1) * 128
  let buf : Array[Byte] = []
  for i = 0; i < len; i = i + 1 {
    buf.push(data[i])
  }
  buf.push(b'\x80')
  while buf.length() < total - 16 {
    buf.push(b'\x00')
  }
  let bit_len = len.to_uint64() * 8UL
  for i = 0; i < 16; i = i + 1 {
    let shift = (15 - i) * 8
    if shift >= 64 {
      buf.push(b'\x00')
    } else {
      buf.push(((bit_len >> shift).to_int() & 0xFF).to_byte())
    }
  }
  let padded = Bytes::from_array(buf[:])
  let mut off = 0
  while off < total {
    let w : Array[UInt64] = []
    for i = 0; i < 16; i = i + 1 {
      w.push(be_u64(padded, off + 8 * i))
    }
    for i = 16; i < 80; i = i + 1 {
      let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
      let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
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
    for i = 0; i < 80; i = i + 1 {
      let sigma1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
      let ch = (e & f) ^ ((e ^ 0xFFFFFFFFFFFFFFFFUL) & g)
      let t1 = hh + sigma1 + ch + sha512_k[i] + w[i]
      let sigma0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = sigma0 + maj
      let na = t1 + t2
      let nb = a
      let nc = b
      let nd = c
      let ne = d + t1
      let nf = e
      let ng = f
      let nhh = g
      a = na
      b = nb
      c = nc
      d = nd
      e = ne
      f = nf
      g = ng
      hh = nhh
    }
    h[0] = h[0] + a
    h[1] = h[1] + b
    h[2] = h[2] + c
    h[3] = h[3] + d
    h[4] = h[4] + e
    h[5] = h[5] + f
    h[6] = h[6] + g
    h[7] = h[7] + hh
    off = off + 128
  }
  let out : Array[Byte] = []
  for x in h {
    out.push(((x >> 56) & 0xFF).to_int().to_byte())
    out.push(((x >> 48) & 0xFF).to_int().to_byte())
    out.push(((x >> 40) & 0xFF).to_int().to_byte())
    out.push(((x >> 32) & 0xFF).to_int().to_byte())
    out.push(((x >> 24) & 0xFF).to_int().to_byte())
    out.push(((x >> 16) & 0xFF).to_int().to_byte())
    out.push(((x >> 8) & 0xFF).to_int().to_byte())
    out.push((x & 0xFF).to_int().to_byte())
  }
  Bytes::from_array(out[:])
}
