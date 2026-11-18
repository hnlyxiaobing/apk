import hashlib, struct

BLOCK = 4096
SALT = b"\x00" * 8
CONTENT = b"the quick brown fox jumps over the lazy dog"  # 45 bytes
NAME = b"foo.txt"

def crc32(b):
    return struct.pack("<I", 0xFFFFFFFF & __import__("binascii").crc32(b))

def zero_pad(b, block=BLOCK):
    return b if len(b) == block else b + b"\x00" * (block - len(b))

def u16(v): return struct.pack("<H", v)
def u32(v): return struct.pack("<I", v)
def u64(v): return struct.pack("<Q", v)

def scheme_value_with_verity(verity_digest, sdk_tail=0):
    # digests seq: u32 seq_len(1) { u32 rec_len u32 0x0421 u32 digest_len digest }
    ds = u32(len(verity_digest) + 8) + u32(0x0421) + u32(len(verity_digest)) + verity_digest
    cert = b"cert"
    cs = u32(len(cert)) + cert
    sd = u32(1) + ds + u32(len(cs)) + cs + b"\x00" * sdk_tail + u32(0)
    signer = u32(len(sd)) + sd + u32(0) + u32(0)
    value = u32(len(signer) + 4) + u32(len(signer)) + signer
    return value

def sig_block(pairs):
    pb = b"".join(u64(len(v) + 4) + u32(id) + v for id, v in pairs)
    out = u64(len(pb) + 24) + pb + u64(len(pb) + 24) + b"APK Sig Block 42"
    return out

def build_apk_with_verity(verity_digest):
    # entry region: local header + name + content
    local = u32(0x04034b50) + u16(20) + u16(0)*3 + crc32(CONTENT) + u32(len(CONTENT))*2 + u16(len(NAME)) + u16(0) + NAME
    out = local + CONTENT
    sb_off = len(out)
    sb = sig_block([(0x7109871a, scheme_value_with_verity(verity_digest))])
    out += sb
    cd_off = len(out)
    cd = (u32(0x02014b50) + u16(20) + u16(20) + u16(0)*4 + crc32(CONTENT) +
          u32(len(CONTENT))*2 + u16(len(NAME)) + u16(0)*4 + u32(0) + u32(0) + NAME)
    out += cd
    eocd = u32(0x06054b50) + u16(0)*4 + u32(len(cd)) + u32(cd_off) + u16(0)
    out += eocd
    return out, sb_off

def fs_verity_source(apk, sb_off):
    # replicate Apk::verity_source_bytes
    # find eocd (comment len 0 -> at end-22)
    eocd = len(apk) - 22
    cd_off = struct.unpack("<I", apk[eocd+16:eocd+20])[0]
    cd_size = struct.unpack("<I", apk[eocd+12:eocd+16])[0]
    eocd_len = 22
    src = apk[:sb_off] + apk[cd_off:cd_off+cd_size]
    eocd_copy = bytearray(apk[eocd:eocd+eocd_len])
    struct.pack_into("<I", eocd_copy, 16, sb_off)
    return src + bytes(eocd_copy)

def verity_root(source):
    level = []
    off = 0
    n = len(source)
    while off < n:
        take = BLOCK if n-off > BLOCK else n-off
        level.append(hashlib.sha256(SALT + zero_pad(source[off:off+take])).digest())
        off += BLOCK
    while len(level)*32 > BLOCK:
        concat = b"".join(level)
        m = len(concat); nxt=[]; o=0
        while o < m:
            take = BLOCK if m-o > BLOCK else m-o
            nxt.append(hashlib.sha256(SALT + zero_pad(concat[o:o+take])).digest())
            o += BLOCK
        level = nxt
    return hashlib.sha256(SALT + zero_pad(b"".join(level))).digest()

def main():
    placeholder = b"\x00" * 40
    apk1, sb1 = build_apk_with_verity(placeholder)
    src = fs_verity_source(apk1, sb1)
    source_len = len(src)
    root = verity_root(src)
    digest = root + struct.pack("<Q", source_len)
    apk2, sb2 = build_apk_with_verity(digest)
    assert sb2 == sb1, "sb offset unchanged"
    # verify the declared root equals recomputed root over apk2's source
    src2 = fs_verity_source(apk2, sb2)
    assert src2 == src, "source unchanged after embedding real root"
    root2 = verity_root(src2)
    assert root2 == root, "root must be stable"
    print("sb_off:", sb1)
    print("source_len:", source_len)
    print("root:", root.hex())
    print("verity digest (40B):", digest.hex())
    print("END-TO-END fs-verity source+root is self-consistent (tree_recomputed_ok == true)")

main()
