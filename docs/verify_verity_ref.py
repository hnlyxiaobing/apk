import hashlib

BLOCK = 4096
SALT = b"\x00" * 8

def zero_pad(b, block=BLOCK):
    if len(b) == block:
        return b
    return b + b"\x00" * (block - len(b))

def concat_salt(data):
    return SALT + data

# MoonBit verity_root implementation (translated 1:1)
def verity_root(source):
    level = []
    n = len(source)
    off = 0
    while off < n:
        take = BLOCK if (n - off > BLOCK) else (n - off)
        block = zero_pad(source[off:off+take])
        level.append(hashlib.sha256(concat_salt(block)).digest())
        off += BLOCK
    while len(level) * 32 > BLOCK:
        concat = b"".join(level)
        m = len(concat)
        nxt = []
        o = 0
        while o < m:
            take = BLOCK if (m - o > BLOCK) else (m - o)
            block = zero_pad(concat[o:o+take])
            nxt.append(hashlib.sha256(concat_salt(block)).digest())
            o += BLOCK
        level = nxt
    top = zero_pad(b"".join(level))
    return hashlib.sha256(concat_salt(top)).digest()

# Independent re-derivation of AOSP calculateVerityLevelOffset to confirm level sizes
def level_sizes(file_size):
    sizes = []
    s = file_size
    while True:
        level_digest = ((s + BLOCK - 1) // BLOCK) * 32
        sizes.append(level_digest)
        if level_digest <= BLOCK:
            break
        s = level_digest
    return sizes

def main():
    # Case 1: single block (<4096). The leaf level (1 digest, 32 bytes) is the top
    # level, so root = sha256(salt || zero_pad(leaf_digest)).
    src1 = b"the quick brown fox jumps over the lazy dog"
    leaf = hashlib.sha256(SALT + zero_pad(src1)).digest()
    r1 = verity_root(src1)
    exp1 = hashlib.sha256(SALT + zero_pad(leaf)).digest()
    assert r1 == exp1, "single-block mismatch"
    print("case1 single-block OK:", r1.hex())

    # Case 2: multi-block (9000 bytes)
    src2 = bytes(i % 251 for i in range(9000))
    r2 = verity_root(src2)
    sizes = level_sizes(len(src2))
    print("case2 9000 bytes root:", r2.hex())
    print("level sizes:", sizes, "num levels:", len(sizes))
    # leaf should have ceil(9000/4096)=3 digests=96 bytes; that's <=4096 so top=leaf
    assert sizes == [96], f"expected [96], got {sizes}"

    # Case 3: enough to force an internal layer (>4096*128 source bytes)
    src3 = bytes(i % 251 for i in range(4096 * 200))  # 200 blocks -> 6400 digest bytes
    sizes3 = level_sizes(len(src3))
    print("case3 level sizes:", sizes3)
    assert len(sizes3) >= 2, "should have an internal layer"
    r3 = verity_root(src3)
    print("case3 root:", r3.hex())

    print("ALL PYTHON REFERENCE CHECKS PASSED")

main()
