#!/usr/bin/env python3
# tests/fixtures/gen_elf_fixtures.py — W7 轨 A 确定性合成 ELF/APK 生成器。
#
# 纯 Python 手工字节构造**结构完整的 ELF64 动态库镜像**（ELF 头 + PT_DYNAMIC +
# DT_NEEDED/DT_SYMTAB/DT_STRTAB/DT_HASH + 符号表含 Java_* 与 _kDart* marker），
# 不依赖任何工具链、字节确定可复现；输出 .so 与一个打入 lib/arm64-v8a/ 的 APK。
#
# 用法：
#   python tests/fixtures/gen_elf_fixtures.py
# 产出：
#   tests/fixtures/w7-arm64-v8a.so        （合成 ELF64，AArch64）
#   tests/fixtures/w7-libs.apk             （ZIP：classes.dex + lib/arm64-v8a/libnative.so）
#
# 哈希登记：产出后须把 SHA-256 同步进 tests/ASSETS.md。

import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "tests" / "fixtures"


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def u64(v):
    return struct.pack("<Q", v)


def make_elf64_aarch64():
    """手工构造结构完整的 ELF64 动态库（AArch64），含 PT_DYNAMIC 与符号表。"""
    # 布局（文件偏移）：
    #   0x0000 ELF header (64 B)
    #   0x0040 program header table (56 B × 2 = 112 B)
    #   0x00B0 .dynstr（变长，紧随 program headers）
    #   .dynsym（紧随 dynstr，4 × 24 = 96 B）
    #   .hash（紧随 dynsym，nbucket=1, nchain=4）
    #   .dynamic（紧随 hash）
    #
    # 为简化，所有段 vaddr = offset（非 PIE 风格但结构合法）。
    # 各段偏移在构造前先按前置段长度推进，保证紧凑且断言自洽。
    ph_end = 0x0040 + 112  # = 0x00B0
    dynstr = b"\x00libnative.so\x00Java_foo_bar\x00_kDartVmSnapshotInstructions\x00_kDartIsolateSnapshotData\x00"
    dynstr_off = ph_end
    dynstr_len = len(dynstr)

    # 符号表：4 个条目（每个 24 B：st_name u32 + st_info u8 + st_other u8 + st_shndx u16 + st_value u64 + st_size u64）
    # 条目 0：空符号（全 0）
    # 条目 1：Java_foo_bar（st_name=14, defined, SHN_ABS=0xfff1）
    # 条目 2：_kDartVmSnapshotInstructions（st_name=27, defined）
    # 条目 3：_kDartIsolateSnapshotData（st_name=56, defined）
    def sym(name_off, defined, value):
        info = 0x12 if defined else 0x10  # STB_GLOBAL | STT_FUNC
        shndx = 0xFFF1 if defined else 0  # SHN_ABS
        return (
            struct.pack("<IBBH", name_off, info, 0, shndx)
            + u64(value)
            + u64(0)
        )

    dynsym_off = dynstr_off + dynstr_len
    syms = [
        sym(0, False, 0),
        sym(14, True, 0x1000),   # Java_foo_bar（dynstr 偏移 14）
        sym(27, True, 0x2000),   # _kDartVmSnapshotInstructions（dynstr 偏移 27）
        sym(56, True, 0x3000),   # _kDartIsolateSnapshotData（dynstr 偏移 56）
    ]
    dynsym = b"".join(syms)
    dynsym_len = len(dynsym)  # 4 × 24 = 96 B

    # .hash: nbucket=1, nchain=4; bucket[0]=1; chain[0]=0, chain[1]=2, chain[2]=3, chain[3]=0
    hash_off = dynsym_off + dynsym_len
    hash_data = u32(1) + u32(4) + u32(1) + u32(0) + u32(2) + u32(3) + u32(0)
    hash_len = len(hash_data)

    # .dynamic: DT_NULL / DT_NEEDED(1) / DT_STRTAB(off) / DT_SYMTAB(off) / DT_HASH(off) / DT_STRSZ / DT_SYMENT(24) / DT_SONAME(1)
    dynamic_off = hash_off + hash_len
    dynamic_entries = [
        (1, 1),                       # DT_NEEDED -> libnative.so 在 dynstr 的偏移 1
        (4, hash_off),               # DT_HASH
        (5, dynstr_off),             # DT_STRTAB
        (6, dynsym_off),             # DT_SYMTAB
        (10, dynstr_len),            # DT_STRSZ
        (11, 24),                    # DT_SYMENT
        (14, 1),                     # DT_SONAME
        (0, 0),                      # DT_NULL
    ]
    dynamic = b"".join(struct.pack("<Qq", tag, val) for tag, val in dynamic_entries)
    dynamic_len = len(dynamic)

    # ELF header
    eh = b"\x7fELF"
    eh += b"\x02"          # EI_CLASS = ELFCLASS64
    eh += b"\x01"          # EI_DATA = ELFDATA2LSB
    eh += b"\x01"          # EI_VERSION
    eh += b"\x00"          # EI_OSABI
    eh += b"\x00" * 8      # EI_ABIVERSION + padding
    assert len(eh) == 16
    eh += u16(3)           # e_type = ET_DYN
    eh += u16(183)         # e_machine = EM_AARCH64
    eh += u32(1)           # e_version
    eh += u64(0x40)        # e_entry
    eh += u64(0x40)        # e_phoff（紧接 ELF header）
    eh += u64(0)           # e_shoff
    eh += u32(0)           # e_flags
    eh += u16(64)          # e_ehsize
    eh += u16(56)          # e_phentsize
    eh += u16(2)           # e_phnum
    eh += u16(0)           # e_shentsize
    eh += u16(0)           # e_shnum
    eh += u16(0)           # e_shstrndx
    assert len(eh) == 64

    # Program headers：PT_LOAD（覆盖整文件）+ PT_DYNAMIC
    ph_load = struct.pack(
        "<IIQQQQQQ",
        1,          # p_type = PT_LOAD
        5 | 4,      # p_flags = R | X
        0,          # p_offset
        0,          # p_vaddr
        0,          # p_paddr
        dynamic_off + dynamic_len,  # p_filesz（覆盖到 dynamic 末尾）
        dynamic_off + dynamic_len,  # p_memsz
        0x1000,     # p_align
    )
    ph_dyn = struct.pack(
        "<IIQQQQQQ",
        2,          # p_type = PT_DYNAMIC
        4,          # p_flags = R
        dynamic_off,
        dynamic_off,
        dynamic_off,
        dynamic_len,
        dynamic_len,
        8,
    )
    ph = ph_load + ph_dyn
    assert len(ph) == 112

    # 拼装
    blob = bytearray()
    blob += eh
    blob += ph
    assert len(blob) == 0x00B0
    blob += dynstr
    assert len(blob) == dynstr_off + dynstr_len
    # 填充到 0x0100
    while len(blob) < dynsym_off:
        blob += b"\x00"
    blob += dynsym
    assert len(blob) == dynsym_off + dynsym_len
    while len(blob) < hash_off:
        blob += b"\x00"
    blob += hash_data
    assert len(blob) == hash_off + hash_len
    while len(blob) < dynamic_off:
        blob += b"\x00"
    blob += dynamic
    return bytes(blob)


def zypack(entries):
    """最小 ZIP 打包（stored，无压缩）。entries: [(name, bytes)]。"""
    out = bytearray()
    cd = bytearray()
    for name, data in entries:
        name_b = name.encode()
        local_off = len(out)
        out += u32(0x04034B50)
        out += u16(20)
        out += u16(0)
        out += u16(0)  # method=stored
        out += u16(0)
        out += u16(0)
        crc = 0  # 简化：测试断言不依赖 CRC
        out += u32(crc)
        out += u32(len(data))
        out += u32(len(data))
        out += u16(len(name_b))
        out += u16(0)
        out += name_b
        out += data
        cd += u32(0x02014B50)
        cd += u16(20)
        cd += u16(20)
        cd += u16(0)
        cd += u16(0)
        cd += u16(0)
        cd += u16(0)
        cd += u32(crc)
        cd += u32(len(data))
        cd += u32(len(data))
        cd += u16(len(name_b))
        cd += u16(0)
        cd += u16(0)
        cd += u16(0)
        cd += u16(0)
        cd += u32(0)
        cd += u32(local_off)
        cd += name_b
    cd_off = len(out)
    out += cd
    out += u32(0x06054B50)
    out += u16(0)
    out += u16(0)
    out += u16(len(entries))
    out += u16(len(entries))
    out += u32(len(cd))
    out += u32(cd_off)
    out += u16(0)
    return bytes(out)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    elf = make_elf64_aarch64()
    (OUT / "w7-arm64-v8a.so").write_bytes(elf)

    fake_dex = b"dex\n035\x00" + b"\x00" * 32
    apk = zypack(
        [
            ("classes.dex", fake_dex),
            ("lib/arm64-v8a/libnative.so", elf),
        ]
    )
    (OUT / "w7-libs.apk").write_bytes(apk)

    for p in [OUT / "w7-arm64-v8a.so", OUT / "w7-libs.apk"]:
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        print(f"{p.name}  {h}  {p.stat().st_size}")


if __name__ == "__main__":
    main()
