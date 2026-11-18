#!/usr/bin/env python3
# tests/fixtures/gen_w6_fixtures.py — W6 inline fixture 确定性生成器。
#
# 目的：把 `verify_wbtest.mbt` 中 11 个内嵌（inline）签名样本的生成过程固化为脚本，
# 使样本可复现、可审计，闭合 tests/ASSETS.md 的「哈希 + 来源口径」账本约定。
#
# 依赖：Python 标准库 + `cryptography`（不引入第三方 APK / Android 工具链）。
#
# 口径：
#   - 所有样本由本脚本确定性合成。RSA 私钥为**仅测试用**的固定内嵌密钥（见
#     TEST_KEY_PEM），证书由该密钥自签（固定序列号 / 固定有效期 / PKCS#1 v1.5）。
#   - PKCS#1 v1.5 签名天然确定；RSA-PSS 的 salt 在标准库 API 中随机，故此处按
#     RFC 8017 §9.1.1 手工编码 EMSA-PSS（固定 salt = 0x5a * hLen），再 `pow(m, d, n)`。
#     这与本库 `rsa_verify_pss`（salt 长度 = hLen，Android 口径）一致。
#   - v2/v3/v3.1 容器为最小伪 APK：8 字节前缀 + APK Signing Block + 仅含 EOCD 的
#     空中央目录。内容摘要按 AOSP 分块口径（0xa5 || chunk_len || chunk，外层
#     0x5a || count || digests，EOCD 中央目录偏移改写为签名块起始偏移）。
#   - v1 为真实 ZIP（stored）：AndroidManifest.xml + MANIFEST.MF + TEST.SF + TEST.RSA。
#
# 用法：
#   python tests/fixtures/gen_w6_fixtures.py --check verify_wbtest.mbt
#       校验 inline 十六进制与生成结果逐字节一致（不一致退出码 1）。
#   python tests/fixtures/gen_w6_fixtures.py --emit-hex
#       打印 JSON: {名称: 十六进制}，供人工更新 inline。
#   python tests/fixtures/gen_w6_fixtures.py --out DIR
#       将 11 个 .apk 写到 DIR（默认不写文件，避免二进制入库）。
#   python tests/fixtures/gen_w6_fixtures.py --sha256
#       打印每个样本的 SHA-256（登记 tests/ASSETS.md 用）。

import argparse
import base64
import datetime
import hashlib
import json
import re
import struct
import sys
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# 固定测试密钥（仅用于合成 fixture，绝不可用于任何真实用途）。
# ---------------------------------------------------------------------------

TEST_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC1KPu1gixt0aQ0
osLNfvHX/RazMh+vJuTR+2OrFJyWDbZZKQTeIM7pM2FxBnhUQpeAjIPK5svNeX2g
TgEoTM9sKYmfJx8uEk4zo+jYAl7MW5OCnySV1WCKXQw2AM46gPkmr9JySF/Jtu0L
G5EfRmZY10uwANDJzq2hz3mKps5ahw0Gv9e4og2iT7THnIBJHbN1zmRO+XLE4JSi
Po1iC5JCoStm557JHNf/Pc0cfoGRDjLEd6iHtWiMPBa1XYr831YmzDISINjUM+7x
IDmx695A8nc98FF5m+upMeNUQuUNYyyG3fButvsqMBgU3RrdnMRtVISA5VqOYBgO
G63Oiw5ZAgMBAAECggEAQ6Nin3lTx0jvqytd2kXcXA1FrXA4fjfiVTgsFVMjx66k
95MmGx1aw50Ic5+7y5H1aOyNxHL5guUqb3DQY9CR3UuA86gyrwvsoMFBDW2NIXXL
lIiAq2S4n9Bv37XbSeKfo78frsWw5epjhLMtMuUhD2iK/NLBIagGEhUZxxfSkd+b
klQ/YSG4mzNUbRvc8250A+a56AEBf1XRXyQ07c2knQouSHoFpfd7zD0xxLSP4aKU
B+o0mcia4JvDQcqowdFuxabf9dngE41aA7QKLA/AoUleLYICqeaoA5BdOJ3x4U13
OcyUUce4FuS7808PL0GaqBlh4VcrwzkK8pk1lMXFRQKBgQDh0b2yEwDO1d3uX9xg
8W8R8L+AO5Imh2DPPcpeNtRH5Ee2Wn1XFQhYpkYhuRZLnGRBrzKKS+qIydksrS12
8uZ60jEFEhRaxcCqY8wFyigp10FJQ5r8qoWm7O792qnMVS43rJKoLJAY81nhARNQ
wiPEBS33jUUNpdPYouB6VPEXjwKBgQDNX0G38lknJPSZNuDhBsYKa7NRMGfbhvYk
xuBXiC1g4Ego6Ha6lCXjW9g6/mbAGMZMPuWNAfSHFvzV8v4CxXP6/P/OMccGJ6uR
y0Zvj1FTFRrn6efaVCRiBv0trMm1k7YF91Qp10pXaoBFCI/q9JOLjrQVbHmGv/eJ
Nm/wcZrHlwKBgQDLkhC4H3ly/El9Qt2gZwYB3k5Eg29VXGVhbgqotDTaOmiLczfa
8RL9F6fRbtEyiGG49P9SvO1JMu2c4OFDgeVUg3e9YncG/Y6aDC04au2aCnrIWTG2
5OJngOBR6HV5xrBLcD8lbEbat0YnGJkZDGrBowm1SJ0fmIZJnUtP/JL68QKBgDo/
tkgR+K9dj/KU2ht47FqwSV/RtuNQ2Cd+MMsi2JwNgOn5ZRNuSYC+4Al7dnEtlbCy
djEUSOK35mZYUStADbE2aOd2vthEECl92jByGcLSzZrRgO0vyFH1YYG+7EcP6iSv
DbQAWBmLH251Czy8ucxvYSxiY+WQNQk5423zCs9pAoGBAIXonmO0BY/3w39PHRSc
WR27c3aUv6rhuAmZW1pjLNDbw0RocRZb0S72/TaNGrypeC5DZ1wRiFmuFn3uXeRQ
7j29wew/+HDeV1gravrt9bOO5Y6zjVXIPrdrIkPz9jGHs5iAmGYc0IQHaa0SMxWU
2c+UU52vmf4XM2YTsZIab2+r
-----END PRIVATE KEY-----
"""

SUBJECT_CN = "w6 fixture"
CERT_SERIAL = 0x40E75D63F15B770A0AECD6C4A99D8F3C487821E4
NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)

# 签名方案 ID（Android 口径）
SIG_ID_V2 = 0x7109871A
SIG_ID_V3 = 0xF05368C0
SIG_ID_V31 = 0x1B93AD61

# 内容摘要 / 签名算法 ID
ALG_PSS_SHA256 = 0x0101
ALG_PSS_SHA512 = 0x0102
ALG_PKCS1_SHA256 = 0x0103
ALG_PKCS1_SHA512 = 0x0104
ALG_ECDSA_SHA256 = 0x0201

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


# ---------------------------------------------------------------------------
# DER 基元
# ---------------------------------------------------------------------------

OID_SIGNED_DATA = bytes.fromhex("2a864886f70d010702")
OID_DATA = bytes.fromhex("2a864886f70d010701")
OID_CONTENT_TYPE = bytes.fromhex("2a864886f70d010903")
OID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")
OID_SIGNING_TIME = bytes.fromhex("2a864886f70d010905")
OID_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")
OID_SHA256 = bytes.fromhex("608648016503040201")
OID_SHA512 = bytes.fromhex("608648016503040203")
OID_CN = bytes.fromhex("550403")


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def der_seq(*items: bytes) -> bytes:
    return der_tlv(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return der_tlv(0x31, b"".join(items))


def der_oid(content: bytes) -> bytes:
    return der_tlv(0x06, content)


def der_int(v: int) -> bytes:
    body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return der_tlv(0x02, body)


def der_octets(data: bytes) -> bytes:
    return der_tlv(0x04, data)


def alg_id(oid: bytes) -> bytes:
    return der_seq(der_oid(oid), der_tlv(0x05, b""))


def name_der() -> bytes:
    atv = der_seq(der_oid(OID_CN), der_tlv(0x0C, SUBJECT_CN.encode()))
    return der_seq(der_set(atv))


# ---------------------------------------------------------------------------
# 密钥 / 证书
# ---------------------------------------------------------------------------

_KEY = serialization.load_pem_private_key(TEST_KEY_PEM, password=None)
_KEY_NUMBERS = _KEY.private_numbers()


def make_cert_der() -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SUBJECT_CN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_KEY.public_key())
        .serial_number(CERT_SERIAL)
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(_KEY, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


CERT_DER = make_cert_der()
SPKI_DER = _KEY.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
MODULUS_BYTES = (_KEY_NUMBERS.public_numbers.n.bit_length() + 7) // 8


def sign_pkcs1(msg: bytes, hash_alg) -> bytes:
    return _KEY.sign(msg, padding.PKCS1v15(), hash_alg())


def mgf1(seed: bytes, length: int, hash_alg) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        h = hashlib.new(hash_alg().name)
        h.update(seed + counter.to_bytes(4, "big"))
        out += h.digest()
        counter += 1
    return out[:length]


def sign_pss(msg: bytes, hash_alg) -> bytes:
    """RFC 8017 §9.1.1，salt 长度 = hLen，固定 salt = 0x5a*hLen（确定性）。"""
    n = _KEY_NUMBERS.public_numbers.n
    d = _KEY_NUMBERS.d
    k = (n.bit_length() + 7) // 8
    em_bits = n.bit_length() - 1
    em_len = (em_bits + 7) // 8
    h = hashlib.new(hash_alg().name)
    h.update(msg)
    m_hash = h.digest()
    h_len = len(m_hash)
    salt = b"\x5a" * h_len
    hh = hashlib.new(hash_alg().name)
    hh.update(b"\x00" * 8 + m_hash + salt)
    h_val = hh.digest()
    ps = b"\x00" * (em_len - h_len - h_len - 2)
    db = ps + b"\x01" + salt
    db_mask = mgf1(h_val, em_len - h_len - 1, hash_alg)
    masked = bytes(a ^ b for a, b in zip(db, db_mask))
    unused = 8 * em_len - em_bits
    if unused:
        masked = bytes([masked[0] & (0xFF >> unused)]) + masked[1:]
    em = masked + h_val + b"\xBC"
    s = pow(int.from_bytes(em, "big"), d, n)
    return s.to_bytes(k, "big")


# ---------------------------------------------------------------------------
# v2 / v3 / v3.1 容器
# ---------------------------------------------------------------------------

PREFIX = bytes(range(8))  # 伪 APK 前 8 字节（内容摘要覆盖对象）


def chunk_digest(chunk: bytes, hash_alg) -> bytes:
    h = hashlib.new(hash_alg().name)
    h.update(b"\xa5" + struct.pack("<I", len(chunk)) + chunk)
    return h.digest()


def content_digest(hash_alg, signing_block_off: int = 8) -> bytes:
    """AOSP 内容摘要：prefix 分块 + 空中央目录 + EOCD（cd_off 改写为块起始偏移）。"""
    eocd = bytearray(22)
    eocd[0:4] = b"PK\x05\x06"
    # cd_size = 0, 条目数 = 0
    struct.pack_into("<I", eocd, 16, signing_block_off)
    outer = (
        b"\x5a"
        + struct.pack("<I", 2)
        + chunk_digest(PREFIX, hash_alg)
        + chunk_digest(bytes(eocd), hash_alg)
    )
    h = hashlib.new(hash_alg().name)
    h.update(outer)
    return h.digest()


def u32(v: int) -> bytes:
    return struct.pack("<I", v)


def build_signed_data(digest: bytes, digest_alg_id: int) -> bytes:
    rec = u32(digest_alg_id) + u32(len(digest)) + digest
    digests = u32(len(rec)) + rec
    certs = u32(len(CERT_DER)) + CERT_DER
    return u32(len(digests)) + digests + u32(len(certs)) + certs + u32(0)


def build_value(
    sig_alg_id: int,
    signature: bytes,
    hash_alg,
    sdk: tuple[int, int] | None = None,
) -> bytes:
    # 内容摘要算法 ID：SHA-512 系列（0x0102/0x0105）用 0x0102，其余 SHA-256 用 0x0103。
    digest_alg_id = ALG_PSS_SHA512 if hash_alg is hashes.SHA512 else ALG_PKCS1_SHA256
    signed_data = build_signed_data(content_digest(hash_alg), digest_alg_id)
    sig_rec = u32(sig_alg_id) + u32(len(signature)) + signature
    sigs = u32(len(sig_rec)) + sig_rec
    signer = (
        u32(len(signed_data))
        + signed_data
        + (u32(sdk[0]) + u32(sdk[1]) if sdk is not None else b"")
        + u32(len(sigs))
        + sigs
        + u32(len(SPKI_DER))
        + SPKI_DER
    )
    # value = 序列长度 + { signer 长度 + signer }（当前仅 1 个 signer）。
    seq = u32(len(signer)) + signer
    return u32(len(seq)) + seq


def build_apk(scheme_id: int, value: bytes) -> bytes:
    pair = struct.pack("<Q", len(value) + 4) + u32(scheme_id) + value
    block_size = len(pair) + 24
    block = (
        struct.pack("<Q", block_size)
        + pair
        + struct.pack("<Q", block_size)
        + APK_SIG_BLOCK_MAGIC
    )
    eocd = bytearray(22)
    eocd[0:4] = b"PK\x05\x06"
    struct.pack_into("<I", eocd, 16, len(PREFIX) + len(block))
    return PREFIX + block + bytes(eocd)


def make_v2(sig_alg_id: int, tamper: bool = False, hash_alg=hashes.SHA256, pss=False) -> bytes:
    # 先构造一次 signed_data 取签名对象（内容摘要与块长度无关，确定性成立）。
    provisional = build_value(sig_alg_id, b"\x00" * MODULUS_BYTES, hash_alg)
    signed_data = extract_signed_data(provisional)
    signature = sign_pss(signed_data, hash_alg) if pss else sign_pkcs1(signed_data, hash_alg)
    if tamper:
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
    value = build_value(sig_alg_id, signature, hash_alg)
    assert extract_signed_data(value) == signed_data, "signed_data must be stable"
    return build_apk(SIG_ID_V2, value)


def extract_signed_data(value: bytes) -> bytes:
    """取 signer 的 signed_data 内容字节（不含长度前缀）。"""
    seq_len = struct.unpack_from("<I", value, 0)[0]
    seq = value[4 : 4 + seq_len]
    signer_len = struct.unpack_from("<I", seq, 0)[0]
    signer = seq[4 : 4 + signer_len]
    sd_len = struct.unpack_from("<I", signer, 0)[0]
    return signer[4 : 4 + sd_len]


def make_v3(scheme_id: int) -> bytes:
    provisional = build_value(ALG_PKCS1_SHA256, b"\x00" * MODULUS_BYTES, hashes.SHA256, sdk=(24, 34))
    signed_data = extract_signed_data(provisional)
    signature = sign_pkcs1(signed_data, hashes.SHA256)
    value = build_value(ALG_PKCS1_SHA256, signature, hashes.SHA256, sdk=(24, 34))
    assert extract_signed_data(value) == signed_data
    return build_apk(scheme_id, value)


def make_ecdsa() -> bytes:
    fake_sig = hashlib.sha512(b"w6 ecdsa placeholder").digest() * 2  # 128 字节
    value = build_value(ALG_ECDSA_SHA256, fake_sig, hashes.SHA256)
    return build_apk(SIG_ID_V2, value)


# ---------------------------------------------------------------------------
# v1（JAR 签名）
# ---------------------------------------------------------------------------

MANIFEST_XML = bytes.fromhex("03000800") + b"\x00" * 16
DOS_TIME = 0x7C51
DOS_DATE = 0x5D72


def zip_build(entries) -> bytes:
    out = bytearray()
    cd = bytearray()
    for name, data in entries:
        nb = name.encode()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        off = len(out)
        out += struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, 0, 0, DOS_TIME, DOS_DATE, crc, len(data), len(data), len(nb), 0,
        )
        out += nb + data
        cd += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, 0, 0, DOS_TIME, DOS_DATE, crc, len(data), len(data),
            len(nb), 0, 0, 0, 0, 0, off,
        )
        cd += nb
    cd_off = len(out)
    out += cd
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(cd), cd_off, 0)
    return bytes(out)


def build_manifest_xml_digest_b64() -> str:
    return base64.b64encode(hashlib.sha256(MANIFEST_XML).digest()).decode()


def build_manifest_mf(b64: str, with_created_by: bool) -> bytes:
    lines = ["Manifest-Version: 1.0\r\n"]
    if with_created_by:
        lines.append("Created-By: fixture\r\n")
    lines.append("\r\n")
    lines.append("Name: AndroidManifest.xml\r\n")
    lines.append("SHA-256-Digest: " + b64 + "\r\n")
    lines.append("\r\n")
    return "".join(lines).encode()


def build_sf(manifest_bytes: bytes, with_created_by: bool) -> bytes:
    b64 = base64.b64encode(hashlib.sha256(manifest_bytes).digest()).decode()
    lines = ["Signature-Version: 1.0\r\n"]
    if with_created_by:
        lines.append("Created-By: fixture\r\n")
    lines.append("SHA-256-Digest-Manifest: " + b64 + "\r\n")
    lines.append("\r\n")
    return "".join(lines).encode()


def build_signing_time() -> bytes:
    # UTCTime 固定值（2026-11-18 07:34:34Z），保证确定性。
    return der_tlv(0x17, b"261118073434Z")


def build_cms(sf_bytes: bytes, with_attrs: bool, tamper: bool) -> bytes:
    attrs = []
    if with_attrs:
        attrs.append(
            der_seq(
                der_oid(OID_CONTENT_TYPE),
                der_set(der_oid(OID_DATA)),
            )
        )
        attrs.append(
            der_seq(
                der_oid(OID_MESSAGE_DIGEST),
                der_set(der_octets(hashlib.sha256(sf_bytes).digest())),
            )
        )
        attrs.append(
            der_seq(
                der_oid(OID_SIGNING_TIME),
                der_set(build_signing_time()),
            )
        )
        attrs.sort()  # DER SET OF 按编码字节排序
        attrs_body = b"".join(attrs)
        signed_attrs = der_tlv(0xA0, attrs_body)
        to_sign = der_tlv(0x31, attrs_body)
    else:
        signed_attrs = b""
        to_sign = sf_bytes
    signature = sign_pkcs1(to_sign, hashes.SHA256)
    if tamper:
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])

    signer_info = der_seq(
        der_int(1),
        der_seq(name_der(), der_int(CERT_SERIAL)),
        alg_id(OID_SHA256),
        signed_attrs,
        alg_id(OID_RSA_ENCRYPTION),
        der_octets(signature),
    )
    encap = der_seq(
        der_oid(OID_DATA),
        der_tlv(0xA0, der_octets(sf_bytes)),
    )
    signed_data = der_seq(
        der_int(1),
        der_set(alg_id(OID_SHA256)),
        encap,
        der_tlv(0xA0, CERT_DER),
        der_set(signer_info),
    )
    return der_seq(der_oid(OID_SIGNED_DATA), der_tlv(0xA0, signed_data))


def make_v1(with_attrs: bool, tamper: bool = False) -> bytes:
    manifest = build_manifest_mf(build_manifest_xml_digest_b64(), with_created_by=with_attrs)
    sf = build_sf(manifest, with_created_by=with_attrs)
    cms = build_cms(sf, with_attrs=with_attrs, tamper=tamper)
    return zip_build(
        [
            ("AndroidManifest.xml", MANIFEST_XML),
            ("META-INF/MANIFEST.MF", manifest),
            ("META-INF/TEST.SF", sf),
            ("META-INF/TEST.RSA", cms),
        ]
    )


# ---------------------------------------------------------------------------
# 全部样本
# ---------------------------------------------------------------------------


def generate() -> dict[str, bytes]:
    return {
        "fixture_apk_v2_ok": make_v2(ALG_PKCS1_SHA256),
        "fixture_apk_v2_bad": make_v2(ALG_PKCS1_SHA256, tamper=True),
        "fixture_apk_v2_pss256": make_v2(ALG_PSS_SHA256, hash_alg=hashes.SHA256, pss=True),
        "fixture_apk_v2_pss512": make_v2(ALG_PSS_SHA512, hash_alg=hashes.SHA512, pss=True),
        "fixture_apk_v2_sha512": make_v2(ALG_PKCS1_SHA512, hash_alg=hashes.SHA512),
        "fixture_apk_v3_ok": make_v3(SIG_ID_V3),
        "fixture_apk_v31_ok": make_v3(SIG_ID_V31),
        "fixture_apk_ecdsa": make_ecdsa(),
        "fixture_apk_v1_ok": make_v1(with_attrs=True),
        "fixture_apk_v1_bad": make_v1(with_attrs=True, tamper=True),
        "fixture_apk_v1_noattr": make_v1(with_attrs=False),
    }


# ---------------------------------------------------------------------------
# inline 校验 / 输出
# ---------------------------------------------------------------------------

INLINE_RE = re.compile(
    r'fn\s+(fixture_apk_[a-z0-9_]+)\s*\(\s*\)\s*->\s*Bytes\s*\{\s*bytes_from_hex\(\s*"([0-9a-fA-F]+)"',
    re.S,
)


def check_inline(path: Path, fixtures: dict[str, bytes]) -> int:
    text = path.read_text(encoding="utf-8")
    found = {m.group(1): bytes.fromhex(m.group(2)) for m in INLINE_RE.finditer(text)}
    bad = 0
    for name, data in fixtures.items():
        if name not in found:
            print(f"MISSING inline: {name}")
            bad += 1
        elif found[name] != data:
            print(
                f"MISMATCH inline: {name} "
                f"(inline {len(found[name])} B, generated {len(data)} B)"
            )
            bad += 1
        else:
            print(f"OK inline: {name} ({len(data)} B)")
    extra = set(found) - set(fixtures)
    for name in sorted(extra):
        print(f"EXTRA inline (not generated): {name}")
        bad += 1
    return 0 if bad == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="校验该 .mbt 中的 inline 十六进制")
    parser.add_argument("--emit-hex", action="store_true", help="输出 JSON 十六进制")
    parser.add_argument("--out", type=Path, help="将样本写入该目录")
    parser.add_argument("--sha256", action="store_true", help="输出 SHA-256 表")
    args = parser.parse_args()

    fixtures = generate()

    if args.check:
        return check_inline(args.check, fixtures)
    if args.emit_hex:
        print(json.dumps({k: v.hex() for k, v in fixtures.items()}, indent=2))
        return 0
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, data in fixtures.items():
            (args.out / f"{name}.apk").write_bytes(data)
            print(f"wrote {args.out / (name + '.apk')}")
        return 0
    if args.sha256:
        for name, data in fixtures.items():
            print(f"| `{name}` (inline) | `{hashlib.sha256(data).hexdigest()}` | {len(data)} |")
        return 0

    # 默认：自检，输出概要。
    for name, data in fixtures.items():
        print(f"{name}: {len(data)} B sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
