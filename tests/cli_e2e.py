#!/usr/bin/env python3
# tests/cli_e2e.py — L4 CLI 端到端场景 E2E（收口轮 P1）。
#
# 仅用 Python 标准库；驱动已构建的 native 二进制（`moon build --target native` 产物），
# 对受控 fixture 与临时构造的恶意 APK 执行命令序列，断言：
#   - 退出码矩阵（0=成功 / 1=解析或IO错误 / 2=用法错误）
#   - stdout 记录行前缀（ENTR| DEX| MANI| ARSC| LIB| EXTR| VERIFY| CERT|）
#   - stdout 单行 JSON 字段契约（list / extract / certs / verify）
#   - extract 落盘文件哈希与 zipfile 独立引用一致（A1 寻址忠实）
#   - 恶意条目名（../、绝对路径、大小写冲突、互为目录前缀）写盘前整体拒绝
#   - 任意失败路径不 panic（stdout/stderr 无 panic/backtrace 标记）
#
# 退出码：0 = 全部断言 PASS（无 FAIL）；1 = 存在 FAIL；78 = 平台能力缺失（SKIPPED，不计通过）。
# 用法：
#   python tests/cli_e2e.py
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIX = REPO / "tests" / "fixtures"

# 计数（纪律：SKIPPED 单列，不计通过）
PASS = 0
FAIL = 0
SKIPPED = []
FAIL_DETAILS = []


def record(ok, name, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAIL_DETAILS.append((name, detail))


def find_binary() -> Path | None:
    """定位 native 二进制；Windows 与 posix 均尝试。"""
    cands = []
    for prof in ("debug", "release"):
        for name in ("main.exe", "main"):
            cands.append(
                REPO / "_build" / "native" / prof / "build" / "cmd" / "main" / name
            )
    for c in cands:
        if c.is_file():
            return c
    return None


def run_cli(binary: Path, args: list[str]) -> subprocess.CompletedProcess:
    """运行 CLI，cwd=repo 根；强制按 UTF-8 解码 stdout/stderr（CLI 输出中文，
    text=True 在 GBK 本机编码下会解码失败）。"""
    return subprocess.run(
        [str(binary), *args],
        cwd=str(REPO),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


def assert_no_panic(res: subprocess.CompletedProcess, name: str):
    """失败路径也绝不允许 panic（A4）。"""
    blob = (res.stdout or "") + (res.stderr or "")
    panic = any(k in blob for k in ("panic", "backtrace", "stack trace", "unhandled"))
    record(not panic, f"{name} [no-panic]", f"panic marker found: {blob[:200]!r}")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def zip_ref(path: Path) -> dict[str, bytes]:
    """以 zipfile 为独立引用，返回 {entry_name: raw_bytes}（A1 黄金基准）。"""
    out = {}
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            if not i.filename.endswith("/"):
                out[i.filename] = z.read(i.filename)
    return out


def build_malicious_apk(tmp: Path, name: str, entries: dict[str, bytes]) -> Path:
    p = tmp / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in entries.items():
            z.writestr(n, b)
    return p


def main() -> int:
    binary = find_binary()
    if binary is None:
        # 平台缺失（无 moon / 无 native 工具链）→ 显式 SKIPPED，不计通过。
        SKIPPED.append(
            "native 二进制不存在：先 `moon build --target native`；本断言组 SKIPPED（exit 78）"
        )
        print("SKIPPED: " + SKIPPED[-1])
        return 78

    tmp = Path(tempfile.mkdtemp(prefix="cli_e2e_"))
    try:
        return run_all(binary, tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_all(binary: Path, tmp: Path) -> int:
    # ---------- 引用基准（zipfile 独立读取） ----------
    base_ref = zip_ref(FIX / "base.apk")
    base_manifest_sha = sha256_bytes(base_ref["AndroidManifest.xml"])
    base_arsc_sha = sha256_bytes(base_ref["resources.arsc"])

    # ========== S1：逆向摸底 list --json → extract --entry ==========
    # S1a: list --json 字段契约 + 与 zipfile 条目一致
    r = run_cli(binary, ["list", "tests/fixtures/base.apk", "--json"])
    assert_no_panic(r, "S1 list --json")
    record(r.returncode == 0, "S1 list --json exit=0", f"rc={r.returncode} stderr={r.stderr!r}")
    try:
        d = json.loads(r.stdout)
        record(True, "S1 list --json valid-JSON")
    except Exception as e:
        d = {}
        record(False, "S1 list --json valid-JSON", str(e) + f" stdout={r.stdout!r}")
    expected_keys = {"tool", "apk", "entries", "dex", "manifest_bytes", "resource_table_bytes", "abis"}
    record(
        expected_keys.issubset(d.keys()),
        "S1 list --json field-contract",
        f"missing={expected_keys - d.keys()}",
    )
    # entries 与 zipfile 独立引用逐条目一致（name/usize/csize）
    got_entries = {e["name"]: e for e in d.get("entries", [])}
    ref_entries_ok = True
    detail = ""
    for nm, raw in base_ref.items():
        g = got_entries.get(nm)
        if g is None or g["uncompressed_size"] != len(raw):
            ref_entries_ok = False
            detail = f"mismatch entry={nm} got={g}"
            break
    record(ref_entries_ok, "S1 list entries match zipfile ref", detail)
    record(d.get("manifest_bytes") == len(base_ref["AndroidManifest.xml"]), "S1 manifest_bytes", f"got={d.get('manifest_bytes')}")
    record(d.get("resource_table_bytes") == len(base_ref["resources.arsc"]), "S1 resource_table_bytes", f"got={d.get('resource_table_bytes')}")

    # S1b: extract --entry 落盘哈希 = zipfile 引用
    out_man = tmp / "out_manifest.xml"
    r = run_cli(binary, ["extract", "tests/fixtures/base.apk", "--entry", "AndroidManifest.xml", "--out", str(out_man)])
    assert_no_panic(r, "S1 extract --entry")
    record(r.returncode == 0, "S1 extract --entry exit=0", f"rc={r.returncode} stderr={r.stderr!r}")
    out_man_sha = sha256_bytes(out_man.read_bytes()) if out_man.is_file() else "<missing>"
    record(out_man_sha == base_manifest_sha, "S1 extract --entry sha256 == zipfile ref", f"out={out_man_sha} ref={base_manifest_sha}")

    # ========== S2：合规初筛 verify / certs ==========
    # S2a: verify v2v3 文本记录行 + 退出码 0
    r = run_cli(binary, ["verify", "tests/fixtures/fx-multidex-v2v3.apk"])
    assert_no_panic(r, "S2 verify v2v3")
    record(r.returncode == 0, "S2 verify v2v3 exit=0", f"rc={r.returncode} stdout={r.stdout!r}")
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("VERIFY|")]
    record(len(lines) == 2, "S2 verify v2v3 has 2 VERIFY lines", f"lines={lines}")
    # 字段契约：VERIFY|scheme|structure_ok|digest_ok|crypto_verified|algo
    contract_ok = all(ln.count("|") == 5 for ln in lines)
    record(contract_ok, "S2 VERIFY line field-contract (6 fields)", f"lines={lines}")
    has_v2 = any(ln.startswith("VERIFY|v2|true|true|true|") for ln in lines)
    has_v3 = any(ln.startswith("VERIFY|v3|true|true|true|") for ln in lines)
    record(has_v2 and has_v3, "S2 verify v2v3 structure+digest+crypto all true", f"lines={lines}")

    # S2b: verify --json 字段契约
    r = run_cli(binary, ["verify", "tests/fixtures/fx-multidex-v2v3.apk", "--json"])
    assert_no_panic(r, "S2 verify --json")
    try:
        d = json.loads(r.stdout)
        record(True, "S2 verify --json valid-JSON")
    except Exception as e:
        d = {}
        record(False, "S2 verify --json valid-JSON", str(e) + f" stdout={r.stdout!r}")
    verifs = d.get("verifications", [])
    rec_keys = {"scheme", "structure_ok", "digest_ok", "crypto_verified", "algo", "detail"}
    rec_ok = len(verifs) == 2 and all(rec_keys.issubset(v.keys()) for v in verifs)
    record(rec_ok, "S2 verify --json field-contract", f"verifs={verifs}")
    # signature_verified 字段不得存在（语义防火墙：验签走新通道）
    no_sigfield = all("signature_verified" not in v for v in verifs)
    record(no_sigfield, "S2 verify --json no signature_verified field", f"verifs={verifs}")

    # S2c: verify unsigned → 退出码 1（验证失败）
    r = run_cli(binary, ["verify", "tests/fixtures/fx-multidex-unsigned.apk"])
    assert_no_panic(r, "S2 verify unsigned")
    record(r.returncode == 1, "S2 verify unsigned exit=1", f"rc={r.returncode} stdout={r.stdout!r}")

    # S2d: certs 记录行契约
    r = run_cli(binary, ["certs", "tests/fixtures/fx-multidex-v2v3.apk"])
    assert_no_panic(r, "S2 certs")
    record(r.returncode == 0, "S2 certs exit=0", f"rc={r.returncode} stderr={r.stderr!r}")
    cert_lines = [ln for ln in r.stdout.splitlines() if ln.startswith("CERT|")]
    record(len(cert_lines) >= 1, "S2 certs has CERT| lines", f"lines={cert_lines}")
    cert_fields_ok = all(ln.count("|") == 4 for ln in cert_lines)
    record(cert_fields_ok, "S2 CERT line field-contract (5 fields)", f"lines={cert_lines}")

    # ========== S3：取证提取 extract --all + 安全拒绝 ==========
    # S3a: extract --all 正常路径 → 落盘集合/哈希 == zipfile 引用
    odir = tmp / "all_base"
    r = run_cli(binary, ["extract", "tests/fixtures/base.apk", "--all", "--out", str(odir)])
    assert_no_panic(r, "S3 extract --all base")
    record(r.returncode == 0, "S3 extract --all base exit=0", f"rc={r.returncode} stderr={r.stderr!r}")
    extr_lines = [ln for ln in r.stdout.splitlines() if ln.startswith("EXTR|")]
    record(len(extr_lines) == len(base_ref), "S3 extract --all wrote all entries", f"lines={extr_lines}")
    all_ok = True
    for nm, raw in base_ref.items():
        dest = odir / nm
        if not dest.is_file() or sha256_bytes(dest.read_bytes()) != sha256_bytes(raw):
            all_ok = False
            break
    record(all_ok, "S3 extract --all hashes == zipfile ref", f"dest files={[str(p) for p in odir.rglob('*') if p.is_file()]}")

    # S3b: 恶意条目名写盘前整体拒绝（退出码 1），且输出目录为空
    malicious = {
        "evil_traversal.apk": {"../evil.txt": b"EVIL"},
        "evil_abs.apk": {"/abs/evil.txt": b"EVIL"},
        "evil_nested.apk": {"a.txt": b"ROOT", "a.txt/A.txt": b"NESTED"},
        "evil_case.apk": {"a.txt": b"lower", "A.txt": b"UPPER"},
    }
    for mname, entries in malicious.items():
        apk = build_malicious_apk(tmp, mname, entries)
        mdir = tmp / ("rej_" + mname)
        mdir.mkdir(exist_ok=True)
        r = run_cli(binary, ["extract", str(apk.relative_to(REPO)) if str(apk).startswith(str(REPO)) else str(apk), "--all", "--out", str(mdir)])
        assert_no_panic(r, f"S3 reject {mname}")
        record(r.returncode == 1, f"S3 reject {mname} exit=1", f"rc={r.returncode} stdout={r.stdout!r}")
        # 输出目录必须为空（写盘前整体拒绝，不产生部分写入）
        leftover = [p for p in mdir.rglob("*") if p.is_file()]
        record(len(leftover) == 0, f"S3 reject {mname} dir empty (no partial write)", f"leftover={leftover}")
        record("error" in (r.stderr or ""), f"S3 reject {mname} stderr error", f"stderr={r.stderr!r}")

    # ========== C4：退出码矩阵 ==========
    # 2 = 用法错误
    r = run_cli(binary, [])  # 无子命令
    record(r.returncode == 2, "C4 no-subcommand exit=2", f"rc={r.returncode}")
    r = run_cli(binary, ["frobnicate"])  # 未知子命令
    record(r.returncode == 2, "C4 unknown-subcommand exit=2", f"rc={r.returncode}")
    r = run_cli(binary, ["extract", "tests/fixtures/base.apk", "--entry", "x"])  # 缺 --out
    record(r.returncode == 2, "C4 missing --out exit=2", f"rc={r.returncode}")
    r = run_cli(binary, ["extract", "tests/fixtures/base.apk", "--entry", "x", "--all", "--out", "z"])  # 互斥
    record(r.returncode == 2, "C4 --entry/--all mutex exit=2", f"rc={r.returncode}")
    r = run_cli(binary, ["list"])  # 缺 <apk>
    record(r.returncode == 2, "C4 list missing apk exit=2", f"rc={r.returncode}")
    # 1 = IO/解析错误
    r = run_cli(binary, ["list", "no_such_file.apk"])
    record(r.returncode == 1, "C4 missing-file exit=1", f"rc={r.returncode}")
    # 0 = 全通过（list base / verify v1 / extract entry）
    r = run_cli(binary, ["list", "tests/fixtures/base.apk"])
    record(r.returncode == 0, "C4 list base exit=0", f"rc={r.returncode}")
    r = run_cli(binary, ["verify", "tests/fixtures/fx-multidex-v1.apk"])
    record(r.returncode == 0, "C4 verify v1 exit=0", f"rc={r.returncode}")

    # ---------- 汇总 ----------
    print("=" * 60)
    print(f"cli_e2e: PASS={PASS}  FAIL={FAIL}  SKIPPED={len(SKIPPED)}")
    for s in SKIPPED:
        print("  SKIPPED:", s)
    if FAIL_DETAILS:
        print("-" * 60)
        print(f"FAILURES ({len(FAIL_DETAILS)}):")
        for name, detail in FAIL_DETAILS:
            print(f"  [FAIL] {name}")
            print(f"         {detail}")
        print("-" * 60)
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
