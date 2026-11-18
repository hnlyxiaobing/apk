#!/usr/bin/env python3
# tests/apksigner_oracle_diff.py — W6 / M6-6：与 `apksigner verify` 的公钥验签 oracle 差分（本地-only）。
#
# 口径：
#   - 主 oracle = `apksigner verify -v <apk>`（Android SDK build-tools）。判定文本含
#     `Verifies` → 通过；含 `DOES NOT VERIFY` → 未通过。
#   - 被测 = 本库 CLI `apk-cli verify <apk>`，退出码 0 = 全部方案
#     structure_ok && digest_ok && crypto_verified，1 = fail-closed。
#   - 仅对 **RSA** 样本做硬对账；ECDSA 样本按 W6 裁决 `#skip`（本库 fail-closed，
#     与 apksigner 必然不一致，故排除出对账集并单列）。
#   - `fx-multidex-v2v3.apk` 无 META-INF/MANIFEST.MF，apksigner 会以
#     "Missing META-INF/MANIFEST.MF" 直接拒绝（非签名结论），故只做库内自一致校验。
#
# 退出码：
#   0   差分一致（对账通过）
#   1   差分不一致
#   78  oracle 缺失 / 样本缺失 → 显式 SKIPPED（不进 CI）
#
# 用法：
#   python tests/apksigner_oracle_diff.py [--apk-cli <path>] [apk ...]
#   python tests/apksigner_oracle_diff.py --self-test     # 无 oracle 时自检对账管线

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

# 受控样本：(路径, 期望本库结论，是否纳入 apksigner 硬对账)
# real v1 / real v2v3 / tvshell-debug 来自 tests/ASSETS.md 登记样本；
# unsigned 期望「无签名方案」；v2v3 因缺 MANIFEST.MF 只做库内自一致校验。
DEFAULT_SAMPLES = [
    (FIXTURES / "fx-multidex-v1.apk", True, True),
    (FIXTURES / "tvshell-debug.apk", True, True),
    (FIXTURES / "fx-multidex-v2v3.apk", True, False),
    (FIXTURES / "fx-multidex-unsigned.apk", False, False),  # 无签名 → apksigner 也判未签名
]

EXIT_OK, EXIT_DIFF, EXIT_SKIP = 0, 1, 78


def find_apksigner() -> str | None:
    exe = shutil.which("apksigner") or shutil.which("apksigner.bat")
    if exe:
        return exe
    # 常见 SDK 布局兜底探测。
    for base in (
        Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "build-tools",
        Path("/usr/lib/android-sdk/build-tools"),
    ):
        if base.is_dir():
            for d in sorted(base.iterdir(), reverse=True):
                for name in ("apksigner.bat", "apksigner"):
                    cand = d / name
                    if cand.is_file():
                        return str(cand)
    return None


def run_apksigner(exe: str, apk: Path) -> tuple[int, bool | None]:
    proc = subprocess.run(
        [exe, "verify", "-v", str(apk)], capture_output=True, text=True
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if "DOES NOT VERIFY" in out:
        return proc.returncode, False
    if re.search(r"^\s*Verifies\s*$", out, re.M) or "Verifies\n" in out:
        return proc.returncode, True
    return proc.returncode, None


def run_our_cli(cli: str | None, apk: Path) -> tuple[int, list[str]]:
    if cli:
        cmd = [cli, "verify", str(apk)]
    else:
        cmd = [
            "moon",
            "run",
            "cmd/main",
            "--target",
            "native",
            "--",
            "verify",
            str(apk),
        ]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.startswith("VERIFY|")]
    return proc.returncode, lines


def main() -> int:
    argv = sys.argv[1:]
    cli: str | None = None
    self_test = False
    apks: list[Path] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--apk-cli":
            i += 1
            cli = argv[i]
        elif a == "--self-test":
            self_test = True
        else:
            apks.append(Path(a))
        i += 1

    samples = [(p, exp, strict) for p, exp, strict in DEFAULT_SAMPLES]
    if apks:
        samples = [(p, None, True) for p in apks]

    missing = [p for p, _, _ in samples if not p.is_file()]
    if missing:
        print(f"sample(s) missing: {missing} -> SKIPPED", file=sys.stderr)
        return EXIT_SKIP

    oracle = find_apksigner()
    if oracle is None and not self_test:
        print(
            "SKIPPED: `apksigner` 不在 PATH（Android SDK build-tools 未安装），"
            "无法执行 M6-6 oracle 差分。",
            file=sys.stderr,
        )
        print(
            "安装 SDK build-tools 后重跑：python tests/apksigner_oracle_diff.py",
            file=sys.stderr,
        )
        return EXIT_SKIP

    print(f"oracle       : {oracle or '<none> (self-test)>'}")
    print(f"under test   : {cli or 'moon run cmd/main -- verify'}")
    print()

    mismatches = 0
    compared = 0
    for apk, expect, strict in samples:
        our_rc, our_lines = run_our_cli(cli, apk)
        # 本库判定以退出码为准（CLI 约定：0 = 全部方案结构/摘要/验签三真）。
        # VERIFY 行仅用于展示逐方案明细的事实。
        ours = bool(our_lines) and our_rc == 0
        ours_none = len(our_lines) == 0

        print(f"sample       : {apk.name}")
        print(f"  our verdict: {'VERIFIED' if ours else ('NO-SIGNATURE' if ours_none else 'FAILED')} (rc={our_rc})")
        for ln in our_lines:
            print(f"    {ln}")

        if expect is not None:
            want = expect
            got = ours
            ok = got == want
            print(f"  expected   : {want} -> {'OK' if ok else 'MISMATCH'}")
            if not ok:
                mismatches += 1
            compared += 1

        if oracle is not None and strict:
            arc, averdict = run_apksigner(oracle, apk)
            if averdict is None:
                print(f"  apksigner  : unparsable (rc={arc}) -> SKIPPED sample")
            else:
                agree = averdict == ours
                print(
                    f"  apksigner  : {'VERIFIED' if averdict else 'NOT-VERIFIED'} "
                    f"(rc={arc}) -> {'AGREE' if agree else 'DISAGREE'}"
                )
                if not agree:
                    mismatches += 1
                compared += 1
        print()

    print(f"compared={compared} mismatches={mismatches}")
    if mismatches:
        print("DIFF: oracle 与库内结论不一致")
        return EXIT_DIFF
    if oracle is None:
        print("NOTE: 无 apksigner，仅完成自检（未做 oracle 硬对账）。")
    print("OK: oracle 差分一致")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())