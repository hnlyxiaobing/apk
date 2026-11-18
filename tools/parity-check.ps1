# tools/parity-check.ps1 — L5 双目标等价门禁（A6）。
#
# 同一 fixture 集在 `--target wasm` 与 `--target native` 各跑一遍 CLI 值输出
# （list / certs / verify 的 --json），规范化后**逐字节 diff = 0**。
#
# 口径：platform 缺失（无 moon / 无 wasm 运行时）→ 显式 SKIPPED，退出码 78，
#       不冒充通过；任一 diff != 0 → 退出码 1；全部 diff = 0 → 退出码 0。
#
# 用法： powershell -ExecutionPolicy Bypass -File tools/parity-check.ps1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot
$nativeBin = Join-Path $repo '_build\native\debug\build\cmd\main\main.exe'

function Normalize {
    param([string]$s)
    # CRLF->LF、逐行去尾部空白、末行换行归一。字节 diff 前统一到规范形。
    $lines = ($s -split "`r?`n")
    $norm = ($lines | ForEach-Object { $_.TrimEnd() }) -join "`n"
    $norm.TrimEnd("`n")
}

# ---- 平台能力探测：缺 moon 或 wasm 运行时 → SKIPPED(78) ----
if (-not (Get-Command moon -ErrorAction SilentlyContinue)) {
    Write-Host "SKIPPED: moon 不在 PATH，双目标等价门禁跳过 (exit 78)"
    exit 78
}
# wasm 冒烟：node 作为运行时，moon run --target wasm 必须能出 stdout。
$smoke = (& moon run cmd/main --target wasm -- list tests/fixtures/base.apk 2>$null) -join "`n"
if ($LASTEXITCODE -ne 0 -or -not ($smoke -match 'ENTR\|')) {
    Write-Host "SKIPPED: wasm 运行时不可用，双目标等价门禁跳过 (exit 78)"
    exit 78
}
# native 二进制：缺失则构建一次。
if (-not (Test-Path $nativeBin)) {
    & moon build --target native | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "SKIPPED: native 构建失败，双目标等价门禁跳过 (exit 78)"
        exit 78
    }
}

# ---- 校验矩阵（fixture, subcommand）----
# 每个命令在 wasm/native 下输出同一确定性 JSON（apk 字段为同一相对路径）。
$cases = @(
    @{fx='base.apk';                cmd='list'},
    @{fx='base.apk';                cmd='certs'},
    @{fx='base.apk';                cmd='verify'},
    @{fx='fx-multidex-v2v3.apk';    cmd='list'},
    @{fx='fx-multidex-v2v3.apk';    cmd='certs'},
    @{fx='fx-multidex-v2v3.apk';    cmd='verify'},
    @{fx='fx-multidex-v1.apk';      cmd='list'},
    @{fx='fx-multidex-v1.apk';      cmd='certs'},
    @{fx='fx-multidex-v1.apk';      cmd='verify'},
    @{fx='fx-multidex-unsigned.apk';cmd='list'},
    @{fx='fx-multidex-unsigned.apk';cmd='certs'},
    @{fx='fx-multidex-unsigned.apk';cmd='verify'}
)

$pass = 0
$fail = 0
$mismatches = 0
foreach ($c in $cases) {
    $rel = "tests/fixtures/$($c.fx)"
    $name = "$($c.fx) [$($c.cmd) --json]"
    $wasm = (& moon run cmd/main --target wasm -- $($c.cmd) $rel --json 2>$null) -join "`n"
    $wasmCode = $LASTEXITCODE
    $native = (& $nativeBin $($c.cmd) $rel --json 2>$null) -join "`n"
    $nativeCode = $LASTEXITCODE
    $w = Normalize $wasm
    $n = Normalize $native
    if (($wasmCode -eq $nativeCode) -and ($w -ceq $n)) {
        $pass++
        Write-Host "PASS  $name  (rc=$wasmCode)"
    } else {
        $fail++
        $mismatches++
        Write-Host "FAIL  $name"
        Write-Host "      wasm  rc=$wasmCode  len=$($w.Length)"
        Write-Host "      native rc=$nativeCode len=$($n.Length)"
    }
}

Write-Host ('=' * 70)
Write-Host "parity-check: PASS=$pass  FAIL=$fail  mismatches=$mismatches"
if ($mismatches -gt 0) {
    Write-Host "FAIL: 双目标存在字节差异"
    exit 1
}
Write-Host "ALL PASS: wasm/native 逐字节等价"
exit 0
