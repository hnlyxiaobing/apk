# tools/error-bookkeeping.ps1 — L5 错误簿记门禁（A2/A5，§6.2 的 10/10 强制）。
#
# 双向核对 §6.2 的 10 个 `ApkError` 变体与测试代码中的断言：
#   · 正向（表→测试）：每个变体必须在测试文件中出现 ≥1 次断言（不是只「报错了」）。
#   · 反向（测试→表）：测试中断言的每个变体都必须在 10 变体表中（防新增变体漏记账）。
# 缺一即红（退出码 1）；moon 缺失与本门禁无关，不判 SKIPPED（纯源码 grep）。
#
# 用法： powershell -ExecutionPolicy Bypass -File tools/error-bookkeeping.ps1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot

# §6.2 表中登记的全部错误变体（与 ApkError 枚举一一对应）。
$registered = @(
    'UnexpectedEof', 'NotAZip', 'BadCentralDirectory', 'Zip64Unsupported',
    'EntryNotFound', 'BadSigningBlock', 'UnsupportedSignatureScheme',
    'BadAlignment', 'BadResourceTable', 'BadElf'
)
$registeredSet = [System.Collections.Generic.HashSet[string]]::new()
foreach ($v in $registered) { [void]$registeredSet.Add($v) }

# 测试文件（黑盒 + 白盒），排除 cmd/main（仅 CLI，不含库错误变体断言）。
$testFiles = Get-ChildItem -Path $repo -Recurse -Include '*_test.mbt', '*_wbtest.mbt' -File |
    Where-Object { $_.FullName -notlike '*\cmd\main\*' }

# 从测试文件中收集每个变体是否被断言（出现 `ApkError::<Variant>`）。
$assertedInTests = [System.Collections.Generic.HashSet[string]]::new()
foreach ($f in $testFiles) {
    $hits = Select-String -Path $f.FullName -Pattern 'ApkError::(\w+)' -AllMatches
    foreach ($h in $hits) {
        foreach ($m in $h.Matches) {
            [void]$assertedInTests.Add($m.Groups[1].Value)
        }
    }
}

$failures = 0
$covered = 0

# ---- 正向：表→测试 ----
Write-Host '正向核对（§6.2 变体 → 测试断言）:'
foreach ($v in $registered) {
    if ($assertedInTests.Contains($v)) {
        $covered++
        Write-Host ("  [x] {0,-28} 已断言" -f $v)
    } else {
        Write-Host ("  [ ] {0,-28} 缺失断言 —— 变红" -f $v)
        $failures++
    }
}

# ---- 反向：测试→表 ----
Write-Host '反向核对（测试断言变体 → §6.2 表）:'
foreach ($v in ($assertedInTests | Sort-Object)) {
    if ($registeredSet.Contains($v)) {
        Write-Host ("  [x] {0,-28} 已在表中" -f $v)
    } else {
        Write-Host ("  [!] {0,-28} 未在 §6.2 表中登记 —— 变红" -f $v)
        $failures++
    }
}

Write-Host ('=' * 70)
Write-Host "error-bookkeeping: 覆盖 $covered/10，FAILURES=$failures"
if ($failures -gt 0) {
    Write-Host 'FAIL: 错误簿记未达 10/10（存在变体缺断言或表未登记）'
    exit 1
}
Write-Host 'ALL PASS: 10/10 变体双向对齐'
exit 0
