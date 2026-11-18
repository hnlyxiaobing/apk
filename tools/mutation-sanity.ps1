# tools/mutation-sanity.ps1 — L5 变异自检（test-of-the-tests，A5）。
#
# 临时注入 3 类缺陷，套件**必须变红**，随后 try/finally 自动还原并**复绿**，
# 证明测试系统真的在守契约而非空转。任何一处「注入后仍绿」即判失败。
#
# 缺陷矩阵：
#   A. 跳过 CRC 校验        apk.mbt      -> moon test 必须变红
#   B. 放行 `..` 条目名     cmd/main/mbt -> python tests/cli_e2e.py 必须变红
#   C. signature_verified 置 true  signature.mbt -> moon test 必须变红
#
# 退出码：0 = 3/3 缺陷均变红且还原后复绿；1 = 任一未满足；78 = moon 缺失（SKIPPED，不计通过）。
#
# 用法： powershell -ExecutionPolicy Bypass -File tools/mutation-sanity.ps1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path -Parent $PSScriptRoot

function Invoke-Suite {
    param([string]$command, [string]$argline)
    # 在 repo 根执行命令，返回退出码。
    if ($command -eq 'moon') {
        Push-Location $repo
        try { moon test | Out-Null; return $LASTEXITCODE }
        finally { Pop-Location }
    } elseif ($command -eq 'python') {
        Push-Location $repo
        try { python $argline | Out-Null; return $LASTEXITCODE }
        finally { Pop-Location }
    }
    return -1
}

function Apply-Mutation {
    # 备份原文件，逐对 (find,repl) 替换写回。返回备份文本供还原。
    param([string]$file, [array]$pairs)
    $path = Join-Path $repo $file
    $original = [System.IO.File]::ReadAllText($path)
    $mutated = $original
    foreach ($p in $pairs) {
        if (-not $mutated.Contains($p.find)) {
            throw "MUTATION-ANCHOR-MISSING: $file 未找到锚点: $($p.find)"
        }
        $mutated = $mutated.Replace($p.find, $p.repl)
    }
    [System.IO.File]::WriteAllText($path, $mutated, (New-Object System.Text.UTF8Encoding $false))
    return $original
}

function Restore-File {
    param([string]$file, [string]$original)
    $path = Join-Path $repo $file
    [System.IO.File]::WriteAllText($path, $original, (New-Object System.Text.UTF8Encoding $false))
}

# ---- moon 缺失 → SKIPPED(78)，不计通过 ----
if (-not (Get-Command moon -ErrorAction SilentlyContinue)) {
    Write-Host "SKIPPED: moon 不在 PATH，变异自检跳过 (exit 78)"
    exit 78
}

$failures = 0

# ---- A. 跳过 CRC 校验 ----
$fileA = 'apk.mbt'
$pairsA = @(
    @{ find = 'if crc32_of(out) != e.crc32 {'; repl = 'if false {' }
)
$suiteA = @{ command = 'moon'; argline = '' }
$originalA = Apply-Mutation $fileA $pairsA
try {
    $rcA = Invoke-Suite $suiteA.command $suiteA.argline
    if ($rcA -ne 0) {
        Write-Host "PASS  A[跳过CRC]  moon test 变红 rc=$rcA"
    } else {
        Write-Host "FAIL  A[跳过CRC]  moon test 仍绿 rc=0 —— 测试系统未守 CRC 契约"
        $failures++
    }
} finally {
    Restore-File $fileA $originalA
}
# 复绿确认
$rcGreen = Invoke-Suite 'moon' ''
if ($rcGreen -ne 0) {
    Write-Host "FAIL  A[跳过CRC] 还原后 moon test 未复绿 rc=$rcGreen"
    $failures++
} else {
    Write-Host "PASS  A[跳过CRC] 还原后复绿"
}

# ---- B. 放行 `..` 条目名 ----
$fileB = 'cmd/main/main.mbt'
$pairsB = @(
    @{ find = 'if segment == "" || segment == "." || segment == ".." {'; repl = 'if segment == "" || segment == "." {' },
    @{ find = 'segment != "" && segment != "." && segment != ".."'; repl = 'segment != "" && segment != "."' }
)
$originalB = Apply-Mutation $fileB $pairsB
try {
    # cli_e2e.py 用 native 二进制，需先重建。
    Push-Location $repo
    moon build --target native | Out-Null
    $buildRc = $LASTEXITCODE
    Pop-Location
    if ($buildRc -ne 0) {
        Write-Host "FAIL  B[放行..]  native 构建失败 rc=$buildRc"
        $failures++
    } else {
        $rcB = Invoke-Suite 'python' 'tests/cli_e2e.py'
        if ($rcB -ne 0) {
            Write-Host "PASS  B[放行..]  cli_e2e.py 变红 rc=$rcB"
        } else {
            Write-Host "FAIL  B[放行..]  cli_e2e.py 仍绿 rc=0 —— 未守路径穿越契约"
            $failures++
        }
    }
} finally {
    Restore-File $fileB $originalB
}
# 复绿确认
Push-Location $repo
moon build --target native | Out-Null
$buildRc = $LASTEXITCODE
Pop-Location
if ($buildRc -eq 0) {
    $rcGreen = Invoke-Suite 'python' 'tests/cli_e2e.py'
    if ($rcGreen -ne 0) {
        Write-Host "FAIL  B[放行..] 还原后 cli_e2e.py 未复绿 rc=$rcGreen"
        $failures++
    } else {
        Write-Host "PASS  B[放行..] 还原后复绿"
    }
} else {
    Write-Host "FAIL  B[放行..] 还原后 native 构建失败"
    $failures++
}

# ---- C. signature_verified 置 true ----
$fileC = 'signature.mbt'
$pairsC = @(
    @{ find = 'signature_verified: false'; repl = 'signature_verified: true' }
)
$originalC = Apply-Mutation $fileC $pairsC
try {
    $rcC = Invoke-Suite 'moon' ''
    if ($rcC -ne 0) {
        Write-Host "PASS  C[置true]  moon test 变红 rc=$rcC"
    } else {
        Write-Host "FAIL  C[置true]  moon test 仍绿 rc=0 —— 未守 signature_verified 恒 false"
        $failures++
    }
} finally {
    Restore-File $fileC $originalC
}
$rcGreen = Invoke-Suite 'moon' ''
if ($rcGreen -ne 0) {
    Write-Host "FAIL  C[置true] 还原后 moon test 未复绿 rc=$rcGreen"
    $failures++
} else {
    Write-Host "PASS  C[置true] 还原后复绿"
}

# ---- 工作区必须干净（无残留脏改动）----
Push-Location $repo
$dirty = (& git diff --stat -- apk.mbt cmd/main/main.mbt signature.mbt 2>$null) -join "`n"
Pop-Location
if ($dirty -ne '') {
    Write-Host "FAIL  工作区残留变异改动：`n$dirty"
    $failures++
} else {
    Write-Host "PASS  工作区无残留变异改动"
}

Write-Host ('=' * 70)
if ($failures -eq 0) {
    Write-Host "mutation-sanity: 3/3 缺陷均变红且还原复绿"
} else {
    Write-Host "mutation-sanity: FAILURES=$failures"
}
if ($failures -gt 0) {
    Write-Host "FAIL: 变异自检未通过（测试系统存在空转）"
    exit 1
}
Write-Host "ALL PASS: 变异自检通过"
exit 0
