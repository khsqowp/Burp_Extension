# Runs every Python manual-test file using THIS project's own .venv,
# regardless of what "python"/"python3" resolves to on the caller's PATH.
#
# spec review finding (2026-09-06): reported failures like "fastapi 미설치"
# / "PyYAML 미설치" were the reviewer's shell resolving to a different, bare
# Python interpreter -- this project's .venv (created for this repo) already
# has every dependency in requirements.txt installed, and every test in this
# suite has only ever been run against it. Hardcoding that path here removes
# the ambiguity instead of relying on whoever runs this to know which
# interpreter to invoke.
#
# Usage: powershell -File run_all_tests.ps1
# Produces a timestamped log under scanner-data/logs/ and a PASS/FAIL summary.

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $root "..\.venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
    Write-Error "venv python not found at $venvPython -- create it first: python -m venv ../.venv ; ../.venv/Scripts/pip install -r requirements.txt"
    exit 1
}

Write-Host "Using interpreter: $venvPython"
& $venvPython --version
if ($LASTEXITCODE -ne 0) {
    Write-Error "venv가 손상된 것으로 보입니다 ($venvPython 실행이 exit $LASTEXITCODE 로 실패) -- Python 설치 상태를 확인하고 venv를 재생성하세요: python -m venv ../.venv ; ../.venv/Scripts/pip install -r requirements.txt"
    exit 1
}

$testFiles = Get-ChildItem -Path $root -Recurse -Filter "test_*_manual.py" | Sort-Object FullName
Write-Host "Found $($testFiles.Count) test file(s)."

$logDir = Join-Path $root "..\scanner-data\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$logFile = Join-Path $logDir ("test_run_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

# Per-file wall-clock cap: a hang in one external tool (confirmed 2026-09-06:
# ssl_tls_scanner's cipher-scan phase can block past its own --timeout flag
# when a specific network path is unresponsive) must not block the rest of
# the suite from being reported.
$perFileTimeoutSec = 240

$results = @()
foreach ($f in $testFiles) {
    $rel = $f.FullName.Substring($root.Length + 1)
    Write-Host "=== $rel ==="
    $outFile = [System.IO.Path]::GetTempFileName()
    $proc = Start-Process -FilePath $venvPython -ArgumentList $f.FullName -NoNewWindow -PassThru `
        -RedirectStandardOutput $outFile -RedirectStandardError "$outFile.err"
    # spec review finding (2026-09-06): Start-Process -PassThru's Process
    # object doesn't always have its exit-code handle populated until
    # something reads .Handle -- without this, .ExitCode below silently
    # comes back empty (not an exception, not $null in a way Continue
    # notices) for every single file, which is how a run where every test
    # actually printed "ALL ... TESTS OK" still summarized as "0 / N PASSED".
    # Touching .Handle here forces .NET to populate it before WaitForExit.
    $proc.Handle | Out-Null
    $finished = $proc.WaitForExit($perFileTimeoutSec * 1000)
    if (-not $finished) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        $exitCode = "TIMEOUT"
    } else {
        $exitCode = $proc.ExitCode
    }
    $output = (Get-Content $outFile -Raw -ErrorAction SilentlyContinue) + (Get-Content "$outFile.err" -Raw -ErrorAction SilentlyContinue)
    Remove-Item $outFile, "$outFile.err" -ErrorAction SilentlyContinue
    Add-Content -Path $logFile -Value "=== $rel (exit $exitCode) ===`r`n$output`r`n"
    $results += [PSCustomObject]@{ File = $rel; ExitCode = $exitCode }
    Write-Host "  exit $exitCode"
}

Write-Host ""
$results | Format-Table -AutoSize
$passed = ($results | Where-Object { $_.ExitCode -eq 0 }).Count
$total = $results.Count
$summary = "$passed / $total PASSED"
Write-Host $summary
Add-Content -Path $logFile -Value "`r`nSUMMARY: $summary`r`n"
Write-Host "Full log: $logFile"

if ($passed -ne $total) {
    exit 1
}
