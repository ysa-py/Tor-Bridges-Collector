param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TS = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$DIAG_DIR = Join-Path -Path 'diagnostics' -ChildPath $TS
New-Item -ItemType Directory -Path $DIAG_DIR -Force | Out-Null
$EXIT_CODE = 0

Write-Output "[self-heal] Starting validation run at $TS"

# 1) cargo fmt check
Write-Output "[self-heal] Running cargo fmt --all -- --check"
try {
  & cargo fmt --all -- --check 2>&1 | Tee-Object -FilePath (Join-Path $DIAG_DIR 'cargo-fmt.log')
  Write-Output "[self-heal] cargo fmt OK"
} catch {
  Write-Output "[self-heal] cargo fmt reported issues"
  $EXIT_CODE = 1
}

# 2) cargo clippy (treat warnings as errors)
Write-Output "[self-heal] Running cargo clippy (warnings as errors)"
try {
  & cargo clippy --workspace --all-targets -- -D warnings 2>&1 | Tee-Object -FilePath (Join-Path $DIAG_DIR 'cargo-clippy.log')
  Write-Output "[self-heal] cargo clippy OK"
} catch {
  Write-Output "[self-heal] cargo clippy reported warnings/errors"
  $EXIT_CODE = 1
}

# 3) cargo audit — produce JSON report and human-readable logs
Write-Output "[self-heal] Running cargo audit to produce JSON report"
try {
  & cargo audit --json > (Join-Path $DIAG_DIR 'audit-report.json') 2> (Join-Path $DIAG_DIR 'cargo-audit-stderr.log')
} catch {
  # allow non-zero
}
try {
  & cargo audit 2>&1 | Tee-Object -FilePath (Join-Path $DIAG_DIR 'cargo-audit-stdout.log')
} catch {
  # allow non-zero
  Write-Output "[self-heal] cargo audit returned non-zero"
  $EXIT_CODE = 1
}

# Deterministic parsing using jq if available
$VCOUNT = 0
if (Test-Path (Join-Path $DIAG_DIR 'audit-report.json')) {
  try {
    $jq = Get-Command jq -ErrorAction SilentlyContinue
    if ($null -ne $jq) {
      $expr = '(.vulnerabilities.count // .vulnerabilities.found // (.vulnerabilities.list | length) // 0) as $c | ($c // 0)'
      $VCOUNT = (& jq -r $expr (Join-Path $DIAG_DIR 'audit-report.json')) 2>$null
    } else {
      Write-Output "[self-heal] jq not found; skipping JSON parsing"
    }
  } catch {
    Write-Output "[self-heal] Error parsing audit JSON: $_"
  }
  if ([int]$VCOUNT -gt 0) { $EXIT_CODE = 1 }
} else {
  Write-Output "[self-heal] No audit-report.json produced"
}

# 4) Run release tests (capture output)
Write-Output "[self-heal] Running cargo test --workspace --release (this may take time)"
$testLog = Join-Path $DIAG_DIR 'test-output.log'
try {
  & cmd /c "cargo test --workspace --release 2>&1 | tee $testLog"; $tcode = $LASTEXITCODE
} catch {
  $tcode = 1
}
if ($tcode -ne 0) {
  Write-Output "[self-heal] Tests failed with exit code $tcode"
  $EXIT_CODE = 1
} else {
  Write-Output "[self-heal] Tests passed"
}

# Finalize
if ($EXIT_CODE -ne 0) {
  Write-Output "[self-heal] Validation detected issues. Diagnostics saved to $DIAG_DIR"
  # Create a lightweight index for diagnostics
  try {
    $index = @{ timestamp = $TS; vulnerabilities = ([int]$VCOUNT) }
    $index | ConvertTo-Json | Out-File -FilePath (Join-Path $DIAG_DIR 'index.json') -Encoding utf8
  } catch { }
  exit 1
}

Write-Output "[self-heal] All checks passed. No diagnostics generated."
exit 0
