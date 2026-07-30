param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
  $PSNativeCommandUseErrorActionPreference = $true
}

$TS = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$DIAG_DIR = Join-Path -Path 'diagnostics' -ChildPath $TS
New-Item -ItemType Directory -Path $DIAG_DIR -Force | Out-Null
$EXIT_CODE = 0
$VCOUNT = 0

function Invoke-LoggedNative {
  param(
    [Parameter(Mandatory = $true)][string]$Command,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$LogPath
  )

  $savedPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & $Command @Arguments 2>&1 | Tee-Object -FilePath $LogPath | Out-Host
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    return [int]$code
  }
  finally {
    $ErrorActionPreference = $savedPreference
  }
}

Write-Output "[self-heal] Starting validation run at $TS"

$fmtCode = Invoke-LoggedNative -Command 'cargo' -Arguments @('fmt', '--all', '--', '--check') -LogPath (Join-Path $DIAG_DIR 'cargo-fmt.log')
if ($fmtCode -ne 0) {
  Write-Output "[self-heal] cargo fmt reported issues (exit $fmtCode)"
  $EXIT_CODE = 1
} else {
  Write-Output '[self-heal] cargo fmt OK'
}

$clippyCode = Invoke-LoggedNative -Command 'cargo' -Arguments @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings') -LogPath (Join-Path $DIAG_DIR 'cargo-clippy.log')
if ($clippyCode -ne 0) {
  Write-Output "[self-heal] cargo clippy reported issues (exit $clippyCode)"
  $EXIT_CODE = 1
} else {
  Write-Output '[self-heal] cargo clippy OK'
}

if ($null -ne (Get-Command cargo-audit -ErrorAction SilentlyContinue)) {
  $auditJsonPath = Join-Path $DIAG_DIR 'audit-report.json'
  $savedPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & cargo audit --json 1> $auditJsonPath 2> (Join-Path $DIAG_DIR 'cargo-audit-stderr.log')
    $null = $LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $savedPreference
  }

  $auditCode = Invoke-LoggedNative -Command 'cargo' -Arguments @('audit') -LogPath (Join-Path $DIAG_DIR 'cargo-audit-stdout.log')
  if (Test-Path $auditJsonPath) {
    try {
      $audit = Get-Content -Raw -Path $auditJsonPath | ConvertFrom-Json
      if ($null -ne $audit.vulnerabilities.count) {
        $VCOUNT = [int]$audit.vulnerabilities.count
      } elseif ($null -ne $audit.vulnerabilities.found) {
        $VCOUNT = [int]$audit.vulnerabilities.found
      } elseif ($null -ne $audit.vulnerabilities.list) {
        $VCOUNT = @($audit.vulnerabilities.list).Count
      }
    } catch {
      Write-Output "[self-heal] Could not parse audit JSON: $_"
      $EXIT_CODE = 1
    }
  }
  if ($auditCode -ne 0 -or $VCOUNT -gt 0) {
    Write-Output "[self-heal] cargo audit reported $VCOUNT vulnerabilities (exit $auditCode)"
    $EXIT_CODE = 1
  }
} else {
  Write-Output '[self-heal] cargo-audit is not installed; audit is covered by the dedicated security job'
}

$testCode = Invoke-LoggedNative -Command 'cargo' -Arguments @('test', '--workspace', '--release') -LogPath (Join-Path $DIAG_DIR 'test-output.log')
if ($testCode -ne 0) {
  Write-Output "[self-heal] Tests failed with exit code $testCode"
  $EXIT_CODE = 1
} else {
  Write-Output '[self-heal] Tests passed'
}

$index = @{
  timestamp = $TS
  vulnerabilities = $VCOUNT
  exit_code = $EXIT_CODE
}
$index | ConvertTo-Json | Out-File -FilePath (Join-Path $DIAG_DIR 'index.json') -Encoding utf8

if ($EXIT_CODE -ne 0) {
  Write-Output "[self-heal] Validation detected issues. Diagnostics saved to $DIAG_DIR"
  exit 1
}

Write-Output '[self-heal] All checks passed.'
exit 0
