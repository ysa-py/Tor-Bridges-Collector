param()

# PowerShell auto-fix for mechanical issues (Windows-friendly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
  $PSNativeCommandUseErrorActionPreference = $true
}

Push-Location -Path (Split-Path -Path $MyInvocation.MyCommand.Path -Parent)
Set-Location ..

# Ensure clean working tree
$porcelain = git status --porcelain
if ($porcelain) {
  Write-Output "[auto-fix.ps1] Working tree is not clean. Aborting auto-fix to avoid clobbering changes.";
  exit 2
}

$ORIG_HEAD = git rev-parse --verify HEAD
$TS = (Get-Date).ToString('yyyyMMddTHHmmssZ')
$ISSUE_ID = "mechanical-$TS"
$DIAG_DIR = Join-Path -Path "diagnostics" -ChildPath "auto-fix-$TS"
New-Item -ItemType Directory -Path $DIAG_DIR -Force | Out-Null
$CHANGES_MADE = $false

Write-Output "[auto-fix.ps1] Starting auto-fix run ($ISSUE_ID)"

# 1) cargo fmt check
Write-Output "[auto-fix.ps1] Running cargo fmt --all -- --check"
try {
  & cargo fmt --all -- --check 2>&1 | Tee-Object -FilePath (Join-Path $DIAG_DIR 'cargo-fmt-check.log')
  Write-Output "[auto-fix.ps1] No formatting issues"
} catch {
  Write-Output "[auto-fix.ps1] Formatting issues found. Applying cargo fmt --all"
  & cargo fmt --all 2>&1 | Tee-Object -FilePath (Join-Path $DIAG_DIR 'cargo-fmt-apply.log')
  git add -A
  $CHANGES_MADE = $true
}

# 2) cargo fix (compiler suggestions), try enabling --clippy if supported
$fixArgs = @('fix', '--workspace', '--allow-dirty', '--allow-staged')
# Check support for --clippy
$supportsClippy = $false
try {
  $help = & cargo fix --help 2>&1
  if ($help -match '--clippy') { $supportsClippy = $true }
} catch {
  # An older Cargo without this option is supported.
}
if ($supportsClippy) {
  $fixArgs += '--clippy'
  Write-Output '[auto-fix.ps1] cargo fix supports --clippy; enabling clippy fixes'
}

# Capture pre-change status
$preStatus = git status --porcelain

# Run cargo fix. The invocation operator receives the command and argument
# array separately; invoking one array as a command is not portable.
Write-Output "[auto-fix.ps1] Running cargo $($fixArgs -join ' ')"
try {
  & cargo @fixArgs 2>&1 | Tee-Object -FilePath (Join-Path $DIAG_DIR 'cargo-fix.log')
} catch {
  Write-Output '[auto-fix.ps1] cargo fix exited with non-zero (it may still have applied changes). Continuing to inspect the tree.'
}

$postStatus = git status --porcelain
if ($postStatus -ne $preStatus) {
  Write-Output "[auto-fix.ps1] cargo fix made changes"
  git add -A
  $CHANGES_MADE = $true
} else {
  Write-Output "[auto-fix.ps1] cargo fix did not change sources"
}

if (-not $CHANGES_MADE) {
  Write-Output "[auto-fix.ps1] No mechanical changes to apply. Exiting."
  Pop-Location
  exit 0
}

# 3) Run validation: clippy and tests
Write-Output "[auto-fix.ps1] Running cargo clippy --workspace --all-targets -- -D warnings"
try {
  & cargo clippy --workspace --all-targets -- -D warnings 2>&1 | Tee-Object -FilePath (Join-Path $DIAG_DIR 'cargo-clippy-postfix.log')
} catch {
  Write-Output "[auto-fix.ps1] clippy failed after fixes — rolling back"
  & git reset --hard $ORIG_HEAD
  & git clean -fd
  Pop-Location
  exit 1
}

Write-Output "[auto-fix.ps1] Running cargo test --workspace --release"
# Capture test output
$testLog = Join-Path $DIAG_DIR 'test-output-postfix.log'
$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.FileName = 'cargo'
$processInfo.Arguments = 'test --workspace --release'
$processInfo.RedirectStandardOutput = $true
$processInfo.RedirectStandardError = $true
$processInfo.UseShellExecute = $false
$processInfo.CreateNoWindow = $true
$process = New-Object System.Diagnostics.Process
$process.StartInfo = $processInfo
$process.Start() | Out-Null
$stdOut = $process.StandardOutput.ReadToEnd()
$stdErr = $process.StandardError.ReadToEnd()
$process.WaitForExit()
$stdOut + $stdErr | Out-File -FilePath $testLog -Encoding utf8
if ($process.ExitCode -ne 0) {
  Write-Output "[auto-fix.ps1] Tests failed after fixes (exit $($process.ExitCode)) — rolling back"
  & git reset --hard $ORIG_HEAD
  & git clean -fd
  Pop-Location
  exit 1
}

# 4) All validations passed; commit changes
$commitMsg = "fix(self-healing): auto-resolved mechanical issue ${ISSUE_ID} via surgical patch"
& git commit -m $commitMsg -a
Write-Output "[auto-fix.ps1] Changes committed: $commitMsg"

Pop-Location
exit 0
