# Run from the repository root in an elevated Windows PowerShell session.
# Requires stable Rust: ./.github/scripts/windows-udp-repro.ps1

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$Repeats = 10
$TimeoutSeconds = 120
$logs = (New-Item -ItemType Directory -Force "repro-logs").FullName
$env:RUST_BACKTRACE = "full"
$env:CARGO_TERM_COLOR = "never"
$env:CARGO_TARGET_DIR = Join-Path $PWD "target"

# Save the tested source/toolchain identity even when building or tracing fails.
& {
    "Trippy master commit:"
    git rev-parse HEAD
    rustc +stable -Vv
    cargo +stable --version
    "Runner image: $env:ImageOS $env:ImageVersion"
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | Format-List
} | Out-File (Join-Path $logs "environment.log")
Copy-Item Cargo.lock $logs

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
"Elevated: $elevated" | Tee-Object -FilePath (Join-Path $logs "environment.log") -Append
if (-not $elevated) {
    throw "An elevated Windows process is required to exercise privileged UDP."
}

cargo +stable build --locked -p trippy-core --example windows_udp_repro `
    --target x86_64-pc-windows-msvc `
    2>&1 | Tee-Object -FilePath (Join-Path $logs "build.log")
if ($LASTEXITCODE -ne 0) {
    throw "Reproducer build failed; see build.log."
}

$binary = Join-Path $env:CARGO_TARGET_DIR "x86_64-pc-windows-msvc/debug/examples/windows_udp_repro.exe"
$results = @()
for ($attempt = 1; $attempt -le $Repeats; $attempt++) {
    $tag = "attempt-{0:D2}" -f $attempt
    $stdout = Join-Path $logs "$tag.stdout.log"
    $stderr = Join-Path $logs "$tag.stderr.log"
    $child = Start-Process -FilePath $binary -NoNewWindow -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    # Retain the process handle so ExitCode remains available after termination.
    $null = $child.Handle
    $exitCode = $null
    if (-not $child.WaitForExit($TimeoutSeconds * 1000)) {
        $child.Kill()
        $child.WaitForExit()
        $outcome = "timeout"
    } else {
        $child.WaitForExit()
        $exitCode = $child.ExitCode
        $out = [string](Get-Content -Raw $stdout)
        $err = [string](Get-Content -Raw $stderr)
        if ($exitCode -eq -1073740791 -and $err -match "from_size_align_unchecked") {
            $outcome = "reported-crash"
        } elseif ($exitCode -eq 0 -and $out -match "REPRO completed rounds=3\b") {
            $outcome = "completed"
        } elseif ($err -match "REPRO typed_error:") {
            $outcome = "typed-error"
        } else {
            $outcome = "unexpected-result"
        }
    }
    $child.Dispose()
    $result = [pscustomobject]@{ attempt = $attempt; outcome = $outcome; exitCode = $exitCode }
    $results += $result
    # Persist after each attempt, including any failures, before continuing.
    ConvertTo-Json -InputObject $results | Set-Content (Join-Path $logs "results.json")
    Write-Host "$tag outcome=$outcome exitCode=$exitCode"
}

$summary = @(
    "## Windows UDP reproduction"
    ""
    "| Attempt | Outcome | Exit code |"
    "| --- | --- | --- |"
)
foreach ($result in $results) {
    $summary += "| $($result.attempt) | $($result.outcome) | $($result.exitCode) |"
}
$summary | Set-Content (Join-Path $logs "summary.md")
if ($env:GITHUB_STEP_SUMMARY) {
    $summary | Add-Content $env:GITHUB_STEP_SUMMARY
}
if (@($results | Where-Object outcome -ne "completed").Count -gt 0) {
    throw "Some attempts did not complete three rounds; inspect the evidence artifact for crashes, typed errors, or timeouts."
}
