param(
    [string]$Target = "x86_64-pc-windows-msvc",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot

function Invoke-Cargo {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Args
    )

    & cargo @Args
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($Args -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Write-Host "[build] Repository: $repoRoot"

if (-not $SkipTests) {
    Write-Host "[build] Running workspace tests..."
    Invoke-Cargo -Args @("test", "--workspace")
}

Write-Host "[build] Building release executable for target $Target..."
Invoke-Cargo -Args @("build", "--release", "--target", $Target)

$targetExe = Join-Path $repoRoot "target/$Target/release/nexus-p2p.exe"
$fallbackExe = Join-Path $repoRoot "target/release/nexus-p2p.exe"

if (Test-Path $targetExe) {
    $sourceExe = $targetExe
} elseif (Test-Path $fallbackExe) {
    $sourceExe = $fallbackExe
} else {
    throw "Release executable not found. Checked: '$targetExe' and '$fallbackExe'."
}

$distDir = Join-Path $repoRoot "dist"
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

$distExe = Join-Path $distDir "nexus-p2p.exe"
Copy-Item -Path $sourceExe -Destination $distExe -Force
Copy-Item -Path (Join-Path $repoRoot "README.md") -Destination (Join-Path $distDir "README.md") -Force

Write-Host "[build] Done. Executable: $distExe"
