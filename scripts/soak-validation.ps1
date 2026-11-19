param(
    [ValidateRange(1, 100)]
    [int]$Cycles = 20,
    [switch]$RunLiveP2P
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $repoRoot
$logDir = Join-Path $repoRoot "validation-results"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logDir "soak-$stamp.log"
"XLINK repeatable soak | cycles=$Cycles | utc=$([DateTime]::UtcNow.ToString('o'))" | Tee-Object -FilePath $logFile
for ($i = 1; $i -le $Cycles; $i++) {
    $started = Get-Date
    "CYCLE $i/$Cycles START $($started.ToString('o'))" | Tee-Object -FilePath $logFile -Append
    & cargo test --workspace --locked --quiet 2>&1 | Tee-Object -FilePath $logFile -Append
    if ($LASTEXITCODE -ne 0) { throw "Workspace test failed in cycle $i; log: $logFile" }
    "CYCLE $i/$Cycles PASS elapsed=$([math]::Round(((Get-Date)-$started).TotalSeconds,2))s" | Tee-Object -FilePath $logFile -Append
}
if ($RunLiveP2P) {
    "LIVE P2P opt-in smoke start" | Tee-Object -FilePath $logFile -Append
    & cargo test -p nexus_network --locked -- --ignored --nocapture 2>&1 | Tee-Object -FilePath $logFile -Append
    if ($LASTEXITCODE -ne 0) { throw "Live P2P test failed; log: $logFile" }
}
"ALL REPEATABLE TESTS PASS (NOT A FIELD CERTIFICATION)" | Tee-Object -FilePath $logFile -Append
Write-Host "Evidence: $logFile"
