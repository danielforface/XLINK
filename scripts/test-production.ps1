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

Write-Host "[test] cargo check --workspace"
Invoke-Cargo -Args @("check", "--workspace")

Write-Host "[test] cargo test --workspace"
Invoke-Cargo -Args @("test", "--workspace")

Write-Host "[test] cargo build --release"
Invoke-Cargo -Args @("build", "--release")

Write-Host "[test] Production validation finished successfully."
