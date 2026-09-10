$ErrorActionPreference = "Stop"
$bundle = Join-Path $PSScriptRoot "bundle"
$manifest = Join-Path $bundle "SHA256SUMS.txt"
if (-not (Test-Path -LiteralPath $manifest)) { throw "SHA256SUMS.txt not found" }

foreach ($line in Get-Content -LiteralPath $manifest) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Invalid manifest line: $line" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $bundle $Matches[2])).Hash.ToLowerInvariant()
    if ($actual -ne $Matches[1]) { throw "Hash mismatch: $($Matches[2])" }
}

docker load --input (Join-Path $bundle "scanner-core-image.tar")
Push-Location $bundle
try {
    docker compose -f docker-compose.yml -f docker-compose.offline.yml up -d --no-build
} finally {
    Pop-Location
}
