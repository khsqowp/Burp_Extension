$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$bundle = Join-Path $PSScriptRoot "bundle"
$resolvedOffline = [IO.Path]::GetFullPath($PSScriptRoot)
$resolvedBundle = [IO.Path]::GetFullPath($bundle)
if ([IO.Path]::GetDirectoryName($resolvedBundle) -ne $resolvedOffline) {
    throw "Unsafe bundle path: $resolvedBundle"
}
if (Test-Path -LiteralPath $bundle) {
    $oldData = Join-Path $bundle "scanner-data"
    if (Test-Path -LiteralPath $oldData) {
        $archiveRoot = Join-Path $root "scanner-data"
        New-Item -ItemType Directory -Force -Path $archiveRoot | Out-Null
        $archive = Join-Path $archiveRoot ("offline-bundle-preserved-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
        Move-Item -LiteralPath $oldData -Destination $archive
        Write-Host "Previous offline validation data preserved: $archive"
    }
    Remove-Item -LiteralPath $resolvedBundle -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $bundle | Out-Null

docker image inspect security_toolkit-scanner-core:latest | Out-Null
docker save --output (Join-Path $bundle "scanner-core-image.tar") security_toolkit-scanner-core:latest
Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $root) "burp-history-bridge.jar") -Destination $bundle -Force
Copy-Item -LiteralPath (Join-Path $root "docker-compose.yml") -Destination $bundle -Force
Copy-Item -LiteralPath (Join-Path $root "docker-compose.offline.yml") -Destination $bundle -Force

Get-ChildItem -LiteralPath $bundle -File |
    Where-Object Name -ne "SHA256SUMS.txt" |
    Get-FileHash -Algorithm SHA256 |
    ForEach-Object { "$($_.Hash.ToLowerInvariant())  $([IO.Path]::GetFileName($_.Path))" } |
    Set-Content -LiteralPath (Join-Path $bundle "SHA256SUMS.txt") -Encoding ascii

Write-Host "Offline bundle created: $bundle"
