[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)][string]$CollectorUrl,
    [Parameter(Mandatory=$false)][string]$CollectorSha256,
    [Parameter(Mandatory=$false)][string]$CollectionId,
    [string]$DeployRoot = 'C:\ProgramData\VelociraptorCollector',
    [switch]$CleanupOnly
)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if ($CleanupOnly) {
    if ($CollectionId) { Remove-Item -LiteralPath (Join-Path $DeployRoot $CollectionId) -Recurse -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -LiteralPath $DeployRoot -Filter "$CollectionId.part*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $DeployRoot "$CollectionId.manifest.txt") -Force -ErrorAction SilentlyContinue
    exit 0
}
if ([string]::IsNullOrWhiteSpace($CollectorUrl) -or [string]::IsNullOrWhiteSpace($CollectorSha256) -or [string]::IsNullOrWhiteSpace($CollectionId)) {
    throw 'CollectorUrl, CollectorSha256, and CollectionId are required.'
}
$JobRoot=Join-Path $DeployRoot $CollectionId
New-Item -ItemType Directory -Path $JobRoot -Force | Out-Null
$Collector=Join-Path $JobRoot 'velociraptor-collector.exe'
Invoke-WebRequest -Uri $CollectorUrl -OutFile $Collector -UseBasicParsing
$Actual=(Get-FileHash -Algorithm SHA256 -LiteralPath $Collector).Hash.ToLowerInvariant()
if ($Actual -ne $CollectorSha256.ToLowerInvariant()) { throw 'Velociraptor collector SHA-256 mismatch.' }
Push-Location $JobRoot
try { & $Collector; if ($LASTEXITCODE -ne 0) { throw "Velociraptor collector exited with $LASTEXITCODE" } } finally { Pop-Location }
$Archive=Get-ChildItem -LiteralPath $JobRoot -Filter 'Collection-*.zip' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $Archive) { throw 'Velociraptor collector produced no collection ZIP.' }
$BytesPerPart=8MB
$Input=[IO.File]::OpenRead($Archive.FullName)
try {
  $Buffer=New-Object byte[] $BytesPerPart; $Index=1; $Parts=@()
  while (($Read=$Input.Read($Buffer,0,$Buffer.Length)) -gt 0) {
    $Part=Join-Path $DeployRoot ("{0}.part{1:D4}" -f $CollectionId,$Index)
    $Out=[IO.File]::Open($Part,[IO.FileMode]::Create,[IO.FileAccess]::Write)
    try { $Out.Write($Buffer,0,$Read) } finally { $Out.Dispose() }
    $Parts += $Part; $Index++
  }
} finally { $Input.Dispose() }
$Manifest=Join-Path $DeployRoot "$CollectionId.manifest.txt"
$Parts | Set-Content -LiteralPath $Manifest -Encoding UTF8
Remove-Item -LiteralPath $Archive.FullName -Force
