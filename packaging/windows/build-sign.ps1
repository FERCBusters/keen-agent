[CmdletBinding()]
param(
  [ValidateSet('amd64','arm64')][string]$Architecture='amd64',
  [string]$CertificateThumbprint,
  [string]$TimestampUrl,
  [switch]$MachineStore,
  [switch]$Unsigned,
  [string]$SignTool='signtool.exe',
  [string]$Wix='wix.exe'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if (!$Unsigned -and (!$CertificateThumbprint -or !$TimestampUrl)) { throw 'Supply CertificateThumbprint and TimestampUrl, or explicitly use -Unsigned for testing.' }
if ($CertificateThumbprint -and $CertificateThumbprint -notmatch '^[a-fA-F0-9]{40}$') { throw 'Expected a 40-character certificate thumbprint.' }
function Checked([string]$Command,[string[]]$Arguments) { & $Command @Arguments; if ($LASTEXITCODE -ne 0) { throw "$Command failed ($LASTEXITCODE)" } }
function Sign([string]$File) {
  if ($Unsigned) { return }
  $a=@('sign','/sha1',$CertificateThumbprint,'/s','My','/fd','SHA256','/tr',$TimestampUrl,'/td','SHA256')
  if ($MachineStore) { $a += '/sm' }
  # The installed token CSP/KSP prompts for its PIN. No exported key or PIN argument.
  Checked $SignTool ($a + $File)
  Checked $SignTool @('verify','/pa','/all','/v',$File)
}
$repo=Resolve-Path "$PSScriptRoot\..\.."
$oldOS=$env:GOOS; $oldArch=$env:GOARCH; $oldCGO=$env:CGO_ENABLED
Push-Location $repo
try {
  $out=Join-Path $repo "dist\windows-$Architecture"
  New-Item -ItemType Directory -Force $out | Out-Null
  $exe=Join-Path $out 'keen-posture.exe'
  $msi=Join-Path $out 'keen-posture-0.1.7.msi'
  $env:GOOS='windows'; $env:GOARCH=$Architecture; $env:CGO_ENABLED='0'
  Checked 'go' @('build','-trimpath','-o',$exe,'./cmd/keen-posture')
  Sign $exe
  $wixArch=if($Architecture -eq 'amd64'){'x64'}else{'arm64'}
  Checked $Wix @('build',"$PSScriptRoot\Product.wxs",'-arch',$wixArch,'-d',"Binary=$exe",'-o',$msi)
  Sign $msi
  Get-FileHash -Algorithm SHA256 $exe,$msi
} finally { $env:GOOS=$oldOS; $env:GOARCH=$oldArch; $env:CGO_ENABLED=$oldCGO; Pop-Location }
