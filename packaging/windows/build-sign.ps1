# Signs with a certificate in the Windows certificate store (a hardware token or
# similar, by thumbprint) or with Azure Artifact Signing (a metadata file naming
# the account and certificate profile; sign in with `az login` first).
[CmdletBinding()]
param(
  [ValidateSet('amd64','arm64')][string]$Architecture='amd64',
  [string]$CertificateThumbprint,
  [string]$ArtifactSigningMetadata,
  [string]$ArtifactSigningDlib,
  [string]$TimestampUrl,
  [switch]$MachineStore,
  [switch]$Unsigned,
  [string]$SignTool,
  [string]$Wix='wix.exe'
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$modes=@($Unsigned.IsPresent, [bool]$CertificateThumbprint, [bool]$ArtifactSigningMetadata) | Where-Object { $_ }
if (@($modes).Count -ne 1) { throw 'Choose one of -CertificateThumbprint, -ArtifactSigningMetadata or -Unsigned (for testing).' }
if ($CertificateThumbprint) {
  if ($CertificateThumbprint -notmatch '^[a-fA-F0-9]{40}$') { throw 'Expected a 40-character certificate thumbprint.' }
  if (!$TimestampUrl) { throw 'Supply -TimestampUrl from your certificate authority.' }
}
function Checked([string]$Command,[string[]]$Arguments) { & $Command @Arguments; if ($LASTEXITCODE -ne 0) { throw "$Command failed ($LASTEXITCODE)" } }
if (!$Unsigned) {
  # signtool from PATH, or else the newest x64 Windows SDK copy.
  if (!$SignTool) {
    $found=Get-Command 'signtool.exe' -ErrorAction SilentlyContinue
    if ($found) { $SignTool=$found.Source }
    else {
      $SignTool=Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1 -ExpandProperty FullName
      if (!$SignTool) { throw 'signtool.exe not found; install the Windows SDK or pass -SignTool.' }
    }
  }
}
if ($ArtifactSigningMetadata) {
  $ArtifactSigningMetadata=(Resolve-Path -LiteralPath $ArtifactSigningMetadata).Path
  $metadata=Get-Content -LiteralPath $ArtifactSigningMetadata -Raw | ConvertFrom-Json
  foreach ($field in 'Endpoint','CodeSigningAccountName','CertificateProfileName') {
    if (!($metadata.PSObject.Properties.Name -contains $field) -or !$metadata.$field) { throw "Artifact Signing metadata lacks $field." }
  }
  if ($metadata.Endpoint -notmatch '^https://[a-z0-9]+\.codesigning\.azure\.net/?$') { throw 'Artifact Signing Endpoint must be https://<region>.codesigning.azure.net' }
  if (!$ArtifactSigningDlib) {
    # The client tools install under %LOCALAPPDATA% by default; the dlib must
    # match signtool's architecture (x64).
    $roots=@("$env:LOCALAPPDATA\Microsoft\MicrosoftArtifactSigningClientTools","$env:ProgramFiles\Microsoft\MicrosoftArtifactSigningClientTools","${env:ProgramFiles(x86)}\Microsoft\MicrosoftArtifactSigningClientTools") | Where-Object { Test-Path -LiteralPath $_ }
    $candidates=@($roots | ForEach-Object { Get-ChildItem -LiteralPath $_ -Recurse -Filter 'Azure.CodeSigning.Dlib.dll' -ErrorAction SilentlyContinue })
    $ArtifactSigningDlib=($candidates | Where-Object { $_.FullName -notmatch '\\x86\\' } | Select-Object -First 1).FullName
    if (!$ArtifactSigningDlib) { throw 'Azure.CodeSigning.Dlib.dll not found; install Microsoft.Azure.ArtifactSigningClientTools or pass -ArtifactSigningDlib.' }
  }
  if (!(Test-Path -LiteralPath $ArtifactSigningDlib)) { throw "Artifact Signing dlib not found: $ArtifactSigningDlib" }
  # Artifact Signing certificates last three days; the timestamp keeps signatures valid.
  if (!$TimestampUrl) { $TimestampUrl='http://timestamp.acs.microsoft.com' }
}
function Sign([string]$File) {
  if ($Unsigned) { return }
  $a=@('sign','/fd','SHA256','/tr',$TimestampUrl,'/td','SHA256')
  if ($ArtifactSigningMetadata) {
    $a += @('/dlib',$ArtifactSigningDlib,'/dmdf',$ArtifactSigningMetadata)
  } else {
    $a += @('/sha1',$CertificateThumbprint,'/s','My')
    if ($MachineStore) { $a += '/sm' }
    # The installed token CSP/KSP prompts for its PIN. No exported key or PIN argument.
  }
  Checked $SignTool ($a + $File)
  Checked $SignTool @('verify','/pa','/all','/v',$File)
}
$repo=Resolve-Path "$PSScriptRoot\..\.."
# VERSION is the single source of the release version.
$version=(Get-Content -LiteralPath (Join-Path $repo 'VERSION') -Raw).Trim()
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw "Invalid VERSION: $version" }
$oldSetupPlatform=$env:SETUP_PLATFORM; $oldSetupArch=$env:SETUP_ARCH
$oldOS=$env:GOOS; $oldArch=$env:GOARCH; $oldCGO=$env:CGO_ENABLED
Push-Location $repo
try {
  $out=Join-Path $repo "dist\windows-$Architecture"
  New-Item -ItemType Directory -Force $out | Out-Null
  $exe=Join-Path $out 'keen-posture.exe'
  $msi=Join-Path $out "keen-posture-$version-windows-$Architecture.msi"
  $env:GOOS='windows'; $env:GOARCH=$Architecture; $env:CGO_ENABLED='0'
  Checked 'go' @('build','-trimpath','-o',$exe,'./cmd/keen-posture')
  Sign $exe
  $helper=Join-Path $out 'keen-setup-helper.exe'
  Checked 'go' @('build','-trimpath','-o',$helper,'./cmd/keen-setup-helper')
  Sign $helper
  Checked 'npm.cmd' @('ci','--prefix','onboarding')
  Checked 'npm.cmd' @('test','--prefix','onboarding')
  $env:SETUP_PLATFORM='win32'; $env:SETUP_ARCH=if($Architecture -eq 'amd64'){'x64'}else{'arm64'}
  Checked 'npm.cmd' @('run','package','--prefix','onboarding')
  $setup=Join-Path $repo "dist\onboarding\KEEN Setup-win32-$($env:SETUP_ARCH)"
  # Sign the application and its executable helpers with the hardware-backed key.
  Get-ChildItem -LiteralPath $setup -Filter '*.exe' -Recurse | ForEach-Object { Sign $_.FullName }
  $fragment=Join-Path $out 'SetupFiles.wxs'
  Checked 'node' @('onboarding/wix-files.cjs',$setup,$fragment)
  $wixArch=if($Architecture -eq 'amd64'){'x64'}else{'arm64'}
  Checked $Wix @('build',"$PSScriptRoot\Product.wxs",$fragment,'-arch',$wixArch,'-d',"Binary=$exe",'-d',"SetupHelper=$helper",'-d',"Version=$version",'-o',$msi)
  Sign $msi
  Get-FileHash -Algorithm SHA256 $exe,$msi
} finally { $env:SETUP_PLATFORM=$oldSetupPlatform; $env:SETUP_ARCH=$oldSetupArch; $env:GOOS=$oldOS; $env:GOARCH=$oldArch; $env:CGO_ENABLED=$oldCGO; Pop-Location }
