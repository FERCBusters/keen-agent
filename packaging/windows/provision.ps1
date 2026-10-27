# Run elevated after MSI installation. Token input is masked and never a CLI argument.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][uri]$Endpoint)
$ErrorActionPreference='Stop'
if ($Endpoint.Scheme -ne 'https' -or !$Endpoint.AbsolutePath.EndsWith('/v1/otlp/logs') -or $Endpoint.UserInfo -or $Endpoint.Query -or $Endpoint.Fragment) { throw 'Expected HTTPS ingestion endpoint without query, credentials or fragment.' }
$root=Join-Path $env:ProgramData 'KEEN\Posture'
# Refuse existing links/junctions before touching files as SYSTEM/Administrator.
for ($p=$root; $p; $p=Split-Path -Parent $p) {
  if ((Test-Path -LiteralPath $p) -and ((Get-Item -Force -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse point in private path' }
  if ($p -eq (Split-Path -Parent $p)) { break }
}
New-Item -ItemType Directory -Force $root | Out-Null
$acl=New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
Set-Acl -LiteralPath $root -AclObject $acl
foreach($name in @('config.json','token','state')) { $p=Join-Path $root $name; if(Test-Path -LiteralPath $p){throw "Existing $name; use an explicit rotation/edit procedure instead."} }
New-Item -ItemType Directory -Path (Join-Path $root 'state') | Out-Null
$secret=Read-Host 'KEEN agent bearer token' -AsSecureString
$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
  $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  [IO.File]::WriteAllText((Join-Path $root 'token'),$plain,(New-Object Text.UTF8Encoding($false)))
} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $plain=$null }
@{ endpoint=$Endpoint.AbsoluteUri; token_file=(Join-Path $root 'token'); state_dir=(Join-Path $root 'state'); interval_seconds=3600 } | ConvertTo-Json | ForEach-Object { [IO.File]::WriteAllText((Join-Path $root 'config.json'),$_,(New-Object Text.UTF8Encoding($false))) }
# Explicit owner and DACL also cover non-default administrator token ownership.
foreach ($name in @('config.json','token')) {
    $fileAcl=New-Object System.Security.AccessControl.FileSecurity
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath (Join-Path $root $name) -AclObject $fileAcl
}
Set-Acl -LiteralPath (Join-Path $root 'state') -AclObject $acl
Set-Service KeenPosture -StartupType Automatic
Start-Service KeenPosture
