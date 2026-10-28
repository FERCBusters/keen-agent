# Run elevated after MSI installation, as an alternative to the KEEN Setup app.
# The enrolment code is read masked, never passed as an argument, used once by
# keen-posture to bind the device's own key, and deleted afterwards.
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
foreach($name in @('config.json','state')) { $p=Join-Path $root $name; if(Test-Path -LiteralPath $p){throw "Existing $name; remove the device's KEEN state deliberately before enrolling it again."} }
New-Item -ItemType Directory -Path (Join-Path $root 'state') | Out-Null
$code=Join-Path $root 'enrollment-code'
$secret=Read-Host 'KEEN enrolment code' -AsSecureString
$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
  $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  if ($plain -notmatch '^kc_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$') { throw 'That is not a KEEN enrolment code.' }
  [IO.File]::WriteAllText($code,$plain,(New-Object Text.UTF8Encoding($false)))
} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $plain=$null }
$config=Join-Path $root 'config.json'
@{ endpoint=$Endpoint.AbsoluteUri; state_dir=(Join-Path $root 'state'); enrollment_code_file=$code; interval_seconds=3600 } | ConvertTo-Json | ForEach-Object { [IO.File]::WriteAllText($config,$_,(New-Object Text.UTF8Encoding($false))) }
# Explicit owner and DACL also cover non-default administrator token ownership.
foreach ($path in @($config,$code)) {
    $fileAcl=New-Object System.Security.AccessControl.FileSecurity
    $fileAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath $path -AclObject $fileAcl
}
Set-Acl -LiteralPath (Join-Path $root 'state') -AclObject $acl
$exe=Join-Path ${env:ProgramFiles} 'KEEN Posture\keen-posture.exe'
try {
  & $exe -command enroll -config $config
  if ($LASTEXITCODE -ne 0) { throw "Enrolment failed ($LASTEXITCODE); the code can be retried until it expires." }
  # The device's key is now its credential; the code cannot be used again.
  @{ endpoint=$Endpoint.AbsoluteUri; state_dir=(Join-Path $root 'state'); interval_seconds=3600 } | ConvertTo-Json | ForEach-Object { [IO.File]::WriteAllText($config,$_,(New-Object Text.UTF8Encoding($false))) }
} finally { Remove-Item -LiteralPath $code -Force -ErrorAction SilentlyContinue }
Set-Service KeenPosture -StartupType Automatic
Start-Service KeenPosture
