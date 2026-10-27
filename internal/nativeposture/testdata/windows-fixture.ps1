# Portable mocked API test; not a Windows integration test. Run with pwsh -File.
$ErrorActionPreference='Stop'
function New-Object {
  param([string]$TypeName,[object[]]$ArgumentList)
  if($TypeName -eq 'Microsoft.Update.AutoUpdate') {
    return [pscustomobject]@{ Settings=[pscustomobject]@{NotificationLevel=4;ReadOnly=$false}; ServiceEnabled=$true; Results=[pscustomobject]@{LastSearchSuccessDate=[DateTime]'2026-10-20';LastInstallationSuccessDate=[DateTime]'2026-10-19'} }
  }
  Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
function Get-CimInstance {
  param($Namespace,$ClassName)
  if($ClassName -eq 'AntivirusProduct') { return [pscustomobject]@{instanceGuid='test-av';displayName='Fixture AV';productState=123} }
  return [pscustomobject]@{DriveLetter='C:';DeviceID='volume-fixture'}
}
function Invoke-CimMethod {
  param($InputObject,$MethodName)
  if($MethodName -eq 'GetProtectionStatus'){return [pscustomobject]@{ReturnValue=0;ProtectionStatus=2}}
  return [pscustomobject]@{ReturnValue=0;ConversionStatus=1;EncryptionPercentage=100}
}
function Get-NetFirewallProfile {param($PolicyStore); @([pscustomobject]@{Name='Domain';Enabled=2;DefaultInboundAction='NotConfigured';DefaultOutboundAction='NotConfigured'},[pscustomobject]@{Name='Public';Enabled=0;DefaultInboundAction='Block';DefaultOutboundAction='Allow'})}
function Get-MpComputerStatus { [pscustomobject]@{AMServiceEnabled=$true;AntivirusEnabled=$true;RealTimeProtectionEnabled=$false;AntivirusSignatureLastUpdated=[DateTime]'2026-10-20';AntivirusSignatureAge=1;QuickScanEndTime=$null;FullScanEndTime=$null;AMRunningMode='Passive'} }
function Get-ItemProperty {
  [CmdletBinding()] param([Parameter(Position=0)]$Path)
  if($Path -like '*Policies\System'){return [pscustomobject]@{InactivityTimeoutSecs=300}}
  if($Path -like '*Policies*Control Panel\Desktop'){return [pscustomobject]@{ScreenSaveActive='1';ScreenSaverIsSecure='1';ScreenSaveTimeOut='300'}}
  if($Path -like '*Control Panel\Desktop'){return [pscustomobject]@{ScreenSaveActive='0';ScreenSaverIsSecure='0';ScreenSaveTimeOut='0'}}
  if($Path -like '*PolicyManager*'){return [pscustomobject]@{AllowAutoUpdate=4}}
  return [pscustomobject]@{NoAutoUpdate=0;AUOptions=4}
}
function Get-ChildItem {param($Path); [pscustomobject]@{PSChildName='S-1-12-1-1-2-3-4'} }
$result = & "$PSScriptRoot/../windows-report.ps1" | ConvertFrom-Json
$disk=@($result | Where-Object provider -eq bitlocker)[0]
if($disk.facts.fully_encrypted -ne 'true' -or $null -ne $disk.facts.protection_enabled){throw 'BitLocker unknown protection misclassified'}
$domain=@($result | Where-Object scope -eq Domain)[0]
if($null -ne $domain.facts.enabled){throw 'NotConfigured firewall misclassified'}
$public=@($result | Where-Object scope -eq Public)[0]
if($public.facts.enabled -ne 'false'){throw 'Disabled firewall lost'}
$user=@($result | Where-Object provider -eq windows_user_policy)[0]
if($user.facts.password_required -ne 'true' -or $user.scope -ne 'S-1-12-1-1-2-3-4'){throw 'Entra/policy precedence failed'}
$defender=@($result | Where-Object provider -eq microsoft_defender)[0]
if($defender.facts.real_time_protection_enabled -ne 'false'){throw 'Passive mode lost'}
Write-Output 'Windows mocked API checks passed'
