# Portable mocked API test; not a Windows integration test. Run with pwsh -File.
$ErrorActionPreference='Stop'
$global:FixtureRegistry = @{}
$global:FixturePowerPlan = $null
$global:FixturePowerIndexes = @()
function New-Object {
  param([string]$TypeName,[object[]]$ArgumentList)
  if($TypeName -eq 'Microsoft.Update.AutoUpdate') {
    return [pscustomobject]@{ Settings=[pscustomobject]@{NotificationLevel=4;ReadOnly=$false}; ServiceEnabled=$true; Results=[pscustomobject]@{LastSearchSuccessDate=[DateTime]'2026-10-20';LastInstallationSuccessDate=[DateTime]'2026-10-19'} }
  }
  Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
}
function Get-CimInstance {
  param($Namespace,$ClassName,$Filter)
  if($ClassName -eq 'AntivirusProduct') { return [pscustomobject]@{instanceGuid='test-av';displayName='Fixture AV';productState=123} }
  if($ClassName -eq 'Win32_PowerPlan') { return $global:FixturePowerPlan }
  if($ClassName -eq 'Win32_PowerSettingDataIndex') {
    if($Filter -notmatch "^InstanceID LIKE '%\{[0-9a-f-]{36}\}%[0-9a-f-]{36}%'$"){throw "unexpected filter $Filter"}
    $guid = ($Filter -split '%')[2]
    return @($global:FixturePowerIndexes | Where-Object { $_.InstanceID -like "*$guid*" })
  }
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
  foreach($pattern in @($global:FixtureRegistry.Keys | Sort-Object Length -Descending)){ if($Path -like $pattern){ return $global:FixtureRegistry[$pattern] } }
  if($Path -like '*Policies\Microsoft\Power\PowerSettings\*'){ return $null }
  if($Path -like '*PolicyManager*'){return [pscustomobject]@{AllowAutoUpdate=4}}
  if($Path -like '*WindowsUpdate\AU'){return [pscustomobject]@{NoAutoUpdate=0;AUOptions=4}}
  return $null
}
function Get-ChildItem {param($Path); [pscustomobject]@{PSChildName='S-1-12-1-1-2-3-4'} }
$plan = '{381b4222-f694-41f0-9685-ff5bb260df2e}'
$lock = '0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
$sleep = '29f6c1db-86da-48c5-9fdb-f2b67b1f44da'
function Set-Plan($Values) {
  $global:FixturePowerPlan = @([pscustomobject]@{InstanceID="Microsoft:PowerPlan\{a1841308-3541-4fab-bc81-f71556f20b4a}";IsActive=$false},[pscustomobject]@{InstanceID="Microsoft:PowerPlan\$plan";IsActive=$true})
  $global:FixturePowerIndexes = @(foreach($key in $Values.Keys){
    $parts = $key -split ':'
    [pscustomobject]@{InstanceID="Microsoft:PowerSettingDataIndex\$plan\$($parts[0])\{$($parts[1])}";SettingIndexValue=$Values[$key]}
  })
}
function Invoke-Scenario($Name, $Registry, $Capabilities, $PlanValues) {
  $global:FixtureRegistry = $Registry
  Set-Plan $PlanValues
  $global:keenPowerCapabilities = $Capabilities
  $result = & "$PSScriptRoot/../windows-report.ps1" | ConvertFrom-Json
  $user = @($result | Where-Object provider -eq windows_user_policy)
  if($user.Count -ne 1 -or $user[0].scope -ne 'S-1-12-1-1-2-3-4'){throw "$($Name): user observation missing"}
  return @{ all=$result; user=$user[0].facts; machine=@($result | Where-Object provider -eq windows_machine_policy) }
}
$desktopDefault = @{ '*\Control Panel\Desktop'=[pscustomobject]@{ScreenSaveActive='1'} }
$s3Desktop = @{sleep_supported=$true;modern_standby=$false;batteries_present=$false}
$defaultPlan = @{ "AC:$lock"=1; "DC:$lock"=1; "AC:$sleep"=1800; "DC:$sleep"=900 }

# Policy precedence, machine inactivity and a secure screen saver.
$r = Invoke-Scenario 'policy' @{
  '*Policies\System'=[pscustomobject]@{InactivityTimeoutSecs=300}
  '*Policies*Control Panel\Desktop'=[pscustomobject]@{ScreenSaveActive='1';ScreenSaverIsSecure='1';ScreenSaveTimeOut='600';'SCRNSAVE.EXE'='C:\Windows\system32\Fixture.scr'}
  '*\Control Panel\Desktop'=[pscustomobject]@{ScreenSaveActive='0';ScreenSaverIsSecure='0';ScreenSaveTimeOut='0'}
} $null @{}
$disk=@($r.all | Where-Object provider -eq bitlocker)[0]
if($disk.facts.fully_encrypted -ne 'true' -or $null -ne $disk.facts.protection_enabled){throw 'BitLocker unknown protection misclassified'}
$domain=@($r.all | Where-Object scope -eq Domain)[0]
if($null -ne $domain.facts.enabled){throw 'NotConfigured firewall misclassified'}
$public=@($r.all | Where-Object scope -eq Public)[0]
if($public.facts.enabled -ne 'false'){throw 'Disabled firewall lost'}
$defender=@($r.all | Where-Object provider -eq microsoft_defender)[0]
if($defender.facts.real_time_protection_enabled -ne 'false'){throw 'Passive mode lost'}
if($r.user.password_required -ne 'true' -or $r.user.screensaver_selected -ne 'true'){throw 'Entra/policy precedence failed'}
if($r.user.automatic_lock_configured -ne 'true' -or $r.user.lock_after_seconds -ne '300' -or $r.user.lock_paths -ne 'machine_inactivity_policy,secure_screen_saver'){throw "combined lock paths wrong: $($r.user | ConvertTo-Json -Compress)"}
if($r.machine.Count -ne 1 -or $r.machine[0].facts.automatic_lock_configured -ne 'true'){throw 'machine policy lost'}
if(($r.user | ConvertTo-Json) -match 'Fixture\.scr'){throw 'screen saver path disclosed'}
if(-not @($r.all | Where-Object { $_.provider -eq 'windows_power_capabilities' -and $_.status -eq 'unknown' })){throw 'missing capabilities not diagnosed'}

# The default profile: ScreenSaveActive=1 alone, no screen saver and no sleep path.
$r = Invoke-Scenario 'default' $desktopDefault $null @{}
if($r.user.saver_enabled -ne 'true' -or $r.user.screensaver_selected -ne 'false' -or $null -ne $r.user.automatic_lock_configured){throw "default profile misclassified: $($r.user | ConvertTo-Json -Compress)"}

# A zero machine limit disables that path only and is not reported as a failure.
$r = Invoke-Scenario 'zero-limit' (@{ '*Policies\System'=[pscustomobject]@{InactivityTimeoutSecs=0} } + $desktopDefault) $s3Desktop $defaultPlan
if($r.machine.Count -ne 0 -or $r.user.machine_inactivity_seconds -ne '0'){throw 'zero machine limit misreported'}
# ...and a desktop without batteries locks through sleep on mains power.
if($r.user.automatic_lock_configured -ne 'true' -or $r.user.lock_paths -ne 'sleep_with_sign_in' -or $r.user.lock_after_seconds -ne '1800'){throw "sleep path lost: $($r.user | ConvertTo-Json -Compress)"}

# A laptop must lock on both sources; the longest timeout applies.
$laptop = @{sleep_supported=$true;modern_standby=$false;batteries_present=$true}
$r = Invoke-Scenario 'laptop' $desktopDefault $laptop $defaultPlan
if($r.user.lock_after_seconds -ne '1800' -or $r.user.batteries_present -ne 'true'){throw 'laptop sleep path wrong'}
$r = Invoke-Scenario 'laptop-dc-never' $desktopDefault $laptop @{ "AC:$lock"=1; "DC:$lock"=1; "AC:$sleep"=1800; "DC:$sleep"=0 }
if($null -ne $r.user.automatic_lock_configured){throw 'battery source without sleep accepted'}

# Group Policy overrides the plan; no sign-in on wake means no sleep path.
$r = Invoke-Scenario 'policy-no-sign-in' (@{ "*PowerSettings\$lock"=[pscustomobject]@{ACSettingIndex=0} } + $desktopDefault) $s3Desktop $defaultPlan
if($r.user.wake_sign_in_ac -ne 'false' -or $null -ne $r.user.automatic_lock_configured){throw 'power policy precedence failed'}

# Modern Standby and platforms without sleep are not confirmed through this path.
foreach($caps in @(@{sleep_supported=$true;modern_standby=$true;batteries_present=$true},@{sleep_supported=$false;modern_standby=$false;batteries_present=$false})){
  $r = Invoke-Scenario 'no-s3' $desktopDefault $caps $defaultPlan
  if($null -ne $r.user.automatic_lock_configured){throw 'unconfirmed sleep platform accepted'}
}
# A "never" sentinel and malformed values are not timeouts.
$r = Invoke-Scenario 'never' $desktopDefault $s3Desktop @{ "AC:$lock"=1; "AC:$sleep"=4294967295 }
if($null -ne $r.user.automatic_lock_configured){throw 'never sentinel accepted'}
$r = Invoke-Scenario 'malformed' $desktopDefault @{sleep_supported='yes';modern_standby=$false;batteries_present=$false} $defaultPlan
if($null -ne $r.user.sleep_supported -or $null -ne $r.user.automatic_lock_configured){throw 'non-boolean capability accepted'}
Write-Output 'Windows mocked API checks passed'
