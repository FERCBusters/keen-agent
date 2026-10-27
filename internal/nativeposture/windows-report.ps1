# Embedded in keen-posture.exe. Read-only, Windows PowerShell 5.1 compatible.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$items = New-Object 'System.Collections.Generic.List[object]'
function Add-Observation($Check, $Provider, $Scope, $Facts, $Reason = 'settings_observed') {
    $f = @{}
    foreach ($key in $Facts.Keys) {
        $v = $Facts[$key]
        if ($null -eq $v) { continue }
        if ($v -is [bool]) { $f[$key] = $v.ToString().ToLowerInvariant() }
        elseif ($v -is [DateTime]) { $f[$key] = $v.ToUniversalTime().ToString('o') }
        else { $f[$key] = [string]$v }
    }
    $items.Add(@{version=1;check=$Check;provider=$Provider;scope=$Scope;status='observed';reason=$Reason;facts=$f})
}
function Add-Diagnostic($Check, $Provider) {
    $items.Add(@{version=1;check=$Check;provider=$Provider;scope='host';status='unknown';reason='query_unavailable';facts=@{}})
}
# Query WMI methods; never return BitLocker recovery passwords/key protectors.
try {
    $volumes = @(Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume)
    foreach ($v in $volumes) {
        try {
            $p = Invoke-CimMethod -InputObject $v -MethodName GetProtectionStatus
            $c = Invoke-CimMethod -InputObject $v -MethodName GetConversionStatus
            if ($p.ReturnValue -ne 0 -or $c.ReturnValue -ne 0) { throw 'query failed' }
            $scope = if ($v.DriveLetter) { [string]$v.DriveLetter } else { [string]$v.DeviceID }
            $facts = @{ encryption_percentage=$c.EncryptionPercentage; conversion_status=$c.ConversionStatus; protection_status=$p.ProtectionStatus }
            if ($c.ConversionStatus -ge 0 -and $c.ConversionStatus -le 5) { $facts['fully_encrypted']=($c.ConversionStatus -eq 1) }
            if ($p.ProtectionStatus -in @(0,1)) { $facts['protection_enabled']=($p.ProtectionStatus -eq 1) }
            Add-Observation disk_encryption bitlocker $scope $facts 'volume_status_observed'
        } catch { Add-Diagnostic disk_encryption bitlocker }
    }
} catch { Add-Diagnostic disk_encryption bitlocker }
try {
    foreach ($p in @(Get-NetFirewallProfile -PolicyStore ActiveStore)) {
        $facts = @{ enabled_raw=[int]$p.Enabled; default_inbound_action=$p.DefaultInboundAction; default_outbound_action=$p.DefaultOutboundAction }
        if ([int]$p.Enabled -in @(0,1)) { $facts['enabled']=([int]$p.Enabled -eq 1) }
        Add-Observation firewall windows_firewall ([string]$p.Name) $facts 'active_profile_policy_observed'
    }
} catch { Add-Diagnostic firewall windows_firewall }
try {
    $d = Get-MpComputerStatus
    Add-Observation antivirus microsoft_defender host @{
        service_enabled=$d.AMServiceEnabled; antivirus_enabled=$d.AntivirusEnabled
        real_time_protection_enabled=$d.RealTimeProtectionEnabled
        signatures_updated=$d.AntivirusSignatureLastUpdated; signatures_age_days=$d.AntivirusSignatureAge
        quick_scan_finished=$d.QuickScanEndTime; full_scan_finished=$d.FullScanEndTime
        running_mode=$d.AMRunningMode
    } 'components_detected'
} catch { Add-Diagnostic antivirus microsoft_defender }
# SecurityCenter2 is unavailable on many Server editions. Do not infer absence.
try {
    foreach ($a in @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct)) {
        Add-Observation antivirus windows_security_center ([string]$a.instanceGuid) @{
            product_name=$a.displayName; product_state_raw=$a.productState
        } 'product_registered'
    }
} catch { Add-Diagnostic antivirus windows_security_center }
try {
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate
    $settings = $au.Settings
    $facts = @{notification_level=$settings.NotificationLevel; service_enabled=$au.ServiceEnabled; read_only=$settings.ReadOnly}
    # Level 4 is scheduled installation, 3 is download/notify. No Search()/DetectNow().
    if ($settings.NotificationLevel -in @(1,2,3,4)) { $facts['legacy_scheduled_install_configured'] = ($settings.NotificationLevel -eq 4) }
    $results = $au.Results
    if ($results.LastSearchSuccessDate) { $facts['last_search_success']=$results.LastSearchSuccessDate }
    if ($results.LastInstallationSuccessDate) { $facts['last_install_success']=$results.LastInstallationSuccessDate }
    $policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($policy) {
        if ($null -ne $policy.NoAutoUpdate) { $facts['policy_no_auto_update']=$policy.NoAutoUpdate }
        if ($null -ne $policy.AUOptions) { $facts['policy_au_options']=$policy.AUOptions }
    }
    Add-Observation automatic_updates windows_update host $facts 'update_settings_and_history_observed'
} catch { Add-Diagnostic automatic_updates windows_update }
# Modern MDM update policy; keep distinct from legacy WUA preferences.
try {
    $mdm = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $facts = @{}
    foreach ($key in @('AllowAutoUpdate','AllowMUUpdateService','PauseQualityUpdatesStartTime','PauseFeatureUpdatesStartTime')) {
        if ($null -ne $mdm.$key) { $facts[$key.ToLowerInvariant()]=$mdm.$key }
    }
    if ($facts.Count -gt 0) { Add-Observation automatic_updates windows_mdm_update host $facts 'managed_update_policy_observed' }
} catch { Add-Diagnostic automatic_updates windows_mdm_update }
try {
    $system = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if ($null -ne $system.InactivityTimeoutSecs) {
        Add-Observation screen_lock windows_machine_policy host @{
            inactivity_seconds=$system.InactivityTimeoutSecs; automatic_lock_configured=($system.InactivityTimeoutSecs -gt 0)
        } 'machine_inactivity_policy_observed'
    }
    # Loaded user hives only. Never load offline hives or inspect other user data.
    $hives = @(Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^(S-1-5-21-(\d+-){3}\d+|S-1-12-1-(\d+-){3}\d+)$' })
    foreach ($hive in $hives) {
        $sid = $hive.PSChildName
        $user = Get-ItemProperty "Registry::HKEY_USERS\$sid\Control Panel\Desktop" -ErrorAction SilentlyContinue
        $policy = Get-ItemProperty "Registry::HKEY_USERS\$sid\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ErrorAction SilentlyContinue
        $facts = @{}
        foreach ($pair in @(@('ScreenSaveActive','saver_enabled'),@('ScreenSaverIsSecure','password_required'),@('ScreenSaveTimeOut','idle_seconds'))) {
            $value = $null
            if ($policy -and $null -ne $policy.($pair[0])) { $value = $policy.($pair[0]) }
            elseif ($user -and $null -ne $user.($pair[0])) { $value = $user.($pair[0]) }
            if ($null -ne $value) {
                if ($pair[0] -eq 'ScreenSaveTimeOut') { $facts[$pair[1]] = $value }
                else { $facts[$pair[1]] = ([string]$value -eq '1') }
            }
        }
        if ($facts.Count -gt 0) { Add-Observation screen_lock windows_user_policy $sid $facts 'user_screensaver_settings_observed' }
    }
} catch { Add-Diagnostic screen_lock windows_policy }
ConvertTo-Json -InputObject @($items.ToArray()) -Depth 8 -Compress
