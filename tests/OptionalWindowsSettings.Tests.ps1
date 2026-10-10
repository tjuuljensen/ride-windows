<#
.SYNOPSIS
  Verify the optional Windows setting registry migration with isolated state fixtures.

.DESCRIPTION
  Checks legacy mappings, explicit and baseline states, planning, preview, repeat apply,
  saved snapshots by scope, restoration dispatch, and recoverable failures. Registry reads and
  writes are mocked; saved runs use TestDrive. No application or shell process is restarted.

.EXAMPLE
  Invoke-Pester .\tests\OptionalWindowsSettings.Tests.ps1

.INPUTS
  None. Pester supplies test case data.

.OUTPUTS
  Pester test results.

.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Repository catalog and engine modules.
  Recovery: TestDrive contains all generated state; system calls are mocked.
  Author: RIDE-Windows maintainers.
  Version: Repository test fixture; no independent CLI version.
  Changelog: 2026-10-09: Cover twenty optional Windows settings and saved-run recovery,
    including inverted, multi-state and corrected user-policy mappings.
    Follow-up: Cover forty further independent settings and partial legacy replacements.
#>

BeforeDiscovery {
  $settingCases = @(
    @{ Id = 'windows.content-delivery'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'ContentDeliveryAllowed'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.oem-preinstalled-app-suggestions'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'OemPreInstalledAppsEnabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.preinstalled-app-suggestions'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'PreInstalledAppsEnabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.silent-app-installation'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SilentInstalledAppsEnabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-310093'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-310093Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-314559'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-314559Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-338387'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-338387Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-338388'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-338388Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-338389'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-338389Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-338393'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-338393Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-353694'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-353694Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-353696'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-353696Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.suggested-content-353698'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SubscribedContent-353698Enabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.settings-pane-suggestions'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; ValueName = 'SystemPaneSuggestionsEnabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.post-setup-suggestions'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement'; ValueName = 'ScoobeSystemSettingEnabled'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.implicit-text-personalization'; Path = 'HKCU:\Software\Microsoft\InputPersonalization'; ValueName = 'RestrictImplicitTextCollection'; Scope = 'User'; On = 'Restricted'; Off = 'Allowed'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Restricted = 1; Allowed = 0 } }
    @{ Id = 'windows.implicit-ink-personalization'; Path = 'HKCU:\Software\Microsoft\InputPersonalization'; ValueName = 'RestrictImplicitInkCollection'; Scope = 'User'; On = 'Restricted'; Off = 'Allowed'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Restricted = 1; Allowed = 0 } }
    @{ Id = 'windows.input-personalization-contact-harvesting'; Path = 'HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore'; ValueName = 'HarvestContacts'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.diagnostic-data-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName = 'AllowTelemetry'; Scope = 'Machine'; On = 'Off'; Off = 'Required'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Off = 0; Required = 1; Optional = 3 } }
    @{ Id = 'windows.linguistic-data-collection-policy'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'; ValueName = 'AllowLinguisticDataCollection'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.feedback-notifications-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; ValueName = 'DoNotShowFeedbackNotifications'; Scope = 'Machine'; On = 'Disabled'; Off = 'Allowed'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Allowed = 0 } }
    @{ Id = 'windows.error-reporting'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'; ValueName = 'Disabled'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Enabled = 0 } }
    @{ Id = 'windows.ncsi-active-probing'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet'; ValueName = 'EnableActiveProbing'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.msrt-update-offering'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\MRT'; ValueName = 'DontOfferThroughWUAU'; Scope = 'Machine'; On = 'Disabled'; Off = 'Allowed'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Allowed = 0 } }
    @{ Id = 'windows.update-driver-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; ValueName = 'ExcludeWUDriversInQualityUpdate'; Scope = 'Machine'; On = 'Excluded'; Off = 'Included'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Excluded = 1; Included = 0 } }
    @{ Id = 'windows.device-metadata-downloads'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'; ValueName = 'PreventDeviceMetadataFromNetwork'; Scope = 'Machine'; On = 'Prevented'; Off = 'UserChoice'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Prevented = 1; UserChoice = 0 } }
    @{ Id = 'windows.update-download-mode'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; ValueName = 'AUOptions'; Scope = 'Machine'; On = 'NotifyDownload'; Off = 'AutoDownload'; OnValue = 2; OffValue = 3; ExpectedStates = @{ NotifyDownload = 2; AutoDownload = 3 } }
    @{ Id = 'windows.automatic-restart-sign-on'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'DisableAutomaticRestartSignOn'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Enabled = 0 } }
    @{ Id = 'windows.storage-sense'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'; ValueName = '01'; Scope = 'User'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Enabled = 1; Disabled = 0 } }
    @{ Id = 'windows.recycle-bin-policy'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName = 'NoRecycleFiles'; Scope = 'User'; On = 'Bypass'; Off = 'UseRecycleBin'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Bypass = 1; UseRecycleBin = 0 } }
    @{ Id = 'windows.lock-screen-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; ValueName = 'NoLockScreen'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Enabled = 0 } }
    @{ Id = 'windows.verbose-logon-status'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'VerboseStatus'; Scope = 'Machine'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Enabled = 1; Disabled = 0 } }
    @{ Id = 'windows.linked-mapped-drives'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'EnableLinkedConnections'; Scope = 'Machine'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Enabled = 1; Disabled = 0 } }
    @{ Id = 'windows.attachment-zone-information'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; ValueName = 'SaveZoneInformation'; Scope = 'User'; On = 'Discard'; Off = 'Preserve'; OnValue = 1; OffValue = 2; ExpectedStates = @{ Discard = 1; Preserve = 2 } }
    @{ Id = 'windows.desktop-recycle-bin-icon'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'; ValueName = '{645FF040-5081-101B-9F08-00AA002F954E}'; Scope = 'User'; On = 'Shown'; Off = 'Hidden'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Shown = 0; Hidden = 1 } }
    @{ Id = 'windows.desktop-this-pc-icon'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'; ValueName = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'; Scope = 'User'; On = 'Shown'; Off = 'Hidden'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Shown = 0; Hidden = 1 } }
    @{ Id = 'windows.desktop-user-files-icon'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'; ValueName = '{59031a47-3f72-44a7-89c5-5595fe6b30ee}'; Scope = 'User'; On = 'Shown'; Off = 'Hidden'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Shown = 0; Hidden = 1 } }
    @{ Id = 'windows.desktop-control-panel-icon'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'; ValueName = '{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}'; Scope = 'User'; On = 'Shown'; Off = 'Hidden'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Shown = 0; Hidden = 1 } }
    @{ Id = 'windows.desktop-network-icon'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'; ValueName = '{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}'; Scope = 'User'; On = 'Shown'; Off = 'Hidden'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Shown = 0; Hidden = 1 } }
    @{ Id = 'windows.desktop-build-number'; Path = 'HKCU:\Control Panel\Desktop'; ValueName = 'PaintDesktopVersion'; Scope = 'User'; On = 'Shown'; Off = 'Hidden'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Shown = 1; Hidden = 0 } }
    @{ Id = 'windows.lock-screen-network-selection'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; ValueName = 'DontDisplayNetworkSelectionUI'; Scope = 'Machine'; On = 'Hidden'; Off = 'Shown'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Hidden = 1; Shown = 0 } }
    @{ Id = 'windows.shutdown-without-logon'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; ValueName = 'ShutdownWithoutLogon'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.title-bar-shake'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; ValueName = 'DisallowShaking'; Scope = 'User'; On = 'Disabled'; Off = 'Enabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Enabled = 0 } }
    @{ Id = 'windows.start-recently-added-apps'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; ValueName = 'HideRecentlyAddedApps'; Scope = 'Machine'; On = 'Hidden'; Off = 'UserChoice'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Hidden = 1; UserChoice = 0 } }
    @{ Id = 'windows.title-bar-accent-color'; Path = 'HKCU:\Software\Microsoft\Windows\DWM'; ValueName = 'ColorPrevalence'; Scope = 'User'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Enabled = 1; Disabled = 0 } }
    @{ Id = 'windows.app-color-mode'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; ValueName = 'AppsUseLightTheme'; Scope = 'User'; On = 'Dark'; Off = 'Light'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Dark = 0; Light = 1 } }
    @{ Id = 'windows.system-color-mode'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; ValueName = 'SystemUsesLightTheme'; Scope = 'User'; On = 'Dark'; Off = 'Light'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Dark = 0; Light = 1 } }
    @{ Id = 'windows.sound-scheme-change-policy'; Path = 'HKCU:\Software\Policies\Microsoft\Windows\Personalization'; ValueName = 'NoChangingSoundScheme'; Scope = 'User'; On = 'Blocked'; Off = 'Allowed'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Blocked = 1; Allowed = 0 } }
    @{ Id = 'windows.taskbar-alignment'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; ValueName = 'TaskbarAl'; Scope = 'User'; On = 'Left'; Off = 'Centered'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Left = 0; Centered = 1 } }
    @{ Id = 'windows.sensors-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; ValueName = 'DisableSensors'; Scope = 'Machine'; On = 'Disabled'; Off = 'Allowed'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Allowed = 0 } }
    @{ Id = 'windows.biometrics-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics'; ValueName = 'Enabled'; Scope = 'Machine'; On = 'Disabled'; Off = 'Allowed'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Allowed = 1 } }
    @{ Id = 'windows.app-camera-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; ValueName = 'LetAppsAccessCamera'; Scope = 'Machine'; On = 'ForceDeny'; Off = 'ForceAllow'; OnValue = 2; OffValue = 1; ExpectedStates = @{ ForceDeny = 2; ForceAllow = 1; UserControl = 0 } }
    @{ Id = 'windows.app-microphone-policy'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; ValueName = 'LetAppsAccessMicrophone'; Scope = 'Machine'; On = 'ForceDeny'; Off = 'ForceAllow'; OnValue = 2; OffValue = 1; ExpectedStates = @{ ForceDeny = 2; ForceAllow = 1; UserControl = 0 } }
    @{ Id = 'windows.delivery-optimization-download-mode'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; ValueName = 'DODownloadMode'; Scope = 'Machine'; On = 'HttpOnly'; Off = 'LocalNetwork'; OnValue = 0; OffValue = 1; ExpectedStates = @{ HttpOnly = 0; LocalNetwork = 1; Internet = 3 } }
    @{ Id = 'windows.clear-recent-documents-on-exit'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName = 'ClearRecentDocsOnExit'; Scope = 'User'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Enabled = 1; Disabled = 0 } }
    @{ Id = 'windows.recent-document-history-policy'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; ValueName = 'NoRecentDocsHistory'; Scope = 'Machine'; On = 'Disabled'; Off = 'Allowed'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Disabled = 1; Allowed = 0 } }
    @{ Id = 'windows.fast-startup'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'; ValueName = 'HiberbootEnabled'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.auto-reboot-on-crash'; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'; ValueName = 'AutoReboot'; Scope = 'Machine'; On = 'Disabled'; Off = 'Enabled'; OnValue = 0; OffValue = 1; ExpectedStates = @{ Disabled = 0; Enabled = 1 } }
    @{ Id = 'windows.clipboard-history'; Path = 'HKCU:\Software\Microsoft\Clipboard'; ValueName = 'EnableClipboardHistory'; Scope = 'User'; On = 'Enabled'; Off = 'Disabled'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Enabled = 1; Disabled = 0 } }
    @{ Id = 'windows.navigation-pane-libraries'; Path = 'HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}'; ValueName = 'System.IsPinnedToNameSpaceTree'; Scope = 'User'; On = 'Shown'; Off = 'Hidden'; OnValue = 1; OffValue = 0; ExpectedStates = @{ Shown = 1; Hidden = 0 } }
  )
}

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  $script:DefaultProfile = Get-RideProfile -Path (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
}

Describe 'Optional Windows settings registry metadata' {
  It 'maps <Id> to the legacy value and keeps the selection optional' -ForEach $settingCases {
    $operation = Get-RideOperation -Id $Id
    $operation.RegistryPath | Should -Be $Path
    $operation.ValueName | Should -Be $ValueName
    $operation.ValueType | Should -Be 'DWord'
    $operation.Kind | Should -Be 'RegistryValue'
    $operation.Handler | Should -Be 'RegistryValue'
    $operation.Scope | Should -Be $Scope
    $operation.RequiresAdmin | Should -Be ($Scope -eq 'Machine')
    $operation.Rollback | Should -Be 'Exact'
    $operation.SupportedTargets | Should -Be @('Windows 11')
    $operation.States[$On] | Should -Be $OnValue
    $operation.States[$Off] | Should -Be $OffValue
    $operation.States.ContainsKey('WindowsDefault') | Should -BeTrue
    $operation.States.WindowsDefault | Should -BeNullOrEmpty
    $operation.BaselineState | Should -Be 'WindowsDefault'
    $operation.DocumentationUri | Should -Match '^https://(learn|support)\.microsoft\.com/'
    @($script:DefaultProfile.Operations.Id) | Should -Not -Contain $Id
  }

  It 'distinguishes explicit zero, missing values and wrong types for <Id>' -ForEach $settingCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On; Off = $Off; OnValue = $OnValue; OffValue = $OffValue } {
      param($Id, $On, $Off, $OnValue, $OffValue)
      $operation = Get-RideOperation -Id $Id
      foreach ($selection in @(@{ State = $On; Value = $OnValue }, @{ State = $Off; Value = $OffValue })) {
        $current = [pscustomobject]@{ Exists = $true; Value = $selection.Value; ValueType = 'DWord' }
        Test-RideCurrentStateMatch -Operation $operation -State $selection.State -CurrentState $current | Should -BeTrue
        Get-RideCurrentStateName -Operation $operation -CurrentState $current | Should -Be $selection.State
        Test-RideCurrentStateMatch -Operation $operation -State WindowsDefault -CurrentState $current | Should -BeFalse
        $current.ValueType = 'String'
        Test-RideCurrentStateMatch -Operation $operation -State $selection.State -CurrentState $current | Should -BeFalse
      }
      $absent = [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null }
      Test-RideCurrentStateMatch -Operation $operation -State WindowsDefault -CurrentState $absent | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State $Off -CurrentState $absent | Should -BeFalse
      Get-RideCurrentStateName -Operation $operation -CurrentState $absent | Should -Be 'WindowsDefault'
      $unsetPlan = @(Get-RideSingleOperationPlan -Id $Id -Action Unset)
      $unsetPlan[0].State | Should -Be 'WindowsDefault'
    }
  }
}

Describe 'Optional Windows settings saved-run lifecycle' {
  BeforeEach {
    InModuleScope RIDE.Engine -Parameters @{ StateRoot = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) } {
      param($StateRoot)
      $script:OptionalStateRoot = $StateRoot
      $script:OptionalCurrent = [pscustomobject]@{ Exists = $true; Value = 'prior custom value'; ValueType = 'String' }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { Join-Path $script:OptionalStateRoot $Scope }
      Mock Initialize-RideStateRoot {
        $root = Get-RideStateRoot -Scope $Scope
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $root
      }
      Mock Get-RideCurrentState { $script:OptionalCurrent }
      Mock Get-Item { [pscustomobject]@{ MockRegistryKey = $true } } -ParameterFilter { $LiteralPath -match '^HK(CU|LM):' }
      Mock Set-RideSettingState {
        $script:OptionalCurrent = [pscustomobject]@{ Exists = ($null -ne $Value); Value = $Value; ValueType = $(if ($null -ne $Value) { $Operation.ValueType } else { $null }) }
      }
      Mock Restore-RideSettingState {
        $script:OptionalCurrent = [pscustomobject]@{ Exists = $Snapshot.Exists; Value = $Snapshot.Value; ValueType = $Snapshot.ValueType }
      }
    }
  }

  It 'previews, saves, repeats and restores <Id> with its original type' -ForEach $settingCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On; OnValue = $OnValue; Scope = $Scope } {
      param($Id, $On, $OnValue, $Scope)
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $On)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path -LiteralPath $script:OptionalStateRoot | Should -BeFalse
      Should -Invoke Set-RideSettingState -Times 0 -Exactly

      $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
      $runId | Should -Match '^[a-f0-9]{32}$'
      $record = Get-Content -LiteralPath (Join-Path (Get-RideStateRoot -Scope $Scope) "$runId/$Id.json") -Raw | ConvertFrom-Json
      $record.Scope | Should -Be $Scope
      $record.Snapshot.Exists | Should -BeTrue
      $record.Snapshot.KeyExisted | Should -BeTrue
      $record.Snapshot.Value | Should -Be 'prior custom value'
      $record.Snapshot.ValueType | Should -Be 'String'
      Test-RideDesiredState -Operation $plan[0].Operation -State $On | Should -BeTrue

      $repeat = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $repeat | Should -Contain 'No changes were needed; no state record was created.'
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.Id -eq $Id -and $Value -eq $OnValue }
      @(Get-ChildItem -LiteralPath (Get-RideStateRoot -Scope $Scope) -Directory).Count | Should -Be 1

      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
      Should -Invoke Restore-RideSettingState -Times 0 -Exactly
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      $script:OptionalCurrent.Value | Should -Be 'prior custom value'
      $script:OptionalCurrent.ValueType | Should -Be 'String'
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.Id -eq $Id -and $Snapshot.ValueType -eq 'String' }
    }
  }

  It 'removes the override and retains an absent snapshot for <Id>' -ForEach $settingCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On; Scope = $Scope } {
      param($Id, $On, $Scope)
      $script:OptionalCurrent = [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null }
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $On)
      $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
      $record = Get-Content -LiteralPath (Join-Path (Get-RideStateRoot -Scope $Scope) "$runId/$Id.json") -Raw | ConvertFrom-Json
      $record.Snapshot.Exists | Should -BeFalse

      $unset = @(Get-RideSingleOperationPlan -Id $Id -Action Unset)
      Invoke-RidePlan -Plan $unset -Confirm:$false | Out-Null
      Test-RideDesiredState -Operation $plan[0].Operation -State WindowsDefault | Should -BeTrue
      Should -Invoke Set-RideSettingState -Times 1 -Exactly -ParameterFilter { $Operation.Id -eq $Id -and $null -eq $Value }
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      $script:OptionalCurrent.Exists | Should -BeFalse
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly -ParameterFilter { -not $Snapshot.Exists }
    }
  }

  It 'preserves recoverable pre-change state when applying <Id> fails' -ForEach $settingCases {
    InModuleScope RIDE.Engine -Parameters @{ Id = $Id; On = $On } {
      param($Id, $On)
      Mock Set-RideSettingState { throw 'simulated Windows setting registry write failure' }
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $On)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated Windows setting registry write failure*'
      $records = @(Get-ChildItem -LiteralPath $script:OptionalStateRoot -Recurse -Filter "$Id.json")
      $records.Count | Should -Be 1
      $record = Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json
      $record.Snapshot.Value | Should -Be 'prior custom value'
      $record.Snapshot.ValueType | Should -Be 'String'
      Restore-RideRun -RunId $record.RunId -Confirm:$false | Out-Null
      Should -Invoke Restore-RideSettingState -Times 1 -Exactly
    }
  }
}


Describe 'Optional Windows settings additional states and defaults' {
  It 'plans every explicit state of <Id> without substituting override removal' -ForEach $settingCases {
    foreach ($state in $ExpectedStates.Keys) {
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $state)
      $plan[0].State | Should -Be $state
      $plan[0].Operation.States[$state] | Should -Be $ExpectedStates[$state]
    }
  }

  It 'leaves image-dependent defaults unknown in status, for present and absent values' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.app-color-mode'
      Mock Get-RideCatalog { @{ Operations = @($operation); Groups = @() } }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
      $status = @(Get-RideStatus -View settings)[0]
      $status.DefaultValue | Should -Be '<platform-defined>'
      $status.MatchesDefault | Should -BeNullOrEmpty
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      $status = @(Get-RideStatus -View settings)[0]
      $status.DefaultValue | Should -Be '<platform-defined>'
      $status.MatchesDefault | Should -BeNullOrEmpty
      $status.CurrentState | Should -Be 'Dark'
    }
  }

  It 'retains explicit zero as a known default and distinguishes absence' {
    InModuleScope RIDE.Engine {
      $operation = (Get-RideOperation -Id 'windows.auto-reboot-on-crash').Clone()
      $operation.TargetDefaults = @{ 'Windows 11' = @{ DefaultValueExists = $true; DefaultValue = 0; EffectiveDefault = 'Fixture' } }
      Mock Get-RideCatalog { @{ Operations = @($operation); Groups = @() } }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      $status = @(Get-RideStatus -View settings)[0]
      $status.DefaultValue | Should -Be '0'
      $status.MatchesDefault | Should -BeTrue
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
      @(Get-RideStatus -View settings)[0].MatchesDefault | Should -BeFalse
    }
  }

  It 'rejects a machine setting without elevation before saving or changing state' {
    InModuleScope RIDE.Engine -Parameters @{ StateRoot = (Join-Path $TestDrive 'unelevated') } {
      param($StateRoot)
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $false }
      Mock Get-RideStateRoot { $StateRoot }
      Mock Set-RideSettingState { throw 'must not write' }
      $plan = @(Get-RideSingleOperationPlan -Id 'windows.sensors-policy' -Action Set -State Disabled)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*elevated PowerShell*'
      Test-Path -LiteralPath $StateRoot | Should -BeFalse
      Should -Invoke Set-RideSettingState -Times 0 -Exactly
    }
  }
}
