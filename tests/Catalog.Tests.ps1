<#
.SYNOPSIS
  Test catalog, completion, plans, and focused handlers with isolated fixtures.

.DESCRIPTION
  Pester tests validate operation/profile metadata, artifact resolution, CLI completion,
  desired-state inspection, lifecycle preview/failure reporting, and focused handlers.
  Most system-changing calls are mocked or use TestDrive fixtures. The WindowsIntegration-tagged
  registry subtree test writes to HKCU and must run only in a disposable Windows VM. The integration
  suite is a
  separate explicit entry point.

.EXAMPLE
  Invoke-Pester .\tests\Catalog.Tests.ps1 -ExcludeTag WindowsIntegration

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  Pester test results through Invoke-Pester; no standalone CLI output contract.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Pester 5.x on Windows and repository modules; test scratch uses Pester TestDrive.
  File/environment inputs: Catalog/profiles and fixture data. BeforeAll imports the engine and
  registry key-set definitions.
  Recovery: Pester cleans fixture storage; mocks prevent real Windows changes.
  Author: RIDE-Windows maintainers.
  Version: Repository test fixture; no independent released version.
  Changelog:
    2026-10-08: Document test purpose and invocation; tag the live-registry test for VM-only
    execution.

  Versioning exception: Pester fixtures are invoked by Pester, not as standalone CLI tools. This
  review does not invent a separate script release or CLI.

#>


BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogValidation.psm1') -Force
  $script:Catalog = Import-RideCatalogData (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')
  $script:EnginePath = Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1'
  Import-Module $script:EnginePath -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-RegistryKeySet.psm1') -Force
}

Describe 'RIDE operation catalog' {
  It 'detects the stable x64 PowerShell MSI without matching preview or ARM64 editions' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'package.powershell'
    'PowerShell 7-x64' | Should -Match $operation.DisplayNamePattern
    'PowerShell 7.6.6' | Should -Match $operation.DisplayNamePattern
    'PowerShell 7-preview-x64' | Should -Not -Match $operation.DisplayNamePattern
    'PowerShell 7-arm64' | Should -Not -Match $operation.DisplayNamePattern
  }
  It 'accepts HashCheck on Windows 11 while retaining the publisher pin and interactive context requirement' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'package.hashcheck-shell-extension'
    $operation.PendingAcceptance | Should -BeFalse
    @($operation.SupportedTargets) | Should -Be @('Windows 11')
    $operation.CandidateTargets | Should -BeNullOrEmpty
    $operation.Description | Should -Match 'elevated interactive session'
    $operation.Scope | Should -Be 'Machine'
    $operation.RequiresAdmin | Should -BeTrue
    $operation.PackageVersion | Should -Be '2.6.3'
    $operation.ExpectedSha256 | Should -Be 'cd890774839177b234a1165fd459ddeb830274ef7d81b289ddb70d43ae5983fa'
    $operation.InstallerArguments | Should -Be '/S'
    $operation.License | Should -Match 'BSD-3-Clause'
    $operation.LicenseUri | Should -Match 'https://github.com/idrassi/HashCheck/blob/v2.6.3/license.txt'
  }
  It 'orders standalone Git LFS after Git and uses documented user policies' {
    $group = $script:Catalog.Groups | Where-Object Id -eq 'solution.git-development'
    $group.Members[0] | Should -Be 'package.git-for-windows'
    $group.Members[1] | Should -Be 'package.git-lfs'
    $runAs = $script:Catalog.Operations | Where-Object Id -eq 'windows.start-run-as-different-user'
    $runAs.RegistryPath | Should -Be 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'
    $runAs.Scope | Should -Be 'User'
    $runAs.RequiresAdmin | Should -BeFalse
    $edge = $script:Catalog.Operations | Where-Object Id -eq 'windows.edge-friendly-url-format'
    $edge.States.PlainText | Should -Be 1
    $edge.States.TitledHyperlink | Should -Be 3
    $edge.States.WindowsDefault | Should -BeNullOrEmpty
  }
  It 'has unique operation and group IDs' {
    $allIds = @($script:Catalog.Operations.Id) + @($script:Catalog.Groups.Id)
    @($allIds | Select-Object -Unique).Count | Should -Be $allIds.Count
  }

  It 'provides user-facing presentation metadata for every setting and control operation' {
    $settings = @($script:Catalog.Operations | Where-Object { $_.Kind -notin @('Package','StoreApp','Artifact','ProfileSetting','WindowsCapability') -and -not ($_.Kind -eq 'WindowsService' -and $_.RequiredCapabilityName) })
    $settings.Count | Should -BeGreaterThan 0
    foreach ($operation in $settings) {
      $operation.ContainsKey('SettingPresentation') | Should -BeTrue -Because $operation.Id
    }
  }

  It 'uses only registered members in solution groups' {
    $operationIds = @($script:Catalog.Operations.Id)
    foreach ($group in $script:Catalog.Groups) {
      foreach ($member in $group.Members) {
        $member | Should -BeIn $operationIds
      }
    }
  }

  It 'declares support, scope, privilege, actions, and rollback for every operation' {
    foreach ($operation in $script:Catalog.Operations) {
      if ($operation.PendingAcceptance) {
        $operation.Kind | Should -BeIn @('Package', 'StoreApp', 'ProfileSetting', 'UserPath', 'UserProxy', 'WinHttpProxy', 'FirewallProfile', 'RemoteDesktopFirewall', 'RegistryValueSet', 'RegistryValue', 'OwnedPowerPlan', 'WindowsService', 'LocalPasswordMaximumAge', 'DesktopShortcut', 'BitLockerWorkflow', 'WindowsCapability')
        $operation.SupportedTargets.Count | Should -Be 0
        $operation.CandidateTargets.Count | Should -BeGreaterThan 0
      } else { $operation.SupportedTargets.Count | Should -BeGreaterThan 0 }
      $operation.Scope | Should -BeIn @('User', 'Machine')
      $operation.Actions.Count | Should -BeGreaterThan 0
      $operation.Rollback | Should -BeIn @('Exact', 'Compensating', 'BestEffort', 'None', 'Staged', 'NonRestorable', 'Conditional')
    }
  }

  It 'provides authoritative documentation references for settings and product references for packages' {
    foreach ($operation in $script:Catalog.Operations) {
      if ($operation.Kind -eq 'RegistryValue') {
        $operation.DocumentationUri | Should -Match '^https://(learn|support)\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'WindowsService') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'BootConfiguration') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'NetworkProfile') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'UserProxy') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'WinHttpProxy') {
        $operation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
      }
      elseif ($operation.Kind -eq 'Package') {
        $operation.ProductUri | Should -Match '^https://'
      }
    }
  }

  It 'discovers the pending OpenSSH Server capability as a component, not a setting or package' {
    $component = @(Show-RideCatalog -View components | Where-Object Id -eq 'component.openssh-server-capability')
    $component.Count | Should -Be 1
    $component[0].Kind | Should -Be 'WindowsCapability'
    @(Show-RideCatalog -View settings | Where-Object Id -eq 'component.openssh-server-capability').Count | Should -Be 0
    @(Show-RideCatalog -View packages | Where-Object Id -eq 'component.openssh-server-capability').Count | Should -Be 0
    $component[0].PendingAcceptance | Should -BeTrue
    $component[0].SupportedTargets | Should -BeNullOrEmpty
  }

  It 'lists sshd activation as a separate capability-bound component' {
    $service = @($script:Catalog.Operations | Where-Object Id -eq 'windows.openssh-server-service')
    $service.Count | Should -Be 1
    $service[0].Kind | Should -Be 'WindowsService'
    $service[0].RequiredCapabilityName | Should -Be 'OpenSSH.Server~~~~0.0.1.0'
    $service[0].ServiceName | Should -Be 'sshd'
    $service[0].SupportedTargets | Should -BeNullOrEmpty
    $service[0].PendingAcceptance | Should -BeTrue
    @(Show-RideCatalog -View components | Where-Object Id -eq $service[0].Id).Count | Should -Be 1
    @(Show-RideCatalog -View settings | Where-Object Id -eq $service[0].Id).Count | Should -Be 0
  }

  It 'lists the OpenSSH inbound firewall rule as a separate pending setting' {
    $firewall = @($script:Catalog.Operations | Where-Object Id -eq 'windows.openssh-server-firewall')
    $firewall.Count | Should -Be 1
    $firewall[0].Kind | Should -Be 'RemoteDesktopFirewall'
    $firewall[0].FirewallRuleNames | Should -Be @('OpenSSH-Server-In-TCP')
    $firewall[0].RequiredCapabilityName | Should -Be 'OpenSSH.Server~~~~0.0.1.0'
    $firewall[0].States.Disabled | Should -Be 'False'
    $firewall[0].States.Enabled | Should -Be 'True'
    $firewall[0].PendingAcceptance | Should -BeTrue
    $firewall[0].SupportedTargets | Should -BeNullOrEmpty
    @(Show-RideCatalog -View settings | Where-Object Id -eq $firewall[0].Id).Count | Should -Be 1
    @(Show-RideCatalog -View components | Where-Object Id -eq $firewall[0].Id).Count | Should -Be 0
  }

  It 'refuses OpenSSH service inspection and state matching while its capability is absent' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.openssh-server-service'
      Mock Get-RideOpenSshServerEngineState { [pscustomobject]@{ Available = $true; Present = $false; Reason = $null } }
      Mock Get-RideWindowsServiceState { throw 'Service must not be inspected when its capability is absent.' }
      $current = Get-RideWindowsServiceEngineState -Operation $operation
      $current.Available | Should -BeFalse
      $current.Reason | Should -Match 'not installed'
      Test-RideCurrentStateMatch -Operation $operation -State ManualRunning -CurrentState $current | Should -BeFalse
      { Assert-RideRequiredServiceCapability -Operation $operation } | Should -Throw '*requires the installed OpenSSH Server capability*'
      Should -Not -Invoke Get-RideWindowsServiceState
    }
  }

  It 'matches OpenSSH capability states without coupling activation or firewall state' {
    InModuleScope RIDE.Engine {
      $operation = @{ Kind = 'WindowsCapability'; States = @{ Present = 'Installed'; Absent = 'NotPresent' } }
      $state = [pscustomobject]@{ Available = $true; CapabilityState = 'Installed' }
      Test-RideCurrentStateMatch -Operation $operation -State Present -CurrentState $state | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Absent -CurrentState $state | Should -BeFalse
      Get-RideCurrentStateName -Operation $operation -CurrentState $state | Should -Be 'Present'
    }
  }

  It 'plans OpenSSH capability installation but refuses apply until target acceptance' {
    InModuleScope RIDE.Engine {
      Mock Get-RideOpenSshServerEngineState {
        [pscustomobject]@{
          Available = $true
          Reason = $null
          Present = $false
          CapabilityState = 'NotPresent'
          Observation = [pscustomobject]@{ WindowsContext = [pscustomobject]@{ ComputerName = 'TEST-VM'; Build = '26100'; EditionId = 'Professional' }; Providers = @() }
        }
      }
      Mock Install-RideOpenSshServerCapability { throw 'Installer must not be called before target acceptance.' }
      $plan = @(Get-RideSingleOperationPlan -Id 'component.openssh-server-capability' -Action Install)
      $plan.Count | Should -Be 1
      $plan[0].State | Should -Be 'Present'
      $plan[0].Operation.PendingAcceptance | Should -BeTrue
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*does not support*'
      Should -Not -Invoke Install-RideOpenSshServerCapability
    }
  }

  It 'declares the versioned ImageMagick runtime package prerequisite' {
    $operation=$script:Catalog.Operations|Where-Object Id -eq 'package.imagemagick-portable-q16'
    $operation.PrerequisiteSystemFiles|Should -Be @('vcomp140.dll')
    $operation.SupportedTargets|Should -Be @('Windows 11')
    $operation.PendingAcceptance|Should -BeFalse
    $operation.TargetDefaults.'Windows 11'.DefaultValue|Should -Be 'Absent'
    $operation.Description|Should -Match 'RIDE adds package.vcredist-v14-x64 to the install plan'
    $operation.Description|Should -Match '14\.50\.35710'
    $operation.Description|Should -Match 'Windows 11-supported runtime package is skipped when a sufficient version is already installed'
    $operation.PrerequisitePackageId|Should -Be 'package.vcredist-v14-x64'
  }

  It 'declares the v14 runtime supported on Windows 11 after the focused lifecycle acceptance passed' {
    $runtime=$script:Catalog.Operations|Where-Object Id -eq 'package.vcredist-v14-x64'
    $runtime.MigrationBatch|Should -BeExactly 'ApplicationsBatch5'
    $runtime.CandidateTargets|Should -BeNullOrEmpty
    $runtime.SupportedTargets|Should -Be @('Windows 11')
    $runtime.PendingAcceptance|Should -BeFalse
    $runtime.TargetDefaults.'Windows 11'.DefaultValue|Should -BeExactly 'Absent'
    $runtime.MinimumInstalledVersion|Should -BeExactly '14.50.35710.0'
  }

  It 'keeps Docker Desktop a plannable Windows 11 candidate until RIDE lifecycle acceptance passes' {
    $operation=$script:Catalog.Operations|Where-Object Id -eq 'package.docker-desktop'
    $operation.PendingAcceptance|Should -BeTrue
    $operation.SupportedTargets|Should -BeNullOrEmpty
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.TargetDefaults|Should -BeNullOrEmpty
    $plan=@(Get-RideSingleOperationPlan -Id 'package.docker-desktop' -Action Install)
    $plan.Count|Should -Be 1
    $plan[0].Operation.PendingAcceptance|Should -BeTrue
    $plan[0].Operation.CandidateTargets|Should -Be @('Windows 11')
  }

  It 'pins the selected TMOG free-edition package without declaring unverified Windows support' {
    $operation=$script:Catalog.Operations|Where-Object Id -eq 'package.tmog'
    $operation.PackageVersion|Should -BeExactly '1.0.1'
    $operation.ExpectedSha256|Should -BeExactly 'b4edf70fa040968958c662ffb09feeeb0eeca07759e6ed7742606bcc39f29fc6'
    $operation.DownloadUri|Should -BeExactly 'https://tmog.org/rtm/downloads/TMOG-Task-Manager-Setup-1.0.1-0-x64-b4edf70fa040.exe'
    $operation.SupportedTargets|Should -BeNullOrEmpty
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.PendingAcceptance|Should -BeTrue
    $operation.MigrationBatch|Should -BeExactly 'ApplicationsBatch1'
    $operation.License|Should -Match 'free features and optional individually licensed PRO features'
    $plan=@(Get-RideSingleOperationPlan -Id 'package.tmog' -Action Install)
    $plan.Count|Should -Be 1
    $plan[0].Operation.PendingAcceptance|Should -BeTrue
    $plan[0].Operation.SupportedTargets|Should -BeNullOrEmpty
  }

  It 'models the Python manager no-implicit-install policy as an exact user environment setting candidate' {
    $operation=$script:Catalog.Operations|Where-Object Id -eq 'windows.python-manager-automatic-install'
    $operation.Kind|Should -BeExactly 'RegistryValue'
    $operation.RegistryPath|Should -BeExactly 'HKCU:\Environment'
    $operation.ValueName|Should -BeExactly 'PYTHON_MANAGER_AUTOMATIC_INSTALL'
    $operation.ValueType|Should -BeExactly 'String'
    $operation.States.Disabled|Should -BeExactly 'false'
    $operation.States.WindowsDefault|Should -BeNullOrEmpty
    $operation.BaselineState|Should -BeExactly 'WindowsDefault'
    $operation.Scope|Should -BeExactly 'User'
    $operation.RequiresAdmin|Should -BeFalse
    $operation.SupportedTargets|Should -BeNullOrEmpty
    $operation.CandidateTargets|Should -Be @('Windows 11','Windows Server 2025')
    $operation.PendingAcceptance|Should -BeTrue
    $operation.Rollback|Should -BeExactly 'Exact'
    $operation.Description|Should -Match 'Explicit py install commands remain available'
    $operation.Description|Should -Match 'Existing processes may retain stale environment data'
    $plan=@(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Disabled)
    $plan.Count|Should -Be 1
    $plan[0].Operation.PendingAcceptance|Should -BeTrue
    $plan[0].State|Should -BeExactly 'Disabled'
  }

  It 'models Click to Do policy availability with exact user-scope recovery and pending target acceptance' {
    $operation=$script:Catalog.Operations|Where-Object Id -eq 'windows.click-to-do-policy'
    $operation.Kind|Should -BeExactly 'RegistryValue'
    $operation.RegistryPath|Should -BeExactly 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
    $operation.ValueName|Should -BeExactly 'DisableClickToDo'
    $operation.ValueType|Should -BeExactly 'DWord'
    $operation.Scope|Should -BeExactly 'User'
    $operation.RequiresAdmin|Should -BeFalse
    $operation.States.Blocked|Should -Be 1
    $operation.States.Allowed|Should -Be 0
    $operation.States.WindowsDefault|Should -BeNullOrEmpty
    $operation.BaselineState|Should -BeExactly 'WindowsDefault'
    $operation.Rollback|Should -BeExactly 'Exact'
    $operation.SupportedTargets|Should -BeNullOrEmpty
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.PendingAcceptance|Should -BeTrue
    $operation.Description|Should -Match 'does not force the user''s own Click to Do Settings toggle on'
    $operation.Description|Should -Match 'independent of Recall and other Copilot features'
    $operation.Description|Should -Match 'ordinary Windows 11 policy behavior and the visible effect remain pending acceptance'
    $plan=@(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Blocked)
    $plan.Count|Should -Be 1
    $plan[0].Operation.PendingAcceptance|Should -BeTrue
    $plan[0].State|Should -BeExactly 'Blocked'
  }

  It 'publishes license references without individual or company review decisions' {
    foreach ($operation in $script:Catalog.Operations) {
      foreach ($field in @('LicenseReviewStatus', 'DistributionNotes', 'LicenseReviewedAt', 'ReviewOwner', 'ReviewedVersion')) {
        $operation.ContainsKey($field) | Should -BeFalse
      }
      if ($operation.Kind -in @('Package', 'Artifact')) {
        $operation.License | Should -Not -BeNullOrEmpty
        $operation.LicenseUri | Should -Match '^https://'
        ([uri]$operation.LicenseUri).IsAbsoluteUri | Should -BeTrue
        if ($operation.ContainsKey('TermsUri')) { $operation.TermsUri | Should -Match '^https://' }
      }
    }
    $rows = @(Show-RideCatalog -View packages)
    foreach ($row in $rows) {
      $row.License | Should -Not -BeNullOrEmpty
      $row.LicenseUri | Should -Match '^https://'
    }
  }

  It 'keeps the legacy BitLocker selector distinct from split future-encryption choices' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'windows.bitlocker-encryption-method'
    $operation.RegistryPath | Should -Be 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
    $operation.ValueName | Should -Be 'EncryptionMethod'
    $operation.ValueType | Should -Be 'DWord'
    $operation.States.AesCbc128 | Should -Be 3
    $operation.States.AesCbc256 | Should -Be 4
    $operation.States.WindowsDefault | Should -BeNullOrEmpty
    $operation.SettingPresentation.Behavior | Should -Be 'Unverified'
    $operation.Description | Should -Match 'Vista/Windows 7-era'
    $operation.Description | Should -Match 'not verified as the current Windows 11'
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $futureOperationIds = @('windows.bitlocker-encryption-method-os', 'windows.bitlocker-encryption-method-fixed-data', 'windows.bitlocker-encryption-method-removable-data')
    foreach ($futureOperationId in $futureOperationIds) {
      $futureOperation = $script:Catalog.Operations | Where-Object Id -eq $futureOperationId
      $futureOperation.SupportedTargets | Should -BeNullOrEmpty
      $futureOperation.CandidateTargets | Should -Contain 'Windows 11'
      $futureOperation.CandidateTargets | Should -Contain 'Windows Server 2025'
      $futureOperation.PendingAcceptance | Should -BeTrue
    }
    $futureStates = @($defaultProfile.Operations | Where-Object Id -in $futureOperationIds)
    $futureStates.Count | Should -Be 3
    @($futureStates | Where-Object State -ne 'XtsAes256').Count | Should -Be 0
    @($defaultProfile.Operations | Where-Object Id -eq $operation.Id).Count | Should -Be 0
  }

  It 'maps Microsoft product updates to the documented Windows Update preference' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'windows.microsoft-product-updates'
    $operation.RegistryPath | Should -Be 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    $operation.ValueName | Should -Be 'AllowMUUpdateService'
    $operation.States.Enabled | Should -Be 1
    $operation.States.Disabled | Should -Be 0
    $operation.States.WindowsDefault | Should -BeNullOrEmpty
    $operation.DocumentationUri | Should -Match 'learn\.microsoft\.com/.*/settings-common'
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object Id -eq $operation.Id).State | Should -Be 'Enabled'
  }

  It 'declares the three This PC folder visibility settings as scoped registry key sets' {
    $operations = @($script:Catalog.Operations | Where-Object Kind -eq 'RegistryKeySet')
    $operations.Id | Should -Contain 'windows.music-folder-this-pc'
    $operations.Id | Should -Contain 'windows.videos-folder-this-pc'
    $operations.Id | Should -Contain 'windows.3d-objects-folder-this-pc'
    foreach ($operation in $operations) {
      $operation.Scope | Should -Be 'Machine'
      $operation.RegistryPaths.Count | Should -BeGreaterThan 0
      $operation.States.Hidden | Should -Be 'Absent'
      $operation.States.Visible | Should -Be 'Present'
      $operation.Rollback | Should -Be 'Exact'
    }
  }

  It 'captures and exactly restores registry subtree values, kinds, and security descriptors' -Tag WindowsIntegration {
    $testRoot = 'HKCU:\Software\RIDE-Tests\RegistryKeySet-' + [guid]::NewGuid().ToString('N')
    $operation = @{ Id = 'test.registry-key-set'; RegistryPaths = @($testRoot); States = @{ Hidden = 'Absent'; Visible = 'Present' } }
    try {
      New-Item -Path (Join-Path $testRoot 'Nested') -Force | Out-Null
      New-ItemProperty -LiteralPath $testRoot -Name 'Text' -Value 'before' -PropertyType String -Force | Out-Null
      New-ItemProperty -LiteralPath $testRoot -Name 'Binary' -Value ([byte[]](1, 2, 3, 255)) -PropertyType Binary -Force | Out-Null
      New-ItemProperty -LiteralPath (Join-Path $testRoot 'Nested') -Name 'Multi' -Value ([string[]]@('one', 'two')) -PropertyType MultiString -Force | Out-Null
      $before = Get-RideRegistryKeyTreeState -Operation $operation

      Set-RideRegistryKeySetState -Operation $operation -State Hidden
      (Get-RideRegistryKeyTreeState -Operation $operation).PresentCount | Should -Be 0
      Restore-RideRegistryKeySetState -Trees $before.Trees

      $after = Get-RideRegistryKeyTreeState -Operation $operation
      $after.PresentCount | Should -Be 1
      $after.Trees[0].Root.SecurityDescriptor | Should -Be $before.Trees[0].Root.SecurityDescriptor
      $restoredRoot = Get-Item -LiteralPath $testRoot
      $restoredRoot.GetValue('Text') | Should -Be 'before'
      $restoredRoot.GetValueKind('Binary').ToString() | Should -Be 'Binary'
      [Convert]::ToBase64String([byte[]]$restoredRoot.GetValue('Binary')) | Should -Be ([Convert]::ToBase64String([byte[]](1, 2, 3, 255)))
      $restoredNested = Get-Item -LiteralPath (Join-Path $testRoot 'Nested')
      $restoredNested.GetValueKind('Multi').ToString() | Should -Be 'MultiString'
      @($restoredNested.GetValue('Multi')) | Should -Be @('one', 'two')
    }
    finally {
      if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
    }
  }
}

Describe 'RIDE package download resolution' {
  BeforeEach {
    InModuleScope RIDE-Packages {
      $script:GitHubReleaseCache = @{}; $script:GitHubReleaseNotBefore = $null; $script:GitHubReleaseRate = $null
    }
  }
  It 'declares latest-download metadata for supported pilot packages' {
    foreach ($packageId in @('package.7zip', 'package.notepadpp')) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $packageId
      $operation.Actions | Should -Contain 'Download'
      $operation.DownloadProvider | Should -Be 'GitHubReleaseApi'
      $operation.AssetPattern | Should -Not -BeNullOrEmpty
      $operation.Architecture | Should -Be 'x64'
    }
    $library = Get-Content -LiteralPath (Join-Path $script:RepositoryRoot 'catalog/artifact-observations.json') -Raw | ConvertFrom-Json
    $library.SchemaVersion | Should -Be 1
    foreach ($observation in $library.Observations) {
      $observation.Sha256 | Should -Match '^[0-9a-fA-F]{64}$'
      $observation.SourceUri | Should -Match '^https://'
    }
  }

  It 'resolves the verified ThreadJob NuGet package through the portable ZIP path' {
    InModuleScope RIDE-Packages {
      $operation = @{
        PackageId = 'microsoft-powershell-threadjob'
        ProductUri = 'https://www.powershellgallery.com/packages/Microsoft.PowerShell.ThreadJob/2.2.0'
        PackageVersion = '2.2.0'
        Architecture = 'neutral'
        InstallerType = 'Portable'
        PortableFormat = 'Zip'
        RequiredFiles = @('Microsoft.PowerShell.ThreadJob.psd1')
        AssetName = 'Microsoft.PowerShell.ThreadJob.2.2.0.nupkg'
        DownloadUri = 'https://www.powershellgallery.com/api/v2/package/Microsoft.PowerShell.ThreadJob/2.2.0'
        DownloadProvider = 'DirectHttps'
      }

      $artifact = Resolve-RidePackageArtifact -Operation $operation
      $artifact.FileName | Should -BeExactly 'Microsoft.PowerShell.ThreadJob.2.2.0.nupkg'
      $artifact.Uri | Should -BeExactly $operation.DownloadUri
      $artifact.Version | Should -BeExactly '2.2.0'
    }
  }

  It 'models the SwiftOnSecurity XML as a separate download-only artifact' {
    $artifact = $script:Catalog.Operations | Where-Object Id -eq 'artifact.sysmon-swift-config'
    $artifact.Kind | Should -Be 'Artifact'
    $artifact.Actions | Should -Be @('Download')
    $artifact.DownloadProvider | Should -Be 'GitHubFileCommitApi'
    $artifact.Description | Should -Match 'never applied automatically'
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    @($defaultProfile.Operations.Id) | Should -Not -Contain $artifact.Id
  }

  It 'pins the RawCopy Windows 11 staging candidate to its official source snapshot' {
    $package = $script:Catalog.Operations | Where-Object Id -eq 'package.rawcopy'
    $package.Kind | Should -Be 'Package'
    $package.CandidateTargets | Should -Contain 'Windows 11'
    $package.SupportedTargets | Should -Be @()
    $package.PendingAcceptance | Should -BeTrue
    $package.DownloadUri | Should -Be 'https://github.com/jschicht/RawCopy/archive/0d8d690c0f0fe9d2c68c5fce02d26d0efa53459c.zip'
    $package.ExpectedSha256 | Should -Be 'F5DAF2C74A4B5A29DBD188E36F003535AB39AA80A5F86A564725A5A1642841DF'
    $package.PortableFormat | Should -Be 'Zip'
    $package.RequiredFiles | Should -Contain 'RawCopy-0d8d690c0f0fe9d2c68c5fce02d26d0efa53459c/LICENSE.md'
    $package.Description | Should -Match 'does not run RawCopy'
  }

  It 'pins ETL2PCAPNG to the signed Microsoft release and retained MIT notice' {
    $package = $script:Catalog.Operations | Where-Object Id -eq 'package.etl2pcapng'
    $package.CandidateTargets | Should -Contain 'Windows 11'
    $package.SupportedTargets | Should -Be @()
    $package.PendingAcceptance | Should -BeTrue
    $package.PackageVersion | Should -BeExactly '1.11.0'
    $package.ExpectedSha256 | Should -Be 'C2D03AAC43EA0F5626FC8D909E6688393FEAF71BD6FACD39AAF8A637382D9043'
    $package.LicenseUri | Should -Be 'https://github.com/microsoft/etl2pcapng/blob/65e2a98feb029a63318de2d821d6444fd7e148c3/LICENSE'
    $package.RequiredFiles | Should -Contain 'LICENSE.txt'
    $package.PortableLocalFiles[0].Sha256 | Should -Be 'C2CFCCB812FE482101A8F04597DFC5A9991A6B2748266C47AC91B6A5AAE15383'
    $originalHash = $package.PortableLocalFiles[0].Sha256
    $package.PortableLocalFiles[0].Sha256 = ('0' * 64)
    (@(Get-RideCatalogValidationErrors -Catalog $script:Catalog) -join ' ') | Should -Match 'PortableLocalFiles source is outside the repository or has a mismatched SHA-256'
    $package.PortableLocalFiles[0].Sha256 = $originalHash
  }

  It 'selects the Sysmon package independently from its optional community configuration' {
    $package = $script:Catalog.Operations | Where-Object Id -eq 'package.sysmon64'
    $package.InstallerType | Should -Be 'SysmonZip'
    $package.DownloadProvider | Should -Be 'SysinternalsSysmonPage'
    $package.Actions | Should -Contain 'Install'
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object Id -eq $package.Id).State | Should -Be 'Present'
    @($defaultProfile.Operations.Id) | Should -Not -Contain 'artifact.sysmon-swift-config'
  }

  It 'honors WhatIf for a CLI download without resolving or downloading an artifact' {
    Mock Save-RidePackageArtifact { throw 'Download should not be attempted in WhatIf.' } -ModuleName RIDE.Engine
    Save-RidePackage -Id 'package.7zip' -Destination (Join-Path $TestDrive 'Artifacts') -WhatIf
    Save-RidePackage -Id 'artifact.sysmon-swift-config' -Destination (Join-Path $TestDrive 'ArtifactFiles') -WhatIf
    Should -Invoke Save-RidePackageArtifact -Exactly 0 -ModuleName RIDE.Engine
  }

  It 'resolves the versioned 64-bit Notepad++ latest-release artifact and its sidecars' {
    InModuleScope RIDE-Packages {
      Mock Invoke-WebRequest {
        $release = [pscustomobject]@{
          tag_name = 'v8.9.8.1'
          html_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8.1'
          assets = @(
            [pscustomobject]@{ name = 'npp.8.9.8.1.Installer.x64.exe'; browser_download_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.Installer.x64.exe'; digest = 'sha256:' + ('a' * 64) }
            [pscustomobject]@{ name = 'npp.8.9.8.1.Installer.x86.exe'; browser_download_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.Installer.x86.exe' }
            [pscustomobject]@{ name = 'npp.8.9.8.1.portable.x64.zip'; browser_download_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.portable.x64.zip' }
            [pscustomobject]@{ name = 'npp.8.9.8.1.checksums.sha256'; browser_download_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.checksums.sha256' }
            [pscustomobject]@{ name = 'npp.8.9.8.1.checksums.sha256.sig'; browser_download_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.checksums.sha256.sig' }
          )
        }
        [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = @{} }
      } -ParameterFilter { $Uri -like 'https://api.github.com/repos/*/releases/latest' -and -not $OutFile }
      $operation = @{ PackageId = 'notepadpp'; DownloadUri = 'https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest'; DownloadProvider = 'GitHubReleaseApi'; AssetPattern = '^npp\..+\.Installer\.x64\.exe$'; Architecture = 'x64' }

      $artifact = Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -Be '8.9.8.1'
      $artifact.FileName | Should -Be 'npp.8.9.8.1.Installer.x64.exe'
      $artifact.Uri | Should -Be 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.Installer.x64.exe'
      $artifact.ProviderDigest | Should -Match '^sha256:'
      $artifact.ChecksumUris.Count | Should -Be 1
      $artifact.SignatureUris.Count | Should -Be 1
      Should -Invoke Invoke-WebRequest -Exactly 1 -ParameterFilter { $Uri -eq $operation.DownloadUri -and -not $OutFile }
    }
  }

  It 'resolves Sysmon latest from the Microsoft page and downloads the official ZIP' {
    InModuleScope RIDE-Packages {
      Mock Invoke-WebRequest { [pscustomobject]@{ Content = '<h1 id="sysmon-v15.22">Sysmon v15.22</h1>' } }
      $operation = @{ PackageId = 'sysmon64'; ProductUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon'; VersionUri = 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon'; DownloadUri = 'https://download.sysinternals.com/files/Sysmon.zip'; DownloadProvider = 'SysinternalsSysmonPage'; AssetName = 'Sysmon.zip'; Architecture = 'x64' }

      $artifact = Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -Be '15.22'
      $artifact.FileName | Should -Be 'Sysmon.zip'
      $artifact.Uri | Should -Be 'https://download.sysinternals.com/files/Sysmon.zip'
      $artifact.ProviderDigest | Should -BeNullOrEmpty
    }
  }

  It 'installs Sysmon with its default config and never applies the separate XML implicitly' {
    InModuleScope RIDE-Packages {
      $root = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Sysmon-' + [guid]::NewGuid().ToString('N'))
      try {
        Mock Save-RidePackageArtifact { [pscustomobject]@{ Path = 'C:\cache\Sysmon.zip'; Version = '15.22' } }
        Mock Expand-Archive { New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null; Set-Content -LiteralPath (Join-Path $DestinationPath 'Sysmon64.exe') -Value 'mock executable' }
        Mock Get-RideSysmonInstallRoot { $root }
        Mock Start-Process { [pscustomobject]@{ ExitCode = 0; ArgumentList = $ArgumentList } }
        Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $true } }
        $operation = @{ Id = 'package.sysmon64'; PackageId = 'sysmon64'; InstallerType = 'SysmonZip'; Name = 'Sysmon'; InstallerArguments = '-accepteula -i' }

        Install-RidePackage -Operation $operation -CacheDirectory (Join-Path $root 'Cache')
        Should -Invoke Start-Process -Exactly 1 -ParameterFilter { $ArgumentList -eq '-accepteula -i' }
        Should -Invoke Save-RidePackageArtifact -Exactly 1
      }
      finally {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
      }
    }
  }

  It 'uses Sysmon force uninstall and verifies the service is gone' {
    InModuleScope RIDE-Packages {
      $script:sysmonDetectionCalls = 0
      Mock Get-RideInstalledPackage {
        $script:sysmonDetectionCalls++
        if ($script:sysmonDetectionCalls -eq 1) {
          [pscustomobject]@{ Present = $true; DisplayName = 'Sysmon'; DisplayVersion = '15.22'; UninstallString = '"C:\ProgramData\RIDE\Programs\Sysmon\15.22\Sysmon64.exe"'; QuietUninstallString = $null; InstallLocation = 'C:\ProgramData\RIDE\Programs\Sysmon\15.22' }
        }
        else { [pscustomobject]@{ Present = $false } }
      }
      Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }
      $operation = @{ Id = 'package.sysmon64'; PackageId = 'sysmon64'; InstallerType = 'SysmonZip'; Name = 'Sysmon'; UninstallerArguments = '-u force' }

      Uninstall-RidePackage -Operation $operation
      Should -Invoke Start-Process -Exactly 1 -ParameterFilter { $ArgumentList -eq '-u force' }
    }
  }

  It 'resolves a community configuration file to an immutable commit URL' {
    InModuleScope RIDE-Packages {
      Mock Invoke-RestMethod {
        @([pscustomobject]@{ sha = '0123456789abcdef0123456789abcdef01234567'; html_url = 'https://github.com/SwiftOnSecurity/sysmon-config/commit/0123456789abcdef0123456789abcdef01234567' })
      }
      $operation = @{ ArtifactId = 'sysmon-swift-config'; ProductUri = 'https://github.com/SwiftOnSecurity/sysmon-config'; DownloadUri = 'https://api.github.com/repos/SwiftOnSecurity/sysmon-config/commits?path=sysmonconfig-export.xml&per_page=1'; DownloadProvider = 'GitHubFileCommitApi'; Repository = 'SwiftOnSecurity/sysmon-config'; AssetPath = 'sysmonconfig-export.xml'; Architecture = 'neutral' }

      $artifact = Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -Be '0123456789abcdef0123456789abcdef01234567'
      $artifact.FileName | Should -Be 'sysmonconfig-export.xml'
      $artifact.Uri | Should -Be 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/0123456789abcdef0123456789abcdef01234567/sysmonconfig-export.xml'
      $artifact.ArtifactId | Should -Be 'sysmon-swift-config'
    }
  }

  It 'retains the selected community configuration without treating it as a package' {
    InModuleScope RIDE-Packages {
      $root = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Artifact-' + [guid]::NewGuid().ToString('N'))
      $destination = Join-Path $root 'Artifacts'
      $observationPath = Join-Path $root 'artifact-observations.json'
      try {
        Mock Invoke-RestMethod { @([pscustomobject]@{ sha = '0123456789abcdef0123456789abcdef01234567'; html_url = 'https://github.com/SwiftOnSecurity/sysmon-config/commit/0123456789abcdef0123456789abcdef01234567' }) }
        Mock Invoke-WebRequest { Set-Content -LiteralPath $OutFile -Value '<Sysmon schemaversion="4.90" />' -NoNewline }
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
        $operation = @{ Kind = 'Artifact'; ArtifactId = 'sysmon-swift-config'; ProductUri = 'https://github.com/SwiftOnSecurity/sysmon-config'; DownloadUri = 'https://api.github.com/repos/SwiftOnSecurity/sysmon-config/commits?path=sysmonconfig-export.xml&per_page=1'; DownloadProvider = 'GitHubFileCommitApi'; Repository = 'SwiftOnSecurity/sysmon-config'; AssetPath = 'sysmonconfig-export.xml'; Architecture = 'neutral' }

        $result = Save-RidePackageArtifact -Operation $operation -DestinationDirectory $destination -ObservationPath $observationPath
        $result.Path | Should -Match 'sysmon-swift-config[\\/]0123456789abcdef0123456789abcdef01234567[\\/]sysmonconfig-export\.xml$'
        $result.ArtifactId | Should -Be 'sysmon-swift-config'
        $result.PackageId | Should -BeNullOrEmpty
        $library = Get-Content -LiteralPath $observationPath -Raw | ConvertFrom-Json
        $library.Observations[0].ArtifactId | Should -Be 'sysmon-swift-config'
        $library.Observations[0].PackageId | Should -BeNullOrEmpty
        Should -Invoke Invoke-WebRequest -Exactly 1
      }
      finally {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
      }
    }
  }

  It 'resolves the 7-Zip x64 asset from the latest versioned release' {
    InModuleScope RIDE-Packages {
      Mock Invoke-WebRequest {
        $release = [pscustomobject]@{
          tag_name = '26.04'
          html_url = 'https://github.com/ip7z/7zip/releases/tag/26.04'
          assets = @([pscustomobject]@{ name = '7z2604-x64.exe'; browser_download_url = 'https://github.com/ip7z/7zip/releases/download/26.04/7z2604-x64.exe'; digest = $null })
        }
        [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = @{} }
      } -ParameterFilter { $Uri -like 'https://api.github.com/repos/*/releases/latest' -and -not $OutFile }
      $operation = @{ PackageId = '7zip'; DownloadUri = 'https://api.github.com/repos/ip7z/7zip/releases/latest'; DownloadProvider = 'GitHubReleaseApi'; AssetPattern = '^7z\d+-x64\.exe$'; Architecture = 'x64' }

      $artifact = Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -Be '26.04'
      $artifact.FileName | Should -Be '7z2604-x64.exe'
      $artifact.Architecture | Should -Be 'x64'
    }
  }

  It 'resolves Git for Windows x64 patch installer while skipping portable and ARM64 assets' {
    InModuleScope RIDE-Packages {
      Mock Invoke-WebRequest {
        $release = [pscustomobject]@{
          tag_name = 'v2.56.0.windows.2'
          html_url = 'https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.2'
          assets = @(
            [pscustomobject]@{ name = 'Git-2.56.0.2-64-bit.exe'; browser_download_url = 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-64-bit.exe'; digest = $null }
            [pscustomobject]@{ name = 'Git-2.56.0.2-arm64.exe'; browser_download_url = 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/Git-2.56.0.2-arm64.exe'; digest = $null }
            [pscustomobject]@{ name = 'PortableGit-2.56.0-64-bit.7z.exe'; browser_download_url = 'https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.1/PortableGit-2.56.0-64-bit.7z.exe'; digest = $null }
          )
        }
        [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = @{} }
      } -ParameterFilter { $Uri -like 'https://api.github.com/repos/*/releases/latest' -and -not $OutFile }
      $operation = @{ PackageId = 'git-for-windows'; DownloadUri = 'https://api.github.com/repos/git-for-windows/git/releases/latest'; DownloadProvider = 'GitHubReleaseApi'; AssetPattern = '^Git-\d+\.\d+\.\d+(?:\.\d+)?-64-bit\.exe$'; Architecture = 'x64' }

      $artifact = Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -Be '2.56.0.windows.2'
      $artifact.FileName | Should -Be 'Git-2.56.0.2-64-bit.exe'
      $artifact.Uri | Should -Match '/Git-2\.56\.0\.2-64-bit\.exe$'
    }
  }

  It 'retains a download, records its hash, and does not invoke an installer' {
    InModuleScope RIDE-Packages {
      $root = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Package-' + [guid]::NewGuid().ToString('N'))
      $destination = Join-Path $root 'Artifacts'
      $observationPath = Join-Path $root 'artifact-observations.json'
      try {
        Mock Invoke-WebRequest {
          $release = [pscustomobject]@{
            tag_name = 'v8.9.8.1'
            html_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8.1'
            assets = @([pscustomobject]@{ name = 'npp.8.9.8.1.Installer.x64.exe'; browser_download_url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.Installer.x64.exe'; digest = $null })
          }
          [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = @{} }
        } -ParameterFilter { $Uri -like 'https://api.github.com/repos/*/releases/latest' -and -not $OutFile }
        Mock Invoke-WebRequest { Set-Content -LiteralPath $OutFile -Value 'test installer bytes' -NoNewline }
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
        $operation = @{ PackageId = 'notepadpp'; DownloadUri = 'https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest'; ProductUri = 'https://notepad-plus-plus.org/'; DownloadProvider = 'GitHubReleaseApi'; AssetPattern = '^npp\..+\.Installer\.x64\.exe$'; Architecture = 'x64' }

        $result = Save-RidePackageArtifact -Operation $operation -DestinationDirectory $destination -ObservationPath $observationPath
        Test-Path -LiteralPath $result.Path -PathType Leaf | Should -BeTrue
        $result.Path | Should -Match 'notepadpp[\\/]8\.9\.8\.1[\\/]npp\.8\.9\.8\.1\.Installer\.x64\.exe$'
        $result.Sha256 | Should -Match '^[0-9a-f]{64}$'
        $library = Get-Content -LiteralPath $observationPath -Raw | ConvertFrom-Json
        $library.Observations.Count | Should -Be 1
        $library.Observations[0].Sha256 | Should -Be $result.Sha256
        $library.Observations[0].AuthenticodeStatus | Should -Be 'NotSigned'
      }
      finally {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
      }
    }
  }
}

Describe 'RIDE profile planning' {
  It 'expands solution groups in apply order and reverse order for removal' {
    $profile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/analyst-basics.psd1')
    $applyPlan = @(Get-RidePlan -Profile $profile)
    $removePlan = @(Get-RidePlan -Profile $profile -Action Remove)

    (@($applyPlan.Operation.Id) -join ',') | Should -Be 'package.7zip,package.notepadpp'
    (@($removePlan.Operation.Id) -join ',') | Should -Be 'package.notepadpp,package.7zip'
    (@($removePlan.State | Select-Object -Unique) -join ',') | Should -Be 'Absent'
  }

  It 'resolves a registry profile state to its catalog value' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.show-known-extensions'
      Get-RideOperationValue -Operation $operation -State 'Enabled' | Should -Be 0
    }
  }

  It 'resolves Baseline to the operation declared baseline state' {
    $profile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/baseline.psd1')
    $plan = @(Get-RidePlan -Profile $profile)
    $plan[0].State | Should -Be 'Disabled'
  }

  It 'maps the legacy inking and typing setting to Disabled and restores its baseline by unsetting it' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      Get-RideOperationValue -Operation $operation -State 'Disabled' | Should -Be 0
      Get-RideOperationValue -Operation $operation -State 'Enabled' | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $defaultPlan = @(Get-RidePlan -Profile $defaultProfile)
    ($defaultPlan | Where-Object { $_.Operation.Id -eq 'windows.inking-typing-data' }).State | Should -Be 'Disabled'

    $baselinePlan = @(Get-RidePlan -Profile @{ SchemaVersion = 1; Name = 'Inking and typing baseline'; Operations = @(@{ Id = 'windows.inking-typing-data'; State = 'Baseline' }) })
    $baselinePlan[0].State | Should -Be 'Enabled'
  }

  It 'allows a declared state to remove a registry value' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.script-host-policy'
      $plan = @(Get-RidePlan -Profile @{ SchemaVersion = 1; Name = 'Restore script host'; Operations = @(@{ Id = $operation.Id; State = 'Enabled' }) })
      Get-RideOperationValue -Operation $operation -State $plan[0].State | Should -BeNullOrEmpty
    }
  }

  It 'maps the low-risk network selectors to reversible registry states in the default profile' {
    InModuleScope RIDE.Engine {
      $proxy = Get-RideOperation -Id 'windows.proxy-autoconfig-url'
      Get-RideOperationValue -Operation $proxy -State 'Disabled' | Should -Be ''
      Get-RideOperationValue -Operation $proxy -State 'Enabled' | Should -BeNullOrEmpty
      $llmnr = Get-RideOperation -Id 'windows.llmnr-policy'
      Get-RideOperationValue -Operation $llmnr -State 'Disabled' | Should -Be 0
      Get-RideOperationValue -Operation $llmnr -State 'Enabled' | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object { $_.Id -in @('windows.proxy-autoconfig-url', 'windows.llmnr-policy') } | ForEach-Object State | Select-Object -Unique) | Should -Be 'Disabled'
  }

  It 'maps low-risk privacy policy values to Disabled and restores their enabled baseline by unsetting' {
    $ids = @(
      'windows.tailored-experiences-policy',
      'windows.activity-history-feed-policy',
      'windows.activity-history-publish-policy',
      'windows.activity-history-upload-policy',
      'windows.location-service-policy',
      'windows.location-scripting-policy',
      'windows.advertising-id-policy',
      'windows.website-language-list-policy'
    )
    foreach ($id in $ids) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation.States.Disabled | Should -Not -BeNullOrEmpty
      $operation.States.Enabled | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object { $_.Id -in $ids }).Count | Should -Be $ids.Count
  }

  It 'maps low-risk service-family registry settings to their declared states' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $defaultProfile)
    ($plan | Where-Object { $_.Operation.Id -in @('windows.maintenance-wake-policy', 'windows.maintenance-wake-timer', 'windows.shared-experiences-policy') } | ForEach-Object State | Select-Object -Unique) | Should -Be 'Disabled'
    ($plan | Where-Object { $_.Operation.Id -eq 'windows.long-paths-policy' }).State | Should -Be 'Enabled'

    $longPaths = $script:Catalog.Operations | Where-Object Id -eq 'windows.long-paths-policy'
    $longPaths.States.Enabled | Should -Be 1
    $longPaths.States.Disabled | Should -Be 0
  }

  It 'plans default/LAN automatic proxy detection as an independent pending user setting' {
    $operation = Get-RideOperation -Id 'windows.proxy-auto-detect'
    $operation.Kind | Should -Be 'UserProxy'
    $operation.Handler | Should -Be 'UserProxy'
    $operation.Scope | Should -Be 'User'
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.CandidateTargets | Should -Contain 'Windows 11'
    $operation.PendingAcceptance | Should -BeTrue
    $operation.States.Enabled | Should -Be 'Enabled'
    $operation.States.Disabled | Should -Be 'Disabled'
    $enabled = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Enabled)
    $disabled = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Disabled)
    $enabled[0].State | Should -Be 'Enabled'
    $disabled[0].State | Should -Be 'Disabled'
    { Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Invalid } | Should -Throw
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideUserProxyCurrentState { throw 'The unsupported candidate must not query WinINet during apply preflight.' }
      $plan=@(Get-RideSingleOperationPlan -Id 'windows.proxy-auto-detect' -Action Set -State Disabled)
      { Invoke-RidePlan -Plan $plan -WhatIf } | Should -Throw '*does not support Windows 11*'
      Should -Invoke Get-RideUserProxyCurrentState -Exactly 0
    }
  }

  It 'plans machine WinHTTP automatic detection as pending until native acceptance' {
    $operation = Get-RideOperation -Id 'windows.winhttp-automatic-proxy-detection'
    $operation.Kind | Should -Be 'WinHttpProxy'
    $operation.Handler | Should -Be 'WinHttpProxy'
    $operation.Scope | Should -Be 'Machine'
    $operation.RequiresAdmin | Should -BeTrue
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.CandidateTargets | Should -Contain 'Windows 11'
    $operation.PendingAcceptance | Should -BeTrue
    $operation.States.Enabled | Should -BeTrue
    $operation.States.Disabled | Should -BeFalse
    $enabled = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Enabled)
    $enabled.Count | Should -Be 1
    $enabled[0].State | Should -Be 'Enabled'
    { Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State Custom } | Should -Throw
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideWinHttpProxyObservation { throw 'Unsupported candidates must fail before native WinHTTP inspection.' }
      $plan = @(Get-RideSingleOperationPlan -Id 'windows.winhttp-automatic-proxy-detection' -Action Set -State Disabled)
      { Invoke-RidePlan -Plan $plan -WhatIf } | Should -Throw '*does not support Windows 11*'
      Should -Invoke Get-RideWinHttpProxyObservation -Exactly 0
    }
  }

  It 'routes proxy status through the read-only inventory and reports the observed flag state' {
    InModuleScope RIDE.Engine {
      $observation=[pscustomobject]@{AutoDetectFlag=$true;FlagsSource='FlagsUi'}
      Mock Get-RideUserProxyCurrentState { [pscustomobject]@{Available=$true;Observation=$observation;Identity=[pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001';SessionId=1}} }
      $operation=Get-RideOperation -Id 'windows.proxy-auto-detect'
      $current=Get-RideCurrentState -Operation $operation
      $current.Available | Should -BeTrue
      Get-RideCurrentStateName -Operation $operation -CurrentState $current | Should -Be 'Enabled'
      Get-RideCurrentValueText -Operation $operation -CurrentState $current | Should -Be 'Default/LAN automatic detection: Enabled; FlagsUi'
      Test-RideCurrentStateMatch -Operation $operation -State Enabled -CurrentState $current | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Disabled -CurrentState $current | Should -BeFalse
      Should -Invoke Get-RideUserProxyCurrentState -Exactly 1
    }
  }

  It 'routes machine WinHTTP status through the read-only inventory and rejects user scope' {
    InModuleScope RIDE.Engine {
      $observation = [pscustomobject]@{Kind='WinHttpProxyConfiguration';Status='Captured';Scope='Machine';AutoDetect=$true;ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001'}
      $script:WinHttpObservation = $observation
      Mock Get-RideWinHttpProxyObservation { $script:WinHttpObservation }
      $operation = Get-RideOperation -Id 'windows.winhttp-automatic-proxy-detection'
      $current = Get-RideCurrentState -Operation $operation
      $current.Available | Should -BeTrue
      Get-RideCurrentStateName -Operation $operation -CurrentState $current | Should -Be 'Enabled'
      Get-RideCurrentValueText -Operation $operation -CurrentState $current | Should -Be 'Machine WinHTTP automatic proxy detection: Enabled'
      Test-RideCurrentStateMatch -Operation $operation -State Enabled -CurrentState $current | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Disabled -CurrentState $current | Should -BeFalse
      Should -Invoke Get-RideWinHttpProxyObservation -Exactly 1

      $script:WinHttpObservation.Scope = 'User'
      $current = Get-RideCurrentState -Operation $operation
      $current.Available | Should -BeFalse
      $current.Reason | Should -Match 'user-scoped'
    }
  }

  It 'captures machine WinHTTP recovery preparation and machine/user identity in saved state' {
    InModuleScope RIDE.Engine {
      Mock Initialize-RideStateRoot { $TestDrive }
      Mock New-RideWinHttpProxyConfigurationPatch { [pscustomobject]@{Snapshot=[pscustomobject]@{SchemaVersion=1;Kind='WinHttpProxyPreparationSnapshot';Scope='Machine';ChangedFields=@('AutoDetect')}} }
      $operation = Get-RideOperation -Id 'windows.winhttp-automatic-proxy-detection'
      $observation = [pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001';Scope='Machine';AutoDetect=$true}
      $current = [pscustomobject]@{Available=$true;Observation=$observation;Identity=[pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001'}}
      Save-RideOperationSnapshot -RunId 'winhttp-run' -Operation $operation -CurrentState $current -DesiredState Disabled
      $path = Join-Path (Join-Path $TestDrive 'winhttp-run') 'windows.winhttp-automatic-proxy-detection.json'
      $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
      $record.Snapshot.OperationId | Should -Be 'windows.winhttp-automatic-proxy-detection'
      $record.Snapshot.WinHttpSnapshot.Scope | Should -Be 'Machine'
      $record.Snapshot.ComputerName | Should -Be 'TEST'
      $record.Snapshot.UserSid | Should -Be 'S-1-5-21-1-2-3-1001'
      Should -Invoke New-RideWinHttpProxyConfigurationPatch -Exactly 1 -ParameterFilter { $Scope -eq 'Machine' -and $AutoDetect -eq $false }
    }
  }

  It 'uses one engine RunId for WinHTTP lifecycle state and the saved run' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Expand-RidePackageDependencyPlan { $Plan }
      Mock Save-RideRunManifest { $script:SavedWinHttpRunId = $RunId }
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideRunOperationProgress {}
      Mock New-RideWinHttpProxyConfigurationPatch { [pscustomobject]@{ChangeRequired=$true;DesiredValues=[pscustomobject]@{AutoDetect=$false};SettingsJson='{}';Snapshot=[pscustomobject]@{SchemaVersion=1;Kind='WinHttpProxyPreparationSnapshot';Scope='Machine';OriginalValues=[pscustomobject]@{}}} }
      Mock Get-RideCurrentState {
        $observation = [pscustomobject]@{Kind='WinHttpProxyConfiguration';Status='Captured';Scope='Machine';AutoDetect=$true;Proxy='';ProxyBypass='';AutoconfigUrl='';ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001'}
        [pscustomobject]@{Available=$true;Observation=$observation;Identity=[pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001'}}
      }
      Mock Apply-RideWinHttpProxyPatch { $script:ForwardedWinHttpRunId=$RunId; [pscustomobject]@{Status='Applied';ChangeApplied=$true} }
      $operation = Get-RideOperation -Id 'windows.winhttp-automatic-proxy-detection'
      $plan = @([pscustomobject]@{Operation=$operation;State='Disabled'})
      $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $engineRunId = [regex]::Match(($output -join "`n"),'Run ID: ([0-9a-f]{32})').Groups[1].Value
      $engineRunId | Should -Match '^[0-9a-f]{32}$'
      $script:ForwardedWinHttpRunId | Should -BeExactly $engineRunId
      $script:SavedWinHttpRunId | Should -BeExactly $engineRunId
      Should -Invoke Save-RideOperationSnapshot -Exactly 1 -ParameterFilter { $RunId -eq $engineRunId -and $Operation.Id -eq 'windows.winhttp-automatic-proxy-detection' }
      Should -Invoke Apply-RideWinHttpProxyPatch -Exactly 1 -ParameterFilter { $RunId -eq $engineRunId }
    }
  }

  It 'captures the automatic-detection edit and machine/user/session identity in saved state' {
    InModuleScope RIDE.Engine {
      Mock Initialize-RideStateRoot { $TestDrive }
      Mock New-RideUserProxyConfigurationPatch { [pscustomobject]@{Snapshot=[pscustomobject]@{SchemaVersion=1;Kind='UserProxyPreparationSnapshot';OwnedFlagMask=8}} }
      $operation=Get-RideOperation -Id 'windows.proxy-auto-detect'
      $observation=[pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;Flags=[uint32]8;AutoDetectFlag=$true}
      $current=[pscustomobject]@{Available=$true;Observation=$observation;Identity=[pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001';SessionId=1}}
      Save-RideOperationSnapshot -RunId 'proxy-run' -Operation $operation -CurrentState $current -DesiredState Disabled
      $path=Join-Path (Join-Path $TestDrive 'proxy-run') 'windows.proxy-auto-detect.json'
      $record=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
      $record.Snapshot.OperationId | Should -Be 'windows.proxy-auto-detect'
      $record.Snapshot.ProxySnapshot.OwnedFlagMask | Should -Be 8
      $record.Snapshot.ComputerName | Should -Be 'TEST'
      $record.Snapshot.UserSid | Should -Be 'S-1-5-21-1-2-3-1001'
      $record.Snapshot.SessionId | Should -Be 1
      Should -Invoke New-RideUserProxyConfigurationPatch -Exactly 1 -ParameterFilter { $AutomaticDetection -eq 'Disabled' -and $SetupScript -eq 'Unchanged' }
    }
  }

  It 'uses one engine RunId for the proxy lifecycle snapshot and saved run' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Initialize-RideStateRoot { $TestDrive }
      Mock New-RideUserProxyConfigurationPatch {
        [pscustomobject]@{ChangeRequired=$true;DesiredValues=[pscustomobject]@{Flags=[uint32]7;AutoConfigUrl=$null};Snapshot=[pscustomobject]@{SchemaVersion=1;Kind='UserProxyPreparationSnapshot';Original=$Observation}}
      }
      Mock Get-RideCurrentState {
        $observation=[pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;Flags=[uint32]15;AutoDetectFlag=$true;ProxyServer=$null;ProxyBypass=$null;AutoConfigUrl=$null;FlagsSource='FlagsUi'}
        [pscustomobject]@{Available=$true;Observation=$observation;Identity=[pscustomobject]@{ComputerName='TEST';UserSid='S-1-5-21-1-2-3-1001';SessionId=1}}
      }
      Mock Set-RideUserProxyConfigurationPatch { $script:ForwardedProxyRunId=$RunId; [pscustomobject]@{Status='Applied';ReadbackMatched=$true} }
      $operation=Get-RideOperation -Id 'windows.proxy-auto-detect'
      $plan=@([pscustomobject]@{Operation=$operation;State='Disabled'})
      $output=@(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $engineRunId=[regex]::Match(($output -join "`n"),'Run ID: ([0-9a-f]{32})').Groups[1].Value
      $engineRunId | Should -Match '^[0-9a-f]{32}$'
      $script:ForwardedProxyRunId | Should -BeExactly $engineRunId
      Should -Invoke Set-RideUserProxyConfigurationPatch -Exactly 1 -ParameterFilter { $RunId -eq $engineRunId }
    }
  }

  It 'maps the first UI Tweaks batch to reversible registry states in the default profile' {
    $expected = @{
      'windows.action-center-policy' = @{ State = 'Disabled'; Value = 1 }
      'windows.toast-notifications-policy' = @{ State = 'Disabled'; Value = 0 }
      'windows.lock-screen-blur' = @{ State = 'Disabled'; Value = 1 }
      'windows.sticky-keys-prompts' = @{ State = 'Disabled'; Value = '506' }
      'windows.toggle-keys-prompts' = @{ State = 'Disabled'; Value = '58' }
      'windows.filter-keys-prompts' = @{ State = 'Disabled'; Value = '122' }
      'windows.file-operation-details' = @{ State = 'Enabled'; Value = 1 }
      'windows.taskbar-search-visibility' = @{ State = 'Hidden'; Value = 0 }
      'windows.task-view-button' = @{ State = 'Hidden'; Value = 0 }
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile)
    foreach ($id in $expected.Keys) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $desired = $expected[$id]
      $plannedOperation = $planned | Where-Object { $_.Operation.Id -eq $id } | Select-Object -First 1
      $plannedOperation.State | Should -Be $desired.State
      InModuleScope RIDE.Engine -Parameters @{ Id = $id; State = $desired.State; Value = $desired.Value } {
        param($Id, $State, $Value)
        $operation = Get-RideOperation -Id $Id
        Get-RideOperationValue -Operation $operation -State $State | Should -Be $Value
      }
    }
  }

  It 'maps the second UI Tweaks batch to reversible registry states in the default profile' {
    $expected = @{
      'windows.taskbar-combine-primary' = @{ State = 'WhenFull'; Value = 1 }
      'windows.taskbar-combine-secondary' = @{ State = 'WhenFull'; Value = 1 }
      'windows.taskbar-people-icon' = @{ State = 'Hidden'; Value = 0 }
      'windows.tray-icon-promotion' = @{ State = 'ShowAll'; Value = 1 }
      'windows.store-app-suggestion' = @{ State = 'Disabled'; Value = 1 }
      'windows.new-app-alert' = @{ State = 'Disabled'; Value = 1 }
      'windows.startup-sound' = @{ State = 'Disabled'; Value = 1 }
      'windows.taskbar-widgets' = @{ State = 'Hidden'; Value = 0 }
      'windows.taskbar-chat' = @{ State = 'Hidden'; Value = 0 }
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile)
    foreach ($id in $expected.Keys) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $desired = $expected[$id]
      $plannedOperation = $planned | Where-Object { $_.Operation.Id -eq $id } | Select-Object -First 1
      $plannedOperation.State | Should -Be $desired.State
      InModuleScope RIDE.Engine -Parameters @{ Id = $id; State = $desired.State; Value = $desired.Value } {
        param($Id, $State, $Value)
        $operation = Get-RideOperation -Id $Id
        Get-RideOperationValue -Operation $operation -State $State | Should -Be $Value
      }
    }
  }

  It 'maps optional UI Tweaks selectors to reversible registry states without adding them to the default profile' {
    $expected = @{
      'windows.taskbar-clock-seconds' = @{ State = 'Shown'; Value = 1; ValueName = 'ShowSecondsInSystemClock' }
      'windows.recycle-bin-delete-confirmation' = @{ State = 'Enabled'; Value = 1; ValueName = 'ConfirmFileDelete' }
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plannedIds = @((Get-RidePlan -Profile $defaultProfile).Operation.Id)
    foreach ($id in $expected.Keys) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $operation.ValueName | Should -Be $expected[$id].ValueName
      $operation.Scope | Should -Be 'User'
      $operation.Rollback | Should -Be 'Exact'
      $plannedIds | Should -Not -Contain $id
      InModuleScope RIDE.Engine -Parameters @{ Id = $id; State = $expected[$id].State; Value = $expected[$id].Value } {
        param($Id, $State, $Value)
        $operation = Get-RideOperation -Id $Id
        Get-RideOperationValue -Operation $operation -State $State | Should -Be $Value
        Get-RideOperationValue -Operation $operation -State $operation.BaselineState | Should -BeNullOrEmpty
      }
    }
  }

  It 'maps Edge Alt+Tab tab exclusion to the declared scalar value' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile | Where-Object { $_.Operation.Id -eq 'windows.edge-tabs-alt-tab' })
    $planned.Count | Should -Be 1
    $planned[0].State | Should -Be 'Excluded'

    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.edge-tabs-alt-tab'
      Get-RideOperationValue -Operation $operation -State 'Excluded' | Should -Be 3
      Get-RideOperationValue -Operation $operation -State 'RecentTabs' | Should -Be 1
    }
  }

  It 'maps optional desktop icon visibility states without adding the selector to the default profile' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'windows.desktop-icons-visibility' | Select-Object -First 1
    $operation | Should -Not -BeNullOrEmpty
    $operation.States.Visible | Should -Be 0
    $operation.States.Hidden | Should -Be 1
    $operation.Scope | Should -Be 'User'
    $operation.Rollback | Should -Be 'Exact'
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    @($defaultProfile.Operations | Where-Object Id -eq 'windows.desktop-icons-visibility').Count | Should -Be 0
  }

  It 'maps low-risk Explorer UI selectors to reversible registry states in the default profile' {
    $expected = @{
      'windows.hidden-files-visibility' = @{ State = 'Visible'; Value = 1 }
      'windows.navigation-pane-auto-expand' = @{ State = 'Enabled'; Value = 1 }
      'windows.sync-provider-notifications' = @{ State = 'Hidden'; Value = 0 }
      'windows.explorer-recent-shortcuts' = @{ State = 'Hidden'; Value = 0 }
      'windows.explorer-frequent-shortcuts' = @{ State = 'Hidden'; Value = 0 }
      'windows.explorer-start-location' = @{ State = 'ThisPC'; Value = 1 }
      'windows.thumbnail-cache-creation' = @{ State = 'Disabled'; Value = 1 }
      'windows.network-thumbnail-database' = @{ State = 'Disabled'; Value = 1 }
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $planned = @(Get-RidePlan -Profile $defaultProfile)
    foreach ($id in $expected.Keys) {
      $operation = $script:Catalog.Operations | Where-Object Id -eq $id | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $desired = $expected[$id]
      $plannedOperation = $planned | Where-Object { $_.Operation.Id -eq $id } | Select-Object -First 1
      $plannedOperation.State | Should -Be $desired.State
      InModuleScope RIDE.Engine -Parameters @{ Id = $id; State = $desired.State; Value = $desired.Value } {
        param($Id, $State, $Value)
        $operation = Get-RideOperation -Id $Id
        Get-RideOperationValue -Operation $operation -State $State | Should -Be $Value
      }
    }
  }
}

Describe 'RIDE desired-state comparison' {
  It 'matches the inking and typing setting with its declared disabled value' {
    InModuleScope RIDE.Engine {
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      Test-RideDesiredState -Operation $operation -State 'Disabled' | Should -BeTrue
    }
  }

  It 'compares a setting with the declared desired value' {
    InModuleScope RIDE.Engine {
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      $operation = Get-RideOperation -Id 'windows.show-known-extensions'
      Test-RideDesiredState -Operation $operation -State 'Enabled' | Should -BeTrue
    }
  }

  It 'reports a partial failure with the run ID and saved operations' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 1; ValueType = 'DWord' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState { throw 'simulated registry failure' }
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Disabled' })

      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*Completed operations:*Failed operation:*Unfinished operations:*Recovery:*restore -RunId*simulated registry failure*'
    }
  }

  It 'applies the legacy disabled value through the registry handler' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState {}
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Disabled' })

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Set-RideSettingState -Exactly 1 -ParameterFilter { $Operation.Id -eq 'windows.inking-typing-data' -and $Value -eq 0 }
    }
  }

  It 'does not rewrite the inking and typing value when it is already disabled' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 0; ValueType = 'DWord' } }
      Mock Test-RideDesiredState { $true }
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState {}
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Disabled' })

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideSettingState -Exactly 0
    }
  }

  It 'calls the package installer through the mocked handler' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $false; DisplayVersion = $null } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Install-RidePackage {}
      $operation = Get-RideOperation -Id 'package.7zip'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Present' })

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Install-RidePackage -Exactly 1
    }
  }

  It 'does not save or mutate state in WhatIf mode' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Exists = $true; Value = 1; ValueType = 'DWord' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState {}
      $operation = Get-RideOperation -Id 'windows.inking-typing-data'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Enabled' })

      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideSettingState -Exactly 0
    }
  }
}

Describe 'RIDE run operation progress' {
  It 'persists pending, snapshot, completion and failure states atomically in the run manifest' {
    $fixtureRoot = Join-Path $TestDrive 'run-progress'
    InModuleScope RIDE.Engine -Parameters @{ Root = $fixtureRoot } {
      Mock Get-RideStateRoot { Join-Path $Root $Scope }
      $runId = 'a' * 32
      $plan = @(
        [pscustomobject]@{ Operation = @{ Id = 'test.user-setting'; Scope = 'User' }; State = 'Enabled' },
        [pscustomobject]@{ Operation = @{ Id = 'test.user-package'; Scope = 'User' }; State = 'Present' }
      )
      Save-RideRunManifest -RunId $runId -Plan $plan
      $manifestPath = Join-Path (Join-Path (Join-Path $Root 'User') $runId) '_manifest.json'
      $initial = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
      @($initial.OperationProgress | ForEach-Object Status) | Should -Be @('Pending', 'Pending')

      Set-RideRunOperationProgress -RunId $runId -OperationId 'test.user-setting' -Status 'SnapshotSaved'
      Set-RideRunOperationProgress -RunId $runId -OperationId 'test.user-setting' -Status 'Completed'
      Set-RideRunOperationProgress -RunId $runId -OperationId 'test.user-package' -Status 'Failed' -ErrorMessage 'simulated package failure'
      $updated = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
      $updated.OperationProgress[0].Status | Should -Be 'Completed'
      $updated.OperationProgress[0].SnapshotSaved | Should -BeTrue
      $updated.OperationProgress[1].Status | Should -Be 'Failed'
      $updated.OperationProgress[1].SnapshotSaved | Should -BeFalse
      $updated.OperationProgress[1].Error | Should -Be 'simulated package failure'
      @(Get-ChildItem -LiteralPath (Split-Path -Parent $manifestPath) -Filter '.manifest-*.tmp' -File).Count | Should -Be 0
    }
  }

  It 'reports prior completion when a later operation fails before its handler starts' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState {
        if ($Operation.Id -eq 'windows.show-known-extensions') { throw 'simulated state inspection failure' }
        [pscustomobject]@{ Exists = $true; Value = 1; ValueType = 'DWord' }
      }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideSettingState {}
      $first = Get-RideOperation -Id 'windows.inking-typing-data'
      $second = Get-RideOperation -Id 'windows.show-known-extensions'
      $plan = @(
        [pscustomobject]@{ Operation = $first; State = 'Disabled' },
        [pscustomobject]@{ Operation = $second; State = 'Enabled' }
      )
      $failure = $null
      try { Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null }
      catch { $failure = $_.Exception.Message }
      $failure | Should -Match 'Completed operations: windows\.inking-typing-data'
      $failure | Should -Match 'Failed operation: windows\.show-known-extensions'
      $failure | Should -Match 'Recovery: run.*restore -RunId.*then reapply the same profile'
      $failure | Should -Match 'simulated state inspection failure'
      Should -Invoke Set-RideSettingState -Exactly 1
    }
  }
}

Describe 'RIDE settings snapshot restore' {
  It 'restores the recorded value and registry type' {
    Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-Settings.psm1') -Force
    InModuleScope RIDE-Settings {
      Mock Set-RideSettingState {}
      $operation = @{ Id = 'test.setting'; RegistryPath = 'HKCU:\Software\RIDE-Test'; ValueName = 'Sample'; ValueType = 'DWord' }
      $snapshot = [pscustomobject]@{ Exists = $true; KeyExisted = $true; Value = 42; ValueType = 'QWord' }
      Restore-RideSettingState -Operation $operation -Snapshot $snapshot
      Should -Invoke Set-RideSettingState -Exactly 1 -ParameterFilter { $Value -eq 42 -and $Operation.ValueType -eq 'QWord' }
    }
  }
}

Describe 'RIDE Defender exclusion handler' {
  BeforeAll {
    Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-Defender.psm1') -Force
  }

  It 'reads an exclusion and reports its resolved path' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @('C:\Tools') }
      $state = Get-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' }
      $state.Present | Should -BeTrue
      $state.Path | Should -Be 'C:\Tools'
    }
  }

  It 'adds an absent exclusion and leaves an already present exclusion unchanged' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @('C:\Tools') }
      Mock Add-RideDefenderExclusion {}
      Mock Remove-RideDefenderExclusion {}
      Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Present
      Should -Invoke Add-RideDefenderExclusion -Exactly 0
      Should -Invoke Remove-RideDefenderExclusion -Exactly 0
    }
  }

  It 'adds the exclusion after preparing its managed directory' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      $script:ExclusionFixture = @()
      Mock Get-RideDefenderExclusionPaths { $script:ExclusionFixture }
      Mock Test-Path { $true }
      Mock Add-RideDefenderExclusion { param($Path) $script:ExclusionFixture = @($Path) }
      Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Present
      Should -Invoke Add-RideDefenderExclusion -Exactly 1 -ParameterFilter { $Path -eq 'C:\Tools' }
    }
  }

  It 'removes an existing exclusion and restores captured membership' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      $script:ExclusionFixture = @('C:\Tools')
      Mock Get-RideDefenderExclusionPaths { $script:ExclusionFixture }
      Mock Remove-RideDefenderExclusion { $script:ExclusionFixture = @() }
      Mock Add-RideDefenderExclusion { param($Path) $script:ExclusionFixture = @($Path) }
      Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Absent
      Should -Invoke Remove-RideDefenderExclusion -Exactly 1 -ParameterFilter { $Path -eq 'C:\Tools' }

      Restore-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -Snapshot ([pscustomobject]@{ Present = $true; Path = 'C:\CapturedTools' })
      Should -Invoke Add-RideDefenderExclusion -Exactly 1 -ParameterFilter { $Path -eq 'C:\CapturedTools' }
    }
  }

  It 'propagates Defender command failures' {
    InModuleScope RIDE-Defender {
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { @() }
      Mock Test-Path { $true }
      Mock Add-RideDefenderExclusion { throw 'simulated Defender failure' }
      { Set-RideDefenderExclusionState -Operation @{ Id = 'test.tools'; PathResolver = 'ToolsDirectory' } -State Present } | Should -Throw '*simulated Defender failure*'
    }
  }
}

Describe 'RIDE Defender exclusion planning and apply' {
  It 'includes both active default selectors as Present and classifies them as settings' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $defaultProfile)
    ($plan | Where-Object { $_.Operation.Kind -eq 'DefenderExclusion' }).Count | Should -Be 2
    ($plan | Where-Object { $_.Operation.Kind -eq 'DefenderExclusion' } | ForEach-Object State | Select-Object -Unique) | Should -Be 'Present'
    (Show-RideCatalog -View settings | Where-Object Kind -eq 'DefenderExclusion').Count | Should -Be 2
  }

  It 'plans direct set and unset states and compares live exclusion membership' {
    $setPlan = @(Get-RideSingleOperationPlan -Id 'windows.defender-tools-exclusion' -Action Set -State Present)
    $unsetPlan = @(Get-RideSingleOperationPlan -Id 'windows.defender-tools-exclusion' -Action Unset)
    $setPlan[0].State | Should -Be 'Present'
    $unsetPlan[0].State | Should -Be 'Absent'

    InModuleScope RIDE.Engine {
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $true; Path = 'C:\Tools' } }
      $operation = Get-RideOperation -Id 'windows.defender-tools-exclusion'
      Test-RideDesiredState -Operation $operation -State Present | Should -BeTrue
      Test-RideDesiredState -Operation $operation -State Absent | Should -BeFalse
    }
  }

  It 'applies through the mocked handler and does not mutate under WhatIf' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $false; Path = 'C:\Tools' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideDefenderExclusionState {}
      $operation = Get-RideOperation -Id 'windows.defender-tools-exclusion'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Present' })

      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideDefenderExclusionState -Exactly 0

      Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
      Should -Invoke Set-RideDefenderExclusionState -Exactly 1 -ParameterFilter { $Operation.Id -eq 'windows.defender-tools-exclusion' -and $State -eq 'Present' -and $ExpectedState.Path -eq 'C:\Tools' -and $ExpectedState.Present -eq $false }
    }
  }

  It 'reports a partial apply failure with the run ID and saved operation' {
    InModuleScope RIDE.Engine {
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $false; Path = 'C:\Tools' } }
      Mock Test-RideDesiredState { $false }
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Set-RideDefenderExclusionState { throw 'simulated Defender write failure' }
      $operation = Get-RideOperation -Id 'windows.defender-tools-exclusion'
      $plan = @([pscustomobject]@{ Operation = $operation; State = 'Present' })
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated Defender write failure*'
    }
  }
}

Describe 'RIDE Windows service operations' {
  It 'plans the Hardening Windows defaults and classifies services as settings' {
    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $defaultProfile)
    $servicePlan = @($plan | Where-Object { $_.Operation.Kind -eq 'WindowsService' })
    $servicePlan.Count | Should -Be 2
    ($servicePlan.State | Select-Object -Unique) | Should -Be 'Disabled'
    $serviceIds = @((Show-RideCatalog -View settings | Where-Object Kind -eq 'WindowsService').Id)
    $serviceIds | Should -Contain 'windows.ssdp-discovery-service'
    $serviceIds | Should -Contain 'windows.upnp-device-host-service'
  }

  It 'discovers service startup mode and running status' {
    InModuleScope RIDE-Services {
      Mock Get-Service { [pscustomobject]@{ Status = 'Stopped'; StartType = 'Manual' } }
      Mock Get-CimInstance { [pscustomobject]@{ StartMode = 'Manual' } }
      $state = Get-RideWindowsServiceState -Operation @{ ServiceName = 'SSDPSRV' }
      $state.StartupType | Should -Be 'Manual'
      $state.Status | Should -Be 'Stopped'
    }
  }

  It 'sets and restores both startup mode and running status' {
    InModuleScope RIDE-Services {
      $script:serviceStatus = 'Stopped'
      $script:serviceStartupType = 'Manual'
      Mock Get-Service { [pscustomobject]@{ Status = $script:serviceStatus; StartType = $script:serviceStartupType } }
      Mock Get-CimInstance { [pscustomobject]@{ StartMode = $(if ($script:serviceStartupType -eq 'Automatic') { 'Auto' } else { $script:serviceStartupType }) } }
      Mock Set-Service { $script:serviceStartupType = $StartupType }
      Mock Start-Service { $script:serviceStatus = 'Running' }
      Mock Stop-Service { $script:serviceStatus = 'Stopped' }
      $operation = @{ Id = 'test.service'; ServiceName = 'SSDPSRV'; States = @{ Enabled = @{ StartupType = 'Manual'; Status = 'Running' } } }
      Set-RideWindowsServiceState -Operation $operation -State Enabled
      Should -Invoke Start-Service -Exactly 1 -ParameterFilter { $Name -eq 'SSDPSRV' }
      Should -Invoke Set-Service -Exactly 0

      Restore-RideWindowsServiceState -Operation $operation -Snapshot ([pscustomobject]@{ StartupType = 'Disabled'; Status = 'Stopped' })
      Should -Invoke Set-Service -Exactly 1 -ParameterFilter { $Name -eq 'SSDPSRV' -and $StartupType -eq 'Disabled' }
      Should -Invoke Stop-Service -Exactly 1 -ParameterFilter { $Name -eq 'SSDPSRV' }
    }
  }

  It 'matches the declared Enabled and Disabled service configurations' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.ssdp-discovery-service'
      $enabled = [pscustomobject]@{ StartupType = 'Manual'; Status = 'Running' }
      $disabled = [pscustomobject]@{ StartupType = 'Disabled'; Status = 'Stopped' }
      Test-RideCurrentStateMatch -Operation $operation -State Enabled -CurrentState $enabled | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Disabled -CurrentState $disabled | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Enabled -CurrentState $disabled | Should -BeFalse
    }
  }

  It 'reports service-handler failures without swallowing them' {
    InModuleScope RIDE-Services {
      Mock Get-Service { throw 'simulated service manager failure' }
      { Get-RideWindowsServiceState -Operation @{ ServiceName = 'SSDPSRV' } } | Should -Throw '*simulated service manager failure*'
    }
  }
}

Describe 'RIDE network profile operations' {
  It 'persists the profile identities and original categories in the run snapshot' {
    InModuleScope RIDE.Engine {
      Mock Initialize-RideStateRoot { $TestDrive }
      $operation = Get-RideOperation -Id 'windows.current-network-category'
      $currentState = [pscustomobject]@{ Profiles = @(
        [pscustomobject]@{ InterfaceIndex = 12; Name = 'Trusted LAN'; NetworkCategory = 'Private' }
        [pscustomobject]@{ InterfaceIndex = 14; Name = 'Guest Wi-Fi'; NetworkCategory = 'Public' }
      ) }

      Save-RideOperationSnapshot -RunId 'network-profile-test' -Operation $operation -CurrentState $currentState
      $recordPath = Join-Path (Join-Path $TestDrive 'network-profile-test') 'windows.current-network-category.json'
      $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
      @($record.Snapshot.Profiles).Count | Should -Be 2
      $record.Snapshot.Profiles[0].InterfaceIndex | Should -Be 12
      $record.Snapshot.Profiles[1].NetworkCategory | Should -Be 'Public'
    }
  }

  It 'captures every reported non-domain profile for the operation state' {
    InModuleScope RIDE-NetworkProfiles {
      Mock Get-NetConnectionProfile {
        @(
          [pscustomobject]@{ InterfaceIndex = 12; Name = 'Trusted LAN'; NetworkCategory = 'Private' }
          [pscustomobject]@{ InterfaceIndex = 13; Name = 'Managed LAN'; NetworkCategory = 'DomainAuthenticated' }
          [pscustomobject]@{ InterfaceIndex = 14; Name = 'Guest Wi-Fi'; NetworkCategory = 'Public' }
        )
      }

      $state = Get-RideNetworkProfileState -Operation @{ Id = 'test.network' }
      $state.Profiles.Count | Should -Be 2
      (@($state.Profiles.Name) -join ',') | Should -Be 'Trusted LAN,Guest Wi-Fi'
    }
  }

  It 'sets every non-domain profile and skips profiles already in the desired category' {
    InModuleScope RIDE-NetworkProfiles {
      Mock Get-NetConnectionProfile {
        @(
          [pscustomobject]@{ InterfaceIndex = 12; Name = 'Trusted LAN'; NetworkCategory = 'Public' }
          [pscustomobject]@{ InterfaceIndex = 14; Name = 'Guest Wi-Fi'; NetworkCategory = 'Private' }
        )
      }
      Mock Set-NetConnectionProfile {}

      Set-RideNetworkProfileState -Operation @{ Id = 'test.network'; States = @{ Private = 'Private' } } -State Private
      Should -Invoke Set-NetConnectionProfile -Exactly 1 -ParameterFilter { $InterfaceIndex -eq 12 -and $NetworkCategory -eq 'Private' }
    }
  }

  It 'restores each captured category using its interface identity' {
    InModuleScope RIDE-NetworkProfiles {
      Mock Get-NetConnectionProfile {
        @(
          [pscustomobject]@{ InterfaceIndex = 12; Name = 'Trusted LAN'; NetworkCategory = 'Private' }
          [pscustomobject]@{ InterfaceIndex = 14; Name = 'Guest Wi-Fi'; NetworkCategory = 'Private' }
        )
      }
      Mock Set-NetConnectionProfile {}

      Restore-RideNetworkProfileState -Snapshot ([pscustomobject]@{ Profiles = @(
        [pscustomobject]@{ InterfaceIndex = 12; Name = 'Trusted LAN'; NetworkCategory = 'Public' }
        [pscustomobject]@{ InterfaceIndex = 14; Name = 'Guest Wi-Fi'; NetworkCategory = 'Public' }
      ) })
      Should -Invoke Set-NetConnectionProfile -Exactly 2
    }
  }

  It 'matches all eligible profiles to the desired category' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.current-network-category'
      $private = [pscustomobject]@{ Profiles = @([pscustomobject]@{ NetworkCategory = 'Private' }, [pscustomobject]@{ NetworkCategory = 'Private' }) }
      $mixed = [pscustomobject]@{ Profiles = @([pscustomobject]@{ NetworkCategory = 'Private' }, [pscustomobject]@{ NetworkCategory = 'Public' }) }
      Test-RideCurrentStateMatch -Operation $operation -State Private -CurrentState $private | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Private -CurrentState $mixed | Should -BeFalse
    }
  }
}

Describe 'RIDE registry value-set recovery snapshot persistence' {
  It 'persists captured ancestor-key existence for exact recovery' {
    InModuleScope RIDE.Engine {
      Mock Initialize-RideStateRoot { $TestDrive }
      $operation = Get-RideOperation -Id 'windows.sha256-certutil-context-menu'
      $keyPathExistence = @(
        [pscustomobject]@{ Path = 'HKCU:\Software'; Existed = $true }
        [pscustomobject]@{ Path = 'HKCU:\Software\Classes'; Existed = $true }
        [pscustomobject]@{ Path = 'HKCU:\Software\Classes\*\shell\RIDE.Sha256Certutil'; Existed = $false }
      )
      $currentState = [pscustomobject]@{
        Values = @(
          [pscustomobject]@{ Key = 'Menu'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $false }
          [pscustomobject]@{ Key = 'Command'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $false }
        )
        KeyPathExistence = $keyPathExistence
      }

      Save-RideOperationSnapshot -RunId 'registry-value-set-test' -Operation $operation -CurrentState $currentState -DesiredState Enabled
      $recordPath = Join-Path (Join-Path $TestDrive 'registry-value-set-test') 'windows.sha256-certutil-context-menu.json'
      $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
      @($record.Snapshot.KeyPathExistence).Count | Should -Be 3
      $record.Snapshot.KeyPathExistence[0].Path | Should -Be 'HKCU:\Software'
      $record.Snapshot.KeyPathExistence[0].Existed | Should -BeTrue
      $record.Snapshot.KeyPathExistence[2].Existed | Should -BeFalse
    }
  }
}

Describe 'RIDE UWP privacy policy migration' {
  It 'maps UWP privacy selectors to policy and capability registry operations' {
    $operation = $script:Catalog.Operations | Where-Object Id -eq 'windows.background-apps-policy'
    $operation.ValueName | Should -Be 'LetAppsRunInBackground'
    $operation.States.Disabled | Should -Be 2
    $operation.States.Enabled | Should -BeNullOrEmpty

    $policyOperations = @($script:Catalog.Operations | Where-Object Id -like 'windows.uwp-*' | Where-Object Kind -eq 'RegistryValue')
    $policyOperations.Count | Should -Be 19
    foreach ($policy in $policyOperations | Where-Object { $_.Id -notmatch 'documents-library|pictures-library|videos-library|file-system-access|swap-file' }) {
      $policy.States.Disabled | Should -Be 2
      $policy.States.Enabled | Should -BeNullOrEmpty
    }
    foreach ($id in @('windows.uwp-documents-library-access', 'windows.uwp-pictures-library-access', 'windows.uwp-videos-library-access', 'windows.uwp-broad-file-system-access-access')) {
      $policy = $script:Catalog.Operations | Where-Object Id -eq $id
      $policy.States.Denied | Should -Be 'Deny'
      $policy.States.Allowed | Should -Be 'Allow'
      $policy.States.UserControlled | Should -BeNullOrEmpty
    }

    $defaultProfile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    ($defaultProfile.Operations | Where-Object Id -eq 'windows.background-apps-policy').State | Should -Be 'Disabled'
  }

  It 'provides direct set planning for the reversible per-app override reset' {
    $plan = @(Get-RideSingleOperationPlan -Id 'windows.uwp-background-app-user-overrides' -Action Set -State Reset)
    $plan[0].State | Should -Be 'Reset'
  }

  It 'captures, clears, and restores app-specific override values' {
    InModuleScope RIDE-BackgroundApps {
      $script:applicationKeys = @(
        [pscustomobject]@{ PSChildName = 'App.One'; PSPath = 'TestDrive:\App.One' }
      )
      $script:storedValues = @{ Disabled = 1; DisabledByUser = 1 }
      Mock Get-ChildItem { $script:applicationKeys }
      Mock Get-RideSettingState {
        param($Operation)
        if ($script:storedValues.ContainsKey($Operation.ValueName)) {
          [pscustomobject]@{ Exists = $true; Value = $script:storedValues[$Operation.ValueName]; ValueType = 'DWord' }
        }
        else { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
      }
      Mock Remove-ItemProperty { param($Name); $script:storedValues.Remove($Name) | Out-Null }
      Mock New-ItemProperty {}

      $operation = @{ RegistryPath = 'TestDrive:\BackgroundApps'; ValueNames = @('Disabled', 'DisabledByUser') }
      $state = Get-RideBackgroundAppOverrides -Operation $operation
      $state.Present | Should -BeTrue
      $state.Count | Should -Be 2
      Reset-RideBackgroundAppOverrides -Operation $operation
      Should -Invoke Remove-ItemProperty -Exactly 2

      $snapshot = [pscustomobject]@{ Overrides = @(
        [pscustomobject]@{ SubKey = 'App.One'; ValueName = 'Disabled'; Value = 1; ValueType = 'DWord' },
        [pscustomobject]@{ SubKey = 'App.One'; ValueName = 'DisabledByUser'; Value = 1; ValueType = 'DWord' }
      ) }
      Restore-RideBackgroundAppOverrides -Operation $operation -Snapshot $snapshot
      Should -Invoke New-ItemProperty -Exactly 2
    }
  }
}

Describe 'RIDE Security Tweaks default migration' {
  It 'plans the migrated registry and BCD defaults with explicit states' {
    $profile = Import-PowerShellDataFile (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $plan = @(Get-RidePlan -Profile $profile)
    $expected = @{
      'windows.admin-share-workstation' = 'Disabled'
      'windows.account-protection-warning' = 'Hidden'
      'windows.script-host-policy' = 'Disabled'
      'windows.dotnet-strong-crypto-64bit' = 'Enabled'
      'windows.dotnet-strong-crypto-32bit' = 'Enabled'
      'windows.f8-boot-menu-policy' = 'Legacy'
      'windows.dep-boot-policy' = 'OptOut'
    }
    foreach ($id in $expected.Keys) {
      ($plan | Where-Object { $_.Operation.Id -eq $id }).State | Should -Be $expected[$id]
    }
    ($script:Catalog.Operations | Where-Object Id -eq 'windows.admin-share-server').SupportedTargets | Should -Be 'Windows Server 2025'
  }

  It 'compares and names captured boot configuration states' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.f8-boot-menu-policy'
      $legacy = [pscustomobject]@{ Exists = $true; Value = 'Legacy' }
      $default = [pscustomobject]@{ Exists = $false; Value = $null }
      Test-RideCurrentStateMatch -Operation $operation -State Legacy -CurrentState $legacy | Should -BeTrue
      Test-RideCurrentStateMatch -Operation $operation -State Standard -CurrentState $default | Should -BeTrue
      Get-RideCurrentStateName -Operation $operation -CurrentState $legacy | Should -Be 'Legacy'
    }
  }

  It 'discovers BCD values and reports command errors' {
    InModuleScope RIDE-BootConfiguration {
      Mock bcdedit.exe { 'bootmenupolicy          Legacy'; $global:LASTEXITCODE = 0 }
      $operation = @{ BcdElement = 'bootmenupolicy' }
      $state = Get-RideBootConfigurationState -Operation $operation
      $state.Exists | Should -BeTrue
      $state.Value | Should -Be 'Legacy'

      Mock bcdedit.exe { 'Access is denied'; $global:LASTEXITCODE = 1 }
      { Get-RideBootConfigurationState -Operation $operation } | Should -Throw '*BCDEdit query failed*'
    }
  }
}
