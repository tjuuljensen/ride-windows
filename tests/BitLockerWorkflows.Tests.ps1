<#
.SYNOPSIS
  Verify secret-safe BitLocker OS-volume workflow boundaries.
.DESCRIPTION
  Uses synthetic BitLocker volume objects and mocked Windows cmdlets. No Windows
  protection state or recovery secret is accessed or changed.
.EXAMPLE
  $config = New-PesterConfiguration
  $config.Run.Path = '.\tests\BitLockerWorkflows.Tests.ps1'
  $config.TestRegistry.Enabled = $false
  Invoke-Pester -Configuration $config
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: Repository module; mocks replace BitLocker and TPM cmdlets.
  Recovery: Pester removes only its own temporary data.
  Version: Test fixture; no independent script version.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  foreach ($name in @('Get-BitLockerVolume', 'Enable-BitLocker', 'Disable-BitLocker', 'Add-BitLockerKeyProtector', 'Remove-BitLockerKeyProtector', 'Get-Tpm')) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
      Set-Item -Path "function:global:$name" -Value ([scriptblock]::Create('param() throw "Unmocked BitLocker command: ' + $name + '"'))
    }
  }
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.BitLockerWorkflows.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogValidation.psm1') -Force
  $script:Catalog = Import-RideCatalogData -Path (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')

  function New-BitLockerTestVolume {
    param([string] $Status = 'FullyDecrypted', [string] $RecoveryId = '{11111111-1111-1111-1111-111111111111}', [string] $Secret = '111111-222222-333333-444444-555555-666666-777777-888888')
    [pscustomobject]@{
      MountPoint = $env:SystemDrive.TrimEnd('\') + '\'
      VolumeStatus = $Status
      VolumeType = 'OperatingSystem'
      EncryptionPercentage = 0
      ProtectionStatus = 'Off'
      EncryptionMethod = 'None'
      KeyProtector = @([pscustomobject]@{ KeyProtectorId = $RecoveryId; KeyProtectorType = 'RecoveryPassword'; RecoveryPassword = $Secret })
    }
  }
}

Describe 'BitLocker workflow catalog' {
  It 'maps all four legacy selectors to separate pending staged workflows' {
    $legacyMap = @{
      EnableBitlocker = 'Enable'
      DisableBitlocker = 'Disable'
      AddBitlockerRecoveryPswd = 'AddRecoveryPassword'
      DisplayBitlockerRecoveryPwd = 'ShowRecoveryPassword'
    }
    foreach ($legacy in $legacyMap.Keys) {
      $operation = $script:Catalog.Operations | Where-Object { $_.Kind -eq 'BitLockerWorkflow' -and $_.LegacySelectors -contains $legacy } | Select-Object -First 1
      $operation | Should -Not -BeNullOrEmpty
      $operation.Workflow | Should -Be $legacyMap[$legacy]
      $operation.PendingAcceptance | Should -BeTrue
      $operation.SupportedTargets | Should -BeNullOrEmpty
      $operation.Rollback | Should -BeIn @('Staged', 'NonRestorable')
    }
  }

  It 'passes catalog schema validation and exposes no BitLocker default-profile selections' {
    @(Get-RideCatalogValidationErrors -Catalog $script:Catalog) | Should -BeNullOrEmpty
    $backupOperation = $script:Catalog.Operations | Where-Object Workflow -eq 'BackupRecoveryPassword' | Select-Object -First 1
    (@($backupOperation.BackupDestinationChoices | Sort-Object) -join ',') | Should -Be 'FileOrUsb,PersonalMicrosoftAccount,Print'
    $defaultProfile = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $workflowIds = @($script:Catalog.Operations | Where-Object Kind -eq 'BitLockerWorkflow' | ForEach-Object Id)
    @($defaultProfile.Operations | Where-Object { $_.Id -in $workflowIds }).Count | Should -Be 0
  }

  It 'blocks the direct tool before action while target acceptance is pending' {
    $tool = Join-Path $script:RepositoryRoot 'tools/Invoke-RideBitLockerWorkflow.ps1'
    { & $tool -OperationId 'windows.bitlocker-add-recovery-password' -MountPoint 'C:' -Confirm:$false } | Should -Throw '*pending disposable Windows acceptance*'
  }

  It 'allows target activation only when catalog support is explicitly recorded' {
    $catalog = @{
      SchemaVersion = $script:Catalog.SchemaVersion
      Operations = @($script:Catalog.Operations | ForEach-Object { $_.Clone() })
      Groups = @($script:Catalog.Groups | ForEach-Object { $_.Clone() })
    }
    foreach ($operation in @($catalog.Operations | Where-Object Kind -eq 'BitLockerWorkflow')) {
      $operation.PendingAcceptance = $false
      $operation.SupportedTargets = @('Windows 11')
      $operation.Remove('CandidateTargets')
    }
    @(Get-RideCatalogValidationErrors -Catalog $catalog) | Should -BeNullOrEmpty
  }
}

Describe 'RIDE BitLocker workflows' {
  BeforeEach {
    Mock Assert-RideBitLockerAdministrator -ModuleName RIDE.BitLockerWorkflows {}
    Mock Assert-RideBitLockerWorkflowAvailability -ModuleName RIDE.BitLockerWorkflows {}
  }
  It 'returns only nonsecret volume and protector metadata' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Get-RideBitLockerStartupPolicyObservation -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ FvePolicyRegistryPresent = $false; FvePolicyValues = @(); PolicyManagerRegistryPresent = $false; PolicyManagerValues = @(); EffectivePolicyEstablished = $false; Interpretation = 'Synthetic raw-policy fixture.' } }
    $observed = Get-RideBitLockerVolumeObservation -MountPoint $env:SystemDrive
    $observed.KeyProtectors[0].KeyProtectorId | Should -Be '{11111111-1111-1111-1111-111111111111}'
    ($observed | ConvertTo-Json -Depth 8) | Should -Not -Match '111111-222222-333333-444444-555555-666666-777777-888888'
    $observed.KeyProtectors[0].PSObject.Properties.Name | Should -Not -Contain 'RecoveryPassword'
    $observed.StartupPolicy.EffectivePolicyEstablished | Should -BeFalse
  }

  It 'labels TpmCertificate as a potential Network Unlock route without claiming it is active' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows {
      $volume = New-BitLockerTestVolume
      $volume.KeyProtector += [pscustomobject]@{ KeyProtectorId = '{44444444-4444-4444-4444-444444444444}'; KeyProtectorType = 'TpmCertificate' }
      $volume
    }
    Mock Get-RideBitLockerStartupPolicyObservation -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ EffectivePolicyEstablished = $false; FvePolicyValues = @(); PolicyManagerValues = @() } }
    $observed = Get-RideBitLockerVolumeObservation -MountPoint $env:SystemDrive
    $networkProtector = $observed.KeyProtectors | Where-Object KeyProtectorType -eq 'TpmCertificate'
    $networkProtector.RouteAssessment | Should -Match 'Potential Network Unlock route'
    $networkProtector.RouteAssessment | Should -Match 'policy, certificate/WDS provisioning and real boot behavior'
    $json = $observed | ConvertTo-Json -Depth 8
    $json | Should -Not -Match '111111-222222-333333-444444-555555-666666-777777-888888'
    $networkProtector.PSObject.Properties.Name | Should -Not -Contain 'RecoveryPassword'
  }

  It 'reports whitelisted raw startup-policy values without claiming effective policy' {
    Mock Test-Path -ModuleName RIDE.BitLockerWorkflows { $true }
    Mock Get-ItemProperty -ModuleName RIDE.BitLockerWorkflows {
      if ($LiteralPath -like '*Microsoft*FVE') { [pscustomobject]@{ UseTPM = 2; UseTPMPIN = 1; IdentificationField = 'synthetic private label' } }
      else { [pscustomobject]@{
          SystemDrivesRequireStartupAuthentication = 'synthetic-policy'
          SystemDrivesEnablePreBootPinExceptionOnDECapableDevice = 1
          SystemDrivesEnablePrebootInputProtectorsOnSlates = 0
          OtherValue = 'ignored'
        } }
    }
    $policy = Get-RideBitLockerStartupPolicyObservation
    $policy.EffectivePolicyEstablished | Should -BeFalse
    (@($policy.FvePolicyValues.Name) -join ',') | Should -Be 'UseTPM,UseTPMPIN'
    (@($policy.PolicyManagerValues.Name | Sort-Object) -join ',') | Should -Be 'SystemDrivesEnablePrebootInputProtectorsOnSlates,SystemDrivesEnablePreBootPinExceptionOnDECapableDevice,SystemDrivesRequireStartupAuthentication'
    ($policy | ConvertTo-Json -Depth 5) | Should -Not -Match 'synthetic private label|OtherValue'
  }

  It 'refuses non-OS mount points before calling BitLocker' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { throw 'must not run' }
    { Get-RideBitLockerVolumeObservation -MountPoint 'D:' } | Should -Throw '*current Windows OS volume*'
    Should -Invoke Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'presents one exact recovery protector without returning the secret' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Show-RideBitLockerSecretDialog -ModuleName RIDE.BitLockerWorkflows { $true }
    Show-RideBitLockerRecoveryPassword -MountPoint $env:SystemDrive -KeyProtectorId '{11111111-1111-1111-1111-111111111111}' -WhatIf
    Should -Invoke Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows -Times 0
    Should -Invoke Show-RideBitLockerSecretDialog -ModuleName RIDE.BitLockerWorkflows -Times 0
    $result = Show-RideBitLockerRecoveryPassword -MountPoint $env:SystemDrive -KeyProtectorId '{11111111-1111-1111-1111-111111111111}' -Confirm:$false
    ($result | ConvertTo-Json -Depth 4) | Should -Not -Match '111111-222222-333333-444444-555555-666666-777777-888888'
    Should -Invoke Show-RideBitLockerSecretDialog -ModuleName RIDE.BitLockerWorkflows -Times 1 -ParameterFilter { $Secret -eq '111111-222222-333333-444444-555555-666666-777777-888888' -and -not $ConfirmBackup }
  }

  It 'opens a native backup handoff but never marks backup verified' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Get-RideBitLockerControlPanelPath -ModuleName RIDE.BitLockerWorkflows { 'C:\Windows\System32\control.exe' }
    Mock Start-Process -ModuleName RIDE.BitLockerWorkflows {}
    Start-RideBitLockerRecoveryBackupHandoff -MountPoint $env:SystemDrive -KeyProtectorId '{11111111-1111-1111-1111-111111111111}' -DestinationCategory FileOrUsb -WhatIf
    Should -Invoke Start-Process -ModuleName RIDE.BitLockerWorkflows -Times 0
    $result = Start-RideBitLockerRecoveryBackupHandoff -MountPoint $env:SystemDrive -KeyProtectorId '{11111111-1111-1111-1111-111111111111}' -DestinationCategory FileOrUsb -Confirm:$false
    $result.Stage | Should -Be 'NativeBackupHandoffOpened'
    $result.BackupVerified | Should -BeFalse
    $result.DestinationCategory | Should -Be 'FileOrUsb'
    (@($result.Instructions) -join ' ') | Should -Match 'Save to a file'
    $result.KeyProtectorId | Should -Be '{11111111-1111-1111-1111-111111111111}'
    Should -Invoke Start-Process -ModuleName RIDE.BitLockerWorkflows -Times 1 -ParameterFilter { $FilePath -eq 'C:\Windows\System32\control.exe' -and ($ArgumentList -join ' ') -eq '/name Microsoft.BitLockerDriveEncryption' }
    Should -Invoke Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows -Times 1
  }

  It 'refuses a missing recovery protector ID before opening the native UI' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Start-Process -ModuleName RIDE.BitLockerWorkflows { throw 'must not open' }
    { Start-RideBitLockerRecoveryBackupHandoff -MountPoint $env:SystemDrive -KeyProtectorId '{99999999-9999-9999-9999-999999999999}' -DestinationCategory FileOrUsb -Confirm:$false } | Should -Throw '*not found uniquely*'
    Should -Invoke Start-Process -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'requires a catalog-declared destination before inspecting a volume' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { throw 'volume inspection must not run' }
    { Start-RideBitLockerRecoveryBackupHandoff -MountPoint $env:SystemDrive -KeyProtectorId '{11111111-1111-1111-1111-111111111111}' -DestinationCategory 'CloudDrive' -Confirm:$false } | Should -Throw '*Choose a backup destination category declared by the BitLocker catalog*'
    Should -Invoke Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'refuses encryption unless the exact backup-confirmed protector exists' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Get-Tpm -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
    Mock Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows {}
    { Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{22222222-2222-2222-2222-222222222222}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMOnly -Confirm:$false } | Should -Throw '*does not match*'
    Should -Invoke Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'fails closed when effective startup policy and route compatibility are unknown' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Get-ItemProperty -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ EditionID = 'Professional' } }
    Mock Get-RideBitLockerStartupPolicyObservation -ModuleName RIDE.BitLockerWorkflows {
      [pscustomobject]@{ EffectivePolicyEstablished = $false; FvePolicyValues = @(); PolicyManagerValues = @() }
    }
    Mock Get-Tpm -ModuleName RIDE.BitLockerWorkflows { throw 'TPM must not be inspected after policy failure' }
    Mock Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows { throw 'encryption must not run after policy failure' }
    { Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{11111111-1111-1111-1111-111111111111}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMOnly -Confirm:$false } | Should -Throw '*Effective startup-authentication policy and boot-route compatibility are not established*'
    Should -Invoke Get-Tpm -ModuleName RIDE.BitLockerWorkflows -Times 0
    Should -Invoke Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'refuses ambiguous preexisting alternate protector routes without removing them' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows {
      $volume = New-BitLockerTestVolume
      $volume.KeyProtector += [pscustomobject]@{ KeyProtectorId = '{33333333-3333-3333-3333-333333333333}'; KeyProtectorType = 'Tpm' }
      $volume
    }
    Mock Assert-RideBitLockerEnrollmentReadiness -ModuleName RIDE.BitLockerWorkflows {}
    Mock Get-Tpm -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
    Mock Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows { throw 'encryption must not run with an alternate protector' }
    { Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{11111111-1111-1111-1111-111111111111}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMAndPIN -Confirm:$false } | Should -Throw '*alternate boot or recovery routes (Tpm)*'
    Should -Invoke Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'names and preserves a possible Network Unlock route during enrollment preflight' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows {
      $volume = New-BitLockerTestVolume
      $volume.KeyProtector += [pscustomobject]@{ KeyProtectorId = '{44444444-4444-4444-4444-444444444444}'; KeyProtectorType = 'TpmCertificate' }
      $volume
    }
    Mock Assert-RideBitLockerEnrollmentReadiness -ModuleName RIDE.BitLockerWorkflows {}
    Mock Get-Tpm -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
    Mock Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows { throw 'encryption must not run with a possible Network Unlock route' }
    { Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{11111111-1111-1111-1111-111111111111}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMAndPIN -Confirm:$false } | Should -Throw '*may provide managed BitLocker Network Unlock*'
    Should -Invoke Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'does not prompt for a startup PIN or invoke encryption during preview' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Assert-RideBitLockerEnrollmentReadiness -ModuleName RIDE.BitLockerWorkflows {}
    Mock Get-Tpm -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
    Mock Read-Host -ModuleName RIDE.BitLockerWorkflows { throw 'PIN prompt must not run during WhatIf' }
    Mock Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows { throw 'encryption must not run during WhatIf' }
    Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{11111111-1111-1111-1111-111111111111}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMAndPIN -WhatIf
    Should -Invoke Read-Host -ModuleName RIDE.BitLockerWorkflows -Times 0
    Should -Invoke Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'passes TPM plus PIN only as SecureString and returns no PIN value' {
    $pinText = '246810'
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Assert-RideBitLockerEnrollmentReadiness -ModuleName RIDE.BitLockerWorkflows {}
    Mock Get-Tpm -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
    Mock Read-Host -ModuleName RIDE.BitLockerWorkflows { ConvertTo-SecureString -String '246810' -AsPlainText -Force }
    Mock Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows {}
    $result = Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{11111111-1111-1111-1111-111111111111}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMAndPIN -Confirm:$false
    ($result | ConvertTo-Json -Depth 4) | Should -Not -Match [regex]::Escape($pinText)
    Should -Invoke Read-Host -ModuleName RIDE.BitLockerWorkflows -Times 1
    Should -Invoke Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 1 -ParameterFilter { $Pin -is [System.Security.SecureString] -and $TpmAndPinProtector -and -not $TpmProtector }
  }

  It 'uses a TPM protector without prompting for a PIN' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Assert-RideBitLockerEnrollmentReadiness -ModuleName RIDE.BitLockerWorkflows {}
    Mock Get-Tpm -ModuleName RIDE.BitLockerWorkflows { [pscustomobject]@{ TpmPresent = $true; TpmReady = $true } }
    Mock Read-Host -ModuleName RIDE.BitLockerWorkflows { throw 'TPM-only startup must not prompt for a PIN' }
    Mock Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows {}
    $result = Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{11111111-1111-1111-1111-111111111111}' -EncryptionScope FullVolume -StartupAuthentication TPMOnly -Confirm:$false
    $result.StartupAuthentication | Should -Be 'TPMOnly'
    Should -Invoke Read-Host -ModuleName RIDE.BitLockerWorkflows -Times 0
    Should -Invoke Enable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 1 -ParameterFilter { $TpmProtector -and -not $TpmAndPinProtector -and -not $Pin }
  }

  It 'keeps disable preview read-only' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume -Status 'FullyEncrypted' }
    Mock Disable-BitLocker -ModuleName RIDE.BitLockerWorkflows {}
    Disable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -WhatIf
    Should -Invoke Disable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'requires the exact typed confirmation before decryption' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume -Status 'FullyEncrypted' }
    Mock Read-Host -ModuleName RIDE.BitLockerWorkflows { 'TURN OFF BITLOCKER' }
    Mock Disable-BitLocker -ModuleName RIDE.BitLockerWorkflows { throw 'decryption must not run after a wrong phrase' }
    { Disable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -Confirm:$false } | Should -Throw '*was not confirmed*'
    Should -Invoke Disable-BitLocker -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'keeps recovery-protector creation preview read-only' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Add-BitLockerKeyProtector -ModuleName RIDE.BitLockerWorkflows { throw 'must not run' }
    Add-RideBitLockerRecoveryPassword -MountPoint $env:SystemDrive -WhatIf
    Should -Invoke Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows -Times 0
    Should -Invoke Add-BitLockerKeyProtector -ModuleName RIDE.BitLockerWorkflows -Times 0
  }

  It 'creates and presents a recovery key but leaves backup explicitly unverified' {
    $secret = '222222-333333-444444-555555-666666-777777-888888-999999'
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Read-Host -ModuleName RIDE.BitLockerWorkflows { 'ADD RECOVERY PASSWORD TO ' + $env:SystemDrive.TrimEnd('\') }
    Mock Add-BitLockerKeyProtector -ModuleName RIDE.BitLockerWorkflows {
      [pscustomobject]@{ KeyProtector = @([pscustomobject]@{KeyProtectorId='{22222222-2222-2222-2222-222222222222}';KeyProtectorType='RecoveryPassword';RecoveryPassword='222222-333333-444444-555555-666666-777777-888888-999999'}) }
    }
    Mock Show-RideBitLockerSecretDialog -ModuleName RIDE.BitLockerWorkflows {}
    $result = Add-RideBitLockerRecoveryPassword -MountPoint $env:SystemDrive -Confirm:$false
    $result.KeyProtectorId | Should -Be '{22222222-2222-2222-2222-222222222222}'
    $result.Stage | Should -Be 'RecoveryPasswordCreatedAndPresented'
    $result.BackupVerified | Should -BeFalse
    $result.NextStep | Should -Match 'exact protector ID and an explicit destination'
    ($result | ConvertTo-Json -Depth 4) | Should -Not -Match [regex]::Escape($secret)
    Should -Invoke Add-BitLockerKeyProtector -ModuleName RIDE.BitLockerWorkflows -Times 1
    Should -Invoke Show-RideBitLockerSecretDialog -ModuleName RIDE.BitLockerWorkflows -Times 1 -ParameterFilter { $ProtectorId -eq '{22222222-2222-2222-2222-222222222222}' -and $Instruction -match 'not backed up by RIDE' }
  }

  It 'retains a new protector and reports unverified backup when local presentation is closed' {
    $secret = '333333-444444-555555-666666-777777-888888-999999-000000'
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { New-BitLockerTestVolume }
    Mock Read-Host -ModuleName RIDE.BitLockerWorkflows { 'ADD RECOVERY PASSWORD TO ' + $env:SystemDrive.TrimEnd('\') }
    Mock Add-BitLockerKeyProtector -ModuleName RIDE.BitLockerWorkflows {
      [pscustomobject]@{ KeyProtector = @([pscustomobject]@{ KeyProtectorId='{33333333-3333-3333-3333-333333333333}'; KeyProtectorType='RecoveryPassword'; RecoveryPassword='333333-444444-555555-666666-777777-888888-999999-000000' }) }
    }
    Mock Show-RideBitLockerSecretDialog -ModuleName RIDE.BitLockerWorkflows {}
    Mock Remove-BitLockerKeyProtector -ModuleName RIDE.BitLockerWorkflows { throw 'existing recovery access must not be removed' }
    $result = Add-RideBitLockerRecoveryPassword -MountPoint $env:SystemDrive -Confirm:$false
    $result.BackupVerified | Should -BeFalse
    $result.KeyProtectorId | Should -Be '{33333333-3333-3333-3333-333333333333}'
    ($result | ConvertTo-Json -Depth 4) | Should -Not -Match [regex]::Escape($secret)
    Should -Invoke Remove-BitLockerKeyProtector -ModuleName RIDE.BitLockerWorkflows -Times 0
  }
}

Describe 'BitLocker activation gate' {
  It 'blocks direct module calls for every pending action before volume inspection' {
    Mock Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows { throw 'volume inspection must not run' }
    { Add-RideBitLockerRecoveryPassword -MountPoint $env:SystemDrive } | Should -Throw '*pending disposable Windows acceptance*'
    { Start-RideBitLockerRecoveryBackupHandoff -MountPoint $env:SystemDrive -KeyProtectorId '{11111111-1111-1111-1111-111111111111}' -DestinationCategory FileOrUsb } | Should -Throw '*pending disposable Windows acceptance*'
    { Show-RideBitLockerRecoveryPassword -MountPoint $env:SystemDrive -KeyProtectorId '{11111111-1111-1111-1111-111111111111}' } | Should -Throw '*pending disposable Windows acceptance*'
    { Enable-RideBitLockerOsVolume -MountPoint $env:SystemDrive -RecoveryProtectorId '{11111111-1111-1111-1111-111111111111}' -VerifiedBackupProtectorId '{11111111-1111-1111-1111-111111111111}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMOnly } | Should -Throw '*pending disposable Windows acceptance*'
    { Disable-RideBitLockerOsVolume -MountPoint $env:SystemDrive } | Should -Throw '*pending disposable Windows acceptance*'
    Should -Invoke Get-BitLockerVolume -ModuleName RIDE.BitLockerWorkflows -Times 0
  }
}
