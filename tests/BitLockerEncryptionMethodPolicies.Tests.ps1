<#
.SYNOPSIS
  Validate the Windows 11 and Windows Server 2025 BitLocker drive-type candidate policies.
.DESCRIPTION
  Checks the exact policy registry values and all documented method choices.
  Planning is read-only; no registry, drive or protector state is changed.
.EXAMPLE
  Invoke-Pester .\tests\BitLockerEncryptionMethodPolicies.Tests.ps1
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository migration coverage.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  $script:Cases = @(
    @{ Id = 'windows.bitlocker-encryption-method-os'; ValueName = 'EncryptionMethodWithXtsOs'; GuiArea = 'Operating System Drives' },
    @{ Id = 'windows.bitlocker-encryption-method-fixed-data'; ValueName = 'EncryptionMethodWithXtsFdv'; GuiArea = 'Fixed Data Drives' },
    @{ Id = 'windows.bitlocker-encryption-method-removable-data'; ValueName = 'EncryptionMethodWithXtsRdv'; GuiArea = 'Removable Data Drives' }
  )
  $script:ExpectedStates = [ordered]@{
    AesCbc128 = 3
    AesCbc256 = 4
    XtsAes128 = 6
    XtsAes256 = 7
    WindowsDefault = $null
  }
}

Describe 'Windows 11 BitLocker drive-type encryption method policies' {
  It 'maps the three drive types to their own modern Group Policy values and exact methods' {
    foreach ($case in $script:Cases) {
      $operation = Get-RideOperation -Id $case.Id
      $operation.Kind | Should -BeExactly 'RegistryValue'
      $operation.Handler | Should -BeExactly 'RegistryValue'
      $operation.RegistryPath | Should -BeExactly 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
      $operation.ValueName | Should -BeExactly $case.ValueName
      $operation.ValueType | Should -BeExactly 'DWord'
      foreach ($state in $script:ExpectedStates.Keys) {
        if ($null -eq $script:ExpectedStates[$state]) {
          $operation.States[$state] | Should -BeNullOrEmpty
        } else {
          $operation.States[$state] | Should -Be $script:ExpectedStates[$state]
        }
      }
      $operation.BaselineState | Should -BeExactly 'WindowsDefault'
      $operation.SupportedTargets | Should -BeNullOrEmpty
      $operation.CandidateTargets | Should -Contain 'Windows 11'
      $operation.CandidateTargets | Should -Contain 'Windows Server 2025'
      $operation.PendingAcceptance | Should -BeTrue
      $operation.Scope | Should -BeExactly 'Machine'
      $operation.RequiresAdmin | Should -BeTrue
      $operation.DocumentationUri | Should -Match 'learn\.microsoft\.com/.+bitlocker/configure#choose-drive-encryption-method-and-cipher-strength'
      $operation.SettingPresentation.GuiPath | Should -Match ([regex]::Escape($case.GuiArea))
      $operation.SettingPresentation.GuiEffect | Should -Match $case.ValueName
      $operation.SettingPresentation.Requirements -join ' ' | Should -Match 'does not convert an already encrypted drive'
      $operation.SettingPresentation.Requirements -join ' ' | Should -Match 'all three drive-type choices together'
      $operation.SettingPresentation.OtherSupportedChoices -join ' ' | Should -Match 'XTS-AES 256-bit = 7'
      $operation.TargetDefaults.'Windows 11'.DefaultValueExists | Should -BeFalse
      $operation.TargetDefaults.'Windows 11'.EffectiveDefault | Should -Match 'XTS-AES 128-bit'

      foreach ($state in $script:ExpectedStates.Keys) {
        $plan = @(Get-RideSingleOperationPlan -Id $case.Id -Action Set -State $state)
        $plan.Count | Should -Be 1
        $plan[0].State | Should -BeExactly $state
      }
      { Get-RideSingleOperationPlan -Id $case.Id -Action Set -State Invalid } | Should -Throw
    }
  }

  It 'retains the historical legacy EncryptionMethod operation without redirecting its recovery identity' {
    $legacy = Get-RideOperation -Id 'windows.bitlocker-encryption-method'
    $legacy.ValueName | Should -BeExactly 'EncryptionMethod'
    $legacy.States.Keys | Should -Contain 'AesCbc128'
    $legacy.States.Keys | Should -Contain 'AesCbc256'
    @($script:Cases | ForEach-Object { (Get-RideOperation -Id $_.Id).ValueName } | Where-Object { $_ -eq $legacy.ValueName }).Count | Should -Be 0
  }

  It 'keeps pending drive-type policies outside release defaults while retaining XTS-AES 256 choices' {
    $profile = Get-RideProfile -Path (Join-Path $PSScriptRoot '../profiles/default.psd1')
    foreach ($case in $script:Cases) {
      $selection = @($profile.Operations | Where-Object Id -ceq $case.Id)
      $selection.Count | Should -Be 0
      (Get-RideOperation -Id $case.Id).States.XtsAes256 | Should -Be 7
    }
    @($profile.Operations | Where-Object Id -ceq 'windows.bitlocker-encryption-method').Count | Should -Be 0
  }

  It 'previews Windows 11 candidates without invoking the registry handler' {
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows 11' }
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
    Mock Set-RideSettingState -ModuleName RIDE.Engine {}

    $warnings = @()
    foreach ($case in $script:Cases) {
      $plan = @(Get-RideSingleOperationPlan -Id $case.Id -Action Set -State XtsAes256)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false -WarningVariable warnings | Out-Null
    }
    ($warnings -join ' ') | Should -Match 'acceptance remains pending'
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 6 -Exactly
    Should -Invoke Set-RideSettingState -ModuleName RIDE.Engine -Times 0
  }

  It 'previews Windows Server 2025 candidates without invoking the registry handler' {
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows Server 2025' }
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { [pscustomobject]@{ Exists = $false; Value = $null; ValueType = $null } }
    Mock Set-RideSettingState -ModuleName RIDE.Engine {}

    $warnings = @()
    foreach ($case in $script:Cases) {
      $plan = @(Get-RideSingleOperationPlan -Id $case.Id -Action Set -State XtsAes256)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false -WarningVariable warnings | Out-Null
    }
    ($warnings -join ' ') | Should -Match 'acceptance remains pending'
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 6 -Exactly
    Should -Invoke Set-RideSettingState -ModuleName RIDE.Engine -Times 0
  }
}
