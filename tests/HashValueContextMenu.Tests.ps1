BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-RegistryValueSet.psm1') -Force
  $script:Operation = Get-RideOperation -Id 'windows.hash-value-context-menu'
  $script:CertutilOperation = Get-RideOperation -Id 'windows.sha256-certutil-context-menu'
  $script:HelperPath = Join-Path $script:RepositoryRoot 'tools/Get-RideHashValue.ps1'
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  $script:RemainingSettingsBatch1 = @((Import-RideCatalogData -Path (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')).Operations | Where-Object MigrationBatch -eq '2026-10-10-remaining-settings-1')
}

Describe 'RIDE hash value context-menu candidate' {
  It 'keeps Windows behavior pending while declaring one user-scope exact-recovery registry set' {
    $script:Operation.Scope | Should -Be 'User'
    $script:Operation.RequiresAdmin | Should -BeFalse
    $script:Operation.SupportedTargets.Count | Should -Be 0
    $script:Operation.CandidateTargets | Should -Contain 'Windows 11'
    $script:Operation.PendingAcceptance | Should -BeTrue
    $script:Operation.MigrationBatch | Should -BeExactly '2026-10-10-remaining-settings-1'
    $script:Operation.Rollback | Should -Be 'Exact'
    $script:Operation.RegistryValues.Count | Should -Be 17
    $script:Operation.States.Enabled.Count | Should -Be 17
    $script:Operation.RegistryValues.RegistryPath | Should -Contain 'HKCU:\Software\Classes\*\shell\RIDE.HashValue\ExtendedSubCommandsKey\shell\MD5'
    $script:Operation.States.WindowsDefault.Values | Where-Object { $null -ne $_ } | Should -BeNullOrEmpty
  }

  It 'resolves only the declared RIDE-root and Windows PowerShell 5.1 tokens for plan and matching' {
    $effective = Get-RideRegistryValueSetEffectiveDesiredState -Operation $script:Operation -State Enabled
    $expectedHelper = Join-Path $script:RepositoryRoot 'tools/Get-RideHashValue.ps1'
    $expectedPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $effective.CommandShowAll | Should -Be (('"{0}" -NoLogo -NoProfile -STA -WindowStyle Hidden -File "{1}" -LiteralPath "%1" -Algorithm ShowAll' -f $expectedPowerShell, $expectedHelper))
    $current = [pscustomobject]@{ Values = @($script:Operation.RegistryValues | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Exists = $true; Value = $effective[$_.Key]; ValueType = $_.ValueType } }) }
    Test-RideRegistryValueSetMatch -Operation $script:Operation -State Enabled -CurrentState $current | Should -BeTrue
    $default = Get-RideRegistryValueSetEffectiveDesiredState -Operation $script:Operation -State WindowsDefault
    $default.Count | Should -Be 17
    @($default.Values | Where-Object { $null -ne $_ }).Count | Should -Be 0
  }

  It 'writes the resolved registry commands through the existing captured registry-set handler' {
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $script:Operation; ExpectedHelper = $script:HelperPath } {
      param($Operation, $ExpectedHelper)
      $script:Writes = @()
      Mock Set-RideSettingState { $script:Writes += [pscustomobject]@{ Key = $Operation.Key; Value = $Value } }
      Set-RideRegistryValueSetState -Operation $Operation -State Enabled
      $script:Writes.Count | Should -Be 17
      ($script:Writes | Where-Object Key -eq 'CommandShowAll').Value | Should -Match ([regex]::Escape($ExpectedHelper))
      ($script:Writes | Where-Object Key -eq 'CommandShowAll').Value | Should -Match 'WindowsPowerShell\\v1\.0\\powershell\.exe'
      ($script:Writes | Where-Object Key -eq 'CommandShowAll').Value | Should -Match '-LiteralPath "%1" -Algorithm ShowAll$'
    }
  }
}

Describe 'RIDE Certutil SHA-256 context-menu candidate' {
  It 'keeps Windows behavior pending with user scope and exact recovery' {
    $script:CertutilOperation.Scope | Should -Be 'User'
    $script:CertutilOperation.RequiresAdmin | Should -BeFalse
    $script:CertutilOperation.SupportedTargets.Count | Should -Be 0
    $script:CertutilOperation.CandidateTargets | Should -Contain 'Windows 11'
    $script:CertutilOperation.PendingAcceptance | Should -BeTrue
    $script:CertutilOperation.MigrationBatch | Should -BeExactly '2026-10-10-remaining-settings-1'
    $script:CertutilOperation.Rollback | Should -Be 'Exact'
    $script:CertutilOperation.RegistryValues.Count | Should -Be 2
    $script:CertutilOperation.States.Enabled.Menu | Should -BeExactly 'shell32.dll,-152'
    $script:CertutilOperation.States.Enabled.Command | Should -BeExactly 'cmd.exe /k certutil -hashfile "%1" SHA256'
    $script:CertutilOperation.States.WindowsDefault.Values | Where-Object { $null -ne $_ } | Should -BeNullOrEmpty
  }

  It 'uses the captured registry-set handler for both values' {
    InModuleScope RIDE-RegistryValueSet -Parameters @{ Operation = $script:CertutilOperation } {
      param($Operation)
      $script:Writes = @()
      Mock Set-RideSettingState { $script:Writes += [pscustomobject]@{ Key = $Operation.Key; Value = $Value } }
      Set-RideRegistryValueSetState -Operation $Operation -State Enabled
      $script:Writes.Count | Should -Be 2
      ($script:Writes | Where-Object Key -eq 'Menu').Value | Should -BeExactly 'shell32.dll,-152'
      ($script:Writes | Where-Object Key -eq 'Command').Value | Should -BeExactly 'cmd.exe /k certutil -hashfile "%1" SHA256'
    }
  }
}

Describe 'Remaining settings batch 1 selection' {
  It 'selects both context-menu candidates in the expected 19-operation batch' {
    $script:RemainingSettingsBatch1.Count | Should -Be 19
    $script:RemainingSettingsBatch1.Id | Should -Contain 'windows.hash-value-context-menu'
    $script:RemainingSettingsBatch1.Id | Should -Contain 'windows.sha256-certutil-context-menu'
  }
}

Describe 'Hash value helper' {
  BeforeAll {
    . $script:HelperPath
  }

  It 'passes the exact literal path for a single algorithm to Get-FileHash' {
    $script:HashCalls = @()
    Mock Get-FileHash {
      $script:HashCalls += [pscustomobject]@{ LiteralPath = $LiteralPath; Algorithm = $Algorithm }
      [pscustomobject]@{ Hash = ('HASH-' + $Algorithm) }
    }
    $path = "C:\fixture\two  spaces\apostrophe's & percent% café.bin"
    $rows = @(Get-RideHashValueRows -LiteralPath $path -Algorithm SHA256)
    $rows.Count | Should -Be 1
    $rows[0].Algorithm | Should -Be 'SHA256'
    $script:HashCalls[0].LiteralPath | Should -BeExactly $path
  }

  It 'passes all seven requested algorithms to Windows PowerShell 5.1 Get-FileHash' -Skip:($PSVersionTable.PSVersion.Major -ge 6) {
    $script:HashCalls = @()
    Mock Get-FileHash {
      $script:HashCalls += [pscustomobject]@{ LiteralPath = $LiteralPath; Algorithm = $Algorithm }
      [pscustomobject]@{ Hash = ('HASH-' + $Algorithm) }
    }
    $path = "C:\fixture\two  spaces\apostrophe's & percent% café.bin"
    $rows = @(Get-RideHashValueRows -LiteralPath $path -Algorithm ShowAll)
    $rows.Count | Should -Be 7
    $rows.Algorithm | Should -Be @('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'RIPEMD160')
    @($script:HashCalls | Where-Object { $_.LiteralPath -cne $path }).Count | Should -Be 0
    $script:HashCalls.Algorithm | Should -Be $rows.Algorithm
  }

  It 'formats all selected values into one bounded display payload without sleeping or writing files' {
    $rows = @(@{ Algorithm = 'MD5'; Hash = 'abc' }, @{ Algorithm = 'SHA256'; Hash = 'def' })
    $formatted = Format-RideHashValueRows -Rows $rows
    $formatted | Should -Be ([string]::Join([Environment]::NewLine, @('MD5: abc', 'SHA256: def')))
    (Get-Command Show-RideHashValueMessage -CommandType Function).Name | Should -Be 'Show-RideHashValueMessage'
    (Get-Content $script:HelperPath -Raw) | Should -Not -Match 'Start-Sleep|Set-Content|Out-File|Export-Csv'
  }
}
