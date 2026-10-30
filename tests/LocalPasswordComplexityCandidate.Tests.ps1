<#
.SYNOPSIS
  Verify inert local password-complexity template and export preparation.
.DESCRIPTION
  Tests the one-field template boundary, supplied-export parser, and mocked
  read-only Secedit export/validation adapters. No Secedit process, policy query, registry
  access, elevation, VM, or Windows state change occurs.
.EXAMPLE
  Invoke-Pester .\tests\LocalPasswordComplexityCandidate.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Native configuration, exact rollback and managed-policy precedence remain deferred.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.LocalPasswordComplexityCandidate.psm1') -Force
}

Describe 'Inert local password-complexity candidate' {
  It 'builds an enabled Unicode template containing only the allow-listed field' {
    $template = New-RideLocalPasswordComplexityTemplate -DesiredState Enabled
    $template.Kind | Should -BeExactly 'LocalPasswordComplexityTemplate'
    $template.SettingName | Should -BeExactly 'PasswordComplexity'
    $template.Value | Should -Be 1
    $template.NativeExecutionSupported | Should -BeFalse
    $template.Encoding | Should -BeExactly 'UTF-16LE'
    $template.Content | Should -Match '(?m)^PasswordComplexity = 1\r?$'
    $section = $template.Content.Substring($template.Content.IndexOf('[System Access]'))
    $sectionLines = @($section -split "`r`n" | Select-Object -Skip 1 | Where-Object { $_ -match '^\s*[^;\s].*=' })
    $sectionLines.Count | Should -Be 1
    [BitConverter]::ToString($template.Bytes[0..1]) | Should -BeExactly 'FF-FE'
    [System.Text.Encoding]::Unicode.GetString($template.Bytes).TrimStart([char]0xFEFF) | Should -BeExactly $template.Content
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $expectedHash = [BitConverter]::ToString($sha.ComputeHash($template.Bytes)).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
    $template.Sha256 | Should -BeExactly $expectedHash
  }

  It 'builds an explicit disabled template' {
    $template = New-RideLocalPasswordComplexityTemplate -DesiredState Disabled
    $template.Value | Should -Be 0
    $template.Content | Should -Match '(?m)^PasswordComplexity = 0\r?$'
  }

  It 'does not infer a baseline or undefined write state' {
    { New-RideLocalPasswordComplexityTemplate -DesiredState NotDefined } | Should -Throw
  }

  It 'prepares explicit-value recovery only when supplied current state matches the applied value' {
    $before = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 0`r`n"
    $current = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 1`r`n"
    $recovery = New-RideLocalPasswordComplexityRecoveryTemplate -PriorObservation $before -CurrentObservation $current -ExpectedAppliedState Enabled
    $recovery.Kind | Should -BeExactly 'LocalPasswordComplexityRecoveryPreparation'
    $recovery.PriorState | Should -BeExactly 'Disabled'
    $recovery.Template.Value | Should -Be 0
    $recovery.ExactRecoveryVerified | Should -BeFalse
    $recovery.ReadyForMutation | Should -BeFalse
  }

  It 'refuses recovery after current state drift and refuses undefined prior state' {
    $before = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 0`r`n"
    $drift = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 0`r`n"
    { New-RideLocalPasswordComplexityRecoveryTemplate -PriorObservation $before -CurrentObservation $drift -ExpectedAppliedState Enabled } | Should -Throw '*differs from the expected applied state*'
    $undefined = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nMinimumPasswordLength = 12`r`n"
    $current = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 1`r`n"
    { New-RideLocalPasswordComplexityRecoveryTemplate -PriorObservation $undefined -CurrentObservation $current -ExpectedAppliedState Enabled } | Should -Throw '*explicit, internally consistent*'
  }

  It 'returns a no-op recovery preparation without claiming ownership when states already match' {
    $before = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 1`r`n"
    $current = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 1`r`n"
    $recovery = New-RideLocalPasswordComplexityRecoveryTemplate -PriorObservation $before -CurrentObservation $current -ExpectedAppliedState Enabled
    $recovery.IsNoOp | Should -BeTrue
    $recovery.Template | Should -BeNullOrEmpty
  }

  It 'parses an explicit local enabled value from the supplied export' {
    $result = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 1`r`n"
    $result.State | Should -BeExactly 'Enabled'
    $result.Value | Should -Be 1
    $result.IsEffective | Should -BeFalse
    $result.SourceValidated | Should -BeFalse
  }

  It 'distinguishes local NotDefined from a merged export that does not report the setting' {
    $local = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nMinimumPasswordLength = 12`r`n"
    $merged = ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Merged -Content "[System Access]`r`nMinimumPasswordLength = 12`r`n"
    $local.State | Should -BeExactly 'NotDefined'
    $merged.State | Should -BeExactly 'NotReported'
  }

  It 'parses an explicit disabled value' {
    (ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 0`r`n").State | Should -BeExactly 'Disabled'
  }

  It 'rejects duplicate, malformed, and repeated policy sections' {
    { ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 0`r`nPasswordComplexity = 1`r`n" } | Should -Throw '*duplicate*'
    { ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`nPasswordComplexity = 2`r`n" } | Should -Throw '*exactly 0 or 1*'
    { ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content "[System Access]`r`n[System Access]`r`n" } | Should -Throw '*exactly one System Access*'
  }

  It 'requires a unique System Access section and bounds supplied export size' {
    { ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content '[Version]' } | Should -Throw '*exactly one System Access*'
    $large = 'x' * 1048577
    { ConvertFrom-RideLocalPasswordComplexityPolicyExport -Scope Local -Content $large } | Should -Throw '*1 MiB*'
  }

  It 'builds an export-only local command argument list' {
    InModuleScope RIDE.LocalPasswordComplexityCandidate {
      $arguments = New-RideLocalPasswordComplexityExportArguments -Scope Local -ConfigurationPath 'C:\temp\policy.inf' -LogPath 'C:\temp\secedit.log'
      $arguments | Should -Contain '/export'
      $arguments | Should -Contain '/cfg'
      $arguments | Should -Contain '/areas'
      $arguments | Should -Contain 'securitypolicy'
      $arguments | Should -Contain '/log'
      $arguments | Should -Not -Contain '/mergedpolicy'
      $arguments | Should -Not -Contain '/configure'
      $arguments | Should -Not -Contain '/import'
    }
  }

  It 'adds merged-policy export only when requested' {
    InModuleScope RIDE.LocalPasswordComplexityCandidate {
      $arguments = New-RideLocalPasswordComplexityExportArguments -Scope Merged -ConfigurationPath 'C:\temp\policy.inf' -LogPath 'C:\temp\secedit.log'
      $arguments | Should -Contain '/mergedpolicy'
      $arguments | Should -Not -Contain '/configure'
    }
  }

  It 'creates its export workspace under the local process temp root' {
    InModuleScope RIDE.LocalPasswordComplexityCandidate {
      $workspace = New-RideLocalPasswordComplexityWorkspace
      try {
        [IO.Path]::GetDirectoryName($workspace) | Should -BeExactly ([IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar))
        [IO.Path]::GetFileName($workspace) | Should -Match '^Ride-PasswordComplexity-[0-9a-f]{32}$'
        (Get-Item -LiteralPath $workspace -Force).Attributes -band [IO.FileAttributes]::ReparsePoint | Should -Be 0
      }
      finally {
        [IO.Directory]::Delete($workspace, $false)
      }
    }
  }

  It 'reads a local policy value through the mocked export boundary and removes its temporary files' {
    $script:ComplexityWorkspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $script:ComplexityExportContent = "[System Access]`r`nPasswordComplexity = 1`r`n"
    Mock New-RideLocalPasswordComplexityWorkspace -ModuleName RIDE.LocalPasswordComplexityCandidate {
      [void][IO.Directory]::CreateDirectory($script:ComplexityWorkspace)
      return $script:ComplexityWorkspace
    }
    Mock Invoke-RideLocalPasswordComplexityExportProcess -ModuleName RIDE.LocalPasswordComplexityCandidate {
      [IO.File]::WriteAllText($ConfigurationPath, $script:ComplexityExportContent)
    }

    $observation = Get-RideLocalPasswordComplexityObservation -Scope Local
    $observation.State | Should -BeExactly 'Enabled'
    $observation.Scope | Should -BeExactly 'Local'
    $observation.IsEffective | Should -BeFalse
    $observation.SourceValidated | Should -BeFalse
    Test-Path -LiteralPath $script:ComplexityWorkspace | Should -BeFalse
    Should -Invoke Invoke-RideLocalPasswordComplexityExportProcess -ModuleName RIDE.LocalPasswordComplexityCandidate -Exactly -Times 1 -ParameterFilter { $Scope -ceq 'Local' }
  }

  It 'preserves NotReported for merged exports that omit PasswordComplexity' {
    $script:ComplexityWorkspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $script:ComplexityExportContent = "[System Access]`r`nMinimumPasswordLength = 12`r`n"
    Mock New-RideLocalPasswordComplexityWorkspace -ModuleName RIDE.LocalPasswordComplexityCandidate {
      [void][IO.Directory]::CreateDirectory($script:ComplexityWorkspace)
      return $script:ComplexityWorkspace
    }
    Mock Invoke-RideLocalPasswordComplexityExportProcess -ModuleName RIDE.LocalPasswordComplexityCandidate {
      [IO.File]::WriteAllText($ConfigurationPath, $script:ComplexityExportContent)
    }

    $observation = Get-RideLocalPasswordComplexityObservation -Scope Merged
    $observation.State | Should -BeExactly 'NotReported'
    $observation.IsEffective | Should -BeFalse
    Test-Path -LiteralPath $script:ComplexityWorkspace | Should -BeFalse
    Should -Invoke Invoke-RideLocalPasswordComplexityExportProcess -ModuleName RIDE.LocalPasswordComplexityCandidate -Exactly -Times 1 -ParameterFilter { $Scope -ceq 'Merged' }
  }

  It 'fails closed when the export process does not produce its configuration file' {
    $script:ComplexityWorkspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    Mock New-RideLocalPasswordComplexityWorkspace -ModuleName RIDE.LocalPasswordComplexityCandidate {
      [void][IO.Directory]::CreateDirectory($script:ComplexityWorkspace)
      return $script:ComplexityWorkspace
    }
    Mock Invoke-RideLocalPasswordComplexityExportProcess -ModuleName RIDE.LocalPasswordComplexityCandidate {}

    { Get-RideLocalPasswordComplexityObservation -Scope Local } | Should -Throw '*did not create*'
    Test-Path -LiteralPath $script:ComplexityWorkspace | Should -BeFalse
  }

  It 'builds the exact native syntax-validation argument list' {
    InModuleScope RIDE.LocalPasswordComplexityCandidate {
      $arguments = New-RideLocalPasswordComplexityValidationArguments -ConfigurationPath 'C:\temp\password-complexity.inf'
      $arguments.Count | Should -Be 2
      $arguments[0] | Should -BeExactly '/validate'
      $arguments[1] | Should -BeExactly 'C:\temp\password-complexity.inf'
      $arguments | Should -Not -Contain '/configure'
      $arguments | Should -Not -Contain '/import'
    }
  }

  It 'validates only the generated template through the mocked Secedit boundary' {
    $script:ComplexityWorkspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    Mock New-RideLocalPasswordComplexityWorkspace -ModuleName RIDE.LocalPasswordComplexityCandidate {
      [void][IO.Directory]::CreateDirectory($script:ComplexityWorkspace)
      return $script:ComplexityWorkspace
    }
    Mock Invoke-RideLocalPasswordComplexityTemplateValidationProcess -ModuleName RIDE.LocalPasswordComplexityCandidate {}

    $template = New-RideLocalPasswordComplexityTemplate -DesiredState Enabled
    $validation = Test-RideLocalPasswordComplexityTemplate -Template $template
    $validation.Kind | Should -BeExactly 'LocalPasswordComplexityTemplateValidation'
    $validation.SyntaxValidated | Should -BeTrue
    $validation.PolicyApplied | Should -BeFalse
    $validation.ExactRecoveryVerified | Should -BeFalse
    $validation.ReadyForMutation | Should -BeFalse
    Test-Path -LiteralPath $script:ComplexityWorkspace | Should -BeFalse
    Should -Invoke Invoke-RideLocalPasswordComplexityTemplateValidationProcess -ModuleName RIDE.LocalPasswordComplexityCandidate -Exactly -Times 1 -ParameterFilter { $ConfigurationPath -like '*password-complexity.inf' }
  }

  It 'rejects altered template bytes before reaching native Secedit validation' {
    $script:ComplexityWorkspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    Mock New-RideLocalPasswordComplexityWorkspace -ModuleName RIDE.LocalPasswordComplexityCandidate {
      [void][IO.Directory]::CreateDirectory($script:ComplexityWorkspace)
      return $script:ComplexityWorkspace
    }
    Mock Invoke-RideLocalPasswordComplexityTemplateValidationProcess -ModuleName RIDE.LocalPasswordComplexityCandidate {}

    $template = New-RideLocalPasswordComplexityTemplate -DesiredState Enabled
    $template.Content = $template.Content.Replace('PasswordComplexity = 1', 'PasswordComplexity = 0')
    { Test-RideLocalPasswordComplexityTemplate -Template $template } | Should -Throw '*differ from the generated*'
    Should -Invoke Invoke-RideLocalPasswordComplexityTemplateValidationProcess -ModuleName RIDE.LocalPasswordComplexityCandidate -Exactly -Times 0
    Test-Path -LiteralPath $script:ComplexityWorkspace | Should -BeFalse
  }
}
