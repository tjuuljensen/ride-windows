<#
.SYNOPSIS
  Verify inert local password-complexity template and export preparation.
.DESCRIPTION
  Tests the one-field template boundary and supplied-export parser. No secedit,
  policy query, registry access, elevation, VM, or Windows state change occurs.
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
}
