<#
.SYNOPSIS
  Verify desktop shortcut metadata resolution without touching the desktop.
.DESCRIPTION
  Extracts the pure metadata path resolver from the lifecycle module and checks
  that path normalization does not mutate catalog operation metadata.
.EXAMPLE
  Invoke-Pester .\tests\DesktopShortcuts.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: Windows desktop-folder metadata; no shortcut or COM access.
  Version: Test fixture; no independent script version.
#>

BeforeDiscovery {
  $script:DiscoveryRepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:DiscoveryRepositoryRoot 'modules/RIDE-DesktopShortcuts.psm1') -Force
}

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  $script:ModulePath = Join-Path $script:RepositoryRoot 'modules/RIDE-DesktopShortcuts.psm1'
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module $script:ModulePath -Force
  $tokens = $null
  $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($script:ModulePath, [ref]$tokens, [ref]$parseErrors)
  if (@($parseErrors).Count) { throw 'The desktop shortcut lifecycle module does not parse.' }
  $functions = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -in @('Resolve-RideDesktopShortcutPath', 'Get-RideDesktopShortcutPathEntry')
  }, $true))
  if ($functions.Count -ne 2) { throw 'A desktop shortcut metadata helper is missing or ambiguous.' }
  foreach ($function in $functions) { . ([scriptblock]::Create($function.Extent.Text)) }
}

Describe 'Desktop shortcut metadata resolution' {
  It 'normalizes declared paths without mutating catalog operation metadata' {
    $operation = @{
      Id = 'windows.bitlocker-wizard-shortcut'
      Scope = 'User'
      PathResolver = 'CurrentUserDesktop'
      ShortcutName = 'BitLocker Drive Encryption.lnk'
      TargetPath = '%SystemRoot%\System32\BitLockerWizardElev.exe'
      Arguments = ''
      DescriptionText = 'Open Windows BitLocker Drive Encryption'
      WorkingDirectory = '%SystemRoot%\System32'
    }
    $originalTarget = $operation.TargetPath
    $originalWorkingDirectory = $operation.WorkingDirectory
    $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
    if (-not $desktop -or -not [IO.Directory]::Exists($desktop)) { throw 'The current-user desktop directory is unavailable.' }

    $resolved = Resolve-RideDesktopShortcutPath -Operation $operation

    $operation.TargetPath | Should -BeExactly $originalTarget
    $operation.WorkingDirectory | Should -BeExactly $originalWorkingDirectory
    $resolved.TargetPath | Should -BeExactly ([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($originalTarget)))
    $resolved.WorkingDirectory | Should -BeExactly ([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($originalWorkingDirectory)))
    $resolved.Path | Should -BeExactly ([IO.Path]::GetFullPath((Join-Path $desktop $operation.ShortcutName)))
  }

  It 'rejects unsupported shortcut metadata before resolving paths' {
    $operation = @{
      Id = 'windows.bitlocker-wizard-shortcut'
      Scope = 'Machine'
      PathResolver = 'CurrentUserDesktop'
      ShortcutName = 'BitLocker Drive Encryption.lnk'
      TargetPath = '%SystemRoot%\System32\BitLockerWizardElev.exe'
      Arguments = ''
      DescriptionText = 'Open Windows BitLocker Drive Encryption'
      WorkingDirectory = '%SystemRoot%\System32'
    }

    { Resolve-RideDesktopShortcutPath -Operation $operation } | Should -Throw '*Unsupported desktop shortcut metadata*'
  }

  It 'resolves only the declared Power Options handoff without mutating the catalog entry' {
    $catalog = Import-RideCatalogData (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')
    $operation = @($catalog.Operations | Where-Object Id -CEQ 'windows.power-options-shortcut')[0]
    $originalTarget = $operation.TargetPath
    $originalWorkingDirectory = $operation.WorkingDirectory
    $desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
    if (-not $desktop -or -not [IO.Directory]::Exists($desktop)) { throw 'The current-user desktop directory is unavailable.' }

    $resolved = Resolve-RideDesktopShortcutPath -Operation $operation

    $operation.TargetPath | Should -BeExactly $originalTarget
    $operation.WorkingDirectory | Should -BeExactly $originalWorkingDirectory
    $resolved.TargetPath | Should -BeExactly ([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables('%SystemRoot%\System32\control.exe')))
    $resolved.Arguments | Should -BeExactly '/name Microsoft.PowerOptions'
    $resolved.DescriptionText | Should -BeExactly 'Open Windows Power Options'
    $resolved.WorkingDirectory | Should -BeExactly ([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables('%SystemRoot%\System32')))
    $resolved.Path | Should -BeExactly ([IO.Path]::GetFullPath((Join-Path $desktop 'Power Options.lnk')))
  }

  It 'keeps the Power Options handoff pending and limited to the current user' {
    $catalog = Import-RideCatalogData (Join-Path $script:RepositoryRoot 'catalog/operations.psd1')
    $operation = @($catalog.Operations | Where-Object Id -CEQ 'windows.power-options-shortcut')[0]

    $operation.Scope | Should -BeExactly 'User'
    $operation.RequiresAdmin | Should -BeFalse
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.CandidateTargets | Should -Be @('Windows 11')
    $operation.PendingAcceptance | Should -BeTrue
    $operation.BaselineState | Should -BeExactly 'Absent'
    $errors = @(Get-RideCatalogValidationErrors -Catalog $catalog)
    $errors | Should -BeNullOrEmpty
  }

  It 'reports a missing shortcut path without opening COM' {
    $path = Join-Path $TestDrive 'missing-shortcut.lnk'

    $entry = Get-RideDesktopShortcutPathEntry -Path $path

    $entry.Exists | Should -BeFalse
    $entry.Attributes | Should -BeNullOrEmpty
  }

  It 'refuses a directory at the shortcut path before opening COM' {
    $path = Join-Path $TestDrive 'directory-collision.lnk'
    $null = New-Item -ItemType Directory -Path $path

    { Get-RideDesktopShortcutPathEntry -Path $path } | Should -Throw '*Refusing a directory or reparse point*'
  }

  It 'identifies an ordinary file as an existing shortcut candidate without opening COM' {
    $path = Join-Path $TestDrive 'synthetic-shortcut.lnk'
    [IO.File]::WriteAllText($path, 'synthetic placeholder')

    $entry = Get-RideDesktopShortcutPathEntry -Path $path

    $entry.Exists | Should -BeTrue
    ($entry.Attributes -band [IO.FileAttributes]::Directory) | Should -Be 0
    ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) | Should -Be 0
  }
}

Describe 'Desktop shortcut lifecycle diagnostics' {
  InModuleScope RIDE-DesktopShortcuts {
    It 'reports a missing Power Options target without naming BitLocker or invoking COM' {
      $missingTarget = Join-Path $TestDrive 'missing-control.exe'
      $workingDirectory = $TestDrive
      $shortcutPath = Join-Path $TestDrive 'Power Options.lnk'
      $operation = @{ Id = 'windows.power-options-shortcut' }
      $spec = [pscustomobject]@{
        Path = $shortcutPath
        TargetPath = $missingTarget
        Arguments = '/name Microsoft.PowerOptions'
        DescriptionText = 'Open Windows Power Options'
        WorkingDirectory = $workingDirectory
      }
      Mock Get-RideDesktopShortcutState {
        [pscustomobject]@{ Path = $shortcutPath; Present = $false; ExistingFile = $false }
      }
      Mock Resolve-RideDesktopShortcutPath { $spec }

      { Set-RideDesktopShortcutState -Operation $operation -State Present } |
        Should -Throw '*declared desktop shortcut target is unavailable*'

      Should -Invoke Get-RideDesktopShortcutState -Exactly 1
      Should -Invoke Resolve-RideDesktopShortcutPath -Exactly 1
    }
  }
}
