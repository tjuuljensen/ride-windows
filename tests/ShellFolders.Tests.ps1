<#
.SYNOPSIS
  Verify the optional God Mode desktop folder using isolated directory fixtures.
.DESCRIPTION
  Redirects desktop lookup to TestDrive. Exercises real empty-directory metadata,
  saved-run recovery, preview and collision protection without using the user's
  desktop, registry or Control Panel settings.
.EXAMPLE
  Invoke-Pester .\tests\ShellFolders.Tests.ps1
.INPUTS
  None. Pester creates isolated fixtures.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Repository engine and Shell folder module; NTFS TestDrive.
  Recovery: All file changes are restricted to TestDrive; desktop lookup is mocked.
  Author: RIDE-Windows maintainers.
  Version: Repository test fixture; no independent CLI version.
  Changelog: 2026-10-09: Add desktop Shell folder lifecycle and recovery coverage.
    Preserve generic ACL rights while adding fixture-only deletion grants.
    Compare restored ACL permissions when Windows recalculates auto-inheritance.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-ShellFolders.psm1') -Global
  $script:ShellOperation = Get-RideOperation -Id 'windows.god-mode-shortcut'
}

Describe 'God Mode desktop folder lifecycle' {
  BeforeEach {
    $script:DesktopFixture = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + ' redirected desktop [test]')
    $null = New-Item -Path $script:DesktopFixture -ItemType Directory
    $script:FolderPath = Join-Path $script:DesktopFixture $script:ShellOperation.FolderName
    InModuleScope RIDE-ShellFolders -Parameters @{ Desktop = $script:DesktopFixture } {
      param($Desktop)
      $script:ShellDesktopFixture = $Desktop
      Mock Get-RideDesktopDirectory { $script:ShellDesktopFixture }
    }
  }

  It 'declares an optional user setting with explicit states and platform defaults' {
    $script:ShellOperation.Kind | Should -Be 'ShellFolder'
    $script:ShellOperation.Handler | Should -Be 'ShellFolder'
    $script:ShellOperation.Scope | Should -Be 'User'
    $script:ShellOperation.RequiresAdmin | Should -BeFalse
    $script:ShellOperation.SupportedTargets | Should -Be @('Windows 11')
    $script:ShellOperation.TargetDefaults['Windows 11'].DefaultValue | Should -Be 'Absent'
    $script:ShellOperation.BaselineState | Should -Be 'Absent'
    $script:ShellOperation.Rollback | Should -Be 'Exact'
    $script:ShellOperation.States.Keys | Should -Contain 'Present'
    $script:ShellOperation.States.Keys | Should -Contain 'Absent'
    $script:ShellOperation.DocumentationUri | Should -Match '^https://learn\.microsoft\.com/'
    $profile = Get-RideProfile -Path (Join-Path $script:RepositoryRoot 'profiles/default.psd1')
    $profile.Operations.Id | Should -Not -Contain $script:ShellOperation.Id
    (Show-RideCatalog -View settings).Id | Should -Contain $script:ShellOperation.Id
    (Show-RideCatalog -View explorer).Id | Should -Contain $script:ShellOperation.Id
  }

  It 'uses the resolved desktop, including spaces and brackets, and applies idempotently' {
    $absent = Get-RideShellFolderState -Operation $script:ShellOperation
    $absent.Path | Should -Be $script:FolderPath
    $absent.Present | Should -BeFalse
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $original = Get-RideShellFolderState -Operation $script:ShellOperation
    $original.Present | Should -BeTrue
    $original.HasContents | Should -BeFalse
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $repeat = Get-RideShellFolderState -Operation $script:ShellOperation
    $repeat.CreationTimeUtc | Should -Be $original.CreationTimeUtc
    $repeat.LastWriteTimeUtc | Should -Be $original.LastWriteTimeUtc
    $repeat.SecurityDescriptor | Should -Be $original.SecurityDescriptor
    Set-RideShellFolderState -Operation $script:ShellOperation -State Absent
    Set-RideShellFolderState -Operation $script:ShellOperation -State Absent
    [IO.Directory]::Exists($script:FolderPath) | Should -BeFalse
  }

  It 'preserves a regular file at the configured folder path' {
    [IO.File]::WriteAllText($script:FolderPath, 'keep this file')
    { Set-RideShellFolderState -Operation $script:ShellOperation -State Present } | Should -Throw '*file or reparse point*'
    { Set-RideShellFolderState -Operation $script:ShellOperation -State Absent } | Should -Throw '*file or reparse point*'
    [IO.File]::ReadAllText($script:FolderPath) | Should -Be 'keep this file'
  }

  It 'refuses reparse points before reading their target or ACL' {
    InModuleScope RIDE-ShellFolders -Parameters @{ Operation = $script:ShellOperation } {
      param($Operation)
      Mock Get-Item { [pscustomobject]@{ PSIsContainer = $true; Attributes = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint } }
      Mock Get-Acl { throw 'ACL must not be read' }
      { Get-RideShellFolderState -Operation $Operation } | Should -Throw '*file or reparse point*'
      Should -Invoke Get-Acl -Times 0 -Exactly
    }
  }

  It 'preserves hidden contents and leaves an existing folder alone for Present' {
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $file = Join-Path $script:FolderPath 'keep.txt'
    [IO.File]::WriteAllText($file, 'keep hidden contents')
    [IO.File]::SetAttributes($file, [IO.FileAttributes]::Hidden)
    (Get-RideShellFolderState -Operation $script:ShellOperation).HasContents | Should -BeTrue
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    { Set-RideShellFolderState -Operation $script:ShellOperation -State Absent } | Should -Throw '*nonempty*'
    [IO.File]::ReadAllText($file) | Should -Be 'keep hidden contents'
  }

  It 'restores an absent snapshot and preserves files added after creation' {
    $snapshot = Get-RideShellFolderState -Operation $script:ShellOperation
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $file = Join-Path $script:FolderPath 'added.txt'
    [IO.File]::WriteAllText($file, 'keep added contents')
    { Restore-RideShellFolderState -Operation $script:ShellOperation -Snapshot $snapshot } | Should -Throw '*nonempty*'
    [IO.File]::ReadAllText($file) | Should -Be 'keep added contents'
    [IO.File]::Delete($file)
    Restore-RideShellFolderState -Operation $script:ShellOperation -Snapshot $snapshot
    (Get-RideShellFolderState -Operation $script:ShellOperation).Present | Should -BeFalse
  }

  It 'recreates a removed empty folder with captured metadata after JSON serialization' {
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $acl = Get-Acl -LiteralPath $script:FolderPath
    $acl.SetAccessRuleProtection($true, $true)
    # The Windows test sandbox grants deletion to its identities on newly
    # created directories. Keep those grants stable across directory recreation.
    foreach ($rule in @($acl.Access | Where-Object AccessControlType -eq 'Allow')) {
      $stableRule = New-Object Security.AccessControl.FileSystemAccessRule(
        $rule.IdentityReference,
        [Security.AccessControl.FileSystemRights]::Delete,
        $rule.InheritanceFlags, $rule.PropagationFlags, $rule.AccessControlType
      )
      $acl.AddAccessRule($stableRule)
    }
    Set-Acl -LiteralPath $script:FolderPath -AclObject $acl
    [IO.File]::SetAttributes($script:FolderPath, [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::Hidden)
    [IO.Directory]::SetCreationTimeUtc($script:FolderPath, [datetime]'2020-02-03T04:05:06.1234567Z')
    [IO.Directory]::SetLastWriteTimeUtc($script:FolderPath, [datetime]'2021-02-03T04:05:06.7654321Z')
    $original = Get-RideShellFolderState -Operation $script:ShellOperation
    $snapshot = $original | ConvertTo-Json | ConvertFrom-Json
    Set-RideShellFolderState -Operation $script:ShellOperation -State Absent
    Restore-RideShellFolderState -Operation $script:ShellOperation -Snapshot $snapshot
    $restored = Get-RideShellFolderState -Operation $script:ShellOperation
    foreach ($field in @('Path', 'Present', 'HasContents', 'Attributes', 'CreationTimeUtc', 'LastWriteTimeUtc')) {
      $restored.$field | Should -Be $original.$field
    }
    # Windows may reorder equivalent allow ACEs. Compare every permission and
    # inheritance flag, as well as owner/group and protected inheritance.
    $expectedAcl = New-Object Security.AccessControl.DirectorySecurity
    $expectedAcl.SetSecurityDescriptorSddlForm($original.SecurityDescriptor)
    $actualAcl = Get-Acl -LiteralPath $script:FolderPath
    $actualAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value | Should -Be $expectedAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $actualAcl.GetGroup([Security.Principal.SecurityIdentifier]).Value | Should -Be $expectedAcl.GetGroup([Security.Principal.SecurityIdentifier]).Value
    $actualAcl.AreAccessRulesProtected | Should -BeTrue
    $ruleSets = foreach ($directoryAcl in @($expectedAcl, $actualAcl)) {
      $rules = $directoryAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value, [int]$_.FileSystemRights, $_.AccessControlType, $_.InheritanceFlags, $_.PropagationFlags, $_.IsInherited
      } | Sort-Object
      $rules -join ';'
    }
    $ruleSets[1] | Should -Be $ruleSets[0]
  }

  It 'refuses to overwrite new contents when restoring an existing empty folder' {
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $snapshot = Get-RideShellFolderState -Operation $script:ShellOperation
    $file = Join-Path $script:FolderPath 'added.txt'
    [IO.File]::WriteAllText($file, 'keep contents')
    { Restore-RideShellFolderState -Operation $script:ShellOperation -Snapshot $snapshot } | Should -Throw '*nonempty*'
    [IO.File]::ReadAllText($file) | Should -Be 'keep contents'
  }

  It 'rejects a snapshot from a different desktop without changing either path' {
    $snapshot = Get-RideShellFolderState -Operation $script:ShellOperation
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $snapshot.Path = Join-Path $TestDrive 'different desktop/GodMode'
    { Restore-RideShellFolderState -Operation $script:ShellOperation -Snapshot $snapshot } | Should -Throw '*desktop redirection*'
    [IO.Directory]::Exists($script:FolderPath) | Should -BeTrue
    Test-Path -LiteralPath $snapshot.Path | Should -BeFalse
  }

  It 'rejects unavailable desktops and unsupported path metadata' {
    InModuleScope RIDE-ShellFolders -Parameters @{ Operation = $script:ShellOperation } {
      param($Operation)
      Mock Get-RideDesktopDirectory { '' }
      { Get-RideShellFolderState -Operation $Operation } | Should -Throw '*desktop directory is unavailable*'
      $invalid = $Operation.Clone()
      $invalid.FolderName = '../escape'
      { Get-RideShellFolderState -Operation $invalid } | Should -Throw '*Unsupported*'
    }
    [IO.Directory]::Exists($script:FolderPath) | Should -BeFalse
  }
}

Describe 'God Mode engine lifecycle' {
  BeforeEach {
    $script:EngineDesktop = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + ' desktop')
    $null = New-Item -Path $script:EngineDesktop -ItemType Directory
    InModuleScope RIDE-ShellFolders -Parameters @{ Desktop = $script:EngineDesktop } {
      param($Desktop)
      $script:ShellDesktopFixture = $Desktop
      Mock Get-RideDesktopDirectory { $script:ShellDesktopFixture }
    }
    InModuleScope RIDE.Engine -Parameters @{ StateRoot = (Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + ' state')) } {
      param($StateRoot)
      $script:ShellStateRoot = $StateRoot
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $false }
      Mock Get-RideStateRoot { $script:ShellStateRoot }
    }
  }

  It 'plans Present, Absent, Baseline and unset, and rejects undeclared states and Server' {
    foreach ($state in @('Present', 'Absent', 'Baseline')) {
      $plan = @(Get-RideSingleOperationPlan -Id $script:ShellOperation.Id -Action Set -State $state)
      $plan[0].State | Should -Be $(if ($state -eq 'Baseline') { 'Absent' } else { $state })
    }
    @(Get-RideSingleOperationPlan -Id $script:ShellOperation.Id -Action Unset)[0].State | Should -Be 'Absent'
    { Get-RideSingleOperationPlan -Id $script:ShellOperation.Id -Action Set -State Enabled } | Should -Throw '*not supported*'
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows Server 2025' }
    { Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $script:ShellOperation.Id -Action Set -State Present) -WhatIf -Confirm:$false } | Should -Throw '*not support*'
  }

  It 'shows the live path and baseline and compares desired and platform default states' {
    $shown = Show-RideOperation -Id $script:ShellOperation.Id | Out-String -Width 4096
    $shown | Should -Match ([regex]::Escape((Join-Path $script:EngineDesktop $script:ShellOperation.FolderName)))
    $shown | Should -Match 'CurrentState\s+: Absent'
    $shown | Should -Match 'BaselineValue\s+: Absent'
    $profile = @{ SchemaVersion = 1; Name = 'God Mode fixture'; Operations = @(@{ Id = $script:ShellOperation.Id; State = 'Present' }) }
    $status = @(Get-RideStatus -Profile $profile -View settings)[0]
    $status.DesiredState | Should -Be 'Present'
    $status.InDesiredState | Should -BeFalse
    $status.CurrentValueType | Should -Be 'Desktop Shell folder'
    InModuleScope RIDE.Engine -Parameters @{ Operation = $script:ShellOperation } {
      param($Operation)
      $script:SingleShellCatalog = @{ Operations = @($Operation); Groups = @() }
      Mock Get-RideCatalog { $script:SingleShellCatalog }
      $row = @(Get-RideStatus -View explorer)[0]
      $row.DefaultValue | Should -Be 'Absent'
      $row.MatchesDefault | Should -BeTrue
      $row.CurrentValueType | Should -Be 'Desktop Shell folder'
    }
  }

  It 'previews, saves absent state, repeats and restores without touching the real desktop' {
    InModuleScope RIDE.Engine {
      $id = 'windows.god-mode-shortcut'
      $operation = Get-RideOperation -Id $id
      $plan = @(Get-RideSingleOperationPlan -Id $id -Action Set -State Present)
      Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
      Test-Path -LiteralPath $script:ShellStateRoot | Should -BeFalse
      (Get-RideCurrentState -Operation $operation).Present | Should -BeFalse
      $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
      $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
      $runId | Should -Match '^[a-f0-9]{32}$'
      $record = Get-Content -LiteralPath (Join-Path $script:ShellStateRoot "$runId/$id.json") -Raw | ConvertFrom-Json
      $record.Scope | Should -Be 'User'
      $record.Snapshot.Present | Should -BeFalse
      $record.Snapshot.Path | Should -Be (Get-RideCurrentState -Operation $operation).Path
      $record.Kind | Should -Be 'ShellFolder'
      @(Invoke-RidePlan -Plan $plan -Confirm:$false) | Should -Contain 'No changes were needed; no state record was created.'
      @(Get-ChildItem -LiteralPath $script:ShellStateRoot -Directory).Count | Should -Be 1
      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
      (Get-RideCurrentState -Operation $operation).Present | Should -BeTrue
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      (Get-RideCurrentState -Operation $operation).Present | Should -BeFalse
    }
  }

  It 'restores an empty folder removed by unset with its complete snapshot' {
    Set-RideShellFolderState -Operation $script:ShellOperation -State Present
    $original = Get-RideShellFolderState -Operation $script:ShellOperation
    $output = @(Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $script:ShellOperation.Id -Action Unset) -Confirm:$false)
    $runId = ($output | Where-Object { $_ -match '^Run ID: ' }) -replace '^Run ID: ', ''
    (Get-RideShellFolderState -Operation $script:ShellOperation).Present | Should -BeFalse
    Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
    $restored = Get-RideShellFolderState -Operation $script:ShellOperation
    foreach ($field in @('Path', 'Present', 'Attributes', 'CreationTimeUtc', 'LastWriteTimeUtc')) {
      $restored.$field | Should -Be $original.$field
    }
    # Windows can recalculate the DACL auto-inherited control flag on recreation.
    # Preserve the owner, group, protection and every explicit/inherited ACE.
    $expectedAcl = New-Object Security.AccessControl.DirectorySecurity
    $expectedAcl.SetSecurityDescriptorSddlForm($original.SecurityDescriptor)
    $actualAcl = New-Object Security.AccessControl.DirectorySecurity
    $actualAcl.SetSecurityDescriptorSddlForm($restored.SecurityDescriptor)
    $actualAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value | Should -Be $expectedAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    $actualAcl.GetGroup([Security.Principal.SecurityIdentifier]).Value | Should -Be $expectedAcl.GetGroup([Security.Principal.SecurityIdentifier]).Value
    $actualAcl.AreAccessRulesProtected | Should -Be $expectedAcl.AreAccessRulesProtected
    $ruleSets = foreach ($directoryAcl in @($expectedAcl, $actualAcl)) {
      $rules = $directoryAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value, [int]$_.FileSystemRights, $_.AccessControlType, $_.InheritanceFlags, $_.PropagationFlags, $_.IsInherited
      } | Sort-Object
      $rules -join ';'
    }
    $ruleSets[1] | Should -Be $ruleSets[0]
  }

  It 'retains a recoverable saved snapshot if creation fails' {
    InModuleScope RIDE.Engine {
      Mock Set-RideShellFolderState { throw 'simulated folder creation failure' }
      $plan = @(Get-RideSingleOperationPlan -Id 'windows.god-mode-shortcut' -Action Set -State Present)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*simulated folder creation failure*'
      $record = Get-Content -LiteralPath @(Get-ChildItem -LiteralPath $script:ShellStateRoot -Recurse -Filter 'windows.god-mode-shortcut.json')[0].FullName -Raw | ConvertFrom-Json
      $record.Snapshot.Present | Should -BeFalse
      Restore-RideRun -RunId $record.RunId -Confirm:$false | Out-Null
    }
  }

  It 'completes the ID and named or positional states from the catalog without inspection' {
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { throw 'Completion must not inspect Windows' }
    foreach ($line in @('.\ride.ps1 show windows.god-mode-', '.\ride.ps1 set windows.god-mode-shortcut -State ', '.\ride.ps1 set windows.god-mode-shortcut ')) {
      $matches = (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText
      if ($line -like '*show*') { $matches | Should -Contain 'windows.god-mode-shortcut' }
      else {
        $matches | Should -Contain 'Present'
        $matches | Should -Contain 'Absent'
        $matches | Should -Contain 'Baseline'
      }
    }
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 0 -Exactly
  }
}
