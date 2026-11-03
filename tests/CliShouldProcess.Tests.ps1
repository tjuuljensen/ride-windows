<#
.SYNOPSIS
  Verify CLI preview and confirmation forwarding without Windows changes.
.DESCRIPTION
  Executes a copied ride.ps1 against a fake engine that records ShouldProcess.
  No operational handler, registry query, download or installer can be invoked.
.EXAMPLE
  Invoke-Pester .\tests\CliShouldProcess.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
#>

BeforeDiscovery {
  $commandCases = @(
    @{ Command = 'apply'; Arguments = @{ Command = 'apply'; Profile = 'fake-profile.psd1' } },
    @{ Command = 'install'; Arguments = @{ Command = 'install'; Id = 'fake.package' } },
    @{ Command = 'set'; Arguments = @{ Command = 'set'; Id = 'fake.setting'; State = 'Enabled' } },
    @{ Command = 'unset'; Arguments = @{ Command = 'unset'; Id = 'fake.setting' } },
    @{ Command = 'remove'; Arguments = @{ Command = 'remove'; Id = 'fake.package' } },
    @{ Command = 'download'; Arguments = @{ Command = 'download'; Id = 'fake.package' } },
    @{ Command = 'restore'; Arguments = @{ Command = 'restore'; RunId = '11111111111111111111111111111111' } }
  )
  $confirmationCases = foreach ($command in @('install','download','restore')) {
    foreach ($enabled in @($true,$false)) {
      @{ Command = $command; Enabled = $enabled; Arguments = ($commandCases | Where-Object Command -eq $command).Arguments }
    }
  }
}

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  $script:OriginalRideModules = @(Get-Module | Where-Object { $_.Path -and $_.Path.StartsWith((Join-Path $script:Root 'modules'),[StringComparison]::OrdinalIgnoreCase) } | ForEach-Object Path)
  $script:EngineSpy = @'
function Set-RideLibraryContext { param([string[]] $Library) }
function Get-RideProfile { param([string] $Path) @{ Operations = @() } }
function Get-RidePlan { param($Profile, $Action) [pscustomobject]@{ State = 'Present'; Operation = @{ Id = 'synthetic' } } }
function Get-RideStatus { param($Profile, $View, $OperationId) [pscustomobject]@{ Stage = 'Status'; View = $View; OperationId = $OperationId; ProfileSet = ($null -ne $Profile) } }
function Get-RideSingleOperationPlan { param($Id, $Action, $State, $Variant) [pscustomobject]@{ State = $State; Operation = @{ Id = $Id } } }
function Show-RidePlan { param($Plan) [pscustomobject]@{ Stage = 'Plan' } }
function New-SpyRecord {
  param($Bound, $Preference, $Performed, $Command)
  [pscustomobject]@{
    Stage = 'Engine'; Command = $Command; Performed = $Performed
    WhatIf = [bool]$Bound['WhatIf']; Preference = [bool]$Preference
    ConfirmBound = $Bound.ContainsKey('Confirm'); Confirm = [bool]$Bound['Confirm']
    GitHubAuthentication = $Bound['GitHubAuthentication']; GitHubCredentialReference = $Bound['GitHubCredentialReference']
    OfflineBundle = $Bound['OfflineBundle']; OfflineProfileId = $Bound['OfflineProfileId']; OfflineCatalogFileId = $Bound['OfflineCatalogFileId']
    AllowCandidate = [bool]$Bound['AllowCandidate']; AllowCandidateBound = $Bound.ContainsKey('AllowCandidate')
    AllowUnsupportedTarget = [bool]$Bound['AllowUnsupportedTarget']
  }
}
function Invoke-RidePlan {
  [CmdletBinding(SupportsShouldProcess)] param($Plan, $GitHubAuthentication, $GitHubCredentialReference, $OfflineBundle, $OfflineProfileId, $OfflineCatalogFileId, [switch]$AllowCandidate, [switch]$AllowUnsupportedTarget)
  $performed = if ($PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']) { $false } else { $PSCmdlet.ShouldProcess('synthetic target', 'record only') }
  New-SpyRecord $PSBoundParameters $WhatIfPreference $performed 'plan'
}
function Save-RidePackage {
  [CmdletBinding(SupportsShouldProcess)] param($Id, $Variant, $Destination, $GitHubAuthentication, $GitHubCredentialReference)
  $performed = if ($PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']) { $false } else { $PSCmdlet.ShouldProcess('synthetic download', 'record only') }
  New-SpyRecord $PSBoundParameters $WhatIfPreference $performed 'download'
}
function Restore-RideRun {
  [CmdletBinding(SupportsShouldProcess)] param($RunId, $GitHubAuthentication, $GitHubCredentialReference, [switch]$AllowCandidate, [switch]$AllowUnsupportedTarget)
  $performed = if ($PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']) { $false } else { $PSCmdlet.ShouldProcess('synthetic restore', 'record only') }
  New-SpyRecord $PSBoundParameters $WhatIfPreference $performed 'restore'
}
Export-ModuleMember -Function Set-RideLibraryContext, Get-RideProfile, Get-RidePlan, Get-RideStatus, Get-RideSingleOperationPlan, Show-RidePlan, Invoke-RidePlan, Save-RidePackage, Restore-RideRun
'@
}

Describe 'CLI ShouldProcess forwarding' {
  BeforeEach {
    $script:Isolated = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory((Join-Path $script:Isolated 'modules'))
    $script:Runner = Join-Path $script:Isolated 'ride.ps1'
    Copy-Item -LiteralPath (Join-Path $script:Root 'ride.ps1') -Destination $script:Runner
    [IO.File]::WriteAllText((Join-Path $script:Isolated 'modules/RIDE.Engine.psm1'), $script:EngineSpy, [Text.UTF8Encoding]::new($false))
  }
  AfterEach {
    Get-Module -All | Where-Object { $_.Path -and $_.Path.StartsWith($script:Isolated + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) } | Remove-Module -Force
  }
  AfterAll {
    # The isolated spies use the engine's name; restore real command discovery
    # for later files in a combined Pester run.
    Import-Module (Join-Path $script:Root 'modules/RIDE.Engine.psm1') -Force
    foreach ($modulePath in $script:OriginalRideModules) { if ([IO.Path]::GetFileName($modulePath) -ne 'RIDE.Engine.psm1') { Import-Module $modulePath -Global } }
  }

  It 'forwards candidate opt-in and preview for <Command>' -TestCases @($commandCases | Where-Object Command -ne download) {
    param($Command, $Arguments)
    $record = & $script:Runner @Arguments -AllowCandidate -WhatIf | Where-Object Stage -eq Engine
    $record.AllowCandidate | Should -BeTrue
    $record.WhatIf | Should -BeTrue
    $record.Performed | Should -BeFalse
    $record = & $script:Runner @Arguments -AllowCandidate:$false -WhatIf | Where-Object Stage -eq Engine
    $record.AllowCandidate | Should -BeFalse
  }
  It 'refuses candidate opt-in on commands without the change or restore gate' {
    foreach ($command in @('list','show','search','plan','status','download','prune-state')) {
      { & $script:Runner $command -AllowCandidate } | Should -Throw '*AllowCandidate is supported by*'
    }
  }
  It 'forwards target exploration and preview for <Command>' -TestCases @($commandCases | Where-Object Command -ne download) {
    param($Command, $Arguments)
    $record = & $script:Runner @Arguments -AllowUnsupportedTarget -WhatIf | Where-Object Stage -eq Engine
    $record.AllowUnsupportedTarget | Should -BeTrue
    $record.Performed | Should -BeFalse
  }
  It 'refuses target exploration on read-only and unrelated commands' {
    foreach ($command in @('list','show','search','plan','status','download','prune-state')) {
      { & $script:Runner $command -AllowUnsupportedTarget } | Should -Throw '*AllowUnsupportedTarget is supported by*'
    }
  }
  It 'completes the target exploration parameter through native PowerShell metadata' {
    $line='& "'+$script:Runner+'" set -AllowUnsup'
    $matches=TabExpansion2 -InputScript $line -CursorColumn $line.Length
    @($matches.CompletionMatches.CompletionText) | Should -Contain '-AllowUnsupportedTarget'
  }

  It 'completes explicit status operation IDs from the local catalog' {
    $commandPath = Join-Path $script:Root 'ride.ps1'
    $line = '& "' + $commandPath + '" status -OperationId windows.show'
    $matches = TabExpansion2 -InputScript $line -CursorColumn $line.Length
    @($matches.CompletionMatches.CompletionText) | Should -Contain 'windows.show-known-extensions'
  }

  It 'forwards explicit PAT selection for <Command> without resolving credentials during preview' -TestCases @(
    @{ Command='download'; Arguments=@{ Command='download'; Id='fake.package' } },
    @{ Command='install'; Arguments=@{ Command='install'; Id='fake.package' } },
    @{ Command='apply'; Arguments=@{ Command='apply'; Profile='fake.psd1' } },
    @{ Command='restore'; Arguments=@{ Command='restore'; RunId=('a'*32) } }
  ) {
    param($Command,$Arguments)
    $record = & $script:Runner @Arguments -GitHubAuthentication PAT -GitHubCredentialReference nonexistent -WhatIf | Where-Object Stage -eq Engine
    $record.GitHubAuthentication | Should -Be PAT
    $record.GitHubCredentialReference | Should -Be nonexistent
    $record.Performed | Should -BeFalse
  }

  It 'refuses incomplete or conflicting authentication choices before loading handlers' {
    { & $script:Runner download fake.package -GitHubAuthentication PAT } | Should -Throw '*requires*'
    { & $script:Runner download fake.package -GitHubCredentialReference fake } | Should -Throw '*Anonymous forbids*'
    { & $script:Runner list -GitHubAuthentication PAT -GitHubCredentialReference fake } | Should -Throw '*only*'
  }
  It 'forwards the complete explicit offline selection for <Command>' -ForEach @(
    @{Command='install';Arguments=@{Command='install';Id='fake.package'}},
    @{Command='apply';Arguments=@{Command='apply';Profile='fake.psd1'}}
  ) {
    $record=& $script:Runner @Arguments -OfflineBundle 'bundle.json' -OfflineProfileId workstation -OfflineCatalogFileId catalog -WhatIf | Where-Object Stage -eq Engine
    $record.OfflineBundle | Should -BeExactly 'bundle.json'
    $record.OfflineProfileId | Should -BeExactly workstation
    $record.OfflineCatalogFileId | Should -BeExactly catalog
    $record.Performed | Should -BeFalse
  }
  It 'refuses incomplete, unsupported and conflicting offline command options' {
    {& $script:Runner install fake.package -OfflineBundle 'bundle.json'} | Should -Throw '*required together*'
    {& $script:Runner install fake.package -OfflineBundle ''} | Should -Throw '*required together*'
    {& $script:Runner restore -OfflineBundle 'bundle.json' -OfflineProfileId p -OfflineCatalogFileId c} | Should -Throw '*install and apply only*'
    {& $script:Runner install fake.package -OfflineBundle 'bundle.json' -OfflineProfileId p -OfflineCatalogFileId c -GitHubAuthentication Anonymous} | Should -Throw '*network authentication*'
    {& $script:Runner apply -OfflineBundle 'bundle.json' -OfflineProfileId p -OfflineCatalogFileId c -UserContext Desktop} | Should -Throw '*desktop handoff*'
  }

  It 'routes named and positional status selectors and rejects ambiguous combinations' {
    $output = (& $script:Runner status packages | Out-String)
    $output | Should -Match 'packages'
    $output = (& $script:Runner status -View settings -Profile fake-profile.psd1 | Out-String)
    $output | Should -Match 'View\s+: settings'
    $output | Should -Match 'ProfileSet\s+: True'
    $output = (& $script:Runner status -OperationId windows.sample -Profile fake-profile.psd1 | Out-String)
    $output | Should -Match 'View\s+: all'
    $output | Should -Match 'OperationId\s+: windows.sample'
    $output | Should -Match 'ProfileSet\s+: True'
    { & $script:Runner status -OperationId windows.sample -View settings } | Should -Throw '*cannot be combined*'
    { & $script:Runner status packages -View settings } | Should -Throw '*either a positional status view or -View*'
    { & $script:Runner list -OperationId windows.sample } | Should -Throw '*status only*'
  }

  It 'refuses search-only filters and conflicting query selectors before discovery' {
    { & $script:Runner list -Query 'synthetic' } | Should -Throw '*only supported by the search command*'
    { & $script:Runner show fake.setting -Field Name } | Should -Throw '*only supported by the search command*'
    { & $script:Runner list -View settings } | Should -Throw '*search and status only*'
    { & $script:Runner search positional -Query named } | Should -Throw '*either a positional search query or -Query*'
    { & $script:Runner search } | Should -Throw '*requires a nonblank query*'
  }

  It 'refuses state-store selectors outside prune-state' {
    { & $script:Runner list -StateScope Machine } | Should -Throw '*only supported by prune-state*'
    { & $script:Runner remove fake.package -OlderThanDays 90 } | Should -Throw '*only supported by prune-state*'
  }

  It 'refuses package variants outside supported commands or without an ID' {
    { & $script:Runner apply -Profile fake-profile.psd1 -Variant portable } | Should -Throw '*Variant is supported by*'
    { & $script:Runner show -Variant portable } | Should -Throw '*Variant requires a package ID*'
  }

  It 'rejects ambiguous direct and profile removal before planning' {
    { & $script:Runner remove fake.package -Profile fake-profile.psd1 } | Should -Throw '*either a single package ID or -Profile*'
  }

  It 'refuses unsupported prune-state selectors before invoking the cleanup handler' {
    { & $script:Runner prune-state -Id fake.package } | Should -Throw '*does not support: Id*'
    { & $script:Runner prune-state -RunId ('a' * 32) } | Should -Throw '*does not support: RunId*'
  }

  It 'allows <Command> without an accidental preview or confirmation switch' -TestCases $commandCases {
    param($Command, $Arguments)
    $rows = @(& $script:Runner @Arguments)
    $record = $rows | Where-Object Stage -eq Engine
    $record.WhatIf | Should -BeFalse
    $record.Preference | Should -BeFalse
    $record.Performed | Should -BeTrue
    $record.ConfirmBound | Should -BeFalse
    $record.AllowCandidateBound | Should -BeFalse
    @($rows | Where-Object Stage -eq Plan).Count | Should -Be 0
  }

  It 'previews <Command> when WhatIf is explicitly enabled' -TestCases $commandCases {
    param($Command, $Arguments)
    $record = @(& $script:Runner @Arguments -WhatIf) | Where-Object Stage -eq Engine
    $record.WhatIf | Should -BeTrue
    $record.Preference | Should -BeTrue
    $record.Performed | Should -BeFalse
  }

  It 'honors inherited preview for <Command>' -TestCases $commandCases {
    param($Command, $Arguments)
    $previousPreference = $WhatIfPreference
    try {
      $WhatIfPreference = $true
      $record = @(& $script:Runner @Arguments) | Where-Object Stage -eq Engine
      $record.WhatIf | Should -BeTrue
      $record.Performed | Should -BeFalse
    } finally { $WhatIfPreference = $previousPreference }
  }

  It 'allows an explicit false switch to override inherited preview for <Command>' -TestCases $commandCases {
    param($Command, $Arguments)
    $previousPreference = $WhatIfPreference
    try {
      $WhatIfPreference = $true
      $record = @(& $script:Runner @Arguments -WhatIf:$false) | Where-Object Stage -eq Engine
      $record.WhatIf | Should -BeFalse
      $record.Performed | Should -BeTrue
    } finally { $WhatIfPreference = $previousPreference }
  }

  It 'forwards Confirm=<Enabled> for <Command> without prompting in the spy' -TestCases $confirmationCases {
    param($Command, $Enabled, $Arguments)
    $record = @(& $script:Runner @Arguments -Confirm:$Enabled) | Where-Object Stage -eq Engine
    $record.ConfirmBound | Should -BeTrue
    $record.Confirm | Should -Be $Enabled
    $record.WhatIf | Should -BeFalse
  }
}
