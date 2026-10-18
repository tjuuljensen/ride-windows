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
  }
}
function Invoke-RidePlan {
  [CmdletBinding(SupportsShouldProcess)] param($Plan, $GitHubAuthentication, $GitHubCredentialReference, $OfflineBundle, $OfflineProfileId, $OfflineCatalogFileId)
  $performed = if ($PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']) { $false } else { $PSCmdlet.ShouldProcess('synthetic target', 'record only') }
  New-SpyRecord $PSBoundParameters $WhatIfPreference $performed 'plan'
}
function Save-RidePackage {
  [CmdletBinding(SupportsShouldProcess)] param($Id, $Variant, $Destination, $GitHubAuthentication, $GitHubCredentialReference)
  $performed = if ($PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']) { $false } else { $PSCmdlet.ShouldProcess('synthetic download', 'record only') }
  New-SpyRecord $PSBoundParameters $WhatIfPreference $performed 'download'
}
function Restore-RideRun {
  [CmdletBinding(SupportsShouldProcess)] param($RunId, $GitHubAuthentication, $GitHubCredentialReference)
  $performed = if ($PSBoundParameters.ContainsKey('Confirm') -and [bool]$PSBoundParameters['Confirm']) { $false } else { $PSCmdlet.ShouldProcess('synthetic restore', 'record only') }
  New-SpyRecord $PSBoundParameters $WhatIfPreference $performed 'restore'
}
Export-ModuleMember -Function Set-RideLibraryContext, Get-RideProfile, Get-RidePlan, Get-RideSingleOperationPlan, Show-RidePlan, Invoke-RidePlan, Save-RidePackage, Restore-RideRun
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

  It 'allows <Command> without an accidental preview or confirmation switch' -TestCases $commandCases {
    param($Command, $Arguments)
    $rows = @(& $script:Runner @Arguments)
    $record = $rows | Where-Object Stage -eq Engine
    $record.WhatIf | Should -BeFalse
    $record.Preference | Should -BeFalse
    $record.Performed | Should -BeTrue
    $record.ConfirmBound | Should -BeFalse
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
