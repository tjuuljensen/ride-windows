<#
.SYNOPSIS
  Plan, inspect, and manage declared Windows settings and packages.

.DESCRIPTION
  Loads catalog metadata and dispatches list, show, plan, apply, download, install,
  set, unset, status, restore, or remove. Command defaults to list. Discovery and
  completion are read-only. State-changing engine commands use ShouldProcess and
  save pre-change state for settings and package presence. Package restoration
  can reinstall the current upstream release; exact prior package versions are
  not guaranteed. Downloads retain artifacts and observation metadata.

.PARAMETER Command
  Declared command; defaults to list. Press Tab to discover the supported command set.

.PARAMETER Id
  Operation/package/group ID, or a view for list/status. Direct actions require an appropriate
  operation ID.

.PARAMETER Profile
  Profile data-file path. Profile commands default to profiles/default.psd1; status compares a
  profile only when explicitly supplied.

.PARAMETER State
  Catalog state for set, also accepted positionally after the ID. Press Tab for declared states.

.PARAMETER RunId
  32-character hexadecimal saved run ID for restore; press Tab to discover saved manifests.

.PARAMETER Destination
  Directory for download artifacts; defaults to the user state root Artifacts directory.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\ride.ps1 -Help

.EXAMPLE
  .\ride.ps1 list packages

.EXAMPLE
  .\ride.ps1 set windows.show-known-extensions Enabled -WhatIf

.EXAMPLE
  .\ride.ps1 apply -Profile .\profiles\analyst-basics.psd1 -WhatIf

.EXAMPLE
  .\ride.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.Object. Catalog objects, formatted inspection/plan/status data, progress strings, or
  downloaded artifact records, depending on the command.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows 11 or Windows Server 2025 as declared per operation; elevate for machine
  changes. Downloads/installers need their catalog sources.
  File/environment inputs: catalog/operations.psd1, profiles/*.psd1, focused modules, and
  machine/user RIDE state stores. Package observations use catalog/artifact-observations.json.
  Recovery: Use restore -RunId for captured state. Package recovery has the catalog-declared limits.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

.LINK
  README.md

.LINK
  docs/models/script-repository-model.md

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [Parameter(Position = 0)]
  [ValidateSet('list', 'show', 'plan', 'apply', 'download', 'install', 'set', 'unset', 'status', 'restore', 'remove')]
  [string] $Command = 'list',

  [Parameter(Position = 1)]
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)

    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptCommand = Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop
        $scriptPath = $scriptCommand.Source
      }
      $catalogPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path) 'catalog/operations.psd1'
      $catalog = Import-PowerShellDataFile -Path $catalogPath -ErrorAction Stop
      $ids = @($catalog.Operations + $catalog.Groups | ForEach-Object { $_.Id } | Sort-Object -Unique)
      $listViews = @('all', 'profiles', 'packages', 'groups', 'settings')
      foreach ($category in @($catalog.Operations + $catalog.Groups | ForEach-Object { $_.Category } | Sort-Object -Unique)) {
        foreach ($part in ($category -split '\s*/\s*')) {
          $view = ($part -replace '\s+', '-').ToLowerInvariant()
          if ($view -and $view -notin $listViews) { $listViews += $view }
        }
      }
      $isListCommand = $commandAst.CommandElements.Count -gt 1 -and $commandAst.CommandElements[1].Value -eq 'list'
      if ($isListCommand) { $ids += $listViews }
      $isStatusCommand = $commandAst.CommandElements.Count -gt 1 -and $commandAst.CommandElements[1].Value -eq 'status'
      if ($isStatusCommand) { $ids += @($listViews | Where-Object { $_ -ne 'profiles' }) }

      foreach ($candidate in @($ids | Sort-Object -Unique)) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
          [System.Management.Automation.CompletionResult]::new(
            $candidate,
            $candidate,
            [System.Management.Automation.CompletionResultType]::ParameterValue,
            $candidate
          )
        }
      }
    }
    catch {
      # Completion should stay quiet if the catalog is unavailable or invalid.
    }
  })]
  [string] $Id = '',

  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $repoRoot = Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path
      $prefix = [string]$wordToComplete
      foreach ($profileFile in @(Get-ChildItem -LiteralPath (Join-Path $repoRoot 'profiles') -Filter '*.psd1' -File -ErrorAction Stop)) {
        $candidate = Resolve-Path -LiteralPath $profileFile.FullName -Relative
        $repositoryRelativePath = 'profiles\' + $profileFile.Name
        if ($candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
            $repositoryRelativePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or
            $profileFile.Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
          $completionText = if ($candidate.Contains(' ')) { '"' + $candidate + '"' } else { $candidate }
          [System.Management.Automation.CompletionResult]::new(
            $completionText,
            $profileFile.Name,
            [System.Management.Automation.CompletionResultType]::ParameterValue,
            $profileFile.Name
          )
        }
      }
    }
    catch {
      # Completion should stay quiet if the repository or profiles are unavailable.
    }
  })]
  [string] $Profile = '',
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      if (-not $fakeBoundParameters.ContainsKey('Id')) { return }
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $catalogPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path) 'catalog/operations.psd1'
      $catalog = Import-PowerShellDataFile -Path $catalogPath -ErrorAction Stop
      $operation = $catalog.Operations | Where-Object { $_.Id -eq $fakeBoundParameters.Id } | Select-Object -First 1
      if ($operation.Kind -in @('RegistryValue', 'RegistryKeySet')) {
        $states = @($operation.States.Keys)
        if ($operation.Kind -eq 'RegistryValue' -and 'Baseline' -notin $states) { $states += 'Baseline' }
      }
      elseif ($operation.Kind -eq 'DefenderExclusion') {
        $states = @('Present', 'Absent')
      }
      if ($states) {
        foreach ($candidate in $states | Sort-Object -Unique) {
          if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
            [System.Management.Automation.CompletionResult]::new($candidate, $candidate, [System.Management.Automation.CompletionResultType]::ParameterValue, $candidate)
          }
        }
      }
    }
    catch { }
  })]
  [Parameter(Position = 2)]
  [string] $State = '',
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $stateRoots = @(
        (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'RIDE/State'),
        (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE/State')
      )
      $runIds = foreach ($stateRoot in $stateRoots) {
        Get-ChildItem -LiteralPath $stateRoot -Directory -ErrorAction SilentlyContinue |
          Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName '_manifest.json') } |
          ForEach-Object { $_.Name }
      }
      foreach ($candidate in @($runIds | Sort-Object -Unique)) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
          [System.Management.Automation.CompletionResult]::new(
            $candidate,
            $candidate,
            [System.Management.Automation.CompletionResultType]::ParameterValue,
            $candidate
          )
        }
      }
    }
    catch {
      # Completion should stay quiet if state storage is unavailable.
    }
  })]
  [string] $RunId = '',
  [string] $Destination = '',
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }

if ($Help) {
  @'
RIDE-Windows - declarative Windows setup and maintenance

Usage:
  .\ride.ps1 <command> [options]

Commands:
  list [view]          List catalog objects; filter with a list view below.
  show <id>            Show metadata and current value; settings include the baseline value.
  plan                 Show current values beside the profile's desired values.
  apply                Apply the profile and record prior state.
  download <catalog-id> Download a package or standalone artifact without applying it.
  install <package-id> Install one catalog package and record its prior state.
  set <setting-id>     Set one catalog setting to a declared state; use -State <state>.
  unset <setting-id>   Remove one setting value when its catalog declares an unset state.
  status [view]         Show default or profile status, optionally filtered.
  restore -RunId <id>  Restore values recorded before a prior run.
  remove [package-id]  Uninstall one package or packages selected by the profile.

Options:
  -Profile <file>      Select a profile (default: profiles/default.psd1).
  -Id <id|view>        ID for show, or a view after list/status.
  -State <state>       Declared state for set; press Tab to complete available states.
  -RunId <id>          Run ID required by restore.
  -Destination <path>  Retain a downloaded artifact under this directory.
  -WhatIf              Preview apply, remove, or restore.
  -Confirm             Ask before each supported change.
  -Help                Display this help.
  -Version             Print the script version without loading the engine.

List views:
  all                  Show operations, groups, and profiles.
  profiles             Show available profile files and the operations they select.
  packages             Show software install and uninstall operations.
  artifacts            Show standalone download-only artifacts.
  windows              Show Windows setting operations; after status, show their defaults or profile state.
  explorer             Show Explorer-related settings; after status, show their defaults or profile state.
  security             Show security-related settings; after status, show their defaults or profile state.
  software             Show software operations and groups; after status, show package state.
  utilities            Show utility package operations.
  groups               Show multi-operation solutions; after status, show their member package state.
  settings             Show Windows settings and managed exclusions; after status, show defaults or profile state.
  (Status supports all views except profiles; use -Profile <file> to select a profile.)

In an interactive PowerShell session, press Tab after a command or value to
complete commands, operation and group IDs, profiles, and saved run IDs.

Examples:
  .\ride.ps1 list
  .\ride.ps1 list packages
  .\ride.ps1 download package.7zip
  .\ride.ps1 download package.notepadpp -Destination C:\RIDE\Artifacts
  .\ride.ps1 download artifact.sysmon-swift-config
  .\ride.ps1 list profiles
  .\ride.ps1 list windows
  .\ride.ps1 status explorer
  .\ride.ps1 status packages -Profile .\profiles\analyst-basics.psd1
  .\ride.ps1 install package.7zip -WhatIf
  .\ride.ps1 set windows.show-known-extensions Enabled -WhatIf
  .\ride.ps1 unset windows.script-host-policy -WhatIf
  .\ride.ps1 remove package.7zip -WhatIf
  .\ride.ps1 show <Tab>  Complete an operation or group ID.
  .\ride.ps1 show windows.show-known-extensions
  .\ride.ps1 plan -Profile .\profiles\analyst-basics.psd1
  .\ride.ps1 apply -Profile .\profiles\analyst-basics.psd1 -WhatIf
  .\ride.ps1 status
  .\ride.ps1 restore -RunId <run-id> -WhatIf
  .\ride.ps1 remove -Profile .\profiles\analyst-basics.psd1 -WhatIf
'@
  return
}

$ErrorActionPreference = 'Stop'
if (-not $Profile) { $Profile = Join-Path $PSScriptRoot 'profiles/default.psd1' }
Import-Module (Join-Path $PSScriptRoot 'modules/RIDE.Engine.psm1') -Force -ErrorAction Stop

switch ($Command) {
  'list' {
    Show-RideCatalog -View $(if ($Id) { $Id } else { 'all' })
  }
  'show' {
    if (-not $Id) { throw 'The show command requires an operation or group ID.' }
    Show-RideOperation -Id $Id
  }
  'plan' {
    $loadedProfile = Get-RideProfile -Path $Profile
    $plan = @(Get-RidePlan -Profile $loadedProfile)
    Show-RidePlan -Plan $plan
  }
  'apply' {
    $loadedProfile = Get-RideProfile -Path $Profile
    $plan = @(Get-RidePlan -Profile $loadedProfile)
    if ($WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan -WhatIf:$WhatIf -Confirm:$Confirm
  }
  'download' {
    if (-not $Id) { throw 'The download command requires a package or artifact ID.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The download command accepts one catalog ID and does not use -Profile.' }
    $downloadParameters = @{ Id = $Id; WhatIf = [bool]$WhatIf; Confirm = [bool]$Confirm }
    if ($Destination) { $downloadParameters.Destination = $Destination }
    Save-RidePackage @downloadParameters
  }
  'install' {
    if (-not $Id) { throw 'The install command requires a package ID.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The install command accepts one package ID and does not use -Profile.' }
    $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Install)
    if ($WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan -WhatIf:$WhatIf -Confirm:$Confirm
  }
  'set' {
    if (-not $Id) { throw 'The set command requires a setting ID.' }
    if (-not $State) { throw 'The set command requires -State. Press Tab after the setting ID to complete declared states.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The set command accepts one setting ID and does not use -Profile.' }
    $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $State)
    if ($WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan -WhatIf:$WhatIf -Confirm:$Confirm
  }
  'unset' {
    if (-not $Id) { throw 'The unset command requires a setting ID.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The unset command accepts one setting ID and does not use -Profile.' }
    $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Unset)
    if ($WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan -WhatIf:$WhatIf -Confirm:$Confirm
  }
  'status' {
    $statusView = if ($Id) { $Id } else { 'all' }
    if ($PSBoundParameters.ContainsKey('Profile')) {
      $loadedProfile = Get-RideProfile -Path $Profile
      Get-RideStatus -Profile $loadedProfile -View $statusView | Format-Table -AutoSize
    }
    else {
      Get-RideStatus -View $statusView | Format-Table -AutoSize
    }
  }
  'restore' {
    if (-not $RunId) { throw 'The restore command requires -RunId.' }
    Restore-RideRun -RunId $RunId -WhatIf:$WhatIf -Confirm:$Confirm
  }
  'remove' {
    if ($Id) {
      if ($PSBoundParameters.ContainsKey('Profile')) { throw 'Use either a single package ID or -Profile, not both.' }
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Remove)
    }
    else {
      $loadedProfile = Get-RideProfile -Path $Profile
      $plan = @(Get-RidePlan -Profile $loadedProfile -Action Remove)
    }
    if ($plan.Count -eq 0) { throw 'The selected profile contains no removable package operations.' }
    if ($WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan -WhatIf:$WhatIf -Confirm:$Confirm
  }
}
