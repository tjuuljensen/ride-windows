<#
.SYNOPSIS
  Plan, inspect, and manage declared Windows settings and packages.

.DESCRIPTION
  Loads catalog metadata and dispatches list, search, show, plan, apply, download, install,
  set, unset, status, restore, or remove. Command defaults to list. Discovery and
  completion are read-only. State-changing engine commands use ShouldProcess and
  save pre-change state for settings and package presence. Package restoration
  can reinstall the current upstream release; exact prior package versions are
  not guaranteed. Downloads retain artifacts and observation metadata.
  Setting details, previews and status keep scope, policy behavior, GUI effects
  and requirements visible. Missing semantic evidence is reported as unverified.

.PARAMETER Command
  Declared command; defaults to list. Press Tab to discover the supported command set.

.PARAMETER Id
  Operation/package/group ID, or a view for list/status. Direct actions require an appropriate
  operation ID. For search, the second positional argument is the literal query.

.PARAMETER Query
  Named literal search query, instead of the second positional argument. Matching is
  case-insensitive; quote phrases and paths. Press Tab for catalog ID suggestions.

.PARAMETER Field
  Search only these metadata fields; defaults to all declared search fields. Multiple
  fields use OR matching. Press Tab to discover fields.

.PARAMETER View
  Search within a named catalog view or category; defaults to all. Profiles are excluded.
  Press Tab to discover views and catalog categories.

.PARAMETER Profile
  Profile data-file path. Profile commands default to profiles/default.psd1; status compares a
  profile only when explicitly supplied.

.PARAMETER State
  Catalog state for set, also accepted positionally after the ID. Press Tab for declared states.
  PowerShell profile colors offer Recommended, AdminBlue, Default and the Baseline alias.
  Default and unset remove only the managed profile block; restore uses captured prior content.
  Owned power-plan candidates offer Create only; creation never selects a plan.
  Local password-age candidates offer NoExpiry and Days1 through Days999.

.PARAMETER RunId
  32-character hexadecimal saved run ID for restore; press Tab to discover saved manifests.

.PARAMETER Library
  Explicit local ride-library.psd1 manifest paths. Press Tab for filesystem paths.
  External IDs, states, categories and declared profiles complete from selected libraries.

.PARAMETER Destination
  Directory for download artifacts; defaults to the user state root Artifacts directory.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Variant
  Catalog-declared package variant for install, remove, download or show. Press Tab
  after -Variant to complete choices for the selected package ID.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\ride.ps1 -Help

.EXAMPLE
  .\ride.ps1 list packages

.EXAMPLE
  .\ride.ps1 search 'File Explorer' -Field Name,Description -View settings

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
  Version: 0.10.4
  Changelog:
    - 0.10.4: Complete bounded explicit local password-age day states from the catalog.
    - 0.10.3: Complete explicit owned power-plan creation states from the catalog.
    - 0.10.2: Complete catalog-declared local firewall profile states.
    - 0.10.1: Complete catalog-declared Windows service states, including startup-only choices.
    0.10.0: Complete managed PowerShell profile color states and baseline removal.
    0.9.3: Refresh library metadata modules in long-lived PowerShell sessions.
    0.9.2: Forward effective WhatIf and explicitly bound Confirm to engine commands.
    0.9.1: Explain Thunderbird current-user execution requirements in help.
    0.9.0: Keep setting scope, GUI behavior and requirements visible in status and preview.
    0.8.0: Select and complete package variants for install, remove, download and show.
  - 0.7.0: Select local metadata libraries for execution, search and completion.
  - 0.6.0: Complete the additional managed-setting IDs and explicit states from the catalog.
  - 0.5.0: Add data-only literal search, field/view filters and completion.
  - 0.4.0: Complete named states for coordinated registry settings.
  - 0.3.0: Add optional desktop Shell folder settings and state completion.
  - 0.2.0: Use bounded data-only catalog loading for execution and read-only completion.
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

.LINK
  README.md

.LINK
  docs/catalog-search.md

.LINK
  docs/custom-libraries.md

.LINK
  docs/models/script-repository-model.md

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [Parameter(Position = 0)]
  [ValidateSet('list', 'search', 'show', 'plan', 'apply', 'download', 'install', 'set', 'unset', 'status', 'restore', 'remove')]
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
      Import-Module (Join-Path (Split-Path -Parent $catalogPath) '../modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      Import-Module (Join-Path (Split-Path -Parent $catalogPath) '../modules/RIDE.Libraries.psm1') -Force -ErrorAction Stop
      $catalog = (Get-RideCatalogContext -Root (Split-Path -Parent (Split-Path -Parent $catalogPath)) -Library $fakeBoundParameters.Library).Catalog
      $ids = @($catalog.Operations + $catalog.Groups | ForEach-Object { $_.Id } | Sort-Object -Unique)
      Import-Module (Join-Path (Split-Path -Parent $catalogPath) '../modules/RIDE.Discovery.psm1') -ErrorAction Stop
      $listViews = @(Get-RideCatalogViews -Catalog $catalog -IncludeProfiles)
      $isListCommand = $fakeBoundParameters.Command -eq 'list' -or
        ($commandAst.CommandElements.Count -gt 1 -and $commandAst.CommandElements[1].Value -eq 'list')
      if ($isListCommand) { $ids += $listViews }
      $isStatusCommand = $fakeBoundParameters.Command -eq 'status' -or
        ($commandAst.CommandElements.Count -gt 1 -and $commandAst.CommandElements[1].Value -eq 'status')
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
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source }
      $repoRoot = Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path
      Import-Module (Join-Path $repoRoot 'modules/RIDE.Libraries.psm1') -Force -ErrorAction Stop
      $catalog = (Get-RideCatalogContext -Root $repoRoot -Library $fakeBoundParameters.Library).Catalog
      $entry = $catalog.Operations | Where-Object { $_.Id -eq $fakeBoundParameters.Id -and $_.Kind -eq 'Package' } | Select-Object -First 1
      if (-not $entry) { return }
      $keys = if ($entry.Variants) { @($entry.Variants.Keys) } else { @('installed') }
      foreach ($candidate in $keys | Sort-Object -Unique) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) { [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate) }
      }
    } catch { }
  })]
  [string] $Variant = '',

  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $repoRoot = Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path
      Import-Module (Join-Path $repoRoot 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      Import-Module (Join-Path $repoRoot 'modules/RIDE.Libraries.psm1') -Force -ErrorAction Stop
      $catalog = (Get-RideCatalogContext -Root $repoRoot -Library $fakeBoundParameters.Library).Catalog
      foreach ($candidate in @($catalog.Operations.Id) + @($catalog.Groups.Id) | Sort-Object -Unique) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
          [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
        }
      }
    }
    catch { }
  })]
  [string] $Query = '',
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $repoRoot = Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path
      Import-Module (Join-Path $repoRoot 'modules/RIDE.Discovery.psm1') -ErrorAction Stop
      foreach ($candidate in Get-RideSearchFields) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase) -and $candidate -notin $fakeBoundParameters.Field) {
          [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
        }
      }
    }
    catch { }
  })]
  [string[]] $Field = @(),
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $repoRoot = Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path
      Import-Module (Join-Path $repoRoot 'modules/RIDE.Discovery.psm1') -ErrorAction Stop
      Import-Module (Join-Path $repoRoot 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      Import-Module (Join-Path $repoRoot 'modules/RIDE.Libraries.psm1') -Force -ErrorAction Stop
      $catalog = (Get-RideCatalogContext -Root $repoRoot -Library $fakeBoundParameters.Library).Catalog
      foreach ($candidate in Get-RideCatalogViews -Catalog $catalog) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) {
          [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate)
        }
      }
    }
    catch { }
  })]
  [string] $View = 'all',

  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $repoRoot = Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path
      $prefix = [string]$wordToComplete
      Import-Module (Join-Path $repoRoot 'modules/RIDE.Libraries.psm1') -Force -ErrorAction Stop
      $context = Get-RideCatalogContext -Root $repoRoot -Library $fakeBoundParameters.Library
      foreach ($profileFile in $context.ProfileFiles) {
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
      if ($fakeBoundParameters.Command -eq 'search') { return }
      if (-not $fakeBoundParameters.ContainsKey('Id')) { return }
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        $scriptPath = (Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Source
      }
      $catalogPath = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path) 'catalog/operations.psd1'
      Import-Module (Join-Path (Split-Path -Parent $catalogPath) '../modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      Import-Module (Join-Path (Split-Path -Parent $catalogPath) '../modules/RIDE.Libraries.psm1') -Force -ErrorAction Stop
      $catalog = (Get-RideCatalogContext -Root (Split-Path -Parent (Split-Path -Parent $catalogPath)) -Library $fakeBoundParameters.Library).Catalog
      $operation = $catalog.Operations | Where-Object { $_.Id -eq $fakeBoundParameters.Id } | Select-Object -First 1
      if ($operation.Kind -in @('RegistryValue', 'RegistryValueSet', 'RegistryKeySet', 'WindowsService', 'PowerSetting', 'ShellFolder', 'ProfileSetting', 'ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge')) {
        $states = @($operation.States.Keys)
        if ($operation.Kind -in @('RegistryValue', 'RegistryValueSet', 'ShellFolder', 'ProfileSetting') -and 'Baseline' -notin $states) { $states += 'Baseline' }
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
  [string[]] $Library = @(),
  [string] $Destination = '',
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.10.4'
if ($Version) { Write-Output $script:ScriptVersion; return }

if ($Help) {
  @'
RIDE-Windows - declarative Windows setup and maintenance

Usage:
  .\ride.ps1 <command> [options]

Commands:
  list [view]          List catalog objects; filter with a list view below.
  search <query>       Search catalog metadata using a case-insensitive literal phrase.
  show <id>            Show metadata and current value; settings include the baseline value.
  plan                 Show current values beside the profile's desired values.
  apply                Apply the profile and record prior state.
  download <catalog-id> Download a package or standalone artifact without applying it.
  install <package-id> Install one catalog package and record its prior state.
  set <setting-id>     Set one catalog setting to a declared state; use -State <state>.
  unset <setting-id>   Remove one setting value when its catalog declares an unset state.
                      Profile colors: Recommended, AdminBlue, Default or Baseline.
                      Default/unset remove the RIDE block; restore recovers prior content.
                      Pending profile operations await disposable target/visual acceptance.
  status [view]         Show default or profile status, optionally filtered.
  restore -RunId <id>  Restore values recorded before a prior run.
  remove [package-id]  Uninstall one package or packages selected by the profile.

Options:
  -Library <files>     Explicit local library manifests; Tab completes filesystem paths.
  -Profile <file>      Select a profile (default: profiles/default.psd1).
  -Id <id|view>        ID for show, or a view after list/status.
  -Query <phrase>      Named search query instead of a positional phrase.
  -Field <fields>      Narrow search fields; press Tab to discover available fields.
  -View <view>         Narrow search to a list view/category (except profiles).
  -State <state>       Declared state for set; press Tab to complete available states.
                       Service states include catalog-declared startup-only and combined presets.
                       Pending firewall profile controls complete On/Off but await VM acceptance.
  -RunId <id>          Run ID required by restore.
  -Destination <path>  Retain a downloaded artifact under this directory.
  -WhatIf              Preview apply, download, install, set, unset, remove or restore.
  -Confirm             Ask before each supported change.
  -Help                Display this help.
  -Variant <name>      Select a declared package edition; Tab completes its variants.
  -Version             Print the script version without loading the engine.

Package scope follows its catalog selection. Thunderbird's user selection requires
non-elevated PowerShell for install, removal and restore; preview remains read-only.

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
Put -Library before the value being completed to include its external metadata.
Search also completes field names, views/categories, and catalog ID suggestions.
Owned power-plan candidates complete Create; normal apply remains blocked until
target acceptance. Creation and existing-plan selection are separate operations.
Local maximum password age completes NoExpiry and Days1..Days999 from catalog
range metadata; candidates remain blocked pending target acceptance.
Search treats backslashes, wildcard and regex punctuation literally. Quote phrases
and paths; backslashes need no doubling. Missing/blank queries are errors; no
matches returns an empty collection. Multiple -Field values use OR matching.

Examples:
  .\ride.ps1 list
  .\ride.ps1 list packages
  .\ride.ps1 list -Library .\examples\library\ride-library.psd1
  .\ride.ps1 search desktop-folder
  .\ride.ps1 search 'File Explorer' -Field Name,Description
  .\ride.ps1 search 'Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\'
  .\ride.ps1 search -Query ThisPCPolicy -Field ValueName -View explorer
  .\ride.ps1 download package.7zip
  .\ride.ps1 download package.notepadpp -Destination C:\RIDE\Artifacts
  .\ride.ps1 download artifact.sysmon-swift-config
  .\ride.ps1 list profiles
  .\ride.ps1 list windows
  .\ride.ps1 status explorer
  .\ride.ps1 status packages -Profile .\profiles\analyst-basics.psd1
  .\ride.ps1 install package.7zip -WhatIf
  .\ride.ps1 set windows.show-known-extensions Enabled -WhatIf
  .\ride.ps1 set windows.god-mode-shortcut Present -WhatIf
  .\ride.ps1 unset windows.god-mode-shortcut -WhatIf
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
$shouldProcessParameters = @{ WhatIf = [bool]$WhatIfPreference }
if ($PSBoundParameters.ContainsKey('Confirm')) { $shouldProcessParameters.Confirm = $PSBoundParameters['Confirm'] }
if ($Command -eq 'search') {
  foreach ($parameter in @('Profile', 'State', 'RunId', 'Destination', 'WhatIf', 'Confirm')) {
    if ($PSBoundParameters.ContainsKey($parameter)) { throw "The search command does not accept -$parameter." }
  }
  if ($PSBoundParameters.ContainsKey('Query') -and $PSBoundParameters.ContainsKey('Id')) {
    throw 'Use either a positional search query or -Query, not both.'
  }
  $searchQuery = if ($PSBoundParameters.ContainsKey('Query')) { $Query } else { $Id }
  if ([string]::IsNullOrWhiteSpace($searchQuery)) { throw 'The search command requires a nonblank query. Quote phrases containing spaces.' }
  Import-Module (Join-Path $PSScriptRoot 'modules/RIDE.Discovery.psm1') -ErrorAction Stop
  Import-Module (Join-Path $PSScriptRoot 'modules/RIDE.Libraries.psm1') -Force -ErrorAction Stop
  $context = Get-RideCatalogContext -Root $PSScriptRoot -Library $Library
  $searchParameters = @{ Query = $searchQuery; View = $View; Catalog = $context.Catalog }
  if ($PSBoundParameters.ContainsKey('Field')) { $searchParameters.Field = $Field }
  Find-RideCatalog @searchParameters
  return
}
foreach ($parameter in @('Query', 'Field', 'View')) {
  if ($PSBoundParameters.ContainsKey($parameter)) { throw "-$parameter is only supported by the search command." }
}
if ($Variant -and $Command -notin @('install', 'remove', 'download', 'show')) { throw '-Variant is supported by install, remove, download and show.' }
if ($Variant -and -not $Id) { throw '-Variant requires a package ID.' }
if (-not $Profile) { $Profile = Join-Path $PSScriptRoot 'profiles/default.psd1' }
Import-Module (Join-Path $PSScriptRoot 'modules/RIDE.Engine.psm1') -Force -ErrorAction Stop
Set-RideLibraryContext -Library $Library

switch ($Command) {
  'list' {
    Show-RideCatalog -View $(if ($Id) { $Id } else { 'all' })
  }
  'show' {
    if (-not $Id) { throw 'The show command requires an operation or group ID.' }
    Show-RideOperation -Id $Id -Variant $Variant
  }
  'plan' {
    $loadedProfile = Get-RideProfile -Path $Profile
    $plan = @(Get-RidePlan -Profile $loadedProfile)
    Show-RidePlan -Plan $plan
  }
  'apply' {
    $loadedProfile = Get-RideProfile -Path $Profile
    $plan = @(Get-RidePlan -Profile $loadedProfile)
    if ($shouldProcessParameters.WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan @shouldProcessParameters
  }
  'download' {
    if (-not $Id) { throw 'The download command requires a package or artifact ID.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The download command accepts one catalog ID and does not use -Profile.' }
    $downloadParameters = @{ Id = $Id; Variant = $Variant } + $shouldProcessParameters
    if ($Destination) { $downloadParameters.Destination = $Destination }
    Save-RidePackage @downloadParameters
  }
  'install' {
    if (-not $Id) { throw 'The install command requires a package ID.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The install command accepts one package ID and does not use -Profile.' }
    $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Install -Variant $Variant)
    if ($shouldProcessParameters.WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan @shouldProcessParameters
  }
  'set' {
    if (-not $Id) { throw 'The set command requires a setting ID.' }
    if (-not $State) { throw 'The set command requires -State. Press Tab after the setting ID to complete declared states.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The set command accepts one setting ID and does not use -Profile.' }
    $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Set -State $State)
    if ($shouldProcessParameters.WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan @shouldProcessParameters
  }
  'unset' {
    if (-not $Id) { throw 'The unset command requires a setting ID.' }
    if ($PSBoundParameters.ContainsKey('Profile')) { throw 'The unset command accepts one setting ID and does not use -Profile.' }
    $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Unset)
    if ($shouldProcessParameters.WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan @shouldProcessParameters
  }
  'status' {
    $statusView = if ($Id) { $Id } else { 'all' }
    if ($PSBoundParameters.ContainsKey('Profile')) {
      $loadedProfile = Get-RideProfile -Path $Profile
      $statusRows = Get-RideStatus -Profile $loadedProfile -View $statusView
    }
    else {
      $statusRows = Get-RideStatus -View $statusView
    }
    if ($statusView -match '^(?i:packages?)$') { $statusRows | Format-Table -AutoSize }
    else { $statusRows | Format-List }
  }
  'restore' {
    if (-not $RunId) { throw 'The restore command requires -RunId.' }
    Restore-RideRun -RunId $RunId @shouldProcessParameters
  }
  'remove' {
    if ($Id) {
      if ($PSBoundParameters.ContainsKey('Profile')) { throw 'Use either a single package ID or -Profile, not both.' }
      $plan = @(Get-RideSingleOperationPlan -Id $Id -Action Remove -Variant $Variant)
    }
    else {
      $loadedProfile = Get-RideProfile -Path $Profile
      $plan = @(Get-RidePlan -Profile $loadedProfile -Action Remove)
    }
    if ($plan.Count -eq 0) { throw 'The selected profile contains no removable package operations.' }
    if ($shouldProcessParameters.WhatIf) { Show-RidePlan -Plan $plan }
    Invoke-RidePlan -Plan $plan @shouldProcessParameters
  }
}
