<#
.SYNOPSIS
  Generate or check the operation reference from the catalog.

.DESCRIPTION
  Reads resolved catalog operations, target defaults, and ordered groups. Check compares the
  generated content without writing; otherwise writes UTF-8 with LF line endings. The default
  output is docs/OPERATIONS.md; external libraries require a separate explicit OutputPath.
  Explains experimental names and the distinction between feature references and value mappings.

.PARAMETER Check
  Compare generated text with the selected output file and throw when missing or stale; no write occurs.

.PARAMETER Root
  Repository root; defaults to the parent of the tools directory.

.PARAMETER Library
  Explicit local library manifest paths to include in the generated reference.

.PARAMETER OutputPath
  Literal output file path. Required with Library to preserve the built-in reference.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\tools\Export-RideCatalog.ps1 -Check

.EXAMPLE
  .\tools\Export-RideCatalog.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Progress and diagnostic messages.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: PowerShell data-file support and read access to the catalog; write access to docs
  for generation.
  File/environment inputs: catalog/operations.psd1 is authoritative; docs/OPERATIONS.md is
  generated.
  Recovery: Regenerate from the reviewed catalog. Check mode is read-only.
  Author: RIDE-Windows maintainers.
  Version: 0.15.2
  Changelog:
    0.15.2: Distinguish user-bin startup PATH from color-only metadata.
    0.15.1: Keep Store app registrations outside reversible setting presentation.
    0.15.0: Render bounded local maximum-age day choices and SAM authority.
    0.14.0: Render KeepCurrent registry components, firewall profiles and owned plan GUIDs.
    0.13.1: Qualify effective-policy inspection by handler after firewall integration.
    0.13.0: Render managed PowerShell profile states, runtimes and color presets.
    0.12.1: Keep setting evidence ordering identical on PowerShell 5.1/7 and omit empty reference links.
    0.12.0: Render setting scope, policy behavior, GUI effects and requirements.
    0.11.0: Export declared package variants and their recovery limits.
  - 0.10.0: Render an omitted custom license URL without an empty Markdown link.
  - 0.9.0: Render optional recovery instructions beside operation references.
  - 0.8.0: Export resolved libraries to an explicitly selected reference file.
  - 0.7.0: Render managed targets and literal states alongside their references.
  - 0.6.0: Render coordinated registry components and named state values.
  - 0.5.0: Render publisher license and optional terms references for downloads.
  - 0.4.0: Explain experimental mappings and the limits of feature references.
  - 0.3.0: Render image-dependent registry defaults as platform-defined.
  - 0.2.0: Generate documentation from the bounded data-only catalog reader;
    sort hashtable keys explicitly for consistent PowerShell 5.1/7 output.
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

#>


[CmdletBinding()]
param(
  [switch] $Check,
  [string] $Root = '',
  [string[]] $Library = @(),
  [string] $OutputPath = '',
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.15.2'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }
$ErrorActionPreference = 'Stop'

if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$catalogPath = Join-Path $Root 'catalog/operations.psd1'
$outputPath = Join-Path $Root 'docs/OPERATIONS.md'
if ($PSBoundParameters.ContainsKey('OutputPath')) {
  if ([string]::IsNullOrWhiteSpace($PSBoundParameters.OutputPath)) { throw 'OutputPath must be a file path.' }
  $outputPath = $PSBoundParameters.OutputPath
}
if ($Library.Count -and -not $PSBoundParameters.ContainsKey('OutputPath')) { throw 'Library references require -OutputPath; the built-in docs/OPERATIONS.md is preserved.' }
if ($Library.Count -and [IO.Path]::GetFullPath($outputPath) -eq [IO.Path]::GetFullPath((Join-Path $Root 'docs/OPERATIONS.md'))) { throw 'Library references must use a separate output file.' }
Import-Module (Join-Path $Root 'modules/RIDE.CatalogData.psm1') -Force
Import-Module (Join-Path $Root 'modules/RIDE.SettingPresentation.psm1') -ErrorAction Stop
$catalog = Import-RideCatalogData -Path $catalogPath
if ($Library.Count) {
  Import-Module (Join-Path $Root 'modules/RIDE.Libraries.psm1') -ErrorAction Stop
  $context = Get-RideCatalogContext -Root $Root -Library $Library
  $catalog = $context.Catalog
}
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# RIDE operation catalog')
$lines.Add('')
$lines.Add('Generated from `catalog/operations.psd1`. Edit catalog metadata, then run `tools/Export-RideCatalog.ps1`.')
if ($Library.Count) {
  $lines.Add('')
  $lines.Add('Selected external libraries: ' + (@($context.Libraries | ForEach-Object { '{0} {1}' -f $_.Id, $_.Version }) -join ', ') + '.')
}
$lines.Add('')
$lines.Add('Names marked experimental identify preferences whose current feature behavior remains unverified. A Microsoft reference may document the feature rather than the exact registry mapping; read the description before selecting it. Registry apply/restore acceptance does not establish a visible feature effect. See the [post-migration review](migrations/settings-post-migration-review.md) for combined legacy tweaks and unresolved channels.')
$lines.Add('')
$lines.Add('## Operations')
$lines.Add('')
$lines.Add('| ID | Name | Category | Scope | Admin | Actions | Supported targets | Rollback | Description | Reference |')
$lines.Add('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Sort-Object { $_.Category }, { $_.Name })) {
  $description = ($operation.Description -replace '\|', '\|')
  $targets = $operation.SupportedTargets -join ', '
  if ($operation.PendingAcceptance) { $targets = 'None (awaiting VM acceptance)' }
  $actions = $operation.Actions -join ', '
  $admin = if ($operation.RequiresAdmin) { 'Yes' } else { 'No' }
  $referenceUri = if ($operation.Kind -in @('Package', 'Artifact')) { $operation.ProductUri } else { $operation.DocumentationUri }
  $referenceLabel = if ($operation.Kind -in @('Package', 'Artifact')) { 'Product info' } else { 'Microsoft docs' }
  $reference = if ($referenceUri) { "[$referenceLabel]($referenceUri)" } else { '' }
  if ($operation.RecoveryUri) { $reference = (@($reference, "[Recovery instructions]($($operation.RecoveryUri))") | Where-Object { $_ }) -join '<br>' }
  $lines.Add("| $($operation.Id) | $($operation.Name) | $($operation.Category) | $($operation.Scope) | $admin | $actions | $targets | $($operation.Rollback) | $description | $reference |")
}
$lines.Add('')
$lines.Add('## Setting scope, behavior and requirements')
$lines.Add('')
$lines.Add('Each operation ID fixes its scope. Administrator rights do not determine who receives a setting, whether it is enforced, or whether its GUI is editable. User operations use the execution account; alternate-administrator execution does not select the interactive user. Presentation metadata is additive to catalog schema 1 and does not change states, handlers or saved-run recovery. Missing metadata remains unverified, including in external libraries.')
$lines.Add('')
$lines.Add('These are declared configuration effects. Effective-policy inspection is handler-specific: modern firewall candidates distinguish local and ActiveStore state and show source when available. Registry values alone do not establish effective policy or its source, and a declared platform default does not prove active enforcement. GUI and target acceptance are tracked separately in the post-migration review. Requirements describe the setting, rather than subscriptions needed only for optional cloud management.')
$lines.Add('')
$lines.Add('| ID | Applies to | Behavior | GUI effect / location | Requirements | Other supported choices | Evidence |')
$lines.Add('| --- | --- | --- | --- | --- | --- | --- |')
$settingsById = @{}
foreach ($entry in ($catalog.Operations | Where-Object { $_.Kind -notin @('Package', 'Artifact', 'StoreApp') })) { $settingsById[$entry.Id] = $entry }
$settingIds = [string[]]@($settingsById.Keys)
[Array]::Sort($settingIds, [StringComparer]::Ordinal)
foreach ($settingId in $settingIds) {
  $operation = $settingsById[$settingId]
  $presentation = Get-RideSettingPresentation -Operation $operation
  $gui = $presentation.GuiEffect
  if ($presentation.GuiPath) { $gui += '<br>' + $presentation.GuiPath }
  $evidence = @($operation.SettingPresentation.ReferenceUris | Where-Object { $_ } | ForEach-Object { "[Reference]($_)" }) -join '<br>'
  $cells = @($operation.Id, $presentation.AppliesTo, $presentation.Behavior, $gui, $presentation.Requirements, $presentation.OtherSupportedChoices, $evidence)
  $cells = @($cells | ForEach-Object { ([string]$_ -replace '\|', '\|') -replace '\r?\n', '<br>' })
  $lines.Add('| ' + ($cells -join ' | ') + ' |')
}
$lines.Add('')
$lines.Add('## Coordinated registry settings')
$lines.Add('')
$lines.Add('Each named state coordinates the values listed below. WindowsDefault removes the overrides; saved-run restore recovers the captured data, type and absence of each value. Platform-defined defaults are not inferred from the baseline.')
$lines.Add('')
$lines.Add('| Operation | Component | Registry value | Type |')
$lines.Add('| --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Where-Object Kind -eq 'RegistryValueSet' | Sort-Object { $_.Id })) {
  foreach ($member in $operation.RegistryValues) { $lines.Add("| $($operation.Id) | $($member.Key) | $($member.RegistryPath) / $($member.ValueName) | $($member.ValueType) |") }
}
$lines.Add('')
$lines.Add('| Operation | State | Component values |')
$lines.Add('| --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Where-Object Kind -eq 'RegistryValueSet' | Sort-Object { $_.Id })) {
  foreach ($state in ($operation.States.Keys | Sort-Object)) {
    $values = @($operation.RegistryValues | ForEach-Object { '{0}={1}' -f $_.Key, $(if ($null -eq $operation.States[$state][$_.Key]) { '<unset>' } elseif ($operation.States[$state][$_.Key] -is [hashtable] -and $operation.States[$state][$_.Key].KeepCurrent -eq $true) { '<keep current>' } else { $operation.States[$state][$_.Key] }) }) -join '; '
    $lines.Add(('| {0} | {1} | `{2}` |' -f $operation.Id, $state, $values))
  }
}
$lines.Add('')
$lines.Add('## Managed settings')
$lines.Add('')
$lines.Add('These settings use Windows management cmdlets, powercfg or NetBIOS/sound registry preferences. The NetBIOS and sound references document feature behavior, not their registry mappings. No baseline or universal clean-image value is assumed. Scheduled tasks must already exist. Adapter recovery captures coupled flags by adapter GUID. Power scheme selection does not create a missing scheme. Refer to the migration review for omitted legacy bundle behavior.')
$lines.Add('')
$lines.Add('| Operation | Managed target | States |')
$lines.Add('| --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Where-Object { $_.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme', 'FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge') } | Sort-Object { $_.Id })) {
  $target = switch ($operation.Kind) {
    LocalPasswordMaximumAge { 'Local SAM maximum age in seconds; domain controllers refused' }
    FirewallProfile { 'PersistentStore Enabled: ' + ($operation.FirewallProfiles -join ', ') }
    OwnedPowerPlan { 'Owned inactive copy of source ' + $operation.SourcePowerPlanGuid }
    ScheduledTask { $operation.TaskPath + $operation.TaskName }
    AdapterBinding { $operation.ComponentIds -join ', ' }
    PowerScheme { 'Active existing scheme GUID' }
    NetBios { 'Existing NetBT interface GUID / NetbiosOptions registry preference' }
    RemoteDesktopFirewall { 'PersistentStore / RemoteDesktop-* existing local rules' }
    SoundScheme { 'Current-user AppEvents selector and existing event mappings' }
    default { $operation.Preference }
  }
  $states = if ($operation.Kind -eq 'LocalPasswordMaximumAge') { 'NoExpiry=Never expires; Days{0}..Days{1}=explicit days' -f $operation.StateRange.Minimum, $operation.StateRange.Maximum } else { @($operation.States.Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, $operation.States[$_] }) -join '; ' }
  $lines.Add("| $($operation.Id) | $target | $states |")
}
$lines.Add('')
$lines.Add('## PowerShell profile settings')
$lines.Add('')
$lines.Add('Optional current-user ConsoleHost startup blocks; see [profile architecture and recovery](powershell-profiles.md). Default/unset remove only the managed block; Baseline resolves to Default. Saved-run restore recovers its captured predecessor. These are fixed reviewed RIDE presets, not edits to Terminal settings.json. show/status inspect configuration rather than observing another session. UserBinPath appends an existing user bin directory only at selected-shell startup, without changing persistent PATH or provisioning files. Pending entries cannot be applied until applicable disposable target and runtime acceptance is recorded.')
$lines.Add('')
$lines.Add('| Operation | Runtime | Setting | States | Normal Recommended palette | Elevated palette |')
$lines.Add('| --- | --- | --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Where-Object Kind -eq 'ProfileSetting' | Sort-Object { $_.Id })) {
  $states = ($operation.States.Keys | Sort-Object) -join ', '
  $normal = if ($operation.ProfileSetting -eq 'TerminalColors') { $operation.NormalColorScheme } else { 'Not applicable' }
  $admin = if ($operation.ProfileSetting -eq 'TerminalColors') { $operation.AdminColorScheme } else { 'Not applicable' }
  $lines.Add("| $($operation.Id) | $($operation.ProfileRuntime) | $($operation.ProfileSetting) | $states; Baseline alias | $normal | $admin |")
}
$lines.Add('')
$lines.Add('## Publisher licenses')
$lines.Add('')
$lines.Add('Packages and standalone artifacts are acquired directly from their declared publisher sources. These license labels are descriptive references, not complete SPDX expressions or individual/company approval. Local review records and export/import are described in [Package licensing](package-licensing.md).')
$lines.Add('')
$lines.Add('| ID | License summary | License / EULA | Additional terms |')
$lines.Add('| --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Where-Object { $_.Kind -in @('Package', 'Artifact') } | Sort-Object { $_.Id })) {
  $license = $operation.License -replace '\|', '\|'
  $terms = if ($operation.TermsUri) { "[Terms]($($operation.TermsUri))" } else { '' }
  $licenseLink = if ($operation.LicenseUri) { "[License]($($operation.LicenseUri))" } else { 'Not provided' }
  $lines.Add("| $($operation.Id) | $license | $licenseLink | $terms |")
}
$lines.Add('')
$lines.Add('## Package variants')
$lines.Add('')
$lines.Add('Flat package entries retain their installed default. Explicit variants never fall back. Portable packages own only manifest-listed files and preserve modified and user-created content.')
$lines.Add('')
$lines.Add('| Product ID | Default | Variant | Installer | Scope | Provider | Recovery | Supported targets |')
$lines.Add('| --- | --- | --- | --- | --- | --- | --- | --- |')
foreach ($package in $catalog.Operations | Where-Object { $_.Kind -eq 'Package' -and $_.Variants } | Sort-Object { $_.Id }) {
  foreach ($key in $package.Variants.Keys | Sort-Object) {
    $variant = $package.Clone()
    foreach ($field in $package.Variants[$key].Keys) { $variant[$field] = $package.Variants[$key][$field] }
    $targets = if ($variant.PendingAcceptance) { 'None (awaiting VM acceptance)' } else { $variant.SupportedTargets -join ', ' }
    $lines.Add("| $($package.Id) | $($package.DefaultVariant) | $key | $($variant.InstallerType) | $($variant.Scope) | $($variant.DownloadProvider) | $($variant.Rollback) | $targets |")
  }
}
$lines.Add('')
$lines.Add('## Registered uninstallers')
$lines.Add('')
$lines.Add('An explicit uninstaller format may differ from the installer format for a publisher wrapper. Removal still uses the registered command and declared quiet arguments.')
$lines.Add('')
foreach ($package in $catalog.Operations | Where-Object { $_.Kind -eq 'Package' -and $_.UninstallerType } | Sort-Object { $_.Id }) { $lines.Add('- `' + $package.Id + '` - installer: ' + $package.InstallerType + '; uninstaller: ' + $package.UninstallerType) }
$lines.Add('')
$lines.Add('## Desktop application applicability')
$lines.Add('')
$lines.Add('The following products require Windows Server Desktop Experience. Server Core is explicitly unavailable; target lifecycle evidence remains in the application ledger. Portable file deployment does not establish application or forensic behavior.')
$lines.Add('')
foreach ($package in $catalog.Operations | Where-Object { $_.Kind -eq 'Package' -and $_.RequiresDesktopExperience } | Sort-Object { $_.Id }) { $lines.Add('- `' + $package.Id + '` - ' + $package.Name) }
$lines.Add('')
$lines.Add('## Target defaults')
$lines.Add('')
$lines.Add('Literal defaults describe the registry data or managed presence expected on a clean target. Platform-defined means the literal default depends on the image or user profile; status does not assume that the value is absent. Effective defaults describe Windows behavior and any dependencies.')
$lines.Add('')
$lines.Add('| Operation | Target | Literal default | Effective default |')
$lines.Add('| --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Sort-Object { $_.Category }, { $_.Name })) {
  foreach ($target in $operation.SupportedTargets) {
    $defaults = $operation.TargetDefaults[$target]
    if ($operation.Kind -eq 'RegistryValue') {
      $literalDefault = if ($null -eq $defaults.DefaultValueExists) { '<platform-defined>' } elseif ($defaults.DefaultValueExists) { [string]$defaults.DefaultValue } else { '<unset>' }
    }
    else {
      $literalDefault = [string]$defaults.DefaultValue
    }
    $effectiveDefault = $defaults.EffectiveDefault -replace '\|', '\|'
    $lines.Add("| $($operation.Id) | $target | $literalDefault | $effectiveDefault |")
  }
}
$lines.Add('')
$lines.Add('## Groups')
$lines.Add('')
$lines.Add('| ID | Name | Category | Members, in apply order | Actions | Rollback | Description |')
$lines.Add('| --- | --- | --- | --- | --- | --- | --- |')
foreach ($group in ($catalog.Groups | Sort-Object { $_.Category }, { $_.Name })) {
  $members = $group.Members -join ', '
  $actions = $group.Actions -join ', '
  $lines.Add("| $($group.Id) | $($group.Name) | $($group.Category) | $members | $actions | $($group.Rollback) | $($group.Description) |")
}
$lines.Add('')
$content = ($lines -join "`n") + "`n"
if ($Check) {
  if (-not (Test-Path -LiteralPath $outputPath)) { throw "$outputPath is missing; run tools/Export-RideCatalog.ps1 with the same library/output selection." }
  $existing = [IO.File]::ReadAllText($outputPath)
  if ($existing -cne $content) { throw "$outputPath is stale; run tools/Export-RideCatalog.ps1 with the same library/output selection." }
  Write-Output 'Operation documentation is current.'
}
else {
  [IO.File]::WriteAllText($outputPath, $content, (New-Object Text.UTF8Encoding($false)))
  Write-Output "Generated $outputPath"
}
