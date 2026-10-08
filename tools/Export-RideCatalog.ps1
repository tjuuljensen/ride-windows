<#
.SYNOPSIS
  Generate or check the operation reference from the catalog.

.DESCRIPTION
  Reads catalog operations, target defaults, and ordered groups. Check compares the generated
  content without writing; otherwise writes docs/OPERATIONS.md as UTF-8 with LF line endings.

.PARAMETER Check
  Compare generated text with docs/OPERATIONS.md and throw when missing or stale; no write occurs.

.PARAMETER Root
  Repository root; defaults to the parent of the tools directory.

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
  Error-handling exception: Existing read policy, explicit Check-mode throws, and throwing .NET
  writes are retained.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

#>


[CmdletBinding()]
param(
  [switch] $Check,
  [string] $Root = '',
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
$catalogPath = Join-Path $Root 'catalog/operations.psd1'
$outputPath = Join-Path $Root 'docs/OPERATIONS.md'
$catalog = Import-PowerShellDataFile -Path $catalogPath
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# RIDE operation catalog')
$lines.Add('')
$lines.Add('Generated from `catalog/operations.psd1`. Edit catalog metadata, then run `tools/Export-RideCatalog.ps1`.')
$lines.Add('')
$lines.Add('## Operations')
$lines.Add('')
$lines.Add('| ID | Name | Category | Scope | Admin | Actions | Supported targets | Rollback | Description | Reference |')
$lines.Add('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Sort-Object Category, Name)) {
  $description = ($operation.Description -replace '\|', '\|')
  $targets = $operation.SupportedTargets -join ', '
  $actions = $operation.Actions -join ', '
  $admin = if ($operation.RequiresAdmin) { 'Yes' } else { 'No' }
  $referenceUri = if ($operation.Kind -in @('Package', 'Artifact')) { $operation.ProductUri } else { $operation.DocumentationUri }
  $referenceLabel = if ($operation.Kind -in @('Package', 'Artifact')) { 'Product info' } else { 'Microsoft docs' }
  $reference = if ($referenceUri) { "[$referenceLabel]($referenceUri)" } else { '' }
  $lines.Add("| $($operation.Id) | $($operation.Name) | $($operation.Category) | $($operation.Scope) | $admin | $actions | $targets | $($operation.Rollback) | $description | $reference |")
}
$lines.Add('')
$lines.Add('## Target defaults')
$lines.Add('')
$lines.Add('Literal defaults describe the registry data or managed presence expected on a clean target. Effective defaults describe the behavior Windows uses when those values are in effect.')
$lines.Add('')
$lines.Add('| Operation | Target | Literal default | Effective default |')
$lines.Add('| --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Sort-Object Category, Name)) {
  foreach ($target in $operation.SupportedTargets) {
    $defaults = $operation.TargetDefaults[$target]
    if ($operation.Kind -eq 'RegistryValue') {
      $literalDefault = if ($defaults.DefaultValueExists) { [string]$defaults.DefaultValue } else { '<unset>' }
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
foreach ($group in ($catalog.Groups | Sort-Object Category, Name)) {
  $members = $group.Members -join ', '
  $actions = $group.Actions -join ', '
  $lines.Add("| $($group.Id) | $($group.Name) | $($group.Category) | $members | $actions | $($group.Rollback) | $($group.Description) |")
}
$lines.Add('')
$content = ($lines -join "`n") + "`n"
if ($Check) {
  if (-not (Test-Path -LiteralPath $outputPath)) { throw 'docs/OPERATIONS.md is missing; run tools/Export-RideCatalog.ps1.' }
  $existing = [IO.File]::ReadAllText($outputPath)
  if ($existing -cne $content) { throw 'docs/OPERATIONS.md is stale; run tools/Export-RideCatalog.ps1.' }
  Write-Output 'Operation documentation is current.'
}
else {
  [IO.File]::WriteAllText($outputPath, $content, (New-Object Text.UTF8Encoding($false)))
  Write-Output "Generated $outputPath"
}
