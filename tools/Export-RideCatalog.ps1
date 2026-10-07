[CmdletBinding()]
param(
  [switch] $Check,
  [string] $Root = ''
)

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
$lines.Add('| ID | Name | Category | Scope | Admin | Actions | Supported targets | Rollback | Description |')
$lines.Add('| --- | --- | --- | --- | --- | --- | --- | --- | --- |')
foreach ($operation in ($catalog.Operations | Sort-Object Category, Name)) {
  $description = ($operation.Description -replace '\|', '\|')
  $targets = $operation.SupportedTargets -join ', '
  $actions = $operation.Actions -join ', '
  $admin = if ($operation.RequiresAdmin) { 'Yes' } else { 'No' }
  $lines.Add("| $($operation.Id) | $($operation.Name) | $($operation.Category) | $($operation.Scope) | $admin | $actions | $targets | $($operation.Rollback) | $description |")
}
$lines.Add('')
$lines.Add('## Target defaults')
$lines.Add('')
$lines.Add('Literal defaults describe the registry data or package presence expected on a clean target. Effective defaults describe the behavior Windows uses when those values are in effect.')
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
