<#
.SYNOPSIS
  Read the growing operation catalog as declarative data on PowerShell 5.1 and 7.
.DESCRIPTION
  Safely evaluates each operation/group hashtable separately to avoid the default
  whole-catalog AST complexity limit. Never executes a script or imports handlers.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Bounded, data-only catalog reader for larger migrations.
#>

$script:ModuleVersion = '0.1.0'

function Import-RideCatalogData {
  <#
  .SYNOPSIS
    Load a size-bounded RIDE catalog without executing expressions.
  .DESCRIPTION
    Requires a single root hashtable with SchemaVersion, Operations and Groups.
    Each collection entry uses PowerShell's SafeGetValue data evaluator.
  .PARAMETER Path
    Literal catalog file path. Maximum size is 2 MiB and 2000 total entries.
  .EXAMPLE
    Import-RideCatalogData -Path .\catalog\operations.psd1
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. Declarative catalog metadata.
  .NOTES
    Read-only; does not import the operational engine or inspect Windows state.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $Path)
  $file = Get-Item -LiteralPath $Path -ErrorAction Stop
  if ($file.Length -gt 2MB) { throw 'Operation catalog exceeds the 2 MiB size limit.' }
  $tokens = $null
  $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
  if ($errors.Count -gt 0 -or $ast.BeginBlock -or $ast.ProcessBlock -or $ast.ParamBlock -or $ast.EndBlock.Statements.Count -ne 1) { throw 'Invalid declarative catalog syntax.' }
  $statement = $ast.EndBlock.Statements[0]
  if ($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1) { throw 'Catalog must contain only a root hashtable.' }
  $root = $statement.PipelineElements[0].Expression
  if ($root -isnot [Management.Automation.Language.HashtableAst]) { throw 'Catalog must contain only a root hashtable.' }
  $result = @{}
  $count = 0
  foreach ($pair in $root.KeyValuePairs) {
    $key = [string]$pair.Item1.SafeGetValue()
    if ($key -notin @('SchemaVersion', 'Operations', 'Groups') -or $result.ContainsKey($key)) { throw "Unexpected or duplicate catalog field '$key'." }
    if ($pair.Item2 -isnot [Management.Automation.Language.PipelineAst] -or $pair.Item2.PipelineElements.Count -ne 1) { throw "Invalid catalog value for '$key'." }
    $value = $pair.Item2.PipelineElements[0].Expression
    if ($key -eq 'SchemaVersion') { $result[$key] = $value.SafeGetValue(); continue }
    if ($value -isnot [Management.Automation.Language.ArrayExpressionAst]) { throw "Catalog '$key' must be a literal array of hashtables." }
    $entries = foreach ($entryStatement in $value.SubExpression.Statements) {
      $count++
      if ($count -gt 2000) { throw 'Catalog exceeds the 2000 entry limit.' }
      if ($entryStatement -isnot [Management.Automation.Language.PipelineAst] -or $entryStatement.PipelineElements.Count -ne 1) { throw "Catalog '$key' contains a non-data statement." }
      $entry = $entryStatement.PipelineElements[0].Expression
      if ($entry -isnot [Management.Automation.Language.HashtableAst]) { throw "Catalog '$key' entries must be literal hashtables." }
      $entry.SafeGetValue()
    }
    $result[$key] = @($entries)
  }
  if ($result.Count -ne 3 -or $result.SchemaVersion -ne 1) { throw 'Catalog requires SchemaVersion 1, Operations and Groups.' }
  $result
}

Export-ModuleMember -Function Import-RideCatalogData
