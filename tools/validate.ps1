<#
.SYNOPSIS
  Run static validation checks for the RIDE Windows repository.
.DESCRIPTION
  Parses tracked PowerShell files, validates preset function names against the
  repository functions, and reports duplicate function definitions.
#>

[CmdletBinding()]
param(
  [string] $Root = "",
  [string[]] $PresetPath = @()
)

$ErrorActionPreference = "Stop"
$scriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $Root) {
  $Root = Resolve-Path (Join-Path $scriptRoot "..")
}

$validationErrors = New-Object System.Collections.Generic.List[string]
$validationWarnings = New-Object System.Collections.Generic.List[string]

function Add-ValidationError {
  param([string] $Message)
  $validationErrors.Add($Message)
}

function Add-ValidationWarning {
  param([string] $Message)
  $validationWarnings.Add($Message)
}

function Get-TrackedFiles {
  param([string] $RepoRoot)

  $gitFiles = & git -C $RepoRoot ls-files --cached --others --exclude-standard
  if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed in $RepoRoot"
  }

  $gitFiles | ForEach-Object { Join-Path $RepoRoot $_ }
}

function Get-PowerShellParseResult {
  param([string] $Path)

  $tokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $Path,
    [ref] $tokens,
    [ref] $parseErrors
  )

  [pscustomobject]@{
    Ast = $ast
    Errors = $parseErrors
  }
}

function Get-PresetEntries {
  param([string] $Path)

  Get-Content -Path $Path | ForEach-Object {
    ($_.Split("#")[0]).Trim()
  } | Where-Object { $_ }
}

$trackedFiles = @(Get-TrackedFiles -RepoRoot $Root)
$powerShellFiles = @(
  $trackedFiles | Where-Object { $_ -match "\.ps(m)?1$" }
)

$allFunctions = New-Object System.Collections.Generic.List[string]

foreach ($file in $powerShellFiles) {
  $relativePath = Resolve-Path -Path $file -Relative
  $parseResult = Get-PowerShellParseResult -Path $file

  foreach ($parseError in $parseResult.Errors) {
    Add-ValidationError ("{0}:{1}:{2}: {3}" -f $relativePath, $parseError.Extent.StartLineNumber, $parseError.Extent.StartColumnNumber, $parseError.Message)
  }

  $functions = $parseResult.Ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
  }, $true)

  $fileDuplicates = $functions | Group-Object Name | Where-Object { $_.Count -gt 1 } | Sort-Object Name
  foreach ($duplicate in $fileDuplicates) {
    Add-ValidationWarning ("{0}: duplicate function definition: {1} ({2} definitions)" -f $relativePath, $duplicate.Name, $duplicate.Count)
  }

  foreach ($function in $functions) {
    $allFunctions.Add($function.Name)
  }
}

if ($PresetPath.Count -eq 0) {
  $PresetPath = @(
    $trackedFiles | Where-Object { $_ -match "\.preset$" }
  )
}

$functionSet = @{}
foreach ($functionName in $allFunctions) {
  $functionSet[$functionName] = $true
}

foreach ($preset in $PresetPath) {
  $presetFullPath = Resolve-Path -Path $preset
  $relativePresetPath = Resolve-Path -Path $presetFullPath -Relative

  foreach ($entry in Get-PresetEntries -Path $presetFullPath) {
    if ($entry.StartsWith("!")) {
      $entry = $entry.Substring(1)
    }

    if (-not $functionSet.ContainsKey($entry)) {
      Add-ValidationError ("{0}: preset entry has no matching function: {1}" -f $relativePresetPath, $entry)
    }
  }
}

if ($validationWarnings.Count -gt 0) {
  Write-Warning "Validation warnings:"
  $validationWarnings | ForEach-Object { Write-Warning $_ }
}

if ($validationErrors.Count -gt 0) {
  Write-Error ("Validation failed with {0} error(s):`n{1}" -f $validationErrors.Count, ($validationErrors -join "`n"))
  exit 1
}

Write-Output ("Validation passed. Checked {0} PowerShell file(s) and {1} preset file(s)." -f $powerShellFiles.Count, $PresetPath.Count)
