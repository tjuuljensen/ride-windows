<#
.SYNOPSIS
  Run static validation checks for the RIDE Windows repository.
.DESCRIPTION
  Parses tracked PowerShell files, validates preset function names against the
  repository functions, checks local Markdown links, rejects stale planning
  note files, checks for likely mojibake, and reports duplicate function
  definitions.
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

function Get-RelativePath {
  param(
    [string] $RepoRoot,
    [string] $Path
  )

  $resolvedRoot = (Resolve-Path -Path $RepoRoot).Path.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $resolvedPath = (Resolve-Path -Path $Path).Path
  $relativePath = $resolvedPath.Substring($resolvedRoot.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $relativePath -replace "\\", "/"
}

function Test-LocalMarkdownLink {
  param(
    [string] $RepoRoot,
    [string] $MarkdownPath,
    [string] $LinkTarget
  )

  if ($LinkTarget -match "^[a-zA-Z][a-zA-Z0-9+.-]*:") {
    return
  }

  if ($LinkTarget.StartsWith("#") -or $LinkTarget.StartsWith("mailto:")) {
    return
  }

  $targetWithoutAnchor = ($LinkTarget -split "#", 2)[0]
  if (-not $targetWithoutAnchor) {
    return
  }

  if ($targetWithoutAnchor -match "^[\\/]") {
    $candidate = Join-Path -Path $RepoRoot -ChildPath $targetWithoutAnchor.TrimStart("\", "/")
  }
  else {
    $candidate = Join-Path -Path (Split-Path -Path $MarkdownPath -Parent) -ChildPath $targetWithoutAnchor
  }

  if (-not (Test-Path -Path $candidate)) {
    $relativePath = Get-RelativePath -RepoRoot $RepoRoot -Path $MarkdownPath
    Add-ValidationError ("{0}: local Markdown link target not found: {1}" -f $relativePath, $LinkTarget)
  }
}

function Test-MarkdownLinks {
  param(
    [string] $RepoRoot,
    [string[]] $MarkdownFiles
  )

  foreach ($file in $MarkdownFiles) {
    $content = Get-Content -Path $file
    foreach ($line in $content) {
      $matches = [regex]::Matches($line, '(?<!\!)\[[^\]]+\]\(([^)]+)\)')
      foreach ($match in $matches) {
        $target = $match.Groups[1].Value.Trim()
        Test-LocalMarkdownLink -RepoRoot $RepoRoot -MarkdownPath $file -LinkTarget $target
      }
    }
  }
}

function Test-StalePlanningNotes {
  param([string] $RepoRoot)

  $stalePlanningNotes = @(
    "RIDEadditions2025.md",
    "TO_DO.md"
  )

  foreach ($note in $stalePlanningNotes) {
    $path = Join-Path -Path $RepoRoot -ChildPath $note
    if (Test-Path -Path $path) {
      Add-ValidationError ("Stale planning note found: {0}. Merge content into TODO.md or docs/ROADMAP.md." -f $note)
    }
  }
}

function Test-Mojibake {
  param([string[]] $Files)

  $textFilePattern = "\.(cmd|ini|md|preset|ps1|psm1|txt|yml|yaml)$"
  $replacementChar = [char]0xFFFD
  $latinCapitalAWithTilde = [char]0x00C3
  $latinSmallAWithCircumflex = [char]0x00E2

  foreach ($file in ($Files | Where-Object { $_ -match $textFilePattern })) {
    $relativePath = Get-RelativePath -RepoRoot $Root -Path $file
    $lineNumber = 0
    foreach ($line in (Get-Content -Path $file)) {
      $lineNumber++
      if (($line.IndexOf($replacementChar) -ge 0) -or ($line.IndexOf($latinCapitalAWithTilde) -ge 0) -or ($line.IndexOf($latinSmallAWithCircumflex) -ge 0)) {
        Add-ValidationError ("{0}:{1}: possible mojibake found" -f $relativePath, $lineNumber)
      }
    }
  }
}

$trackedFiles = @(Get-TrackedFiles -RepoRoot $Root)
$powerShellFiles = @(
  $trackedFiles | Where-Object { $_ -match "\.ps(m)?1$" }
)
$markdownFiles = @(
  $trackedFiles | Where-Object { $_ -match "\.md$" }
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

Test-MarkdownLinks -RepoRoot $Root -MarkdownFiles $markdownFiles
Test-StalePlanningNotes -RepoRoot $Root
Test-Mojibake -Files $trackedFiles

if ($validationWarnings.Count -gt 0) {
  Write-Warning "Validation warnings:"
  $validationWarnings | ForEach-Object { Write-Warning $_ }
}

if ($validationErrors.Count -gt 0) {
  Write-Error ("Validation failed with {0} error(s):`n{1}" -f $validationErrors.Count, ($validationErrors -join "`n"))
  exit 1
}

Write-Output ("Validation passed. Checked {0} PowerShell file(s), {1} preset file(s), and {2} Markdown file(s)." -f $powerShellFiles.Count, $PresetPath.Count, $markdownFiles.Count)
