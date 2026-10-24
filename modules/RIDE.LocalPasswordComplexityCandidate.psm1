<#
.SYNOPSIS
  Build and inspect a one-setting password-complexity security template.
.DESCRIPTION
  Provides inert candidate preparation for the local PasswordComplexity security
  policy. It only builds a UTF-16LE security template or parses supplied secedit
  exports. It does not read Windows policy, invoke secedit, or change system state.
.EXAMPLE
  New-RideLocalPasswordComplexityTemplate -DesiredState Enabled
.INPUTS
  None.
.OUTPUTS
  PSCustomObject with a one-setting INF template and its UTF-16LE bytes.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  This unregistered candidate does not establish exact rollback, local/GPO
  precedence, or Windows target support. Native execution requires disposable
  Windows 11 and Windows Server 2025 acceptance.
  Version: 0.1.0.
  Changelog: 0.1.0: Build and parse the allow-listed PasswordComplexity field only.
.LINK
  ../docs/migrations/remaining-settings-plan.md
#>
$ErrorActionPreference = 'Stop'

function ConvertTo-RidePasswordComplexityTemplateBytes {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Content)

  $encoding = [System.Text.Encoding]::Unicode
  $body = $encoding.GetBytes($Content)
  $preamble = $encoding.GetPreamble()
  $bytes = [byte[]]::new($preamble.Length + $body.Length)
  [Array]::Copy($preamble, 0, $bytes, 0, $preamble.Length)
  [Array]::Copy($body, 0, $bytes, $preamble.Length, $body.Length)
  return ,$bytes
}

function New-RideLocalPasswordComplexityTemplate {
  <#
  .SYNOPSIS
    Build a one-setting Unicode INF template for password complexity.
  .PARAMETER DesiredState
    Enabled or Disabled. No unsetting or baseline state is inferred.
  .EXAMPLE
    New-RideLocalPasswordComplexityTemplate -DesiredState Disabled
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. The template contains only System Access/PasswordComplexity.
  .NOTES
    Template generation is inert. The candidate must not be registered or applied
    until exact policy ownership and rollback pass disposable Windows acceptance.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateSet('Enabled', 'Disabled')][string]$DesiredState)

  $value = if ($DesiredState -ceq 'Enabled') { 1 } else { 0 }
  $lines = @(
    '[Unicode]'
    'Unicode=yes'
    '[Version]'
    'signature="$CHICAGO$"'
    'Revision=1'
    '[System Access]'
    "PasswordComplexity = $value"
    ''
  )
  $content = [string]::Join("`r`n", $lines)
  $bytes = ConvertTo-RidePasswordComplexityTemplateBytes -Content $content
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try { $hash = $sha256.ComputeHash($bytes) } finally { $sha256.Dispose() }

  [pscustomobject]@{
    SchemaVersion = 1
    Kind = 'LocalPasswordComplexityTemplate'
    DesiredState = $DesiredState
    SettingName = 'PasswordComplexity'
    Value = $value
    Encoding = 'UTF-16LE'
    Content = $content
    Bytes = $bytes
    Sha256 = ([BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant())
    NativeExecutionSupported = $false
  }
}

function ConvertFrom-RideLocalPasswordComplexityPolicyExport {
  <#
  .SYNOPSIS
    Read the PasswordComplexity value from a supplied secedit INF export.
  .PARAMETER Content
    Supplied export text. This function performs no operating-system query.
  .PARAMETER Scope
    Local or Merged, identifying how the supplied export was obtained.
  .EXAMPLE
    ConvertFrom-RideLocalPasswordComplexityPolicyExport -Content $export -Scope Local
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject with Enabled, Disabled, NotDefined, or NotReported state.
  .NOTES
    Local means the caller supplied a non-merged export; Merged means a caller
    supplied an export that may combine local and domain policy. Neither label
    proves that a local value is effective under MDM or other management.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Content,
    [Parameter(Mandatory)][ValidateSet('Local', 'Merged')][string]$Scope
  )

  if ($Content.Length -gt 1048576) { throw 'Security-policy export exceeds the 1 MiB inspection limit.' }
  $insideSystemAccess = $false
  $systemAccessSections = 0
  $values = [System.Collections.Generic.List[int]]::new()

  foreach ($line in ($Content -split "`r?`n")) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith(';')) { continue }
    if ($trimmed -match '^\[([^\]]+)\]$') {
      $insideSystemAccess = $Matches[1] -ieq 'System Access'
      if ($insideSystemAccess) { $systemAccessSections++ }
      continue
    }
    if ($insideSystemAccess -and $trimmed -match '^PasswordComplexity\s*=') {
      if ($trimmed -notmatch '^PasswordComplexity\s*=\s*([01])\s*$') {
        throw 'PasswordComplexity export value must be exactly 0 or 1.'
      }
      $values.Add([int]$Matches[1])
    }
  }

  if ($systemAccessSections -ne 1) { throw 'Export must contain exactly one System Access section.' }
  if ($values.Count -gt 1) { throw 'Export contains duplicate PasswordComplexity values.' }

  $state = if ($values.Count -eq 1) {
    if ($values[0] -eq 1) { 'Enabled' } else { 'Disabled' }
  } elseif ($Scope -ceq 'Local') {
    'NotDefined'
  } else {
    'NotReported'
  }

  [pscustomobject]@{
    SchemaVersion = 1
    Kind = 'LocalPasswordComplexityObservation'
    Scope = $Scope
    State = $state
    Value = if ($values.Count -eq 1) { $values[0] } else { $null }
    IsEffective = $false
    SourceValidated = $false
  }
}

Export-ModuleMember -Function New-RideLocalPasswordComplexityTemplate, ConvertFrom-RideLocalPasswordComplexityPolicyExport
