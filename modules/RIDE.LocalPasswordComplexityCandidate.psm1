<#
.SYNOPSIS
  Build and inspect a one-setting password-complexity security template.
.DESCRIPTION
  Provides candidate preparation and read-only observation for the local
  PasswordComplexity security policy. It builds a UTF-16LE security template,
  parses supplied exports, or explicitly invokes secedit /export. It never applies
  or configures security policy.
.EXAMPLE
  New-RideLocalPasswordComplexityTemplate -DesiredState Enabled
.INPUTS
  None.
.OUTPUTS
  PSCustomObject with a one-setting INF template and its UTF-16LE bytes.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  This unregistered candidate does not establish exact rollback, local/GPO
  precedence, or Windows target support. The read-only export path requires
  disposable Windows 11 and Windows Server 2025 validation.
  Version: 0.4.0.
  Changelog:
    0.4.0: Add inert native Secedit template validation; still no apply path.
    0.3.0: Add scoped read-only local/merged secedit export observation; still no apply path.
    0.2.0: Prepare conflict-checked recovery templates for explicit local values without authorizing mutation.
    0.1.0: Build and parse the allow-listed PasswordComplexity field only.
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

function New-RideLocalPasswordComplexityRecoveryTemplate {
  <#
  .SYNOPSIS
    Prepare an explicit-value recovery template after checking supplied state.
  .PARAMETER PriorObservation
    Local export observation captured before the proposed change.
  .PARAMETER CurrentObservation
    Fresh local export observation supplied by the caller.
  .PARAMETER ExpectedAppliedState
    Explicit state the candidate operation is expected to have applied.
  .EXAMPLE
    New-RideLocalPasswordComplexityRecoveryTemplate -PriorObservation $before `
      -CurrentObservation $now -ExpectedAppliedState Enabled
  .INPUTS
    Supplied observation objects only.
  .OUTPUTS
    PSCustomObject containing a recovery template or a no-op result.
  .NOTES
    This inert preparation supports only explicit prior values. It refuses
    NotDefined and NotReported because exact removal/recovery semantics are not
    established. It does not validate export provenance or authorize secedit.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNull()][pscustomobject]$PriorObservation,
    [Parameter(Mandatory)][ValidateNotNull()][pscustomobject]$CurrentObservation,
    [Parameter(Mandatory)][ValidateSet('Enabled', 'Disabled')][string]$ExpectedAppliedState
  )

  foreach ($observation in @($PriorObservation, $CurrentObservation)) {
    if ($observation.SchemaVersion -ne 1 -or
        $observation.Kind -cne 'LocalPasswordComplexityObservation' -or
        $observation.Scope -cne 'Local' -or
        $observation.IsEffective -ne $false -or
        $observation.SourceValidated -ne $false) {
      throw 'Recovery requires version-1, supplied, non-effective Local observations.'
    }
    if ($observation.State -notin @('Enabled', 'Disabled') -or
        $observation.Value -notin @(0, 1) -or
        [int]$observation.Value -ne $(if ($observation.State -ceq 'Enabled') { 1 } else { 0 })) {
      throw 'Recovery requires an explicit, internally consistent local policy value.'
    }
  }

  if ($CurrentObservation.State -cne $ExpectedAppliedState) {
    throw 'Current local PasswordComplexity state differs from the expected applied state.'
  }

  $isNoOp = $PriorObservation.State -ceq $ExpectedAppliedState
  [pscustomobject]@{
    SchemaVersion = 1
    Kind = 'LocalPasswordComplexityRecoveryPreparation'
    PriorState = $PriorObservation.State
    ExpectedCurrentState = $ExpectedAppliedState
    IsNoOp = $isNoOp
    Template = if ($isNoOp) { $null } else { New-RideLocalPasswordComplexityTemplate -DesiredState $PriorObservation.State }
    ExactRecoveryVerified = $false
    ReadyForMutation = $false
  }
}

function New-RideLocalPasswordComplexityWorkspace {
  [CmdletBinding()]
  param()

  $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  if (-not [IO.Directory]::Exists($tempRoot)) { throw 'The process temporary directory is unavailable.' }
  $driveRoot = [IO.Path]::GetPathRoot($tempRoot)
  if ($driveRoot -notmatch '^[A-Za-z]:\\$') { throw 'The process temporary directory must be on a local drive.' }
  $drive = [IO.DriveInfo]::new($driveRoot)
  if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'The process temporary directory must be on a fixed local drive.' }

  $cursor = [IO.DirectoryInfo]::new($tempRoot)
  $reachedDriveRoot = $false
  while ($null -ne $cursor) {
    if (-not $cursor.Exists -or ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'The process temporary path contains a missing or reparse-point directory.'
    }
    if ($cursor.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) -ieq $driveRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)) {
      $reachedDriveRoot = $true
      break
    }
    $cursor = $cursor.Parent
  }
  if (-not $reachedDriveRoot) { throw 'The process temporary path does not resolve beneath its local drive root.' }

  $name = 'Ride-PasswordComplexity-' + [guid]::NewGuid().ToString('N')
  $workspace = Join-Path $tempRoot $name
  [void][IO.Directory]::CreateDirectory($workspace)
  $resolved = [IO.Path]::GetFullPath($workspace)
  $parent = [IO.Path]::GetDirectoryName($resolved).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  if ($parent -ine $tempRoot -or [IO.Path]::GetFileName($resolved) -cnotmatch '^Ride-PasswordComplexity-[0-9a-f]{32}$') {
    throw 'The Secedit workspace is outside the process temporary directory.'
  }
  $item = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
  if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The Secedit workspace is not a plain directory.'
  }
  return $resolved
}

function New-RideLocalPasswordComplexityExportArguments {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Local', 'Merged')][string]$Scope,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ConfigurationPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LogPath
  )

  $arguments = [System.Collections.Generic.List[string]]::new()
  $arguments.Add('/export')
  if ($Scope -ceq 'Merged') { $arguments.Add('/mergedpolicy') }
  $arguments.Add('/cfg')
  $arguments.Add($ConfigurationPath)
  $arguments.Add('/areas')
  $arguments.Add('securitypolicy')
  $arguments.Add('/log')
  $arguments.Add($LogPath)
  return ,$arguments.ToArray()
}

function Invoke-RideLocalPasswordComplexityExportProcess {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Local', 'Merged')][string]$Scope,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ConfigurationPath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LogPath
  )

  $command = Get-Command -Name 'secedit.exe' -CommandType Application -ErrorAction Stop
  $arguments = New-RideLocalPasswordComplexityExportArguments -Scope $Scope -ConfigurationPath $ConfigurationPath -LogPath $LogPath
  $null = & $command.Source @arguments 2>&1
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) { throw "secedit /export failed with exit code $exitCode." }
}

function New-RideLocalPasswordComplexityValidationArguments {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ConfigurationPath)

  return ,@('/validate', $ConfigurationPath)
}

function Invoke-RideLocalPasswordComplexityTemplateValidationProcess {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ConfigurationPath)

  $command = Get-Command -Name 'secedit.exe' -CommandType Application -ErrorAction Stop
  $arguments = New-RideLocalPasswordComplexityValidationArguments -ConfigurationPath $ConfigurationPath
  $null = & $command.Source @arguments 2>&1
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0) { throw "secedit /validate failed with exit code $exitCode." }
}

function Test-RideLocalPasswordComplexityTemplate {
  <#
  .SYNOPSIS
    Validate an allow-listed template with the native Secedit syntax checker.
  .DESCRIPTION
    Confirms that the supplied object is byte-for-byte the one-setting template
    generated by this module, writes it to a unique local temporary workspace,
    and invokes secedit /validate. This does not import or apply security policy.
  .PARAMETER Template
    A template returned by New-RideLocalPasswordComplexityTemplate.
  .EXAMPLE
    $template = New-RideLocalPasswordComplexityTemplate -DesiredState Enabled
    Test-RideLocalPasswordComplexityTemplate -Template $template
  .INPUTS
    Supplied template object only.
  .OUTPUTS
    PSCustomObject reporting native syntax validation, not policy application.
  .NOTES
    Windows-only, read-only with respect to security policy. Native one-setting
    isolation, effective policy and exact rollback remain unverified.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateNotNull()][pscustomobject]$Template)

  if ($env:OS -cne 'Windows_NT') { throw 'Native Secedit template validation is supported only on Windows.' }
  if ($Template.SchemaVersion -ne 1 -or
      $Template.Kind -cne 'LocalPasswordComplexityTemplate' -or
      $Template.NativeExecutionSupported -ne $false -or
      $Template.SettingName -cne 'PasswordComplexity' -or
      $Template.DesiredState -notin @('Enabled', 'Disabled')) {
    throw 'Template is not a version-1 allow-listed local PasswordComplexity template.'
  }

  $expected = New-RideLocalPasswordComplexityTemplate -DesiredState $Template.DesiredState
  if ($Template.Value -ne $expected.Value -or
      $Template.Encoding -cne $expected.Encoding -or
      $Template.Content -cne $expected.Content -or
      $Template.Sha256 -cne $expected.Sha256 -or
      $null -eq $Template.Bytes -or
      [Convert]::ToBase64String([byte[]]$Template.Bytes) -cne [Convert]::ToBase64String([byte[]]$expected.Bytes)) {
    throw 'Template content or bytes differ from the generated one-setting candidate.'
  }

  $workspace = New-RideLocalPasswordComplexityWorkspace
  $configurationPath = Join-Path $workspace 'password-complexity.inf'
  try {
    [IO.File]::WriteAllBytes($configurationPath, [byte[]]$expected.Bytes)
    $configuration = Get-Item -LiteralPath $configurationPath -Force -ErrorAction Stop
    if (-not $configuration.PSIsContainer -and
        -not ($configuration.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        $configuration.Length -eq $expected.Bytes.Length -and
        [Convert]::ToBase64String([IO.File]::ReadAllBytes($configurationPath)) -ceq [Convert]::ToBase64String([byte[]]$expected.Bytes)) {
      Invoke-RideLocalPasswordComplexityTemplateValidationProcess -ConfigurationPath $configurationPath
    } else {
      throw 'Secedit validation input differs from the approved one-setting template bytes.'
    }

    [pscustomobject]@{
      SchemaVersion = 1
      Kind = 'LocalPasswordComplexityTemplateValidation'
      DesiredState = $Template.DesiredState
      TemplateSha256 = $expected.Sha256
      SyntaxValidated = $true
      PolicyApplied = $false
      ExactRecoveryVerified = $false
      ReadyForMutation = $false
    }
  }
  finally {
    if (Test-Path -LiteralPath $configurationPath -PathType Leaf) {
      $item = Get-Item -LiteralPath $configurationPath -Force -ErrorAction Stop
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a reparse-point Secedit template.' }
      Remove-Item -LiteralPath $configurationPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $workspace -PathType Container) {
      $directory = Get-Item -LiteralPath $workspace -Force -ErrorAction Stop
      if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a reparse-point Secedit workspace.' }
      [IO.Directory]::Delete($workspace, $false)
    }
  }
}

function Get-RideLocalPasswordComplexityObservation {
  <#
  .SYNOPSIS
    Read the PasswordComplexity value from a local or merged Secedit export.
  .PARAMETER Scope
    Local exports the local policy database; Merged requests merged domain/local policy.
  .EXAMPLE
    Get-RideLocalPasswordComplexityObservation -Scope Local
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. A non-effective observation; missing values remain NotDefined or NotReported.
  .NOTES
    Read-only with respect to Windows policy. Creates and removes bounded temporary files.
    Export results do not prove policy effectiveness or exact apply/rollback semantics.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateSet('Local', 'Merged')][string]$Scope)

  if ($env:OS -cne 'Windows_NT') { throw 'Secedit policy observation is supported only on Windows.' }

  $workspace = New-RideLocalPasswordComplexityWorkspace
  $configurationPath = Join-Path $workspace 'password-policy.inf'
  $logPath = Join-Path $workspace 'secedit.log'
  try {
    Invoke-RideLocalPasswordComplexityExportProcess -Scope $Scope -ConfigurationPath $configurationPath -LogPath $logPath
    if (-not (Test-Path -LiteralPath $configurationPath -PathType Leaf)) { throw 'secedit /export did not create the requested configuration file.' }

    $configuration = Get-Item -LiteralPath $configurationPath -Force -ErrorAction Stop
    if (($configuration.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $configuration.Length -gt 1048576) {
      throw 'Secedit export is a reparse point or exceeds the 1 MiB inspection limit.'
    }
    $content = [IO.File]::ReadAllText($configurationPath)
    ConvertFrom-RideLocalPasswordComplexityPolicyExport -Content $content -Scope $Scope
  }
  finally {
    foreach ($path in @($configurationPath, $logPath)) {
      if (Test-Path -LiteralPath $path -PathType Leaf) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a reparse-point Secedit output.' }
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
      }
    }
    if (Test-Path -LiteralPath $workspace -PathType Container) {
      $directory = Get-Item -LiteralPath $workspace -Force -ErrorAction Stop
      if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to remove a reparse-point Secedit workspace.' }
      [IO.Directory]::Delete($workspace, $false)
    }
  }
}

Export-ModuleMember -Function New-RideLocalPasswordComplexityTemplate, ConvertFrom-RideLocalPasswordComplexityPolicyExport, New-RideLocalPasswordComplexityRecoveryTemplate, Get-RideLocalPasswordComplexityObservation, Test-RideLocalPasswordComplexityTemplate
