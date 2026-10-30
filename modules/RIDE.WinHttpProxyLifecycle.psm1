<#
.SYNOPSIS
  Apply and restore a guarded WinHTTP advanced proxy configuration candidate.
.DESCRIPTION
  Persists a protected, caller-owned run snapshot before calling the documented
  netsh winhttp set advproxy settings-file interface. It binds apply and restore
  to machine, user SID, scope and observed configuration. It records only the
  state reported by netsh; omitted disabled strings and exact underlying registry
  bytes remain outside its recovery guarantee. The module is not catalog-wired.
.PARAMETER RunId
  Caller-owned 32-character hexadecimal RIDE operation/run ID.
.PARAMETER Patch
  A complete explicit-scope patch from RIDE.WinHttpProxyPreparation.
.PARAMETER ExpectedComputerName
  Exact current machine name expected by the caller.
.PARAMETER ExpectedUserSid
  Exact current user SID expected by the caller.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: netsh advanced proxy support; machine scope requires an existing elevated process.
  Recovery: Protected per-scope snapshot and conflict-checked reported-state restore by RunId.
  Limitations: No atomic protection from external non-RIDE writers; no exact hidden/literal registry recovery.
  Version: 0.1.0.
  Changelog: 0.1.0: Add durable guarded WinHTTP apply and recovery candidate.
.LINK
  ../docs/user-proxy-inventory.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/winhttp/netsh-exe-commands
#>
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.WinHttpProxyInventory.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'RIDE.WinHttpProxyPreparation.psm1') -Force

function Get-RideWinHttpProxyLifecycleIdentity {
  $identity = Get-RideWinHttpProxyCurrentIdentity
  if ([string]::IsNullOrWhiteSpace([string]$identity.ComputerName) -or [string]::IsNullOrWhiteSpace([string]$identity.UserSid)) {
    throw 'WinHTTP lifecycle requires a current machine name and user SID.'
  }
  $identity
}

function Test-RideWinHttpProxyLifecycleAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } finally { $identity.Dispose() }
}

function Get-RideWinHttpProxyLifecycleStateDirectory {
  param([Parameter(Mandatory)][ValidateSet('User','Machine')][string]$Scope)
  if ($Scope -ceq 'Machine') {
    $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($base)) { throw 'CommonApplicationData is unavailable.' }
    return Join-Path $base 'RIDE/State/WinHttpProxy/Machine'
  }
  $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
  if ([string]::IsNullOrWhiteSpace($base)) { throw 'LocalApplicationData is unavailable.' }
  Join-Path $base 'RIDE/State/WinHttpProxy/User'
}

function Initialize-RideWinHttpProxyLifecycleStateDirectory {
  param([Parameter(Mandatory)][ValidateSet('User','Machine')][string]$Scope)
  $path = Get-RideWinHttpProxyLifecycleStateDirectory -Scope $Scope
  if ($Scope -ceq 'Machine') { $basePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData) }
  else { $basePath = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData) }
  $base = [IO.Path]::GetFullPath($basePath).TrimEnd('\') + '\'
  $full = [IO.Path]::GetFullPath($path)
  if (-not $full.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { throw 'WinHTTP state directory escaped its per-scope root.' }
  $cursor = $full
  while ($cursor.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) {
    if (Test-Path -LiteralPath $cursor) {
      $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'WinHTTP state path cannot contain a reparse point.' }
    }
    if ($cursor -ceq $base.TrimEnd('\')) { break }
    $parent = Split-Path -Parent $cursor
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) { throw 'WinHTTP state path has no local parent.' }
    $cursor = $parent
  }
  New-Item -ItemType Directory -Path $full -Force | Out-Null
  $acl = Get-Acl -LiteralPath $full -ErrorAction Stop
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleAll($rule) }
  $sidTexts = if ($Scope -ceq 'Machine') { @('S-1-5-18', 'S-1-5-32-544') } else { @('S-1-5-18', (Get-RideWinHttpProxyLifecycleIdentity).UserSid) }
  foreach ($sidText in $sidTexts) {
    $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
    $access = [Security.AccessControl.FileSystemAccessRule]::new(
      $sid,
      [Security.AccessControl.FileSystemRights]::FullControl,
      [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit,
      [Security.AccessControl.PropagationFlags]::None,
      [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($access)
  }
  Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
  $full
}

function Enter-RideWinHttpProxyLifecycleLock {
  param([Parameter(Mandatory)][string]$StateDirectory)
  $path = Join-Path $StateDirectory 'lifecycle.lock'
  try { [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
  catch { throw 'Another RIDE WinHTTP operation owns the per-scope lock; refusing concurrent mutation.' }
}

function Assert-RideWinHttpProxyLifecycleObservation {
  param([Parameter(Mandatory)]$Observation, [Parameter(Mandatory)][string]$Scope)
  if ($Observation.Kind -cne 'WinHttpProxyConfiguration' -or $Observation.SchemaVersion -ne 1 -or
      $Observation.Status -cne 'Captured' -or $Observation.Scope -cne $Scope -or
      ($Scope -ceq 'User') -ne [bool]$Observation.PerUserProxySettings) {
    throw 'Fresh WinHTTP observation does not match the requested schema and scope.'
  }
  foreach ($pair in @(
    @('Proxy', $Observation.Proxy, $Observation.ProxyReported),
    @('ProxyBypass', $Observation.ProxyBypass, $Observation.ProxyBypassReported),
    @('AutoconfigUrl', $Observation.AutoconfigUrl, $Observation.AutoconfigUrlReported)
  )) {
    if ($pair[2] -isnot [bool]) { throw "WinHTTP reported-field marker '$($pair[0])' is not Boolean." }
    if ($pair[2]) {
      if ($pair[1] -isnot [string] -or $pair[1].Length -gt 32768 -or $pair[1].Contains([string][char]0)) { throw "WinHTTP field '$($pair[0])' is not a valid bounded string." }
    } elseif ($null -ne $pair[1]) { throw "WinHTTP omitted '$($pair[0])' but returned a value." }
  }
  foreach ($field in @('ProxyIsEnabled','AutoConfigIsEnabled','AutoDetect','PerUserProxySettings')) {
    if ($Observation.$field -isnot [bool]) { throw "WinHTTP Boolean field '$field' is invalid." }
  }
  if ($Observation.ProxyIsEnabled -and (-not $Observation.ProxyReported -or [string]::IsNullOrWhiteSpace($Observation.Proxy))) { throw 'WinHTTP reports an enabled proxy without its value.' }
  if ($Observation.AutoConfigIsEnabled -and (-not $Observation.AutoconfigUrlReported -or [string]::IsNullOrWhiteSpace($Observation.AutoconfigUrl))) { throw 'WinHTTP reports enabled auto-configuration without its URL.' }
}

function Test-RideWinHttpProxyLifecycleObservationEqual {
  param([Parameter(Mandatory)]$Left, [Parameter(Mandatory)]$Right)
  if ($Left.Scope -cne $Right.Scope) { return $false }
  foreach ($field in @('ProxyIsEnabled','ProxyReported','ProxyBypassReported','AutoConfigIsEnabled','AutoconfigUrlReported','AutoDetect','PerUserProxySettings')) {
    if ([bool]$Left.$field -ne [bool]$Right.$field) { return $false }
  }
  foreach ($field in @('Proxy','ProxyBypass','AutoconfigUrl')) {
    if (-not [string]::Equals([string]$Left.$field, [string]$Right.$field, [StringComparison]::Ordinal)) { return $false }
  }
  return $true
}

function Test-RideWinHttpProxyLifecycleValuesEqual {
  param([Parameter(Mandatory)]$Observation, [Parameter(Mandatory)]$Values)
  if ($Observation.Scope -cne $Values.Scope -or $Observation.AutoDetect -ne [bool]$Values.AutoDetect) { return $false }
  foreach ($field in @('Proxy','ProxyBypass','AutoconfigUrl')) {
    if (-not [string]::Equals([string]$Observation.$field, [string]$Values.$field, [StringComparison]::Ordinal)) { return $false }
  }
  return $true
}

function Assert-RideWinHttpProxyLifecyclePatch {
  param([Parameter(Mandatory)]$Patch)
  foreach ($field in @('SchemaVersion','Kind','Scope','ChangeRequired','ChangedFields','DesiredValues','SettingsJson','Snapshot')) {
    if ($null -eq $Patch.PSObject.Properties[$field]) { throw "WinHTTP patch is missing '$field'." }
  }
  if ($Patch.SchemaVersion -ne 1 -or $Patch.Kind -cne 'WinHttpProxyPreparation' -or $Patch.Scope -cnotin @('User','Machine') -or $Patch.ChangeRequired -isnot [bool]) { throw 'WinHTTP patch schema is invalid.' }
  if ($Patch.ReadyForMutation -ne $false -or $Patch.MutationAuthorized -ne $false -or $Patch.ExactLiteralStateVerified -ne $false) { throw 'WinHTTP preparation flags are invalid; mutation authorization is owned by the lifecycle candidate.' }
  $expected = $Patch.Snapshot.ExpectedValues
  $desired = $Patch.DesiredValues
  if ($null -eq $expected -or $null -eq $desired -or $desired.Scope -cne $Patch.Scope) { throw 'WinHTTP patch desired values or scope are missing.' }
  foreach ($field in @('Proxy','ProxyBypass','AutoconfigUrl')) {
    if ($expected.$field -isnot [string] -or $expected.$field.Length -gt 32768 -or $expected.$field.Contains([string][char]0) -or
        -not [string]::Equals([string]$desired.$field, [string]$expected.$field, [StringComparison]::Ordinal)) { throw "WinHTTP patch field '$field' is invalid or inconsistent." }
  }
  if ($expected.AutoDetect -isnot [bool] -or [bool]$desired.AutoDetect -ne $expected.AutoDetect) { throw 'WinHTTP patch AutoDetect value is invalid or inconsistent.' }
  $json = ConvertTo-Json -InputObject ([ordered]@{Proxy=$expected.Proxy;ProxyBypass=$expected.ProxyBypass;AutoconfigUrl=$expected.AutoconfigUrl;AutoDetect=[bool]$expected.AutoDetect}) -Depth 3 -Compress
  if (-not [string]::Equals([string]$Patch.SettingsJson, $json, [StringComparison]::Ordinal)) { throw 'WinHTTP patch JSON does not match its structured desired values.' }
  $synthetic = [pscustomobject]@{
    SchemaVersion=1;Kind='WinHttpProxyConfiguration';Status='Captured';Scope=$Patch.Scope
    ProxyIsEnabled=(-not [string]::IsNullOrEmpty([string]$expected.Proxy));Proxy=[string]$expected.Proxy;ProxyReported=$true
    ProxyBypass=[string]$expected.ProxyBypass;ProxyBypassReported=$true
    AutoConfigIsEnabled=(-not [string]::IsNullOrEmpty([string]$expected.AutoconfigUrl));AutoconfigUrl=[string]$expected.AutoconfigUrl;AutoconfigUrlReported=$true
    AutoDetect=[bool]$expected.AutoDetect;PerUserProxySettings=($Patch.Scope -ceq 'User')
  }
  $null = Restore-RideWinHttpProxyConfigurationPatch -Observation $synthetic -Snapshot $Patch.Snapshot
  $computed = @()
  foreach ($field in @('Proxy','ProxyBypass','AutoconfigUrl')) { if (-not [string]::Equals([string]$Patch.Snapshot.OriginalValues.$field, [string]$expected.$field, [StringComparison]::Ordinal)) { $computed += $field } }
  if ([bool]$Patch.Snapshot.OriginalValues.AutoDetect -ne [bool]$expected.AutoDetect) { $computed += 'AutoDetect' }
  $stored = @($Patch.ChangedFields)
  if ($Patch.ChangeRequired -ne ($computed.Count -gt 0) -or $stored.Count -ne $computed.Count) { throw 'WinHTTP patch changed-field summary is inconsistent.' }
  for ($i=0; $i -lt $stored.Count; $i++) { if ($stored[$i] -cne $computed[$i]) { throw 'WinHTTP patch changed-field list is inconsistent.' } }
  $Patch
}

function Save-RideWinHttpProxyLifecycleRecord {
  param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][string]$StateDirectory, [switch]$Update)
  $path = Join-Path $StateDirectory ($Record.RunId + '.json')
  $temp = Join-Path $StateDirectory ($Record.RunId + '.tmp-' + [guid]::NewGuid().ToString('N'))
  $backup = $null
  $json = ConvertTo-Json -InputObject $Record -Depth 16 -Compress
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
  if ($bytes.Length -gt 262144) { throw 'WinHTTP lifecycle record exceeds 256 KiB.' }
  $stream = [IO.File]::Open($temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  try {
    if ($Update) {
      if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'WinHTTP lifecycle record disappeared before atomic update.' }
      $backup = Join-Path $StateDirectory ($Record.RunId + '.backup-' + [guid]::NewGuid().ToString('N'))
      [IO.File]::Replace($temp, $path, $backup)
    } else {
      [IO.File]::Move($temp, $path)
    }
  } finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }
    if ($backup -and (Test-Path -LiteralPath $backup)) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
  }
}

function Read-RideWinHttpProxyLifecycleRecord {
  param([Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$StateDirectory, [Parameter(Mandatory)][string]$Scope)
  if ($RunId -notmatch '^[0-9a-fA-F]{32}$') { throw 'RunId must be 32 hexadecimal characters.' }
  $path = Join-Path $StateDirectory ($RunId + '.json')
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Saved WinHTTP lifecycle state was not found.' }
  $item = Get-Item -LiteralPath $path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 262144) { throw 'Saved WinHTTP record path or size is invalid.' }
  $json = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
  $record = ConvertFrom-Json -InputObject $json -ErrorAction Stop
  if ($record.SchemaVersion -ne 1 -or $record.Kind -cne 'WinHttpProxyLifecycleRecord' -or $record.OperationId -cne 'windows.winhttp-automatic-proxy-detection' -or $record.RunId -cne $RunId -or
      $record.Scope -cne $Scope -or $record.Status -notin @('Prepared','Applied','FailedNoChange','Partial','Restored') -or
      [string]::IsNullOrWhiteSpace([string]$record.ComputerName) -or [string]::IsNullOrWhiteSpace([string]$record.UserSid)) {
    throw 'Saved WinHTTP lifecycle record does not match its identity or supported schema.'
  }
  Assert-RideWinHttpProxyLifecycleObservation -Observation $record.BeforeObservation -Scope $Scope
  if ($record.ExpectedCurrentObservation) { Assert-RideWinHttpProxyLifecycleObservation -Observation $record.ExpectedCurrentObservation -Scope $Scope }
  $record
}

function Write-RideWinHttpProxyLifecycleSettingsFile {
  param([Parameter(Mandatory)][string]$StateDirectory, [Parameter(Mandatory)][string]$Json)
  $path = Join-Path $StateDirectory ('settings-' + [guid]::NewGuid().ToString('N') + '.json')
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Json)
  $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  $path
}

function Invoke-RideWinHttpProxyLifecycleSetCommand {
  param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$SettingsFile)
  $systemRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
  if ([string]::IsNullOrWhiteSpace($systemRoot)) { throw 'SystemRoot is unavailable; refusing to resolve netsh by search path.' }
  $netsh = Join-Path $systemRoot 'System32/netsh.exe'
  if (-not (Test-Path -LiteralPath $netsh -PathType Leaf)) { throw 'The system netsh executable was not found.' }
  $null = @(& $netsh winhttp set advproxy ("setting-scope=" + $Scope.ToLowerInvariant()) ("settings-file=" + $SettingsFile) 2>&1)
  [int]$LASTEXITCODE
}

function Apply-RideWinHttpProxyPatch {
  <#
  .SYNOPSIS
    Apply one prepared WinHTTP patch with a durable pre-change record.
  .DESCRIPTION
    Uses a fixed system netsh path and Microsoft-documented settings-file syntax.
    A successful result means only the reported advanced configuration matched.
  .PARAMETER RunId
    Caller-owned 32-character hexadecimal RIDE run ID.
  .PARAMETER Patch
    Complete patch produced by New-RideWinHttpProxyConfigurationPatch.
  .PARAMETER ExpectedComputerName
    Exact current machine name.
  .PARAMETER ExpectedUserSid
    Exact current user SID.
  .EXAMPLE
    Apply-RideWinHttpProxyPatch -RunId $runId -Patch $patch -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -WhatIf
  .OUTPUTS
    Structured applied, failed or partial result. The durable snapshot remains for recovery.
  #>
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
  param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunId,
    [Parameter(Mandatory)]$Patch,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid
  )
  $null = Assert-RideWinHttpProxyLifecyclePatch -Patch $Patch
  if ($Patch.Scope -ceq 'Machine' -and -not (Test-RideWinHttpProxyLifecycleAdministrator)) { throw 'Machine WinHTTP configuration requires an already elevated process.' }
  if (-not $PSCmdlet.ShouldProcess("$($Patch.Scope) WinHTTP proxy configuration on $ExpectedComputerName", 'Apply advanced proxy settings')) {
    return [pscustomobject]@{RunId=$RunId;Scope=$Patch.Scope;Status='Preview';ChangeApplied=$false;RecoveryPrecision='ReportedConfiguration'}
  }
  $stateDirectory = Initialize-RideWinHttpProxyLifecycleStateDirectory -Scope $Patch.Scope
  $lock = Enter-RideWinHttpProxyLifecycleLock -StateDirectory $stateDirectory
  $settingsFile = $null
  try {
    $identity = Get-RideWinHttpProxyLifecycleIdentity
    if ($identity.ComputerName -cne $ExpectedComputerName -or $identity.UserSid -cne $ExpectedUserSid) { throw 'WinHTTP target identity changed; refusing apply.' }
    $before = Get-RideWinHttpProxyObservation
    Assert-RideWinHttpProxyLifecycleObservation -Observation $before -Scope $Patch.Scope
    if (-not (Test-RideWinHttpProxyLifecycleValuesEqual -Observation $before -Values $Patch.Snapshot.OriginalValues)) { throw 'WinHTTP reported configuration changed since preparation; refusing apply.' }
    if (-not $Patch.ChangeRequired) { return [pscustomobject]@{RunId=$RunId;Scope=$Patch.Scope;Status='AlreadyDesired';ChangeApplied=$false;RecoveryPrecision='ReportedConfiguration'} }
    $record = [ordered]@{
      SchemaVersion=1;Kind='WinHttpProxyLifecycleRecord';RunId=$RunId;OperationId='windows.winhttp-automatic-proxy-detection'
      Scope=$Patch.Scope;ComputerName=$identity.ComputerName;UserSid=$identity.UserSid;Status='Prepared'
      PreparedAtUtc=[DateTime]::UtcNow.ToString('o');AppliedAtUtc=$null;RestoredAtUtc=$null
      BeforeObservation=$before;OriginalValues=$Patch.Snapshot.OriginalValues;DesiredValues=$Patch.DesiredValues
      ChangedFields=@($Patch.ChangedFields);ExpectedCurrentObservation=$before;ExitCode=$null
      RecoveryPrecision='ReportedConfiguration'
      Limitation='netsh does not expose disabled or omitted strings or exact underlying registry state; recovery is conflict-checked to reported configuration only.'
    }
    Save-RideWinHttpProxyLifecycleRecord -Record $record -StateDirectory $stateDirectory
    $settingsFile = Write-RideWinHttpProxyLifecycleSettingsFile -StateDirectory $stateDirectory -Json $Patch.SettingsJson
    $setterErrorType = $null
    try { $exitCode = Invoke-RideWinHttpProxyLifecycleSetCommand -Scope $Patch.Scope -SettingsFile $settingsFile }
    catch { $setterErrorType = $_.Exception.GetType().FullName; $exitCode = $null }
    $record.ExitCode = $exitCode
    try { $after = Get-RideWinHttpProxyObservation; Assert-RideWinHttpProxyLifecycleObservation -Observation $after -Scope $Patch.Scope }
    catch {
      $record.Status = 'Partial'; $record.ExpectedCurrentObservation = $null
      Save-RideWinHttpProxyLifecycleRecord -Record $record -StateDirectory $stateDirectory -Update
      return [pscustomobject]@{RunId=$RunId;Scope=$Patch.Scope;Status='Partial';ChangeApplied=$null;ExitCode=$exitCode;SetterErrorType=$setterErrorType;ReadbackErrorType=$_.Exception.GetType().FullName;RecoveryPrecision='ReportedConfiguration'}
    }
    $record.ExpectedCurrentObservation = $after
    $isDesired = Test-RideWinHttpProxyLifecycleValuesEqual -Observation $after -Values $Patch.DesiredValues
    $isOriginal = Test-RideWinHttpProxyLifecycleObservationEqual -Left $after -Right $before
    if ($null -eq $setterErrorType -and $exitCode -eq 0 -and $isDesired) { $record.Status='Applied';$record.AppliedAtUtc=[DateTime]::UtcNow.ToString('o') }
    elseif ($isOriginal) { $record.Status='FailedNoChange' }
    else { $record.Status='Partial' }
    Save-RideWinHttpProxyLifecycleRecord -Record $record -StateDirectory $stateDirectory -Update
    [pscustomobject]@{RunId=$RunId;Scope=$Patch.Scope;Status=$record.Status;ChangeApplied=$(if($record.Status -eq 'Applied'){$true}elseif($record.Status -eq 'FailedNoChange'){$false}else{$null});ExitCode=$exitCode;SetterErrorType=$setterErrorType;RecoveryPrecision='ReportedConfiguration'}
  } finally {
    if ($settingsFile -and (Test-Path -LiteralPath $settingsFile -PathType Leaf)) { Remove-Item -LiteralPath $settingsFile -Force -ErrorAction SilentlyContinue }
    $lock.Dispose()
  }
}

function Restore-RideWinHttpProxyPatch {
  <#
  .SYNOPSIS
    Restore the reported WinHTTP configuration saved by Apply-RideWinHttpProxyPatch.
  .DESCRIPTION
    Refuses if machine/user identity, scope or reported current settings differ from
    the last observed state recorded by the run. A restored repeat is idempotent.
  .PARAMETER RunId
    Caller-owned RIDE run ID used during apply.
  .PARAMETER ExpectedComputerName
    Exact current machine name.
  .PARAMETER ExpectedUserSid
    Exact current user SID.
  .EXAMPLE
    Restore-RideWinHttpProxyPatch -RunId $runId -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -WhatIf
  .OUTPUTS
    Structured restore result. Exact hidden/literal registry restoration is not claimed.
  #>
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
  param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^S-1-[0-9-]+$')][string]$ExpectedUserSid
  )
  $identity = Get-RideWinHttpProxyLifecycleIdentity
  if ($identity.ComputerName -cne $ExpectedComputerName -or $identity.UserSid -cne $ExpectedUserSid) { throw 'WinHTTP target identity changed; refusing restore.' }
  $userDirectory = Get-RideWinHttpProxyLifecycleStateDirectory -Scope User
  $machineDirectory = Get-RideWinHttpProxyLifecycleStateDirectory -Scope Machine
  $userRecordPath = Join-Path $userDirectory ($RunId + '.json')
  $machineRecordPath = Join-Path $machineDirectory ($RunId + '.json')
  $hasUserRecord = Test-Path -LiteralPath $userRecordPath -PathType Leaf
  $hasMachineRecord = Test-Path -LiteralPath $machineRecordPath -PathType Leaf
  if ($hasUserRecord -eq $hasMachineRecord) { throw 'Saved WinHTTP state was not found uniquely in one scope; refusing restore.' }
  $scope = if ($hasMachineRecord) { 'Machine' } else { 'User' }
  $stateDirectory = Initialize-RideWinHttpProxyLifecycleStateDirectory -Scope $scope
  $record = Read-RideWinHttpProxyLifecycleRecord -RunId $RunId -StateDirectory $stateDirectory -Scope $scope
  if ($record.ComputerName -cne $identity.ComputerName -or $record.UserSid -cne $identity.UserSid) { throw 'Saved WinHTTP state belongs to a different machine or user; refusing restore.' }
  if ($record.Scope -ceq 'Machine' -and -not (Test-RideWinHttpProxyLifecycleAdministrator)) { throw 'Machine WinHTTP restore requires an already elevated process.' }
  if (-not $PSCmdlet.ShouldProcess("$($record.Scope) WinHTTP proxy configuration on $ExpectedComputerName", 'Restore saved advanced proxy settings')) {
    return [pscustomobject]@{RunId=$RunId;Scope=$record.Scope;Status='Preview';ChangeApplied=$false;RecoveryPrecision=$record.RecoveryPrecision}
  }
  $lock = Enter-RideWinHttpProxyLifecycleLock -StateDirectory $stateDirectory
  $settingsFile = $null
  try {
    $record = Read-RideWinHttpProxyLifecycleRecord -RunId $RunId -StateDirectory $stateDirectory -Scope $scope
    if ($record.ComputerName -cne $identity.ComputerName -or $record.UserSid -cne $identity.UserSid) { throw 'Saved WinHTTP state belongs to a different machine or user; refusing restore.' }
    $current = Get-RideWinHttpProxyObservation
    Assert-RideWinHttpProxyLifecycleObservation -Observation $current -Scope $record.Scope
    if ($record.Status -ceq 'Restored') {
      if (-not (Test-RideWinHttpProxyLifecycleObservationEqual -Left $current -Right $record.BeforeObservation)) { throw 'WinHTTP state changed after the saved run was restored; refusing repeat restore.' }
      return [pscustomobject]@{RunId=$RunId;Scope=$record.Scope;Status='AlreadyRestored';ChangeApplied=$false;RecoveryPrecision=$record.RecoveryPrecision}
    }
    if ($null -eq $record.ExpectedCurrentObservation) { throw 'Saved WinHTTP run has no verified current observation; refusing restore.' }
    if (-not (Test-RideWinHttpProxyLifecycleObservationEqual -Left $current -Right $record.ExpectedCurrentObservation)) { throw 'WinHTTP configuration drifted since the saved run; refusing restore.' }
    if (Test-RideWinHttpProxyLifecycleObservationEqual -Left $current -Right $record.BeforeObservation) {
      $record.Status='Restored';$record.RestoredAtUtc=[DateTime]::UtcNow.ToString('o')
      Save-RideWinHttpProxyLifecycleRecord -Record $record -StateDirectory $stateDirectory -Update
      return [pscustomobject]@{RunId=$RunId;Scope=$record.Scope;Status='AlreadyOriginal';ChangeApplied=$false;RecoveryPrecision=$record.RecoveryPrecision}
    }
    $originalJson = ConvertTo-Json -InputObject ([ordered]@{
      Proxy=[string]$record.OriginalValues.Proxy;ProxyBypass=[string]$record.OriginalValues.ProxyBypass
      AutoconfigUrl=[string]$record.OriginalValues.AutoconfigUrl;AutoDetect=[bool]$record.OriginalValues.AutoDetect
    }) -Depth 3 -Compress
    $settingsFile = Write-RideWinHttpProxyLifecycleSettingsFile -StateDirectory $stateDirectory -Json $originalJson
    $exitCode = Invoke-RideWinHttpProxyLifecycleSetCommand -Scope $record.Scope -SettingsFile $settingsFile
    $currentAfter = Get-RideWinHttpProxyObservation
    Assert-RideWinHttpProxyLifecycleObservation -Observation $currentAfter -Scope $record.Scope
    if ($exitCode -ne 0 -or -not (Test-RideWinHttpProxyLifecycleObservationEqual -Left $currentAfter -Right $record.BeforeObservation)) {
      $record.Status='Partial';$record.ExitCode=$exitCode;$record.ExpectedCurrentObservation=$currentAfter
      Save-RideWinHttpProxyLifecycleRecord -Record $record -StateDirectory $stateDirectory -Update
      return [pscustomobject]@{RunId=$RunId;Scope=$record.Scope;Status='Partial';ChangeApplied=$null;ExitCode=$exitCode;RecoveryPrecision=$record.RecoveryPrecision}
    }
    $record.Status='Restored';$record.RestoredAtUtc=[DateTime]::UtcNow.ToString('o');$record.ExitCode=$exitCode
    Save-RideWinHttpProxyLifecycleRecord -Record $record -StateDirectory $stateDirectory -Update
    [pscustomobject]@{RunId=$RunId;Scope=$record.Scope;Status='Restored';ChangeApplied=$true;ExitCode=$exitCode;RecoveryPrecision=$record.RecoveryPrecision}
  } finally {
    if ($settingsFile -and (Test-Path -LiteralPath $settingsFile -PathType Leaf)) { Remove-Item -LiteralPath $settingsFile -Force -ErrorAction SilentlyContinue }
    $lock.Dispose()
  }
}

Export-ModuleMember -Function Apply-RideWinHttpProxyPatch, Restore-RideWinHttpProxyPatch
