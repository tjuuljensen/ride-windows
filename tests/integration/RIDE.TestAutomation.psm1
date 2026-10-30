<#
.SYNOPSIS
  Share configuration, staging, queue and recovery helpers for RIDE VM tasks.

.DESCRIPTION
  - Import is read-only; explicit setup/worker calls manage only configured resources.
  Explicit helpers write files, launch controllers and restore disposable VMs.

.EXAMPLE
  Import-Module .\tests\integration\RIDE.TestAutomation.psm1

.EXAMPLE
  Get-Help Invoke-RideAutomationRequest -Full

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported helper output and side effects are documented per command.

.NOTES
  Compatibility: 64-bit Windows PowerShell 5.1 controller; pure helpers also support PowerShell 7.
  Prerequisites: Prepared AutomatedLab host for operational helpers; none for read-only helpers.
  File/environment inputs: Administrative configuration and correlated request objects.
  Recovery: Follow automatedlab-tasks.md for blocked requests; the fixed worker restores only its
  pinned disposable VM/checkpoint.
  Author: RIDE-Windows maintainers.
  Version: 1.17.1
  Changelog:
    1.17.1: Serialize host progress reads/writes with bounded file-lock contention.
    1.17.0: Supervise host preparation, execution and recovery with durable stage records.
    1.16.0: Require ApplicationsBatch11InteractiveV1 for the signed-in HashCheck guest route.
    1.15.0: Require ApplicationsBatch12NtcoreExplorerSuiteV1 before queueing or dispatching Explorer Suite acceptance.
    1.14.0: Validate and dispatch the WinPmem single-file package acceptance batch.
    1.13.0: Require ApplicationsBatch11HashCheckV1 before accepting HashCheck lifecycle acceptance.
    1.12.0: Require MiTeCSystemAndTelephonyV1 before accepting the focused MiTeC system/TAPI lifecycle request.
    1.11.0: Require MiTeCAnalysisToolsV1 before accepting EXE Explorer and HexEdit portable lifecycle requests.
    1.10.0: Require the registered ApplicationsBatch10ProjectMakerV1 capability before queueing or dispatching Project Maker acceptance.
    1.9.0: Require the registered ApplicationsBatch9InfoBarV1 capability before queueing or dispatching InfoBar acceptance.
    1.8.1: Pass explicit reconnect arguments without capturing the caller's typed script scope.
    1.8.0: Validate and dispatch the RawCopy synthetic-only package acceptance batch.
    1.7.0: Gate split ApplicationsBatch1 requests on an explicit registered-controller capability.
    1.6.0: Validate and dispatch the split ApplicationsBatch1 machine- and limited-user suites.
    1.5.0: Reconnect an unavailable AutomatedLab guest session before exporting test results.
    1.4.0: Validate and dispatch the MiTeC mail/history viewer fixed portable suite.
    1.3.0: Validate and dispatch the NTCoreAdditional fixed portable suite.
    1.2.0: Validate and queue Server 2025 OpenJDK ApplicationsBatch8 acceptance.
    1.1.0: Validate and queue the dedicated ArtCraft Launcher ApplicationsBatch7 suite.
    1.0.0: Validate and dispatch the pinned ImageMagick Q16 feature batch.
    0.9.0: Validate and dispatch the fixed MiTeC utility file-lifecycle batch.
    0.8.0: Validate and dispatch the fixed SQLiteQuery file-lifecycle batch.
    0.7.0: Validate and dispatch focused Slack and Discord package acceptance.
    0.6.0: Dispatch fixed portable acceptance through the preregistered worker.
    0.5.0: Add explicit GitHub PAT selection and credential-safe acceptance boundaries.
    - 0.4.6: Normalize JSON-parsed queue timestamps before culture-sensitive validation.
    - 0.4.5: Remove host UAC inspection and comparison from controller execution.
    - 0.4.4: Preserve the host's existing UAC configuration without requiring enabled prompting.
    - 0.4.3: Disable AutomatedLab's optional release check in each controller process.
    - 0.4.2: Allow bounded failure-evidence session teardown up to 90 seconds.
    - 0.4.1: Stop callers when controller JSON writes or final renames fail.
    0.4.0: Validate application suite requests and exclude private local configuration from snapshots.
  - 0.3.0: Validate and correlate both remaining-settings batch selections.
  - 0.2.0: Validate, forward and verify correlated integration-suite selection.
    - 0.1.2: Retain redirected child-process handles for reliable exit-code reporting.
  - 0.1.1: Start the pinned VM through Hyper-V's supported VM-object parameter.
  - 0.1.0: Initial opt-in task orchestration helpers.

.LINK
  tests/integration/automatedlab-tasks.md

#>


$script:ModuleVersion = '1.17.1'

Set-StrictMode -Version 2

function Get-RideAutomationRoot {
  <#
  .SYNOPSIS
    Resolve the protected controller root for a valid task name.

  .DESCRIPTION
    Validates the RIDE-prefixed name and combines it with CommonApplicationData. Does not create the
    directory.

  .PARAMETER Name
    RIDE-prefixed controller name containing only letters, digits, and hyphens; suffix length 1-55.

  .EXAMPLE
    Get-Help Get-RideAutomationRoot -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.String. ProgramData RIDE/TestAutomation controller path.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory)][string] $Name)
  if ($Name -notmatch '^RIDE[A-Za-z0-9-]{1,55}$') { throw 'Name must start with RIDE and contain only letters, digits and hyphens.' }
  Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "RIDE\TestAutomation\$Name"
}

function Get-RideAutomationResultSession {
  <#
  .SYNOPSIS
    Reuse or reconnect a guest session for exporting correlated VM test results.

  .DESCRIPTION
    Reuses an open, available session. A busy session is left untouched and rejected.
    Disconnected, broken, closed, or unavailable sessions are removed before the supplied
    reconnect action runs. This is intended for result collection after a test activity
    interrupted its original remoting session.

  .PARAMETER Session
    Existing guest session, if one is available.

  .PARAMETER Reconnect
    Action that creates and returns one new guest session.

  .PARAMETER ReconnectArgumentList
    Arguments passed to the reconnect action. Use this to bind reconnect inputs without capturing
    the caller's full script scope.

  .EXAMPLE
    $reconnect = { param($name) New-LabPSSession -ComputerName $name }
    Get-RideAutomationResultSession -Session $session -Reconnect $reconnect -ReconnectArgumentList @('RIDE-Win11-Test')

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    The existing or newly connected guest session.

  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Prerequisites: A caller-provided guest-session reconnect action.
    Side effects: May close a stale session and run the reconnect action.
    Recovery: The caller must preserve the VM checkpoint and report collection failure if reconnection fails.
    Author: RIDE-Windows maintainers.
    Version: 1.0.0
    Changelog:
      1.0.0: Add bounded-state validation for guest result-export sessions.
  #>
  [CmdletBinding()]
  param(
    [object] $Session,
    [Parameter(Mandatory)][scriptblock] $Reconnect,
    [object[]] $ReconnectArgumentList = @()
  )

  if ($Session) {
    $state = [string]$Session.State
    $availability = [string]$Session.Availability
    if ($state -eq 'Opened' -and $availability -eq 'Available') { return $Session }
    if ($state -eq 'Opened' -and $availability -eq 'Busy') {
      throw 'The guest result-export session is still busy; refusing to replace an active command session.'
    }
    if ($Session -is [System.Management.Automation.Runspaces.PSSession]) {
      Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
    }
  }

  $replacement = @(& $Reconnect @ReconnectArgumentList)
  if ($replacement.Count -ne 1 -or -not $replacement[0]) {
    throw 'The guest result-export reconnect action did not return exactly one session.'
  }
  $replacement[0]
}

function Read-RideAutomationConfiguration {
  <#
  .SYNOPSIS
    Read and validate controller seed or installed configuration data.

  .DESCRIPTION
    Loads PSD1 or JSON, validates schema/disposable marker, VM GUID, names, and distinct absolute
    local/CI paths. Requires the guest path to end with ride-windows. Does not provision or register
    resources.

  .PARAMETER Path
    Literal seed PSD1 or installed configuration JSON path.

  .EXAMPLE
    Get-Help Read-RideAutomationConfiguration -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Collections.Hashtable or System.Management.Automation.PSCustomObject. Validated
    configuration.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory)][string] $Path)
  $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  if ([IO.Path]::GetExtension($resolved) -eq '.psd1') { $config = Import-PowerShellDataFile -LiteralPath $resolved }
  else { $config = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json }
  foreach ($key in @('SchemaVersion', 'Name', 'LabName', 'VMName', 'VMId', 'CheckpointName', 'GuestRepositoryPath', 'LocalRepositoryPath', 'CIRepositoryPath', 'IsDisposable')) {
    if ($null -eq $config.$key -or [string]::IsNullOrWhiteSpace([string]$config.$key)) { throw "Configuration is missing $key." }
  }
  if ($config.SchemaVersion -notin @(1,2) -or $config.IsDisposable -ne $true) { throw 'SchemaVersion 1 or 2 and IsDisposable = true are required.' }
  if ($config.PSObject.Properties.Name -contains 'GuestGitHubCredentialReference' -or ($config -is [Collections.IDictionary] -and $config.Contains('GuestGitHubCredentialReference'))) {
    if ($config.SchemaVersion -ne 2 -or $config.GuestGitHubCredentialReference -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'Guest GitHub reference requires SchemaVersion 2 and a safe enrollment name.' }
  }
  if ($config.LabName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,30}$' -or $config.VMName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') { throw 'Invalid lab or VM name.' }
  $null = Get-RideAutomationRoot $config.Name
  $null = [guid]::Parse($config.VMId)
  if ($config.GuestRepositoryPath -notmatch '^[A-Za-z]:\\[^"\r\n]+$') { throw 'GuestRepositoryPath must be an absolute Windows directory below a drive root.' }
  if ((Split-Path -Leaf $config.GuestRepositoryPath) -ne 'ride-windows') { throw 'GuestRepositoryPath must end with ride-windows for the AutomatedLab copy transport.' }
  foreach ($key in @('LocalRepositoryPath', 'CIRepositoryPath')) {
    if ($config.$key -notmatch '^[A-Za-z]:\\[^"\r\n]+$') { throw "$key must be an absolute local Windows directory below a drive root." }
  }
  if ($config.LocalRepositoryPath.TrimEnd('\') -eq $config.CIRepositoryPath.TrimEnd('\')) { throw 'Local and CI checkout paths must be separate.' }
  $config
}

function Assert-RideAutomationSuiteCapability {
  <#
  .SYNOPSIS
    Refuse a suite when the protected controller was not registered with its required capability.
  .DESCRIPTION
    Checks versioned task-client/controller protocol support before queue submission or VM import.
  .PARAMETER Configuration
    Validated registered controller configuration.
  .PARAMETER Suite
    Selected finite integration suite.
  .EXAMPLE
    Assert-RideAutomationSuiteCapability -Configuration $config -Suite ApplicationsBatch1User
  .INPUTS
    None.
  .OUTPUTS
    None; throws before a request is queued or a VM is touched when the controller is stale.
  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7.
    Author: RIDE-Windows maintainers.
  #>
  param([Parameter(Mandatory)][object] $Configuration, [Parameter(Mandatory)][string] $Suite)
  if ($Suite -in @('ApplicationsBatch1Machine','ApplicationsBatch1User') -and
      ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or
       'ApplicationsBatch1SplitV1' -notin @($Configuration.Capabilities))) {
    throw 'Refresh the protected controller for ApplicationsBatch1SplitV1; no request was queued.'
  }
  if ($Suite -eq 'ApplicationsBatch9' -and
      ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or
       'ApplicationsBatch9InfoBarV1' -notin @($Configuration.Capabilities))) {
    throw 'Refresh the protected controller for ApplicationsBatch9InfoBarV1; no request was queued.'
  }
  if ($Suite -eq 'ApplicationsBatch11' -and
      ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or
       'ApplicationsBatch11HashCheckV1' -notin @($Configuration.Capabilities))) {
    throw 'Refresh the protected controller for ApplicationsBatch11HashCheckV1; no request was queued.'
  }
  if ($Suite -eq 'ApplicationsBatch11' -and 'ApplicationsBatch11InteractiveV1' -notin @($Configuration.Capabilities)) {
    throw 'Refresh the protected controller for ApplicationsBatch11InteractiveV1; HashCheck requires a signed-in guest administrator. No request was queued.'
  }
  if ($Suite -eq 'MiTeCAnalysisTools' -and
      ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or
       'MiTeCAnalysisToolsV1' -notin @($Configuration.Capabilities))) {
    throw 'Refresh the protected controller for MiTeCAnalysisToolsV1; no request was queued.'
  }
  if ($Suite -eq 'MiTeCSystemAndTelephony' -and
      ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or
       'MiTeCSystemAndTelephonyV1' -notin @($Configuration.Capabilities))) {
    throw 'Refresh the protected controller for MiTeCSystemAndTelephonyV1; no request was queued.'
  }
  if ($Suite -eq 'ApplicationsBatch10' -and
      ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or
       'ApplicationsBatch10ProjectMakerV1' -notin @($Configuration.Capabilities))) {
    throw 'Refresh the protected controller for ApplicationsBatch10ProjectMakerV1; no request was queued.'
  }
  if ($Suite -eq 'ApplicationsBatch12' -and
      ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or
       'ApplicationsBatch12NtcoreExplorerSuiteV1' -notin @($Configuration.Capabilities))) {
    throw 'Refresh the protected controller for ApplicationsBatch12NtcoreExplorerSuiteV1; no request was queued.'
  }
}

function Assert-RideAutomationRegistrationPins {
  <#
  .SYNOPSIS
    Refuse a controller refresh that changes existing resource or account pins.
  .DESCRIPTION
    Authentication capability upgrades retain the registered VM, checkpoint,
    execution identity, approved source paths and installation ISO identity.
  .PARAMETER Existing
    Previously installed configuration.
  .PARAMETER Candidate
    Newly resolved registration configuration.
  .EXAMPLE
    Assert-RideAutomationRegistrationPins $installed $candidate
  .INPUTS
    None.
  .OUTPUTS
    None; throws before registration writes when any pin changes.
  .NOTES
    Version and compatibility follow this module. Read-only comparison.
  #>
  param($Existing, $Candidate)
  foreach ($field in @('Name','LabName','VMName','VMId','CheckpointName','CheckpointId','HostAccountSid','GuestRepositoryPath','LocalRepositoryPath','CIRepositoryPath','IsoPath','IsoSHA256')) {
    if ([string]$Existing.$field -ne [string]$Candidate.$field) { throw "Controller refresh must preserve the registered $field pin." }
  }
}

function Write-RideAutomationJson {
  <#
  .SYNOPSIS
    Atomically replace a controller JSON file.

  .DESCRIPTION
    Serializes at depth 15 to a unique sibling temporary file, then renames over the destination.
    Write and rename failures terminate the call. Cleans the temporary file in finally;
    the parent must exist.

  .PARAMETER Path
    Destination JSON file; caller validates its ownership and directory.

  .PARAMETER Value
    Object to serialize as JSON.

  .EXAMPLE
    Get-Help Write-RideAutomationJson -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $Path, [object] $Value)
  $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
  try {
    $Value | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $temporary -Encoding UTF8 -ErrorAction Stop
    Move-Item -LiteralPath $temporary -Destination $Path -Force -ErrorAction Stop
  }
  finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}

function Assert-RideAutomationDirectory {
  <#
  .SYNOPSIS
    Reject controller paths traversing filesystem reparse points.

  .DESCRIPTION
    Walks the full path and existing ancestors; throws on any reparse point. Does not create or
    change directories.

  .PARAMETER Path
    Controller directory/path to inspect.

  .EXAMPLE
    Get-Help Assert-RideAutomationDirectory -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None; throws for a rejected path.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $Path)
  $current = [IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Controller paths may not traverse reparse points: $current" }
    }
    $current = Split-Path -Parent $current
  }
}

function Stop-RideAutomationProcess {
  <#
  .SYNOPSIS
    Terminate the timed-out controller process tree.

  .DESCRIPTION
    Runs taskkill /PID /T /F with a ten-second bound, then waits at most five
    seconds for the supplied process. Throws if termination cannot be confirmed.
    Internal destructive timeout recovery helper.

  .PARAMETER Process
    Controller Process object retained by the worker; Id and HasExited are required.

  .EXAMPLE
    Get-Help Stop-RideAutomationProcess -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Process)
  if($Process.HasExited){return}
  $killer=Start-Process -FilePath "$env:SystemRoot\System32\taskkill.exe" -ArgumentList @('/PID',[string]$Process.Id,'/T','/F') -WindowStyle Hidden -PassThru
  $null=$killer.Handle
  if(-not $killer.WaitForExit(10000)){
    $killer.Kill()
    throw 'Process-tree termination exceeded ten seconds. VM recovery is required.'
  }
  $killer.Refresh()
  if($killer.ExitCode -ne 0 -or -not $Process.WaitForExit(5000)){throw 'Could not confirm termination of the timed-out process tree. VM recovery is required.'}
}

function Save-RideAutomationFailureEvidence {
  <#
  .SYNOPSIS
    Launch bounded partial-evidence collection before VM reset.

  .DESCRIPTION
    Starts the installed collector in hidden 64-bit Windows PowerShell, redirects logs, retains the
    process handle, and waits at most 90 seconds. Terminates a timed-out process tree; failure does
    not itself reset the VM.

  .PARAMETER Root
    Controller root returned by Get-RideAutomationRoot for this registered configuration.

  .PARAMETER RunId
    Saved run or correlated request identifier, as required by this command.

  .PARAMETER ResultDirectory
    Existing correlated host result directory for collector logs and guest exports.

  .PARAMETER VerifyGitHubCredentialAbsence
    After checkpoint recovery, verify the request-bound credential is absent in a bounded guest session.

  .EXAMPLE
    Get-Help Save-RideAutomationFailureEvidence -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None; throws on collector failure or timeout.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $Root, [string] $RunId, [string] $ResultDirectory, [switch] $VerifyGitHubCredentialAbsence)
  # A separate bounded collector ensures broken remoting cannot prevent VM reset.
  $arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$(Join-Path $Root 'bin\Export-RideVmTestEvidence.ps1')`" -ConfigurationPath `"$(Join-Path $Root 'configuration.json')`" -RunId $RunId -ResultDirectory `"$ResultDirectory`""
  $logPrefix = 'collection'
  if ($VerifyGitHubCredentialAbsence) { $arguments += ' -VerifyGitHubCredentialAbsence'; $logPrefix = 'collection-credential-recovery' }
  $collector = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $ResultDirectory ($logPrefix + '.log')) -RedirectStandardError (Join-Path $ResultDirectory ($logPrefix + '-errors.log'))
  # Windows PowerShell 5.1 needs the handle retained before a redirected child exits.
  $null = $collector.Handle
  if (-not $collector.WaitForExit(90000)) { Stop-RideAutomationProcess $collector; throw 'Partial-evidence collection timed out after 90 seconds.' }
  $collector.Refresh()
  if ($null -eq $collector.ExitCode) { throw 'Could not read the partial-evidence collector exit code.' }
  if ($collector.ExitCode -ne 0) { throw 'Partial-evidence collection failed. See collection-errors.log.' }
}

function Test-RideAutomationAdministrator {
  <#
  .SYNOPSIS
    Check whether the current Windows process is elevated.

  .DESCRIPTION
    Tests the current principal's administrator role without modifying identity or policies.

  .EXAMPLE
    Get-Help Test-RideAutomationAdministrator -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Boolean. Administrator-role membership of the effective token.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-RideAutomationHost {
  <#
  .SYNOPSIS
    Validate the prepared elevated controller host without policy repair.

  .DESCRIPTION
    Requires 64-bit Windows PowerShell 5.1, elevation, running VMMS/WinRM,
    Hyper-V access, pinned AutomatedLab versions, optional dependency versions, and existing host
    remoting configuration. Imports pinned modules; does not repair policies or start stopped
    services. Does not inspect or enforce host UAC configuration.

  .PARAMETER Configuration
    Optional installed configuration for dependency-version drift checks; omit during initial
    registration.

  .EXAMPLE
    Get-Help Assert-RideAutomationHost -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None. Throws when a required host prerequisite is unavailable.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Configuration)
  if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1 for the controller.' }
  if (-not (Test-RideAutomationAdministrator)) { throw 'The controller needs an elevated process. Register the highest-privilege task from elevated PowerShell.' }
  foreach ($name in @('vmms', 'WinRM')) {
    if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running') { throw "$name must already be running. Prepare the host in an elevated session; no services were started." }
  }
  $null = Get-VMHost -ErrorAction Stop
  # The public publisher quota belongs to RIDE package discovery, not this optional dependency check.
  # This PSFramework setting is process-local; never export it to host or user configuration.
  Import-Module PSFramework -RequiredVersion '1.14.457' -ErrorAction Stop
  Set-PSFConfig -FullName 'AutomatedLab.DisableVersionCheck' -Value $true -EnableException
  Import-Module AutomatedLab -RequiredVersion '5.61.0' -ErrorAction Stop
  if ((Get-Module AutomatedLab.Common).Version -ne [version]'2.3.37') { throw 'AutomatedLab.Common 2.3.37 is required.' }
  foreach ($companion in Get-Module -Name 'AutomatedLab*' | Where-Object Name -NE 'AutomatedLab.Common') {
    if ($companion.Version -ne [version]'5.61.0') { throw "AutomatedLab companion version mismatch: $($companion.Name) must be 5.61.0." }
  }
  if ($Configuration -and $Configuration.PSObject.Properties['DependencyVersions']) {
    foreach ($dependency in $Configuration.DependencyVersions) {
      $loaded = Get-Module -Name $dependency.Name
      if (-not $loaded -or $loaded.Version.ToString() -ne $dependency.Version) { throw "Dependency drift: $($dependency.Name) must be $($dependency.Version). Revalidate before registering a new baseline." }
    }
  }
  # This upstream check starts WinRM if stopped; the service guard above prevents that.
  if (-not (Test-LabHostRemoting)) { throw 'Existing AutomatedLab host remoting configuration is incomplete. Review Enable-LabHostRemoting separately; test execution never repairs host policies.' }
}

function Import-RideAutomationLab {
  <#
  .SYNOPSIS
    Import the selected lab and verify pinned VM/checkpoint identity.

  .DESCRIPTION
    Imports an existing AutomatedLab definition without validation and cross-checks Hyper-V VM
    ID/name and a unique clean checkpoint, including CheckpointId when recorded.

  .PARAMETER Configuration
    Validated disposable-VM controller configuration, including pinned VM and checkpoint identity.

  .EXAMPLE
    Get-Help Import-RideAutomationLab -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. VM and Snapshot objects.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Configuration)
  Import-Lab -Name $Configuration.LabName -NoValidation -ErrorAction Stop
  $machine = @(Get-LabVM -ComputerName $Configuration.VMName)
  if ($machine.Count -ne 1 -or [string]$machine[0].HostType -ne 'HyperV') { throw 'Configured VM must belong to the selected Hyper-V lab.' }
  $vm = Get-VM -Id ([guid]$Configuration.VMId) -ErrorAction Stop
  if ($vm.Name -ne $Configuration.VMName) { throw 'Configured VM ID and VM name do not identify the same VM.' }
  $snapshots = @(Get-VMSnapshot -VM $vm -Name $Configuration.CheckpointName -ErrorAction Stop)
  if ($snapshots.Count -ne 1) { throw 'A unique clean checkpoint is required.' }
  if ($Configuration.PSObject.Properties['CheckpointId'] -and $snapshots[0].Id.ToString() -ne $Configuration.CheckpointId) { throw 'Clean checkpoint identity changed. Revalidate and register the configuration again.' }
  [pscustomobject]@{ VM = $vm; Snapshot = $snapshots[0] }
}

function Reset-RideAutomationVm {
  <#
  .SYNOPSIS
    Power off and restore the pinned disposable VM checkpoint.

  .DESCRIPTION
    Revalidates the target, forcibly stops a non-Off VM, and restores the pinned clean checkpoint.
    Internal destructive recovery helper; use the registered controller.

  .PARAMETER Configuration
    Validated disposable-VM controller configuration, including pinned VM and checkpoint identity.

  .EXAMPLE
    Get-Help Reset-RideAutomationVm -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Configuration)
  $target = Import-RideAutomationLab $Configuration
  if ($target.VM.State -ne 'Off') { Stop-VM -VM $target.VM -TurnOff -Force -Confirm:$false -ErrorAction Stop }
  Restore-VMSnapshot -VMSnapshot $target.Snapshot -Confirm:$false -ErrorAction Stop
}

function Test-RideAutomationWatchPath {
  <#
  .SYNOPSIS
    Test whether a relative path can trigger local VM requests.

  .DESCRIPTION
    Filters Git/private/generated directories and testResults.xml, then selects maintained source
    trees, ride.ps1/default.cmd, and the bootstrap documentation path. Does not access filesystem
    state.

  .PARAMETER RelativePath
    Repository-relative path to classify; separators are normalized for comparison.

  .EXAMPLE
    Get-Help Test-RideAutomationWatchPath -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Boolean. Whether this path is watched.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $RelativePath)
  $relative = $RelativePath.Replace('\', '/')
  if ($relative -match '(^|/)(\.git|\.vs|\.codex|\.agents|\.aws|results|TestResults|node_modules)(/|$)' -or $relative -match '(^|/)testResults\.xml$') { return $false }
  if ($relative -match '^(modules|catalog|profiles|components|tests|tools)(/|$)') { return $true }
  $relative -match '^(ride\.ps1|default\.cmd|docs|docs/bootstrap\.ps1)$'
}

function Copy-RideAutomationSnapshot {
  <#
  .SYNOPSIS
    Stage approved checkout files with source/copied SHA-256 checks.

  .DESCRIPTION
    Requires a RIDE checkout, rejects ancestor/child reparse points, excludes Git/private/generated
    files, and hashes before/after each copy. Throws when the source changes while staging. Returns
    a manifest; destination must be caller-owned.

  .PARAMETER Source
    Approved local/CI repository checkout root.

  .PARAMETER Destination
    Controller-owned snapshot directory for the correlated request.

  .EXAMPLE
    Get-Help Copy-RideAutomationSnapshot -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Relative Path and SHA256 for each staged file.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $Source, [string] $Destination)
  $sourcePath = (Resolve-Path -LiteralPath $Source -ErrorAction Stop).Path.TrimEnd('\')
  if (-not (Test-Path -LiteralPath (Join-Path $sourcePath 'tools\validate.ps1'))) { throw 'Approved source is not a RIDE checkout.' }
  # Reject links before copying so a checkout cannot redirect elevated I/O outside itself.
  $ancestors = Get-Item -LiteralPath $sourcePath
  while ($ancestors) {
    if ($ancestors.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Checkout paths may not traverse reparse points.' }
    $ancestors = $ancestors.Parent
  }
  New-Item -ItemType Directory -Path $Destination -Force | Out-Null
  $files = [Collections.Generic.List[object]]::new()
  $directories = [Collections.Generic.Queue[string]]::new()
  $directories.Enqueue($sourcePath)
  while ($directories.Count) {
    foreach ($item in Get-ChildItem -LiteralPath $directories.Dequeue() -Force) {
      if ($item.Name -in @('.git', '.vs', '.local', '.codex', '.agents', '.aws', 'testResults.xml', 'TestResults', 'results', 'node_modules', 'config.ini', 'serials.ini', 'private.preset') -or $item.Name -like '*.private.preset') { continue }
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Checkout contains a reparse point: $($item.FullName)" }
      $relative = $item.FullName.Substring($sourcePath.Length + 1)
      $target = Join-Path $Destination $relative
      if ($item.PSIsContainer) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        $directories.Enqueue($item.FullName)
      }
      else {
        $before = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        Copy-Item -LiteralPath $item.FullName -Destination $target
        $copied = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
        if ($before -ne $copied -or $before -ne (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash) { throw 'Checkout changed while staging. Submit again after edits settle.' }
        $files.Add([pscustomobject]@{ Path = $relative; SHA256 = $copied })
      }
    }
  }
  $files.ToArray()
}

function Assert-RideAutomationRequest {
  <#
  .SYNOPSIS
    Validate a correlated queue request without executing it.

  .DESCRIPTION
    Validates GUID N format, Local/CI source, Boolean UnitOnly, timeout range, and a parseable
    submission timestamp. Optional IntegrationSuite is a fixed supported name;
    older requests without it retain Full behavior. Reject suite selection with UnitOnly.

  .PARAMETER Request
    Correlated request with RunId, Source, UnitOnly, TimeoutMinutes, and SubmittedAtUtc.

  .EXAMPLE
    Get-Help Assert-RideAutomationRequest -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None; throws for malformed requests.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Request)
  $null = [guid]::ParseExact([string]$Request.RunId, 'N')
  if ($Request.Source -notin @('Local', 'CI') -or $Request.UnitOnly -isnot [bool]) { throw 'Invalid request source or UnitOnly value.' }
  if ($Request.PSObject.Properties.Name -contains 'GuestGitHubAuthentication') {
    if ($Request.GuestGitHubAuthentication -notin @('Anonymous','PAT')) { throw 'Invalid guest GitHub authentication mode.' }
    if ($Request.GuestGitHubAuthentication -eq 'PAT' -and ($Request.UnitOnly -or $Request.IntegrationSuite -ne 'GitHubAuthentication' -or $Request.SchemaVersion -ne 2)) { throw 'Guest PAT requires a version-2 GitHubAuthentication suite request.' }
  }
  if ($Request.PSObject.Properties.Name -contains 'GitHubTestScenario') {
    if ($Request.GitHubTestScenario -notin @('Acquire','FailAfterDelivery','WaitForTimeout') -or $Request.IntegrationSuite -ne 'GitHubAuthentication') { throw 'Invalid focused GitHub recovery scenario.' }
  }
  foreach ($name in $Request.PSObject.Properties.Name) {
    if ($name -notin @('SchemaVersion','RunId','Source','UnitOnly','IntegrationSuite','TimeoutMinutes','SubmittedAtUtc','GuestGitHubAuthentication','GitHubTestScenario')) { throw 'Request contains an unsupported field; credentials and paths are not accepted in the queue.' }
  }
  if ($Request.PSObject.Properties.Name -contains 'IntegrationSuite') {
    if ($Request.IntegrationSuite -notin @('Full', 'SettingsBatch40', 'SettingsBatch60', 'SettingsBatch60Recovery', 'SettingsRemainingBatch1', 'SettingsRemainingBatch2', 'ApplicationsBatch1', 'ApplicationsBatch1Machine', 'ApplicationsBatch1User', 'ApplicationsBatch2', 'ApplicationsBatch3', 'ApplicationsBatch3AllUsers', 'ApplicationsBatch4', 'ApplicationsBatch5', 'ApplicationsBatch6', 'ApplicationsBatch7', 'ApplicationsBatch8', 'ApplicationsBatch9', 'ApplicationsBatch10', 'ApplicationsBatch11', 'ApplicationsBatch12', 'GitHubAuthentication', 'NTCore', 'NTCoreAdditional', 'MiTeCMailHistoryViewers', 'MiTeCAnalysisTools', 'MiTeCSystemAndTelephony', 'PSScriptTools', 'OfflineCaffeine', 'SQLiteQuery', 'MiTeCUtilityFiles', 'SysinternalsSuite', 'SysinternalsProducts', 'ImageMagick', 'RawCopy', 'WinPmem')) { throw 'Invalid request IntegrationSuite.' }
    if ($Request.UnitOnly -and $Request.IntegrationSuite -ne 'Full') { throw 'IntegrationSuite cannot be selected with UnitOnly.' }
    if ($Request.IntegrationSuite -in @('NTCore','NTCoreAdditional','MiTeCMailHistoryViewers','MiTeCAnalysisTools','MiTeCSystemAndTelephony','PSScriptTools','OfflineCaffeine','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick','RawCopy','WinPmem') -and $Request.Source -ne 'Local') { throw 'Focused portable acceptance requires the registered Local source.' }
  }
  if ($Request.TimeoutMinutes -lt 1 -or $Request.TimeoutMinutes -gt 180) { throw 'Invalid request timeout.' }
  $null = [datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()
}

function Enter-RideAutomationWorker {
  <#
  .SYNOPSIS
    Acquire an exclusive process-scoped worker file lock.

  .DESCRIPTION
    Opens runtime/worker.lock with no sharing. Returns null when another worker owns the lock;
    creates the file when absent. Caller disposes the handle in finally.

  .PARAMETER Root
    Controller root returned by Get-RideAutomationRoot for this registered configuration.

  .EXAMPLE
    Get-Help Enter-RideAutomationWorker -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.IO.FileStream or null. Worker lock handle.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $Root)
  try { [IO.File]::Open((Join-Path $Root 'runtime\worker.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
  catch [IO.IOException] { return $null }
}

function Get-RideAutomationClaim {
  <#
  .SYNOPSIS
    Move the oldest valid pending request into the running queue.

  .DESCRIPTION
    Orders pending JSON files, rejects reparse points/malformed or mismatched requests, archives
    invalid requests, and moves a valid request to queue/running. Requires the worker serialization
    lock.

  .PARAMETER Root
    Controller root returned by Get-RideAutomationRoot for this registered configuration.

  .EXAMPLE
    Get-Help Get-RideAutomationClaim -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject or null. Request, claimed Path, and Name.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([string] $Root)
  while ($true) {
    $pending = Get-ChildItem -LiteralPath (Join-Path $Root 'queue\pending') -Filter '*.json' -File | Sort-Object LastWriteTimeUtc, Name | Select-Object -First 1
    if (-not $pending) { return $null }
    try {
      if ($pending.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Request cannot be a reparse point.' }
      $request = Get-Content -LiteralPath $pending.FullName -Raw | ConvertFrom-Json
      # PowerShell 7 can deserialize ISO timestamps as DateTime; keep the queue's string contract.
      if ($request.SubmittedAtUtc -is [datetime]) { $request.SubmittedAtUtc = $request.SubmittedAtUtc.ToUniversalTime().ToString('o') }
      Assert-RideAutomationRequest $request
      if ($pending.BaseName -ne $request.RunId) { throw 'Request filename does not match RunId.' }
    }
    catch {
      Move-Item -LiteralPath $pending.FullName -Destination (Join-Path $Root "queue\finished\invalid-$([guid]::NewGuid().ToString('N')).json")
      continue
    }
    $claimed = Join-Path $Root "queue\running\$($pending.Name)"
    Move-Item -LiteralPath $pending.FullName -Destination $claimed
    return [pscustomobject]@{ Request = $request; Path = $claimed; Name = $pending.Name }
  }
}

function Get-RideAutomationTaskParameters {
  <#
  .SYNOPSIS
    Build the fixed interactive elevated scheduled-task definition.

  .DESCRIPTION
    Builds action, principal, and settings objects for the installed worker, hidden 64-bit Windows
    PowerShell, and IgnoreNew serialization. Does not register the task.

  .PARAMETER Configuration
    Validated disposable-VM controller configuration, including pinned VM and checkpoint identity.

  .PARAMETER ConfigurationPath
    Installed protected configuration.json referenced by the task action.

  .EXAMPLE
    Get-Help Get-RideAutomationTaskParameters -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Collections.Hashtable. Register-ScheduledTask parameters.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Configuration, [string] $ConfigurationPath)
  $root = Get-RideAutomationRoot $Configuration.Name
  $executable = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $worker = Join-Path $root 'bin\Invoke-RideVmTestTaskWorker.ps1'
  @{
    TaskName = $Configuration.Name
    TaskPath = '\RIDE\'
    Description = "RIDE disposable VM test controller: $ConfigurationPath"
    Action = New-ScheduledTaskAction -Execute $executable -Argument "-NoLogo -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$worker`" -ConfigurationPath `"$ConfigurationPath`"" -WorkingDirectory (Join-Path $root 'bin')
    Principal = New-ScheduledTaskPrincipal -UserId $Configuration.HostAccountSid -LogonType Interactive -RunLevel Highest
    Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([timespan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  }
}

function Enter-RideAutomationHostProgressLock {
  <#
  .SYNOPSIS
    Serialize progress readers and the single writer across processes.
  .DESCRIPTION
    Acquires an exclusive sibling lock file, retrying sharing/lock violations
    for at most one second. The caller must dispose the returned handle.
    The lock file is retained; handle lifetime, not file presence, owns the lock.
  .PARAMETER Path
    Literal progress JSON path; its sibling .lock file is used.
  .OUTPUTS
    FileStream holding the exclusive lock.
  .NOTES
    Internal local-filesystem coordination; never loads host/guest services.
  #>
  param([string]$Path)
  $elapsed=[Diagnostics.Stopwatch]::StartNew()
  while($true){
    try{return [IO.File]::Open(($Path+'.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
    catch{
      $failure=$_.Exception
      while($failure.InnerException){$failure=$failure.InnerException}
      if($failure -isnot [IO.IOException] -or ($failure.HResult -band 0xffff) -notin @(32,33) -or $elapsed.ElapsedMilliseconds -ge 1000){throw}
      Start-Sleep -Milliseconds 25
    }
  }
}

function Read-RideAutomationHostProgress {
  <#
  .SYNOPSIS
    Read one complete host progress snapshot under the shared coordination lock.
  .DESCRIPTION
    Holds the sibling progress lock while reading, so a writer cannot change
    an open snapshot. Uses read-only access with ReadWrite/Delete sharing.
    Lock acquisition and sharing/lock I/O retries are each limited to one second;
    malformed JSON and other I/O errors remain failures. Always closes handles.
  .PARAMETER Path
    Literal path to the correlated host-phase.json file.
  .OUTPUTS
    Parsed progress object.
  .NOTES
    Windows PowerShell 5.1. Writes only the sibling coordination lock file.
  #>
  param([string]$Path)
  $progressLock=Enter-RideAutomationHostProgressLock $Path
  try{
  $elapsed=[Diagnostics.Stopwatch]::StartNew()
  while($true){
    $stream=$null;$reader=$null
    try{
      $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
      $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8,$true)
      $json=$reader.ReadToEnd()
      break
    }catch{
      $failure=$_.Exception
      while($failure.InnerException){$failure=$failure.InnerException}
      $code=$failure.HResult -band 0xffff
      if($failure -isnot [IO.IOException] -or $code -notin @(32,33) -or $elapsed.ElapsedMilliseconds -ge 1000){throw}
      Start-Sleep -Milliseconds 25
    }finally{
      if($reader){$reader.Dispose()}elseif($stream){$stream.Dispose()}
    }
  }
  $json|ConvertFrom-Json -ErrorAction Stop
  }finally{$progressLock.Dispose()}
}

function Write-RideAutomationHostProgress {
  <#
  .SYNOPSIS
    Record a bounded request phase before beginning its next operation.
  .DESCRIPTION
    Retains the phase start time and a sticky possible-VM-change marker. Writes
    a current-state file under an exclusive coordination lock and a closed-handle
    JSON-lines history. Interrupted/incomplete writes fail closed on the next read.
  .PARAMETER ResultDirectory
    Existing correlated result directory.
  .PARAMETER RunId
    Correlated request identifier.
  .PARAMETER Phase
    Preparation, Execution or Recovery; phases cannot move backwards.
  .PARAMETER Stage
    Fixed operator-readable stage description; never include credentials.
  .PARAMETER VmMayHaveChanged
    Set before invoking any VM mutation; it cannot be cleared in later records.
  .OUTPUTS
    None.
  .NOTES
    Internal watchdog evidence; does not change VM state.
  #>
  param([string]$ResultDirectory,[string]$RunId,
    [ValidateSet('Preparation','Execution','Recovery')][string]$Phase,
    [string]$Stage,[bool]$VmMayHaveChanged=$false)
  $path=Join-Path $ResultDirectory 'host-phase.json'
  $now=[datetime]::UtcNow.ToString('o')
  $phaseStarted=$now
  if(Test-Path -LiteralPath $path){
    $previous=Read-RideAutomationHostProgress $path
    if($previous.RunId -cne $RunId){throw 'Host progress correlation failed.'}
    $order=@{Preparation=0;Execution=1;Recovery=2}
    if($order[$Phase] -lt $order[[string]$previous.Phase]){throw 'Host phase cannot move backwards.'}
    if($previous.Phase -eq $Phase){$phaseStarted=$previous.PhaseStartedAtUtc}
    $VmMayHaveChanged=$VmMayHaveChanged -or $previous.VmMayHaveChanged
  }
  $state=[ordered]@{RunId=$RunId;Phase=$Phase;Stage=$Stage;RecordedAtUtc=$now;PhaseStartedAtUtc=$phaseStarted;VmMayHaveChanged=$VmMayHaveChanged}
  # All readers use this same bounded lock. Avoid replacing an open Windows file.
  # A crash during writing leaves invalid evidence, which the supervisor blocks.
  $json=$state|ConvertTo-Json
  $progressLock=Enter-RideAutomationHostProgressLock $path
  try {
    [IO.File]::WriteAllText($path,$json,[Text.UTF8Encoding]::new($false))
  } finally {$progressLock.Dispose()}
  [IO.File]::AppendAllText((Join-Path $ResultDirectory 'host-progress.jsonl'),($state|ConvertTo-Json -Compress)+[Environment]::NewLine)
}

function Wait-RideAutomationSupervisedProcess {
  <#
  .SYNOPSIS
    Observe a request child without loading Hyper-V or AutomatedLab in the parent.
  .DESCRIPTION
    Preparation gets at most five minutes and shares the request deadline.
    Execution gets the request deadline plus 15 seconds to enter recovery.
    Recovery gets three minutes, capped at four minutes after the request deadline.
    Returns on child exit or deadline; the caller owns termination and results.
  .PARAMETER Process
    Started child process with its retained handle.
  .PARAMETER ResultDirectory
    Directory containing coordinated host-phase.json.
  .PARAMETER RunId
    Expected request identifier.
  .PARAMETER DeadlineUtc
    Absolute submitted-request execution deadline.
  .PARAMETER PreparationSeconds
    Internal preparation budget; smaller values support inert-process tests.
  .PARAMETER RecoverySeconds
    Internal recovery budget; smaller values support inert-process tests.
  .OUTPUTS
    Last phase state and TimedOut flag. Does not stop processes or touch a VM.
  .NOTES
    Windows PowerShell 5.1. Queue requests cannot override these phase budgets.
  #>
  param($Process,[string]$ResultDirectory,[string]$RunId,[datetime]$DeadlineUtc,
    [ValidateRange(0.1,300)][double]$PreparationSeconds=300,
    [ValidateRange(0.1,180)][double]$RecoverySeconds=180)
  $preparationDeadline=[datetime]::UtcNow.AddSeconds($PreparationSeconds)
  $recoveryDeadline=$null
  $state=$null
  while($true){
    $state=Read-RideAutomationHostProgress (Join-Path $ResultDirectory 'host-phase.json')
    if($state.RunId -cne $RunId -or $state.Phase -notin @('Preparation','Execution','Recovery')){throw 'Invalid supervised host progress.'}
    if($Process.WaitForExit(200)){return [pscustomobject]@{TimedOut=$false;State=$state}}
    $limit=$DeadlineUtc
    switch($state.Phase){
      Preparation {if($preparationDeadline -lt $limit){$limit=$preparationDeadline}}
      Execution {$limit=$DeadlineUtc.AddSeconds(15)}
      Recovery {
        if($null -eq $recoveryDeadline){$recoveryDeadline=[datetime]::UtcNow.AddSeconds($RecoverySeconds)}
        $limit=$DeadlineUtc.AddSeconds(240)
        if($recoveryDeadline -lt $limit){$limit=$recoveryDeadline}
      }
    }
    if([datetime]::UtcNow -ge $limit){return [pscustomobject]@{TimedOut=$true;State=$state}}
  }
}

function Invoke-RideAutomationSupervisedRequest {
  <#
  .SYNOPSIS
    Run a claimed request with an independent host-preparation watchdog.
  .DESCRIPTION
    The parent retains the queue lock and invokes only the fixed installed child.
    Host checks, lab import, staging and VM startup are supervised. A timeout
    terminates the child tree and records a terminal result. If the VM may have
    changed, termination fails, or progress is untrustworthy, block new requests
    for explicit recovery rather than calling another potentially hung host API.
  .PARAMETER Configuration
    Installed configuration already read by the worker.
  .PARAMETER Request
    Validated, claimed request; no arbitrary script path or timeout hook accepted.
  .PARAMETER Root
    Installed controller root.
  .OUTPUTS
    Correlated terminal summary.
  .NOTES
    Windows PowerShell 5.1; called by the serialized elevated worker only.
  #>
  param($Configuration,$Request,[string]$Root)
  Assert-RideAutomationRequest $Request
  $runDirectory=Join-Path $Root "results\$($Request.RunId)"
  Assert-RideAutomationDirectory $runDirectory
  $null=New-Item -ItemType Directory -Path $runDirectory -Force
  $deadline=([datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).AddMinutes($Request.TimeoutMinutes)
  $suite=if($Request.PSObject.Properties.Name -contains 'IntegrationSuite'){$Request.IntegrationSuite}else{'Full'}
  $resultPath=Join-Path $runDirectory 'result.json'
  if(Test-Path -LiteralPath $resultPath){throw 'Terminal result already exists; refuse duplicate dispatch.'}
  $process=$null;$state=$null;$terminationError=$null
  $summary=[ordered]@{SchemaVersion=1;RunId=$Request.RunId;Source=$Request.Source;UnitOnly=$Request.UnitOnly;IntegrationSuite=$suite;Status='Failed';StartedAtUtc=[datetime]::UtcNow.ToString('o');FinishedAtUtc=$null;Error=$null;CleanupError=$null;CollectionError=$null;EvidenceExportError=$null;Supervisor=$true;RecoveryRequired=$false;GuestGitHubAuthentication=if($Request.PSObject.Properties.Name -contains 'GuestGitHubAuthentication'){$Request.GuestGitHubAuthentication}else{'Anonymous'}}
  try{
    Write-RideAutomationHostProgress $runDirectory $Request.RunId Preparation 'Starting isolated request process'
    if([datetime]::UtcNow -ge $deadline){throw 'Request expired while waiting in the queue.'}
    $arguments="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$(Join-Path $Root 'bin\Invoke-RideVmTestRequest.ps1')`" -ConfigurationPath `"$(Join-Path $Root 'configuration.json')`" -RunId $($Request.RunId)"
    $process=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runDirectory 'host-worker.log') -RedirectStandardError (Join-Path $runDirectory 'host-worker-errors.log')
    $null=$process.Handle
    $wait=Wait-RideAutomationSupervisedProcess -Process $process -ResultDirectory $runDirectory -RunId $Request.RunId -DeadlineUtc $deadline
    $state=$wait.State
    if($wait.TimedOut){$summary.Status='TimedOut';throw "Host watchdog expired in $($state.Phase): $($state.Stage)."}
    $process.Refresh()
    if(-not (Test-Path -LiteralPath $resultPath)){throw 'Request child exited without a terminal result; inspect host-worker-errors.log.'}
    $result=Get-Content -LiteralPath $resultPath -Raw|ConvertFrom-Json
    if($result.RunId -cne $Request.RunId -or $result.IntegrationSuite -cne $suite -or $result.Status -notin @('Passed','Failed','TimedOut') -or ($result.Status -eq 'Passed' -and $process.ExitCode -ne 0)){throw 'Invalid supervised terminal result.'}
    return $result
  }
  catch{
    $summary.Error=$_.Exception.Message
    if($process){
      try{if(-not $process.HasExited){Stop-RideAutomationProcess $process}}
      catch{$terminationError=$_.Exception.Message}
      # Read again after termination: the child could have announced a VM
      # mutation between the watchdog's last observation and the stop request.
      try{$state=Read-RideAutomationHostProgress (Join-Path $runDirectory 'host-phase.json');if($state.RunId -cne $Request.RunId -or $state.Phase -notin @('Preparation','Execution','Recovery') -or $state.VmMayHaveChanged -isnot [bool]){$state=$null}}
      catch{$state=$null}
    }
    $summary.RecoveryRequired=[bool]($terminationError -or ($process -and ($null -eq $state -or $state.VmMayHaveChanged)))
    if($state){$summary.LastHostPhase=$state.Phase;$summary.LastHostStage=$state.Stage}
    if($summary.RecoveryRequired){
      $summary.CleanupError=if($terminationError){$terminationError}else{'Request interrupted after a possible VM change; explicit checkpoint recovery required.'}
      Write-RideAutomationJson -Path (Join-Path $Root 'runtime\blocked.json') -Value @{RunId=$Request.RunId;Error=$summary.CleanupError}
    }
    $summary.FinishedAtUtc=[datetime]::UtcNow.ToString('o')
    if(Test-Path -LiteralPath $resultPath){Copy-Item -LiteralPath $resultPath -Destination (Join-Path $runDirectory 'request-child-result.json') -ErrorAction Stop}
    Write-RideAutomationJson -Path $resultPath -Value $summary
    return [pscustomobject]$summary
  }
}

function Invoke-RideAutomationRequest {
  <#
  .SYNOPSIS
    Run one correlated test request and recover its disposable VM.

  .DESCRIPTION
    Validates prepared host/target, stages an approved checkout, resets/starts the pinned VM, runs
    the installed controller with bounded remaining timeout, and verifies correlated guest evidence.
    Collects failure evidence and restores the checkpoint in finally; cleanup failures create a
    block marker. Writes the correlated result.json without inspecting host UAC.

  .PARAMETER Configuration
    Validated disposable-VM controller configuration, including pinned VM and checkpoint identity.

  .PARAMETER Request
    Correlated request with RunId, Source, UnitOnly, TimeoutMinutes, and SubmittedAtUtc.

  .PARAMETER Root
    Controller root returned by Get-RideAutomationRoot for this registered configuration.

  .PARAMETER Supervised
    Emit host phases for the independent parent watchdog. Used by the fixed request child.

  .EXAMPLE
    Get-Help Invoke-RideAutomationRequest -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Terminal correlated run summary.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Configuration, [object] $Request, [string] $Root, [switch]$Supervised)
  Assert-RideAutomationRequest $Request
  $selectedSuite = if ($Request.PSObject.Properties.Name -contains 'IntegrationSuite') { $Request.IntegrationSuite } else { 'Full' }
  $focusedPortable = $selectedSuite -in @('NTCore','NTCoreAdditional','MiTeCMailHistoryViewers','MiTeCAnalysisTools','MiTeCSystemAndTelephony','PSScriptTools','OfflineCaffeine','SQLiteQuery','MiTeCUtilityFiles','SysinternalsSuite','SysinternalsProducts','ImageMagick','RawCopy','WinPmem')
  $guestAuthentication = if ($Request.PSObject.Properties.Name -contains 'GuestGitHubAuthentication') { $Request.GuestGitHubAuthentication } else { 'Anonymous' }
  $authenticationContext = $null
  $gitHubScenario = if ($Request.PSObject.Properties.Name -contains 'GitHubTestScenario') { $Request.GitHubTestScenario } else { 'Acquire' }
  $runDirectory = Join-Path $Root "results\$($Request.RunId)"
  Assert-RideAutomationDirectory $runDirectory
  New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
  $summary = [ordered]@{ SchemaVersion = 1; RunId = $Request.RunId; Source = $Request.Source; UnitOnly = $Request.UnitOnly; IntegrationSuite = $selectedSuite; Status = 'Failed'; StartedAtUtc = [datetime]::UtcNow.ToString('o'); FinishedAtUtc = $null; Error = $null; CleanupError = $null; CollectionError = $null }
  $touchedVm = $false
  $summary.GuestGitHubAuthentication = $guestAuthentication
  $summary.GitHubTestScenario = $gitHubScenario
  $summary.CredentialCleanupVerified = $null
  $summary.EvidenceExportError = $null
  function Set-HostStage([string]$Phase,[string]$Stage){
    if($Supervised){Write-RideAutomationHostProgress -ResultDirectory $runDirectory -RunId $Request.RunId -Phase $Phase -Stage $Stage -VmMayHaveChanged $touchedVm}
  }
  try {
    Set-HostStage Preparation 'Validate request prerequisites'
    if (Test-Path -LiteralPath (Join-Path $Root 'runtime\blocked.json')) { throw 'VM cleanup is blocked. Follow the recovery runbook before submitting another run.' }
    Assert-RideAutomationSuiteCapability -Configuration $Configuration -Suite $selectedSuite
    if (([datetime]::UtcNow - [datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).TotalMinutes -ge $Request.TimeoutMinutes) { throw 'Request expired while waiting in the queue.' }
    Set-HostStage Preparation 'Validate host and import dependencies'
    Assert-RideAutomationHost $Configuration
    if ($focusedPortable -and ($Configuration.PSObject.Properties.Name -notcontains 'Capabilities' -or 'FocusedPortableV1' -notin @($Configuration.Capabilities))) { throw 'Refresh the protected controller for FocusedPortableV1 before requesting this batch.' }
    if ($guestAuthentication -eq 'PAT') {
      Set-HostStage Preparation 'Read configured guest authentication'
      Import-Module (Join-Path $Root 'bin\RIDE.GitHubVmAuthentication.psm1') -ErrorAction Stop
      $authenticationContext = Get-RideVmGitHubContext $Configuration
    }
    Set-HostStage Preparation 'Import lab and verify VM/checkpoint pins'
    $target = Import-RideAutomationLab $Configuration
    if ($focusedPortable -and $target.VM.State -ne 'Off') { throw 'Focused acceptance requires the pinned VM to be Off before dispatch.' }
    if (([datetime]::UtcNow - [datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).TotalMinutes -ge $Request.TimeoutMinutes) { throw 'Request expired while waiting in the queue.' }
    $source = if ($Request.Source -eq 'CI') { $Configuration.CIRepositoryPath } else { $Configuration.LocalRepositoryPath }
    $snapshotPath = Join-Path $runDirectory 'snapshot\ride-windows'
    Set-HostStage Preparation 'Copy approved checkout snapshot'
    $manifest = @(Copy-RideAutomationSnapshot -Source $source -Destination $snapshotPath)
    Write-RideAutomationJson -Path (Join-Path $runDirectory 'source-files.json') -Value $manifest
    if ($selectedSuite -eq 'GitHubAuthentication' -and (Test-Path -LiteralPath (Join-Path $snapshotPath 'tests\integration\settings-validation.fixture.psd1'))) { throw 'Use an isolated reviewed authentication source without the active settings fixture.' }
    if (([datetime]::UtcNow - [datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).TotalMinutes -ge $Request.TimeoutMinutes) { throw 'Request expired while staging the checkout.' }
    $touchedVm = $true
    Set-HostStage Preparation 'VM mutation may begin'
    if ($focusedPortable) {
      $arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$(Join-Path $Root 'bin\Invoke-RidePortableVmAcceptance.ps1')`" -ConfigurationPath `"$(Join-Path $Root 'configuration.json')`" -ControllerRunId $($Request.RunId) -Batch $selectedSuite -TimeoutMinutes $([math]::Min(60,$Request.TimeoutMinutes))"
    } else {
      Set-HostStage Preparation 'Restore pinned checkpoint'
      Reset-RideAutomationVm $Configuration
      Set-HostStage Preparation 'Start test VM'
      Start-VM -VM (Get-VM -Id ([guid]$Configuration.VMId) -ErrorAction Stop) -ErrorAction Stop | Out-Null
      $arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$(Join-Path $Root 'bin\Invoke-RideVmTest.ps1')`" -Transport AutomatedLab -LabName `"$($Configuration.LabName)`" -VMName `"$($Configuration.VMName)`" -RepositoryPath `"$snapshotPath`" -GuestRepositoryPath `"$($Configuration.GuestRepositoryPath)`" -ResultDirectory `"$runDirectory`" -RunId $($Request.RunId)"
      if ($Request.UnitOnly) { $arguments += ' -UnitOnly' }
      else { $arguments += " -IntegrationSuite $selectedSuite" }
    }
    if ($selectedSuite -eq 'GitHubAuthentication') { $arguments += " -GuestGitHubAuthentication $guestAuthentication -GitHubTestScenario $gitHubScenario" }
    if ($guestAuthentication -eq 'PAT') {
      $deadline = ([datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).AddMinutes($Request.TimeoutMinutes).ToString('o')
      $arguments += " -AuthenticationConfigurationPath `"$(Join-Path $Root 'configuration.json')`" -AuthenticationDeadlineUtc $deadline -AuthenticationCredentialRevision $($authenticationContext.Revision)"
    }
    Set-HostStage Execution 'Run test controller'
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runDirectory 'controller.log') -RedirectStandardError (Join-Path $runDirectory 'controller-errors.log')
    # Retain the handle before waiting; otherwise Windows PowerShell 5.1 can lose ExitCode.
    $null = $process.Handle
    $remaining = [math]::Max(1, ($Request.TimeoutMinutes * 60) - ([datetime]::UtcNow - [datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).TotalSeconds)
    if (-not $process.WaitForExit([int]($remaining * 1000))) {
      $summary.Status = 'TimedOut'
      try { Stop-RideAutomationProcess $process }
      catch {
        $summary.Status = 'Failed'
        $summary.CleanupError = $_.Exception.Message
        Write-RideAutomationJson -Path (Join-Path $Root 'runtime\blocked.json') -Value @{ RunId = $Request.RunId; Error = $summary.CleanupError }
        throw
      }
      throw 'Test controller exceeded its timeout; process tree terminated.'
    }
    $process.Refresh()
    if ($null -eq $process.ExitCode) { throw 'Could not read the test controller exit code. See controller logs.' }
    if ($process.ExitCode -ne 0) { throw "Test controller exited with code $($process.ExitCode). See controller-errors.log." }
    if ($focusedPortable) {
      $focused = Get-Content -LiteralPath (Join-Path $runDirectory 'focused/result.json') -Raw -ErrorAction Stop | ConvertFrom-Json
      $expectedToolExecution = $selectedSuite -in @('ImageMagick','NTCore','RawCopy')
      if ($focused.RunId -cne $Request.RunId -or $focused.Batch -cne $selectedSuite -or $focused.Status -ne 'Passed' -or $focused.Cleanup -ne 'ResetAndOff' -or $focused.EvidenceCollected -ne $true -or $focused.ToolExecuted -ne $expectedToolExecution) { throw 'Focused result is missing, mismatched, incomplete or unsuccessful.' }
      $summary.FocusedResult = $focused
    } else {
    $guest = Get-Content -LiteralPath (Join-Path $runDirectory 'guest\summary.json') -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($guest.RunId -ne $Request.RunId -or $guest.Status -ne 'Passed' -or $guest.Pester.Total -lt 1 -or $guest.Pester.Failed -ne 0 -or -not $guest.ValidationPassed -or (-not $Request.UnitOnly -and -not $guest.IntegrationPassed)) { throw 'Guest result is missing, mismatched, incomplete or unsuccessful.' }
    if (-not $Request.UnitOnly -and ($guest.PSObject.Properties.Name -notcontains 'IntegrationSuite' -or $guest.IntegrationSuite -ne $selectedSuite)) { throw 'Guest integration suite does not match the requested suite.' }
    if ($selectedSuite -eq 'GitHubAuthentication' -and $guest.GuestGitHubAuthentication -ne $guestAuthentication) { throw 'Guest authentication mode does not match the request.' }
    if ($selectedSuite -eq 'GitHubAuthentication' -and $guest.GitHubTestScenario -ne $gitHubScenario) { throw 'Guest authentication scenario does not match the request.' }
    if ($guestAuthentication -eq 'PAT' -and $guest.CredentialCleanupVerified -ne $true) { throw 'Guest credential cleanup evidence is missing.' }
    if (-not (Test-Path -LiteralPath (Join-Path $runDirectory 'guest\pester.xml') -PathType Leaf)) { throw 'Guest Pester XML is missing.' }
    }
    $summary.Status = 'Passed'
  }
  catch { $summary.Error = $_.Exception.Message }
  finally {
    Set-HostStage Recovery 'Finalize request and recover VM if needed'
    if ($touchedVm) {
      if ($summary.Status -ne 'Passed' -and -not $focusedPortable) {
        try { Set-HostStage Recovery 'Collect partial guest evidence'; Save-RideAutomationFailureEvidence -Root $Root -RunId $Request.RunId -ResultDirectory $runDirectory }
        catch { $summary.CollectionError = $_.Exception.Message }
      }
      try {
        Set-HostStage Recovery 'Restore checkpoint after request'
        Reset-RideAutomationVm $Configuration
        if ($guestAuthentication -eq 'PAT') {
          try { Save-RideAutomationFailureEvidence -Root $Root -RunId $Request.RunId -ResultDirectory $runDirectory -VerifyGitHubCredentialAbsence }
          finally { Reset-RideAutomationVm $Configuration }
          $recovery = Get-Content -LiteralPath (Join-Path $runDirectory 'guest\credential-recovery.json') -Raw | ConvertFrom-Json
          if ($recovery.RunId -ne $Request.RunId -or $recovery.CredentialAbsent -ne $true) { throw 'Post-reset credential absence was not verified.' }
          $summary.CredentialCleanupVerified = $true
        }
      }
      catch {
        $summary.Status = 'Failed'
        $summary.CleanupError = $_.Exception.Message
        Write-RideAutomationJson -Path (Join-Path $Root 'runtime\blocked.json') -Value @{ RunId = $Request.RunId; Error = $summary.CleanupError }
      }
    }
    $summary.FinishedAtUtc = [datetime]::UtcNow.ToString('o')
    if ($authenticationContext) {
      try { Publish-RideVmGitHubEvidence -ResultDirectory $runDirectory -RunId $Request.RunId -Token $authenticationContext.Token -Summary $summary }
      catch {
        $summary.Status = 'Failed'; $summary.EvidenceExportError = 'PAT evidence scan failed or was incomplete; export refused.'
      }
      finally { $authenticationContext.Token.Dispose() }
    }
    Write-RideAutomationJson -Path (Join-Path $runDirectory 'result.json') -Value $summary
  }
  [pscustomobject]$summary
}

function Assert-RideAutomationInteractiveEvidence {
  <#
  .SYNOPSIS
  Validate collected interactive guest task and worker evidence on the host.
  .DESCRIPTION
  Read-only validation independent of remoting error propagation. Requires a
  correlated successful worker and task, with completed task removal.
  .PARAMETER Path
  Collected guest result directory.
  .PARAMETER RunId
  Expected controller request ID.
  .OUTPUTS
  None. Throws when evidence is missing, mismatched or unsuccessful.
  .NOTES
  Windows PowerShell 5.1; module version 1.16.0. No guest or task changes.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$RunId)
  $task = Get-Content -LiteralPath (Join-Path $Path 'interactive-task.json') -Raw -ErrorAction Stop | ConvertFrom-Json
  $worker = Get-Content -LiteralPath (Join-Path $Path 'interactive-worker.json') -Raw -ErrorAction Stop | ConvertFrom-Json
  if ($task.RunId -cne $RunId -or $worker.RunId -cne $RunId -or $task.LastTaskResult -ne 0 -or
      $task.TaskRemoved -ne $true -or $task.Error -or $task.CleanupError -or $worker.Status -ne 'Passed' -or $worker.Error -or
      $worker.Context.SID -ne $task.ExpectedUserSid -or $task.ExpectedSessionId -le 0 -or
      $worker.Context.SessionId -ne $task.ExpectedSessionId -or $worker.Context.Elevated -ne $true -or $worker.Context.UserInteractive -ne $true) {
    throw 'Interactive guest evidence is mismatched, incomplete or unsuccessful; inspect task and worker records.'
  }
}

Export-ModuleMember -Function *-RideAutomation*
