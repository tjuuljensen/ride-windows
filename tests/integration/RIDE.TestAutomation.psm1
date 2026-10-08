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
  Recovery: Follow AUTOMATEDLAB-TASKS.md for blocked requests; the fixed worker restores only its
  pinned disposable VM/checkpoint.
  Author: RIDE-Windows maintainers.
  Version: 0.1.2
  Changelog:
    - 0.1.2: Retain redirected child-process handles for reliable exit-code reporting.
  - 0.1.1: Start the pinned VM through Hyper-V's supported VM-object parameter.
  - 0.1.0: Initial opt-in task orchestration helpers.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

#>


$script:ModuleVersion = '0.1.2'

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
  if ($config.SchemaVersion -ne 1 -or $config.IsDisposable -ne $true) { throw 'SchemaVersion 1 and IsDisposable = true are required.' }
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

function Write-RideAutomationJson {
  <#
  .SYNOPSIS
    Atomically replace a controller JSON file.

  .DESCRIPTION
    Serializes at depth 15 to a unique sibling temporary file, then renames over the destination.
    Cleans the temporary file in finally; the parent must exist.

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
    $Value | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
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
    Runs taskkill /PID /T /F for the supplied process. Throws when taskkill fails and the process
    remains alive. Internal destructive timeout recovery helper.

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
  & "$env:SystemRoot\System32\taskkill.exe" /PID $Process.Id /T /F | Out-Null
  if ($LASTEXITCODE -ne 0 -and -not $Process.HasExited) { throw 'Could not terminate the timed-out controller. VM recovery is required.' }
}

function Save-RideAutomationFailureEvidence {
  <#
  .SYNOPSIS
    Launch bounded partial-evidence collection before VM reset.

  .DESCRIPTION
    Starts the installed collector in hidden 64-bit Windows PowerShell, redirects logs, retains the
    process handle, and waits at most 60 seconds. Terminates a timed-out process tree; failure does
    not itself reset the VM.

  .PARAMETER Root
    Controller root returned by Get-RideAutomationRoot for this registered configuration.

  .PARAMETER RunId
    Saved run or correlated request identifier, as required by this command.

  .PARAMETER ResultDirectory
    Existing correlated host result directory for collector logs and guest exports.

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

  param([string] $Root, [string] $RunId, [string] $ResultDirectory)
  # A separate bounded collector ensures broken remoting cannot prevent VM reset.
  $arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$(Join-Path $Root 'bin\Export-RideVmTestEvidence.ps1')`" -ConfigurationPath `"$(Join-Path $Root 'configuration.json')`" -RunId $RunId -ResultDirectory `"$ResultDirectory`""
  $collector = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $ResultDirectory 'collection.log') -RedirectStandardError (Join-Path $ResultDirectory 'collection-errors.log')
  # Windows PowerShell 5.1 needs the handle retained before a redirected child exits.
  $null = $collector.Handle
  if (-not $collector.WaitForExit(60000)) { Stop-RideAutomationProcess $collector; throw 'Partial-evidence collection timed out after 60 seconds.' }
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

function Get-RideAutomationUac {
  <#
  .SYNOPSIS
    Read the host UAC settings used by controller guards.

  .DESCRIPTION
    Reads EnableLUA, ConsentPromptBehaviorAdmin, and PromptOnSecureDesktop. Does not write policy.

  .EXAMPLE
    Get-Help Get-RideAutomationUac -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Selected UAC values.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  $value = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
  [pscustomobject]@{ EnableLUA = $value.EnableLUA; ConsentPromptBehaviorAdmin = $value.ConsentPromptBehaviorAdmin; PromptOnSecureDesktop = $value.PromptOnSecureDesktop }
}

function Assert-RideAutomationHost {
  <#
  .SYNOPSIS
    Validate the prepared elevated controller host without policy repair.

  .DESCRIPTION
    Requires 64-bit Windows PowerShell 5.1, elevation, enabled UAC prompting, running VMMS/WinRM,
    Hyper-V access, pinned AutomatedLab versions, optional dependency versions, and existing host
    remoting configuration. Imports pinned modules; does not repair policies or start stopped
    services.

  .PARAMETER Configuration
    Optional installed configuration for dependency-version drift checks; omit during initial
    registration.

  .EXAMPLE
    Get-Help Assert-RideAutomationHost -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. UAC values after successful validation.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([object] $Configuration)
  if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1 for the controller.' }
  if (-not (Test-RideAutomationAdministrator)) { throw 'The controller needs an elevated process. Register the highest-privilege task from elevated PowerShell; keep UAC enabled.' }
  $uac = Get-RideAutomationUac
  if ($uac.EnableLUA -ne 1 -or $uac.ConsentPromptBehaviorAdmin -eq 0 -or $uac.PromptOnSecureDesktop -ne 1) { throw 'Host UAC must be enabled with consent/credential prompting on the secure desktop. See AUTOMATEDLAB-TASKS.md; no policies were changed.' }
  foreach ($name in @('vmms', 'WinRM')) {
    if ((Get-Service -Name $name -ErrorAction Stop).Status -ne 'Running') { throw "$name must already be running. Prepare the host in an elevated session; no services were started." }
  }
  $null = Get-VMHost -ErrorAction Stop
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
  $uac
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
      if ($item.Name -in @('.git', '.vs', '.codex', '.agents', '.aws', 'testResults.xml', 'TestResults', 'results', 'node_modules', 'config.ini', 'serials.ini', 'private.preset') -or $item.Name -like '*.private.preset') { continue }
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
    submission timestamp.

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

function Invoke-RideAutomationRequest {
  <#
  .SYNOPSIS
    Run one correlated test request and recover its disposable VM.

  .DESCRIPTION
    Validates prepared host/target, stages an approved checkout, resets/starts the pinned VM, runs
    the installed controller with bounded remaining timeout, and verifies correlated guest evidence.
    Collects failure evidence and restores the checkpoint in finally; cleanup failures create a
    block marker. Writes result.json and verifies UAC stayed unchanged.

  .PARAMETER Configuration
    Validated disposable-VM controller configuration, including pinned VM and checkpoint identity.

  .PARAMETER Request
    Correlated request with RunId, Source, UnitOnly, TimeoutMinutes, and SubmittedAtUtc.

  .PARAMETER Root
    Controller root returned by Get-RideAutomationRoot for this registered configuration.

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

  param([object] $Configuration, [object] $Request, [string] $Root)
  Assert-RideAutomationRequest $Request
  $runDirectory = Join-Path $Root "results\$($Request.RunId)"
  Assert-RideAutomationDirectory $runDirectory
  New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
  $summary = [ordered]@{ SchemaVersion = 1; RunId = $Request.RunId; Source = $Request.Source; UnitOnly = $Request.UnitOnly; Status = 'Failed'; StartedAtUtc = [datetime]::UtcNow.ToString('o'); FinishedAtUtc = $null; Error = $null; CleanupError = $null; CollectionError = $null; UacBefore = $null; UacAfter = $null }
  $touchedVm = $false
  try {
    if (Test-Path -LiteralPath (Join-Path $Root 'runtime\blocked.json')) { throw 'VM cleanup is blocked. Follow the recovery runbook before submitting another run.' }
    $summary.UacBefore = Assert-RideAutomationHost $Configuration
    $null = Import-RideAutomationLab $Configuration
    if (([datetime]::UtcNow - [datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).TotalMinutes -ge $Request.TimeoutMinutes) { throw 'Request expired while waiting in the queue.' }
    $source = if ($Request.Source -eq 'CI') { $Configuration.CIRepositoryPath } else { $Configuration.LocalRepositoryPath }
    $snapshotPath = Join-Path $runDirectory 'snapshot\ride-windows'
    $manifest = @(Copy-RideAutomationSnapshot -Source $source -Destination $snapshotPath)
    Write-RideAutomationJson -Path (Join-Path $runDirectory 'source-files.json') -Value $manifest
    if (([datetime]::UtcNow - [datetime]::Parse($Request.SubmittedAtUtc).ToUniversalTime()).TotalMinutes -ge $Request.TimeoutMinutes) { throw 'Request expired while staging the checkout.' }
    $touchedVm = $true
    Reset-RideAutomationVm $Configuration
    Start-VM -VM (Get-VM -Id ([guid]$Configuration.VMId) -ErrorAction Stop) -ErrorAction Stop | Out-Null
    $arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$(Join-Path $Root 'bin\Invoke-RideVmTest.ps1')`" -Transport AutomatedLab -LabName `"$($Configuration.LabName)`" -VMName `"$($Configuration.VMName)`" -RepositoryPath `"$snapshotPath`" -GuestRepositoryPath `"$($Configuration.GuestRepositoryPath)`" -ResultDirectory `"$runDirectory`" -RunId $($Request.RunId)"
    if ($Request.UnitOnly) { $arguments += ' -UnitOnly' }
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
    $guest = Get-Content -LiteralPath (Join-Path $runDirectory 'guest\summary.json') -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($guest.RunId -ne $Request.RunId -or $guest.Status -ne 'Passed' -or $guest.Pester.Total -lt 1 -or $guest.Pester.Failed -ne 0 -or -not $guest.ValidationPassed -or (-not $Request.UnitOnly -and -not $guest.IntegrationPassed)) { throw 'Guest result is missing, mismatched, incomplete or unsuccessful.' }
    if (-not (Test-Path -LiteralPath (Join-Path $runDirectory 'guest\pester.xml') -PathType Leaf)) { throw 'Guest Pester XML is missing.' }
    $summary.Status = 'Passed'
  }
  catch { $summary.Error = $_.Exception.Message }
  finally {
    if ($touchedVm) {
      if ($summary.Status -ne 'Passed') {
        try { Save-RideAutomationFailureEvidence -Root $Root -RunId $Request.RunId -ResultDirectory $runDirectory }
        catch { $summary.CollectionError = $_.Exception.Message }
      }
      try { Reset-RideAutomationVm $Configuration }
      catch {
        $summary.Status = 'Failed'
        $summary.CleanupError = $_.Exception.Message
        Write-RideAutomationJson -Path (Join-Path $Root 'runtime\blocked.json') -Value @{ RunId = $Request.RunId; Error = $summary.CleanupError }
      }
    }
    try {
      $summary.UacAfter = Get-RideAutomationUac
      if ($summary.UacBefore -and (ConvertTo-Json $summary.UacBefore -Compress) -ne (ConvertTo-Json $summary.UacAfter -Compress)) { $summary.Status = 'Failed'; $summary.Error = 'Host UAC settings changed during the run.' }
    }
    catch { $summary.Status = 'Failed'; $summary.Error = "Cannot verify host UAC after execution: $($_.Exception.Message)" }
    $summary.FinishedAtUtc = [datetime]::UtcNow.ToString('o')
    Write-RideAutomationJson -Path (Join-Path $runDirectory 'result.json') -Value $summary
  }
  [pscustomobject]$summary
}

Export-ModuleMember -Function *-RideAutomation*
