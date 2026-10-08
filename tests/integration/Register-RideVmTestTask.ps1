<#
.SYNOPSIS
  Register or remove an opt-in elevated controller for a disposable RIDE VM.

.DESCRIPTION
  - Requires elevated setup with host UAC enabled; does not repair host policies.
  - Installs a fixed worker and runner outside the checkout and captures evidence.
  Creates protected controller files and a highest-privilege interactive task.
  Removal deletes only the task, preserving configuration and results.

.PARAMETER ConfigurationPath
  Seed PSD1 for registration, or installed configuration.json for removal. Required for operational
  use.

.PARAMETER Action
  Register (default) installs/updates the fixed controller; Remove unregisters its idle task while
  retaining files/results.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Register-RideVmTestTask.ps1 -Version

.EXAMPLE
  .\tests\integration\Register-RideVmTestTask.ps1 -ConfigurationPath .\tests\integration\automation.example.psd1 -WhatIf

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Registration/removal status; controller configuration, evidence, ACLs, and task are
  material side effects.

.NOTES
  Compatibility: 64-bit Windows PowerShell 5.1, AutomatedLab 5.61.0 on a Windows Hyper-V host.
  Prerequisites: Existing disposable lab, clean checkpoint, ISO file and prepared host remoting.
  File/environment inputs: Configuration PSD1 for registration; installed configuration JSON for
  removal.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    - 0.1.0: Initial task registration and configuration evidence.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string] $ConfigurationPath,
  [ValidateSet('Register', 'Remove')][string] $Action = 'Register',
  [switch] $Version
)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -Force
if (-not $ConfigurationPath) { throw '-ConfigurationPath is required. See automation.example.psd1.' }
$config = Read-RideAutomationConfiguration $ConfigurationPath
$root = Get-RideAutomationRoot $config.Name
$installedConfiguration = Join-Path $root 'configuration.json'
Assert-RideAutomationDirectory $root
if (-not (Test-RideAutomationAdministrator)) { throw 'Run registration/removal in elevated PowerShell. Do not disable UAC.' }
$existing = Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name -ErrorAction SilentlyContinue
if ($existing -and $existing.Description -ne "RIDE disposable VM test controller: $installedConfiguration") { throw 'A task with this name already exists and is not owned by this configuration.' }
if ($existing -and $existing.State -eq 'Running') { throw 'Wait for the current test task to finish before registration/removal.' }
if (-not $PSCmdlet.ShouldProcess("$($config.Name) ($root)", "$Action the RIDE VM test task")) { return }
if ($Action -eq 'Remove') {
  if ($existing) { Unregister-ScheduledTask -TaskPath '\RIDE\' -TaskName $config.Name -Confirm:$false }
  Write-Output "Task removed. Configuration and results retained at '$root'. Stop the watcher/CI runner separately."
  return
}
$uac = Assert-RideAutomationHost
$target = Import-RideAutomationLab $config
$controllerBase = Split-Path -Parent $root
if (Test-Path -LiteralPath $controllerBase) {
  foreach ($directory in Get-ChildItem -LiteralPath $controllerBase -Directory) {
    $otherPath = Join-Path $directory.FullName 'configuration.json'
    if ($directory.Name -ne $config.Name -and (Test-Path -LiteralPath $otherPath)) {
      $other = Get-Content -LiteralPath $otherPath -Raw | ConvertFrom-Json
      if ($other.VMId -eq $config.VMId) { throw 'Use one controller configuration per VM to preserve serialization and cleanup blocking.' }
    }
  }
}
if (-not $config.IsoPath -or -not (Test-Path -LiteralPath $config.IsoPath -PathType Leaf)) { throw 'IsoPath must identify the ISO used to provision this guest.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$config = [ordered]@{
  SchemaVersion = 1; Name = $config.Name; IsDisposable = $true
  LabName = $config.LabName; VMName = $config.VMName; VMId = $target.VM.Id.ToString()
  CheckpointName = $config.CheckpointName; CheckpointId = $target.Snapshot.Id.ToString()
  GuestRepositoryPath = $config.GuestRepositoryPath
  LocalRepositoryPath = $config.LocalRepositoryPath; CIRepositoryPath = $config.CIRepositoryPath
  HostAccount = $identity.Name; HostAccountSid = $identity.User.Value
  IsoPath = (Resolve-Path -LiteralPath $config.IsoPath).Path
  IsoSHA256 = (Get-FileHash -LiteralPath $config.IsoPath -Algorithm SHA256).Hash
  DependencyVersions = @(Get-Module | Where-Object { $_.Name -like 'AutomatedLab*' -or $_.Name -in @('Pester', 'PSFramework', 'PSLog', 'PSFileTransfer', 'powershell-yaml', 'SHiPS') } | Sort-Object Name | ForEach-Object { @{ Name = $_.Name; Version = $_.Version.ToString() } })
}

function Set-ControllerDirectoryAccess {
  param([string] $Path, [switch] $Writable)
  $acl = [Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true, $false)
  $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', $inheritance, 'None', 'Allow'))
  }
  $rights = if ($Writable) { 'Modify' } else { 'ReadAndExecute' }
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity.User, $rights, $inheritance, 'None', 'Allow'))
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

New-Item -ItemType Directory -Path $root -Force | Out-Null
Set-ControllerDirectoryAccess $root
foreach ($folder in @('bin', 'runtime', 'queue', 'queue\pending', 'queue\running', 'queue\finished', 'results')) {
  $path = Join-Path $root $folder
  Assert-RideAutomationDirectory $path
  New-Item -ItemType Directory -Path $path -Force | Out-Null
  Set-ControllerDirectoryAccess $path -Writable:($folder -ne 'bin')
}
foreach ($file in @('RIDE.TestAutomation.psm1', 'Invoke-RideVmTestTaskWorker.ps1', 'Invoke-RideVmTest.ps1', 'Invoke-RideVmTestTask.ps1', 'Export-RideVmTestEvidence.ps1')) {
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $root "bin\$file") -Force
}
Write-RideAutomationJson -Path $installedConfiguration -Value $config
$vm = $target.VM
$evidence = @{
  SchemaVersion = 1; CapturedAtUtc = [datetime]::UtcNow.ToString('o'); ValidationStatus = 'NotValidated'
  Host = @{ Account = $identity.Name; OS = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber); PowerShell = $PSVersionTable.PSVersion.ToString(); Uac = $uac }
  VM = @{ Name = $vm.Name; Id = $vm.Id.ToString(); Generation = $vm.Generation; Version = $vm.Version.ToString(); MemoryStartup = $vm.MemoryStartup; ProcessorCount = $vm.ProcessorCount; Firmware = (Get-VMFirmware -VM $vm | Select-Object SecureBoot, SecureBootTemplate); Security = (Get-VMSecurity -VM $vm | Select-Object TpmEnabled); Network = @(Get-VMNetworkAdapter -VM $vm | Select-Object Name, SwitchName, MacAddress) }
  Checkpoint = @{ Id = $target.Snapshot.Id.ToString(); Name = $target.Snapshot.Name; CreationTime = $target.Snapshot.CreationTime.ToUniversalTime().ToString('o') }
  ISO = @{ Path = $config.IsoPath; SHA256 = $config.IsoSHA256 }; Dependencies = $config.DependencyVersions
  ControllerFiles = @(Get-ChildItem -LiteralPath (Join-Path $root 'bin') -File | ForEach-Object { @{ Name = $_.Name; SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } })
}
Write-RideAutomationJson -Path (Join-Path $root 'evidence.json') -Value $evidence
$taskService = New-Object -ComObject 'Schedule.Service'
$taskService.Connect()
$folderSddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;$($identity.User.Value))"
try { $null = $taskService.GetFolder('\RIDE') }
catch { $null = $taskService.GetFolder('\').CreateFolder('RIDE', $folderSddl) }
$parameters = Get-RideAutomationTaskParameters -Configuration ([pscustomobject]$config) -ConfigurationPath $installedConfiguration
Register-ScheduledTask @parameters -Force | Out-Null
$taskService.GetFolder('\RIDE').GetTask($config.Name).SetSecurityDescriptor($folderSddl, 0)
Write-Output "Task registered for '$($identity.Name)' (signed in or locked). Configuration: $installedConfiguration"
Write-Output 'Configuration is not yet validated. Follow the pilot acceptance checklist before cutover.'
