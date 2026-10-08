<#
.SYNOPSIS
  Provision and prepare an AutomatedLab VM for RIDE integration testing.

.DESCRIPTION
  - Checks host permissions, Hyper-V availability, AutomatedLab, ISO, storage,
  and NAT state before changing the host or creating a VM.
  - Supports Windows OS entries exposed by Get-LabAvailableOperatingSystem;
  VM memory, processor count, TPM, and Secure Boot settings are configurable.
  RIDE's integration suite has its own narrower supported-target declarations.
  - Uses Invoke-LabCommand for guest connectivity and Pester setup, creates a
  shared-name clean checkpoint, then stages the current checkout (step 6A).
  - Waits for guest Windows Update by default; -WindowsUpdateMode Continue
  proceeds without requiring the update pause.
  - Creates a Hyper-V VM, AutomatedLab NAT network, and clean checkpoint.
  - Installs Pester 5.7.1 in the guest, then copies this checkout to C:\RIDE\ride-windows.

.PARAMETER OperatingSystemName
  Exact unique ISO OS name returned by Get-LabAvailableOperatingSystem; required unless
  PreflightOnly.

.PARAMETER LabName
  Unique lab name, 1-31 letters/digits/hyphens starting with a letter or digit; required unless
  PreflightOnly.

.PARAMETER VMName
  Guest computer name, 1-15 letters/digits/hyphens starting with a letter or digit; required unless
  PreflightOnly.

.PARAMETER VMPath
  Host VM storage path; required unless PreflightOnly. Preflight reports storage headroom.

.PARAMETER GuestRepositoryPath
  Reported guest checkout path; defaults to C:\RIDE\ride-windows. Current staging is hard-coded to
  that default; do not override until fixed.

.PARAMETER MemoryGB
  VM memory in GiB, range 2-64; defaults to 8.

.PARAMETER ProcessorCount
  Virtual processor count, range 1-32; defaults to 4.

.PARAMETER DisableTpm
  Disable TPM in the new guest; otherwise provisioning requests TPM enabled.

.PARAMETER DisableSecureBoot
  Disable Secure Boot in the new guest; otherwise provisioning requests it enabled.

.PARAMETER WindowsUpdateMode
  Wait (default) pauses for operator confirmation of guest updates; Continue preserves the update
  state as-is.

.PARAMETER PreflightOnly
  Inspect host prerequisites and report failures without provisioning; imports AutomatedLab and
  makes a connectivity probe.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\New-RideAutomatedLabVm.ps1 -Version

.EXAMPLE
  Get-Help .\tests\integration\New-RideAutomatedLabVm.ps1 -Full

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.Object. Host preflight/guest diagnostics and completion messages.

.NOTES
  Compatibility: Windows PowerShell 5.1 or PowerShell 7 on a Windows Hyper-V host.
  Prerequisites: - Run elevated or as a Hyper-V Administrators member with an effective token.
  - Hardware virtualization enabled, Hyper-V/VMMS operational, LabSources and
  VM storage available, and enough host disk/memory for the selected guest.
  File/environment inputs: - Exact OS name from Get-LabAvailableOperatingSystem and unique lab/VM
  names.
  - An installed/configured AutomatedLab module and an OS ISO under LabSources\ISOs.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    - 0.1.0: Initial OS-selectable AutomatedLab provisioning workflow.
  Known limitation: nondefault GuestRepositoryPath is not honored by the staging code; documented
  for a separate tested correction.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string] $OperatingSystemName,
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,30}$')]
  [string] $LabName,
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,14}$')]
  [string] $VMName,
  [string] $VMPath,
  [string] $GuestRepositoryPath = 'C:\RIDE\ride-windows',
  [ValidateRange(2, 64)]
  [int] $MemoryGB = 8,
  [ValidateRange(1, 32)]
  [int] $ProcessorCount = 4,
  [switch] $DisableTpm,
  [switch] $DisableSecureBoot,
  [ValidateSet('Wait', 'Continue')]
  [string] $WindowsUpdateMode = 'Wait',
  [switch] $PreflightOnly,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) {
  Write-Output $script:ScriptVersion
  return
}

$ErrorActionPreference = 'Stop'
$snapshotName = 'RIDE-clean-test-base'
$networkName = 'RIDE-Internet'
$checks = [System.Collections.Generic.List[object]]::new()

function Add-PreflightCheck {
  param(
    [string] $Name,
    [bool] $Passed,
    [bool] $Required,
    [string] $Detail
  )

  $checks.Add([pscustomobject]@{
      Name = $Name
      Passed = $Passed
      Required = $Required
      Detail = $Detail
    })
}

function Test-HostAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-PreflightReport {
  $checks | Format-Table Name, Passed, Required, Detail -Wrap -AutoSize | Out-Host
  $failedRequired = @($checks | Where-Object { $_.Required -and -not $_.Passed })
  if ($failedRequired.Count -gt 0) {
    $names = ($failedRequired.Name -join ', ')
    throw "AutomatedLab preflight failed: $names. Review the details above and the Hyper-V troubleshooting section in AUTOMATEDLAB.md."
  }
}

if ($PSVersionTable.PSEdition -notin @('Desktop', 'Core') -or $PSVersionTable.PSVersion.Major -lt 5) {
  throw 'Run this script in Windows PowerShell 5.1 or PowerShell 7 on Windows.'
}
if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
  throw 'AutomatedLab VM provisioning requires a Windows host.'
}

$isAdmin = Test-HostAdministrator
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$hyperVAdministratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-578')
$isHyperVAdministratorsMember = @($identity.Groups | ForEach-Object { $_.Translate([Security.Principal.SecurityIdentifier]) } | Where-Object { $_.Value -eq $hyperVAdministratorsSid.Value }).Count -gt 0
Add-PreflightCheck -Name 'Host privilege context' -Passed ($isAdmin -or $isHyperVAdministratorsMember) -Required $false -Detail $(if ($isAdmin) { 'Current process is elevated.' } elseif ($isHyperVAdministratorsMember) { 'Hyper-V Administrators membership is present; the CIM access check below determines whether it is effective.' } else { 'Neither elevated nor in Hyper-V Administrators. Try elevated PowerShell or add the account to the group, then sign out and back in.' })

if (Get-Module -ListAvailable -Name AutomatedLab) {
  try {
    Import-Module AutomatedLab -ErrorAction Stop
  } catch {
    Add-PreflightCheck -Name 'AutomatedLab module import' -Passed $false -Required $true -Detail $_.Exception.Message
  }
}

$automatedLabCommands = @('Import-Lab', 'Get-LabSourcesLocation', 'Get-LabAvailableOperatingSystem', 'New-LabDefinition', 'Add-LabVirtualNetworkDefinition', 'New-LabNetworkAdapterDefinition', 'Add-LabMachineDefinition', 'Install-Lab', 'Invoke-LabCommand', 'Stop-LabVM', 'Checkpoint-LabVM', 'Get-LabVMSnapshot', 'Start-LabVM', 'Copy-LabFileItem')
$missingAutomatedLabCommands = @($automatedLabCommands | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missingAutomatedLabCommands.Count -eq 0) {
  Add-PreflightCheck -Name 'AutomatedLab commands' -Passed $true -Required $true -Detail 'Required commands are available in the current PowerShell session.'
} else {
  Add-PreflightCheck -Name 'AutomatedLab commands' -Passed $false -Required $true -Detail ("Missing: " + ($missingAutomatedLabCommands -join ', ') + '. Follow the upstream installation guide, then open a new host session.')
}

$getVMHostCommand = Get-Command Get-VMHost -ErrorAction SilentlyContinue
if (-not $getVMHostCommand) {
  Add-PreflightCheck -Name 'Hyper-V management module' -Passed $false -Required $true -Detail 'Get-VMHost is unavailable. Enable/install Hyper-V management tools on this host.'
} else {
  try {
    $null = Get-VMHost -ErrorAction Stop
    Add-PreflightCheck -Name 'Hyper-V CIM access' -Passed $true -Required $true -Detail 'Get-VMHost succeeded for the current token.'
  } catch {
    $permissionMessage = 'Get-VMHost failed: ' + $_.Exception.Message
    if ($permissionMessage -match 'access|denied|CIM resource') {
      $permissionMessage += ' Try elevated PowerShell. Alternatively add the account to Hyper-V Administrators and sign out/in, then rerun. Hyper-V Manager is a partial manual workaround, but AutomatedLab needs CIM access.'
    }
    Add-PreflightCheck -Name 'Hyper-V CIM access' -Passed $false -Required $true -Detail $permissionMessage
  }
}

$vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
Add-PreflightCheck -Name 'Hyper-V Virtual Machine Management service' -Passed ([bool]($vmms -and $vmms.Status -eq 'Running')) -Required $true -Detail $(if ($vmms) { "Status: $($vmms.Status)." } else { 'VMMS service is not installed; enable the Hyper-V role/feature and reboot if required.' })

try {
  $labSources = Get-LabSourcesLocation
  $isoDirectory = Join-Path $labSources 'ISOs'
  $availableOperatingSystems = @(Get-LabAvailableOperatingSystem -Path $isoDirectory)
  Add-PreflightCheck -Name 'AutomatedLab LabSources' -Passed (Test-Path -LiteralPath $isoDirectory -PathType Container) -Required $true -Detail "ISO directory: $isoDirectory; available OS entries: $($availableOperatingSystems.Count)."
} catch {
  $labSources = $null
  $availableOperatingSystems = @()
  Add-PreflightCheck -Name 'AutomatedLab LabSources' -Passed $false -Required $true -Detail $_.Exception.Message
}

if ($OperatingSystemName) {
  $matchedOperatingSystem = @($availableOperatingSystems | Where-Object { $_.OperatingSystemName -eq $OperatingSystemName })
  Add-PreflightCheck -Name 'Selected OS ISO' -Passed ($matchedOperatingSystem.Count -eq 1) -Required $true -Detail $(if ($matchedOperatingSystem.Count -eq 1) { "Found exact OS entry '$OperatingSystemName'." } else { "No unique exact match for '$OperatingSystemName'. Choose a listed value from Get-LabAvailableOperatingSystem -Path '$isoDirectory'." })
}

if ($VMPath) {
  try {
    $fullVMPath = [System.IO.Path]::GetFullPath($VMPath)
    $rootPath = [System.IO.Path]::GetPathRoot($fullVMPath)
    $drive = Get-PSDrive -Name $rootPath.Substring(0, 1) -ErrorAction Stop
    $freeGB = [math]::Round($drive.Free / 1GB, 1)
    $hasStorageHeadroom = $freeGB -ge 120
    Add-PreflightCheck -Name 'VM storage path' -Passed ((Test-Path -LiteralPath $rootPath -PathType Container) -and $hasStorageHeadroom) -Required $false -Detail "$fullVMPath; $freeGB GB free on $rootPath. 120 GB or more is recommended for the ISO and VM files."
  } catch {
    Add-PreflightCheck -Name 'VM storage path' -Passed $false -Required $true -Detail $_.Exception.Message
  }
}

try {
  $existingNats = @(Get-NetNat -ErrorAction Stop)
  $natDetail = if ($existingNats.Count -eq 0) { 'No host WinNAT networks found.' } else { 'Existing host WinNAT networks: ' + (($existingNats | ForEach-Object { "$($_.Name) [$($_.InternalIPInterfaceAddressPrefix)]" }) -join '; ') + '. Review for overlap before creating AutomatedLab NAT.' }
  Add-PreflightCheck -Name 'Host WinNAT state' -Passed $true -Required $false -Detail $natDetail
} catch {
  Add-PreflightCheck -Name 'Host WinNAT state' -Passed $false -Required $false -Detail ('Could not inspect WinNAT: ' + $_.Exception.Message)
}

try {
  $hostCanReachGallery = Test-NetConnection -ComputerName 'www.powershellgallery.com' -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue
  Add-PreflightCheck -Name 'Host outbound HTTPS' -Passed ([bool]$hostCanReachGallery) -Required $true -Detail 'PowerShell Gallery TCP 443 connectivity is required for guest dependency setup.'
} catch {
  Add-PreflightCheck -Name 'Host outbound HTTPS' -Passed $false -Required $true -Detail $_.Exception.Message
}

if ($PreflightOnly) {
  Show-PreflightReport
  return
}

foreach ($requiredValue in @(@{ Name = 'OperatingSystemName'; Value = $OperatingSystemName }, @{ Name = 'LabName'; Value = $LabName }, @{ Name = 'VMName'; Value = $VMName }, @{ Name = 'VMPath'; Value = $VMPath })) {
  if ([string]::IsNullOrWhiteSpace($requiredValue.Value)) { throw "-$($requiredValue.Name) is required unless -PreflightOnly is used." }
}
if ([string]::IsNullOrWhiteSpace($GuestRepositoryPath) -or $GuestRepositoryPath -match '^[A-Za-z]:\\?$') {
  throw '-GuestRepositoryPath must identify a guest directory below a drive root.'
}
if ($VMName.Length -gt 15) { throw 'AutomatedLab guest computer names must be 15 characters or fewer.' }
if (@($availableOperatingSystems | Where-Object { $_.OperatingSystemName -eq $OperatingSystemName }).Count -ne 1) { throw "Operating system '$OperatingSystemName' is not a unique available ISO entry." }
Show-PreflightReport

$repoRootOutput = & git -C $PSScriptRoot rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0 -or -not $repoRootOutput) { throw 'Could not resolve the RIDE-Windows checkout with git rev-parse.' }
$repoPath = $repoRootOutput.Trim()
foreach ($requiredPath in @('tools/validate.ps1', 'tools/Export-RideCatalog.ps1', 'tests/Catalog.Tests.ps1')) {
  if (-not (Test-Path -LiteralPath (Join-Path $repoPath $requiredPath) -PathType Leaf)) { throw "'$repoPath' is not a RIDE-Windows checkout; missing '$requiredPath'." }
}

$action = "create '$VMName' for '$OperatingSystemName', install Pester, create '$snapshotName', and copy the current checkout"
if (-not $PSCmdlet.ShouldProcess("AutomatedLab '$LabName' on this Hyper-V host", $action)) { return }

$installationCredential = Get-Credential -Message 'Choose a local administrator account for the disposable guest'
New-LabDefinition -Name $LabName -DefaultVirtualizationEngine HyperV -VmPath $VMPath
Add-LabVirtualNetworkDefinition -Name $networkName -UseNat
$networkAdapter = New-LabNetworkAdapterDefinition -VirtualSwitch $networkName
Add-LabMachineDefinition -Name $VMName `
  -OperatingSystem $OperatingSystemName `
  -Memory ([long]$MemoryGB * 1GB) `
  -Processors $ProcessorCount `
  -InstallationUserCredential $installationCredential `
  -HypervProperties @{
    EnableTpm = if ($DisableTpm) { 'false' } else { 'true' }
    EnableSecureBoot = if ($DisableSecureBoot) { 'off' } else { 'on' }
  } `
  -NetworkAdapter $networkAdapter

Install-Lab
Show-LabDeploymentSummary

if ($WindowsUpdateMode -eq 'Wait') {
  Write-Host 'Complete Windows Update in the guest, including required restarts, then return here and press Enter.'
  $null = Read-Host 'Press Enter after Windows Update reports no further updates'
} else {
  Write-Warning 'Continuing without confirming Windows Update. The clean checkpoint will preserve the guest update state as-is.'
}

Invoke-LabCommand -ComputerName $VMName -Retries 20 -RetryIntervalInSeconds 30 -ScriptBlock {
  $ErrorActionPreference = 'Stop'
  Get-NetIPConfiguration
  $connection = Test-NetConnection www.powershellgallery.com -Port 443
  $connection
  if (-not $connection.TcpTestSucceeded) { throw 'The guest could not connect to PowerShell Gallery over HTTPS.' }
} -PassThru

Invoke-LabCommand -ComputerName $VMName -ScriptBlock {
  $ErrorActionPreference = 'Stop'
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'AutomatedLab remote commands are not running with guest administrator rights. Correct the guest setup account or install Pester in an elevated guest session.'
  }
  Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force
  Install-Module -Name Pester -RequiredVersion '5.7.1' -Repository PSGallery -Scope CurrentUser -Force -SkipPublisherCheck
  $pester = Get-Module Pester -ListAvailable | Where-Object Version -eq '5.7.1'
  if (-not $pester) { throw 'Pester 5.7.1 was not found after installation.' }
  $pester | Select-Object Name, Version, Path
} -PassThru

Stop-LabVM -ComputerName $VMName -Wait
Checkpoint-LabVM -ComputerName $VMName -SnapshotName $snapshotName
Get-LabVMSnapshot -ComputerName $VMName
Start-LabVM -ComputerName $VMName

Invoke-LabCommand -ComputerName $VMName -Retries 20 -RetryIntervalInSeconds 30 -ScriptBlock {
  New-Item -ItemType Directory -Path 'C:\RIDE' -Force | Out-Null
}
Copy-LabFileItem -Path $repoPath -ComputerName $VMName -DestinationFolderPath 'C:\RIDE' -Recurse
$checkoutPresent = Invoke-LabCommand -ComputerName $VMName -ScriptBlock {
  Test-Path 'C:\RIDE\ride-windows\tools\validate.ps1'
} -PassThru
if (-not ($checkoutPresent -contains $true)) { throw 'The checkout copy did not pass the guest verification at runbook step 6A.' }

Write-Output "AutomatedLab VM '$VMName' is ready. Clean checkpoint: '$snapshotName'. Current checkout copied to '$GuestRepositoryPath'."
