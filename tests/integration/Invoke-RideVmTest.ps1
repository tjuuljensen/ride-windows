# Purpose:
#   Stage this checkout in a disposable Windows VM and run RIDE validation,
#   Pester, and optionally the real-Windows integration suite.
#
# Behavior:
#   - Supports AutomatedLab and PowerShell Direct transports.
#   - Uses ShouldProcess before staging files or running guest commands.
#   - Removes its temporary host staging directory after the run.
#
# Compatibility:
#   Windows PowerShell 5.1 or PowerShell 7 on Windows with Hyper-V management
#   support; the guest must be Windows 11 or Windows Server 2025.
#
# Usage:
#   .\tests\integration\Invoke-RideVmTest.ps1 -Transport AutomatedLab -LabName <name> [-VMName <name>] [-UnitOnly] [-WhatIf]
#   .\tests\integration\Invoke-RideVmTest.ps1 -Transport PowerShellDirect [-VMName <name>] [-UnitOnly] [-WhatIf]
#   .\tests\integration\Invoke-RideVmTest.ps1 -Version
#
# Inputs / environment:
#   - Transport, optional lab/VM names and checkout/guest paths, and UnitOnly.
#   - PowerShell Direct prompts for a guest administrator credential.
#
# Outputs / side effects:
#   - Copies the working tree to the guest and runs validation and Pester.
#   - Unless UnitOnly is set, changes guest Windows state and installs/removes
#     packages; restore the guest's clean checkpoint after the run.
#
# Prerequisites:
#   - Host access to the selected VM transport; Pester 5.7.1 in the guest.
#   - AutomatedLab commands for AutomatedLab transport, or a configured
#     PowerShell Direct-capable Hyper-V VM.
#
# Author:
#   RIDE-Windows maintainers.
#
# Version:
#   0.1.0
#
# Changelog:
#   - 0.1.0: Initial versioned VM test runner.
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidateSet('AutomatedLab', 'PowerShellDirect')]
  [string] $Transport,

  [string] $LabName,
  [string] $VMName = 'RIDE-Win11-Test',
  [string] $RepositoryPath,
  [string] $GuestRepositoryPath = 'C:\RIDE\ride-windows',
  [switch] $UnitOnly,

  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) {
  Write-Output $script:ScriptVersion
  return
}

if (-not $Transport) {
  throw "Specify -Transport as 'AutomatedLab' or 'PowerShellDirect'."
}

$ErrorActionPreference = 'Stop'

if ($Transport -eq 'AutomatedLab' -and -not $LabName) {
  throw "-LabName is required when -Transport is 'AutomatedLab'."
}

if (-not $RepositoryPath) {
  $RepositoryPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
}
$resolvedRepositoryPath = (Resolve-Path -LiteralPath $RepositoryPath).Path
foreach ($requiredPath in @('tools/validate.ps1', 'tools/Export-RideCatalog.ps1', 'tests/Catalog.Tests.ps1')) {
  if (-not (Test-Path -LiteralPath (Join-Path $resolvedRepositoryPath $requiredPath) -PathType Leaf)) {
    throw "'$resolvedRepositoryPath' is not a RIDE-Windows checkout; missing '$requiredPath'."
  }
}

if ([string]::IsNullOrWhiteSpace($GuestRepositoryPath) -or $GuestRepositoryPath -match '^[A-Za-z]:\\?$') {
  throw '-GuestRepositoryPath must identify a guest directory below a drive root.'
}

$runIntegration = -not $UnitOnly
$action = if ($runIntegration) { 'copy the checkout and run validation, Pester, and VM integration tests' } else { 'copy the checkout and run validation and Pester' }
if (-not $PSCmdlet.ShouldProcess("$VMName via $Transport", $action)) { return }

$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ride-vm-test-' + [guid]::NewGuid().ToString('N'))
$stagedRepository = Join-Path $stageRoot 'ride-windows'
$session = $null

try {
  New-Item -ItemType Directory -Path $stagedRepository -Force | Out-Null
  Get-ChildItem -LiteralPath $resolvedRepositoryPath -Force |
    Where-Object { $_.Name -notin @('.git', 'testResults.xml') } |
    ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $stagedRepository -Recurse -Force }

  $remoteTest = {
    param(
      [string] $GuestPath,
      [bool] $RunIntegration
    )

    $ErrorActionPreference = 'Stop'
    Set-Location -LiteralPath $GuestPath

    Import-Module Pester -RequiredVersion '5.7.1' -ErrorAction Stop
    & .\tools\Export-RideCatalog.ps1
    & .\tools\validate.ps1

    $pesterResult = Invoke-Pester -Path .\tests -PassThru
    if ($pesterResult.FailedCount -gt 0) {
      throw "Pester reported $($pesterResult.FailedCount) failing test(s)."
    }
    Write-Output ("Pester passed: {0} test(s)." -f $pesterResult.PassedCount)

    if ($RunIntegration) {
      $env:RIDE_INTEGRATION_VM = '1'
      & .\tests\integration\Invoke-RideVmSuite.ps1
    }
    else {
      Write-Output 'VM integration suite skipped by -UnitOnly.'
    }
  }

  if ($Transport -eq 'AutomatedLab') {
    if (-not (Get-Command Import-Lab -ErrorAction SilentlyContinue) -or -not (Get-Command Copy-LabFileItem -ErrorAction SilentlyContinue)) {
      throw 'AutomatedLab commands are unavailable. Install/import AutomatedLab or select -Transport PowerShellDirect.'
    }

    Import-Lab -Name $LabName
    Invoke-LabCommand -ComputerName $VMName -ScriptBlock {
      param([string] $Path)
      New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    } -ArgumentList $GuestRepositoryPath | Out-Null

    Copy-LabFileItem -Path $stagedRepository -ComputerName $VMName -DestinationFolderPath (Split-Path -Parent $GuestRepositoryPath) -Recurse
    Invoke-LabCommand -ComputerName $VMName -ScriptBlock $remoteTest -ArgumentList @($GuestRepositoryPath, [bool]$runIntegration) -PassThru
  }
  else {
    $credential = Get-Credential -Message "Enter the local administrator account for guest VM '$VMName'."
    $session = New-PSSession -VMName $VMName -Credential $credential
    Invoke-Command -Session $session -ScriptBlock {
      param([string] $Path)
      New-Item -ItemType Directory -Path $Path -Force | Out-Null
    } -ArgumentList $GuestRepositoryPath | Out-Null

    Copy-Item -Path (Join-Path $stagedRepository '*') -Destination $GuestRepositoryPath -ToSession $session -Recurse -Force
    Invoke-Command -Session $session -ScriptBlock $remoteTest -ArgumentList @($GuestRepositoryPath, [bool]$runIntegration)
  }

  Write-Output "RIDE VM test completed on '$VMName'. Restore the VM's clean checkpoint before its next integration run."
}
finally {
  if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
  if (Test-Path -LiteralPath $stageRoot) { Remove-Item -LiteralPath $stageRoot -Recurse -Force }
}
