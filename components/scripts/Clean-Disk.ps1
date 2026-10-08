<#
.SYNOPSIS
  Clear Windows Update downloads and run configured Windows disk cleanup.

.DESCRIPTION
  Legacy VM cleanup helper. Operational invocation self-elevates, stops Windows Update/BITS, removes
  SoftwareDistribution download contents, restarts services, writes cleanmgr flags, runs cleanup,
  then removes flags. Has no WhatIf or exact restore and may leave intermediate state after failure.
  Use only in a disposable VM.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\components\scripts\Clean-Disk.ps1 -Help

.EXAMPLE
  .\components\scripts\Clean-Disk.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Progress and diagnostic messages.

.NOTES
  Compatibility: Historical Windows 10/11 helper; this walkthrough does not establish current
  integration support.
  Prerequisites: Disposable Windows VM, elevation, cleanmgr.exe, and Windows Update/BITS services.
  File/environment inputs: SystemDrive Windows Update download cache and HKLM VolumeCaches settings.
  Recovery: Restore a clean VM checkpoint. Deleted update downloads and disk-cleanup data have no
  script rollback.
  Error-handling exception: Existing operational error policy is retained; globally enabling Stop
  requires a separate tested change.
  Author: Torsten Juul-Jensen.
  Version: 1.1.0
  Changelog:
    1.1.0: Add read-only help/version entry points and document cleanup limitations.
    1.0: Previously recorded cleanup version dated 2022-12-28.

.LINK
  https://github.com/tjuuljensen/ride-windows/tree/master/components/scripts

#>


[CmdletBinding()]
param(
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '1.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}

function CleanLocalWindowsUpdateCache{
  Write-Output "###"
  Write-Output "Clean Windows Update cache..."
  # Stop Service wuauserv (Windows Update Service)
  # Stop bits (Background Intelligent Transfer Service)
  Get-Service -Name "wuauserv" | Stop-Service
  Get-Service -Name "bits" | Stop-Service
  Remove-Item ("$($env:SystemDrive)"+"\Windows\SoftwareDistribution\Download\*") -recurse -force
  Get-Service -Name "wuauserv" | Start-Service
  Get-Service -Name "bits" | Start-Service
}


function RunDiskCleanup{
    Write-Output "###"
    Write-Output "Disk cleanup..."

    $strKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
    $strValueName = "StateFlags0001"

    $subkeys = Get-ChildItem -Path HKLM:\$strKeyPath -Name

    ForEach ($subkey in $subkeys) {
        If($subkey -ne "DownloadsFolder") {
            New-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -PropertyType DWORD -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
 
    # run cleanmgr.exe
    Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
 
    ForEach ($subkey in $subkeys) {
        Remove-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -ErrorAction SilentlyContinue | Out-Null
    }
}

RequireAdmin
CleanLocalWindowsUpdateCache
RunDiskCleanup
