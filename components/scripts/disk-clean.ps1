# Windows 10/11 disk cleanup script for VM's
# Author: Torsten Juul-Jensen
# Version: v1.0, 2022-12-28
# Source: https://github.com/tjuuljensen/ride-windows/disk-clean/disk-clean.ps1
#

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
