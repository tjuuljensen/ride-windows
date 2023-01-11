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
  <#
  Same functions as:
  Dism.exe /online /Cleanup-Image /StartComponentCleanup
  Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
  #>

  $HKLM = [UInt32] "0x80000002"
  $strKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
  $strValueName = "StateFlags0065"

  $subkeys = Get-ChildItem -Path HKLM:\$strKeyPath -Name

  ForEach ($subkey in $subkeys) {
      Try {
          New-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue | Out-Null
      }
      Catch {
      }
      Try {
          Start-Process cleanmgr -ArgumentList "/sagerun:65" -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
      }
      Catch {
          }
      }
  ForEach ($subkey in $subkeys) {
      Try {
          Remove-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName | Out-Null
      }
      Catch {
      }
  }
}

RequireAdmin
CleanLocalWindowsUpdateCache
RunDiskCleanup
