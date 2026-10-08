<#
.SYNOPSIS
  Create, format, and mount a dynamic NTFS VHDX file.

.DESCRIPTION
  Legacy disk helper. Resolves relative Path below the script directory, checks elevation and
  Hyper-V, may dismount/delete an existing target, then creates and mounts a dynamic VHDX and
  formats its partition as NTFS. Has no ShouldProcess; verify targets in a disposable VM before
  operational use.

.PARAMETER Path
  VHDX path; defaults to HyperVdisk.vhdx below the script directory.

.PARAMETER DiskSize
  Maximum dynamic disk size in bytes; defaults to 1GB.

.PARAMETER Force
  Request replacement of an existing VHDX. This legacy branch requires disposable-VM validation.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\components\scripts\Create-HyperVDisk.ps1 -Help

.EXAMPLE
  .\components\scripts\Create-HyperVDisk.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String and storage cmdlet objects. Progress/errors and the formatted volume result.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Elevated Windows session with the Hyper-V feature and storage cmdlets.
  File/environment inputs: Selected VHDX file and the attached virtual disk; operational invocation
  formats a new partition.
  Recovery: Back up existing targets first. Deletion/formatting has no automatic rollback; use a
  disposable VM checkpoint.
  Error-handling exception: Existing operational error policy is retained; globally enabling Stop
  requires a separate tested change.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.
  Known limitation: existing-file checks and replacement branches are retained for a separate tested
  safety change.

.LINK
  docs/migrations/powershell-script-walkthrough.md

#>


[CmdletBinding()]
param($Path="HyperVdisk.vhdx", 
[uint64] $DiskSize = 1GB, 
[Switch] $Force,
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

# Check if in administrator context
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
      Write-Output "ERROR: This function must run in an elevated context."
      Exit 1
}

# Define full name of file
if (Split-Path -Path $Path -IsAbsolute) {
      # If absolute path is entered, use that
      $FileFullName = $Path 
}
else {
      # use script root as default location for file
      $FileFullName = Join-Path -Path $PSScriptRoot -ChildPath $Path 
}

# Make sanity checks and create file or throw error
if ((Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online).state -eq "Enabled")  {
      if ((Test-VHD -Path $FileFullName)-and -not $Force) {
        Write-Output "ERROR: The file $FileFullName exists. Use the Force flag to overwrite"
        Exit 1
      }
      elseif ((Get-VHD $FileFullName).Attached -eq $True -and $Force) {
            # force flag enabled, VHD is mounted
            Dismount-VHD $FileFullName | Out-Null
            Remove-Item -Path $FileFullName -Recurse -Force
      }
      else {
            Remove-Item -Path $FileFullName -Recurse -Force
      }

      Write-Output "Creating $FileFullName..."
      New-VHD -Path $FileFullName -Dynamic -SizeBytes $DiskSize | Mount-VHD -Passthru |Initialize-Disk -Passthru |New-Partition -AssignDriveLetter -UseMaximumSize |Format-Volume -FileSystem NTFS -Confirm:$false -Force
}
else {
      Write-Output "ERROR: The Hyper-V role must be installed and active before creating a Hyper-V disk"
      Exit 1
}
