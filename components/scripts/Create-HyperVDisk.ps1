<#
.SYNOPSIS
      Creates a VHDX disk file with partition and file system and mounts it 
.DESCRIPTION
      Sometimes it can come in handy to create a VHDX file to export or share data in.
      This script contains the required checks and interconnected steps required to create a file like that.
.NOTES
      Must be run with administrator credentials.
      Requires Hyper-V role to be installed. 
      Disk will always be created as a dynamic (auto expanding) VHDX file.
      File system is always NTFS.
.LINK
      https://github.com/tjuuljensen/ride-windows/tree/master/components/scripts
.EXAMPLE
      Create-HyperVDisk.ps1 -Path C:\Users\bob\Desktop\VHDdisk.vhdx -DiskSize 2GB -Force
      The command creates a vhdx file on the user Desktop of bob with a size of 2GB. If the file exists, the Force parameter
      ensures that the old file is deleted before a new one is created.  
#>

# Define script parameters
param($Path="HyperVdisk.vhdx", 
[uint64] $DiskSize = 1GB, 
[Switch] $Force)

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
