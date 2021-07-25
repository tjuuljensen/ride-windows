#
# A GUI version of WIM Witch: https://msendpointmgr.com/2019/10/04/wim-witch-a-gui-driven-solution-for-image-customization/
# PW CleanUp script: https://www.powershellgallery.com/packages/Invoke-WindowsDiskCleanup/1.0/Content/Invoke-WindowsDiskCleanup.ps1

# SERIOUSLY - check this:
# https://theitbros.com/sysprep-windows-machine/

#1.	Create a baseline Windows 10 image
#2.	Update it to newest patch level
#3.	Delete everything under C:\Windows\SoftwareDistribution\Download
#4.	Run from elevated prompt: Dism.exe /online /Cleanup-Image /StartComponentCleanup
#5.	Run from elevated prompt: Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
#6.	Shut it down
#7.	Run “Clean Up Disks” (releases all the used space cleaned up in task 3,4 and 5)
#8.	You can do extra stuff like deleting temp files etc using “Disk Clean-Up” or “Storage Sense” inside the VM , but don’t expect much. You can also uninstall all the default Apps in Windows, but whenever you patch your VM some of these are reinstalled and it just becomes a pain. Scripts does exist for all of this, but the gain is minimal in my opinion.
#9.	Now you have top squeezed Win10 VM ready to go
#10. Use this VM going forward for whatever. Doing a new assignment for a customer? Use this baseline VM for it. Just copy the folder you have the VM in and modify nvme0:0.fileName in the VMX file to point to the new VMDK. The Computer Name persists of course, so change it if needed. If it is NATed, it will get a different IP through DHCP so no problem. Pretty neat. Only using the VMWare Clean-Up disks a fully patched Windows 10 and a deleted Download folder is around 17 GB.
#11. Protip: Whenever a cumulative update is installed on your Improsec host, boot up your baseline VM and install it on that as well. That way, you always have your baseline VM patched and you don’t have to worry about it. And of course, run “Clean Up Disks” after updating. It takes 1-2 minutes.


Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# PowerShellGet requires NuGet provider to interact with NuGet-based repositories
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

Install-Module PSWindowsUpdate -Force
Import-Module PSWindowsUpdate

Get-WindowsUpdate -AcceptAll -Install  # -AutoReboot

Remove-Item C:\Windows\SoftwareDistribution\Download\*

# Dism.exe /online /Cleanup-Image /StartComponentCleanup
# Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

# Run CleanMgr functions

$HKLM = [UInt32] “0x80000002”
$strKeyPath = “SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches”
$strValueName = “StateFlags0065”

$subkeys = gci -Path HKLM:\$strKeyPath -Name

ForEach ($subkey in $subkeys) {
    Try {
        New-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue| Out-Null
    }
        
    Catch {
    }
    
    Try {
        Start-Process cleanmgr -ArgumentList “/sagerun:65” -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
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


# Sysprep
# https://stackoverflow.com/questions/52144405/run-sysprep-remotely-through-commands-from-azure-powershell
$sysprep = 'C:\Windows\System32\Sysprep\Sysprep.exe'
$arg = '/generalize /oobe /shutdown /quiet'
Invoke-Command -ScriptBlock {param($sysprep,$arg) Start-Process -FilePath $sysprep -ArgumentList $arg} -ArgumentList $sysprep,$arg

# Handle Activation on Sysprep
# Check this (old article - WIn7)
# https://social.technet.microsoft.com/Forums/windows/en-US/4104fa3f-9c36-4d45-aa36-677602894768/sysprep-maintain-activation-and-product-key?forum=w7itproinstall