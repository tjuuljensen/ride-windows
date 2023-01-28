# Ride-Windows Task list

## Roadmap tasks:

### Priority A:
- [ ] Log overwrite (or rotate)
- [ ] Disable Teams start on boot
- [ ] Uninstall Teams AppXPackage (comes with Windows 11)?! - Get-AppxPackage 'MicrosoftTeams'
- [ ] Copy display language and input language to new users and welcome screen
- [ ] Uninstall functions (msi & exe) 
- [ ] BitLocker CD/USB bootable check
- [ ] Java for Bloodhound, sharphound etc
- [ ] Add-WiFi
- [ ] ImageMagick
- [ ] Slack
- [ ] Signal - https://signal.org/en/download/windows/

### Prority B:
- [ ] Unload modules in ride.ps1 (remove-module INCLUDED_MODULES_ARRAY)
- [ ] VSCode config - disable telemetry, install markdown plugin...
- [ ] Explorer view, default view 3 timestamps
- [ ] Fix dynamic Lenovo Vantage Tools Download - https://support.lenovo.com/gb/en/solutions/hf003321
- [ ] Windows - screen capture - https://getsharex.com/downloads
- [ ] Fix nuget requirements (uninstall-package)

### Priority C:
- [ ] Check Sysprep
- [ ] Update readme (config.ini example)
- [ ] Adjust activation (serial number checks)
  * https://scribbleghost.net/2019/08/23/how-to-find-and-backup-your-windows-10-license-key/
- [ ] Retire Atom (deprecated))

### Priority D:
- [ ] PowerShell Whois
  * https://powershellisfun.com/2022/06/12/get-whois-information-using-powershell/
  * https://www.powershellgallery.com/packages/PSScriptTools/2.9.0/Content/functions%5CGet-WhoIs.ps1
- [ ] Arsenal Image Mounter (mega.nz downloads https://arsenalrecon.com/downloads)
- [ ] AXIOM Free Tools (incl EDD)
  * https://support.magnetforensics.com/s/software-and-downloads?productTag=free-tools
- [ ] FTK Imager
  * https://accessdata.com/product-download-page
  * https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe
  * https://d1kpmuwb7gvu1i.cloudfront.net/Imager/4_7_1/FTKImager_UserGuide.pdf
  * https://d1kpmuwb7gvu1i.cloudfront.net/Imager/Imager_4.7.1_RN.pdf
- [ ] Improve bitlockerrecoverykey on command-line
  * https://learn.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector?view=windowsserver2022-ps
  * Add-BitLockerKeyProtector -MountPoint "$($env:SystemDrive)" -RecoveryPasswordProtector # -Confirm 
  * Export to file/USB: (Get-BitLockerVolume -MountPoint "$($env:SystemDrive)" | Select-Object -ExpandProperty KeyProtector)[1] | Select-Object KeyprotectorId,RecoveryPassword
  * Export to AD: https://arconnetblog.wordpress.com/2018/09/04/retrieve-bitlocker-recovery-key/

### Software
- [ ] CyberChef
  * https://github.com/thalesgroup-cert/FAST/blob/main/Softwares/CyberChef/CyberChef.py
- [ ] Forensics plugins for Firefox
- [ ] https://www.brimdata.io/download/
- [ ] https://github.com/secdev/scapy
- [ ] https://www.niwcatlantic.navy.mil/scap/
- [ ] xmind
- [ ] PowerToys
- [ ] Windows - pwd cracking - https://kraken.nswardh.com/home
- [ ] Distributed cracker (?) - https://github.com/arcaneiceman/kraken

&nbsp;

## Things marked as done:
- [x] Vmware not installing when serials are loaded?
- [X] ERROR: Cannot shutdown WinHttpAutoProxySvc (seen on Win11)
- [x] Random errors on Mitec download (server side) - make 2nd run on error? - Mitec PDESetup.exe error
- [x] Install VSCode - https://code.visualstudio.com/docs/?dv=win64
- [x] Windows 11 tweaks, Disable Taskbar features:  Chat, Widget, Task View, Search
- [X] Prompt for Bitlocker key PIN twice!!!!!
- [x] Close VSCode after installation (command line parameter)
- [x] Alt-Tab in edge switches between browser tabs
  
&nbsp;

## Roadmap tasks - v2:
- [ ] Download tool installer if only the installer is not already present
- [ ] Add PingCastle license with ini file
- [ ] Test running twice, and fix any issues
- [ ] Change all MSI installs to this: Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
- [ ] Split lib file into configs, installs, etc.
- [ ] Fix two/four space vs tab indent
- [ ] GPG verification
- [ ] SHA verification
- [ ] one-line install (check fedora repo for function)

