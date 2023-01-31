# ride-windows tasks

## Burndown list:

### Priority A - Issues:

- [ ] Missing Uninstall functions (msi & exe) 
  * Office365 - https://support.microsoft.com/en-us/office/uninstall-office-automatically-9ad57b43-fa12-859a-9cf0-b694637b3b05
- [ ] BitLocker CD/USB bootable check
- [ ] Java for Bloodhound, sharphound etc
- [ ] Fix InstallVolatility3  
- [ ] Update readme (config.ini example)
- [ ] Nucleus Filesystem recovery prompt (do not install on...)


### Prority B - Improvements:
- [ ] Add-WiFi
- [ ] InstallLanguagePacks
  * https://www.stefandingemanse.com/2022/08/27/install-language-packs-on-windows-10-11-the-easy-way/
  * Get-AppxPackage -AllUsers 'Microsoft.LanguageExperiencePacken-GB' | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
- [ ] Unload modules in ride.ps1 (remove-module INCLUDED_MODULES_ARRAY)
- [ ] Explorer view, default view 3 timestamps
- [ ] Windows - screen capture - https://getsharex.com/downloads
- [ ] Fix nuget requirements (uninstall-package)
- [ ] Log overwrite (or rotate)
- [ ] VSCode config - disable telemetry, install markdown plugin...
- [ ] Adjust activation (serial number checks)
  * https://scribbleghost.net/2019/08/23/how-to-find-and-backup-your-windows-10-license-key/
- [ ] Stage Office365 deployment, so custom XML can be used for installation - https://config.office.com/deploymentsettings
- [ ] Bitlocker Recoverykey export to AD
  * Export to AD: https://arconnetblog.wordpress.com/2018/09/04/retrieve-bitlocker-recovery-key/

### Priority C - New Packages:
- [ ] Slack
- [ ] Retire Atom (deprecated))
- [ ] Arsenal Image Mounter (mega.nz downloads https://arsenalrecon.com/downloads)
- [ ] CyberChef
  * https://github.com/thalesgroup-cert/FAST/blob/main/Softwares/CyberChef/CyberChef.py
- [ ] Forensics plugins for Firefox
- [ ] https://www.brimdata.io/download/
- [ ] https://github.com/secdev/scapy
- [ ] https://www.niwcatlantic.navy.mil/scap/
- [ ] xmind
- [ ] PowerToys


### Priority D - Under Consideration:
- [ ] PowerShell Whois
  * https://powershellisfun.com/2022/06/12/get-whois-information-using-powershell/
  * https://www.powershellgallery.com/packages/PSScriptTools/2.9.0/Content/functions%5CGet-WhoIs.ps1
- [ ] AXIOM Free Tools (incl EDD)
  * https://support.magnetforensics.com/s/software-and-downloads?productTag=free-tools
- [ ] FTK Imager
  * https://accessdata.com/product-download-page
  * https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe
  * https://d1kpmuwb7gvu1i.cloudfront.net/Imager/4_7_1/FTKImager_UserGuide.pdf
  * https://d1kpmuwb7gvu1i.cloudfront.net/Imager/Imager_4.7.1_RN.pdf
- [ ] Windows - pwd cracking - https://kraken.nswardh.com/home


&nbsp;

## Finished tasks:

- [x] Vmware not installing when serials are loaded?
- [X] ERROR: Cannot shutdown WinHttpAutoProxySvc (seen on Win11)
- [x] Random errors on Mitec download (server side) - make 2nd run on error? - Mitec PDESetup.exe error
- [x] Install VSCode - https://code.visualstudio.com/docs/?dv=win64
- [x] Windows 11 tweaks, Disable Taskbar features:  Chat, Widget, Task View, Search
- [X] Prompt for Bitlocker key PIN twice!!!!!
- [x] Close VSCode after installation (command line parameter)
- [x] Alt-Tab in edge switches between browser tabs
- [x] Improve bitlockerrecoverykey on command-line
  * https://learn.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector?view=windowsserver2022-ps
  * Add-BitLockerKeyProtector -MountPoint "$($env:SystemDrive)" -RecoveryPasswordProtector # -Confirm 
  * Export to file/USB: (Get-BitLockerVolume -MountPoint "$($env:SystemDrive)" | Select-Object -ExpandProperty KeyProtector)[1] | Select-Object KeyprotectorId,RecoveryPassword
- [x] Copy display language and input language to new users and welcome screen
- [x] ImageMagick - https://imagemagick.org/script/download.php
- [x] Disable Teams start on boot
- [x] Check Sysprep
- [x] Uninstall Teams AppXPackage (comes with Windows 11) - Get-AppxPackage 'MicrosoftTeams'
- [x] Signal - https://signal.org/en/download/windows/
- [x] Fix dynamic Lenovo Vantage Tools Download - https://support.lenovo.com/gb/en/solutions/hf003321
- [x] Forensic downloads - add installation
- [x] Double nested InstallGoogleAnalyticCookieCruncher (zip inside)
- [x] Install python for windows and test python scripts - https://www.python.org/downloads/windows/
 
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

