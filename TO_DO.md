# ride-windows tasks

## Burndown list:

### Priority A - Improvements:
- [x] Add git-lfs executable to script https://git-lfs.com/
- [x] Unload modules in ride.ps1 when closing (remove-module INCLUDED_MODULES_ARRAY)
- [ ] Add-WiFi
- [ ] Add PSScriptTools - https://github.com/jdhitsolutions/PSScriptTools
- [ ] Adjust activation function (Check for OEM serial number & use for activation)
- [ ] Backup Serial number before SysPrep
- [ ] Use High performance power schema on host machine when used as virtual host - https://winaero.com/how-to-change-power-plan-in-windows-11/
- [ ] InstallLanguagePacks
  * https://www.stefandingemanse.com/2022/08/27/install-language-packs-on-windows-10-11-the-easy-way/
  * Get-AppxPackage -AllUsers 'Microsoft.LanguageExperiencePacken-GB' | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
- [ ] Warn when enabling advanced Bitlocker PIN and current keyboard layout does not match installed  
- [ ] Bitlocker Recoverykey export to AD
  * Export to AD: https://arconnetblog.wordpress.com/2018/09/04/retrieve-bitlocker-recovery-key/
- [ ] Explorer view, default view 3 timestamps
- [ ] Log overwrite (or rotate)
- [ ] VSCode config - disable telemetry, install markdown plugin...
- [ ] Stage Office365 deployment, so custom XML can be used for installation - https://config.office.com/deploymentsettings
- [ ] Nucleus Filesystem recovery prompt (do not install on...)

### Priority B - New Packages:
- [ ] Add: Balena Etcher - https://www.balena.io/etcher#download-etcher
- [ ] Windows screen capture - https://getsharex.com/downloads
- [ ] Slack
- [x] CyberChef - https://github.com/gchq/CyberChef
- [ ] Forensics plugins for Firefox
- [ ] https://www.brimdata.io/download/
- [ ] https://github.com/secdev/scapy
- [ ] https://www.niwcatlantic.navy.mil/scap/
- [ ] xmind
- [ ] PowerToys
- [ ] Windows Firewall Notifier - https://github.com/wokhan/WFN
- [ ] ADReplStatus https://github.com/ryanries/ADReplStatus
- [ ] WinDirStat https://windirstat.net/download.html

### Priority C - Under Consideration:
- [ ] PowerShell Whois
  * https://powershellisfun.com/2022/06/12/get-whois-information-using-powershell/
  * https://www.powershellgallery.com/packages/PSScriptTools/2.9.0/Content/functions%5CGet-WhoIs.ps1
- [ ] AXIOM Free Tools (incl EDD)
  * https://support.magnetforensics.com/s/software-and-downloads?productTag=free-tools
- [ ] FTK Imager
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
- [x] BitLocker CD/USB bootable check
- [X] Fix InstallVolatility3  
- [x] Check if path to python exists and alter path if it does not
- [x] Arsenal Image Mounter (mega.nz downloads https://arsenalrecon.com/downloads)
- [x] Update readme (config.ini example)
- [x] Install yara & yara-python
- [x] Fix nuget requirements (uninstall-package?!)
- [x] Add Hashcat & hashcat.launcher - https://hashcat.net/forum/thread-9151.html / https://github.com/s77rt/hashcat.launcher/releases
- [x] Java for Bloodhound, sharphound etc
- [x] Retire Atom (deprecated))
- [x] Re-add firewall functions


&nbsp;

## Roadmap tasks - v2:
- [ ] Download tool installer if only the installer is not already present (install from repo version)
- [ ] Add PingCastle license with ini file
- [ ] Test running twice, and fix any issues
- [ ] Change all MSI installs to this: Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
- [ ] Split lib file into configs, installs, etc.
- [ ] Fix two/four space vs tab indent
- [ ] GPG verification
- [ ] SHA verification
- [ ] one-line install (check fedora repo for function)

