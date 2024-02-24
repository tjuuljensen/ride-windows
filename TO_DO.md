# ride-windows tasks

## Burndown list:

### Priority A - Improvements:
- [ ] Bitlocker Recoverykey export to AD
  * Export to AD: https://arconnetblog.wordpress.com/2018/09/04/retrieve-bitlocker-recovery-key/
- [ ] Log overwrite (or rotate)
- [ ] VSCode config - disable telemetry, install markdown plugin...
- [ ] Stage Office365 deployment, so custom XML can be used for installation
  * https://config.office.com/deploymentsettings
- [ ] Nucleus Filesystem recovery prompt (do not install on...)
- [ ] Install "Workflow" functionality on WSL packages
  * Workflows are not supported on Powershell 6+, so Schdeuled Tasks will be used
  * Consider building a complete script file with function declarations and the call of these inside the ps1.

### Priority B - New Packages:
- [ ] Rufus - https://rufus.ie/en/
- [ ] Add: Balena Etcher - https://www.balena.io/etcher#download-etcher
- [ ] Slack https://slack.com/downloads/windows
- [ ] Forensic plugins for Firefox
- [ ] https://www.brimdata.io/download/
- [ ] https://github.com/secdev/scapy
- [ ] https://www.niwcatlantic.navy.mil/scap/
- [ ] xmind
- [ ] PowerToys


### Priority C - Under Consideration:
- [ ] Windows - pwd cracking - https://kraken.nswardh.com/home
- [ ] Explorer view, default view 3 timestamps (pretty easy in GUI)
  * https://github.com/LesFerch/WinSetView/tree/main
  * https://stackoverflow.com/questions/65166834/enforce-list-view-on-all-windows-explorer-views-including-all-media-folders
  * https://stackoverflow.com/questions/4491999/configure-windows-explorer-folder-options-through-powershell

&nbsp;

## Finished tasks:
- [x] PowerShell Whois - solution changed to adding %SUERPROFILE%\bin to path (sysinternals whois can be copied manually)
- [x] Windows screen capture - https://getsharex.com/downloads
- [x] WinDirStat https://windirstat.net/download.html
- [x] Windows Firewall Notifier - https://github.com/wokhan/WFN
- [x] ADReplStatus https://github.com/ryanries/ADReplStatus
- [x] Backup Serial number before SysPrep
- [x] Use High performance power schema on host machine when used as virtual host
  * https://winaero.com/how-to-change-power-plan-in-windows-11/
  * https://powers-hell.com/2018/12/10/control-advanced-power-settings-with-powercfg-powershell/
- [x] Warn when enabling advanced Bitlocker PIN and current keyboard layout does not match installed 
- [x] InstallLanguagePacks
  * https://www.stefandingemanse.com/2022/08/27/install-language-packs-on-windows-10-11-the-easy-way/
  * Get-AppxPackage -AllUsers 'Microsoft.LanguageExperiencePacken-GB' | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
- [x] Adjust activation function (Check for OEM serial number & use for activation)
- [x] CyberChef - https://github.com/gchq/CyberChef
- [x] Add git-lfs executable to script https://git-lfs.com/
- [x] Unload modules in ride.ps1 when closing (remove-module INCLUDED_MODULES_ARRAY)
- [x] Add-WiFi
- [x] Add PSScriptTools - https://github.com/jdhitsolutions/PSScriptTools
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

