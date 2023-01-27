## Errors:
- [ ] Vmware not installing when serials are loaded?
- [ ] ERROR: Cannot shutdown WinHttpAutoProxySvc (seen on Win11)
- [x] Random errors on Mitec download (server side) - make 2nd run on error? - Mitec PDESetup.exe error

&nbsp;

## Roadmap tasks:

### Priority A:

- [ ] Uninstall Teams App (comes with Office Install?)?!
- [x] Install VSCode - https://code.visualstudio.com/docs/?dv=win64
- [x] Windows 11 tweaks, Disable Taskbar features:  Chat, Widget, Task View, Search

### Prority B:
- [ ] VSCode config - disable telemetry, install markdown plugin...
- [X] Prompt for Bitlocker key PIN twice!!!!!
- [ ] Add bitlockerrecoverykey on command-line (manage-bde or powershell)
  * https://learn.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector?view=windowsserver2022-ps
  * Add-BitLockerKeyProtector -MountPoint "$($env:SystemDrive)" -RecoveryPasswordProtector # -Confirm 
  * Export to file/USB: (Get-BitLockerVolume -MountPoint "$($env:SystemDrive)" | Select-Object -ExpandProperty KeyProtector)[1] | Select-Object KeyprotectorId,RecoveryPassword
  * Export to AD: https://arconnetblog.wordpress.com/2018/09/04/retrieve-bitlocker-recovery-key/
- [ ] Uninstall functions (msi & exe) 
- [ ] BitLocker CD/USB bootable check
- [ ] Add-WiFi
- [ ] Fix dynamic Lenovo Vantage Tools Download - https://support.lenovo.com/gb/en/solutions/hf003321

### Priority C:
- [ ] Check Sysprep
- [ ] Update readme (config.ini example)
- [ ] Explorer view, default view 3 timestamps
- [ ] Adjust activation (serial number checks)
  * https://scribbleghost.net/2019/08/23/how-to-find-and-backup-your-windows-10-license-key/

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

### Software
- [ ] CyberChef
  * https://github.com/thalesgroup-cert/FAST/blob/main/Softwares/CyberChef/CyberChef.py
- [ ] ImageMagick
- [ ] Slack
- [ ] Signal - https://signal.org/en/download/windows/
- [ ] Forensics plugins for Firefox
- [ ] https://www.brimdata.io/download/
- [ ] https://github.com/secdev/scapy
- [ ] https://www.niwcatlantic.navy.mil/scap/
- [ ] xmind
- [ ] PowerToys
- [ ] Windows - pwd cracking - https://kraken.nswardh.com/home
- [ ] Distributed cracker (?) - https://github.com/arcaneiceman/kraken
- [ ] Windows - screen capture - https://getsharex.com/downloads

### Retire:
- [ ] Atom (deprecated))

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
