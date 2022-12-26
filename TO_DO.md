## Tasks:
* Uninstall functions (msi & exe) [TJJ]
* BitLocker CD/USB bootable check
* Log Output check (Bitlocker output)
* Check Sysprep
* Configurable \Tools folder
* SysInternals Suite to \Tools
* Opdateret readme (config.ini eksempel)

- AXIOM Free Tools (incl EDD)
  https://support.magnetforensics.com/s/software-and-downloads?productTag=free-tools

- FTK Imager
  https://accessdata.com/product-download-page
  https://d1kpmuwb7gvu1i.cloudfront.net/AccessData_FTK_Imager_4.7.1.exe
  https://d1kpmuwb7gvu1i.cloudfront.net/Imager/4_7_1/FTKImager_UserGuide.pdf
  https://d1kpmuwb7gvu1i.cloudfront.net/Imager/Imager_4.7.1_RN.pdf

- Wireshark
  https://www.wireshark.org/download.html

- CyberChef
  https://github.com/thalesgroup-cert/FAST/blob/main/Softwares/CyberChef/CyberChef.py


### Version 2:
* Download tool installer if only the installer is not already present
* Add PingCastle license with ini file
* Disable Teams boot on startup function
* Prevent creation of desktop shortcuts (or delete after install): Firefox, autopsy, vmware workstation, teams, edge, chrome, atom
* Test running twice, and fix any issues
* Change all MSI installs to this: Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
* Stop Atom from starting up after installation
* Split lib file into configs, installs, etc.
* Fix two/four space vs tab indent
* GPG verification
* SHA verification
* one-line install (check fedora repo for function)
