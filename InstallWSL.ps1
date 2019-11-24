# Enable Windows Subsystem Linux PowerShell Script
#
# Sources:
# https://stackoverflow.com/questions/7330187/how-to-find-the-windows-version-from-the-powershell-command-line
# https://www.computerhope.com/issues/ch001879.htm (How to install WSL on Windows 10)
# https://www.how2shout.com/how-to/how-to-install-fedora-remix-for-wsl-on-windows-10-using-choco.html
# https://docs.microsoft.com/en-us/windows/wsl/wsl2-install
# https://devblogs.microsoft.com/commandline/wsl-2-is-now-available-in-windows-insiders/
# https://docs.microsoft.com/en-us/windows/wsl/install-manual

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart

# Return the Windows version
# Original: (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").BuildLabEx -match '^[0-9]+\.[0-9]+' |  % { $matches.Values }
# (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").BuildLabEx -match '^[0-9]+' |  % { $matches.Values }
# Alternatives:  ([System.Environment]::OSVersion.Version).Build
#                Get-ComputerInfo | select WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer

 $WindowsVersion = ([System.Environment]::OSVersion.Version).Build

 if ( $WindowsVersion -ge 18917 ) {
   # If WSL 2 available
   wsl --set-default-version 2
}

# curl.exe is available in Windows 10 Spring 2018 Update (or later) - could use "curl.exe -L and -o"
Invoke-WebRequest https://aka.ms/wsl-ubuntu-1804 -OutFile ubuntu-1804.appx
Add-AppxPackage .\ubuntu-1804.appx

# Fedora remix is available on github
# https://github.com/WhitewaterFoundry/Fedora-Remix-for-WSL/releases
$FedoraRemixURL = "https://github.com" + (((Invoke-WebRequest "https://github.com/WhitewaterFoundry/Fedora-Remix-for-WSL/releases" -UseBasicParsing ).links).href  | Select-String "x64" | Select-Object -First 1)
Invoke-WebRequest $FedoraRemixURL -UseBasicParsing -OutFile fedoraremix.appx
Add-AppxPackage .\fedoraremix.appx





#Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
#Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
