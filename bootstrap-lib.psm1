# Customizer for Disassembler0's Win10-Initial-Setup-Script
# Win 10 / Server 2016 / Server 2019 Initial Setup Script
# Author: Torsten Juul-Jensen
# Version: v2.0, 2020-02-15
# Source: https://github.com/tjuuljensen/bootstrap-win10
#


################################################################
###### Windows 10 configuration  ###
################################################################

function ActivateWindows10{

  if ((Get-WindowsEdition -Online | select Edition) -like "*Professional*"){$key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}
  if ((Get-WindowsEdition -Online | select Edition) -like "*Enterprise*"){$key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}

	$computer = gc env:computername

	$service = get-wmiObject -query "select * from SoftwareLicensingService" -computername $computer
	$service.InstallProductKey($key)
	$service.RefreshLicenseStatus()
}

function Sysprep{
  # sysprep installation - for templates
  Start-Process -FilePath C:\Windows\System32\Sysprep\Sysprep.exe -ArgumentList "/generalize /oobe /shutdown /quiet"
}


function DisableWindowsStoreApp(){
  # Disable Windows Store App - Windows Enterprise Only!!!
  Write-Output "Disabling Windows Store app (Windows Enterprise only)..."
  if ((Get-WindowsEdition -Online | select Edition) -like "*Enterprise*"){
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\" -Force | Out-Null
    }
    Set-ItemProperty -path $regKey -name RemoveWindowsStore -value 1
    Set-ItemProperty -path $regKey -name DisableStoreApps -value 1
  } else {
    Write-Output "INFO: This version of Windows is not Enterprise. Windows Store app is not disabled."
  }
}

function EnableWindowsStoreApp(){
  # Disable Windows Store App - Windows Enterprise Only!!!
  Write-Output "Enabling Windows Store app (Windows Enterprise only)..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\" -Name "DisableStoreApps" -ErrorAction SilentlyContinue
}


################################################################
###### Privacy configurations  ###
################################################################

function DisableInkingAndTypingData{
  # Disable sending of inking and typing data to Microsoft to improve the language recognition and suggestion capabilities of apps and services.
  Write-Output "Disabling sending of inking and typing data..."
  Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Input\TIPC\" -name Enabled -value 0
}

function EnableInkingAndTypingData{
  # Send inking and typing data to Microsoft to improve the language recognition and suggestion capabilities of apps and services.
  Write-Output "Enabling sending of inking and typing data..."
  Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Input\TIPC\" -name Enabled -value 1
}


################################################################
###### Hardening Windows  ###
################################################################

function SetBitLockerAES256{
    # Set BitLocker to AES-256
    # Check with "manage-bde -status" and Encrypt AFTERWARDS!
    # See more here: http://www.howtogeek.com/193649/how-to-make-bitlocker-use-256-bit-aes-encryption-instead-of-128-bit-aes/
    Write-Output "Setting default Bitlocker encryption to AES256..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\")) {
  		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Force | Out-Null
  	}

    Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -name "EncryptionMethod" -value 4
    #To-do: start BitLocker Encryption with PowerShell https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
}

function SetBitLockerAES128{
    # Set BitLocker to AES-128 (default)
    Write-Output "Setting default Bitlocker encryption to AES128..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\")) {
  		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Force | Out-Null
  	}
    Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -name "EncryptionMethod" -value 3
    #To-do: start BitLocker Encryption with PowerShell https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
}

function PutBitlockerShortCutOnDesktop{
    # Start Bitlocker wizard https://social.technet.microsoft.com/Forums/windows/en-US/12388d10-196a-483a-8421-7dcbffed123b/run-bitlocker-drive-encryption-wizard-from-command-line?forum=w7itprosecurity
    $AppLocation = "C:\Windows\System32\BitLockerWizardElev.exe"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Bitlocker Wizard.lnk")
    $Shortcut.TargetPath = $AppLocation
    $Shortcut.Arguments ="\ t"
    #$Shortcut.IconLocation = "C:\Windows\System32\BitLockerWizardElev.exe,0"
    $Shortcut.Description ="Start Bitlocker Wizard"
    $Shortcut.WorkingDirectory ="C:\Windows\System32"
    $Shortcut.Save()
}


Function DisableSSDPdiscovery{
  # Disables discovery of networked devices and services that use the SSDP discovery protocol, such as UPnP devices.
  # SSDP Discovery service is required for UPnP and Media Center Extender (as per Windows Services > Dependencies tab for SSDP discovery)
  # and so if you don't need UPnP it won't have any negative affects.
  # Network Management in Windows isn't affected by SSDP; you can confidently disable it
Write-Output "Stopping and disabling SSDP discovery protocol..."
	Stop-Service "SSDPSRV" -WarningAction SilentlyContinue
	Set-Service "SSDPSRV" -StartupType Disabled
}

Function EnableSSDPdiscovery {
  # Discovers networked devices and services that use the SSDP discovery protocol, such as UPnP devices.
  # Also announces SSDP devices and services running on the local computer.
	Write-Output "Enabling and starting SSDP discovery protocol..."
	Set-Service "SSDPSRV" -StartupType Manual
	Start-Service "SSDPSRV" -WarningAction SilentlyContinue
}

Function DisableUniversalPlugAndPlay{
  # Without UPnP enabled things like torrents and multiplayer gaming won't work properly unless you manually identify and forward all the ports required
  Write-Output "Stopping and disabling UPNP service..."
	Stop-Service "upnphost" -WarningAction SilentlyContinue
	Set-Service "upnphost" -StartupType Disabled
}

Function EnableUniversalPlugAndPlay {

	Write-Output "Enabling UPNP service..."
	Set-Service "upnphost" -StartupType Manual
	#Start-Service "upnphost" -WarningAction SilentlyContinue
}

Function DisableWinHttpAutoProxySvc {
  # Disable IE proxy autoconfig service
	Write-Output "Stopping and disabling HTTP Proxy auto-discovery ..."
	Stop-Service "WinHttpAutoProxySvc" -WarningAction SilentlyContinue
	Set-Service "WinHttpAutoProxySvc" -StartupType Disabled
}

Function EnableWinHttpAutoProxySvc {
  # Enable IE proxy autoconfig service
	Write-Output "Enabling and starting HTTP Proxy auto-discovery..."
	Set-Service "WinHttpAutoProxySvc" -StartupType Manual
	Start-Service "WinHttpAutoProxySvc" -WarningAction SilentlyContinue
}


################################################################
###### Network Functions  ###
################################################################

function DisableIEProxyAutoconfig{
    # Disable IE proxy autoconfig by editing binary registry value
    # prevents WPAD atttack
    Write-Output "Disabling Internet Explorer Proxy autoconfig..."
    $data = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings).DefaultConnectionSettings
    $data[8] = 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings -Value $data
}

function DisableMulticastDNS{
    # Specifies that link local multicast name resolution (LLMNR) is disabled on client computers.
    # If this policy setting is enabled, LLMNR will be disabled on all available network adapters on the client computer.
    Write-Output "Disabling multicast traffic..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -name "EnableMulticast" -value 0 -PropertyType DWord -Force
}

function EnableMulticastDNS{
    Write-Output "Enabling multicast traffic..."
    # LMNR will be enabled on all available network adapters (default setting)
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}


function GetTelemetryBlockingHostfile{
    # Null-routing hostfile to block Microsoft and NVidia telemetry
    # read more here: https://encrypt-the-planet.com/windows-10-anti-spy-host-file/
    Write-Output "Enabling blocking hostsfile from encrypt-the-planet.com..."
    $Hostsfile=Join-Path -Path $Env:windir -ChildPath "\System32\Drivers\etc\hosts"
    Invoke-WebRequest https://www.encrypt-the-planet.com/downloads/hosts -OutFile $Hostsfile

}

function SetDefaultHostsfile{
  # Use a default Windows 10 hostfile
  Write-Output "Setting hosts file to default (empty file)..."
  $Hostsfile=Join-Path -Path $Env:windir -ChildPath "\System32\Drivers\etc\hosts"

  '# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a ''#'' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
' | out-file $Hostsfile

}


################################################################
###### Windows Subsystem for Linux  ###
################################################################

function EnableWSL{
  # Enable Windows Subsystem Linux PowerShell Script
  #
  # Sources:
  # https://stackoverflow.com/questions/7330187/how-to-find-the-windows-version-from-the-powershell-command-line
  # https://www.computerhope.com/issues/ch001879.htm (How to install WSL on Windows 10)
  # https://www.how2shout.com/how-to/how-to-install-fedora-remix-for-wsl-on-windows-10-using-choco.html
  # https://docs.microsoft.com/en-us/windows/wsl/wsl2-install
  # https://devblogs.microsoft.com/commandline/wsl-2-is-now-available-in-windows-insiders/
  # https://docs.microsoft.com/en-us/windows/wsl/install-manual
  # https://medium.com/swlh/get-wsl2-working-on-windows-10-2ee84ef8ed43 (see X.11 section)

  Write-Output "Enabling Windows Subsystem for Linux..."

  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart

  # Set wsl version as default version on latest versions of Windows 10
   $WindowsVersion = ([System.Environment]::OSVersion.Version).Build

   if ( $WindowsVersion -ge 18917 ) {
     # If WSL 2 available
     Write-Output "Setting Windows Subsystem for Linux version 2 as default WSL..."
     wsl --set-default-version 2
  }
}

function DisableWSL{
  Write-Output "Disabling Windows Subsystem for Linux..."
  Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
  Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
}

function InstallWSLubuntu1804{
  Write-Output "Installing WSL Ubuntu 18.04..."
  $URL="https://aka.ms/wsl-ubuntu-1804"

  # Downloading file
  $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
  Write-Output "Downloading file from: $FullDownloadURL"
  Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile

  # Installing File
  Add-AppxPackage $LocalFile
}

function RemoveWSLubuntu1804{
  Get-AppxPackage "CanonicalGroupLimited.Ubuntu18.04onWindows" | Remove-AppxPackage
}

function InstallWSLdebian{
  Write-Output "Installing WSL Debian..."
  $URL="https://aka.ms/wsl-debian-gnulinux"

  # Downloading file
  $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
  Write-Output "Downloading file from: $FullDownloadURL"
  Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile

  # Installing File
  Add-AppxPackage $LocalFile
}

function RemoveWSLdebian{
  Get-AppxPackage "TheDebianProject.DebianGNULinux" | Remove-AppxPackage
}

function InstallWSLkali{
  Write-Output "Installing WSL Kali..."
  $URL="https://aka.ms/wsl-kali-linux-new"

  # Downloading file
  $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
  Write-Output "Downloading file from: $FullDownloadURL"
  Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile

  # Installing File
  Add-AppxPackage $LocalFile
}

function RemoveWSLkali{
  Get-AppxPackage "KaliLinux.54290C8133FEE" | Remove-AppxPackage
}

function InstallWSLFedoraRemix{
  # Fedora remix is available on github
  # https://github.com/WhitewaterFoundry/Fedora-Remix-for-WSL/releases
  # Fedora Remix cannot use BitsTransfer due to githubs extremely long download URLs

  Write-Output "Installing WSL Fedora Remix..."
  $FedoraRemixURL = "https://github.com" + (((Invoke-WebRequest "https://github.com/WhitewaterFoundry/Fedora-Remix-for-WSL/releases" -UseBasicParsing ).links).href  | Select-String "x64" | Select-Object -First 1)
  Invoke-WebRequest $FedoraRemixURL -UseBasicParsing -OutFile fedoraremix.appx
  Add-AppxPackage .\fedoraremix.appx
}

function RemoveWSLFedoraRemix{
  Get-AppxPackage "WhitewaterFoundryLtd.Co.FedoraRemixforWSL" | Remove-AppxPackage
}



################################################################
###### Install programs  ###
################################################################

function InstallSpiceGuestTool{
  # Install spice guest tool (for Gnome boxes) - https://www.spice-space.org/download.html
  # Read more here: https://www.ctrl.blog/entry/how-to-win10-in-gnome-boxes.html
  Write-Output "Installing Spice Guest Tools for VM..."
  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $SPICEWEBDAVD="https://spice-space.org/download/windows/spice-webdavd/spice-webdavd-x64-latest.msi"
  $SPICEGUESTTOOLS="https://spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe"

  $SPICEWEBDAVDFILE=$SPICEWEBDAVD.Substring($SPICEWEBDAVD.LastIndexOf("/") + 1)
  $SPICEGUESTTOOLSFILE=$SPICEGUESTTOOLS.Substring($SPICEGUESTTOOLS.LastIndexOf("/") + 1)

  cd $DefaultDownloadDir

  Import-Module BitsTransfer

  Start-BitsTransfer -Source $SPICEWEBDAVD
  Start-BitsTransfer -Source $SPICEGUESTTTOLS

  Invoke-Expression "msiexec /qb /i $SPICEWEBDAVDFILE"
  Invoke-Expression "$SPICEGUESTTOOLSFILE"
}


function InstallGPGwin{
    Write-Output "Installing GPG for Windows..."
    # Define Download URL
    $URL="https://files.gpg4win.org/gpg4win-latest.exe"

    # Resolve full download URL
    Write-Output "Checking URL: $URL"
    $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
    if (! $FullDownloadURL) {Write-Output "Error: URL not resolved"; return}

    # Download file
    $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
    $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
    $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
    Write-Output "Downloading file from: $FullDownloadURL"
    Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile
    #(New-Object System.Net.WebClient).DownloadFile($FullDownloadURL, $LocalFile)

    # Install
    $FileType=([System.IO.Path]::GetExtension($Localfile))
    Write-Output "Starting installation of: $FileName"
    switch ($FileType){
            ".exe" {Start-Process $LocalFile -NoNewWindow -Wait}
            ".msi" {msiexec.exe /i $Localfile /qb}
    }
}

function InstallThunderbird{
  Write-Output "Installing Mozilla Thunderbird..."
  # Define Download URL
  $URL= "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=en-US"

  # Resolve full download URL
  Write-Output "Checking URL: $URL"
  $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
  if (! $FullDownloadURL) {Write-Output "Error: URL not resolved"; return}

  # Download file
  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
  Write-Output "Downloading file from: $FullDownloadURL"
  Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile
  #(New-Object System.Net.WebClient).DownloadFile($FullDownloadURL, $LocalFile)

  # Install
  $FileType=([System.IO.Path]::GetExtension($Localfile))
  Write-Output "Starting installation of: $FileName"
  switch ($FileType){
          ".exe" {Start-Process $LocalFile -NoNewWindow -Wait}
          ".msi" {msiexec.exe /i $Localfile /qb}
  }
}

function InstallOffice365{
  # download and install office365 using office deployment tool

  Write-Output "Installing Microsoft Office 365..."
  # scrape web page for right file link
  $URL="https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117"
  $CheckURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
  if (! $CheckURL) {Write-Output "Error: URL not resolved"; return}
  $FullDownloadURL=(Invoke-WebRequest -UseBasicParsing  -Uri $URL).Links.Href | Get-Unique -asstring | Select-String -Pattern officedeploymenttool
  if (! $FullDownloadURL) {Write-Output "Error: OfficeDeploymentTool Not found"; return}

  #Download file
  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
  Import-Module BitsTransfer
  Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile

  # Extract Deployment tool in a subdirectory
  $DeploymentDirectory=Join-Path -Path $DefaultDownloadDir -ChildPath "office365deploy\"
  Invoke-Expression "$LocalFile /quiet /extract:$DeploymentDirectory"

  # Create Office365 XMl file
  $CustomOffice365XML=Join-Path -Path $DeploymentDirectory -ChildPath "custom-Office365-x86.xml"

  '<!-- Office 365 client configuration file for custom downloads -->

  <Configuration>

    <Add OfficeClientEdition="32" Channel="Monthly">
      <Product ID="O365ProPlusRetail">
        <Language ID="en-us" />
        <Language ID="da-dk" />
      </Product>
      <Product ID="VisioProRetail">
        <Language ID="en-us" />
        <Language ID="da-dk" />
      </Product>
    </Add>

  <Updates Enabled="TRUE" Channel="Monthly" />
  <Display Level="None" AcceptEULA="TRUE" />
  <Property Name="AUTOACTIVATE" Value="1" />
  </Configuration>' |  Out-File $CustomOffice365XML

  # start download using OfficeDeploymentTool
  Invoke-Expression (Join-Path -Path $DeploymentDirectory -ChildPath "setup.exe") "/download $CustomOffice365XML"

  # start install using OfficeDeploymentTool
  Invoke-Expression (Join-Path -Path $DeploymentDirectory -ChildPath "setup.exe") "/configure $CustomOffice365XML"

}

function InstallVMwareWorkstation{

      #Download vmware workstation
      $URL = "https://www.vmware.com/go/getworkstation-win"

      Write-Output "Installing VMware Workstation..."
      # Resolve full download URL
      Write-Output "Checking URL: $URL"
      $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
      if (! $FullDownloadURL) {Write-Output "Error: URL not resolved"; return}

      # Download file
      $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
      $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
      $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
      Write-Output "Downloading file from: $FullDownloadURL"
      Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile
      #(New-Object System.Net.WebClient).DownloadFile($FullDownloadURL, $LocalFile)

      # Install
      $FileType=([System.IO.Path]::GetExtension($Localfile))
      Write-Output "Starting installation of: $FileName"
      Start-Process -FilePath $LocalFile -NoNewWindow -Wait -ArgumentList "/s /v/qn REBOOT=ReallySuppress ADDLOCAL=ALL EULAS_AGREED=1 SERIALNUMBER=""XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"""

}


################################################################
###### Browsers and Internet  ###
################################################################

function DisableEdgePagePrediction{
  # Disable Microsoft Edge Page Prediction
  # When Page Prediction is enabled in Microsoft Edge, the browser might crawl pages you never actually visit during the browsing session.
  # This exposes your machine fingerprint and also creates a notable load on PCs with low end hardware because the browser calculates the
  # possible URL address every time you type something into the address bar. It also creates potentially unnecessary bandwidth usage.

  Write-Output "Disabling Microsoft Edge page prediction..."
  If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\")) {
    New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\" -Force | Out-Null
  }
	Set-ItemProperty -path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\" -name FPEnabled -value 0

}

function InstallFirefox{
    Write-Output "Installing Mozilla Firefox..."
    # Define Download URL
    $URL="https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US"

    # Resolve full download URL
    Write-Output "Checking URL: $URL"
    $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
    if (! $FullDownloadURL) {Write-Output "Error: URL not resolved"; return}

    # Download file
    $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
    $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
    $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
    Write-Output "Downloading file from: $FullDownloadURL"
    Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile
    #(New-Object System.Net.WebClient).DownloadFile($FullDownloadURL, $LocalFile)

    # Install
    $FileType=([System.IO.Path]::GetExtension($Localfile))
    Write-Output "Starting installation of: $FileName"
    switch ($FileType){
            ".exe" {Start-Process $LocalFile -NoNewWindow -Wait}
            ".msi" {msiexec.exe /i $Localfile /qb}
    }
}

function RemoveFirefox{
  Write-Output "Removing Mozilla Firefox..."
  $MyVar=Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*"  | % { Get-ItemProperty $_.PsPath } | Select UninstallString
}

function CreateFirefoxPreferenceFiles {
  # See more at https://developer.mozilla.org/en-US/Firefox/Enterprise_deployment
  Write-Output "Creating prefence files for Mozilla Firefox..."

  param([string]$FirefoxInstallDir=([System.Environment]::GetFolderPath("ProgramFilesX86")+"\Mozilla Firefox\"))

  # Create the config file
  New-Item ($firefoxInstallDir+"mozilla.cfg") -type file -force -value "
//disable DNS prefetch
lockPref(""network.dns.disablePrefetch"", true);

//disable prefetch
lockPref(""network.prefetch-next"", false);

// Don't show 'know your rights' on first run
pref(""browser.rights.3.shown"", true);

// Don't show WhatsNew on first run after every update
pref(""browser.startup.homepage_override.mstone"",""ignore"");

// Don't show new tab page intro
pref(""browser.newtabpage.introShown"", false);

// Set additional welcome page
pref(""startup.homepage_welcome_url.additional"", ""https://encrypted.google.com"");

// Don't show Windows 10 page
pref(""browser.usedOnWindows10"", true);

// Set default homepage - users can change
// Requires a complex preference
defaultPref(""browser.startup.homepage"",""data:text/plain,browser.startup.homepage=https://encrypted.google.com"");

// Disable health reporter
lockPref(""datareporting.healthreport.service.enabled"", false);

// Disable all data upload (Telemetry and FHR)
lockPref(""datareporting.policy.dataSubmissionEnabled"", false);

// Disable crash reporter
lockPref(""toolkit.crashreporter.enabled"", false);
Components.classes[""@mozilla.org/toolkit/crash-reporter;1""].getService(Components.interfaces.nsICrashReporter).submitReports = false;

// Disable sync services
pref(""services.sync.enabled"", false);

"

  # Create the autoconfig.js file
  New-Item ($firefoxInstallDir+"defaults\pref\autoconfig.js") -type file -force -value "pref(""general.config.filename"", ""mozilla.cfg"");
pref(""general.config.obscure_value"", 0);
"

  # Create the override.ini file (disables Migration Wizard)
  New-Item ($firefoxInstallDir+"browser\override.ini") -type file -force -value "[XRE]
EnableProfileMigrator=false
"
}

function InstallChrome{
    # Define Download URL
    #$CHROMEMSIURL = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B41280CF8-747D-3F47-BA8E-0E6CEDBB4C51%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable/dl/chrome/install/googlechromestandaloneenterprise64.msi"
    Write-Output "Installing Google Chrome..."
    $URL="https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%3Dx64-stable/dl/chrome/install/googlechromestandaloneenterprise64.msi"

    # Resolve full download URL
    Write-Output "Checking URL: $URL"
    $FullDownloadURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
    if (! $FullDownloadURL) {Write-Output "Error: URL not resolved"; return}

    # Download file
    $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
    $FileName=([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
    $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
    Write-Output "Downloading file from: $FullDownloadURL"
    Start-BitsTransfer -Source $FullDownloadURL -Destination $LocalFile
    #(New-Object System.Net.WebClient).DownloadFile($FullDownloadURL, $LocalFile)

    # Install
    $FileType=([System.IO.Path]::GetExtension($Localfile))
    Write-Output "Starting installation of: $FileName"
    switch ($FileType){
            ".exe" {Start-Process $LocalFile -NoNewWindow -Wait}
            ".msi" {msiexec.exe /i $Localfile /qb}
    }
}

function RemoveChrome{
  Write-Output "Removing Google Chrome..."
  Uninstall-Package -InputObject ( Get-Package -Name "Google Chrome")
}


function CreateChromePreferenceFiles {
Write-Output "Creating preference files for Google Chrome..."

param($ChromeInstallDir=([System.Environment]::GetFolderPath("ProgramFilesX86")+"\Google\Chrome\Application\"))

# Create the master_preferences file
# File contents based on source fils: https://src.chromium.org/viewvc/chrome/trunk/src/chrome/common/pref_names.cc
New-Item ($chromeInstallDir+"master_preferences") -type file -force -value "{
 ""homepage"" : ""https://www.google.com"",
 ""homepage_is_newtabpage"" : false,
 ""dns_prefetching.enabled"" : false,
 ""browser"" : {
   ""show_home_button"" : true,
   ""check_default_browser"" : false
 },
 ""safebrowsing"" : {
   ""enabled"" : false,
   ""reporting_enabled"" : false
 },
 ""net"": {""network_prediction_options"": 2},
 ""bookmark_bar"" : {
   ""show_on_all_tabs"" : true
 },
 ""distribution"" : {
  ""import_bookmarks"" : false,
  ""import_history"" : false,
  ""import_home_page"" : false,
  ""import_search_engine"" : false,
  ""suppress_first_run_bubble"" : true,
  ""do_not_create_desktop_shortcut"" : true,
  ""do_not_create_quick_launch_shortcut"" : true,
  ""do_not_create_taskbar_shortcut"" : true,
  ""do_not_launch_chrome"" : true,
  ""do_not_register_for_update_launch"" : true,
  ""make_chrome_default"" : false,
  ""make_chrome_default_for_user"" : false,
  ""msi"" : true,
  ""require_eula"" : false,
  ""suppress_first_run_default_browser_prompt"" : true,
  ""system_level"" : true,
  ""verbose_logging"" : true
 },
 ""first_run_tabs"" : [
   ""http://www.google.com"",
   ""welcome_page"",
   ""new_tab_page""
 ]
}
"
}

function CustomizeChrome{

  # Add Default Search engines on Chrome
      # http://ludovic.chabant.com/devblog/2010/12/29/poor-mans-search-engines-sync-for-google-chrome/
      # Chrome search string (for manually adding): https://encrypted.google.com/search?hl=en&as_q=%s
      # https://productforums.google.com/forum/#!topic/chrome/7a5G3eGur5Y
      # Disable 3rd party cookies

  # Change Edge default search engine and home page

}

function InstallOpera{
  Write-Output "Installing Opera..."
  #$URL="https://www.opera.com/da/computer/thanks?ni=stable&os=windows"
  $URL="https://get.geo.opera.com/pub/opera/desktop/"

  # Scrape ftp site for latest Version
  $CheckURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
  if (! $CheckURL) {Write-Output "Error: URL not resolved"; return}
  $LatestOperaVersion=(Invoke-WebRequest -UseBasicParsing  -Uri $URL).Links.Href | Get-Unique -asstring | Sort-Object -Descending | select-object -First 1
  if (! $LatestOperaVersion) {Write-Output "Error: Opera browser not found"; return}
  $LatestOperaPath="$($URL)$($LatestOperaVersion)win/"
  $LatestOperaInstallerFiles=(Invoke-WebRequest -UseBasicParsing  -Uri $LatestOperaPath).Links.Href | Get-Unique -asstring | Sort-Object -Descending | Select-String -Pattern Autoupdate_x64 # | select-object -First 1
  # returns two objects (also a sha256 file)

  # Download file
  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  # FIXME - foreach file download
  Foreach ($file in $LatestOperaInstallerFiles)
  {
    $OperaInstallerFile=$LatestOperaPath + $file
    $FileName=([System.IO.Path]::GetFileName($OperaInstallerFile).Replace("%20"," "))
    $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath $FileName
    Write-Output "Downloading file from: $OperaInstallerFile"
    Start-BitsTransfer -Source $OperaInstallerFile -Destination $LocalFile

    # Install
    $FileType=([System.IO.Path]::GetExtension($Localfile))
    switch ($FileType){
            ".exe" {
                Write-Output "Starting installation of: $FileName"
                # .\Opera_66.0.3515.95_Setup_x64.exe --runimmediately --allusers=0 --setdefaultbrowser=0 --enable-installer-stats=0 --enable-stats=0
                Start-Process $LocalFile -NoNewWindow -Wait
                }
            # sha256 - https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7
      }
  }
}

function InstallAutopsy{
  # SleuthKit/InstallAutopsy
  # scrape github page - https://github.com/sleuthkit/autopsy/releases/
  # get 64 bit files like autopsy-4.14.0-64bit.msi and autopsy-4.14.0-64bit.msi.asc
}

################################################################
###### Auxiliary Functions  ###
################################################################

# Wait for keypress
Function WaitForKey {
	Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
	Write-Output "Restarting..."
	Restart-Computer
}



# Export functions
Export-ModuleMember -Function *
