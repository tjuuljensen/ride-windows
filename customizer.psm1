##########
# Customizer for Disassembler0's Win10-Initial-Setup-Script
# Win 10 / Server 2016 / Server 2019 Initial Setup Script
# Author: Torsten Juul-Jensen
# Version: v1.0, 2019-11-02
# Source: https://github.com/tjuuljensen/win10-initial-customized
##########


##########
#
##########

function SetBitLockerAES256{
    # Set BitLocker to AES-256
    # Check with "manage-bde -status"
    # Encrypt AFTERWARDS!
    # See more here: http://www.howtogeek.com/193649/how-to-make-bitlocker-use-256-bit-aes-encryption-instead-of-128-bit-aes/
    $regKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE\"
    _createRegKey($regKey)
    Set-ItemProperty -path $regKey -name EncryptionMethod -value 4
    #To-do: start BitLocker Encryption with PowerShell https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
}

function DisableMulticastDNS{
    # Disable Multicast
    $multiCastRegKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    _createRegKey($multiCastRegKey)
    New-ItemProperty -path $multiCastRegKey -name EnableMulticast -value 0 -PropertyType DWord -Force
}

function DisableIEProxyAutoconfig{
    # Disable IE proxy autoconfig by editing binary registry value
    # prevents WPAD atttack
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
    $data = (Get-ItemProperty -Path $key -Name DefaultConnectionSettings).DefaultConnectionSettings
    $data[8] = 1
    Set-ItemProperty -Path $key -Name DefaultConnectionSettings -Value $data
}


function _SetWin10privacySettings(){
  # Sets a long list of Windows 10 privacy settings
  # See what can be configured how here: https://technet.microsoft.com/en-us/library/mt577208%28v=vs.85%29.aspx
  # A good listing over all Windows 10 privacy settings: https://4sysops.com/archives/windows-10-privacy-all-group-policy-settings
  # And more here: https://fix10.isleaked.com/
  # BTW: You should change your SSID on your WPA2 Wi-Fi: http://www.pcworld.com/article/2951824/windows/how-to-disable-windows-10s-wi-fi-sense-password-sharing.html

	#"Send Microsoft info about how ..." (typing and writing)
	$regKey="HKCU:\SOFTWARE\Microsoft\Input\TIPC\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name Enabled -value 0

	# Disable Microsoft Edge Page Prediction
  # When Page Prediction is enabled in Microsoft Edge, the browser might crawl pages you never actually visit during the browsing session. This exposes your machine fingerprint and also creates a notable load on PCs with low end hardware because the browser calculates the possible URL address every time you type something into the address bar. It also creates potentially unnecessary bandwidth usage.
	$regKey="HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name FPEnabled -value 0

  # Disable Windows Store App - Windows Enterprise Only!!!
  $regKey="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\"
  _createRegKey($regKey)
  Set-ItemProperty -path $regKey -name RemoveWindowsStore -value 1
  Set-ItemProperty -path $regKey -name DisableStoreApps -value 1
}

# SSDP Discovery service is required for UPnP and Media Center Extender (as per Windows Services > Dependencies tab for SSDP discovery) and so if you don't need UPnP it won't have any negative affects.
# Network Management in Windows isn't affected by SSDP; you can confidently disable it
function _fixServices{
    # Disabling services
    # check disabled state via WMI: gwmi win32_service -filter "name = 'WinHttpAutoProxySvc' OR name = 'SSDPSRV' OR name = 'upnphost'"
    Get-Service WinHttpAutoProxySvc,SSDPSRV,upnphost | Stop-Service -PassThru -Force | Set-Service -StartupType disabled

    #### FIXME
    #### Se hvordan dmwappushservice er implementeret i Win10.psm1 og lav det på samme måde med de andre

    # Stopping services  & setting them to manual
    Get-Service WerSvc | Stop-Service -PassThru -Force | Set-Service -StartupType manual
}

# Upnp: Without UPnP enabled things like torrents and multiplayer gaming won't work properly unless you manually identify and forward all the ports required

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

  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
  Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart

  # Return the Windows version
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
}

function ActivateWin10{

  if ((Get-WindowsEdition -Online | select Edition) -like "*Professional*"){$key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}
  if ((Get-WindowsEdition -Online | select Edition) -like "*Enterprise*"){$key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}

	$computer = gc env:computername

	$service = get-wmiObject -query "select * from SoftwareLicensingService" -computername $computer
	$service.InstallProductKey($key)
	$service.RefreshLicenseStatus()
}

function Sysprep{
  # sysprep installation - for templates
}

########
# Install 3rd party programs
########

function InstallSpiceGuestTool{
  # Install spice guest tool (for boxes)
  # https://www.spice-space.org/download.html
  # Check article : https://www.ctrl.blog/entry/how-to-win10-in-gnome-boxes.html

  # download spice tools
  #
  #https://spice-space.org/download/windows/spice-webdavd/spice-webdavd-x64-latest.msi
  # https://spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe

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

function _ResolveURL {
    # Get filename from URL (redirected or direct)

    Param (
        [Parameter(Mandatory=$true)]
        [String]$Path
    )

    $request = [System.Net.WebRequest]::Create($Path)
    $request.AllowAutoRedirect=$false
    $response=$request.GetResponse()

    switch([int]$response.StatusCode){

        200 {$Path} # OK
        302 {$response.GetResponseHeader("Location")} # Redirect
        #default {Write-host "Nothing happened"}
        }
}

function _DownloadWebFile{
    # Download a file from an exploded URL and return local filename as return argument

    Param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [ValidateNotNullOrEmpty()]
        [string]$DownloadDirectory=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}", # Default Download Directory

        [ValidateNotNullOrEmpty()]
        [string]$FileName=([System.IO.Path]::GetFileName($URL))
    )

    $LocalFile = Join-Path -Path $DownloadDirectory -ChildPath ([System.IO.Path]::GetFileName($FileName).Replace("%20"," "))

    (New-Object System.Net.WebClient).DownloadFile($URL, $LocalFile)
    $localFile #return local filename
    }


function InstallFirefox{
    # Define Download URL
    $URL="https://download.mozilla.org/?product=firefox-latest&os=win&lang=en-US" #Resolve full URL filename (as this is a redirect)

    $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"

    # Resolve full download URL
    $request = [System.Net.WebRequest]::Create($URL)
    $request.AllowAutoRedirect=$false
    $response=$request.GetResponse()

    switch([int]$response.StatusCode){

        200 {$FullDownloadURL = $URL} # OK
        302 {$FullDownloadURL = $response.GetResponseHeader("Location")} # Redirect
        default {Write-host "Did not resolve URL"
                  return 1}
        }

    $FileName=([System.IO.Path]::GetFileName($FullDownloadURL))
    $LocalFile = Join-Path -Path $DefaultDownloadDir -ChildPath ([System.IO.Path]::GetFileName($FileName).Replace("%20"," "))

    # Download file
    (New-Object System.Net.WebClient).DownloadFile($FullDownloadURL, $LocalFile)

    # Install Firefox and make customizations
    Start-Process ($LocalFile) /s -NoNewWindow -Wait
}

function InstallChrome{
    # Define Download URL
    $CHROMEMSIURL = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B41280CF8-747D-3F47-BA8E-0E6CEDBB4C51%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable/dl/chrome/install/googlechromestandaloneenterprise64.msi"

    # Install Chrome and make customization
    # Read more about deployment on Chrome here: https://support.google.com/chrome/a/answer/3115278?hl=en
    msiexec.exe /i (_DownloadWebFile $CHROMEMSIURL) /quiet | Out-Null
    _createChromePreferenceFiles
}

function InstallGPGwin{
    # Define Download URL
    $GPGWINURL="https://files.gpg4win.org/gpg4win-latest.exe"

    # Install other programs
    Start-Process (_DownloadWebFile $GPGWINURL) /S -NoNewWindow -Wait
}

function InstallThunderbird{
    # Define Download URL
    $THUNDERBIRDURL= _ResolveURL -Path "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=en-US" #Resolve full URL filename (as this is a redirect)
  Start-Process (_DownloadWebFile $THUNDERBIRDURL) /s -NoNewWindow -Wait
}

function InstallOffice365{
  # download and install office365 using office deployment tool

  # Avoid security warning
  # remember to test on freshly configured system (when IE wizard is not complete)
  # reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /t REG_DWORD /v 1A10 /f /d 0

  $DefaultDownloadDir=(Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $OFFICEDEPLOYMENTOOLURL="https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117"

  $DOWNLOADLINK=(Invoke-WebRequest -UseBasicParsing  -Uri $OFFICEDEPLOYMENTOOLURL).Links.Href | Get-Unique -asstring| Select-String -Pattern officedeploymenttool
  $OUTFILE = "$DefaultDownloadDir\officedeploymenttool.exe"
  $OutFilename=[System.IO.Path]::GetFileName($DOWNLOADLINK)
  $OFFICE365XML="$DEPLOYWORKDIR\custom-Office365-x86.xml"

  Import-Module BitsTransfer
  Start-BitsTransfer -Source $DOWNLOADLINK -Destination $OutFilename

  $DEPLOYWORKDIR="$DefaultDownloadDir\office365deploy"
  Invoke-Expression "$OutFilename /quiet /extract:$DEPLOYWORKDIR"

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
  </Configuration>' |  Out-File $OFFICE365XML

  # start download
  Invoke-Expression "$DEPLOYWORKDIR\setup.exe /download $OFFICE365XML"

  # this must follow in the end
  # reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v 1A10 /f

  # start install
  Invoke-Expression "$DEPLOYWORKDIR\setup.exe /configure $OFFICE365XML"

}

##########
# Browser tweaks and functions
##########

#
function _createFirefoxPreferenceFiles {
  # See more at https://developer.mozilla.org/en-US/Firefox/Enterprise_deployment

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

function _createChromePreferenceFiles {

param($ChromeInstallDir=([System.Environment]::GetFolderPath("ProgramFilesX86")+"\Google\Chrome\Application\"))

# Create the master_preferences file
# File contents based on source fils: https://src.chromium.org/viewvc/chrome/trunk/src/chrome/common/pref_names.cc
New-Item ($chromeInstallDir+"master_preferences") -type file -force -value "{
 ""homepage"" : ""https://encrypted.google.com"",
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
   ""http://encrypted.google.com"",
   ""welcome_page"",
   ""new_tab_page""
 ]
}
"
}


##########
#region Auxiliary Functions
##########

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

##########
#endregion Auxiliary Functions
##########


# Export functions
Export-ModuleMember -Function *
