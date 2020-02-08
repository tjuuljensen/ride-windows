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

function _configureBitLocker{
    # Set BitLocker to AES-256
    # Check with "manage-bde -status"
    # Encrypt AFTERWARDS!
    # See more here: http://www.howtogeek.com/193649/how-to-make-bitlocker-use-256-bit-aes-encryption-instead-of-128-bit-aes/
    $regKey="HKLM:\SOFTWARE\Policies\Microsoft\FVE\"
    _createRegKey($regKey)
    Set-ItemProperty -path $regKey -name EncryptionMethod -value 4
    #To-do: start BitLocker Encryption with PowerShell https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
}

function _disableMulticast{
    # Disable Multicast
    $multiCastRegKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    _createRegKey($multiCastRegKey)
    New-ItemProperty -path $multiCastRegKey -name EnableMulticast -value 0 -PropertyType DWord -Force
}

function _fixWPAD{
    # Disable IE proxy autoconfig by editing binary registry value
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


function _activateWin10{
    param(
        [parameter(Mandatory=$true,ParameterSetName = "SuppliedKey")]
	    [ValidateNotNullOrEmpty()]
        [string]$key,
        [parameter(Mandatory=$true,ParameterSetName = "Enterprise")]
	    [ValidateNotNullOrEmpty()]
        [switch]$Enterprise,
        [parameter(Mandatory=$true,ParameterSetName = "Professional")]
	    [ValidateNotNullOrEmpty()]
        [switch]$Professional
    )

    if ($Enterprise){$key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}
    if ($Professional){$key="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"}

	$computer = gc env:computername

	$service = get-wmiObject -query "select * from SoftwareLicensingService" -computername $computer
	$service.InstallProductKey($key)
	$service.RefreshLicenseStatus()

}

function Sysprep{
  # sysprep installation - for templates
}

function InstallOffice365{
  #https://www.microsoft.com/en-us/download/details.aspx?id=49117
}

########
# Install 3rd party programs
########

function _installSpiceGuestTool{
  #Install spice guest tool (for boxes)
  #https://www.spice-space.org/download.html

  # Spice webdavd for folder sharing
  #https://www.spice-space.org/download/windows/spice-webdavd/
  # https://www.spice-space.org/download/windows/spice-webdavd/spice-webdavd-x64-latest.msi

  # Check article : https://www.ctrl.blog/entry/how-to-win10-in-gnome-boxes.html
}

function _installPrograms{
    #Install programs

    # Define Download URLs
    $FIREFOXURL= _ResolveURL -Path "https://download.mozilla.org/?product=firefox-latest&os=win&lang=en-US" #Resolve full URL filename (as this is a redirect)
    $THUNDERBIRDURL= _ResolveURL -Path "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=en-US" #Resolve full URL filename (as this is a redirect)
    $CHROMEMSIURL = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B41280CF8-747D-3F47-BA8E-0E6CEDBB4C51%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable/dl/chrome/install/googlechromestandaloneenterprise64.msi"
    $GPGWINURL="https://files.gpg4win.org/gpg4win-2.3.3.exe" #NOTICE! get latest version @ https://www.gpg4win.org/download.html

    # Install Firefox and make customizations
    Start-Process (_DownloadWebFile $FIREFOXURL) /s -NoNewWindow -Wait
    _createFirefoxPreferenceFiles

    # Install Chrome and make customization
    # Read more about deployment on Chrome here: https://support.google.com/chrome/a/answer/3115278?hl=en
    msiexec.exe /i (_DownloadWebFile $CHROMEMSIURL) /quiet | Out-Null
    _createChromePreferenceFiles

    # Install other programs
    Start-Process (_DownloadWebFile $THUNDERBIRDURL) /s -NoNewWindow -Wait
    Start-Process (_DownloadWebFile $GPGWINURL) /S -NoNewWindow -Wait

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
