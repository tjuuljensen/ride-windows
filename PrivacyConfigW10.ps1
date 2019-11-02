#
# Privacy config Windows 10 script
# January 2016
#
# authored by Torsten Juul-Jensen
# last edited: February 15, 2017
# Script must be run with elevated privileges and Powershell ExecutionPolicy must be set. (THE NASTY WAY: Set-ExecutionPolicy Unrestricted)
#
# For Windows 10
# Check Anniversary Update changes on http://www.ghacks.net/2016/07/28/microsoft-removes-policies-windows-10-pro/

#Check for admin rights or restart script with admin right
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

function _createRegKey{
    # Function to check for registry keys and create them if the key does not exist
    param( [Parameter(mandatory=$true)] [string]$Path)

	# Test if the key exist and create it if it doesn't
	if(-not (Test-Path $Path))
	{
		# Create the key, since it doesn't exist already
		# The -Force parameter will create any non-existing parent keys recursively
		New-Item -Path $Path -Force
	}
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

function _addHostFileContent {
    # Puts a line i hosts file
    param(
        [Parameter(mandatory=$true)]
        [string]$IPAddress,
        [Parameter(mandatory=$true)]
        [string]$FQDN,
        [string]$Hostfile=(Join-Path -Path $([Environment]::GetEnvironmentVariable("windir")) -ChildPath "system32\drivers\etc\hosts")
        )

	if (-not (Test-Path -Path $Hostfile)){
	    Throw "Hosts file not found"
	    }
	    $data = Get-Content -Path $Hostfile
	    $data += "$IPAddress  $FQDN"
	    Set-Content -Value $data -Path $Hostfile -Force -Encoding ASCII
}

function _populateHostsFile{
	# List from https://github.com/WindowsLies/BlockWindows/blob/master/hosts
	# Check whether list is blocked by executing "ping telemetry.urs.microsoft.com"

    param(
        [string]$Hostfile=(Join-Path -Path $([Environment]::GetEnvironmentVariable("windir")) -ChildPath "system32\drivers\etc\hosts")
        )

	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a.ads1.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a.ads2.msads.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a.ads2.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a.rad.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0001.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0002.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0003.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0004.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0005.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0006.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0008.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0007.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-0009.a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ac3.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ad.doubleclick.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "adnexus.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "adnxs.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ads.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ads1.msads.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ads1.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "aidps.atdmt.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "aka-cdn-ns.adtech.de" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "a-msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "apps.skype.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "az361816.vo.msecnd.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "az512334.vo.msecnd.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "b.ads1.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "b.ads2.msads.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "b.rad.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "bingads.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "bs.serving-sys.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "c.atdmt.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "c.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "cdn.atdmt.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "cds26.ams9.msecn.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "choice.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "choice.microsoft.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "compatexchange.cloudapp.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "corp.sts.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "corpext.msitadfs.glbdns2.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "cs1.wpc.v0cdn.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "db3aqu.atdmt.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "df.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "diagnostics.support.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ec.atdmt.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "feedback.microsoft-hohm.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "feedback.search.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "feedback.windows.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "flex.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "g.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "h1.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "i1.services.social.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "i1.services.social.microsoft.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "lb1.www.ms.akadns.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "live.rads.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "m.adnxs.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "m.hotmail.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "msedge.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "msftncsi.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "msnbot-65-55-108-23.search.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "msntest.serving-sys.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "oca.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "oca.telemetry.microsoft.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "pre.footprintpredict.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "preview.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "pricelist.skype.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "rad.live.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "rad.msn.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "redir.metaservices.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "reports.wes.df.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "s.gateway.messenger.live.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "schemas.microsoft.akadns.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "secure.adnxs.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "secure.flashtalking.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "services.wes.df.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "settings-sandbox.data.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "settings-win.data.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "sO.2mdn.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "sqm.df.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "sqm.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "sqm.telemetry.microsoft.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ssw.live.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "static.2mdn.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "statsfe1.ws.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "statsfe2.update.microsoft.com.akadns.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "statsfe2.ws.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "survey.watson.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "telecommand.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "telecommand.telemetry.microsoft.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "telemetry.appex.bing.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "telemetry.urs.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "ui.skype.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "view.atdmt.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "vortex.data.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "vortex-bn2.metron.live.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "vortex-cy2.metron.live.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "vortex-sandbox.data.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "vortex-win.data.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "watson.live.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "watson.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "watson.ppe.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "watson.telemetry.microsoft.com" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "watson.telemetry.microsoft.com.nsatc.net" -Hostfile $Hostfile
	_addHostFileContent -IPAddress "0.0.0.0" -FQDN "wes.df.telemetry.microsoft.com" -Hostfile $Hostfile
}

function _SetWin10privacySettings(){
    # Sets a long list of Windows 10 privacy settings
    # See what can be configured how here: https://technet.microsoft.com/en-us/library/mt577208%28v=vs.85%29.aspx
    # A good listing over all Windows 10 privacy settings: https://4sysops.com/archives/windows-10-privacy-all-group-policy-settings
    # And more here: https://fix10.isleaked.com/
    # BTW: You should change your SSID on your WPA2 Wi-Fi: http://www.pcworld.com/article/2951824/windows/how-to-disable-windows-10s-wi-fi-sense-password-sharing.html

	# SmartScreen filter
	$regKey="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name EnableWebContentEvaluation -value 0

	# Opt out of web site offers based on language list
	$regKey="HKCU:\Control Panel\International\User Profile\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name HttpAcceptLanguageOptOut -value 1

	# "Let apps use my adverstising ID..."
	$regKey="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name Enabled -value 0

	#"Send Miccrosoft info about how ..." (typing and writing)
	$regKey="HKCU:\SOFTWARE\Microsoft\Input\TIPC\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name Enabled -value 0

	#"Send Miccrosoft info about how ..." (typing and writing)
	$regKey="HKCU:\SOFTWARE\Microsoft\Input\TIPC\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name Enabled -value 0

	# Disable Feedback frequency
	$regKey="HKCU:\SOFTWARE\Microsoft\Siuf\Rules\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name NumberOfSIUFInPeriod -value 0

	# Disable Microsoft Edge Page Prediction
	$regKey="HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name FPEnabled -value 0

	# Disable keylogger
	# Following command skipped (not shown in all guides): "cacls  C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl  /d SYSTEM"
	$command = 'cmd.exe /c echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl'
	Invoke-Expression -Command:$command

	# Disable Wifi Password Sharing
	$regKey="HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name AutoConnectAllowedOEM -value 0

	# Disable Windows Update Delivery Optimization
	$regKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name DownloadMode -value 0
	# Same shit - just the policy part (locks setting in the GUI)
	$regKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\"
	_createRegKey($regKey)
	Set-ItemProperty -path $regKey -name DODownloadMode -value 0

  # Disable Windows Store App - Windows Enterprise Only!!!
  $regKey="HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\"
  _createRegKey($regKey)
  Set-ItemProperty -path $regKey -name RemoveWindowsStore -value 1
  Set-ItemProperty -path $regKey -name DisableStoreApps -value 1

  # Disable Microsoft Consumer Experience
  # http://www.ghacks.net/2016/03/02/turn-off-microsoft-consumer-experience/
  $regKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\"
  _createRegKey($regKey)
  Set-ItemProperty -path $regKey -name DisableWindowsConsumerFeatures -value 1

}

function _uninstallWin10Apps{
	#Uninstall Store
	#Get-AppxPackage *windowsstore* | Remove-AppxPackage
	#Uninstall 3D Builder
	Get-AppxPackage *3dbuilder* | Remove-AppxPackage
	#Uninstall Alarms and Clock
	Get-AppxPackage *windowsalarms* | Remove-AppxPackage
	#Uninstall Calculator
	Get-AppxPackage *windowscalculator* | Remove-AppxPackage
	#Uninstall Calendar and Mail
	Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
	#Uninstall Camera
	Get-AppxPackage *windowscamera* | Remove-AppxPackage
	#Uninstall Get Office
	Get-AppxPackage *officehub* | Remove-AppxPackage
	#Uninstall Get Skype
	Get-AppxPackage *skypeapp* | Remove-AppxPackage
	#Uninstall Get Started
	Get-AppxPackage *getstarted* | Remove-AppxPackage
	#Uninstall Groove Music
	Get-AppxPackage *zunemusic* | Remove-AppxPackage
	#Uninstall Maps
	Get-AppxPackage *windowsmaps* | Remove-AppxPackage
	#Uninstall Microsoft Solitaire Collection
	Get-AppxPackage *solitairecollection* | Remove-AppxPackage
	#Uninstall Money
	Get-AppxPackage *bingfinance* | Remove-AppxPackage
	#Uninstall Movies & TV
	Get-AppxPackage *zunevideo* | Remove-AppxPackage
	#Uninstall News
	Get-AppxPackage *bingnews* | Remove-AppxPackage
	#Uninstall OneNote
	Get-AppxPackage *onenote* | Remove-AppxPackage
	#Uninstall People
	Get-AppxPackage *people* | Remove-AppxPackage
	#Uninstall Phone Companion:
	Get-AppxPackage *windowsphone* | Remove-AppxPackage
	#Uninstall Photos
	Get-AppxPackage *photos* | Remove-AppxPackage
	#Uninstall Sports
	Get-AppxPackage *bingsports* | Remove-AppxPackage
	#Uninstall Voice Recorder:
	Get-AppxPackage *soundrecorder* | Remove-AppxPackage
	#Uninstall Weather
	Get-AppxPackage *bingweather* | Remove-AppxPackage
	#Uninstall Xbox
	Get-AppxPackage *xboxapp* | Remove-AppxPackage
}

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

function _RemoveOnedrive{
    #Remove 64bit OneDrive from Explorer
    #http://www.howtogeek.com/225973/how-to-disable-onedrive-and-remove-it-from-file-explorer-on-windows-10/
    New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
    $regKey="HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\"
    _createRegKey($regKey)
    Set-ItemProperty -path $regKey -name System.IsPinnedToNameSpaceTree -value 0
    $regKey="HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\"
    _createRegKey($regKey)
    Set-ItemProperty -path $regKey -name System.IsPinnedToNameSpaceTree -value 0
    # Prevent OneDrive from running at startup
    $regkey="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    Remove-ItemProperty -Path $regkey -name OneDrive
}

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

function _fixServices{
    # Disabling services
    # check disabled state via WMI: gwmi win32_service -filter "name = 'WinHttpAutoProxySvc' OR name = 'SSDPSRV' OR name = 'upnphost'"
    Get-Service WinHttpAutoProxySvc,SSDPSRV,upnphost,DiagTrack,dmwappushservice | Stop-Service -PassThru -Force | Set-Service -StartupType disabled

    # Stopping services  & setting them to manual
    Get-Service WerSvc | Stop-Service -PassThru -Force | Set-Service -StartupType manual
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

function _disableIPv6{
    # Disable IPv6 machine-wide using registry
    # http://blogs.technet.com/b/askpfeplat/archive/2014/09/15/a-5-second-boot-optimization-if-you-ve-disabled-ipv6-on-windows-client-and-server-by-setting-disabledcomponents-to-0xffffffff.aspx
    New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\' -Name  'DisabledComponents' -Value '0xffffffff' -PropertyType 'DWord'

    # Disable ISATAP, Teredo and 6to4
    # Read more in Mark Minasi's newletter: http://www.minasi.com/newsletters/nws1303.htm
    set-net6to4configuration -state disabled
    set-NetTeredoConfiguration -type disabled
    set-netisatapconfiguration -state disabled
}

function _fixNICconfig{
    # Disable NetBIOS and disable DNS registration
    # NETBIOS AND MORE: http://www.remilner.co.uk/some-useful-server-2012-powershell-commands/
    # 					http://www.alexmags.com/infra/2015/03/12/powershell-to-disable-netbios-over-tcpip/

    param(
        [parameter(ValueFromPipeline=$true)]
        [string[]]$NIC
    )

      # Code below SHOULD work, but doesn't. :-(
      #$searchString="Description LIKE '"+$NIC[0]+"%'"
      #for ($i=1; $i -lt $NIC.length; $i++) {
      #	$searchString="Description LIKE '%"+$NIC[$i]+"%' OR "+$searchString
      #    }
    $LocalNIC=Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=True #DISABLED: -Filter "$searchString"
    $LocalNIC.SetTcpipNetbios(2)
    $LocalNIC.SetDynamicDNSRegistration($false,$false)

    # Disable IPv6 and File and Printer Sharing on "Ethernet"
    $searchString="$_.InterfaceDescription -like '"+$NIC[0]+"*'"
    for ($i=1; $i -lt $NIC.length; $i++) {
	    $searchString="$_.InterfaceDescription -like '"+$NIC[$i]+"*' -or "+$searchString
        }
    Get-NetAdapter | where-object {$searchString} | Disable-NetAdapterBinding -ComponentID ms_server
    Get-NetAdapter | where-object {$searchString} | Disable-NetAdapterBinding -ComponentID ms_tcpip6

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

function _installMiscPrograms {
    # Install CERT specific programs from SMB server

    param([string]$UserName = [Environment]::UserName)

     # Local paths
    $LocalDNScheck = "fileserver.domain.tld"
    $FileServerRoot = "\\fileserver\sharename"
    $SYMANTEC_EP_PATH = "\\fileserver\sharename\Antivirus\SymantecEP\setup_1003_64bit_laptops.exe"

    if (Resolve-DnsName $LocalDNScheck) {
        # Download from network and install
        $credential = Get-Credential -Message "Enter network credentials:" -UserName ($UserName)
        New-PSDrive -Name FileServer -PSProvider FileSystem -Root $FileServerRoot -Credential $credential | ForEach-Object { Set-Location "$_`:" }

        Start-Process ($SYMANTEC_EP_PATH) /s -NoNewWindow -Wait
        # TODO: Install MS Office from Installpoint
    }
}

function _customizeStartMenu{
    #http://ccmexec.com/2015/09/customizing-the-windows-10-start-menu-and-add-ie-shortcut-during-osd/
}

function _whatsLeftForTheUser{
  # Misc. Configs

  # Firefox (Encrypted Google) search: http://www.adminarsenal.com/admin-arsenal-blog/powershell-silently-change-firefox-default-search-providers-for-us/
  # Create Desktop shortcut? : http://stackoverflow.com/questions/9701840/how-to-create-a-shortcut-using-powershell
  $AppLocation = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
  $WshShell = New-Object -ComObject WScript.Shell
  $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Add Google (encrypted) Search.lnk")
  $Shortcut.TargetPath = $AppLocation
  $Shortcut.Arguments ="https://addons.mozilla.org/en-US/firefox/addon/google-encrypted-/"
  $Shortcut.IconLocation = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe,1"
  $Shortcut.Description ="Add Encrypted Google Search to Firefox"
  $Shortcut.WorkingDirectory ="C:\Program Files (x86)\Mozilla Firefox"
  $Shortcut.Save()


  # Add Default Search engines on Chrome
      # http://ludovic.chabant.com/devblog/2010/12/29/poor-mans-search-engines-sync-for-google-chrome/
      # Chrome search string (for manually adding): https://encrypted.google.com/search?hl=en&as_q=%s
      # https://productforums.google.com/forum/#!topic/chrome/7a5G3eGur5Y

  # Change Edge default search engine and home page

  #Download vmware workstation
  $AppLocation = _DownloadWebFile (_ResolveURL http://www.vmware.com/go/tryworkstation-win)
  # DOC HERE: https://pubs.vmware.com/workstation-12/index.jsp?topic=%2Fcom.vmware.ws.using.doc%2FGUID-F3F1A8B9-D298-4461-BEAB-185CE3E158ED.html
  $WshShell = New-Object -ComObject WScript.Shell
  $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Install VMware Workstation Pro.lnk")
  $Shortcut.TargetPath = $AppLocation
  $Shortcut.Arguments ="/s /v/qn REBOOT=ReallySuppress ADDLOCAL=ALL EULAS_AGREED=1 SERIALNUMBER=""XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"""
  $Shortcut.Description ="Start silent installation of VMware Workstation Pro"
  #$Shortcut.WorkingDirectory ="C:\Windows\System32"
  $Shortcut.Save()

  # Check for bitlocker and encrypt drives

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

  # Install Office
  # Activate Office

}

#########################################################################################

#Load Modules
Import-Module NetAdapter
# MORE TO LOAD

#Disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true
Start-Sleep -m 2000

# Calling functions
_populateHostsFile
_fixServices
_uninstallWin10Apps
_SetWin10privacySettings
_RemoveOnedrive
_fixWPAD
_configureBitLocker
_disableMulticast
_disableIPv6
_fixNICconfig "Intel", "Lenovo", "Thinkpad", "ASIX"

#_activateWin10 -Enterprise
_installPrograms
_installMiscPrograms

_whatsLeftForTheUser

#Test & check setting with this tool: https://dl5.oo-software.com/files/ooshutup10/OOSU10.zip
