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

  # A more recent blocklist is here:
  # https://www.encrypt-the-planet.com/downloads/hosts

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

#Test & check setting with this tool: https://dl5.oo-software.com/files/ooshutup10/OOSU10.zip
