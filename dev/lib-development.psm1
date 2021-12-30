
function InstallBurpPro{
  # https://portswigger.net/burp/releases/community/latest
  $URL="https://portswigger.net/burp/releases/community/latest"
  $PAGELINKS=(Invoke-WebRequest -UseBasicParsing –Uri $URL).Links
  $PACKAGELINK=($PAGELINKS | where { $_.href -Like "*64" -And $_.href -Like "*product=pro*" }).href
  $FullDownloadURL="https://portswigger.net$PACKAGELINK"

}

function InstallBurpCommunity{
  # https://portswigger.net/burp/releases/community/latest
  $URL="https://portswigger.net/burp/releases/community/latest"
  $PAGELINKS=(Invoke-WebRequest -UseBasicParsing –Uri $URL).Links
  $PACKAGELINK=($PAGELINKS | where { $_.href -Like "*64" -And $_.href -Like "*product=community*" }).href
  $DOWNLOADURL="https://portswigger.net$PACKAGELINK"

  # FIXME - missing install
}


function InstallActiveDirectoryRSAT{
  # https://theitbros.com/install-and-import-powershell-active-directory-module/
  <#
  # Windows Server
  Import-Module ServerManager
  Add-WindowsFeature -Name "RSAT-AD-PowerShell" –IncludeAllSubFeature

  # Windows 10 (up to 1803)
  Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell

  # Windows 10 (and later)
  Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”
  #>
}

function GetSecurityComplianceToolkit{
  # https://www.microsoft.com/en-us/download/details.aspx?id=55319
}

function CustomizeChrome{

  # Add Default Search engines on Chrome
      # http://ludovic.chabant.com/devblog/2010/12/29/poor-mans-search-engines-sync-for-google-chrome/
      # Chrome search string (for manually adding): https://encrypted.google.com/search?hl=en&as_q=%s
      # https://productforums.google.com/forum/#!topic/chrome/7a5G3eGur5Y
      # Disable 3rd party cookies

  # Change Edge default search engine and home page

}
