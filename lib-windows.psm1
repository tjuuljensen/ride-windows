# Windows 10 / Windows 11 / Server 2016 / Server 2019 Setup Script
# Author: Torsten Juul-Jensen
# Version: v2.5, 2023-10-27
# Source: https://github.com/tjuuljensen/ride-windows/lib-windows.psm1
#

################################################################
###### Windows configuration  ###
################################################################

function StopComputer {
  Stop-Computer
}

function ActivateWindows{
  Write-Output "###"
  Write-Output "Activating Windows from INI file/Environment variable..."

  # Determine variable name holding Windows License Key - loaded from ini file
  if (([Environment]::OSVersion.Version).Major -eq "10") { # Either Windows 10 or 11
    $WindowsBuild= ([Environment]::OSVersion.Version).Build
    $WindowsEdition=(Get-WindowsEdition -Online).Edition
    Switch( $WindowsBuild )
    {
      ({$PSItem -lt 20000 -and $PSItem -gt 10240})
        { $WindowsVersion=("Windows" + "10" + $WindowsEdition)}
      ({$PSItem -ge 22000})
        { $WindowsVersion=("Windows" + "11" + $WindowsEdition)}
    }
  }

  # Read variable content (if any) and install licence key if it exists
  $LicenseKey = [Environment]::GetEnvironmentVariable("RIDEVAR-WindowsKey-$WindowsVersion", "Process")
  if ( $LicenseKey -ne $null ) {
    $computer = Get-Content Env:ComputerName

    $service = Get-WmiObject -Query "select * from SoftwareLicensingService" -ComputerName $computer
    $service.InstallProductKey($LicenseKey)
    $service.RefreshLicenseStatus()
  }
}


function ActivateWindowsOEM{
  Write-Output "###"
  Write-Output "Activating Windows with OEM license in BIOS..."

  # implement decoder
  $code = @'
// original implementation: https://github.com/mrpeardotnet/WinProdKeyFinder
using System;
using System.Collections;

  public static class Decoder
  {
        public static string DecodeProductKeyWin7(byte[] digitalProductId)
        {
            const int keyStartIndex = 52;
            const int keyEndIndex = keyStartIndex + 15;
            var digits = new[]
            {
                'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R',
                'T', 'V', 'W', 'X', 'Y', '2', '3', '4', '6', '7', '8', '9',
            };
            const int decodeLength = 29;
            const int decodeStringLength = 15;
            var decodedChars = new char[decodeLength];
            var hexPid = new ArrayList();
            for (var i = keyStartIndex; i <= keyEndIndex; i++)
            {
                hexPid.Add(digitalProductId[i]);
            }
            for (var i = decodeLength - 1; i >= 0; i--)
            {
                // Every sixth char is a separator.
                if ((i + 1) % 6 == 0)
                {
                    decodedChars[i] = '-';
                }
                else
                {
                    // Do the actual decoding.
                    var digitMapIndex = 0;
                    for (var j = decodeStringLength - 1; j >= 0; j--)
                    {
                        var byteValue = (digitMapIndex << 8) | (byte)hexPid[j];
                        hexPid[j] = (byte)(byteValue / 24);
                        digitMapIndex = byteValue % 24;
                        decodedChars[i] = digits[digitMapIndex];
                    }
                }
            }
            return new string(decodedChars);
        }

        public static string DecodeProductKey(byte[] digitalProductId)
        {
            var key = String.Empty;
            const int keyOffset = 52;
            var isWin8 = (byte)((digitalProductId[66] / 6) & 1);
            digitalProductId[66] = (byte)((digitalProductId[66] & 0xf7) | (isWin8 & 2) * 4);

            const string digits = "BCDFGHJKMPQRTVWXY2346789";
            var last = 0;
            for (var i = 24; i >= 0; i--)
            {
                var current = 0;
                for (var j = 14; j >= 0; j--)
                {
                    current = current*256;
                    current = digitalProductId[j + keyOffset] + current;
                    digitalProductId[j + keyOffset] = (byte)(current/24);
                    current = current%24;
                    last = current;
                }
                key = digits[current] + key;
            }

            var keypart1 = key.Substring(1, last);
            var keypart2 = key.Substring(last + 1, key.Length - (last + 1));
            key = keypart1 + "N" + keypart2;

            for (var i = 5; i < key.Length; i += 6)
            {
                key = key.Insert(i, "-");
            }

            return key;
        }
   }
'@
  # compile c#:
  Add-Type -TypeDefinition $code
 
  # get raw product key:
  $digitalId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DigitalProductId).DigitalProductId
  
  # use static c# method to get LicenseKey
  $LicenseKey = [Decoder]::DecodeProductKey($digitalId)

  # Install licence key 
  if ( $null -ne $LicenseKey ) {
    Write-Output "OEM license: $LicenseKey"
    $computer = Get-Content Env:ComputerName

    $service = Get-WmiObject -Query "select * from SoftwareLicensingService" -ComputerName $computer
    $service.InstallProductKey($LicenseKey)
    $service.RefreshLicenseStatus()
    }
  else {
    Write-Output "OEM license not found..."
  }
}


function CreateNewLocalAdmin{
  Write-Output "###"
  # Tested on Windows 10 Pro 10.0.19044

  $DefaultAdminName="admin"
  $LocalAdminUser = if ($null -eq [Environment]::GetEnvironmentVariable("RIDEVAR-LocalAdmin-AdminUser", "Process")) {$DefaultAdminName}  else {[Environment]::GetEnvironmentVariable("RIDEVAR-LocalAdmin-AdminUser", "Process")}

  if ((Get-LocalUser $LocalAdminUser -ErrorAction Ignore).count -eq 1) {
    write-output "ERROR: User $LocalAdminUser exists - Exiting."
  } else {
    # If Password was set in ini file, use this

   if ($null -ne [Environment]::GetEnvironmentVariable("RIDEVAR-LocalAdmin-AdminPassword", "Process") -and ([Environment]::GetEnvironmentVariable("RIDEVAR-LocalAdmin-AdminPassword", "Process")).tolower() -ne "[prompt]") {
          $Password = ConvertTo-SecureString -String $([Environment]::GetEnvironmentVariable("RIDEVAR-LocalAdmin-AdminPassword", "Process"))
        } else {
          $Password = Read-Host -AsSecureString "Enter password of the Local Admin User: "
        }

    Write-Output "Creating local admin user: $LocalAdminUser"
    New-LocalUser $LocalAdminUser -Password $Password -FullName "Local Administrator" -Description "Replacement for default Administrator Account" | Out-Null

    Add-LocalGroupMember -Group "Administrators" -Member $LocalAdminUser
  }
}

function DisableBuiltinAdministrator{
  Write-Output "###"
  # Tested on Windows 10 Pro 10.0.19044

  $AdditionalLocalAdmins=Get-LocalGroupMember -group "Administrators" | Where-Object Name -NotLike "*\Administrator"
  if ( $AdditionalLocalAdmins.count -gt 0 ) {
      Disable-LocalUser -Name "Administrator"
      Write-Output "Builtin\Administrator disabled"
  } else {
     Write-Output "ERROR: You need other users in the Administrators group before disabling the default Administrator"
  }
}

function MakeLoggedOnUserAdmin {
  Write-Output "###"
  $Group = "Administrators"
  Write-Output "Adding logged on user to the $Group group..."
    
  $Member = (Get-CimInstance -ClassName Win32_ComputerSystem).Username
  $Group = "Administrators"
        
  # Is it an admin
  if ($null -ne (Get-LocalGroupMember -Group $Group | Where-Object { $_.Name -eq $Member})) {
      Write-Output "$Member is already a member of the $Group group" 
  } else {
      Write-Output "Adding $Member to the $Group group" 
      Add-LocalGroupMember -Group $Group -Member $Member
  }
}

function MakeLoggedOnUserNoAdmin {
  Write-Output "###"
  $Group = "Administrators"
  Write-Output "Removing logged on user from $Group..."
 
  $Member = (Get-CimInstance -ClassName Win32_ComputerSystem).Username

  if ($null -ne (Get-LocalGroupMember -Group $Group | Where-Object { $_.Name -eq $Member})) {
    Write-Output "Removing $Member from the $Group group" 
    Remove-LocalGroupMember -Group "$Group" -Member $Member -ErrorAction SilentlyContinue
  } else {
    Write-Output "$Member is not a member of the $Group group" 
  }
  
}

function AddWiFi {
  # Add Wifi profiles based on data from INI file 
  # Original source: https://www.cyberdrain.com/automating-with-powershell-deploying-wifi-profiles/
  # 
  # If PSK password is not defined in INI file, or if INI line contains "[prompt]", password will be prompted at run time

  # Reference to variable names SSID, SSID1, ... defined in INI file [WiFi] section
  $SSIDvars = @("RIDEVAR-WiFi-SSID","RIDEVAR-WiFi-SSID1","RIDEVAR-WiFi-SSID2")
  $SSIDpwdvars = @("RIDEVAR-WiFi-SSIDpwd","RIDEVAR-WiFi-SSIDpwd1","RIDEVAR-WiFi-SSIDpwd2")

  $i = 0
  foreach ($SSIDname in $SSIDvars) {

    # Get SSID name and PSK from environment variables
    $SSID = [Environment]::GetEnvironmentVariable($SSIDname, "Process")
    if ($SSID) {
      $PSK = [Environment]::GetEnvironmentVariable($SSIDpwdvars[$i], "Process")
      if (-not $PSK -or "[prompt]" -eq $PSK.tolower) {
        # Read PSK from console
        if ($PSVersionTable.PSVersion -ge [version]"7.1") {
          $PSK = Read-Host -MaskInput "Enter password for SSID ${SSID} "
          }
        else {
          $PSK = Read-Host "Enter password for SSID ${SSID} "
          }
        }
        
        # Create XML file with WiFi data to import
        $guid = New-Guid
        $HexArray = $SSID.ToCharArray() | foreach-object { [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($_)) }
			  $HexSSID = $HexArray -join ""
@"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>$($SSID)</name>
	<SSIDConfig>
		<SSID>
			<hex>$($HexSSID)</hex>
			<name>$($SSID)</name>
		</SSID>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption>
				<authentication>WPA2PSK</authentication>
				<encryption>AES</encryption>
				<useOneX>false</useOneX>
			</authEncryption>
			<sharedKey>
				<keyType>passPhrase</keyType>
				<protected>false</protected>
				<keyMaterial>$($PSK)</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
	<MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
		<enableRandomization>false</enableRandomization>
		<randomizationSeed>1451755948</randomizationSeed>
	</MacRandomization>
</WLANProfile>
"@ 			| out-file "$($ENV:TEMP)\$guid.SSID"
		
        # Add WiFi profile
        netsh wlan add profile filename="$($ENV:TEMP)\$guid.SSID" user=all
        
        # Remove temp file
        remove-item "$($ENV:TEMP)\$guid.SSID" -Force
    }
  $i = $i +1  
  }
}


function DisableWindowsStoreApp{
  Write-Output "###"
  # Disable Windows Store App - Windows Enterprise Only!!!
  Write-Output "Disabling Windows Store app (Windows Enterprise only)..."
  if ((Get-WindowsEdition -Online | Select-Object Edition) -like "*Enterprise*"){
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\" -Force | Out-Null
    }
    Set-ItemProperty -path $regKey -name RemoveWindowsStore -value 1
    Set-ItemProperty -path $regKey -name DisableStoreApps -value 1
  } else {
    Write-Output "INFO: This version of Windows is not Enterprise. Windows Store app is not disabled."
  }
}

function EnableWindowsStoreApp{
  Write-Output "###"
  # Disable Windows Store App - Windows Enterprise Only!!!
  Write-Output "Enabling Windows Store app (Windows Enterprise only)..."
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\" -Name "RemoveWindowsStore" -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore\" -Name "DisableStoreApps" -ErrorAction SilentlyContinue
}

function DisableFriendlyURLFormat{
  Write-Output "###"
  # Disable Friendly URL paste funtion from Microsoft Edge - can be HKLM or HKCU
  # https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::ConfigureFriendlyURLFormat
  Write-Output "Disabling Microsoft Edge Friendly URL Format..."

  If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge\")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge\" -Force | Out-Null
  }
  New-ItemProperty -path "HKCU:\SOFTWARE\Policies\Microsoft\Edge\" -name "ConfigureFriendlyURLFormat" -value 1 -PropertyType DWord -Force | Out-Null
}

function UnconfigureFriendlyURLFormat{
  Write-Output "###"
  # Unconfigure Friendly URL paste funtion from Microsoft Edge - can be HKLM or HKCU
  # https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::ConfigureFriendlyURLFormat
  Write-Output "Unconfiguring Microsoft Edge Friendly URL Format..."
  Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge\" -name "ConfigureFriendlyURLFormat"  -ErrorAction SilentlyContinue
}

function EnableRunAsInStartMenu{
  Write-Output "###"
  # https://winaero.com/add-run-start-menu-windows-10/
  Write-Output "Enabling RunAs context menu in Start Menu..."

  $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
  if (-not (Test-Path $Path)) {
    New-Item -Path $Path | Out-Null
  }
  Set-ItemProperty -path $Path -name "ShowRunAsDifferentUserInStart" -value 1 -Type DWord -Force | Out-Null
}

function DisableRunAsInStartMenu{
  Write-Output "###"
  # https://winaero.com/add-run-start-menu-windows-10/
  Write-Output "Disabling RunAs context menu in Start Menu..."
  Remove-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -name "ShowRunAsDifferentUserInStart" -ErrorAction SilentlyContinue
}

function EnableInternetPrinting{
  Write-Output "###"
  Write-Output "Enabling Internet Printing..."
  Enable-WindowsOptionalFeature -FeatureName Printing-Foundation-InternetPrinting-Client -Online -NoRestart | Out-Null
}

function DisableInternetPrinting{
  Write-Output "###"
  Write-Output "Disabling Internet Printing..."
  Disable-WindowsOptionalFeature -FeatureName Printing-Foundation-InternetPrinting-Client -Online -NoRestart | Out-Null
}

function EnableMemoryIntegrity{
  Write-Output "###"
  # https://docs.microsoft.com/en-us/windows/security/threat-protection/device-guard/enable-virtualization-based-protection-of-code-integrity
  # https://winbuzzer.com/2020/06/05/windows-10-how-to-disable-or-enable-core-isolation-memory-integrity-xcxwbt/
  Write-Output "Enabling Memory Integrity..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Name "HypervisorEnforcedCodeIntegrity" -Type DWord -Value 1
}

function DisableMemoryIntegrity{
  Write-Output "###"
  Write-Output "Disabling Memory Integrity..."
	Remove-ItemProperty -Path  "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Name "HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
}

function InstallLanguagePackGB{
  $LanguagePack="en-GB"
  Write-Output "###"
  Write-Output "Installing LanguagePack $LanguagePack"

  Install-Language $LanguagePack 
  
}

function InstallLanguagePackDK{
  $LanguagePack="da-DK"
  Write-Output "###"
  Write-Output "Installing LanguagePack $LanguagePack"

  Install-Language $LanguagePack 
  
}

function InstallLanguagePackCustom{
  # This function reads from environment variables defined in INI file
  $LanguagePack = [Environment]::GetEnvironmentVariable("RIDEVAR-Language-LanguagePack", "Process")
  Write-Output "###"
  Write-Output "Installing LanguagePack $LanguagePack"

  if ( $LanguagePack -ne $null ) {
    Install-Language $LanguagePack 
  } 
  else {
    Write-Host "No LanguagePack specified. Check command line options or LanguagePack value in [Language] section of INI file."
  }
  

}


function SetRegionalSettings{
  Write-Output "###"
  # https://scribbleghost.net/2018/04/30/add-keyboard-language-to-windows-10-with-powershell/

  $DefaultWinUserLanguage="en-GB"
  $DefaultCulture="en-GB"
  $DefaultKeyboard="0406:00000406" # Danish keyboard
  $DefaultLocation="0x3d" # Denmark
  $DefaultSystemLocale="da-DK"
  $DefaultTimeZone="Romance Standard Time"

  $WinUserLanguage = if ($null -eq [Environment]::GetEnvironmentVariable("RIDEVAR-Language-WinUserLanguage", "Process")) {$DefaultWinUserLanguage}  else {[Environment]::GetEnvironmentVariable("RIDEVAR-Language-WinUserLanguage", "Process")}
  $Culture = if ($null -eq [Environment]::GetEnvironmentVariable("RIDEVAR-Language-Culture", "Process")) {$DefaultCulture}  else {[Environment]::GetEnvironmentVariable("RIDEVAR-Language-Culture", "Process")}
  $Keyboard = if ($null -eq [Environment]::GetEnvironmentVariable("RIDEVAR-Language-Keyboard", "Process")) {$DefaultKeyboard}  else {[Environment]::GetEnvironmentVariable("RIDEVAR-Language-Keyboard", "Process")}
  $Location = if ($null -eq [Environment]::GetEnvironmentVariable("RIDEVAR-Language-Location", "Process")) {$DefaultLocation}  else {[Environment]::GetEnvironmentVariable("RIDEVAR-Language-Location", "Process")}
  $SystemLocale = if ($null -eq [Environment]::GetEnvironmentVariable("RIDEVAR-Language-SystemLocale", "Process")) {$DefaultSystemLocale}  else {[Environment]::GetEnvironmentVariable("RIDEVAR-Language-SystemLocale", "Process")}
  $TimeZone = if ($null -eq [Environment]::GetEnvironmentVariable("RIDEVAR-Language-TimeZone", "Process")) {$DefaultTimeZone}  else {[Environment]::GetEnvironmentVariable("RIDEVAR-Language-TimeZone", "Process")}

  # Save WinUserLanguageList into a variable object and build the list from scratch
  $LanguageList = Get-WinUserLanguageList
  $LanguageList.Clear()
  $LanguageList.add($WinUserLanguage)
  $LanguageList[0].InputMethodTips.Clear()
  # Add DK keyboard as keyboard language
  $LanguageList[0].InputMethodTips.Add($Keyboard)
  Set-WinUserLanguageList $LanguageList -Force

  # Make region settings independent of OS language and set culture and location
  Set-WinCultureFromLanguageListOptOut -OptOut $True
  Set-Culture $Culture
  Set-WinHomeLocation -GeoId $Location

  # Set non-unicode legacy software to use this language as default
  Set-WinSystemLocale -SystemLocale $SystemLocale

  # Copy settings to entire system - Only on Windows 11 and forward
   if (([environment]::OSVersion.Version).Build -ge 22000) {
     Write-Output "Copying sessings to system default..."
     Copy-UserInternationalSettingsToSystem -WelcomeScreen $True -NewUser $True
     }

  # Set timezone
  Write-Output "Setting Time Zone"
  Set-TimeZone $TimeZone
}

function CopyRegionSettingsToAll {
  # Major version = 10 -> either Windows 10 or 11 / Build over 22000 -> Windows 11
  $SupportedOS=(([Environment]::OSVersion.Version).Major -eq "10") -and ([int]([Environment]::OSVersion.Version).Build -ge 22000)
  if ($SupportedOS) { 
      Copy-UserInternationalSettingsToSystem -WelcomeScreen $True -NewUser $True
  } else {
    Write-Output "This Feature is only available on Windows 11."
  }
}

function CopyRegionSettingsWelcome {
  # Major version = 10 -> either Windows 10 or 11 / Build over 22000 -> Windows 11
  $SupportedOS=(([Environment]::OSVersion.Version).Major -eq "10") -and ([int]([Environment]::OSVersion.Version).Build -ge 22000)
  if ($SupportedOS) { 
      Copy-UserInternationalSettingsToSystem -WelcomeScreen $True
  } else {
    Write-Output "This Feature is only available on Windows 11."
  }
}

function CopyRegionSettingsNewUser {
  # Major version = 10 -> either Windows 10 or 11 / Build over 22000 -> Windows 11
  $SupportedOS=(([Environment]::OSVersion.Version).Major -eq "10") -and ([int]([Environment]::OSVersion.Version).Build -ge 22000)
  if ($SupportedOS) { 
      Copy-UserInternationalSettingsToSystem -NewUser $True
  } else {
    Write-Output "This Feature is only available on Windows 11."
  }
}

function SetPowerSchemeBalanced{
  Write-Output "###"
  # Define target scheme
  $PowerScheme="Balanced"
  Write-Output "Setting Power Scheme $PowerScheme..."

  # Define default (known) power schemes
  $DefaultPowerSchemes=('Balanced',"Power Saver","High Performance","Ultimate Performance")

  # Get Power schemes on this device
  $DevicePowerSchemes = powercfg.exe /list

  # Regex to identify power scheme GUID 
  $GUIDRegEx = "(?<TargetGUID>[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}).*(\b$PowerScheme\b)"

  If ( ($DevicePowerSchemes | Out-String) -match $GUIDRegEx ) {
      powercfg.exe /setactive $matches["TargetGUID"]
  }
  elseif ($PowerScheme -in $DefaultPowerSchemes ) {
      # default power schemes can be re-created if not on the system
      switch ( $PowerScheme.ToLower() )
      {
          'power saver' { $NewGUID = "a1841308-3541-4fab-bc81-f71556f20b4a" }
          'balanced' { $NewGUID = "381b4222-f694-41f0-9685-ff5bb260df2e" }
          'high performance' { $NewGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" }
          'ultimate performance' { $NewGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61" }
      }
      # Re-create the power scheme and set it as active scheme
      powercfg.exe -duplicatescheme $NewGUID
      if ( $LASTEXITCODE -eq 0) {
          powercfg.exe -setactive $NewGUID 
          Exit 0
      }
      else {
          Write-Output "#ERROR# Error while recreating power scheme ""$PowerScheme""."
      }
      Exit 1
  }
  else {
      Write-Output "The power scheme ""$PowerScheme"" was not found on this system"
      Exit 1
  }
}

function SetPowerSchemeHighPerf{
  Write-Output "###"
  # Define target scheme
  $PowerScheme="High Performance"
  Write-Output "Setting Power Scheme $PowerScheme..."
  
  
  # Define default (known) power schemes
  $DefaultPowerSchemes=('Balanced',"Power Saver","High Performance","Ultimate Performance")

  # Get Power schemes on this device
  $DevicePowerSchemes = powercfg.exe /list

  # Regex to identify power scheme GUID 
  $GUIDRegEx = "(?<TargetGUID>[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}).*(\b$PowerScheme\b)"

  If ( ($DevicePowerSchemes | Out-String) -match $GUIDRegEx ) {
      powercfg.exe /setactive $matches["TargetGUID"]
  }
  elseif ($PowerScheme -in $DefaultPowerSchemes ) {
      # default power schemes can be re-created if not on the system
      switch ( $PowerScheme.ToLower() )
      {
          'power saver' { $NewGUID = "a1841308-3541-4fab-bc81-f71556f20b4a" }
          'balanced' { $NewGUID = "381b4222-f694-41f0-9685-ff5bb260df2e" }
          'high performance' { $NewGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" }
          'ultimate performance' { $NewGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61" }
      }
      # Re-create the power scheme and set it as active scheme
      powercfg.exe -duplicatescheme $NewGUID
      if ( $LASTEXITCODE -eq 0) {
          powercfg.exe -setactive $NewGUID 
          Exit 0
      }
      else {
          Write-Output "#ERROR# Error while recreating power scheme ""$PowerScheme""."
      }
      Exit 1
  }
  else {
      Write-Output "The power scheme ""$PowerScheme"" was not found on this system"
      Exit 1
  }
}

function SetPowerSchemeUltimate{
  Write-Output "###"
  # Define target scheme
  $PowerScheme="Ultimate Performance"
  Write-Output "Setting Power Scheme $PowerScheme..."

  # Define default (known) power schemes
  $DefaultPowerSchemes=('Balanced',"Power Saver","High Performance","Ultimate Performance")

  # Get Power schemes on this device
  $DevicePowerSchemes = powercfg.exe /list

  # Regex to identify power scheme GUID 
  $GUIDRegEx = "(?<TargetGUID>[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}).*(\b$PowerScheme\b)"

  If ( ($DevicePowerSchemes | Out-String) -match $GUIDRegEx ) {
      powercfg.exe /setactive $matches["TargetGUID"]
  }
  elseif ($PowerScheme -in $DefaultPowerSchemes ) {
      # default power schemes can be re-created if not on the system
      switch ( $PowerScheme.ToLower() )
      {
          'power saver' { $NewGUID = "a1841308-3541-4fab-bc81-f71556f20b4a" }
          'balanced' { $NewGUID = "381b4222-f694-41f0-9685-ff5bb260df2e" }
          'high performance' { $NewGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" }
          'ultimate performance' { $NewGUID = "e9a42b02-d5df-448d-aa00-03f14749eb61" }
      }
      # Re-create the power scheme and set it as active scheme
      powercfg.exe -duplicatescheme $NewGUID
      if ( $LASTEXITCODE -eq 0) {
          powercfg.exe -setactive $NewGUID 
          Exit 0
      }
      else {
          Write-Output "#ERROR# Error while recreating power scheme ""$PowerScheme""."
      }
      Exit 1
  }
  else {
      Write-Output "The power scheme ""$PowerScheme"" was not found on this system"
      Exit 1
  }
}

function SetPwrSchemeDesktopMenu{

  Write-Output "###"
  Write-Output "Adding power scheme desktop menu option..."
  # Define default (known) power schemes
  $DefaultPowerSchemes=('Balanced',"Power Saver","High Performance","Ultimate Performance")
  
  # Get Power schemes on this device
  $DevicePowerSchemes = powercfg.exe /list
  
  # Create menu item in desktop context menu
  If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}

  If (!(Test-Path "HKCR:\DesktopBackground\Shell\Switch Power Plan")) {
    New-Item -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan" | Out-Null
    }
  
  Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan" -Name "Icon" -Type String -Value "powercpl.dll"
  Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan" -Name "MUIVerb" -Type String -Value "Switch Power Plan"
  Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan" -Name "Position" -Type String -Value "Top"
  Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan" -Name "SubCommands" -Type String -Value ""
  
  $DefaultPowerSchemes | ForEach-Object {
    # MUST start with a test to see if this power scheme exist on the computer
    If ( ($DevicePowerSchemes | Out-String) -match $_ ) {
          Write-Output "Adding Power Scheme $_ to menu..."
          $GUIDRegEx = "(?<TargetGUID>[A-Fa-f0-9]{8}-(?:[A-Fa-f0-9]{4}-){3}[A-Fa-f0-9]{12}).*(\b$_\b)"
          If ( ($DevicePowerSchemes | Out-String) -match $GUIDRegEx ) {
              If (!(Test-Path "HKCR:\DesktopBackground\Shell\Switch Power Plan\Shell\$_")) {
                  New-Item -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan\Shell\$_" -force | Out-Null
                  }
              
              Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan\Shell\$_" -Name "Icon" -Type String -Value "powercpl.dll"
              Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan\Shell\$_" -Name "MUIVerb" -Type String -Value "$_"
              
              If (!(Test-Path "HKCR:\DesktopBackground\Shell\Switch Power Plan\Shell\$_\Command")) {
                  New-Item -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan\Shell\$_\Command" -force | Out-Null
                  }
              Set-ItemProperty -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan\Shell\$_\Command" -Name "(Default)" -Type String -Value "powercfg.exe -setactive $matches[""TargetGUID""]"
          }
    }
    }
  }

function RemovePwrSchemeDesktopMenu{
  Write-Output "###"
  Write-Output "Removing power scheme desktop menu option..."
  If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
  Remove-Item -Path "HKCR:\DesktopBackground\Shell\Switch Power Plan" -Recurse -ErrorAction SilentlyContinue
}

################################################################
###### Privacy configurations  ###
################################################################

function DisableInkingAndTypingData{
  Write-Output "###"
  # Disable sending of inking and typing data to Microsoft to improve the language recognition and suggestion capabilities of apps and services.
  Write-Output "Disabling sending of inking and typing data..."
  Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Input\TIPC\" -name Enabled -value 0
}

function ExcludeToolsDirDefender{
  # More configuration here:
  # https://www.windowscentral.com/how-manage-microsoft-defender-antivirus-powershell-windows-10
  Write-Output "###"
  # Exclude C:\Tools from Defender Antivirus scan
  Write-Output "Exclude C:\Tools from Defender Antivirus scans..."
  Add-MpPreference -ExclusionPath C:\Tools
}

function RemoveToolsDirDefender{
  Write-Output "###"
  # Remove C:\Tools from Defender Antivirus scan
  Write-Output "Remove C:\Tools from Defender Antivirus scan..."
  Remove-MpPreference -ExclusionPath C:\Tools
}

function ExcludeBootstrapDirDefender{
  Write-Output "###"
  Write-Output "Exclude Bootstrap (download) from Defender Antivirus scans..."

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  Add-MpPreference -ExclusionPath $BootstrapFolder
}

function RemoveBootstrapDirDefender{
  Write-Output "###"
  Write-Output "Remove C:\Tools from Defender Antivirus exclusion..."
  
  # Get Bootstrap folder
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"

  Remove-MpPreference -ExclusionPath $BootstrapFolder
}

################################################################
###### Privacy configurations  ###
################################################################

function DisableInkingAndTypingData{
  Write-Output "###"
  # Disable sending of inking and typing data to Microsoft to improve the language recognition and suggestion capabilities of apps and services.
  Write-Output "Disabling sending of inking and typing data..."
  Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Input\TIPC\" -name Enabled -value 0
}

################################################################
###### Bitlocker configuration  ###
################################################################

function SetDefaultBitLockerAES256{
  Write-Output "###"
    # Set BitLocker to AES-256
    # Check with "manage-bde -status" and Encrypt AFTERWARDS!
    # See more here: http://www.howtogeek.com/193649/how-to-make-bitlocker-use-256-bit-aes-encryption-instead-of-128-bit-aes/
    Write-Output "Setting default Bitlocker encryption to AES256..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\")) {
  		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Force | Out-Null
  	}

    Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name "EncryptionMethod" -value 4
    #To-do: start BitLocker Encryption with PowerShell https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
}

function SetDefaultBitLockerAES128{
  Write-Output "###"
    # Set BitLocker to AES-128 (default)
    Write-Output "Setting default Bitlocker encryption to AES128..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\")) {
  		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Force | Out-Null
  	}
    Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -name "EncryptionMethod" -value 3
    #To-do: start BitLocker Encryption with PowerShell https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
}

function PutBitlockerShortCutOnDesktop{
  Write-Output "###"
    # Start Bitlocker wizard https://social.technet.microsoft.com/Forums/windows/en-US/12388d10-196a-483a-8421-7dcbffed123b/run-bitlocker-drive-encryption-wizard-from-command-line?forum=w7itprosecurity
    $AppLocation = "$env:SystemDrive\Windows\System32\BitLockerWizardElev.exe"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Bitlocker Wizard.lnk")
    $Shortcut.TargetPath = $AppLocation
    $Shortcut.Arguments ="\ t"
    $Shortcut.Description ="Start Bitlocker Wizard"
    $Shortcut.WorkingDirectory = ($env:SystemDrive+"\Windows\System32")
    #$Shortcut.IconLocation = "C:\Windows\System32\BitLockerWizardElev.exe,0"
    $Shortcut.Save()
}

Function EnableLockOutThreshold {
  Write-Output "###"
	Write-Output "Setting Bitlocker Lockout Threshold to 10 attempts..."
	If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System")) {
		New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Type DWord -Value 10
}

Function DisableLockOutThreshold {
  Write-Output "###"
	Write-Output "Disabling Bitlocker Lockout Threshold..."
	If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System")) {
		New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxDevicePasswordFailedAttempts" -Type DWord -Value 0
}

function EnableEnhancedPIN{
  Write-Output "###"
  Write-Output "Enabling Enhanced PIN..."

  # Verify if current keyboard matches installed UI keyboard.

  # Get Installed LCID (Language Culture ID)
  # A reference list of LCID values can be found here: https://limagito.com/list-of-locale-id-lcid-values/
  $InstalledUICulture = [CultureInfo]::InstalledUICulture

  # Get languagelist
  $LanguageList = Get-WinUserLanguageList

  # Start from top of LanguageList and look for first InputMethodTips entry and extract keyboard LCID
  foreach ( $LanguageConfig in $LanguageList) {
    if ( -not "" -eq $LanguageConfig.InputMethodTips ) 
      { $CurrentUIKeyboard = $LanguageConfig.InputMethodTips.Substring(9,4)
        break }
  }
  # Check if current keyboard corresponds to installed UI keyboard
  If ($CurrentUIKeyboard -ne $InstalledUICulture) {
    Write-Host  "WARNING! " -NoNewline -ForegroundColor red
    Write-Output "Current keyboard setting does not match installed (OS) language."
    Write-Output "Bitlocker enhanced PIN will always use original installed keyboard!"
    Write-Output "`nPress any key to continue..."
	  [Console]::ReadKey($true) | Out-Null
  }
  
  # Set registry keys
  If (!(Test-Path "HKLM:\Software\Policies\Microsoft\FVE")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\FVE" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:Software\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Type DWord -Value 1
}

function DisableEnhancedPIN{
  Write-Output "###"
  Write-Output "Disabling Enhanced PIN..."
  If (!(Test-Path "HKLM:\Software\Policies\Microsoft\FVE")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\FVE" -Force | Out-Null
  }
  Set-ItemProperty -Path "HKLM:Software\Policies\Microsoft\FVE" -Name "UseEnhancedPin" -Type DWord -Value 0
}

function EnableAdvancedAuthAtStart{
  Write-Output "###"
  # https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
  Write-Output "Enabling Additional Authentication at Startup..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Force | Out-Null
  }
  Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -name "UseAdvancedStartup" -value 1
}

function DisableAdvancedAuthAtStart{
  Write-Output "###"
  # https://technet.microsoft.com/en-us/library/jj649829(v=wps.630).aspx
  Write-Output "Enabling Additional Authentication at Startup..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Force | Out-Null
  }
  Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -name "UseAdvancedStartup" -value 0
}

function EnableBitlockerTPMandPIN{
  Write-Output "###"
  Write-Output "Enabling Bitlocker TPM and PIN..."

  if ($null -ne [Environment]::GetEnvironmentVariable("RIDEVAR-Bitlocker-TPMandPINPassword", "Process") -and ([Environment]::GetEnvironmentVariable("RIDEVAR-Bitlocker-TPMandPINPassword", "Process")).tolower() -ne "[prompt]") {
    $Password = ConvertTo-SecureString -String ([Environment]::GetEnvironmentVariable("RIDEVAR-Bitlocker-TPMandPINPassword", "Process"))
  } else {
    do {
      $Password  = Read-Host "Enter new Bitlocker Pre-Boot PIN " -AsSecureString
      $Password2 = Read-Host "Re-enter Bitlocker Pre-Boot PIN  " -AsSecureString
      $pwd1_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
      $pwd2_text = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2))
      }
      while ($pwd1_text -ne $pwd2_text)
  }

  # As virtual machines very often have an ISO connected after a fresh install, eject all CD's if in a VM
  $IsVirtual=((Get-WmiObject Win32_ComputerSystem).model -like ("*Virtual*") -or (Get-WmiObject Win32_ComputerSystem).model -like ("*VMware*"))
  if ($IsVirtual) {
    $Eject = New-Object -ComObject "Shell.Application"
    $Eject.Namespace(17).Items() | Where-Object { $_.Type -eq "CD Drive" } | ForEach-Object { $_.InvokeVerb("Eject") }
    }

  # Bitlocker will check if bootable CD's are in the drive before enabling BitLocker
  $CDMediaLoaded = (Get-WMIObject -Class Win32_CDROMDrive -Property *).MediaLoaded
  $BootableUSBloaded =  (Get-Disk |Where-Object {$_.IsBoot -eq $true -and $_.BootFromDisk -eq $true -and $_.BusType -eq "USB"}).count -gt 0

  if ($CDMediaLoaded -or  $BootableUSBloaded) {
    Write-Host "WARNING! Please unload all CD-ROM medias and bootable USB disks before enabling Bitlocker."
    Write-Host "Failing to do so will prevent Bitlocker from being enabled."
    Write-Output "`nPress any key to continue..."
	  [Console]::ReadKey($true) | Out-Null
  }

  Enable-BitLocker -MountPoint "$($env:SystemDrive)" -EncryptionMethod Aes256 -UsedSpaceOnly -Pin $Password -TPMandPinProtector -SkipHardwareTest
}

function EnableBitlocker{
  Write-Output "###"
  # https://docs.microsoft.com/en-us/powershell/module/bitlocker/enable-bitlocker
  # https://lazyadmin.nl/it/enable-bitlocker-windows-10/
  Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod Aes256  -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector
}

function DisableBitlocker{
  Write-Output "###"
  Disable-BitLocker -MountPoint $env:SystemDrive
}

function AddBitlockerRecoveryPswd {
  Add-BitLockerKeyProtector -MountPoint "$($env:SystemDrive)" -RecoveryPasswordProtector 
}
function DisplayBitlockerRecoveryPwd{
  (Get-BitLockerVolume -MountPoint "$($env:SystemDrive)" | Select-Object -ExpandProperty KeyProtector)[1] | Select-Object KeyprotectorId,RecoveryPassword
}

################################################################
###### Hardening Windows  ###
################################################################

function DisableSSDPdiscovery{
  Write-Output "###"
  # Disables discovery of networked devices and services that use the SSDP discovery protocol, such as UPnP devices.
  # SSDP Discovery service is required for UPnP and Media Center Extender (as per Windows Services > Dependencies tab for SSDP discovery)
  # and so if you don't need UPnP it won't have any negative affects.
  # Network Management in Windows isn't affected by SSDP; you can confidently disable it
Write-Output "Stopping and disabling SSDP discovery protocol..."
	Stop-Service "SSDPSRV" -WarningAction SilentlyContinue
	Set-Service "SSDPSRV" -StartupType Disabled
}

Function EnableSSDPdiscovery {
  Write-Output "###"
  # Discovers networked devices and services that use the SSDP discovery protocol, such as UPnP devices.
  # Also announces SSDP devices and services running on the local computer.
	Write-Output "Enabling and starting SSDP discovery protocol..."
	Set-Service "SSDPSRV" -StartupType Manual
	Start-Service "SSDPSRV" -WarningAction SilentlyContinue
}

Function DisableUniversalPlugAndPlay{
  Write-Output "###"
  # Without UPnP enabled things like torrents and multiplayer gaming won't work properly unless you manually identify and forward all the ports required
  Write-Output "Stopping and disabling UPNP service..."
	Stop-Service "upnphost" -WarningAction SilentlyContinue
	Set-Service "upnphost" -StartupType Disabled
}

Function EnableUniversalPlugAndPlay {
  Write-Output "###"

	Write-Output "Enabling UPNP service..."
	Set-Service "upnphost" -StartupType Manual
	#Start-Service "upnphost" -WarningAction SilentlyContinue
}

Function DisableWinHttpAutoProxySvc {
  # Disable IE proxy autoconfig service
  # https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features
	
  Write-Output "###"
  Write-Output "Stopping and disabling HTTP Proxy auto-discovery (WPAD)..."
  If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Force | Out-Null
  }
  New-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -name "DisableWpad" -Type DWORD -Value 1 -Force | Out-Null
}

Function EnableWinHttpAutoProxySvc {
   # Enable IE proxy autoconfig service
   Write-Output "###"
   Write-Output "Enabling and starting HTTP Proxy auto-discovery (WPAD)..."
	Remove-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -name "DisableWpad" -ErrorAction SilentlyContinue | Out-Null
}


################################################################
###### Network Functions  ###
################################################################

function DisableAutoconfigURL{
  Write-Output "###"
  # Disable machine proxy script
  Write-Output "Disabling autoconfig URL (Proxy script)..."
  If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Force | Out-Null
  }
  New-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -name "AutoconfigURL" -Type String -Value "" -Force | Out-Null

}

function EnableAutoconfigURL{
  Write-Output "###"
    # Disable machine proxy script
    Write-Output "Disabling autoconfig URL (Proxy script)..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoconfigURL" -ErrorAction SilentlyContinue
}

function DisableIEProxyAutoconfig{
  Write-Output "###"
    # Disable IE proxy autoconfig by editing binary registry value
    # prevents WPAD atttack
    Write-Output "Disabling Internet Explorer Proxy autoconfig..."
    $data = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings).DefaultConnectionSettings
    $data[8] = 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings -Value $data
}

function EnableIEProxyAutoconfig{
  Write-Output "###"
    # Enable IE proxy autoconfig by editing binary registry value
    Write-Output "Enabling Internet Explorer Proxy autoconfig..."
    $data = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings).DefaultConnectionSettings
    $data[8] = 9
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name DefaultConnectionSettings -Value $data
}

function DisableMulticastDNS{
  Write-Output "###"
    # Specifies that link local multicast name resolution (LLMNR) is disabled on client computers.
    # If this policy setting is enabled, LLMNR will be disabled on all available network adapters on the client computer.
    Write-Output "Disabling multicast traffic..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -name "EnableMulticast" -value 0 -PropertyType DWord -Force | Out-Null
}

function EnableMulticastDNS{
  Write-Output "###"
    Write-Output "Enabling multicast traffic..."
    # LMNR will be enabled on all available network adapters (default setting)
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}


function GetNoTelemetryHostsFile{
  Write-Output "###"

    # Null-routing hostfile to block Microsoft and NVidia telemetry
    # Originated from: https://encrypt-the-planet.com

    Write-Output "Enabling blocking hosts file ..."
    $SourceFile = Join-Path -Path $PSScriptRoot -ChildPath "components\files\hosts"
    $DestinationFile=Join-Path -Path $Env:windir -ChildPath "\System32\Drivers\etc\hosts"

    if ((Test-Path -Path $SourceFile)) {
        Copy-Item $SourceFile $DestinationFile -Force
        Write-Output "Hostfile copied to $DestinationFile"
    }

}

function SetDefaultHostsfile{
  Write-Output "###"
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
  Write-Output "###"
  # Enable Windows Subsystem Linux PowerShell Script
  # https://docs.microsoft.com/en-us/windows/wsl/install

  Write-Output "Enabling Windows Subsystem for Linux..."

  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart | Out-Null
  Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart | Out-Null
  Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart | Out-Null

  # Set wsl version as default version on latest versions of Windows 10
   $WindowsVersion = ([System.Environment]::OSVersion.Version).Build

   if ( $WindowsVersion -ge 18917 ) {
     # If WSL 2 available
     Write-Output "Setting Windows Subsystem for Linux version 2 as default WSL..."
     wsl --set-default-version 2
  }
}

function DisableWSL{
  Write-Output "###"
  Write-Output "Disabling Windows Subsystem for Linux..."
  Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
  Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
  Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
}

function InstallWSLubuntu{
  Write-Output "###"
  $SoftwareName = "WSL Ubuntu"
  Write-Output "Installing $SoftwareName..."
  wsl --install -d Ubuntu
}

function RemoveWSLubuntu{
  Write-Output "###"
  Write-Output "Removing WSL Ubuntu..."
  Get-AppxPackage "CanonicalGroupLimited.UbuntuonWindows" | Remove-AppxPackage
}

function InstallWSLdebian{
  Write-Output "###"
  $SoftwareName = "WSL Debian"
  Write-Output "Installing $SoftwareName..."
  wsl --install -d Debian
}

function RemoveWSLdebian{
  Write-Output "###"
    Write-Output "Removing WSL Debian..."
  Get-AppxPackage "TheDebianProject.DebianGNULinux" | Remove-AppxPackage
}

function InstallWSLkali{
  Write-Output "###"
  $SoftwareName = "WSL Kali"
  Write-Output "Installing $SoftwareName..."
  wsl --install -d kali-linux
}

function RemoveWSLkali{
  Write-Output "###"
  Write-Output "Removing WSL Kali..."
  Get-AppxPackage "KaliLinux.54290C8133FEE" | Remove-AppxPackage
}

function InstallWSLFedora{
  Write-Output "###"
  # Inspiration found in page:
  # https://dev.to/bowmanjd/install-fedora-on-windows-subsystem-for-linux-wsl-4b26

  $SoftwareName = "WSL Fedora"
  Write-Output "Installing $SoftwareName..."

  # get lastest Fedora version
  $FedoraReleaseUri="https://download.fedoraproject.org/pub/fedora/linux/releases/"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $FedoraReleaseUri).Links
  $FedoraVersion= ($ReleasePageLinks.href | ForEach-Object{$_.Substring(0, $_.length - 1) -as [int]}  | Sort-Object -Descending | Select-Object -First 1)

  # Get second latest release page (most likely yesterday)
  $url="https://koji.fedoraproject.org/koji/packageinfo?packageID=26387"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $BuildPage = ("https://koji.fedoraproject.org/koji/" + ($ReleasePageLinks | Where-Object { $_.outerHTML -Like "*Container*" -and $_.outerHTML -Like "*$FedoraVersion*" } | Select-Object -Skip 1 -First 1).href)

  # Get rootfs image link in page
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $BuildPage).Links
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_.outerHTML -Like "*x86_64.tar.xz*"}).href

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Install (FIXME)
  # & 'C:\Program Files\7-Zip\7z.exe' x .\Fedora-Container-Base-35-20220212.0.x86_64.tar.xz
  #  & 'C:\Program Files\7-Zip\7z.exe' e .\Fedora-Container-Base-35-20220212.0.x86_64.tar 64f3db080638d17ae803eb06b0515b6f99fb90a9b490f310bd98a02b8a5df6c4\layer.tar
  # Move layer.tar to fedora-35-rootfs.tar

  # mkdir $HOME\wsl\fedora
  # wsl --import fedora $HOME\wsl\fedora $HOME\Downloads\fedora-35-rootfs.tar
  # set this as defaul: wsl -s fedora


  Write-Output "Installation done for $SoftwareName"
}

################################################################
###### Operational Tasks  ###
################################################################

function GetWindowsUpdatesWithPwsh{
  Write-Output "###"
  # Get-WindowsUpdates using PowerShell
  Write-Output "Installing PowerShell Requirements for Windows Update..."
  # PowerShellGet requires NuGet provider to interact with NuGet-based repositories
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null

  Install-Module PSWindowsUpdate -Force | Out-Null
  Import-Module PSWindowsUpdate
  Write-Output "Installing Windows Updates..."
  Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot | Out-Null
}


function CleanLocalWindowsUpdateCache{
  Write-Output "###"
  Write-Output "Clean Windows Update cache..."
  # Stop Service wuauserv (Windows Update Service)
  # Stop bits (Background Intelligent Transfer Service)
  Get-Service -Name "wuauserv" | Stop-Service
  Get-Service -Name "bits" | Stop-Service
  Remove-Item ("$($env:SystemDrive)"+"\Windows\SoftwareDistribution\Download\*") -recurse -force
  Get-Service -Name "wuauserv" | Start-Service
  Get-Service -Name "bits" | Start-Service
}


function RunDiskCleanup{
  Write-Output "###"
  Write-Output "Disk cleanup..."

  $strKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
  $strValueName = "StateFlags0001"

  $subkeys = Get-ChildItem -Path HKLM:\$strKeyPath -Name

  ForEach ($subkey in $subkeys) {
      If($subkey -ne "DownloadsFolder") {
          New-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -PropertyType DWORD -Value 2 -Force -ErrorAction SilentlyContinue | Out-Null
      }
  }

  # run cleanmgr.exe
  Start-Process cleanmgr.exe -ArgumentList "/sagerun:1" -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

  ForEach ($subkey in $subkeys) {
      Remove-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -ErrorAction SilentlyContinue | Out-Null
  }
}

function GetWindowsProductKey{
  # This function is included to easily extract the Window sproduct key before running sysprep on the machine

  # implement decoder
  $code = @'
// original implementation: https://github.com/mrpeardotnet/WinProdKeyFinder
using System;
using System.Collections;

  public static class Decoder
  {
        public static string DecodeProductKeyWin7(byte[] digitalProductId)
        {
            const int keyStartIndex = 52;
            const int keyEndIndex = keyStartIndex + 15;
            var digits = new[]
            {
                'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R',
                'T', 'V', 'W', 'X', 'Y', '2', '3', '4', '6', '7', '8', '9',
            };
            const int decodeLength = 29;
            const int decodeStringLength = 15;
            var decodedChars = new char[decodeLength];
            var hexPid = new ArrayList();
            for (var i = keyStartIndex; i <= keyEndIndex; i++)
            {
                hexPid.Add(digitalProductId[i]);
            }
            for (var i = decodeLength - 1; i >= 0; i--)
            {
                // Every sixth char is a separator.
                if ((i + 1) % 6 == 0)
                {
                    decodedChars[i] = '-';
                }
                else
                {
                    // Do the actual decoding.
                    var digitMapIndex = 0;
                    for (var j = decodeStringLength - 1; j >= 0; j--)
                    {
                        var byteValue = (digitMapIndex << 8) | (byte)hexPid[j];
                        hexPid[j] = (byte)(byteValue / 24);
                        digitMapIndex = byteValue % 24;
                        decodedChars[i] = digits[digitMapIndex];
                    }
                }
            }
            return new string(decodedChars);
        }

        public static string DecodeProductKey(byte[] digitalProductId)
        {
            var key = String.Empty;
            const int keyOffset = 52;
            var isWin8 = (byte)((digitalProductId[66] / 6) & 1);
            digitalProductId[66] = (byte)((digitalProductId[66] & 0xf7) | (isWin8 & 2) * 4);

            const string digits = "BCDFGHJKMPQRTVWXY2346789";
            var last = 0;
            for (var i = 24; i >= 0; i--)
            {
                var current = 0;
                for (var j = 14; j >= 0; j--)
                {
                    current = current*256;
                    current = digitalProductId[j + keyOffset] + current;
                    digitalProductId[j + keyOffset] = (byte)(current/24);
                    current = current%24;
                    last = current;
                }
                key = digits[current] + key;
            }

            var keypart1 = key.Substring(1, last);
            var keypart2 = key.Substring(last + 1, key.Length - (last + 1));
            key = keypart1 + "N" + keypart2;

            for (var i = 5; i < key.Length; i += 6)
            {
                key = key.Insert(i, "-");
            }

            return key;
        }
  }
'@
  # compile c#:
  Add-Type -TypeDefinition $code
  
  # get raw product key:
  $digitalId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DigitalProductId).DigitalProductId
  
  # use static c# method to get LicenseKey
  $LicenseKey = [Decoder]::DecodeProductKey($digitalId)

  Write-Output "Product key is: $LicenseKey"
}


function RunSysprepGeneralizeOOBE{
  Write-Output "###"
  Write-Output "Sysprepping image. Will shut down when finished..."
  # Sysprep installation - for templates
  # https://theitbros.com/sysprep-windows-machine/
  
  $SysprepExecutable = Join-Path -Path $Env:windir -ChildPath "\System32\Sysprep\Sysprep.exe"
  $AllArguments = '/generalize /oobe /shutdown'
  Start-Process -FilePath $SysprepExecutable -ArgumentList $AllArguments

  # Handle Activation on Sysprep
  # Check this (old article - WIn7)
  # https://social.technet.microsoft.com/Forums/windows/en-US/4104fa3f-9c36-4d45-aa36-677602894768/sysprep-maintain-activation-and-product-key?forum=w7itproinstall
}



################################################################
###### Install programs  ###
################################################################

function InstallGitLFS{
  Write-Output "###"
  $SoftwareName = "Git-LFS"
  Write-Output "Installing $SoftwareName..."

  $author="git-lfs"
  $repo="git-lfs"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*exe*" -and $_ -Like "*windows*" })
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "/SILENT /LOG"
    Start-Process -FilePath $FileFullName -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveGitLFS {
  Import-Module PackageManagement
  Write-Output "###"
  Write-Output "Removing GitLFS..."
  Uninstall-Package -InputObject ( Get-Package -Name "*Git LFS*" )
}

function InstallGit4Win{
  Write-Output "###"
  $SoftwareName = "Git4Win"
  Write-Output "Installing $SoftwareName..."

  $author="git-for-windows"
  $repo="git"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*64*" -and $_ -Like "*exe*" -and $_ -notlike "*Portable*" })
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "/SILENT /LOG"
    Start-Process -FilePath $FileFullName -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveGit4Win {
  Write-Output "###"
  Write-Output "Removing Git4Win..."
  $UninstallString=Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git*"  | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object UninstallString 
  $AllArguments = " "
  Start-Process -FilePath $UninstallString -ArgumentList $AllArguments -NoNewWindow -Wait
}

function InstallPSScriptTools{
  Write-Output "###"
  $SoftwareName = "PSScriptTools"
  Write-Output "Installing $SoftwareName..."

  $author="jdhitsolutions"
  $repo="PSScriptTools"
  $Url = "https://github.com/$author/$repo"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
    New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Check if repo folder exists and delete it if it does
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (Test-Path -Path $SoftwareFolderFullName) {
    Remove-Item -Path $SoftwareFolderFullName -Recurse -Force
  }

  # Clone git repo
  Set-Location $BootstrapFolder
  Start-Process git.exe -ArgumentList  "clone $Url" -NoNewWindow -wait
  
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
    Write-Output "Directory $SoftwareFolderFullName was not found. Exiting..."
    return
  }

  # Copy to tools folder
  Set-Location $BootstrapFolder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }

}


function RemovePSScriptTools {
  Write-Output "###"
  $SoftwareName = "PSScriptTools"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}


function InstallNotepadPlusPlus{
  Write-Output "###"
  $SoftwareName = "NotepadPlusPlus"
  Write-Output "Installing $SoftwareName..."

  $author="notepad-plus-plus"
  $repo="notepad-plus-plus"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*64.exe" -and $_ -NotLike "*arm64*"} | Select-Object -First 1)

  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "/S"
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveNotepadPlusPlus{
  Import-Module PackageManagement
  Write-Output "###"
  Write-Output "Removing Notepad++..."
  Uninstall-Package -InputObject ( Get-Package -Name "Notepad++")
}

function Install7Zip{
  Write-Output "###"
  $SoftwareName = "7zip"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://www.7-zip.org/"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $SoftwareUri = ($ReleasePageLinks | Where-Object { $_.href -Like "*x64.exe" }).href
  $FullDownloadURL = "$Url$SoftwareUri"
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "/S"
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function Remove7Zip{
  Import-Module PackageManagement
  Write-Output "###"
  Write-Output "Removing 7-Zip..."
  Uninstall-Package -InputObject ( Get-Package -Name "7-Zip")
}

function InstallVSCode{
  Write-Output "###"
  $SoftwareName = "VSCode"
  Write-Output "Installing $SoftwareName..."

  # Setting the direct download link
  $FullDownloadURL = "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "VSCodeSetup-x64.exe"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  if ((Get-AuthenticodeSignature $FileFullName).Status -eq 'Valid') {
    Write-Output "Downloaded: $FileFullName"

    if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
      # Install exe
      $CommandLineOptions = " /SILENT /NORESTART /mergetasks=!runcode"
      Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
      Write-Output "Installation done for $SoftwareName"
    }
  } else {
    Write-Output "ERROR installing $SoftwareName. Downloaded file did not pass verification."
  }
}

function RemoveVSCode{
  Import-Module PackageManagement
  Write-Output "###"
  Write-Output "Removing VSCode..."
  Uninstall-Package -InputObject (Get-Package -Name 'Microsoft Visual Studio Code*')
}

function InstallRSAT{
  Write-Output "###"
  $SoftwareName = "Remote Server Administration Tool (RSAT)"
  Write-Output "Getting $SoftwareName..."
  Get-WindowsCapability -Name RSAT* -Online | Where-Object { $_.State -ne "Installed"} | Add-WindowsCapability -Online | Out-Null
}

function RemoveRSAT{
  Write-Output "###"
  Write-Output "Remote Server Administration Tool (RSAT)"
  Get-WindowsCapability -Name RSAT* -Online | Remove-WindowsCapability -Online | Out-Null
}

function GetSysmonSwiftXML{
  Write-Output "###"
  $SoftwareName = "Sysmon Swift XML"
  Write-Output "Getting $SoftwareName..."

  $FullDownloadURL = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
		New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
		Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}


function GetSysmonOlafXML{
  Write-Output "###"
  $SoftwareName = "Sysmon Olaf XML"
  Write-Output "Getting $SoftwareName..."

  $FullDownloadURL = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}


function InstallSysmon64{
  Write-Output "###"
  $SoftwareName = "Sysmon64"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://download.sysinternals.com/files/Sysmon.zip"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
	# Get tools folder
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  
	# Create tools folder if not existing
	if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
	}

	# Copy to tools folder (overwrite existing)
	$NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
	if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
	}
	Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
	Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

	# Unzip
	$NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
	Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
	Remove-Item -Path $NewFileFullName -ErrorAction Ignore
	Write-Output "Unzipped to: $NewSoftwareFolderFullName"

	# Set command line options
	$CommandLineOptions = "-accepteula"
	if (Test-Path -Path "$BootstrapFolder\Sysmon Olaf XML\sysmonconfig.xml") {
	  $CommandLineOptions += " -i ""$BootstrapFolder\Sysmon Olaf XML\sysmonconfig.xml"""
	}
	elseIf (Test-Path -Path "$BootstrapFolder\Sysmon Swift XML\sysmonconfig-export.xml") {
	  $CommandLineOptions += " -i ""$BootstrapFolder\Sysmon Swift XML\sysmonconfig-export.xml"""
	}
	Write-Output "Command line arguments: $CommandLineOptions"

    # Install exe
    $InstallFileFullName = "$NewSoftwareFolderFullName\Sysmon64.exe"
    Start-Process $InstallFileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveSysmon64 {
  Write-Output "###"
  $SoftwareName = "Sysmon64"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName

  Get-Service -Name $SoftwareName | Stop-Service | Out-Null
  $CommandLineOptions += "-u force"
  $InstallFileFullName = "$NewSoftwareFolderFullName\Sysmon64.exe"
  Start-Process $InstallFileFullName $CommandLineOptions -NoNewWindow -Wait
    
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetSysinternalsSuite{
  Write-Output "###"
  $SoftwareName = "SysinternalsSuite"
  Write-Output "Getting $SoftwareName..."

  $FullDownloadURL = "https://download.sysinternals.com/files/SysinternalsSuite.zip"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveSysinternalsSuite {
  Write-Output "###"
  $SoftwareName = "SysinternalsSuite"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}


function InstallNirsoftLauncher(){

  Write-Output "###"
  $SoftwareName = "NirsoftLauncher"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://launcher.nirsoft.net/downloads/index.html"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).links.href
  $SubDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*_enc*" })
  $FullDownloadURL = "https:$SubDownloadURL"

  if (-not $SubDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Get password from HTML
  $DownloadpageHTML=Invoke-RestMethod $Url
  $DownloadpageHTML -match '<span class="notranslate"><a href="" onclick="copyTextToClipboard\(''(?<NirsoftPass>.*)''\);return' | Out-Null
  # $matches.NirsoftPass now holds the password
  $ZipPassword=$matches.NirsoftPass

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName

  # Web page requires a referer, so a invoke-webrequest is used
  $headers = @{}
  $headers["referer"] = "https://www.nirsoft.net"
  Invoke-WebRequest -Uri $FullDownloadURL -OutFile $FileFullName -Headers $headers 
  
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
      # Get tools folder
      $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
      if (-not $ToolsFolder) {
        # Set default tools folder
        $ToolsFolder = "\Tools"
      }

      # Create tools folder if not existing
      if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
      }

      # Write password to file
      $PasswordFileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath "zip_password.txt"
      $ZipPassword | Out-File -FilePath $PasswordFileFullName

      # Create software directory in Tools folder
      $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
      if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
      } 
      New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null
      
      # To unpack package, this function depends on 7-Zip
      $ArchiveTool = [System.Environment]::GetFolderPath("ProgramFiles")+"\7-Zip\7z.exe"
      # Unzip password protected file
      if (-not (Test-Path $ArchiveTool)) {
          Write-Output "Warning: 7-Zip not found. Cannot unpack software"
      } else {# 
        Write-Output "Unpacking with 7-zip"
        & $ArchiveTool x "-o$NewSoftwareFolderFullName" "-p$ZipPassword" $FileFullName | out-null
      Write-Output "Installation done for $SoftwareName"
      }      
  }
}

function RemoveNirsoftLauncher {
  Write-Output "###"
  $SoftwareName = "NirsoftLauncher"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallNirsoftPkgFiles{
  
  Write-Output "###"
  $SoftwareName = "NirsoftLauncherPackages"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://launcher.nirsoft.net/downloads/index.html"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).links.href
  
  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download - Web page requires a referer, so a invoke-webrequest is used
  $headers = @{}
  $headers["referer"] = "https://www.nirsoft.net"

  # Downloading NLP Files #
  $NLPFileURLs=($ReleasePageLinks | Where-Object { $_ -Like "*.nlp" })

  Foreach ($SubUrl in $NLPFileURLs)
      {
      $FullDownloadURL = "https:"+$SubUrl
      $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
      $NLPFileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
      Write-Output "Downloading files from: $FullDownloadURL"

      # Web page requires a referer, so a invoke-webrequest is used
      Invoke-WebRequest -Uri $FullDownloadURL -OutFile $NLPFileFullName -Headers $headers 
      Write-Output "Downloaded: $NLPFileFullName"
      }

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
      # Get tools folder
      $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
      if (-not $ToolsFolder) {
        # Set default tools folder
        $ToolsFolder = "\Tools"
      }
   
      # Create tools folder if not existing
      if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
      }
  }  

  # Copy NLP file for ZimmerManTools from repo "files" directory
  $NLPfile = "zimmermantools.nlp"
  $NLPpackage = "ZimmerManTools"

  # If repo NLP file can be identified, copy to Bootstrap and to Tools directory
  if ($PSScriptRoot) {
      $SourceDir = Join-Path -Path $PSScriptRoot -ChildPath "components\files"
      $SourceFile = Join-Path -Path $SourceDir -ChildPath $NLPfile
      $DestinationFile = Join-Path -Path $SoftwareFolderFullName -ChildPath $NLPfile

      if ((Test-Path -Path $SourceFile)) {
          Copy-Item $SourceFile $DestinationFile -Force
          Write-Output "File $NLPfile copied to $SoftwareFolderFullName"
      }

    # Copy Zimmerman NLP to Tools directory
    if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
      $DestinationDir = Join-Path -Path $ToolsFolder -ChildPath $NLPpackage
      $DestinationFile = Join-Path -Path $DestinationDir -ChildPath $NLPfile
      if ((Test-Path -Path $DestinationDir) -And (Test-Path -Path $SourceFile)) {
            Copy-Item $SourceFile $DestinationFile -Force
            Write-Output "File $NLPfile copied to $DestinationDir"
        }
    }
  }

  # Create NLP file for CCleaner from Piriform by replacing paths in downloaded file
  $NLPfile = "piriform.nlp"
  $NLPpackage = "CCleaner"

  $SourceFile = Join-Path -Path $SoftwareFolderFullName -ChildPath $NLPfile
  $DestinationDir = Join-Path -Path $ToolsFolder -ChildPath $NLPpackage

  (Get-Content $SourceFile).Replace(".\Speccy\Speccy", "Speccy").Replace(".\Recuva\Recuva", "recuva").Replace(".\Defraggler\df", "df").Replace(".\Defraggler\Defraggler", "Defraggler").Replace(".\CCleaner\CCleaner", "CCleaner") | Out-File $SourceFile -Force -Encoding ascii

  # Copy CCleaner package file to Tools Package directory
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
      $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $NLPpackage
      $ToolsNLPFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $NLPfile

      if ((Test-Path -Path $SourceFile) -And (Test-Path -Path $DestinationDir)) {
        Copy-Item $NLPFileFullName $ToolsNLPFileFullName -Force
        Write-Output "File $NLPfile copied to $NewSoftwareFolderFullName"
      }
  }
  
  # Copy SysInternals NLP file to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    $NLPfile = "sysinternals6.nlp"
    $NLPpackage = "SysinternalsSuite"
    $SourceFile = Join-Path -Path $SoftwareFolderFullName -ChildPath $NLPfile
    $DestinationDir = Join-Path -Path $ToolsFolder -ChildPath $NLPpackage
    $DestinationFile = Join-Path -Path $DestinationDir -ChildPath $NLPfile

    if ((Test-Path -Path $SourceFile) -And (Test-Path -Path $DestinationDir)) {
        Copy-Item $SourceFile $DestinationFile -Force
        Write-Output "File $NLPfile copied to $DestinationDir"
    }
  }

  # Copy Mitec NLP file to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    $NLPfile = "mitec.nlp"
    $NLPpackage = "Mitec"
    $SourceFile = Join-Path -Path $SoftwareFolderFullName -ChildPath $NLPfile
    $DestinationDir = Join-Path -Path $ToolsFolder -ChildPath $NLPpackage
    $DestinationFile = Join-Path -Path $DestinationDir -ChildPath $NLPfile

    if ((Test-Path -Path $SourceFile) -And (Test-Path -Path $DestinationDir)) {
        Copy-Item $SourceFile $DestinationFile -Force
        Write-Output "File $NLPfile copied to $DestinationDir"
    }
  }

  # Copy NTCore NLP file to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    $NLPfile = "ntcore.nlp"
    $NLPpackage = "NTCore"
    $SourceFile = Join-Path -Path $SoftwareFolderFullName -ChildPath $NLPfile
    $DestinationDir = Join-Path -Path $ToolsFolder -ChildPath $NLPpackage
    $DestinationFile = Join-Path -Path $DestinationDir -ChildPath $NLPfile

    if ((Test-Path -Path $SourceFile) -And (Test-Path -Path $DestinationDir)) {
        Copy-Item $SourceFile $DestinationFile -Force
        Write-Output "File $NLPfile copied to $DestinationDir"
    }
  }

  # Copy JoeWare NLP file to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    $NLPfile = "joeware.nlp"
    $NLPpackage = "JoeWare"
    $SourceFile = Join-Path -Path $SoftwareFolderFullName -ChildPath $NLPfile
    $DestinationDir = Join-Path -Path $ToolsFolder -ChildPath $NLPpackage
    $DestinationFile = Join-Path -Path $DestinationDir -ChildPath $NLPfile

    if ((Test-Path -Path $SourceFile) -And (Test-Path -Path $DestinationDir)) {
        Copy-Item $SourceFile $DestinationFile -Force
        Write-Output "File $NLPfile copied to $DestinationDir"
    }
  }
}

function RemoveNirsoftPkgFiles {
  Write-Output "###"
  $SoftwareName = "NirsoftLauncherPackages"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallNirsoftToolsX64(){

  Write-Output "###"
  $SoftwareName = "NirsoftTools"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://www.nirsoft.net/x64_download_package.html"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).links.href
  $SubDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*x64tools*" })
  $FullDownloadURL = "https://www.nirsoft.net/$SubDownloadURL"

  if (-not $SubDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Get password from HTML
  $DownloadpageHTML=Invoke-RestMethod $Url
  $DownloadpageHTML -match '<a href="" onclick="copyTextToClipboard\(''(?<NirsoftPass>.*)''\);return' | Out-Null
  # $matches.NirsoftPass now holds the password
  $ZipPassword=$matches.NirsoftPass

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  # Web page requires a referer, so a invoke-webrequest is used
  $headers = @{}
  $headers["referer"] = "https://www.nirsoft.net"
  Invoke-WebRequest -Uri $FullDownloadURL -OutFile $FileFullName -Headers $headers 
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
      # Get tools folder
      $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
      if (-not $ToolsFolder) {
        # Set default tools folder
        $ToolsFolder = "\Tools"
      }
      
      # Create tools folder if not existing
      if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
      }

      # Write password to file
      $PasswordFileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath "zip_password.txt"
      $ZipPassword | Out-File -FilePath $PasswordFileFullName 

      # Create software directory in Tools folder
      $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
      if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
      } 
      New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null
      
      # To unpack package, this function depends on 7-Zip
      $ArchiveTool = [System.Environment]::GetFolderPath("ProgramFiles")+"\7-Zip\7z.exe"
      # Unzip password protected file
      if (-not (Test-Path $ArchiveTool)) {
          Write-Output "Warning: 7-Zip not found. Cannot unpack software"
      } else {
        Write-Output "Unpacking with 7-zip"
        & $ArchiveTool x "-o$NewSoftwareFolderFullName" "-p$ZipPassword" $FileFullName | out-null
      Write-Output "Installation done for $SoftwareName"
      }    
  }
}

function RemoveNirsoftToolsX64 {
  Write-Output "###"
  $SoftwareName = "NirsoftTools"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallJoeWare(){
  Write-Output "###"
  # http://www.joeware.net/freetools/index.htm
  $SoftwareName = "JoeWare"
  Write-Output "Installing $SoftwareName..."

  $Url = "http://www.joeware.net/freetools/index.htm"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $DownloadPages =  ($ReleasePageLinks | Where-Object { $_.href -Like "*tools/*" } ).href | Sort-Object | Get-Unique
  if (-not $DownloadPages) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  $PHPpage="https://www.joeware.net/downloads/dl2.php"
  Foreach ($SubUrl in $DownloadPages)
  {
    $FullDownloadURL = "http://www.joeware.net/freetools/"+$SubUrl
    $Fields=(Invoke-WebRequest -UseBasicParsing -Uri $FullDownloadURL).inputfields
    $DownloadFile=( $Fields | Where-Object { $_.name -eq "download" } ).value
    $Action=( $Fields | Where-Object { $_.name -eq "B1" } ).value
    $Payload=@{download=$DownloadFile
            email=""
            B1=$Action}
    $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $DownloadFile
    
    Write-Output "Downloading files from: $FullDownloadURL"
    Invoke-WebRequest -Uri $PHPpage -Method Post -Body $Payload -OutFile $FileFullName 
    Write-Output "Downloaded: $FileFullName"
  }
  
  # Move files to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {

    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
  
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }
  
    # Create software directory in Tools folder
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    } 
    New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null
    
    # Unzip
    $ZipFiles = Get-ChildItem $SoftwareFolderFullName -Filter *.zip 
  
      foreach ($ZipFile in $ZipFiles) {
          try { $ZipFile | Expand-Archive -DestinationPath $NewSoftwareFolderFullName  }
          catch { Write-Output "FAILED to unzip:"$ZipFile -ForegroundColor red }
      }
    
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveJoeWare {
  Write-Output "###"
  $SoftwareName = "JoeWare"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallCCleaner(){

  Write-Output "###"
  $SoftwareName = "CCleaner"
  Write-Output "Installing $SoftwareName..."

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  $CCleanerURLs=@("https://www.ccleaner.com/ccleaner/download/portable"
                  "https://www.ccleaner.com/defraggler/builds"
                  "https://www.ccleaner.com/recuva/builds"
                  "https://www.ccleaner.com/speccy/builds"
                  )
 
  Foreach ($Url in $CCleanerURLs)
    {
    $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).links.href
    $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*.zip" -or $_ -Like "*.exe" })

    if (-not $FullDownloadURL) {
    Write-Output "Error: $SoftwareName not found"
    return
    }

    $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
    $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
    Write-Output "Downloading files from: $FullDownloadURL"
    Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
    Write-Output "Downloaded: $FileFullName"
    }
  
  # Move files to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {

    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
    New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Create software directory in Tools folder
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
    Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    } 
    New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null

    # Unzip with built-in unzip
    $ZipFiles = Get-ChildItem $SoftwareFolderFullName -Filter *.zip 
    Write-Output "Unpacking zip files"

    foreach ($ZipFile in $ZipFiles) {
        try { $ZipFile | Expand-Archive -DestinationPath $NewSoftwareFolderFullName  }
        catch { Write-Output "FAILED to unzip:"$ZipFile -ForegroundColor red }
    }

    # Unzip .exe with 7-Zip
    $ArchiveTool = [System.Environment]::GetFolderPath("ProgramFiles")+"\7-Zip\7z.exe"
    if (-not (Test-Path $ArchiveTool)) {
      Write-Output "Warning: 7-Zip not found. Cannot unpack software"
    } else {
      Write-Output "Unpacking with 7-zip"
      $ExeFiles = Get-ChildItem $SoftwareFolderFullName -Filter *.exe 

      foreach ($File in $ExeFiles) {
        $FileFullName=$File.FullName
        & $ArchiveTool x "-y" "-o$NewSoftwareFolderFullName" "$FileFullName" ""-xr!$*\*"" "-xr!uninst.exe" | Out-Null
      }
    }
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveCCleaner {
  Write-Output "###"
  $SoftwareName = "CCleaner"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallMitec(){
  Write-Output "###"
  # http://www.mitec.cz
  $SoftwareName = "Mitec"
  Write-Output "Installing $SoftwareName..."

  $Url = "http://www.mitec.cz"
  #$ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $DownloadPages =  ($ReleasePageLinks | Where-Object { $_.href -Like "*.html" -and  $_.href -NotLike "/*.*"} ).href | Sort-Object | Get-Unique

  # ($ReleasePageLinks | Where-Object { $_.href -Like "*.zip" } ).href | Sort-Object | Get-Unique
  if (-not $DownloadPages) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  Foreach ($SubUrl in $DownloadPages)
  {
    $DownloadPageURL = "$Url"+"/"+$SubUrl
    $PageLinks=(Invoke-WebRequest -UseBasicParsing -Uri $DownloadPageURL).links.href
    $DownloadFile=($PageLinks | Where-Object { $_ -Like "*Downloads*" -And $_ -NotLike "*Trial.*" -And $_ -NotLike "*Demo*" -And ($_ -Like "*.exe" -or $_ -Like "*.zip")}) | Select-Object -First 1
    if ($null -ne $DownloadFile ) {
        $FileSubPath=$DownloadFile.replace("./","/")
        $FullDownloadURL = $Url+$FileSubPath
        $DownloadFile=$DownloadFile -replace ".*/"
        $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $DownloadFile
    
        Write-Output "Downloading files from: $FullDownloadURL"
        Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName -ErrorAction SilentlyContinue
        if (! (Test-Path -Path $FileFullName)) {
          Write-Host "Retrying..."
          Start-Sleep -Seconds 2
          Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName 
        } 
        if (Test-Path -Path $FileFullName) {
          Write-Output "Downloaded: $FileFullName"}
        else {
          Write-Output "Error downloading: $FileFullName" 
        }
    } 
  }
  
  # Move files to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {

    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
  
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }
  
    # Create software directory in Tools folder
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    } 
    New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null

    # Unzip
    $ZipFiles = Get-ChildItem $SoftwareFolderFullName -Filter *.zip 
  
      foreach ($ZipFile in $ZipFiles) {
          try { $ZipFile | Expand-Archive -DestinationPath $NewSoftwareFolderFullName -Force | Out-Null }
          catch { Write-Output "FAILED to unzip:"$ZipFile -ForegroundColor red }
      }
    
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveMitec {
  Write-Output "###"
  $SoftwareName = "Mitec"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallNtcore(){
  Write-Output "###"
  
  $SoftwareName = "NTCore"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://ntcore.com/?page_id=345"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  # Capture subpages in a variable
  $DownloadPages = ($ReleasePageLinks | Where-Object { $_.href -Like "/?page_id*" } ).href | Sort-Object | Get-Unique 
  # Capture direct download links in another variable
  $DownloadURLs = ($ReleasePageLinks | Where-Object { $_.href -Like "/files*" } ).href | Sort-Object | Get-Unique

  # ($ReleasePageLinks | Where-Object { $_.href -Like "*.zip" } ).href | Sort-Object | Get-Unique
  if (-not $DownloadPages) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  ForEach ($SubUrl in $DownloadPages)
  {
    $DownloadPageURL = "https://ntcore.com"+$SubUrl
    $PageLinks=(Invoke-WebRequest -UseBasicParsing -Uri $DownloadPageURL).links.href
    $DownloadFiles=$PageLinks | Where-Object { $_ -Like "*.exe" -or $_ -Like "*.zip" } | Sort-Object | Get-Unique 
    if ($null -ne $DownloadFiles ) {
        ForEach ($File in $DownloadFiles) {
            $FullDownloadURL = "https://ntcore.com"+$File
            $FileName=$File -replace ".*files/"
            $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
            #Write-Output $DownloadPageURL
            Write-Output "Downloading files from: $FullDownloadURL"
            Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName 
            Write-Output "Downloaded: $FileFullName"
        }
    } 
  }
  
  ForEach ($File in $DownloadURLs) {
    $FullDownloadURL = "https://ntcore.com"+$File.replace("qtida.py","qtida.zip")
    $FileName=($File -replace ".*files/" -replace ".*/").replace("qtida.py","qtida.zip")
    $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
    Write-Output "Downloading files from: $FullDownloadURL"
    Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName 
    Write-Output "Downloaded: $FileFullName"
  }

  # Move files to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {

    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
  
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }
  
    # Create software directory in Tools folder
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    } 
    New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null
    
    # Unzip
    $ZipFiles = Get-ChildItem $SoftwareFolderFullName -Filter *.zip 
  
      foreach ($ZipFile in $ZipFiles) {
          try { $ZipFile | Expand-Archive -DestinationPath $NewSoftwareFolderFullName -Force | Out-Null }
          catch { Write-Output "FAILED to unzip:"$ZipFile -ForegroundColor red }
      }
    
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveNTCore {
  Write-Output "###"
  $SoftwareName = "NTCore"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallArsenalRecon{
  Write-Output "###"
  $SoftwareName = "Arsenal Recon"
  Write-Output "Installing $SoftwareName..."

  ### Step 1 - Set up Arsenal Recon destination directories
  
  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  ### Step 2 - Install mega.io command line tool (always on fixed address)

  $MegaFullDownloadURL = "https://mega.nz/MEGAcmdSetup64.exe"

  # Create software directory in a subdir to the bootstrap software folder
  $MegaCmdFolderFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath "MegaCmd"
  if (Test-Path -Path $MegaCmdFolderFullName) {
  Remove-Item -Path $MegaCmdFolderFullName -Recurse -Force
  } 
  New-Item -Path $MegaCmdFolderFullName -ItemType Directory | Out-Null
  
  # Get the filename of the MegaCmd file
  $MegaFileName = ([System.IO.Path]::GetFileName($MegaFullDownloadURL).Replace("%20"," "))
  $MegaFileFullName = Join-Path -Path $MegaCmdFolderFullName -ChildPath $MegaFileName

  Set-Location $MegaCmdFolderFullName

  # Download to a subdirectory of Arsenal Recon
  Write-Output "Downloading file from: $MegaFullDownloadURL"
  #$FileName = ([System.IO.Path]::GetFileName($MegaFullDownloadURL).Replace("%20"," "))
  #$FileFullName = Join-Path -Path $MegaCmdFolderFullName -ChildPath $MegaFileName
  Start-BitsTransfer -Source $MegaFullDownloadURL -Destination $MegaFileName
  Write-Output "Downloaded: $MegaFileFullName"

  # To unpack package, this function depends on 7-Zip
  $ArchiveTool = [System.Environment]::GetFolderPath("ProgramFiles")+"\7-Zip\7z.exe"
  # Unzip file
  if (-not (Test-Path $ArchiveTool)) {
      Write-Output "Warning: 7-Zip not found. Cannot unpack software"
  } else {# 
      Write-Output "Unpacking with 7-zip"
      & $ArchiveTool x "-o$MegaCmdFolderFullName" $MegaFileName | out-null
      Write-Output "MegaCmd downloaded and unpacked in $MegaCmdFolderFullName"
  }    

  ## Step 3 - Fetch all Arsenal Recon files from mega.io

  $Url = "https://arsenalrecon.com/downloads"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $DownloadURLs = ($ReleasePageLinks | Where-Object { $_.href -Like "*mega.nz*" } ).href
  if (-not $DownloadURLs) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  $MegaCmdExe = Join-Path -Path $MegaCmdFolderFullName -ChildPath "MegaClient.exe"
  $MegaSrvExe = Join-Path -Path $MegaCmdFolderFullName -ChildPath "MegacmdServer.exe"

  # Download
  # Start MegaServer in new Window
  Start-Process $MegaSrvExe -WindowStyle Normal 

  Set-Location $SoftwareFolderFullName
  # Download all URLs hosted
  Write-Output "Downloading files from mega.nz:"
  Foreach ($FullDownloadURL in $DownloadURLs)
  {
    Write-Host "Fetching from: $FullDownloadURL "
    Start-Process -FilePath $MegaCmdExe -ArgumentList "get $FullDownloadURL" -NoNewWindow -ErrorAction Ignore -Wait
  } 
    
  Set-Location  $BootstrapFolder
  Get-Process "MEGAcmdServer" | Stop-Process -ErrorAction SilentlyContinue -Force

  Write-Output "$SoftwareName tools downloaded"
  Set-Location $BootstrapFolder

  # Step 4 - unpack Arsenal Zip files in tools directory
  
  # Move files to Tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
    New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
      if (Test-Path -Path $NewSoftwareFolderFullName) {
        Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
      } 
      New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null
      
    $ZipFiles = Get-ChildItem $SoftwareFolderFullName -Filter *.zip 
    
        foreach ($ZipFile in $ZipFiles) {
            try { $ZipFile | Expand-Archive -DestinationPath $NewSoftwareFolderFullName  }
            catch { Write-Output "FAILED to unzip:"$ZipFile -ForegroundColor red }
        }
      
      Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function InstallOpenJDK{
  Write-Output "###"
  # We select version 11 instead of 17 because Neo4j/BloodHound require 11
  $SoftwareName = "OpenJDK"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://docs.microsoft.com/en-us/java/openjdk/download#openjdk-11"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_.href -Like "*x64.msi" -and $_.href -Like "*jdk-11*" }).href
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Invoke-Expression "msiexec /qb /i $FileFullName ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome"
    Write-Output "Installation done for $SoftwareName"
  }
}


function InstallNeo4j{
  Write-Output "###"
  # Depends on InstallOpenJDK
  # APOC plugin included. Required for other tools like ImproHound

  $SoftwareName = "Neo4j Community"
  Write-Output "Installing $SoftwareName..."

  ### DISCLAIMER ###
  # Official recommendation (February 2023) is to install Neo4j version 4.4.0.13
  # Download link selection below will reflect this recommendation until further notice
  # https://bloodhound.readthedocs.io/en/latest/installation/windows.html#install-java
  
  # Process is in two steps. First APOC - then bloodhound.
  # Get the latest Neo4j APOC version number and download link
  # We don't want the latest Neo4j if a compatible APOC is not out yet
  $author="neo4j-contrib"
  $repo="neo4j-apoc-procedures"

  $Url = "https://api.github.com/repos/$author/$repo/releases"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $ApocFullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*4.4.0.13-all.jar" })
  if (-not $ApocFullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }
  $VersionFound = $ApocFullDownloadURL | Where-Object {$_ -match "(?<=download/)(.*)(?=/apoc)"}
  if (-not $VersionFound) {
    Write-Output "Error: APOC version not fould in download url"
	return
  }
  $ApocVersion = [version]$Matches[0]
  $ApocVersionShort = "$($ApocVersion.Major).$($ApocVersion.Minor)"

  # Set Neo4j download URL
  $Url = "https://neo4j.com/download-center/#community"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $WinzipCommunityLinks = $ReleasePageLinks.href | Where-Object { $_ -Like "*winzip" -and $_ -Like "*community*" }
  $DownloadURL = $WinzipCommunityLinks | Where-Object {$_ -like "*release=$ApocVersionShort*"}
  if (-not $DownloadURL) {
    Write-Output "Error: Could not find right Neo4j version"
	return
  }
  $VersionFound = $DownloadURL | Where-Object {$_ -match "(?<=release=)(.*)(?=&)"}
  if (-not $VersionFound) {
    Write-Output "Error: Neo4j version not fould in download url"
	return
  }
  $Neo4jVersion = $Matches[0]
  $Neo4jFileName = "neo4j-community-$Neo4jVersion-windows.zip"
  $FullDownloadURL = "https://neo4j.com/artifact.php?name=$Neo4jFileName"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download Neo4j
  Write-Output "Downloading file from: $FullDownloadURL"
  $Neo4jFileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $Neo4jFileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $Neo4jFileFullName
  Write-Output "Downloaded: $Neo4jFileFullName"

  # Download APOC plugin
  Write-Output "Downloading file from: $ApocFullDownloadURL"
  $ApocFileName = ([System.IO.Path]::GetFileName($ApocFullDownloadURL).Replace("%20"," "))
  $ApocFileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $ApocFileName
  Start-BitsTransfer -Source $ApocFullDownloadURL -Destination $ApocFileFullName
  Write-Output "Downloaded: $ApocFileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewNeo4jFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $Neo4jFileName
    Expand-Archive $NewNeo4jFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewNeo4jFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"

    # Move APOC to plugin folder
    $NewApocFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $ApocFileName
    $Neo4jRootDirFullName = (Get-ChildItem $NewSoftwareFolderFullName -Directory).FullName
    $FinalApocFileFullName = Join-Path -Path $Neo4jRootDirFullName -ChildPath "plugins\$ApocFileName"
    Move-Item -Path $NewApocFileFullName -Destination $FinalApocFileFullName
    Write-Output "Moved APOC plugin to: $FinalApocFileFullName"

    # Config - Allow APOC queries
    $ConfigFileFullName = Join-Path -Path $Neo4jRootDirFullName -ChildPath "conf\neo4j.conf"
    (Get-Content $ConfigFileFullName).replace('#dbms.security.procedures.unrestricted=my.extensions.example,my.procedures.*', 'dbms.security.procedures.unrestricted=apoc.*') | Set-Content $ConfigFileFullName

    # Install service
    $JavaIsInstalled=Get-Command java -ErrorAction SilentlyContinue
    if ($null -ne $JavaIsInstalled) {
      $InstallFileFullName = Join-Path -Path $Neo4jRootDirFullName -ChildPath "bin\neo4j.bat"
      Start-Process $InstallFileFullName "install-service" -NoNewWindow -Wait
      net start neo4j
      Write-Output "Installation done for $SoftwareName"
    } else {
      Write-Output "Java not found. Installation did not finish for $SoftwareName"
    }
  }
}


function GetBloodhound {
  Write-Output "###"
  # Depends on InstallOpenJDK, InstallNeo4j
  $SoftwareName = "Bloodhound"
  Write-Output "Get $SoftwareName..."

  $author="BloodHoundAD"
  $repo="BloodHound"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*win32-x64.zip" })
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
	# Get tools folder
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }

	# Create tools folder if not existing
	if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
	}

	# Copy to tools folder (overwrite existing)
	$NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
	if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
	}
	Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
	Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

	# Unzip
	# Cannot unzip directly to software folder due to too long path. Even with Long paths enabled. This hack works, also with long paths disabled.
	$NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
  $BloodhoundTempDir="\tmp_bh"
	Expand-Archive $NewFileFullName -DestinationPath $BloodhoundTempDir
	Move-Item -Path $BloodhoundTempDir\* -Destination $NewSoftwareFolderFullName
  Remove-Item -Path $BloodhoundTempDir -Recurse -Force | Out-Null
	Remove-Item -Path $NewFileFullName -ErrorAction Ignore
	Remove-Item -Path $BloodhoundTempDir -Recurse -ErrorAction Ignore
	Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveBloodhound {
  Write-Output "###"
  $SoftwareName = "Bloodhound"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetSharphound {
  Write-Output "###"
  $SoftwareName = "Sharphound"
  Write-Output "Get $SoftwareName..."

  #$author="BloodHoundAD"
  #$repo="SharpHound"
  #$Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  #$ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  #$FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -NotLike "*debug*" })
  $FullDownloadURL = "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.exe"
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveSharphound {
  Write-Output "###"
  $SoftwareName = "Sharphound"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetAzurehound {
  Write-Output "###"
  $SoftwareName = "Azurehound"
  Write-Output "Get $SoftwareName..."

  $author="BloodHoundAD"
  $repo="AzureHound"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*windows-amd64*" -and $_ -NotLike "*sha*" })

  #$FullDownloadURL = "https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/AzureHound.ps1"
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveAzurehound {
  Write-Output "###"
  $SoftwareName = "Azurehound"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetImproHound{
  Write-Output "###"
  $SoftwareName = "ImproHound"
  Write-Output "Getting $SoftwareName..."

  $author="improsec" #bloodsuckers
  $repo="ImproHound"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $FullDownloadURL = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveImprohound {
  Write-Output "###"
  $SoftwareName = "Improhound"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetPingCastle{
  Write-Output "###"
  $SoftwareName = "PingCastle"
  Write-Output "Getting $SoftwareName..."


  $author="vletoux"
  $repo="pingcastle"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $FullDownloadURL = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
	# Get tools folder
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  
	# Create tools folder if not existing
	if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
	}

	# Copy to tools folder (overwrite existing)
	$NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
	if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
	}
	Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
	Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

	# Unzip
	$NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
	Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
	Remove-Item -Path $NewFileFullName -ErrorAction Ignore
	Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemovePingCastle {
  Write-Output "###"
  $SoftwareName = "PingCastle"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallVirtIOGuestTool{
  Write-Output "###"

  $SoftwareName = "VirtIOGuestTools"
  Write-Output "Installing $SoftwareName..."
  
  $Url="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $SubUrl = ($ReleasePageLinks | Where-Object { $_.href -Like "*x64*" -And $_.href -Like "*msi" }).href
  $FullDownloadURL = "$Url/$SubUrl"

  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
    Write-Output "Installation done for $SoftwareName"
  }
}


function InstallSpiceGuestTool{
  # Windows SPICE Guest Tools contains optional drivers and services that can be installed in the 
  # Windows guest to improve SPICE performance and integration. This includes the qxl video driver 
  # and the SPICE guest agent (for copy and paste, automatic resolution switching, ...)
  Write-Output "###"
  $SoftwareName = "Spice Guest Tool"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    
    # Install exe
    $CommandLineOptions = "/S"
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function InstallSpiceWebDAV{
  Write-Output "###"
  $SoftwareName = "Spice WebDAV Daemon"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://spice-space.org/download/windows/spice-webdavd/spice-webdavd-x64-latest.msi"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
    Write-Output "Installation done for $SoftwareName"
  }
}


function InstallGPGwin{
  Write-Output "###"
  $SoftwareName = "GPG4Win"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://files.gpg4win.org/gpg4win-latest.exe"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "/S"
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}


function InstallThunderbird{
  Write-Output "###"
  $SoftwareName = "Thunderbird"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=en-US"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "Thunderbird Setup.exe"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "-ms" # silent install
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}


function InstallOffice365{
  Write-Output "###"
  $SoftwareName = "Office365"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = (Invoke-WebRequest -UseBasicParsing -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117").Links.Href | Get-Unique -asstring | Select-String -Pattern officedeploymenttool
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download Office deployment tool
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Download Office binaries
  Start-Process $FileFullName "/quiet /extract:""$SoftwareFolderFullName""" -NoNewWindow -Wait -ErrorAction SilentlyContinue

  # Build a custom XML at https://config.office.com/deploymentsettings
  $ConfigFileFullName = "$SoftwareFolderFullName\setupcustom-Office365.xml"
  '<!-- Office 365 client configuration file for custom downloads -->

  <Configuration>

    <Add Channel="Current">
      <Product ID="O365ProPlusRetail">
        <Language ID="en-gb" />
      </Product>
      <Product ID="LanguagePack">
        <Language ID="en-gb" />
        <Language ID="da-dk" />
        <Language ID="MatchOS"/>
      </Product>
      <Product ID="ProofingTools">
        <Language ID="da-dk" />
        <Language ID="en-us" />
        <Language ID="en-gb" />
      </Product>
    </Add>
    <RemoveMSI/>
    <AppSettings>
    <User Key="software\microsoft\office\16.0\excel\options" Name="defaultformat" Value="51" Type="REG_DWORD" App="excel16" Id="L_SaveExcelfilesas"/>
    <User Key="software\microsoft\office\16.0\powerpoint\options" Name="defaultformat" Value="27" Type="REG_DWORD" App="ppt16" Id="L_SavePowerPointfilesas"/>
    <User Key="software\microsoft\office\16.0\word\options" Name="defaultformat" Value="" Type="REG_SZ" App="word16" Id="L_SaveWordfilesas"/>
    </AppSettings>
    <Updates Enabled="TRUE" Channel="Current" />
    <Display Level="None" AcceptEULA="TRUE" />
    <Property Name="AUTOACTIVATE" Value="1" />
    <Property Name="FORCEAPPSSHUTDOWN" Value="TRUE" />
  </Configuration>' | Out-File $ConfigFileFullName -Force

  Set-Location $SoftwareFolderFullName
  $SetupFileFullName = "$SoftwareFolderFullName\setup.exe"
  Write-Output "Downloading latest installation files. This may take some time..."
  Start-Process -FilePath $SetupFileFullName  -ArgumentList "/download ""$ConfigFileFullName""" -NoNewWindow -Wait

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install
    Write-Output "Starting installation of $SoftwareName. Sit back and wait some more..."
    Start-Process -FilePath $SetupFileFullName -ArgumentList "/configure ""$ConfigFileFullName""" -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
  Set-Location $DefaultDownloadDir 
}

Function DisableTeamsAutoStart {
  Write-Output "###"
	Write-Output "Disabling automatic start of Teams after boot..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -ErrorAction SilentlyContinue
}

# Enable access to messaging from UWP apps
Function ResetTeamsAutoStart {
  Write-Output "###"
	Write-Output "Resetting Teams startup settings..."

  # This is a modification of the script found at https://www.prajwaldesai.com/disable-microsoft-teams-auto-startup
  $TeamsDesktopConfigJsonPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft', 'Teams', 'desktop-config.json')
  $TeamsUpdatePath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams', 'Update.exe')

  $teamsProc = Get-Process -name Teams -ErrorAction SilentlyContinue
  if ($null -ne $teamsProc) { # Teams is runnning
      Stop-Process -Name Teams -Force
      Start-Sleep 5
  } 
  # is Teams process still running
  $teamsProc = Get-Process -name Teams -ErrorAction SilentlyContinue

  if($null -eq $teamsProc) {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Teams" -Name "LoggedInOnce" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Teams" -Name "HomeUserUpn" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Teams" -Name "DeadEnd" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect" -ErrorAction SilentlyContinue
    
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -Value "$TeamsUpdatePath --processStart ""Teams.exe"" --process-start-args ""--system-initiated""" -Force

    # Removing entries 'isLoggedOut' and 'openAtLogin' in the desktop-config.json file
    if (Test-Path -Path $TeamsDesktopConfigJsonPath) {
        # open desktop-config.json file
        $desktopConfigFile = Get-Content -path $TeamsDesktopConfigJsonPath -Raw | ConvertFrom-Json
        $desktopConfigFile.PSObject.Properties.Remove("guestTenantId")
        $desktopConfigFile.PSObject.Properties.Remove("isLoggedOut")
        try {
            $desktopConfigFile.appPreferenceSettings.openAtLogin = $true
        } catch {
          # Do nothing
        }
        $desktopConfigFile | ConvertTo-Json -Compress | Set-Content -Path $TeamsDesktopConfigJsonPath -Force
    }
    Write-Host "Teams autostart functions restored to default"	
  } else {
      Write-Host  "ERROR: Teams process did not shut down in time. No actions performed."
  }
}

function RemoveTeamsWideInstaller{
  Write-Output "###"
  # Remove Teams Machine-Wide Installer
  Write-Output "Removing Teams Machine-wide Installer" 

  $MachineWide = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Teams Machine-Wide Installer"}
  $MachineWide.Uninstall() | Out-Null
}

function RemoveTeamsStoreApp{
  Write-Output "###"
  Write-Output "Removing Teams Store App" 

  Get-AppxPackage 'MicrosoftTeams' | Remove-AppxPackage
}

function InstallVisioPro{
  Write-Output "###"
  $SoftwareName = "VisioPro"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = (Invoke-WebRequest -UseBasicParsing -Uri "https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117").Links.Href | Get-Unique -asstring | Select-String -Pattern officedeploymenttool
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download Office deployment tool
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Download Visio
  Start-Process $FileFullName "/quiet /extract:$SoftwareFolderFullName" -NoNewWindow -Wait
  $ConfigFileFullName = "$SoftwareFolderFullName\custom-visio.xml"
  '<!-- Office 365 client configuration file for custom downloads -->

  <Configuration>

    <Add Channel="Current">
      <Product ID="VisioProRetail">
        <Language ID="en-gb" />
      </Product>
      <Product ID="LanguagePack">
        <Language ID="en-gb" />
        <Language ID="da-dk" />
        <Language ID="MatchOS"/>
      </Product>
      <Product ID="ProofingTools">
        <Language ID="da-dk" />
        <Language ID="en-us" />
        <Language ID="en-gb" />
      </Product>
    </Add>
    <RemoveMSI/>
    <Updates Enabled="TRUE" Channel="Current" />
    <Display Level="None" AcceptEULA="TRUE" />
    <Property Name="AUTOACTIVATE" Value="1" />
    <Property Name="FORCEAPPSSHUTDOWN" Value="TRUE" />
  </Configuration>' | Out-File $ConfigFileFullName
  
  Set-Location $SoftwareFolderFullName
  $SetupFileFullName = "$SoftwareFolderFullName\setup.exe"
  Start-Process -FilePath "$SetupFileFullName" -ArgumentList "/download ""$ConfigFileFullName""" -NoNewWindow -Wait

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install
    Start-Process -FilePath "$SetupFileFullName" -ArgumentList "/configure ""$ConfigFileFullName""" -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
  Set-Location $DefaultDownloadDir 
}


function InstallVMwareWorkstation{
  Write-Output "###"
  $SoftwareName = "VMware Workstation"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = [System.Net.HttpWebRequest]::Create("https://www.vmware.com/go/getworkstation-win").GetResponse().ResponseUri.AbsoluteUri
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Determine variable name of variable holding serial number (in case ini file was loaded)
  $FoundMajorVersion = $FullDownloadURL -match '.*workstation-full-(\d+)\.*'
  if ($FoundMajorVersion) {
      $MajorVersion=$matches[1]
      $KeyName=("VMWAREWORKSTATION" + $MajorVersion)
      $VMwareSerialNumber = [Environment]::GetEnvironmentVariable("RIDEVAR-VMwareWorkstation-$KeyName", "Process")
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "/s /v/qn REBOOT=ReallySuppress ADDLOCAL=ALL EULAS_AGREED=1 "
    if ($null -ne $VMwareSerialNumber) {
      $CommandLineOptions += "SERIALNUMBER=""$VMwareSerialNumber"""
    }
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveVMwareWorkstation{
  Import-Module PackageManagement
  Write-Output "###"
  Write-Output "Removing VMware Workstation..."
  Uninstall-Package -InputObject ( Get-Package -Name "VMware Workstation")
}

function SetVMDirUserhome(){

  # Edit VMWare preference file and set default VM directory
  $VMWareWkstDir="$env:APPDATA\VMware"
  $VMWareWkstIni="$VMWareWkstDir\preferences.ini"
  
  $NewDefaultVMPath="$env:USERPROFILE\Virtual Machines"
  $ConfigKey="prefvmx.defaultVMPath = "
  $ConfigParameter = $NewDefaultVMPath

  # Test if new default vm dir exists
  if (-not (Test-Path -Path $NewDefaultVMPath)) {
    New-Item -Path $NewDefaultVMPath -ItemType Directory | Out-Null
    }

  # Test if ini file exists and contains default directory value
  if ((Test-Path $VMWareWkstIni) -and ((Get-Content $VMWareWkstIni | Select-String -Pattern $ConfigKey ).Matches.Success )) {
      # Replace value in ConfigKey with new value and write it to the ini file
      (Get-Content $VMWareWkstIni) -replace ("(?<=$ConfigKey)" +'(.*?)(?="$)'),$ConfigParameter | Set-Content $VMWareWkstIni
  } else { 
    if (-not (Test-Path -Path $VMWareWkstDir)) {
      New-Item -Path $VMWareWkstDir -ItemType Directory | Out-Null
      }
    # Write a single line to the inifile (-Append is obsolete)
    $ConfigKey+""""+$ConfigParameter+""""| Out-File -FilePath "$VMWareWkstIni" -Encoding utf8 -Append
    }
}

function SetVMDirDocuments(){

  # Edit VMWare preference file and set default VM directory
  $VMWareWkstDir="$env:APPDATA\VMware"
  $VMWareWkstIni="$VMWareWkstDir\preferences.ini"

  $DefaultDocumentsPath=[Environment]::GetFolderPath("MyDocuments")
  $NewDefaultVMPath="$DefaultDocumentsPath\Virtual Machines"
  
  $ConfigKey="prefvmx.defaultVMPath = "
  $ConfigParameter = $NewDefaultVMPath

  # Test if new default vm dir exists
  if (-not (Test-Path -Path $NewDefaultVMPath)) {
    New-Item -Path $NewDefaultVMPath -ItemType Directory | Out-Null
    }

  # Test if ini file exists and contains default directory value
  if ((Test-Path $VMWareWkstIni) -and ((Get-Content $VMWareWkstIni | Select-String -Pattern $ConfigKey ).Matches.Success )) {
      # Replace value in ConfigKey with new value and write it to the ini file
      (Get-Content $VMWareWkstIni) -replace ("(?<=$ConfigKey)" +'(.*?)(?="$)'),$ConfigParameter | Set-Content $VMWareWkstIni
  } else { 
    if (-not (Test-Path -Path $VMWareWkstDir)) {
      New-Item -Path $VMWareWkstDir -ItemType Directory | Out-Null
      }
    # Write a single line to the inifile (-Append is obsolete)
    $ConfigKey+""""+$ConfigParameter+""""| Out-File -FilePath "$VMWareWkstIni" -Encoding utf8 -Append
    }
}

function InstallJoplin{
  Write-Output "###"
  $SoftwareName = "Joplin"
  Write-Output "Installing $SoftwareName..."

  $author="laurent22"
  $repo="joplin"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*Joplin-Setup*" -and $_ -Like "*.exe*"})
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $CommandLineOptions = "/allusers /S"
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function InstallImageMagick {
  Write-Output "###"

  $SoftwareName = "ImageMagick"
  Write-Output "Installing $SoftwareName..."
  
  $Url="https://imagemagick.org/script/download.php#windows"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_.href -Like "*x64*" -And $_.href -Like "*exe" -And $_.href -Like "*HDRI*" -And $_.href -Like "*dll*"} | Select-Object -First 1).href

  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe 
    $InstallFile = $FileFullName
    $CommandLineOptions = "/SILENT /NORESTART"
    Start-Process -FilePath $InstallFile -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function InstallImageMagickPortable {
  Write-Output "###"

  $SoftwareName = "ImageMagickPortable"
  Write-Output "Installing $SoftwareName..."
  
  $Url="https://imagemagick.org/script/download.php#windows"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_.href -Like "*x64*" -And $_.href -Like "*zip" -And $_.href -Like "*HDRI*" -And $_.href -Like "*portable*"} | Select-Object -First 1).href

  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveImageMagickPortable {
  Write-Output "###"
  $SoftwareName = "ImageMagickPortable"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallSignal {
  Write-Output "###"

  $SoftwareName = "Signal"
  Write-Output "Installing $SoftwareName..."
  
  $SubUrl = "https://updates.signal.org/desktop"
  $Url="$SubUrl/latest.yml"
  $YAMLfileraw = (Invoke-WebRequest -UseBasicParsing -Uri $Url).rawcontent
  $Regex = [Regex]::new("(?<=url: )(.*)")
  $FileName = $Regex.Match($YAMLfileraw).Value
  $FullDownloadURL = "$SubUrl/$FileName"

  if (-not $FileName) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe 
    $InstallFile = $FileFullName
    $CommandLineOptions = "/S"
    Start-Process -FilePath $InstallFile -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function InstallPython {
  Write-Output "###"
  $SoftwareName = "Python"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://www.python.org/downloads/windows/"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_.href -Like "*amd64*" -and $_.href -Like "*exe*"} | Select-Object -first 1 ).href
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Install exe 
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    $CommandLineOptions = "/quiet InstallAllUsers=1 AssociateFiles=1 PrependPath=1" 
    Start-Process -FilePath $FileFullName -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    
    # Test if python exists as path environment variable and add if it does not
    $PythonFolder = (Get-Item ([System.Environment]::GetFolderPath("ProgramFiles")+"\Python*")).FullName
    if ($null -eq $PythonFolder) {
      Write-Host "Python folder not found. Exiting."
      break
    } else { 
      # The Python folder exist - check if it is in environment variable
      $PythonFolderInPath = $env:path -split ";" | Where-Object { $_ -eq $PythonFolder }
      if ($null -eq $PythonFolderInPath ) { 
        # Python is not in path - adding
        $PythonScripts = Join-Path -Path $PythonFolder -ChildPath "Scripts"
        $env:Path = "$PythonScripts;$PythonFolder;" + $env:Path
      }
    }

    Write-Output "Upgrading pip"
    $CommandLineOptions = "-m pip install --upgrade pip"
    Start-Process -FilePath python.exe -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function InstallYara {
  Write-Output "###"
  $SoftwareName = "Yara"
  Write-Output "Installing $SoftwareName..."

  $author="VirusTotal"
  $repo="yara"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*win*" -and $_ -Like "*64*" -and $_ -Like "*zip*" })
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}


function RemoveYara {
  Write-Output "###"
  $SoftwareName = "Yara"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetCyberChef {
  Write-Output "###"
  $SoftwareName = "CyberChef"
  Write-Output "Get $SoftwareName..."

  $author="gchq"
  $repo="CyberChef"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = ($ReleasePageLinks | Select-Object -First 1 )
  if (-not $FullDownloadURL) {
    Write-Output "Error: $SoftwareName not found"
    return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
    New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
    New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
    $ToolsFolder = "\Tools"
  }

    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveCyberChef {
  Write-Output "###"
  $SoftwareName = "CyberChef"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallCaffeine {
  Write-Output "###"
  $SoftwareName = "Caffeine"
  Write-Output "Get $SoftwareName..."

  $FullDownloadURL = "https://www.zhornsoftware.co.uk/caffeine/caffeine.zip"
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "$SoftwareName.zip"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Invoke-WebRequest -Uri $FullDownloadURL -OutFile $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    
    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }
    
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"

  }
}

function RemoveCaffeine {
  Write-Output "###"
  $SoftwareName = "Caffeine"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}


function InstallPutty {
  Write-Output "###"
  $SoftwareName = "Putty"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $SoftwareUri = ($ReleasePageLinks | Where-Object { $_.href -Like "*w64/putty.exe" }).href
  $FullDownloadURL = "$SoftwareUri"
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
		New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
		Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
  
}

function RemovePutty {
  Write-Output "###"
  $SoftwareName = "Putty"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}


function InstallWinSCP {
  Write-Output "###"
  $SoftwareName = "WinSCP"
  Write-Output "Installing $SoftwareName..."

  $BaseUrl = "https://winscp.net"
  $Url = "https://winscp.net/eng/downloads.php"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $SoftwareUri = ($ReleasePageLinks | Where-Object { ($_.href -Like "*Portable.zip") -and ( $_.href -NotLike "*beta*") }).href
  $FullDownloadURL = "${BaseUrl}${SoftwareUri}"
  if (-not $SoftwareUri) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  #Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName -ErrorAction SilentlyContinue

  # WinSCP webserver is not playing nice. 
  $ServerResponse = Invoke-WebRequest $FullDownloadURL -MaximumRedirection 0 -UseBasicParsing
  $WinscpDownloadURL = $ServerResponse.Links | Where-Object {$_.outerHTML -match "Direct download"}  | Select-Object -ExpandProperty href
  # $filename = ([uri]$WinscpDownloadURL).Segments[-1]
  Invoke-WebRequest -UseBasicParsing -Uri $WinscpDownloadURL -OutFile $FileFullName

  if (Test-Path -Path $FileFullName) {
    Write-Output "Downloaded: $FileFullName"}
  else {
    Write-Output "Error downloading: $FileFullName" 
  }

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
		New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
		Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }

  # Unzip
	$NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
	Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
	Remove-Item -Path $NewFileFullName -ErrorAction Ignore
	Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  
}

function RemoveWinSCP {
  Write-Output "###"
  $SoftwareName = "WinSCP"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}


function InstallKAPE {
  Write-Output "###"
  $SoftwareName = "KAPE"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://s3.amazonaws.com/cyb-us-prd-kape/kape.zip"
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName -ErrorAction SilentlyContinue

  if (Test-Path -Path $FileFullName) {
    Write-Output "Downloaded: $FileFullName"}
  else {
    Write-Output "Error downloading: $FileFullName" 
  }

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
		New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
		Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }

  # Unzip
	$NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
	Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
	Remove-Item -Path $NewFileFullName -ErrorAction Ignore
	Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  
}

function RemoveKAPE {
  Write-Output "###"
  $SoftwareName = "KAPE"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}


function InstallVeraCryptPortable {
  Write-Output "###"
  $SoftwareName = "VeraCryptPortable"
  Write-Output "Fetching $SoftwareName..."

  $author="veracrypt"
  $repo="VeraCrypt"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = $ReleasePageLinks | Where-Object { ($_ -Like "*exe") -and ($_ -Like "*Portable*") | Select-Object -First 1 }
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName -ErrorAction SilentlyContinue

  if (Test-Path -Path $FileFullName) {
    Write-Output "Downloaded: $FileFullName"}
  else {
    Write-Output "Error downloading: $FileFullName" 
  }

  Write-Output "The portable installer does not support unattaended install. Please run installer manually."
  
}

function InstallVeraCrypt {

  Write-Output "###"
  $SoftwareName = "VeraCrypt"
  Write-Output "Installing $SoftwareName..."

  $author="veracrypt"
  $repo="VeraCrypt"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = $ReleasePageLinks | Where-Object { ($_ -Like "*msi") | Select-Object -First 1 }
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName -ErrorAction SilentlyContinue

  if (Test-Path -Path $FileFullName) {
    Write-Output "Downloaded: $FileFullName"}
  else {
    Write-Output "Error downloading: $FileFullName" 
  }

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" ACCEPTLICENSE=YES /qn" -Wait -NoNewWindow
    Write-Output "Installation done for $SoftwareName"
  }
  
}


################################################################
###### Browsers and Internet ###
################################################################

function DisableEdgePagePrediction{
  Write-Output "###"
  # Disable Microsoft Edge Page Prediction
  # When Page Prediction is enabled in Microsoft Edge, the browser might crawl pages you never actually visit during the browsing session.
  # This exposes your machine fingerprint and also creates a notable load on PCs with low end hardware because the browser calculates the
  # possible URL address every time you type something into the address bar. It also creates potentially unnecessary bandwidth usage.

  # https://www.kapilarya.com/how-to-enable-disable-page-prediction-in-microsoft-edge


  Write-Output "Disabling Microsoft Edge page prediction..."
  If (!(Test-Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\")) {
    New-Item -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\" -Force | Out-Null
  }
	Set-ItemProperty -path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead\" -name FPEnabled -value 0

}

function InstallFirefox{
  Write-Output "###"
  $SoftwareName = "Mozilla Firefox"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = [System.Net.HttpWebRequest]::Create("https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US").GetResponse().ResponseUri.AbsoluteUri
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveFirefox{
  Write-Output "###"
  Write-Output "Removing Mozilla Firefox..."
  
  $UninstallString=Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox*"  | ForEach-Object { Get-ItemProperty $_.PsPath } | Select-Object UninstallString
  $AllArguments = " "
  Start-Process -FilePath $UninstallString -ArgumentList $AllArguments -NoNewWindow -Wait
}

function CreateFirefoxPreferenceFiles {
  Write-Output "###"
  # See more at https://developer.mozilla.org/en-US/Firefox/Enterprise_deployment
  Write-Output "Creating prefence files for Mozilla Firefox..."

  $FirefoxInstallDir = [System.Environment]::GetFolderPath("ProgramFilesX86")+"\Mozilla Firefox\"

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

" | Out-Null

  # Create the autoconfig.js file
  New-Item ($firefoxInstallDir+"defaults\pref\autoconfig.js") -type file -force -value "pref(""general.config.filename"", ""mozilla.cfg"");
pref(""general.config.obscure_value"", 0);
" | Out-Null

  # Create the override.ini file (disables Migration Wizard)
  New-Item ($firefoxInstallDir+"browser\override.ini") -type file -force -value "[XRE]
EnableProfileMigrator=false
" | Out-Null
}

function InstallChrome{
  Write-Output "###"
  $SoftwareName = "Chrome"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = [System.Net.HttpWebRequest]::Create("https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%3Dx64-stable/dl/chrome/install/googlechromestandaloneenterprise64.msi").GetResponse().ResponseUri.AbsoluteUri
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveFirefoxPreferenceFiles {
  Write-Output "###"
  Write-Output "Removing prefence files for Mozilla Firefox..."

  $InstallDir = [System.Environment]::GetFolderPath("ProgramFilesX86")+"\Mozilla Firefox\"

  # Remove mozilla.cfg
  $FileFullName = Join-Path -Path  $InstallDir -ChildPath "mozilla.cfg"
  Remove-Item $FileFullName -Recurse -Force -ErrorAction SilentlyContinue

  # Remove autoconfig.js 
  $FileFullName = Join-Path -Path  $InstallDir -ChildPath "defaults\pref\autoconfig.js"
  Remove-Item $FileFullName -Recurse -Force -ErrorAction SilentlyContinue

  # Remove override.ini
  $FileFullName = Join-Path -Path  $InstallDir -ChildPath "browser\override.ini"
  Remove-Item $FileFullName -Recurse -Force -ErrorAction SilentlyContinue

}

function RemoveChrome{
  Import-Module PackageManagement
  Write-Output "###"
  Write-Output "Removing Google Chrome..."
  Uninstall-Package -InputObject ( Get-Package -Name "Google Chrome")
}

function CreateChromePreferenceFile {
  Write-Output "###"
Write-Output "Creating preference file for Google Chrome..."

  $ChromeInstallDir = [System.Environment]::GetFolderPath("ProgramFilesX86")+"\Google\Chrome\Application\"

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
" | Out-Null
}

function RemoveChromePreferenceFile {
  Write-Output "###"
  Write-Output "Removing prefence files for Mozilla Firefox..."

  $InstallDir = [System.Environment]::GetFolderPath("ProgramFilesX86")+"\Google\Chrome\Application\"
  $FileFullName = Join-Path -Path  $InstallDir -ChildPath "master_preferences"

  Remove-Item $FileFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallOpera{
  Write-Output "###"
  $SoftwareName = "Opera"
  Write-Output "Installing $SoftwareName..."

  $URL = "https://get.geo.opera.com/pub/opera/desktop/"
  $CheckURL=[System.Net.HttpWebRequest]::Create($URL).GetResponse().ResponseUri.AbsoluteUri
  if (! $CheckURL) {Write-Output "Error: URL not resolved"; return}
  $LatestOperaVersion=(Invoke-WebRequest -UseBasicParsing  -Uri $URL).Links.Href | Get-Unique -asstring | Sort-Object -Descending | select-object -First 1
  if (! $LatestOperaVersion) {Write-Output "Error: Opera browser not found"; return}
  $LatestOperaPath = "$($URL)$($LatestOperaVersion)win/"
  $FullDownloadURL = $LatestOperaPath + ((Invoke-WebRequest -UseBasicParsing -Uri $LatestOperaPath).Links.Href | Get-Unique -asstring | Sort-Object -Descending | Select-String -Pattern "Autoupdate_x64.exe$")
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Unpack
  $CommandLineOptions = "/SILENT /LOG"
  Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    $InstallFile = "$SoftwareFolderFullName\installer.exe"
    $CommandLineOptions = "--silent --setdefaultbrowser=0 --startmenushortcut=0 --desktopshortcut=0 --pintotaskbar=0 --pin-additional-shortcuts=0 --launchbrowser=0"
    Start-Process -FilePath $InstallFile -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}


################################################################
###### Forensic Functions  ###
################################################################

function InstallAutorunner{
  Write-Output "###"
  $SoftwareName = "Autorunner"
  Write-Output "Installing $SoftwareName..."
  # https://github.com/woanware/autorunner

  $author="woanware"
  $repo="autorunner"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $FullDownloadURL = ((Invoke-WebRequest -UseBasicParsing -Uri $Url).content | ConvertFrom-Json).assets.browser_download_url

  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveAutorunner {
  Write-Output "###"
  $SoftwareName = "Autorunner"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallChainsaw{
  Write-Output "###"
  $SoftwareName = "chainsaw"
  Write-Output "Installing $SoftwareName..."

  $author="WithSecureLabs"
  $repo="chainsaw"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*windows*" -and $_ -Like "*msvc*" -and $_ -Like "*zip*"})
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    
    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }

    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveChainsaw {
  Write-Output "###"
  $SoftwareName = "Chainsaw"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetChromeParser {
  Write-Output "###"
  $SoftwareName = "ChromeParser"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "https://raw.githubusercontent.com/marleyjaffe/ChromeSyncParser/master/ChromeParser.py"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

  }
}
function RemoveChromeParser {
  Write-Output "###"
  $SoftwareName = "ChromeParser"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallCyLR{
  Write-Output "###"
  $SoftwareName = "CyLR"
  Write-Output "Installing $SoftwareName..."

  $author="orlikoski"
  $repo="CyLR"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*win*" -and $_ -Like "*86*" -and $_ -Like "*zip*" })
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveCyLR {
  Write-Output "###"
  $SoftwareName = "CyLR"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallDejsonlz4{
  Write-Output "###"
  $SoftwareName = "Dejsonlz4"
  Write-Output "Installing $SoftwareName..."
  
  $author="avih"
  $repo="dejsonlz4"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*zip*" })
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveDejsonlz4 {
  Write-Output "###"
  $SoftwareName = "Dejsonlz4"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function GetHex2text{
  Write-Output "###"
  $SoftwareName = "Hex2text"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "https://raw.githubusercontent.com/gh05t-4/hex2text/master/hex2text.py"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

  }
}

function RemoveHex2text {
  Write-Output "###"
  $SoftwareName = "Hex2text"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallHindsight{
  Write-Output "###"
  $SoftwareName = "Hindsight"
  Write-Output "Installing $SoftwareName..."
  
  $author="obsidianforensics"
  $repo="hindsight"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*gui*" -and $_ -Like "*exe*" })

  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"
  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveHindsight {
  Write-Output "###"
  $SoftwareName = "Hindsight"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallLoki{
  Write-Output "###"
  $SoftwareName = "Loki"
  Write-Output "Installing $SoftwareName..."

  $author="Neo23x0"
  $repo="Loki"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*loki_*" -and $_ -Like "*zip*" })
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
    
    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }
  }
}

function RemoveLoki {
  Write-Output "###"
  $SoftwareName = "Loki"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallNucleusKernelFATNTFS{
  Write-Output "###"
  $SoftwareName = "NucleusKernelFATNTFS"
  Write-Output "Get $SoftwareName..."
  $Url = "https://www.nucleustechnologies.com/data-recovery.html"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $FullDownloadURL =  ($ReleasePageLinks | Where-Object { $_.href -Like "*dl*" -and $_.href -Like "*id=1" }).href
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }
  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "Nucleus-Kernel-FAT-NTFS.exe"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe 
    $InstallFile = $FileFullName
    $CommandLineOptions = "/VERYSILENT /NORESTART /LOG /SUPPRESSMSGBOXES"
    Start-Process -FilePath $InstallFile -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}


function GetOSTViewer{
  Write-Output "###"
  $SoftwareName = "OST_Viewer"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "https://www.nucleustechnologies.com/dl/dl.php?id=127"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "OST_Viewer.exe"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe 
    $InstallFile = $FileFullName
    $CommandLineOptions = "/SILENT /NORESTART"
    Start-Process -FilePath $InstallFile -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Remove-Item "$Home\Desktop\Kernel OST Viewer*.lnk" -Force -ErrorAction SilentlyContinue
    Write-Output "Installation done for $SoftwareName"
  }
}


function GetPSTViewer{
  Write-Output "###"
  $SoftwareName = "PST_Viewer"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "https://www.nucleustechnologies.com/dl/dl.php?id=125"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "PST_Viewer.exe"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe 
    $InstallFile = $FileFullName
    $CommandLineOptions = "/SILENT /NORESTART"
    Start-Process -FilePath $InstallFile -ArgumentList $CommandLineOptions -NoNewWindow -Wait
    Remove-Item "$Home\Desktop\Kernel Outlook PST Viewer*.lnk" -Force -ErrorAction SilentlyContinue
    Write-Output "Installation done for $SoftwareName"
  }
}


function GetShimCacheParser{
  Write-Output "###"
  $SoftwareName = "ShimCacheParser"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "https://raw.githubusercontent.com/mandiant/ShimCacheParser/master/ShimCacheParser.py"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveShimCacheParser {
  Write-Output "###"
  $SoftwareName = "ShimCacheParser"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallSqlitebrowser{
  Write-Output "###"
  $SoftwareName = "sqlitebrowser"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://download.sqlitebrowser.org"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $SoftwareUri = ($ReleasePageLinks | Where-Object { $_.href -Like "*win64*" -and $_.href -Like "*msi*" -and $_.href -notlike "*.11*" -and $_.href -notlike "*.0*"}).href
  $FullDownloadURL = "https://download.sqlitebrowser.org$SoftwareUri"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Install MSI 
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
    Write-Output "Installation done for $SoftwareName"
  }
}

function InstallSrumDump{
  Write-Output "###"
  $SoftwareName = "srum_dump2"
  Write-Output "Installing $SoftwareName..."

  $author="MarkBaggett"
  $repo="srum-dump"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*srum_*" -and $_ -Like "*exe*" })
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveSrumDump {
  Write-Output "###"
  $SoftwareName = "SrumDump"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallSrumMonkey{
  Write-Output "###"
  $SoftwareName = "SrumMonkey"
  Write-Output "Installing $SoftwareName..."

  $author="devgc"
  $repo="SrumMonkey"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*SrumMonkey*" -and $_ -Like "*exe*" })
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

  }
}

function RemoveSrumMonkey {
  Write-Output "###"
  $SoftwareName = "SrumMonkey"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallSSView {
  Write-Output "###"
  $SoftwareName = "SSView"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "https://www.mitec.cz/Downloads/SSView.zip"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }

}

function RemoveSSView {
  Write-Output "###"
  $SoftwareName = "SSView"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallThumbcacheviewer {
  Write-Output "###"
  $SoftwareName = "ThumbCacheViewer"
  Write-Output "Installing $SoftwareName..."

  $author="thumbcacheviewer"
  $repo="thumbcacheviewer"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*64*" -and $_ -Like "*zip*" })

  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveThumbcacheviewer {
  Write-Output "###"
  $SoftwareName = "Thumbcacheviewer"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallSuperFetchTools2 {
  Write-Output "###"
  $SoftwareName = "SuperFetchTools2"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "https://www.tmurgent.com/download/SuperFetch_Tools2.zip"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveSuperFetchTools2 {
  Write-Output "###"
  $SoftwareName = "SuperFetchTools2"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallUserAssist {
  Write-Output "###"
  $SoftwareName = "UserAssist"
  Write-Output "Installing $SoftwareName..."

  $Url = "https://blog.didierstevens.com/my-software/#UserAssist"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $SoftwareUri = ($ReleasePageLinks | Where-Object { $_.href -Like "*UserAssist_*" -and $_.href -Like "*zip*" -and $_.href -notlike "*_4_*"-and $_.href -notlike "*_3_*" -and $_.href -notlike "https*"}).href
  $FullDownloadURL = "$SoftwareUri"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction SilentlyContinue -Force
    
    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName -ErrorAction SilentlyContinue
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }
    
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveUserAssist {
  Write-Output "###"
  $SoftwareName = "UserAssist"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallThumbsviewer{
  Write-Output "###"
  $SoftwareName = "Thumbsviewer"
  Write-Output "Installing $SoftwareName..."

  $author="thumbsviewer"
  $repo="thumbsviewer"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*64*" -and $_ -Like "*zip*" })
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveThumbsviewer {
  Write-Output "###"
  $SoftwareName = "Thumbsviewer"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallRegRipper{
  Write-Output "###"
  $SoftwareName = "RegRipper3.0"
  Write-Output "Get $SoftwareName..."

  $FullDownloadURL = "https://github.com/keydet89/RegRipper3.0/raw/master/rr.exe"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveRegRipper {
  Write-Output "###"
  $SoftwareName = "RegRipper3.0"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallWinhex {
  Write-Output "###"
  $SoftwareName = "Winhex"
  Write-Output "Get $SoftwareName..."
  $FullDownloadURL = "http://www.x-ways.net/winhex.zip"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }

}

function RemoveWinhex {
  Write-Output "###"
  $SoftwareName = "Winhex"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallWinPmem{
  Write-Output "###"
  $SoftwareName = "WinPmem"
  Write-Output "Installing $SoftwareName..."

  $author="Velocidex"
  $repo="WinPmem"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*64*" -and $_ -Like "*exe*" })
 
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveWinPmem {
  Write-Output "###"
  $SoftwareName = "WinPmem"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallVolatility2{
  Write-Output "###"
  $SoftwareName = "volatility2"
  Write-Output "Get $SoftwareName..."
  # Released: December 2016 indicating no further updates
  $FullDownloadURL = "http://downloads.volatilityfoundation.org/releases/2.6/volatility_2.6_win64_standalone.zip"
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore

    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName 
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }

    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemoveVolatility2 {
  Write-Output "###"
  $SoftwareName = "Volatility2"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallVolatility3{
  Write-Output "###"
  $SoftwareName = "volatility3"
  Write-Output "Installing $SoftwareName..."

  $author="volatilityfoundation"
  $repo="volatility3"
  $Url = "https://github.com/$author/$repo"
  $PageLinks =  (Invoke-WebRequest -UseBasicParsing -Uri $Url ).links 
  $SymbolLinks = ($PageLinks | Where-Object { $_ -Like "*symbols*" }).href  

  if (-not $SymbolLinks) {
    Write-Output "Error: Symbol tables not found"
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
    New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Check if repo folder exists and delete it if it does
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (Test-Path -Path $SoftwareFolderFullName) {
    Remove-Item -Path $SoftwareFolderFullName -Recurse -Force
  }

  # clone git repo
  Set-Location $BootstrapFolder
  Start-Process git.exe -ArgumentList  "clone $Url" -NoNewWindow -wait
  
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
    Write-Output "Directory $SoftwareFolderFullName was not found. Exiting..."
    return
  }

  # Download symbol tables
  Write-Output "Downloading symbol tables."
  $SymbolsFolder = Join-Path -Path $SoftwareFolderFullName -ChildPath "$repo\symbols"
  Set-Location $SymbolsFolder
  foreach ($File in $SymbolLinks) {
    Start-BitsTransfer -Source $File
  }
  $SymbolsFolder = Join-Path -Path $SoftwareFolderFullName -ChildPath "$repo\symbols"
  Write-Output "Downloaded symbol tables to: $SymbolsFolder"

  # Install full set of requirements
  Set-Location $SoftwareFolderFullName

  # Test if python exists as path environment variable and add if it does not
  $PythonFolder = (Get-Item ([System.Environment]::GetFolderPath("ProgramFiles")+"\Python*")).FullName
  if ($null -eq $PythonFolder) {
    Write-Host "Python folder not found. Exiting."
    break
  } else { 
    # The Python folder exist - check if it is in environment variable
    $PythonFolderInPath = $env:path -split ";" | Where-Object { $_ -eq $PythonFolder }
    if ($null -eq $PythonFolderInPath ) { 
      # Python is not in path - adding
      $PythonScripts = Join-Path -Path $PythonFolder -ChildPath "Scripts"
      $env:Path = "$PythonScripts;$PythonFolder;" + $env:Path
    }
  }
  $CommandLineOptions = "setup.py build"
  Start-Process python.exe -ArgumentList $CommandLineOptions -NoNewWindow -Wait
  $CommandLineOptions = "setup.py install"
  Start-Process python.exe -ArgumentList $CommandLineOptions -NoNewWindow -Wait
  
  # Copy to tools folder
  Set-Location $BootstrapFolder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }

}

function InstallPartDiagParser {
  Write-Output "###"
  $SoftwareName = "PartitionDiagnosticParser"
  Write-Output "Get $SoftwareName..."
 
  $author="theAtropos4n6"
  $repo="Partition-4DiagnosticParser"
  $Url = "https://api.github.com/repos/$author/$repo/zipball"
  $FullDownloadURL = $Url
 
  if (-not $FullDownloadURL) {
    Write-Output "Error: $SoftwareName not found"
    return
    }
  
  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
    New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
    New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "$SoftwareName.zip"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Invoke-WebRequest -Uri $FullDownloadURL -OutFile $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore

    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }

    Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }
}

function RemovePartDiagParser {
  Write-Output "###"
  $SoftwareName = "PartitionDiagnosticParser"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallGglCookieCruncher{
  Write-Output "###"
  $SoftwareName = "GoogleAnalyticCookieCruncher"
  Write-Output "Get $SoftwareName..."

  $author="mdegrazia"
  $repo="Google-Analytic-Cookie-Cruncher"
  $FullDownloadURL = "https://api.github.com/repos/$author/$repo/zipball"
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "$SoftwareName.zip"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Invoke-WebRequest -Uri $FullDownloadURL -OutFile $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

    # Unzip
    $NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
    Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $NewFileFullName -ErrorAction Ignore
    
    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }
    
    # Unpack zip file inside the package
    $ZipFile = (Get-ChildItem -Path  $NewSoftwareFolderFullName -Filter "*.zip" | Select-Object -First 1).FullName
    Expand-Archive $ZipFile -DestinationPath $NewSoftwareFolderFullName
    Remove-Item -Path $ZipFile -ErrorAction SilentlyContinue -Force

    Write-Output "Unzipped to: $NewSoftwareFolderFullName"

  }
}

function RemoveGglCookieCruncher {
  Write-Output "###"
  $SoftwareName = "GoogleAnalyticCookieCruncher"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallSigma{
  Write-Output "###"
  $SoftwareName = "Sigma"
  Write-Output "Installing $SoftwareName..."

  $author="SigmaHQ"
  $repo="sigma"
  $Url = "https://github.com/$author/$repo"
  
  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
    New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Check if repo folder exists and delete it if it does
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (Test-Path -Path $SoftwareFolderFullName) {
    Remove-Item -Path $SoftwareFolderFullName -Recurse -Force
  }

  # clone git repo
  Set-Location $BootstrapFolder
  Start-Process git.exe -ArgumentList  "clone $Url" -NoNewWindow -wait
  
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
    Write-Output "Directory $SoftwareFolderFullName was not found. Exiting..."
    return
  }

  # Copy to tools folder
  Set-Location $BootstrapFolder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }

}

function RemoveSigma {
  Write-Output "###"
  $SoftwareName = "Sigma"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallHashcat { 
  Write-Output "###"
  $SoftwareName = "Hashcat"
  Write-Output "Get $SoftwareName..."

  $BaseUrl = "https://hashcat.net"
  $Url = "$BaseUrl/hashcat/"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $SoftwareUri = ($ReleasePageLinks | Where-Object { $_.href -Like "*7z" }).href | Select-Object -First 1
  $FullDownloadURL = "$BaseUrl$SoftwareUri"
  
  if (-not $SoftwareUri) {
	Write-Output "Error: $SoftwareName not found"
	return
  }
 
  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Invoke-WebRequest -Uri $FullDownloadURL -OutFile $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

    # Create software directory in Tools folder
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
    Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force | Out-Null
    } 
    New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null
    
    # To unpack package, this function depends on 7-Zip
    $ArchiveTool = [System.Environment]::GetFolderPath("ProgramFiles")+"\7-Zip\7z.exe"
    # Unzip password protected file
    if (-not (Test-Path $ArchiveTool)) {
        Write-Output "Warning: 7-Zip not found. Cannot unpack software"
    } else {
      Write-Output "Unpacking with 7-zip"
      & $ArchiveTool x "-o$NewSoftwareFolderFullName" $FileFullName | out-null
    Write-Output "Installation done for $SoftwareName"
    }   
    
    # If directory is nested, move contents one directory up
    $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
    if ($SubPath.count -eq 1) {
      $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
      $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
      if ($FolderIsNested) {
        Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName
        Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
      }  
    }

    Write-Output "Unzipped to: $NewSoftwareFolderFullName"

  }
}

function RemoveHashcat {
  Write-Output "###"
  $SoftwareName = "Hashcat"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallHashcatLauncher {
  # https://github.com/s77rt/hashcat.launcher
  Write-Output "###"
  $SoftwareName = "HashcatLauncher"
  Write-Output "Installing $SoftwareName..."

  $author="s77rt"
  $repo="hashcat.launcher"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*7z" -And $_ -Like "*windows*"})
  
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
  New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
  New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Copy to tools folder
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
    
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }

      # Create software directory in Tools folder
      $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
      if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
      } 
      New-Item -Path $NewSoftwareFolderFullName -ItemType Directory | Out-Null
      
      # To unpack package, this function depends on 7-Zip
      $ArchiveTool = [System.Environment]::GetFolderPath("ProgramFiles")+"\7-Zip\7z.exe"
      # Unzip password protected file
      if (-not (Test-Path $ArchiveTool)) {
          Write-Output "Warning: 7-Zip not found. Cannot unpack software"
      } else {
        Write-Output "Unpacking with 7-zip"
        & $ArchiveTool x "-o$NewSoftwareFolderFullName" $FileFullName | out-null
        Write-Output "Unzipped to: $NewSoftwareFolderFullName"
      }    
  }
}


function RemoveHashcatLauncher {
  Write-Output "###"
  $SoftwareName = "HashcatLauncher"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallWireshark{
  Write-Output "###"
  $SoftwareName = "Wireshark"
  Write-Output "Installing $SoftwareName..."

 
  $Url = "https://www.wireshark.org/download.html"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url).Links
  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_.href -Like "*64*" -and $_.href -Like "*exe*" -and $_.href -NotLike "*Portable*" }).href | Select-Object -First 1
  if (-not $FullDownloadURL) {
  Write-Output "Error: $SoftwareName not found"
  return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install exe
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    $CommandLineOptions = "/S"
    Start-Process $FileFullName $CommandLineOptions -NoNewWindow -Wait
    Write-Output "Installation done for $SoftwareName"
  }
}

function RemoveWireshark{
  Import-Module PackageManagement
  Write-Output "###"
  Write-Output "Removing Wireshark..."
  Uninstall-Package -InputObject ( Get-Package -Name "Wireshark*" )
}

function InstallAutopsy{
  Write-Output "###"

  $SoftwareName = "Autopsy"
  Write-Output "Installing $SoftwareName..."
  
  $author="sleuthkit"
  $repo="autopsy"
  $Url = "https://api.github.com/repos/$author/$repo/releases/latest"
  $ReleasePageLinks = (Invoke-WebRequest -UseBasicParsing -Uri $Url | ConvertFrom-Json).assets.browser_download_url

  $FullDownloadURL = ($ReleasePageLinks | Where-Object { $_ -Like "*64*" -and $_ -NotLike "*.asc"})
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Install msi
    Start-Process msiexec.exe -ArgumentList "/I ""$FileFullName"" /quiet" -Wait -NoNewWindow
    Write-Output "Installation done for $SoftwareName"
  }
}

function InstallZimmermanTools{
  Write-Output "###"

  $SoftwareName = "ZimmermanTools"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1"
  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  # Run ps1 file which will download the tools
  Invoke-Expression "$FileFullName -Dest $SoftwareFolderFullName"
  
  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get tools folder
    $ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
    if (-not $ToolsFolder) {
      # Set default tools folder
      $ToolsFolder = "\Tools"
    }
  
    # Create tools folder if not existing
    if (-not (Test-Path -Path $ToolsFolder)) {
      New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
    }
  
    # Copy to tools folder (overwrite existing)
    $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
    if (Test-Path -Path $NewSoftwareFolderFullName) {
      Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
    }
    Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
    Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"
  }
}

function RemoveZimmermanTools {
  Write-Output "###"
  $SoftwareName = "ZimmermanTools"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}

function InstallNetworkMiner{
  Write-Output "###"
  $SoftwareName = "NetworkMiner"
  Write-Output "Installing $SoftwareName..."

  $FullDownloadURL = "https://www.netresec.com/?download=NetworkMiner"

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = "$SoftwareName.zip"
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
	# Get tools folder
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  
	# Create tools folder if not existing
	if (-not (Test-Path -Path $ToolsFolder)) {
	  New-Item -Path $ToolsFolder -ItemType Directory | Out-Null
	}

	# Copy to tools folder (overwrite existing)
	$NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
	if (Test-Path -Path $NewSoftwareFolderFullName) {
	  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force
	}
	Copy-Item -Path $SoftwareFolderFullName -Recurse -Destination $ToolsFolder
	Write-Output "$SoftwareName copied to $NewSoftwareFolderFullName"

	# Unzip
	$NewFileFullName = Join-Path -Path $NewSoftwareFolderFullName -ChildPath $FileName
	Expand-Archive $NewFileFullName -DestinationPath $NewSoftwareFolderFullName
	Remove-Item -Path $NewFileFullName -ErrorAction Ignore
	Write-Output "Unzipped to: $NewSoftwareFolderFullName"
  }

  # If directory is nested, move contents one directory up
  $SubPath = Get-ChildItem $NewSoftwareFolderFullName -Name 
  if ($SubPath.count -eq 1) {
    $FullSubPath =Join-Path -Path $NewSoftwareFolderFullName -ChildPath $SubPath
    $FolderIsNested = (Get-ChildItem -Path "$NewSoftwareFolderFullName" -Directory).count -eq (Get-ChildItem -Path "$NewSoftwareFolderFullName" ).count
    if ($FolderIsNested) {
      Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $NewSoftwareFolderFullName
      Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
    }  
  }
}

function RemoveNetworkMiner {
  Write-Output "###"
  $SoftwareName = "NetworkMiner"
  Write-Output "Removing $SoftwareName..."
  
  # Get software folder name
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars

  # Get tools folder name
	$ToolsFolder = [Environment]::GetEnvironmentVariable("RIDEVAR-Customization-ToolsFolder", "Process")
	if (-not $ToolsFolder) {
	  # Set default tools folder
    $ToolsFolder = "\Tools"
  }
  $NewSoftwareFolderFullName = Join-Path -Path $ToolsFolder -ChildPath $SoftwareFolderName
  
  Remove-Item -Path $NewSoftwareFolderFullName -Recurse -Force -ErrorAction SilentlyContinue
}


################################################################
###### Customization  ###
################################################################

function InstallFonts{

  param ( [string] $FontPath = "$PSScriptRoot\components\fonts")

  Write-Output "###"
  Write-Output "Installing fonts..."
  # Inspired by https://www.powershellgallery.com/packages/PSWinGlue/0.3.3/Content/Functions%5CInstall-Font.ps1

  if (Test-Path -Path $FontPath) {
      $FontItem = Get-Item -Path $FontPath
      $Fonts = Get-ChildItem -Path $FontItem -Include ('*.fon','*.otf','*.ttc','*.ttf') -Recurse
  }

  $ShellAppFontNamespace = 0x14
  $ShellApp = New-Object -ComObject Shell.Application
  $FontsFolder = $ShellApp.NameSpace($ShellAppFontNamespace)
  foreach ($Font in $Fonts) {
      $TargetPath = Join-Path $FontsFolder $Font.Name
      if (Test-Path $TargetPath) {
        Remove-Item $TargetPath -Force
		    Copy-Item $FontFile.FullName $TargetPath -Force
        }
      else {
        Write-Verbose -Message ('Installing font: {0}' -f $Font.BaseName)
        $FontsFolder.CopyHere($Font.FullName)
      }
  }
}

function ReplaceDefaultWallpapers{

  param( [string] $WallpaperSourcePath = "$PSScriptRoot\components\wallpaper" )

  Write-Output "###"
  Write-Output "Replacing wallpapers..."

  if ( ! (Test-Path -Path "$WallpaperSourcePath" )) {
    Write-Output "ERROR: Wallpaper source directory not found at: $WallpaperSourcePath. Cannot continue."
    return
  }

  <#
  https://ccmexec.com/2015/08/replacing-default-wallpaper-in-windows-10-using-scriptmdtsccm/
  Default 4k images in C:\Windows\Web\4K\Wallpaper\Windows:
  768x1024  - img0_768x1024.jpg
  768x1366  - img0_768x1366.jpg
  1024x768  - img0_1024x768.jpg
  1200x1920 - img0_1200x1920.jpg
  1366x768  - img0_1366x768.jpg
  1600x2560 - img0_1600x2560.jpg
  2160x3840 - img0_2160x3840.jpg
  2560x1600 - img0_2560x1600.jpg
  3840x2160 - img0_3840x2160.jpg
  #>

  $WallpaperPath=($env:SystemDrive+"\Windows\Web\Wallpaper\Windows")
  $WallpaperPath4k=($env:SystemDrive+"\Windows\Web\4K\Wallpaper\Windows")
  
  $NumberOfWallpaperImgs = (Get-ChildItem $WallpaperSourcePath\* -Include ('*.png','*.jpg')| Measure-Object).Count
  $AdminUser = ${env:UserName}

  Start-Process takeown -ArgumentList "/R /A /F $WallpaperPath" -Wait -WindowStyle Hidden
  Start-Process takeown -ArgumentList "/R /A /F $WallpaperPath4k" -Wait -WindowStyle Hidden

  $AllArguments = $WallpaperPath+"\* /grant $AdminUser"+":(F) /Q"
  Start-Process icacls -ArgumentList $AllArguments -Wait -WindowStyle Hidden
  
  $AllArguments = $WallpaperPath4k+"\* /grant $AdminUser"+":(F) /Q"
  Start-Process icacls -ArgumentList $AllArguments -Wait -WindowStyle Hidden


  if ($NumberOfWallpaperImgs -eq 1) { # If there is only one image in wallpaper folder
    # Copy the single file found in wallpaper source path to new wallpaper file
    $SingleFileFoundName = (Get-ChildItem $WallpaperSourcePath\* -Include ('*.png','*.jpg')).FullName
    Copy-Item "$SingleFileFoundName" "$WallpaperPath4k" -Recurse -Force | Out-Null
    Copy-Item "$SingleFileFoundName" "$WallpaperPath" -Recurse -Force | Out-Null
  } else {  
    # If img0* files exist, copy images to wallpaper folder
    if (Test-Path -Path "$WallpaperSourcePath\img0*") {
      Remove-Item $WallpaperPath4k\*.* -Recurse -ErrorAction SilentlyContinue
      Copy-Item "$WallpaperSourcePath\img0*" $WallpaperPath4k -Recurse -Force | Out-Null
    }
  
    # default (light mode) wallpaper
    if (Test-Path -Path "$WallpaperSourcePath\img0.jpg") {
      Remove-Item $WallpaperPath\img0.jpg -Force -ErrorAction SilentlyContinue
      Copy-Item "$WallpaperSourcePath\img0.jpg" $WallpaperPath -Force
    }
  
    # dark mode wallpaper 
    if (Test-Path -Path "$WallpaperSourcePath\img19.jpg") {
      Remove-Item $WallpaperPath4k\img19.jpg -Force -ErrorAction SilentlyContinue
      Copy-Item "$WallpaperSourcePath\img19.jpg" $WallpaperPath4k -Force
    }
  
  }
}

function SetCustomLockScreen {  
 
  param( [string] $LockScreenSourcePath = "$PSScriptRoot\components\lockscreen" )

  Write-Output "###"
  Write-Output "Setting custom lock screen..."
  
  if ( ! (Test-Path -Path "$LockScreenSourcePath" )) {
    if ((Test-Path -Path "$PSScriptRoot\components\wallpaper" )) {
      Write-Output "Expected lockscreen source directory not found at: $LockScreenSourcePath, using wallpaper path"
    }
    else {
    Write-Output "ERROR: Lockscreen source directory not found at: $LockScreenSourcePath. Cannot continue."}
    return
  }

  $LockScreenPath = ($env:SystemDrive+"\Windows\Web\Screen")
  $LockScreenImageName = "img0.jpg"
  $LockScreenImageFullName = Join-Path -Path $LockScreenPath -ChildPath $LockScreenImageName
  $NumberOfLockScreenImgs = (Get-ChildItem $LockScreenSourcePath\* -Include ('*.png','*.jpg')| Measure-Object).Count

  # Cleanup if this function was run before - check for img0.jpg which is not standard
  if (Test-Path -Path "$LockScreenImageFullName") {
    Write-Output "Cleaning up old custom lockscreen file."
    Remove-Item $LockScreenImageFullName -Recurse -Force -ErrorAction SilentlyContinue
  }

  if ($NumberOfLockScreenImgs -eq 1) { # If there is only one image in lockscreen folder
    # Copy the single file found in lockscreen source path to new lockscreen file
    $SingleFileFoundName = (Get-ChildItem $LockScreenSourcePath\* -Include ('*.png','*.jpg')).FullName
    Copy-Item "$SingleFileFoundName" "$LockScreenImageFullName" -Recurse -Force | Out-Null
  } elseif (Test-Path -Path "$LockScreenSourcePath\$LockScreenImage") { # If lockscreen\img0.jpg exist
    # Copy default lock screen image to lock screen
    Copy-Item "$LockScreenSourcePath\$LockScreenImage" $LockScreenImageFullName -Recurse -Force | Out-Null
  } elseif (Test-Path -Path "$PSScriptRoot\components\wallpaper\$LockScreenImageName") { # If a wallpaper exists, use this
    # Copy default wallpaper to lock screen
    Copy-Item "$PSScriptRoot\components\wallpaper\$LockScreenImageName" $LockScreenImageFullName -Force | Out-Null
  }

  # Get windows version and handle registry settings different whether it's pro or enterprise
  $WindowsEdition=(Get-WindowsEdition -Online).Edition

  if ($WindowsEdition -eq 'Enterprise') {
    # https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ControlPanelDisplay::CPL_Personalization_ForceDefaultLockScreen
    # This only applies to Enterprise, Education, and Server SKUs

    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenImage" -Type String -Value "$LockScreenImageFullName"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -Type DWORD -Value 1

  } elseif ($WindowsEdition -eq 'Professional') {

    # Only if it's a Windows Pro
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP")) {
      New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImagePath" -Type String -Value "$LockScreenImageFullName"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImageUrl" -Type String -Value "$LockScreenImageFullName"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImageStatus" -Type DWORD -Value 1

    $SystemDataPath = "C:\ProgramData\Microsoft\Windows\SystemData"
    
    Start-Process takeown -ArgumentList "/R /A /F /D ""Y"" $SystemDataPath" -Wait -WindowStyle Hidden
    $AllArguments = "$SystemDataPath+  /reset /t /c /l"
    Start-Process icacls -ArgumentList $AllArguments -Wait -WindowStyle Hidden
    
  }
}

function SetDefaultLockScreen {  
  Write-Output "###"
  Write-Output "Setting default lock screen..."
  
  $LockScreenPath = ($env:SystemDrive+"\Windows\Web\Screen")
  $LockScreenImageName = "img0.jpg"
  $LockScreenImageFullName = Join-Path -Path $LockScreenPath -ChildPath $LockScreenImageName

  if (Test-Path -Path "$LockScreenImageFullName") {
    Remove-Item $LockScreenImageFullName -Recurse -Force -ErrorAction SilentlyContinue
  }

  $WindowsEdition=(Get-WindowsEdition -Online).Edition

  if ($WindowsEdition -eq 'Enterprise') {
    # https://admx.help/?Category=Windows_11_2022&Policy=Microsoft.Policies.ControlPanelDisplay::CPL_Personalization_ForceDefaultLockScreen
    # This only applies to Enterprise, Education, and Server SKUs

    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenImage" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlaysDisabled" -Force -ErrorAction SilentlyContinue

  } elseif ($WindowsEdition -eq 'Professional') {

    # Only if it's a Windows Pro

    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImagePath" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImageUrl" -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImageStatus" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Force -ErrorAction SilentlyContinue | Out-Null
    
  }
  Write-Output "Default lock screen restored."
}

# Installation of Lenovo Commercial Vantage software package. 
# Missing a method for dynamically identifying latest version.
function InstallLenovoVantage{

  Write-Output "###"
  $SoftwareName = "LenovoVantage"
  Write-Output "Installing $SoftwareName..."
  
  # Temp fix to missing dynamic version identification:
  $SubUrl="https://support.lenovo.com"
  $Url = "$SubUrl/gb/en/solutions/hf003321"
  $HTML = Invoke-RestMethod -UseBasicParsing -Uri $Url
  $HTML -match '/gb/en/api/v4/contents(.*)js' | Out-Null
  $ScriptFile = $matches[0]

  if (-not $ScriptFile) {
    Write-Output "Error: $SoftwareName not found"
    return
  }
  
  $ScriptContent=Invoke-RestMethod -UseBasicParsing -Uri $SubUrl$ScriptFile
  $ScriptContent -match 'href=\\"(?<url>.*zip)\\"' | Out-Null
  $FullDownloadURL=$matches.url

  if (-not $FullDownloadURL) {
	Write-Output "Error: $SoftwareName not found"
	return
  }

  # Create bootstrap folder if not existing
  $DefaultDownloadDir = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")."{374DE290-123F-4565-9164-39C4925E467B}"
  $BootstrapFolder = Join-Path -Path $DefaultDownloadDir -ChildPath "bootstrap"
  if (-not (Test-Path -Path $BootstrapFolder)) {
	New-Item -Path $BootstrapFolder -ItemType Directory | Out-Null
  }

  # Create software folder
  $InvalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
  $RegexInvalidChars = "[{0}]" -f [RegEx]::Escape($InvalidChars)
  $SoftwareFolderName = $SoftwareName -replace $RegexInvalidChars
  $SoftwareFolderFullName = Join-Path -Path $BootstrapFolder -ChildPath $SoftwareFolderName
  if (-not (Test-Path -Path $SoftwareFolderFullName)) {
	New-Item -Path $SoftwareFolderFullName -ItemType Directory | Out-Null
  }

  # Download
  Write-Output "Downloading file from: $FullDownloadURL"
  $FileName = ([System.IO.Path]::GetFileName($FullDownloadURL).Replace("%20"," "))
  $FileFullName = Join-Path -Path $SoftwareFolderFullName -ChildPath $FileName
  Start-BitsTransfer -Source $FullDownloadURL -Destination $FileFullName
  Write-Output "Downloaded: $FileFullName"

  try {
    Expand-Archive $FileFullName -DestinationPath $SoftwareFolderFullName 
	  Remove-Item -Path $FileFullName -ErrorAction Ignore
    Write-Output "Unzipped to: $SoftwareFolderFullName"
  }
  catch {
    Write-Output "Expansion of archive failed: $FileFullName"
  }

  if (-not [Environment]::GetEnvironmentVariable("RIDEVAR-Download-Only", "Process")) {
    # Get the computermodel - look for ThinkPad
    $ComputerModel=Get-CimInstance -ClassName Win32_ComputerSystemProduct | Where-Object { $_.Version -like 'ThinkPad*' } 

    # Install Lenovo Companion if it's a ThinkPad
    if ( $null -ne $ComputerModel ) { 

        # Write-Output "Installing $SoftwareName..."

        $InstallFile = "setup-commercial-vantage.bat"
        $InstallFileFullName = (Get-ChildItem $InstallFile -recurse | Select-Object -First 1).fullname
        $CommandLineOptions = " "

        Start-Process $InstallFileFullName -Argumentlist $CommandLineOptions -NoNewWindow -Wait
        Write-Output "Installation done for $SoftwareName"
    } else {
        Write-Output "Computer could not be identified as a ThinkPad. You must install $SoftwareName manually"
    }
  }
}

function RemoveLenovoVantage{
  Write-Output "###"
  Write-Output "Removing LenovoVantage..."
  Get-AppxPackage 'E046963F.LenovoSettingsforEnterprise' | Remove-AppxPackage
}


################################################################
###### Auxiliary Functions  ###
################################################################

function SetHostname{
  Write-Output "###"
  Write-Output "Changing hostname..."
  $hostname = Read-Host "Enter new Hostname [$env:computername]"
  if ($null -ne $hostname -and $hostname -ne "") {
      Rename-Computer -NewName "$hostname"  #-LocalCredential $env:computername\$env:username #-Restart
  }
}

# Wait for keypress
Function WaitForKey {
  Write-Output "###"
	Write-Output "`nPress any key to continue..."
	[Console]::ReadKey($true) | Out-Null
}

# Restart computer
Function Restart {
  Write-Output "###"
	Write-Output "Restarting..."
	Restart-Computer
}

##########
# Functions from this point forward is from the original Disassembler repo <disassembler@dasm.cz>
# These functions will merge together over time
##########

##########
#region Privacy Tweaks
##########

# Disable Telemetry
# Note: This tweak also disables the possibility to join Windows Insider Program and breaks Microsoft Intune enrollment/deployment, as these feaures require Telemetry data.
# Windows Update control panel may show message "Your device is at risk because it's out of date and missing important security and quality updates. Let's get you back on track so Windows can run more securely. Select this button to get going".
# In such case, enable telemetry, run Windows update and then disable telemetry again.
# See also https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/57 and https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/92
Function DisableTelemetry {
  Write-Output "###"
	Write-Output "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction SilentlyContinue | Out-Null
	# Office 2016 / 2019
	Disable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null
}

# Enable Telemetry
Function EnableTelemetry {
  Write-Output "###"
	Write-Output "Enabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	# Office 2016 / 2019
	Enable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null
}

# Disable Cortana
Function DisableCortana {
  Write-Output "###"
	Write-Output "Disabling Cortana..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0
	Get-AppxPackage "Microsoft.549981C3F5F10" | Remove-AppxPackage
}

# Enable Cortana
Function EnableCortana {
  Write-Output "###"
	Write-Output "Enabling Cortana..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -ErrorAction SilentlyContinue
	Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}

# Disable Wi-Fi Sense
Function DisableWiFiSense {
  Write-Output "###"
	Write-Output "Disabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0
}

# Enable Wi-Fi Sense
Function EnableWiFiSense {
  Write-Output "###"
	Write-Output "Enabling Wi-Fi Sense..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -ErrorAction SilentlyContinue
}

# Disable SmartScreen Filter
Function DisableSmartScreen {
  Write-Output "###"
	Write-Output "Disabling SmartScreen Filter..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}

# Enable SmartScreen Filter
Function EnableSmartScreen {
  Write-Output "###"
	Write-Output "Enabling SmartScreen Filter..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
}

# Disable Web Search in Start Menu
Function DisableWebSearch {
  Write-Output "###"
	Write-Output "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}

# Enable Web Search in Start Menu
Function EnableWebSearch {
  Write-Output "###"
	Write-Output "Enabling Bing Search in Start Menu..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
}

# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
  Write-Output "###"
	Write-Output "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0
	# Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}

# Enable Application suggestions and automatic installation
Function EnableAppSuggestions {
  Write-Output "###"
	Write-Output "Enabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -ErrorAction SilentlyContinue
}

# Disable Activity History feed in Task View
# Note: The checkbox "Store my activity history on this device" ("Let Windows collect my activities from this PC" on older versions) remains checked even when the function is disabled
Function DisableActivityHistory {
  Write-Output "###"
	Write-Output "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
}

# Enable Activity History feed in Task View
Function EnableActivityHistory {
  Write-Output "###"
	Write-Output "Enabling Activity History..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue
}

# Disable sensor features, such as screen auto rotation
Function DisableSensors {
  Write-Output "###"
	Write-Output "Disabling sensors..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
}

# Enable sensor features
Function EnableSensors {
  Write-Output "###"
	Write-Output "Enabling sensors..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -ErrorAction SilentlyContinue
}

# Disable location feature and scripting for the location feature
Function DisableLocation {
  Write-Output "###"
	Write-Output "Disabling location services..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
}

# Enable location feature and scripting for the location feature
Function EnableLocation {
  Write-Output "###"
	Write-Output "Enabling location services..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -ErrorAction SilentlyContinue
}

# Disable automatic Maps updates
Function DisableMapUpdates {
  Write-Output "###"
	Write-Output "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

# Enable automatic Maps updates
Function EnableMapUpdates {
  Write-Output "###"
	Write-Output "Enable automatic Maps updates..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue
}

# Disable Feedback
Function DisableFeedback {
  Write-Output "###"
	Write-Output "Disabling Feedback..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Enable Feedback
Function EnableFeedback {
  Write-Output "###"
	Write-Output "Enabling Feedback..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

# Disable Tailored Experiences
Function DisableTailoredExperiences {
  Write-Output "###"
	Write-Output "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
}

# Enable Tailored Experiences
Function EnableTailoredExperiences {
  Write-Output "###"
	Write-Output "Enabling Tailored Experiences..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue
}

# Disable Advertising ID
Function DisableAdvertisingID {
  Write-Output "###"
	Write-Output "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
}

# Enable Advertising ID
Function EnableAdvertisingID {
  Write-Output "###"
	Write-Output "Enabling Advertising ID..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue
}

# Disable setting 'Let websites provide locally relevant content by accessing my language list'
Function DisableWebLangList {
  Write-Output "###"
	Write-Output "Disabling Website Access to Language List..."
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1
}

# Enable setting 'Let websites provide locally relevant content by accessing my language list'
Function EnableWebLangList {
  Write-Output "###"
	Write-Output "Enabling Website Access to Language List..."
	Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -ErrorAction SilentlyContinue
}

# Disable biometric features
# Note: If you log on using biometrics (fingerprint, Windows Hello etc.) it's recommended to create a password recovery disk before applying this tweak.
Function DisableBiometrics {
  Write-Output "###"
	Write-Output "Disabling biometric services..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0
}

# Enable biometric features
Function EnableBiometrics {
  Write-Output "###"
	Write-Output "Enabling biometric services..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Disable access to camera
# Note: This disables access using standard Windows API. Direct access to device will still be allowed.
Function DisableCamera {
  Write-Output "###"
	Write-Output "Disabling access to camera..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Type DWord -Value 2
}

# Enable access to camera
Function EnableCamera {
  Write-Output "###"
	Write-Output "Enabling access to camera..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -ErrorAction SilentlyContinue
}

# Disable access to microphone
# Note: This disables access using standard Windows API. Direct access to device will still be allowed.
Function DisableMicrophone {
  Write-Output "###"
	Write-Output "Disabling access to microphone..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Type DWord -Value 2
}

# Enable access to microphone
Function EnableMicrophone {
  Write-Output "###"
	Write-Output "Enabling access to microphone..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -ErrorAction SilentlyContinue
}

# Disable Error reporting
Function DisableErrorReporting {
  Write-Output "###"
	Write-Output "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Enable Error reporting
Function EnableErrorReporting {
  Write-Output "###"
	Write-Output "Enabling Error reporting..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

# Restrict Windows Update P2P delivery optimization to computers in local network - Default since 1703
Function SetP2PUpdateLocal {
  Write-Output "###"
	Write-Output "Restricting Windows Update P2P optimization to local network..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
	} ElseIf ([System.Environment]::OSVersion.Version.Build -le 14393) {
		# Method used in 1511 and 1607
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 1
	} Else {
		# Method used since 1703
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
	}
}

# Unrestrict Windows Update P2P delivery optimization to both local networks and internet - Default in 1507 - 1607
Function SetP2PUpdateInternet {
  Write-Output "###"
	Write-Output "Unrestricting Windows Update P2P optimization to internet..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 3
	} ElseIf ([System.Environment]::OSVersion.Version.Build -le 14393) {
		# Method used in 1511 and 1607
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue
	} Else {
		# Method used since 1703
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 3
	}
}

# Disable Windows Update P2P delivery optimization completely
# Warning: Completely disabling delivery optimization can break Windows Store downloads - see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/281
Function SetP2PUpdateDisable {
  Write-Output "###"
	Write-Output "Disabling Windows Update P2P optimization..."
	If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
		# Method used in 1507
		If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
			New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
	} Else {
		# Method used since 1511
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 100
	}
}

# Stop and disable Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
Function DisableDiagTrack {
  Write-Output "###"
	Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}

# Enable and start Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
Function EnableDiagTrack {
  Write-Output "###"
	Write-Output "Enabling and starting Connected User Experiences and Telemetry Service ..."
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack" -WarningAction SilentlyContinue
}

# Stop and disable Device Management Wireless Application Protocol (WAP) Push Service
# Note: This service is needed for Microsoft Intune interoperability
Function DisableWAPPush {
  Write-Output "###"
	Write-Output "Stopping and disabling Device Management WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}

# Enable and start Device Management Wireless Application Protocol (WAP) Push Service
Function EnableWAPPush {
  Write-Output "###"
	Write-Output "Enabling and starting Device Management WAP Push Service..."
	Set-Service "dmwappushservice" -StartupType Automatic
	Start-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1
}

# Enable clearing of recent files on exit
# Empties most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications during every logout.
Function EnableClearRecentFiles {
  Write-Output "###"
	Write-Output "Enabling clearing of recent files on exit..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1
}

# Disable clearing of recent files on exit
Function DisableClearRecentFiles {
  Write-Output "###"
	Write-Output "Disabling clearing of recent files on exit..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -ErrorAction SilentlyContinue
}

# Disable recent files lists
# Stops creating most recently used (MRU) items lists such as 'Recent Items' menu on the Start menu, jump lists, and shortcuts at the bottom of the 'File' menu in applications.
Function DisableRecentFiles {
  Write-Output "###"
	Write-Output "Disabling recent files lists..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1
}

# Enable recent files lists
Function EnableRecentFiles {
  Write-Output "###"
	Write-Output "Enabling recent files lists..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -ErrorAction SilentlyContinue
}

##########
#endregion Privacy Tweaks
##########



##########
#region UWP Privacy Tweaks
##########
# Universal Windows Platform (UWP) is an API for common application and device controls unified for all devices capable of running Windows 10.
# UWP applications are running sandboxed and the user can control devices and capabilities available to them.

# Disable UWP apps background access - ie. if UWP apps can download data or update themselves when they aren't used
# Until 1809, Cortana and ShellExperienceHost need to be explicitly excluded as their inclusion breaks start menu search and toast notifications respectively.
Function DisableUWPBackgroundApps {
  Write-Output "###"
	Write-Output "Disabling UWP apps background access..."
	If ([System.Environment]::OSVersion.Version.Build -ge 17763) {
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
	} Else {
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*", "Microsoft.Windows.ShellExperienceHost*" | ForEach-Object {
			Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
			Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
		}
	}
}

# Enable UWP apps background access
Function EnableUWPBackgroundApps {
  Write-Output "###"
	Write-Output "Enabling UWP apps background access..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -ErrorAction SilentlyContinue
	Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
		Remove-ItemProperty -Path $_.PsPath -Name "Disabled" -ErrorAction SilentlyContinue
		Remove-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -ErrorAction SilentlyContinue
	}
}

# Disable access to voice activation from UWP apps
Function DisableUWPVoiceActivation {
  Write-Output "###"
	Write-Output "Disabling access to voice activation from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2
}

# Enable access to voice activation from UWP apps
Function EnableUWPVoiceActivation {
  Write-Output "###"
	Write-Output "Enabling access to voice activation from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -ErrorAction SilentlyContinue
}

# Disable access to notifications from UWP apps
Function DisableUWPNotifications {
  Write-Output "###"
	Write-Output "Disabling access to notifications from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2
}

# Enable access to notifications from UWP apps
Function EnableUWPNotifications {
  Write-Output "###"
	Write-Output "Enabling access to notifications from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -ErrorAction SilentlyContinue
}

# Disable access to account info from UWP apps
Function DisableUWPAccountInfo {
  Write-Output "###"
	Write-Output "Disabling access to account info from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2
}

# Enable access to account info from UWP apps
Function EnableUWPAccountInfo {
  Write-Output "###"
	Write-Output "Enabling access to account info from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -ErrorAction SilentlyContinue
}

# Disable access to contacts from UWP apps
Function DisableUWPContacts {
  Write-Output "###"
	Write-Output "Disabling access to contacts from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2
}

# Enable access to contacts from UWP apps
Function EnableUWPContacts {
  Write-Output "###"
	Write-Output "Enabling access to contacts from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -ErrorAction SilentlyContinue
}

# Disable access to calendar from UWP apps
Function DisableUWPCalendar {
  Write-Output "###"
	Write-Output "Disabling access to calendar from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2
}

# Enable access to calendar from UWP apps
Function EnableUWPCalendar {
  Write-Output "###"
	Write-Output "Enabling access to calendar from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -ErrorAction SilentlyContinue
}

# Disable access to phone calls from UWP apps
Function DisableUWPPhoneCalls {
  Write-Output "###"
	Write-Output "Disabling access to phone calls from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2
}

# Enable access to phone calls from UWP apps
Function EnableUWPPhoneCalls {
  Write-Output "###"
	Write-Output "Enabling access to phone calls from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -ErrorAction SilentlyContinue
}

# Disable access to call history from UWP apps
Function DisableUWPCallHistory {
  Write-Output "###"
	Write-Output "Disabling access to call history from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2
}

# Enable access to call history from UWP apps
Function EnableUWPCallHistory {
  Write-Output "###"
	Write-Output "Enabling access to call history from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -ErrorAction SilentlyContinue
}

# Disable access to email from UWP apps
Function DisableUWPEmail {
  Write-Output "###"
	Write-Output "Disabling access to email from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2
}

# Enable access to email from UWP apps
Function EnableUWPEmail {
  Write-Output "###"
	Write-Output "Enabling access to email from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -ErrorAction SilentlyContinue
}

# Disable access to tasks from UWP apps
Function DisableUWPTasks {
  Write-Output "###"
	Write-Output "Disabling access to tasks from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2
}

# Enable access to tasks from UWP apps
Function EnableUWPTasks {
  Write-Output "###"
	Write-Output "Enabling access to tasks from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -ErrorAction SilentlyContinue
}

# Disable access to messaging (SMS, MMS) from UWP apps
Function DisableUWPMessaging {
  Write-Output "###"
	Write-Output "Disabling access to messaging from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2
}

# Enable access to messaging from UWP apps
Function EnableUWPMessaging {
  Write-Output "###"
	Write-Output "Enabling access to messaging from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -ErrorAction SilentlyContinue
}

# Disable access to radios (e.g. Bluetooth) from UWP apps
Function DisableUWPRadios {
  Write-Output "###"
	Write-Output "Disabling access to radios from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2
}

# Enable access to radios from UWP apps
Function EnableUWPRadios {
  Write-Output "###"
	Write-Output "Enabling access to radios from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -ErrorAction SilentlyContinue
}

# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
Function DisableUWPOtherDevices {
  Write-Output "###"
	Write-Output "Disabling access to other devices from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2
}

# Enable access to other devices from UWP apps
Function EnableUWPOtherDevices {
  Write-Output "###"
	Write-Output "Enabling access to other devices from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -ErrorAction SilentlyContinue
}

# Disable access to diagnostic information from UWP apps
Function DisableUWPDiagInfo {
  Write-Output "###"
	Write-Output "Disabling access to diagnostic information from UWP apps..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2
}

# Enable access to diagnostic information from UWP apps
Function EnableUWPDiagInfo {
  Write-Output "###"
	Write-Output "Enabling access to diagnostic information from UWP apps..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -ErrorAction SilentlyContinue
}

# Disable access to libraries and file system from UWP apps
Function DisableUWPFileSystem {
  Write-Output "###"
	Write-Output "Disabling access to libraries and file system from UWP apps..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny"
}

# Enable access to libraries and file system from UWP apps
Function EnableUWPFileSystem {
  Write-Output "###"
	Write-Output "Enabling access to libraries and file system from UWP apps..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Allow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Allow"
}

# Disable UWP apps swap file
# This disables creation and use of swapfile.sys and frees 256 MB of disk space. Swapfile.sys is used only by UWP apps. The tweak has no effect on the real swap in pagefile.sys.
Function DisableUWPSwapFile {
  Write-Output "###"
	Write-Output "Disabling UWP apps swap file..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0
}

# Enable UWP apps swap file
Function EnableUWPSwapFile {
  Write-Output "###"
	Write-Output "Enabling UWP apps swap file..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -ErrorAction SilentlyContinue
}

##########
#endregion UWP Privacy Tweaks
##########



##########
#region Security Tweaks
##########

# Lower UAC level (disabling it completely would break apps)
Function SetUACLow {
  Write-Output "###"
	Write-Output "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}

# Raise UAC level
Function SetUACHigh {
  Write-Output "###"
	Write-Output "Raising UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1
}

# Enable sharing mapped drives between users
Function EnableSharingMappedDrives {
  Write-Output "###"
	Write-Output "Enabling sharing mapped drives between users..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}

# Disable sharing mapped drives between users
Function DisableSharingMappedDrives {
  Write-Output "###"
	Write-Output "Disabling sharing mapped drives between users..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

# Disable implicit administrative shares
Function DisableAdminShares {
  Write-Output "###"
	Write-Output "Disabling implicit administrative shares..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
}

# Enable implicit administrative shares
Function EnableAdminShares {
  Write-Output "###"
	Write-Output "Enabling implicit administrative shares..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue
}

# Hide from computer browser service by not sending announcements to browsers on the domain. 
Function DisableBrowserSvcView {
  Write-Output "###"
	Write-Output "Hiding from computer browser service..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Hidden" -Type DWord -Value 1
}

# Show in computer browser service 
Function EnableBrowserServiceView {
  Write-Output "###"
	Write-Output "Enabling implicit administrative shares..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Hidden" -ErrorAction SilentlyContinue
}

# Disable Firewall
Function DisableFirewall {
  Write-Output "###"
	Write-Output "Disabling Firewall..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0
}

# Enable Firewall
Function EnableFirewall {
  Write-Output "###"
	Write-Output "Enabling Firewall..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
}

# Hide Windows Defender SysTray icon
Function HideDefenderTrayIcon {
  Write-Output "###"
	Write-Output "Hiding Windows Defender SysTray icon..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
}

# Show Windows Defender SysTray icon
Function ShowDefenderTrayIcon {
  Write-Output "###"
	Write-Output "Showing Windows Defender SysTray icon..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe"
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
	}
}

# Disable Windows Defender
Function DisableDefender {
  Write-Output "###"
	Write-Output "Disabling Windows Defender..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	}
}

# Enable Windows Defender
Function EnableDefender {
  Write-Output "###"
	Write-Output "Enabling Windows Defender..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`""
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe"
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe"
	}
}

# Disable Windows Defender Cloud
Function DisableDefenderCloud {
  Write-Output "###"
	Write-Output "Disabling Windows Defender Cloud..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}

# Enable Windows Defender Cloud
Function EnableDefenderCloud {
  Write-Output "###"
	Write-Output "Enabling Windows Defender Cloud..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue
}

# Enable Controlled Folder Access (Defender Exploit Guard feature) - Applicable since 1709, requires Windows Defender to be enabled
Function EnableCtrldFolderAccess {
  Write-Output "###"
	Write-Output "Enabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
}

# Disable Controlled Folder Access (Defender Exploit Guard feature) - Applicable since 1709, requires Windows Defender to be enabled
Function DisableCtrldFolderAccess {
  Write-Output "###"
	Write-Output "Disabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
}

# Enable Core Isolation Memory Integrity - Part of Windows Defender System Guard virtualization-based security - Applicable since 1803
# Warning: This may cause old applications and drivers to crash or even cause BSOD
# Problems were confirmed with old video drivers (Intel HD Graphics for 2nd gen., Radeon HD 6850), and old antivirus software (Kaspersky Endpoint Security 10.2, 11.2)
Function EnableCIMemoryIntegrity {
  Write-Output "###"
	Write-Output "Enabling Core Isolation Memory Integrity..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
		New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
}

# Disable Core Isolation Memory Integrity - Applicable since 1803
Function DisableCIMemoryIntegrity {
  Write-Output "###"
	Write-Output "Disabling Core Isolation Memory Integrity..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Enable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
# Not supported on VMs and VDI environment. Check requirements on https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-guard/reqs-wd-app-guard
Function EnableDefenderAppGuard {
  Write-Output "###"
	Write-Output "Enabling Windows Defender Application Guard..."
	Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Disable Windows Defender Application Guard - Applicable since 1709 Enterprise and 1803 Pro. Not applicable to Server
Function DisableDefenderAppGuard {
  Write-Output "###"
	Write-Output "Disabling Windows Defender Application Guard..."
	Disable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Hide Account Protection warning in Defender about not using a Microsoft account
Function HideAccountProtectionWarn {
  Write-Output "###"
	Write-Output "Hiding Account Protection warning..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force | Out-Null
	}
	Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1
}

# Show Account Protection warning in Defender
Function ShowAccountProtectionWarn {
  Write-Output "###"
	Write-Output "Showing Account Protection warning..."
	Remove-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue
}

# Disable blocking of downloaded files (i.e. storing zone information - no need to do File\Properties\Unblock)
Function DisableDownloadBlocking {
  Write-Output "###"
	Write-Output "Disabling blocking of downloaded files..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1
}

# Enable blocking of downloaded files
Function EnableDownloadBlocking {
  Write-Output "###"
	Write-Output "Enabling blocking of downloaded files..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue
}

# Disable Windows Script Host (execution of *.vbs scripts and alike)
Function DisableScriptHost {
  Write-Output "###"
	Write-Output "Disabling Windows Script Host..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0
}

# Enable Windows Script Host
Function EnableScriptHost {
  Write-Output "###"
	Write-Output "Enabling Windows Script Host..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
}

# Enable strong cryptography for old versions of .NET Framework (4.6 and newer have strong crypto enabled by default)
# https://docs.microsoft.com/en-us/dotnet/framework/network-programming/tls#schusestrongcrypto
Function EnableDotNetStrongCrypto {
  Write-Output "###"
	Write-output "Enabling .NET strong cryptography..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
}

# Disable strong cryptography for old versions of .NET Framework
Function DisableDotNetStrongCrypto {
  Write-Output "###"
	Write-output "Disabling .NET strong cryptography..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
}

# Enable Meltdown (CVE-2017-5754) compatibility flag - Required for January and February 2018 Windows updates
# This flag is normally automatically enabled by compatible antivirus software (such as Windows Defender).
# Use the tweak only if you have confirmed that your AV is compatible but unable to set the flag automatically or if you don't use any AV at all.
# As of March 2018, the compatibility check has been lifted for security updates.
# See https://support.microsoft.com/en-us/help/4072699/windows-security-updates-and-antivirus-software for details
Function EnableMeltdownCompatFlag {
  Write-Output "###"
	Write-Output "Enabling Meltdown (CVE-2017-5754) compatibility flag..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

# Disable Meltdown (CVE-2017-5754) compatibility flag
Function DisableMeltdownCompatFlag {
  Write-Output "###"
	Write-Output "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue
}

# Enable F8 boot menu options
Function EnableF8BootMenu {
  Write-Output "###"
	Write-Output "Enabling F8 boot menu options..."
	bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
}

# Disable F8 boot menu options
Function DisableF8BootMenu {
  Write-Output "###"
	Write-Output "Disabling F8 boot menu options..."
	bcdedit /set `{current`} BootMenuPolicy Standard | Out-Null
}

# Disable automatic recovery mode during boot
# This causes boot process to always ignore startup errors and attempt to boot normally
# It is still possible to interrupt the boot and enter recovery mode manually. In order to disable even that, apply also DisableRecoveryAndReset tweak
Function DisableBootRecovery {
  Write-Output "###"
	Write-Output "Disabling automatic recovery mode during boot..."
	bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
}

# Enable automatic entering recovery mode during boot
# This allows the boot process to automatically enter recovery mode when it detects startup errors (default behavior)
Function EnableBootRecovery {
  Write-Output "###"
	Write-Output "Enabling automatic recovery mode during boot..."
	bcdedit /deletevalue `{current`} BootStatusPolicy | Out-Null
}

# Disable System Recovery and Factory reset
# Warning: This tweak completely removes the option to enter the system recovery during boot and the possibility to perform a factory reset
Function DisableRecoveryAndReset {
  Write-Output "###"
	Write-Output "Disabling System Recovery and Factory reset..."
	reagentc /disable 2>&1 | Out-Null
}

# Enable System Recovery and Factory reset
Function EnableRecoveryAndReset {
  Write-Output "###"
	Write-Output "Enabling System Recovery and Factory reset..."
	reagentc /enable 2>&1 | Out-Null
}

# Set Data Execution Prevention (DEP) policy to OptOut - Turn on DEP for all 32-bit applications except manually excluded. 64-bit applications have DEP always on.
Function SetDEPOptOut {
  Write-Output "###"
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptOut..."
	bcdedit /set `{current`} nx OptOut | Out-Null
}

# Set Data Execution Prevention (DEP) policy to OptIn - Turn on DEP only for essential 32-bit Windows executables and manually included applications. 64-bit applications have DEP always on.
Function SetDEPOptIn {
  Write-Output "###"
	Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
	bcdedit /set `{current`} nx OptIn | Out-Null
}

##########
#endregion Security Tweaks
##########



##########
#region Network Tweaks
##########

# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate {
  Write-Output "###"
	Write-Output "Setting current network profile to private..."
	Set-NetConnectionProfile -NetworkCategory Private
}

# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic {
  Write-Output "###"
	Write-Output "Setting current network profile to public..."
	Set-NetConnectionProfile -NetworkCategory Public
}

# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate {
  Write-Output "###"
	Write-Output "Setting unknown networks profile to private..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1
}

# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic {
  Write-Output "###"
	Write-Output "Setting unknown networks profile to public..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue
}

# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst {
  Write-Output "###"
	Write-Output "Disabling automatic installation of network devices..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}

# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst {
  Write-Output "###"
	Write-Output "Enabling automatic installation of network devices..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue
}

# Stop and disable Home Groups services - Not applicable since 1803. Not applicable to Server
Function DisableHomeGroups {
  Write-Output "###"
	Write-Output "Stopping and disabling Home Groups services..."
	If (Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue) {
		Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
		Set-Service "HomeGroupListener" -StartupType Disabled
	}
	If (Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue) {
		Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
		Set-Service "HomeGroupProvider" -StartupType Disabled
	}
}

# Enable and start Home Groups services - Not applicable since 1803. Not applicable to Server
Function EnableHomeGroups {
  Write-Output "###"
	Write-Output "Starting and enabling Home Groups services..."
	Set-Service "HomeGroupListener" -StartupType Manual
	Set-Service "HomeGroupProvider" -StartupType Manual
	Start-Service "HomeGroupProvider" -WarningAction SilentlyContinue
}

# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1 {
  Write-Output "###"
	Write-Output "Disabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1 {
  Write-Output "###"
	Write-Output "Enabling SMB 1.0 protocol..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}

# Disable SMB Server - Completely disables file and printer sharing, but leaves the system able to connect to another SMB server as a client
# Note: Do not run this if you plan to use Docker and Shared Drives (as it uses SMB internally), see https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/216
Function DisableSMBServer {
  Write-Output "###"
	Write-Output "Disabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

# Enable SMB Server
Function EnableSMBServer {
  Write-Output "###"
	Write-Output "Enabling SMB Server..."
	Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}

# Disable NetBIOS over TCP/IP on all currently installed network interfaces
Function DisableNetBIOS {
  Write-Output "###"
	Write-Output "Disabling NetBIOS over TCP/IP..."
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2
}

# Enable NetBIOS over TCP/IP on all currently installed network interfaces
Function EnableNetBIOS {
  Write-Output "###"
	Write-Output "Enabling NetBIOS over TCP/IP..."
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 0
}

# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
Function DisableLLMNR {
  Write-Output "###"
	Write-Output "Disabling Link-Local Multicast Name Resolution (LLMNR)..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
}

# Enable Link-Local Multicast Name Resolution (LLMNR) protocol
Function EnableLLMNR {
  Write-Output "###"
	Write-Output "Enabling Link-Local Multicast Name Resolution (LLMNR)..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
}

# Disable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
Function DisableLLDP {
  Write-Output "###"
	Write-Output "Disabling Local-Link Discovery Protocol (LLDP)..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}

# Enable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
Function EnableLLDP {
  Write-Output "###"
	Write-Output "Enabling Local-Link Discovery Protocol (LLDP)..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}

# Disable Local-Link Topology Discovery (LLTD) for all installed network interfaces
Function DisableLLTD {
  Write-Output "###"
	Write-Output "Disabling Local-Link Topology Discovery (LLTD)..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}

# Enable Local-Link Topology Discovery (LLTD) for all installed network interfaces
Function EnableLLTD {
  Write-Output "###"
	Write-Output "Enabling Local-Link Topology Discovery (LLTD)..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}

# Disable Client for Microsoft Networks for all installed network interfaces
Function DisableMSNetClient {
  Write-Output "###"
	Write-Output "Disabling Client for Microsoft Networks..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}

# Enable Client for Microsoft Networks for all installed network interfaces
Function EnableMSNetClient {
  Write-Output "###"
	Write-Output "Enabling Client for Microsoft Networks..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}

# Disable Quality of Service (QoS) packet scheduler for all installed network interfaces
Function DisableQoS {
  Write-Output "###"
	Write-Output "Disabling Quality of Service (QoS) packet scheduler..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}

# Enable Quality of Service (QoS) packet scheduler for all installed network interfaces
Function EnableQoS {
  Write-Output "###"
	Write-Output "Enabling Quality of Service (QoS) packet scheduler..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}

# Disable IPv4 stack for all installed network interfaces
Function DisableIPv4 {
  Write-Output "###"
	Write-Output "Disabling IPv4 stack..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}

# Enable IPv4 stack for all installed network interfaces
Function EnableIPv4 {
  Write-Output "###"
	Write-Output "Enabling IPv4 stack..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}

# Disable IPv6 stack for all installed network interfaces
Function DisableIPv6 {
  Write-Output "###"
	Write-Output "Disabling IPv6 stack..."
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}

# Enable IPv6 stack for all installed network interfaces
Function EnableIPv6 {
  Write-Output "###"
	Write-Output "Enabling IPv6 stack..."
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}

# Disable Network Connectivity Status Indicator active test
# Note: This may reduce the ability of OS and other components to determine internet access, however protects against a specific type of zero-click attack.
# See https://github.com/Disassembler0/Win10-Initial-Setup-Script/pull/111 for details
Function DisableNCSIProbe {
  Write-Output "###"
	Write-Output "Disabling Network Connectivity Status Indicator (NCSI) active test..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1
}

# Enable Network Connectivity Status Indicator active test
Function EnableNCSIProbe {
  Write-Output "###"
	Write-Output "Enabling Network Connectivity Status Indicator (NCSI) active test..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -ErrorAction SilentlyContinue
}

# Disable Internet Connection Sharing (e.g. mobile hotspot)
Function DisableConnectionSharing {
  Write-Output "###"
	Write-Output "Disabling Internet Connection Sharing..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0
}

# Enable Internet Connection Sharing (e.g. mobile hotspot)
Function EnableConnectionSharing {
  Write-Output "###"
	Write-Output "Enabling Internet Connection Sharing..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue
}

# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance {
  Write-Output "###"
	Write-Output "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online | Out-Null
}

# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance {
  Write-Output "###"
	Write-Output "Enabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Add-WindowsCapability -Online | Out-Null
}

# Enable Remote Desktop
Function EnableRemoteDesktop {
  Write-Output "###"
	Write-Output "Enabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0
	Enable-NetFirewallRule -Name "RemoteDesktop*"
}

# Disable Remote Desktop
Function DisableRemoteDesktop {
  Write-Output "###"
	Write-Output "Disabling Remote Desktop..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
	Disable-NetFirewallRule -Name "RemoteDesktop*"
}

##########
#endregion Network Tweaks
##########



##########
#region Service Tweaks
##########

# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT {
  Write-Output "###"
	Write-Output "Disabling Malicious Software Removal Tool offering..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1
}

# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT {
  Write-Output "###"
	Write-Output "Enabling Malicious Software Removal Tool offering..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

# Disable offering of drivers through Windows Update
# Note: This doesn't work properly if you use a driver intended for another hardware model. E.g. Intel I219-V on WinServer works only with I219-LM driver.
# Therefore Windows update will repeatedly try and fail to install I219-V driver indefinitely even if you use the tweak.
Function DisableUpdateDriver {
  Write-Output "###"
	Write-Output "Disabling driver offering through Windows Update..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
}

# Enable offering of drivers through Windows Update
Function EnableUpdateDriver {
  Write-Output "###"
	Write-Output "Enabling driver offering through Windows Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}

# Enable receiving updates for other Microsoft products via Windows Update
Function EnableUpdateMSProducts {
  Write-Output "###"
	Write-Output "Enabling updates for other Microsoft products..."
	(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null
}

# Disable receiving updates for other Microsoft products via Windows Update
Function DisableUpdateMSProducts {
  Write-Output "###"
	Write-Output "Disabling updates for other Microsoft products..."
	If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d"}) {
		(New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
	}
}

# Disable Windows Update automatic downloads
Function DisableUpdateAutoDownload {
  Write-Output "###"
	Write-Output "Disabling Windows Update automatic downloads..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
}

# Enable Windows Update automatic downloads
Function EnableUpdateAutoDownload {
  Write-Output "###"
	Write-Output "Enabling Windows Update automatic downloads..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
}

# Disable automatic restart after Windows Update installation
# The tweak is slightly experimental, as it registers a dummy debugger for MusNotification.exe
# which blocks the restart prompt executable from running, thus never scheduling the restart
Function DisableUpdateRestart {
  Write-Output "###"
	Write-Output "Disabling Windows Update automatic restart..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -Type String -Value "cmd.exe"
}

# Enable automatic restart after Windows Update installation
Function EnableUpdateRestart {
  Write-Output "###"
	Write-Output "Enabling Windows Update automatic restart..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" -Name "Debugger" -ErrorAction SilentlyContinue
}

# Disable nightly wake-up for Automatic Maintenance and Windows Updates
Function DisableMaintenanceWakeUp {
  Write-Output "###"
	Write-Output "Disabling nightly wake-up for Automatic Maintenance..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0
}

# Enable nightly wake-up for Automatic Maintenance and Windows Updates
Function EnableMaintenanceWakeUp {
  Write-Output "###"
	Write-Output "Enabling nightly wake-up for Automatic Maintenance..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -ErrorAction SilentlyContinue
}

# Disable Automatic Restart Sign-on - Applicable since 1903
# See https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/winlogon-automatic-restart-sign-on--arso-
Function DisableAutoRestartSignOn {
  Write-Output "###"
	Write-Output "Disabling Automatic Restart Sign-on..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Type DWord -Value 1
}

# Enable Automatic Restart Sign-on - Applicable since 1903
Function EnableAutoRestartSignOn {
  Write-Output "###"
	Write-Output "Enabling Automatic Restart Sign-on..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -ErrorAction SilentlyContinue
}

# Disable Shared Experiences - Applicable since 1703. Not applicable to Server
# This setting can be set also via GPO, however doing so causes reset of Start Menu cache. See https://github.com/Disassembler0/Win10-Initial-Setup-Script/issues/145 for details
Function DisableSharedExperiences {
  Write-Output "###"
	Write-Output "Disabling Shared Experiences..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0
}

# Enable Shared Experiences - Applicable since 1703. Not applicable to Server
Function EnableSharedExperiences {
  Write-Output "###"
	Write-Output "Enabling Shared Experiences..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 1
}

# Enable Clipboard History - Applicable since 1809. Not applicable to Server
Function EnableClipboardHistory {
  Write-Output "###"
	Write-Output "Enabling Clipboard History..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1
}

# Disable Clipboard History - Applicable since 1809. Not applicable to Server
Function DisableClipboardHistory {
  Write-Output "###"
	Write-Output "Disabling Clipboard History..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue
}

# Disable Autoplay
Function DisableAutoplay {
  Write-Output "###"
	Write-Output "Disabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
}

# Enable Autoplay
Function EnableAutoplay {
  Write-Output "###"
	Write-Output "Enabling Autoplay..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0
}

# Disable Autorun for all drives
Function DisableAutorun {
  Write-Output "###"
	Write-Output "Disabling Autorun for all drives..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255
}

# Enable Autorun for removable drives
Function EnableAutorun {
  Write-Output "###"
	Write-Output "Enabling Autorun for all drives..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
}

# Disable System Restore for system drive - Not applicable to Server
# Note: This does not delete already existing restore points as the deletion of restore points is irreversible. In order to do that, run also following command.
# vssadmin Delete Shadows /For=$env:SYSTEMDRIVE /Quiet
Function DisableRestorePoints {
  Write-Output "###"
	Write-Output "Disabling System Restore for system drive..."
	Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
}

# Enable System Restore for system drive - Not applicable to Server
# Note: Some systems (notably VMs) have maximum size allowed to be used for shadow copies set to zero. In order to increase the size, run following command.
# vssadmin Resize ShadowStorage /On=$env:SYSTEMDRIVE /For=$env:SYSTEMDRIVE /MaxSize=10GB
Function EnableRestorePoints {
  Write-Output "###"
	Write-Output "Enabling System Restore for system drive..."
	Enable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
}

# Enable Storage Sense - automatic disk cleanup - Applicable since 1703
Function EnableStorageSense {
  Write-Output "###"
	Write-Output "Enabling Storage Sense..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1
}

# Disable Storage Sense - Applicable since 1703
Function DisableStorageSense {
  Write-Output "###"
	Write-Output "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

# Disable scheduled defragmentation task
Function DisableDefragmentation {
  Write-Output "###"
	Write-Output "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Enable scheduled defragmentation task
Function EnableDefragmentation {
  Write-Output "###"
	Write-Output "Enabling scheduled defragmentation..."
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

# Stop and disable Superfetch service
Function DisableSuperfetch {
  Write-Output "###"
	Write-Output "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}

# Start and enable Superfetch service
Function EnableSuperfetch {
  Write-Output "###"
	Write-Output "Starting and enabling Superfetch service..."
	Set-Service "SysMain" -StartupType Automatic
	Start-Service "SysMain" -WarningAction SilentlyContinue
}

# Stop and disable Windows Search indexing service
Function DisableIndexing {
  Write-Output "###"
	Write-Output "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
}

# Start and enable Windows Search indexing service
Function EnableIndexing {
  Write-Output "###"
	Write-Output "Starting and enabling Windows Search indexing service..."
	Set-Service "WSearch" -StartupType Automatic
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1
	Start-Service "WSearch" -WarningAction SilentlyContinue
}

# Disable Recycle Bin - Files will be permanently deleted without placing into Recycle Bin
Function DisableRecycleBin {
  Write-Output "###"
	Write-Output "Disabling Recycle Bin..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecycleFiles" -Type DWord -Value 1
}

# Enable Recycle Bin
Function EnableRecycleBin {
  Write-Output "###"
	Write-Output "Enable Recycle Bin..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecycleFiles" -ErrorAction SilentlyContinue
}

# Enable NTFS paths with length over 260 characters
Function EnableNTFSLongPaths {
  Write-Output "###"
	Write-Output "Enabling NTFS paths with length over 260 characters..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1
}

# Disable NTFS paths with length over 260 characters
Function DisableNTFSLongPaths {
  Write-Output "###"
	Write-Output "Disabling NTFS paths with length over 260 characters..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 0
}

# Disable updating of NTFS last access timestamps
Function DisableNTFSLastAccess {
  Write-Output "###"
	Write-Output "Disabling updating of NTFS last access timestamps..."
	# User Managed, Last Access Updates Disabled
	fsutil behavior set DisableLastAccess 1 | Out-Null
}

# Enable updating of NTFS last access timestamps
Function EnableNTFSLastAccess {
  Write-Output "###"
	Write-Output "Enabling updating of NTFS last access timestamps..."
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		# System Managed, Last Access Updates Enabled
		fsutil behavior set DisableLastAccess 2 | Out-Null
	} Else {
		# Last Access Updates Enabled
		fsutil behavior set DisableLastAccess 0 | Out-Null
	}
}

# Set BIOS time to UTC
Function SetBIOSTimeUTC {
  Write-Output "###"
	Write-Output "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
}

# Set BIOS time to local time
Function SetBIOSTimeLocal {
  Write-Output "###"
	Write-Output "Setting BIOS time to Local time..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
}

# Enable Hibernation - Do not use on Server with automatically started Hyper-V hvboot service as it may lead to BSODs (Win10 with Hyper-V is fine)
Function EnableHibernation {
  Write-Output "###"
	Write-Output "Enabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 1
	powercfg /HIBERNATE ON 2>&1 | Out-Null
}

# Disable Hibernation
Function DisableHibernation {
  Write-Output "###"
	Write-Output "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
	powercfg /HIBERNATE OFF 2>&1 | Out-Null
}

# Disable Sleep start menu and keyboard button
Function DisableSleepButton {
  Write-Output "###"
	Write-Output "Disabling Sleep start menu and keyboard button..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
}

# Enable Sleep start menu and keyboard button
Function EnableSleepButton {
  Write-Output "###"
	Write-Output "Enabling Sleep start menu and keyboard button..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 1
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
}

# Disable display and sleep mode timeouts
Function DisableSleepTimeout {
  Write-Output "###"
	Write-Output "Disabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
}

# Enable display and sleep mode timeouts
Function EnableSleepTimeout {
  Write-Output "###"
	Write-Output "Enabling display and sleep mode timeouts..."
	powercfg /X monitor-timeout-ac 10
	powercfg /X monitor-timeout-dc 5
	powercfg /X standby-timeout-ac 30
	powercfg /X standby-timeout-dc 15
}

# Disable Fast Startup
Function DisableFastStartup {
  Write-Output "###"
	Write-Output "Disabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

# Enable Fast Startup
Function EnableFastStartup {
  Write-Output "###"
	Write-Output "Enabling Fast Startup..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}

# Disable automatic reboot on crash (BSOD)
Function DisableAutoRebootOnCrash {
  Write-Output "###"
	Write-Output "Disabling automatic reboot on crash (BSOD)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0
}

# Enable automatic reboot on crash (BSOD)
Function EnableAutoRebootOnCrash {
  Write-Output "###"
	Write-Output "Enabling automatic reboot on crash (BSOD)..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1
}

##########
#endregion Service Tweaks
##########



##########
#region UI Tweaks
##########

# Disable Action Center (Notification Center)
Function DisableActionCenter {
  Write-Output "###"
	Write-Output "Disabling Action Center (Notification Center)..."
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
}

# Enable Action Center (Notification Center)
Function EnableActionCenter {
  Write-Output "###"
	Write-Output "Enabling Action Center (Notification Center)..."
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue
}

# Disable Lock screen
Function DisableLockScreen {
  Write-Output "###"
	Write-Output "Disabling Lock screen..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
}

# Enable Lock screen
Function EnableLockScreen {
  Write-Output "###"
	Write-Output "Enabling Lock screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue
}

# Disable Lock screen - Anniversary Update workaround. The GPO used in DisableLockScreen has been broken in 1607 and fixed again in 1803
Function DisableLockScreenRS1 {
  Write-Output "###"
	Write-Output "Disabling Lock screen using scheduler workaround..."
	$service = New-Object -com Schedule.Service
	$service.Connect()
	$task = $service.NewTask(0)
	$task.Settings.DisallowStartIfOnBatteries = $false
	$trigger = $task.Triggers.Create(9)
	$trigger = $task.Triggers.Create(11)
	$trigger.StateChange = 8
	$action = $task.Actions.Create(0)
	$action.Path = "reg.exe"
	$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
	$service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
}

# Enable Lock screen - Anniversary Update workaround. The GPO used in DisableLockScreen has been broken in 1607 and fixed again in 1803
Function EnableLockScreenRS1 {
  Write-Output "###"
	Write-Output "Enabling Lock screen (removing scheduler workaround)..."
	Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
}

# Hide network options from Lock Screen
Function HideNetworkFromLockScreen {
  Write-Output "###"
	Write-Output "Hiding network options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1
}

# Show network options on lock screen
Function ShowNetworkOnLockScreen {
  Write-Output "###"
	Write-Output "Showing network options on Lock Screen..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
}

# Hide shutdown options from Lock Screen
Function HideShutdownFromLockScreen {
  Write-Output "###"
	Write-Output "Hiding shutdown options from Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
}

# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen {
  Write-Output "###"
	Write-Output "Showing shutdown options on Lock Screen..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1
}

# Disable Lock screen Blur - Applicable since 1903
Function DisableLockScreenBlur {
  Write-Output "###"
	Write-Output "Disabling Lock screen Blur..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value 1
}

# Enable Lock screen Blur - Applicable since 1903
Function EnableLockScreenBlur {
  Write-Output "###"
	Write-Output "Enabling Lock screen Blur..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -ErrorAction SilentlyContinue
}

# Disable Aero Shake (minimizing other windows when one is dragged by mouse and shaken)
Function DisableAeroShake {
  Write-Output "###"
	Write-Output "Disabling Aero Shake..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
}

# Enable Aero Shake
Function EnableAeroShake {
  Write-Output "###"
	Write-Output "Enabling Aero Shake..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -ErrorAction SilentlyContinue
}

# Disable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
Function DisableAccessibilityKeys {
  Write-Output "###"
	Write-Output "Disabling accessibility keys prompts..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122"
}

# Enable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
Function EnableAccessibilityKeys {
  Write-Output "###"
	Write-Output "Enabling accessibility keys prompts..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "62"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "126"
}

# Show Task Manager details - Applicable since 1607
# Although this functionality exist even in earlier versions, the Task Manager's behavior is different there and is not compatible with this tweak
Function ShowTaskManagerDetails {
  Write-Output "###"
	Write-Output "Showing task manager details..."
	$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
	$timeout = 30000
	$sleep = 100
	Do {
		Start-Sleep -Milliseconds $sleep
		$timeout -= $sleep
		$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	} Until ($preferences -or $timeout -le 0)
	Stop-Process $taskmgr
	If ($preferences) {
		$preferences.Preferences[28] = 0
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	}
}

# Hide Task Manager details - Applicable since 1607
Function HideTaskManagerDetails {
  Write-Output "###"
	Write-Output "Hiding task manager details..."
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	If ($preferences) {
		$preferences.Preferences[28] = 1
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	}
}

# Show file operations details
Function ShowFileOperationsDetails {
  Write-Output "###"
	Write-Output "Showing file operations details..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
}

# Hide file operations details
Function HideFileOperationsDetails {
  Write-Output "###"
	Write-Output "Hiding file operations details..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue
}

# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm {
  Write-Output "###"
	Write-Output "Enabling file delete confirmation dialog..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
}

# Disable file delete confirmation dialog
Function DisableFileDeleteConfirm {
  Write-Output "###"
	Write-Output "Disabling file delete confirmation dialog..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
}

# Hide Taskbar Search icon / box
Function HideTaskbarSearch {
  Write-Output "###"
	Write-Output "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
}

# Show Taskbar Search icon
Function ShowTaskbarSearchIcon {
  Write-Output "###"
	Write-Output "Showing Taskbar Search icon..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
}

# Show Taskbar Search box
Function ShowTaskbarSearchBox {
  Write-Output "###"
	Write-Output "Showing Taskbar Search box..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 2
}

# Hide Task View button
Function HideTaskView {
  Write-Output "###"
	Write-Output "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

# Show Task View button
Function ShowTaskView {
  Write-Output "###"
	Write-Output "Showing Task View button..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}

# Show small icons in taskbar
Function ShowSmallTaskbarIcons {
  Write-Output "###"
	Write-Output "Showing small icons in taskbar..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
}

# Show large icons in taskbar
Function ShowLargeTaskbarIcons {
  Write-Output "###"
	Write-Output "Showing large icons in taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue
}

# Set taskbar buttons to show labels and combine when taskbar is full
Function SetTaskbarCombineWhenFull {
  Write-Output "###"
	Write-Output "Setting taskbar buttons to combine when taskbar is full..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 1
}

# Set taskbar buttons to show labels and never combine
Function SetTaskbarCombineNever {
  Write-Output "###"
	Write-Output "Setting taskbar buttons to never combine..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 2
}

# Set taskbar buttons to always combine and hide labels
Function SetTaskbarCombineAlways {
  Write-Output "###"
	Write-Output "Setting taskbar buttons to always combine, hide labels..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -ErrorAction SilentlyContinue
}

# Hide Taskbar People icon
Function HideTaskbarPeopleIcon {
  Write-Output "###"
	Write-Output "Hiding People icon..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}

# Show Taskbar People icon
Function ShowTaskbarPeopleIcon {
  Write-Output "###"
	Write-Output "Showing People icon..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue
}

# Show all tray icons
Function ShowTrayIcons {
  Write-Output "###"
	Write-Output "Showing all tray icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -Type DWord -Value 1
}

# Hide tray icons as needed
Function HideTrayIcons {
  Write-Output "###"
	Write-Output "Hiding tray icons..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -ErrorAction SilentlyContinue
}

# Show seconds in taskbar
Function ShowSecondsInTaskbar {
  Write-Output "###"
	Write-Output "Showing seconds in taskbar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1
}

# Hide seconds from taskbar
Function HideSecondsFromTaskbar {
  Write-Output "###"
	Write-Output "Hiding seconds from taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -ErrorAction SilentlyContinue
}

# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore {
  Write-Output "###"
	Write-Output "Disabling search for app in store for unknown extensions..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore {
  Write-Output "###"
	Write-Output "Enabling search for app in store for unknown extensions..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
}

# Disable 'How do you want to open this file?' prompt
Function DisableNewAppPrompt {
  Write-Output "###"
	Write-Output "Disabling 'How do you want to open this file?' prompt..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}

# Enable 'How do you want to open this file?' prompt
Function EnableNewAppPrompt {
  Write-Output "###"
	Write-Output "Enabling 'How do you want to open this file?' prompt..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
}

# Hide 'Recently added' list from the Start Menu
Function HideRecentlyAddedApps {
  Write-Output "###"
	Write-Output "Hiding 'Recently added' list from the Start Menu..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
}

# Show 'Recently added' list in the Start Menu
Function ShowRecentlyAddedApps {
  Write-Output "###"
	Write-Output "Showing 'Recently added' list in the Start Menu..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction SilentlyContinue
}

# Hide 'Most used' apps list from the Start Menu - Applicable until 1703 (hidden by default since then)
Function HideMostUsedApps {
  Write-Output "###"
	Write-Output "Hiding 'Most used' apps list from the Start Menu..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Type DWord -Value 1
}

# Show 'Most used' apps list in the Start Menu - Applicable until 1703 (GPO broken since then)
Function ShowMostUsedApps {
  Write-Output "###"
	Write-Output "Showing 'Most used' apps list in the Start Menu..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -ErrorAction SilentlyContinue
}

# Set PowerShell instead of Command prompt in Start Button context menu (Win+X) - Default since 1703
Function SetWinXMenuPowerShell {
  Write-Output "###"
	Write-Output "Setting PowerShell instead of Command prompt in WinX menu..."
	If ([System.Environment]::OSVersion.Version.Build -le 14393) {
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Type DWord -Value 0
	} Else {
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -ErrorAction SilentlyContinue
	}
}

# Set Command prompt instead of PowerShell in Start Button context menu (Win+X) - Default in 1507 - 1607
Function SetWinXMenuCmd {
  Write-Output "###"
	Write-Output "Setting Command prompt instead of PowerShell in WinX menu..."
	If ([System.Environment]::OSVersion.Version.Build -le 14393) {
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -ErrorAction SilentlyContinue
	} Else {
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Type DWord -Value 1
	}
}

# Set Control Panel view to Small icons (Classic)
Function SetControlPanelSmallIcons {
  Write-Output "###"
	Write-Output "Setting Control Panel view to small icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
}

# Set Control Panel view to Large icons (Classic)
Function SetControlPanelLargeIcons {
  Write-Output "###"
	Write-Output "Setting Control Panel view to large icons..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0
}

# Set Control Panel view to categories
Function SetControlPanelCategories {
  Write-Output "###"
	Write-Output "Setting Control Panel view to categories..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue
}

# Disable adding '- shortcut' to shortcut name
Function DisableShortcutInName {
  Write-Output "###"
	Write-Output "Disabling adding '- shortcut' to shortcut name..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0))
}

# Enable adding '- shortcut' to shortcut name
Function EnableShortcutInName {
  Write-Output "###"
	Write-Output "Enabling adding '- shortcut' to shortcut name..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -ErrorAction SilentlyContinue
}

# Hide shortcut icon arrow
Function HideShortcutArrow {
  Write-Output "###"
	Write-Output "Hiding shortcut icon arrow..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value "%SystemRoot%\System32\imageres.dll,-1015"
}

# Show shortcut icon arrow
Function ShowShortcutArrow {
  Write-Output "###"
	Write-Output "Showing shortcut icon arrow..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -ErrorAction SilentlyContinue
}

# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
  Write-Output "###"
	Write-Output "Adjusting visual effects for performance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
}

# Adjusts visual effects for appearance
Function SetVisualFXAppearance {
  Write-Output "###"
	Write-Output "Adjusting visual effects for appearance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0))
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
}

# Enable window title bar color according to prevalent background color
Function EnableTitleBarColor {
  Write-Output "###"
	Write-Output "Enabling window title bar color..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 1
}

# Disable window title bar color
Function DisableTitleBarColor {
  Write-Output "###"
	Write-Output "Disabling window title bar color..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 0
}

# Set Dark Mode for Applications
Function SetAppsDarkMode {
  Write-Output "###"
	Write-Output "Setting Dark Mode for Applications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
}

# Set Light Mode for Applications
Function SetAppsLightMode {
  Write-Output "###"
	Write-Output "Setting Light Mode for Applications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1
}

# Set Light Mode for System - Applicable since 1903
Function SetSystemLightMode {
  Write-Output "###"
	Write-Output "Setting Light Mode for System..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1
}

# Set Dark Mode for System - Applicable since 1903
Function SetSystemDarkMode {
  Write-Output "###"
	Write-Output "Setting Dark Mode for System..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0
}

# Add secondary en-US keyboard
Function AddENKeyboard {
  Write-Output "###"
	Write-Output "Adding secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	$langs.Add("en-US")
	Set-WinUserLanguageList $langs -Force
}

# Remove secondary en-US keyboard
Function RemoveENKeyboard {
  Write-Output "###"
	Write-Output "Removing secondary en-US keyboard..."
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | Where-Object {$_.LanguageTag -ne "en-US"}) -Force
}

# Enable NumLock after startup
Function EnableNumlock {
  Write-Output "###"
	Write-Output "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

# Disable NumLock after startup
Function DisableNumlock {
  Write-Output "###"
	Write-Output "Disabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}

# Disable enhanced pointer precision
Function DisableEnhPointerPrecision {
  Write-Output "###"
	Write-Output "Disabling enhanced pointer precision..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0"
}

# Enable enhanced pointer precision
Function EnableEnhPointerPrecision {
  Write-Output "###"
	Write-Output "Enabling enhanced pointer precision..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "1"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "6"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "10"
}

# Set sound scheme to No Sounds
Function SetSoundSchemeNone {
  Write-Output "###"
	Write-Output "Setting sound scheme to No Sounds..."
	$SoundScheme = ".None"
	Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
		# If scheme keys do not exist in an event, create empty ones (similar behavior to Sound control panel).
		If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
			New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
		}
		If (!(Test-Path "$($_.PsPath)\.Current")) {
			New-Item -Path "$($_.PsPath)\.Current" | Out-Null
		}
		# Get a regular string from any possible kind of value, i.e. resolve REG_EXPAND_SZ, copy REG_SZ or empty from non-existing.
		$Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
		# Replace any kind of value with a regular string (similar behavior to Sound control panel).
		Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -Type String -Value $Data
		# Copy data from source scheme to current.
		Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -Type String -Value $Data
	}
	Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Type String -Value $SoundScheme
}

# Set sound scheme to Windows Default
Function SetSoundSchemeDefault {
  Write-Output "###"
	Write-Output "Setting sound scheme to Windows Default..."
	$SoundScheme = ".Default"
	Get-ChildItem -Path "HKCU:\AppEvents\Schemes\Apps\*\*" | ForEach-Object {
		# If scheme keys do not exist in an event, create empty ones (similar behavior to Sound control panel).
		If (!(Test-Path "$($_.PsPath)\$($SoundScheme)")) {
			New-Item -Path "$($_.PsPath)\$($SoundScheme)" | Out-Null
		}
		If (!(Test-Path "$($_.PsPath)\.Current")) {
			New-Item -Path "$($_.PsPath)\.Current" | Out-Null
		}
		# Get a regular string from any possible kind of value, i.e. resolve REG_EXPAND_SZ, copy REG_SZ or empty from non-existing.
		$Data = (Get-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -ErrorAction SilentlyContinue)."(Default)"
		# Replace any kind of value with a regular string (similar behavior to Sound control panel).
		Set-ItemProperty -Path "$($_.PsPath)\$($SoundScheme)" -Name "(Default)" -Type String -Value $Data
		# Copy data from source scheme to current.
		Set-ItemProperty -Path "$($_.PsPath)\.Current" -Name "(Default)" -Type String -Value $Data
	}
	Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Type String -Value $SoundScheme
}

# Disable playing Windows Startup sound
Function DisableStartupSound {
  Write-Output "###"
	Write-Output "Disabling Windows Startup sound..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 1
}

# Enable playing Windows Startup sound
Function EnableStartupSound {
  Write-Output "###"
	Write-Output "Enabling Windows Startup sound..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 0
}

# Disable changing sound scheme
Function DisableChangingSoundScheme {
  Write-Output "###"
	Write-Output "Disabling changing sound scheme..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -Type DWord -Value 1
}

# Enable changing sound scheme
Function EnableChangingSoundScheme {
  Write-Output "###"
	Write-Output "Enabling changing sound scheme..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoChangingSoundScheme" -ErrorAction SilentlyContinue
}

# Enable verbose startup/shutdown status messages
Function EnableVerboseStatus {
  Write-Output "###"
	Write-Output "Enabling verbose startup/shutdown status messages..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1
	} Else {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
	}
}

# Disable verbose startup/shutdown status messages
Function DisableVerboseStatus {
  Write-Output "###"
	Write-Output "Disabling verbose startup/shutdown status messages..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
	} Else {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 0
	}
}

# Disable F1 Help key in Explorer and on the Desktop
Function DisableF1HelpKey {
  Write-Output "###"
	Write-Output "Disabling F1 Help key..."
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type "String" -Value ""
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type "String" -Value ""
}

# Enable F1 Help key in Explorer and on the Desktop
Function EnableF1HelpKey {
  Write-Output "###"
	Write-Output "Enabling F1 Help key..."
	Remove-Item "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0" -Recurse -ErrorAction SilentlyContinue
}

# Remove multiple desktops button on taskbar
Function DisableTaskbarDesktops {
  Write-Output "###"
	Write-Output "Removing Multiple Desktops from taskbar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}

# Show multiple desktops button on taskbar
Function EnableTaskbarDesktops {
  Write-Output "###"
	Write-Output "Showing Multiple Desktops on taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
}

# Disable widgets on taskbar
Function DisableTaskbarWidgets {
  Write-Output "###"
	Write-Output "Removing widgets from taskbar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Type DWord -Value 0
}

# Show widgets on taskbar
Function EnableTaskbarWidgets {
  Write-Output "###"
	Write-Output "Showing widgets on taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -ErrorAction SilentlyContinue
}


# Hide Chat icon on taskbar
Function DisableTaskbarChat {
  Write-Output "###"
	Write-Output "Removing chat icon in taskbar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Type DWord -Value 0
}

# Show chat icon on taskbar
Function EnableTaskbarChat {
  Write-Output "###"
	Write-Output "Showing chat icon on taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -ErrorAction SilentlyContinue
}

# Align taskbar left
Function SetTaskbarAlignmentLeft {
  Write-Output "###"
	Write-Output "Aligning taskbar to the left..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Type DWord -Value 0
}

# Put taskbar in the center (default Windows 11)
Function SetTaskbarAlignmentMiddle {
  Write-Output "###"
	Write-Output "Centering taskbar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -ErrorAction SilentlyContinue
}

# Remove Edge Tabs From Alt-Tab
Function RemoveEdgeTabsFromAltTab {
  Write-Output "###"
	Write-Output "Removing Edge Tabs From Alt-Tab..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MultiTaskingAltTabFilter" -Type DWord -Value 3
}

# Default behaviour - Show Open windows and 5 most recent tabs in Microsoft Edge
Function SetEdgeTabsWindowsAnd5tabs {
  Write-Output "###"
	Write-Output "Set Alt-Tab behaviour to show open windows and 5 most recent Edge tabs..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MultiTaskingAltTabFilter" -Type DWord -Value 1
}

# Show Open windows and 3 most recent tabs in Microsoft Edge
Function SetEdgeTabsWindowsAnd3tabs {
  Write-Output "###"
	Write-Output "Set Alt-Tab behaviour to show open windows and 3 most recent Edge tabs..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MultiTaskingAltTabFilter" -Type DWord -Value 2
}

# Show Open windows and all tabs in Microsoft Edge
Function SetEdgeTabsWindowsAndAll {
  Write-Output "###"
	Write-Output "Set Alt-Tab behaviour to show open windows and all Edge tabs..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MultiTaskingAltTabFilter" -Type DWord -Value 0
}

##########
#endregion UI Tweaks
##########


##########
#region Explorer UI Tweaks
##########

# Show full directory path in Explorer title bar
Function ShowExplorerTitleFullPath {
  Write-Output "###"
	Write-Output "Showing full directory path in Explorer title bar..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Type DWord -Value 1
}

# Hide full directory path in Explorer title bar, only directory name will be shown
Function HideExplorerTitleFullPath {
  Write-Output "###"
	Write-Output "Hiding full directory path in Explorer title bar..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -ErrorAction SilentlyContinue
}

# Show known file extensions
Function ShowKnownExtensions {
  Write-Output "###"
	Write-Output "Showing known file extensions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
}

# Hide known file extensions
Function HideKnownExtensions {
  Write-Output "###"
	Write-Output "Hiding known file extensions..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1
}

# Show hidden files
Function ShowHiddenFiles {
  Write-Output "###"
	Write-Output "Showing hidden files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1
}

# Hide hidden files
Function HideHiddenFiles {
  Write-Output "###"
	Write-Output "Hiding hidden files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2
}

# Show protected operating system files
Function ShowSuperHiddenFiles {
  Write-Output "###"
	Write-Output "Showing protected operating system files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1
}

# Hide protected operating system files
Function HideSuperHiddenFiles {
  Write-Output "###"
	Write-Output "Hiding protected operating system files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 0
}

# Show empty drives (with no media)
Function ShowEmptyDrives {
  Write-Output "###"
	Write-Output "Showing empty drives (with no media)..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -Type DWord -Value 0
}

# Hide empty drives (with no media)
Function HideEmptyDrives {
  Write-Output "###"
	Write-Output "Hiding empty drives (with no media)..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -ErrorAction SilentlyContinue
}

# Show folder merge conflicts
Function ShowFolderMergeConflicts {
  Write-Output "###"
	Write-Output "Showing folder merge conflicts..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -Type DWord -Value 0
}

# Hide folder merge conflicts
Function HideFolderMergeConflicts {
  Write-Output "###"
	Write-Output "Hiding folder merge conflicts..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -ErrorAction SilentlyContinue
}

# Enable Explorer navigation pane expanding to current folder
Function EnableNavPaneExpand {
  Write-Output "###"
	Write-Output "Enabling navigation pane expanding to current folder..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 1
}

# Disable Explorer navigation pane expanding to current folder
Function DisableNavPaneExpand {
  Write-Output "###"
	Write-Output "Disabling navigation pane expanding to current folder..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -ErrorAction SilentlyContinue
}

# Show all folders in Explorer navigation pane
Function ShowNavPaneAllFolders {
  Write-Output "###"
	Write-Output "Showing all folders in Explorer navigation pane..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Type DWord -Value 1
}

# Hide all folders from Explorer navigation pane except the basic ones (Quick access, OneDrive, This PC, Network), some of which can be disabled using other tweaks
Function HideNavPaneAllFolders {
  Write-Output "###"
	Write-Output "Hiding all folders in Explorer navigation pane (except the basic ones)..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -ErrorAction SilentlyContinue
}

# Show Libraries in Explorer navigation pane
Function ShowNavPaneLibraries {
  Write-Output "###"
	Write-Output "Showing Libraries icon in Explorer namespace..."
	If (!(Test-Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}")) {
		New-Item -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1
}

# Hide Libraries from Explorer navigation pane
Function HideNavPaneLibraries {
  Write-Output "###"
	Write-Output "Hiding Libraries icon from Explorer namespace..."
	Remove-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue
}

# Enable launching folder windows in a separate process
Function EnableFldrSeparateProcess {
  Write-Output "###"
	Write-Output "Enabling launching folder windows in a separate process..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 1
}

# Disable launching folder windows in a separate process
Function DisableFldrSeparateProcess {
  Write-Output "###"
	Write-Output "Disabling launching folder windows in a separate process..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 0
}

# Enable restoring previous folder windows at logon
Function EnableRestoreFldrWindows {
  Write-Output "###"
	Write-Output "Enabling restoring previous folder windows at logon..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -Type DWord -Value 1
}

# Disable restoring previous folder windows at logon
Function DisableRestoreFldrWindows {
  Write-Output "###"
	Write-Output "Disabling restoring previous folder windows at logon..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -ErrorAction SilentlyContinue
}

# Show coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)
Function ShowEncCompFilesColor {
  Write-Output "###"
	Write-Output "Showing coloring of encrypted or compressed NTFS files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Type DWord -Value 1
}

# Hide coloring of encrypted or compressed NTFS files
Function HideEncCompFilesColor {
  Write-Output "###"
	Write-Output "Hiding coloring of encrypted or compressed NTFS files..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -ErrorAction SilentlyContinue
}

# Disable Sharing Wizard
Function DisableSharingWizard {
  Write-Output "###"
	Write-Output "Disabling Sharing Wizard..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Type DWord -Value 0
}

# Enable Sharing Wizard
Function EnableSharingWizard {
  Write-Output "###"
	Write-Output "Enabling Sharing Wizard..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -ErrorAction SilentlyContinue
}

# Hide item selection checkboxes
Function HideSelectCheckboxes {
  Write-Output "###"
	Write-Output "Hiding item selection checkboxes..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 0
}

# Show item selection checkboxes
Function ShowSelectCheckboxes {
  Write-Output "###"
	Write-Output "Showing item selection checkboxes..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 1
}

# Hide sync provider notifications
Function HideSyncNotifications {
  Write-Output "###"
	Write-Output "Hiding sync provider notifications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
}

# Show sync provider notifications
Function ShowSyncNotifications {
  Write-Output "###"
	Write-Output "Showing sync provider notifications..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1
}

# Hide recently and frequently used item shortcuts in Explorer
# Note: This is only UI tweak to hide the shortcuts. In order to stop creating most recently used (MRU) items lists everywhere, use privacy tweak 'DisableRecentFiles' instead.
Function HideRecentShortcuts {
  Write-Output "###"
	Write-Output "Hiding recent shortcuts in Explorer..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0
}

# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts {
  Write-Output "###"
	Write-Output "Showing recent shortcuts in Explorer..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue
}

# Change default Explorer view to This PC
Function SetExplorerThisPC {
  Write-Output "###"
	Write-Output "Changing default Explorer view to This PC..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}

# Change default Explorer view to Quick Access
Function SetExplorerQuickAccess {
  Write-Output "###"
	Write-Output "Changing default Explorer view to Quick Access..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue
}

# Hide Quick Access from Explorer navigation pane
Function HideQuickAccess {
  Write-Output "###"
	Write-Output "Hiding Quick Access from Explorer navigation pane..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Type DWord -Value 1
}

# Show Quick Access in Explorer navigation pane
Function ShowQuickAccess {
  Write-Output "###"
	Write-Output "Showing Quick Access in Explorer navigation pane..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -ErrorAction SilentlyContinue
}

# Hide Recycle Bin shortcut from desktop
Function HideRecycleBinFromDesktop {
  Write-Output "###"
	Write-Output "Hiding Recycle Bin shortcut from desktop..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1
}

# Show Recycle Bin shortcut on desktop
Function ShowRecycleBinOnDesktop {
  Write-Output "###"
	Write-Output "Showing Recycle Bin shortcut on desktop..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -ErrorAction SilentlyContinue
}

# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop {
  Write-Output "###"
	Write-Output "Showing This PC shortcut on desktop..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}

# Hide This PC shortcut from desktop
Function HideThisPCFromDesktop {
  Write-Output "###"
	Write-Output "Hiding This PC shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue
}

# Show User Folder shortcut on desktop
Function ShowUserFolderOnDesktop {
  Write-Output "###"
	Write-Output "Showing User Folder shortcut on desktop..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}

# Hide User Folder shortcut from desktop
Function HideUserFolderFromDesktop {
  Write-Output "###"
	Write-Output "Hiding User Folder shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue
}

# Show Control panel shortcut on desktop
Function ShowControlPanelOnDesktop {
  Write-Output "###"
	Write-Output "Showing Control panel shortcut on desktop..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0
}

# Hide Control panel shortcut from desktop
Function HideControlPanelFromDesktop {
  Write-Output "###"
	Write-Output "Hiding Control panel shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -ErrorAction SilentlyContinue
}

# Show Network shortcut on desktop
Function ShowNetworkOnDesktop {
  Write-Output "###"
	Write-Output "Showing Network shortcut on desktop..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" )) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"  -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" )) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 0
}

# Hide Network shortcut from desktop
Function HideNetworkFromDesktop {
  Write-Output "###"
	Write-Output "Hiding Network shortcut from desktop..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue
}

# Hide all icons from desktop
Function HideDesktopIcons {
  Write-Output "###"
	Write-Output "Hiding all icons from desktop..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1
}

# Show all icons on desktop
Function ShowDesktopIcons {
  Write-Output "###"
	Write-Output "Showing all icons on desktop..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 0
}

# Show Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function ShowBuildNumberOnDesktop {
  Write-Output "###"
	Write-Output "Showing Windows build number on desktop..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1
}

# Remove Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function HideBuildNumberFromDesktop {
  Write-Output "###"
	Write-Output "Hiding Windows build number from desktop..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 0
}

# Hide Desktop icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDesktopFromThisPC {
  Write-Output "###"
	Write-Output "Hiding Desktop icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
}

# Show Desktop icon in This PC
Function ShowDesktopInThisPC {
  Write-Output "###"
	Write-Output "Showing Desktop icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" | Out-Null
	}
}

# Hide Desktop icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDesktopFromExplorer {
  Write-Output "###"
	Write-Output "Hiding Desktop icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Desktop icon in Explorer namespace
Function ShowDesktopInExplorer {
  Write-Output "###"
	Write-Output "Showing Desktop icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Documents icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDocumentsFromThisPC {
  Write-Output "###"
	Write-Output "Hiding Documents icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
}

# Show Documents icon in This PC
Function ShowDocumentsInThisPC {
  Write-Output "###"
	Write-Output "Showing Documents icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" | Out-Null
	}
}

# Hide Documents icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDocumentsFromExplorer {
  Write-Output "###"
	Write-Output "Hiding Documents icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Documents icon in Explorer namespace
Function ShowDocumentsInExplorer {
  Write-Output "###"
	Write-Output "Showing Documents icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Downloads icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideDownloadsFromThisPC {
  Write-Output "###"
	Write-Output "Hiding Downloads icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
}

# Show Downloads icon in This PC
Function ShowDownloadsInThisPC {
  Write-Output "###"
	Write-Output "Showing Downloads icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" | Out-Null
	}
}

# Hide Downloads icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideDownloadsFromExplorer {
  Write-Output "###"
	Write-Output "Hiding Downloads icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Downloads icon in Explorer namespace
Function ShowDownloadsInExplorer {
  Write-Output "###"
	Write-Output "Showing Downloads icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Music icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideMusicFromThisPC {
  Write-Output "###"
	Write-Output "Hiding Music icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
}

# Show Music icon in This PC
Function ShowMusicInThisPC {
  Write-Output "###"
	Write-Output "Showing Music icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" | Out-Null
	}
}

# Hide Music icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideMusicFromExplorer {
  Write-Output "###"
	Write-Output "Hiding Music icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Music icon in Explorer namespace
Function ShowMusicInExplorer {
  Write-Output "###"
	Write-Output "Showing Music icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Pictures icon from This PC - The icon remains in personal folders and open/save dialogs
Function HidePicturesFromThisPC {
  Write-Output "###"
	Write-Output "Hiding Pictures icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
}

# Show Pictures icon in This PC
Function ShowPicturesInThisPC {
  Write-Output "###"
	Write-Output "Showing Pictures icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" | Out-Null
	}
}

# Hide Pictures icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HidePicturesFromExplorer {
  Write-Output "###"
	Write-Output "Hiding Pictures icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Pictures icon in Explorer namespace
Function ShowPicturesInExplorer {
  Write-Output "###"
	Write-Output "Showing Pictures icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Videos icon from This PC - The icon remains in personal folders and open/save dialogs
Function HideVideosFromThisPC {
  Write-Output "###"
	Write-Output "Hiding Videos icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
}

# Show Videos icon in This PC
Function ShowVideosInThisPC {
  Write-Output "###"
	Write-Output "Showing Videos icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" | Out-Null
	}
}

# Hide Videos icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideVideosFromExplorer {
  Write-Output "###"
	Write-Output "Hiding Videos icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Videos icon in Explorer namespace
Function ShowVideosInExplorer {
  Write-Output "###"
	Write-Output "Showing Videos icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
Function Hide3DObjectsFromThisPC {
  Write-Output "###"
	Write-Output "Hiding 3D Objects icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

# Show 3D Objects icon in This PC
Function Show3DObjectsInThisPC {
  Write-Output "###"
	Write-Output "Showing 3D Objects icon in This PC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
	}
}

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function Hide3DObjectsFromExplorer {
  Write-Output "###"
	Write-Output "Hiding 3D Objects icon from Explorer namespace..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show 3D Objects icon in Explorer namespace
Function Show3DObjectsInExplorer {
  Write-Output "###"
	Write-Output "Showing 3D Objects icon in Explorer namespace..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue
}

# Hide Network icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideNetworkFromExplorer {
  Write-Output "###"
	Write-Output "Hiding Network icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 1
}

# Show Network icon in Explorer namespace
Function ShowNetworkInExplorer {
  Write-Output "###"
	Write-Output "Showing Network icon in Explorer namespace..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue
}

# Hide 'Include in library' context menu item
Function HideIncludeInLibraryMenu {
  Write-Output "###"
	Write-Output "Hiding 'Include in library' context menu item..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue
}

# Show 'Include in library' context menu item
Function ShowIncludeInLibraryMenu {
  Write-Output "###"
	Write-Output "Showing 'Include in library' context menu item..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	New-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -Name "(Default)" -Type String -Value "{3dad6c5d-2167-4cae-9914-f99e41c12cfa}"
}

# Hide 'Give access to' (until 1703 'Share With') context menu item.
Function HideGiveAccessToMenu {
  Write-Output "###"
	Write-Output "Hiding 'Give access to' context menu item..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue

}

# Show 'Give access to' (until 1703 'Share With') context menu item.
Function ShowGiveAccessToMenu {
  Write-Output "###"
	Write-Output "Showing 'Give access to' context menu item..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	New-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
	New-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
	New-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
	New-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"
}

# Hide 'Share' context menu item. Applicable since 1709
Function HideShareMenu {
  Write-Output "###"
	Write-Output "Hiding 'Share' context menu item..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue
}

# Show 'Share' context menu item. Applicable since 1709
Function ShowShareMenu {
  Write-Output "###"
	Write-Output "Showing 'Share' context menu item..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	New-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -Name "(Default)" -Type String -Value "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}"
}

# Disable thumbnails, show only file extension icons
Function DisableThumbnails {
  Write-Output "###"
	Write-Output "Disabling thumbnails..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1
}

# Enable thumbnails
Function EnableThumbnails {
  Write-Output "###"
	Write-Output "Enabling thumbnails..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0
}

# Disable creation of thumbnail cache files
Function DisableThumbnailCache {
  Write-Output "###"
	Write-Output "Disabling creation of thumbnail cache files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1
}

# Enable creation of thumbnail cache files
Function EnableThumbnailCache {
  Write-Output "###"
	Write-Output "Enabling creation of thumbnail cache files..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue
}

# Disable creation of Thumbs.db thumbnail cache files on network folders
Function DisableThumbsDBOnNetwork {
  Write-Output "###"
	Write-Output "Disabling creation of Thumbs.db on network folders..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
}

# Enable creation of Thumbs.db thumbnail cache files on network folders
Function EnableThumbsDBOnNetwork {
  Write-Output "###"
	Write-Output "Enabling creation of Thumbs.db on network folders..."
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue
}

##########
#endregion Explorer UI Tweaks
##########



##########
#region Application Tweaks
##########

# Disable OneDrive
Function DisableOneDrive {
  Write-Output "###"
	Write-Output "Disabling OneDrive..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}

# Enable OneDrive
Function EnableOneDrive {
  Write-Output "###"
	Write-Output "Enabling OneDrive..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue
}

# Uninstall OneDrive - Not applicable to Server
Function UninstallOneDrive {
  Write-Output "###"
	Write-Output "Uninstalling OneDrive..."
	Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	If ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	}
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}

# Install OneDrive - Not applicable to Server
Function InstallOneDrive {
  Write-Output "###"
	Write-Output "Installing OneDrive..."
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive -NoNewWindow
}

# Uninstall default Microsoft applications
Function UninstallMsftBloat {
  Write-Output "###"
	Write-Output "Uninstalling default Microsoft applications..."
	Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingMaps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.FreshPaint" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.HelpAndTips" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Media.PlayReadyClient.2" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MoCamera" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.OfficeLens" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Reader" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Todos" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Whiteboard" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
	Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsReadingList" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsScan" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WinJS.1.0" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WinJS.2.0" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage # Dependency for microsoft.windowscommunicationsapps, Microsoft.BingWeather
}

# Install default Microsoft applications
Function InstallMsftBloat {
  Write-Output "###"
	Write-Output "Installing default Microsoft applications..."
	Get-AppxPackage -AllUsers "Microsoft.3DBuilder" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Advertising.Xaml" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} # Dependency for microsoft.windowscommunicationsapps, Microsoft.BingWeather
	Get-AppxPackage -AllUsers "Microsoft.AppConnector" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingFinance" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingFoodAndDrink" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingHealthAndFitness" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingMaps" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingNews" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingSports" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingTranslator" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingTravel" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.BingWeather" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.CommsPhone" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.FreshPaint" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.GetHelp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Getstarted" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.HelpAndTips" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Media.PlayReadyClient.2" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Messaging" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MicrosoftStickyNotes" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MinecraftUWP" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MoCamera" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.MSPaint" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.OfficeLens" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Office.OneNote" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Office.Sway" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.OneConnect" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.People" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Print3D" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Reader" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.RemoteDesktop" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.SkypeApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Todos" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Wallet" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WebMediaExtensions" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Whiteboard" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsAlarms" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsCamera" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.windowscommunicationsapps" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsMaps" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsPhone" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Windows.Photos" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsReadingList" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsScan" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsSoundRecorder" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WinJS.1.0" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WinJS.2.0" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.YourPhone" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.ZuneMusic" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.ZuneVideo" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# In case you have removed them for good, you can try to restore the files using installation medium as follows
# New-Item C:\Mnt -Type Directory | Out-Null
# dism /Mount-Image /ImageFile:D:\sources\install.wim /index:1 /ReadOnly /MountDir:C:\Mnt
# robocopy /S /SEC /R:0 "C:\Mnt\Program Files\WindowsApps" "C:\Program Files\WindowsApps"
# dism /Unmount-Image /Discard /MountDir:C:\Mnt
# Remove-Item -Path C:\Mnt -Recurse

# Uninstall default third party applications
function UninstallThirdPartyBloat {
  Write-Output "###"
	Write-Output "Uninstalling default third party applications..."
	Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
	Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
	Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
	Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
	Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
	Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
	Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
	Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
	Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.DragonManiaLegends" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
	Get-AppxPackage "AD2F1837.GettingStartedwithWindows8" | Remove-AppxPackage
	Get-AppxPackage "AD2F1837.HPJumpStart" | Remove-AppxPackage
	Get-AppxPackage "AD2F1837.HPRegistration" | Remove-AppxPackage
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
	Get-AppxPackage "Amazon.com.Amazon" | Remove-AppxPackage  
  Get-AppxPackage "AmazonVideo.PrimeVideo" | Remove-AppxPackage  
  Get-AppxPackage "BytedancePte.Ltd.TikTok" | Remove-AppxPackage  
	Get-AppxPackage "C27EB4BA.DropboxOEM" | Remove-AppxPackage
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
  Get-AppxPackage "Clipchamp.Clipchamp" | Remove-AppxPackage
	Get-AppxPackage "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | Remove-AppxPackage
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
	Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
  Get-AppxPackage "Facebook.InstagramBeta" | Remove-AppxPackage
	Get-AppxPackage "Fitbit.FitbitCoach" | Remove-AppxPackage
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
	Get-AppxPackage "king.com.FarmHeroesSaga" | Remove-AppxPackage
	Get-AppxPackage "Nordcurrent.CookingFever" | Remove-AppxPackage
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
	Get-AppxPackage "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | Remove-AppxPackage
	Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
	Get-AppxPackage "ThumbmunkeysLtd.PhototasticCollage" | Remove-AppxPackage
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
	Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage
  Get-AppxPackage "Disney.37853FC22B2CE" | Remove-AppxPackage
}

# Install default third party applications
Function InstallThirdPartyBloat {
  Write-Output "###"
	Write-Output "Installing default third party applications..."
	Get-AppxPackage -AllUsers "2414FC7A.Viber" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "41038Axilesoft.ACGMediaPlayer" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "46928bounde.EclipseManager" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "4DF9E0F8.Netflix" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "64885BlueEdge.OneCalendar" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "7EE7776C.LinkedInforWindows" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "828B5831.HiddenCityMysteryofShadows" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "89006A2E.AutodeskSketchBook" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "9E2F88E3.Twitter" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "A278AB0D.DisneyMagicKingdoms" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "A278AB0D.DragonManiaLegends" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "A278AB0D.MarchofEmpires" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "ActiproSoftwareLLC.562882FEEB491" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "AD2F1837.GettingStartedwithWindows8" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "AD2F1837.HPJumpStart" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "AD2F1837.HPRegistration" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "AdobeSystemsIncorporated.AdobePhotoshopExpress" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Amazon.com.Amazon" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "C27EB4BA.DropboxOEM" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "CAF9E577.Plex" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "D52A8D61.FarmVille2CountryEscape" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "D5EA27B7.Duolingo-LearnLanguagesforFree" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "DB6EA5DB.CyberLinkMediaSuiteEssentials" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "DolbyLaboratories.DolbyAccess" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Drawboard.DrawboardPDF" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Facebook.Facebook" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Fitbit.FitbitCoach" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "flaregamesGmbH.RoyalRevolt2" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "GAMELOFTSA.Asphalt8Airborne" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "KeeperSecurityInc.Keeper" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "king.com.BubbleWitch3Saga" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "king.com.CandyCrushFriends" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "king.com.CandyCrushSaga" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "king.com.CandyCrushSodaSaga" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "king.com.FarmHeroesSaga" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Nordcurrent.CookingFever" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "PandoraMediaInc.29680B314EFC2" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "SpotifyAB.SpotifyMusic" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "ThumbmunkeysLtd.PhototasticCollage" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "WinZipComputing.WinZipUniversal" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "XINGAG.XING" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
  Get-AppxPackage -AllUsers "Disney.37853FC22B2CE" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}

# Uninstall Windows Store
Function UninstallWindowsStore {
  Write-Output "###"
	Write-Output "Uninstalling Windows Store..."
	Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Services.Store.Engagement" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.StorePurchaseApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}

# Install Windows Store
Function InstallWindowsStore {
  Write-Output "###"
	Write-Output "Installing Windows Store..."
	Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Services.Store.Engagement" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.StorePurchaseApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}

# Disable Xbox features - Not applicable to Server
Function DisableXboxFeatures {
  Write-Output "###"
	Write-Output "Disabling Xbox features..."
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
}

# Enable Xbox features - Not applicable to Server
Function EnableXboxFeatures {
  Write-Output "###"
	Write-Output "Enabling Xbox features..."
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGamingOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue
}

# Disable Fullscreen optimizations
Function DisableFullscreenOptims {
  Write-Output "###"
	Write-Output "Disabling Fullscreen optimizations..."
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1
}

# Enable Fullscreen optimizations
Function EnableFullscreenOptims {
  Write-Output "###"
	Write-Output "Enabling Fullscreen optimizations..."
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 0
	Remove-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 0
}

# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash {
  Write-Output "###"
	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0
}

# Enable built-in Adobe Flash in IE and Edge
Function EnableAdobeFlash {
  Write-Output "###"
	Write-Output "Enabling built-in Adobe Flash in IE and Edge..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -ErrorAction SilentlyContinue
}

# Disable Edge preload after Windows startup - Applicable since Win10 1809
Function DisableEdgePreload {
  Write-Output "###"
	Write-Output "Disabling Edge preload..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0
}

# Enable Edge preload after Windows startup
Function EnableEdgePreload {
  Write-Output "###"
	Write-Output "Enabling Edge preload..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -ErrorAction SilentlyContinue
}

# Disable Edge desktop shortcut creation after certain Windows updates are applied
Function DisableEdgeShortcutCreation {
  Write-Output "###"
	Write-Output "Disabling Edge shortcut creation..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1
}

# Enable Edge desktop shortcut creation after certain Windows updates are applied
Function EnableEdgeShortcutCreation {
  Write-Output "###"
	Write-Output "Enabling Edge shortcut creation..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -ErrorAction SilentlyContinue
}

# Disable Internet Explorer first run wizard
Function DisableIEFirstRun {
  Write-Output "###"
	Write-Output "Disabling Internet Explorer first run wizard..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1
}

# Enable Internet Explorer first run wizard
Function EnableIEFirstRun {
  Write-Output "###"
	Write-Output "Disabling Internet Explorer first run wizard..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -ErrorAction SilentlyContinue
}

# Disable "Hi!" First Logon Animation (it will be replaced by "Preparing Windows" message)
Function DisableFirstLogonAnimation {
  Write-Output "###"
	Write-Output "Disabling First Logon Animation..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -Type DWord -Value 0
}

# Enable "Hi!" First Logon Animation
Function EnableFirstLogonAnimation {
  Write-Output "###"
	Write-Output "Enabling First Logon Animation..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -ErrorAction SilentlyContinue
}

# Disable Windows Media Player's media sharing feature
Function DisableMediaSharing {
  Write-Output "###"
	Write-Output "Disabling Windows Media Player media sharing..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -Type DWord -Value 1
}

# Enable Windows Media Player's media sharing feature
Function EnableMediaSharing {
  Write-Output "###"
	Write-Output "Enabling Windows Media Player media sharing..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -ErrorAction SilentlyContinue
}

# Disable Windows Media Player online access - audio file metadata download, radio presets, DRM.
Function DisableMediaOnlineAccess {
  Write-Output "###"
	Write-Output "Disabling Windows Media Player online access..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWord -Value 1
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1
}

# Enable Windows Media Player online access
Function EnableMediaOnlineAccess {
  Write-Output "###"
	Write-Output "Enabling Windows Media Player online access..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -ErrorAction SilentlyContinue
}

# Enable Developer Mode
Function EnableDeveloperMode {
  Write-Output "###"
	Write-Output "Enabling Developer Mode..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1
}

# Disable Developer Mode
Function DisableDeveloperMode {
  Write-Output "###"
	Write-Output "Disabling Developer Mode..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -ErrorAction SilentlyContinue
}

# Uninstall Windows Media Player
Function UninstallMediaPlayer {
  Write-Output "###"
	Write-Output "Uninstalling Windows Media Player..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Windows Media Player
Function InstallMediaPlayer {
  Write-Output "###"
	Write-Output "Installing Windows Media Player..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WindowsMediaPlayer" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Media.WindowsMediaPlayer*" } | Add-WindowsCapability -Online | Out-Null
}

# Uninstall Internet Explorer
Function UninstallInternetExplorer {
  Write-Output "###"
	Write-Output "Uninstalling Internet Explorer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Internet Explorer
Function InstallInternetExplorer {
  Write-Output "###"
	Write-Output "Installing Internet Explorer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "Internet-Explorer-Optional*" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Browser.InternetExplorer*" } | Add-WindowsCapability -Online | Out-Null
}

# Uninstall Work Folders Client - Not applicable to Server
Function UninstallWorkFolders {
  Write-Output "###"
	Write-Output "Uninstalling Work Folders Client..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Work Folders Client - Not applicable to Server
Function InstallWorkFolders {
  Write-Output "###"
	Write-Output "Installing Work Folders Client..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "WorkFolders-Client" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Windows Hello Face - Not applicable to Server
Function UninstallHelloFace {
  Write-Output "###"
	Write-Output "Uninstalling Windows Hello Face..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Hello.Face*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Windows Hello Face - Not applicable to Server
Function InstallHelloFace {
  Write-Output "###"
	Write-Output "Installing Windows Hello Face..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Hello.Face*" } | Add-WindowsCapability -Online | Out-Null
}

# Uninstall Math Recognizer - Not applicable to Server
Function UninstallMathRecognizer {
  Write-Output "###"
	Write-Output "Uninstalling Math Recognizer..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "MathRecognizer*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Math Recognizer - Not applicable to Server
Function InstallMathRecognizer {
  Write-Output "###"
	Write-Output "Installing Math Recognizer..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "MathRecognizer*" } | Add-WindowsCapability -Online | Out-Null
}

# Uninstall PowerShell 2.0 Environment
# PowerShell 2.0 is deprecated since September 2018. This doesn't affect PowerShell 5 or newer which is the default PowerShell environment.
# May affect Microsoft Diagnostic Tool and possibly other scripts. See https://blogs.msdn.microsoft.com/powershell/2017/08/24/windows-powershell-2-0-deprecation/
Function UninstallPowerShellV2 {
  Write-Output "###"
	Write-Output "Uninstalling PowerShell 2.0 Environment..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "MicrosoftWindowsPowerShellV2Root" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "PowerShell-V2" -WarningAction SilentlyContinue | Out-Null
	}
}

# Install PowerShell 2.0 Environment
Function InstallPowerShellV2 {
  Write-Output "###"
	Write-Output "Installing PowerShell 2.0 Environment..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "MicrosoftWindowsPowerShellV2Root" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "PowerShell-V2" -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall PowerShell Integrated Scripting Environment - Applicable since 2004
# Note: Also removes built-in graphical methods like Out-GridView
Function UninstallPowerShellISE {
  Write-Output "###"
	Write-Output "Uninstalling PowerShell Integrated Scripting Environment..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Microsoft.Windows.PowerShell.ISE*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install PowerShell Integrated Scripting Environment - Applicable since 2004
Function InstallPowerShellISE {
  Write-Output "###"
	Write-Output "Installing PowerShell Integrated Scripting Environment..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Microsoft.Windows.PowerShell.ISE*" } | Add-WindowsCapability -Online | Out-Null
}

# Install Linux Subsystem - Applicable since Win10 1607 and Server 1709
# Note: 1607 requires also EnableDevelopmentMode for WSL to work
# For automated Linux distribution installation, see https://docs.microsoft.com/en-us/windows/wsl/install-on-server
Function InstallLinuxSubsystem {
  Write-Output "###"
	Write-Output "Installing Linux Subsystem..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Windows-Subsystem-Linux" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Linux Subsystem - Applicable since Win10 1607 and Server 1709
Function UninstallLinuxSubsystem {
  Write-Output "###"
	Write-Output "Uninstalling Linux Subsystem..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Windows-Subsystem-Linux" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Hyper-V - Not applicable to Home
Function InstallHyperV {
  Write-Output "###"
	Write-Output "Installing Hyper-V..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Hyper-V-All" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall Hyper-V - Not applicable to Home
Function UninstallHyperV {
  Write-Output "###"
	Write-Output "Uninstalling Hyper-V..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Microsoft-Hyper-V-All" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall OpenSSH Client - Applicable since 1803
Function UninstallSSHClient {
  Write-Output "###"
	Write-Output "Uninstalling OpenSSH Client..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Client*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install OpenSSH Client - Applicable since 1803
Function InstallSSHClient {
  Write-Output "###"
	Write-Output "Installing OpenSSH Client..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Client*" } | Add-WindowsCapability -Online | Out-Null
}

# Install OpenSSH Server - Applicable since 1809
Function InstallSSHServer {
  Write-Output "###"
	Write-Output "Installing OpenSSH Server..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" } | Add-WindowsCapability -Online | Out-Null
}

# Uninstall OpenSSH Server - Applicable since 1809
Function UninstallSSHServer {
  Write-Output "###"
	Write-Output "Uninstalling OpenSSH Server..."
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Telnet Client
Function InstallTelnetClient {
  Write-Output "###"
	Write-Output "Installing Telnet Client..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "TelnetClient" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "Telnet-Client" -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall Telnet Client
Function UninstallTelnetClient {
  Write-Output "###"
	Write-Output "Uninstalling Telnet Client..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "TelnetClient" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "Telnet-Client" -WarningAction SilentlyContinue | Out-Null
	}
}

# Install .NET Framework 2.0, 3.0 and 3.5 runtimes - Requires internet connection
Function InstallNET23 {
  Write-Output "###"
	Write-Output "Installing .NET Framework 2.0, 3.0 and 3.5 runtimes..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "NetFx3" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Install-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
	}
}

# Uninstall .NET Framework 2.0, 3.0 and 3.5 runtimes
Function UninstallNET23 {
  Write-Output "###"
	Write-Output "Uninstalling .NET Framework 2.0, 3.0 and 3.5 runtimes..."
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "NetFx3" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	} Else {
		Uninstall-WindowsFeature -Name "NET-Framework-Core" -WarningAction SilentlyContinue | Out-Null
	}
}

# Set Photo Viewer association for bmp, gif, jpg, png and tif
Function SetPhotoViewerAssociation {
  Write-Output "###"
	Write-Output "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
		New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
		New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
		Set-ItemProperty -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -Type ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043"
		Set-ItemProperty -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	}
}

# Unset Photo Viewer association for bmp, gif, jpg, png and tif
Function UnsetPhotoViewerAssociation {
  Write-Output "###"
	Write-Output "Unsetting Photo Viewer association for bmp, gif, jpg, png and tif..."
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\Paint.Picture\shell\open" -Recurse -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "MuiVerb" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCR:\giffile\shell\open" -Name "CommandId" -Type String -Value "IE.File"
	Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "(Default)" -Type String -Value "`"$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe`" %1"
	Set-ItemProperty -Path "HKCR:\giffile\shell\open\command" -Name "DelegateExecute" -Type String -Value "{17FE9752-0B5A-4665-84CD-569794602F5C}"
	Remove-Item -Path "HKCR:\jpegfile\shell\open" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\pngfile\shell\open" -Recurse -ErrorAction SilentlyContinue
}

# Add Photo Viewer to 'Open with...'
Function AddPhotoViewerOpenWith {
  Write-Output "###"
	Write-Output "Adding Photo Viewer to 'Open with...'"
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Name "MuiVerb" -Type String -Value "@photoviewer.dll,-3043"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Name "(Default)" -Type ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
	Set-ItemProperty -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Name "Clsid" -Type String -Value "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
}

# Remove Photo Viewer from 'Open with...'
Function RemovePhotoViewerOpenWith {
  Write-Output "###"
	Write-Output "Removing Photo Viewer from 'Open with...'"
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	}
	Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse -ErrorAction SilentlyContinue
}

# Uninstall Microsoft Print to PDF
Function UninstallPDFPrinter {
  Write-Output "###"
	Write-Output "Uninstalling Microsoft Print to PDF..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft Print to PDF
Function InstallPDFPrinter {
  Write-Output "###"
	Write-Output "Installing Microsoft Print to PDF..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-PrintToPDFServices-Features" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Uninstall Microsoft XPS Document Writer
Function UninstallXPSPrinter {
  Write-Output "###"
	Write-Output "Uninstalling Microsoft XPS Document Writer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Install Microsoft XPS Document Writer
Function InstallXPSPrinter {
  Write-Output "###"
	Write-Output "Installing Microsoft XPS Document Writer..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "Printing-XPSServices-Features" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# Remove Default Fax Printer
Function RemoveFaxPrinter {
  Write-Output "###"
	Write-Output "Removing Default Fax Printer..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

# Add Default Fax Printer
Function AddFaxPrinter {
  Write-Output "###"
	Write-Output "Adding Default Fax Printer..."
	Add-Printer -Name "Fax" -DriverName "Microsoft Shared Fax Driver" -PortName "SHRFAX:" -ErrorAction SilentlyContinue
}

# Uninstall Windows Fax and Scan Services - Not applicable to Server
Function UninstallFaxAndScan {
  Write-Output "###"
	Write-Output "Uninstalling Windows Fax and Scan Services..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Disable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Remove-WindowsCapability -Online | Out-Null
}

# Install Windows Fax and Scan Services - Not applicable to Server
Function InstallFaxAndScan {
  Write-Output "###"
	Write-Output "Installing Windows Fax and Scan Services..."
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "FaxServicesClientPackage" } | Enable-WindowsOptionalFeature -Online -NoRestart -WarningAction SilentlyContinue | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "Print.Fax.Scan*" } | Add-WindowsCapability -Online | Out-Null
}

##########
#endregion Application Tweaks
##########



##########
#region Server specific Tweaks
##########

# Hide Server Manager after login
Function HideServerManagerOnLogin {
  Write-Output "###"
	Write-Output "Hiding Server Manager after login..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -Type DWord -Value 1
}

# Show Server Manager after login
Function ShowServerManagerOnLogin {
  Write-Output "###"
	Write-Output "Showing Server Manager after login..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager" -Name "DoNotOpenAtLogon" -ErrorAction SilentlyContinue
}

# Disable Shutdown Event Tracker
Function DisableShutdownTracker {
  Write-Output "###"
	Write-Output "Disabling Shutdown Event Tracker..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -Type DWord -Value 0
}

# Enable Shutdown Event Tracker
Function EnableShutdownTracker {
  Write-Output "###"
	Write-Output "Enabling Shutdown Event Tracker..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" -Name "ShutdownReasonOn" -ErrorAction SilentlyContinue
}

# Disable password complexity and maximum age requirements
Function DisablePasswordPolicy {
  Write-Output "###"
	Write-Output "Disabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
}

# Enable password complexity and maximum age requirements
Function EnablePasswordPolicy {
  Write-Output "###"
	Write-Output "Enabling password complexity and maximum age requirements..."
	$tmpfile = New-TemporaryFile
	secedit /export /cfg $tmpfile /quiet
	(Get-Content $tmpfile).Replace("PasswordComplexity = 0", "PasswordComplexity = 1").Replace("MaximumPasswordAge = -1", "MaximumPasswordAge = 42") | Out-File $tmpfile
	secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
	Remove-Item -Path $tmpfile
}

# Disable Ctrl+Alt+Del requirement before login
Function DisableCtrlAltDelLogin {
  Write-Output "###"
	Write-Output "Disabling Ctrl+Alt+Del requirement before login..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 1
}

# Enable Ctrl+Alt+Del requirement before login
Function EnableCtrlAltDelLogin {
  Write-Output "###"
	Write-Output "Enabling Ctrl+Alt+Del requirement before login..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Type DWord -Value 0
}

# Disable Internet Explorer Enhanced Security Configuration (IE ESC)
Function DisableIEEnhancedSecurity {
  Write-Output "###"
	Write-Output "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 0
}

# Enable Internet Explorer Enhanced Security Configuration (IE ESC)
Function EnableIEEnhancedSecurity {
  Write-Output "###"
	Write-Output "Enabling Internet Explorer Enhanced Security Configuration (IE ESC)..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Type DWord -Value 1
}

# Enable Audio
Function EnableAudio {
  Write-Output "###"
	Write-Output "Enabling Audio..."
	Set-Service "Audiosrv" -StartupType Automatic
	Start-Service "Audiosrv" -WarningAction SilentlyContinue
}

# Disable Audio
Function DisableAudio {
  Write-Output "###"
	Write-Output "Disabling Audio..."
	Stop-Service "Audiosrv" -WarningAction SilentlyContinue
	Set-Service "Audiosrv" -StartupType Manual
}

##########
#endregion Server specific Tweaks
##########



##########
#region Unpinning
##########

# Unpin all Start Menu tiles
# Note: This function has no counterpart. You have to pin the tiles back manually.
Function UnpinStartMenuTiles {
  Write-Output "###"
	Write-Output "Unpinning all Start Menu tiles..."
	If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
		Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
			$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
			$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
			Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
		}
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
		$data = $key.Data[0..25] + ([byte[]](202,50,0,226,44,1,1,0,0))
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}

# Unpin all Taskbar icons
# Note: This function has no counterpart. You have to pin the icons back manually.
Function UnpinTaskbarIcons {
  Write-Output "###"
	Write-Output "Unpinning all Taskbar icons..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}

Function CleanPublicDesktop(){
  $PublicDesktop="\Users\Public\Desktop"
  Remove-Item -Path $PublicDesktop\*.* 
}

##########
#endregion Unpinning
##########

# Export functions
Export-ModuleMember -Function *
