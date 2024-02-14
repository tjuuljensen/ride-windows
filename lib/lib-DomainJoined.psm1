# Disable WSUS updates on Domain networks - it will revert as soon as the computer is reconnected to the domain
Function DisableWSUS {
  Write-Output "###"
  Write-Output "Disabling Windows Update over WSUS..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Type DWord -Value 0

  If (Get-Service "wuauserv" -ErrorAction SilentlyContinue) {
      Restart-Service "wuauserv" -WarningAction SilentlyContinue
  }
  If (Get-Service "BITS" -ErrorAction SilentlyContinue) {
    Restart-Service "BITS" -WarningAction SilentlyContinue
  }
 
}

# Enable WSUS updates on Domain networks 
Function EnableWSUS {
  Write-Output "###"
  Write-Output "Enabling Windows Update over WSUS..."
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Type DWord -Value 1

  If (Get-Service "wuauserv" -ErrorAction SilentlyContinue) {
      Restart-Service "wuauserv" -WarningAction SilentlyContinue
  }
}

# Enable Firewall on Domain networks
Function EnableFirewallDomain {
  Write-Output "###"
  Write-Output "Enabling Firewall for domain networks..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Force | Out-Null
  }
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -name "EnableFirewall" -Type DWORD -Value 1 -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -name "DefaultInboundAction" -Type DWORD -Value 1 -Force | Out-Null
}

# Disable Firewall on Domain networks
Function DisableFirewallDomain {
  Write-Output "###"
  Write-Output "Disabling Firewall for domain networks..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Force | Out-Null
  }
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -name "EnableFirewall" -Type DWORD -Value 0 -Force | Out-Null
}

# Enable Firewall on Private networks
Function EnableFirewallPrivate {
  Write-Output "###"
  Write-Output "Enabling Firewall for private networks..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Force | Out-Null
  }
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -name "EnableFirewall" -Type DWORD -Value 1 -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -name "DefaultInboundAction" -Type DWORD -Value 1 -Force | Out-Null
}

# Disable Firewall on Private networks
Function DisableFirewallPrivate {
  Write-Output "###"
  Write-Output "Disabling Firewall for private networks..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Force | Out-Null
  }
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -name "EnableFirewall" -Type DWORD -Value 0 -Force | Out-Null
}

# Enable Firewall on Public networks
Function EnableFirewallPublic {
  Write-Output "###"
  Write-Output "Enabling Firewall for public networks..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Force | Out-Null
  }
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -name "EnableFirewall" -Type DWORD -Value 1 -Force | Out-Null
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -name "DefaultInboundAction" -Type DWORD -Value 1 -Force | Out-Null
}

# Disable Firewall on Public networks
Function DisableFirewallPublic {
  Write-Output "###"
  Write-Output "Disabling Firewall for public networks..."
  If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Force | Out-Null
  }
  New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -name "EnableFirewall" -Type DWORD -Value 0 -Force | Out-Null
}


function InstallADConnect {
  # https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-roadmap#install-azure-ad-connect

  Write-Output "###"
  $SoftwareName = "Microsoft Entra Connect"
  Write-Output "Installing $SoftwareName..."

  # (Invoke-WebRequest -UseBasicParsing -Uri "https://www.microsoft.com/en-us/download/details.aspx?id=47594").Links.href  | Select-String -Pattern AzureADConnect
  $FullDownloadURL = (Invoke-WebRequest -UseBasicParsing -Uri "https://www.microsoft.com/en-us/download/details.aspx?id=47594").Links.Href | Select-String -Pattern AzureADConnect | Select-Object -first 1
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

  # Download software
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