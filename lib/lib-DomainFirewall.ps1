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