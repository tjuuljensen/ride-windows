 Get-WindowsCapability -Name RSAT* -Online | Where-Object { $_.State -ne "Installed"} | Add-WindowsCapability -Online | Out-Null