function ridevars(){
    $RideVariables=Select-String -Path ./lib-windows.psm1 -Pattern '(RIDEVAR-)[^"]*' | ForEach-Object {$_.matches} | Foreach-Object {if ($_.value -NotLike "*$*" -and $_.value -ne "RIDEVAR-Download-Only") {$_.value}} | Sort-Object | Get-Unique
    foreach ($variable in $RideVariables) {
        Write-Host $variable": " -ForegroundColor Green -NoNewline 
        Write-Host ([Environment]::GetEnvironmentVariable($variable, "Process"))
    }
}

function GetPackageInfo {

    $appname = read-host "Enter your program name"

    Write-Output "Get-Package:"
    (Get-Package -Name "*$appname*").name
    Write-Output ""
    Write-Output "Get-AppXpackage:"
    (Get-AppxPackage -Name "*$appname*").name
    Write-Output ""
    Write-Output "Uninstallstring:"
    #Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -Filter  "*$InpuString*"  | where-Object {$_.DisplayName -like "*$InpuString*"} | ForEach-Object { Write-Output $_.PSChildName }

    $32bit = get-itemproperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, UninstallString, PSChildName | Where-Object { $_.DisplayName -match "^*$appname*"}
    $64bit = get-itemproperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, UninstallString, PSChildName | Where-Object { $_.DisplayName -match "^*$appname*"}

    
    if ($64bit -eq "" -or $64bit.count -eq 0) {
    
        switch ($32bit.DisplayName.count) {
            0 {Write-Host "Cannot find the uninstall string" -ForegroundColor Red}
            1 {
                if ($32bit -match "msiexec.exe") {
                $32bit.UninstallString -replace 'msiexec.exe /i','msiexec.exe /x'
                }
                else
                {
                    $32bit.UninstallString 
                }
                }
            default { $32bit |Foreach-Object {Write-Host  $_.DisplayName,  $_.UninstallString  }} 
        }
    }
    else {
    
        switch ($64bit.DisplayName.count) {
            0 {Write-Host "Cannot find the uninstall string" -ForegroundColor Red}
            1 {
                if ($64bit -match "msiexec.exe") {
                    $64bit.UninstallString -replace 'msiexec.exe /i','msiexec.exe /x'
                }
                else
                {
                    $64bit.UninstallString 
                }
                }
            default { $64bit |Foreach-Object {Write-Host  $_.DisplayName,  $_.UninstallString }
        }
    }
}