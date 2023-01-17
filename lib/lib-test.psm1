function ridevars(){
    $RideVariables=Select-String -Path ./lib-windows.psm1 -Pattern '(RIDEVAR-)[^"]*' 
                   | ForEach-Object {$_.matches} 
                   | Foreach-Object {if ($_.value -NotLike "*$*" -and $_.value -ne "RIDEVAR-Download-Only") {$_.value}} 
                   | sort | Get-Unique
    foreach ($variable in $RideVariables) {
        Write-Host $variable": " -ForegroundColor Green -NoNewline 
        Write-Host ([Environment]::GetEnvironmentVariable($variable, "Process"))
    }
}