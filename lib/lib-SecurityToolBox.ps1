
function GetLogSize{
    [OutputType("LogSize")]
    Param([Parameter(Mandatory)]$LogName, $ComputerName=".")
    $LogData = ( Get-EventLog -List -ComputerName $ComputerName | Where-Object {$_.Log -eq "$LogName" })
    [PSCustomObject]@{
        PSTypeName             = "LogSize"
        "LogSize(MB)"          = $LogData.Maximumkilobytes / 1024
        LogName                = $LogData.LogDisplayName
    }
}


function SetLogSize{
    Param([Parameter(Mandatory)]$LogName, $ComputerName=".", ${LogSize}=20)
    Limit-EventLog -logname "$LogName" -ComputerName $ComputerName -MaximumSize ${LogSize}MB
}


function GetCmdLnInPrcsAuditEvnts{
    $Enabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled"  -ErrorAction SilentlyContinue
    $BoolOutput = (&{If($Enabled) {"True"} Else {"False"}})
    Write-Output "Command Line in Process Audit Events: $BoolOutput"
}


function EnableCmdLnInPrcsAuditEvnts{
    Write-Output "###"
	Write-Output "Enabling Command Line in process audit events..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 
}

function DisableCmdLnInPrcsAuditEvnts{
    Write-Output "###"
	Write-Output "Disabling Command Line in process audit events..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue 
}

Export-ModuleMember -Function *

<#
Get-LogSize Application
Get-LogSize System
Get-LogSize Security
Get-LogSize "Windows Powershell"
#>