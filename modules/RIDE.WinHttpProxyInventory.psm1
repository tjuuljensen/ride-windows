<#
.SYNOPSIS
  Read the advanced WinHTTP proxy configuration through its documented netsh view.
.DESCRIPTION
  Captures the JSON object emitted by `netsh winhttp show advproxy`, validates its
  reported state and binds the observation to the current computer and user.
  This module does not write configuration, infer application routing, or persist
  proxy values.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Native netsh WinHTTP advanced proxy support.
  Inputs: Current machine/user identity; no caller-supplied command text.
  Recovery: Read-only observation only. No mutation or recovery is provided.
  Version: 0.1.0.
  Changelog: 0.1.0: Add strict read-only advanced WinHTTP configuration capture.
.LINK
  ../docs/user-proxy-inventory.md
.LINK
  https://learn.microsoft.com/en-us/windows/win32/winhttp/netsh-exe-commands
#>
$ErrorActionPreference='Stop'

function Get-RideWinHttpProxyCurrentIdentity {
  if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'WinHTTP proxy inventory requires Windows.'}
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try {
    if($null -eq $identity.User -or [string]::IsNullOrWhiteSpace($identity.User.Value)){throw 'Current Windows user SID is unavailable.'}
    [pscustomobject]@{ComputerName=[Environment]::MachineName;UserSid=$identity.User.Value}
  } finally {$identity.Dispose()}
}

function Invoke-RideWinHttpProxyShow {
  $systemRoot=[Environment]::GetEnvironmentVariable('SystemRoot')
  if([string]::IsNullOrWhiteSpace($systemRoot)){throw 'SystemRoot is unavailable; refusing to resolve netsh by search path.'}
  $netshPath=Join-Path $systemRoot 'System32/netsh.exe'
  if(-not (Test-Path -LiteralPath $netshPath -PathType Leaf)){throw 'The system netsh executable was not found.'}
  $output=@(& $netshPath winhttp show advproxy 2>&1)
  $exitCode=$LASTEXITCODE
  $text=($output|ForEach-Object{[string]$_}) -join [Environment]::NewLine
  if($exitCode -ne 0){throw "netsh winhttp show advproxy failed with exit code $exitCode."}
  $text
}

function Get-RideWinHttpJsonObject {
  param([Parameter(Mandatory)][string]$Output)
  if($Output.Length -gt 65536 -or $Output.Contains([string][char]0)){throw 'WinHTTP command output is invalid or exceeds 64 KiB.'}
  $start=-1;$depth=0;$quoted=$false;$escaped=$false;$end=-1
  for($i=0;$i -lt $Output.Length;$i++){
    $character=$Output[$i]
    if($start -lt 0){if($character -eq '{'){$start=$i;$depth=1};continue}
    if($quoted){
      if($escaped){$escaped=$false;continue}
      if($character -eq '\'){$escaped=$true;continue}
      if($character -eq '"'){$quoted=$false}
      continue
    }
    if($character -eq '"'){$quoted=$true;continue}
    if($character -eq '{'){$depth++}
    elseif($character -eq '}'){$depth--;if($depth -eq 0){$end=$i;break}}
  }
  if($start -lt 0 -or $end -lt $start -or $quoted -or $depth -ne 0){throw 'WinHTTP command output does not contain one complete JSON object.'}
  if(-not [string]::IsNullOrWhiteSpace($Output.Substring($end+1))){throw 'WinHTTP command output contains trailing data after its JSON object.'}
  $json=$Output.Substring($start,$end-$start+1)
  try{$value=ConvertFrom-Json -InputObject $json -ErrorAction Stop}catch{throw 'WinHTTP advanced proxy output contains invalid JSON.'}
  if($null -eq $value -or $value -isnot [pscustomobject]){throw 'WinHTTP advanced proxy output must be a JSON object.'}
  $value
}

function Assert-RideWinHttpProxyString {
  param($Value,[string]$Name,[switch]$Optional)
  if($Optional -and $null -eq $Value){return}
  if($Value -isnot [string] -or $Value.Length -gt 32768 -or $Value.Contains([string][char]0)){throw "WinHTTP field '$Name' must be a string of at most 32768 characters without NUL."}
}

function ConvertFrom-RideWinHttpProxyOutput {
  <#
  .SYNOPSIS
    Parse and validate the JSON state reported by netsh winhttp show advproxy.
  .PARAMETER Output
    Complete command output. Text before or after the JSON object is ignored.
  .EXAMPLE
    $state = ConvertFrom-RideWinHttpProxyOutput -Output $capturedText
  .OUTPUTS
    Validated PSCustomObject with reported scope and literal field-presence data.
  .NOTES
    Missing optional strings remain distinguishable from reported empty strings.
    This parser does not infer disabled proxy strings or exact registry state.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Output)
  $json=Get-RideWinHttpJsonObject -Output $Output
  foreach($field in @('ProxyIsEnabled','AutoConfigIsEnabled','AutoDetect','PerUserProxySettings')){
    $property=$json.PSObject.Properties[$field]
    if($null -eq $property -or $property.Value -isnot [bool]){throw "WinHTTP field '$field' must be present as a JSON Boolean."}
  }
  $proxyProperty=$json.PSObject.Properties['Proxy']
  $bypassProperty=$json.PSObject.Properties['ProxyBypass']
  $urlProperty=$json.PSObject.Properties['AutoconfigUrl']
  if($null -ne $proxyProperty){Assert-RideWinHttpProxyString $proxyProperty.Value 'Proxy'}
  if($null -ne $bypassProperty){Assert-RideWinHttpProxyString $bypassProperty.Value 'ProxyBypass'}
  if($null -ne $urlProperty){Assert-RideWinHttpProxyString $urlProperty.Value 'AutoconfigUrl'}
  if($json.ProxyIsEnabled -and ($null -eq $proxyProperty -or [string]::IsNullOrWhiteSpace([string]$proxyProperty.Value))){throw 'WinHTTP reports an enabled proxy without a Proxy value.'}
  if($json.AutoConfigIsEnabled -and ($null -eq $urlProperty -or [string]::IsNullOrWhiteSpace([string]$urlProperty.Value))){throw 'WinHTTP reports an enabled automatic configuration without an AutoconfigUrl value.'}
  [pscustomobject]@{
    SchemaVersion=1;Kind='WinHttpProxyConfiguration';Status='Captured'
    Scope=$(if($json.PerUserProxySettings){'User'}else{'Machine'})
    ProxyIsEnabled=[bool]$json.ProxyIsEnabled
    Proxy=$(if($null -ne $proxyProperty){$proxyProperty.Value}else{$null})
    ProxyReported=($null -ne $proxyProperty)
    ProxyBypass=$(if($null -ne $bypassProperty){$bypassProperty.Value}else{$null})
    ProxyBypassReported=($null -ne $bypassProperty)
    AutoConfigIsEnabled=[bool]$json.AutoConfigIsEnabled
    AutoconfigUrl=$(if($null -ne $urlProperty){$urlProperty.Value}else{$null})
    AutoconfigUrlReported=($null -ne $urlProperty)
    AutoDetect=[bool]$json.AutoDetect
    PerUserProxySettings=[bool]$json.PerUserProxySettings
    ExactLiteralStateVerified=$false
    Limitation='Only fields reported by netsh are captured; disabled or omitted strings and underlying registry state are not inferred.'
  }
}

function Get-RideWinHttpProxyObservation {
  <#
  .SYNOPSIS
    Capture the current WinHTTP advanced proxy configuration without changing it.
  .DESCRIPTION
    Runs the system netsh executable with the fixed read-only `winhttp show advproxy`
    command and binds the result to the current computer and user SID.
  .EXAMPLE
    Get-RideWinHttpProxyObservation
  .OUTPUTS
    PSCustomObject. No file is written and no proxy state is changed.
  .NOTES
    The reported user/machine scope comes from PerUserProxySettings. The command
    does not establish which applications consume the configuration.
  #>
  [CmdletBinding()]
  param()
  $identity=Get-RideWinHttpProxyCurrentIdentity
  $reported=ConvertFrom-RideWinHttpProxyOutput -Output (Invoke-RideWinHttpProxyShow)
  $reported|Add-Member -NotePropertyName ComputerName -NotePropertyValue $identity.ComputerName
  $reported|Add-Member -NotePropertyName UserSid -NotePropertyValue $identity.UserSid
  $reported
}

Export-ModuleMember -Function ConvertFrom-RideWinHttpProxyOutput,Get-RideWinHttpProxyObservation
