<#
.SYNOPSIS
  Compare public IP addresses reported by DNS and HTTPS providers.

.DESCRIPTION
  Checks OpenDNS, Google DNS TXT and ipify for public addresses, and shows the
  local source address selected for an outbound route. The local route is not
  treated as a public-IP provider. Provider failures are reported without
  stopping other checks. DNS and HTTPS requests expose the caller's network
  egress to those providers; this script does not change Windows settings.

.PARAMETER IPv4
  Check IPv4 only. Cannot be combined with IPv6.

.PARAMETER IPv6
  Check IPv6 only. Cannot be combined with IPv4.

.PARAMETER Json
  Emit one JSON object instead of human-readable text.

.PARAMETER Quiet
  In text mode, print only resolved public addresses, one per enabled family.
  With Json, include only available public ipv4 and ipv6 keys.

.PARAMETER NoIpify
  Disable ipify HTTPS requests. Also accepts NoHttps and NoCurlFallback aliases.

.PARAMETER TimeoutSeconds
  HTTPS request timeout in seconds; defaults to 8. DNS uses Windows' quick
  timeout setting, which does not accept a numeric value.

.PARAMETER Help
  Show brief usage without making network requests.

.PARAMETER Version
  Show the script version without making network requests.

.EXAMPLE
  .\components\scripts\whatismyip.ps1

.EXAMPLE
  .\components\scripts\whatismyip.ps1 -IPv4 -Quiet

.EXAMPLE
  .\components\scripts\whatismyip.ps1 -IPv6 -Json -Debug

.EXAMPLE
  .\components\scripts\whatismyip.ps1 -NoIpify -Verbose

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Human-readable lines or one JSON object string.

.NOTES
  Compatibility: Intended for Windows PowerShell 5.1 and PowerShell 7 on Windows;
  native Windows acceptance remains pending.
  Prerequisites: Resolve-DnsName for DNS checks and Invoke-WebRequest for HTTPS.
  At least one public-IP method must be available and enabled.
  File/environment inputs: None. System DNS, network routing and HTTPS proxy
  settings affect the results.
  Recovery: No Windows state is changed.
  Adapted from whatismyip.sh by Torsten Juul-Jensen:
  https://github.com/tjuuljensen/linux-scripts/blob/master/whatismyip.sh
  Version: 0.1.0
  Changelog: 0.1.0: Initial Windows-focused PowerShell port.

.LINK
  https://github.com/tjuuljensen/linux-scripts/blob/master/whatismyip.sh
#>


[CmdletBinding()]
param(
    [switch]$IPv4,
    [switch]$IPv6,
    [switch]$Json,

    [Alias('q')]
    [switch]$Quiet,

    [Alias('NoHttps', 'NoCurlFallback')]
    [switch]$NoIpify,

    [Alias('Timeout')]
    [ValidateRange(1, 2147483647)]
    [int]$TimeoutSeconds = 8,

    [Alias('h')]
    [switch]$Help,

    [switch]$Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) {
    Write-Output @'
Usage: whatismyip.ps1 [-IPv4 | -IPv6] [-Json] [-Quiet] [-Debug]
                      [-Verbose] [-NoIpify] [-TimeoutSeconds <n>]
                      [-Help] [-Version]

Compare public IP addresses from DNS and HTTPS providers with the local route.
-Quiet prints only available public addresses. -Json -Quiet emits only available
ipv4/ipv6 keys; -Json -Debug includes provider statuses and warnings.
Use Get-Help .\components\scripts\whatismyip.ps1 -Full for details.
'@
    return
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($IPv4 -and $IPv6) { throw '-IPv4 and -IPv6 cannot be combined.' }
$checkIpv4 = -not $IPv6
$checkIpv6 = -not $IPv4
$diagnostic = ($PSBoundParameters.ContainsKey('Debug') -and [bool]$PSBoundParameters['Debug'])
$showProgress = -not $Json -and -not $Quiet -and (
    $diagnostic -or ($PSBoundParameters.ContainsKey('Verbose') -and [bool]$PSBoundParameters['Verbose'])
)
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$warnings = [Collections.Generic.List[string]]::new()

function Write-Diagnostic {
    param([string]$Message)
    if ($showProgress) { Write-Verbose -Message $Message -Verbose }
}

function Add-IpWarning {
    param([string]$Message)
    $warnings.Add($Message)
    if (-not $Json -and -not $Quiet) { Write-Warning $Message }
}

function Get-ValidIp {
    param([object[]]$Candidates, [Net.Sockets.AddressFamily]$Family)

    foreach ($candidate in $Candidates) {
        if ($null -eq $candidate) { continue }
        $text = ([string]$candidate).Trim().Trim('"')
        if ($Family -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            $text -notmatch '^([0-9]{1,3}\.){3}[0-9]{1,3}$') { continue }
        if ($Family -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            $text -notmatch ':') { continue }
        $parsed = $null
        if ([Net.IPAddress]::TryParse($text, [ref]$parsed) -and $parsed.AddressFamily -eq $Family) {
            return $parsed.ToString()
        }
    }
    return $null
}

function Get-DnsServerAddress {
    param([string]$Name, [Net.Sockets.AddressFamily]$Family)

    $type = if ($Family -eq [Net.Sockets.AddressFamily]::InterNetwork) { 'A' } else { 'AAAA' }
    try {
        $records = @(Resolve-DnsName -Name $Name -Type $type -DnsOnly -QuickTimeout -ErrorAction Stop)
        $addresses = @($records | ForEach-Object {
            if ($_.PSObject.Properties['IPAddress']) { $_.IPAddress }
        })
        return Get-ValidIp -Candidates $addresses -Family $Family
    } catch {
        Write-Diagnostic "Could not resolve DNS server $Name over $type."
        return $null
    }
}

function Get-DnsIp {
    param([string]$Name, [string]$Type, [string]$Server,
          [Net.Sockets.AddressFamily]$Family)

    try {
        $records = @(Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -QuickTimeout -ErrorAction Stop)
        $candidates = [Collections.Generic.List[object]]::new()
        foreach ($record in $records) {
            if ($Type -eq 'TXT') {
                if ($record.PSObject.Properties['Strings']) {
                    foreach ($part in @($record.Strings)) { $candidates.Add($part) }
                }
            } else {
                if ($record.PSObject.Properties['IPAddress']) { $candidates.Add($record.IPAddress) }
            }
        }
        return Get-ValidIp -Candidates $candidates.ToArray() -Family $Family
    } catch {
        Write-Diagnostic "DNS query failed: $Name ($Type) via $Server."
        return $null
    }
}

function Get-HttpsIp {
    param([string]$Uri, [Net.Sockets.AddressFamily]$Family)

    try {
        $response = Invoke-WebRequest -Uri $Uri -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        $firstLine = ([string]$response.Content -split '\r?\n', 2)[0]
        return Get-ValidIp -Candidates @($firstLine) -Family $Family
    } catch {
        Write-Diagnostic "HTTPS query failed: $Uri."
        return $null
    }
}

function Get-LocalRouteIp {
    param([Net.Sockets.AddressFamily]$Family, [string]$Destination)

    $socket = $null
    try {
        # Connecting a UDP socket selects a route and source address; no datagram is sent.
        $socket = [Net.Sockets.Socket]::new($Family, [Net.Sockets.SocketType]::Dgram,
            [Net.Sockets.ProtocolType]::Udp)
        $socket.Connect([Net.IPAddress]::Parse($Destination), 53)
        return Get-ValidIp -Candidates @($socket.LocalEndPoint.Address.ToString()) -Family $Family
    } catch {
        Write-Diagnostic "No usable local route for $Destination."
        return $null
    } finally {
        if ($socket) { $socket.Dispose() }
    }
}

function New-Provider {
    param([string]$Label)
    return [pscustomobject]@{ label = $Label; value = $null; status = 'not_run' }
}

function Set-Provider {
    param([psobject]$Provider, [string]$Value, [bool]$Enabled)
    if (-not $Enabled) { $Provider.status = 'skipped'; return }
    if ($Value) {
        $Provider.value = $Value
        $Provider.status = 'ok'
    } else {
        $Provider.status = 'unavailable'
    }
}

function New-FamilyResult {
    param([object[]]$PublicProviders, [psobject]$LocalRoute)

    $values = @($PublicProviders | Where-Object { $_.status -eq 'ok' } |
        ForEach-Object { $_.value } | Sort-Object -Unique)
    $providerCount = @($PublicProviders | Where-Object { $_.status -eq 'ok' }).Count
    $status = if ($providerCount -eq 0) { 'unavailable' }
        elseif ($providerCount -eq 1) { 'single_provider' }
        elseif ($values.Count -eq 1) { 'consistent' }
        else { 'provider_mismatch' }
    $consistent = if ($providerCount -lt 2) { $null } else { $status -eq 'consistent' }
    return [pscustomobject]@{
        public = $(if ($values.Count) { $values[0] } else { $null })
        values = $values
        providerCount = $providerCount
        status = $status
        consistent = $consistent
        localRoute = $LocalRoute
    }
}

function Get-DisplayValue {
    param([psobject]$Provider)
    if ($Provider.value) { return $Provider.value }
    return $Provider.status
}

function New-ResultJsonFamily {
    param([psobject]$Family, [System.Collections.IDictionary]$Providers)
    $providerValues = [ordered]@{}
    foreach ($name in $Providers.Keys) { $providerValues[$name] = $Providers[$name].value }
    return [ordered]@{
        public = $Family.public
        values = @($Family.values)
        providers = $providerValues
        providerCount = $Family.providerCount
        status = $Family.status
        consistent = $Family.consistent
    }
}

function New-DebugJsonFamily {
    param([psobject]$Family, [System.Collections.IDictionary]$Providers)
    $providerDetails = [ordered]@{}
    foreach ($name in $Providers.Keys) {
        $provider = $Providers[$name]
        $providerDetails[$name] = [ordered]@{
            label = $provider.label
            value = $provider.value
            status = $provider.status
        }
    }
    return [ordered]@{
        public = $Family.public
        values = @($Family.values)
        providers = $providerDetails
        providerCount = $Family.providerCount
        status = $Family.status
        consistent = $Family.consistent
    }
}

$dnsAvailable = $null -ne (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
$httpsAvailable = -not $NoIpify -and $null -ne (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)
if (-not $dnsAvailable) { Add-IpWarning 'Resolve-DnsName is unavailable; DNS providers skipped.' }
if (-not $NoIpify -and -not $httpsAvailable) { Add-IpWarning 'Invoke-WebRequest is unavailable; ipify HTTPS provider skipped.' }
if (-not $dnsAvailable -and -not $httpsAvailable) {
    throw 'No public-IP provider is available. Enable HTTPS or run on Windows with Resolve-DnsName.'
}

$ipv4Providers = [ordered]@{
    openDns = New-Provider 'OpenDNS'
    googleDnsTxt = New-Provider 'Google DNS TXT'
    ipifyHttps = New-Provider 'ipify HTTPS'
    localRoute = New-Provider 'Local route'
}
$ipv6Providers = [ordered]@{
    googleDnsTxt = New-Provider 'Google DNS TXT'
    ipifyHttps = New-Provider 'ipify HTTPS'
    localRoute = New-Provider 'Local route'
}

if ($checkIpv4) {
    if ($dnsAvailable) {
        Write-Diagnostic 'Querying IPv4 via OpenDNS.'
        $openDnsServer = Get-DnsServerAddress -Name 'resolver1.opendns.com' -Family InterNetwork
        if (-not $openDnsServer) { $openDnsServer = 'resolver1.opendns.com' }
        $value = Get-DnsIp -Name 'myip.opendns.com' -Type A -Server $openDnsServer -Family InterNetwork
        Set-Provider $ipv4Providers.openDns $value $true

        Write-Diagnostic 'Querying IPv4 via Google DNS TXT.'
        $google4Server = Get-DnsServerAddress -Name 'ns1.google.com' -Family InterNetwork
        if (-not $google4Server) { $google4Server = 'ns1.google.com' }
        $value = Get-DnsIp -Name 'o-o.myaddr.l.google.com' -Type TXT -Server $google4Server -Family InterNetwork
        Set-Provider $ipv4Providers.googleDnsTxt $value $true
    } else {
        Set-Provider $ipv4Providers.openDns $null $false
        Set-Provider $ipv4Providers.googleDnsTxt $null $false
    }

    if ($httpsAvailable) {
        Write-Diagnostic 'Querying IPv4 via ipify HTTPS.'
        $value = Get-HttpsIp -Uri 'https://api.ipify.org' -Family InterNetwork
        Set-Provider $ipv4Providers.ipifyHttps $value $true
    } else {
        Set-Provider $ipv4Providers.ipifyHttps $null $false
    }
    Write-Diagnostic 'Inspecting the IPv4 local route source.'
    Set-Provider $ipv4Providers.localRoute (Get-LocalRouteIp -Family InterNetwork -Destination '1.1.1.1') $true
}

if ($checkIpv6) {
    if ($dnsAvailable) {
        Write-Diagnostic 'Querying IPv6 via Google DNS TXT.'
        $google6Server = Get-DnsServerAddress -Name 'ns1.google.com' -Family InterNetworkV6
        $value = $null
        if ($google6Server) {
            $value = Get-DnsIp -Name 'o-o.myaddr.l.google.com' -Type TXT -Server $google6Server -Family InterNetworkV6
        }
        if (-not $value) {
            $value = Get-DnsIp -Name 'o-o.myaddr.l.google.com' -Type TXT -Server 'ns1.google.com' -Family InterNetworkV6
        }
        Set-Provider $ipv6Providers.googleDnsTxt $value $true
    } else {
        Set-Provider $ipv6Providers.googleDnsTxt $null $false
    }

    if ($httpsAvailable) {
        Write-Diagnostic 'Querying IPv6 via ipify HTTPS.'
        $value = Get-HttpsIp -Uri 'https://api6.ipify.org' -Family InterNetworkV6
        if (-not $value) { $value = Get-HttpsIp -Uri 'https://api64.ipify.org' -Family InterNetworkV6 }
        Set-Provider $ipv6Providers.ipifyHttps $value $true
    } else {
        Set-Provider $ipv6Providers.ipifyHttps $null $false
    }
    Write-Diagnostic 'Inspecting the IPv6 local route source.'
    Set-Provider $ipv6Providers.localRoute (Get-LocalRouteIp -Family InterNetworkV6 -Destination '2001:4860:4860::8888') $true
}

$ipv4Result = $null
$ipv6Result = $null
if ($checkIpv4) {
    $ipv4Result = New-FamilyResult -PublicProviders @($ipv4Providers.openDns, $ipv4Providers.googleDnsTxt,
        $ipv4Providers.ipifyHttps) -LocalRoute $ipv4Providers.localRoute
    if ($ipv4Result.status -eq 'provider_mismatch') { Add-IpWarning 'IPv4 providers disagree.' }
    if ($ipv4Result.status -eq 'unavailable') { Add-IpWarning 'No public IPv4 address could be determined.' }
}
if ($checkIpv6) {
    $ipv6Result = New-FamilyResult -PublicProviders @($ipv6Providers.googleDnsTxt,
        $ipv6Providers.ipifyHttps) -LocalRoute $ipv6Providers.localRoute
    if ($ipv6Result.status -eq 'provider_mismatch') { Add-IpWarning 'IPv6 providers disagree.' }
    if ($ipv6Result.status -eq 'unavailable') { Add-IpWarning 'No public IPv6 address could be determined.' }
}

if ($Json) {
    $output = [ordered]@{}
    if ($Quiet) {
        if ($checkIpv4 -and $ipv4Result.public) { $output.ipv4 = $ipv4Result.public }
        if ($checkIpv6 -and $ipv6Result.public) { $output.ipv6 = $ipv6Result.public }
    } else {
        if ($diagnostic) {
            $output.script = [ordered]@{ name = 'whatismyip.ps1'; version = $script:ScriptVersion }
            $output.options = [ordered]@{
                checkIpv4 = $checkIpv4
                checkIpv6 = $checkIpv6
                useIpify = $httpsAvailable
                quiet = [bool]$Quiet
                verbose = ($PSBoundParameters.ContainsKey('Verbose') -and [bool]$PSBoundParameters['Verbose'])
                debug = $diagnostic
                timeoutSeconds = $TimeoutSeconds
            }
        }
        if ($checkIpv4) {
            if ($diagnostic) { $output.ipv4 = New-DebugJsonFamily $ipv4Result $ipv4Providers }
            else { $output.ipv4 = New-ResultJsonFamily $ipv4Result $ipv4Providers }
        }
        if ($checkIpv6) {
            if ($diagnostic) { $output.ipv6 = New-DebugJsonFamily $ipv6Result $ipv6Providers }
            else { $output.ipv6 = New-ResultJsonFamily $ipv6Result $ipv6Providers }
        }
        if ($diagnostic) { $output.warnings = @($warnings.ToArray()) }
    }
    Write-Output (ConvertTo-Json -InputObject $output -Depth 10)
    return
}

if ($Quiet) {
    if ($checkIpv4 -and $ipv4Result.public) { Write-Output $ipv4Result.public }
    if ($checkIpv6 -and $ipv6Result.public) { Write-Output $ipv6Result.public }
    return
}

if ($checkIpv4) {
    Write-Output 'IPv4'
    Write-Output '===='
    Write-Output "  OpenDNS:         $(Get-DisplayValue $ipv4Providers.openDns)"
    Write-Output "  Google DNS TXT:  $(Get-DisplayValue $ipv4Providers.googleDnsTxt)"
    Write-Output "  ipify HTTPS:     $(Get-DisplayValue $ipv4Providers.ipifyHttps)"
    Write-Output "  Local route:     $(Get-DisplayValue $ipv4Providers.localRoute)"
    Write-Output ''
    $public = if ($ipv4Result.public) { $ipv4Result.public } else { 'unavailable' }
    Write-Output "  Public IPv4:     $public"
    Write-Output "  Status:          $($ipv4Result.status.Replace('_', ' '))"
    Write-Output ''
}
if ($checkIpv6) {
    Write-Output 'IPv6'
    Write-Output '===='
    Write-Output "  Google DNS TXT:  $(Get-DisplayValue $ipv6Providers.googleDnsTxt)"
    Write-Output "  ipify HTTPS:     $(Get-DisplayValue $ipv6Providers.ipifyHttps)"
    Write-Output "  Local route:     $(Get-DisplayValue $ipv6Providers.localRoute)"
    Write-Output ''
    $public = if ($ipv6Result.public) { $ipv6Result.public } else { 'unavailable' }
    Write-Output "  Public IPv6:     $public"
    Write-Output "  Status:          $($ipv6Result.status.Replace('_', ' '))"
    Write-Output ''
}
