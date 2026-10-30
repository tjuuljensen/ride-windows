<#
.SYNOPSIS
  Look up IEEE MAC address registry assignees from a local cache.

.DESCRIPTION
  Downloads the public MA-L, MA-M, MA-S and IAB registries when the cache is
  missing or older than MaxAgeDays, then uses the longest matching prefix.
  Accepts positional addresses, PowerShell pipeline input or an interactive
  prompt. Lookups stay local; queried addresses are never sent to a lookup API.
  Update changes only files in CacheDir and supports -WhatIf.

.PARAMETER Addresses
  MAC addresses or prefixes. Formats include colon, hyphen, dotted and bare
  hexadecimal text. At least six and at most twelve hex digits are required.

.PARAMETER Quiet
  Print only the assignee name, or Unknown. With Json, emit only the
  organization property for each query.

.PARAMETER Update
  Force a download of all four registries before looking up addresses.

.PARAMETER Offline
  Never download; require an existing nonempty cache. Cannot be used with Update.

.PARAMETER Json
  Emit one JSON array instead of human-readable lines.

.PARAMETER ShowAddress
  Include the registry address in normal text output when available.

.PARAMETER CacheDir
  Directory for ieee-mac-vendors.tsv and metadata.json. Defaults to
  %LOCALAPPDATA%\mac-vendor on Windows (or the platform's local app data folder).

.PARAMETER MaxAgeDays
  Cache freshness threshold in days; defaults to 7. Zero refreshes on every
  online invocation.

.PARAMETER TimeoutSeconds
  Timeout for each registry download in seconds; defaults to 30.

.PARAMETER Help
  Show brief usage without reading the cache or contacting IEEE.

.PARAMETER Version
  Show the script version without reading the cache or contacting IEEE.

.EXAMPLE
  .\components\scripts\mac-vendor.ps1 00:1A:2B:33:44:55

.EXAMPLE
  '00:1A:2B:33:44:55', '3C:52:82:AA:BB:CC' | .\components\scripts\mac-vendor.ps1 -Offline

.EXAMPLE
  .\components\scripts\mac-vendor.ps1 -Update -WhatIf

.EXAMPLE
  .\components\scripts\mac-vendor.ps1 -Quiet -Json 00-1A-2B

.INPUTS
  System.String. One MAC address or prefix per pipeline item.

.OUTPUTS
  System.String. Human-readable lines or a single JSON array string.

.NOTES
  Compatibility: Intended for Windows PowerShell 5.1 and PowerShell 7 on Windows;
  native Windows acceptance remains pending.
  Prerequisites: HTTPS access to standards-oui.ieee.org for downloads. Offline
  lookup needs only a previously populated cache.
  File/environment inputs: Reads and writes ieee-mac-vendors.tsv and
  metadata.json in CacheDir; uses LOCALAPPDATA for the Windows default.
  Recovery: Delete or replace only this tool's cache files to rebuild or restore
  the cache. A failed download or parse leaves the previous cache in place.
  Adapted from mac-vendor.sh by Torsten Juul-Jensen:
  https://github.com/tjuuljensen/linux-scripts/blob/master/mac-vendor.sh
  Version: 0.1.0
  Changelog: 0.1.0: Initial Windows-focused PowerShell port.

.LINK
  https://github.com/tjuuljensen/linux-scripts/blob/master/mac-vendor.sh
#>


[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromRemainingArguments = $true)]
    [Alias('Address', 'MacAddress')]
    [string[]]$Addresses,

    [Alias('s')]
    [switch]$Quiet,

    [Alias('u')]
    [switch]$Update,

    [switch]$Offline,
    [switch]$Json,
    [switch]$ShowAddress,

    [ValidateNotNullOrEmpty()]
    [string]$CacheDir,

    [ValidateRange(0, 2147483647)]
    [int]$MaxAgeDays = 7,

    [ValidateRange(1, 2147483647)]
    [int]$TimeoutSeconds = 30,

    [Alias('h')]
    [switch]$Help,

    [switch]$Version
)

begin {
    $script:ScriptVersion = '0.1.0'
    Set-StrictMode -Version 2.0
    $ErrorActionPreference = 'Stop'
    $queries = [Collections.Generic.List[string]]::new()

    function New-RegistryParser {
        param([string]$Path, [string]$Delimiter)

        $parser = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($Path, [Text.Encoding]::UTF8)
        $parser.SetDelimiters($Delimiter)
        $parser.HasFieldsEnclosedInQuotes = $true
        $parser.TrimWhiteSpace = $false
        return $parser
    }

    function Get-RowField {
        param([string[]]$Row, [hashtable]$Columns, [string[]]$Names)

        foreach ($name in $Names) {
            if ($Columns.ContainsKey($name)) {
                $index = $Columns[$name]
                if ($index -lt $Row.Count) { return $Row[$index].Trim() }
                return ''
            }
        }
        return ''
    }

    function Get-Columns {
        param([string[]]$Header)

        $columns = @{}
        for ($index = 0; $index -lt $Header.Count; $index++) {
            $columns[$Header[$index].Trim()] = $index
        }
        return $columns
    }

    function ConvertTo-TsvField {
        param([string]$Value)

        if ($Value -match '[\t\r\n"]') {
            return '"' + $Value.Replace('"', '""') + '"'
        }
        return $Value
    }

    function Move-CacheFile {
        param([string]$Source, [string]$Destination)

        if ([IO.File]::Exists($Destination)) {
            [IO.File]::Replace($Source, $Destination, $null)
        } else {
            [IO.File]::Move($Source, $Destination)
        }
    }

    function Update-VendorCache {
        param([string]$Directory, [string]$CacheFile, [string]$MetadataFile)

        [void][IO.Directory]::CreateDirectory($Directory)
        $temporaryDirectory = Join-Path $Directory ('.mac-vendor.' + [guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($temporaryDirectory)
        $registries = @(
            @{ Name = 'MA-L'; Bits = 24; Url = 'https://standards-oui.ieee.org/oui/oui.csv' },
            @{ Name = 'MA-M'; Bits = 28; Url = 'https://standards-oui.ieee.org/oui28/mam.csv' },
            @{ Name = 'MA-S'; Bits = 36; Url = 'https://standards-oui.ieee.org/oui36/oui36.csv' },
            @{ Name = 'IAB'; Bits = 36; Url = 'https://standards-oui.ieee.org/iab/iab.csv' }
        )
        $rows = [Collections.Generic.List[object]]::new()
        $recordCount = 0

        try {
            foreach ($registry in $registries) {
                $download = Join-Path $temporaryDirectory ($registry.Name + '.csv')
                if (-not $Quiet) { Write-Information "Downloading $($registry.Name): $($registry.Url)" -InformationAction Continue }
                Invoke-WebRequest -Uri $registry.Url -OutFile $download -TimeoutSec $TimeoutSeconds -UseBasicParsing |
                    Out-Null

                $parser = New-RegistryParser -Path $download -Delimiter ','
                try {
                    if ($parser.EndOfData) { throw "$($registry.Name): CSV has no header row." }
                    $columns = Get-Columns -Header $parser.ReadFields()
                    $count = 0
                    while (-not $parser.EndOfData) {
                        $row = $parser.ReadFields()
                        $prefix = [regex]::Replace((Get-RowField $row $columns @('Assignment')), '[^0-9A-Fa-f]', '').ToUpperInvariant()
                        $organization = Get-RowField $row $columns @('Organization Name', 'Organization', 'Company Name')
                        $address = Get-RowField $row $columns @('Organization Address', 'Address')
                        if ($prefix.Length -lt ($registry.Bits / 4) -or -not $organization) { continue }
                        $rows.Add([pscustomobject]@{
                            Prefix = $prefix.Substring(0, ($registry.Bits / 4))
                            Bits = $registry.Bits
                            Registry = $registry.Name
                            Organization = $organization
                            Address = $address
                        })
                        $count++
                    }
                    $recordCount += $count
                    if (-not $Quiet) { Write-Information "  $count records" -InformationAction Continue }
                } finally {
                    $parser.Close()
                }
            }

            if ($recordCount -eq 0) { throw 'IEEE registries contained no usable assignments.' }
            $newCache = Join-Path $temporaryDirectory 'ieee-mac-vendors.tsv'
            $writer = [IO.StreamWriter]::new($newCache, $false, [Text.UTF8Encoding]::new($false))
            try {
                $writer.WriteLine("prefix`tbits`tregistry`torganization`taddress")
                foreach ($row in ($rows | Sort-Object Prefix, @{ Expression = 'Bits'; Descending = $true }, Registry, Organization, Address)) {
                    $fields = @(
                        $row.Prefix, [string]$row.Bits, $row.Registry,
                        (ConvertTo-TsvField $row.Organization), (ConvertTo-TsvField $row.Address)
                    )
                    $writer.WriteLine(($fields -join "`t"))
                }
            } finally {
                $writer.Dispose()
            }

            $metadata = [ordered]@{
                tool = 'mac-vendor.ps1'
                tool_version = $script:ScriptVersion
                updated_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss+00:00')
                registries = @($registries | ForEach-Object {
                    [ordered]@{ name = $_.Name; bits = $_.Bits; url = $_.Url }
                })
                record_count = $recordCount
            }
            $newMetadata = Join-Path $temporaryDirectory 'metadata.json'
            [IO.File]::WriteAllText($newMetadata, ($metadata | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
            Move-CacheFile -Source $newCache -Destination $CacheFile
            Move-CacheFile -Source $newMetadata -Destination $MetadataFile
            if (-not $Quiet) { Write-Information "Cache updated: $CacheFile" -InformationAction Continue }
        } finally {
            Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    function Read-VendorCache {
        param([string]$Path)

        $vendors = @{}
        $parser = New-RegistryParser -Path $Path -Delimiter "`t"
        try {
            if ($parser.EndOfData) { return $vendors }
            $columns = Get-Columns -Header $parser.ReadFields()
            while (-not $parser.EndOfData) {
                $row = $parser.ReadFields()
                $prefix = (Get-RowField $row $columns @('prefix')).ToUpperInvariant()
                $bitsText = Get-RowField $row $columns @('bits')
                $organization = Get-RowField $row $columns @('organization')
                if ($bitsText -notmatch '^(24|28|36)$' -or -not $organization) { continue }
                $bits = [int]$bitsText
                if ($prefix -notmatch ('^[0-9A-F]{' + ($bits / 4) + '}$')) { continue }
                $key = "$bits/$prefix"
                if (-not $vendors.ContainsKey($key)) {
                    $vendors[$key] = [pscustomobject]@{
                        Prefix = $prefix
                        Bits = $bits
                        Registry = Get-RowField $row $columns @('registry')
                        Organization = $organization
                        Address = Get-RowField $row $columns @('address')
                    }
                }
            }
        } finally {
            $parser.Close()
        }
        return $vendors
    }

    function Resolve-Vendor {
        param([string]$Query, [hashtable]$Vendors)

        $normalized = [regex]::Replace($Query, '[^0-9A-Fa-f]', '').ToUpperInvariant()
        if ($normalized.Length -lt 6) { throw "MAC address/prefix is too short: '$Query'" }
        if ($normalized.Length -gt 12) { throw "MAC address/prefix is too long: '$Query'" }
        $firstOctet = [Convert]::ToInt32($normalized.Substring(0, 2), 16)
        $match = $null
        foreach ($bits in @(36, 28, 24)) {
            $length = $bits / 4
            if ($normalized.Length -lt $length) { continue }
            $key = "$bits/$($normalized.Substring(0, $length))"
            if ($Vendors.ContainsKey($key)) { $match = $Vendors[$key]; break }
        }
        return [pscustomobject]@{
            query = $Query
            normalized = $normalized
            prefix = $(if ($match) { $match.Prefix } else { $null })
            bits = $(if ($match) { $match.Bits } else { $null })
            registry = $(if ($match) { $match.Registry } else { $null })
            organization = $(if ($match) { $match.Organization } else { $null })
            address = $(if ($match) { $match.Address } else { $null })
            locally_administered = (($firstOctet -band 2) -ne 0)
            multicast = (($firstOctet -band 1) -ne 0)
        }
    }
}

process {
    foreach ($address in $Addresses) { $queries.Add($address) }
}

end {
    if ($Version) { Write-Output $script:ScriptVersion; return }
    if ($Help) {
        Write-Output @'
Usage: mac-vendor.ps1 [addresses ...] [-Quiet] [-Update] [-Offline] [-Json]
                      [-ShowAddress] [-CacheDir <directory>] [-MaxAgeDays <n>]
                      [-TimeoutSeconds <n>] [-WhatIf] [-Help] [-Version]

Look up IEEE MAC/OUI vendor assignments from a local cache. Input may be
positional, piped, or prompted. -Update and -Offline cannot be combined.
Use Get-Help .\components\scripts\mac-vendor.ps1 -Full for details.
'@
        return
    }
    if ($Offline -and $Update) { throw '-Update and -Offline cannot be combined.' }
    Add-Type -AssemblyName Microsoft.VisualBasic

    if (-not $CacheDir) {
        $baseDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if ($env:LOCALAPPDATA) { $baseDirectory = $env:LOCALAPPDATA }
        if (-not $baseDirectory) { throw 'Cannot determine a local cache directory; use -CacheDir.' }
        $CacheDir = Join-Path $baseDirectory 'mac-vendor'
    }
    $CacheDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CacheDir)
    $cacheFile = Join-Path $CacheDir 'ieee-mac-vendors.tsv'
    $metadataFile = Join-Path $CacheDir 'metadata.json'
    $cacheExists = [IO.File]::Exists($cacheFile) -and ((Get-Item -LiteralPath $cacheFile).Length -gt 0)
    $isFresh = $false
    if ($cacheExists) {
        $cacheAge = [DateTime]::UtcNow - [IO.File]::GetLastWriteTimeUtc($cacheFile)
        $isFresh = ($cacheAge.TotalDays -le $MaxAgeDays)
    }

    if ($Update -or (-not $Offline -and -not $isFresh)) {
        if ($PSCmdlet.ShouldProcess($cacheFile, 'Download and replace IEEE MAC registry cache')) {
            Update-VendorCache -Directory $CacheDir -CacheFile $cacheFile -MetadataFile $metadataFile
            $cacheExists = $true
        } elseif (-not $cacheExists) {
            return
        }
    }
    if (-not $cacheExists) { throw "Vendor cache does not exist or is empty: $cacheFile" }
    if ($Update -and $queries.Count -eq 0 -and -not $MyInvocation.ExpectingInput) { return }

    if ($queries.Count -eq 0) {
        if ($MyInvocation.ExpectingInput) { throw 'No MAC addresses were supplied on the pipeline.' }
        $prompted = Read-Host 'MAC address or prefix'
        if (-not [string]::IsNullOrWhiteSpace($prompted)) { $queries.Add($prompted.Trim()) }
    }
    $results = [Collections.Generic.List[object]]::new()
    $vendors = Read-VendorCache -Path $cacheFile
    foreach ($query in $queries) {
        if ([string]::IsNullOrWhiteSpace($query)) { continue }
        $results.Add((Resolve-Vendor -Query $query.Trim() -Vendors $vendors))
    }
    if ($results.Count -eq 0) { throw 'No MAC addresses were supplied.' }

    if ($Json) {
        if ($Quiet) {
            $outputRows = @($results | ForEach-Object { [pscustomobject]@{ organization = $_.organization } })
        } else {
            $outputRows = $results.ToArray()
        }
        Write-Output (ConvertTo-Json -InputObject $outputRows -Depth 4)
        return
    }
    foreach ($result in $results) {
        if ($Quiet) {
            if ($result.organization) { Write-Output $result.organization } else { Write-Output 'Unknown' }
            continue
        }
        if ($result.organization) {
            Write-Output "$($result.query) -> $($result.organization) [$($result.registry), $($result.prefix)/$($result.bits)]"
            if ($ShowAddress -and $result.address) { Write-Output "  $($result.address)" }
        } else {
            Write-Output "$($result.query) -> Unknown"
        }
        if ($result.locally_administered) {
            Write-Output '  Note: locally administered/randomized MAC; vendor lookup may be meaningless.'
        }
        if ($result.multicast) {
            Write-Output '  Note: multicast/group MAC; vendor lookup may be meaningless.'
        }
    }
}
