<#
.SYNOPSIS
  Inspect installer bytes and bounded ZIP members without executing payloads.
.DESCRIPTION
  Reads file headers, version resources and hashes. Optional HTTPS sample downloads
  use temporary files and publisher-origin referrers. ZIP extraction selects one
  declared self-contained installer, never expands an entire archive.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: HTTPS access for URL inspection; writable temporary directory.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add bounded sample inspection and single-member extraction.
#>


function Test-RideInstallerEntryName {
  param([string] $Name)
  $Name -and $Name.Length -le 240 -and $Name -notmatch '[\\\x00-\x1f:"*?<>|]' -and
    $Name -notmatch '^/|(^|/)\.{1,2}(/|$)|[. ](/|$)' -and $Name -notmatch '//|/$' -and
    $Name -match '\.(exe|msi)$'
}

function Expand-RideInstallerEntry {
  <#
  .SYNOPSIS
    Copy one declared ZIP installer to a new file.
  .DESCRIPTION
    Rejects unsafe paths, duplicate names, links and oversized archives. Extracts
    only the exact member; accompanying files remain in the retained ZIP.
  .PARAMETER Path
    ZIP file. At most 256 MiB, 128 entries and 1 GiB declared expanded content.
  .PARAMETER Entry
    Exact case-sensitive relative ZIP path with forward slashes, ending exe or msi.
  .PARAMETER Destination
    New output file with an existing parent. Never overwrites.
  .EXAMPLE
    Expand-RideInstallerEntry -Path .\setup.zip -Entry 'setup.exe' -Destination .\scratch\setup.exe
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Installer member limit: 512 MiB. WhatIf writes no output. Entry completes from
    the selected ZIP without extraction. No payload execution. Module version 0.1.0.
  #>
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $Entry, [Parameter(Mandatory)][string] $Destination)
  if (-not (Test-RideInstallerEntryName $Entry)) { throw 'Unsafe ZIP InstallerEntry; use a relative EXE/MSI member path with forward slashes.' }
  if (-not $PSCmdlet.ShouldProcess($Destination, "Extract declared ZIP installer '$Entry'")) { return }
  if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 256MB) { throw 'ZIP exceeds the 256 MiB limit.' }
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [IO.Compression.ZipFile]::OpenRead($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
  try {
    if ($archive.Entries.Count -gt 128 -or ($archive.Entries | Measure-Object Length -Sum).Sum -gt 1GB) { throw 'ZIP exceeds entry-count or expanded-size limits.' }
    $members = @($archive.Entries | Where-Object { $_.FullName -ieq $Entry })
    if ($members.Count -ne 1 -or $members[0].FullName -cne $Entry) { throw 'ZIP must contain exactly one member matching InstallerEntry, including case.' }
    $member = $members[0]
    if (($member.ExternalAttributes -shr 16 -band 0xF000) -eq 0xA000 -or $member.Length -gt 512MB) { throw 'ZIP installer is a link or exceeds the 512 MiB member limit.' }
    $target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
    $source = $member.Open(); $output = $null
    try {
      $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
      $buffer = New-Object byte[] 65536; $total = 0L
      while (($count = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $total += $count
        if ($total -gt 512MB -or $total -gt $member.Length) { throw 'ZIP member exceeds its declared size.' }
        $output.Write($buffer, 0, $count)
      }
      if ($total -ne $member.Length) { throw 'ZIP member is truncated.' }
    } finally { $source.Dispose(); if ($output) { $output.Dispose() } }
  } finally { $archive.Dispose() }
}

function Get-RideInstallerFileDetails {
  param([string] $Path)
  $stream = [IO.File]::OpenRead($Path); $reader = New-Object IO.BinaryReader($stream)
  $type = ''; $architecture = ''
  try {
    if ($stream.Length -lt 8 -or $stream.Length -gt 512MB) { throw 'Sample is empty, truncated or oversized.' }
    $magic = $reader.ReadBytes(8)
    if ($magic[0] -eq 0x4D -and $magic[1] -eq 0x5A) {
      if ($stream.Length -lt 64) { throw 'Invalid PE header.' }
      $stream.Position = 60; $offset = $reader.ReadInt32()
      if ($offset -lt 64 -or $offset -gt $stream.Length - 6) { throw 'Invalid PE header offset.' }
      $stream.Position = $offset
      if ($reader.ReadUInt32() -ne 0x4550) { throw 'Invalid PE signature.' }
      $architecture = switch ($reader.ReadUInt16()) { 0x14c { 'x86' } 0x8664 { 'x64' } 0xaa64 { 'arm64' } default { 'Unknown' } }
      $type = 'Exe'
    } elseif ([BitConverter]::ToString($magic) -eq 'D0-CF-11-E0-A1-B1-1A-E1' -and [IO.Path]::GetExtension($Path) -eq '.msi') { $type = 'Msi' }
    else { throw 'Sample content is not a supported PE EXE or MSI container.' }
  } finally { $reader.Dispose() }
  $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
  [pscustomobject]@{
    InstallerType = $type; BinaryArchitecture = $architecture
    ProductName = ([string]$version.ProductName).Trim()
    ProductVersion = ([string]$version.ProductVersion).Trim()
    Sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  }
}

function Invoke-RideInspectionDownload {
  param([string] $Uri, [string] $Destination)
  $current = [uri]$Uri; $clock = [Diagnostics.Stopwatch]::StartNew()
  for ($redirect = 0; $redirect -le 5; $redirect++) {
    if ($current.Scheme -ne 'https' -or -not $current.IsDefaultPort -or $current.UserInfo -or $current.Fragment) { throw 'Inspection requires default-port HTTPS without credentials or fragments, including redirects.' }
    $request = [Net.HttpWebRequest]::Create($current)
    $request.AllowAutoRedirect = $false; $request.Timeout = 30000; $request.ReadWriteTimeout = 30000
    $request.UserAgent = 'Mozilla/5.0 RIDE-InstallerInspection/0.1'
    $request.Referer = $current.GetLeftPart([UriPartial]::Authority) + '/'
    $response = $request.GetResponse()
    try {
      if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
        if ($redirect -eq 5) { throw 'Too many download redirects.' }
        $current = New-Object uri($current, $response.Headers['Location']); continue
      }
      if ($response.ContentLength -gt 256MB) { throw 'Sample exceeds the 256 MiB download limit.' }
      $source = $response.GetResponseStream(); $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew)
      try {
        $buffer = New-Object byte[] 65536; $total = 0L
        while (($count = $source.Read($buffer, 0, $buffer.Length)) -gt 0) {
          $total += $count
          if ($total -gt 256MB -or $clock.Elapsed.TotalSeconds -gt 120) { throw 'Sample exceeds the download size/time limit.' }
          $output.Write($buffer, 0, $count)
        }
      } finally { $source.Dispose(); $output.Dispose() }
      return
    } finally { $response.Dispose() }
  }
}

function Get-RideInstallerInspection {
  <#
  .SYNOPSIS
    Inspect a local or HTTPS sample before entering package metadata.
  .DESCRIPTION
    Uses content headers, version resources and SHA-256. Lists ZIP EXE/MSI candidates
    and inspects only a unique candidate or the explicitly selected member. Never
    runs an installer. Suggestions require operator review; binary architecture
    describes the launcher, not payload compatibility. Temporary files are removed.
  .PARAMETER Path
    Existing local EXE, MSI or ZIP, at most 256 MiB. Not modified.
  .PARAMETER Uri
    Optional HTTPS sample URL; downloads at most 256 MiB within bounded time.
  .PARAMETER InstallerEntry
    Exact ZIP member to inspect when several installers exist.
  .EXAMPLE
    Get-RideInstallerInspection -Path .\setup.zip
  .EXAMPLE
    Get-RideInstallerInspection -Uri 'https://publisher.example/setup.zip'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Archive type, candidate paths, resource hints and separate hashes.
  .NOTES
    WhatIf prevents downloads and temporary extraction. Version 0.1.0.
  #>
  [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Path')]
  param(
    [Parameter(Mandatory, ParameterSetName = 'Path')][string] $Path,
    [Parameter(Mandatory, ParameterSetName = 'Uri')][string] $Uri,
    [ArgumentCompleter({
      param($commandName, $parameterName, $wordToComplete, $commandAst, $boundParameters)
      try {
        if (-not $boundParameters.Path) { return }
        $file = Get-Item -LiteralPath $boundParameters.Path -ErrorAction Stop
        if ($file.PSIsContainer -or $file.Length -gt 256MB) { return }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($file.FullName)
        try {
          if ($zip.Entries.Count -gt 128) { return }
          $prefix = $wordToComplete.Trim("'", '"')
          $zip.Entries | Where-Object { $_.FullName -match '\.(exe|msi)$' -and $_.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object FullName | Sort-Object -Unique | ForEach-Object {
              [Management.Automation.CompletionResult]::new(("'" + $_.Replace("'", "''") + "'"), $_, 'ParameterValue', $_)
            }
        } finally { $zip.Dispose() }
      } catch { return }
    })]
    [string] $InstallerEntry = ''
  )
  $ErrorActionPreference = 'Stop'
  if (-not $PSCmdlet.ShouldProcess($(if ($Uri) { $Uri } else { $Path }), 'Inspect installer sample without execution; use temporary files')) { return }
  $scratch = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Inspect-' + [guid]::NewGuid().ToString('N'))
  $scratch = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($scratch)
  $null = [IO.Directory]::CreateDirectory($scratch)
  try {
    $name = if ($Uri) { [IO.Path]::GetFileName(([uri]$Uri).AbsolutePath) } else { (Get-Item -LiteralPath $Path).Name }
    if ($Uri) {
      $Path = Join-Path $scratch $(if ($name -match '\.msi$') { 'sample.msi' } else { 'sample.bin' })
      Invoke-RideInspectionDownload -Uri $Uri -Destination $Path
    }
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt 256MB) { throw 'Sample must be a file of at most 256 MiB.' }
    $result = [ordered]@{ SourceUri = $Uri; AssetName = $name; ArchiveType = 'None'; InstallerEntry = ''; Candidates = @(); InstallerType = ''; BinaryArchitecture = ''; ProductName = ''; ProductVersion = ''; Sha256 = (Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant(); InstallerSha256 = '' }
    $stream = [IO.File]::OpenRead($file.FullName)
    try { $magic = New-Object byte[] 4; $null = $stream.Read($magic, 0, 4) } finally { $stream.Dispose() }
    $memberPath = $file.FullName
    if ([BitConverter]::ToString($magic) -eq '50-4B-03-04') {
      $result.ArchiveType = 'Zip'
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      $zip = [IO.Compression.ZipFile]::OpenRead($file.FullName)
      try {
        if ($zip.Entries.Count -gt 128 -or ($zip.Entries | Measure-Object Length -Sum).Sum -gt 1GB) { throw 'ZIP exceeds entry-count or expanded-size limits.' }
        $result.Candidates = @($zip.Entries | Where-Object { Test-RideInstallerEntryName $_.FullName } | ForEach-Object FullName)
      } finally { $zip.Dispose() }
      if (-not $InstallerEntry -and $result.Candidates.Count -eq 1) { $InstallerEntry = $result.Candidates[0] }
      if (-not $InstallerEntry) { return [pscustomobject]$result }
      $result.InstallerEntry = $InstallerEntry
      $memberPath = Join-Path $scratch ('installer' + [IO.Path]::GetExtension($InstallerEntry))
      Expand-RideInstallerEntry -Path $file.FullName -Entry $InstallerEntry -Destination $memberPath -Confirm:$false
    } elseif ($InstallerEntry) { throw 'InstallerEntry requires ZIP content.' }
    $details = Get-RideInstallerFileDetails -Path $memberPath
    foreach ($field in @('InstallerType', 'BinaryArchitecture', 'ProductName', 'ProductVersion')) { $result[$field] = $details.$field }
    $result.InstallerSha256 = $details.Sha256
    [pscustomobject]$result
  } finally {
    if ([IO.Directory]::Exists($scratch)) {
      $resolved = (Get-Item -LiteralPath $scratch).FullName
      if ($resolved -ne [IO.Path]::GetFullPath($scratch) -or (Split-Path -Leaf $resolved) -notmatch '^RIDE-Inspect-[a-f0-9]{32}$') { throw 'Unexpected inspection cleanup path.' }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }
}

Export-ModuleMember -Function Get-RideInstallerInspection, Expand-RideInstallerEntry
$script:entryCompletion = (Get-Command Get-RideInstallerInspection).Parameters.InstallerEntry.Attributes |
  Where-Object { $_ -is [Management.Automation.ArgumentCompleterAttribute] } | Select-Object -First 1
Register-ArgumentCompleter -CommandName Expand-RideInstallerEntry -ParameterName Entry -ScriptBlock $script:entryCompletion.ScriptBlock
