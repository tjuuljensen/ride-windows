<#
.SYNOPSIS
  Acquire pinned screen-lock evaluation inputs without executing them.

.DESCRIPTION
  Downloads three official publisher archives, verifies SHA-256 before extraction,
  copies the current caffeine scripts, retains publisher notices, and writes a
  manifest of guest launch cases. Never installs packages or launches input tools.
  Use a new directory for each acquisition. Supports WhatIf.

.PARAMETER Destination
  New local input directory. Required for acquisition; existing paths are rejected.

.PARAMETER Version
  Print the tooling version without acquiring files.

.EXAMPLE
  .\tests\integration\New-RideScreenLockInputs.ps1 -Destination .\.local\screen-lock-impact\inputs

.INPUTS
  None.

.OUTPUTS
  String. Path to manifest.json.

.NOTES
  Compatibility: PowerShell 5.1 and 7 on Windows; guest execution remains pending.
  Prerequisites: HTTPS access to Zhorn and GitHub; ZIP extraction support.
  File inputs: Current checkout scripts, including uncommitted edits.
  Recovery: Failed acquisition retains its partial directory for inspection.
  Author: RIDE-Windows maintainers. Version: 0.1.0
  Changelog: 0.1.0: Add pinned, download-only evaluation input preparation.

.LINK
  ../../docs/screen-lock-impact.md
#>
[CmdletBinding(SupportsShouldProcess)]
param([string] $Destination, [switch] $Version)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $Destination) { throw 'Destination is required.' }
$destinationPath = [IO.Path]::GetFullPath($Destination)
if (Test-Path -LiteralPath $destinationPath) { throw 'Use a new acquisition directory.' }
if (-not $PSCmdlet.ShouldProcess($destinationPath, 'Download, verify and extract pinned evaluation inputs')) { return }
$repository = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$artifacts = @(
  @{ Id = 'zhorn'; Version = '1.98'; Name = 'caffeine.zip'; Uri = 'https://www.zhornsoftware.co.uk/caffeine/caffeine.zip'; Sha256 = '4a259c348e59eb51bbb75aac7fdcc798705496d575892ee1e01fff6970d5ba1c' },
  @{ Id = 'arkane-mainline'; Version = '3.0.0'; Name = 'MouseJiggler-mainline-x64.zip'; Uri = 'https://github.com/arkane-systems/mousejiggler/releases/download/3.0.0/MouseJiggler-mainline-x64.zip'; Sha256 = '389bc7e4166aeb9c3b43380fad9dd3e4e65ddd0de5e6f25f296c9d3bcc5bcc16' },
  @{ Id = 'arkane-standalone'; Version = '3.0.0'; Name = 'MouseJiggler-standalone-x64.zip'; Uri = 'https://github.com/arkane-systems/mousejiggler/releases/download/3.0.0/MouseJiggler-standalone-x64.zip'; Sha256 = '7b4d95659b3777789e7cfaff62e60f095e06ad6d321dd61c65dd87f792339953' }
)
[void](New-Item -ItemType Directory -Path $destinationPath)
$pins = [Collections.Generic.List[object]]::new()
foreach ($artifact in $artifacts) {
  $archive = Join-Path $destinationPath $artifact.Name
  Invoke-WebRequest -Uri $artifact.Uri -OutFile $archive -UseBasicParsing
  $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($hash -ne $artifact.Sha256) { throw "Publisher archive changed: $($artifact.Id). Do not execute these bytes." }
  $extract = Join-Path $destinationPath $artifact.Id
  Expand-Archive -LiteralPath $archive -DestinationPath $extract
  $pins.Add([pscustomobject]@{ Path = $artifact.Name; Sha256 = $hash; Bytes = (Get-Item -LiteralPath $archive).Length; SourceUri = $artifact.Uri; PublisherVersion = $artifact.Version })
}
$scriptDirectory = Join-Path $destinationPath 'scripts'
[void](New-Item -ItemType Directory -Path $scriptDirectory)
foreach ($name in @('caffeine.ps1', 'caffeine-light.ps1')) {
  Copy-Item -LiteralPath (Join-Path $repository "components/scripts/$name") -Destination $scriptDirectory
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-RideIdleHost.ps1') -Destination $scriptDirectory
# Retain the release's license/readme even if a ZIP omits them.
foreach ($name in @('LICENSE', 'README.md')) {
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/arkane-systems/mousejiggler/3.0.0/$name" -OutFile (Join-Path $destinationPath "arkane-3.0.0-$name") -UseBasicParsing
}
foreach ($file in Get-ChildItem -LiteralPath $destinationPath -File -Recurse | Where-Object { $_.Extension -ne '.zip' }) {
  $architecture = $null
  if ($file.Extension -eq '.exe') {
    $stream = [IO.File]::OpenRead($file.FullName)
    try {
      $reader = [IO.BinaryReader]::new($stream)
      $stream.Position = 0x3c; $peOffset = $reader.ReadInt32(); $stream.Position = $peOffset + 4
      $architecture = switch ($reader.ReadUInt16()) { 0x014c { 'x86' } 0x8664 { 'x64' } 0xaa64 { 'arm64' } default { 'Unknown' } }
    } finally { $stream.Dispose() }
  }
  $pins.Add([pscustomobject]@{
    Path = $file.FullName.Substring($destinationPath.Length + 1)
    Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Bytes = $file.Length; FileVersion = $file.VersionInfo.FileVersion; ProductVersion = $file.VersionInfo.ProductVersion; Architecture = $architecture
  })
}
$cases = [Collections.Generic.List[object]]::new()
$cases.Add(@{ Id = 'instrumentation'; Executable = ''; Arguments = ''; Purpose = 'Instrumentation-only idle control' })
foreach ($hostName in @('powershell.exe', 'pwsh.exe')) {
  $prefix = if ($hostName -eq 'powershell.exe') { 'ps51' } else { 'ps7' }
  foreach ($variant in @(
    @{ Name = 'idle'; Script = 'Invoke-RideIdleHost.ps1'; Options = '' },
    @{ Name = 'full-default'; Script = 'caffeine.ps1'; Options = '' },
    @{ Name = 'full-quiet'; Script = 'caffeine.ps1'; Options = '-NoConsoleCustomization -ReportIntervalSeconds 0' },
    @{ Name = 'full-60'; Script = 'caffeine.ps1'; Options = '-IntervalSeconds 60' },
    @{ Name = 'full-quiet-60'; Script = 'caffeine.ps1'; Options = '-NoConsoleCustomization -ReportIntervalSeconds 0 -IntervalSeconds 60' },
    @{ Name = 'light'; Script = 'caffeine-light.ps1'; Options = '' }
  )) {
    $cases.Add(@{ Id = "$prefix-$($variant.Name)"; Executable = $hostName; Arguments = "-NoLogo -NoProfile -File `"{Inputs}\scripts\$($variant.Script)`" $($variant.Options)"; Purpose = $variant.Name })
  }
}
foreach ($architecture in @('32', '64')) {
  foreach ($mode in @(
    @{ Id = 'default'; Arguments = '' }, @{ Id = '60'; Arguments = '60' },
    @{ Id = 'shift-60'; Arguments = '60 -useshift' }, @{ Id = 'keypress-60'; Arguments = '60 -keypress' },
    @{ Id = 'stes'; Arguments = '-stes' }, @{ Id = 'allowss'; Arguments = '-allowss' }
  )) {
    $cases.Add(@{ Id = "zhorn$architecture-$($mode.Id)"; Executable = "zhorn\caffeine$architecture.exe"; Arguments = $mode.Arguments; Purpose = $mode.Id })
  }
}
foreach ($packaging in @('mainline', 'standalone')) {
  $executables = @(Get-ChildItem -LiteralPath (Join-Path $destinationPath "arkane-$packaging") -Filter 'MouseJiggler.exe' -File -Recurse)
  if ($executables.Count -ne 1) { throw "Expected one MouseJiggler.exe in $packaging archive." }
  $relativeExecutable = $executables[0].FullName.Substring($destinationPath.Length + 1)
  foreach ($mode in @(
    @{ Id = 'first-launch'; Arguments = '' },
    @{ Id = 'normal-default'; Arguments = '--jiggle' },
    @{ Id = 'normal-60'; Arguments = '--jiggle --mode Normal --seconds 60 --distance 1' },
    @{ Id = 'zen-60'; Arguments = '--jiggle --mode Zen --seconds 60 --distance 1' }
  )) {
    $cases.Add(@{ Id = "arkane-$packaging-$($mode.Id)"; Executable = $relativeExecutable; Arguments = $mode.Arguments; Purpose = $mode.Id })
  }
}
$manifest = [ordered]@{
  SchemaVersion = 1; ToolingVersion = $script:ScriptVersion; AcquiredAtUtc = [datetime]::UtcNow.ToString('o')
  SourceRevision = (& git -C $repository rev-parse HEAD); SourceStatus = @(& git -C $repository status --short)
  Pins = @($pins.ToArray()); Cases = @($cases.ToArray())
  RuntimeNotes = 'PS 5.1/7 hosts are resolved and hashed in the guest. Arkane mainline 3.0.0 needs .NET 10 Desktop Runtime of matching architecture; standalone includes its runtime. Acquisition/extraction is not execution cost.'
}
$manifestPath = Join-Path $destinationPath 'manifest.json'
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$manifestPath
