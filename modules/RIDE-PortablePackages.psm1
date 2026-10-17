<#
.SYNOPSIS
  Manage declarative portable package files and exact file recovery.
.DESCRIPTION
  Installs without executing payloads, creating shortcuts, changing PATH, or
  adding exclusions. Owns only manifest-listed content; preserves other files.
  Engine-internal writers require engine ShouldProcess and snapshot capture.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Local filesystem, ZIP APIs, resolved package metadata.
  Recovery: Versioned file snapshots; missing backups stop restore before writes.
  Failed manifest commits retain staged evidence for review, never automatic adoption.
  Owner: RIDE-Windows maintainers. Version: 0.3.0.
  Changelog: 0.3.0: Bound unchanged-file replacement retries and retain failed manifest evidence.
    0.2.0: Inspect available signatures on portable COM executables.
    0.1.0: Add bounded extraction, manifest ownership and file recovery.
#>

$ErrorActionPreference = 'Stop'

function Assert-RidePortablePath {
  param([string] $Path)
  $full = [IO.Path]::GetFullPath($Path)
  $cursor = $full
  while ($cursor) {
    if (Test-Path -LiteralPath $cursor) {
      $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Portable paths cannot contain reparse points: $cursor" }
    }
    $parent = Split-Path -Parent $cursor
    if ($parent -eq $cursor) { break }
    $cursor = $parent
  }
  $full
}

function Get-RidePortableMemberPath {
  param([string] $Root, [string] $RelativePath)
  if (-not $RelativePath -or $RelativePath.Length -gt 240 -or
      $RelativePath -match '[\\\x00-\x1f:"*?<>|]|^/|(^|/)\.{1,2}(/|$)|[. ](/|$)|//|/$|(^|/)(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|/|$)') { throw "Unsafe portable member: $RelativePath" }
  $base = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
  $path = [IO.Path]::GetFullPath((Join-Path $Root $RelativePath))
  if (-not $path.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { throw 'Portable member escapes its product directory.' }
  $parent = Split-Path -Parent $path
  while ($parent -and $parent.StartsWith($base.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    if (Test-Path -LiteralPath $parent -PathType Leaf) { throw "Portable destination collision: parent is a file: $parent" }
    if ($parent -eq $base.TrimEnd('\', '/')) { break }
    $parent = Split-Path -Parent $parent
  }
  Assert-RidePortablePath $path
}

function Invoke-RidePortableManifestReplace {
  param([string]$Temporary, [string]$Destination)
  [IO.File]::Replace($Temporary, $Destination, [NullString]::Value)
}

function Write-RidePortableManifest {
  param([string] $Root, $Manifest)
  $path = Join-Path $Root '.ride-package.json'
  $temporary = Join-Path $Root ('.ride-package-' + [guid]::NewGuid().ToString('N') + '.tmp')
  $null = Assert-RidePortablePath $path
  $created = $false
  try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Manifest | ConvertTo-Json -Depth 8))
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $created = $true
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      $beforeHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
      $proposedHash = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash
      for ($attempt = 1; $attempt -le 3; $attempt++) {
        try { Invoke-RidePortableManifestReplace -Temporary $temporary -Destination $path; break }
        catch {
          $failure = $_
          $cause = $_.Exception.GetBaseException()
          $code = $cause.HResult -band 65535
          if ($attempt -eq 3 -or $cause -isnot [IO.IOException] -or $code -notin @(32,33,1175)) { throw }
          # Never retry a partial replacement, external edit or redirected path.
          Start-Sleep -Milliseconds (50 * $attempt)
          $null = Assert-RidePortablePath $path
          $null = Assert-RidePortablePath $temporary
          if (-not [IO.File]::Exists($path) -or -not [IO.File]::Exists($temporary)) { throw $failure }
          if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $beforeHash -or
              (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -cne $proposedHash) { throw $failure }
        }
      }
    }
    else { [IO.File]::Move($temporary, $path) }
  } catch {
    if ($created -and [IO.File]::Exists($temporary)) {
      Write-Warning "Portable manifest commit failed. Retained staged evidence at '$temporary'; preserve it and the saved run for recovery review." -WarningAction Continue
    }
    throw
  }
}

function Get-RidePortableState {
  <#
  .SYNOPSIS
    Inspect ownership and actual files without changing them.
  .PARAMETER Operation
    Resolved portable package metadata.
  .EXAMPLE
    Get-RidePortableState -Operation $package
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Presence, health and manifest.
  .NOTES
    Read-only. Compatibility and version follow the module overview.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation)
  if ($Operation.PackageId -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*$' -or -not $Operation.ResolvedToolsDirectory -or
      $Operation.PackageId -match '[. ]$|^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)' -or
      [IO.Path]::GetFullPath($Operation.InstallDirectory) -ne [IO.Path]::GetFullPath((Join-Path $Operation.ResolvedToolsDirectory $Operation.PackageId))) { throw 'Portable destination must be its resolved product directory.' }
  $root = Assert-RidePortablePath $Operation.InstallDirectory
  if (Test-Path -LiteralPath $root -PathType Leaf) { throw 'Portable destination collision: product directory is a file.' }
  $manifestPath = Join-Path $root '.ride-package.json'
  $manifest = $null
  $files = @()
  if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
    $null = Assert-RidePortablePath $manifestPath
    if ((Get-Item -LiteralPath $manifestPath).Length -gt 4194304) { throw 'Portable manifest exceeds 4 MiB.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.SchemaVersion -ne 1 -or $manifest.PackageId -ne $Operation.PackageId -or
        $manifest.Variant -ne $Operation.SelectedVariant -or -not $manifest.Files -or @($manifest.Files).Count -gt 10000) { throw 'Invalid portable ownership manifest.' }
    $seen = @{}
    $files = @(foreach ($file in $manifest.Files) {
      $path = Get-RidePortableMemberPath $root $file.RelativePath
      if ($file.RelativePath -eq '.ride-package.json' -or $seen.ContainsKey($file.RelativePath) -or $file.Sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid or duplicate portable ownership member.' }
      $seen[$file.RelativePath] = $true
      $hash = if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
      [pscustomobject]@{ RelativePath = $file.RelativePath; Sha256 = $file.Sha256; ActualSha256 = $hash; Missing = -not $hash; Modified = [bool]($hash -and $hash -ne $file.Sha256) }
    })
  }
  [pscustomobject]@{
    Present = [bool]$manifest; Healthy = [bool]($manifest -and $manifest.Status -eq 'Installed' -and -not @($files | Where-Object { $_.Missing -or $_.Modified }).Count)
    DisplayName = $Operation.Name; DisplayVersion = if ($manifest) { $manifest.Version } else { $null }
    InstallLocation = $root; Manifest = $manifest; Files = $files
  }
}

function Install-RidePortablePayload {
  <#
  .SYNOPSIS
    Stage a retained artifact and install only validated owned files.
  .PARAMETER Operation
    Resolved portable package metadata.
  .PARAMETER Artifact
    Retained payload path, version and SHA-256 evidence.
  .EXAMPLE
    Install-RidePortablePayload -Operation $package -Artifact $artifact
  .INPUTS
    None.
  .OUTPUTS
    None. Throws on collisions, unsafe extraction or partial failure.
  .NOTES
    Engine-internal writer. Payloads are never executed.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation, [Parameter(Mandatory)] $Artifact)
  $state = Get-RidePortableState $Operation
  if (@($state.Files | Where-Object Modified).Count) { throw 'Portable upgrade would overwrite modified managed files.' }
  if ((Get-FileHash -LiteralPath $Artifact.Path -Algorithm SHA256).Hash -ne $Artifact.Sha256) { throw 'Portable artifact SHA-256 changed before extraction.' }
  $root = $state.InstallLocation
  $stage = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Portable-' + [guid]::NewGuid().ToString('N'))
  $archive = $null
  try {
    New-Item -ItemType Directory -Path $stage | Out-Null
    if ($Operation.PortableFormat -eq 'Zip') {
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      $archive = [IO.Compression.ZipFile]::OpenRead($Artifact.Path)
      if ($archive.Entries.Count -gt 10000) { throw 'Portable archive exceeds 10000 members.' }
      $total = [long]0
      $seen = @{}
      foreach ($entry in $archive.Entries) {
        $name = $entry.FullName.TrimEnd('/')
        $path = Get-RidePortableMemberPath $stage $name
        if ($seen.ContainsKey($name)) { throw 'Portable archive has duplicate case-insensitive paths.' }
        $seen[$name] = $true
        if ($name -eq '.ride-package.json' -or (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000 -or ($entry.ExternalAttributes -band 0x400)) { throw 'Portable archive contains a reserved manifest or link.' }
        $total += $entry.Length
        if ($total -gt 2147483648 -or $entry.Length -gt 536870912) { throw 'Portable archive exceeds extraction bounds.' }
        if ($entry.FullName.EndsWith('/')) { New-Item -ItemType Directory -Path $path -Force | Out-Null; continue }
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $path)
      }
    } elseif ($Operation.PortableFormat -eq 'File') {
      $path = Get-RidePortableMemberPath $stage $Operation.PortableFileName
      New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
      Copy-Item -LiteralPath $Artifact.Path -Destination $path
    } else { throw 'Unsupported portable format.' }
    foreach ($requiredTemplate in $Operation.RequiredFiles) {
      $required = ([string]$requiredTemplate).Replace('{version}', [string]$Artifact.Version)
      if (-not (Test-Path -LiteralPath (Get-RidePortableMemberPath $stage $required) -PathType Leaf)) { throw "Portable payload is missing required file: $required" }
    }
    $owned = @{}
    foreach ($file in $state.Files) { $owned[$file.RelativePath] = $file }
    $newFiles = @(Get-ChildItem -LiteralPath $stage -File -Recurse | ForEach-Object {
      $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
      $destination = Get-RidePortableMemberPath $root $relative
      if (Test-Path -LiteralPath $destination) {
        if (-not $owned.ContainsKey($relative) -or -not (Test-Path -LiteralPath $destination -PathType Leaf)) { throw "Portable destination collision: $relative" }
      }
      $signature = if ($_.Extension -in @('.exe', '.com', '.dll', '.ps1', '.msi')) { Get-AuthenticodeSignature -LiteralPath $_.FullName -ErrorAction SilentlyContinue } else { $null }
      if ($signature -and [string]$signature.Status -eq 'HashMismatch') { throw "Portable signature integrity failure: $relative" }
      [pscustomobject]@{ RelativePath = $relative; Sha256 = (Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant(); AuthenticodeStatus = if ($signature) { [string]$signature.Status } else { 'NotApplicable' }; SignerThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { $null } }
    })
    if (-not $newFiles.Count) { throw 'Portable payload contains no files.' }
    # Preflight all destinations before the first product write.
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $manifest = [ordered]@{ SchemaVersion = 1; PackageId = $Operation.PackageId; Variant = $Operation.SelectedVariant; Version = $Artifact.Version; ArtifactSha256 = $Artifact.Sha256; ArtifactPath = $Artifact.Path; Files = @(); Status = 'Installing' }
    $manifestPath = Join-Path $root '.ride-package.json'
    $journal = @{}
    foreach ($old in $state.Manifest.Files) { if ($old) { $journal[$old.RelativePath] = $old } }
    foreach ($file in $newFiles) {
      $source = Get-RidePortableMemberPath $stage $file.RelativePath
      $dest = Get-RidePortableMemberPath $root $file.RelativePath
      New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force | Out-Null
      # Journal ownership before copying, so interrupted writes remain recoverable.
      $journal[$file.RelativePath] = $file
      $manifest.Files = @($journal.Values)
      Write-RidePortableManifest -Root $root -Manifest $manifest
      Copy-Item -LiteralPath $source -Destination $dest -Force
    }
    foreach ($old in $state.Files) {
      if ($old.RelativePath -notin $newFiles.RelativePath -and -not $old.Missing) { Remove-Item -LiteralPath (Get-RidePortableMemberPath $root $old.RelativePath) -Force }
    }
    $manifest.Files = $newFiles; $manifest.Status = 'Installed'
    Write-RidePortableManifest -Root $root -Manifest $manifest
  }
  finally {
    if ($archive) { $archive.Dispose() }
    $checked = Assert-RidePortablePath $stage
    if ((Split-Path -Leaf $checked) -notmatch '^RIDE-Portable-[0-9a-f]{32}$') { throw 'Unexpected portable staging path.' }
    if (Test-Path -LiteralPath $checked) { Remove-Item -LiteralPath $checked -Recurse -Force }
  }
}

function Uninstall-RidePortablePayload {
  <#
  .SYNOPSIS
    Remove matching owned files and preserve modified or user-created files.
  .PARAMETER Operation
    Resolved portable metadata.
  .EXAMPLE
    Uninstall-RidePortablePayload -Operation $package
  .INPUTS
    None.
  .OUTPUTS
    Warnings identify preserved modified content.
  .NOTES
    Engine-internal writer. The tools root is never removed.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Operation)
  $state = Get-RidePortableState $Operation
  if (-not $state.Present) { return }
  foreach ($file in $state.Files) {
    if ($file.Modified) { Write-Warning "Preserved modified portable file: $($file.RelativePath)" }
    elseif (-not $file.Missing) { Remove-Item -LiteralPath (Get-RidePortableMemberPath $state.InstallLocation $file.RelativePath) -Force }
  }
  Remove-Item -LiteralPath (Join-Path $state.InstallLocation '.ride-package.json') -Force
}

function Save-RidePortableSnapshot {
  <#
  .SYNOPSIS
    Retain exact pre-change owned bytes beneath the saved run.
  .PARAMETER Operation
    Resolved package metadata.
  .PARAMETER BackupDirectory
    Engine-owned directory within the saved run.
  .EXAMPLE
    Save-RidePortableSnapshot -Operation $package -BackupDirectory $backup
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Versioned file snapshot.
  .NOTES
    Called only after engine ShouldProcess approval.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, [string] $BackupDirectory)
  $state = Get-RidePortableState $Operation
  $backup = Assert-RidePortablePath $BackupDirectory
  foreach ($file in $state.Files | Where-Object { -not $_.Missing }) {
    $dest = Get-RidePortableMemberPath $backup $file.RelativePath
    New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force | Out-Null
    Copy-Item -LiteralPath (Get-RidePortableMemberPath $state.InstallLocation $file.RelativePath) -Destination $dest
    if ((Get-FileHash -LiteralPath $dest).Hash -ne $file.ActualSha256) { throw 'Portable snapshot changed while copying.' }
  }
  [pscustomobject]@{ SnapshotVersion = 1; Present = $state.Present; InstallLocation = $state.InstallLocation; BackupDirectory = $backup; Manifest = $state.Manifest; Files = $state.Files }
}

function Restore-RidePortableSnapshot {
  <#
  .SYNOPSIS
    Validate and restore saved portable bytes, preserving unrelated content.
  .PARAMETER Operation
    Saved resolved package selection.
  .PARAMETER Snapshot
    Versioned manifest and retained-file snapshot.
  .PARAMETER ValidateOnly
    Preflight without writing.
  .EXAMPLE
    Restore-RidePortableSnapshot -Operation $package -Snapshot $snapshot -ValidateOnly
  .INPUTS
    None.
  .OUTPUTS
    None. Errors stop before writes when backups or destinations conflict.
  .NOTES
    Engine-internal writer. Missing backups are never replaced by latest downloads.
  #>
  [CmdletBinding()]
  param([hashtable] $Operation, $Snapshot, [switch] $ValidateOnly)
  if ($Snapshot.SnapshotVersion -ne 1 -or $Snapshot.InstallLocation -ne $Operation.InstallDirectory) { throw 'Portable snapshot contract mismatch.' }
  $state = Get-RidePortableState $Operation
  foreach ($file in $Snapshot.Files | Where-Object { -not $_.Missing }) {
    $source = Get-RidePortableMemberPath $Snapshot.BackupDirectory $file.RelativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or (Get-FileHash -LiteralPath $source).Hash -ne $file.ActualSha256) { throw "Portable recovery bytes are unavailable: $($file.RelativePath)" }
    $dest = Get-RidePortableMemberPath $Operation.InstallDirectory $file.RelativePath
    if (Test-Path -LiteralPath $dest) {
      if (-not (Test-Path -LiteralPath $dest -PathType Leaf)) { throw 'Portable recovery destination is not a file.' }
      $hash = (Get-FileHash -LiteralPath $dest).Hash
      $current = @($state.Files | Where-Object RelativePath -eq $file.RelativePath)
      if (-not $current.Count -and -not ($file.Modified -and $hash -eq $file.ActualSha256)) { throw 'Portable recovery destination contains unowned content.' }
      if ($hash -ne $file.ActualSha256 -and ($current.Count -ne 1 -or $current[0].Modified)) { throw 'Portable recovery would overwrite modified or unowned content.' }
    }
  }
  if ($ValidateOnly) { return }
  Uninstall-RidePortablePayload $Operation
  if (-not $Snapshot.Present) { return }
  New-Item -ItemType Directory -Path $Operation.InstallDirectory -Force | Out-Null
  $journal = @{}
  if ($Snapshot.Manifest -is [hashtable]) { $journal = $Snapshot.Manifest.Clone() }
  else { foreach ($property in $Snapshot.Manifest.PSObject.Properties) { $journal[$property.Name] = $property.Value } }
  $journal.Status = 'Restoring'
  Write-RidePortableManifest -Root $Operation.InstallDirectory -Manifest $journal
  foreach ($file in $Snapshot.Files | Where-Object { -not $_.Missing }) {
    $dest = Get-RidePortableMemberPath $Operation.InstallDirectory $file.RelativePath
    New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force | Out-Null
    Copy-Item -LiteralPath (Get-RidePortableMemberPath $Snapshot.BackupDirectory $file.RelativePath) -Destination $dest -Force
  }
  Write-RidePortableManifest -Root $Operation.InstallDirectory -Manifest $Snapshot.Manifest
}

Export-ModuleMember -Function Get-RidePortableState, Install-RidePortablePayload, Uninstall-RidePortablePayload, Save-RidePortableSnapshot, Restore-RidePortableSnapshot
