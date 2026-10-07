function Get-RideInstalledPackage {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  foreach ($root in $uninstallRoots) {
    foreach ($entry in (Get-ItemProperty -Path $root -ErrorAction SilentlyContinue)) {
      if ($entry.DisplayName -match $Operation.DisplayNamePattern) {
        return [pscustomobject]@{
          Present = $true
          DisplayName = $entry.DisplayName
          DisplayVersion = $entry.DisplayVersion
          UninstallString = $entry.UninstallString
          QuietUninstallString = $entry.QuietUninstallString
          InstallLocation = $entry.InstallLocation
        }
      }
    }
  }

  [pscustomobject]@{ Present = $false; DisplayName = $null; DisplayVersion = $null; UninstallString = $null; QuietUninstallString = $null; InstallLocation = $null }
}

function Resolve-RidePackageDownloadUri {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  if ($Operation.PackageId -ne '7zip') { return $Operation.DownloadUri }

  $page = Invoke-WebRequest -Uri $Operation.DownloadUri -UseBasicParsing -ErrorAction Stop
  $link = $page.Links | Where-Object { $_.href -match 'x64\.exe$' } | Select-Object -First 1
  if (-not $link) { throw 'Could not find the 64-bit 7-Zip installer on the upstream page.' }
  [uri]::new([uri]$Operation.DownloadUri, $link.href).AbsoluteUri
}

function Install-RidePackage {
  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][string] $CacheDirectory
  )

  if ($Operation.InstallerType -ne 'Exe') { throw "Unsupported installer type for $($Operation.Id): $($Operation.InstallerType)" }
  $uri = Resolve-RidePackageDownloadUri -Operation $Operation
  New-Item -ItemType Directory -Path $CacheDirectory -Force | Out-Null
  $extension = [IO.Path]::GetExtension(([uri]$uri).AbsolutePath)
  if (-not $extension) { $extension = '.exe' }
  $installer = Join-Path $CacheDirectory ($Operation.PackageId + $extension)
  Invoke-WebRequest -Uri $uri -OutFile $installer -UseBasicParsing -ErrorAction Stop
  $process = Start-Process -FilePath $installer -ArgumentList $Operation.InstallerArguments -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Installer for $($Operation.Name) exited with code $($process.ExitCode)." }
  Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
  if (-not (Get-RideInstalledPackage -Operation $Operation).Present) { throw "Installer completed but $($Operation.Name) was not detected afterward." }
}

function Uninstall-RidePackage {
  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $installed = Get-RideInstalledPackage -Operation $Operation
  if (-not $installed.Present) { return }
  $command = if ($installed.QuietUninstallString) { $installed.QuietUninstallString } else { $installed.UninstallString }
  if (-not $command) { throw "No uninstall command was registered for $($installed.DisplayName)." }

  $exe = $null
  $arguments = ''
  if ($command -match '^\s*"([^"]+)"\s*(.*)$') {
    $exe = $matches[1]
    $arguments = $matches[2]
  }
  elseif ($command -match '^\s*(\S+\.exe)\s*(.*)$') {
    $exe = $matches[1]
    $arguments = $matches[2]
  }
  if (-not $exe) { throw "Could not parse the uninstall command for $($installed.DisplayName)." }
  if ($arguments -notmatch '(?i)(/quiet|/s|/silent|--uninstall)') { $arguments = ($arguments + ' ' + $Operation.UninstallerArguments).Trim() }
  $process = Start-Process -FilePath $exe -ArgumentList $arguments -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Uninstaller for $($Operation.Name) exited with code $($process.ExitCode)." }
  if ((Get-RideInstalledPackage -Operation $Operation).Present) { throw "Uninstaller completed but $($Operation.Name) is still detected." }
}

Export-ModuleMember -Function Get-RideInstalledPackage, Install-RidePackage, Uninstall-RidePackage
