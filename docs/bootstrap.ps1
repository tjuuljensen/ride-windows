<#
.SYNOPSIS
  Download ride-windows and optionally run the default bootstrap preset.
.DESCRIPTION
  This script is the supported one-line bootstrap entrypoint for a fresh
  Windows machine. It downloads a branch or release archive from GitHub,
  extracts it to a temporary directory, and can then run ride.ps1 with the
  repository default module and preset.

  The script intentionally does not run installation tasks unless an execution
  mode such as -Default, -Edit, or custom -Include/-Preset/-Tweak arguments is
  supplied.
#>

[CmdletBinding()]
param(
  [string] $Author = "tjuuljensen",
  [string] $Repo = "ride-windows",
  [string] $Branch = "master",
  [string] $Release = "",
  [string] $InstallRoot = "",
  [switch] $Default,
  [switch] $Edit,
  [Alias("Stop")]
  [switch] $NoRun,
  [switch] $NoAdmin,
  [switch] $DownloadOnly,
  [string] $Log = "",
  [string] $Ini = "",
  [string[]] $Include = @(),
  [string[]] $Preset = @(),
  [string[]] $Tweak = @()
)

$ErrorActionPreference = "Stop"
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
  Write-Verbose "Unable to set TLS 1.2 explicitly; continuing with platform defaults."
}

function Show-SyntaxHelp {
  $scriptName = Split-Path -Leaf $MyInvocation.ScriptName
  Write-Output "Usage:"
  Write-Output "  $scriptName -Default [-Release v1.2.3] [-Log install.log] [-Ini config.ini] [-DownloadOnly]"
  Write-Output "  $scriptName -Edit [-Release v1.2.3]"
  Write-Output "  $scriptName -NoRun [-Release v1.2.3]"
  Write-Output "  $scriptName -Include module.psm1 -Preset preset.preset [-Tweak FunctionName]"
  Write-Output ""
  Write-Output "Modes:"
  Write-Output "  -Default      Run ride.ps1 with lib-windows.psm1 and default.preset."
  Write-Output "  -Edit         Copy default.preset to custom-bootstrap.preset, edit it in Notepad, then run it."
  Write-Output "  -NoRun/-Stop  Download and extract only. Print the extracted repository path."
  Write-Output ""
  Write-Output "Source selection:"
  Write-Output "  -Branch name  Download a branch archive. Default: master."
  Write-Output "  -Release tag  Download a tagged release archive instead of a branch archive."
}

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-ProcessArgument {
  param([string] $Argument)

  if ($null -eq $Argument) {
    return '""'
  }

  if ($Argument -notmatch '[\s"`]') {
    return $Argument
  }

  '"' + ($Argument -replace '"', '\"') + '"'
}

function ConvertTo-ProcessArgumentList {
  param([hashtable] $Parameters)

  $argumentList = New-Object System.Collections.Generic.List[string]
  $argumentList.Add("-NoProfile")
  $argumentList.Add("-ExecutionPolicy")
  $argumentList.Add("Bypass")
  $argumentList.Add("-File")
  $argumentList.Add((Quote-ProcessArgument $PSCommandPath))

  foreach ($key in ($Parameters.Keys | Sort-Object)) {
    $value = $Parameters[$key]
    if ($value -is [switch]) {
      if ($value.IsPresent) {
        $argumentList.Add("-$key")
      }
      continue
    }

    if ($null -eq $value -or $value -eq "") {
      continue
    }

    if ($value -is [array]) {
      foreach ($item in $value) {
        $argumentList.Add("-$key")
        $argumentList.Add((Quote-ProcessArgument $item))
      }
      continue
    }

    $argumentList.Add("-$key")
    $argumentList.Add((Quote-ProcessArgument $value))
  }

  $argumentList -join " "
}

function Restart-AsAdministrator {
  if (-not $PSCommandPath) {
    throw "Cannot relaunch as administrator because the bootstrapper is not running from a script file."
  }

  $argumentList = ConvertTo-ProcessArgumentList -Parameters $PSBoundParameters
  Start-Process -FilePath "powershell.exe" -ArgumentList $argumentList -Verb RunAs | Out-Null
  exit
}

function New-TemporaryDirectory {
  $parent = [IO.Path]::GetTempPath()
  $name = "ride-windows-" + [guid]::NewGuid().ToString("N")
  New-Item -ItemType Directory -Path (Join-Path -Path $parent -ChildPath $name) -Force
}

function Get-BootstrapArchiveUrl {
  if ($Release) {
    return "https://github.com/$Author/$Repo/archive/refs/tags/$Release.zip"
  }

  "https://github.com/$Author/$Repo/archive/refs/heads/$Branch.zip"
}

function Expand-RideRepository {
  param([string] $ArchivePath, [string] $DestinationPath)

  Expand-Archive -Path $ArchivePath -DestinationPath $DestinationPath -Force
  Remove-Item -Path $ArchivePath -ErrorAction SilentlyContinue

  $rideScript = Get-ChildItem -Path $DestinationPath -Filter "ride.ps1" -Recurse -File | Select-Object -First 1
  if (-not $rideScript) {
    throw "The downloaded archive did not contain ride.ps1."
  }

  $rideScript.Directory.FullName
}

function Download-RideRepository {
  if (-not $InstallRoot) {
    $InstallRoot = (New-TemporaryDirectory).FullName
  }
  else {
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
  }

  $archiveUrl = Get-BootstrapArchiveUrl
  $archivePath = Join-Path -Path $InstallRoot -ChildPath "$Repo.zip"

  Write-Host "Downloading $archiveUrl"
  Write-Host "Destination: $InstallRoot"
  Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing

  $repoPath = Expand-RideRepository -ArchivePath $archivePath -DestinationPath $InstallRoot
  Write-Host "Repository extracted to: $repoPath"
  $repoPath
}

function Add-RidePathArgument {
  param(
    [System.Collections.Generic.List[string]] $Arguments,
    [string] $Name,
    [string] $Path
  )

  if (-not $Path) {
    return
  }

  $Arguments.Add($Name)
  $Arguments.Add($Path)
}

function Get-RideArguments {
  param([string] $RepoPath)

  $rideArguments = New-Object System.Collections.Generic.List[string]

  if ($Default -or $Edit) {
    Add-RidePathArgument -Arguments $rideArguments -Name "-include" -Path (Join-Path -Path $RepoPath -ChildPath "lib-windows.psm1")

    if ($Edit) {
      $customPreset = Join-Path -Path $RepoPath -ChildPath "custom-bootstrap.preset"
      Copy-Item -Path (Join-Path -Path $RepoPath -ChildPath "default.preset") -Destination $customPreset -Force
      Write-Host "Opening preset for editing: $customPreset"
      Start-Process -FilePath "notepad.exe" -ArgumentList (Quote-ProcessArgument $customPreset) -Wait
      Add-RidePathArgument -Arguments $rideArguments -Name "-preset" -Path $customPreset
    }
    else {
      Add-RidePathArgument -Arguments $rideArguments -Name "-preset" -Path (Join-Path -Path $RepoPath -ChildPath "default.preset")
    }
  }

  foreach ($item in $Include) {
    Add-RidePathArgument -Arguments $rideArguments -Name "-include" -Path $item
  }

  foreach ($item in $Preset) {
    Add-RidePathArgument -Arguments $rideArguments -Name "-preset" -Path $item
  }

  if ($Ini) {
    Add-RidePathArgument -Arguments $rideArguments -Name "-ini" -Path $Ini
  }

  if ($Log) {
    Add-RidePathArgument -Arguments $rideArguments -Name "-log" -Path $Log
  }

  if ($DownloadOnly) {
    $rideArguments.Add("-downloadonly")
  }

  foreach ($item in $Tweak) {
    $rideArguments.Add($item)
  }

  $rideArguments.ToArray()
}

function Invoke-Ride {
  param(
    [string] $RepoPath,
    [string[]] $RideArguments
  )

  $rideScript = Join-Path -Path $RepoPath -ChildPath "ride.ps1"
  if (-not (Test-Path -Path $rideScript)) {
    throw "ride.ps1 was not found in $RepoPath."
  }

  Push-Location $RepoPath
  try {
    Write-Output "Running ride.ps1..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $rideScript @RideArguments
    if ($LASTEXITCODE -ne 0) {
      throw "ride.ps1 exited with code $LASTEXITCODE."
    }
  }
  finally {
    Pop-Location
  }
}

$hasCustomRideArguments = ($Include.Count -gt 0) -or ($Preset.Count -gt 0) -or ($Tweak.Count -gt 0)
$hasRunMode = $Default -or $Edit -or $hasCustomRideArguments

if (-not $hasRunMode -and -not $NoRun) {
  Show-SyntaxHelp
  exit 1
}

if ($hasRunMode -and -not $NoAdmin -and -not (Test-IsAdministrator)) {
  Restart-AsAdministrator
}

$repoPath = Download-RideRepository

if ($NoRun) {
  Write-Output "No installation tasks performed."
  Write-Output "Run manually from: $repoPath"
  exit 0
}

$rideArguments = Get-RideArguments -RepoPath $repoPath
if ($rideArguments.Count -eq 0) {
  throw "No ride.ps1 arguments were produced."
}

Invoke-Ride -RepoPath $repoPath -RideArguments $rideArguments
