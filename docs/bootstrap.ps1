<#
.SYNOPSIS
  Download ride-windows and optionally run a profile with the RIDE engine.
.DESCRIPTION
  Downloads a branch or release archive, extracts it to a temporary directory,
  and runs the declarative RIDE command selected by the operator.
#>
[CmdletBinding()]
param(
  [string] $Author = 'tjuuljensen',
  [string] $Repo = 'ride-windows',
  [string] $Branch = 'master',
  [string] $Release = '',
  [string] $InstallRoot = '',
  [switch] $Default,
  [switch] $Edit,
  [Alias('Stop')][switch] $NoRun,
  [switch] $NoAdmin,
  [ValidateSet('list', 'plan', 'apply', 'status', 'remove')]
  [string] $Command = 'apply',
  [string] $Profile = ''
)

$ErrorActionPreference = 'Stop'
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch { Write-Verbose 'Unable to set TLS 1.2 explicitly; continuing with platform defaults.' }

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-ProcessArgument {
  param([string] $Argument)
  if ($null -eq $Argument) { return '""' }
  if ($Argument -notmatch '[\s"`]') { return $Argument }
  '"' + ($Argument -replace '"', '\"') + '"'
}

function New-TemporaryDirectory {
  $path = Join-Path ([IO.Path]::GetTempPath()) ('ride-windows-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $path -Force | Out-Null
  $path
}

function Get-RepositoryArchiveUrl {
  if ($Release) { return "https://github.com/$Author/$Repo/archive/refs/tags/$Release.zip" }
  "https://github.com/$Author/$Repo/archive/refs/heads/$Branch.zip"
}

function Get-RepositoryPath {
  if (-not $InstallRoot) { $script:InstallRoot = New-TemporaryDirectory }
  New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
  $archivePath = Join-Path $InstallRoot ($Repo + '.zip')
  Invoke-WebRequest -Uri (Get-RepositoryArchiveUrl) -OutFile $archivePath -UseBasicParsing -ErrorAction Stop
  Expand-Archive -Path $archivePath -DestinationPath $InstallRoot -Force
  Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
  $scriptPath = Get-ChildItem -Path $InstallRoot -Filter 'ride.ps1' -Recurse -File | Select-Object -First 1
  if (-not $scriptPath) { throw 'The downloaded archive did not contain ride.ps1.' }
  $scriptPath.Directory.FullName
}

function Start-RideAsAdministrator {
  $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Quote-ProcessArgument $PSCommandPath))
  foreach ($key in $PSBoundParameters.Keys) {
    $value = $PSBoundParameters[$key]
    if ($value -is [switch]) {
      if ($value.IsPresent) { $arguments += "-$key" }
    }
    elseif ($null -ne $value -and $value -ne '') {
      $arguments += "-$key"
      $arguments += (Quote-ProcessArgument ([string]$value))
    }
  }
  Start-Process -FilePath 'powershell.exe' -ArgumentList ($arguments -join ' ') -Verb RunAs | Out-Null
  exit
}

$hasRunMode = $Default -or $Edit -or ($Profile -ne '') -or ($Command -ne 'apply')
if ($NoRun) { $hasRunMode = $false }
if (-not $hasRunMode -and -not $NoRun) {
  Write-Output 'Usage: bootstrap.ps1 -Default | -Edit | -Profile .\my-profile.psd1 [-Command list|plan|apply|status|remove] | -NoRun'
  exit 1
}
if ($hasRunMode -and -not $NoAdmin -and -not (Test-IsAdministrator)) { Start-RideAsAdministrator }

$repositoryPath = Get-RepositoryPath
if ($NoRun) {
  Write-Output "No installation tasks performed. Repository extracted to: $repositoryPath"
  exit 0
}

$selectedProfile = $Profile
if ($Default -or $Edit -or -not $selectedProfile) {
  $selectedProfile = Join-Path $repositoryPath 'profiles/default.psd1'
}
if ($Edit) {
  $selectedProfile = Join-Path $repositoryPath 'profiles/custom.profile.psd1'
  Copy-Item -LiteralPath (Join-Path $repositoryPath 'profiles/default.psd1') -Destination $selectedProfile -Force
  Start-Process -FilePath 'notepad.exe' -ArgumentList (Quote-ProcessArgument $selectedProfile) -Wait
}
elseif ($Profile -and -not [IO.Path]::IsPathRooted($Profile)) {
  $selectedProfile = Join-Path (Get-Location).Path $Profile
}

$rideScript = Join-Path $repositoryPath 'ride.ps1'
$rideArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Quote-ProcessArgument $rideScript), $Command, '-Profile', (Quote-ProcessArgument $selectedProfile))
& powershell.exe ($rideArguments -join ' ')
if ($LASTEXITCODE -ne 0) { throw "ride.ps1 exited with code $LASTEXITCODE." }
