<#
.SYNOPSIS
  Download a selected RIDE source archive and optionally run its profile command.

.DESCRIPTION
  Downloads a GitHub tag when Release is supplied, otherwise Branch (master by
  default). Extracts below InstallRoot or a new temporary directory. NoRun only
  downloads/extracts. Default, Edit, Profile, or an explicit non-apply command
  select execution; the default command is apply. Execution normally relaunches
  with elevation. Edit copies the default profile and waits for Notepad.
  This bootstrapper has no ShouldProcess preview; selecting apply changes Windows.

.PARAMETER Author
  GitHub repository owner; defaults to tjuuljensen.

.PARAMETER Repo
  Repository name; defaults to ride-windows.

.PARAMETER Branch
  Branch archive used when Release is empty; defaults to master.

.PARAMETER Release
  Optional Git tag archive. Prefer a reviewed tagged release for distribution.

.PARAMETER InstallRoot
  Extraction directory; omitted selects a new temporary directory. Existing files may be overwritten
  during extraction.

.PARAMETER Default
  Explicitly select the downloaded default profile for execution.

.PARAMETER Edit
  Copy the default profile to custom.profile.psd1, edit in Notepad, then run the selected command.

.PARAMETER NoRun
  Download and extract without launching RIDE; Stop is an alias.

.PARAMETER NoAdmin
  Suppress the normal elevated relaunch. Machine operations still require elevation.

.PARAMETER Command
  list, plan, apply, status, or remove; defaults to apply. Use an explicit run selector for apply.

.PARAMETER Profile
  Explicit profile path; relative paths resolve from the caller working directory.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\docs\bootstrap.ps1 -NoRun -Branch master
  Download the branch source without running it; use -Release with a reviewed tag for distribution.

.EXAMPLE
  .\docs\bootstrap.ps1 -Help

.EXAMPLE
  .\docs\bootstrap.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Progress and diagnostic messages.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: GitHub HTTPS access, Expand-Archive, powershell.exe, and permissions to the
  extraction directory; elevation for machine application.
  File/environment inputs: GitHub archive selection and optional profile file; launches Windows
  PowerShell with -NoProfile.
  Recovery: Retain extracted sources for inspection. Use RIDE saved state for applied operations;
  archive extraction itself has no rollback.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.
  Known limitation: see docs/migrations/powershell-script-walkthrough.md for child-process argument
  handling and preview boundaries.

.LINK
  docs/migrations/powershell-script-walkthrough.md

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
  [string] $Profile = '',
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

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
