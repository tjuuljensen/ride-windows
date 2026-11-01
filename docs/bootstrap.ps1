<#
.SYNOPSIS
  Download a selected RIDE source archive and optionally run its profile command.

.DESCRIPTION
  Downloads an explicitly selected GitHub tag or branch and extracts below
  InstallRoot or a new temporary directory. NoRun only downloads and extracts.
  Selecting Default, Edit, or Profile defaults to the read-only plan command;
  apply and remove require an explicit command. Machine-changing commands may
  relaunch with elevation and wait for the child exit code. Edit copies the
  default profile and waits for Notepad.

.PARAMETER Author
  GitHub repository owner; defaults to tjuuljensen.

.PARAMETER Repo
  Repository name; defaults to ride-windows.

.PARAMETER Branch
  Explicit branch archive. Select either Branch or Release; neither is implicit.

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
  list, plan, apply, status, or remove; defaults to plan. Pass apply explicitly to change Windows.

.PARAMETER Profile
  Explicit profile path; relative paths resolve from the caller working directory.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\docs\bootstrap.ps1 -Release '<published-v3.0-tag>' -NoRun
  Download and extract the exact published v3.0 tag without launching RIDE.

.EXAMPLE
  .\docs\bootstrap.ps1 -Release '<published-v3.0-tag>' -Default
  Preview the default profile from the exact published v3.0 tag. Applying it requires
  the explicit -Command apply parameter.

.EXAMPLE
  .\docs\bootstrap.ps1 -Release '<published-v3.0-tag>' -Default -Command apply
  Explicitly apply the default profile from the exact published v3.0 tag.

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
  Prerequisites: An explicit reviewed GitHub release tag or source branch, HTTPS access,
  the adjacent modules/RIDE.Bootstrap.psm1 helper, Expand-Archive, powershell.exe, and
  extraction-directory write access; elevation for machine apply/remove unless NoAdmin.
  File/environment inputs: GitHub archive selection and optional profile file; launches Windows
  PowerShell with -NoProfile.
  Recovery: Retain extracted sources for inspection. Use RIDE saved state for applied operations;
  archive extraction itself has no rollback.
  Author: RIDE-Windows maintainers.
  Version: 0.2.0
  Changelog:
    0.2.0: Require an explicit source, make plan the default, quote and wait for
    child processes, and report child exit codes.
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.
  Standalone copies must preserve the docs/bootstrap.ps1 and modules/RIDE.Bootstrap.psm1
  relative layout. The v3.0 entry point uses the published tag explicitly; do not use a
  mutable branch for release installation.

.LINK
  docs/migrations/powershell-script-walkthrough.md

#>


[CmdletBinding()]
param(
  [string] $Author = 'tjuuljensen',
  [string] $Repo = 'ride-windows',
  [string] $Branch = '',
  [string] $Release = '',
  [string] $InstallRoot = '',
  [switch] $Default,
  [switch] $Edit,
  [Alias('Stop')][switch] $NoRun,
  [switch] $NoAdmin,
  [ValidateSet('list', 'plan', 'apply', 'status', 'remove')]
  [string] $Command = 'plan',
  [string] $Profile = '',
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.2.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

$ErrorActionPreference = 'Stop'
$bootstrapRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Import-Module (Join-Path $bootstrapRoot 'modules/RIDE.Bootstrap.psm1') -Force -ErrorAction Stop
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch { Write-Verbose 'Unable to set TLS 1.2 explicitly; continuing with platform defaults.' }

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-TemporaryDirectory {
  $path = Join-Path ([IO.Path]::GetTempPath()) ('ride-windows-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $path -Force | Out-Null
  $path
}

function Get-RepositoryArchiveUrl {
  if ($Release -and $Branch) { throw 'Select exactly one source: -Release <tag> or -Branch <branch>.' }
  if (-not $Release -and -not $Branch) { throw 'Select a reviewed release tag with -Release or an explicit source branch with -Branch.' }
  $ref = if ($Release) { $Release } else { $Branch }
  $escapedRef = (($ref -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
  if ($Release) { return "https://github.com/$Author/$Repo/archive/refs/tags/$escapedRef.zip" }
  "https://github.com/$Author/$Repo/archive/refs/heads/$escapedRef.zip"
}

function Get-RepositoryPath {
  if (-not $InstallRoot) { $script:InstallRoot = New-TemporaryDirectory }
  New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
  $archivePath = Join-Path $InstallRoot ($Repo + '.zip')
  Invoke-WebRequest -Uri $script:ArchiveUrl -OutFile $archivePath -UseBasicParsing -ErrorAction Stop
  Expand-Archive -Path $archivePath -DestinationPath $InstallRoot -Force
  Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
  $scriptPath = Get-ChildItem -Path $InstallRoot -Filter 'ride.ps1' -Recurse -File | Select-Object -First 1
  if (-not $scriptPath) { throw 'The downloaded archive did not contain ride.ps1.' }
  $scriptPath.Directory.FullName
}

function Start-RideAsAdministrator {
  $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
  foreach ($key in $PSBoundParameters.Keys) {
    $value = $PSBoundParameters[$key]
    if ($value -is [switch]) {
      if ($value.IsPresent) { $arguments += "-$key" }
    }
    elseif ($null -ne $value -and $value -ne '') {
      $arguments += "-$key"
      $arguments += [string]$value
    }
  }
  $process = Start-Process -FilePath 'powershell.exe' -ArgumentList (Join-RideWindowsCommandLine $arguments) -Verb RunAs -WorkingDirectory (Get-Location).Path -Wait -PassThru -ErrorAction Stop
  if ($null -eq $process.ExitCode) { throw 'The elevated bootstrap process did not return an exit code.' }
  [int]$process.ExitCode
}

$hasRunMode = $Default -or $Edit -or ($Profile -ne '') -or ($Command -ne 'plan')
if ($NoRun) { $hasRunMode = $false }
if (-not $hasRunMode -and -not $NoRun) {
  throw 'Select -NoRun or a profile mode (-Default, -Edit or -Profile); source selection is also required.'
}
$script:ArchiveUrl = Get-RepositoryArchiveUrl
$requiresElevation = $hasRunMode -and -not $NoAdmin -and $Command -in @('apply', 'remove')
if ($requiresElevation -and -not (Test-IsAdministrator)) {
  $exitCode = Start-RideAsAdministrator
  if ($exitCode -ne 0) { throw "Elevated bootstrap process exited with code $exitCode." }
  return
}

$repositoryPath = Get-RepositoryPath
if ($NoRun) {
  Write-Output "No installation tasks performed. Repository extracted to: $repositoryPath"
  return
}

$selectedProfile = $Profile
if ($Default -or $Edit -or -not $selectedProfile) {
  $selectedProfile = Join-Path $repositoryPath 'profiles/default.psd1'
}
if ($Edit) {
  $selectedProfile = Join-Path $repositoryPath 'profiles/custom.profile.psd1'
  Copy-Item -LiteralPath (Join-Path $repositoryPath 'profiles/default.psd1') -Destination $selectedProfile -Force
  Start-Process -FilePath 'notepad.exe' -ArgumentList (ConvertTo-RideWindowsCommandLineArgument $selectedProfile) -WorkingDirectory (Get-Location).Path -Wait
}
elseif ($Profile -and -not [IO.Path]::IsPathRooted($Profile)) {
  $selectedProfile = Join-Path (Get-Location).Path $Profile
}

$rideScript = Join-Path $repositoryPath 'ride.ps1'
$rideArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $rideScript, $Command, '-Profile', $selectedProfile)
& powershell.exe @rideArguments
$rideExitCode = $LASTEXITCODE
if ($null -eq $rideExitCode) { throw 'The RIDE child process did not return an exit code.' }
if ($rideExitCode -ne 0) { throw "ride.ps1 exited with code $rideExitCode." }
