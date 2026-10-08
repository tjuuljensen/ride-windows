<#
.SYNOPSIS
  Publish the repository ssh-copy-id tool to an existing user directory.

.DESCRIPTION
  Compares source/destination SHA-256 and copies only when different and approved by ShouldProcess.
  Verifies the copy. Does not create the destination directory or contact SSH hosts.

.PARAMETER DestinationDirectory
  Existing destination directory; defaults to the current user profile bin directory.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\tools\Deploy-SSHCopyId.ps1 -WhatIf

.EXAMPLE
  .\tools\Deploy-SSHCopyId.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Progress and diagnostic messages.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Existing writable destination directory and repository source tool.
  File/environment inputs: components/scripts/ssh-copy-id.ps1; USERPROFILE provides the default
  destination.
  Recovery: Republish the desired reviewed source version. No destination backup is created.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

#>


[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationDirectory = (Join-Path $env:USERPROFILE 'bin'),
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repositoryRoot 'components\scripts\ssh-copy-id.ps1'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Source tool was not found: $source"
}

$destinationRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationDirectory)
if (-not (Test-Path -LiteralPath $destinationRoot -PathType Container)) {
    throw "Destination directory does not exist: $destinationRoot"
}

$destination = Join-Path $destinationRoot 'ssh-copy-id.ps1'
$sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
if (Test-Path -LiteralPath $destination -PathType Leaf) {
    $destinationHash = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($sourceHash -eq $destinationHash) {
        Write-Output "Already current: $destination"
        return
    }
}

if ($PSCmdlet.ShouldProcess($destination, 'Publish ssh-copy-id.ps1 from ride-windows')) {
    Copy-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $sourceHash) {
        throw "Published file does not match the source: $destination"
    }
    Write-Output "Published: $destination"
}
