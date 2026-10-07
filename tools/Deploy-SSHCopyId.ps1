<#
.SYNOPSIS
    Publish the ride-windows ssh-copy-id tool to the current user's bin folder.

.DESCRIPTION
    Copies components/scripts/ssh-copy-id.ps1 to the selected existing folder.
    The repository copy is the source of truth. No other files are changed.

.EXAMPLE
    .\tools\Deploy-SSHCopyId.ps1 -WhatIf

.EXAMPLE
    .\tools\Deploy-SSHCopyId.ps1
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationDirectory = (Join-Path $env:USERPROFILE 'bin')
)

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
