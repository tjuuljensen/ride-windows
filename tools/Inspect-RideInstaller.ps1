<#
.SYNOPSIS
  Inspect an installer sample without running it.
.DESCRIPTION
  Inspect a local file or download a bounded temporary HTTPS sample. Identify
  ZIP packaging and contained EXE/MSI candidates, version/name resource hints,
  launcher architecture and separate download/installer SHA-256 values. A single
  ZIP candidate is inspected automatically; multiple candidates require selection
  in New-RideLibrary.ps1. Suggestions need review. Temporary files are removed.
.PARAMETER Path
  Existing local EXE, MSI or ZIP. At most 256 MiB. Mutually exclusive with Uri.
.PARAMETER Uri
  HTTPS sample URL. Redirects remain HTTPS; download limit is 256 MiB.
.PARAMETER Help
  Display native help and return.
.PARAMETER Version
  Print the script version and return.
.EXAMPLE
  .\tools\Inspect-RideInstaller.ps1 -Uri 'https://win7games.com/download/Windows7Games_for_Windows_11_10_8.zip'
.EXAMPLE
  .\tools\Inspect-RideInstaller.ps1 -Path .\setup.zip
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Sample facts and resource hints; no installation metadata is saved.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Writable temporary directory; HTTPS access for Uri.
  Recovery: WhatIf prevents downloads/extraction. Local files remain unchanged.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add independent inspection of custom-library sample downloads.
.LINK
  ../docs/custom-libraries.md
#>


[CmdletBinding(SupportsShouldProcess)]
param([string] $Path = '', [string] $Uri = '', [switch] $Help, [switch] $Version)
$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }
$ErrorActionPreference = 'Stop'
if ([bool]$Path -eq [bool]$Uri) { throw 'Specify exactly one of -Path or -Uri.' }
Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.InstallerInspection.psm1') -ErrorAction Stop
$parameters = @{ WhatIf = $WhatIfPreference }
if ($Path) { $parameters.Path = $Path } else { $parameters.Uri = $Uri }
if ($PSBoundParameters.ContainsKey('Confirm')) { $parameters.Confirm = $PSBoundParameters.Confirm }
Get-RideInstallerInspection @parameters
