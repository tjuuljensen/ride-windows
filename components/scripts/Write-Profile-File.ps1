<#
.SYNOPSIS
  Append user-bin and WindowsApps PATH snippets to the current host profile.

.DESCRIPTION
  Creates the current user/current host profile file when absent. Adds user bin configuration only
  when that folder exists and a UserBinaries marker is absent. Adds WindowsApps when its marker is
  absent. Writes profile text immediately; has no WhatIf or automatic backup.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\components\scripts\Write-Profile-File.ps1 -Help

.EXAMPLE
  .\components\scripts\Write-Profile-File.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String and System.IO.FileInfo. Status strings and a newly created profile file when
  applicable.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Writable current-user PowerShell profile directory; back up the profile before
  operational invocation.
  File/environment inputs: PROFILE.CurrentUserCurrentHost, USERPROFILE, LOCALAPPDATA, and existing
  profile marker text.
  Recovery: Restore the prior profile backup or remove only the added snippets.
  Error-handling exception: Existing operational error policy is retained; globally enabling Stop
  requires a separate tested change.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.

#>


[CmdletBinding()]
param(
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

$ProfileFile = $profile.CurrentUserCurrentHost

if (!(Test-Path -Path $ProfileFile)) {
    New-Item -ItemType File -Path $ProfileFile -Force
    Add-Content -Path $ProfileFile -Value '# PowerShell Profile file
# This file was created by ride-windows script'
  }

# UserBinaries
if (Test-Path -Path  (Join-Path -Path ([System.Environment]::GetFolderPath("USERPROFILE")) -ChildPath "bin")) {
    If (Select-String -Path $ProfileFile -Pattern "UserBinaries" -SimpleMatch -Quiet) {
        Write-Output "UserBinary path is already in profile."
    } else {
        # Add UserBinary config to $ProfileFile
        Add-Content -Path $ProfileFile -Value '
    # UserBinaries
    $UserBinaries = Join-Path -Path ([System.Environment]::GetFolderPath("USERPROFILE")) -ChildPath "bin"
    $env:Path += ";$UserBinaries"
    ' 
}
}

# WindowsApps path
If (Select-String -Path $ProfileFile -Pattern "WindowsApps" -SimpleMatch -Quiet) {
    Write-Output "WindowsApps path is already in profile."
} else {
    # Add WindowsApps config to $ProfileFile
    Add-Content -Path $ProfileFile -Value '
# WindowsApps
$WindowsAppsPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\WindowsApps"
$env:Path += ";$WindowsAppsPath"
' 
}
