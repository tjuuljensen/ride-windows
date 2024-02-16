# Profile file writer
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
