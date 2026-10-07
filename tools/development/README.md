# Development scripts

These scripts are retained as development material. They are not loaded by
`ride.ps1` or enabled by `default.preset`.

## OpenSSH preview

`openssh-preview/Install-OpenSSH.ps1` explores installing the winget OpenSSH
Preview package and preferring its client in PowerShell. RIDE already has
`InstallSSHClient` and `InstallSSHServer` functions for Windows capabilities.
Review package availability, detection, profile changes, and repeatability
before exposing the preview installer through RIDE.

Do not run these scripts as part of a standard RIDE preset until that work is
complete.
