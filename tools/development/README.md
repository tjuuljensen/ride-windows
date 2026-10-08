# Development scripts

These scripts are retained as development material. They are not loaded by
`ride.ps1` or selected by the maintained profiles.

## OpenSSH preview

`openssh-preview/Install-OpenSSH.ps1` explores installing the winget OpenSSH
Preview package and preferring its client in PowerShell. The historical v2
library contains Windows capability helpers; it is not part of the maintained engine.
Review package availability, detection, profile changes, and repeatability
before exposing the preview installer through RIDE.

Inspect native help with `Get-Help .\tools\development\openssh-preview\Install-OpenSSH.ps1 -Full`.
The script's `-Help` and `-Version` switches return before package or profile changes.

Do not run these scripts as part of a standard RIDE profile until that work is
complete.
