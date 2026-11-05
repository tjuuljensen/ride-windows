<#
.SYNOPSIS
  Ensure the pinned Pester test runner is available to the disposable guest user.

.DESCRIPTION
  Installs Pester 5.7.1 from PowerShell Gallery for the current guest user only when the
  exact version is absent. The caller is responsible for restoring the disposable VM checkpoint.

.EXAMPLE
  Install-RideGuestPester
  Return the installed module path and whether this run acquired the pinned version.

.INPUTS
  None.

.OUTPUTS
  System.Management.Automation.PSCustomObject. Pinned version, module path and setup action.

.NOTES
  Compatibility: Windows PowerShell 5.1 on disposable Windows guests.
  Prerequisites: PowerShellGet, NuGet provider access and HTTPS access to PowerShell Gallery.
  Source: https://www.powershellgallery.com/packages/Pester/5.7.1
  Recovery: This setup is transient; the VM controller restores the pinned checkpoint after the run.
  Version: 0.1.0
  Changelog:
    0.1.0: Install the pinned guest test dependency only when it is missing.
#>

function Install-RideGuestPester {
  [CmdletBinding()]
  param()

  $requiredVersion = [version]'5.7.1'
  $available = @(Get-Module -ListAvailable -Name 'Pester' | Where-Object { $_.Version -eq $requiredVersion })
  $action = 'AlreadyPresent'
  if (-not $available.Count) {
    Install-PackageProvider -Name 'NuGet' -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
    Install-Module -Name 'Pester' -RequiredVersion ($requiredVersion.ToString()) -Repository 'PSGallery' -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop
    $action = 'Installed'
    $available = @(Get-Module -ListAvailable -Name 'Pester' | Where-Object { $_.Version -eq $requiredVersion })
  }

  if (-not $available.Count) { throw 'Pester 5.7.1 is unavailable after the guest dependency setup.' }
  [pscustomobject]@{
    Name = 'Pester'
    Version = $requiredVersion.ToString()
    Action = $action
    Repository = if ($action -eq 'Installed') { 'PSGallery' } else { $null }
    ModuleBase = $available[0].ModuleBase
  }
}

Export-ModuleMember -Function 'Install-RideGuestPester'
