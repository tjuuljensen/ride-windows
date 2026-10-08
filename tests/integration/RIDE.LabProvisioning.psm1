<#
.SYNOPSIS
  Resolve local provisioning data and generate per-VM controller seeds.
.DESCRIPTION
  Data-only helpers; importing this module never provisions or controls a VM.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Explicit provisioning-to-controller configuration handoff.
#>

$script:ModuleVersion = '0.1.0'

function Resolve-RideLabProvisioningConfiguration {
  <#
  .SYNOPSIS
    Merge local provisioning data with explicitly supplied CLI parameters.
  .DESCRIPTION
    Reads bounded declarative data, applies explicit overrides and validates values.
  .PARAMETER ConfigurationPath
    Optional local schema-versioned PSD1 data file.
  .PARAMETER ExplicitParameters
    Provisioning script bound parameters; explicit values take precedence.
  .EXAMPLE
    Resolve-RideLabProvisioningConfiguration -ConfigurationPath C:\RIDE-Automation\win11.psd1
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. Validated effective configuration.
  .NOTES
    Never evaluates configuration as script; no host state changes.
  #>
  [CmdletBinding()]
  param([string] $ConfigurationPath, [System.Collections.IDictionary] $ExplicitParameters = @{})
  $allowed = @('OperatingSystemName', 'LabName', 'VMName', 'VMPath', 'GuestRepositoryPath', 'MemoryGB', 'ProcessorCount', 'DisableTpm', 'DisableSecureBoot', 'WindowsUpdateMode', 'NetworkName', 'CheckpointName', 'AutomationName', 'CIRepositoryPath', 'IsoPath', 'AutomationSeedPath')
  $config = @{ GuestRepositoryPath = 'C:\RIDE\ride-windows'; MemoryGB = 8; ProcessorCount = 4; DisableTpm = $false; DisableSecureBoot = $false; WindowsUpdateMode = 'Wait'; NetworkName = 'RIDE-Internet'; CheckpointName = 'RIDE-clean-test-base' }
  if ($ConfigurationPath) {
    $inputFile = Get-Item -LiteralPath $ConfigurationPath -ErrorAction Stop
    if ($inputFile.Length -gt 64KB -or $inputFile.Extension -ne '.psd1') { throw 'Provisioning configuration must be a PSD1 data file no larger than 64 KiB.' }
    $seed = Import-PowerShellDataFile -LiteralPath $inputFile.FullName -ErrorAction Stop
    if ($seed.SchemaVersion -ne 1) { throw 'Provisioning configuration requires SchemaVersion 1.' }
    foreach ($key in $seed.Keys) {
      if ($key -eq 'SchemaVersion') { continue }
      if ($key -notin $allowed) { throw "Unsupported provisioning field '$key'. Credentials must not be stored here." }
      $config[$key] = $seed[$key]
    }
  }
  foreach ($key in $allowed) { if ($key -in $ExplicitParameters.Keys) { $config[$key] = $ExplicitParameters[$key] } }
  foreach ($field in @('LabName', 'AutomationName')) {
    if ($config[$field] -and $config[$field] -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,30}$') { throw "Invalid $field." }
  }
  if ($config.VMName -and $config.VMName -notmatch '^[A-Za-z0-9][A-Za-z0-9-]{0,14}$') { throw 'VMName must be 1-15 letters, digits or hyphens.' }
  if ($config.MemoryGB -isnot [int] -or $config.MemoryGB -lt 2 -or $config.MemoryGB -gt 64) { throw 'MemoryGB must be an integer from 2 to 64.' }
  if ($config.ProcessorCount -isnot [int] -or $config.ProcessorCount -lt 1 -or $config.ProcessorCount -gt 32) { throw 'ProcessorCount must be an integer from 1 to 32.' }
  foreach ($field in @('DisableTpm', 'DisableSecureBoot')) {
    if ($config[$field] -isnot [bool] -and $config[$field] -isnot [Management.Automation.SwitchParameter]) { throw "$field must be Boolean." }
  }
  if ($config.WindowsUpdateMode -notin @('Wait', 'Continue')) { throw 'WindowsUpdateMode must be Wait or Continue.' }
  foreach ($field in @('NetworkName', 'CheckpointName')) { if ([string]::IsNullOrWhiteSpace($config[$field]) -or $config[$field] -match '["\r\n]') { throw "Invalid $field." } }
  foreach ($field in @('VMPath', 'GuestRepositoryPath', 'CIRepositoryPath', 'IsoPath', 'AutomationSeedPath')) {
    if ($config[$field] -and $config[$field] -notmatch '^[A-Za-z]:\\[^"\r\n*?]+$') { throw "$field must be an absolute local Windows path below a drive root." }
  }
  if ((Split-Path -Leaf $config.GuestRepositoryPath) -ne 'ride-windows') { throw 'GuestRepositoryPath must end with ride-windows.' }
  if ($config.AutomationSeedPath -and ([IO.Path]::GetExtension($config.AutomationSeedPath) -ne '.json' -or -not $config.CIRepositoryPath)) { throw 'AutomationSeedPath must end with .json and requires CIRepositoryPath.' }
  if (-not $config.AutomationName -and $config.LabName) { $config.AutomationName = $config.LabName }
  $config
}

function New-RideLabAutomationSeed {
  <#
  .SYNOPSIS
    Build the existing controller schema from resolved provisioning identities.
  .DESCRIPTION
    Returns registration seed data without writing files or changing host resources.
  .PARAMETER Configuration
    Effective provisioning configuration.
  .PARAMETER VMId
    Hyper-V VM GUID discovered after provisioning.
  .PARAMETER RepositoryPath
    Host source checkout used for provisioning and Local test requests.
  .PARAMETER IsoPath
    Exact source ISO path used for the selected operating-system entry.
  .EXAMPLE
    New-RideLabAutomationSeed -Configuration $config -VMId $vm.Id -RepositoryPath $repo -IsoPath $iso
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. SchemaVersion 1 controller registration seed.
  .NOTES
    Registration remains explicit and pins checkpoint identity/dependency hashes.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Configuration, [Parameter(Mandatory)][guid] $VMId, [Parameter(Mandatory)][string] $RepositoryPath, [Parameter(Mandatory)][string] $IsoPath)
  if ($VMId -eq [guid]::Empty -or -not $Configuration.CIRepositoryPath -or -not $Configuration.AutomationName -or -not $IsoPath) { throw 'Controller seed requires a discovered VM ID, ISO, automation name and CI checkout path.' }
  if ($RepositoryPath.TrimEnd('\') -eq $Configuration.CIRepositoryPath.TrimEnd('\')) { throw 'Local and CI repository paths must differ.' }
  @{
    SchemaVersion = 1; Name = $Configuration.AutomationName; IsDisposable = $true
    LabName = $Configuration.LabName; VMName = $Configuration.VMName; VMId = $VMId.ToString()
    CheckpointName = $Configuration.CheckpointName; GuestRepositoryPath = $Configuration.GuestRepositoryPath
    LocalRepositoryPath = $RepositoryPath; CIRepositoryPath = $Configuration.CIRepositoryPath; IsoPath = $IsoPath
  }
}

Export-ModuleMember -Function Resolve-RideLabProvisioningConfiguration, New-RideLabAutomationSeed
