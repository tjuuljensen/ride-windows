<#
.SYNOPSIS
  Observe OpenSSH Server capability, service, firewall and server-data state.
.DESCRIPTION
  Captures bounded read-only local observations for a specifically identified Windows
  target. It never starts/stops sshd, changes firewall rules, reads file contents, or
  claims mutation readiness or recovery support.
.PARAMETER ExpectedComputerName
  Intended local machine name.
.PARAMETER ExpectedBuild
  Exact intended Windows build number.
.PARAMETER ExpectedEditionId
  Intended Windows EditionID.
.INPUTS
  None.
.OUTPUTS
  PSCustomObject. Schema-versioned observation with independent component surfaces.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Native Windows process and readable local component/service/firewall data.
  Version: 0.1.0.
  Recovery: Observation only; ReadyForMutation and RecoverySupported are always false.
  Changelog: 0.1.0: Add bounded, read-only OpenSSH Server surface observation.
.LINK
  ../docs/windows-component-inventory.md#openssh-server-component-boundary
#>
$ErrorActionPreference = 'Stop'

function Get-RideOpenSshServerPlatformContext {
  if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') { throw 'OpenSSH Server observation is available only on Windows.' }
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'OpenSSH Server observation is available only on Windows.' }
  $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $product = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop
  [pscustomobject]@{
    ComputerName = [Environment]::MachineName
    Build = [string]$version.CurrentBuildNumber
    EditionId = [string]$version.EditionID
    UpdateBuildRevision = $version.UBR
    InstallationType = [string]$version.InstallationType
    ProductType = [string]$product.ProductType
    NativeProcess = ([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)
  }
}

function Get-RideOpenSshServerCapabilityState {
  $matches = @(Dism\Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -ceq 'OpenSSH.Server~~~~0.0.1.0' })
  if ($matches.Count -gt 1) { throw 'OpenSSH Server capability identity is duplicated.' }
  if ($matches.Count -eq 0) { return [pscustomobject]@{ Status = 'NotObserved'; Name = 'OpenSSH.Server~~~~0.0.1.0'; State = $null } }
  if ([string]$matches[0].State -cnotin @('Installed','NotPresent')) { throw 'OpenSSH Server capability state is not recognized.' }
  [pscustomobject]@{ Status = 'Captured'; Name = [string]$matches[0].Name; State = [string]$matches[0].State }
}

function Get-RideOpenSshServerDataRoot {
  Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'ssh'
}

function Get-RideOpenSshServerServiceState {
  $matches = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'" -ErrorAction Stop)
  if ($matches.Count -gt 1) { throw 'OpenSSH Server service identity is duplicated.' }
  if ($matches.Count -eq 0) { return [pscustomobject]@{ Status = 'NotFound'; Name = 'sshd'; State = $null; StartMode = $null; StartName = $null } }
  foreach ($field in @('State','StartMode','StartName')) {
    $value = [string]$matches[0].$field
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 128 -or $value -match '[\x00-\x1f]') { throw "OpenSSH Server service $field is missing or invalid." }
  }
  [pscustomobject]@{ Status = 'Captured'; Name = 'sshd'; State = [string]$matches[0].State; StartMode = [string]$matches[0].StartMode; StartName = [string]$matches[0].StartName }
}

function Get-RideOpenSshServerFirewallState {
  $matches = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop)
  if ($matches.Count -gt 1) { throw 'OpenSSH Server firewall rule identity is duplicated.' }
  if ($matches.Count -eq 0) { return [pscustomobject]@{ Status = 'NotFound'; Name = 'OpenSSH-Server-In-TCP'; Enabled = $null; Direction = $null; Action = $null; Profile = $null; Protocol = $null; LocalPort = $null; PolicyStoreSourceType = $null; PolicyStoreSource = $null } }
  $rule = $matches[0]
  $ports = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
  if ($ports.Count -ne 1) { throw 'OpenSSH Server firewall port-filter state is missing or ambiguous.' }
  $enabled = [string]$rule.Enabled
  $direction = [string]$rule.Direction
  $action = [string]$rule.Action
  $profile = [string]$rule.Profile
  $protocol = [string]$ports[0].Protocol
  $localPort = [string]$ports[0].LocalPort
  foreach ($value in @($enabled,$direction,$action,$profile,$protocol,$localPort)) {
    if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 256 -or $value -match '[\x00-\x1f]') { throw 'OpenSSH Server firewall rule contains missing or invalid fields.' }
  }
  [pscustomobject]@{
    Status = 'Captured'; Name = [string]$rule.Name; Enabled = $enabled; Direction = $direction
    Action = $action; Profile = $profile; Protocol = $protocol; LocalPort = $localPort
    PolicyStoreSourceType = [string]$rule.PolicyStoreSourceType; PolicyStoreSource = [string]$rule.PolicyStoreSource
  }
}

function Get-RideOpenSshServerDataState {
  $root = Get-RideOpenSshServerDataRoot
  if (-not [IO.Directory]::Exists($root)) { return [pscustomobject]@{ Status = 'NotFound'; Root = $root; Files = @(); TotalBytes = 0 } }
  $directory = Get-Item -LiteralPath $root -Force -ErrorAction Stop
  if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'OpenSSH Server data directory cannot be a reparse point.' }
  $files = @(Get-ChildItem -LiteralPath $root -Force -File -ErrorAction Stop | Sort-Object Name)
  if ($files.Count -gt 256) { throw 'OpenSSH Server data directory exceeds the file-count bound.' }
  $totalBytes = [long]0
  $records = [Collections.Generic.List[object]]::new()
  foreach ($file in $files) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'OpenSSH Server data contains a reparse-point file.' }
    $totalBytes += [long]$file.Length
    if ($totalBytes -gt 16777216) { throw 'OpenSSH Server data directory exceeds the 16 MiB observation bound.' }
    $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop
    $records.Add([pscustomobject]@{
      Name = [string]$file.Name
      Length = [long]$file.Length
      LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString('o')
      Sha256 = $hash.Hash.ToLowerInvariant()
      PrivateHostKey = ($file.Name -match '^ssh_host_.+_key$')
    })
  }
  [pscustomobject]@{ Status = 'Captured'; Root = $root; Files = @($records.ToArray()); TotalBytes = $totalBytes }
}

function Get-RideOpenSshServerState {
  <#
  .SYNOPSIS
    Capture the separate OpenSSH Server state surfaces without changing them.
  .DESCRIPTION
    Reads the exact capability, sshd service, built-in firewall rule, and bounded
    direct-child file inventory under ProgramData\ssh. Private key bytes are never
    returned; file hashes support later comparison but are not recovery copies.
  .PARAMETER ExpectedComputerName
    Intended local computer name.
  .PARAMETER ExpectedBuild
    Exact build to compare with the current local target.
  .PARAMETER ExpectedEditionId
    Exact edition to compare with the current local target.
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Read-only OpenSshServerObservation.
  .NOTES
    This observation is not a transition plan, authorization, or support declaration.
    Failed providers are Unavailable and never imply absence.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId
  )
  $context = Get-RideOpenSshServerPlatformContext
  if (-not $context.NativeProcess -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId -or $context.ProductType -cnotin @('WinNT','ServerNT','LanmanNT')) {
    throw 'OpenSSH Server observation target differs from the expected native machine/build/edition.'
  }
  $providers = foreach ($name in @('Capability','Service','Firewall','ServerData')) {
    try {
      $value = switch ($name) {
        'Capability' { Get-RideOpenSshServerCapabilityState }
        'Service' { Get-RideOpenSshServerServiceState }
        'Firewall' { Get-RideOpenSshServerFirewallState }
        'ServerData' { Get-RideOpenSshServerDataState }
      }
      [pscustomobject]@{ Name = $name; Status = [string]$value.Status; Observation = $value; ErrorType = $null }
    } catch {
      [pscustomobject]@{ Name = $name; Status = 'Unavailable'; Observation = $null; ErrorType = $_.Exception.GetType().FullName }
    }
  }
  [pscustomobject]@{
    SchemaVersion = 1
    Kind = 'OpenSshServerObservation'
    WindowsContext = $context
    Providers = @($providers)
    Consistency = 'Sequential read-only observations; not atomic'
    ReadyForMutation = $false
    RecoverySupported = $false
  }
}

Export-ModuleMember -Function Get-RideOpenSshServerState
