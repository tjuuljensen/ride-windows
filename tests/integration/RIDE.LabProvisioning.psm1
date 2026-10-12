<#
.SYNOPSIS
  Resolve local provisioning data and generate per-VM controller seeds.
.DESCRIPTION
  Data-only helpers; importing this module never provisions or controls a VM.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog:
    0.2.0: Validate explicit existing-NAT topology and address reservations.
    0.1.0: Explicit provisioning-to-controller configuration handoff.
#>

$script:ModuleVersion = '0.2.0'

function ConvertTo-RideLabIpv4Number {
  param([string] $Address)
  if ($Address -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$') { throw "Invalid IPv4 address '$Address'." }
  [long] $number = 0
  foreach ($octet in $Address.Split('.')) {
    if ([int]$octet -gt 255) { throw "Invalid IPv4 address '$Address'." }
    $number = $number * 256 + [int]$octet
  }
  if ($number -eq 0 -or $number -ge 3758096384 -or $Address.StartsWith('127.')) { throw "IPv4 address '$Address' must be unicast and non-loopback." }
  $number
}

function Get-RideLabIpv4Subnet {
  param([string] $Address)
  if ($Address -notmatch '^([^/]+)/([0-9]+)$') { throw 'GuestIpv4Address must include a prefix, for example 192.168.11.50/24.' }
  $ip = $Matches[1]
  $prefix = [int]$Matches[2]
  if ($prefix -lt 2 -or $prefix -gt 30) { throw 'GuestIpv4Address prefix must be from 2 through 30.' }
  $number = ConvertTo-RideLabIpv4Number $ip
  [long] $size = [math]::Pow(2, 32 - $prefix)
  [long] $network = [math]::Floor($number / $size) * $size
  $octets = for ($shift = 24; $shift -ge 0; $shift -= 8) { ($network -shr $shift) -band 255 }
  [pscustomobject]@{ IPAddress = $ip; Number = $number; PrefixLength = $prefix; Network = $network; Broadcast = $network + $size - 1; AddressSpace = ($octets -join '.') + '/' + $prefix }
}

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
  $allowed = @('OperatingSystemName', 'LabName', 'VMName', 'VMPath', 'GuestRepositoryPath', 'MemoryGB', 'ProcessorCount', 'DisableTpm', 'DisableSecureBoot', 'WindowsUpdateMode', 'NetworkName', 'NetworkMode', 'NatName', 'GuestIpv4Address', 'Ipv4Gateway', 'Ipv4DnsServers', 'CheckpointName', 'AutomationName', 'CIRepositoryPath', 'IsoPath', 'AutomationSeedPath')
  $config = @{ GuestRepositoryPath = 'C:\RIDE\ride-windows'; MemoryGB = 8; ProcessorCount = 4; DisableTpm = $false; DisableSecureBoot = $false; WindowsUpdateMode = 'Wait'; NetworkName = 'RIDE-Internet'; NetworkMode = 'NewNat'; CheckpointName = 'RIDE-clean-test-base' }
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
  if ($config.NetworkMode -notin @('NewNat', 'ExistingNat')) { throw 'NetworkMode must be NewNat or ExistingNat.' }
  if ($config.NetworkMode -eq 'ExistingNat') {
    if ([string]::IsNullOrWhiteSpace($config.NatName) -or $config.NatName -match '["\r\n]') { throw 'ExistingNat requires NatName.' }
    $subnet = Get-RideLabIpv4Subnet $config.GuestIpv4Address
    $gateway = ConvertTo-RideLabIpv4Number $config.Ipv4Gateway
    if ($subnet.Number -le $subnet.Network -or $subnet.Number -ge $subnet.Broadcast) { throw 'GuestIpv4Address cannot be the network or broadcast address.' }
    if ($gateway -le $subnet.Network -or $gateway -ge $subnet.Broadcast -or $gateway -eq $subnet.Number) { throw 'Ipv4Gateway must be a different usable address in the guest subnet.' }
    if (@($config.Ipv4DnsServers).Count -eq 0) { throw 'ExistingNat requires explicit Ipv4DnsServers; WinNAT does not supply DNS or DHCP.' }
    foreach ($dns in $config.Ipv4DnsServers) { $null = ConvertTo-RideLabIpv4Number $dns }
    $config.Ipv4DnsServers = [string[]]@($config.Ipv4DnsServers)
  } else {
    foreach ($field in @('NatName', 'GuestIpv4Address', 'Ipv4Gateway', 'Ipv4DnsServers')) {
      if ($config[$field]) { throw "$field is only supported with NetworkMode ExistingNat." }
    }
  }
  foreach ($field in @('VMPath', 'GuestRepositoryPath', 'CIRepositoryPath', 'IsoPath', 'AutomationSeedPath')) {
    if ($config[$field] -and $config[$field] -notmatch '^[A-Za-z]:\\[^"\r\n*?]+$') { throw "$field must be an absolute local Windows path below a drive root." }
  }
  if ((Split-Path -Leaf $config.GuestRepositoryPath) -ne 'ride-windows') { throw 'GuestRepositoryPath must end with ride-windows.' }
  if ($config.AutomationSeedPath -and ([IO.Path]::GetExtension($config.AutomationSeedPath) -ne '.json' -or -not $config.CIRepositoryPath)) { throw 'AutomationSeedPath must end with .json and requires CIRepositoryPath.' }
  if (-not $config.AutomationName -and $config.LabName) { $config.AutomationName = $config.LabName }
  $config
}

function Resolve-RideLabNetworkPlan {
  <#
  .SYNOPSIS
    Validate network inventory and return AutomatedLab definition parameters.
  .DESCRIPTION
    Uses supplied snapshots only. Does not query or change host or lab state.
  .PARAMETER Configuration
    Validated provisioning configuration.
  .PARAMETER Switches
    Hyper-V switch inventory.
  .PARAMETER Nats
    Host WinNAT inventory.
  .PARAMETER HostAddresses
    Host IPv4 addresses, including the selected switch gateway.
  .PARAMETER VMAdapters
    Hyper-V VM adapter inventory, including stopped VMs.
  .PARAMETER ReservedAddresses
    Saved AutomatedLab reservations with VMName, SwitchName and IPAddress.
  .EXAMPLE
    Resolve-RideLabNetworkPlan -Configuration $config -Switches $switches -Nats $nats -HostAddresses $addresses -VMAdapters $adapters -ReservedAddresses $reservations
  .INPUTS
    None.
  .OUTPUTS
    System.Collections.Hashtable. Network and guest adapter parameter splats.
  .NOTES
    Known assignments are checked; silent unmanaged devices still require operator review.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Configuration, [object[]] $Switches = @(), [object[]] $Nats = @(), [object[]] $HostAddresses = @(), [object[]] $VMAdapters = @(), [object[]] $ReservedAddresses = @())
  $config = Resolve-RideLabProvisioningConfiguration -ExplicitParameters $Configuration
  $selectedSwitch = @($Switches | Where-Object Name -eq $config.NetworkName)
  if ($config.NetworkMode -eq 'NewNat') {
    if ($selectedSwitch.Count) { throw "Virtual switch '$($config.NetworkName)' already exists. Select ExistingNat to reuse a reviewed network." }
    if ($Nats.Count) { throw 'Host WinNAT already exists. Select ExistingNat with explicit addressing instead of creating a second NAT.' }
    return @{ VirtualNetworkParameters = @{ Name = $config.NetworkName; UseNat = $true }; NetworkAdapterParameters = @{ VirtualSwitch = $config.NetworkName } }
  }
  if ($selectedSwitch.Count -ne 1 -or $selectedSwitch[0].SwitchType -ne 'Internal') { throw 'ExistingNat requires one existing Internal virtual switch.' }
  if ($Nats.Count -ne 1 -or $Nats[0].Name -ne $config.NatName) { throw "ExistingNat requires exactly one host NAT named '$($config.NatName)'." }
  $subnet = Get-RideLabIpv4Subnet $config.GuestIpv4Address
  if ([string]$Nats[0].InternalIPInterfaceAddressPrefix -ne $subnet.AddressSpace) { throw 'The guest subnet must exactly match the existing NAT prefix.' }
  $gateway = @($HostAddresses | Where-Object { $_.InterfaceAlias -eq "vEthernet ($($config.NetworkName))" -and $_.IPAddress -eq $config.Ipv4Gateway -and $_.PrefixLength -eq $subnet.PrefixLength })
  if ($gateway.Count -ne 1) { throw 'The declared gateway and prefix must already exist on the selected host switch adapter.' }
  if ($HostAddresses.IPAddress -contains $subnet.IPAddress) { throw "Guest IP '$($subnet.IPAddress)' is already assigned to the host." }
  if (@($ReservedAddresses | Where-Object { $_.SwitchName -eq $config.NetworkName -and $_.IPAddress -eq $subnet.IPAddress }).Count) { throw "Guest IP '$($subnet.IPAddress)' is reserved by an existing AutomatedLab machine." }
  foreach ($adapter in @($VMAdapters | Where-Object SwitchName -eq $config.NetworkName)) {
    if (@($adapter.IPAddresses) -contains $subnet.IPAddress) { throw "Guest IP '$($subnet.IPAddress)' is reported by VM '$($adapter.VMName)'." }
    $known = @($adapter.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
    $saved = @($ReservedAddresses | Where-Object { $_.SwitchName -eq $config.NetworkName -and $_.VMName -eq $adapter.VMName })
    if (-not $known.Count -and -not $saved.Count) { throw "Cannot verify addresses for VM '$($adapter.VMName)' on the shared switch. Inspect its guest configuration and AutomatedLab reservation before proceeding." }
  }
  @{
    # Explicit false overrides AutomatedLab's configurable HyperVUseNAT default.
    VirtualNetworkParameters = @{ Name = $config.NetworkName; AddressSpace = $subnet.AddressSpace; UseNat = $false }
    NetworkAdapterParameters = @{ VirtualSwitch = $config.NetworkName; Ipv4Address = $config.GuestIpv4Address; Ipv4Gateway = $config.Ipv4Gateway; Ipv4DnsServers = @($config.Ipv4DnsServers) }
  }
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

Export-ModuleMember -Function Resolve-RideLabProvisioningConfiguration, Resolve-RideLabNetworkPlan, New-RideLabAutomationSeed
