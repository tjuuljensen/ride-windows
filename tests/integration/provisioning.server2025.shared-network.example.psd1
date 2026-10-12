# Existing-network preparation template. Copy outside the repository for local use.
# Confirm the existing NAT/switch/gateway and reserve the guest IP before applying.
@{
  SchemaVersion = 1
  OperatingSystemName = 'Windows Server 2025 Standard Evaluation (Desktop Experience)'
  LabName = 'RIDESrv2025Test'
  VMName = 'RIDE-S25-Test'
  VMPath = 'D:\VMs\RIDESrv2025Test'
  NetworkMode = 'ExistingNat'
  NetworkName = 'RIDE-Internet'
  NatName = 'RIDE-Internet'
  GuestIpv4Address = '192.168.11.50/24' # Proposed reservation; preflight checks known assignments.
  Ipv4Gateway = '192.168.11.1'
  Ipv4DnsServers = @('1.1.1.1', '8.8.8.8') # Replace if the network requires other resolvers.
  MemoryGB = 8
  ProcessorCount = 4
  DisableTpm = $false
  DisableSecureBoot = $false
  WindowsUpdateMode = 'Wait'
  GuestRepositoryPath = 'C:\RIDE\ride-windows'
  CheckpointName = 'RIDE-clean-test-base'
  AutomationName = 'RIDESrv2025Test'
  CIRepositoryPath = 'C:\RIDE-CI\runner\_work\ride-windows\ride-windows'
  AutomationSeedPath = 'C:\RIDE-Automation\server2025-controller.json'
}
