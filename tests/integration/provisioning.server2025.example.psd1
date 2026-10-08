# Preparation template, not a declaration of Server integration acceptance.
# Copy outside the repository and select the exact edition/install-mode name from your ISO.
@{
  SchemaVersion = 1
  OperatingSystemName = 'REPLACE WITH EXACT SERVER 2025 ISO ENTRY'
  LabName = 'RIDEServer2025Test'
  VMName = 'RIDE-S25-Test'
  VMPath = 'D:\VMs\RIDEServer2025Test'
  NetworkName = 'RIDE-S25-Test-NAT'
  MemoryGB = 8
  ProcessorCount = 4
  DisableTpm = $false
  DisableSecureBoot = $false
  WindowsUpdateMode = 'Wait'
  GuestRepositoryPath = 'C:\RIDE\ride-windows'
  CheckpointName = 'RIDE-clean-test-base'
  AutomationName = 'RIDEServer2025Test'
  CIRepositoryPath = 'C:\RIDE-CI\runner\_work\ride-windows\ride-windows'
  AutomationSeedPath = 'C:\RIDE-Automation\server2025-controller.json'
}
