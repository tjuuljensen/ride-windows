# Preparation template, not a declaration of Server integration acceptance.
# Copy outside the repository and select the exact edition/install-mode name from your ISO.
@{
  SchemaVersion = 1
  OperatingSystemName = 'Windows Server 2025 Standard Evaluation (Desktop Experience)'
  LabName = 'RIDES25Test'
  VMName = 'RIDE-S25-Test'
  VMPath = 'D:\VMs\RIDE-S25-Test'
  NetworkName = 'RIDE-Internet'
  MemoryGB = 8
  ProcessorCount = 4
  DisableTpm = $false
  DisableSecureBoot = $false
  WindowsUpdateMode = 'Wait'
  GuestRepositoryPath = 'C:\RIDE\ride-windows'
  CheckpointName = 'RIDE-clean-test-base'
  AutomationName = 'RIDES2025Test'
  CIRepositoryPath = 'C:\RIDE-CI\runner\_work\ride-windows\ride-windows'
  AutomationSeedPath = 'C:\RIDE-Automation\server2025-controller.json'
}
