# Local provisioning template. Copy outside the repository and replace OS/media/storage paths.
# SchemaVersion 1; credentials are requested interactively and never stored here.
@{
  SchemaVersion = 1
  OperatingSystemName = 'Windows 11 Enterprise Evaluation' # Use the exact discovered ISO entry.
  LabName = 'RIDEWin11Pilot'
  VMName = 'RIDE-W11-Pilot'
  VMPath = 'D:\VMs\RIDEWin11Pilot' # New or empty per-lab storage directory.
  NetworkName = 'RIDE-W11-Pilot-NAT' # Must not identify an existing virtual switch.
  MemoryGB = 8
  ProcessorCount = 4
  DisableTpm = $false
  DisableSecureBoot = $false
  WindowsUpdateMode = 'Wait'
  GuestRepositoryPath = 'C:\RIDE\ride-windows'
  CheckpointName = 'RIDE-clean-test-base'
  AutomationName = 'RIDEWin11Pilot'
  CIRepositoryPath = 'C:\RIDE-CI\runner\_work\ride-windows\ride-windows'
  AutomationSeedPath = 'C:\RIDE-Automation\win11-controller.json'
}
