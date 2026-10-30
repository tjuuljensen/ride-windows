<#
.SYNOPSIS
  Run one explicit RIDE BitLocker OS-volume workflow action.
.DESCRIPTION
  Exposes the focused BitLocker lifecycle module without using generic apply,
  saved-run restore, pipeline display, or snapshots for recovery secrets. Use a
  disposable Windows target for acceptance; this tool never selects a data drive.
.PARAMETER OperationId
  One BitLocker workflow ID from catalog/operations.psd1; completion reads that catalog.
.PARAMETER MountPoint
  Explicit current OS drive-letter mount point.
.PARAMETER KeyProtectorId
  Exact existing recovery-password protector ID for backup handoff or ShowRecoveryPassword.
.PARAMETER BackupDestination
  Intended native UI destination: FileOrUsb, PersonalMicrosoftAccount, or Print.
.PARAMETER RecoveryProtectorId
  Exact protector ID to rely on for Enable.
.PARAMETER VerifiedBackupProtectorId
  Exact matching ID, entered only after verifying off-device recovery access.
.PARAMETER EncryptionScope
  UsedSpaceOnly or FullVolume. Consider prior contents before selecting.
.PARAMETER StartupAuthentication
  TPMOnly or TPMAndPIN. The PIN is read as a SecureString after preview approval.
.EXAMPLE
  .\tools\Invoke-RideBitLockerWorkflow.ps1 -OperationId windows.bitlocker-enrollment -MountPoint C: -RecoveryProtectorId '{id}' -VerifiedBackupProtectorId '{id}' -EncryptionScope UsedSpaceOnly -StartupAuthentication TPMOnly
.EXAMPLE
  .\tools\Invoke-RideBitLockerWorkflow.ps1 -OperationId windows.bitlocker-add-recovery-password -MountPoint C: -Confirm
.EXAMPLE
  .\tools\Invoke-RideBitLockerWorkflow.ps1 -OperationId windows.bitlocker-backup-recovery-password -MountPoint C: -KeyProtectorId '{id}' -BackupDestination FileOrUsb
.INPUTS
  None. Values are supplied explicitly.
.OUTPUTS
  Nonsecret status and protector metadata. Recovery passwords are shown only in
  a local dialog and are never returned to the pipeline.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: BitLocker PowerShell feature; elevation for state changes; an
  interactive desktop for local secret presentation.
  Recovery: Enrollment and decryption are staged native operations and cannot
  be exactly undone through RIDE restore. See docs/bitlocker-recovery.md.
  Version: 0.1.0
  Changelog: 0.1.0: Add explicit BitLocker OS-volume workflow entry point.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { $scriptPath = (Get-Command $commandName -CommandType ExternalScript -ErrorAction Stop).Source }
      $root = Split-Path -Parent (Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path)
      Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      $catalog = Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
      foreach ($candidate in @($catalog.Operations | Where-Object Kind -eq 'BitLockerWorkflow' | ForEach-Object Id | Sort-Object -Unique)) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) { [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate) }
      }
    } catch { }
  })]
  [string] $OperationId,
  [Parameter(Mandatory = $true)][string] $MountPoint,
  [string] $KeyProtectorId,
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { $scriptPath = (Get-Command $commandName -CommandType ExternalScript -ErrorAction Stop).Source }
      $root = Split-Path -Parent (Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path)
      Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      $catalog = Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
      $operation = $catalog.Operations | Where-Object { $_.Id -eq $fakeBoundParameters.OperationId -and $_.Kind -eq 'BitLockerWorkflow' -and $_.Workflow -eq 'BackupRecoveryPassword' } | Select-Object -First 1
      foreach ($candidate in @($operation.BackupDestinationChoices | Sort-Object -Unique)) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) { [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate) }
      }
    } catch { }
  })][string] $BackupDestination,
  [string] $RecoveryProtectorId,
  [string] $VerifiedBackupProtectorId,
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { $scriptPath = (Get-Command $commandName -CommandType ExternalScript -ErrorAction Stop).Source }
      $root = Split-Path -Parent (Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path)
      Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      $catalog = Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
      $operation = $catalog.Operations | Where-Object { $_.Id -eq $fakeBoundParameters.OperationId -and $_.Kind -eq 'BitLockerWorkflow' } | Select-Object -First 1
      foreach ($candidate in @($operation.EncryptionScopes | Sort-Object -Unique)) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) { [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate) }
      }
    } catch { }
  })][string] $EncryptionScope,
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $scriptPath = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { $scriptPath = (Get-Command $commandName -CommandType ExternalScript -ErrorAction Stop).Source }
      $root = Split-Path -Parent (Split-Path -Parent (Resolve-Path -LiteralPath $scriptPath).Path)
      Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      $catalog = Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
      $operation = $catalog.Operations | Where-Object { $_.Id -eq $fakeBoundParameters.OperationId -and $_.Kind -eq 'BitLockerWorkflow' } | Select-Object -First 1
      foreach ($candidate in @($operation.StartupAuthenticationChoices | Sort-Object -Unique)) {
        if ($candidate.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase)) { [Management.Automation.CompletionResult]::new($candidate, $candidate, 'ParameterValue', $candidate) }
      }
    } catch { }
  })][string] $StartupAuthentication
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repositoryRoot 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
Import-Module (Join-Path $repositoryRoot 'modules/RIDE.CatalogValidation.psm1') -ErrorAction Stop
$catalog = Import-RideCatalogData -Path (Join-Path $repositoryRoot 'catalog/operations.psd1')
$validationErrors = @(Get-RideCatalogValidationErrors -Catalog $catalog)
if ($validationErrors.Count -gt 0) { throw 'The BitLocker workflow catalog is invalid; no action was started.' }
$operation = $catalog.Operations | Where-Object { $_.Id -eq $OperationId -and $_.Kind -eq 'BitLockerWorkflow' } | Select-Object -First 1
if (-not $operation) { throw "Unknown BitLocker workflow operation '$OperationId'." }
if ($operation.PendingAcceptance -or @($operation.SupportedTargets).Count -eq 0) { throw "'$OperationId' remains pending disposable Windows acceptance; no action was started." }
$currentTarget = $null
try {
  $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  if ([string]$windows.ProductName -match 'Windows Server') {
    if ([int]$windows.CurrentBuildNumber -ge 26100) { $currentTarget = 'Windows Server 2025' }
  }
  elseif ([int]$windows.CurrentBuildNumber -ge 22000) { $currentTarget = 'Windows 11' }
}
catch { throw 'The current Windows target could not be verified; no action was started.' }
if ($currentTarget -notin $operation.SupportedTargets) { throw "'$OperationId' is not enabled for the current Windows target; no action was started." }
if ($operation.Workflow -notin $operation.Actions) { throw "The catalog workflow for '$OperationId' is invalid; no action was started." }
if ($EncryptionScope -and $EncryptionScope -notin $operation.EncryptionScopes) { throw "EncryptionScope must be one of the choices declared for '$OperationId'." }
if ($StartupAuthentication -and $StartupAuthentication -notin $operation.StartupAuthenticationChoices) { throw "StartupAuthentication must be one of the choices declared for '$OperationId'." }
if ($BackupDestination -and $BackupDestination -notin $operation.BackupDestinationChoices) { throw "BackupDestination must be one of the choices declared for '$OperationId'." }
Import-Module (Join-Path $repositoryRoot 'modules/RIDE.BitLockerWorkflows.psm1') -Force -ErrorAction Stop

switch ($operation.Workflow) {
  'AddRecoveryPassword' {
    if ($KeyProtectorId -or $BackupDestination -or $RecoveryProtectorId -or $VerifiedBackupProtectorId -or $EncryptionScope -or $StartupAuthentication) { throw 'AddRecoveryPassword accepts MountPoint only.' }
    Add-RideBitLockerRecoveryPassword -MountPoint $MountPoint
  }
  'BackupRecoveryPassword' {
    if (-not $KeyProtectorId -or -not $BackupDestination) { throw 'BackupRecoveryPassword requires the exact -KeyProtectorId and a catalog-declared -BackupDestination.' }
    if ($RecoveryProtectorId -or $VerifiedBackupProtectorId -or $EncryptionScope -or $StartupAuthentication) { throw 'BackupRecoveryPassword accepts only MountPoint, KeyProtectorId and BackupDestination.' }
    Start-RideBitLockerRecoveryBackupHandoff -MountPoint $MountPoint -KeyProtectorId $KeyProtectorId -DestinationCategory $BackupDestination
  }
  'ShowRecoveryPassword' {
    if (-not $KeyProtectorId) { throw 'ShowRecoveryPassword requires the exact -KeyProtectorId.' }
    if ($BackupDestination -or $RecoveryProtectorId -or $VerifiedBackupProtectorId -or $EncryptionScope -or $StartupAuthentication) { throw 'ShowRecoveryPassword accepts only MountPoint and KeyProtectorId.' }
    Show-RideBitLockerRecoveryPassword -MountPoint $MountPoint -KeyProtectorId $KeyProtectorId
  }
  'Enable' {
    if (-not $RecoveryProtectorId -or -not $VerifiedBackupProtectorId -or -not $EncryptionScope -or -not $StartupAuthentication) { throw 'Enable requires RecoveryProtectorId, VerifiedBackupProtectorId, EncryptionScope and StartupAuthentication.' }
    if ($KeyProtectorId -or $BackupDestination) { throw 'Enable does not accept KeyProtectorId or BackupDestination.' }
    Enable-RideBitLockerOsVolume -MountPoint $MountPoint -RecoveryProtectorId $RecoveryProtectorId -VerifiedBackupProtectorId $VerifiedBackupProtectorId -EncryptionScope $EncryptionScope -StartupAuthentication $StartupAuthentication
  }
  'Disable' {
    if ($KeyProtectorId -or $BackupDestination -or $RecoveryProtectorId -or $VerifiedBackupProtectorId -or $EncryptionScope -or $StartupAuthentication) { throw 'Disable accepts MountPoint only.' }
    Disable-RideBitLockerOsVolume -MountPoint $MountPoint
  }
}
