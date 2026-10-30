<#
.SYNOPSIS
  Provide explicit, secret-safe BitLocker OS-volume workflow primitives.
.DESCRIPTION
  Inspects only nonsecret OS-volume state, adds and presents recovery passwords
  in a local Windows dialog, starts guided TPM-only or TPM-plus-PIN encryption after explicit
  recovery-backup confirmation, and exposes decryption as a separate action.
  This module does not capture recovery secrets in RIDE snapshots or output.
.EXAMPLE
  Get-RideBitLockerVolumeObservation -MountPoint $env:SystemDrive
.INPUTS
  None. Callers pass explicit volume identifiers and recovery protector IDs.
.OUTPUTS
  Nonsecret volume and protector metadata only.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: BitLocker PowerShell feature, OS-volume access, and elevation
  for enrollment, protector creation, or decryption.
  Recovery: Encryption and decryption are staged Windows operations, not exact
  RIDE restore actions. Recovery passwords stay outside standard output/state.
  Version: 0.1.0
  Changelog: 0.1.0: Add explicit OS-volume BitLocker workflow primitives.
  References: https://learn.microsoft.com/en-us/powershell/module/bitlocker/enable-bitlocker?view=windowsserver2025-ps
              https://learn.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector?view=windowsserver2025-ps
              https://learn.microsoft.com/en-us/powershell/module/bitlocker/disable-bitlocker?view=windowsserver2025-ps
#>

$ErrorActionPreference = 'Stop'
$script:BitLockerRepositoryRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $script:BitLockerRepositoryRoot 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop

function Resolve-RideBitLockerOsVolume {
  param([Parameter(Mandatory = $true)][string] $MountPoint)
  $MountPoint = [Environment]::ExpandEnvironmentVariables($MountPoint)
  if (-not $MountPoint -or $MountPoint -notmatch '^[A-Za-z]:\\?$') {
    throw 'BitLocker workflows accept an explicit drive-letter mount point only.'
  }
  $requested = $MountPoint.Substring(0, 2)
  $systemDrive = [string]$env:SystemDrive
  if ($systemDrive.Length -lt 2) { throw 'The current Windows OS drive could not be identified.' }
  $system = $systemDrive.Substring(0, 2)
  if (-not [string]::Equals($requested, $system, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'This workflow is limited to the current Windows OS volume.'
  }
  if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) -or
      -not (Get-Command Enable-BitLocker -ErrorAction SilentlyContinue) -or
      -not (Get-Command Disable-BitLocker -ErrorAction SilentlyContinue) -or
      -not (Get-Command Add-BitLockerKeyProtector -ErrorAction SilentlyContinue)) {
    throw 'The Windows BitLocker PowerShell feature is unavailable; no change was made.'
  }
  $requested
}

function Get-RideBitLockerRawVolume {
  param([Parameter(Mandatory = $true)][string] $MountPoint)
  $path = Resolve-RideBitLockerOsVolume -MountPoint $MountPoint
  try {
    $volume = @(Get-BitLockerVolume -MountPoint $path -ErrorAction Stop)
    if ($volume.Count -ne 1 -or -not [string]::Equals(([string]$volume[0].MountPoint).TrimEnd('\'), $path.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or [string]$volume[0].VolumeType -ne 'OperatingSystem') {
      throw 'Volume identity mismatch.'
    }
    return $volume[0]
  }
  catch {
    throw 'The selected OS volume could not be inspected; no change was made.'
  }
}

function Assert-RideBitLockerWorkflowAvailability {
  param([Parameter(Mandatory = $true)][string] $Workflow)
  try {
    $catalogPath = Join-Path $script:BitLockerRepositoryRoot 'catalog/operations.psd1'
    $catalog = Import-RideCatalogData -Path $catalogPath
    $operation = @($catalog.Operations | Where-Object { $_.Kind -eq 'BitLockerWorkflow' -and $_.Workflow -eq $Workflow })
  }
  catch { throw 'The BitLocker workflow catalog could not be verified; no action was started.' }
  if ($operation.Count -ne 1) { throw 'The requested BitLocker workflow is not uniquely declared; no action was started.' }
  $operation = $operation[0]
  if ($operation.PendingAcceptance -or @($operation.SupportedTargets).Count -eq 0) {
    throw "'$($operation.Id)' remains pending disposable Windows acceptance; no action was started."
  }
  $currentTarget = $null
  try {
    if ($env:OS -ne 'Windows_NT') { throw 'Not Windows.' }
    $windows = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $build = [int]$windows.CurrentBuildNumber
    if ([string]$windows.ProductName -match 'Windows Server') {
      if ($build -ge 26100) { $currentTarget = 'Windows Server 2025' }
    }
    elseif ($build -ge 22000) { $currentTarget = 'Windows 11' }
  }
  catch { throw 'The current Windows target could not be verified; no BitLocker action was started.' }
  if ($currentTarget -notin @($operation.SupportedTargets)) {
    throw "'$($operation.Id)' is not enabled for the current Windows target; no action was started."
  }
}

function Assert-RideBitLockerBackupDestination {
  param([Parameter(Mandatory = $true)][string] $DestinationCategory)
  try {
    $catalogPath = Join-Path $script:BitLockerRepositoryRoot 'catalog/operations.psd1'
    $catalog = Import-RideCatalogData -Path $catalogPath
    $operation = @($catalog.Operations | Where-Object { $_.Kind -eq 'BitLockerWorkflow' -and $_.Workflow -eq 'BackupRecoveryPassword' })
    $choices = @($operation[0].BackupDestinationChoices)
  }
  catch { throw 'Catalog backup destination choices are unavailable; no backup UI was opened.' }
  if ($operation.Count -ne 1 -or $DestinationCategory -notin $choices) {
    throw 'Choose a backup destination category declared by the BitLocker catalog.'
  }
}

function Get-RideBitLockerStartupPolicyObservation {
  $fvePath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
  $policyManagerPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker'
  $fveNames = @('UseAdvancedStartup', 'UseTPM', 'UseTPMPIN', 'UseTPMKey', 'UseTPMKeyPIN', 'UseEnhancedPin')
  $mdmNames = @(
    'SystemDrivesRequireStartupAuthentication',
    'SystemDrivesEnhancedPIN',
    'SystemDrivesMinimumPINLength',
    'SystemDrivesEnablePreBootPinExceptionOnDECapableDevice',
    'SystemDrivesEnablePrebootInputProtectorsOnSlates'
  )
  $fveValues = @()
  $mdmValues = @()
  $fvePresent = $false
  $mdmPresent = $false
  try {
    if (Test-Path -LiteralPath $fvePath) {
      $fvePresent = $true
      $item = Get-ItemProperty -LiteralPath $fvePath -ErrorAction Stop
      foreach ($name in $fveNames) {
        $property = $item.PSObject.Properties[$name]
        if ($null -ne $property) { $fveValues += [pscustomobject]@{ Name = $name; Value = $property.Value } }
      }
    }
    if (Test-Path -LiteralPath $policyManagerPath) {
      $mdmPresent = $true
      $item = Get-ItemProperty -LiteralPath $policyManagerPath -ErrorAction Stop
      foreach ($name in $mdmNames) {
        $property = $item.PSObject.Properties[$name]
        if ($null -ne $property) { $mdmValues += [pscustomobject]@{ Name = $name; Value = $property.Value } }
      }
    }
  }
  catch { throw 'BitLocker startup policy registry values could not be inspected.' }
  [pscustomobject]@{
    FvePolicyRegistryPresent = $fvePresent
    FvePolicyValues = $fveValues
    PolicyManagerRegistryPresent = $mdmPresent
    PolicyManagerValues = $mdmValues
    EffectivePolicyEstablished = $false
    Interpretation = 'Raw startup-policy registry snapshots only; policy precedence, management provenance and effective boot behavior are not established.'
  }
}

function Get-RideBitLockerVolumeObservation {
  <#
  .SYNOPSIS
    Inspect OS-volume BitLocker state without returning recovery secrets.
  .PARAMETER MountPoint
    Explicit current OS drive-letter mount point, such as C:.
  .OUTPUTS
    Nonsecret volume status and recovery protector ID/type records.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory = $true)][string] $MountPoint)
  $volume = Get-RideBitLockerRawVolume -MountPoint $MountPoint
  $protectors = @(
    foreach ($protector in @($volume.KeyProtector)) {
      $protectorType = [string]$protector.KeyProtectorType
      $routeAssessment = switch -CaseSensitive ($protectorType) {
        'RecoveryPassword' { 'Recovery route; off-device backup and retrieval still require separate verification.'; break }
        'TpmCertificate' { 'Potential Network Unlock route; verify managed policy, certificate/WDS provisioning and real boot behavior.'; break }
        default { 'Alternate or unreviewed protector route; inspect ownership, policy and actual boot behavior.' }
      }
      [pscustomobject]@{
        KeyProtectorId = [string]$protector.KeyProtectorId
        KeyProtectorType = $protectorType
        RouteAssessment = $routeAssessment
      }
    }
  )
  [pscustomobject]@{
    MountPoint = [string]$volume.MountPoint
    VolumeStatus = [string]$volume.VolumeStatus
    VolumeType = [string]$volume.VolumeType
    EncryptionPercentage = [int]$volume.EncryptionPercentage
    ProtectionStatus = [string]$volume.ProtectionStatus
    EncryptionMethod = [string]$volume.EncryptionMethod
    KeyProtectors = $protectors
    StartupPolicy = Get-RideBitLockerStartupPolicyObservation
  }
}

function Assert-RideBitLockerAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This BitLocker workflow requires an elevated PowerShell session; no change was made.'
  }
}

function Assert-RideBitLockerEnrollmentReadiness {
  param([Parameter(Mandatory = $true)] $Volume)
  $edition = $null
  try { $edition = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID }
  catch { throw 'Windows edition could not be verified; no encryption was started.' }
  if ($edition -notin @('Professional', 'Enterprise', 'Education')) {
    throw 'Guided BitLocker Drive Encryption requires Windows Pro, Enterprise or Education; Home Device Encryption is a separate workflow.'
  }
  try { $startupPolicy = Get-RideBitLockerStartupPolicyObservation }
  catch { throw 'BitLocker startup policy could not be inspected; no encryption was started.' }
  if ($startupPolicy.EffectivePolicyEstablished -ne $true) {
    throw 'Effective startup-authentication policy and boot-route compatibility are not established; no encryption was started.'
  }
  $policyValues = @($startupPolicy.FvePolicyValues) + @($startupPolicy.PolicyManagerValues)
  if ($policyValues.Count -gt 0) { throw 'BitLocker startup-authentication policy values are configured. Review effective policy before enrollment; no policy was changed.' }
  $reagent = Join-Path $env:SystemRoot 'System32/reagentc.exe'
  if (-not [IO.File]::Exists($reagent)) { throw 'Windows Recovery Environment readiness cannot be inspected; no encryption was started.' }
  try {
    $reagentOutput = @(& $reagent /info 2>&1)
    $reagentExitCode = $LASTEXITCODE
  }
  catch { throw 'Windows Recovery Environment readiness could not be inspected; no encryption was started.' }
  $reagentText = @($reagentOutput) -join "`n"
  if ($reagentExitCode -ne 0 -or $reagentText -notmatch '(?im)^\s*Windows RE status:\s*Enabled\s*$') {
    throw 'Windows Recovery Environment is not verified as enabled; no encryption was started.'
  }
  if ([string]$Volume.VolumeStatus -ne 'FullyDecrypted' -or [int]$Volume.EncryptionPercentage -ne 0) {
    throw 'The OS volume is not fully decrypted; inspect its existing protection/conversion state before proceeding.'
  }
}

function Assert-RideBitLockerEncryptionScope {
  param([Parameter(Mandatory = $true)][string] $EncryptionScope)
  try {
    $catalogPath = Join-Path $script:BitLockerRepositoryRoot 'catalog/operations.psd1'
    $catalog = Import-RideCatalogData -Path $catalogPath
    $operation = $catalog.Operations | Where-Object { $_.Kind -eq 'BitLockerWorkflow' -and $_.Workflow -eq 'Enable' } | Select-Object -First 1
    $choices = @($operation.EncryptionScopes)
  }
  catch { throw 'Catalog enrollment scope choices are unavailable; no encryption was started.' }
  if (-not $operation -or $EncryptionScope -notin $choices) { throw 'EncryptionScope must match an enrollment choice declared in the RIDE catalog.' }
}

function Assert-RideBitLockerStartupAuthentication {
  param([Parameter(Mandatory = $true)][string] $StartupAuthentication)
  try {
    $catalogPath = Join-Path $script:BitLockerRepositoryRoot 'catalog/operations.psd1'
    $catalog = Import-RideCatalogData -Path $catalogPath
    $operation = $catalog.Operations | Where-Object { $_.Kind -eq 'BitLockerWorkflow' -and $_.Workflow -eq 'Enable' } | Select-Object -First 1
    $choices = @($operation.StartupAuthenticationChoices)
  }
  catch { throw 'Catalog startup-authentication choices are unavailable; no encryption was started.' }
  if (-not $operation -or $StartupAuthentication -notin $choices) { throw 'StartupAuthentication must match a choice declared in the RIDE catalog.' }
}

function Show-RideBitLockerSecretDialog {
  param(
    [Parameter(Mandatory = $true)][string] $Secret,
    [Parameter(Mandatory = $true)][string] $ProtectorId,
    [string] $Instruction = 'This is an explicit local reveal. RIDE does not copy, save or back up the recovery password.'
  )
  if (-not $IsWindows -and $env:OS -ne 'Windows_NT') { throw 'Secret presentation is available only in an interactive Windows session.' }
  $form = $null
  $text = $null
  try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    $form = New-Object Windows.Forms.Form
    $form.Text = 'BitLocker recovery password'
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MinimizeBox = $false
    $form.MaximizeBox = $false
    $form.ShowInTaskbar = $true
    $form.ClientSize = New-Object Drawing.Size(620, 220)
    $form.TopMost = $true

    $label = New-Object Windows.Forms.Label
    $label.Location = New-Object Drawing.Point(16, 12)
    $label.Size = New-Object Drawing.Size(588, 62)
    $label.Text = "Protector ID: $ProtectorId`r`n$Instruction"
    $form.Controls.Add($label)

    $text = New-Object Windows.Forms.TextBox
    $text.Location = New-Object Drawing.Point(16, 82)
    $text.Size = New-Object Drawing.Size(588, 28)
    $text.Font = New-Object Drawing.Font('Consolas', 11)
    $text.ReadOnly = $true
    $text.Enabled = $false
    $text.UseSystemPasswordChar = $true
    $text.Text = $Secret
    $form.Controls.Add($text)

    $reveal = New-Object Windows.Forms.CheckBox
    $reveal.Location = New-Object Drawing.Point(16, 120)
    $reveal.Size = New-Object Drawing.Size(180, 24)
    $reveal.Text = 'Reveal while this dialog is open'
    $reveal.Add_CheckedChanged({ $text.UseSystemPasswordChar = -not $reveal.Checked })
    $form.Controls.Add($reveal)

    $closed = New-Object Windows.Forms.Button
    $closed.Location = New-Object Drawing.Point(490, 166)
    $closed.Size = New-Object Drawing.Size(110, 32)
    $closed.Text = 'Close'
    $closed.DialogResult = [Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($closed)
    $form.CancelButton = $closed

    [void]$form.ShowDialog()
  }
  catch {
    throw 'The recovery password could not be presented safely; the recovery protector was retained.'
  }
  finally {
    if ($text) { try { $text.Clear() } catch { } }
    if ($form) { try { $form.Dispose() } catch { } }
    $Secret = $null
    $text = $null
    $form = $null
  }
}

function Add-RideBitLockerRecoveryPassword {
  <#
  .SYNOPSIS
    Add a recovery-password protector and present it only in a local dialog.
  .DESCRIPTION
    Creates one additional protector after ShouldProcess approval. It never
    writes the returned secret to pipeline, console, logs, or saved state.
    A typed volume-specific phrase is required after ShouldProcess confirms.
    The protector is retained if dialog presentation fails. This action never
    claims backup verification; use the separate exact-ID backup handoff.
    A created protector is never silently deleted as rollback.
  .PARAMETER MountPoint
    Explicit current OS volume.
  .OUTPUTS
    Nonsecret protector ID, unverified backup state and the next backup action.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param([Parameter(Mandatory = $true)][string] $MountPoint)
  Assert-RideBitLockerWorkflowAvailability -Workflow 'AddRecoveryPassword'
  $path = Resolve-RideBitLockerOsVolume -MountPoint $MountPoint
  Assert-RideBitLockerAdministrator
  if (-not $PSCmdlet.ShouldProcess($path, 'Add one recovery-password protector and present it locally')) { return }
  $before = Get-RideBitLockerRawVolume -MountPoint $path
  if ([string]$before.VolumeStatus -notin @('FullyEncrypted', 'EncryptionInProgress', 'FullyDecrypted')) {
    throw 'The OS volume is in an unsupported transition state; no protector was added.'
  }
  $confirmation = Read-Host "Type ADD RECOVERY PASSWORD TO $path to create one additional protector"
  if ($confirmation -cne "ADD RECOVERY PASSWORD TO $path") { throw 'Recovery protector creation was not confirmed; no protector was added.' }
  $existingIds = @($before.KeyProtector | ForEach-Object { [string]$_.KeyProtectorId })
  $created = $null
  try { $created = Add-BitLockerKeyProtector -MountPoint $path -RecoveryPasswordProtector -ErrorAction Stop }
  catch { throw 'BitLocker did not confirm creation of a recovery-password protector.' }
  $newProtectors = @($created.KeyProtector | Where-Object {
      $_.KeyProtectorType -eq 'RecoveryPassword' -and [string]$_.KeyProtectorId -notin $existingIds
    })
  if ($newProtectors.Count -ne 1) { throw 'A protector may have been created, but its identity was not confirmed uniquely. Inspect BitLocker state before retrying.' }
  $protector = $newProtectors[0]
  $secret = [string]$protector.RecoveryPassword
  $id = [string]$protector.KeyProtectorId
  if (-not $secret -or -not $id) { throw 'A protector may have been created, but secure presentation data was unavailable. Inspect BitLocker state before retrying.' }
  $instruction = 'This additional key is not backed up by RIDE. After closing this dialog, use the separate exact-ID backup handoff and verify retrieval from another device.'
  try { Show-RideBitLockerSecretDialog -Secret $secret -ProtectorId $id -Instruction $instruction }
  finally {
    $secret = $null
    $protector = $null
    $newProtectors = $null
    $created = $null
  }
  [pscustomobject]@{
    MountPoint = $path
    KeyProtectorId = $id
    Stage = 'RecoveryPasswordCreatedAndPresented'
    BackupVerified = $false
    NextStep = 'Use the separate existing-key backup workflow with this exact protector ID and an explicit destination; verify retrieval from another device before relying on this recovery key.'
  }
}

function Get-RideBitLockerControlPanelPath {
  $controlPath = Join-Path $env:SystemRoot 'System32/control.exe'
  if (-not [IO.File]::Exists($controlPath)) { throw 'The native BitLocker control panel could not be located.' }
  $controlPath
}

function Start-RideBitLockerRecoveryBackupHandoff {
  <#
  .SYNOPSIS
    Open the native BitLocker UI for a user-directed existing-key backup.
  .DESCRIPTION
    Requires one exact existing RecoveryPassword protector ID. This only opens
    the native UI; it does not export or read the key and never claims the
    backup was saved or retrievable from another device.
  .PARAMETER MountPoint
    Explicit current OS volume.
  .PARAMETER KeyProtectorId
    Exact existing RecoveryPassword protector ID.
  .PARAMETER DestinationCategory
    Intended native backup destination declared by the catalog.
  .OUTPUTS
    Nonsecret handoff status, exact ID and verification instructions.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
  param(
    [Parameter(Mandatory = $true)][string] $MountPoint,
    [Parameter(Mandatory = $true)][string] $KeyProtectorId,
    [Parameter(Mandatory = $true)][string] $DestinationCategory
  )
  Assert-RideBitLockerWorkflowAvailability -Workflow 'BackupRecoveryPassword'
  Assert-RideBitLockerBackupDestination -DestinationCategory $DestinationCategory
  $path = Resolve-RideBitLockerOsVolume -MountPoint $MountPoint
  Assert-RideBitLockerAdministrator
  if (-not $PSCmdlet.ShouldProcess($path, "Open native BitLocker backup UI for protector $KeyProtectorId to $DestinationCategory")) { return }
  $volume = Get-RideBitLockerRawVolume -MountPoint $path
  $recoveryProtectors = @($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' })
  $selected = @($recoveryProtectors | Where-Object { [string]::Equals([string]$_.KeyProtectorId, $KeyProtectorId, [StringComparison]::OrdinalIgnoreCase) })
  if ($selected.Count -ne 1) { throw 'The exact RecoveryPassword protector ID was not found uniquely; no backup UI was opened.' }
  $destinationInstruction = switch ($DestinationCategory) {
    'FileOrUsb' { 'Choose Save to a file and store it outside this device where it remains accessible from another device.' }
    'PersonalMicrosoftAccount' { 'Choose the personal Microsoft account that owns the backup, if that destination is available in the native UI.' }
    'Print' { 'Choose Print only if the output can be stored securely away from this device.' }
  }
  try { $controlPath = Get-RideBitLockerControlPanelPath }
  catch { throw 'The native BitLocker control panel could not be located; no backup was started.' }
  try { Start-Process -FilePath $controlPath -ArgumentList @('/name', 'Microsoft.BitLockerDriveEncryption') -ErrorAction Stop }
  catch { throw 'The native BitLocker control panel did not open; no backup was started.' }
  [pscustomobject]@{
    MountPoint = $path
    KeyProtectorId = [string]$selected[0].KeyProtectorId
    DestinationCategory = $DestinationCategory
    Stage = 'NativeBackupHandoffOpened'
    BackupVerified = $false
    Instructions = @('Select the matching operating-system drive.', $destinationInstruction, 'Confirm the saved recovery entry has the exact protector ID shown here.', 'Verify retrieval from another device; if the native UI cannot establish the matching ID or destination, leave recovery readiness pending.')
  }
}

function Show-RideBitLockerRecoveryPassword {
  <#
  .SYNOPSIS
    Present one explicitly selected recovery password in a local dialog.
  .PARAMETER MountPoint
    Explicit current OS volume.
  .PARAMETER KeyProtectorId
    Exact protector ID; array position is never used.
  .OUTPUTS
    Nonsecret protector ID and volume identity only.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param([Parameter(Mandatory = $true)][string] $MountPoint, [Parameter(Mandatory = $true)][string] $KeyProtectorId)
  Assert-RideBitLockerWorkflowAvailability -Workflow 'ShowRecoveryPassword'
  $path = Resolve-RideBitLockerOsVolume -MountPoint $MountPoint
  Assert-RideBitLockerAdministrator
  if (-not $PSCmdlet.ShouldProcess($KeyProtectorId, 'Reveal selected BitLocker recovery password in a local dialog')) { return }
  $volume = Get-RideBitLockerRawVolume -MountPoint $path
  $matches = @($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' -and [string]::Equals([string]$_.KeyProtectorId, $KeyProtectorId, [StringComparison]::OrdinalIgnoreCase) })
  if ($matches.Count -ne 1) { throw 'The exact recovery-password protector ID was not found uniquely.' }
  $secret = [string]$matches[0].RecoveryPassword
  if (-not $secret) { throw 'The selected recovery password is unavailable; no secret was shown.' }
  try {
    [void](Show-RideBitLockerSecretDialog -Secret $secret -ProtectorId $KeyProtectorId)
    [pscustomobject]@{ MountPoint = [string]$volume.MountPoint; KeyProtectorId = $KeyProtectorId }
  }
  finally {
    $secret = $null
    $matches = $null
    $volume = $null
  }
}

function Enable-RideBitLockerOsVolume {
  <#
  .SYNOPSIS
    Begin TPM-based OS-volume encryption after recovery backup confirmation.
  .DESCRIPTION
    Requires a preexisting recovery-password protector and a typed exact-ID
    confirmation that its backup was verified from another device. Keeps the
    BitLocker hardware test enabled, does not reboot, and records no secret.
  .PARAMETER MountPoint
    Explicit current OS volume.
  .PARAMETER RecoveryProtectorId
    Exact existing recovery-password protector whose backup was verified.
  .PARAMETER EncryptionScope
    UsedSpaceOnly or FullVolume; user must consider prior volume contents.
.PARAMETER StartupAuthentication
    TPMOnly or TPMAndPIN. A TPMAndPIN value is prompted securely after preview approval.
  .PARAMETER VerifiedBackupProtectorId
    Exact ID typed to confirm verified off-device recovery access.
  .OUTPUTS
    Nonsecret submission status and volume identity.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory = $true)][string] $MountPoint,
    [Parameter(Mandatory = $true)][string] $RecoveryProtectorId,
    [Parameter(Mandatory = $true)][string] $EncryptionScope,
    [Parameter(Mandatory = $true)][string] $StartupAuthentication,
    [Parameter(Mandatory = $true)][string] $VerifiedBackupProtectorId
  )
  Assert-RideBitLockerWorkflowAvailability -Workflow 'Enable'
  $path = Resolve-RideBitLockerOsVolume -MountPoint $MountPoint
  Assert-RideBitLockerAdministrator
  Assert-RideBitLockerEncryptionScope -EncryptionScope $EncryptionScope
  Assert-RideBitLockerStartupAuthentication -StartupAuthentication $StartupAuthentication
  if (-not [string]::Equals($RecoveryProtectorId, $VerifiedBackupProtectorId, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The confirmed backup protector ID does not match the selected recovery protector.'
  }
  $volume = Get-RideBitLockerRawVolume -MountPoint $path
  $recovery = @($volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' -and [string]::Equals([string]$_.KeyProtectorId, $RecoveryProtectorId, [StringComparison]::OrdinalIgnoreCase) })
  if ($recovery.Count -ne 1) { throw 'The selected recovery-password protector was not found uniquely.' }
  $alternateProtectors = @($volume.KeyProtector | Where-Object { $_.KeyProtectorType -ne 'RecoveryPassword' })
  if ($alternateProtectors.Count -gt 0) {
    $types = @($alternateProtectors | ForEach-Object { [string]$_.KeyProtectorType } | Sort-Object -Unique) -join ', '
    if (@($alternateProtectors | Where-Object { $_.KeyProtectorType -eq 'TpmCertificate' }).Count -gt 0) {
      throw "A TpmCertificate protector may provide managed BitLocker Network Unlock. Preserve it and verify policy, certificate/WDS provisioning and actual boot behavior before enrollment; this workflow will not change startup routes or start encryption. Other protector types: $types."
    }
    throw "Existing non-RecoveryPassword protector types may provide alternate boot or recovery routes ($types). Review ownership and effective policy; this workflow will preserve them and add no protector."
  }
  Assert-RideBitLockerEnrollmentReadiness -Volume $volume
  if (-not (Get-Command Get-Tpm -ErrorAction SilentlyContinue)) { throw 'TPM readiness cannot be inspected on this system; no encryption was started.' }
  try { $tpm = Get-Tpm -ErrorAction Stop } catch { throw 'TPM readiness could not be inspected; no encryption was started.' }
  if (-not $tpm.TpmPresent -or -not $tpm.TpmReady) { throw 'A present, ready TPM is required for this TPM-only workflow.' }
  $authenticationLabel = if ($StartupAuthentication -eq 'TPMAndPIN') { 'TPM plus startup PIN' } else { 'TPM-only' }
  if (-not $PSCmdlet.ShouldProcess($path, "Start $authenticationLabel BitLocker encryption ($EncryptionScope, XTS-AES 128)")) { return }
  $pin = $null
  if ($StartupAuthentication -eq 'TPMAndPIN') {
    try { $pin = Read-Host -Prompt 'Enter the BitLocker preboot startup PIN' -AsSecureString }
    catch { throw 'The startup PIN could not be read securely; no encryption was started.' }
    if (-not $pin -or $pin.Length -lt 1) {
      if ($pin) { $pin.Dispose() }
      throw 'A nonempty startup PIN is required; no encryption was started.'
    }
  }
  try {
    $parameters = @{ MountPoint = $path; EncryptionMethod = 'XtsAes128'; ErrorAction = 'Stop' }
    if ($StartupAuthentication -eq 'TPMAndPIN') {
      $parameters.Pin = $pin
      $parameters.TpmAndPinProtector = $true
    }
    else { $parameters.TpmProtector = $true }
    if ($EncryptionScope -eq 'UsedSpaceOnly') { $parameters.UsedSpaceOnly = $true }
    $null = Enable-BitLocker @parameters
  }
  catch { throw 'BitLocker encryption initiation failed or needs attention. Inspect the OS-volume conversion and recovery-protector state; no automatic rollback was attempted.' }
  finally { if ($pin) { $pin.Dispose(); $pin = $null } }
  [pscustomobject]@{ MountPoint = $path; Stage = 'EncryptionSubmitted'; EncryptionScope = $EncryptionScope; EncryptionMethod = 'XtsAes128'; StartupAuthentication = $StartupAuthentication; RecoveryProtectorId = $RecoveryProtectorId }
}

function Disable-RideBitLockerOsVolume {
  <#
  .SYNOPSIS
    Explicitly begin OS-volume BitLocker decryption.
  .DESCRIPTION
    This advanced action removes BitLocker protection and starts decryption.
    It is separate from suspend, unset, and saved-run restore. No other drive's
    auto-unlock state or recovery protector is modified. A typed volume-specific
    phrase is required after ShouldProcess confirms.
  .PARAMETER MountPoint
    Explicit current OS volume.
  .OUTPUTS
    Nonsecret submission status and volume identity.
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param([Parameter(Mandatory = $true)][string] $MountPoint)
  Assert-RideBitLockerWorkflowAvailability -Workflow 'Disable'
  $path = Resolve-RideBitLockerOsVolume -MountPoint $MountPoint
  Assert-RideBitLockerAdministrator
  $volume = Get-RideBitLockerRawVolume -MountPoint $path
  if ([string]$volume.VolumeStatus -eq 'FullyDecrypted') {
    return [pscustomobject]@{ MountPoint = $path; Stage = 'AlreadyDecrypted' }
  }
  if ([string]$volume.VolumeStatus -notin @('FullyEncrypted', 'EncryptionInProgress', 'EncryptionPaused', 'DecryptionInProgress', 'DecryptionPaused')) {
    throw 'The OS volume conversion state is unsupported; inspect it before requesting decryption.'
  }
  if (-not $PSCmdlet.ShouldProcess($path, 'Turn off BitLocker and start OS-volume decryption')) { return }
  $confirmation = Read-Host "Type TURN OFF BITLOCKER ON $path to remove all OS-volume protectors and begin decryption"
  if ($confirmation -cne "TURN OFF BITLOCKER ON $path") { throw 'BitLocker decryption was not confirmed; no change was made.' }
  try { $null = Disable-BitLocker -MountPoint $path -ErrorAction Stop }
  catch { throw 'BitLocker decryption initiation failed or needs attention. Inspect the OS-volume conversion and recovery-protector state; no automatic rollback was attempted.' }
  [pscustomobject]@{ MountPoint = $path; Stage = 'DecryptionSubmitted' }
}

Export-ModuleMember -Function Get-RideBitLockerVolumeObservation, Get-RideBitLockerStartupPolicyObservation, Add-RideBitLockerRecoveryPassword, Start-RideBitLockerRecoveryBackupHandoff, Show-RideBitLockerRecoveryPassword, Enable-RideBitLockerOsVolume, Disable-RideBitLockerOsVolume
