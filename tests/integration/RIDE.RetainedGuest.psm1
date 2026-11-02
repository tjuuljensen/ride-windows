<#
.SYNOPSIS
  Reserve a registered disposable guest across independent acceptance phases.
.DESCRIPTION
  Maintains a private, correlated hold using the controller's existing block
  marker. The worker lock serializes each phase; the durable hold prevents the
  ordinary reset-per-request worker from taking the guest between phases.
.NOTES
  Native Windows PowerShell 5.1, existing elevation and registered host account.
  Version: 0.1.0. No UAC, VM start/reset, guest code or policy changes are invoked
  by this coordination module. Dispatch and evidence export remain separate.
.LINK
  ../../docs/image-personalization.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.TestAutomation.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -ErrorAction Stop

function Get-RideRetainedHostIdentity {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try{[pscustomobject]@{Sid=$identity.User.Value;Elevated=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);NativeDesktop=($PSVersionTable.PSEdition -eq 'Desktop' -and $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1 -and [Environment]::Is64BitProcess)}}finally{$identity.Dispose()}
}
function Read-RideRetainedRecord {
  param([string]$Path)
  $bytes=Read-RidePrivateFileBytes -Path $Path -Scope Machine -MaximumBytes 1048576
  [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
}
function Write-RideRetainedRecord {
  param([string]$Path,$Record)
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12 -Compress))
  if($bytes.Length -gt 1048576){throw 'Retained record exceeds one MiB.'}
  $stream=New-RidePrivateFileStream -Path $Path -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Get-RideRetainedConfiguration {
  param([string]$Path,[bool]$Mutation)
  $configuration=Read-RideAutomationConfiguration $Path
  $root=Get-RideAutomationRoot $configuration.Name
  if([IO.Path]::GetFullPath($Path) -ine (Join-Path $root 'configuration.json')){throw 'Use the installed controller configuration.'}
  $null=Assert-RideAutomationDirectory $root
  $identity=Get-RideRetainedHostIdentity
  if($identity.Sid -cne $configuration.HostAccountSid -or -not $identity.NativeDesktop){throw 'Use the registered account in native Windows PowerShell 5.1.'}
  if($Mutation -and -not $identity.Elevated){throw 'Existing elevation is required; no UAC is launched.'}
  if(-not $configuration.CheckpointId -or [guid]::Parse($configuration.CheckpointId) -eq [guid]::Empty -or [guid]::Parse($configuration.VMId) -eq [guid]::Empty){throw 'Exact VM and checkpoint IDs are required.'}
  [pscustomobject]@{Root=$root;Configuration=$configuration;ConfigurationSha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash}
}
function Enter-RideRetainedWorkerLock {
  param([string]$Root)
  $path=Join-Path $Root 'runtime/worker.lock'
  $null=& (Get-Module RIDE.PrivateFiles) {param($p) Resolve-RidePrivateFilePath $p} $path
  [IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
}
function Assert-RideRetainedIdle {
  param($Context)
  if((Get-ScheduledTask -TaskPath '\RIDE\' -TaskName $Context.Configuration.Name).State -ne 'Ready' -or
    @(Get-ChildItem -LiteralPath (Join-Path $Context.Root 'queue/pending') -File -Force).Count -or
    @(Get-ChildItem -LiteralPath (Join-Path $Context.Root 'queue/running') -File -Force).Count){throw 'The controller must be idle with no pending or running requests.'}
}
function Assert-RideRetainedHold {
  param($Hold,$Context,[string]$RunId)
  if($Hold.SchemaVersion -ne 1 -or $Hold.Kind -cne 'RetainedGuestAcceptance' -or $Hold.RunId -cne $RunId -or $Hold.LeaseId -cnotmatch '^[a-f0-9]{32}$' -or
    $Hold.ConfigurationSha256 -cne $Context.ConfigurationSha256 -or $Hold.VMId -cne $Context.Configuration.VMId -or
    $Hold.CheckpointId -cne $Context.Configuration.CheckpointId -or $Hold.VMName -cne $Context.Configuration.VMName -or
    $Hold.HostAccountSid -cne $Context.Configuration.HostAccountSid -or $Hold.RecoveryRequired -ne $true){throw 'Retained guest ownership or registered target changed; preserve the block for recovery.'}
}

function New-RideRetainedGuestHold {
  <#
  .SYNOPSIS
    Reserve an idle registered guest without changing the VM.
  .PARAMETER ConfigurationPath
    Installed controller configuration.json; arbitrary registrations are refused.
  .PARAMETER RunId
    New lowercase 32-character hexadecimal acceptance request identity.
  .EXAMPLE
    New-RideRetainedGuestHold -ConfigurationPath '<installed-configuration>' -RunId '<request-id>' -WhatIf
  .OUTPUTS
    Schema-1 hold or read-only Preview. Reserved is not native acceptance.
  .NOTES
    Requires the existing worker lock and an Off VM with its pinned checkpoint.
    The private runtime/blocked.json is created before returning ownership.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId)
  $context=Get-RideRetainedConfiguration $ConfigurationPath (-not $WhatIfPreference)
  $path=Join-Path $context.Root 'runtime/blocked.json'
  if(Test-Path -LiteralPath $path){throw 'A controller block already exists; it will not be replaced or adopted.'}
  if(-not $PSCmdlet.ShouldProcess($context.Configuration.VMName,'Reserve guest for retained acceptance phases')){return [pscustomobject]@{SchemaVersion=1;RunId=$RunId;Status='Preview';NativeAcceptancePassed=$false}}
  $lock=Enter-RideRetainedWorkerLock $context.Root
  try{
    Assert-RideRetainedIdle $context
    if(Test-Path -LiteralPath $path){throw 'A controller block appeared before reservation.'}
    Assert-RideAutomationHost $context.Configuration
    $target=Import-RideAutomationLab $context.Configuration
    if($target.VM.State -ne 'Off'){throw 'Reserve only an Off disposable VM; no VM was stopped.'}
    $hold=[pscustomobject][ordered]@{SchemaVersion=1;Kind='RetainedGuestAcceptance';RunId=$RunId;LeaseId=[guid]::NewGuid().ToString('N');Status='Reserved';VMId=$context.Configuration.VMId;VMName=$context.Configuration.VMName;CheckpointId=$context.Configuration.CheckpointId;HostAccountSid=$context.Configuration.HostAccountSid;ConfigurationSha256=$context.ConfigurationSha256;CreatedAtUtc=[datetime]::UtcNow.ToString('o');RecoveryRequired=$true;NativeAcceptancePassed=$false;Error='Guest reserved for explicit retained acceptance phases. Do not use generic recovery before collecting evidence.'}
    Write-RideRetainedRecord $path $hold
    $saved=Read-RideRetainedRecord $path
    Assert-RideRetainedHold $saved $context $RunId
    $saved
  }finally{$lock.Dispose()}
}

function Open-RideRetainedGuestPhase {
  <#
  .SYNOPSIS
    Acquire exclusive phase ownership and validate the durable retained hold.
  .PARAMETER ConfigurationPath
    Installed controller configuration.json unchanged since reservation.
  .PARAMETER RunId
    Exact retained request ID. A saved hold is not permission to mutate the guest.
  .OUTPUTS
    Context, hold and disposable worker-lock handle. Caller must dispose Lock in
    finally and keep it held through guest execution, export and journal writes.
  .NOTES
    Internal host dispatch boundary. No arbitrary script callback, guest command,
    VM reset or privileged child is executed by this function.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId)
  $context=Get-RideRetainedConfiguration $ConfigurationPath $true
  $lock=Enter-RideRetainedWorkerLock $context.Root
  try{
    Assert-RideRetainedIdle $context
    $hold=Read-RideRetainedRecord (Join-Path $context.Root 'runtime/blocked.json')
    Assert-RideRetainedHold $hold $context $RunId
    Assert-RideAutomationHost $context.Configuration
    $target=Import-RideAutomationLab $context.Configuration
    [pscustomobject]@{Context=$context;Hold=$hold;Target=$target;Lock=$lock}
  }catch{$lock.Dispose();throw}
}

function Remove-RideRetainedGuestHold {
  <#
  .SYNOPSIS
    Release a retained hold after independently recorded checkpoint cleanup.
  .DESCRIPTION
    Requires a private correlated recovery receipt and rechecks the same pinned
    VM is Off. This does not restore a checkpoint, export evidence, or establish
    lifecycle/visual acceptance. Ordinary failure blocks are never removed.
  .PARAMETER ConfigurationPath
    Installed controller configuration.json unchanged since reservation.
  .PARAMETER RunId
    Retained request ID. This finite set completes from the installed hold only.
  .PARAMETER RecoveryReceiptPath
    Private machine receipt from explicit retained dispatch recovery, with exact
    run/VM/checkpoint/configuration identity and verified evidence export/reset.
  .EXAMPLE
    Remove-RideRetainedGuestHold -ConfigurationPath '<installed-configuration>' -RunId '<request-id>' -RecoveryReceiptPath '<private-receipt>' -WhatIf
  .OUTPUTS
    Schema-1 Released or Preview; NativeAcceptancePassed is always false.
  .NOTES
    No reset or cleanup is inferred from an Off VM alone. The receipt writer and
    retained native dispatch are not supplied by this coordination module.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$ConfigurationPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RunId,
    [Parameter(Mandatory)][string]$RecoveryReceiptPath)
  $context=Get-RideRetainedConfiguration $ConfigurationPath (-not $WhatIfPreference)
  $receipt=Read-RideRetainedRecord $RecoveryReceiptPath
  if($receipt.SchemaVersion -ne 1 -or $receipt.Kind -cne 'RetainedGuestRecovery' -or $receipt.RunId -cne $RunId -or
    $receipt.VMId -cne $context.Configuration.VMId -or $receipt.CheckpointId -cne $context.Configuration.CheckpointId -or
    $receipt.ConfigurationSha256 -cne $context.ConfigurationSha256 -or $receipt.EvidenceExportVerified -isnot [bool] -or -not $receipt.EvidenceExportVerified -or
    $receipt.CheckpointResetVerified -isnot [bool] -or -not $receipt.CheckpointResetVerified -or $receipt.Status -cne 'ResetAndOff'){throw 'A correlated private export and checkpoint-recovery receipt is required.'}
  $path=Join-Path $context.Root 'runtime/blocked.json'
  $hold=Read-RideRetainedRecord $path
  Assert-RideRetainedHold $hold $context $RunId
  if($receipt.LeaseId -cne $hold.LeaseId){throw 'Recovery receipt belongs to a different reservation; hold preserved.'}
  if(-not $PSCmdlet.ShouldProcess($context.Configuration.VMName,'Release retained guest hold after recorded export and checkpoint recovery')){return [pscustomobject]@{SchemaVersion=1;RunId=$RunId;Status='Preview';NativeAcceptancePassed=$false}}
  $phase=Open-RideRetainedGuestPhase -ConfigurationPath $ConfigurationPath -RunId $RunId
  try{
    if($phase.Hold.LeaseId -cne $receipt.LeaseId){throw 'Reservation changed before release; hold preserved.'}
    if($phase.Target.VM.State -ne 'Off'){throw 'Recovered pinned VM must be Off; hold preserved.'}
    # Hold identity and private permissions were verified under the same worker
    # lock. Release only this exact ordinary file; never recursively clean state.
    [IO.File]::Delete($path)
    [pscustomobject]@{SchemaVersion=1;RunId=$RunId;Status='Released';NativeAcceptancePassed=$false}
  }finally{$phase.Lock.Dispose()}
}
$script:RetainedRunCompleter={
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{
    if(-not $fakeBoundParameters.ContainsKey('ConfigurationPath')){return}
    $configuration=Read-RideAutomationConfiguration $fakeBoundParameters.ConfigurationPath
    $root=Get-RideAutomationRoot $configuration.Name
    if([IO.Path]::GetFullPath($fakeBoundParameters.ConfigurationPath) -ine (Join-Path $root 'configuration.json')){return}
    $hold=Read-RideRetainedRecord (Join-Path $root 'runtime/blocked.json')
    if($hold.Kind -ceq 'RetainedGuestAcceptance' -and $hold.RunId -cmatch '^[a-f0-9]{32}$' -and $hold.RunId.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($hold.RunId,$hold.RunId,'ParameterValue','Retained guest acceptance request')}
  }catch{}
}
Register-ArgumentCompleter -CommandName Open-RideRetainedGuestPhase,Remove-RideRetainedGuestHold -ParameterName RunId -ScriptBlock $script:RetainedRunCompleter
Export-ModuleMember -Function New-RideRetainedGuestHold,Open-RideRetainedGuestPhase,Remove-RideRetainedGuestHold
