<#
.SYNOPSIS
  Exercise catalog client capability recovery in a disposable Windows guest.
.DESCRIPTION
  Tests OpenSSH Client or all observed catalog RSAT members through the normal
  engine. Captures bounded capability inventory and engine journal fingerprints,
  checks preview/repeat, removal and both saved restores. Stops on failure or
  restart requests, retaining private evidence and any partial engine run ID.
.NOTES
  Compatibility: Native Windows PowerShell 5.1/7; Windows 11 x64 candidate.
  Prerequisites: Existing elevation, correlated Hyper-V guest and explicitly
  selected Windows Update acquisition. Requires a separately reviewed host route.
  Recovery: Conditional literal-state recovery, never exact payload recovery.
  No automatic reboot, retry, checkpoint reset, SSH connection or domain query.
  Version: 0.1.1. Changelog: Persist preflight readiness rejection as failed
  terminal evidence without servicing or weakening preview/recovery guards.
.LINK
  ../../docs/windows-component-inventory.md
#>
$ErrorActionPreference='Stop'
$script:engine=Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.Engine.psm1') -PassThru -ErrorAction Stop
$script:provider=Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.ClientCapability.psm1') -PassThru -ErrorAction Stop
$script:private=Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.PrivateFiles.psm1') -PassThru -ErrorAction Stop

function Get-RideCapabilityAcceptanceContext {
  $context=& $script:provider {Get-RideClientCapabilityContext}
  $machine=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  $context|Add-Member -NotePropertyMembers @{Administrator=(& $script:provider {Test-RideClientCapabilityAdministrator});Manufacturer=$machine.Manufacturer;Model=$machine.Model;GuestMarker=$env:RIDE_TEST_GUEST;IntegrationMarker=$env:RIDE_INTEGRATION_VM;RunMarker=$env:RIDE_TEST_RUN_ID}
  $context
}

function Get-RideCapabilityAcceptanceInventory {
  $rows=[Collections.Generic.List[object]]::new();$names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  & $script:provider {Get-RideClientCapabilityNativeState} | ForEach-Object {
    $name=[string]$_.Name;$state=[string]$_.State
    if($rows.Count -ge 4096 -or [string]::IsNullOrWhiteSpace($name) -or $name.Length -gt 256 -or $name -match '[\x00-\x1f]' -or -not $names.Add($name) -or [string]::IsNullOrWhiteSpace($state) -or $state.Length -gt 64 -or $state -match '[\x00-\x1f]'){throw 'Invalid or excessive capability inventory.'}
    $rows.Add([pscustomobject][ordered]@{Name=$name;State=$state})
  }
  if(-not $rows.Count){throw 'Capability inventory is empty.'}
  @($rows.ToArray()|Sort-Object Name)
}

function Get-RideCapabilityAcceptanceStateRoot {& $script:engine {Get-RideStateRoot -Scope Machine}}

function Get-RideCapabilityAcceptanceJournals {
  $root=Get-RideCapabilityAcceptanceStateRoot
  if(-not (Test-Path -LiteralPath $root)){return}
  $null=& $script:private {param($path) Resolve-RidePrivateFilePath $path} (Join-Path $root '_probe.json')
  $directories=@(Get-ChildItem -LiteralPath $root -Directory -Force | Where-Object Name -Match '^[a-fA-F0-9]{32}$')
  if($directories.Count -gt 512){throw 'Engine run inventory exceeds its bound.'}
  $rows=[Collections.Generic.List[object]]::new()
  foreach($directory in $directories){
    if($directory.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Engine run directory is a reparse point.'}
    foreach($file in @(Get-ChildItem -LiteralPath $directory.FullName -File -Filter '*.json' -Force)){
      if($rows.Count -ge 4096 -or $file.Length -gt 4194304 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Engine journal exceeds its bound or uses a reparse point.'}
      $rows.Add([pscustomobject][ordered]@{Path=$directory.Name+'/'+$file.Name;Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash})
    }
  }
  @($rows.ToArray()|Sort-Object Path)
}

function Get-RideCapabilityAcceptanceClientBinary {
  $path=Join-Path $env:SystemRoot 'System32/OpenSSH/ssh.exe'
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){return [pscustomobject]@{Exists=$false}}
  $file=Get-Item -LiteralPath $path -Force
  if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Native OpenSSH client is a reparse point.'}
  $signature=Get-AuthenticodeSignature -LiteralPath $path
  [pscustomobject][ordered]@{Exists=$true;FileVersion=$file.VersionInfo.FileVersion;ProductVersion=$file.VersionInfo.ProductVersion;Sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash;SignatureStatus=[string]$signature.Status;SignerSubject=[string]$signature.SignerCertificate.Subject}
}

function Assert-RideCapabilityAcceptanceReady {
  param($Expected)
  $current=Get-RideCapabilityAcceptanceContext
  & $script:provider {param($expected,$actual) Assert-RideClientCapabilitySameTarget $expected $actual} $Expected $current
  if(-not $current.Administrator -or $current.GuestMarker -cne '1' -or $current.IntegrationMarker -cne '1' -or $current.RunMarker -cne $Expected.RunMarker -or $current.Model -cne 'Virtual Machine' -or $current.Manufacturer -cne 'Microsoft Corporation'){throw 'Guest attestation or elevation changed.'}
  if(& $script:provider {Test-RideClientCapabilityPendingReboot}){throw 'A servicing restart is pending; retain evidence without further changes.'}
}

function Test-RideCapabilityAcceptanceEqual {
  param($Left,$Right)
  (ConvertTo-Json -InputObject @($Left) -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject @($Right) -Depth 8 -Compress)
}

function Assert-RideCapabilityAcceptanceInventory {
  param($Before,$After,[string[]]$Names,[ValidateSet('Installed','NotPresent','Original')][string]$Expected)
  $unrelatedBefore=@($Before|Where-Object Name -CNotIn $Names)
  $unrelatedAfter=@($After|Where-Object Name -CNotIn $Names)
  if(-not (Test-RideCapabilityAcceptanceEqual $unrelatedBefore $unrelatedAfter)){throw 'Unrelated capability inventory changed.'}
  foreach($name in $Names){
    $old=@($Before|Where-Object Name -CEQ $name);$new=@($After|Where-Object Name -CEQ $name)
    $state=if($Expected -ceq 'Original'){$old[0].State}else{$Expected}
    if($old.Count -ne 1 -or $new.Count -ne 1 -or $new[0].State -cne $state){throw "Capability readback differs: $name"}
  }
}

function Save-RideCapabilityAcceptanceEvidence {
  param([string]$Path,$Value,[switch]$Raw)
  $bytes=if($Raw){[byte[]]$Value}else{[Text.UTF8Encoding]::new($false).GetBytes(($Value|ConvertTo-Json -Depth 14).Replace("`r`n","`n")+"`n")}
  $stream=New-RidePrivateFileStream -Path $Path -Scope Machine
  try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

function Export-RideCapabilityAcceptanceRun {
  param([string]$RunId,$Report,[string]$Directory)
  $root=Get-RideCapabilityAcceptanceStateRoot
  $runPath=Join-Path $root $RunId
  $null=& $script:private {param($path) Resolve-RidePrivateFilePath $path} (Join-Path $runPath '_manifest.json')
  $files=@(Get-ChildItem -LiteralPath $runPath -File -Filter '*.json' -Force)
  if(-not $files.Count -or $files.Count -gt ($Report.Selection.Count+1) -or @($files|Where-Object Name -CEQ '_manifest.json').Count -ne 1){throw 'Engine run evidence is missing or excessive.'}
  $target=Join-Path $Directory ('engine-'+$RunId)
  $null=New-Item -ItemType Directory -Path $target -ErrorAction Stop
  foreach($file in $files){
    if($file.Length -gt 4194304 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Invalid engine evidence file.'}
    $bytes=[IO.File]::ReadAllBytes($file.FullName)
    if($bytes.Length -gt 4194304){throw 'Engine evidence grew beyond its bound.'}
    $record=[Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xfeff)|ConvertFrom-Json -ErrorAction Stop
    if($record.RunId -cne $RunId){throw 'Engine evidence run identity differs.'}
    if($file.Name -ceq '_manifest.json'){
      if(-not @($record.OperationIds).Count -or @($record.OperationIds|Where-Object {$_ -cnotin @($Report.Selection.Id)}).Count -or @($record.Scopes).Count -ne 1 -or $record.Scopes[0] -cne 'Machine'){throw 'Engine manifest selection differs.'}
    } else {
      $selected=@($Report.Selection|Where-Object Id -CEQ $record.OperationId)
      if($selected.Count -ne 1 -or $record.Kind -cne 'WindowsCapability' -or $record.Scope -cne 'Machine' -or $file.Name -cne ($record.OperationId+'.json') -or $record.Snapshot.OperationId -cne $record.OperationId -or $record.Snapshot.CapabilityName -cne $selected[0].CapabilityName -or $record.Snapshot.SnapshotVersion -ne 2 -or $record.Snapshot.ServicingSource -cne 'WindowsUpdate' -or $record.Snapshot.CapabilityState -cnotin @('Installed','NotPresent') -or $record.Snapshot.ExpectedState -cnotin @('Installed','NotPresent')){throw 'Engine snapshot selection/source differs.'}
      & $script:provider {param($expected,$actual) Assert-RideClientCapabilitySameTarget $expected $actual} $Report.WindowsContext $record.Snapshot.WindowsContext
    }
    Save-RideCapabilityAcceptanceEvidence (Join-Path $target $file.Name) $bytes -Raw
  }
}

function Invoke-RideCapabilityAcceptanceStep {
  param([string]$Stage,[scriptblock]$Action,$Report,[string]$Directory)
  $output=[Collections.Generic.List[string]]::new();$failure=$null
  try {& $Action | ForEach-Object {$output.Add([string]$_)}}
  catch {$failure=$_;$output.Add($_.Exception.Message)}
  $ids=@([regex]::Matches(($output -join "`n"),'Run ID: ([a-f0-9]{32})(?:\.|\s|$)')|ForEach-Object {$_.Groups[1].Value}|Sort-Object -Unique)
  foreach($id in $ids){
    if($id -notin @($Report.LifecycleRuns.RunId)){
      $Report.LifecycleRuns+=@([pscustomobject]@{Stage=$Stage;RunId=$id;Restored=$false})
      try {Export-RideCapabilityAcceptanceRun $id $Report $Directory}
      catch {$Report.EvidenceErrors+=@($_.Exception.Message);if(-not $failure){$failure=$_}}
    }
  }
  Save-RideCapabilityAcceptanceEvidence (Join-Path $Directory ($Stage+'-action.json')) ([pscustomobject]@{Stage=$Stage;Output=@($output.ToArray());RunIds=$ids;Failed=($null -ne $failure)})
  if($failure){throw $failure}
  if($ids.Count -gt 1){throw 'One capability step reported multiple engine runs.'}
  if($ids.Count){$ids[0]}
}

function Invoke-RideClientCapabilityAcceptance {
  <#
  .SYNOPSIS
    Test one reviewed capability family through catalog apply and saved recovery.
  .PARAMETER Family
    OpenSSHClient or RSAT; RSAT selects all currently observed catalog members.
  .PARAMETER RunId
    New request ID matching RIDE_TEST_RUN_ID in the disposable guest.
  .PARAMETER ExpectedComputerName
    Exact disposable guest computer name.
  .PARAMETER ExpectedBuild
    Exact Windows build.
  .PARAMETER ExpectedEditionId
    Exact Windows edition.
  .PARAMETER ExpectedRevision
    Exact Windows update build revision.
  .PARAMETER ServicingSource
    Explicit WindowsUpdate acquisition; policy is never overridden.
  .PARAMETER EvidenceRoot
    Existing local directory for new private request evidence.
  .PARAMETER DisposableVm
    Required explicit disposable-target attestation.
  .EXAMPLE
    Invoke-RideClientCapabilityAcceptance -Family OpenSSHClient -RunId $request -ExpectedComputerName $guest -ExpectedBuild '26300' -ExpectedEditionId 'EnterpriseEval' -ExpectedRevision 9711 -ServicingSource WindowsUpdate -EvidenceRoot $evidence -DisposableVm -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 scenario report. Passed covers literal-state lifecycle only.
  .NOTES
    Does not certify SSH connectivity, SSH user-data preservation, RSAT console
    functionality, restart recovery or exact payload/version restoration.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][ValidateSet('OpenSSHClient','RSAT')][string]$Family,
    [Parameter(Mandatory)][ValidatePattern('(?-i)^[a-f0-9]{32}$')][string]$RunId,
    [Parameter(Mandatory)][string]$ExpectedComputerName,[Parameter(Mandatory)][string]$ExpectedBuild,
    [Parameter(Mandatory)][string]$ExpectedEditionId,[Parameter(Mandatory)][ValidateRange(0,2147483647)][int]$ExpectedRevision,
    [Parameter(Mandatory)][ValidateSet('WindowsUpdate')][string]$ServicingSource,
    [Parameter(Mandatory)][string]$EvidenceRoot,[switch]$DisposableVm)
  $context=Get-RideCapabilityAcceptanceContext
  if(-not $DisposableVm -or $context.GuestMarker -cne '1' -or $context.IntegrationMarker -cne '1' -or $context.RunMarker -cne $RunId -or $context.Manufacturer -cne 'Microsoft Corporation' -or $context.Model -cne 'Virtual Machine'){throw 'Capability acceptance requires a correlated disposable Hyper-V guest.'}
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId -or $context.UpdateBuildRevision -ne $ExpectedRevision -or $context.Architecture -cne 'AMD64'){throw 'Capability acceptance target differs.'}
  & $script:provider {param($context) Assert-RideClientCapabilityContext $context} $context
  $null=& $script:private {param($path) Resolve-RidePrivateFilePath $path} (Join-Path $EvidenceRoot '_probe.json')
  $directory=Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) $RunId
  if(Test-Path -LiteralPath $directory){throw 'Acceptance evidence already exists; use a new request ID.'}
  $report=[pscustomobject][ordered]@{SchemaVersion=1;Kind='ClientCapabilityAcceptance';RunId=$RunId;Family=$Family;Status='NotRun';Reason=$null;Stage='Preflight';Error=$null;RecordedAtUtc=[datetime]::UtcNow.ToString('o');WindowsContext=$context;ServicingSource=$ServicingSource;LifecyclePassed=$false;ExactPayloadRecoverySupported=$false;RestartAcceptancePassed=$false;RecoveryRequired=$false;Checks=@();LifecycleRuns=@();Selection=@();EvidenceErrors=@();EvidenceDirectory=$null}
  if(-not $context.Administrator){$report.Reason='ExistingElevationRequired';return $report}
  try {Assert-RideCapabilityAcceptanceReady $context}
  catch {
    # A host lifecycle intent is already durable when this guest function is
    # called. Record a synchronous readiness refusal so collection can distinguish
    # it from a still-running or interrupted servicing job. Preview writes nothing.
    if($WhatIfPreference -or -not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Record failed capability readiness preflight')){throw}
    $report.Status='Failed';$report.Reason='ReadinessPreflightRejected'
    $report.Error=$_.Exception.Message;$report.EvidenceDirectory=$directory
    $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    Save-RideCapabilityAcceptanceEvidence (Join-Path $directory 'result.json') $report
    return $report
  }
  $id=if($Family -ceq 'OpenSSHClient'){'component.openssh-client-capability'}else{'solution.rsat-client-tools'}
  $install=@(Get-RideSingleOperationPlan -Id $id -Action Install)
  if(-not $install.Count -or @($install|Where-Object {$_.Operation.Kind -cne 'WindowsCapability' -or $_.Operation.Handler -cne 'ClientCapability' -or $_.Operation.Scope -cne 'Machine' -or $_.Operation.ServicingSource -cne $ServicingSource -or $_.State -cne 'Present'}).Count){throw 'Unexpected capability plan.'}
  $names=@($install.Operation.CapabilityName|Sort-Object -Unique)
  if($names.Count -ne $install.Count){throw 'Duplicate capability selection.'}
  if($Family -ceq 'OpenSSHClient'){
    if($install.Count -ne 1 -or $install[0].Operation.Id -cne 'component.openssh-client-capability' -or $names[0] -cne 'OpenSSH.Client~~~~0.0.1.0'){throw 'Plan differs from the selected OpenSSH Client family.'}
  } elseif(@($install|Where-Object {$_.Operation.Id -cnotmatch '^component\.rsat-[a-z0-9-]+$' -or $_.Operation.CapabilityName -cnotmatch '^Rsat\.[A-Za-z0-9.-]+\.Tools~~~~0\.0\.1\.0$'}).Count){throw 'Plan differs from the selected RSAT family.'}
  $report.Selection=@($install.Operation|Select-Object Id,CapabilityName,CapabilityDependencies)
  $before=@(Get-RideCapabilityAcceptanceInventory)
  foreach($name in $names){$row=@($before|Where-Object Name -CEQ $name);if($row.Count -ne 1 -or $row[0].State -cnotin @('Installed','NotPresent')){throw 'Selected capability is absent from inventory or has a pending/unknown state.'}}
  if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,"Run $Family capability install/repeat/remove/saved restore using Windows Update")){$report.Status='Preview';return $report}
  $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
  $report.EvidenceDirectory=$directory
  Save-RideCapabilityAcceptanceEvidence (Join-Path $directory 'before.json') $before
  try {
    $report.Stage='Preview';$journals=@(Get-RideCapabilityAcceptanceJournals)
    $null=Invoke-RidePlan -Plan $install -WhatIf
    if(-not (Test-RideCapabilityAcceptanceEqual $journals @(Get-RideCapabilityAcceptanceJournals)) -or -not (Test-RideCapabilityAcceptanceEqual $before @(Get-RideCapabilityAcceptanceInventory))){throw 'Preview changed capability state or engine journals.'}
    $report.Checks+='PreviewNoChanges'
    foreach($stage in @('Install','Repeat','Remove','RestoreRemoval','RestoreInitial','RepeatRestore')){
      $report.Stage=$stage;Assert-RideCapabilityAcceptanceReady $context
      $priorJournals=@(Get-RideCapabilityAcceptanceJournals)
      switch($stage){
        Install {$installRun=Invoke-RideCapabilityAcceptanceStep $stage {Invoke-RidePlan -Plan $install -AllowCandidate -Confirm:$false} $report $directory}
        Repeat {
          $repeatPlan=@(Get-RideSingleOperationPlan -Id $id -Action Install)
          if(-not (Test-RideCapabilityAcceptanceEqual @($repeatPlan.Operation.CapabilityName|Sort-Object) $names)){throw 'Repeat selection changed.'}
          $unexpected=Invoke-RideCapabilityAcceptanceStep $stage {Invoke-RidePlan -Plan $repeatPlan -AllowCandidate -Confirm:$false} $report $directory
          if($unexpected){throw 'Repeat created an engine run.'}
        }
        Remove {
          $remove=@(Get-RideSingleOperationPlan -Id $id -Action Remove)
          if(-not (Test-RideCapabilityAcceptanceEqual @($remove.Operation.CapabilityName|Sort-Object) $names)){throw 'Removal selection changed.'}
          $removeRun=Invoke-RideCapabilityAcceptanceStep $stage {Invoke-RidePlan -Plan $remove -AllowCandidate -Confirm:$false} $report $directory
          if(-not $removeRun){throw 'Removal did not report a saved engine run.'}
        }
        RestoreRemoval {$null=Invoke-RideCapabilityAcceptanceStep $stage {Restore-RideRun -RunId $removeRun -AllowCandidate -Confirm:$false} $report $directory}
        RestoreInitial {if($installRun){$null=Invoke-RideCapabilityAcceptanceStep $stage {Restore-RideRun -RunId $installRun -AllowCandidate -Confirm:$false} $report $directory}}
        RepeatRestore {$lastRun=if($installRun){$installRun}else{$removeRun};$null=Invoke-RideCapabilityAcceptanceStep $stage {Restore-RideRun -RunId $lastRun -AllowCandidate -Confirm:$false} $report $directory}
      }
      Assert-RideCapabilityAcceptanceReady $context
      $after=@(Get-RideCapabilityAcceptanceInventory)
      $expected=switch($stage){Remove {'NotPresent'};{$_ -in @('RestoreInitial','RepeatRestore')} {'Original'};default {'Installed'}}
      Assert-RideCapabilityAcceptanceInventory $before $after $names $expected
      if($stage -ceq 'Install' -and -not $installRun -and @($before|Where-Object {$_.Name -cin $names -and $_.State -ceq 'NotPresent'}).Count){throw 'Installation did not report a saved engine run.'}
      if($stage -cin @('Repeat','RepeatRestore') -and -not (Test-RideCapabilityAcceptanceEqual $priorJournals @(Get-RideCapabilityAcceptanceJournals))){throw 'Repeated operation changed engine journals.'}
      $binary=$null
      if($Family -ceq 'OpenSSHClient'){
        $binary=Get-RideCapabilityAcceptanceClientBinary
        $present=@($after|Where-Object {$_.Name -cin $names -and $_.State -ceq 'Installed'}).Count -gt 0
        if($present -and (-not $binary.Exists -or [string]::IsNullOrWhiteSpace($binary.FileVersion) -or $binary.SignatureStatus -cne 'Valid' -or $binary.SignerSubject -notmatch 'O=Microsoft Corporation(?:,|$)')){throw 'Native OpenSSH client identity/version could not be verified.'}
        if(-not $present -and $binary.Exists){throw 'Native OpenSSH client remains after capability removal.'}
      }
      Save-RideCapabilityAcceptanceEvidence (Join-Path $directory ($stage+'-state.json')) ([pscustomobject]@{Inventory=$after;ClientBinary=$binary;Journals=@(Get-RideCapabilityAcceptanceJournals)})
      if($stage -ceq 'RestoreRemoval'){foreach($run in $report.LifecycleRuns|Where-Object RunId -CEQ $removeRun){$run.Restored=$true}}
      if($stage -ceq 'RestoreInitial' -and $installRun){foreach($run in $report.LifecycleRuns|Where-Object RunId -CEQ $installRun){$run.Restored=$true}}
      $report.Checks+=($stage+'ReadbackPassed')
    }
    $report.Status='Passed';$report.LifecyclePassed=$true
  } catch {$report.Status='Failed';$report.Error=$_.Exception.Message;$report.RecoveryRequired=$true}
  Save-RideCapabilityAcceptanceEvidence (Join-Path $directory 'result.json') $report
  $report
}
Export-ModuleMember -Function Invoke-RideClientCapabilityAcceptance
