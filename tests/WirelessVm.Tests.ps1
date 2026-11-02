<#
.SYNOPSIS
  Exercise retained synthetic WLAN VM dispatch without touching a real guest.
.DESCRIPTION
  Mocks host identity, Hyper-V, credentials and PowerShell Direct. Real TestDrive
  snapshots/exports test byte identity and private user-scope journal files.
.EXAMPLE
  Invoke-Pester ./tests/WirelessVm.Tests.ps1
.NOTES
  Native Windows PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.WirelessVm.psm1') -Force}
Describe 'Retained synthetic WLAN VM phase orchestration' {
  InModuleScope RIDE.WirelessVm {
    BeforeAll {
      function Restore-VMSnapshot { [CmdletBinding()] param($VMSnapshot,[switch]$Confirm) }
      function Start-VM { [CmdletBinding()] param($VM) }
    }
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      $script:run='a'*32;$script:lease='b'*32;$script:vmState='Off';$script:events=[Collections.Generic.List[string]]::new()
      $script:context=[pscustomobject]@{Root=$script:root;ConfigurationSha256=('C'*64);Configuration=[pscustomobject]@{VMName='RIDE-Test';VMId='11111111-1111-1111-1111-111111111111';LocalRepositoryPath=[IO.Path]::GetFullPath((Join-Path (Split-Path (Get-Module RIDE.WirelessVm).Path -Parent) '../..'))}}
      $script:hold=[pscustomobject]@{RunId=$script:run;LeaseId=$script:lease;VMId=$script:context.Configuration.VMId;VMName='RIDE-Test';CheckpointId='22222222-2222-2222-2222-222222222222';ConfigurationSha256=$script:context.ConfigurationSha256}
      $script:store=Join-Path $script:root ('retained.'+$script:lease)
      $script:selection=@{ConfigurationPath=(Join-Path $script:root 'configuration.json');RunId=$script:run;Confirm=$false}
      $script:interface=[guid]'de81fe79-7a46-4d65-a865-e38bfa8aaeb8'
      $script:prepare=@{Phase='Prepare';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      Mock Get-RideWirelessVmContext {$script:context}
      Mock New-RideRetainedGuestHold {$script:events.Add('Reserve');$script:hold}
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=$script:context;Hold=$script:hold;Lock=$script:lastLock;Target=[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState};Snapshot='synthetic-checkpoint'}}}
      Mock New-RideWirelessVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideWirelessVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideWirelessVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      Mock New-RideWirelessVmSnapshot {@([pscustomobject]@{Path='synthetic-source';Sha256=('A'*64);Bytes=1})}
      Mock Get-RideWirelessVmPayload {@([pscustomobject]@{Path='synthetic-source';Content='QQ=='})}
      Mock Get-RideWirelessVmCredential {[pscredential]::new('synthetic-user',(ConvertTo-SecureString 'Synthetic-test-only' -AsPlainText -Force))}
      Mock Restore-VMSnapshot {$script:events.Add('InitialCheckpoint')}
      Mock Start-VM {$script:events.Add('Start');$script:vmState='Running'}
      Mock Wait-RideWirelessVmReady {[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';Revision=9711}}
      Mock Invoke-RideWirelessVmRemote {
        param($Action,$Descriptor,$InterfaceId)
        $script:events.Add($Action)
        if($Action -eq 'Prepare'){return [pscustomobject]@{SchemaVersion=1;Kind='WirelessVmPreparation';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Prepared';NativeAcceptancePassed=$false;Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'};Availability=[pscustomobject]@{SchemaVersion=1;Kind='WirelessInterfaceObservation';Status='Available';Reason=$null;Interfaces=@([pscustomobject]@{Id=$script:interface.ToString('D');State=[uint32]4});ProfileContentRead=$false;ConnectionAttempted=$false;NativeAcceptancePassed=$false}}}
        [pscustomobject]@{SchemaVersion=1;Kind='WirelessLifecycleAcceptance';RunId=$Descriptor.RunId;Status='Passed';Stage='Complete';ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';InterfaceId=$InterfaceId.ToString('D');NativeAcceptancePassed=$true;ConnectionAttempted=$false;RecoveryRequired=$false;LifecycleRuns=@([pscustomobject]@{Action='Import';RunId=('1'*32);Restored=$true},[pscustomobject]@{Action='Replace';RunId=('2'*32);Restored=$true},[pscustomobject]@{Action='Remove';RunId=('3'*32);Restored=$true});StateRunIds=@(('1'*32),('2'*32),('3'*32));Checks=@('PreviewNoChanges','ImportAndNativeReadback','RepeatWithoutNewRun','ReplacementAndNativeReadback','PriorSyntheticProfileRestored','OwnedRemoval','RemovedProfileRestored','InitialAbsenceAndOrderRestored','RepeatedRestoreNoChange')}
      }
      Mock Export-RideWirelessVmEvidence {$script:events.Add('Export');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected'}}
      Mock Read-RideWirelessVmResetExport {$script:events.Add('VerifySavedExport');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected'}}
      Mock Reset-RideAutomationVm {$script:events.Add('Reset');$script:vmState='Off'}
      Mock Import-RideAutomationLab {[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState}}}
      Mock Remove-RideRetainedGuestHold {$script:events.Add('Release');[pscustomobject]@{Status='Released'}}
    }
    It 'prepares, retains synthetic profile lifecycle, collects, then explicitly exports before reset and release' {
      $reports=@(Invoke-RideWirelessVmPhase @script:selection @script:prepare)
      foreach($phase in @('Lifecycle','Collect','Reset')){$extra=if($phase -ceq 'Lifecycle'){@{InterfaceId=$script:interface}}else{@{}};$reports+=Invoke-RideWirelessVmPhase @script:selection -Phase $phase @extra}
      ($reports.Status -join ';')|Should -BeExactly 'Prepared;Passed;Collected;ResetAndOff'
      @($reports|Where-Object NativeAcceptancePassed).Count|Should -Be 0
      $reports[-1].RecoveryRequired|Should -BeFalse
      $reports[1].ProfileLifecycleAcceptancePassed|Should -BeTrue
      @($reports|Where-Object ConnectionAttempted).Count|Should -Be 0
      @($reports|Where-Object ConnectionVerified).Count|Should -Be 0
      @($reports|Where-Object FullDaclRecoveryVerified).Count|Should -Be 0
      ($script:events -join ';')|Should -BeExactly 'Reserve;InitialCheckpoint;Start;Prepare;Export;Lifecycle;Export;Export;Export;Reset;Release'
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 4
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 1 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 1 -Exactly
    }
    It 'previews all phases without holds, snapshots, VM calls or records' {
      (Invoke-RideWirelessVmPhase @script:selection @script:prepare -WhatIf).Status|Should -Be Preview
      foreach($phase in @('Lifecycle','Collect','Reset')){$extra=if($phase -ceq 'Lifecycle'){@{InterfaceId=$script:interface}}else{@{}};(Invoke-RideWirelessVmPhase @script:selection -Phase $phase @extra -WhatIf).Status|Should -Be Preview}
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      Should -Invoke Open-RideRetainedGuestPhase -Times 0 -Exactly
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
      Should -Invoke Write-RideWirelessVmRecord -Times 0 -Exactly
    }
    It 'rejects irrelevant inputs, old builds and a different checkout before reservation' {
      {Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface -ExpectedBuild '26300'}|Should -Throw '*only to Prepare*'
      $script:prepare.ExpectedBuild='19045'
      {Invoke-RideWirelessVmPhase @script:selection @script:prepare}|Should -Throw '*Windows 11*'
      $script:prepare.ExpectedBuild='26300';$script:context.Configuration.LocalRepositoryPath=$script:root
      {Invoke-RideWirelessVmPhase @script:selection @script:prepare}|Should -Throw '*registered checkout*'
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'uses declared canonical phase and edition values while requiring lowercase request IDs' {
      $script:selection.RunId='A'*32
      {Invoke-RideWirelessVmPhase @script:selection @script:prepare}|Should -Throw
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      $script:selection.RunId=$script:run;$script:prepare.Phase='prepare';$script:prepare.ExpectedEditionId='enterpriseeval'
      (Invoke-RideWirelessVmPhase @script:selection @script:prepare).Status|Should -Be Prepared
      (Read-RideWirelessVmRecord (Join-Path $script:store 'session.json')).ExpectedEditionId|Should -BeExactly EnterpriseEval
      (Invoke-RideWirelessVmPhase @script:selection -Phase 'lifecycle' -InterfaceId $script:interface).Status|Should -Be Passed
    }
    It 'refuses a changed controller digest under phase ownership' {
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=[pscustomobject]@{ConfigurationSha256=('D'*64)};Hold=$script:hold;Lock=$script:lastLock}}
      $report=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'configuration changed'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
    }
    It 'retains a preparation failure and never performs automatic reset or release' {
      Mock New-RideWirelessVmSnapshot {throw 'Synthetic snapshot failure.'}
      $report=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 1
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'exports partial guest evidence after lifecycle failure and leaves the guest running' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Invoke-RideWirelessVmRemote {throw 'Synthetic lifecycle failure.'}
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Lifecycle;$report.EvidenceExport.Verified|Should -BeTrue
      $script:vmState|Should -Be Running
      Should -Invoke Export-RideWirelessVmEvidence -Times 2 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'rejects a mismatched guest result instead of treating an exit as acceptance' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Invoke-RideWirelessVmRemote {[pscustomobject]@{SchemaVersion=1;RunId=('c'*32);Status='Passed';NativeAcceptancePassed=$false}}
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'correlation'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses reset when current evidence export fails' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Export-RideWirelessVmEvidence {throw 'Synthetic export failure.'}
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be EvidenceExport
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses an absent export after a claimed successful guest phase' {
      Mock Export-RideWirelessVmEvidence {[pscustomobject]@{Verified=$true;GuestStatus='Absent';FileCount=0}}
      $report=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'not exported'
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'retries explicit reset from Off only through the saved verified export path' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $script:vmState='Off'
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be ResetAndOff;$report.RecoveryRequired|Should -BeFalse
      Should -Invoke Read-RideWirelessVmResetExport -Times 1 -Exactly
      Should -Invoke Wait-RideWirelessVmReady -Times 1 -Exactly
      Should -Invoke Get-RideWirelessVmCredential -Times 1 -Exactly
      Should -Invoke Export-RideWirelessVmEvidence -Times 1 -Exactly
    }
    It 'retains the hold when checkpoint recovery fails or its final state is not Off' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Reset-RideAutomationVm {throw 'Synthetic reset failure.'}
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be ExplicitCheckpointReset
      @((Get-ChildItem -LiteralPath $script:store -Filter 'reset-intent.*.json')).Count|Should -Be 1
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
      Mock Reset-RideAutomationVm {}
      $retry=Invoke-RideWirelessVmPhase @script:selection -Phase Reset
      $retry.Status|Should -Be Failed;$retry.Error|Should -Match 'did not leave the pinned guest Off'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'keeps the recovery receipt when hold release fails after the reset' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Remove-RideRetainedGuestHold {throw 'Synthetic release failure.'}
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be HoldRelease;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'recovery.*.json')).Count|Should -Be 1
      $script:vmState|Should -Be Off
    }
    It 'disposes the phase lock when journaling itself fails' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Write-RideWirelessVmRecord {throw 'Synthetic journal failure.'}
      {Invoke-RideWirelessVmPhase @script:selection -Phase Collect}|Should -Throw '*journal failure*'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'refuses a saved session from another lease before guest calls' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $path=Join-Path $script:store 'session.json';$saved=Read-RideWirelessVmRecord $path;$saved.LeaseId='c'*32
      [IO.File]::WriteAllText($path,($saved|ConvertTo-Json -Depth 10))
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'session identity'
      Should -Invoke Invoke-RideWirelessVmRemote -Times 1 -Exactly
    }
    It 'preserves NotRun without inventing lifecycle acceptance or cleanup' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Invoke-RideWirelessVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='WirelessLifecycleAcceptance';RunId=$script:run;ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';InterfaceId=$script:interface.ToString('D');Status='NotRun';Reason='WlanInterfaceUnavailable';NativeAcceptancePassed=$false;ConnectionAttempted=$false;ConnectionVerified=$false;RecoveryRequired=$false;Checks=@();LifecycleRuns=@();StateRunIds=@()}}
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface
      $report.Status|Should -Be NotRun;$report.ProfileLifecycleAcceptancePassed|Should -BeFalse
      $report.RecoveryRequired|Should -BeTrue;$report.EvidenceExport.Verified|Should -BeTrue
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'does not certify a successful lifecycle when its evidence export fails' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      Mock Export-RideWirelessVmEvidence {throw 'Synthetic evidence failure.'}
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface
      $report.Status|Should -Be Failed;$report.ProfileLifecycleAcceptancePassed|Should -BeFalse
      $report.GuestResult.Status|Should -Be Passed;$report.RecoveryRequired|Should -BeTrue
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'rejects another interface and incomplete saved recovery runs' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $descriptor=Read-RideWirelessVmRecord (Join-Path $script:store 'session.json')
      $guest=Invoke-RideWirelessVmRemote $null $null Lifecycle $descriptor $null -InterfaceId $script:interface
      $guest.InterfaceId='00000000-0000-0000-0000-000000000001'
      {Assert-RideWirelessVmGuestResult $guest Lifecycle $descriptor $script:interface}|Should -Throw '*interface or acceptance*'
      $guest.InterfaceId=$script:interface.ToString('D');$guest.LifecycleRuns[2].Restored=$false
      {Assert-RideWirelessVmGuestResult $guest Lifecycle $descriptor $script:interface}|Should -Throw '*recovery runs*'
      $guest.LifecycleRuns[2].Restored=$true;$guest.StateRunIds=@('1'*32)
      {Assert-RideWirelessVmGuestResult $guest Lifecycle $descriptor $script:interface}|Should -Throw '*recovery runs*'
      $guest.StateRunIds=@(('1'*32),('2'*32),('3'*32));$guest.ConnectionAttempted=$true
      {Assert-RideWirelessVmGuestResult $guest Lifecycle $descriptor $script:interface}|Should -Throw '*acceptance boundary*'
    }
    It 'retains a missing-WLAN preparation result and permits only explicit cleanup' {
      Mock Invoke-RideWirelessVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmPreparation';RunId=$script:run;LeaseId=$script:lease;Status='NotRun';NativeAcceptancePassed=$false;Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'};Availability=[pscustomobject]@{SchemaVersion=1;Kind='WirelessInterfaceObservation';Status='NotRun';Reason='NoWlanInterfaces';Interfaces=@();ProfileContentRead=$false;ConnectionAttempted=$false;NativeAcceptancePassed=$false}}}
      $report=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $report.Status|Should -Be NotRun;$report.ProfileLifecycleAcceptancePassed|Should -BeFalse
      $report.EvidenceExport.Verified|Should -BeTrue
      (Read-RideWirelessVmRecord (Join-Path $script:store 'wlan-observation.json')).Availability.Reason|Should -Be NoWlanInterfaces
      $refused=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface
      $refused.Status|Should -Be Failed;$refused.Error|Should -Match 'prepared guest observation'
      Should -Invoke Invoke-RideWirelessVmRemote -Times 1 -Exactly
      (Invoke-RideWirelessVmPhase @script:selection -Phase Reset).Status|Should -Be ResetAndOff
    }
    It 'requires the lifecycle interface and refuses misplaced selections before opening a hold' {
      {Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle}|Should -Throw '*nonempty InterfaceId*'
      {Invoke-RideWirelessVmPhase @script:selection @script:prepare -InterfaceId $script:interface}|Should -Throw '*only to Lifecycle*'
      {Invoke-RideWirelessVmPhase @script:selection -Phase Collect -InterfaceId ([guid]::Empty)}|Should -Throw '*only to Lifecycle*'
      Should -Invoke Open-RideRetainedGuestPhase -Times 0 -Exactly
    }
    It 'refuses an unobserved interface before guest credential lookup or dispatch' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId '00000000-0000-0000-0000-000000000001'
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Preflight
      Should -Invoke Get-RideWirelessVmCredential -Times 1 -Exactly
      Should -Invoke Invoke-RideWirelessVmRemote -Times 1 -Exactly
    }
    It 'rejects another lease observation before a lifecycle dispatch' {
      $null=Invoke-RideWirelessVmPhase @script:selection @script:prepare
      $path=Join-Path $script:store 'wlan-observation.json';$observation=Read-RideWirelessVmRecord $path
      $observation.LeaseId='c'*32;[IO.File]::WriteAllText($path,($observation|ConvertTo-Json -Depth 8))
      $report=Invoke-RideWirelessVmPhase @script:selection -Phase Lifecycle -InterfaceId $script:interface
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'preparation result differs'
      Should -Invoke Invoke-RideWirelessVmRemote -Times 1 -Exactly
    }
  }
}
Describe 'Retained snapshot and export byte boundaries' {
  InModuleScope RIDE.WirelessVm {
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      Mock New-RideWirelessVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideWirelessVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideWirelessVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      $script:descriptor=[pscustomobject]@{RunId=('a'*32);LeaseId=('b'*32);ConfigurationSha256=('C'*64);VMName='RIDE-Test';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      $script:bytes=[Text.Encoding]::UTF8.GetBytes('synthetic private evidence')
      $script:entry=[pscustomobject]@{Path='evidence/owned/state.json';Bytes=$script:bytes.Length;Sha256=(Get-RideWirelessVmHash $script:bytes);Content=[Convert]::ToBase64String($script:bytes)}
      Mock Invoke-RideWirelessVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';Files=@($script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
    }
    It 'stages exactly the required sources and detects snapshot drift' {
      $repo=Join-Path $script:root 'repo';$null=New-Item -ItemType Directory -Path $repo
      foreach($relative in $script:WirelessVmSources){
        $path=Join-Path $repo $relative
        $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force;[IO.File]::WriteAllText($path,'inert source fixture')
      }
      $snapshot=Join-Path $script:root 'snapshot';$manifest=@(New-RideWirelessVmSnapshot $repo $snapshot)
      $manifest.Count|Should -Be 7
      @(Get-RideWirelessVmPayload $snapshot $manifest).Count|Should -Be 7
      {Get-RideWirelessVmPayload $snapshot (@($manifest)+@([pscustomobject]@{Path='legacy/unselected.ps1'}))}|Should -Throw '*selection differs*'
      [IO.File]::AppendAllText((Join-Path $snapshot $manifest[0].Path),'changed')
      {Get-RideWirelessVmPayload $snapshot $manifest}|Should -Throw '*size changed*'
    }
    It 'exports verified bytes and retains a private correlated manifest' {
      $export=Export-RideWirelessVmEvidence $null $null $script:descriptor $script:root
      $export.Verified|Should -BeTrue;$export.FileCount|Should -Be 1
      $receipt=Read-RideWirelessVmRecord (Join-Path $export.Path 'export-receipt.json')
      $receipt.RunId|Should -BeExactly $script:descriptor.RunId
      (Get-FileHash -LiteralPath (Join-Path $export.Path $script:entry.Path)).Hash|Should -BeExactly $script:entry.Sha256
    }
    It 'rejects traversal, duplicate paths and mismatched payload bytes before certifying export' {
      $script:entry.Path='../escape.json'
      {Export-RideWirelessVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*Unsafe*'
      $script:entry.Path='evidence.json';$script:entry.Sha256='0'*64
      {Export-RideWirelessVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*bytes differ*'
      $script:entry.Sha256=Get-RideWirelessVmHash $script:bytes
      Mock Invoke-RideWirelessVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';Files=@($script:entry,$script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideWirelessVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*duplicate*'
    }
    It 'reverifies a private pre-reset export and refuses changed saved bytes or a missing intent' {
      {Read-RideWirelessVmResetExport $script:root $script:descriptor}|Should -Throw '*pre-reset export intent*'
      $export=Export-RideWirelessVmEvidence $null $null $script:descriptor $script:root
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=$export.Path}
      Write-RideWirelessVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      (Read-RideWirelessVmResetExport $script:root $script:descriptor).Verified|Should -BeTrue
      [IO.File]::AppendAllText((Join-Path $export.Path $script:entry.Path),'changed')
      {Read-RideWirelessVmResetExport $script:root $script:descriptor}|Should -Throw '*evidence changed*'
    }
    It 'rejects incomplete or invented lifecycle reports' {
      $guest=[pscustomobject]@{SchemaVersion=1;Kind='WirelessLifecycleAcceptance';RunId=$script:descriptor.RunId;Status='Passed';Stage='Complete';ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';InterfaceId='de81fe79-7a46-4d65-a865-e38bfa8aaeb8';NativeAcceptancePassed=$true;ConnectionAttempted=$false;ConnectionVerified=$false;RecoveryRequired=$false;Checks=@('InitialStateRestored')}
      {Assert-RideWirelessVmGuestResult $guest Lifecycle $script:descriptor ([guid]'de81fe79-7a46-4d65-a865-e38bfa8aaeb8')}|Should -Throw '*every required*'
      $guest.ConnectionAttempted=$true
      {Assert-RideWirelessVmGuestResult $guest Lifecycle $script:descriptor ([guid]'de81fe79-7a46-4d65-a865-e38bfa8aaeb8')}|Should -Throw '*acceptance boundary*'
    }
    It 'refuses a collection from another lease before creating an export directory' {
      Mock Invoke-RideWirelessVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmCollection';RunId=$script:descriptor.RunId;LeaseId=('f'*32);Status='Collected';Files=@();Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideWirelessVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*mismatched*'
      Should -Invoke New-RideWirelessVmDirectory -Times 0 -Exactly
    }
    It 'rejects a reset receipt that points outside its owned export directory' {
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='WirelessVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=(Join-Path $script:root ('elsewhere/export.'+('c'*32)))}
      Write-RideWirelessVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      {Read-RideWirelessVmResetExport $script:root $script:descriptor}|Should -Throw '*escaped*'
    }
  }
}
Describe 'Bounded fixed PowerShell Direct job transport' {
  InModuleScope RIDE.WirelessVm {
    BeforeAll {
      function Invoke-Command { [CmdletBinding()] param($VMId,$Credential,$ScriptBlock,$ArgumentList,[switch]$AsJob) }
      function Wait-Job { param($Job,$Timeout) }
      function Receive-Job { [CmdletBinding()] param($Job) }
      function Stop-Job { [CmdletBinding()] param($Job) }
      function Remove-Job { [CmdletBinding()] param($Job,[switch]$Force) }
    }
    BeforeEach {
      $script:configuration=[pscustomobject]@{VMId='11111111-1111-1111-1111-111111111111'}
      $script:job=[pscustomobject]@{State='Completed'}
      Mock Invoke-Command {$script:job}
      Mock Wait-Job {$script:job}
      Mock Receive-Job {[pscustomobject]@{Status='synthetic-result'}}
      Mock Stop-Job {}
      Mock Remove-Job {}
    }
    It 'uses only the fixed remote scriptblock and returns one completed result' {
      (Invoke-RideWirelessVmRemote $script:configuration $null Collect $null $null).Status|Should -Be synthetic-result
      Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {$VMId -eq [guid]$script:configuration.VMId -and $ScriptBlock -eq $script:WirelessVmRemote -and $AsJob}
      Should -Invoke Wait-Job -Times 1 -Exactly -ParameterFilter {$Timeout -eq 180}
      Should -Invoke Remove-Job -Times 1 -Exactly
    }
    It 'stops and removes a timed-out job without receiving a success result' {
      Mock Wait-Job {$null}
      {Invoke-RideWirelessVmRemote $script:configuration $null Lifecycle $null $null 15}|Should -Throw '*timed out*'
      Should -Invoke Stop-Job -Times 1 -Exactly
      Should -Invoke Remove-Job -Times 1 -Exactly
      Should -Invoke Receive-Job -Times 0 -Exactly
    }
    It 'rejects a failed job or multiple result objects and still disposes the job' {
      $script:job.State='Failed'
      {Invoke-RideWirelessVmRemote $script:configuration $null Lifecycle $null $null}|Should -Throw '*one completed result*'
      $script:job.State='Completed'
      Mock Receive-Job {@('unexpected','extra output')}
      {Invoke-RideWirelessVmRemote $script:configuration $null Lifecycle $null $null}|Should -Throw '*one completed result*'
      Should -Invoke Remove-Job -Times 2 -Exactly
    }
    It 'transports only the selected canonical GUID as the fourth fixed argument' {
      $selected=[guid]'DE81FE79-7A46-4D65-A865-E38BFA8AAEB8'
      $null=Invoke-RideWirelessVmRemote $script:configuration $null Lifecycle $null $null -InterfaceId $selected
      Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {$ArgumentList.Count -eq 4 -and $ArgumentList[3] -ceq 'de81fe79-7a46-4d65-a865-e38bfa8aaeb8'}
    }
  }
}

Describe 'Saved interface validation and completion' {
  InModuleScope RIDE.WirelessVm {
    BeforeEach {
      $script:availability=[pscustomobject]@{SchemaVersion=1;Kind='WirelessInterfaceObservation';Status='Available';Reason=$null;Interfaces=@([pscustomobject]@{Id='de81fe79-7a46-4d65-a865-e38bfa8aaeb8';State=[uint32]4});ProfileContentRead=$false;ConnectionAttempted=$false;NativeAcceptancePassed=$false}
      Mock Get-RideWirelessVmSavedObservation {[pscustomobject]@{Availability=$script:availability}}
      Mock Invoke-RideWirelessVmRemote {throw 'Completion must not dispatch.'}
      Mock Open-RideRetainedGuestPhase {throw 'Completion must not lock a guest.'}
      $script:bound=@{Phase='Lifecycle';ConfigurationPath='C:\Synthetic\configuration.json';RunId=('a'*32)}
    }
    It 'refuses duplicate, nonminimal and invalid interface observations' {
      $script:availability.Interfaces+=@($script:availability.Interfaces[0])
      {Assert-RideWirelessVmAvailability $script:availability}|Should -Throw '*interface observation*'
      $script:availability.Interfaces=@($script:availability.Interfaces[0]);$script:availability.Interfaces[0]|Add-Member -NotePropertyName Profiles -NotePropertyValue @('unwanted name')
      {Assert-RideWirelessVmAvailability $script:availability}|Should -Throw '*nonminimal*'
      $script:availability.Interfaces[0].PSObject.Properties.Remove('Profiles');$script:availability.Interfaces[0].State=-1
      {Assert-RideWirelessVmAvailability $script:availability}|Should -Throw '*interface observation*'
      $script:availability.Status='NotRun';$script:availability.Reason='NoWlanInterfaces'
      {Assert-RideWirelessVmAvailability $script:availability}|Should -Throw '*unavailable*'
    }
    It 'completes only saved matching GUIDs without a VM query or hold' {
      $results=@(& $script:WirelessVmInterfaceCompleter '' '' 'DE81' $null $script:bound)
      $results.Count|Should -Be 1;$results[0].CompletionText|Should -BeExactly 'de81fe79-7a46-4d65-a865-e38bfa8aaeb8'
      @(& $script:WirelessVmInterfaceCompleter '' '' 'other' $null $script:bound).Count|Should -Be 0
      Should -Invoke Invoke-RideWirelessVmRemote -Times 0 -Exactly
      Should -Invoke Open-RideRetainedGuestPhase -Times 0 -Exactly
    }
    It 'fails completion quietly for unavailable data, duplicates and the wrong phase' {
      Mock Get-RideWirelessVmSavedObservation {throw 'Synthetic private record unavailable.'}
      @(& $script:WirelessVmInterfaceCompleter '' '' '' $null $script:bound).Count|Should -Be 0
      Mock Get-RideWirelessVmSavedObservation {[pscustomobject]@{Availability=$script:availability}}
      $script:availability.Interfaces+=@($script:availability.Interfaces[0])
      @(& $script:WirelessVmInterfaceCompleter '' '' '' $null $script:bound).Count|Should -Be 0
      $script:bound.Phase='Prepare'
      @(& $script:WirelessVmInterfaceCompleter '' '' '' $null $script:bound).Count|Should -Be 0
    }
    It 'keeps the fixed remote allowlist aligned with all seven staged sources' {
      $assignment=$script:WirelessVmRemote.Ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$expectedSources'},$true)
      $literals=@($assignment.Right.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst]},$true)|ForEach-Object Value)
      ($literals -join ';')|Should -BeExactly ($script:WirelessVmSources -join ';')
      $literals.Count|Should -Be 7
    }
  }
}
