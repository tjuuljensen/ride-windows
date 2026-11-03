<#
.SYNOPSIS
  Exercise retained machine-font VM dispatch without touching a real guest.
.DESCRIPTION
  Mocks host identity, Hyper-V, credentials and PowerShell Direct. Real TestDrive
  snapshots/exports test byte identity and private user-scope journal files.
.EXAMPLE
  Invoke-Pester ./tests/FontVm.Tests.ps1
.NOTES
  Native Windows PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.FontVm.psm1') -Force}
Describe 'Retained machine-font VM phase orchestration' {
  InModuleScope RIDE.FontVm {
    BeforeAll {
      function Restore-VMSnapshot { [CmdletBinding()] param($VMSnapshot,[switch]$Confirm) }
      function Start-VM { [CmdletBinding()] param($VM) }
    }
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      $script:run='a'*32;$script:lease='b'*32;$script:vmState='Off';$script:events=[Collections.Generic.List[string]]::new()
      $script:context=[pscustomobject]@{Root=$script:root;ConfigurationSha256=('C'*64);Configuration=[pscustomobject]@{VMName='RIDE-Test';VMId='11111111-1111-1111-1111-111111111111';LocalRepositoryPath=[IO.Path]::GetFullPath((Join-Path (Split-Path (Get-Module RIDE.FontVm).Path -Parent) '../..'))}}
      $script:hold=[pscustomobject]@{RunId=$script:run;LeaseId=$script:lease;VMId=$script:context.Configuration.VMId;VMName='RIDE-Test';CheckpointId='22222222-2222-2222-2222-222222222222';ConfigurationSha256=$script:context.ConfigurationSha256}
      $script:store=Join-Path $script:root ('retained.'+$script:lease)
      $script:selection=@{ConfigurationPath=(Join-Path $script:root 'configuration.json');RunId=$script:run;Confirm=$false}
      $script:fontSelection=@(1..14|ForEach-Object {[pscustomobject]@{FileName="Synthetic-$_.ttf";RegistryName="Synthetic $_ (TrueType)";FullName="Synthetic $_";Sha256=('F'*64)}})
      $script:prepare=@{Phase='Prepare';InputDirectory='synthetic-fonts';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      Mock Get-RideFontVmContext {$script:context}
      Mock Get-RideFontVmInputs {[pscustomobject]@{Selection=$script:fontSelection;Files=@()}}
      Mock New-RideRetainedGuestHold {
        $script:events.Add('Reserve')
        $null=New-Item -ItemType Directory -Path (Join-Path $script:root 'runtime') -Force
        [IO.File]::WriteAllText((Join-Path $script:root 'runtime/blocked.json'),'synthetic hold')
        $script:hold
      }
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=$script:context;Hold=$script:hold;Lock=$script:lastLock;Target=[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState};Snapshot='synthetic-checkpoint'}}}
      Mock New-RideFontVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideFontVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideFontVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      Mock New-RideFontVmSnapshot {@([pscustomobject]@{Path='synthetic-source';Sha256=('A'*64);Bytes=1})}
      Mock Get-RideFontVmPayload {@([pscustomobject]@{Path='synthetic-source';Content='QQ=='})}
      Mock Get-RideFontVmCredential {[pscredential]::new('synthetic-user',(ConvertTo-SecureString 'Synthetic-test-only' -AsPlainText -Force))}
      Mock Restore-VMSnapshot {$script:events.Add('InitialCheckpoint')}
      Mock Start-VM {$script:events.Add('Start');$script:vmState='Running'}
      Mock Wait-RideFontVmReady {[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';Revision=9711}}
      Mock Invoke-RideFontVmRemote {
        param($Action,$Descriptor)
        $script:events.Add($Action)
        if($Action -eq 'Prepare'){return [pscustomobject]@{SchemaVersion=1;Kind='FontVmPreparation';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Prepared';NativeAcceptancePassed=$false}}
        [pscustomobject]@{SchemaVersion=1;Kind='MachineFontAcceptance';RunId=$Descriptor.RunId;Status='Passed';Stage='Complete';ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';NativeAcceptancePassed=$true;CrossSessionAcceptancePassed=$false;RestartAcceptancePassed=$false;RecoveryRequired=$false;Selection=$Descriptor.Selection;LifecycleRuns=@([pscustomobject]@{Action='Install';RunId=('1'*32);Restored=$true},[pscustomobject]@{Action='Remove';RunId=('2'*32);Restored=$true});StateRunIds=@(('1'*32),('2'*32));Checks=@('PreviewNoChanges','InstalledNativeNamesFilesRegistrationAndPrivateState','RepeatNoChanges','RemovedToInitialState','InstalledBytesPermissionsMetadataAndNativeNamesRestored','InitialStateRestored','RepeatedRestoreNoChanges')}
      }
      Mock Export-RideFontVmEvidence {$script:events.Add('Export');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected'}}
      Mock Read-RideFontVmResetExport {$script:events.Add('VerifySavedExport');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected'}}
      Mock Reset-RideAutomationVm {$script:events.Add('Reset');$script:vmState='Off'}
      Mock Import-RideAutomationLab {[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState}}}
      Mock Remove-RideRetainedGuestHold {$script:events.Add('Release');[pscustomobject]@{Status='Released'}}
    }
    It 'prepares, retains current-session lifecycle, collects, then explicitly exports before reset and release' {
      $reports=@(Invoke-RideFontVmPhase @script:selection @script:prepare)
      foreach($phase in @('Lifecycle','Collect','Reset')){$reports+=Invoke-RideFontVmPhase @script:selection -Phase $phase}
      ($reports.Status -join ';')|Should -BeExactly 'Prepared;Passed;Collected;ResetAndOff'
      @($reports|Where-Object NativeAcceptancePassed).Count|Should -Be 0
      $reports[-1].RecoveryRequired|Should -BeFalse
      $reports[1].CurrentSessionAcceptancePassed|Should -BeTrue
      @($reports|Where-Object CrossSessionAcceptancePassed).Count|Should -Be 0
      @($reports|Where-Object RestartAcceptancePassed).Count|Should -Be 0
      @($reports|Where-Object ActiveConsumerAcceptancePassed).Count|Should -Be 0
      ($script:events -join ';')|Should -BeExactly 'Reserve;InitialCheckpoint;Start;Prepare;Export;Lifecycle;Export;Export;Export;Reset;Release'
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 4
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 1 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 1 -Exactly
    }
    It 'previews all phases without holds, snapshots, VM calls or records' {
      (Invoke-RideFontVmPhase @script:selection @script:prepare -WhatIf).Status|Should -Be Preview
      foreach($phase in @('Lifecycle','Collect','Reset')){(Invoke-RideFontVmPhase @script:selection -Phase $phase -WhatIf).Status|Should -Be Preview}
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      Should -Invoke Open-RideRetainedGuestPhase -Times 0 -Exactly
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
      Should -Invoke Write-RideFontVmRecord -Times 0 -Exactly
    }
    It 'rejects irrelevant inputs, old builds and a different checkout before reservation' {
      {Invoke-RideFontVmPhase @script:selection -Phase Lifecycle -InputDirectory 'unused-fonts'}|Should -Throw '*only to Prepare*'
      $script:prepare.ExpectedBuild='19045'
      {Invoke-RideFontVmPhase @script:selection @script:prepare}|Should -Throw '*Windows 11*'
      $script:prepare.ExpectedBuild='26300';$script:context.Configuration.LocalRepositoryPath=$script:root
      {Invoke-RideFontVmPhase @script:selection @script:prepare}|Should -Throw '*registered checkout*'
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'uses declared canonical phase and edition values while requiring lowercase request IDs' {
      $script:selection.RunId='A'*32
      {Invoke-RideFontVmPhase @script:selection @script:prepare}|Should -Throw
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      $script:selection.RunId=$script:run;$script:prepare.Phase='prepare';$script:prepare.ExpectedEditionId='enterpriseeval'
      (Invoke-RideFontVmPhase @script:selection @script:prepare).Status|Should -Be Prepared
      (Read-RideFontVmRecord (Join-Path $script:store 'session.json')).ExpectedEditionId|Should -BeExactly EnterpriseEval
      (Invoke-RideFontVmPhase @script:selection -Phase 'lifecycle').Status|Should -Be Passed
    }
    It 'refuses a changed controller digest under phase ownership' {
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=[pscustomobject]@{ConfigurationSha256=('D'*64)};Hold=$script:hold;Lock=$script:lastLock}}
      $report=Invoke-RideFontVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'configuration changed'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
    }
    It 'retains a preparation failure and never performs automatic reset or release' {
      Mock New-RideFontVmSnapshot {throw 'Synthetic snapshot failure.'}
      $report=Invoke-RideFontVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 1
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'exports partial guest evidence after lifecycle failure and leaves the guest running' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Invoke-RideFontVmRemote {throw 'Synthetic lifecycle failure.'}
      $report=Invoke-RideFontVmPhase @script:selection -Phase Lifecycle
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Lifecycle;$report.EvidenceExport.Verified|Should -BeTrue
      $script:vmState|Should -Be Running
      Should -Invoke Export-RideFontVmEvidence -Times 2 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'retries an owned preparation before checkpoint intent using its original snapshot' {
      Mock Get-RideFontVmCredential {throw 'Synthetic credential lookup failure.'}
      (Invoke-RideFontVmPhase @script:selection @script:prepare).Status|Should -Be Failed
      Mock Get-RideFontVmCredential {[pscredential]::new('synthetic-user',(ConvertTo-SecureString 'Synthetic-test-only' -AsPlainText -Force))}
      (Invoke-RideFontVmPhase @script:selection @script:prepare).Status|Should -Be Prepared
      Should -Invoke New-RideRetainedGuestHold -Times 1 -Exactly
      Should -Invoke New-RideFontVmSnapshot -Times 1 -Exactly
      Should -Invoke Restore-VMSnapshot -Times 1 -Exactly
    }
    It 'refuses preparation retry after checkpoint intent even when the VM is Off' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      $script:vmState='Off'
      $report=Invoke-RideFontVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'no prior checkpoint intent'
      Should -Invoke Restore-VMSnapshot -Times 1 -Exactly
      Should -Invoke New-RideFontVmSnapshot -Times 1 -Exactly
    }
    It 'refuses preparation retry with a changed target, input or cached snapshot' {
      Mock Get-RideFontVmCredential {throw 'Synthetic credential lookup failure.'}
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      $script:prepare.ExpectedBuild='26301'
      (Invoke-RideFontVmPhase @script:selection @script:prepare).Error|Should -Match 'target selection differs'
      $script:prepare.ExpectedBuild='26300';$script:fontSelection[0].Sha256='E'*64
      (Invoke-RideFontVmPhase @script:selection @script:prepare).Error|Should -Match 'font selection differs'
      $script:fontSelection[0].Sha256='F'*64
      Mock Get-RideFontVmCredential {[pscredential]::new('synthetic-user',(ConvertTo-SecureString 'Synthetic-test-only' -AsPlainText -Force))}
      Mock Get-RideFontVmPayload {throw 'Retained snapshot bytes changed.'}
      (Invoke-RideFontVmPhase @script:selection @script:prepare).Error|Should -Match 'snapshot bytes changed'
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
      Should -Invoke New-RideFontVmSnapshot -Times 1 -Exactly
    }
    It 'cannot adopt a different hold while retrying preparation' {
      Mock Get-RideFontVmCredential {throw 'Synthetic credential lookup failure.'}
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Open-RideRetainedGuestPhase {throw 'Retained hold request identity differs.'}
      {Invoke-RideFontVmPhase @script:selection @script:prepare}|Should -Throw '*identity differs*'
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
    }
    It 'rejects a mismatched guest result instead of treating an exit as acceptance' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Invoke-RideFontVmRemote {[pscustomobject]@{SchemaVersion=1;RunId=('c'*32);Status='Passed';NativeAcceptancePassed=$false}}
      $report=Invoke-RideFontVmPhase @script:selection -Phase Lifecycle
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'correlation'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses reset when current evidence export fails' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Export-RideFontVmEvidence {throw 'Synthetic export failure.'}
      $report=Invoke-RideFontVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be EvidenceExport
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses an absent export after a claimed successful guest phase' {
      Mock Export-RideFontVmEvidence {[pscustomobject]@{Verified=$true;GuestStatus='Absent';FileCount=0}}
      $report=Invoke-RideFontVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'not exported'
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'retries explicit reset from Off only through the saved verified export path' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      $script:vmState='Off'
      $report=Invoke-RideFontVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be ResetAndOff;$report.RecoveryRequired|Should -BeFalse
      Should -Invoke Read-RideFontVmResetExport -Times 1 -Exactly
      Should -Invoke Wait-RideFontVmReady -Times 1 -Exactly
      Should -Invoke Get-RideFontVmCredential -Times 1 -Exactly
      Should -Invoke Export-RideFontVmEvidence -Times 1 -Exactly
    }
    It 'retains the hold when checkpoint recovery fails or its final state is not Off' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Reset-RideAutomationVm {throw 'Synthetic reset failure.'}
      $report=Invoke-RideFontVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be ExplicitCheckpointReset
      @((Get-ChildItem -LiteralPath $script:store -Filter 'reset-intent.*.json')).Count|Should -Be 1
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
      Mock Reset-RideAutomationVm {}
      $retry=Invoke-RideFontVmPhase @script:selection -Phase Reset
      $retry.Status|Should -Be Failed;$retry.Error|Should -Match 'did not leave the pinned guest Off'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'keeps the recovery receipt when hold release fails after the reset' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Remove-RideRetainedGuestHold {throw 'Synthetic release failure.'}
      $report=Invoke-RideFontVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be HoldRelease;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'recovery.*.json')).Count|Should -Be 1
      $script:vmState|Should -Be Off
    }
    It 'disposes the phase lock when journaling itself fails' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Write-RideFontVmRecord {throw 'Synthetic journal failure.'}
      {Invoke-RideFontVmPhase @script:selection -Phase Collect}|Should -Throw '*journal failure*'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'refuses a saved session from another lease before guest calls' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      $path=Join-Path $script:store 'session.json';$saved=Read-RideFontVmRecord $path;$saved.LeaseId='c'*32
      [IO.File]::WriteAllText($path,($saved|ConvertTo-Json -Depth 10))
      $report=Invoke-RideFontVmPhase @script:selection -Phase Lifecycle
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'session identity'
      Should -Invoke Invoke-RideFontVmRemote -Times 1 -Exactly
    }
    It 'preserves NotRun without inventing lifecycle acceptance or cleanup' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Invoke-RideFontVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='MachineFontAcceptance';RunId=$script:run;ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';Status='NotRun';Reason='SelectedFontsMustBeInitiallyAbsent';NativeAcceptancePassed=$false;CrossSessionAcceptancePassed=$false;RestartAcceptancePassed=$false;RecoveryRequired=$false;Checks=@();LifecycleRuns=@();StateRunIds=@()}}
      $report=Invoke-RideFontVmPhase @script:selection -Phase Lifecycle
      $report.Status|Should -Be NotRun;$report.CurrentSessionAcceptancePassed|Should -BeFalse
      $report.RecoveryRequired|Should -BeTrue;$report.EvidenceExport.Verified|Should -BeTrue
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'does not certify a successful lifecycle when its evidence export fails' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      Mock Export-RideFontVmEvidence {throw 'Synthetic evidence failure.'}
      $report=Invoke-RideFontVmPhase @script:selection -Phase Lifecycle
      $report.Status|Should -Be Failed;$report.CurrentSessionAcceptancePassed|Should -BeFalse
      $report.GuestResult.Status|Should -Be Passed;$report.RecoveryRequired|Should -BeTrue
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'rejects wrong font selection and incomplete saved recovery runs' {
      $null=Invoke-RideFontVmPhase @script:selection @script:prepare
      $descriptor=Read-RideFontVmRecord (Join-Path $script:store 'session.json')
      $guest=Invoke-RideFontVmRemote $null $null Lifecycle $descriptor $null
      $guest.Selection[0].Sha256='0'*64
      $descriptor=Read-RideFontVmRecord (Join-Path $script:store 'session.json')
      {Assert-RideFontVmGuestResult $guest Lifecycle $descriptor}|Should -Throw '*selection differs*'
      $guest.Selection=$descriptor.Selection;$guest.LifecycleRuns[1].Restored=$false
      {Assert-RideFontVmGuestResult $guest Lifecycle $descriptor}|Should -Throw '*recovery runs*'
      $guest.LifecycleRuns[1].Restored=$true;$guest.StateRunIds=@('1'*32)
      {Assert-RideFontVmGuestResult $guest Lifecycle $descriptor}|Should -Throw '*recovery runs*'
      $guest.StateRunIds=@(('1'*32),('2'*32));$guest.RestartAcceptancePassed=$true
      {Assert-RideFontVmGuestResult $guest Lifecycle $descriptor}|Should -Throw '*acceptance boundary*'
    }
  }
}
Describe 'Retained snapshot and export byte boundaries' {
  InModuleScope RIDE.FontVm {
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      Mock New-RideFontVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideFontVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideFontVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      $script:descriptor=[pscustomobject]@{RunId=('a'*32);LeaseId=('b'*32);ConfigurationSha256=('C'*64);VMName='RIDE-Test';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      $script:bytes=[Text.Encoding]::UTF8.GetBytes('synthetic private evidence')
      $script:entry=[pscustomobject]@{Path='evidence/owned/state.json';Bytes=$script:bytes.Length;Sha256=(Get-RideFontVmHash $script:bytes);Content=[Convert]::ToBase64String($script:bytes)}
      Mock Invoke-RideFontVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='FontVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';Files=@($script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
    }
    It 'stages exactly required sources and selected bytes, then detects snapshot drift' {
      $repo=Join-Path $script:root 'repo';$null=New-Item -ItemType Directory -Path $repo
      foreach($relative in $script:FontVmSources){
        $path=if($relative -ceq 'inputs/fonts.psd1'){Join-Path $repo 'tests/fixtures/machine-fonts.acceptance.psd1'}else{Join-Path $repo $relative}
        $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force;[IO.File]::WriteAllText($path,'inert source fixture')
      }
      $source=Join-Path $repo 'inert.bin';[IO.File]::WriteAllBytes($source,$script:bytes)
      $files=@(Get-RideFontVmExpectedPaths|Where-Object {$_ -cnotin $script:FontVmSources}|ForEach-Object {[pscustomobject]@{Path=$_;Source=$source;Bytes=$script:bytes.Length;Sha256=(Get-RideFontVmHash $script:bytes)}})
      $snapshot=Join-Path $script:root 'snapshot';$manifest=@(New-RideFontVmSnapshot $repo $snapshot ([pscustomobject]@{Files=$files}))
      $manifest.Count|Should -Be 20
      @(Get-RideFontVmPayload $snapshot $manifest).Count|Should -Be 20
      {Get-RideFontVmPayload $snapshot (@($manifest)+@([pscustomobject]@{Path='legacy/unselected.ps1'}))}|Should -Throw '*selection differs*'
      [IO.File]::AppendAllText((Join-Path $snapshot $manifest[0].Path),'changed')
      {Get-RideFontVmPayload $snapshot $manifest}|Should -Throw '*size changed*'
    }
    It 'exports verified bytes and retains a private correlated manifest' {
      $export=Export-RideFontVmEvidence $null $null $script:descriptor $script:root
      $export.Verified|Should -BeTrue;$export.FileCount|Should -Be 1
      $receipt=Read-RideFontVmRecord (Join-Path $export.Path 'export-receipt.json')
      $receipt.RunId|Should -BeExactly $script:descriptor.RunId
      (Get-FileHash -LiteralPath (Join-Path $export.Path $script:entry.Path)).Hash|Should -BeExactly $script:entry.Sha256
    }
    It 'returns only the fixed observation file after its bytes are verified' {
      $script:bytes=[Text.Encoding]::UTF8.GetBytes('{"FilesMatchInitial":true,"NativeNamesMatchInitial":false,"CurrentSelectedNativeNames":["Synthetic Regular"],"ObservedAtUtc":"2026-11-03T00:00:00.0000000Z","ProcessIdentity":{"ProcessId":456,"ProcessStartUtc":"2026-11-02T23:59:00.0000000Z","SessionId":0}}')
      $script:entry=[pscustomobject]@{Path='collection-font-observation.json';Bytes=$script:bytes.Length;Sha256=(Get-RideFontVmHash $script:bytes);Content=[Convert]::ToBase64String($script:bytes)}
      $export=Export-RideFontVmEvidence $null $null $script:descriptor $script:root
      $export.FontObservation.FilesMatchInitial|Should -BeTrue
      $export.FontObservation.NativeNamesMatchInitial|Should -BeFalse
      $export.FontObservation.CurrentSelectedNativeNames|Should -BeExactly 'Synthetic Regular'
      $export.FontObservation.ProcessIdentity.ProcessId|Should -Be 456
      $export.FontObservation.ProcessIdentity.SessionId|Should -Be 0
      $receipt=Read-RideFontVmRecord (Join-Path $export.Path 'export-receipt.json')
      $receipt.Files.Path|Should -BeExactly 'collection-font-observation.json'
      $receipt.Files.Sha256|Should -BeExactly $script:entry.Sha256
    }
    It 'rejects traversal, duplicate paths and mismatched payload bytes before certifying export' {
      $script:entry.Path='../escape.json'
      {Export-RideFontVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*Unsafe*'
      $script:entry.Path='evidence.json';$script:entry.Sha256='0'*64
      {Export-RideFontVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*bytes differ*'
      $script:entry.Sha256=Get-RideFontVmHash $script:bytes
      Mock Invoke-RideFontVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='FontVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';Files=@($script:entry,$script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideFontVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*duplicate*'
    }
    It 'reverifies a private pre-reset export and refuses changed saved bytes or a missing intent' {
      {Read-RideFontVmResetExport $script:root $script:descriptor}|Should -Throw '*pre-reset export intent*'
      $export=Export-RideFontVmEvidence $null $null $script:descriptor $script:root
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='FontVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=$export.Path}
      Write-RideFontVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      (Read-RideFontVmResetExport $script:root $script:descriptor).Verified|Should -BeTrue
      [IO.File]::AppendAllText((Join-Path $export.Path $script:entry.Path),'changed')
      {Read-RideFontVmResetExport $script:root $script:descriptor}|Should -Throw '*evidence changed*'
    }
    It 'rejects incomplete or invented lifecycle reports' {
      $guest=[pscustomobject]@{SchemaVersion=1;Kind='MachineFontAcceptance';RunId=$script:descriptor.RunId;Status='Passed';Stage='Complete';ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';NativeAcceptancePassed=$true;CrossSessionAcceptancePassed=$false;RestartAcceptancePassed=$false;RecoveryRequired=$false;Checks=@('InitialStateRestored')}
      {Assert-RideFontVmGuestResult $guest Lifecycle $script:descriptor}|Should -Throw '*every required*'
      $guest.CrossSessionAcceptancePassed=$true
      {Assert-RideFontVmGuestResult $guest Lifecycle $script:descriptor}|Should -Throw '*acceptance boundary*'
    }
    It 'refuses a collection from another lease before creating an export directory' {
      Mock Invoke-RideFontVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='FontVmCollection';RunId=$script:descriptor.RunId;LeaseId=('f'*32);Status='Collected';Files=@();Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideFontVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*mismatched*'
      Should -Invoke New-RideFontVmDirectory -Times 0 -Exactly
    }
    It 'rejects a reset receipt that points outside its owned export directory' {
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='FontVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=(Join-Path $script:root ('elsewhere/export.'+('c'*32)))}
      Write-RideFontVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      {Read-RideFontVmResetExport $script:root $script:descriptor}|Should -Throw '*escaped*'
    }
  }
}
Describe 'Bounded fixed PowerShell Direct job transport' {
  InModuleScope RIDE.FontVm {
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
      (Invoke-RideFontVmRemote $script:configuration $null Collect $null $null).Status|Should -Be synthetic-result
      Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {$VMId -eq [guid]$script:configuration.VMId -and $ScriptBlock -eq $script:FontVmRemote -and $AsJob}
      Should -Invoke Wait-Job -Times 1 -Exactly -ParameterFilter {$Timeout -eq 180}
      Should -Invoke Remove-Job -Times 1 -Exactly
    }
    It 'stops and removes a timed-out job without receiving a success result' {
      Mock Wait-Job {$null}
      {Invoke-RideFontVmRemote $script:configuration $null Lifecycle $null $null 15}|Should -Throw '*timed out*'
      Should -Invoke Stop-Job -Times 1 -Exactly
      Should -Invoke Remove-Job -Times 1 -Exactly
      Should -Invoke Receive-Job -Times 0 -Exactly
    }
    It 'rejects a failed job or multiple result objects and still disposes the job' {
      $script:job.State='Failed'
      {Invoke-RideFontVmRemote $script:configuration $null Lifecycle $null $null}|Should -Throw '*one completed result*'
      $script:job.State='Completed'
      Mock Receive-Job {@('unexpected','extra output')}
      {Invoke-RideFontVmRemote $script:configuration $null Lifecycle $null $null}|Should -Throw '*one completed result*'
      Should -Invoke Remove-Job -Times 2 -Exactly
    }
  }
}

Describe 'Pinned font input and fixed guest selection' {
  InModuleScope RIDE.FontVm {
    BeforeEach {
      $script:inputRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:inputRoot
      $script:inputBytes=[Text.Encoding]::UTF8.GetBytes('Inert test data; never load as a font.')
      $script:inputHash=Get-RideFontVmHash $script:inputBytes
      $script:pin=@{SchemaVersion=1;Fonts=@(1..14|ForEach-Object {@{Path="Synthetic-$_.ttf";Sha256=$script:inputHash}});License=@{Path='OFL.txt';Sha256=$script:inputHash}}
      foreach($entry in @($script:pin.Fonts)+@($script:pin.License)){[IO.File]::WriteAllBytes((Join-Path $script:inputRoot $entry.Path),$script:inputBytes)}
      Mock Import-PowerShellDataFile {$script:pin}
      Mock Get-RideTrueTypeMetadata {param($Path) [pscustomobject]@{FileName=[IO.Path]::GetFileName($Path);RegistryName='Inert';FullName='Inert';Sha256=$script:inputHash;FontLoadPerformed=$false;InstallationPerformed=$false}}
    }
    It 'selects all fourteen pinned fonts and the original notice without loading any font' {
      $inputs=Get-RideFontVmInputs $script:inputRoot
      $inputs.Files.Count|Should -Be 15;$inputs.Selection.Count|Should -Be 14
      $inputs.Files[-1].Path|Should -BeExactly inputs/OFL.txt
      Should -Invoke Get-RideTrueTypeMetadata -Times 14 -Exactly
    }
    It 'refuses altered font or license bytes before accepting the batch' {
      [IO.File]::AppendAllText((Join-Path $script:inputRoot 'Synthetic-1.ttf'),'changed')
      {Get-RideFontVmInputs $script:inputRoot}|Should -Throw '*pin differs*'
      [IO.File]::WriteAllBytes((Join-Path $script:inputRoot 'Synthetic-1.ttf'),$script:inputBytes)
      [IO.File]::AppendAllText((Join-Path $script:inputRoot 'OFL.txt'),'changed')
      {Get-RideFontVmInputs $script:inputRoot}|Should -Throw '*pin differs*'
    }
    It 'refuses unsafe fixture names and missing members' {
      $script:pin.Fonts[0].Path='../elsewhere.ttf'
      {Get-RideFontVmInputs $script:inputRoot}|Should -Throw '*input name*'
      $script:pin.Fonts=@($script:pin.Fonts|Select-Object -Skip 1)
      {Get-RideFontVmInputs $script:inputRoot}|Should -Throw '*batch differs*'
    }
  }
}
Describe 'Versioned guest source allowlist' {
  It 'keeps the remote allowlist aligned with the versioned font pin' {
    $paths=& (Get-Module RIDE.FontVm) {Get-RideFontVmExpectedPaths}
    $remote=& (Get-Module RIDE.FontVm) {$script:FontVmRemote}
    $assignment=$remote.Ast.Find({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq '$expectedSources'},$true)
    $literals=@($assignment.Right.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst]},$true)|ForEach-Object Value)
    ($literals -join ';')|Should -BeExactly ($paths -join ';')
    $paths.Count|Should -Be 20
  }
}
