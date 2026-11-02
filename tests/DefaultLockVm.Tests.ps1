<#
.SYNOPSIS
  Exercise retained default-image VM dispatch without touching a real guest.
.DESCRIPTION
  Mocks host identity, Hyper-V, credentials and PowerShell Direct. Real TestDrive
  snapshots/exports test byte identity and private user-scope journal files.
.EXAMPLE
  Invoke-Pester ./tests/DefaultLockVm.Tests.ps1
.NOTES
  Native Windows PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.DefaultLockVm.psm1') -Force}
Describe 'Retained default-image VM phase orchestration' {
  InModuleScope RIDE.DefaultLockVm {
    BeforeAll {
      function Restore-VMSnapshot { [CmdletBinding()] param($VMSnapshot,[switch]$Confirm) }
      function Start-VM { [CmdletBinding()] param($VM) }
    }
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      $script:run='a'*32;$script:lease='b'*32;$script:vmState='Off';$script:events=[Collections.Generic.List[string]]::new()
      $script:context=[pscustomobject]@{Root=$script:root;ConfigurationSha256=('C'*64);Configuration=[pscustomobject]@{VMName='RIDE-Test';VMId='11111111-1111-1111-1111-111111111111';LocalRepositoryPath=[IO.Path]::GetFullPath((Join-Path (Split-Path (Get-Module RIDE.DefaultLockVm).Path -Parent) '../..'))}}
      $script:hold=[pscustomobject]@{RunId=$script:run;LeaseId=$script:lease;VMId=$script:context.Configuration.VMId;VMName='RIDE-Test';CheckpointId='22222222-2222-2222-2222-222222222222';ConfigurationSha256=$script:context.ConfigurationSha256}
      $script:store=Join-Path $script:root ('retained.'+$script:lease)
      $script:selection=@{ConfigurationPath=(Join-Path $script:root 'configuration.json');RunId=$script:run;Confirm=$false}
      $script:prepare=@{Phase='Prepare';SourcePath='synthetic.png';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      Mock Get-RideDefaultLockVmContext {$script:context}
      Mock Get-RideDefaultLockVmSource {[pscustomobject]@{Path='synthetic.png';Sha256=('F'*64);Bytes=100}}
      Mock New-RideRetainedGuestHold {$script:events.Add('Reserve');$script:hold}
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=$script:context;Hold=$script:hold;Lock=$script:lastLock;Target=[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState};Snapshot='synthetic-checkpoint'}}}
      Mock New-RideDefaultLockVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideDefaultLockVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideDefaultLockVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      Mock New-RideDefaultLockVmSnapshot {@([pscustomobject]@{Path='synthetic-source';Sha256=('A'*64);Bytes=1})}
      Mock Get-RideDefaultLockVmPayload {@([pscustomobject]@{Path='synthetic-source';Content='QQ=='})}
      Mock Get-RideDefaultLockVmCredential {[pscredential]::new('synthetic-user',(ConvertTo-SecureString 'Synthetic-test-only' -AsPlainText -Force))}
      Mock Restore-VMSnapshot {$script:events.Add('InitialCheckpoint')}
      Mock Start-VM {$script:events.Add('Start');$script:vmState='Running'}
      Mock Wait-RideDefaultLockVmReady {[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';Revision=9711}}
      Mock Invoke-RideDefaultLockVmRemote {
        param($Action,$Descriptor)
        $script:events.Add($Action)
        if($Action -eq 'Prepare'){return [pscustomobject]@{SchemaVersion=1;Kind='DefaultLockVmPreparation';RunId=$Descriptor.RunId;LeaseId=$Descriptor.LeaseId;Status='Prepared';NativeAcceptancePassed=$false}}
        [pscustomobject]@{SchemaVersion=1;Kind='DefaultLockScreenAcceptance';Phase=$Action;RunId=$Descriptor.RunId;Status=if($Action -eq 'Apply'){'AwaitingVisualVerification'}else{'LifecyclePassedVisualPending'};NativeAcceptancePassed=$false;NativeVisualAcceptancePassed=$false;NativeLifecycleAcceptancePassed=($Action -eq 'Restore');Checks=if($Action -eq 'Apply'){@('PreviewNoChanges','AppliedPolicyImageAndPrivateState','RepeatNoChanges')}else{@('RestorePreviewNoChanges','CapturedStateRestored','RepeatedRestoreNoChanges')}}
      }
      Mock Export-RideDefaultLockVmEvidence {$script:events.Add('Export');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected'}}
      Mock Read-RideDefaultLockVmResetExport {$script:events.Add('VerifySavedExport');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected'}}
      Mock Reset-RideAutomationVm {$script:events.Add('Reset');$script:vmState='Off'}
      Mock Import-RideAutomationLab {[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState}}}
      Mock Remove-RideRetainedGuestHold {$script:events.Add('Release');[pscustomobject]@{Status='Released'}}
    }
    It 'prepares, retains apply and restore, collects, then explicitly exports before reset and release' {
      $reports=@(Invoke-RideDefaultLockVmPhase @script:selection @script:prepare)
      foreach($phase in @('Apply','Restore','Collect','Reset')){$reports+=Invoke-RideDefaultLockVmPhase @script:selection -Phase $phase}
      ($reports.Status -join ';')|Should -BeExactly 'Prepared;AwaitingVisualVerification;LifecyclePassedVisualPending;Collected;ResetAndOff'
      @($reports|Where-Object NativeAcceptancePassed).Count|Should -Be 0
      $reports[-1].RecoveryRequired|Should -BeFalse
      ($script:events -join ';')|Should -BeExactly 'Reserve;InitialCheckpoint;Start;Prepare;Export;Apply;Export;Restore;Export;Export;Export;Reset;Release'
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 5
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 1 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 1 -Exactly
    }
    It 'previews all phases without holds, snapshots, VM calls or records' {
      (Invoke-RideDefaultLockVmPhase @script:selection @script:prepare -WhatIf).Status|Should -Be Preview
      foreach($phase in @('Apply','Restore','Collect','Reset')){(Invoke-RideDefaultLockVmPhase @script:selection -Phase $phase -WhatIf).Status|Should -Be Preview}
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      Should -Invoke Open-RideRetainedGuestPhase -Times 0 -Exactly
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
      Should -Invoke Write-RideDefaultLockVmRecord -Times 0 -Exactly
    }
    It 'rejects irrelevant inputs, old builds and a different checkout before reservation' {
      {Invoke-RideDefaultLockVmPhase @script:selection -Phase Restore -SourcePath 'unused.png'}|Should -Throw '*only to Prepare*'
      $script:prepare.ExpectedBuild='19045'
      {Invoke-RideDefaultLockVmPhase @script:selection @script:prepare}|Should -Throw '*Windows 11*'
      $script:prepare.ExpectedBuild='26300';$script:context.Configuration.LocalRepositoryPath=$script:root
      {Invoke-RideDefaultLockVmPhase @script:selection @script:prepare}|Should -Throw '*registered checkout*'
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'uses declared canonical phase and edition values while requiring lowercase request IDs' {
      $script:selection.RunId='A'*32
      {Invoke-RideDefaultLockVmPhase @script:selection @script:prepare}|Should -Throw
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      $script:selection.RunId=$script:run;$script:prepare.Phase='prepare';$script:prepare.ExpectedEditionId='enterpriseeval'
      (Invoke-RideDefaultLockVmPhase @script:selection @script:prepare).Status|Should -Be Prepared
      (Read-RideDefaultLockVmRecord (Join-Path $script:store 'session.json')).ExpectedEditionId|Should -BeExactly EnterpriseEval
      (Invoke-RideDefaultLockVmPhase @script:selection -Phase 'apply').Status|Should -Be AwaitingVisualVerification
    }
    It 'refuses a changed controller digest under phase ownership' {
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=[pscustomobject]@{ConfigurationSha256=('D'*64)};Hold=$script:hold;Lock=$script:lastLock}}
      $report=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'configuration changed'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
    }
    It 'retains a preparation failure and never performs automatic reset or release' {
      Mock New-RideDefaultLockVmSnapshot {throw 'Synthetic snapshot failure.'}
      $report=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 1
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'exports partial guest evidence after apply failure and leaves the guest running' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      Mock Invoke-RideDefaultLockVmRemote {throw 'Synthetic apply failure.'}
      $report=Invoke-RideDefaultLockVmPhase @script:selection -Phase Apply
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Apply;$report.EvidenceExport.Verified|Should -BeTrue
      $script:vmState|Should -Be Running
      Should -Invoke Export-RideDefaultLockVmEvidence -Times 2 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'rejects a mismatched guest result instead of treating an exit as acceptance' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      Mock Invoke-RideDefaultLockVmRemote {[pscustomobject]@{SchemaVersion=1;RunId=('c'*32);Status='AwaitingVisualVerification';NativeAcceptancePassed=$false}}
      $report=Invoke-RideDefaultLockVmPhase @script:selection -Phase Apply
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'correlation'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses reset when current evidence export fails' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      Mock Export-RideDefaultLockVmEvidence {throw 'Synthetic export failure.'}
      $report=Invoke-RideDefaultLockVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be EvidenceExport
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses an absent export after a claimed successful guest phase' {
      Mock Export-RideDefaultLockVmEvidence {[pscustomobject]@{Verified=$true;GuestStatus='Absent';FileCount=0}}
      $report=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'not exported'
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'retries explicit reset from Off only through the saved verified export path' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      $script:vmState='Off'
      $report=Invoke-RideDefaultLockVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be ResetAndOff;$report.RecoveryRequired|Should -BeFalse
      Should -Invoke Read-RideDefaultLockVmResetExport -Times 1 -Exactly
      Should -Invoke Wait-RideDefaultLockVmReady -Times 1 -Exactly
      Should -Invoke Get-RideDefaultLockVmCredential -Times 1 -Exactly
      Should -Invoke Export-RideDefaultLockVmEvidence -Times 1 -Exactly
    }
    It 'retains the hold when checkpoint recovery fails or its final state is not Off' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      Mock Reset-RideAutomationVm {throw 'Synthetic reset failure.'}
      $report=Invoke-RideDefaultLockVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be ExplicitCheckpointReset
      @((Get-ChildItem -LiteralPath $script:store -Filter 'reset-intent.*.json')).Count|Should -Be 1
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
      Mock Reset-RideAutomationVm {}
      $retry=Invoke-RideDefaultLockVmPhase @script:selection -Phase Reset
      $retry.Status|Should -Be Failed;$retry.Error|Should -Match 'did not leave the pinned guest Off'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'keeps the recovery receipt when hold release fails after the reset' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      Mock Remove-RideRetainedGuestHold {throw 'Synthetic release failure.'}
      $report=Invoke-RideDefaultLockVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be HoldRelease;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'recovery.*.json')).Count|Should -Be 1
      $script:vmState|Should -Be Off
    }
    It 'disposes the phase lock when journaling itself fails' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      Mock Write-RideDefaultLockVmRecord {throw 'Synthetic journal failure.'}
      {Invoke-RideDefaultLockVmPhase @script:selection -Phase Collect}|Should -Throw '*journal failure*'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'refuses a saved session from another lease before guest calls' {
      $null=Invoke-RideDefaultLockVmPhase @script:selection @script:prepare
      $path=Join-Path $script:store 'session.json';$saved=Read-RideDefaultLockVmRecord $path;$saved.LeaseId='c'*32
      [IO.File]::WriteAllText($path,($saved|ConvertTo-Json -Depth 10))
      $report=Invoke-RideDefaultLockVmPhase @script:selection -Phase Apply
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'session identity'
      Should -Invoke Invoke-RideDefaultLockVmRemote -Times 1 -Exactly
    }
  }
}
Describe 'Retained snapshot and export byte boundaries' {
  InModuleScope RIDE.DefaultLockVm {
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      Mock New-RideDefaultLockVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideDefaultLockVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideDefaultLockVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      $script:descriptor=[pscustomobject]@{RunId=('a'*32);LeaseId=('b'*32);ConfigurationSha256=('C'*64);VMName='RIDE-Test';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      $script:bytes=[Text.Encoding]::UTF8.GetBytes('synthetic private evidence')
      $script:entry=[pscustomobject]@{Path='evidence/owned/state.json';Bytes=$script:bytes.Length;Sha256=(Get-RideDefaultLockVmHash $script:bytes);Content=[Convert]::ToBase64String($script:bytes)}
      Mock Invoke-RideDefaultLockVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';Files=@($script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
    }
    It 'stages exactly the required sources and selected bytes, then detects snapshot drift' {
      $repo=Join-Path $script:root 'repo';$null=New-Item -ItemType Directory -Path $repo
      foreach($relative in $script:DefaultLockVmSources){$path=Join-Path $repo $relative;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force;[IO.File]::WriteAllText($path,'inert source fixture')}
      $imagePath=Join-Path $repo 'image.png';[IO.File]::WriteAllBytes($imagePath,$script:bytes)
      $image=[pscustomobject]@{Path=$imagePath;Bytes=$script:bytes.Length;Sha256=(Get-RideDefaultLockVmHash $script:bytes)}
      $snapshot=Join-Path $script:root 'snapshot';$manifest=@(New-RideDefaultLockVmSnapshot $repo $snapshot $image)
      $manifest.Count|Should -Be 6
      @(Get-RideDefaultLockVmPayload $snapshot $manifest).Count|Should -Be 6
      {Get-RideDefaultLockVmPayload $snapshot (@($manifest)+@([pscustomobject]@{Path='legacy/unselected.ps1'}))}|Should -Throw '*selection differs*'
      [IO.File]::AppendAllText((Join-Path $snapshot $manifest[0].Path),'changed')
      {Get-RideDefaultLockVmPayload $snapshot $manifest}|Should -Throw '*size changed*'
    }
    It 'exports verified bytes and retains a private correlated manifest' {
      $export=Export-RideDefaultLockVmEvidence $null $null $script:descriptor $script:root
      $export.Verified|Should -BeTrue;$export.FileCount|Should -Be 1
      $receipt=Read-RideDefaultLockVmRecord (Join-Path $export.Path 'export-receipt.json')
      $receipt.RunId|Should -BeExactly $script:descriptor.RunId
      (Get-FileHash -LiteralPath (Join-Path $export.Path $script:entry.Path)).Hash|Should -BeExactly $script:entry.Sha256
    }
    It 'rejects traversal, duplicate paths and mismatched payload bytes before certifying export' {
      $script:entry.Path='../escape.json'
      {Export-RideDefaultLockVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*Unsafe*'
      $script:entry.Path='evidence.json';$script:entry.Sha256='0'*64
      {Export-RideDefaultLockVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*bytes differ*'
      $script:entry.Sha256=Get-RideDefaultLockVmHash $script:bytes
      Mock Invoke-RideDefaultLockVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';Files=@($script:entry,$script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideDefaultLockVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*duplicate*'
    }
    It 'reverifies a private pre-reset export and refuses changed saved bytes or a missing intent' {
      {Read-RideDefaultLockVmResetExport $script:root $script:descriptor}|Should -Throw '*pre-reset export intent*'
      $export=Export-RideDefaultLockVmEvidence $null $null $script:descriptor $script:root
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=$export.Path}
      Write-RideDefaultLockVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      (Read-RideDefaultLockVmResetExport $script:root $script:descriptor).Verified|Should -BeTrue
      [IO.File]::AppendAllText((Join-Path $export.Path $script:entry.Path),'changed')
      {Read-RideDefaultLockVmResetExport $script:root $script:descriptor}|Should -Throw '*evidence changed*'
    }
    It 'rejects incomplete or invented native lifecycle pass reports' {
      $guest=[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockScreenAcceptance';RunId=$script:descriptor.RunId;Phase='Restore';Status='LifecyclePassedVisualPending';NativeAcceptancePassed=$false;NativeVisualAcceptancePassed=$false;NativeLifecycleAcceptancePassed=$true;Checks=@('CapturedStateRestored')}
      {Assert-RideDefaultLockVmGuestResult $guest Restore $script:descriptor}|Should -Throw '*every required*'
      $guest.NativeAcceptancePassed=$true
      {Assert-RideDefaultLockVmGuestResult $guest Restore $script:descriptor}|Should -Throw '*acceptance boundary*'
    }
    It 'refuses a collection from another lease before creating an export directory' {
      Mock Invoke-RideDefaultLockVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockVmCollection';RunId=$script:descriptor.RunId;LeaseId=('f'*32);Status='Collected';Files=@();Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideDefaultLockVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*mismatched*'
      Should -Invoke New-RideDefaultLockVmDirectory -Times 0 -Exactly
    }
    It 'rejects a reset receipt that points outside its owned export directory' {
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='DefaultLockVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=(Join-Path $script:root ('elsewhere/export.'+('c'*32)))}
      Write-RideDefaultLockVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      {Read-RideDefaultLockVmResetExport $script:root $script:descriptor}|Should -Throw '*escaped*'
    }
  }
}
Describe 'Bounded fixed PowerShell Direct job transport' {
  InModuleScope RIDE.DefaultLockVm {
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
      (Invoke-RideDefaultLockVmRemote $script:configuration $null Collect $null $null).Status|Should -Be synthetic-result
      Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {$VMId -eq [guid]$script:configuration.VMId -and $ScriptBlock -eq $script:DefaultLockVmRemote -and $AsJob}
      Should -Invoke Wait-Job -Times 1 -Exactly -ParameterFilter {$Timeout -eq 180}
      Should -Invoke Remove-Job -Times 1 -Exactly
    }
    It 'stops and removes a timed-out job without receiving a success result' {
      Mock Wait-Job {$null}
      {Invoke-RideDefaultLockVmRemote $script:configuration $null Apply $null $null 15}|Should -Throw '*timed out*'
      Should -Invoke Stop-Job -Times 1 -Exactly
      Should -Invoke Remove-Job -Times 1 -Exactly
      Should -Invoke Receive-Job -Times 0 -Exactly
    }
    It 'rejects a failed job or multiple result objects and still disposes the job' {
      $script:job.State='Failed'
      {Invoke-RideDefaultLockVmRemote $script:configuration $null Apply $null $null}|Should -Throw '*one completed result*'
      $script:job.State='Completed'
      Mock Receive-Job {@('unexpected','extra output')}
      {Invoke-RideDefaultLockVmRemote $script:configuration $null Apply $null $null}|Should -Throw '*one completed result*'
      Should -Invoke Remove-Job -Times 2 -Exactly
    }
  }
}
