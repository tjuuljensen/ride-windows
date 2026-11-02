<#
.SYNOPSIS
  Exercise retained Sysmon VM dispatch without touching a real guest.
.DESCRIPTION
  Mocks host identity, Hyper-V, credentials and PowerShell Direct. Real TestDrive
  snapshots/exports test byte identity and private user-scope journal files.
.EXAMPLE
  Invoke-Pester ./tests/SysmonVm.Tests.ps1
.NOTES
  Native Windows PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.SysmonVm.psm1') -Force}
Describe 'Retained Sysmon VM phase orchestration' {
  InModuleScope RIDE.SysmonVm {
    BeforeAll {
      function Restore-VMSnapshot { [CmdletBinding()] param($VMSnapshot,[switch]$Confirm) }
      function Start-VM { [CmdletBinding()] param($VM) }
    }
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      $script:run='a'*32;$script:lease='b'*32;$script:vmState='Off';$script:events=[Collections.Generic.List[string]]::new()
      $script:context=[pscustomobject]@{Root=$script:root;ConfigurationSha256=('C'*64);Configuration=[pscustomobject]@{VMName='RIDE-Test';VMId='11111111-1111-1111-1111-111111111111';LocalRepositoryPath=[IO.Path]::GetFullPath((Join-Path (Split-Path (Get-Module RIDE.SysmonVm).Path -Parent) '../..'))}}
      $script:hold=[pscustomobject]@{RunId=$script:run;LeaseId=$script:lease;VMId=$script:context.Configuration.VMId;VMName='RIDE-Test';CheckpointId='22222222-2222-2222-2222-222222222222';ConfigurationSha256=$script:context.ConfigurationSha256}
      $script:store=Join-Path $script:root ('retained.'+$script:lease)
      $script:selection=@{ConfigurationPath=(Join-Path $script:root 'configuration.json');RunId=$script:run;Confirm=$false}
      $script:prepare=@{Phase='Prepare';ExecutableDirectory='synthetic-exe';InputDirectory='synthetic-configs';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      Mock Get-RideSysmonVmContext {$script:context}
      Mock Get-RideSysmonVmInputs {[pscustomobject]@{ExecutableSha256=('F'*64);SysmonVersion='15.22';Files=@()}}
      Mock New-RideRetainedGuestHold {$script:events.Add('Reserve');$script:hold}
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=$script:context;Hold=$script:hold;Lock=$script:lastLock;Target=[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState};Snapshot='synthetic-checkpoint'}}}
      Mock New-RideSysmonVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideSysmonVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideSysmonVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      Mock New-RideSysmonVmSnapshot {@([pscustomobject]@{Path='synthetic-source';Sha256=('A'*64);Bytes=1})}
      Mock Get-RideSysmonVmPayload {@([pscustomobject]@{Path='synthetic-source';Content='QQ=='})}
      Mock Get-RideSysmonVmCredential {[pscredential]::new('synthetic-user',(ConvertTo-SecureString 'Synthetic-test-only' -AsPlainText -Force))}
      Mock Restore-VMSnapshot {$script:events.Add('InitialCheckpoint')}
      Mock Start-VM {$script:events.Add('Start');$script:vmState='Running'}
      Mock Wait-RideSysmonVmReady {[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';Revision=9711}}
      Mock Invoke-RideSysmonVmRemote {
        param($Action,$Descriptor)
        $script:events.Add($Action)
        $guest=[pscustomobject]@{SchemaVersion=1;Kind='SysmonAcceptanceFixture';RunId=$Descriptor.RunId;Status='Prepared';NativeAcceptancePassed=$false;ComputerName=$Descriptor.VMName;Build=$Descriptor.ExpectedBuild;EditionId=$Descriptor.ExpectedEditionId;SysmonVersion=$Descriptor.SysmonVersion;ExecutableSha256=$Descriptor.ExecutableSha256;ReleaseTag='configs-a45dedb13a43';Profiles=@()}
        if($Action -eq 'Prepare'){return $guest}
        $guest.Kind='SysmonConfigurationAcceptance';$guest.Status='Passed';$guest.NativeAcceptancePassed=$true
        $pin=Import-PowerShellDataFile -LiteralPath (Join-Path (Split-Path (Get-Module RIDE.SysmonVm).Path -Parent) '../fixtures/sysmon-configurations.acceptance.psd1')
        $guest.Profiles=@(foreach($item in $pin.Configurations){[pscustomobject]@{ArtifactId=$item.ArtifactId;Sha256=$item.Sha256;RunId=[guid]::NewGuid().ToString('N');Restored=$true;Checks=@('PreviewNoChanges','AppliedSourceEventAndServiceVerified','RepeatNoChanges','BaselineRestoredAndServiceVerified','RepeatedRestoreNoChanges')}})
        $guest
      }
      Mock Export-RideSysmonVmEvidence {$script:events.Add('Export');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected';BaselineLoaded=$true;ArchiveExportComplete=$true}}
      Mock Read-RideSysmonVmResetExport {$script:events.Add('VerifySavedExport');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store ('export.'+('d'*32)));FileCount=10;GuestStatus='Collected';BaselineLoaded=$true;ArchiveExportComplete=$true}}
      Mock Reset-RideAutomationVm {$script:events.Add('Reset');$script:vmState='Off'}
      Mock Import-RideAutomationLab {[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState}}}
      Mock Remove-RideRetainedGuestHold {$script:events.Add('Release');[pscustomobject]@{Status='Released'}}
    }
    It 'prepares, retains apply and restore, collects, then explicitly exports before reset and release' {
      $reports=@(Invoke-RideSysmonVmPhase @script:selection @script:prepare)
      foreach($phase in @('Configurations','Collect','Reset')){$reports+=Invoke-RideSysmonVmPhase @script:selection -Phase $phase}
      ($reports.Status -join ';')|Should -BeExactly 'Prepared;Passed;Collected;ResetAndOff'
      @($reports|Where-Object NativeAcceptancePassed).Count|Should -Be 1
      $reports[-1].RecoveryRequired|Should -BeFalse
      ($script:events -join ';')|Should -BeExactly 'Reserve;InitialCheckpoint;Start;Prepare;Export;Configurations;Export;Export;Export;Reset;Release'
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 4
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 1 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 1 -Exactly
    }
    It 'previews all phases without holds, snapshots, VM calls or records' {
      (Invoke-RideSysmonVmPhase @script:selection @script:prepare -WhatIf).Status|Should -Be Preview
      foreach($phase in @('Configurations','Collect','Reset')){(Invoke-RideSysmonVmPhase @script:selection -Phase $phase -WhatIf).Status|Should -Be Preview}
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      Should -Invoke Open-RideRetainedGuestPhase -Times 0 -Exactly
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
      Should -Invoke Write-RideSysmonVmRecord -Times 0 -Exactly
    }
    It 'rejects irrelevant inputs, old builds and a different checkout before reservation' {
      {Invoke-RideSysmonVmPhase @script:selection -Phase Configurations -ExecutableDirectory 'unused'}|Should -Throw '*only to Prepare*'
      $script:prepare.ExpectedBuild='19045'
      {Invoke-RideSysmonVmPhase @script:selection @script:prepare}|Should -Throw '*Windows 11*'
      $script:prepare.ExpectedBuild='26300';$script:context.Configuration.LocalRepositoryPath=$script:root
      {Invoke-RideSysmonVmPhase @script:selection @script:prepare}|Should -Throw '*registered checkout*'
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'uses declared canonical phase and edition values while requiring lowercase request IDs' {
      $script:selection.RunId='A'*32
      {Invoke-RideSysmonVmPhase @script:selection @script:prepare}|Should -Throw
      Should -Invoke New-RideRetainedGuestHold -Times 0 -Exactly
      $script:selection.RunId=$script:run;$script:prepare.Phase='prepare';$script:prepare.ExpectedEditionId='enterpriseeval'
      (Invoke-RideSysmonVmPhase @script:selection @script:prepare).Status|Should -Be Prepared
      (Read-RideSysmonVmRecord (Join-Path $script:store 'session.json')).ExpectedEditionId|Should -BeExactly EnterpriseEval
      (Invoke-RideSysmonVmPhase @script:selection -Phase 'configurations').Status|Should -Be Passed
    }
    It 'refuses a changed controller digest under phase ownership' {
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=[pscustomobject]@{ConfigurationSha256=('D'*64)};Hold=$script:hold;Lock=$script:lastLock}}
      $report=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'configuration changed'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Times 0 -Exactly
    }
    It 'retains a preparation failure and never performs automatic reset or release' {
      Mock New-RideSysmonVmSnapshot {throw 'Synthetic snapshot failure.'}
      $report=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'phase.*.json')).Count|Should -Be 1
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'exports partial guest evidence after apply failure and leaves the guest running' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Invoke-RideSysmonVmRemote {throw 'Synthetic apply failure.'}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Configurations
      $report.Status|Should -Be Failed;$report.Stage|Should -Be Configurations;$report.EvidenceExport.Verified|Should -BeTrue
      $script:vmState|Should -Be Running
      Should -Invoke Export-RideSysmonVmEvidence -Times 2 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'rejects a mismatched guest result instead of treating an exit as acceptance' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Invoke-RideSysmonVmRemote {[pscustomobject]@{SchemaVersion=1;RunId=('c'*32);Status='AwaitingVisualVerification';NativeAcceptancePassed=$false}}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Configurations
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'correlation'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses reset when current evidence export fails' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Export-RideSysmonVmEvidence {throw 'Synthetic export failure.'}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be EvidenceExport
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses an absent export after a claimed successful guest phase' {
      Mock Export-RideSysmonVmEvidence {[pscustomobject]@{Verified=$true;GuestStatus='Absent';FileCount=0}}
      $report=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'not exported'
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'retries explicit reset from Off only through the saved verified export path' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      $script:vmState='Off'
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be ResetAndOff;$report.RecoveryRequired|Should -BeFalse
      Should -Invoke Read-RideSysmonVmResetExport -Times 1 -Exactly
      Should -Invoke Wait-RideSysmonVmReady -Times 1 -Exactly
      Should -Invoke Get-RideSysmonVmCredential -Times 1 -Exactly
      Should -Invoke Export-RideSysmonVmEvidence -Times 1 -Exactly
    }
    It 'refuses explicit reset when the synthetic baseline is not loaded' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Export-RideSysmonVmEvidence {[pscustomobject]@{Verified=$true;Path='unused';FileCount=10;GuestStatus='Collected';BaselineLoaded=$false;ArchiveExportComplete=$true}}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'loaded synthetic baseline'
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'refuses explicit reset without complete archive export' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Export-RideSysmonVmEvidence {[pscustomobject]@{Verified=$true;Path='unused';FileCount=10;GuestStatus='Collected';BaselineLoaded=$true;ArchiveExportComplete=$false}}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'does not promote a guest pass when host evidence export fails' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Export-RideSysmonVmEvidence {throw 'Synthetic archive access denied.'}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Configurations
      $report.Status|Should -Be Failed;$report.NativeAcceptancePassed|Should -BeFalse
      $report.GuestResult.Status|Should -Be Passed
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'withholds acceptance when the exported live baseline no longer matches' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Export-RideSysmonVmEvidence {[pscustomobject]@{Verified=$true;Path='unused';FileCount=10;GuestStatus='Collected';BaselineLoaded=$false;ArchiveExportComplete=$true}}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Configurations
      $report.Status|Should -Be Failed;$report.NativeAcceptancePassed|Should -BeFalse
      $report.GuestResult.Status|Should -Be Passed
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'retains the hold when checkpoint recovery fails or its final state is not Off' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Reset-RideAutomationVm {throw 'Synthetic reset failure.'}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be ExplicitCheckpointReset
      @((Get-ChildItem -LiteralPath $script:store -Filter 'reset-intent.*.json')).Count|Should -Be 1
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
      Mock Reset-RideAutomationVm {}
      $retry=Invoke-RideSysmonVmPhase @script:selection -Phase Reset
      $retry.Status|Should -Be Failed;$retry.Error|Should -Match 'did not leave the pinned guest Off'
      Should -Invoke Remove-RideRetainedGuestHold -Times 0 -Exactly
    }
    It 'keeps the recovery receipt when hold release fails after the reset' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Remove-RideRetainedGuestHold {throw 'Synthetic release failure.'}
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Reset
      $report.Status|Should -Be Failed;$report.Stage|Should -Be HoldRelease;$report.RecoveryRequired|Should -BeTrue
      @((Get-ChildItem -LiteralPath $script:store -Filter 'recovery.*.json')).Count|Should -Be 1
      $script:vmState|Should -Be Off
    }
    It 'disposes the phase lock when journaling itself fails' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      Mock Write-RideSysmonVmRecord {throw 'Synthetic journal failure.'}
      {Invoke-RideSysmonVmPhase @script:selection -Phase Collect}|Should -Throw '*journal failure*'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }
    It 'refuses a saved session from another lease before guest calls' {
      $null=Invoke-RideSysmonVmPhase @script:selection @script:prepare
      $path=Join-Path $script:store 'session.json';$saved=Read-RideSysmonVmRecord $path;$saved.LeaseId='c'*32
      [IO.File]::WriteAllText($path,($saved|ConvertTo-Json -Depth 10))
      $report=Invoke-RideSysmonVmPhase @script:selection -Phase Configurations
      $report.Status|Should -Be Failed;$report.Error|Should -Match 'session identity'
      Should -Invoke Invoke-RideSysmonVmRemote -Times 1 -Exactly
    }
  }
}
Describe 'Retained snapshot and export byte boundaries' {
  InModuleScope RIDE.SysmonVm {
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      Mock New-RideSysmonVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideSysmonVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideSysmonVmRecord {
        param($Path)
        $bytes=& (Get-Module RIDE.PrivateFiles) {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      $script:descriptor=[pscustomobject]@{RunId=('a'*32);LeaseId=('b'*32);ConfigurationSha256=('C'*64);VMName='RIDE-Test';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval'}
      $script:bytes=[Text.Encoding]::UTF8.GetBytes('synthetic private evidence')
      $script:entry=[pscustomobject]@{Path='evidence/owned/state.json';Bytes=$script:bytes.Length;Sha256=(Get-RideSysmonVmHash $script:bytes);Content=[Convert]::ToBase64String($script:bytes)}
      Mock Invoke-RideSysmonVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='SysmonVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';BaselineLoaded=$true;ArchiveExportComplete=$true;Files=@($script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
    }
    It 'stages only selected source/input files and refuses drift or an unselected member' {
      $repo=Join-Path $script:root 'repo';$null=New-Item -ItemType Directory -Path $repo
      foreach($relative in $script:SysmonVmSources){$path=Join-Path $repo $relative;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force;[IO.File]::WriteAllText($path,'inert source fixture')}
      $inputs=[pscustomobject]@{Files=@(foreach($relative in Get-RideSysmonVmExpectedPaths|Where-Object {$_ -like 'inputs/*'}){
        $path=Join-Path $repo $relative;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force;[IO.File]::WriteAllBytes($path,$script:bytes)
        [pscustomobject]@{Path=$relative;Source=$path;Bytes=$script:bytes.Length;Sha256=(Get-RideSysmonVmHash $script:bytes)}
      })}
      $snapshot=Join-Path $script:root 'snapshot';$manifest=@(New-RideSysmonVmSnapshot $repo $snapshot $inputs)
      $manifest.Count|Should -Be 15
      @(Get-RideSysmonVmPayload $snapshot $manifest).Count|Should -Be 15
      {Get-RideSysmonVmPayload $snapshot (@($manifest)+@([pscustomobject]@{Path='legacy/unselected.ps1'}))}|Should -Throw '*selection differs*'
      [IO.File]::AppendAllText((Join-Path $snapshot $manifest[0].Path),'changed')
      {Get-RideSysmonVmPayload $snapshot $manifest}|Should -Throw '*size changed*'
    }
    It 'exports verified bytes and retains a private correlated manifest' {
      $export=Export-RideSysmonVmEvidence $null $null $script:descriptor $script:root
      $export.Verified|Should -BeTrue;$export.FileCount|Should -Be 1
      $receipt=Read-RideSysmonVmRecord (Join-Path $export.Path 'export-receipt.json')
      $receipt.RunId|Should -BeExactly $script:descriptor.RunId
      (Get-FileHash -LiteralPath (Join-Path $export.Path $script:entry.Path)).Hash|Should -BeExactly $script:entry.Sha256
    }
    It 'refuses a supplied input whose bytes changed after source preflight' {
      $repo=Join-Path $script:root 'repo';$null=New-Item -ItemType Directory -Path $repo
      Mock Get-RideSysmonVmExpectedPaths {@('inputs/changed.txt')}
      $saved=$script:SysmonVmSources
      try {
        $script:SysmonVmSources=@();$path=Join-Path $repo 'changed.txt';[IO.File]::WriteAllBytes($path,$script:bytes)
        $inputs=[pscustomobject]@{Files=@([pscustomobject]@{Path='inputs/changed.txt';Source=$path;Bytes=$script:bytes.Length;Sha256=('0'*64)})}
        {New-RideSysmonVmSnapshot $repo (Join-Path $script:root 'snapshot') $inputs}|Should -Throw '*changed during snapshot*'
      }finally{$script:SysmonVmSources=$saved}
    }
    It 'rejects traversal, duplicate paths and mismatched payload bytes before certifying export' {
      $script:entry.Path='../escape.json'
      {Export-RideSysmonVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*Unsafe*'
      $script:entry.Path='evidence.json';$script:entry.Sha256='0'*64
      {Export-RideSysmonVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*bytes differ*'
      $script:entry.Sha256=Get-RideSysmonVmHash $script:bytes
      Mock Invoke-RideSysmonVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='SysmonVmCollection';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;Status='Collected';BaselineLoaded=$true;ArchiveExportComplete=$true;Files=@($script:entry,$script:entry);Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideSysmonVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*duplicate*'
    }
    It 'reverifies a private pre-reset export and refuses changed saved bytes or a missing intent' {
      {Read-RideSysmonVmResetExport $script:root $script:descriptor}|Should -Throw '*pre-reset export intent*'
      $export=Export-RideSysmonVmEvidence $null $null $script:descriptor $script:root
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='SysmonVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=$export.Path}
      Write-RideSysmonVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      (Read-RideSysmonVmResetExport $script:root $script:descriptor).Verified|Should -BeTrue
      [IO.File]::AppendAllText((Join-Path $export.Path $script:entry.Path),'changed')
      {Read-RideSysmonVmResetExport $script:root $script:descriptor}|Should -Throw '*evidence changed*'
    }
    It 'rejects an invented fixture pass and incomplete configuration coverage' {
      $script:descriptor|Add-Member -NotePropertyMembers @{ExecutableSha256=('F'*64);SysmonVersion='15.22'}
      $guest=[pscustomobject]@{SchemaVersion=1;Kind='SysmonAcceptanceFixture';RunId=$script:descriptor.RunId;Status='Prepared';NativeAcceptancePassed=$true;ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';ExecutableSha256=('F'*64);SysmonVersion='15.22';ReleaseTag='configs-a45dedb13a43';Profiles=@()}
      {Assert-RideSysmonVmGuestResult $guest Prepare $script:descriptor}|Should -Throw '*preparation*'
      $guest.Kind='SysmonConfigurationAcceptance';$guest.Status='Passed'
      {Assert-RideSysmonVmGuestResult $guest Configurations $script:descriptor}|Should -Throw '*incomplete*'
    }
    It 'refuses a collection from another lease before creating an export directory' {
      Mock Invoke-RideSysmonVmRemote {[pscustomobject]@{SchemaVersion=1;Kind='SysmonVmCollection';RunId=$script:descriptor.RunId;LeaseId=('f'*32);Status='Collected';BaselineLoaded=$true;ArchiveExportComplete=$true;Files=@();Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval'}}}
      {Export-RideSysmonVmEvidence $null $null $script:descriptor $script:root}|Should -Throw '*mismatched*'
      Should -Invoke New-RideSysmonVmDirectory -Times 0 -Exactly
    }
    It 'requires each of the three pinned configurations and all five checks' {
      $script:descriptor|Add-Member -NotePropertyMembers @{ExecutableSha256=('F'*64);SysmonVersion='15.22'}
      $pin=Import-PowerShellDataFile -LiteralPath (Join-Path (Split-Path (Get-Module RIDE.SysmonVm).Path -Parent) '../fixtures/sysmon-configurations.acceptance.psd1')
      $guest=[pscustomobject]@{SchemaVersion=1;Kind='SysmonConfigurationAcceptance';RunId=$script:descriptor.RunId;Status='Passed';NativeAcceptancePassed=$true;ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';ExecutableSha256=('F'*64);SysmonVersion='15.22';ReleaseTag=$pin.ReleaseTag;Profiles=@(foreach($item in $pin.Configurations){[pscustomobject]@{ArtifactId=$item.ArtifactId;Sha256=$item.Sha256;RunId=[guid]::NewGuid().ToString('N');Restored=$true;Checks=@('PreviewNoChanges','AppliedSourceEventAndServiceVerified','RepeatNoChanges','BaselineRestoredAndServiceVerified','RepeatedRestoreNoChanges')}})}
      Assert-RideSysmonVmGuestResult $guest Configurations $script:descriptor
      $guest.Profiles[1].Checks=@('PreviewNoChanges')
      {Assert-RideSysmonVmGuestResult $guest Configurations $script:descriptor}|Should -Throw '*every required*'
      $guest.Profiles[1]=$guest.Profiles[0]
      {Assert-RideSysmonVmGuestResult $guest Configurations $script:descriptor}|Should -Throw '*every required*'
    }
    It 'rejects a reset receipt that points outside its owned export directory' {
      $intent=[pscustomobject]@{SchemaVersion=1;Kind='SysmonVmResetIntent';RunId=$script:descriptor.RunId;LeaseId=$script:descriptor.LeaseId;ConfigurationSha256=$script:descriptor.ConfigurationSha256;ExportPath=(Join-Path $script:root ('elsewhere/export.'+('c'*32)))}
      Write-RideSysmonVmRecord (Join-Path $script:root 'reset-intent.000.json') $intent
      {Read-RideSysmonVmResetExport $script:root $script:descriptor}|Should -Throw '*escaped*'
    }
  }
}
Describe 'Bounded fixed PowerShell Direct job transport' {
  InModuleScope RIDE.SysmonVm {
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
      (Invoke-RideSysmonVmRemote $script:configuration $null Collect $null $null).Status|Should -Be synthetic-result
      Should -Invoke Invoke-Command -Times 1 -Exactly -ParameterFilter {$VMId -eq [guid]$script:configuration.VMId -and $ScriptBlock -eq $script:SysmonVmRemote -and $AsJob}
      Should -Invoke Wait-Job -Times 1 -Exactly -ParameterFilter {$Timeout -eq 180}
      Should -Invoke Remove-Job -Times 1 -Exactly
    }
    It 'stops and removes a timed-out job without receiving a success result' {
      Mock Wait-Job {$null}
      {Invoke-RideSysmonVmRemote $script:configuration $null Apply $null $null 15}|Should -Throw '*timed out*'
      Should -Invoke Stop-Job -Times 1 -Exactly
      Should -Invoke Remove-Job -Times 1 -Exactly
      Should -Invoke Receive-Job -Times 0 -Exactly
    }
    It 'rejects a failed job or multiple result objects and still disposes the job' {
      $script:job.State='Failed'
      {Invoke-RideSysmonVmRemote $script:configuration $null Apply $null $null}|Should -Throw '*one completed result*'
      $script:job.State='Completed'
      Mock Receive-Job {@('unexpected','extra output')}
      {Invoke-RideSysmonVmRemote $script:configuration $null Apply $null $null}|Should -Throw '*one completed result*'
      Should -Invoke Remove-Job -Times 2 -Exactly
    }
  }
}
