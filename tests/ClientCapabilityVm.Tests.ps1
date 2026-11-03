<#
.SYNOPSIS
  Verify retained capability host dispatch without operating a real VM.
.DESCRIPTION
  Mocks Hyper-V, guest credentials, retained ownership and remote execution.
  TestDrive fixtures verify snapshot hashes and bounded evidence transfer.
.EXAMPLE
  Invoke-Pester ./tests/ClientCapabilityVm.Tests.ps1
.NOTES
  Compatibility: Native PowerShell 5.1/7, Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.ClientCapabilityVm.psm1') -Force}
Describe 'Retained client capability phases' {
  InModuleScope RIDE.ClientCapabilityVm {
    BeforeAll {
      function Restore-VMSnapshot {[CmdletBinding()]param($VMSnapshot,[switch]$Confirm)}
      function Start-VM {[CmdletBinding()]param($VM)}
    }
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      $script:run='a'*32;$script:lease='b'*32;$script:vmState='Off';$script:events=[Collections.Generic.List[string]]::new()
      $repository=[IO.Path]::GetFullPath((Join-Path (Split-Path (Get-Module RIDE.ClientCapabilityVm).Path -Parent) '../..'))
      $script:context=[pscustomobject]@{Root=$script:root;ConfigurationSha256=('C'*64);Configuration=[pscustomobject]@{VMName='RIDE-Test';VMId='11111111-1111-1111-1111-111111111111';LocalRepositoryPath=$repository}}
      $script:hold=[pscustomobject]@{RunId=$script:run;LeaseId=$script:lease;VMId=$script:context.Configuration.VMId;VMName='RIDE-Test';CheckpointId='22222222-2222-2222-2222-222222222222';ConfigurationSha256=$script:context.ConfigurationSha256}
      $script:store=Join-Path $script:root ('retained-capability-'+$script:run)
      $script:parameters=@{ConfigurationPath=(Join-Path $script:root 'configuration.json');RunId=$script:run;Confirm=$false}
      $script:prepare=@{Phase='Prepare';Family='RSAT';ServicingSource='WindowsUpdate';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';ExpectedRevision=9711}
      $script:admitted=$false;$script:terminal=$false;$script:terminalStatus=$null
      Mock Get-RideCapabilityVmContext {$script:context}
      Mock New-RideRetainedGuestHold {$script:events.Add('Reserve');$script:hold}
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=$script:context;Hold=$script:hold;Lock=$script:lastLock;Target=[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState};Snapshot='synthetic-checkpoint'}}}
      Mock New-RideCapabilityVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideCapabilityVmRecord {
        param($Path,$Record)
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($Record|ConvertTo-Json -Depth 12))
        $stream=& $script:private {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
      Mock Read-RideCapabilityVmRecord {
        param($Path)
        $bytes=& $script:private {param($p) Read-RidePrivateFileBytes -Path $p -Scope User} $Path
        [Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json
      }
      Mock New-RideCapabilityVmSnapshot {@([pscustomobject]@{Path='fixture';Sha256=('A'*64);Bytes=1})}
      Mock Get-RideCapabilityVmPayload {@([pscustomobject]@{Path='fixture';Content='QQ=='})}
      Mock Get-RideCapabilityVmCredential {[pscredential]::new('synthetic-user',(ConvertTo-SecureString 'Synthetic-test-only' -AsPlainText -Force))}
      Mock Restore-VMSnapshot {$script:events.Add('InitialCheckpoint')}
      Mock Start-VM {$script:events.Add('Start');$script:vmState='Running'}
      Mock Wait-RideCapabilityVmReady {[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';Revision=9711}}
      Mock Invoke-RideCapabilityVmRemote {
        param($Action,$Descriptor)
        $script:events.Add($Action)
        if($Action -ceq 'Prepare'){return [pscustomobject]@{RunId=$Descriptor.RunId;Family=$Descriptor.Family;Status='Prepared';SourceCount=1}}
        $script:admitted=$true;$script:terminal=$true;$script:terminalStatus='Passed'
        [pscustomobject]@{Kind='ClientCapabilityAcceptance';RunId=$Descriptor.RunId;Family=$Descriptor.Family;Status='Passed';LifecyclePassed=$true;RecoveryRequired=$false;Checks=@(1..7)}
      }
      Mock Export-RideCapabilityVmEvidence {$script:events.Add('Export');[pscustomobject]@{Verified=$true;Path=(Join-Path $script:store 'synthetic-export');FileCount=3;LifecycleAdmitted=$script:admitted;TerminalResultPresent=$script:terminal;TerminalStatus=$script:terminalStatus}}
      Mock Reset-RideAutomationVm {$script:events.Add('Reset');$script:vmState='Off'}
      Mock Import-RideAutomationLab {[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState}}}
      Mock Remove-RideRetainedGuestHold {$script:events.Add('Release');[pscustomobject]@{Status='Released'}}
    }
    It 'runs one explicit lifecycle and exports before separately requested reset' {
      (Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare).Status|Should -Be Prepared
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Lifecycle
      $result.Status|Should -Be Passed;$result.LifecyclePassed|Should -BeTrue;$result.RecoveryRequired|Should -BeTrue
      (Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Collect).Status|Should -Be Collected
      $reset=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Reset
      $reset.Status|Should -Be ResetAndOff;$reset.RecoveryRequired|Should -BeFalse;$reset.LifecyclePassed|Should -BeFalse
      @($script:events)|Should -Be @('Reserve','InitialCheckpoint','Start','Prepare','Export','Lifecycle','Export','Export','Export','Reset','Release')
      $script:lastLock.CanRead|Should -BeFalse
    }
    It 'previews every phase without reserving, writing or contacting the guest' {
      (Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare -WhatIf).Status|Should -Be Preview
      foreach($phase in @('Lifecycle','Collect','Reset')){(Invoke-RideClientCapabilityVmPhase @script:parameters -Phase $phase -WhatIf).Status|Should -Be Preview}
      Should -Invoke New-RideRetainedGuestHold -Exactly 0
      Should -Invoke Write-RideCapabilityVmRecord -Exactly 0
      Should -Invoke Invoke-RideCapabilityVmRemote -Exactly 0
    }
    It 'requires explicit source and target selection only on Prepare' {
      $script:prepare.Remove('ServicingSource')
      {Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare}|Should -Throw '*explicit ServicingSource*'
      {Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Lifecycle -Family RSAT}|Should -Throw '*only to Prepare*'
      Should -Invoke New-RideRetainedGuestHold -Exactly 0
    }
    It 'canonicalizes declared values without accepting uppercase request IDs' {
      $script:prepare.Phase='prepare';$script:prepare.Family='rsat';$script:prepare.ServicingSource='windowsupdate';$script:prepare.ExpectedEditionId='enterpriseeval'
      (Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare -WhatIf).Status|Should -Be Preview
      (Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare).Status|Should -Be Prepared
      $saved=Read-RideCapabilityVmRecord (Join-Path $script:store 'session.json')
      $saved.Family|Should -BeExactly RSAT;$saved.ServicingSource|Should -BeExactly WindowsUpdate;$saved.ExpectedEditionId|Should -BeExactly EnterpriseEval
      $script:parameters.RunId='A'*32
      {Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Collect}|Should -Throw
    }
    It 'refuses an old build or a different checkout before reserving' {
      $script:prepare.ExpectedBuild='19045'
      {Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare}|Should -Throw '*Windows 11*'
      $script:prepare.ExpectedBuild='26300';$script:context.Configuration.LocalRepositoryPath=$script:root
      {Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare}|Should -Throw '*registered checkout*'
      Should -Invoke New-RideRetainedGuestHold -Exactly 0
    }
    It 'uses the production RSAT edition guard before reserving a guest' {
      $script:prepare.ExpectedEditionId='Education'
      {Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare}|Should -Throw '*Pro/Enterprise*'
      Should -Invoke New-RideRetainedGuestHold -Exactly 0
      Should -Invoke Get-RideCapabilityVmContext -Exactly 0
    }
    It 'stops if registration changes under phase ownership' {
      Mock Open-RideRetainedGuestPhase {$script:lastLock=[IO.MemoryStream]::new();[pscustomobject]@{Context=[pscustomobject]@{ConfigurationSha256=('D'*64)};Hold=$script:hold;Lock=$script:lastLock}}
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      $result.Status|Should -Be Failed;$result.Error|Should -Match 'configuration changed'
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Restore-VMSnapshot -Exactly 0
    }
    It 'retains a snapshot failure without resetting or releasing' {
      Mock New-RideCapabilityVmSnapshot {throw 'snapshot fixture failed'}
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      $result.Status|Should -Be Failed;$result.RecoveryRequired|Should -BeTrue
      $script:lastLock.CanRead|Should -BeFalse
      Should -Invoke Reset-RideAutomationVm -Exactly 0
      Should -Invoke Remove-RideRetainedGuestHold -Exactly 0
    }
    It 'exports a failed lifecycle without treating it as passed or resetting' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      Mock Invoke-RideCapabilityVmRemote {$script:admitted=$true;$script:terminal=$true;$script:terminalStatus='Failed';[pscustomobject]@{Kind='ClientCapabilityAcceptance';RunId=$script:run;Family='RSAT';Status='Failed';LifecyclePassed=$false;RecoveryRequired=$true;Checks=@()}}
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Lifecycle
      $result.Status|Should -Be Failed;$result.EvidenceExport.Verified|Should -BeTrue;$result.LifecyclePassed|Should -BeFalse
      Should -Invoke Reset-RideAutomationVm -Exactly 0
      $script:vmState|Should -Be Running
    }
    It 'refuses reset after a timeout without a terminal guest result' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      Mock Invoke-RideCapabilityVmRemote {$script:admitted=$true;throw 'phase timed out; servicing may still be running'}
      (Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Lifecycle).Status|Should -Be Failed
      $reset=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Reset
      $reset.Status|Should -Be Failed;$reset.Error|Should -Match 'no terminal result'
      Should -Invoke Reset-RideAutomationVm -Exactly 0
      Should -Invoke Remove-RideRetainedGuestHold -Exactly 0
    }
    It 'can clean up a terminal failed scenario without upgrading its outcome' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      $script:admitted=$true;$script:terminal=$true;$script:terminalStatus='Failed'
      $reset=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Reset
      $reset.Status|Should -Be ResetAndOff;$reset.LifecyclePassed|Should -BeFalse
    }
    It 'refuses reset if evidence export fails' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      Mock Export-RideCapabilityVmEvidence {throw 'export fixture failed'}
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Reset
      $result.Status|Should -Be Failed
      Should -Invoke Reset-RideAutomationVm -Exactly 0
    }
    It 'does not release the hold unless the reset leaves the VM Off' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      Mock Reset-RideAutomationVm {}
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Reset
      $result.Status|Should -Be Failed;$result.Error|Should -Match 'leave the VM Off'
      Should -Invoke Remove-RideRetainedGuestHold -Exactly 0
    }
    It 'reports a release failure with recovery still required' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      Mock Remove-RideRetainedGuestHold {throw 'release fixture failed'}
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Reset
      $result.Status|Should -Be Failed;$result.Stage|Should -Be HoldRelease;$result.RecoveryRequired|Should -BeTrue
    }
    It 'refuses a saved session with another lease before reading a credential' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      Mock Read-RideCapabilityVmRecord {[pscustomobject]@{SchemaVersion=1;Kind='CapabilityVmSession';RunId=$script:run;LeaseId=('c'*32)}}
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Lifecycle
      $result.Status|Should -Be Failed;$result.Error|Should -Match 'ownership differs'
      Should -Invoke Get-RideCapabilityVmCredential -Exactly 1
    }
    It 'retains an unexpected Off guest without guessing that cleanup succeeded' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      $script:vmState='Off'
      $result=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Reset
      $result.Status|Should -Be Failed;$result.Error|Should -Match 'require a running guest'
      Should -Invoke Remove-RideRetainedGuestHold -Exactly 0
    }
    It 'passes the selected bounded execution timeout only to Lifecycle' {
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters @script:prepare
      $null=Invoke-RideClientCapabilityVmPhase @script:parameters -Phase Lifecycle -TimeoutSeconds 45
      Should -Invoke Invoke-RideCapabilityVmRemote -Exactly 1 -ParameterFilter {$Action -ceq 'Lifecycle' -and $TimeoutSeconds -eq 45}
    }
  }
}

Describe 'Capability source and export transfer' {
  InModuleScope RIDE.ClientCapabilityVm {
    BeforeEach {
      $script:case=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:case
      $script:repository=Join-Path $script:case 'repository';$script:snapshot=Join-Path $script:case 'snapshot'
      foreach($folder in @('modules','profiles','catalog','tests/integration','components','legacy')){$null=New-Item -ItemType Directory -Path (Join-Path $script:repository $folder) -Force}
      foreach($path in @('modules/RIDE.Engine.psm1','modules/RIDE.ClientCapability.psm1','modules/RIDE.PrivateFiles.psm1','catalog/operations.psd1','tests/integration/RIDE.ClientCapabilityAcceptance.psm1','profiles/fixture.psd1','components/not-selected.txt','legacy/not-selected.txt')){[IO.File]::WriteAllText((Join-Path $script:repository $path),'inert source fixture')}
      Mock New-RideCapabilityVmDirectory {param($Path);$null=New-Item -ItemType Directory -Path $Path}
      Mock Write-RideCapabilityVmRecord {param($Path,$Record);$Record|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $Path -Encoding UTF8}
      $script:descriptor=[pscustomobject]@{RunId=('a'*32);LeaseId=('b'*32);Family='RSAT';VMName='RIDE-Test';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';ExpectedRevision=9711}
      $script:collected=[pscustomobject]@{RunId=$script:descriptor.RunId;Family='RSAT';Status='Collected';Context=[pscustomobject]@{ComputerName='RIDE-Test';Build='26300';EditionId='EnterpriseEval';Revision=9711};LifecycleAdmitted=$false;TerminalResultPresent=$false;TerminalStatus=$null;Files=@()}
      Mock Invoke-RideCapabilityVmRemote {$script:collected}
    }
    It 'stages only bounded runtime sources and retains byte-identical payloads' {
      $manifest=@(New-RideCapabilityVmSnapshot $script:repository $script:snapshot)
      $manifest.Count|Should -Be 6
      @($manifest.Path|Where-Object {$_ -match '^(components|legacy)/'}).Count|Should -Be 0
      $payload=@(Get-RideCapabilityVmPayload $script:snapshot $manifest)
      $payload.Count|Should -Be 6
      foreach($entry in $payload){[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($entry.Content))|Should -BeExactly 'inert source fixture'}
    }
    It 'produces a self-contained current engine snapshot for read-only catalog loading' {
      $actualRoot=[IO.Path]::GetFullPath((Join-Path (Split-Path (Get-Module RIDE.ClientCapabilityVm).Path -Parent) '../..'))
      $manifest=@(New-RideCapabilityVmSnapshot $actualRoot $script:snapshot)
      $manifest.Count|Should -BeGreaterThan 5
      $shell=[powershell]::Create()
      try{
        $null=$shell.AddScript('param($path) Import-Module $path -ErrorAction Stop; (Get-RideCatalog).Operations.Count').AddArgument((Join-Path $script:snapshot 'modules/RIDE.Engine.psm1'))
        $values=@($shell.Invoke())
        if($shell.HadErrors){throw ($shell.Streams.Error -join '; ')}
        $values.Count|Should -Be 1
        [int]$values[0]|Should -BeGreaterThan 0
      }finally{$shell.Dispose()}
    }
    It 'refuses source bytes changed after snapshot creation' {
      $manifest=@(New-RideCapabilityVmSnapshot $script:repository $script:snapshot)
      [IO.File]::WriteAllText((Join-Path $script:snapshot 'modules/RIDE.Engine.psm1'),'changed source bytes')
      {Get-RideCapabilityVmPayload $script:snapshot $manifest}|Should -Throw '*Retained source*changed*'
    }
    It 'rejects traversal, duplicate identities and missing required sources' {
      $manifest=@(New-RideCapabilityVmSnapshot $script:repository $script:snapshot)
      $old=$manifest[0].Path;$manifest[0].Path='../escape.psm1'
      {Assert-RideCapabilityVmSourceManifest $manifest}|Should -Throw '*manifest entry*'
      $manifest[0].Path=$old
      {Assert-RideCapabilityVmSourceManifest @($manifest+$manifest[0])}|Should -Throw '*manifest entry*'
      {Assert-RideCapabilityVmSourceManifest @($manifest|Where-Object Path -CNE 'modules/RIDE.Engine.psm1')}|Should -Throw '*Required capability source*'
    }
    It 'exports an untouched prepared guest without claiming lifecycle completion' {
      $result=Export-RideCapabilityVmEvidence $null $null $script:descriptor $script:case
      $result.Verified|Should -BeTrue;$result.FileCount|Should -Be 0;$result.TerminalResultPresent|Should -BeFalse
    }
    It 'rejects wrong target or ambiguous admission metadata before writing exports' {
      $script:collected.Context.Revision=1
      {Export-RideCapabilityVmEvidence $null $null $script:descriptor $script:case}|Should -Throw '*target or terminal metadata*'
      $script:collected.Context.Revision=9711;$script:collected.LifecycleAdmitted=$null
      {Export-RideCapabilityVmEvidence $null $null $script:descriptor $script:case}|Should -Throw '*target or terminal metadata*'
      Should -Invoke New-RideCapabilityVmDirectory -Exactly 0
    }
    It 'rejects a claimed terminal result without its exported file' {
      $script:collected.TerminalResultPresent=$true;$script:collected.TerminalStatus='Passed'
      {Export-RideCapabilityVmEvidence $null $null $script:descriptor $script:case}|Should -Throw '*terminal files differ*'
    }
    It 'rejects an export digest mismatch before writing the file' {
      $script:collected.Files=@([pscustomobject]@{Path='fixture.json';Bytes=2;Content='e30=';Sha256=('A'*64)})
      {Export-RideCapabilityVmEvidence $null $null $script:descriptor $script:case}|Should -Throw '*export bytes differ*'
    }
    It 'exports matching terminal evidence with exact bytes' {
      $script:collected.LifecycleAdmitted=$true;$script:collected.TerminalResultPresent=$true;$script:collected.TerminalStatus='Failed'
      $values=@{ 'lifecycle-intent.json'='{}'; ($script:descriptor.RunId+'/result.json')=([pscustomobject]@{RunId=$script:descriptor.RunId;Family='RSAT';Status='Failed'}|ConvertTo-Json -Compress)}
      $script:collected.Files=@(foreach($path in $values.Keys){$bytes=[Text.Encoding]::UTF8.GetBytes($values[$path]);[pscustomobject]@{Path=$path;Bytes=$bytes.Length;Sha256=(Get-RideCapabilityVmHash $bytes);Content=[Convert]::ToBase64String($bytes)}})
      $result=Export-RideCapabilityVmEvidence $null $null $script:descriptor $script:case
      $result.Verified|Should -BeTrue;$result.TerminalStatus|Should -Be Failed;$result.FileCount|Should -Be 2
      foreach($entry in $script:collected.Files){(Get-FileHash -LiteralPath (Join-Path $result.Path $entry.Path)).Hash|Should -BeExactly $entry.Sha256}
    }
  }
}

Describe 'Fixed capability PowerShell Direct transport' {
  InModuleScope RIDE.ClientCapabilityVm {
    BeforeAll {
      function Invoke-Command {[CmdletBinding()]param($VMId,$Credential,$ScriptBlock,$ArgumentList,[switch]$AsJob)}
      function Wait-Job {param($Job,$Timeout)}
      function Receive-Job {[CmdletBinding()]param($Job)}
      function Stop-Job {[CmdletBinding()]param($Job)}
      function Remove-Job {[CmdletBinding()]param($Job,[switch]$Force)}
    }
    BeforeEach {
      $script:configuration=[pscustomobject]@{VMId='11111111-1111-1111-1111-111111111111'}
      $script:job=[pscustomobject]@{State='Completed'}
      Mock Invoke-Command {$script:job}
      Mock Wait-Job {$script:job}
      Mock Receive-Job {[pscustomobject]@{Status='fixture'}}
      Mock Stop-Job {}
      Mock Remove-Job {}
    }
    It 'binds the fixed remote scriptblock to the registered VM and disposes the job' {
      (Invoke-RideCapabilityVmRemote $script:configuration $null Collect $null $null).Status|Should -Be fixture
      Should -Invoke Invoke-Command -Exactly 1 -ParameterFilter {$VMId -eq [guid]$script:configuration.VMId -and $ScriptBlock -eq $script:capabilityRemote -and $AsJob}
      Should -Invoke Wait-Job -Exactly 1 -ParameterFilter {$Timeout -eq 180}
      Should -Invoke Remove-Job -Exactly 1
    }
    It 'reports timeout without claiming that native servicing stopped' {
      Mock Wait-Job {$null}
      {Invoke-RideCapabilityVmRemote $script:configuration $null Lifecycle $null $null 30}|Should -Throw '*servicing may still be running*Retain the VM*'
      Should -Invoke Receive-Job -Exactly 0
      Should -Invoke Stop-Job -Exactly 1
      Should -Invoke Remove-Job -Exactly 1
    }
    It 'rejects failed jobs and ambiguous result streams while still disposing them' {
      $script:job.State='Failed'
      {Invoke-RideCapabilityVmRemote $script:configuration $null Lifecycle $null $null}|Should -Throw '*one completed result*'
      $script:job.State='Completed'
      Mock Receive-Job {@('first','second')}
      {Invoke-RideCapabilityVmRemote $script:configuration $null Lifecycle $null $null}|Should -Throw '*one completed result*'
      Should -Invoke Remove-Job -Exactly 2
    }
  }
}
