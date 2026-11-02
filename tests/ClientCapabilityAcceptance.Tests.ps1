<#
.SYNOPSIS
  Verify disposable capability scenario control flow without servicing Windows.
.DESCRIPTION
  Mocks guest identity, engine actions, DISM inventory and native binary reads.
  Writes only inert TestDrive evidence using user-private ACLs.
.EXAMPLE
  Invoke-Pester ./tests/ClientCapabilityAcceptance.Tests.ps1
.NOTES
  Compatibility: Native PowerShell 5.1/7, Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.ClientCapabilityAcceptance.psm1') -Force}
Describe 'Disposable client capability acceptance' {
  InModuleScope RIDE.ClientCapabilityAcceptance {
    BeforeEach {
      $script:request=[guid]::NewGuid().ToString('N')
      $script:parameters=@{Family='RSAT';RunId=$script:request;ExpectedComputerName='SYNTHETIC-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';ExpectedRevision=9711;ServicingSource='WindowsUpdate';EvidenceRoot=$TestDrive;DisposableVm=$true;Confirm=$false}
      $script:context=[pscustomobject]@{ComputerName='SYNTHETIC-VM';Build='26300';EditionId='EnterpriseEval';UpdateBuildRevision=9711;InstallationType='Client';ProductType='WinNT';NativeProcess=$true;Architecture='AMD64';Administrator=$true;Manufacturer='Microsoft Corporation';Model='Virtual Machine';GuestMarker='1';IntegrationMarker='1';RunMarker=$script:request}
      $script:operations=@(
        @{Id='component.rsat-server-manager';Kind='WindowsCapability';Handler='ClientCapability';Scope='Machine';CapabilityName='Rsat.ServerManager.Tools~~~~0.0.1.0';CapabilityDependencies=@();ServicingSource='WindowsUpdate'},
        @{Id='component.rsat-dns';Kind='WindowsCapability';Handler='ClientCapability';Scope='Machine';CapabilityName='Rsat.Dns.Tools~~~~0.0.1.0';CapabilityDependencies=@();ServicingSource='WindowsUpdate'})
      $script:states=@{'Rsat.ServerManager.Tools~~~~0.0.1.0'='Installed';'Rsat.Dns.Tools~~~~0.0.1.0'='NotPresent';'Unrelated~~~~0.0.1.0'='Installed'}
      $script:runs=@{};$script:events=[Collections.Generic.List[string]]::new();$script:journalRows=@()
      $script:injectFailure=$false;$script:drift=$false
      Mock Get-RideCapabilityAcceptanceContext {$script:context}
      Mock Assert-RideCapabilityAcceptanceReady {}
      Mock Get-RideCapabilityAcceptanceInventory {@($script:states.Keys|Sort-Object|ForEach-Object {[pscustomobject][ordered]@{Name=$_;State=$script:states[$_]}})}
      Mock Get-RideCapabilityAcceptanceJournals {$script:journalRows}
      Mock Get-RideSingleOperationPlan {
        @($script:operations|ForEach-Object {[pscustomobject]@{Operation=$_;State=$(if($Action -ceq 'Remove'){'Absent'}else{'Present'})}})
      }
      Mock Invoke-RidePlan {
        param($Plan,$WhatIf,$AllowCandidate)
        if($WhatIf){$script:events.Add('Preview');return}
        if(-not $AllowCandidate){throw 'Candidate opt-in missing'}
        $desired=if($Plan[0].State -ceq 'Present'){'Installed'}else{'NotPresent'}
        $changed=@($Plan|Where-Object {$script:states[$_.Operation.CapabilityName] -cne $desired})
        if(-not $changed.Count){$script:events.Add('NoChange');return 'No changes were needed; no state record was created.'}
        $run=[guid]::NewGuid().ToString('N');$prior=@{}
        foreach($item in $changed){$name=$item.Operation.CapabilityName;$prior[$name]=$script:states[$name];$script:states[$name]=$desired}
        $script:runs[$run]=$prior;$script:journalRows+=@([pscustomobject]@{Path=$run+'/_manifest.json';Sha256=('A'*64)})
        $script:events.Add($desired)
        if($script:drift){$script:states['Unrelated~~~~0.0.1.0']='NotPresent'}
        if($script:injectFailure){throw "DISM restart fixture. Run ID: $run. Saved state retained."}
        "Run ID: $run"
      }
      Mock Restore-RideRun {
        param($RunId,$AllowCandidate)
        if(-not $AllowCandidate -or -not $script:runs.ContainsKey($RunId)){throw 'Unexpected recovery'}
        foreach($name in $script:runs[$RunId].Keys){$script:states[$name]=$script:runs[$RunId][$name]}
        $script:events.Add('Restore')
      }
      Mock Export-RideCapabilityAcceptanceRun {}
      Mock New-RidePrivateFileStream {param($Path,$Scope) & $script:private {param($path) New-RidePrivateFileStream -Path $path -Scope User} $Path}
      Mock Get-RideCapabilityAcceptanceClientBinary {throw 'Unexpected OpenSSH binary read'}
    }
    It 'restores mixed original states and preserves unrelated capabilities' {
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Passed
      $result.Checks.Count|Should -Be 7
      $result.LifecyclePassed|Should -BeTrue
      $result.ExactPayloadRecoverySupported|Should -BeFalse
      $result.RestartAcceptancePassed|Should -BeFalse
      $result.LifecycleRuns.Count|Should -Be 2
      @($result.LifecycleRuns|Where-Object {-not $_.Restored}).Count|Should -Be 0
      $script:states['Rsat.ServerManager.Tools~~~~0.0.1.0']|Should -Be Installed
      $script:states['Rsat.Dns.Tools~~~~0.0.1.0']|Should -Be NotPresent
      $script:states['Unrelated~~~~0.0.1.0']|Should -Be Installed
      @($script:events)|Should -Be @('Preview','Installed','NoChange','NotPresent','Restore','Restore','Restore')
      Should -Invoke Export-RideCapabilityAcceptanceRun -Times 2 -Exactly
      (Get-Acl -LiteralPath (Join-Path $result.EvidenceDirectory 'result.json')).AreAccessRulesProtected|Should -BeTrue
    }
    It 'handles an entirely pre-existing selection without inventing an install run' {
      $script:states['Rsat.Dns.Tools~~~~0.0.1.0']='Installed'
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Passed
      $result.LifecycleRuns.Count|Should -Be 1
      $result.LifecycleRuns[0].Stage|Should -Be Remove
      $result.LifecycleRuns[0].Restored|Should -BeTrue
      @($script:events)|Should -Be @('Preview','NoChange','NoChange','NotPresent','Restore','Restore')
    }
    It 'previews without evidence, engine calls or state changes' {
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters -WhatIf
      $result.Status|Should -Be Preview
      Test-Path -LiteralPath (Join-Path $TestDrive $script:request)|Should -BeFalse
      Should -Invoke Invoke-RidePlan -Exactly 0
      Should -Invoke New-RidePrivateFileStream -Exactly 0
    }
    It 'requires existing elevation without asking for UAC' {
      $script:context.Administrator=$false
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be NotRun
      $result.Reason|Should -Be ExistingElevationRequired
      Should -Invoke Get-RideSingleOperationPlan -Exactly 0
    }
    It 'refuses uncorrelated guests, workstation models and target drift' {
      $script:context.RunMarker='different'
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*correlated disposable*'
      $script:context.RunMarker=$script:request;$script:context.Model='Workstation'
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*correlated disposable*'
      $script:context.Model='Virtual Machine';$script:context.UpdateBuildRevision=1
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*target differs*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
    It 'rejects empty plans, duplicate selections and pending literal states' {
      $original=$script:operations;$script:operations=@()
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*Unexpected capability plan*'
      $script:operations=@($original[0],$original[0])
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*Duplicate capability*'
      $script:operations=$original;$script:states['Rsat.Dns.Tools~~~~0.0.1.0']='InstallPending'
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*pending/unknown*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
    It 'refuses a different capability family before any engine action' {
      $script:parameters.Family='OpenSSHClient'
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*selected OpenSSH Client family*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
    It 'retains the partial run ID and exports it before stopping after a servicing failure' {
      $script:injectFailure=$true
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Install
      $result.RecoveryRequired|Should -BeTrue
      $result.LifecycleRuns.Count|Should -Be 1
      $result.LifecycleRuns[0].RunId|Should -Match '^[a-f0-9]{32}$'
      $result.LifecycleRuns[0].Restored|Should -BeFalse
      Should -Invoke Export-RideCapabilityAcceptanceRun -Exactly 1
      Should -Invoke Restore-RideRun -Exactly 0
      @($script:events)|Should -Be @('Preview','Installed')
    }
    It 'retains both the original servicing error and a secondary export error' {
      $script:injectFailure=$true
      Mock Export-RideCapabilityAcceptanceRun {throw 'export fixture failed'}
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Error|Should -Match 'DISM restart fixture'
      $result.EvidenceErrors|Should -Contain 'export fixture failed'
      $result.LifecycleRuns.Count|Should -Be 1
      Should -Invoke Restore-RideRun -Exactly 0
    }
    It 'stops on unexpected collateral capability changes' {
      $script:drift=$true
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Error|Should -Match 'Unrelated capability inventory changed'
      Should -Invoke Restore-RideRun -Exactly 0
    }
    It 'refuses a changed repeat selection before invoking its writer' {
      Mock Get-RideSingleOperationPlan {
        $selected=if($script:events -contains 'Installed'){@($script:operations[0])}else{$script:operations}
        @($selected|ForEach-Object {[pscustomobject]@{Operation=$_;State='Present'}})
      }
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Repeat
      $result.Error|Should -Match 'Repeat selection changed'
      Should -Invoke Invoke-RidePlan -Exactly 1 -ParameterFilter {-not $WhatIf}
      Should -Invoke Restore-RideRun -Exactly 0
    }
    It 'detects a preview that writes an engine journal' {
      Mock Invoke-RidePlan {$script:journalRows=@([pscustomobject]@{Path='unexpected';Sha256='fixture'})}
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Preview
      Should -Invoke Invoke-RidePlan -Exactly 1
      Should -Invoke Restore-RideRun -Exactly 0
    }
    It 'stops if the ready check detects a restart before another lifecycle stage' {
      Mock Assert-RideCapabilityAcceptanceReady {if($script:events -contains 'Installed'){throw 'servicing restart fixture'}}
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Error|Should -Match 'servicing restart fixture'
      @($script:events)|Should -Be @('Preview','Installed')
      Should -Invoke Restore-RideRun -Exactly 0
    }
    It 'never hides failed saved recovery behind checkpoint cleanup' {
      Mock Restore-RideRun {throw 'recovery acquisition unavailable'}
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be RestoreRemoval
      $result.Error|Should -Match 'recovery acquisition unavailable'
      @($result.LifecycleRuns|Where-Object Restored).Count|Should -Be 0
      Should -Invoke Restore-RideRun -Exactly 1
    }
    It 'refuses to overwrite an existing evidence request' {
      $null=New-Item -ItemType Directory -Path (Join-Path $TestDrive $script:request)
      {Invoke-RideClientCapabilityAcceptance @script:parameters}|Should -Throw '*already exists*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
    It 'checks native client identity at every lifecycle readback without making a connection' {
      $script:parameters.Family='OpenSSHClient'
      $script:operations=@(@{Id='component.openssh-client-capability';Kind='WindowsCapability';Handler='ClientCapability';Scope='Machine';CapabilityName='OpenSSH.Client~~~~0.0.1.0';CapabilityDependencies=@();ServicingSource='WindowsUpdate'})
      $script:states=@{'OpenSSH.Client~~~~0.0.1.0'='NotPresent';'Unrelated~~~~0.0.1.0'='Installed'}
      Mock Get-RideCapabilityAcceptanceClientBinary {if($script:states['OpenSSH.Client~~~~0.0.1.0'] -ceq 'Installed'){[pscustomobject]@{Exists=$true;FileVersion='fixture';SignatureStatus='Valid';SignerSubject='CN=fixture, O=Microsoft Corporation, C=US'}}else{[pscustomobject]@{Exists=$false}}}
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Passed
      Should -Invoke Get-RideCapabilityAcceptanceClientBinary -Exactly 6
    }
    It 'rejects an unverifiable client binary after a successful capability state change' {
      $script:parameters.Family='OpenSSHClient'
      $script:operations=@(@{Id='component.openssh-client-capability';Kind='WindowsCapability';Handler='ClientCapability';Scope='Machine';CapabilityName='OpenSSH.Client~~~~0.0.1.0';CapabilityDependencies=@();ServicingSource='WindowsUpdate'})
      $script:states=@{'OpenSSH.Client~~~~0.0.1.0'='NotPresent'}
      Mock Get-RideCapabilityAcceptanceClientBinary {[pscustomobject]@{Exists=$true;FileVersion='fixture';SignatureStatus='NotSigned';SignerSubject=''}}
      $result=Invoke-RideClientCapabilityAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Error|Should -Match 'identity/version'
      Should -Invoke Restore-RideRun -Exactly 0
    }
  }
}

Describe 'Capability evidence boundaries' {
  InModuleScope RIDE.ClientCapabilityAcceptance {
    BeforeEach {
      $script:evidenceRun='11111111111111111111111111111111'
      $caseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $script:stateRoot=Join-Path $caseRoot 'state';$script:exportRoot=Join-Path $caseRoot 'export'
      $null=New-Item -ItemType Directory -Path (Join-Path $script:stateRoot $script:evidenceRun),$script:exportRoot -Force
      $script:target=[pscustomobject]@{ComputerName='SYNTHETIC-VM';Build='26300';EditionId='EnterpriseEval';UpdateBuildRevision=9711;InstallationType='Client';ProductType='WinNT';NativeProcess=$true;Architecture='AMD64'}
      $script:selection=@([pscustomobject]@{Id='component.openssh-client-capability';CapabilityName='OpenSSH.Client~~~~0.0.1.0'})
      $script:report=[pscustomobject]@{Selection=$script:selection;WindowsContext=$script:target}
      $script:manifest=[pscustomobject]@{RunId=$script:evidenceRun;OperationIds=@('component.openssh-client-capability');Scopes=@('Machine')}
      $script:snapshot=[pscustomobject]@{SchemaVersion=1;RunId=$script:evidenceRun;OperationId='component.openssh-client-capability';Kind='WindowsCapability';Scope='Machine';Snapshot=[pscustomobject]@{SnapshotVersion=2;OperationId='component.openssh-client-capability';CapabilityName='OpenSSH.Client~~~~0.0.1.0';CapabilityState='NotPresent';ExpectedState='Installed';ServicingSource='WindowsUpdate';WindowsContext=$script:target}}
      $script:manifestPath=Join-Path (Join-Path $script:stateRoot $script:evidenceRun) '_manifest.json'
      $script:snapshotPath=Join-Path (Join-Path $script:stateRoot $script:evidenceRun) 'component.openssh-client-capability.json'
      $script:manifest|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:manifestPath -Encoding UTF8
      $script:snapshot|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:snapshotPath -Encoding UTF8
      Mock Get-RideCapabilityAcceptanceStateRoot {$script:stateRoot}
      Mock New-RidePrivateFileStream {param($Path,$Scope) & $script:private {param($path) New-RidePrivateFileStream -Path $path -Scope User} $Path}
    }
    It 'exports only correlated capability journals into new private evidence files' {
      Export-RideCapabilityAcceptanceRun $script:evidenceRun $script:report $script:exportRoot
      $path=Join-Path (Join-Path $script:exportRoot ('engine-'+$script:evidenceRun)) 'component.openssh-client-capability.json'
      (Get-Content -LiteralPath $path -Raw|ConvertFrom-Json).RunId|Should -Be $script:evidenceRun
      (Get-Acl -LiteralPath $path).AreAccessRulesProtected|Should -BeTrue
      (Get-FileHash -LiteralPath $path).Hash|Should -Be (Get-FileHash -LiteralPath $script:snapshotPath).Hash
      Should -Invoke New-RidePrivateFileStream -Exactly 2 -ParameterFilter {$Scope -ceq 'Machine'}
    }
    It 'rejects another run identity without copying that record' {
      $script:manifest.RunId='22222222222222222222222222222222'
      $script:manifest|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:manifestPath -Encoding UTF8
      {Export-RideCapabilityAcceptanceRun $script:evidenceRun $script:report $script:exportRoot}|Should -Throw '*run identity differs*'
      Test-Path -LiteralPath (Join-Path (Join-Path $script:exportRoot ('engine-'+$script:evidenceRun)) '_manifest.json')|Should -BeFalse
    }
    It 'rejects a foreign operation or servicing source' {
      $script:snapshot.Snapshot.ServicingSource='LocalSource'
      $script:snapshot|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:snapshotPath -Encoding UTF8
      {Export-RideCapabilityAcceptanceRun $script:evidenceRun $script:report $script:exportRoot}|Should -Throw '*snapshot selection/source differs*'
    }
    It 'rejects a different Windows revision in recovery evidence' {
      $script:snapshot.Snapshot.WindowsContext=$script:target|Select-Object *
      $script:snapshot.Snapshot.WindowsContext.UpdateBuildRevision=1
      $script:snapshot|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:snapshotPath -Encoding UTF8
      {Export-RideCapabilityAcceptanceRun $script:evidenceRun $script:report $script:exportRoot}|Should -Throw '*target drift*'
    }
    It 'fingerprints journal content and ignores payload subdirectories' {
      $payload=Join-Path (Split-Path $script:manifestPath -Parent) 'package.files'
      $null=New-Item -ItemType Directory -Path $payload
      'payload fixture'|Set-Content -LiteralPath (Join-Path $payload 'ignored.json')
      $first=@(Get-RideCapabilityAcceptanceJournals)
      $first.Count|Should -Be 2
      $script:manifest|Add-Member -NotePropertyName Additional -NotePropertyValue 'fixture'
      $script:manifest|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $script:manifestPath -Encoding UTF8
      $second=@(Get-RideCapabilityAcceptanceJournals)
      (Test-RideCapabilityAcceptanceEqual $first $second)|Should -BeFalse
    }
  }
}
