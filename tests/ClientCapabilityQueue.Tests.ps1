<#
.SYNOPSIS
  Test finite capability requests and held source identity without a real task.
.DESCRIPTION
  Uses inert TestDrive files, deterministic clocks and mocked controller access.
  No servicing, VM changes, protected writes or task registration occurs.
.EXAMPLE
  Invoke-Pester ./tests/ClientCapabilityQueue.Tests.ps1
.NOTES
  Compatibility: Native PowerShell 5.1/7, Pester 5. Version: 0.1.0.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.ClientCapabilityQueue.psm1') -Force
  function New-QueueFixture {
    param($Directory)
    $paths=@('modules/RIDE.Engine.psm1','modules/RIDE.ClientCapability.psm1','modules/RIDE.PrivateFiles.psm1','catalog/operations.psd1','tests/integration/RIDE.ClientCapabilityVm.psm1','tests/integration/RIDE.ClientCapabilityAcceptance.psm1','tests/integration/RIDE.RetainedGuest.psm1','tests/integration/RIDE.TestAutomation.psm1')
    foreach($path in $paths){$full=Join-Path $Directory $path;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $full) -Force;[IO.File]::WriteAllText($full,'# inert source '+$path)}
    $config=[pscustomobject]@{Name='Synthetic';HostAccountSid='S-1-5-21-1-2-3-1001';VMId='11111111-1111-1111-1111-111111111111';CheckpointId='22222222-2222-2222-2222-222222222222';LocalRepositoryPath=$Directory;IsDisposable=$true}
    $activation=[pscustomobject]@{SchemaVersion=1;Kind='ClientCapabilityQueueActivation';ActivationId=('a'*32);ConfigurationSha256=('C'*64);Name=$config.Name;HostAccountSid=$config.HostAccountSid;VMId=$config.VMId;CheckpointId=$config.CheckpointId;LocalRepositoryPath=$Directory;TaskName='SyntheticCapabilities';CreatedAtUtc='2026-11-03T00:00:00.0000000+00:00';ExpiresAtUtc='2026-11-03T06:00:00.0000000+00:00';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';ExpectedRevision=9711;HostSources=@(New-RideCapabilityQueueSourceManifest $Directory)}
    $request=[pscustomobject]@{SchemaVersion=1;ActivationId=('a'*32);RequestId=('b'*32);RunId=('c'*32);Family='OpenSSHClient';Phase='Prepare';Preview=$false;SubmittedAtUtc='2026-11-03T01:00:00.0000000+00:00';ServicingSource='WindowsUpdate'}
    [pscustomobject]@{Config=$config;Activation=$activation;Request=$request;Now=[datetimeoffset]'2026-11-03T01:00:00Z'}
  }
}
Describe 'Capability queue activation and request contract' {
  BeforeEach {$script:f=New-QueueFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))}
  It 'validates a bounded activation and both explicit acquisition families' {
    {Assert-RideCapabilityQueueActivation $f.Activation $f.Config ('C'*64)}|Should -Not -Throw
    foreach($family in @('OpenSSHClient','RSAT')){
      $f.Request.Family=$family;$resolved=Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now
      $resolved.Command|Should -BeExactly Invoke-RideClientCapabilityVmPhase
      $resolved.Parameters.Family|Should -BeExactly $family
      $resolved.Parameters.ServicingSource|Should -BeExactly WindowsUpdate
      $resolved.Parameters.ExpectedRevision|Should -Be 9711
      $resolved.Parameters.ExpectedBuild|Should -BeExactly '26300'
      $resolved.AdmissionBudgetMinutes|Should -Be 60
    }
  }
  It 'binds <Field> to the installed controller' -ForEach @('Name','HostAccountSid','VMId','CheckpointId','LocalRepositoryPath'|ForEach-Object {@{Field=$_}}) {
    $f.Activation.$Field='different';{Assert-RideCapabilityQueueActivation $f.Activation $f.Config ('C'*64)}|Should -Throw '*binding differs*'
  }
  It 'refuses activation digest drift' {{Assert-RideCapabilityQueueActivation $f.Activation $f.Config ('D'*64)}|Should -Throw '*digest differs*'}
  It 'refuses a non-disposable fixture' {$f.Config.IsDisposable=$false;{Assert-RideCapabilityQueueActivation $f.Activation $f.Config ('C'*64)}|Should -Throw '*disposable*'}
  It 'refuses activation lifetime beyond twelve hours' {$f.Activation.ExpiresAtUtc='2026-11-04T01:00:00.0000000+00:00';{Assert-RideCapabilityQueueActivation $f.Activation $f.Config ('C'*64)}|Should -Throw '*twelve hours*'}
  It 'requires an integer schema instead of coercing <Value>' -ForEach @(@{Value='1'},@{Value=$true},@{Value=1.5}) {
    $f.Activation.SchemaVersion=$Value;{Assert-RideCapabilityQueueActivation $f.Activation $f.Config ('C'*64)}|Should -Throw '*schema*'
    $f.Request.SchemaVersion=$Value;{Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw '*schema*'
  }
  It 'refuses unsupported target metadata <Field>' -ForEach @(@{Field='ExpectedBuild';Value='19045'},@{Field='ExpectedEditionId';Value='ServerStandard'},@{Field='ExpectedRevision';Value=$true},@{Field='ExpectedRevision';Value=-1},@{Field='ExpectedRevision';Value=9711.5}) {
    $f.Activation.$Field=$Value;{Assert-RideCapabilityQueueActivation $f.Activation $f.Config ('C'*64)}|Should -Throw '*exact Windows 11*'
  }
  It 'refuses arbitrary request field <Field>' -ForEach @('Command','ScriptBlock','ConfigurationPath','ExpectedBuild','PayloadPath','TimeoutSeconds'|ForEach-Object {@{Field=$_}}) {
    $f.Request|Add-Member NoteProperty $Field 'untrusted';{Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw '*Unknown*field*'
  }
  It 'refuses malformed or replayed identity <Field>' -ForEach @(@{Field='RunId';Value=('../'+'a'*32)},@{Field='RequestId';Value=('A'*32)},@{Field='ActivationId';Value=('d'*32)}) {
    $f.Request.$Field=$Value;{Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw
  }
  It 'refuses invalid finite request values <Field>' -ForEach @(@{Field='Family';Value='OpenSSHServer'},@{Field='Phase';Value='Reboot'},@{Field='Preview';Value='false'},@{Field='ServicingSource';Value='LocalMedia'}) {
    $f.Request.$Field=$Value;{Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw
  }
  It 'requires explicit acquisition authorization' {$f.Request.PSObject.Properties.Remove('ServicingSource');{Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw '*explicit WindowsUpdate*'}
  It 'refuses stale and future requests' {
    foreach($minutes in @(-11,2)){$f.Request.SubmittedAtUtc=$f.Now.AddMinutes($minutes).ToString('o');{Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw '*stale or from the future*'}
  }
  It 'keeps a phase and recovery margin before expiration' -ForEach @(@{Phase='Prepare';Budget=60},@{Phase='Lifecycle';Budget=45},@{Phase='Collect';Budget=15},@{Phase='Reset';Budget=15}) {
    $f.Request.Phase=$Phase;if($Phase -ne 'Prepare'){$f.Request.PSObject.Properties.Remove('ServicingSource')}
    $f.Activation.ExpiresAtUtc=$f.Now.AddMinutes($Budget).ToString('o')
    {Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw '*insufficient time*'
    $f.Activation.ExpiresAtUtc=$f.Now.AddMinutes($Budget+1).ToString('o')
    $selection=Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now
    $selection.AdmissionBudgetMinutes|Should -Be $Budget
    if($Phase -ne 'Prepare'){$selection.Parameters.ContainsKey('Family')|Should -BeFalse;$selection.Parameters.ContainsKey('ServicingSource')|Should -BeFalse}
    if($Phase -eq 'Lifecycle'){$selection.Parameters.TimeoutSeconds|Should -Be 1800}
  }
  It 'does not allow a later phase to change acquisition' {$f.Request.Phase='Lifecycle';{Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Throw '*only to Prepare*'}
  It 'passes preview explicitly to native ShouldProcess and suppresses confirmation' {$f.Request.Preview=$true;$r=Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now;$r.Parameters.WhatIf|Should -BeTrue;$r.Parameters.Confirm|Should -BeFalse}
  It 'supports both native JSON date representations without locale parsing' {
    $f.Activation.CreatedAtUtc=[datetime]'2026-11-03T00:00:00Z';$f.Request.SubmittedAtUtc=$f.Now
    {Resolve-RideCapabilityQueueRequest $f.Request $f.Activation $f.Now}|Should -Not -Throw
  }
}
Describe 'Capability host source leases' {
  BeforeEach {$script:f=New-QueueFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))}
  It 'holds source bytes against writes until explicitly disposed' {
    $leases=@(Open-RideCapabilityQueueSourceLease $f.Config.LocalRepositoryPath $f.Activation.HostSources)
    try{$leases.Count|Should -Be 8;{[IO.File]::WriteAllText((Join-Path $f.Config.LocalRepositoryPath 'modules/RIDE.Engine.psm1'),'changed')}|Should -Throw}finally{foreach($lease in $leases){$lease.Dispose()}}
    {[IO.File]::WriteAllText((Join-Path $f.Config.LocalRepositoryPath 'modules/RIDE.Engine.psm1'),'changed')}|Should -Not -Throw
  }
  It 'refuses same-length byte drift and releases all earlier leases' {
    $last=$f.Activation.HostSources[-1];$path=Join-Path $f.Config.LocalRepositoryPath $last.Path
    [IO.File]::WriteAllText($path,('x'*$last.Bytes))
    {Open-RideCapabilityQueueSourceLease $f.Config.LocalRepositoryPath $f.Activation.HostSources}|Should -Throw '*source changed*'
    foreach($entry in $f.Activation.HostSources){$stream=[IO.File]::Open((Join-Path $f.Config.LocalRepositoryPath $entry.Path),'Open','ReadWrite','None');$stream.Dispose()}
  }
  It 'refuses an added importable module' {
    [IO.File]::WriteAllText((Join-Path $f.Config.LocalRepositoryPath 'modules/Unexpected.psm1'),'# inert')
    {Open-RideCapabilityQueueSourceLease $f.Config.LocalRepositoryPath $f.Activation.HostSources}|Should -Throw '*inventory changed*'
  }
  It 'refuses duplicate or traversing source entries' {
    $f.Activation.HostSources[1].Path=$f.Activation.HostSources[0].Path
    {Open-RideCapabilityQueueSourceLease $f.Config.LocalRepositoryPath $f.Activation.HostSources}|Should -Throw '*duplicated*'
    $f.Activation.HostSources[1].Path='modules/../outside.psm1'
    {Open-RideCapabilityQueueSourceLease $f.Config.LocalRepositoryPath $f.Activation.HostSources}|Should -Throw '*Invalid*'
  }
  It 'refuses missing required sources and oversized files' {
    $f.Activation.HostSources=$f.Activation.HostSources|Where-Object {$_.Path -ne 'modules/RIDE.Engine.psm1'}
    {Open-RideCapabilityQueueSourceLease $f.Config.LocalRepositoryPath $f.Activation.HostSources}|Should -Throw
    $f=New-QueueFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')));$f.Activation.HostSources[0].Bytes=8388609
    {Open-RideCapabilityQueueSourceLease $f.Config.LocalRepositoryPath $f.Activation.HostSources}|Should -Throw
  }
}
Describe 'Capability queue script source surface' {
  It 'parses <Name> natively without executing it' -ForEach @('RIDE.ClientCapabilityQueue.psm1','Invoke-RideClientCapabilityQueue.ps1','Invoke-RideClientCapabilityQueueWorker.ps1','Register-RideClientCapabilityQueue.ps1'|ForEach-Object {@{Name=$_}}) {
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot ('integration/'+$Name)),[ref]$tokens,[ref]$errors)
    @($errors).Count|Should -Be 0
  }
  It 'prints client and registration versions without controller or elevation access' {
    & (Join-Path $PSScriptRoot 'integration/Invoke-RideClientCapabilityQueue.ps1') -Version|Should -BeExactly '0.1.0'
    & (Join-Path $PSScriptRoot 'integration/Register-RideClientCapabilityQueue.ps1') -Version|Should -BeExactly '0.1.0'
  }
}
Describe 'Capability queue local submission preview' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.TestAutomation.psm1') -Force
    function Start-ScheduledTask {param($TaskPath,$TaskName);throw 'No real task start is allowed in this fixture.'}
  }
  BeforeEach {
    $script:f=New-QueueFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
    $script:queueRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path (Join-Path $script:queueRoot 'bin')
    $script:configPath=Join-Path $script:queueRoot 'configuration.json'
    [IO.File]::WriteAllText($script:configPath,'{}')
    $f.Config.HostAccountSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $f.Activation.HostAccountSid=$f.Config.HostAccountSid
    $f.Activation.ConfigurationSha256=(Get-FileHash $script:configPath).Hash
    $f.Activation.CreatedAtUtc=[datetimeoffset]::UtcNow.ToString('o');$f.Activation.ExpiresAtUtc=[datetimeoffset]::UtcNow.AddHours(4).ToString('o')
    [IO.File]::WriteAllText((Join-Path $script:queueRoot 'bin/capability-queue-activation.json'),($f.Activation|ConvertTo-Json -Depth 8))
    Mock Import-Module {} -ParameterFilter {$Name -like '*RIDE.TestAutomation.psm1' -or $Name -like '*RIDE.ClientCapabilityQueue.psm1'}
    $global:RideCapabilityQueueFixtureTest=@{Config=$f.Config;Root=$script:queueRoot;HostModule=$null}
    Mock Read-RideAutomationConfiguration {$global:RideCapabilityQueueFixtureTest.Config}
    Mock Get-RideAutomationRoot {$global:RideCapabilityQueueFixtureTest.Root}
    Mock Start-ScheduledTask {}
  }
  AfterAll {Remove-Variable -Name RideCapabilityQueueFixtureTest -Scope Global -ErrorAction SilentlyContinue}
  It 'validates a canonical request without creating a queue or starting a task' {
    $result=& (Join-Path $PSScriptRoot 'integration/Invoke-RideClientCapabilityQueue.ps1') -ConfigurationPath $script:configPath -Family opensshclient -Phase prepare -ServicingSource windowsupdate -WhatIf
    $result.Status|Should -BeExactly Preview;$result.TaskStarted|Should -BeFalse;$result.SubmissionWritten|Should -BeFalse
    $result.Family|Should -BeExactly OpenSSHClient;$result.Phase|Should -BeExactly Prepare
    $result.RunId|Should -Match '^[a-f0-9]{32}$'
    Test-Path -LiteralPath (Join-Path $script:queueRoot 'runtime')|Should -BeFalse
    Should -Invoke Start-ScheduledTask -Exactly 0
  }
  It 'refuses missing retained identity before queue access' {
    {& (Join-Path $PSScriptRoot 'integration/Invoke-RideClientCapabilityQueue.ps1') -ConfigurationPath $script:configPath -Family RSAT -Phase Lifecycle -WhatIf}|Should -Throw '*explicit retained RunId*'
    Should -Invoke Start-ScheduledTask -Exactly 0
  }
  It 'refuses configuration drift before submission' {
    [IO.File]::WriteAllText($script:configPath,'{"changed":true}')
    {& (Join-Path $PSScriptRoot 'integration/Invoke-RideClientCapabilityQueue.ps1') -ConfigurationPath $script:configPath -Family RSAT -Phase Prepare -ServicingSource WindowsUpdate -WhatIf}|Should -Throw '*digest differs*'
    Should -Invoke Start-ScheduledTask -Exactly 0
  }
  It 'previews registration without protected writes or task changes' -Skip:($PSVersionTable.PSEdition -ne 'Desktop') {
    $f.Config.LocalRepositoryPath=Split-Path -Parent $PSScriptRoot
    $r=& (Join-Path $PSScriptRoot 'integration/Register-RideClientCapabilityQueue.ps1') -ConfigurationPath $script:configPath -ExpiresAtUtc ([datetimeoffset]::UtcNow.AddHours(4)) -ExpectedBuild 26300 -ExpectedEditionId EnterpriseEval -ExpectedRevision 9711 -WhatIf
    $r.Status|Should -BeExactly Preview;$r.VMChanged|Should -BeFalse;$r.SourceCount|Should -BeGreaterThan 8
    Test-Path -LiteralPath (Join-Path $script:queueRoot 'runtime')|Should -BeFalse
  }
  It 'dispatches only the correlated preview through pinned sources and archives its request' -Skip:($PSVersionTable.PSEdition -ne 'Desktop') {
    foreach($name in @('runtime','results')){$null=New-Item -ItemType Directory -Path (Join-Path $script:queueRoot $name)}
    $workerPath=Join-Path $script:queueRoot 'bin/Invoke-RideClientCapabilityQueueWorker.ps1'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'integration/Invoke-RideClientCapabilityQueueWorker.ps1') -Destination $workerPath
    $script:syntheticHost=New-Module -Name SyntheticCapabilityQueueHost -ScriptBlock {
      function Invoke-RideClientCapabilityVmPhase {
        [CmdletBinding(SupportsShouldProcess=$true)]param($Phase,$RunId,$ConfigurationPath,$Family,$ServicingSource,$ExpectedBuild,$ExpectedEditionId,$ExpectedRevision)
        if(-not $WhatIfPreference){throw 'Synthetic host must only receive preview.'}
        [pscustomobject]@{Status='Preview';RunId=$RunId;Phase=$Phase;LifecyclePassed=$false}
      }
      Export-ModuleMember -Function Invoke-RideClientCapabilityVmPhase
    }
    $global:RideCapabilityQueueFixtureTest.HostModule=$script:syntheticHost
    Mock Import-Module {$global:RideCapabilityQueueFixtureTest.HostModule} -ParameterFilter {$Name -like '*RIDE.ClientCapabilityVm.psm1'}
    Mock Test-RideAutomationAdministrator {$true}
    $f.Request.Preview=$true;$f.Request.SubmittedAtUtc=[datetimeoffset]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $script:queueRoot 'runtime/capability-pending.json'),($f.Request|ConvertTo-Json))
    & $workerPath -ActivationPath (Join-Path $script:queueRoot 'bin/capability-queue-activation.json')
    $report=Get-Content -LiteralPath (Join-Path $script:queueRoot ('results/capability-'+$f.Request.RequestId+'.json')) -Raw|ConvertFrom-Json
    $report.Status|Should -BeExactly Preview;$report.Result.RunId|Should -BeExactly $f.Request.RunId;$report.ServicingStopInferred|Should -BeFalse
    Test-Path -LiteralPath (Join-Path $script:queueRoot 'runtime/capability-running.json')|Should -BeFalse
    Test-Path -LiteralPath (Join-Path $script:queueRoot ('results/capability-'+$f.Request.RequestId+'-request.json'))|Should -BeTrue
    {[IO.File]::WriteAllText((Join-Path $f.Config.LocalRepositoryPath 'modules/RIDE.Engine.psm1'),'# lease released')}|Should -Not -Throw
    Should -Invoke Start-ScheduledTask -Exactly 0
  }
}
