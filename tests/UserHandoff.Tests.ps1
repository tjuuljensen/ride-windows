<#
.SYNOPSIS
  Test desktop-user handoff boundaries with mocked shell and engine calls.
.DESCRIPTION
  Verifies user/session/source correlation, preview, refusal before launch or
  mutation, encoded data and user-only saved recovery. Never launches a process.
.EXAMPLE
  Invoke-Pester .\tests\UserHandoff.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  All native identity, COM launch and engine writes are mocked. TestRegistry off.
#>
BeforeAll {
  $script:Repo=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Repo 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:Repo 'modules/RIDE.UserHandoff.psm1') -Force
  $script:FixtureOp=(Get-RideCatalog).Operations|Where-Object Id -eq 'windows.show-known-extensions'
  InModuleScope RIDE.UserHandoff {
    $script:FixtureOp=(Get-RideCatalog).Operations|Where-Object Id -eq 'windows.show-known-extensions'
    function script:New-HandoffTestRequest {
      [pscustomobject]@{SchemaVersion=1;RequestId=('b'*32);Root=$script:HandoffRoot;SourceHash=('A'*64);TargetSid='S-1-5-21-1-2-3-1001';SessionId=2;ShellProcessId=123;Command='set';RunId='';Items=@([pscustomobject]@{Id=$script:FixtureOp.Id;State='Enabled';ContractHash=Get-RideHandoffHash $script:FixtureOp});Library=@();Confirm=$false}
    }
  }
}
Describe 'Desktop-user launch preparation' {
  BeforeEach {
    Mock Get-RideDesktopHandoffContext -ModuleName RIDE.UserHandoff {[pscustomobject]@{TargetSid='S-1-5-21-1-2-3-1001';SessionId=2;ShellProcessId=123;ShellElevated=$false;CurrentSessionId=2;CurrentSid='S-1-5-21-1-2-3-500';CurrentElevated=$true}}
    Mock Get-RideHandoffSourceHash -ModuleName RIDE.UserHandoff {'A'*64}
    Mock Get-RideHandoffPlan -ModuleName RIDE.UserHandoff {@([pscustomobject]@{Operation=$script:FixtureOp;State='Enabled'})}
    Mock Start-RideHandoffShellProcess -ModuleName RIDE.UserHandoff {}
  }
  It 'returns a launch receipt without claiming completion or using the administrator SID' {
    $r=Start-RideDesktopUserHandoff set -Id windows.show-known-extensions -State Enabled -Confirm:$false
    $r.Status|Should -Be 'Launched';$r.TargetSid|Should -Be 'S-1-5-21-1-2-3-1001';$r.CompletionVerified|Should -BeFalse
    Should -Invoke Start-RideHandoffShellProcess -ModuleName RIDE.UserHandoff -Exactly 1
  }
  It 'starts no process under WhatIf' {
    $r=Start-RideDesktopUserHandoff set -Id windows.show-known-extensions -State Enabled -WhatIf
    $r.Status|Should -Be 'NotLaunched'
    Should -Invoke Start-RideHandoffShellProcess -ModuleName RIDE.UserHandoff -Exactly 0
  }
  It 'refuses a different desktop session' {
    Mock Get-RideDesktopHandoffContext -ModuleName RIDE.UserHandoff {[pscustomobject]@{TargetSid='S-1-5-21-1-2-3-1001';SessionId=3;ShellProcessId=123;ShellElevated=$false;CurrentSessionId=2}}
    {Start-RideDesktopUserHandoff set -Id fixture -State Enabled -Confirm:$false}|Should -Throw '*current session*'
    Should -Invoke Start-RideHandoffShellProcess -ModuleName RIDE.UserHandoff -Exactly 0
  }
  It 'refuses an absent desktop without preparing engine work' {
    Mock Get-RideDesktopHandoffContext -ModuleName RIDE.UserHandoff {throw 'No desktop shell in the current session.'}
    {Start-RideDesktopUserHandoff set -Id fixture -State Enabled -Confirm:$false}|Should -Throw '*No desktop shell*'
    Should -Invoke Get-RideHandoffPlan -ModuleName RIDE.UserHandoff -Exactly 0
    Should -Invoke Start-RideHandoffShellProcess -ModuleName RIDE.UserHandoff -Exactly 0
  }
  It 'refuses an elevated desktop shell' {
    Mock Get-RideDesktopHandoffContext -ModuleName RIDE.UserHandoff {[pscustomobject]@{TargetSid='S-1-5-21-1-2-3-1001';SessionId=2;ShellProcessId=123;ShellElevated=$true;CurrentSessionId=2}}
    {Start-RideDesktopUserHandoff set -Id fixture -State Enabled -Confirm:$false}|Should -Throw '*unelevated*'
    Should -Invoke Start-RideHandoffShellProcess -ModuleName RIDE.UserHandoff -Exactly 0
  }
  It 'rejects machine and mixed selections before launch' {
    InModuleScope RIDE.UserHandoff {
      $machine=$script:FixtureOp.Clone();$machine.Scope='Machine';$machine.RequiresAdmin=$true
      Mock Get-RideHandoffPlan {@([pscustomobject]@{Operation=$script:FixtureOp;State='Enabled'},[pscustomobject]@{Operation=$machine;State='Enabled'})}
      {Start-RideDesktopUserHandoff apply -Profile fixture -Confirm:$false}|Should -Throw '*user-only settings*'
      Should -Invoke Start-RideHandoffShellProcess -Exactly 0
    }
  }
  It 'rejects user packages before launch' {
    InModuleScope RIDE.UserHandoff {
      $package=$script:FixtureOp.Clone();$package.Kind='Package'
      Mock Get-RideHandoffPlan {@([pscustomobject]@{Operation=$package;State='Present'})}
      {Start-RideDesktopUserHandoff apply -Profile fixture -Confirm:$false}|Should -Throw '*package actions*'
      Should -Invoke Start-RideHandoffShellProcess -Exactly 0
    }
  }
  It 'requires a bounded saved run identity for restore' {
    {Start-RideDesktopUserHandoff restore -RunId '../other-user' -Confirm:$false}|Should -Throw '*32-character*'
    Should -Invoke Start-RideHandoffShellProcess -ModuleName RIDE.UserHandoff -Exactly 0
  }
  It 'encodes command data without interpolating a state into executable source' {
    InModuleScope RIDE.UserHandoff {
      Mock Get-RideHandoffPlan {@([pscustomobject]@{Operation=$script:FixtureOp;State='quote"; Write-Error injected'})}
      Mock Start-RideHandoffShellProcess {param($Context,$Arguments)$script:CapturedArguments=$Arguments}
      $null=Start-RideDesktopUserHandoff set -Id fixture -State fixture -Confirm:$false
      $script:CapturedArguments|Should -Match '^-NoProfile -NoExit -EncodedCommand [A-Za-z0-9+/=]+$'
      $code=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(($script:CapturedArguments -split ' ')[-1]))
      $code|Should -Not -Match 'Write-Error injected'
      $code|Should -Not -Match 'ExecutionPolicy|Credential|runas'
    }
  }
}
Describe 'Desktop worker preflight and recovery' {
  BeforeEach {
    Mock Get-RideDesktopHandoffContext -ModuleName RIDE.UserHandoff {[pscustomobject]@{TargetSid='S-1-5-21-1-2-3-1001';SessionId=2;ShellProcessId=123;ShellElevated=$false;CurrentSessionId=2;CurrentSid='S-1-5-21-1-2-3-1001';CurrentElevated=$false}}
    Mock Get-RideHandoffSourceHash -ModuleName RIDE.UserHandoff {'A'*64}
    Mock Import-Module -ModuleName RIDE.UserHandoff {}
    Mock Set-RideLibraryContext -ModuleName RIDE.UserHandoff {}
    Mock Get-RideSingleOperationPlan -ModuleName RIDE.UserHandoff {@([pscustomobject]@{Operation=$script:FixtureOp;State='Enabled'})}
    Mock Invoke-RidePlan -ModuleName RIDE.UserHandoff {'Run ID: '+('c'*32)}
    Mock Restore-RideRun -ModuleName RIDE.UserHandoff {}
    Mock Show-RidePlan -ModuleName RIDE.UserHandoff {}
  }
  It 'applies the validated user plan with saved-run output' {
    InModuleScope RIDE.UserHandoff {
      Invoke-RideDesktopUserRequest (New-HandoffTestRequest)|Should -Match '^Run ID:'
      Should -Invoke Invoke-RidePlan -Exactly 1
    }
  }
  It 'shows a plan without invoking apply' {
    InModuleScope RIDE.UserHandoff {
      $r=New-HandoffTestRequest;$r.Command='plan';Invoke-RideDesktopUserRequest $r
      Should -Invoke Show-RidePlan -Exactly 1;Should -Invoke Invoke-RidePlan -Exactly 0
    }
  }
  It 'forwards the explicit confirmation choice to the child engine' {
    InModuleScope RIDE.UserHandoff {
      $r=New-HandoffTestRequest;$r.Confirm=$true;Invoke-RideDesktopUserRequest $r
      Should -Invoke Invoke-RidePlan -Exactly 1 -ParameterFilter {$Confirm -eq $true}
    }
  }
  It 'refuses source drift during plan preparation before the first apply' {
    InModuleScope RIDE.UserHandoff {
      $script:HashCalls=0
      Mock Get-RideHandoffSourceHash {$script:HashCalls++;if($script:HashCalls -eq 1){'A'*64}else{'B'*64}}
      {Invoke-RideDesktopUserRequest (New-HandoffTestRequest)}|Should -Throw '*during desktop preflight*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
  }
  It 'refuses malformed frozen items before the first apply' {
    InModuleScope RIDE.UserHandoff {
      $r=New-HandoffTestRequest;$r.Items[0]=[pscustomobject]@{Id=$script:FixtureOp.Id;ArbitraryState='Enabled';ContractHash=('A'*64)}
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*Invalid desktop plan item*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
  }
  It 'rejects the wrong user before engine loading' {
    InModuleScope RIDE.UserHandoff {
      $r=New-HandoffTestRequest;$r.TargetSid='S-1-5-21-1-2-3-500'
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*identity/session/elevation mismatch*'
      Should -Invoke Import-Module -Exactly 0;Should -Invoke Invoke-RidePlan -Exactly 0
    }
  }
  It 'rejects a changed shell process before engine loading' {
    InModuleScope RIDE.UserHandoff {
      $r=New-HandoffTestRequest;$r.ShellProcessId=999
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*identity/session/elevation mismatch*'
      Should -Invoke Import-Module -Exactly 0
    }
  }
  It 'rejects an elevated worker before engine loading' {
    Mock Get-RideDesktopHandoffContext -ModuleName RIDE.UserHandoff {[pscustomobject]@{TargetSid='S-1-5-21-1-2-3-1001';SessionId=2;ShellProcessId=123;ShellElevated=$false;CurrentSessionId=2;CurrentSid='S-1-5-21-1-2-3-1001';CurrentElevated=$true}}
    InModuleScope RIDE.UserHandoff {
      {Invoke-RideDesktopUserRequest (New-HandoffTestRequest)}|Should -Throw '*identity/session/elevation mismatch*'
      Should -Invoke Import-Module -Exactly 0
    }
  }
  It 'rejects changed source and operation contracts before apply' {
    InModuleScope RIDE.UserHandoff {
      $r=New-HandoffTestRequest;$r.SourceHash='B'*64
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*source changed*'
      $r=New-HandoffTestRequest;$r.Items[0].ContractHash='B'*64
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*operation contract changed*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
  }
  It 'rejects unknown request fields' {
    InModuleScope RIDE.UserHandoff {
      $r=New-HandoffTestRequest;$r|Add-Member NoteProperty ArbitraryCommand 'script'
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*Invalid desktop handoff request*'
      Should -Invoke Import-Module -Exactly 0
    }
  }
  It 'does not trust a machine operation returned for a user request' {
    InModuleScope RIDE.UserHandoff {
      $machine=$script:FixtureOp.Clone();$machine.Scope='Machine';$machine.RequiresAdmin=$true
      Mock Get-RideSingleOperationPlan {@([pscustomobject]@{Operation=$machine;State='Enabled'})}
      $r=New-HandoffTestRequest;$r.Items[0].ContractHash=Get-RideHandoffHash $machine
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*user-only settings*'
      Should -Invoke Invoke-RidePlan -Exactly 0
    }
  }
  It 'recovers only a saved run in the actual user namespace' {
    InModuleScope RIDE.UserHandoff -Parameters @{FixtureRoot=$TestDrive} {
      $script:TestStateRoot=$FixtureRoot
      Mock Get-RideHandoffUserStateRoot {$script:TestStateRoot}
      Mock Get-RideCatalog {@{Operations=@($script:FixtureOp)}}
      $id='d'*32;$dir=Join-Path $FixtureRoot $id;$null=New-Item -ItemType Directory -Path $dir
      @{SchemaVersion=1;RunId=$id;Scopes=@('User');OperationIds=@($script:FixtureOp.Id)}|ConvertTo-Json|Set-Content (Join-Path $dir '_manifest.json')
      $recordPath=Join-Path $dir ($script:FixtureOp.Id+'.json')
      @{SchemaVersion=1;RunId=$id;OperationId=$script:FixtureOp.Id;Kind=$script:FixtureOp.Kind;Scope='User'}|ConvertTo-Json|Set-Content $recordPath
      $r=New-HandoffTestRequest;$r.Command='restore';$r.RunId=$id;$r.Items=@()
      Invoke-RideDesktopUserRequest $r;Should -Invoke Restore-RideRun -Exactly 1
      @{RunId=$id;Scopes=@('User','Machine')}|ConvertTo-Json|Set-Content (Join-Path $dir '_manifest.json')
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*user-only saved manifest*'
      Should -Invoke Restore-RideRun -Exactly 1
      @{SchemaVersion=1;RunId=$id;Scopes=@('User');OperationIds=@($script:FixtureOp.Id)}|ConvertTo-Json|Set-Content (Join-Path $dir '_manifest.json')
      @{SchemaVersion=1;RunId=('e'*32);OperationId=$script:FixtureOp.Id;Kind=$script:FixtureOp.Kind;Scope='User'}|ConvertTo-Json|Set-Content $recordPath
      {Invoke-RideDesktopUserRequest $r}|Should -Throw '*record identity changed*'
      Should -Invoke Restore-RideRun -Exactly 1
    }
  }
}
Describe 'Desktop handoff command discovery' {
  It 'completes the declared UserContext values without invoking a launcher' {
    $line='& "'+(Join-Path $script:Repo 'ride.ps1')+'" set -UserContext D'
    $completion=TabExpansion2 -InputScript $line -CursorColumn $line.Length
    @($completion.CompletionMatches.CompletionText)|Should -Contain 'Desktop'
  }
}
Describe 'CLI desktop-user routing' {
  BeforeEach {
    $script:CliRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path (Join-Path $script:CliRoot 'modules')
    $script:Cli=Join-Path $script:CliRoot 'ride.ps1'
    Copy-Item -LiteralPath (Join-Path $script:Repo 'ride.ps1') -Destination $script:Cli
    $spy=@'
function Start-RideDesktopUserHandoff {
 [CmdletBinding(SupportsShouldProcess)]
 param($Command,$Id,$State,$RunId,$Library,$Profile)
 [pscustomobject]@{Command=$Command;Id=$Id;State=$State;WhatIf=[bool]$WhatIfPreference;ConfirmBound=$PSBoundParameters.ContainsKey('Confirm');Confirm=[bool]$PSBoundParameters['Confirm']}
}
Export-ModuleMember -Function Start-RideDesktopUserHandoff
'@
    [IO.File]::WriteAllText((Join-Path $script:CliRoot 'modules/RIDE.UserHandoff.psm1'),$spy,[Text.UTF8Encoding]::new($false))
  }
  AfterEach {
    Get-Module -All|Where-Object {$_.Path -and $_.Path.StartsWith($script:CliRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)}|Remove-Module -Force
  }
  It 'routes a user setting and preview without loading an operational engine' {
    $r=& $script:Cli set windows.show-known-extensions Enabled -UserContext Desktop -WhatIf -Confirm:$false
    $r.Command|Should -Be set;$r.Id|Should -Be windows.show-known-extensions;$r.State|Should -Be Enabled
    $r.WhatIf|Should -BeTrue;$r.ConfirmBound|Should -BeTrue;$r.Confirm|Should -BeFalse
  }
  It 'refuses unsupported commands before importing the handoff' {
    {& $script:Cli install package.7zip -UserContext Desktop}|Should -Throw '*supports set*'
    {& $script:Cli status -UserContext Desktop}|Should -Throw '*supports set*'
  }
  It 'refuses package authentication options on a desktop-user setting' {
    {& $script:Cli apply -UserContext Desktop -GitHubAuthentication Anonymous}|Should -Throw '*not supported by desktop-user*'
  }
  It 'refuses a profile attached to a direct user action' {
    {& $script:Cli unset windows.show-known-extensions -UserContext Desktop -Profile arbitrary}|Should -Throw '*do not accept -Profile*'
  }
}
