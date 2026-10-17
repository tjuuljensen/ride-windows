<#
.SYNOPSIS
  Test the power setting handler's parsing, setting, and exact restoration behavior.

.DESCRIPTION
  Mocks native power reads and powercfg writes to verify scheme selection and index lifecycle without changing
  Windows configuration.

.EXAMPLE
  Invoke-Pester .\tests\PowerSettings.Tests.ps1

.INPUTS
  None. Pester invokes the test cases.

.OUTPUTS
  Pester test results.

.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 or PowerShell 7.
  Prerequisites: Repository power setting module.
  Recovery: No system state is changed; PowrProf and powercfg are mocked.
  Author: RIDE-Windows maintainers.
  Version: 0.3.0
  Changelog: 0.3.0: Verify typed native reads and read-time plan drift.
    0.2.0: Exercise unsigned boundaries, legacy recovery and snapshot validation.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $script:RepositoryRoot 'modules/RIDE-PowerSettings.psm1') -Force -Global
  $script:PowerOperation = @{
    Id = 'windows.lid-close-action-ac'
    PowerIndex = 'AC'
    PowerSubgroupGuid = '4f971e89-eebd-4455-a8de-9e59040e7347'
    PowerSettingGuid = '5ca83367-6e45-459f-a27b-476b1d01c936'
    States = @{ DoNothing = 0; Sleep = 1 }
  }
}

Describe 'RIDE power setting handler' {
  BeforeEach {
    Mock Get-RideNativeActivePowerScheme -ModuleName RIDE-PowerSettings {'381b4222-f694-41f0-9685-ff5bb260df2e'}
    Mock Get-RideNativePowerIndex -ModuleName RIDE-PowerSettings {[pscustomobject]@{Available=$true;Index=[uint32]$script:PowercfgIndex;ErrorCode=0}}
  }
  It 'reads the active scheme and selected AC index' {
    Mock Get-RideNativePowerIndex -ModuleName RIDE-PowerSettings {[pscustomobject]@{Available=$true;Index=[uint32]1;ErrorCode=0}}

    $state = Get-RidePowerSettingState -Operation $script:PowerOperation

    $state.SchemeGuid | Should -Be '381b4222-f694-41f0-9685-ff5bb260df2e'
    $state.Index | Should -Be 1
    $state.PowerIndex | Should -Be 'AC'
  }

  It 'reports a device without the requested setting as unavailable' {
    Mock Get-RideNativePowerIndex -ModuleName RIDE-PowerSettings {[pscustomobject]@{Available=$false;Index=$null;ErrorCode=2}}

    $state = Get-RidePowerSettingState -Operation $script:PowerOperation

    $state.Available | Should -BeFalse
    $state.Index | Should -BeNullOrEmpty
    $state.NativeErrorCode | Should -Be 2
  }

  It 'refuses an active-plan change during index inspection' {
    InModuleScope RIDE-PowerSettings {$script:ActiveReadCalls=0}
    Mock Get-RideNativeActivePowerScheme -ModuleName RIDE-PowerSettings {
      $script:ActiveReadCalls++
      if($script:ActiveReadCalls -eq 1){'381b4222-f694-41f0-9685-ff5bb260df2e'}else{'aaaaaaaa-1111-1111-1111-111111111111'}
    }
    {Get-RidePowerSettingState -Operation $PowerOperation} | Should -Throw '*changed during inspection*'
    Should -Invoke Get-RideNativePowerIndex -ModuleName RIDE-PowerSettings -Exactly 1
  }

  It 'queries an explicit saved scheme without selecting or reading the active scheme' {
    $operation=$PowerOperation.Clone();$operation.PowerIndex='DC'
    $saved='aaaaaaaa-1111-1111-1111-111111111111'
    $state=Get-RidePowerSettingState -Operation $operation -SchemeGuid $saved
    $state.SchemeGuid | Should -BeExactly $saved
    $state.PowerIndex | Should -BeExactly DC
    Should -Invoke Get-RideNativeActivePowerScheme -ModuleName RIDE-PowerSettings -Exactly 0
    Should -Invoke Get-RideNativePowerIndex -ModuleName RIDE-PowerSettings -Exactly 1 -ParameterFilter {$SchemeGuid -eq [guid]$saved -and $PowerIndex -eq 'DC'}
  }

  It 'does not translate a provider failure into absent hardware' {
    Mock Get-RideNativePowerIndex -ModuleName RIDE-PowerSettings {throw 'Read failed with code 5'}
    {Get-RidePowerSettingState -Operation $PowerOperation} | Should -Throw '*code 5*'
  }

  It 'changes only the declared AC index and verifies the resulting state' {
    $script:PowercfgIndex = 0
    Mock Invoke-RidePowercfg -ModuleName RIDE-PowerSettings {
      if ($Arguments[0] -eq '/setacvalueindex') { $script:PowercfgIndex = [int]$Arguments[4] }
      if ($Arguments[0] -eq '/setdcvalueindex') { throw 'Unexpected DC write' }
      [pscustomobject]@{ ExitCode = 0; Output = '' }
    }

    Set-RidePowerSettingState -Operation $script:PowerOperation -State Sleep

    $script:PowercfgIndex | Should -Be 1
    Should -Invoke Invoke-RidePowercfg -ModuleName RIDE-PowerSettings -Times 1 -ParameterFilter { $Arguments[0] -eq '/setacvalueindex' }
  }

  It 'restores the exact captured index in the captured scheme' {
    $script:PowercfgIndex = 0
    $script:PowercfgCalls = [System.Collections.Generic.List[object]]::new()
    Mock Invoke-RidePowercfg -ModuleName RIDE-PowerSettings {
      $script:PowercfgCalls.Add(@($Arguments))
      [pscustomobject]@{ ExitCode = 0; Output = '' }
    }

    Restore-RidePowerSettingState -Operation $script:PowerOperation -Snapshot @{ SchemeGuid = '381b4222-f694-41f0-9685-ff5bb260df2e'; Index = 0 }

    @($script:PowercfgCalls | Where-Object { $_[0] -eq '/setacvalueindex' }).Count | Should -Be 1
    $restoreCall = $script:PowercfgCalls | Where-Object { $_[0] -eq '/setacvalueindex' } | Select-Object -First 1
    $restoreCall[4] | Should -Be '0'
  }
}

Describe 'Unsigned power index capture and compatible recovery' {
  BeforeEach {
    Mock Invoke-RidePowercfg -ModuleName RIDE-PowerSettings { throw 'Unexpected native call' }
  }
  It 'retains native UInt32 value <Hex> without signed conversion' -ForEach @(
    @{Hex='00000000';Expected=[uint32]0},@{Hex='7fffffff';Expected=[uint32]2147483647},
    @{Hex='80000000';Expected=[uint32]2147483648},@{Hex='ffffffff';Expected=[uint32]4294967295}
  ) {
    InModuleScope RIDE-PowerSettings -Parameters @{Hex=$Hex;Expected=$Expected;Op=$PowerOperation} {
      param($Hex,$Expected,$Op)
      $script:NativeFixture=$Expected
      Mock Get-RideNativePowerIndex {[pscustomobject]@{Available=$true;Index=$script:NativeFixture;ErrorCode=0}}
      $r=Get-RidePowerSettingState -Operation $Op -SchemeGuid '381b4222-f694-41f0-9685-ff5bb260df2e'
      $r.Index | Should -Be $Expected
      $r.Index | Should -BeOfType ([uint32])
      $r.IndexEncoding | Should -BeExactly UInt32
    }
  }
  It 'restores <Case> as unsigned decimal without switching another active plan' -ForEach @(
    @{Case='new maximum';Index=[uint32]4294967295;Encoding='UInt32';Expected='4294967295'},
    @{Case='legacy signed minus one';Index=-1;Encoding=$null;Expected='4294967295'},
    @{Case='legacy signed minimum';Index=[int32]::MinValue;Encoding=$null;Expected='2147483648'},
    @{Case='legacy ordinary';Index=600;Encoding=$null;Expected='600'}
  ) {
    InModuleScope RIDE-PowerSettings -Parameters @{Index=$Index;Encoding=$Encoding;Expected=$Expected;Op=$PowerOperation} {
      param($Index,$Encoding,$Expected,$Op)
      $script:ExpectedIndex=[uint32]$Expected
      Mock Get-RidePowerSettingState {
        if($SchemeGuid){[pscustomobject]@{Available=$true;Index=$script:ExpectedIndex;SchemeGuid=$SchemeGuid}}
        else{[pscustomobject]@{Available=$true;Index=0;SchemeGuid='aaaaaaaa-1111-1111-1111-111111111111'}}
      }
      Mock Invoke-RidePowercfg {[pscustomobject]@{ExitCode=0;Output=''}}
      $snapshot=@{SchemeGuid='381b4222-f694-41f0-9685-ff5bb260df2e';Index=$Index}
      if($Encoding){$snapshot.IndexEncoding=$Encoding;$snapshot.SnapshotVersion=1;$snapshot.PowerIndex='AC'}
      $json=$snapshot|ConvertTo-Json|ConvertFrom-Json
      Restore-RidePowerSettingState -Operation $Op -Snapshot $json
      Should -Invoke Invoke-RidePowercfg -Exactly 1 -ParameterFilter {$Arguments[0] -eq '/setacvalueindex' -and $Arguments[1] -eq $snapshot.SchemeGuid -and $Arguments[4] -ceq $Expected}
      Should -Invoke Invoke-RidePowercfg -Exactly 0 -ParameterFilter {$Arguments[0] -eq '/setactive'}
      $json.Index | Should -Be $Index
    }
  }
  It 'refuses malformed snapshot <Case> before any native write' -ForEach @(
    @{Case='marked negative';Changes=@{Index=-1;IndexEncoding='UInt32'}},
    @{Case='negative overflow';Changes=@{Index=[long]-2147483649}},
    @{Case='unsigned overflow';Changes=@{Index=[long]4294967296}},
    @{Case='fraction';Changes=@{Index=1.5}},
    @{Case='boolean';Changes=@{Index=$true}},
    @{Case='string';Changes=@{Index='600'}},
    @{Case='null';Changes=@{Index=$null}},
    @{Case='unknown encoding';Changes=@{IndexEncoding='Future'}},
    @{Case='future version';Changes=@{SnapshotVersion=2}},
    @{Case='missing versioned fields';Changes=@{SnapshotVersion=1}},
    @{Case='invalid GUID';Changes=@{SchemeGuid='SCHEME_CURRENT'}},
    @{Case='wrong power source';Changes=@{PowerIndex='DC'}},
    @{Case='empty power source';Changes=@{PowerIndex=''}}
  ) {
    $snapshot=@{SchemeGuid='381b4222-f694-41f0-9685-ff5bb260df2e';Index=600}
    foreach($key in $Changes.Keys){$snapshot[$key]=$Changes[$key]}
    {Restore-RidePowerSettingState -Operation $PowerOperation -Snapshot $snapshot} | Should -Throw
    Should -Invoke Invoke-RidePowercfg -ModuleName RIDE-PowerSettings -Exactly 0
  }
  It 'refuses an invalid oversized index from the read boundary' {
    Mock Get-RideNativePowerIndex -ModuleName RIDE-PowerSettings {[pscustomobject]@{Available=$true;Index=[long]4294967296;ErrorCode=0}}
    {Get-RidePowerSettingState -Operation $PowerOperation -SchemeGuid '381b4222-f694-41f0-9685-ff5bb260df2e'} | Should -Throw
  }
  It 'refuses invalid desired indexes before discovery or write' {
    $invalid=$PowerOperation.Clone();$invalid.States=@{Invalid=-1}
    {Set-RidePowerSettingState -Operation $invalid -State Invalid} | Should -Throw '*UInt32*'
    Should -Invoke Invoke-RidePowercfg -ModuleName RIDE-PowerSettings -Exactly 0
  }
}

Describe 'RIDE power setting engine integration' {
  It 'reports a high unsigned live index as Custom and saves it without narrowing' {
    InModuleScope RIDE.Engine -Parameters @{EvidenceRoot=$TestDrive} {
      param($EvidenceRoot)
      $script:PowerSnapshotRoot=$EvidenceRoot
      Mock Initialize-RideStateRoot {$script:PowerSnapshotRoot}
      $operation=Get-RideOperation -Id 'windows.display-idle-timeout-ac'
      $live=[pscustomobject]@{Available=$true;Index=[uint32]4294967295;SchemeGuid='381b4222-f694-41f0-9685-ff5bb260df2e';PowerIndex='AC'}
      (Get-RideCurrentStateName -Operation $operation -CurrentState $live) | Should -Be Custom
      (Test-RideCurrentStateMatch -Operation $operation -State Never -CurrentState $live) | Should -BeFalse
      Save-RideOperationSnapshot -RunId 'unsigned-fixture' -Operation $operation -CurrentState $live -DesiredState Never
      $path=Join-Path $EvidenceRoot 'unsigned-fixture/windows.display-idle-timeout-ac.json'
      $record=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
      $record.SchemaVersion | Should -Be 1
      $record.Snapshot.SnapshotVersion | Should -Be 1
      $record.Snapshot.Index | Should -Be 4294967295
      $record.Snapshot.IndexEncoding | Should -BeExactly UInt32
      $record.Snapshot.PowerIndex | Should -BeExactly AC
    }
  }
  It 'builds a standard Set plan for a catalog power setting' {
    InModuleScope RIDE.Engine {
      $plan = @(Get-RideSingleOperationPlan -Id 'windows.lid-close-action-ac' -Action Set -State Sleep)
      $plan.Count | Should -Be 1
      $plan[0].Operation.Kind | Should -Be 'PowerSetting'
      $plan[0].State | Should -Be 'Sleep'
    }
  }

  It 'compares supported and unavailable current states without confusing index zero with availability' {
    InModuleScope RIDE.Engine {
      $operation = Get-RideOperation -Id 'windows.lid-close-action-ac'
      $sleep = [pscustomobject]@{ Available = $true; Index = 1 }
      $doNothing = [pscustomobject]@{ Available = $true; Index = 0 }
      $unavailable = [pscustomobject]@{ Available = $false; Index = $null }

      (Test-RideCurrentStateMatch -Operation $operation -State 'Sleep' -CurrentState $sleep) | Should -BeTrue
      (Test-RideCurrentStateMatch -Operation $operation -State 'Sleep' -CurrentState $doNothing) | Should -BeFalse
      (Test-RideCurrentStateMatch -Operation $operation -State 'DoNothing' -CurrentState $unavailable) | Should -BeFalse
      (Get-RideCurrentStateName -Operation $operation -CurrentState $unavailable) | Should -Be 'Unavailable'
    }
  }
}
