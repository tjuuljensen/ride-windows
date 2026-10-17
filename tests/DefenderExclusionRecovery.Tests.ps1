<#
.SYNOPSIS
  Verify captured-path Defender exclusion writes and recovery without Windows changes.
.DESCRIPTION
  Uses mocked provider membership and isolated JSON records. No Defender cmdlet,
  registry write, protection change or workstation directory provisioning runs.
.EXAMPLE
  Invoke-Pester .\tests\DefenderExclusionRecovery.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: Repository fixture; native managed/visibility acceptance remains open.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $Root 'modules/RIDE-Defender.psm1') -Force
}
Describe 'Defender captured-path apply and recovery' {
  BeforeEach {
    InModuleScope RIDE-Defender {
      $script:ObservedExclusions=@()
      $script:Operation=@{Id='test.tools';PathResolver='ToolsDirectory'}
      Mock Resolve-RideDefenderExclusionPath { 'C:\Tools' }
      Mock Get-RideDefenderExclusionPaths { $script:ObservedExclusions }
      Mock Ensure-RideDefenderExclusionDirectory {}
      Mock Add-RideDefenderExclusion { param($Path) $script:ObservedExclusions+=@($Path) }
      Mock Remove-RideDefenderExclusion { param($Path) $script:ObservedExclusions=@($script:ObservedExclusions|Where-Object {$_ -ine $Path}) }
    }
  }
  It 'refuses changed path before directory preparation or Defender mutation' {
    InModuleScope RIDE-Defender {
      { Set-RideDefenderExclusionState $Operation Present -ExpectedState @{Present=$false;Path='D:\Tools'} } | Should -Throw '*changed after capture*'
      Should -Invoke Ensure-RideDefenderExclusionDirectory -Times 0 -Exactly
      Should -Invoke Add-RideDefenderExclusion -Times 0 -Exactly
      Should -Invoke Remove-RideDefenderExclusion -Times 0 -Exactly
    }
  }
  It 'refuses changed membership even if another writer reached the requested state' {
    InModuleScope RIDE-Defender {
      $script:ObservedExclusions=@('C:\Tools')
      { Set-RideDefenderExclusionState $Operation Present -ExpectedState @{Present=$false;Path='C:\Tools'} } | Should -Throw '*changed after capture*'
      Should -Invoke Add-RideDefenderExclusion -Times 0 -Exactly
    }
  }
  It 'rejects an explicit missing capture rather than treating it as direct-call mode' {
    InModuleScope RIDE-Defender {
      { Set-RideDefenderExclusionState $Operation Present -ExpectedState $null } | Should -Throw '*capture requires*'
      Should -Invoke Ensure-RideDefenderExclusionDirectory -Times 0 -Exactly
    }
  }
  It 'binds a successful add to the captured path and preserves unrelated entries' {
    InModuleScope RIDE-Defender {
      $script:ObservedExclusions=@('D:\Unrelated')
      Set-RideDefenderExclusionState $Operation Present -ExpectedState @{Present=$false;Path='c:\tools\'}
      $script:ObservedExclusions.Count | Should -Be 2
      $script:ObservedExclusions | Should -Contain 'D:\Unrelated'
      Should -Invoke Add-RideDefenderExclusion -Times 1 -Exactly -ParameterFilter {$Path -ceq 'C:\Tools'}
    }
  }
  It 'refuses membership drift during directory preparation' {
    InModuleScope RIDE-Defender {
      Mock Ensure-RideDefenderExclusionDirectory { $script:ObservedExclusions=@('C:\Tools') }
      { Set-RideDefenderExclusionState $Operation Present -ExpectedState @{Present=$false;Path='C:\Tools'} } | Should -Throw '*during directory preparation*'
      Should -Invoke Add-RideDefenderExclusion -Times 0 -Exactly
    }
  }
  It 'reports an ignored add rather than claiming success' {
    InModuleScope RIDE-Defender {
      Mock Add-RideDefenderExclusion {}
      { Set-RideDefenderExclusionState $Operation Present } | Should -Throw '*did not report*'
    }
  }
  It 'reports an ignored remove rather than claiming success' {
    InModuleScope RIDE-Defender {
      $script:ObservedExclusions=@('C:\Tools')
      Mock Remove-RideDefenderExclusion {}
      { Set-RideDefenderExclusionState $Operation Absent } | Should -Throw '*did not report*'
    }
  }
  It 'keeps same-state direct calls idempotent' {
    InModuleScope RIDE-Defender {
      Set-RideDefenderExclusionState $Operation Absent
      $script:ObservedExclusions=@('C:\Tools')
      Set-RideDefenderExclusionState $Operation Present
      Should -Invoke Add-RideDefenderExclusion -Times 0 -Exactly
      Should -Invoke Remove-RideDefenderExclusion -Times 0 -Exactly
      Should -Invoke Ensure-RideDefenderExclusionDirectory -Times 0 -Exactly
    }
  }
  It 'restores legacy Boolean/path records at the saved path without resolving current configuration' {
    InModuleScope RIDE-Defender {
      Restore-RideDefenderExclusionState $Operation @{Present=$true;Path='D:\SavedTools'}
      Should -Invoke Resolve-RideDefenderExclusionPath -Times 0 -Exactly
      Should -Invoke Add-RideDefenderExclusion -Times 1 -Exactly -ParameterFilter {$Path -eq 'D:\SavedTools'}
      Should -Invoke Ensure-RideDefenderExclusionDirectory -Times 0 -Exactly
    }
  }
  It 'restores a JSON round-tripped versioned capture and supports a no-op retry' {
    InModuleScope RIDE-Defender {
      $saved=@{SnapshotVersion=1;OperationId='test.tools';PathResolver='ToolsDirectory';Present=$false;ExpectedPresent=$true;Path='D:\SavedTools'}|ConvertTo-Json|ConvertFrom-Json
      $script:ObservedExclusions=@('D:\SavedTools','C:\Other')
      Restore-RideDefenderExclusionState $Operation $saved
      Restore-RideDefenderExclusionState $Operation $saved
      Should -Invoke Remove-RideDefenderExclusion -Times 1 -Exactly -ParameterFilter {$Path -eq 'D:\SavedTools'}
      $script:ObservedExclusions | Should -Be @('C:\Other')
    }
  }
  It 'does not own later membership when versioned original and desired membership match' {
    InModuleScope RIDE-Defender {
      Restore-RideDefenderExclusionState $Operation @{SnapshotVersion=1;OperationId='test.tools';PathResolver='ToolsDirectory';Present=$true;ExpectedPresent=$true;Path='C:\Tools'}
      Should -Invoke Add-RideDefenderExclusion -Times 0 -Exactly
      Should -Invoke Get-RideDefenderExclusionPaths -Times 0 -Exactly
    }
  }
  It 'reports failed restore verification and retains retry compatibility' {
    InModuleScope RIDE-Defender {
      Mock Add-RideDefenderExclusion {}
      { Restore-RideDefenderExclusionState $Operation @{Present=$true;Path='C:\Tools'} } | Should -Throw '*recovery was not observed*'
    }
  }
  It 'rejects malformed recovery <Case> before provider or writer calls' -ForEach @(
    @{Case='string Boolean';Patch=@{Present='false'}},
    @{Case='missing path';Patch=@{Path=$null}},
    @{Case='future version';Patch=@{SnapshotVersion=2}},
    @{Case='null version';Patch=@{SnapshotVersion=$null}},
    @{Case='string version';Patch=@{SnapshotVersion='1'}},
    @{Case='Boolean version';Patch=@{SnapshotVersion=$true}},
    @{Case='other operation';Patch=@{OperationId='test.other'}},
    @{Case='other resolver';Patch=@{PathResolver='BootstrapDirectory'}},
    @{Case='missing expectation';Patch=@{ExpectedPresent=$null}}
  ) {
    InModuleScope RIDE-Defender -Parameters @{Patch=$Patch} {
      param($Patch)
      $saved=@{SnapshotVersion=1;OperationId='test.tools';PathResolver='ToolsDirectory';Present=$false;ExpectedPresent=$true;Path='C:\Tools'}
      foreach($key in $Patch.Keys){$saved[$key]=$Patch[$key]}
      { Restore-RideDefenderExclusionState $Operation $saved } | Should -Throw
      Should -Invoke Get-RideDefenderExclusionPaths -Times 0 -Exactly
      Should -Invoke Add-RideDefenderExclusion -Times 0 -Exactly
      Should -Invoke Remove-RideDefenderExclusion -Times 0 -Exactly
    }
  }
  It 'refuses unsafe captured path <Path>' -ForEach @(
    @{Path='C:\'},@{Path='C:\..\'},@{Path='\\server\share\'},@{Path='relative'},
    @{Path='C:Tools'},@{Path='\Tools'},@{Path='C:\Tools\*'},@{Path='%SystemDrive%\Tools'},
    @{Path='\\?\C:\Tools'},@{Path='\\.\C:\Tools'},@{Path='C:\Tools:stream'},@{Path="C:\Bad`nPath"}
  ) {
    InModuleScope RIDE-Defender -Parameters @{Path=$Path} {
      param($Path)
      { Restore-RideDefenderExclusionState $Operation @{Present=$false;Path=$Path} } | Should -Throw
      Should -Invoke Get-RideDefenderExclusionPaths -Times 0 -Exactly
      Should -Invoke Remove-RideDefenderExclusion -Times 0 -Exactly
    }
  }
  It 'accepts a literal UNC subdirectory without touching the share' {
    InModuleScope RIDE-Defender {
      ConvertTo-RideDefenderLiteralPath '\\server\share\tools\' | Should -Be '\\server\share\tools'
    }
  }
}
Describe 'Defender provider observation shape' {
  It 'rejects missing provider object or property <Case>' -ForEach @(
    @{Case='no object';Data=$null},@{Case='no property';Data=[pscustomobject]@{Other=1}},
    @{Case='multiple objects';Data=@([pscustomobject]@{ExclusionPath=@()},[pscustomobject]@{ExclusionPath=@()})}
  ) {
    InModuleScope RIDE-Defender -Parameters @{Data=$Data} {
      param($Data)
      $script:ProviderFixture=$Data
      Mock Get-RideDefenderPreferenceObservation { $script:ProviderFixture }
      { Get-RideDefenderExclusionPaths } | Should -Throw '*no usable*'
    }
  }
  It 'retains a provider null list as an observation with no visible entries' {
    InModuleScope RIDE-Defender {
      Mock Get-RideDefenderPreferenceObservation { [pscustomobject]@{ExclusionPath=$null} }
      @(Get-RideDefenderExclusionPaths).Count | Should -Be 0
    }
  }
}
Describe 'Defender versioned engine capture' {
  It 'persists operation identity, literal path and desired membership in an isolated record' {
    InModuleScope RIDE.Engine -Parameters @{FixtureRoot=$TestDrive} {
      param($FixtureRoot)
      $script:CaptureFixtureRoot=$FixtureRoot
      Mock Initialize-RideStateRoot { $script:CaptureFixtureRoot }
      $operation=Get-RideOperation 'windows.defender-tools-exclusion'
      Save-RideOperationSnapshot -RunId 'defender-fixture' -Operation $operation -CurrentState ([pscustomobject]@{Present=$false;Path='D:\Captured'}) -DesiredState Present
      $saved=Get-Content -LiteralPath (Join-Path $FixtureRoot 'defender-fixture/windows.defender-tools-exclusion.json') -Raw|ConvertFrom-Json
      $saved.Snapshot.SnapshotVersion | Should -Be 1
      $saved.Snapshot.OperationId | Should -Be $operation.Id
      $saved.Snapshot.PathResolver | Should -Be 'ToolsDirectory'
      $saved.Snapshot.Path | Should -Be 'D:\Captured'
      $saved.Snapshot.Present | Should -BeFalse
      $saved.Snapshot.ExpectedPresent | Should -BeTrue
    }
  }
}
