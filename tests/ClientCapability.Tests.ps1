<#
.SYNOPSIS
  Verify catalog client capability lifecycle and recovery without servicing Windows.
.DESCRIPTION
  Uses mocked DISM, identity, privilege and reboot boundaries plus TestDrive state.
.EXAMPLE
  Invoke-Pester ./tests/ClientCapability.Tests.ps1
.NOTES
  Windows PowerShell 5.1/PowerShell 7, Pester 5. Version: 0.1.0.
  No payload acquisition, native capability change or VM acceptance is performed.
#>
BeforeAll { Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force }

Describe 'OpenSSH Client conditional capability lifecycle' {
  BeforeEach {
    InModuleScope RIDE.ClientCapability {
      $script:op=@{Id='component.openssh-client-capability';Kind='WindowsCapability';Handler='ClientCapability';Scope='Machine';CapabilityName='OpenSSH.Client~~~~0.0.1.0';ServicingSource='WindowsUpdate'}
      $script:context=[pscustomobject]@{ComputerName='TEST-VM';Build='26300';EditionId='EnterpriseEval';UpdateBuildRevision=9711;InstallationType='Client';ProductType='WinNT';NativeProcess=$true}
      $script:literal='NotPresent'
      Mock Get-RideClientCapabilityContext { $script:context }
      Mock Get-RideClientCapabilityNativeState { [pscustomobject]@{Name='OpenSSH.Client~~~~0.0.1.0';State=$script:literal} }
      Mock Test-RideClientCapabilityAdministrator { $true }
      Mock Test-RideClientCapabilityPendingReboot { $false }
      Mock Invoke-RideClientCapabilityNativeChange { $script:literal=$DesiredState; [pscustomobject]@{RestartNeeded=$false} }
      $script:captured=Get-RideClientCapabilityState $script:op
      $script:snapshot=[pscustomobject]@{SnapshotVersion=2;OperationId=$script:op.Id;CapabilityName=$script:op.CapabilityName;ServicingSource='WindowsUpdate';CapabilityState='NotPresent';ExpectedState='Installed';WindowsContext=($script:context | Select-Object *)}
    }
  }
  It 'installs once and restores the original absent state without claiming payload recovery' {
    InModuleScope RIDE.ClientCapability {
      $result=Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false
      $result.CapabilityState | Should -Be 'Installed'
      $result.ExactPayloadRecoverySupported | Should -BeFalse
      (Set-RideClientCapabilityState $script:op Present (Get-RideClientCapabilityState $script:op) -Confirm:$false).Status | Should -Be 'AlreadyDesired'
      Restore-RideClientCapabilityState $script:op $script:snapshot -Confirm:$false | Out-Null
      (Restore-RideClientCapabilityState $script:op $script:snapshot -Confirm:$false).Status | Should -Be 'AlreadyRestored'
      $script:literal | Should -Be 'NotPresent'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 2
    }
  }
  It 'restores a prior installed state through the declared acquisition route' {
    InModuleScope RIDE.ClientCapability {
      $script:literal='Installed'
      $script:snapshot.CapabilityState='Installed';$script:snapshot.ExpectedState='NotPresent'
      Set-RideClientCapabilityState $script:op Absent (Get-RideClientCapabilityState $script:op) -Confirm:$false | Out-Null
      Restore-RideClientCapabilityState $script:op $script:snapshot -Confirm:$false | Out-Null
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 1 -ParameterFilter {$DesiredState -ceq 'Installed' -and $Name -ceq 'OpenSSH.Client~~~~0.0.1.0'}
    }
  }
  It 'previews apply and restore without a servicing writer' {
    InModuleScope RIDE.ClientCapability {
      Set-RideClientCapabilityState $script:op Present $script:captured -WhatIf | Out-Null
      $script:literal='Installed'
      Restore-RideClientCapabilityState $script:op $script:snapshot -WhatIf | Out-Null
      Restore-RideClientCapabilityState $script:op $script:snapshot -ValidateOnly | Out-Null
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
  It 'rejects a changed source or operation identity' {
    InModuleScope RIDE.ClientCapability {
      $script:op.ServicingSource='LocalSource'
      { Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false } | Should -Throw '*identity or servicing source*'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
  It 'refuses recovery on another machine or OS revision' {
    InModuleScope RIDE.ClientCapability {
      $script:literal='Installed'
      $script:snapshot.WindowsContext.UpdateBuildRevision=1
      { Restore-RideClientCapabilityState $script:op $script:snapshot -Confirm:$false } | Should -Throw '*target drift*'
      $script:snapshot.WindowsContext.UpdateBuildRevision=9711
      $script:snapshot.WindowsContext.ComputerName='OTHER-VM'
      { Restore-RideClientCapabilityState $script:op $script:snapshot -Confirm:$false } | Should -Throw '*target drift*'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
  It 'refuses live state drift between capture and mutation' {
    InModuleScope RIDE.ClientCapability {
      $script:literal='Installed'
      { Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false } | Should -Throw '*state drifted*'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
  It 'fails closed on pending states and provider errors' {
    InModuleScope RIDE.ClientCapability {
      $script:literal='InstallPending'
      (Get-RideClientCapabilityState $script:op).Available | Should -BeFalse
      { Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false } | Should -Throw '*unavailable*'
      Mock Get-RideClientCapabilityNativeState { throw 'provider unavailable' }
      (Get-RideClientCapabilityState $script:op).Available | Should -BeFalse
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
  It 'rejects a server or non-native process before querying capabilities' {
    InModuleScope RIDE.ClientCapability {
      $script:context.ProductType='ServerNT'
      (Get-RideClientCapabilityState $script:op).Available | Should -BeFalse
      $script:context.ProductType='WinNT';$script:context.NativeProcess=$false
      (Get-RideClientCapabilityState $script:op).Available | Should -BeFalse
      # One query came from the BeforeEach capture; invalid contexts add none.
      Should -Invoke Get-RideClientCapabilityNativeState -Exactly 1
    }
  }
  It 'retains elevation and pending-reboot guards' {
    InModuleScope RIDE.ClientCapability {
      Mock Test-RideClientCapabilityAdministrator { $false }
      { Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false } | Should -Throw '*existing elevation*'
      Mock Test-RideClientCapabilityAdministrator { $true }
      Mock Test-RideClientCapabilityPendingReboot { $true }
      { Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false } | Should -Throw '*restart is pending*'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
  It 'does not report success when DISM returns without the requested state' {
    InModuleScope RIDE.ClientCapability {
      Mock Invoke-RideClientCapabilityNativeChange { [pscustomobject]@{RestartNeeded=$true} }
      { Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false } | Should -Throw '*did not reach the requested literal state*'
    }
  }
  It 'stops after DISM requests a restart even when literal readback matches' {
    InModuleScope RIDE.ClientCapability {
      Mock Invoke-RideClientCapabilityNativeChange { $script:literal=$DesiredState; [pscustomobject]@{RestartNeeded=$true} }
      { Set-RideClientCapabilityState $script:op Present $script:captured -Confirm:$false } | Should -Throw '*reached the requested literal state*restart is needed*'
      $script:literal | Should -Be 'Installed'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 1
    }
  }
  It 'also stops a recovery that reaches its state but requests a restart' {
    InModuleScope RIDE.ClientCapability {
      $script:literal='Installed'
      Mock Invoke-RideClientCapabilityNativeChange { $script:literal=$DesiredState; [pscustomobject]@{RestartNeeded=$true} }
      { Restore-RideClientCapabilityState $script:op $script:snapshot -Confirm:$false } | Should -Throw '*restart is needed*retain the saved run*'
      $script:literal | Should -Be 'NotPresent'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 1
    }
  }
  It 'rejects a mismatched recovery identity before calling DISM' {
    InModuleScope RIDE.ClientCapability {
      $script:snapshot.CapabilityName='OpenSSH.Server~~~~0.0.1.0'
      { Restore-RideClientCapabilityState $script:op $script:snapshot -Confirm:$false } | Should -Throw '*recovery identity*'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
}

Describe 'Catalog client capability engine integration' {
  BeforeEach {
    InModuleScope RIDE.Engine -Parameters @{Root=$TestDrive} {
      $script:clientTestRoot=Join-Path $Root ([guid]::NewGuid().ToString('N'))
      $script:clientOp=Get-RideOperation component.openssh-client-capability
      $script:clientPlan=@([pscustomobject]@{Operation=$script:clientOp;State='Present'})
      $script:clientState=[pscustomobject]@{Available=$true;Present=$false;CapabilityState='NotPresent';Observation=[pscustomobject]@{CapabilityName=$script:clientOp.CapabilityName;ServicingSource='WindowsUpdate';WindowsContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26300';EditionId='EnterpriseEval';UpdateBuildRevision=9711;InstallationType='Client';ProductType='WinNT';NativeProcess=$true}}}
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-ItemProperty { [pscustomobject]@{CurrentBuildNumber='26300';InstallationType='Client'} }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideClientCapabilityState { $script:clientState }
      Mock Get-RideStateRoot { Join-Path $script:clientTestRoot $Scope }
      Mock Initialize-RideStateRoot { $root=Join-Path $script:clientTestRoot $Scope; New-Item -ItemType Directory -Path $root -Force | Out-Null; $root }
      Mock Set-RideClientCapabilityState {}
      Mock Restore-RideClientCapabilityState {}
    }
  }
  It 'discovers the capability with source and conditional recovery, without server surfaces' {
    InModuleScope RIDE.Engine {
      $script:clientOp.SupportedTargets.Count | Should -Be 0
      $script:clientOp.CandidateTargets | Should -Be @('Windows 11')
      $script:clientOp.ServicingSource | Should -Be 'WindowsUpdate'
      Get-RideCurrentValueText $script:clientOp $script:clientState | Should -Not -Match 'sshd|TCP/22'
      (Get-RideSingleOperationPlan -Id $script:clientOp.Id -Action Remove).State | Should -Be 'Absent'
    }
  }
  It 'previews without snapshots or a writer and still requires actual candidate opt-in' {
    InModuleScope RIDE.Engine {
      Mock Save-RideOperationSnapshot {}
      Invoke-RidePlan $script:clientPlan -WhatIf | Out-Null
      { Invoke-RidePlan $script:clientPlan -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideClientCapabilityState -Exactly 0
      Should -Invoke Initialize-RideStateRoot -Exactly 0
    }
  }
  It 'persists source and target recovery identity before the mutation handler' {
    InModuleScope RIDE.Engine {
      Mock Set-RideClientCapabilityState {
        $saved=@(Get-ChildItem -LiteralPath $script:clientTestRoot -Recurse -Filter 'component.openssh-client-capability.json')
        $saved.Count | Should -Be 1
        $record=Get-Content -LiteralPath $saved[0].FullName -Raw | ConvertFrom-Json
        $record.Snapshot.SnapshotVersion | Should -Be 2
        $record.Snapshot.CapabilityState | Should -Be 'NotPresent'
        $record.Snapshot.ExpectedState | Should -Be 'Installed'
        $record.Snapshot.ServicingSource | Should -Be 'WindowsUpdate'
        $record.Snapshot.WindowsContext.Build | Should -Be '26300'
      }
      Invoke-RidePlan $script:clientPlan -AllowCandidate -Confirm:$false | Out-Null
      Should -Invoke Set-RideClientCapabilityState -Exactly 1
      $record=Get-ChildItem -LiteralPath $script:clientTestRoot -Recurse -Filter 'component.openssh-client-capability.json' | Get-Content -Raw | ConvertFrom-Json
      Restore-RideRun -RunId $record.RunId -AllowCandidate -Confirm:$false | Out-Null
      Should -Invoke Restore-RideClientCapabilityState -Exactly 1 -ParameterFilter {$ValidateOnly -and $Snapshot.ServicingSource -ceq 'WindowsUpdate' -and $Snapshot.SnapshotVersion -eq 2}
      Should -Invoke Restore-RideClientCapabilityState -Exactly 1 -ParameterFilter {-not $ValidateOnly -and $Snapshot.ServicingSource -ceq 'WindowsUpdate' -and $Snapshot.SnapshotVersion -eq 2}
    }
  }
  It 'does not call the writer if durable snapshot capture fails' {
    InModuleScope RIDE.Engine {
      Mock Save-RideOperationSnapshot { throw 'snapshot fixture failed' }
      { Invoke-RidePlan $script:clientPlan -AllowCandidate -Confirm:$false } | Should -Throw '*snapshot fixture failed*'
      Should -Invoke Set-RideClientCapabilityState -Exactly 0
    }
  }
  It 'retains the captured state and reports the run when the servicing writer fails' {
    InModuleScope RIDE.Engine {
      Mock Set-RideClientCapabilityState { throw 'DISM fixture failed' }
      { Invoke-RidePlan $script:clientPlan -AllowCandidate -Confirm:$false } | Should -Throw '*Run ID:*DISM fixture failed*'
      @(Get-ChildItem -LiteralPath $script:clientTestRoot -Recurse -Filter 'component.openssh-client-capability.json').Count | Should -Be 1
    }
  }
  It 'completes the catalog capability ID without querying native state' {
    $path=Join-Path $PSScriptRoot '../ride.ps1'
    $line="& '$path' install -Id component.openssh-cl"
    @([Management.Automation.CommandCompletion]::CompleteInput($line,$line.Length,$null).CompletionMatches.CompletionText) | Should -Contain 'component.openssh-client-capability'
    InModuleScope RIDE.Engine { Should -Invoke Get-RideClientCapabilityState -Exactly 0 }
  }
}
