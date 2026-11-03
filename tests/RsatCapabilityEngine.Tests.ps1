<#
.SYNOPSIS
  Verify RSAT catalog expansion, partial recovery and native-handler guards with mocks.
.EXAMPLE
  Invoke-Pester ./tests/RsatCapabilityEngine.Tests.ps1
.NOTES
  Pester 5, native Windows PowerShell 5.1/PowerShell 7. Version: 0.1.0.
  Servicing, target, privilege and registry observations are mocked; files use TestDrive.
#>
BeforeAll { Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force }
Describe 'RSAT catalog group and dependency recovery' {
  BeforeEach {
    InModuleScope RIDE.Engine -Parameters @{Root=$TestDrive} {
      $script:rsatRoot=Join-Path $Root ([guid]::NewGuid().ToString('N'))
      $script:rsatContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26300';EditionId='EnterpriseEval';UpdateBuildRevision=9711;ProductType='WinNT';InstallationType='Client';NativeProcess=$true;Architecture='AMD64'}
      $script:rsatStates=@{'Rsat.ServerManager.Tools~~~~0.0.1.0'='NotPresent';'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'='NotPresent';'Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0'='NotPresent';'Rsat.Dns.Tools~~~~0.0.1.0'='Installed'}
      $script:rsatCalls=[Collections.Generic.List[string]]::new()
      Mock Get-RidePlatform {'Windows 11'}
      Mock Test-RideAdministrator {$true}
      Mock Get-ItemProperty {[pscustomobject]@{CurrentBuildNumber='26300';InstallationType='Client'}}
      Mock Get-RideStateRoot {Join-Path $script:rsatRoot $Scope}
      Mock Initialize-RideStateRoot {$p=Join-Path $script:rsatRoot $Scope;New-Item -ItemType Directory -Path $p -Force|Out-Null;$p}
      Mock Get-RideRsatCapabilityInventory {
        [pscustomobject]@{SchemaVersion=1;Kind='WindowsComponentObservation';ReadyForMutation=$false;RecoverySupported=$false;WindowsContext=$script:rsatContext;Providers=@([pscustomobject]@{Kind='Capability';Status='Captured';Rows=@($script:rsatStates.Keys|ForEach-Object {[pscustomobject]@{Name=$_;StateObserved=$script:rsatStates[$_]}})})}
      }
      Mock Get-RideClientCapabilityState {
        [pscustomobject]@{Available=$true;Present=($script:rsatStates[$Operation.CapabilityName] -ceq 'Installed');CapabilityState=$script:rsatStates[$Operation.CapabilityName];Observation=[pscustomobject]@{CapabilityName=$Operation.CapabilityName;ServicingSource='WindowsUpdate';WindowsContext=$script:rsatContext}}
      }
      Mock Set-RideClientCapabilityState {
        $script:rsatCalls.Add('apply:'+ $Operation.Id)
        $script:rsatStates[$Operation.CapabilityName]=if($State -eq 'Present'){'Installed'}else{'NotPresent'}
      }
      Mock Restore-RideClientCapabilityState {
        if(-not $ValidateOnly){$script:rsatCalls.Add('restore:'+$Operation.Id);$script:rsatStates[$Operation.CapabilityName]=$Snapshot.CapabilityState}
      }
    }
  }
  It 'selects every observed group member and includes already installed state explicitly' {
    InModuleScope RIDE.Engine {
      $plan=@(Get-RideSingleOperationPlan -Id solution.rsat-client-tools -Action Install)
      $plan.Count | Should -Be 4
      $plan.Operation.Id | Should -Contain 'component.rsat-dns'
      $plan.Operation.Id | Should -Not -Contain 'component.rsat-wsus'
      foreach($item in $plan){$item.RsatObservedNames.Count|Should -Be 4}
    }
  }
  It 'adds transitive prerequisites for a single selected capability' {
    InModuleScope RIDE.Engine {
      $plan=@(Get-RideSingleOperationPlan -Id component.rsat-bitlocker-recovery -Action Install)
      $plan.Operation.Id | Should -Be @('component.rsat-server-manager','component.rsat-active-directory','component.rsat-bitlocker-recovery')
    }
  }
  It 'refuses removing a prerequisite still used outside the selected removal plan' {
    InModuleScope RIDE.Engine {
      $script:rsatStates['Rsat.ServerManager.Tools~~~~0.0.1.0']='Installed'
      $script:rsatStates['Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0']='Installed'
      {Get-RideSingleOperationPlan -Id component.rsat-server-manager -Action Remove} | Should -Throw '*Remove RSAT dependent*'
      Should -Invoke Set-RideClientCapabilityState -Exactly 0
    }
  }
  It 'previews the full group without snapshots or writers' {
    InModuleScope RIDE.Engine {
      Mock Save-RideOperationSnapshot {}
      $plan=@(Get-RideSingleOperationPlan -Id solution.rsat-client-tools -Action Install)
      Invoke-RidePlan $plan -WhatIf | Out-Null
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Set-RideClientCapabilityState -Exactly 0
      Should -Invoke Initialize-RideStateRoot -Exactly 0
    }
  }
  It 'refuses a stale all-observed selection before any mutation' {
    InModuleScope RIDE.Engine {
      $plan=@(Get-RideSingleOperationPlan -Id solution.rsat-client-tools -Action Install)
      $script:rsatStates['Rsat.FileServices.Tools~~~~0.0.1.0']='NotPresent'
      {Invoke-RidePlan $plan -AllowCandidate -Confirm:$false} | Should -Throw '*inventory changed*'
      Should -Invoke Set-RideClientCapabilityState -Exactly 0
    }
  }
  It 'restores installed members in reverse dependency order and preserves pre-existing members' {
    InModuleScope RIDE.Engine {
      $plan=@(Get-RideSingleOperationPlan -Id solution.rsat-client-tools -Action Install)
      Invoke-RidePlan $plan -AllowCandidate -Confirm:$false | Out-Null
      $record=Get-ChildItem -LiteralPath $script:rsatRoot -Recurse -Filter 'component.rsat-server-manager.json' | Get-Content -Raw | ConvertFrom-Json
      $record.Snapshot.CapabilityDependencies.Count | Should -Be 0
      Restore-RideRun -RunId $record.RunId -AllowCandidate -Confirm:$false | Out-Null
      @($script:rsatCalls | Where-Object {$_ -like 'restore:*'}) | Should -Be @('restore:component.rsat-bitlocker-recovery','restore:component.rsat-active-directory','restore:component.rsat-server-manager')
      $script:rsatStates['Rsat.Dns.Tools~~~~0.0.1.0'] | Should -Be 'Installed'
    }
  }
  It 'retains recoverable per-member records after a partial installation failure' {
    InModuleScope RIDE.Engine {
      Mock Set-RideClientCapabilityState {
        if($Operation.Id -ceq 'component.rsat-active-directory'){throw 'RSAT partial failure fixture'}
        $script:rsatStates[$Operation.CapabilityName]='Installed'
      }
      $plan=@(Get-RideSingleOperationPlan -Id solution.rsat-client-tools -Action Install)
      {Invoke-RidePlan $plan -AllowCandidate -Confirm:$false} | Should -Throw '*Run ID:*RSAT partial failure fixture*'
      $records=@(Get-ChildItem -LiteralPath $script:rsatRoot -Recurse -Filter 'component.rsat-*.json')
      $records.Count | Should -Be 2
      $record=Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json
      Restore-RideRun -RunId $record.RunId -AllowCandidate -Confirm:$false | Out-Null
      $script:rsatStates['Rsat.ServerManager.Tools~~~~0.0.1.0'] | Should -Be 'NotPresent'
      $script:rsatStates['Rsat.Dns.Tools~~~~0.0.1.0'] | Should -Be 'Installed'
    }
  }
  It 'stops the group and retains the changed member when servicing requires a restart' {
    InModuleScope RIDE.Engine {
      Mock Set-RideClientCapabilityState {
        $script:rsatStates[$Operation.CapabilityName]='Installed'
        throw 'DISM reached the requested literal state but reports a restart is needed.'
      }
      $plan=@(Get-RideSingleOperationPlan -Id solution.rsat-client-tools -Action Install)
      {Invoke-RidePlan $plan -AllowCandidate -Confirm:$false} | Should -Throw '*Run ID:*restart is needed*'
      Should -Invoke Set-RideClientCapabilityState -Exactly 1
      $records=@(Get-ChildItem -LiteralPath $script:rsatRoot -Recurse -Filter 'component.rsat-*.json')
      $records.Count | Should -Be 1
      $record=Get-Content -LiteralPath $records[0].FullName -Raw | ConvertFrom-Json
      $record.Snapshot.CapabilityState | Should -Be 'NotPresent'
      $script:rsatStates[$record.Snapshot.CapabilityName] | Should -Be 'Installed'
      $manifest=Get-Content -LiteralPath (Join-Path $records[0].DirectoryName '_manifest.json') -Raw | ConvertFrom-Json
      @($manifest.OperationProgress | Where-Object Status -EQ Failed).Count | Should -Be 1
      Should -Invoke Restore-RideClientCapabilityState -Exactly 0
    }
  }
  It 'removes dependents first and restores removed prerequisites first' {
    InModuleScope RIDE.Engine {
      foreach($name in @($script:rsatStates.Keys)) {$script:rsatStates[$name]='Installed'}
      $plan=@(Get-RideSingleOperationPlan -Id solution.rsat-client-tools -Action Remove)
      Invoke-RidePlan $plan -AllowCandidate -Confirm:$false | Out-Null
      $calls=@($script:rsatCalls)
      [array]::IndexOf($calls,'apply:component.rsat-bitlocker-recovery') | Should -BeLessThan ([array]::IndexOf($calls,'apply:component.rsat-active-directory'))
      [array]::IndexOf($calls,'apply:component.rsat-active-directory') | Should -BeLessThan ([array]::IndexOf($calls,'apply:component.rsat-server-manager'))
      $record=Get-ChildItem -LiteralPath $script:rsatRoot -Recurse -Filter 'component.rsat-server-manager.json' | Get-Content -Raw | ConvertFrom-Json
      Restore-RideRun -RunId $record.RunId -AllowCandidate -Confirm:$false | Out-Null
      $calls=@($script:rsatCalls)
      [array]::IndexOf($calls,'restore:component.rsat-server-manager') | Should -BeLessThan ([array]::IndexOf($calls,'restore:component.rsat-active-directory'))
      [array]::IndexOf($calls,'restore:component.rsat-active-directory') | Should -BeLessThan ([array]::IndexOf($calls,'restore:component.rsat-bitlocker-recovery'))
      @($script:rsatStates.Values | Where-Object {$_ -cne 'Installed'}).Count | Should -Be 0
    }
  }
  It 'refuses recovery that would orphan a newly installed dependent' {
    InModuleScope RIDE.Engine {
      $plan=@(Get-RideSingleOperationPlan -Id component.rsat-active-directory -Action Install)
      Invoke-RidePlan $plan -AllowCandidate -Confirm:$false | Out-Null
      $script:rsatStates['Rsat.BitLocker.Recovery.Tools~~~~0.0.1.0']='Installed'
      $record=Get-ChildItem -LiteralPath $script:rsatRoot -Recurse -Filter 'component.rsat-server-manager.json' | Get-Content -Raw | ConvertFrom-Json
      {Restore-RideRun -RunId $record.RunId -AllowCandidate -Confirm:$false} | Should -Throw '*installed-state dependency mismatch*'
      Should -Invoke Restore-RideClientCapabilityState -Exactly 0 -ParameterFilter {-not $ValidateOnly}
    }
  }
  It 'completes the RSAT group from catalog data without live inventory' {
    $path=Join-Path $PSScriptRoot '../ride.ps1';$line="& '$path' install -Id solution.rsat"
    @([Management.Automation.CommandCompletion]::CompleteInput($line,$line.Length,$null).CompletionMatches.CompletionText) | Should -Contain 'solution.rsat-client-tools'
    InModuleScope RIDE.Engine {Should -Invoke Get-RideRsatCapabilityInventory -Exactly 0}
  }
}

Describe 'RSAT native handler guards' {
  BeforeEach {
    InModuleScope RIDE.ClientCapability {
      $catalog=Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')
      $script:rsatOp=$catalog.Operations|Where-Object Id -CEQ 'component.rsat-active-directory'
      $script:rsatContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26300';EditionId='EnterpriseEval';UpdateBuildRevision=9711;InstallationType='Client';ProductType='WinNT';NativeProcess=$true;Architecture='AMD64'}
      $script:nativeStates=@{'Rsat.ServerManager.Tools~~~~0.0.1.0'='NotPresent';'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'='NotPresent'}
      Mock Get-RideClientCapabilityContext {$script:rsatContext}
      Mock Test-RideClientCapabilityAdministrator {$true}
      Mock Test-RideClientCapabilityPendingReboot {$false}
      Mock Get-RideClientCapabilityNativeState {if($script:nativeStates.ContainsKey($Name)){[pscustomobject]@{Name=$Name;State=$script:nativeStates[$Name]}}}
      Mock Invoke-RideClientCapabilityNativeChange {$script:nativeStates[$Name]=$DesiredState;[pscustomobject]@{RestartNeeded=$false}}
    }
  }
  It 'requires a live installed prerequisite before adding the dependent' {
    InModuleScope RIDE.ClientCapability {
      $before=Get-RideClientCapabilityState $script:rsatOp
      {Set-RideClientCapabilityState $script:rsatOp Present $before -Confirm:$false} | Should -Throw '*prerequisite*must be installed*'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
      $script:nativeStates['Rsat.ServerManager.Tools~~~~0.0.1.0']='Installed'
      (Set-RideClientCapabilityState $script:rsatOp Present $before -Confirm:$false).CapabilityState|Should -Be 'Installed'
    }
  }
  It 'refuses removal with a live dependent and does not trust rewritten dependency metadata' {
    InModuleScope RIDE.ClientCapability {
      $script:nativeStates['Rsat.ServerManager.Tools~~~~0.0.1.0']='Installed'
      $script:nativeStates['Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0']='Installed'
      $catalog=Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')
      $parent=$catalog.Operations|Where-Object Id -CEQ 'component.rsat-server-manager'
      {Set-RideClientCapabilityState $parent Absent (Get-RideClientCapabilityState $parent) -Confirm:$false} | Should -Throw '*Remove RSAT dependent*'
      $script:rsatOp.CapabilityDependencies=@()
      {Get-RideClientCapabilityState $script:rsatOp} | Should -Throw '*metadata differs*'
      Should -Invoke Invoke-RideClientCapabilityNativeChange -Exactly 0
    }
  }
  It 'does not claim Arm64 or Home edition FOD applicability' {
    InModuleScope RIDE.ClientCapability {
      $script:rsatContext.Architecture='ARM64'
      (Get-RideClientCapabilityState $script:rsatOp).Available|Should -BeFalse
      $script:rsatContext.Architecture='AMD64';$script:rsatContext.EditionId='Core'
      (Get-RideClientCapabilityState $script:rsatOp).Available|Should -BeFalse
      Should -Invoke Get-RideClientCapabilityNativeState -Exactly 0
    }
  }
}

Describe 'RSAT catalog validation guards' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogData.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
  }
  It 'rejects broken or cyclic prerequisites without throwing an unstructured validator error' {
    foreach($scenario in @('unknown','null','cycle')) {
      $catalog=Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')
      $op=$catalog.Operations|Where-Object Id -CEQ 'component.rsat-server-manager'
      $op.CapabilityDependencies=switch($scenario){'unknown'{@('component.rsat-missing')};'null'{@($null)};'cycle'{@('component.rsat-active-directory')}}
      $problems=@(Get-RideCatalogValidationErrors -Catalog $catalog) -join ' '
      $problems | Should -Match 'RSAT prerequisite|RSAT dependency cycle|Invalid RSAT capability identity or dependency collection'
    }
  }
  It 'rejects duplicate native identities and incomplete all-observed group metadata' {
    $catalog=Import-RideCatalogData -Path (Join-Path $PSScriptRoot '../catalog/operations.psd1')
    ($catalog.Operations|Where-Object Id -CEQ 'component.rsat-dns').CapabilityName='Rsat.ServerManager.Tools~~~~0.0.1.0'
    ($catalog.Groups|Where-Object Id -CEQ 'solution.rsat-client-tools').Members=@('component.rsat-server-manager')
    $problems=@(Get-RideCatalogValidationErrors -Catalog $catalog) -join ' '
    $problems | Should -Match 'Duplicate RSAT native identity'
    $problems | Should -Match 'RSAT group must select the complete'
  }
}
