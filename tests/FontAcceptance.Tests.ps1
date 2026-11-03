<#
.SYNOPSIS
  Verify font guest orchestration without invoking Windows font APIs.
.DESCRIPTION
  Mocks guest, registry, native enumeration and lifecycle boundaries. TestDrive
  evidence is written with user-private ACLs; no machine state is changed.
.EXAMPLE
  Invoke-Pester ./tests/FontAcceptance.Tests.ps1
.NOTES
  Compatibility: Pester 5; native PowerShell 5.1 and 7. Version: 0.4.0.
  Changelog: Preserve removal failures and recovery across paired process diagnostics.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.FontAcceptance.psm1') -Force}
Describe 'Guarded machine-font guest acceptance' {
  InModuleScope RIDE.FontAcceptance {
    BeforeEach {
      $script:request=[guid]::NewGuid().ToString('N')
      $script:parameters=@{RunId=$script:request;ManifestPath='synthetic-only.psd1';ExpectedComputerName='RIDE-Synthetic-VM';ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';EvidenceRoot=$TestDrive;DisposableVm=$true;Confirm=$false}
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';Revision=9711;InstallationType='Client';NativeProcess=$true;Architecture='AMD64';UserSid='S-1-5-21-1-2-3-4';SessionId=1;FontDirectory=$TestDrive;Administrator=$true;Manufacturer='Microsoft Corporation';Model='Virtual Machine';GuestMarker='1';IntegrationMarker='1';RunMarker=$script:request}
      $script:selection=@([pscustomobject]@{FileName='synthetic.ttf';FullName='Synthetic Regular';RegistryName='Synthetic Regular (TrueType)';Sha256=('A'*64)})
      $script:absent=[pscustomobject]@{Registry=[pscustomobject]@{Security='original';Rows=@()};Files=@([pscustomobject]@{File=[pscustomobject]@{Exists=$false};Registration=$null;Aliases=@()});NativeNames=@()}
      $script:registration=[pscustomobject]@{Name='Synthetic Regular (TrueType)';Kind='String';Value='synthetic.ttf'}
      $script:installed=[pscustomobject]@{Registry=[pscustomobject]@{Security='original';Rows=@($script:registration)};Files=@([pscustomobject]@{File=[pscustomobject]@{Exists=$true;Sha256=('A'*64);Security='captured';CreationUtcTicks='100';LastWriteUtcTicks='200'};Registration=$script:registration;Aliases=@('Synthetic Regular (TrueType)')});NativeNames=@('Synthetic Regular')}
      $script:present=$false;$script:events=[Collections.Generic.List[string]]::new()
      $script:installId='11111111111111111111111111111111';$script:removeId='22222222222222222222222222222222'
      Mock Get-RideFontAcceptanceContext {$script:context}
      $script:context|Add-Member NoteProperty ProcessIdentity ([pscustomobject]@{ProcessId=123;ProcessStartUtc='2026-11-03T00:00:00.0000000Z';SessionId=1})
      Mock Read-RideFontAcceptanceSelection {$script:selection}
      Mock Get-RideFontAcceptanceSnapshot {if($script:present){$script:installed}else{$script:absent}}
      Mock Get-RideFontAcceptanceFreshProcessNames {[pscustomobject]@{Status='Observed';ProcessId=456;NativeNames=@()}}
      Mock Assert-RideFontAcceptanceRecords {}
      Mock New-RidePrivateFileStream {param($Path,$Scope) & (Get-Module RIDE.PrivateFiles) {param($path) New-RidePrivateFileStream -Path $path -Scope User} $Path}
      Mock Install-RideMachineFonts {
        param($StateDirectory,$WhatIf)
        if($WhatIf){$script:events.Add('Preview');return}
        if($script:present){$script:events.Add('Repeat');return [pscustomobject]@{SchemaVersion=1;Status='AlreadyDesired'}}
        $script:events.Add('Install');$script:present=$true
        [IO.File]::WriteAllText((Join-Path $StateDirectory ($script:installId+'.fonts.intent.json')),'inert fixture')
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:installId}
      }
      Mock Remove-RideMachineFonts {
        param($OwnerRunId)
        if($OwnerRunId -cne $script:installId){throw 'Wrong owner'}
        $script:events.Add('Remove');$script:present=$false
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:removeId}
      }
      Mock Restore-RideMachineFontRun {
        param($RunId)
        $status='Restored'
        if($RunId -ceq $script:removeId){$script:events.Add('RestoreRemoval');$script:present=$true}
        elseif($RunId -ceq $script:installId){$script:events.Add('RestoreInitial');if(-not $script:present){$status='AlreadyRestored'};$script:present=$false}
        else{throw 'Wrong restore'}
        [pscustomobject]@{SchemaVersion=1;Status=$status;RunId=$RunId}
      }
    }
    It 'records the actual process without invoking font or lifecycle APIs' {
      $identity=Get-RideFontAcceptanceProcessIdentity
      $identity.ProcessId|Should -Be $PID
      $process=[Diagnostics.Process]::GetCurrentProcess()
      try{
        $identity.ProcessStartUtc|Should -BeExactly $process.StartTime.ToUniversalTime().ToString('o')
        $identity.SessionId|Should -Be $process.SessionId
      }finally{$process.Dispose()}
      $script:events.Count|Should -Be 0
    }
    It 'requires all seven readback checks and both restores before passing' {
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Passed
      $result.ProcessIdentity.ProcessId|Should -Be 123
      $result.ProcessIdentity.SessionId|Should -Be 1
      $result.Checks.Count|Should -Be 7
      $result.RecoveryRequired|Should -BeFalse
      $result.DurableLifecyclePassed|Should -BeTrue
      $result.NativeEnumerationFailures.Count|Should -Be 0
      $result.DurableRecoveryChecks.Count|Should -Be 4
      $result.CrossSessionAcceptancePassed|Should -BeFalse
      $result.RestartAcceptancePassed|Should -BeFalse
      @($script:events)|Should -Be @('Preview','Install','Repeat','Remove','RestoreRemoval','RestoreInitial','RestoreInitial')
      @($result.LifecycleRuns|Where-Object {-not $_.Restored}).Count|Should -Be 0
      Should -Invoke Assert-RideFontAcceptanceRecords -Times 2 -Exactly
      Should -Invoke New-RidePrivateFileStream -Times 6 -Exactly -ParameterFilter {$Scope -ceq 'Machine'}
      (Get-Acl -LiteralPath (Join-Path $result.EvidenceDirectory 'result.json')).AreAccessRulesProtected|Should -BeTrue
    }
    It 'previews without creating files or invoking lifecycle writers' {
      $script:context.Administrator=$false
      $result=Invoke-RideFontAcceptance @script:parameters -WhatIf
      $result.Status|Should -Be Preview
      Test-Path -LiteralPath (Join-Path $TestDrive $script:request)|Should -BeFalse
      $script:events.Count|Should -Be 0
    }
    It 'refuses workstation, wrong marker and mismatched target' {
      $script:context.Model='Workstation'
      {Invoke-RideFontAcceptance @script:parameters}|Should -Throw '*disposable Hyper-V*'
      $script:context.Model='Virtual Machine';$script:context.RunMarker='other'
      {Invoke-RideFontAcceptance @script:parameters}|Should -Throw '*correlated*'
      $script:context.RunMarker=$script:request;$script:parameters.ExpectedBuild='26100'
      {Invoke-RideFontAcceptance @script:parameters}|Should -Throw '*target differs*'
      $script:events.Count|Should -Be 0
    }
    It 'returns NotRun without elevation or for an existing selected font' {
      $script:context.Administrator=$false
      (Invoke-RideFontAcceptance @script:parameters).Reason|Should -Be ExistingElevationRequired
      $script:context.Administrator=$true;$script:present=$true
      (Invoke-RideFontAcceptance @script:parameters).Reason|Should -Be SelectedFontsMustBeInitiallyAbsent
      $script:events.Count|Should -Be 0
    }
    It 'preserves existing evidence and rejects missing evidence roots' {
      $null=New-Item -ItemType Directory -Path (Join-Path $TestDrive $script:request)
      {Invoke-RideFontAcceptance @script:parameters}|Should -Throw '*already exists*'
      $script:parameters.EvidenceRoot=Join-Path $TestDrive 'not-created'
      {Invoke-RideFontAcceptance @script:parameters}|Should -Throw '*existing local directory*'
      $script:events.Count|Should -Be 0
    }
    It 'fails and retains the install ID when native enumeration omits a font' {
      $script:installed.NativeNames=@()
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Install
      $result.RecoveryRequired|Should -BeTrue
      $result.NativeAcceptancePassed|Should -BeFalse
      $result.StateRunIds|Should -Contain $script:installId
      $script:present|Should -BeTrue
      Should -Invoke Remove-RideMachineFonts -Times 0 -Exactly
    }
    It 'fails before further mutation when machine-state permissions fail verification' {
      Mock Assert-RideFontAcceptanceRecords {throw 'Wrong machine ACL'}
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Install
      @($script:events)|Should -Be @('Preview','Install')
    }
    It 'exercises both saved restores but remains failed when only native names remain' {
      Mock Remove-RideMachineFonts {
        $script:present=$false;$script:absent.NativeNames=@('Synthetic Regular')
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:removeId}
      }
      # Return distinct observations, as the real snapshot provider does.
      Mock Get-RideFontAcceptanceSnapshot {if($script:present){$script:installed|ConvertTo-Json -Depth 10|ConvertFrom-Json}else{$script:absent|ConvertTo-Json -Depth 10|ConvertFrom-Json}}
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Complete
      $result.Reason|Should -Be NativeEnumerationMismatch
      $result.DurableLifecyclePassed|Should -BeTrue
      $result.NativeAcceptancePassed|Should -BeFalse
      $result.RecoveryRequired|Should -BeTrue
      $result.NativeEnumerationFailures|Should -Be @('Remove','RestoreInitial','RepeatRestore')
      $result.Checks|Should -Not -Contain 'RemovedToInitialState'
      $result.Checks|Should -Not -Contain 'InitialStateRestored'
      @($result.LifecycleRuns|Where-Object {-not $_.Restored}).Count|Should -Be 0
      $path=Join-Path $result.EvidenceDirectory 'after-removal.json'
      (Get-Content -LiteralPath $path -Raw|ConvertFrom-Json).NativeNames|Should -BeExactly 'Synthetic Regular'
      Should -Invoke Restore-RideMachineFontRun -Times 3 -Exactly
    }
    It 'stops before saved restores when removal changes file or registry state' {
      Mock Remove-RideMachineFonts {
        $script:present=$false;$script:absent.Registry.Security='drifted'
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:removeId}
      }
      Mock Get-RideFontAcceptanceSnapshot {if($script:present){$script:installed|ConvertTo-Json -Depth 10|ConvertFrom-Json}else{$script:absent|ConvertTo-Json -Depth 10|ConvertFrom-Json}}
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Remove
      $result.DurableLifecyclePassed|Should -BeFalse
      $result.RecoveryRequired|Should -BeTrue
      Should -Invoke Restore-RideMachineFontRun -Times 0 -Exactly
    }
    It 'retains removal failure and finishes recovery with fresh-process diagnostic <FreshStatus>' -ForEach @(
      @{FreshStatus='Observed'},@{FreshStatus='Failed'}
    ) {
      if($FreshStatus -eq 'Failed'){Mock Get-RideFontAcceptanceFreshProcessNames {throw 'Synthetic fresh reader failure'}}
      Mock Remove-RideMachineFonts {
        $script:present=$false;$script:absent.NativeNames=@('Synthetic Regular')
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:removeId}
      }
      Mock Get-RideFontAcceptanceSnapshot {if($script:present){$script:installed|ConvertTo-Json -Depth 10|ConvertFrom-Json}else{$script:absent|ConvertTo-Json -Depth 10|ConvertFrom-Json}}
      Mock Restore-RideMachineFontRun {
        param($RunId)
        if($RunId -ceq $script:removeId){$script:present=$true;return [pscustomobject]@{SchemaVersion=1;Status='Restored';RunId=$RunId}}
        $status=if($script:present){'Restored'}else{'AlreadyRestored'}
        $script:present=$false;$script:absent.NativeNames=@()
        [pscustomobject]@{SchemaVersion=1;Status=$status;RunId=$RunId}
      }
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.NativeAcceptancePassed|Should -BeFalse
      $result.DurableLifecyclePassed|Should -BeTrue
      $result.NativeEnumerationFailures|Should -Be @('Remove')
      $result.Checks|Should -Contain 'InitialStateRestored'
      $result.RemovalFreshProcessObservation.Status|Should -BeExactly $FreshStatus
      if($FreshStatus -eq 'Observed'){$result.RemovalFreshProcessObservation.ParentNativeNamesAfterFresh|Should -Be @('Synthetic Regular')}
      Test-Path -LiteralPath (Join-Path $result.EvidenceDirectory 'after-removal-fresh-process.json')|Should -BeTrue
      Should -Invoke Get-RideFontAcceptanceFreshProcessNames -Times 1 -Exactly
    }
    It 'detects recovery metadata drift and leaves the install recovery outstanding' {
      Mock Restore-RideMachineFontRun {
        param($RunId)
        if($RunId -cne $script:removeId){throw 'Unexpected subsequent recovery'}
        $script:present=$true
        $script:installed=$script:installed|ConvertTo-Json -Depth 10|ConvertFrom-Json
        $script:installed.Files[0].File.CreationUtcTicks='changed'
        [pscustomobject]@{SchemaVersion=1;Status='Restored';RunId=$RunId}
      }
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be RestoreRemoval
      $result.RecoveryRequired|Should -BeTrue
      @($result.LifecycleRuns|Where-Object {-not $_.Restored}).Count|Should -Be 2
    }
    It 'rejects mismatched registration kind and unrelated registry changes' {
      $script:installed.Files[0].Registration.Kind='ExpandString'
      {Assert-RideFontAcceptanceInstalled $script:installed $script:absent $script:selection}|Should -Throw '*readback differs*'
      $script:installed.Files[0].Registration.Kind='String'
      $script:installed.Registry.Security='different'
      {Assert-RideFontAcceptanceInstalled $script:installed $script:absent $script:selection}|Should -Throw '*Unrelated*'
    }
    It 'compiles the bounded enumeration layouts without invoking a native API' {
      Initialize-RideFontAcceptanceNative
      [Runtime.InteropServices.Marshal]::SizeOf([type][Ride.FontAcceptanceV1.LogFont])|Should -Be 92
      [Runtime.InteropServices.Marshal]::OffsetOf([type][Ride.FontAcceptanceV1.EnumFont],'FullName').ToInt32()|Should -Be 92
      [Runtime.InteropServices.Marshal]::SizeOf([type][Ride.FontAcceptanceV1.EnumFont])|Should -Be 348
    }
  }
}
