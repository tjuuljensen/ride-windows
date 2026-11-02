<#
.SYNOPSIS
  Verify font guest orchestration without invoking Windows font APIs.
.DESCRIPTION
  Mocks guest, registry, native enumeration and lifecycle boundaries. TestDrive
  evidence is written with user-private ACLs; no machine state is changed.
.EXAMPLE
  Invoke-Pester ./tests/FontAcceptance.Tests.ps1
.NOTES
  Compatibility: Pester 5; native PowerShell 5.1 and 7. Version: 0.1.0.
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
      Mock Read-RideFontAcceptanceSelection {$script:selection}
      Mock Get-RideFontAcceptanceSnapshot {if($script:present){$script:installed}else{$script:absent}}
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
    It 'requires all seven readback checks and both restores before passing' {
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Passed
      $result.Checks.Count|Should -Be 7
      $result.RecoveryRequired|Should -BeFalse
      $result.CrossSessionAcceptancePassed|Should -BeFalse
      $result.RestartAcceptancePassed|Should -BeFalse
      @($script:events)|Should -Be @('Preview','Install','Repeat','Remove','RestoreRemoval','RestoreInitial','RestoreInitial')
      @($result.LifecycleRuns|Where-Object {-not $_.Restored}).Count|Should -Be 0
      Should -Invoke Assert-RideFontAcceptanceRecords -Times 2 -Exactly
      Should -Invoke New-RidePrivateFileStream -Times 4 -Exactly -ParameterFilter {$Scope -ceq 'Machine'}
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
    It 'retains removal observations and both run IDs when a native name remains' {
      Mock Remove-RideMachineFonts {
        $script:present=$false;$script:absent.NativeNames=@('Synthetic Regular')
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$script:removeId}
      }
      # Return distinct observations, as the real snapshot provider does.
      Mock Get-RideFontAcceptanceSnapshot {if($script:present){$script:installed|ConvertTo-Json -Depth 10|ConvertFrom-Json}else{$script:absent|ConvertTo-Json -Depth 10|ConvertFrom-Json}}
      $result=Invoke-RideFontAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Remove
      $result.Error|Should -Match 'native enumeration'
      @($result.LifecycleRuns|Where-Object {-not $_.Restored}).Count|Should -Be 2
      $path=Join-Path $result.EvidenceDirectory 'after-removal.json'
      (Get-Content -LiteralPath $path -Raw|ConvertFrom-Json).NativeNames|Should -BeExactly 'Synthetic Regular'
      Should -Invoke Restore-RideMachineFontRun -Times 0 -Exactly
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
