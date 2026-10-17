<#
.SYNOPSIS
  Test component observation boundaries without querying Windows servicing.
.DESCRIPTION
  Mocks identity, elevation and providers. Checks target guards, complete/failed
  enumerations, namespace separation, unavailable and missing states, completion
  and preview/non-overwriting export using temporary files only.
.EXAMPLE
  Invoke-Pester .\tests\ComponentInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture. No live DISM, Server Manager or registry writes.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.ComponentInventory.psm1') -Force
  function New-ComponentContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;ProductType='WinNT';NativeProcess=$true}
  }
  function New-ComponentObservation {
    [pscustomobject]@{SchemaVersion=1;Kind='WindowsComponentObservation';Providers=@(
      [pscustomobject]@{Kind='OptionalFeature';Status='Captured';Coverage='Foundation';Rows=@([pscustomobject]@{Name='TelnetClient';StateObserved='Disabled'})},
      [pscustomobject]@{Kind='Capability';Status='Unavailable';Rows=$null;Coverage='Capabilities'}
    )}
  }
}
Describe 'Component provider capture guards and observations' {
  BeforeEach {
    $script:CaptureArgs=@{Kind=@('OptionalFeature','Capability');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';LogDirectory=$TestDrive}
    Mock Test-RideComponentInventoryAdministrator -ModuleName RIDE.ComponentInventory {$true}
    Mock Get-RideComponentWindowsContext -ModuleName RIDE.ComponentInventory {New-ComponentContext}
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {
      param($Kind)
      if($Kind -eq 'OptionalFeature'){[pscustomobject]@{FeatureName='TelnetClient';State='Disabled'}}
      elseif($Kind -eq 'Capability'){[pscustomobject]@{Name='OpenSSH.Client~~~~0.0.1.0';State='Installed'}}
      else{[pscustomobject]@{Name='RSAT';InstallState='Available'}}
    }
  }
  It 'refuses missing elevation without invoking a provider' {
    Mock Test-RideComponentInventoryAdministrator -ModuleName RIDE.ComponentInventory {$false}
    {Get-RideWindowsComponentInventory @CaptureArgs} | Should -Throw '*existing elevation*'
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'refuses machine, edition and build mismatch before invoking providers' {
    foreach($field in @('ExpectedComputerName','ExpectedBuild','ExpectedEditionId')){
      $mismatchedTarget=$CaptureArgs.Clone();$mismatchedTarget[$field]='12345'
      {Get-RideWindowsComponentInventory @mismatchedTarget} | Should -Throw '*target differs*'
    }
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'refuses nonnative process and unknown product type' {
    Mock Get-RideComponentWindowsContext -ModuleName RIDE.ComponentInventory {$v=New-ComponentContext;$v.NativeProcess=$false;$v}
    {Get-RideWindowsComponentInventory @CaptureArgs} | Should -Throw '*target differs*'
    Mock Get-RideComponentWindowsContext -ModuleName RIDE.ComponentInventory {$v=New-ComponentContext;$v.ProductType='Unknown';$v}
    {Get-RideWindowsComponentInventory @CaptureArgs} | Should -Throw '*target differs*'
  }
  It 'refuses repeated providers regardless of casing' {
    $CaptureArgs.Kind=@('Capability','capability')
    {Get-RideWindowsComponentInventory @CaptureArgs} | Should -Throw '*only once*'
  }
  It 'refuses a missing evidence directory before querying providers' {
    $CaptureArgs.LogDirectory=Join-Path $TestDrive 'missing'
    {Get-RideWindowsComponentInventory @CaptureArgs} | Should -Throw '*existing local directory*'
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'keeps namespaces and literal states separate without selecting or inferring sources' {
    $r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers.Count | Should -Be 2
    $r.Providers[0].Rows[0].StateObserved | Should -Be Disabled
    $r.Providers[1].Rows[0].Name | Should -Be 'OpenSSH.Client~~~~0.0.1.0'
    $r.Providers[1].Rows[0].SourceAvailability | Should -Be Unknown
    $r.Providers[1].Rows[0].Selected | Should -BeFalse
    $r.Providers[0].LogPath | Should -Not -Be $r.Providers[1].LogPath
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    $r | ConvertTo-Json -Depth 10 | ConvertFrom-Json | ForEach-Object {
      (Find-RideWindowsComponentObservation -Inventory $_ -Kind OptionalFeature -Name TelnetClient).Status | Should -Be Observed
    }
  }
  It 'canonicalizes provider argument casing' {
    $CaptureArgs.Kind=@('capability')
    $r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers[0].Kind | Should -BeExactly Capability
    (Find-RideWindowsComponentObservation -Inventory $r -Kind capability -Name 'OpenSSH.Client~~~~0.0.1.0').Status | Should -Be Observed
  }
  It 'retains unknown future native states rather than interpreting them as absent' {
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {[pscustomobject]@{FeatureName='FutureFeature';State='FutureServicingState'}}
    $CaptureArgs.Kind=@('OptionalFeature');$r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers[0].Rows[0].StateObserved | Should -Be FutureServicingState
  }
  It 'distinguishes an empty completed enumeration from a failed one' {
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {param($Kind) if($Kind -eq 'Capability'){throw 'Unavailable'}}
    $r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers[0].Status | Should -Be Captured
    $r.Providers[0].Rows.Count | Should -Be 0
    $r.Providers[1].Status | Should -Be Unavailable
    $r.Providers[1].Rows | Should -BeNullOrEmpty
    (Find-RideWindowsComponentObservation -Inventory $r -Kind OptionalFeature -Name Missing).Status | Should -Be NotObserved
    (Find-RideWindowsComponentObservation -Inventory $r -Kind Capability -Name Missing).Status | Should -Be Unavailable
  }
  It 'discards partial rows after an enumeration error' {
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {[pscustomobject]@{FeatureName='First';State='Enabled'};throw 'Provider failed after first row'}
    $CaptureArgs.Kind=@('OptionalFeature');$r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers[0].Status | Should -Be Unavailable
    $r.Providers[0].Rows | Should -BeNullOrEmpty
  }
  It 'refuses duplicate, missing identity and missing state provider data' {
    $CaptureArgs.Kind=@('OptionalFeature')
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {[pscustomobject]@{FeatureName='A';State='Enabled'};[pscustomobject]@{FeatureName='a';State='Enabled'}}
    (Get-RideWindowsComponentInventory @CaptureArgs).Providers[0].Status | Should -Be Unavailable
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {[pscustomobject]@{FeatureName='';State='Enabled'}}
    (Get-RideWindowsComponentInventory @CaptureArgs).Providers[0].Status | Should -Be Unavailable
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {[pscustomobject]@{FeatureName='A';State=$null}}
    (Get-RideWindowsComponentInventory @CaptureArgs).Providers[0].Status | Should -Be Unavailable
  }
  It 'does not invoke Server Manager on a known client OS' {
    $CaptureArgs.Kind=@('ServerFeature');$r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers[0].Status | Should -Be NotApplicable
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'queries selected Server Manager features on a server and retains InstallState' {
    Mock Get-RideComponentWindowsContext -ModuleName RIDE.ComponentInventory {$v=New-ComponentContext;$v.ProductType='ServerNT';$v}
    $CaptureArgs.Kind=@('ServerFeature');$r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers[0].Rows[0].StateObserved | Should -Be Available
    $r.Providers[0].LogPath | Should -BeNullOrEmpty
  }
  It 'refuses target update drift after collection' {
    InModuleScope RIDE.ComponentInventory {$script:ContextCount=0}
    Mock Get-RideComponentWindowsContext -ModuleName RIDE.ComponentInventory {$script:ContextCount++;$v=New-ComponentContext;$v.UpdateBuildRevision=$script:ContextCount;$v}
    {Get-RideWindowsComponentInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'discards a provider that exceeds the row bound' {
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {1..4097 | ForEach-Object {[pscustomobject]@{FeatureName=('Feature'+$_);State='Enabled'}}}
    $CaptureArgs.Kind=@('OptionalFeature');$r=Get-RideWindowsComponentInventory @CaptureArgs
    $r.Providers[0].Status | Should -Be Unavailable
    $r.Providers[0].Rows | Should -BeNullOrEmpty
  }
}
Describe 'Saved component lookup and completion' {
  It 'does not confuse missing, uncollected and unavailable namespaces' {
    $data=New-ComponentObservation
    (Find-RideWindowsComponentObservation -Inventory $data -Kind OptionalFeature -Name Missing).Status | Should -Be NotObserved
    (Find-RideWindowsComponentObservation -Inventory $data -Kind Capability -Name Missing).Status | Should -Be Unavailable
    (Find-RideWindowsComponentObservation -Inventory $data -Kind ServerFeature -Name Missing).Status | Should -Be NotCollected
    (Find-RideWindowsComponentObservation -Inventory $data -Kind OptionalFeature -Name telnetclient).Status | Should -Be NotObserved
  }
  It 'refuses malformed, duplicate or partial saved rows' {
    $data=New-ComponentObservation;$data.Providers[0].Rows+=@($data.Providers[0].Rows[0])
    {Find-RideWindowsComponentObservation -Inventory $data -Kind OptionalFeature -Name TelnetClient} | Should -Throw '*duplicate captured*'
    $data=New-ComponentObservation;$data.Providers[1].Rows=@()
    {Find-RideWindowsComponentObservation -Inventory $data -Kind OptionalFeature -Name TelnetClient} | Should -Throw '*unavailable provider*'
    $data=New-ComponentObservation;$data.Providers+=@($data.Providers[0])
    {Find-RideWindowsComponentObservation -Inventory $data -Kind OptionalFeature -Name TelnetClient} | Should -Throw '*duplicate component provider*'
  }
  It 'completes only the selected captured namespace, ignoring case and duplicates' {
    $data=New-ComponentObservation;$data.Providers[0].Rows=@([pscustomobject]@{Name="Test'Feature"},[pscustomobject]@{Name="Test'Feature"},[pscustomobject]@{Name='Other'})
    $attr=(Get-Command Find-RideWindowsComponentObservation).Parameters.Name.Attributes | Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $r=@(& $attr.ScriptBlock 'Find-RideWindowsComponentObservation' 'Name' 'TEST' $null @{Inventory=$data;Kind='OptionalFeature'})
    $r.Count | Should -Be 1
    $r[0].CompletionText | Should -Be "'Test''Feature'"
    @(& $attr.ScriptBlock '' '' '' $null @{Inventory=$data;Kind='Capability'}).Count | Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count | Should -Be 0
  }
}
Describe 'Component export file boundaries' {
  BeforeEach {
    $script:ExportArgs=@{Kind='OptionalFeature';ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';LogDirectory=$TestDrive;OutputPath=(Join-Path $TestDrive 'components.json')}
    Mock Import-Module {}
    Mock Get-RideWindowsComponentInventory {New-ComponentObservation}
  }
  It 'previews without querying or creating files' {
    & (Join-Path $script:Root 'tools/Export-RideComponentInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideWindowsComponentInventory -Exactly 0
  }
  It 'exports JSON and preserves existing evidence' {
    & (Join-Path $script:Root 'tools/Export-RideComponentInventory.ps1') @ExportArgs | Should -Be $ExportArgs.OutputPath
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before | ConvertFrom-Json).Kind | Should -Be WindowsComponentObservation
    {& (Join-Path $script:Root 'tools/Export-RideComponentInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -Be $before
  }
}
