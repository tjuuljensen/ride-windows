<#
.SYNOPSIS
  Verify read-only network adapter observations using mocked providers and saved data.
.DESCRIPTION
  Tests explicit target guards, GUID selection, incomplete identities, provider failures,
  bounded capture, completion and exclusive JSON output. No live adapter, connection,
  binding, registry or network provider is queried or changed.
.EXAMPLE
  Invoke-Pester .\tests\AdapterInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native provider acceptance remains pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.AdapterInventory.psm1') -Force
  function New-AdapterContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true}
  }
  function New-AdapterRow {
    [pscustomobject]@{InterfaceGuid='{ABCDEF01-1111-1111-1111-111111111111}';Name='Ethernet [2]';InterfaceDescription='Fixture adapter';InterfaceIndex=12;Status='Disconnected';HardwareInterface=$true;Virtual=$false;ConnectorPresent=$true}
  }
  function New-AdapterObservation {
    [pscustomobject]@{
      SchemaVersion=1;Kind='NetworkAdapterObservation';Status='Captured';WindowsContext=New-AdapterContext
      Coverage='Fixture visible and hidden adapter rows';ReadyForMutation=$false;RecoverySupported=$false
      Adapters=@([pscustomobject]@{InterfaceGuid='abcdef01-1111-1111-1111-111111111111';IdentityStatus='Identified';Name='Ethernet [2]';InterfaceIndex=12;StatusObserved='Disconnected';Selected=$false})
    }
  }
}
Describe 'Read-only adapter capture' {
  BeforeEach {
    $script:CaptureArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional'}
    Mock Get-RideAdapterInventoryContext -ModuleName RIDE.AdapterInventory {New-AdapterContext}
    Mock Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory {New-AdapterRow}
  }
  It 'captures GUID identity separately from mutable aliases and indexes' {
    $r=Get-RideNetworkAdapterInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Adapters.Count | Should -Be 1
    $r.Adapters[0].InterfaceGuid | Should -BeExactly 'abcdef01-1111-1111-1111-111111111111'
    $r.Adapters[0].Name | Should -BeExactly 'Ethernet [2]'
    $r.Adapters[0].InterfaceIndex | Should -Be 12
    $r.Adapters[0].StatusObserved | Should -Be Disconnected
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    Should -Invoke Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory -Exactly 1
  }
  It 'refuses <Field> target mismatch before querying adapters' -ForEach @(
    @{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedBuild';Value='26101'},@{Field='ExpectedEditionId';Value='Enterprise'}
  ) {
    $mismatch=$CaptureArgs.Clone();$mismatch[$Field]=$Value
    {Get-RideNetworkAdapterInventory @mismatch} | Should -Throw '*target differs*'
    Should -Invoke Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory -Exactly 0
  }
  It 'refuses a non-native process before adapter collection' {
    Mock Get-RideAdapterInventoryContext -ModuleName RIDE.AdapterInventory {$c=New-AdapterContext;$c.NativeProcess=$false;$c}
    {Get-RideNetworkAdapterInventory @CaptureArgs} | Should -Throw '*target differs*'
    Should -Invoke Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory -Exactly 0
  }
  It 'rejects target drift after a provider completes' {
    InModuleScope RIDE.AdapterInventory {$script:ContextCalls=0}
    Mock Get-RideAdapterInventoryContext -ModuleName RIDE.AdapterInventory {$script:ContextCalls++;$c=New-AdapterContext;$c.UpdateBuildRevision=$script:ContextCalls;$c}
    {Get-RideNetworkAdapterInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'keeps missing or empty GUID rows visible but unselectable' {
    Mock Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory {
      $a=New-AdapterRow;$a.InterfaceGuid=$null;$a.HardwareInterface=$null;$a.Virtual=$null;$a.ConnectorPresent=$null;$a
      $b=New-AdapterRow;$b.InterfaceGuid=[guid]::Empty;$b
    }
    $r=Get-RideNetworkAdapterInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Adapters.Count | Should -Be 2
    foreach($a in $r.Adapters){$a.InterfaceGuid | Should -BeNullOrEmpty;$a.IdentityStatus | Should -Be Unavailable}
    $r.Adapters[0].HardwareInterface | Should -BeNullOrEmpty
  }
  It 'distinguishes captured empty from a failed or partially completed provider' {
    Mock Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory {}
    $r=Get-RideNetworkAdapterInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Adapters.Count | Should -Be 0
    Mock Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory {New-AdapterRow;throw 'private driver diagnostic'}
    $r=Get-RideNetworkAdapterInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Adapters | Should -BeNullOrEmpty
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'private driver diagnostic'
  }
  It 'discards duplicate GUIDs instead of choosing a matching alias' {
    Mock Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory {New-AdapterRow;$b=New-AdapterRow;$b.Name='Other alias';$b}
    (Get-RideNetworkAdapterInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'refuses invalid literal provider metadata for <Field>' -ForEach @(
    @{Field='InterfaceGuid';Value='not-a-guid'},@{Field='InterfaceIndex';Value='12'},
    @{Field='InterfaceIndex';Value=-1},@{Field='InterfaceIndex';Value=1.25},
    @{Field='HardwareInterface';Value='False'},@{Field='Name';Value="invalid`nname"}
  ) {
    $invalidRow=New-AdapterRow;$invalidRow.$Field=$Value
    InModuleScope RIDE.AdapterInventory -Parameters @{InvalidRow=$invalidRow} {
      param($InvalidRow)
      $script:InvalidRow=$InvalidRow
      Mock Get-RideAdapterInventoryRows {$script:InvalidRow}
    }
    (Get-RideNetworkAdapterInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'bounds output even when a provider emits too many unidentified rows' {
    Mock Get-RideAdapterInventoryRows -ModuleName RIDE.AdapterInventory {1..513|ForEach-Object {$r=New-AdapterRow;$r.InterfaceGuid=$null;$r}}
    $r=Get-RideNetworkAdapterInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Adapters | Should -BeNullOrEmpty
  }
}
Describe 'Saved adapter lookup and completion' {
  It 'uses GUID identity across a renamed alias and accepts Windows GUID casing' {
    $saved=New-AdapterObservation;$saved.Adapters[0].Name='Renamed';$saved.Adapters[0].InterfaceIndex=51
    $json=$saved|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $r=Find-RideNetworkAdapterObservation $json '{ABCDEF01-1111-1111-1111-111111111111}'
    $r.Status | Should -Be Observed
    $r.Observation.Name | Should -BeExactly Renamed
    $r.ReadyForMutation | Should -BeFalse
    {Find-RideNetworkAdapterObservation $json Renamed} | Should -Throw '*GUID*'
  }
  It 'keeps missing and unavailable distinct and never falls back to another adapter' {
    $saved=New-AdapterObservation
    (Find-RideNetworkAdapterObservation $saved 'bbbbbbbb-2222-2222-2222-222222222222').Status | Should -Be NotObserved
    $saved.Status='Unavailable';$saved.Adapters=$null
    (Find-RideNetworkAdapterObservation $saved 'bbbbbbbb-2222-2222-2222-222222222222').Status | Should -Be Unavailable
  }
  It 'rejects malformed saved identities, partial rows and unknown schemas' {
    $saved=New-AdapterObservation;$saved.Adapters+=@($saved.Adapters[0])
    {Find-RideNetworkAdapterObservation $saved 'abcdef01-1111-1111-1111-111111111111'} | Should -Throw '*duplicate*'
    $saved=New-AdapterObservation;$saved.Status='Unavailable'
    {Find-RideNetworkAdapterObservation $saved 'abcdef01-1111-1111-1111-111111111111'} | Should -Throw '*cannot contain rows*'
    $saved=New-AdapterObservation;$saved.SchemaVersion=2
    {Find-RideNetworkAdapterObservation $saved 'abcdef01-1111-1111-1111-111111111111'} | Should -Throw '*schema*'
    {Find-RideNetworkAdapterObservation (New-AdapterObservation) '00000000-0000-0000-0000-000000000000'} | Should -Throw '*nonempty*'
  }
  It 'completes only identified saved GUIDs with filtering and duplicate suppression' {
    $saved=New-AdapterObservation;$saved.Adapters+=@($saved.Adapters[0],[pscustomobject]@{InterfaceGuid=$null;IdentityStatus='Unavailable'})
    $attr=(Get-Command Find-RideNetworkAdapterObservation).Parameters.InterfaceGuid.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 'ABC' $null @{Inventory=$saved})
    $matches.Count | Should -Be 1
    $matches[0].CompletionText | Should -BeExactly "'abcdef01-1111-1111-1111-111111111111'"
    @(& $attr.ScriptBlock '' '' 'missing' $null @{Inventory=$saved}).Count | Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count | Should -Be 0
    $saved.Status='Unavailable'
    @(& $attr.ScriptBlock '' '' '' $null @{Inventory=$saved}).Count | Should -Be 0
  }
}
Describe 'Adapter inventory export boundaries' {
  BeforeEach {
    $script:ExportArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';OutputPath=(Join-Path $TestDrive 'adapters.json')}
    Mock Import-Module {}
    Mock Get-RideNetworkAdapterInventory {New-AdapterObservation}
  }
  It 'previews without querying Windows or creating output' {
    & (Join-Path $Root 'tools/Export-RideAdapterInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideNetworkAdapterInventory -Exactly 0
  }
  It 'creates UTF-8 JSON and refuses existing output without truncation' {
    & (Join-Path $Root 'tools/Export-RideAdapterInventory.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before|ConvertFrom-Json).Kind | Should -Be NetworkAdapterObservation
    {& (Join-Path $Root 'tools/Export-RideAdapterInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly $before
  }
  It 'refuses a racing output file created during collection' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'racing-adapters.json'
    Mock Get-RideNetworkAdapterInventory {[IO.File]::WriteAllText((Join-Path $TestDrive 'racing-adapters.json'),'other writer');New-AdapterObservation}
    {& (Join-Path $Root 'tools/Export-RideAdapterInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    Should -Invoke Get-RideNetworkAdapterInventory -Exactly 1
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
  }
}
