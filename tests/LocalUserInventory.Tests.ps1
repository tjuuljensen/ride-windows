<#
.SYNOPSIS
  Verify local-user identity observations with mocked providers and saved data.
.DESCRIPTION
  Covers context guards, SID selection, missing/invalid rows, bounded failure,
  completion and exclusive export. No live account, registry or credential query.
.EXAMPLE
  Invoke-Pester .\tests\LocalUserInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native provider acceptance remains pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.LocalUserInventory.psm1') -Force
  function New-LocalUserContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true}
  }
  function New-LocalUserRow {
    [pscustomobject]@{SID=[Security.Principal.SecurityIdentifier]::new('S-1-5-21-111-222-333-1001');Name='Fixture';Enabled=$true;PrincipalSource='Local';Description='Must not export';PasswordLastSet='Must not export'}
  }
  function New-LocalUserObservation {
    [pscustomobject]@{
      SchemaVersion=1;Kind='LocalUserObservation';Status='Captured';WindowsContext=New-LocalUserContext
      Coverage='Fixture local users';ReadyForMutation=$false;RecoverySupported=$false
      Users=@([pscustomobject]@{Sid='S-1-5-21-111-222-333-1001';IdentityStatus='Identified';Name='Fixture';Enabled=$true;PrincipalSource='Local';Selected=$false})
    }
  }
}
Describe 'Read-only local user capture' {
  BeforeEach {
    $script:CaptureArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional'}
    Mock Get-RideLocalUserInventoryContext -ModuleName RIDE.LocalUserInventory {New-LocalUserContext}
    Mock Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory {New-LocalUserRow}
  }
  It 'captures SID and minimal literal metadata without implying administrator viability' {
    $r=Get-RideLocalUserInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Users.Count | Should -Be 1
    $r.Users[0].Sid | Should -BeExactly 'S-1-5-21-111-222-333-1001'
    $r.Users[0].Name | Should -BeExactly Fixture
    $r.Users[0].Enabled | Should -BeTrue
    $r.Users[0].Selected | Should -BeFalse
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'Must not export|PasswordLastSet|Description'
    Should -Invoke Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory -Exactly 1
  }
  It 'refuses <Field> mismatch before collection' -ForEach @(
    @{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedBuild';Value='26101'},@{Field='ExpectedEditionId';Value='Enterprise'}
  ) {
    $argsCopy=$CaptureArgs.Clone();$argsCopy[$Field]=$Value
    {Get-RideLocalUserInventory @argsCopy} | Should -Throw '*target differs*'
    Should -Invoke Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory -Exactly 0
  }
  It 'refuses a non-native process before collection' {
    Mock Get-RideLocalUserInventoryContext -ModuleName RIDE.LocalUserInventory {$c=New-LocalUserContext;$c.NativeProcess=$false;$c}
    {Get-RideLocalUserInventory @CaptureArgs} | Should -Throw '*target differs*'
    Should -Invoke Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory -Exactly 0
  }
  It 'rejects update-revision drift during collection' {
    InModuleScope RIDE.LocalUserInventory {$script:ContextCalls=0}
    Mock Get-RideLocalUserInventoryContext -ModuleName RIDE.LocalUserInventory {$script:ContextCalls++;$c=New-LocalUserContext;$c.UpdateBuildRevision=$script:ContextCalls;$c}
    {Get-RideLocalUserInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'keeps missing SID and nullable fields visible but unselectable' {
    Mock Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory {$r=New-LocalUserRow;$r.SID=$null;$r.Enabled=$null;$r.PrincipalSource=$null;$r}
    $r=Get-RideLocalUserInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Users[0].IdentityStatus | Should -Be Unavailable
    $r.Users[0].Sid | Should -BeNullOrEmpty
    $r.Users[0].Enabled | Should -BeNullOrEmpty
    $r.Users[0].PrincipalSource | Should -BeNullOrEmpty
  }
  It 'keeps false Enabled distinct from missing and preserves source labels literally' {
    Mock Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory {$r=New-LocalUserRow;$r.Enabled=$false;$r.PrincipalSource='MicrosoftAccount';$r}
    $r=Get-RideLocalUserInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Users[0].Enabled | Should -BeFalse
    ($null -eq $r.Users[0].Enabled) | Should -BeFalse
    $r.Users[0].PrincipalSource | Should -BeExactly MicrosoftAccount
  }
  It 'distinguishes empty completion from missing or partially failed providers' {
    Mock Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory {}
    $r=Get-RideLocalUserInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Users.Count | Should -Be 0
    Mock Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory {New-LocalUserRow;throw 'private account diagnostic'}
    $r=Get-RideLocalUserInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Users | Should -BeNullOrEmpty
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'private account diagnostic'
  }
  It 'rejects duplicate SID rows instead of selecting by name' {
    Mock Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory {New-LocalUserRow;$r=New-LocalUserRow;$r.Name='Alias';$r}
    (Get-RideLocalUserInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'rejects malformed provider <Field> metadata: <Value>' -ForEach @(
    @{Field='SID';Value='Administrator'},@{Field='SID';Value='S-1-5-32-544'},
    @{Field='SID';Value='S-1-5-21-4294967296-222-333-1001'},
    @{Field='Enabled';Value='False'},@{Field='Enabled';Value=0},
    @{Field='Name';Value="bad`nname"},@{Field='Name';Value=('x'*513)},
    @{Field='PrincipalSource';Value=('x'*129)}
  ) {
    $invalid=New-LocalUserRow;$invalid.$Field=$Value
    InModuleScope RIDE.LocalUserInventory -Parameters @{Invalid=$invalid} {
      param($Invalid)
      $script:InvalidRow=$Invalid
      Mock Get-RideLocalUserInventoryRows {$script:InvalidRow}
    }
    (Get-RideLocalUserInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'bounds a provider even when all row SIDs are missing' {
    Mock Get-RideLocalUserInventoryRows -ModuleName RIDE.LocalUserInventory {1..1025|ForEach-Object {$r=New-LocalUserRow;$r.SID=$null;$r}}
    $r=Get-RideLocalUserInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Users | Should -BeNullOrEmpty
  }
}
Describe 'Saved local user lookup and completion' {
  It 'matches SID across name changes and JSON serialization' {
    $saved=New-LocalUserObservation;$saved.Users[0].Name='Renamed'
    $json=$saved|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $r=Find-RideLocalUserObservation $json 's-1-5-21-111-222-333-1001'
    $r.Status | Should -Be Observed
    $r.Observation.Name | Should -BeExactly Renamed
    $r.ReadyForMutation | Should -BeFalse
    {Find-RideLocalUserObservation $json Renamed} | Should -Throw '*SID*'
  }
  It 'does not use a recreated same-name account as a replacement SID' {
    $saved=New-LocalUserObservation;$saved.Users[0].Sid='S-1-5-21-111-222-333-1002'
    (Find-RideLocalUserObservation $saved 'S-1-5-21-111-222-333-1001').Status | Should -Be NotObserved
    $saved.Status='Unavailable';$saved.Users=$null
    (Find-RideLocalUserObservation $saved 'S-1-5-21-111-222-333-1001').Status | Should -Be Unavailable
  }
  It 'rejects duplicate or partial saved rows and unknown schemas' {
    $saved=New-LocalUserObservation;$saved.Users+=@($saved.Users[0])
    {Find-RideLocalUserObservation $saved 'S-1-5-21-111-222-333-1001'} | Should -Throw '*duplicate*'
    $saved=New-LocalUserObservation;$saved.Status='Unavailable'
    {Find-RideLocalUserObservation $saved 'S-1-5-21-111-222-333-1001'} | Should -Throw '*cannot contain rows*'
    $saved=New-LocalUserObservation;$saved.SchemaVersion=2
    {Find-RideLocalUserObservation $saved 'S-1-5-21-111-222-333-1001'} | Should -Throw '*schema*'
  }
  It 'completes saved valid SIDs only with prefix filtering and duplicate suppression' {
    $saved=New-LocalUserObservation
    $saved.Users+=@($saved.Users[0],[pscustomobject]@{Sid='S-1-5-32-544';IdentityStatus='Identified'},[pscustomobject]@{Sid='S-1-5-21-4294967296-222-333-1001';IdentityStatus='Identified'},[pscustomobject]@{Sid=$null;IdentityStatus='Unavailable'})
    $attr=(Get-Command Find-RideLocalUserObservation).Parameters.Sid.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 's-1-5-21-111' $null @{Inventory=$saved})
    $matches.Count | Should -Be 1
    $matches[0].CompletionText | Should -BeExactly "'S-1-5-21-111-222-333-1001'"
    @(& $attr.ScriptBlock '' '' 'missing' $null @{Inventory=$saved}).Count | Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count | Should -Be 0
    $saved.Status='Unavailable'
    @(& $attr.ScriptBlock '' '' '' $null @{Inventory=$saved}).Count | Should -Be 0
  }
}
Describe 'Local user export boundaries' {
  BeforeEach {
    $script:ExportArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';OutputPath=(Join-Path $TestDrive 'local-users.json')}
    Mock Import-Module {}
    Mock Get-RideLocalUserInventory {New-LocalUserObservation}
  }
  It 'previews without provider calls or output creation' {
    & (Join-Path $Root 'tools/Export-RideLocalUserInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideLocalUserInventory -Exactly 0
  }
  It 'creates JSON without truncating existing output' {
    & (Join-Path $Root 'tools/Export-RideLocalUserInventory.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before|ConvertFrom-Json).Kind | Should -Be LocalUserObservation
    {& (Join-Path $Root 'tools/Export-RideLocalUserInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly $before
  }
  It 'refuses a racing output created during collection' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'racing-users.json'
    Mock Get-RideLocalUserInventory {[IO.File]::WriteAllText((Join-Path $TestDrive 'racing-users.json'),'other writer');New-LocalUserObservation}
    {& (Join-Path $Root 'tools/Export-RideLocalUserInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
  }
}
