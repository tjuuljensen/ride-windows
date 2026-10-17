<#
.SYNOPSIS
  Verify read-only volume observations using mocked providers and saved data.
.DESCRIPTION
  Tests explicit target guards, GUID selection, incomplete identities, provider failures,
  bounded capture, completion and exclusive JSON output. No live volume, disk, mount,
  registry or storage provider is queried or changed.
.EXAMPLE
  Invoke-Pester .\tests\VolumeInventory.Tests.ps1
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
  Import-Module (Join-Path $Root 'modules/RIDE.VolumeInventory.psm1') -Force
  function New-VolumeContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true}
  }
  function New-VolumeRow {
    [pscustomobject]@{DeviceID='\\?\Volume{ABCDEF01-1111-1111-1111-111111111111}\';DriveLetter='D:';Label='Evidence';FileSystem='NTFS';DriveType=[uint32]3;SerialNumber=[uint32]123}
  }
  function New-VolumeObservation {
    [pscustomobject]@{
      SchemaVersion=1;Kind='VolumeObservation';Status='Captured';WindowsContext=New-VolumeContext
      Coverage='Fixture local volume rows';ReadyForMutation=$false;RecoverySupported=$false
      Volumes=@([pscustomobject]@{VolumeGuidPath='\\?\Volume{abcdef01-1111-1111-1111-111111111111}\';IdentityStatus='Identified';DriveLetter='D:';Label='Evidence';FileSystem='NTFS';DriveType=3;SerialNumber=123;Selected=$false})
    }
  }
}
Describe 'Read-only volume capture' {
  BeforeEach {
    $script:CaptureArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional'}
    Mock Get-RideVolumeInventoryContext -ModuleName RIDE.VolumeInventory {New-VolumeContext}
    Mock Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory {New-VolumeRow}
  }
  It 'captures GUID path separately from mutable letters and labels' {
    $r=Get-RideVolumeInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Volumes.Count | Should -Be 1
    $r.Volumes[0].VolumeGuidPath | Should -BeExactly '\\?\Volume{abcdef01-1111-1111-1111-111111111111}\'
    $r.Volumes[0].DriveLetter | Should -BeExactly 'D:'
    $r.Volumes[0].Label | Should -BeExactly 'Evidence'
    $r.Volumes[0].DriveType | Should -Be 3
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    Should -Invoke Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory -Exactly 1
  }
  It 'refuses <Field> target mismatch before querying volumes' -ForEach @(
    @{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedBuild';Value='26101'},@{Field='ExpectedEditionId';Value='Enterprise'}
  ) {
    $mismatch=$CaptureArgs.Clone();$mismatch[$Field]=$Value
    {Get-RideVolumeInventory @mismatch} | Should -Throw '*target differs*'
    Should -Invoke Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory -Exactly 0
  }
  It 'refuses a non-native process before volume collection' {
    Mock Get-RideVolumeInventoryContext -ModuleName RIDE.VolumeInventory {$c=New-VolumeContext;$c.NativeProcess=$false;$c}
    {Get-RideVolumeInventory @CaptureArgs} | Should -Throw '*target differs*'
    Should -Invoke Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory -Exactly 0
  }
  It 'rejects target drift after a provider completes' {
    InModuleScope RIDE.VolumeInventory {$script:ContextCalls=0}
    Mock Get-RideVolumeInventoryContext -ModuleName RIDE.VolumeInventory {$script:ContextCalls++;$c=New-VolumeContext;$c.UpdateBuildRevision=$script:ContextCalls;$c}
    {Get-RideVolumeInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'keeps missing or empty GUID rows visible but unselectable' {
    Mock Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory {
      $a=New-VolumeRow;$a.DeviceID=$null;$a.DriveLetter=$null;$a.FileSystem=$null;$a.SerialNumber=$null;$a
      $b=New-VolumeRow;$b.DeviceID='\\?\Volume{00000000-0000-0000-0000-000000000000}\';$b
    }
    $r=Get-RideVolumeInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Volumes.Count | Should -Be 2
    foreach($a in $r.Volumes){$a.VolumeGuidPath | Should -BeNullOrEmpty;$a.IdentityStatus | Should -Be Unavailable}
    $r.Volumes[0].SerialNumber | Should -BeNullOrEmpty
  }
  It 'distinguishes captured empty from a failed or partially completed provider' {
    Mock Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory {}
    $r=Get-RideVolumeInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Volumes.Count | Should -Be 0
    Mock Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory {New-VolumeRow;throw 'private driver diagnostic'}
    $r=Get-RideVolumeInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Volumes | Should -BeNullOrEmpty
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'private driver diagnostic'
  }
  It 'discards duplicate GUIDs instead of choosing a matching alias' {
    Mock Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory {New-VolumeRow;$b=New-VolumeRow;$b.DriveLetter='E:';$b}
    (Get-RideVolumeInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'refuses invalid literal provider metadata for <Field>' -ForEach @(
    @{Field='DeviceID';Value='D:'},@{Field='DeviceID';Value='\\?\Volume{abcdef01-1111-1111-1111-111111111111}'},
    @{Field='DriveType';Value='3'},@{Field='DriveType';Value=-1},@{Field='DriveType';Value=1.25},
    @{Field='SerialNumber';Value=[uint64]4294967296},@{Field='DriveLetter';Value='C:\'},@{Field='Label';Value="invalid`nlabel"}
  ) {
    $invalidRow=New-VolumeRow;$invalidRow.$Field=$Value
    InModuleScope RIDE.VolumeInventory -Parameters @{InvalidRow=$invalidRow} {
      param($InvalidRow)
      $script:InvalidRow=$InvalidRow
      Mock Get-RideVolumeInventoryRows {$script:InvalidRow}
    }
    (Get-RideVolumeInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'bounds output even when a provider emits too many unidentified rows' {
    Mock Get-RideVolumeInventoryRows -ModuleName RIDE.VolumeInventory {1..513|ForEach-Object {$r=New-VolumeRow;$r.DeviceID=$null;$r}}
    $r=Get-RideVolumeInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Volumes | Should -BeNullOrEmpty
  }
}
Describe 'Saved volume lookup and completion' {
  It 'uses GUID path identity across changed drive letters and casing' {
    $saved=New-VolumeObservation;$saved.Volumes[0].Label='Renamed';$saved.Volumes[0].DriveLetter='E:'
    $json=$saved|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $r=Find-RideVolumeObservation $json '\\?\Volume{ABCDEF01-1111-1111-1111-111111111111}\'
    $r.Status | Should -Be Observed
    $r.Observation.Label | Should -BeExactly Renamed
    $r.ReadyForMutation | Should -BeFalse
    {Find-RideVolumeObservation $json Renamed} | Should -Throw '*GUID*'
  }
  It 'keeps missing and unavailable distinct and never falls back to another volume' {
    $saved=New-VolumeObservation
    (Find-RideVolumeObservation $saved '\\?\Volume{bbbbbbbb-2222-2222-2222-222222222222}\').Status | Should -Be NotObserved
    $saved.Status='Unavailable';$saved.Volumes=$null
    (Find-RideVolumeObservation $saved '\\?\Volume{bbbbbbbb-2222-2222-2222-222222222222}\').Status | Should -Be Unavailable
  }
  It 'rejects malformed saved identities, partial rows and unknown schemas' {
    $saved=New-VolumeObservation;$saved.Volumes+=@($saved.Volumes[0])
    {Find-RideVolumeObservation $saved '\\?\Volume{abcdef01-1111-1111-1111-111111111111}\'} | Should -Throw '*duplicate*'
    $saved=New-VolumeObservation;$saved.Status='Unavailable'
    {Find-RideVolumeObservation $saved '\\?\Volume{abcdef01-1111-1111-1111-111111111111}\'} | Should -Throw '*cannot contain rows*'
    $saved=New-VolumeObservation;$saved.SchemaVersion=2
    {Find-RideVolumeObservation $saved '\\?\Volume{abcdef01-1111-1111-1111-111111111111}\'} | Should -Throw '*schema*'
    {Find-RideVolumeObservation (New-VolumeObservation) '\\?\Volume{00000000-0000-0000-0000-000000000000}\'} | Should -Throw '*nonempty*'
  }
  It 'completes only identified saved GUIDs with filtering and duplicate suppression' {
    $saved=New-VolumeObservation;$saved.Volumes+=@($saved.Volumes[0],[pscustomobject]@{VolumeGuidPath=$null;IdentityStatus='Unavailable'})
    $attr=(Get-Command Find-RideVolumeObservation).Parameters.VolumeGuidPath.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' '\\?\volume{ABC' $null @{Inventory=$saved})
    $matches.Count | Should -Be 1
    $matches[0].CompletionText | Should -BeExactly "'\\?\Volume{abcdef01-1111-1111-1111-111111111111}\'"
    @(& $attr.ScriptBlock '' '' 'missing' $null @{Inventory=$saved}).Count | Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count | Should -Be 0
    $saved.Status='Unavailable'
    @(& $attr.ScriptBlock '' '' '' $null @{Inventory=$saved}).Count | Should -Be 0
  }
}
Describe 'Volume inventory export boundaries' {
  BeforeEach {
    $script:ExportArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';OutputPath=(Join-Path $TestDrive 'volumes.json')}
    Mock Import-Module {}
    Mock Get-RideVolumeInventory {New-VolumeObservation}
  }
  It 'previews without querying Windows or creating output' {
    & (Join-Path $Root 'tools/Export-RideVolumeInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideVolumeInventory -Exactly 0
  }
  It 'creates UTF-8 JSON and refuses existing output without truncation' {
    & (Join-Path $Root 'tools/Export-RideVolumeInventory.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before|ConvertFrom-Json).Kind | Should -Be VolumeObservation
    {& (Join-Path $Root 'tools/Export-RideVolumeInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly $before
  }
  It 'refuses a racing output file created during collection' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'racing-volumes.json'
    Mock Get-RideVolumeInventory {[IO.File]::WriteAllText((Join-Path $TestDrive 'racing-volumes.json'),'other writer');New-VolumeObservation}
    {& (Join-Path $Root 'tools/Export-RideVolumeInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    Should -Invoke Get-RideVolumeInventory -Exactly 1
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
  }
}
