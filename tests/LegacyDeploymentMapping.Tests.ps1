<#
.SYNOPSIS
  Verify named legacy mapping without rewriting existing state stores.
.DESCRIPTION
  Preserves supplied literal metadata, rejects identity drift and exercises logical
  recovery. No state-file, catalog preference, installer or native query occurs.
.EXAMPLE
  Invoke-Pester .\tests\LegacyDeploymentMapping.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; durable byte/store migration remains pending.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.LegacyDeploymentMapping.psm1') -Force
  function New-LegacySelectionFixture {
    [pscustomobject]@{SchemaVersion=1;Operation=[pscustomobject]@{
      Id='package.example';Kind='Package';PackageId='example';SelectedVariant='old-portable';Scope='Machine'
      InstallDirectory='D:\Original tools\Example';Name='Original edition';InstallerType='Portable'
      SupportedTargets=@('Windows Server 2025');RequiredFiles=@('tool.exe','LICENSE');VariantMetadata=@{Keep='literal';Flags=@($true,$false,$null);Empty=@()}
    };AdditionalField=[pscustomobject]@{String='unchanged';Number=[uint32]4294967295}}
  }
  function New-ExpectedLegacyOperation {
    @{Id='package.example';Kind='Package';PackageId='example';Scope='User';DefaultVariant='installed';Variants=@{installed=@{}};InstallDirectory='C:\New tools'}
  }
  function New-LegacyMappingFixture {
    New-RideLegacyDeploymentMapping -Selection (New-LegacySelectionFixture) -DeploymentId original-example -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine
  }
}
Describe 'Versioned legacy deployment preparation' {
  It 'retains retired variant, original destination and all unknown logical fields' {
    $old=New-LegacySelectionFixture;$before=$old|ConvertTo-Json -Depth 12 -Compress
    $r=New-RideLegacyDeploymentMapping -Selection $old -DeploymentId original-example -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine
    $r.Identity.Variant|Should -BeExactly old-portable
    $r.Identity.Scope|Should -BeExactly Machine
    $r.OriginalSelection.Operation.InstallDirectory|Should -BeExactly 'D:\Original tools\Example'
    ($r.OriginalSelection|ConvertTo-Json -Depth 12 -Compress)|Should -BeExactly $before
    $r.ReadyForMigration|Should -BeFalse;$r.OriginalFileBytesPreserved|Should -BeFalse
    ($old|ConvertTo-Json -Depth 12 -Compress)|Should -BeExactly $before
  }
  It 'does not share mutable arrays and dictionaries with the source or recovered copy' {
    $old=New-LegacySelectionFixture
    $r=New-RideLegacyDeploymentMapping -Selection $old -DeploymentId original-example -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine
    $old.Operation.RequiredFiles[0]='changed.exe';$old.Operation.VariantMetadata.Keep='changed'
    $r.OriginalSelection.Operation.RequiredFiles[0]|Should -BeExactly tool.exe
    $r.OriginalSelection.Operation.VariantMetadata.Keep|Should -BeExactly literal
    $copy=Get-RideLegacyDeploymentSelection -Mapping $r
    $copy.Operation.RequiredFiles[1]='changed'
    $r.OriginalSelection.Operation.RequiredFiles[1]|Should -BeExactly LICENSE
    $copy.Operation.VariantMetadata.Empty.Count|Should -Be 0
    $copy.Operation.VariantMetadata.Flags.Count|Should -Be 3
    ($null -eq $copy.Operation.VariantMetadata.Flags[2])|Should -BeTrue
  }
  It 'round trips JSON preparation while preserving original logical selection' {
    $r=New-LegacyMappingFixture
    $saved=ConvertFrom-Json ($r|ConvertTo-Json -Depth 20)
    $saved.SchemaVersion=[long]1;$saved.OriginalSelection.SchemaVersion=[long]1
    $copy=Get-RideLegacyDeploymentSelection -Mapping $saved
    $copy.Operation.SelectedVariant|Should -BeExactly old-portable
    $copy.AdditionalField.Number|Should -Be 4294967295
    $copy.Operation.VariantMetadata.Empty.Count|Should -Be 0
  }
  It 'supports literal hashtable source records without converting their meaning' {
    $old=@{SchemaVersion=1;Operation=@{Id='package.example';Kind='Package';PackageId='example';Scope='Machine';SelectedVariant='installed'};Retained=@{Item=@()}}
    $r=New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine
    $copy=Get-RideLegacyDeploymentSelection $r
    $copy.Operation.Id|Should -BeExactly package.example;$copy.Retained.Item.Count|Should -Be 0
  }
  It 'requires explicit user store owner and preserves matching library identity' {
    $old=New-LegacySelectionFixture;$old.Operation.Scope='User';$old.Operation|Add-Member NoteProperty Library @{Id='example-library';Version='0.9.0'}
    $expected=New-ExpectedLegacyOperation;$expected.Library=@{Id='example-library';Version='1.0.0'}
    {New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation $expected -ExpectedScope User}|Should -Throw '*SID*'
    $r=New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation $expected -ExpectedScope User -UserSid S-1-5-21-1-2-3-1001
    $r.Identity.LibraryId|Should -BeExactly example-library
    (Get-RideLegacyDeploymentSelection $r).Operation.Library.Version|Should -BeExactly '0.9.0'
  }
  It 'rejects stable product, library and store mismatch <Case>' -ForEach @(
    @{Case='OperationId'},@{Case='PackageId'},@{Case='Scope'},@{Case='Library'},@{Case='Kind'}
  ) {
    $old=New-LegacySelectionFixture;$expected=New-ExpectedLegacyOperation;$scope='Machine'
    switch($Case){OperationId{$expected.Id='package.other'}PackageId{$expected.PackageId='other'}Scope{$scope='User'}Library{$expected.Library=@{Id='other'}}Kind{$expected.Kind='Artifact'}}
    {New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation $expected -ExpectedScope $scope}|Should -Throw '*identity*'
  }
  It 'refuses run snapshots, unknown schema and unresolved selections' {
    foreach($value in @(
      [pscustomobject]@{SchemaVersion=3;OperationId='package.example';PackageSelection=@{};Snapshot=@{}},
      [pscustomobject]@{SchemaVersion='1';Operation=@{}},
      [pscustomobject]@{SchemaVersion=1;Operation=@{Kind='Package';Variants=@{installed=@{}}}}
    )){{New-RideLegacyDeploymentMapping -Selection $value -DeploymentId explicit-name -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine}|Should -Throw '*schema-1*'}
  }
  It 'refuses unsupported values without evaluating script properties' {
    $old=New-LegacySelectionFixture;$old|Add-Member ScriptProperty Unsafe {throw 'must never execute'}
    {New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine}|Should -Throw '*literal data*'
    $old=New-LegacySelectionFixture;$old.AdditionalField.String=[datetime]::UtcNow
    {New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine}|Should -Throw '*non-data*'
  }
  It 'bounds excessive depth, strings and non-finite numbers' {
    $old=New-LegacySelectionFixture;$old.AdditionalField.String='a'*65537
    {New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine}|Should -Throw '*string bound*'
    $old=New-LegacySelectionFixture;$node=@{};$old.AdditionalField.String=$node
    for($i=0;$i -lt 34;$i++){$node.Child=@{};$node=$node.Child}
    {New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine}|Should -Throw '*depth or node*'
    $old=New-LegacySelectionFixture;$old.AdditionalField.Number=[double]::NaN
    {New-RideLegacyDeploymentMapping -Selection $old -DeploymentId explicit-name -ExpectedOperation (New-ExpectedLegacyOperation) -ExpectedScope Machine}|Should -Throw '*Non-finite*'
  }
  It 'rejects inconsistent recovery field <Field>' -ForEach @(
    @{Field='OperationId';Value='package.other'},@{Field='PackageId';Value='other'},@{Field='Variant';Value='installed'},
    @{Field='LibraryId';Value='other-library'},@{Field='Scope';Value='User'}
  ) {
    $r=New-LegacyMappingFixture;$r.Identity.$Field=$Value
    {Get-RideLegacyDeploymentSelection -Mapping $r}|Should -Throw
  }
  It 'refuses a prepared record that falsely claims durable migration or original bytes' {
    foreach($field in @('ReadyForMigration','OriginalFileBytesPreserved')){
      $r=New-LegacyMappingFixture;$r.$field=$true
      {Get-RideLegacyDeploymentSelection $r}|Should -Throw '*schema*'
    }
  }
  It 'completes store scopes without reading any source record' {
    $line='New-RideLegacyDeploymentMapping -ExpectedScope Ma'
    (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText|Should -Contain Machine
  }
}
