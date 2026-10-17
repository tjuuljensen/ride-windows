<#
.SYNOPSIS
  Verify explicit deployment selection without installed state or native mutation.
.DESCRIPTION
  Uses synthetic resolved package records and named identity collections. Covers
  ambiguity across variants/owners/scopes, versioned input and read-only completion.
.EXAMPLE
  Invoke-Pester .\tests\DeploymentIdentity.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5; native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; no engine, installer, state migration or runtime query.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.DeploymentIdentity.psm1') -Force
  function New-DeploymentFixture {
    param([string]$Name='sharex-workstation',[string]$Variant='installed',[string]$Scope='Machine',[string]$Sid='S-1-5-21-1-2-3-1001',[string]$OperationId='package.sharex',[string]$Library='')
    $op=@{Id=$OperationId;PackageId='sharex';Kind='Package';SelectedVariant=$Variant;Scope=$Scope}
    if($Library){$op.Library=@{Id=$Library;Version='1.0.0'}}
    $args=@{Operation=$op;DeploymentId=$Name}
    if($Scope -eq 'User'){$args.UserSid=$Sid}
    New-RidePackageDeploymentIdentity @args
  }
}
Describe 'Named deployment identity preparation' {
  It 'preserves the stable product and explicit variant without carrying paths or installer commands' {
    $op=@{Id='package.sharex';PackageId='sharex';Kind='Package';SelectedVariant='portable';Scope='Machine';InstallDirectory='C:\Other';InstallerArguments='/silent'}
    $before=$op|ConvertTo-Json -Compress
    $row=New-RidePackageDeploymentIdentity -Operation $op -DeploymentId sharex-field
    $row.OperationId|Should -BeExactly 'package.sharex';$row.PackageId|Should -BeExactly 'sharex'
    $row.Variant|Should -BeExactly 'portable';$row.ReadyForMutation|Should -BeFalse
    $row.LibraryId|Should -BeExactly '';($null -eq $row.UserSid)|Should -BeTrue
    ($row|ConvertTo-Json)|Should -Not -Match 'InstallDirectory|InstallerArguments|Other|silent'
    ($op|ConvertTo-Json -Compress)|Should -BeExactly $before
  }
  It 'retains explicit library and user ownership identity without verifying the account' {
    $row=New-DeploymentFixture -Scope User -Library custom-tools
    $row.UserSid|Should -BeExactly 'S-1-5-21-1-2-3-1001';$row.LibraryId|Should -BeExactly 'custom-tools'
    $row.ReadyForMutation|Should -BeFalse
  }
  It 'rejects invalid or reserved deployment name <Name>' -ForEach @(
    @{Name='SHAREX'},@{Name='with space'},@{Name='../escape'},@{Name='bad.name'},@{Name='-prefix'},
    @{Name='con'},@{Name='lpt9'},@{Name=('a'*65)},@{Name="bad`nname"}
  ) { {New-DeploymentFixture -Name $Name}|Should -Throw }
  It 'accepts a 64-character name and distinguishes a longer non-reserved device prefix' {
    (New-DeploymentFixture -Name ('a'*64)).DeploymentId.Length|Should -Be 64
    (New-DeploymentFixture -Name con-tools).DeploymentId|Should -BeExactly 'con-tools'
  }
  It 'refuses unresolved defaults, missing variants and non-package metadata' {
    foreach($op in @(
      @{Id='package.sharex';PackageId='sharex';Kind='Package';DefaultVariant='installed';Scope='Machine'},
      @{Id='package.sharex';PackageId='sharex';Kind='Package';SelectedVariant='installed';Variants=@{installed=@{}};Scope='Machine'},
      @{Id='windows.other';PackageId='other';Kind='RegistryValue';SelectedVariant='installed';Scope='User'}
    )){{New-RidePackageDeploymentIdentity -Operation $op -DeploymentId example}|Should -Throw '*resolved*'}
  }
  It 'requires a canonical explicit SID for user scope and no SID for machine scope' {
    $op=@{Id='package.sharex';PackageId='sharex';Kind='Package';SelectedVariant='installed';Scope='User'}
    {New-RidePackageDeploymentIdentity -Operation $op -DeploymentId example}|Should -Throw '*SID*'
    foreach($sid in @('someone','S-1-5-21-1-2-3-4294967296','S-1-5-21-01-2-3-1001')){
      {New-RidePackageDeploymentIdentity -Operation $op -DeploymentId example -UserSid $sid}|Should -Throw '*SID*'
    }
    $op.Scope='Machine'
    {New-RidePackageDeploymentIdentity -Operation $op -DeploymentId example -UserSid 'S-1-5-18'}|Should -Throw '*must not*'
  }
}
Describe 'Inspection and exact deployment selection' {
  BeforeEach {
    $rows=@((New-DeploymentFixture),(New-DeploymentFixture -Name sharex-field -Variant portable),(New-DeploymentFixture -Name other-copy -OperationId package.other))
  }
  It 'lists each deployment without silently choosing a catalog default' {
    $before=$rows|ConvertTo-Json -Depth 8 -Compress
    $found=@(Get-RidePackageDeploymentIdentity -Records $rows -OperationId PACKAGE.SHAREX)
    $found.Count|Should -Be 2
    ($found.DeploymentId -join ',')|Should -BeExactly 'sharex-workstation,sharex-field'
    $found[0].DeploymentId='changed-copy'
    ($rows|ConvertTo-Json -Depth 8 -Compress)|Should -BeExactly $before
  }
  It 'requires a named deployment when a product has installed and portable copies' {
    {Resolve-RidePackageDeploymentIdentity -Records $rows -OperationId package.sharex}|Should -Throw '*Multiple deployments*'
    (Resolve-RidePackageDeploymentIdentity -Records $rows -DeploymentId SHAREX-FIELD).Variant|Should -BeExactly 'portable'
  }
  It 'counts distinct user owners and scopes toward product ambiguity' {
    $identities=@((New-DeploymentFixture),(New-DeploymentFixture -Name user-a -Scope User),(New-DeploymentFixture -Name user-b -Scope User -Sid 'S-1-5-21-1-2-3-1002'))
    {Resolve-RidePackageDeploymentIdentity -Records $identities -OperationId package.sharex}|Should -Throw '*Multiple deployments*'
    (Resolve-RidePackageDeploymentIdentity -Records $identities -DeploymentId user-b).UserSid|Should -BeExactly 'S-1-5-21-1-2-3-1002'
  }
  It 'allows a product-only lookup when exactly one supplied deployment exists' {
    (Resolve-RidePackageDeploymentIdentity -Records $rows -OperationId package.other).DeploymentId|Should -BeExactly 'other-copy'
  }
  It 'requires matching product and deployment when both selectors are supplied' {
    {Resolve-RidePackageDeploymentIdentity -Records $rows -DeploymentId sharex-field -OperationId package.other}|Should -Throw '*No matching*'
    (Resolve-RidePackageDeploymentIdentity -Records $rows -DeploymentId sharex-field -OperationId package.sharex).DeploymentId|Should -BeExactly 'sharex-field'
  }
  It 'never falls back, creates a missing identity or selects the first unfiltered row' {
    {Resolve-RidePackageDeploymentIdentity -Records $rows -DeploymentId absent}|Should -Throw '*No matching*'
    {Resolve-RidePackageDeploymentIdentity -Records $rows}|Should -Throw '*Select*'
    {Resolve-RidePackageDeploymentIdentity -Records @() -OperationId package.sharex}|Should -Throw '*No matching*'
    @(Get-RidePackageDeploymentIdentity -Records @()).Count|Should -Be 0
    @(Get-RidePackageDeploymentIdentity -Records $rows -OperationId package.absent).Count|Should -Be 0
  }
  It 'refuses a duplicate name across product, library, scope or owner boundaries' {
    $duplicate=New-DeploymentFixture -Scope User -Library other-library -OperationId package.other
    {Get-RidePackageDeploymentIdentity -Records @($rows[0],$duplicate)}|Should -Throw '*Duplicate*'
    {Resolve-RidePackageDeploymentIdentity -Records @($rows[0],$duplicate) -DeploymentId sharex-workstation}|Should -Throw '*Duplicate*'
  }
  It 'validates unrelated records before exposing any partial result' {
    $bad=New-DeploymentFixture -Name broken -OperationId package.other;$bad.Scope='Invalid'
    $emitted=[Collections.Generic.List[object]]::new()
    {Get-RidePackageDeploymentIdentity -Records @($rows[0],$bad) -OperationId package.sharex|ForEach-Object {$emitted.Add($_)}}|Should -Throw
    $emitted.Count|Should -Be 0
  }
  It 'refuses malformed schema or readiness field <Field>' -ForEach @(
    @{Field='SchemaVersion';Value='1'},@{Field='SchemaVersion';Value=2},@{Field='SchemaVersion';Value=$true},
    @{Field='Kind';Value='PackageSelection'},@{Field='ReadyForMutation';Value=$true},@{Field='ReadyForMutation';Value='false'},
    @{Field='PackageId';Value='../escape'},@{Field='LibraryId';Value=$null},@{Field='Variant';Value='default*'}
  ) {
    $rows[0].$Field=$Value
    {Get-RidePackageDeploymentIdentity -Records $rows}|Should -Throw
  }
  It 'accepts JSON round trips including Int64 schema values without enabling mutation' {
    $saved=ConvertFrom-Json ($rows|ConvertTo-Json -Depth 8)
    $saved[0].SchemaVersion=[long]1
    (Resolve-RidePackageDeploymentIdentity -Records $saved -DeploymentId sharex-field).ReadyForMutation|Should -BeFalse
  }
  It 'refuses a legacy selection record instead of assigning a default deployment ID' {
    $old=[pscustomobject]@{SchemaVersion=1;Operation=@{Id='package.sharex';Kind='Package';PackageId='sharex';Scope='Machine';SelectedVariant='installed'}}
    $before=$old|ConvertTo-Json -Depth 8 -Compress
    {Get-RidePackageDeploymentIdentity -Records @($old)}|Should -Throw '*preparation identity*'
    ($old|ConvertTo-Json -Depth 8 -Compress)|Should -BeExactly $before
  }
  It 'rejects noncollections and excessive collections with no partial output' {
    foreach($invalid in @('text',@{DeploymentId='fake'},$null)){{Get-RidePackageDeploymentIdentity -Records $invalid}|Should -Throw}
    $large=@(for($i=0;$i -lt 4097;$i++){New-DeploymentFixture -Name ('item-'+$i)})
    {Get-RidePackageDeploymentIdentity -Records $large}|Should -Throw '*4096*'
  }
  It 'rejects empty or malformed explicit selectors' {
    {Resolve-RidePackageDeploymentIdentity -Records $rows -DeploymentId '' -OperationId package.sharex}|Should -Throw '*selector*'
    {Resolve-RidePackageDeploymentIdentity -Records $rows -DeploymentId '../bad'}|Should -Throw '*selector*'
    {Get-RidePackageDeploymentIdentity -Records $rows -OperationId ''}|Should -Throw '*selector*'
  }
  It 'completes deployment IDs from the supplied records with product and prefix filtering' {
    $attr=(Get-Command Resolve-RidePackageDeploymentIdentity).Parameters.DeploymentId.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 'SHAREX-F' $null @{Records=$rows;OperationId='PACKAGE.SHAREX'})
    $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly 'sharex-field'
    @(& $attr.ScriptBlock '' '' '' $null @{Records=$rows;OperationId='package.absent'}).Count|Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count|Should -Be 0
  }
  It 'completes deduplicated product IDs quietly from the same validated input' {
    foreach($command in @('Get-RidePackageDeploymentIdentity','Resolve-RidePackageDeploymentIdentity')){
      $attr=(Get-Command $command).Parameters.OperationId.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
      $matches=@(& $attr.ScriptBlock '' '' 'PACKAGE.SH' $null @{Records=$rows})
      $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly 'package.sharex'
      @(& $attr.ScriptBlock '' '' '' $null @{Records=@($rows[0],$rows[0])}).Count|Should -Be 0
    }
  }
}
