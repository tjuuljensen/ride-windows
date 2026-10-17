<#
.SYNOPSIS
  Verify offline catalog matching without granting adoption ownership.
.DESCRIPTION
  Uses supplied synthetic registrations and catalog variants. No native inventory,
  package configuration, installer, filesystem scan or uninstall command is invoked.
.EXAMPLE
  Invoke-Pester .\tests\PackageAdoptionReview.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5; Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: Repository fixture; native identity and adoption acceptance remain pending.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.PackageAdoptionReview.psm1') -Force
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.InstalledRegistrationInventory.psm1') -Force
  function New-AdoptionRegistration {
    param([string]$Name='Example',[string]$Key='example-key')
    $values=[ordered]@{}
    foreach($field in @('DisplayName','DisplayVersion','Publisher','InstallLocation','WindowsInstaller','SystemComponent')){$values[$field]=[pscustomobject]@{Exists=$false;Kind=$null;Value=$null}}
    $values.DisplayName=[pscustomobject]@{Exists=$true;Kind='String';Value=$Name}
    $values.InstallLocation=[pscustomobject]@{Exists=$true;Kind='ExpandString';Value='%LOCALAPPDATA%\Example'}
    [pscustomobject]@{KeyName=$Key;Values=[pscustomobject]$values}
  }
  function New-AdoptionInventory {
    $sources=@(foreach($scope in @('Machine','User')){foreach($view in @('Registry64','Registry32')){[pscustomobject]@{Scope=$scope;RegistryView=$view;RegistryPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';RootExists=$true;Status='Captured';Entries=@();ErrorId=$null}}})
    $sources[0].Entries=@((New-AdoptionRegistration))
    [pscustomobject]@{SchemaVersion=1;Kind='InstalledRegistrationObservation';ReadyForMutation=$false;RecoverySupported=$false
      WindowsContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;Is64BitOperatingSystem=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true};Sources=$sources}
  }
  function New-AdoptionCatalog {
    @{SchemaVersion=1;Operations=@(
      @{Id='package.example';PackageId='example';Kind='Package';Scope='Machine';InstallerType='Exe';DisplayNamePattern='^Example$';SupportedTargets=@('Windows 11');DefaultVariant='installed';Variants=@{installed=@{};portable=@{InstallerType='Portable';Scope='Machine'}}},
      @{Id='package.other';PackageId='other';Kind='Package';Scope='User';InstallerType='Msi';DisplayNamePattern='^Other$';SupportedTargets=@('Windows 11')},
      @{Id='windows.preference';Kind='RegistryValue';SupportedTargets=@('Windows 11')}
    )}
  }
}
Describe 'Metadata-only package variant resolution' {
  BeforeEach {Mock Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection {throw 'Configuration must not be queried for metadata inspection'}}
  It 'resolves all variant overrides without preferences or portable destination lookup' {
    $op=(New-AdoptionCatalog).Operations[0]
    $r=Resolve-RidePackageSelection -Operation $op -Variant portable -MetadataOnly
    $r.SelectedVariant|Should -Be portable;$r.InstallerType|Should -Be Portable
    $r.ContainsKey('InstallDirectory')|Should -BeFalse
    $r.ContainsKey('ResolvedToolsDirectory')|Should -BeFalse
    Should -Invoke Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection -Exactly 0
  }
  It 'does not substitute current-user environment paths or installer arguments' {
    $op=(New-AdoptionCatalog).Operations[1];$op.LocalAppDataInstallDirectory='Example';$op.InstallerArguments='/D={InstallDirectory}'
    $r=Resolve-RidePackageSelection -Operation $op -MetadataOnly
    $r.InstallerArguments|Should -BeExactly '/D={InstallDirectory}'
    $r.ContainsKey('InstallDirectory')|Should -BeFalse
    Should -Invoke Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection -Exactly 0
  }
  It 'completes variants from the supplied operation only' {
    $attr=(Get-Command Resolve-RidePackageSelection).Parameters.Variant.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 'POR' $null @{Operation=(New-AdoptionCatalog).Operations[0]})
    $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly portable
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count|Should -Be 0
    Should -Invoke Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection -Exactly 0
  }
}
Describe 'Adoption review without implicit ownership' {
  BeforeEach {
    $script:Catalog=New-AdoptionCatalog;$script:Inventory=New-AdoptionInventory
    Mock Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection {throw 'Unexpected configuration read'}
    Mock Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory {throw 'Unexpected native context query'}
    Mock Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory {throw 'Unexpected registry query'}
  }
  It 'reports a provisional single candidate and uncovered portable distribution separately' {
    $before=$Inventory|ConvertTo-Json -Depth 12 -Compress
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    $r.Rows.Count|Should -Be 3
    ($r.Rows|Where-Object {$_.OperationId -eq 'package.example' -and $_.Variant -eq 'installed'}).Status|Should -Be SingleCandidate
    ($r.Rows|Where-Object Variant -eq portable).Status|Should -Be NotCovered
    ($r.Rows|Where-Object OperationId -eq package.other).Status|Should -Be NoMatch
    $r.ReadyForMutation|Should -BeFalse
    @($r.Rows|Where-Object ReadyForAdoption).Count|Should -Be 0
    $r.Rows[0].Candidates[0].OwnershipVerified|Should -BeFalse
    $r.Rows[0].Candidates[0].Values.InstallLocation.Value|Should -BeExactly '%LOCALAPPDATA%\Example'
    $r.Rows[0].Candidates[0].Values.InstallLocation.Value='changed-copy'
    ($Inventory|ConvertTo-Json -Depth 12 -Compress)|Should -BeExactly $before
    Should -Invoke Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection -Exactly 0
    Should -Invoke Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
  }
  It 'retains multiple matches and requires individual resolution without blocking another product' {
    $Inventory.Sources[1].Entries=@((New-AdoptionRegistration -Key another))
    $Inventory.Sources[2].Entries=@((New-AdoptionRegistration Other other-key))
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    $row=$r.Rows|Where-Object {$_.OperationId -eq 'package.example' -and $_.Variant -eq 'installed'}
    $row.Status|Should -Be Ambiguous;$row.Candidates.Count|Should -Be 2
    ($r.Rows|Where-Object OperationId -eq package.other).Status|Should -Be SingleCandidate
  }
  It 'marks overlaps between two catalog products instead of adopting one registration twice' {
    $Catalog.Operations[1].Scope='Machine';$Catalog.Operations[1].DisplayNamePattern='Example'
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    @($r.Rows|Where-Object Status -eq Ambiguous).Count|Should -Be 2
    @($r.Rows|ForEach-Object {$_.Candidates}|Where-Object OverlapsOtherDistributions).Count|Should -Be 2
  }
  It 'marks overlap between installed variants even when the product ID is the same' {
    $Catalog.Operations[0].Variants['alternate']=@{InstallerType='Exe'}
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    @($r.Rows|Where-Object Status -eq Ambiguous).Count|Should -Be 2
  }
  It 'retains known matches but refuses uniqueness when a required source is unavailable' {
    $Inventory.Sources[1].Status='Unavailable';$Inventory.Sources[1].RootExists=$null;$Inventory.Sources[1].ErrorId='System.UnauthorizedAccessException'
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    $row=$r.Rows|Where-Object {$_.OperationId -eq 'package.example' -and $_.Variant -eq 'installed'}
    $row.Status|Should -Be IncompleteSources;$row.Candidates.Count|Should -Be 1
  }
  It 'does not treat an uncollected scope as absent' {
    $Inventory.Sources=@($Inventory.Sources|Where-Object Scope -eq Machine)
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    ($r.Rows|Where-Object OperationId -eq package.other).Status|Should -Be IncompleteSources
  }
  It 'does not widen target support from a matching name or pending distribution' {
    $Catalog.Operations[0].SupportedTargets=@()
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    @($r.Rows|Where-Object {$_.OperationId -eq 'package.example' -and $_.Status -eq 'TargetNotDeclared'}).Count|Should -Be 2
    @($r.Rows|Where-Object ObservedTargetVerified).Count|Should -Be 0
  }
  It 'uses variant target and scope metadata rather than the product default' {
    $Catalog.Operations[0].Variants['user']=@{Scope='User';SupportedTargets=@('Windows Server 2025')}
    $Inventory.Sources[2].Entries=@((New-AdoptionRegistration))
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows Server 2025'
    ($r.Rows|Where-Object Variant -eq user).Status|Should -Be SingleCandidate
    ($r.Rows|Where-Object Variant -eq user).Candidates[0].Scope|Should -Be User
    ($r.Rows|Where-Object {$_.OperationId -eq 'package.example' -and $_.Variant -eq 'installed'}).Status|Should -Be TargetNotDeclared
  }
  It 'reports invalid regex only for that distribution and continues review' {
    $Catalog.Operations[0].DisplayNamePattern='['
    $Inventory.Sources[2].Entries=@((New-AdoptionRegistration Other other-key))
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    ($r.Rows|Where-Object {$_.OperationId -eq 'package.example' -and $_.Variant -eq 'installed'}).Status|Should -Be ReviewFailed
    ($r.Rows|Where-Object OperationId -eq package.other).Status|Should -Be SingleCandidate
  }
  It 'reviews every repository package distribution without configuration or native discovery' {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.CatalogData.psm1')
    $data=Import-RideCatalogData (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $expected=0;foreach($op in $data.Operations){if($op.Kind -eq 'Package'){$expected+=if($op.Variants){$op.Variants.Count}else{1}}}
    $r=Get-RidePackageAdoptionReview -Catalog $data -Inventory $Inventory -Target 'Windows 11'
    $r.Rows.Count|Should -Be $expected
    @($r.Rows|Where-Object Status -eq ReviewFailed).Count|Should -Be 0
    @($r.Rows|Where-Object ReadyForAdoption).Count|Should -Be 0
    Should -Invoke Get-RidePackageConfiguration -ModuleName RIDE.PackageSelection -Exactly 0
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
  }
  It 'bounds a pathological display-name regex and discards its partial matches' {
    $Catalog.Operations[0].DisplayNamePattern='^(a+)+$'
    $Inventory.Sources[0].Entries=@((New-AdoptionRegistration 'a' good),(New-AdoptionRegistration (('a'*3000)+'!') slow))
    $r=Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'
    $row=$r.Rows|Where-Object {$_.OperationId -eq 'package.example' -and $_.Variant -eq 'installed'}
    $row.Status|Should -Be ReviewFailed;$row.Candidates.Count|Should -Be 0
  }
  It 'rejects duplicate catalog identities without returning partial results' {
    $Catalog.Operations+=@($Catalog.Operations[0])
    {Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'}|Should -Throw '*duplicate*'
  }
  It 'completes targets from base and variant declarations without queries' {
    $Catalog.Operations[0].Variants.portable.SupportedTargets=@('Windows Server 2025')
    $attr=(Get-Command Get-RidePackageAdoptionReview).Parameters.Target.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 'windows s' $null @{Catalog=$Catalog})
    $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly "'Windows Server 2025'"
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count|Should -Be 0
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
  }
  It 'refuses malformed saved observation <Case> without native fallback' -ForEach @(
    @{Case='SchemaString'},@{Case='DuplicateSource'},@{Case='WrongRoot'},@{Case='PartialUnavailable'},
    @{Case='WrongSid'},@{Case='WrongBits'},@{Case='NativeFalse'},@{Case='NonLiteralValue'},@{Case='DuplicateKey'}
  ) {
    switch($Case){
      SchemaString {$Inventory.SchemaVersion='1'}
      DuplicateSource {$Inventory.Sources+=@($Inventory.Sources[0])}
      WrongRoot {$Inventory.Sources[0].RegistryPath='OTHER'}
      PartialUnavailable {$Inventory.Sources[0].Status='Unavailable';$Inventory.Sources[0].RootExists=$null;$Inventory.Sources[0].ErrorId='System.Exception'}
      WrongSid {$Inventory.WindowsContext.UserSid='S-1-5-21-1-2-3-4294967296'}
      WrongBits {$Inventory.WindowsContext.Is64BitOperatingSystem=$false}
      NativeFalse {$Inventory.WindowsContext.NativeProcess=$false}
      NonLiteralValue {$Inventory.Sources[0].Entries[0].Values.DisplayName.Exists='true'}
      DuplicateKey {$Inventory.Sources[0].Entries+=@((New-AdoptionRegistration))}
    }
    {Get-RidePackageAdoptionReview -Catalog $Catalog -Inventory $Inventory -Target 'Windows 11'}|Should -Throw
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
  }
}
