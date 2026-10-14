<#
.SYNOPSIS
  Verify Store app reconciliation without live Appx or removal calls.
.DESCRIPTION
  Tests explicit user scope, identity changes, historical gaps and missing flags
  with mocked inventory. No Windows changes or package acquisition.
.EXAMPLE
  Invoke-Pester .\tests\StoreAppReview.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x; Windows PowerShell 5.1 and PowerShell 7.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.StoreAppReview.psm1') -Force
  function New-AppReviewInventory([object[]]$Packages=@()) {
    [pscustomobject]@{SchemaVersion=1;Scope='CurrentUser';UserSid='S-1-5-21-1-2-3-1001';CapturedAtUtc='2026-10-14T00:00:00Z';WindowsContext=[pscustomobject]@{Status='Captured';EditionId='Professional';DisplayVersion='24H2';CurrentBuild='26100';UpdateBuildRevision=1000};Packages=$Packages}
  }
  function New-AppReviewPackage([string]$Name='Microsoft.Paint',[string]$PublisherId='8wekyb3d8bbwe') {
    [pscustomobject]@{Name=$Name;PackageFamilyName=($Name+'_'+$PublisherId);PackageFullName=($Name+'_1.0.0.0_x64__'+$PublisherId);Publisher='CN=Fixture';Version='1.0.0.0';Architecture='x64';Status='Ok';IsFramework=$false;IsResourcePackage=$false;NonRemovable=$false;IsPartOfSystem=$false;Dependencies=@()}
  }
}
Describe 'Store app review definitions' {
  It 'retains every historical removal and registration name without importing v2' {
    $e=Get-Content (Join-Path $script:Root 'docs/archive/evidence/store-app-removal-source-review-2026-10-14.json') -Raw|ConvertFrom-Json
    $definitions=@(Get-RideStoreAppDefinition -IncludeHistoricalCoverage)
    foreach($family in @('Microsoft','ThirdParty')){
      $suffix=if($family -eq 'Microsoft'){'MsftBloat'}else{'ThirdPartyBloat'}
      @(Compare-Object @($e.LegacyFunctions.('Uninstall'+$suffix)|Sort-Object) @($definitions|Where-Object {$family -in $_.LegacyRemoval}|ForEach-Object Name|Sort-Object)).Count|Should -Be 0
      @(Compare-Object @($e.LegacyFunctions.('Install'+$suffix)|Sort-Object) @($definitions|Where-Object {$family -in $_.LegacyRegistration}|ForEach-Object Name|Sort-Object)).Count|Should -Be 0
    }
  }
  It 'uses the actual inspected template family identities rather than guessed friendly names' {
    $e=Get-Content (Join-Path $script:Root 'docs/archive/evidence/store-app-removal-source-review-2026-10-14.json') -Raw|ConvertFrom-Json
    $definitions=@(Get-RideStoreAppDefinition)
    foreach($policy in $e.StaticCrosswalk){
      @($definitions|Where-Object {$_.StaticPolicyId -ceq $policy.PolicyId -and $_.PolicyFamilyName -ceq $policy.PackageFamilyName}).Count|Should -Be 1
    }
    @($definitions|Where-Object StaticPolicyId).Count|Should -Be $e.StaticCrosswalk.Count
  }
  It 'keeps historical-only names outside the default active review set' {
    $current=@(Get-RideStoreAppDefinition)
    @($current|Where-Object {-not $_.StaticPolicyId}).Count|Should -Be 0
    @($current|Where-Object Name -eq Microsoft.MSPaint).Count|Should -Be 0
    @(Get-RideStoreAppDefinition -IncludeHistoricalCoverage|Where-Object Name -eq Microsoft.MSPaint).Count|Should -Be 1
  }
}
Describe 'Explicit-user read-only inventory' {
  BeforeEach {
    Mock Get-RideStoreInventoryUserSid -ModuleName RIDE.StoreAppReview {'S-1-5-21-1-2-3-1001'}
    Mock Get-RideStoreWindowsContext -ModuleName RIDE.StoreAppReview {[pscustomobject]@{Status='Captured';EditionId='Enterprise';DisplayVersion='24H2';CurrentBuild='26100';UpdateBuildRevision=1000}}
    Mock Get-RideStoreCurrentAppx -ModuleName RIDE.StoreAppReview {@()}
  }
  It 'refuses an administrator account mismatch before querying Appx' {
    {Get-RideStoreAppInventory -ExpectedUserSid S-1-5-21-1-2-3-500}|Should -Throw '*differs*'
    Should -Invoke Get-RideStoreCurrentAppx -ModuleName RIDE.StoreAppReview -Exactly 0
    Should -Invoke Get-RideStoreWindowsContext -ModuleName RIDE.StoreAppReview -Exactly 0
  }
  It 'retains current-user identity and an empty collection without claiming removal' {
    $r=Get-RideStoreAppInventory -ExpectedUserSid S-1-5-21-1-2-3-1001
    $r.UserSid|Should -Be S-1-5-21-1-2-3-1001;$r.Scope|Should -Be CurrentUser
    @($r.Packages).Count|Should -Be 0
  }
  It 'keeps unavailable protection flags unknown' {
    Mock Get-RideStoreCurrentAppx -ModuleName RIDE.StoreAppReview {@([pscustomobject]@{Name='Microsoft.Paint';PackageFamilyName='Microsoft.Paint_8wekyb3d8bbwe';PackageFullName='fixture';Version='1.0'})}
    $r=Get-RideStoreAppInventory -ExpectedUserSid S-1-5-21-1-2-3-1001
    $r.Packages[0].NonRemovable|Should -BeNullOrEmpty;$r.Packages[0].IsPartOfSystem|Should -BeNullOrEmpty
    $review=Compare-RideStoreAppInventory $r|Where-Object Name -eq Microsoft.Paint
    $review.PendingReview|Should -Contain 'Protection/type flags incomplete'
    $review.RemovalApproved|Should -BeFalse
  }
  It 'reports provider failure rather than manufacturing an empty successful inventory' {
    Mock Get-RideStoreCurrentAppx -ModuleName RIDE.StoreAppReview {throw 'Appx query denied'}
    {Get-RideStoreAppInventory -ExpectedUserSid S-1-5-21-1-2-3-1001}|Should -Throw '*query denied*'
  }
  It 'retains unavailable edition metadata without manufacturing a release baseline' {
    Mock Get-RideStoreWindowsContext -ModuleName RIDE.StoreAppReview {[pscustomobject]@{Status='Unavailable'}}
    $i=Get-RideStoreAppInventory -ExpectedUserSid S-1-5-21-1-2-3-1001
    $i.WindowsContext.Status|Should -Be Unavailable
    $r=@(Compare-RideStoreAppInventory $i)
    $r[0].PendingReview|Should -Contain 'Edition/build context incomplete; no cross-release coverage inferred'
  }
}
Describe 'App identity reconciliation' {
  It 'keeps absence separate from successful removal or retirement' {
    $r=@(Compare-RideStoreAppInventory (New-AppReviewInventory))
    @($r|Where-Object MappingStatus -ne NotObserved).Count|Should -Be 0
    @($r|Where-Object RemovalApproved).Count|Should -Be 0
    @($r|Where-Object Selection -ne Unselected).Count|Should -Be 0
  }
  It 'keeps the old MSPaint name separate from the current Paint family' {
    $r=@(Compare-RideStoreAppInventory (New-AppReviewInventory @((New-AppReviewPackage))) -IncludeHistoricalCoverage)
    ($r|Where-Object Name -eq Microsoft.Paint).MappingStatus|Should -Be ExactPolicyFamilyObserved
    ($r|Where-Object Name -eq Microsoft.MSPaint).MappingStatus|Should -Be NotObserved
  }
  It 'refuses to equate a different publisher family with the declared policy app' {
    $r=Compare-RideStoreAppInventory (New-AppReviewInventory @((New-AppReviewPackage -PublisherId abcdefghijklm)))|Where-Object Name -eq Microsoft.Paint
    $r.MappingStatus|Should -Be PolicyFamilyMismatch;$r.RemovalApproved|Should -BeFalse
  }
  It 'compares Windows family identities without treating casing as a different app' {
    $r=Compare-RideStoreAppInventory (New-AppReviewInventory @((New-AppReviewPackage -Name microsoft.paint)))|Where-Object Name -eq Microsoft.Paint
    $r.MappingStatus|Should -Be ExactPolicyFamilyObserved
  }
  It 'includes current apps missing from both historical lists and the installed template' {
    $r=Compare-RideStoreAppInventory (New-AppReviewInventory @((New-AppReviewPackage -Name Microsoft.XboxGamingOverlay)))|Where-Object Name -eq Microsoft.XboxGamingOverlay
    $r.MappingStatus|Should -Be UnreviewedCurrentName;$r.StaticPolicyId|Should -BeNullOrEmpty
  }
  It 'retains the four missing historical reverse entries' {
    $r=@(Compare-RideStoreAppInventory (New-AppReviewInventory) -IncludeHistoricalCoverage)
    @($r|Where-Object {$_.PendingReview -contains 'Historical removal has no matching registration entry'}).Count|Should -Be 4
  }
  It 'flags protected frameworks without approving a direct removal' {
    $package=New-AppReviewPackage -Name Microsoft.WinJS.1.0;$package.IsFramework=$true;$package.NonRemovable=$true
    $r=Compare-RideStoreAppInventory (New-AppReviewInventory @($package))|Where-Object Name -eq Microsoft.WinJS.1.0
    $r.PendingReview|Should -Contain 'Dependency/resource review required'
    $r.PendingReview|Should -Contain 'Observed protected/system package; no automatic removal'
    $r.RemovalApproved|Should -BeFalse
  }
  It 'refuses mixed-user inventory and malformed observed identities' {
    $i=New-AppReviewInventory;$i.Scope='AllUsers'
    {Compare-RideStoreAppInventory $i}|Should -Throw '*Invalid current-user*'
    $p=New-AppReviewPackage;$p.PackageFamilyName='Microsoft.Other_8wekyb3d8bbwe'
    {Compare-RideStoreAppInventory (New-AppReviewInventory @($p))}|Should -Throw '*Invalid observed*'
  }
  It 'reads serialized review data through the CLI without an Appx query' {
    $path=Join-Path $TestDrive 'apps.json'
    New-AppReviewInventory @((New-AppReviewPackage))|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $path
    $r=@(& (Join-Path $script:Root 'tools/Compare-RideStoreAppInventory.ps1') -InventoryPath $path)
    ($r|Where-Object Name -eq Microsoft.Paint).MappingStatus|Should -Be ExactPolicyFamilyObserved
  }
  It 'retains edition/build identity in each reconciled row' {
    $r=Compare-RideStoreAppInventory (New-AppReviewInventory @((New-AppReviewPackage)))|Where-Object Name -eq Microsoft.Paint
    $r.WindowsContext.EditionId|Should -Be Professional
    $r.WindowsContext.CurrentBuild|Should -Be 26100
  }
  It 'keeps older schema-1 inventories readable while flagging missing context' {
    $i=New-AppReviewInventory;$i.PSObject.Properties.Remove('WindowsContext')
    $r=@(Compare-RideStoreAppInventory $i)
    $r[0].PendingReview|Should -Contain 'Edition/build context incomplete; no cross-release coverage inferred'
  }
}
Describe 'Separate provisioning reference collection' {
  BeforeEach {
    Mock Test-RideStoreInventoryAdministrator -ModuleName RIDE.StoreAppReview {$true}
    Mock Get-RideStoreWindowsContext -ModuleName RIDE.StoreAppReview {[pscustomobject]@{Status='Captured';EditionId='Enterprise';CurrentBuild='26100'}}
    Mock Get-RideStoreProvisionedPackages -ModuleName RIDE.StoreAppReview {@([pscustomobject]@{DisplayName='Microsoft.Paint';PackageName='Microsoft.Paint_1.0.0.0_neutral_~_8wekyb3d8bbwe';Version='1.0.0.0';Architecture='neutral';ResourceId='~';Regions=@('all')})}
  }
  It 'retains raw image provisioning separately without deriving user PFNs' {
    $log=Join-Path $TestDrive 'provisioning.log'
    $r=Get-RideStoreProvisionedAppInventory -LogPath $log
    $r.Scope|Should -Be ProvisionedImage;$r.ImageSource|Should -Be OnlineOperatingSystem
    $r.RegistrationEvidence|Should -BeFalse;$r.RemovalApproved|Should -BeFalse
    $r.Packages[0].PackageName|Should -Be 'Microsoft.Paint_1.0.0.0_neutral_~_8wekyb3d8bbwe'
    $r.Packages[0].PSObject.Properties.Name|Should -Not -Contain PackageFamilyName
    Should -Invoke Get-RideStoreProvisionedPackages -ModuleName RIDE.StoreAppReview -Exactly 1 -ParameterFilter {$LogPath -eq $log}
    {Compare-RideStoreAppInventory -Inventory $r}|Should -Throw '*current-user inventory*'
  }
  It 'postpones elevation rather than querying DISM from an unelevated process' {
    Mock Test-RideStoreInventoryAdministrator -ModuleName RIDE.StoreAppReview {$false}
    {Get-RideStoreProvisionedAppInventory -LogPath (Join-Path $TestDrive 'provisioning.log')}|Should -Throw '*postpone elevation*'
    Should -Invoke Get-RideStoreProvisionedPackages -ModuleName RIDE.StoreAppReview -Exactly 0
  }
  It 'retains provider failure rather than reporting an empty image' {
    Mock Get-RideStoreProvisionedPackages -ModuleName RIDE.StoreAppReview {throw 'DISM query failed'}
    {Get-RideStoreProvisionedAppInventory -LogPath (Join-Path $TestDrive 'provisioning.log')}|Should -Throw '*DISM query failed*'
  }
  It 'requires complete raw package identities' {
    Mock Get-RideStoreProvisionedPackages -ModuleName RIDE.StoreAppReview {@([pscustomobject]@{DisplayName='Microsoft.Paint'})}
    {Get-RideStoreProvisionedAppInventory -LogPath (Join-Path $TestDrive 'provisioning.log')}|Should -Throw '*Incomplete provisioned*'
  }
}
Describe 'Read-only Windows context' {
  It 'preserves raw edition/build even when the registry product label differs' {
    InModuleScope RIDE.StoreAppReview {
      Mock Get-ItemProperty {[pscustomobject]@{EditionID='Professional';DisplayVersion='24H2';CurrentBuildNumber='26100';UBR=1000;ProductName='Windows 10 Pro'}}
      $r=Get-RideStoreWindowsContext
      $r.Status|Should -Be Captured;$r.CurrentBuild|Should -Be 26100
      $r.ProductNameObserved|Should -Be 'Windows 10 Pro'
      $r.Source|Should -Be 'CurrentVersion registry observation; not a support declaration'
    }
  }
}
Describe 'Inventory export preview' {
  BeforeEach {
    $script:ExportRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path (Join-Path $script:ExportRoot 'tools')
    $null=New-Item -ItemType Directory -Path (Join-Path $script:ExportRoot 'modules')
    $script:ExportTool=Join-Path $script:ExportRoot 'tools/Export-RideStoreAppInventory.ps1'
    Copy-Item -LiteralPath (Join-Path $script:Root 'tools/Export-RideStoreAppInventory.ps1') -Destination $script:ExportTool
    [IO.File]::WriteAllText((Join-Path $script:ExportRoot 'modules/RIDE.StoreAppReview.psm1'),"function Get-RideStoreAppInventory {throw 'Inventory spy was queried'}; Export-ModuleMember -Function Get-RideStoreAppInventory",[Text.UTF8Encoding]::new($false))
  }
  AfterEach {
    Get-Module -All|Where-Object {$_.Path -and $_.Path.StartsWith($script:ExportRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)}|Remove-Module -Force
  }
  It 'does not query Appx or write a file during preview' {
    $output=Join-Path $script:ExportRoot 'apps.json'
    {& $script:ExportTool -ExpectedUserSid S-1-5-21-1-2-3-1001 -OutputPath $output -WhatIf}|Should -Not -Throw
    Test-Path -LiteralPath $output|Should -BeFalse
  }
  It 'does not query DISM or write evidence during provisioning preview' {
    $tool=Join-Path $script:ExportRoot 'tools/Export-RideStoreProvisionedInventory.ps1'
    Copy-Item -LiteralPath (Join-Path $script:Root 'tools/Export-RideStoreProvisionedInventory.ps1') -Destination $tool
    [IO.File]::WriteAllText((Join-Path $script:ExportRoot 'modules/RIDE.StoreAppReview.psm1'),"function Get-RideStoreProvisionedAppInventory {throw 'Provisioning spy was queried'}; Export-ModuleMember -Function Get-RideStoreProvisionedAppInventory",[Text.UTF8Encoding]::new($false))
    $output=Join-Path $script:ExportRoot 'provisioned.json'
    {& $tool -OutputPath $output -WhatIf}|Should -Not -Throw
    Test-Path -LiteralPath $output|Should -BeFalse
    Test-Path -LiteralPath ($output+'.dism.log')|Should -BeFalse
  }
}
