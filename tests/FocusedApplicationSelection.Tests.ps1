<#
.SYNOPSIS
  Verify fixed application selection and synthetic user-data preservation.
.DESCRIPTION
  Loads only pure helper definitions from the guest runner. Uses catalog data and
  inert TestDrive files; never starts an installer, account, task or VM.
.EXAMPLE
  Invoke-Pester ./tests/FocusedApplicationSelection.Tests.ps1
.NOTES
  Compatibility: Pester 5.7.1; native Windows PowerShell 5.1 and PowerShell 7.
  Version: 0.2.3. Changelog: Verify exact TMOG release-to-registration version mapping.
#>
BeforeAll {
  $script:repo=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:repo 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $script:repo 'modules/RIDE.PackageSelection.psm1') -Force
  $tokens=$null;$errors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'integration/Invoke-RideApplicationBatch.ps1'),[ref]$tokens,[ref]$errors)
  if($errors.Count){throw ($errors -join '; ')}
  $script:applicationAst=$ast
  $names=@('Assert-RideApplicationPackageSelection','Test-RideApplicationBatchSelection','Assert-RideFocusedApplicationScenario','Assert-RideMailCheckerScenario','Resolve-RideMailCheckerInstallDirectory','Get-RideApplicationExpectedInstalledVersion','New-RideApplicationUserDataFixtures','Assert-RideApplicationUserDataPreserved')
  $definitions=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names},$true))
  if($definitions.Count -ne $names.Count){throw 'Focused pure helper definitions differ.'}
  . ([scriptblock]::Create(($definitions|ForEach-Object {$_.Extent.Text}) -join "`n"))
}
Describe 'Exact installed application version expectations' {
  It 'maps only the observed TMOG release and retains exact version gates elsewhere' {
    Get-RideApplicationExpectedInstalledVersion @{Id='package.tmog';PackageVersion='1.0.1'} 1|Should -BeExactly '1.0.1.0'
    Get-RideApplicationExpectedInstalledVersion @{Id='package.tmog';PackageVersion='1.0.2'} 1|Should -BeExactly '1.0.2'
    Get-RideApplicationExpectedInstalledVersion @{Id='package.other';PackageVersion='1.0.1'} 1|Should -BeExactly '1.0.1'
    Get-RideApplicationExpectedInstalledVersion @{Id='package.hashcheck';PackageVersion='2.6.3'} 11|Should -BeExactly '2.6.3.0'
  }
}
Describe 'Fixed Mail Checker guest selection' {
  BeforeEach {
    $catalog=Import-RideCatalogData (Join-Path $script:repo 'catalog/operations.psd1')
    $script:mailOperation=Resolve-RidePackageSelection ($catalog.Operations|Where-Object Id -eq 'package.mitec-mail-checker') -Variant installed
    $script:mailScenario=[pscustomobject]@{Id='package.mitec-mail-checker';Variant='installed';Selected=$script:mailOperation}
  }
  It 'selects only the declared Mail Checker operation from the complete catalog' {
    $selected=@($catalog.Operations|Where-Object {Test-RideApplicationBatchSelection $_ 13})
    $selected.Count|Should -Be 1;$selected[0].Id|Should -BeExactly 'package.mitec-mail-checker'
    {Assert-RideApplicationPackageSelection 13}|Should -Not -Throw
    {Assert-RideMailCheckerScenario @($script:mailScenario) 'Windows 11'}|Should -Not -Throw
    $script:mailOperation.ExpectedSha256|Should -BeExactly 'da47910bf3eab1efabb6fc7200a6bdfc394c17a24dfb236b0aafb220967c8ce0'
    $script:mailOperation.SupportedTargets|Should -Be @()
  }
  It 'refuses alternate products, variants, targets and ambiguous selection' {
    {Assert-RideApplicationPackageSelection 13 'package.tmog'}|Should -Throw
    {Assert-RideMailCheckerScenario @($script:mailScenario) 'Windows Server 2025'}|Should -Throw '*Windows 11*'
    {Assert-RideMailCheckerScenario @($script:mailScenario,$script:mailScenario) 'Windows 11'}|Should -Throw '*exactly*'
    $script:mailScenario.Variant='portable';{Assert-RideMailCheckerScenario @($script:mailScenario) 'Windows 11'}|Should -Throw
  }
  It 'admits Mail Checker to explicit vendor removal and compensating recovery without user-data fixtures' {
    $branches=@($script:applicationAst.FindAll({param($node)
      $node -is [Management.Automation.Language.IfStatementAst] -and
      @($node.Clauses|Where-Object {$_.Item2.Extent.Text -match "scenarioStage='Run vendor uninstaller'"}).Count -gt 0
    },$true))
    $branches.Count|Should -Be 1
    $condition=[scriptblock]::Create($branches[0].Clauses[0].Item1.Extent.Text)
    $Batch=13;$userDataFixtures=@();$profileFixture=$null
    $scenario=@{Id='package.mitec-mail-checker'}
    (& $condition)|Should -BeTrue
  }
  It 'refuses changed privilege, installer or release metadata <Field>' -ForEach @(
    @{Field='Scope';Value='User'},@{Field='RequiresAdmin';Value=$false},@{Field='RequiresUnelevatedUser';Value=$true},@{Field='InstallerType';Value='Portable'},@{Field='PackageVersion';Value='7.2.1'}
  ) {$script:mailOperation[$Field]=$Value;{Assert-RideMailCheckerScenario @($script:mailScenario) 'Windows 11'}|Should -Throw '*pinned 7.2.0 elevated machine installer*'}
}
Describe 'Old Mail Checker installer registration paths' {
  BeforeEach {
    $script:installed=@{Present=$true;DisplayName='Mail Checker';DisplayVersion=$null;InstallLocation=$null;UninstallString='"C:\Program Files (x86)\Mail Checker\unins000.exe"'}
    $script:roots=@('C:\Program Files (x86)','C:\Program Files')
  }
  It 'uses the direct quoted Inno uninstall directory when location/version are absent' {
    Resolve-RideMailCheckerInstallDirectory $script:installed $script:roots|Should -BeExactly 'C:\Program Files (x86)\Mail Checker'
    $script:installed.DisplayVersion|Should -BeNullOrEmpty
  }
  It 'accepts the direct unquoted uninstall path without executing it' {
    $script:installed.UninstallString='C:\Program Files (x86)\Mail Checker\unins000.exe'
    Resolve-RideMailCheckerInstallDirectory $script:installed $script:roots|Should -BeExactly 'C:\Program Files (x86)\Mail Checker'
  }
  It 'prefers an explicit installation directory within Program Files' {
    $script:installed.InstallLocation='C:\Program Files\Mail Checker'
    $script:installed.UninstallString=$null
    Resolve-RideMailCheckerInstallDirectory $script:installed $script:roots|Should -BeExactly $script:installed.InstallLocation
  }
  It 'refuses ambiguous or indirect uninstall commands <Command>' -ForEach @(
    @{Command='cmd.exe /c unins000.exe'},@{Command='"C:\Program Files (x86)\Mail Checker\unins000.exe" /extra'},@{Command='C:\Windows\unins000.exe'}
  ) {
    $script:installed.UninstallString=$Command
    {Resolve-RideMailCheckerInstallDirectory $script:installed $script:roots}|Should -Throw
  }
  It 'refuses a path escaping the installation roots' {
    $script:installed.InstallLocation='C:\Program Files\..\Windows'
    {Resolve-RideMailCheckerInstallDirectory $script:installed $script:roots}|Should -Throw '*outside*'
  }
  It 'refuses an unrelated registration' {
    $script:installed.DisplayName='Other product'
    {Resolve-RideMailCheckerInstallDirectory $script:installed $script:roots}|Should -Throw '*Exact Mail Checker*'
  }
}
Describe 'Fixed Gpg4win and TMOG guest selection' {
  It 'selects only <Id> and retains its intended privilege context' -ForEach @(
    @{Id='package.gpg4win';Scope='User';Limited=$true},@{Id='package.tmog';Scope='Machine';Limited=$false}
  ) {
    Assert-RideApplicationPackageSelection -SelectedBatch 1 -SelectedPackageId $Id
    $catalog=Import-RideCatalogData (Join-Path $script:repo 'catalog/operations.psd1')
    $selected=@(foreach($package in $catalog.Operations|Where-Object Kind -eq Package){
      foreach($variant in $(if($package.Variants){@($package.Variants.Keys)}else{@('installed')})){
        $operation=Resolve-RidePackageSelection -Operation $package -Variant $variant
        if(Test-RideApplicationBatchSelection -Operation $operation -SelectedBatch 1 -SelectedPackageId $Id){
          [pscustomobject]@{Id=$package.Id;Variant=$variant;Selected=$operation}
        }
      }
    })
    $selected.Count|Should -Be 1
    $selected[0].Selected.Scope|Should -BeExactly $Scope
    [bool]$selected[0].Selected.RequiresUnelevatedUser|Should -Be $Limited
    $selected[0].Selected.PendingAcceptance|Should -BeTrue
    $selected[0].Selected.SupportedTargets|Should -Be @()
    {Assert-RideFocusedApplicationScenario -Scenarios $selected -Target 'Windows 11' -SelectedPackageId $Id}|Should -Not -Throw
    {Assert-RideFocusedApplicationScenario -Scenarios $selected -Target 'Windows Server 2025' -SelectedPackageId $Id}|Should -Throw '*Windows 11*'
    {Assert-RideFocusedApplicationScenario -Scenarios @($selected[0],$selected[0]) -Target 'Windows 11' -SelectedPackageId $Id}|Should -Throw '*exactly*'
  }
  It 'rejects cross-batch or arbitrary package selection for <Batch>/<Id>' -ForEach @(
    @{Batch=2;Id='package.gpg4win'},@{Batch=1;Id='package.other'},@{Batch=1;Id='package.ntcore-explorer-suite'},
    @{Batch=12;Id='package.tmog'},@{Batch=12;Id=''}
  ) {{Assert-RideApplicationPackageSelection -SelectedBatch $Batch -SelectedPackageId $Id}|Should -Throw}
  It 'retains legacy unfiltered batch and focused Explorer Suite selection' {
    {Assert-RideApplicationPackageSelection -SelectedBatch 1}|Should -Not -Throw
    {Assert-RideApplicationPackageSelection -SelectedBatch 12 -SelectedPackageId 'package.ntcore-explorer-suite'}|Should -Not -Throw
    Test-RideApplicationBatchSelection -Operation @{Id='package.other';MigrationBatch='ApplicationsBatch1'} -SelectedBatch 1|Should -BeTrue
    Test-RideApplicationBatchSelection -Operation @{Id='package.other';MigrationBatch='ApplicationsBatch2'} -SelectedBatch 1|Should -BeFalse
    Test-RideApplicationBatchSelection -Operation @{Id='package.other';MigrationBatch='OpenJDKCompatibility'} -SelectedBatch 8|Should -BeTrue
  }
  It 'refuses elevated Gpg4win or limited TMOG metadata' {
    $gpg=@{Id='package.gpg4win';Variant='installed';Selected=@{Scope='User';RequiresUnelevatedUser=$true;RequiresAdmin=$true}}
    {Assert-RideFocusedApplicationScenario @($gpg) 'Windows 11' 'package.gpg4win'}|Should -Throw '*limited intended-user*'
    $tmog=@{Id='package.tmog';Variant='installed';Selected=@{Scope='Machine';RequiresUnelevatedUser=$true;RequiresAdmin=$true}}
    {Assert-RideFocusedApplicationScenario @($tmog) 'Windows 11' 'package.tmog'}|Should -Throw '*elevated machine*'
  }
  It 'detects changed and deleted synthetic pre-existing data for <Id>' -ForEach @(@{Id='package.gpg4win'},@{Id='package.tmog'}) {
    $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $fixtures=@(New-RideApplicationUserDataFixtures -PackageId $Id -Roots @{Roaming=$root;Local=$root})
    $fixtures.Count|Should -Be 1
    {Assert-RideApplicationUserDataPreserved $fixtures 'Before install'}|Should -Not -Throw
    [IO.File]::WriteAllText($fixtures[0].Path,'changed synthetic fixture')
    {Assert-RideApplicationUserDataPreserved $fixtures 'After uninstall'}|Should -Throw '*modified user data*'
    Remove-Item -LiteralPath $fixtures[0].Path
    {Assert-RideApplicationUserDataPreserved $fixtures 'After recovery'}|Should -Throw '*removed user data*'
  }
}
