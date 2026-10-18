<#
.SYNOPSIS
  Verify explicit offline execution refuses incomplete plans before mutation.
.DESCRIPTION
  Uses inert local source/payload fixtures and mocked Windows target/handlers.
  No installers, downloaded code, real state stores or Windows settings are used.
.EXAMPLE
  Invoke-Pester .\tests\OfflineExecution.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture. Native disconnected-VM acceptance is separate.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  foreach($module in @('RIDE.CatalogData','RIDE-Packages','RIDE-PortablePackages')) { Import-Module (Join-Path $RepositoryRoot ('modules/'+$module+'.psm1')) -Global }
  function New-ExecutionFile($Root,$Id,$Relative,$Role,$Text) {
    $path=Join-Path $Root $Relative
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path,$Text,[Text.UTF8Encoding]::new($false))
    [pscustomobject]@{Id=$Id;RelativePath=$Relative;Role=$Role;Length=(Get-Item -LiteralPath $path).Length;Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}
  }
  $script:CatalogText=@'
@{SchemaVersion=1;Groups=@();Operations=@(
 @{Id='package.fixture';Name='Fixture';Kind='Package';PackageId='fixture';Scope='User';InstallerType='Portable';PortableFormat='File';PortableFileName='fixture.ps1';RequiredFiles=@('fixture.ps1');Architecture='x64';SupportedTargets=@('Windows 11');Actions=@('Install','Uninstall');ProductUri='https://publisher.example/product';License='Fixture';LicenseUri='https://publisher.example/license';DownloadUri='https://publisher.example/source';PackageVersion='1.0'}
)}
'@
  function Save-ExecutionManifest {
    [IO.File]::WriteAllText($script:ManifestPath,($script:Manifest|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
  }
  function Open-ExecutionContext {
    InModuleScope RIDE.Engine -Parameters @{Plan=$script:Plan;Path=$script:ManifestPath;Source=$script:SourceRoot} {
      param($Plan,$Path,$Source)
      Get-RideOfflinePlanContext -Plan $Plan -ManifestPath $Path -ProfileId workstation -CatalogFileId catalog -SourceRoot $Source
    }
  }
}
Describe 'Whole-plan offline source and byte gate' {
  BeforeEach {
    $fixtureRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $script:BundleRoot=Join-Path $fixtureRoot 'bundle';$script:SourceRoot=Join-Path $fixtureRoot 'source'
    $script:ManifestPath=Join-Path $BundleRoot 'manifest.json'
    $script:PayloadPath=Join-Path $BundleRoot 'payload/fixture.ps1'
    $files=@(
      New-ExecutionFile $BundleRoot runner 'ride/ride.ps1' Engine '# inert runner'
      New-ExecutionFile $BundleRoot catalog 'ride/catalog/operations.psd1' Engine $CatalogText
      New-ExecutionFile $BundleRoot runtime 'ride/modules/runtime.psm1' Engine '# inert module'
      New-ExecutionFile $BundleRoot profile 'ride/profiles/fixture.psd1' Profile "@{SchemaVersion=1;Name='Fixture';Operations=@(@{Id='package.fixture';State='Present';Variant='installed'})}"
      New-ExecutionFile $BundleRoot payload 'payload/fixture.ps1' Payload '# inert payload'
      New-ExecutionFile $BundleRoot notice 'notices/fixture.txt' Notice 'fixture notice'
    )
    $null=New-ExecutionFile $SourceRoot runner 'ride.ps1' Engine '# inert runner'
    $null=New-ExecutionFile $SourceRoot catalog 'catalog/operations.psd1' Engine $CatalogText
    $null=New-ExecutionFile $SourceRoot runtime 'modules/runtime.psm1' Engine '# inert module'
    $script:Manifest=[pscustomobject]@{SchemaVersion=1;Kind='RideOfflineBundle';BundleId='fixture';BundleVersion='v1';
      Engine=[pscustomobject]@{Version='3.0';SourceCommit=('a'*40);FileIds=@('runner','catalog','runtime')};Files=$files;ServicingSources=@();
      Artifacts=@([pscustomobject]@{Id='tool';PackageId='package.fixture';Variant='installed';Version='1.0';Architecture='x64';Targets=@('Windows 11');Status='Included';OmissionCode=$null;FileIds=@('payload','notice');DependencyIds=@();OfflineCapability='DeclaredNoNetwork';ProductUri='https://publisher.example/product';DownloadUri='https://publisher.example/source';License='Fixture';LicenseUri='https://publisher.example/license'});
      Profiles=@([pscustomobject]@{Id='workstation';FileId='profile';Target='Windows 11';Build=26100;EditionId='Professional';Architecture='x64';ArtifactIds=@('tool');ServicingSourceIds=@()})}
    $script:Operation=(Import-RideCatalogData -Content $CatalogText).Operations[0]
    $Operation.SelectedVariant='installed'
    $script:Plan=@([pscustomobject]@{Operation=$Operation;State='Present'})
    Save-ExecutionManifest
    Mock Get-RideOfflineTarget -ModuleName RIDE.Engine {[pscustomobject]@{Name='Windows 11';Build=26100;EditionId='Professional';Architecture='x64'}}
    Mock Save-RidePackageArtifact -ModuleName RIDE-Packages {throw 'Network acquisition must not occur'}
  }
  AfterEach { Should -Invoke Save-RidePackageArtifact -ModuleName RIDE-Packages -Exactly 0 }
  It 'binds the complete source and plan, and locks content until execution finishes' {
    $context=Open-ExecutionContext
    try {
      $context.Artifacts['package.fixture'].Path | Should -Be $PayloadPath
      $context.Artifacts['package.fixture'].Offline | Should -BeTrue
      $context.Preflight.ProfileCoverage.ParsedBytesBindingVerified | Should -BeTrue
      {[IO.File]::WriteAllText($PayloadPath,'changed')} | Should -Throw
      {[IO.File]::WriteAllText($ManifestPath,'changed')} | Should -Throw
      {[IO.File]::WriteAllText((Join-Path $SourceRoot 'modules/runtime.psm1'),'changed')} | Should -Throw
    } finally { foreach($lease in $context.Leases){$lease.Dispose()} }
    {[IO.File]::WriteAllText($PayloadPath,'released')} | Should -Not -Throw
  }
  It 'fails <Case> before returning an executable context and releases all leases' -ForEach @(
    @{Case='MissingPayload'},@{Case='ChangedPayload'},@{Case='MissingNotice'},@{Case='WrongPublisherSource'},
    @{Case='Omission'},@{Case='NetworkRequired'},@{Case='MissingEngineSource'},@{Case='ChangedRunningSource'},
    @{Case='WrongTarget'},@{Case='WrongPlan'},@{Case='WrongVariant'},@{Case='ExecutableInstaller'},
    @{Case='CatalogDependency'},@{Case='PendingAcceptance'},@{Case='ManifestDependency'},@{Case='BadCatalogRoot'},@{Case='RemovalRequirement'}
  ) {
    switch($Case){
      MissingPayload {Remove-Item -LiteralPath $PayloadPath}
      ChangedPayload {[IO.File]::WriteAllText($PayloadPath,'changed')}
      MissingNotice {Remove-Item -LiteralPath (Join-Path $BundleRoot 'notices/fixture.txt')}
      WrongPublisherSource {$Manifest.Artifacts[0].DownloadUri='https://publisher.example/different'}
      Omission {$Manifest.Artifacts[0].Status='Omitted';$Manifest.Artifacts[0].OmissionCode='Missing';$Manifest.Artifacts[0].FileIds=@()}
      NetworkRequired {$Manifest.Artifacts[0].OfflineCapability='NetworkRequired'}
      MissingEngineSource {$Manifest.Engine.FileIds=@('runner','catalog')}
      ChangedRunningSource {[IO.File]::WriteAllText((Join-Path $SourceRoot 'modules/runtime.psm1'),'changed')}
      WrongTarget {$Manifest.Profiles[0].Build=26200}
      WrongPlan {$Plan[0].Operation.Id='package.other'}
      WrongVariant {$Plan[0].Operation.SelectedVariant='portable'}
      ExecutableInstaller {$Plan[0].Operation.InstallerType='Exe'}
      CatalogDependency {$Plan[0].Operation.PrerequisitePackageId='package.runtime'}
      PendingAcceptance {$Plan[0].Operation.PendingAcceptance=$true}
      BadCatalogRoot {$Manifest.Files[1].RelativePath='ride/notcatalog/operations.psd1';$null=New-ExecutionFile $BundleRoot catalog $Manifest.Files[1].RelativePath Engine $CatalogText}
      RemovalRequirement {$replacement=New-ExecutionFile $BundleRoot profile 'ride/profiles/fixture.psd1' Profile "@{SchemaVersion=1;Name='Fixture';Operations=@(@{Id='package.fixture';State='Absent';Variant='installed'})}";$Manifest.Files[3]=$replacement}
      ManifestDependency {$dep=$Manifest.Artifacts[0].PSObject.Copy();$dep.Id='dependency';$dep.PackageId='package.dependency';$dep.Status='Omitted';$dep.OmissionCode='TechnicalPending';$dep.FileIds=@();$Manifest.Artifacts+=@($dep);$Manifest.Artifacts[0].DependencyIds=@('dependency')}
    }
    Save-ExecutionManifest
    {Open-ExecutionContext} | Should -Throw
    $stream=[IO.File]::Open($ManifestPath,'Open','ReadWrite','None');$stream.Dispose()
  }
  It 'stops a mixed plan at the gate before even its first setting is changed' {
    Remove-Item -LiteralPath $PayloadPath
    Mock Save-RideRunManifest -ModuleName RIDE.Engine {throw 'Must not save state'}
    Mock Save-RideOperationSnapshot -ModuleName RIDE.Engine {throw 'Must not capture'}
    Mock Set-RideSettingState -ModuleName RIDE.Engine {throw 'Must not set'}
    Mock Install-RidePackage -ModuleName RIDE.Engine {throw 'Must not install'}
    $mixed=@([pscustomobject]@{Operation=@{Id='setting.first';Kind='RegistryValue'};State='Enabled'})+$Plan
    {Invoke-RidePlan $mixed -OfflineBundle $ManifestPath -OfflineProfileId workstation -OfflineCatalogFileId catalog -Confirm:$false} | Should -Throw '*coverage failed*'
    Should -Invoke Save-RideRunManifest -ModuleName RIDE.Engine -Exactly 0
    Should -Invoke Save-RideOperationSnapshot -ModuleName RIDE.Engine -Exactly 0
    Should -Invoke Set-RideSettingState -ModuleName RIDE.Engine -Exactly 0
    Should -Invoke Install-RidePackage -ModuleName RIDE.Engine -Exactly 0
  }
  It 'rejects an explicitly empty offline option instead of treating it as online' {
    {Invoke-RidePlan $Plan -OfflineBundle '' -Confirm:$false} | Should -Throw '*required together*'
  }
  It 'completes selected profile and catalog IDs from the same bounded manifest' {
    foreach($command in @((Join-Path $RepositoryRoot 'ride.ps1'),'Invoke-RidePlan')){
      foreach($case in @(@{Parameter='OfflineProfileId';Prefix='Wo';Expected="'workstation'"},@{Parameter='OfflineCatalogFileId';Prefix='Ca';Expected="'catalog'"})){
        $line="& '$command' -OfflineBundle '$ManifestPath' -$($case.Parameter) $($case.Prefix)"
        (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain $case.Expected
      }
    }
  }
}

Describe 'Engine offline dispatch and lease recovery' {
  BeforeEach {
    $script:DispatchLease=[IO.MemoryStream]::new()
    InModuleScope RIDE.Engine -Parameters @{Lease=$DispatchLease;Root=$TestDrive} {
      param($Lease,$Root)
      $script:OfflineDispatchOperation=@{Id='package.fixture';Kind='Package';Name='Fixture';Scope='User';SelectedVariant='installed'}
      $script:OfflineDispatchRoot=$Root
      $script:OfflineDispatchContext=[pscustomobject]@{Leases=@($Lease);Artifacts=@{'package.fixture'=[pscustomobject]@{Offline=$true;Sha256=('a'*64);Path='fixture';Version='1.0'}}}
      Mock Get-RideOfflinePlanContext {$script:OfflineDispatchContext}
      Mock Assert-RidePlanAllowed {}
      Mock Get-RideOperation {$script:OfflineDispatchOperation}
      Mock Get-RideRecordedPackageSelection {$null}
      Mock Get-RideCurrentState {[pscustomobject]@{Present=$false}}
      Mock Test-RideDesiredState {$false}
      Mock Save-RideRunManifest {}
      Mock Save-RideOperationSnapshot {}
      Mock Save-RidePackageSelectionIndex {}
      Mock Get-RideStateRoot {$script:OfflineDispatchRoot}
      Mock Install-RidePackage {$null}
    }
    $script:DispatchPlan=@([pscustomobject]@{Operation=@{Id='package.fixture';Kind='Package';Name='Fixture';Scope='User';SelectedVariant='installed'};State='Present'})
  }
  It 'forwards only the preflight artifact and closes its leases after success' {
    Invoke-RidePlan $DispatchPlan -OfflineBundle fixture -OfflineProfileId p -OfflineCatalogFileId c -Confirm:$false | Out-Null
    Should -Invoke Install-RidePackage -ModuleName RIDE.Engine -Exactly 1 -ParameterFilter {$OfflineArtifact.Offline -and $OfflineArtifact.Sha256 -eq ('a'*64)}
    Should -Invoke Save-RideOperationSnapshot -ModuleName RIDE.Engine -Exactly 1
    $DispatchLease.CanRead | Should -BeFalse
  }
  It 'runs the gate but performs no capture or handler in preview' {
    Invoke-RidePlan $DispatchPlan -OfflineBundle fixture -OfflineProfileId p -OfflineCatalogFileId c -WhatIf | Out-Null
    Should -Invoke Get-RideOfflinePlanContext -ModuleName RIDE.Engine -Exactly 1
    Should -Invoke Save-RideRunManifest -ModuleName RIDE.Engine -Exactly 0
    Should -Invoke Save-RideOperationSnapshot -ModuleName RIDE.Engine -Exactly 0
    Should -Invoke Install-RidePackage -ModuleName RIDE.Engine -Exactly 0
    $DispatchLease.CanRead | Should -BeFalse
  }
  It 'retains the saved run failure contract and closes leases on handler failure' {
    Mock Install-RidePackage -ModuleName RIDE.Engine {throw 'injected offline handler failure'}
    {Invoke-RidePlan $DispatchPlan -OfflineBundle fixture -OfflineProfileId p -OfflineCatalogFileId c -Confirm:$false} | Should -Throw '*Run ID:*'
    Should -Invoke Save-RideOperationSnapshot -ModuleName RIDE.Engine -Exactly 1
    $DispatchLease.CanRead | Should -BeFalse
  }
}

Describe 'Offline handler cannot fall back to acquisition or certificate networking' {
  BeforeEach {
    $script:HandlerRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $HandlerRoot
    $script:HandlerPath=Join-Path $HandlerRoot 'fixture.ps1';[IO.File]::WriteAllText($HandlerPath,'# inert payload')
    $script:HandlerArtifact=[pscustomobject]@{Path=$HandlerPath;Sha256=(Get-FileHash -LiteralPath $HandlerPath).Hash;Version='1.0';Offline=$true}
    $script:HandlerOperation=@{Id='package.fixture';Name='Fixture';Kind='Package';PackageId='fixture';Scope='User';InstallerType='Portable';PortableFormat='File';PortableFileName='fixture.ps1';RequiredFiles=@('fixture.ps1');SelectedVariant='installed';ResolvedToolsDirectory=$HandlerRoot;InstallDirectory=(Join-Path $HandlerRoot 'fixture')}
    Mock Save-RidePackageArtifact -ModuleName RIDE-Packages {throw 'No network'}
    Mock Get-RidePackagePrerequisiteDirectory -ModuleName RIDE-Packages {}
    Mock Assert-RidePackageExecutionContext -ModuleName RIDE-Packages {}
    Mock Get-AuthenticodeSignature -ModuleName RIDE-PortablePackages {throw 'No certificate network provider'}
  }
  AfterEach {
    Should -Invoke Save-RidePackageArtifact -ModuleName RIDE-Packages -Exactly 0
    Should -Invoke Get-AuthenticodeSignature -ModuleName RIDE-PortablePackages -Exactly 0
  }
  It 'deploys only verified inert bytes and records skipped offline signature inspection' {
    $result=Install-RidePackage $HandlerOperation $HandlerRoot -OfflineArtifact $HandlerArtifact
    $result.Sha256 | Should -Be $HandlerArtifact.Sha256
    [IO.File]::ReadAllText((Join-Path $HandlerOperation.InstallDirectory 'fixture.ps1')) | Should -BeExactly '# inert payload'
    (Get-RidePortableState $HandlerOperation).Manifest.Files[0].AuthenticodeStatus | Should -Be NotInspectedOffline
  }
  It 'refuses <Case> without downloading or installing' -ForEach @(@{Case='Null'},@{Case='Changed'},@{Case='Installer'}) {
    switch($Case){Null {$HandlerArtifact=$null} Changed {[IO.File]::WriteAllText($HandlerPath,'changed')} Installer {$HandlerOperation.InstallerType='Exe'}}
    {Install-RidePackage $HandlerOperation $HandlerRoot -OfflineArtifact $HandlerArtifact} | Should -Throw
    Test-Path -LiteralPath $HandlerOperation.InstallDirectory | Should -BeFalse
  }
}
