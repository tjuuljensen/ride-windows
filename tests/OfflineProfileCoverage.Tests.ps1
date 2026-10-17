BeforeAll {
  $Repo=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Repo 'modules/RIDE.OfflineBundle.psm1') -Force
  function New-CoveragePackage([string]$Id='package.tool'){
    @{Id=$Id;Kind='Package';Scope='Machine';InstallerType='Exe';Architecture='x64';SupportedTargets=@('Windows 11');ProductUri='https://publisher.example/product';License='Fixture licence';LicenseUri='https://publisher.example/license';DownloadUri='https://publisher.example/tool.exe'}
  }
  function New-CoverageArtifact([string]$Id='tool',[string]$PackageId='package.tool'){
    [pscustomobject]@{Id=$Id;PackageId=$PackageId;Variant='installed';Version='1.0';Architecture='x64';Targets=@('Windows 11');Status='Included';OmissionCode=$null;FileIds=@('payload');DependencyIds=@();OfflineCapability='Unverified';ProductUri='https://publisher.example/product';DownloadUri='https://publisher.example/tool.exe';License='Fixture licence';LicenseUri='https://publisher.example/license'}
  }
  function New-CoverageManifest {
    [pscustomobject]@{SchemaVersion=1;Kind='RideOfflineBundle';BundleId='test';BundleVersion='v1';Engine=[pscustomobject]@{Version='3.0';SourceCommit=('a'*40);FileIds=@('catalog')};
      Files=@(
        [pscustomobject]@{Id='catalog';RelativePath='ride/catalog/operations.psd1';Role='Engine';Sha256=('b'*64);Length=10},
        [pscustomobject]@{Id='profile';RelativePath='ride/profiles/selected.psd1';Role='Profile';Sha256=('c'*64);Length=10},
        [pscustomobject]@{Id='payload';RelativePath='payload/tool.exe';Role='Payload';Sha256=('d'*64);Length=10}
      );Artifacts=@(New-CoverageArtifact);ServicingSources=@();Profiles=@([pscustomobject]@{Id='workstation';FileId='profile';Target='Windows 11';Build=26100;EditionId='Professional';Architecture='x64';ArtifactIds=@('tool');ServicingSourceIds=@()})}
  }
}
Describe 'Byte-bound offline profile coverage' {
  BeforeAll {
    function Set-CoverageSource {
      param($Manifest,[string]$Root,[string]$Id,[string]$Text)
      $record=$Manifest.Files|Where-Object Id -eq $Id
      $path=Join-Path $Root $record.RelativePath
      $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
      [IO.File]::WriteAllText($path,$Text,[Text.UTF8Encoding]::new($false))
      $record.Length=(Get-Item -LiteralPath $path).Length;$record.Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
    }
    $catalogSource=@'
@{
 SchemaVersion=1
 Operations=@(
  @{Id='package.tool';Kind='Package';Scope='Machine';InstallerType='Exe';Architecture='x64';SupportedTargets=@('Windows 11');ProductUri='https://publisher.example/product';License='Fixture licence';LicenseUri='https://publisher.example/license';DownloadUri='https://publisher.example/tool.exe'}
 )
 Groups=@()
}
'@
    $profileSource="@{SchemaVersion=1;Name='Fixture';Operations=@(@{Id='package.tool';State='Present'})}"
  }
  BeforeEach {
    $manifest=New-CoverageManifest;$bundleRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    Set-CoverageSource $manifest $bundleRoot catalog $catalogSource
    Set-CoverageSource $manifest $bundleRoot profile $profileSource
    Set-CoverageSource $manifest $bundleRoot payload 'inert executable fixture'
    $boundInput=@{Manifest=$manifest;Root=$bundleRoot;ProfileId='workstation';CatalogFileId='catalog'}
  }
  It 'hashes and parses the same captured catalog/profile bytes' {
    $r=Test-RideOfflineBundle @boundInput
    $r.ProfileCoverageStatus|Should -BeExactly Compared
    $r.ProfileCoverage.ParsedBytesBindingVerified|Should -BeTrue
    $r.SelectedPackageContentComplete|Should -BeTrue
    $r.ManifestCoverageVerified|Should -BeFalse;$r.ReadyForMutation|Should -BeFalse
    $r.ProfileCoverage.FileIntegrityVerified|Should -BeFalse
    $r.ProfileCoverage.CatalogSha256|Should -BeExactly $manifest.Files[0].Sha256
  }
  It 'exposes a profile omission even when all manifest-declared files pass' {
    $manifest.Profiles[0].ArtifactIds=@()
    $r=Test-RideOfflineBundle @boundInput
    $r.SelectedDeclaredContentComplete|Should -BeTrue
    $r.SelectedPackageContentComplete|Should -BeFalse
    $r.ProfileCoverage.CoverageIssues.Reason|Should -Contain MissingSelectedArtifact
  }
  It 'keeps original integrity-only behavior when coverage is not requested' {
    $boundInput.Remove('CatalogFileId')
    $r=Test-RideOfflineBundle @boundInput
    $r.ProfileCoverageStatus|Should -BeExactly NotRequested
    $r.ProfileCoverage|Should -BeNullOrEmpty
    $r.SelectedPackageContentComplete|Should -BeNullOrEmpty
  }
  It 'retains unavailable source evidence rather than parsing mismatched bytes' {
    [IO.File]::WriteAllText((Join-Path $bundleRoot 'ride/profiles/selected.psd1'),'changed',[Text.UTF8Encoding]::new($false))
    $r=Test-RideOfflineBundle @boundInput
    $r.ProfileCoverageStatus|Should -BeExactly SourceUnavailable
    $r.SelectedPackageContentComplete|Should -BeFalse
    $r.ProfileCoverage|Should -BeNullOrEmpty
  }
  It 'still compares package declarations when a selected payload is missing' {
    Remove-Item -LiteralPath (Join-Path $bundleRoot 'payload/tool.exe')
    $r=Test-RideOfflineBundle @boundInput
    $r.ProfileCoverageStatus|Should -BeExactly Compared
    $r.ProfileCoverage.SelectedPackageDeclarationsComplete|Should -BeTrue
    $r.SelectedPackageContentComplete|Should -BeFalse
  }
  It 'refuses <Case> executable or unsupported profile source without executing it' -ForEach @(
    @{Case='Command';Text="@{SchemaVersion=1;Name=(Get-Date);Operations=@()}"},
    @{Case='Statement';Text="throw 'executed'; @{SchemaVersion=1;Name='Fixture';Operations=@()}"},
    @{Case='Parameter';Text="param(); @{SchemaVersion=1;Name='Fixture';Operations=@()}"},
    @{Case='UnknownField';Text="@{SchemaVersion=1;Name='Fixture';Operations=@();Condition='Lenovo'}"}
  ) {
    Set-CoverageSource $manifest $bundleRoot profile $Text
    {Test-RideOfflineBundle @boundInput}|Should -Throw
  }
  It 'refuses executable catalog expressions without importing bundled code' {
    Set-CoverageSource $manifest $bundleRoot catalog "@{SchemaVersion=1;Operations=@(@{Id=(Get-Date)});Groups=@()}"
    {Test-RideOfflineBundle @boundInput}|Should -Throw
  }
  It 'refuses invalid UTF-8 instead of repairing source text before evaluation' {
    $record=$manifest.Files|Where-Object Id -eq profile;$path=Join-Path $bundleRoot $record.RelativePath
    [IO.File]::WriteAllBytes($path,[byte[]]@(0xff,0xfe,0xff));$record.Length=3;$record.Sha256=(Get-FileHash -LiteralPath $path).Hash
    {Test-RideOfflineBundle @boundInput}|Should -Throw
  }
  It 'applies source parser bounds before source file reads' {
    $manifest.Files[1].Length=65537
    {Test-RideOfflineBundle @boundInput}|Should -Throw '*64 KiB*'
  }
  It 'binds UTF-8 BOM bytes while parsing the intended text' {
    Set-CoverageSource $manifest $bundleRoot profile ([string][char]0xfeff+$profileSource)
    $r=Test-RideOfflineBundle @boundInput
    $r.SelectedPackageContentComplete|Should -BeTrue
    $r.ProfileCoverage.ProfileSha256|Should -BeExactly $manifest.Files[1].Sha256
  }
  It 'refuses a source digest that changes between integrity and bound parsing' {
    $record=$manifest.Files[1];$path=Join-Path $bundleRoot $record.RelativePath
    [IO.File]::WriteAllText($path,$profileSource.Replace('Fixture','Changed'),[Text.UTF8Encoding]::new($false))
    InModuleScope RIDE.OfflineBundle -Parameters @{Root=$bundleRoot;Record=$record} {
      param($Root,$Record)
      {Read-RideBundleBoundText -Root $Root -File $Record -MaximumBytes 64KB}|Should -Throw '*digest mismatch*'
    }
  }
  It 'refuses a new reparse point at the bound-read boundary' {
    InModuleScope RIDE.OfflineBundle -Parameters @{Root=$bundleRoot;Record=$manifest.Files[1]} {
      param($Root,$Record)
      Mock Get-RideBundlePathAttributes {[IO.FileAttributes]::ReparsePoint}
      {Read-RideBundleBoundText -Root $Root -File $Record -MaximumBytes 64KB}|Should -Throw '*reparse*'
    }
  }
  It 'runs CLI coverage and completes catalog file IDs from the manifest' {
    $path=Join-Path $bundleRoot manifest.json;$manifest|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $path -Encoding UTF8
    $tool=Join-Path $Repo tools/Test-RideOfflineBundle.ps1
    $r=& $tool -ManifestPath $path -ProfileId workstation -CatalogFileId catalog
    $r.ProfileCoverage.ParsedBytesBindingVerified|Should -BeTrue
    $r.ManifestSha256|Should -Match '^[a-f0-9]{64}$'
    $command=Get-Command $tool
    $completer=$command.Parameters['CatalogFileId'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $completer.ScriptBlock $tool CatalogFileId CAT $null @{ManifestPath=$path})
    $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly "'catalog'"
  }
}

Describe 'In-memory catalog data reader' {
  BeforeAll {Import-Module (Join-Path $Repo 'modules/RIDE.CatalogData.psm1') -Force}
  It 'matches the native file reader for the current full catalog' {
    $path=Join-Path $Repo catalog/operations.psd1
    $fromFile=Import-RideCatalogData -Path $path
    $fromText=Import-RideCatalogData -Content ([IO.File]::ReadAllText($path))
    $fromText.Operations.Count|Should -Be $fromFile.Operations.Count
    ($fromText.Operations.Id -join '|')|Should -BeExactly ($fromFile.Operations.Id -join '|')
    ($fromText.Groups.Id -join '|')|Should -BeExactly ($fromFile.Groups.Id -join '|')
    ($fromText.Operations|Where-Object Kind -eq LocalPasswordMaximumAge).States.Count|Should -Be 1000
  }
  It 'rejects <Case> content through the same declarative evaluator' -ForEach @(
    @{Case='Command';Text="@{SchemaVersion=1;Operations=@(@{Id=(Get-Date)});Groups=@()}"},
    @{Case='Duplicate';Text="@{SchemaVersion=1;SchemaVersion=1;Operations=@();Groups=@()}"},
    @{Case='Unknown';Text="@{SchemaVersion=1;Operations=@();Groups=@();Extra=1}"},
    @{Case='Statement';Text="Get-Date; @{SchemaVersion=1;Operations=@();Groups=@()}"}
  ) {{Import-RideCatalogData -Content $Text}|Should -Throw}
  It 'bounds UTF-8 bytes rather than only text character count' {
    {Import-RideCatalogData -Content ([string][char]0x20ac * 800000)}|Should -Throw '*2 MiB*'
  }
}
Describe 'Offline profile package coverage' {
  BeforeEach {
    $manifest=New-CoverageManifest
    $catalog=@{SchemaVersion=1;Operations=@(New-CoveragePackage);Groups=@()}
    $profile=@{SchemaVersion=1;Name='Fixture';Operations=@(@{Id='package.tool';State='Present'})}
    $inputData=@{Manifest=$manifest;ProfileId='workstation';CatalogFileId='catalog';Catalog=$catalog;Profile=$profile;CatalogSha256=('b'*64);ProfileSha256=('c'*64)}
  }
  It 'checks selected declarations without granting integrity or runtime readiness' {
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeTrue
    $r.PackageRequirements.Count|Should -Be 1
    $r.PackageRequirements[0].Status|Should -BeExactly Declared
    $r.SourceHashClaimsMatchManifest|Should -BeTrue
    foreach($field in @('ParsedBytesBindingVerified','FileIntegrityVerified','InstallerDependencyClosureVerified','NonPackageSourceCoverageVerified','ActualTargetVerified','ReadyForMutation','RecoverySupported','NetworkFallbackAllowed')){$r.$field|Should -BeFalse}
  }
  It 'finds a package omitted from an otherwise valid manifest selection' {
    $manifest.Profiles[0].ArtifactIds=@()
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeFalse
    $r.CoverageIssues.Reason|Should -Contain MissingSelectedArtifact
  }
  It 'does not count an unrelated full-bundle artifact as selected coverage' {
    $manifest.Artifacts+=New-CoverageArtifact extra package.other
    $manifest.Profiles[0].ArtifactIds=@('extra')
    (Test-RideOfflineProfileCoverage @inputData).CoverageIssues.Reason|Should -Contain MissingSelectedArtifact
  }
  It 'retains an explicit omission without silently selecting another artifact' {
    $manifest.Artifacts[0].Status='Omitted';$manifest.Artifacts[0].FileIds=@();$manifest.Artifacts[0].OmissionCode='Restricted'
    (Test-RideOfflineProfileCoverage @inputData).CoverageIssues.Reason|Should -Contain SelectedArtifactOmitted
  }
  It 'rejects mismatched <Field> source hash claims' -ForEach @(@{Field='CatalogSha256'},@{Field='ProfileSha256'}) {
    $inputData[$Field]='e'*64
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*hashes*'
  }
  It 'requires catalog binding to an engine file' {
    $inputData.CatalogFileId='payload';$inputData.CatalogSha256='d'*64
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*hashes*'
  }
  It 'does not resolve host preferences for a package with multiple variants' {
    $catalog.Operations[0].Variants=@{installed=@{};portable=@{InstallerType='Portable'}}
    $catalog.Operations[0].DefaultVariant='installed'
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeFalse
    $r.CoverageIssues.Reason|Should -Contain ExplicitVariantRequired
    $r.PackageRequirements.Count|Should -Be 0
  }
  It 'resolves only an explicitly selected variant and its publisher metadata' {
    $catalog.Operations[0].Variants=@{portable=@{InstallerType='Portable';Architecture='any';License='Portable terms'}}
    $profile.Operations[0].Variant='portable';$manifest.Artifacts[0].Variant='portable';$manifest.Artifacts[0].Architecture='any';$manifest.Artifacts[0].License='Portable terms'
    $before=$catalog|ConvertTo-Json -Depth 20 -Compress
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeTrue
    $r.PackageRequirements[0].Variant|Should -BeExactly portable
    ($catalog|ConvertTo-Json -Depth 20 -Compress)|Should -BeExactly $before
  }
  It 'refuses an undeclared explicit variant' {
    $profile.Operations[0].Variant='portable'
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*variant*'
  }
  It 'expands package groups in catalog order' {
    $catalog.Operations+=New-CoveragePackage package.second
    $catalog.Groups=@(@{Id='solution.tools';Members=@('package.second','package.tool')})
    $profile.Operations=@(@{Id='solution.tools';State='Present'})
    $manifest.Artifacts+=New-CoverageArtifact second package.second;$manifest.Profiles[0].ArtifactIds+=@('second')
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeTrue
    ($r.PackageRequirements.Id -join ',')|Should -BeExactly 'package.second,package.tool'
    $r.PackageRequirements[0].Origin|Should -BeExactly solution.tools
  }
  It 'requires flattening overlapping selections rather than guessing override precedence' {
    $catalog.Groups=@(@{Id='solution.tools';Members=@('package.tool')})
    $profile.Operations+=@{Id='solution.tools';State='Present'}
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*overlapping*'
  }
  It 'refuses a Store workflow group' {
    $catalog.Groups=@(@{Id='solution.store';Members=@('package.tool');Workflow='StoreApps'})
    $profile.Operations=@(@{Id='solution.store';State='Present'})
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*workflow*'
  }
  It 'finds a catalog prerequisite absent from the manifest graph' {
    $catalog.Operations[0].PrerequisitePackageId='package.runtime';$catalog.Operations+=New-CoveragePackage package.runtime
    $r=Test-RideOfflineProfileCoverage @inputData
    ($r.PackageRequirements.Id -join ',')|Should -BeExactly 'package.runtime,package.tool'
    $r.PackageRequirements[0].CatalogPrerequisite|Should -BeTrue
    $r.PackageRequirements[0].ExplicitlySelected|Should -BeFalse
    $r.CoverageIssues[0].Id|Should -BeExactly package.runtime
  }
  It 'accepts a declared prerequisite through the selected manifest dependency graph' {
    $catalog.Operations[0].PrerequisitePackageId='package.runtime';$catalog.Operations+=New-CoveragePackage package.runtime
    $manifest.Artifacts+=New-CoverageArtifact runtime package.runtime;$manifest.Artifacts[0].DependencyIds=@('runtime')
    (Test-RideOfflineProfileCoverage @inputData).SelectedPackageDeclarationsComplete|Should -BeTrue
  }
  It 'reports an explicitly absent prerequisite as a conflict' {
    $catalog.Operations[0].PrerequisitePackageId='package.runtime';$catalog.Operations+=New-CoveragePackage package.runtime
    $profile.Operations+=@{Id='package.runtime';State='Absent'}
    (Test-RideOfflineProfileCoverage @inputData).CoverageIssues.Reason|Should -Contain PrerequisiteSelectedAbsent
  }
  It 'refuses cyclic catalog prerequisites' {
    $catalog.Operations[0].PrerequisitePackageId='package.runtime';$catalog.Operations+=New-CoveragePackage package.runtime
    $catalog.Operations[1].PrerequisitePackageId='package.tool'
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*Cyclic*'
  }
  It 'refuses cyclic manifest dependencies independently' {
    $manifest.Artifacts[0].DependencyIds=@('tool')
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*Cyclic*'
  }
  It 'rejects ambiguous selected versions of the same package variant' {
    $manifest.Artifacts+=New-CoverageArtifact tool2 package.tool;$manifest.Profiles[0].ArtifactIds+=@('tool2')
    (Test-RideOfflineProfileCoverage @inputData).CoverageIssues.Reason|Should -Contain AmbiguousSelectedArtifact
  }
  It 'checks catalog <Field> metadata without inventing publisher authenticity' -ForEach @(
    @{Field='PackageVersion';Value='2.0';Reason='CatalogVersionMismatch'},
    @{Field='Architecture';Value='arm64';Reason='CatalogArchitectureMismatch'},
    @{Field='ProductUri';Value='https://publisher.example/other';Reason='CatalogPublisherMetadataMismatch'},
    @{Field='License';Value='Other terms';Reason='CatalogPublisherMetadataMismatch'},
    @{Field='LicenseUri';Value='https://publisher.example/other-terms';Reason='CatalogPublisherMetadataMismatch'},
    @{Field='TermsUri';Value='https://publisher.example/terms';Reason='CatalogPublisherMetadataMismatch'},
    @{Field='ExpectedSha256';Value=('e'*64);Reason='CatalogDigestMismatch'}
  ) {
    $catalog.Operations[0][$Field]=$Value
    (Test-RideOfflineProfileCoverage @inputData).CoverageIssues.Reason|Should -Contain $Reason
  }
  It 'compares exact catalog version and single-payload digest pins' {
    $catalog.Operations[0].PackageVersion='1.0';$catalog.Operations[0].ExpectedSha256='d'*64
    (Test-RideOfflineProfileCoverage @inputData).SelectedPackageDeclarationsComplete|Should -BeTrue
  }
  It 'refuses a changed download <Case> even with matching payload digest and version' -ForEach @(
    @{Case='host';Uri='https://other.example/tool.exe'},
    @{Case='path';Uri='https://publisher.example/Tool.exe'},
    @{Case='query';Uri='https://publisher.example/tool.exe?release=other'}
  ) {
    $catalog.Operations[0].PackageVersion='1.0';$catalog.Operations[0].ExpectedSha256='d'*64
    $manifest.Artifacts[0].DownloadUri=$Uri
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeFalse
    $r.CoverageIssues.Reason|Should -Contain CatalogDownloadUriMismatch
    $r.PackageRequirements[0].CatalogDownloadUriComparison|Should -BeExactly Mismatch
    $r.PackageRequirements[0].DownloadSourceVerified|Should -BeFalse
  }
  It 'compares the selected variant source instead of the parent package source' {
    $catalog.Operations[0].Variants=@{portable=@{DownloadUri='https://publisher.example/portable.zip'}}
    $profile.Operations[0].Variant='portable';$manifest.Artifacts[0].Variant='portable'
    (Test-RideOfflineProfileCoverage @inputData).SelectedPackageDeclarationsComplete|Should -BeFalse
    $manifest.Artifacts[0].DownloadUri='https://publisher.example/portable.zip'
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeTrue
    $r.PackageRequirements[0].CatalogDownloadUriComparison|Should -BeExactly Matched
    $r.PackageRequirements[0].DownloadSourceVerified|Should -BeFalse
  }
  It 'keeps provider-resolved source provenance explicitly unresolved' {
    $catalog.Operations[0].Remove('DownloadUri')
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.SelectedPackageDeclarationsComplete|Should -BeTrue
    $r.PackageRequirements[0].CatalogDownloadUriComparison|Should -BeExactly NotDeclared
    $r.PackageRequirements[0].DownloadSourceVerified|Should -BeFalse
    $r.ReadyForMutation|Should -BeFalse
  }
  It 'does not turn catalog target or pending declarations into actual target acceptance' {
    $catalog.Operations[0].SupportedTargets=@();$catalog.Operations[0].PendingAcceptance=$true
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.PackageRequirements[0].CatalogTargetDeclared|Should -BeFalse
    $r.PackageRequirements[0].PendingAcceptance|Should -BeTrue
    $r.ActualTargetVerified|Should -BeFalse
  }
  It 'keeps non-package selections and removal source needs unresolved' {
    $catalog.Operations+=@{Id='windows.setting';Kind='RegistryValue';States=@{Enabled=1;WindowsDefault=$null};BaselineState='WindowsDefault'}
    $profile.Operations=@(@{Id='windows.setting';State='Baseline'},@{Id='package.tool';State='Absent'})
    $r=Test-RideOfflineProfileCoverage @inputData
    $r.PackageRequirements.Count|Should -Be 0
    $r.OtherSelections.Count|Should -Be 2
    $r.OtherSelections[0].State|Should -BeExactly WindowsDefault
    $r.OtherSelections[1].Reason|Should -BeExactly RemovalAndRecoverySourceUnverified
    $r.NonPackageSourceCoverageVerified|Should -BeFalse
  }
  It 'refuses unknown conditional profile fields instead of dropping requirements' {
    $profile.Operations[0].Condition='CompatibleLenovo'
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw '*unknown field*'
  }
  It 'refuses duplicate, unknown or invalid selections: <Case>' -ForEach @(
    @{Case='Duplicate'},@{Case='Unknown'},@{Case='State'},@{Case='Empty'},@{Case='UnknownPrerequisite'}
  ) {
    switch($Case){
      Duplicate {$profile.Operations+=@{Id='PACKAGE.TOOL';State='Present'}}
      Unknown {$profile.Operations[0].Id='package.missing'}
      State {$profile.Operations[0].State='Enabled'}
      Empty {$profile.Operations=@()}
      UnknownPrerequisite {$catalog.Operations[0].PrerequisitePackageId='package.missing'}
    }
    {Test-RideOfflineProfileCoverage @inputData}|Should -Throw
  }
  It 'completes IDs from supplied metadata without file or host queries' {
    $command=Get-Command Test-RideOfflineProfileCoverage
    foreach($pair in @(@{Parameter='ProfileId';Prefix='WORK';Expected="'workstation'"},@{Parameter='CatalogFileId';Prefix='CAT';Expected="'catalog'"})){
      $completer=$command.Parameters[$pair.Parameter].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
      $matches=@(& $completer.ScriptBlock 'Test-RideOfflineProfileCoverage' $pair.Parameter $pair.Prefix $null @{Manifest=$manifest})
      $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly $pair.Expected
    }
  }
}
