BeforeAll {
  $Repo=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Repo 'modules/RIDE.OfflineBundle.psm1') -Force
  function New-BundleTestFile {
    param([string]$Root,[string]$Id,[string]$RelativePath,[string]$Role,[string]$Content='fixture')
    $path=Join-Path $Root $RelativePath
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path,$Content,[Text.UTF8Encoding]::new($false))
    [pscustomobject]@{Id=$Id;RelativePath=$RelativePath;Role=$Role;Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();Length=(Get-Item -LiteralPath $path).Length}
  }
  function New-BundleTestArtifact {
    param([string]$Id='tool',[string]$FileId='payload')
    [pscustomobject]@{Id=$Id;PackageId=('package.'+$Id);Variant='installed';Version='1.0';Architecture='x64';Targets=@('Windows 11');Status='Included';OmissionCode=$null;FileIds=@($FileId);DependencyIds=@();OfflineCapability='Unverified';ProductUri='https://publisher.example/product';DownloadUri='https://publisher.example/tool.exe';License='Fixture licence';LicenseUri='https://publisher.example/license#terms'}
  }
  function New-BundleFixture {
    param([string]$Root)
    $null=New-Item -ItemType Directory -Path $Root -Force
    $files=@(
      New-BundleTestFile $Root 'engine' 'ride/ride.ps1' Engine 'inert engine fixture'
      New-BundleTestFile $Root 'profile' 'ride/profiles/selected.psd1' Profile 'inert profile fixture'
      New-BundleTestFile $Root 'payload' 'payloads/tool.exe' Payload 'inert payload'
      New-BundleTestFile $Root 'notice' 'notices/tool.txt' Notice 'fixture notices'
    )
    $artifact=New-BundleTestArtifact;$artifact.FileIds=@('payload','notice')
    [pscustomobject]@{SchemaVersion=1;Kind='RideOfflineBundle';BundleId='test';BundleVersion='v1';Engine=[pscustomobject]@{Version='3.0';SourceCommit=('a'*40);FileIds=@('engine')};Files=$files;Artifacts=@($artifact);ServicingSources=@();Profiles=@([pscustomobject]@{Id='workstation';FileId='profile';Target='Windows 11';Build=26100;EditionId='Professional';Architecture='x64';ArtifactIds=@('tool');ServicingSourceIds=@()})}
  }
}

Describe 'Selected offline bundle integrity' {
  BeforeEach {
    Remove-Module RIDE.Engine -Force -ErrorAction SilentlyContinue
    $bundleRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $manifest=New-BundleFixture $bundleRoot
  }
  It 'checks local engine/profile/payload/notices and retains all unverified installation gates' {
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeTrue
    $r.Files.Count|Should -Be 4
    @($r.Files|Where-Object Status -ne Verified).Count|Should -Be 0
    $r.OfflineGates[0].Reason|Should -BeExactly Unverified
    $r.NetworkFallbackAllowed|Should -BeFalse;$r.ReadyForMutation|Should -BeFalse
    $r.ProfileDependencyClosureVerified|Should -BeFalse;$r.EngineSourceCommitVerified|Should -BeFalse
    $r.ManifestCoverageVerified|Should -BeFalse;$r.ActualTargetVerified|Should -BeFalse
    Get-Module RIDE.Engine|Should -BeNullOrEmpty
  }
  It 'does not block a complete selected profile on an unrelated restricted omission' {
    $other=New-BundleTestArtifact other unused;$other.Status='Omitted';$other.OmissionCode='Restricted';$other.FileIds=@()
    $manifest.Artifacts+=@($other)
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeTrue
    $r.BundleDeclaredStatus|Should -BeExactly Incomplete
    $r.BundleOmissions[0].Id|Should -BeExactly other
    $r.RequiredArtifactIds|Should -Not -Contain other
  }
  It 'finds missing transitive content and keeps dependency order without duplicate reads' {
    $dep=New-BundleTestArtifact dependency unused;$dep.Status='Omitted';$dep.OmissionCode='Missing';$dep.FileIds=@()
    $manifest.Artifacts+=@($dep);$manifest.Artifacts[0].DependencyIds=@('dependency')
    $manifest.Profiles[0].ArtifactIds=@('tool','dependency')
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeFalse
    $r.RequiredArtifactIds.Count|Should -Be 2
    $r.RequiredArtifactIds[0]|Should -BeExactly dependency
    $r.RequirementIssues[0].Reason|Should -BeExactly Missing
    $r.Files.Count|Should -Be 4
  }
  It 'reports <Case> without changing any existing file' -ForEach @(
    @{Case='Missing';Expected='Missing'},@{Case='Hash';Expected='HashMismatch'},
    @{Case='Length';Expected='LengthMismatch'},@{Case='Directory';Expected='NotAFile'}
  ) {
    $path=Join-Path $bundleRoot 'payloads/tool.exe'
    switch($Case){
      Missing {Remove-Item -LiteralPath $path}
      Hash {[IO.File]::WriteAllText($path,'different dat',[Text.UTF8Encoding]::new($false))}
      Length {[IO.File]::WriteAllText($path,'too long different data',[Text.UTF8Encoding]::new($false))}
      Directory {Remove-Item -LiteralPath $path;$null=New-Item -ItemType Directory -Path $path}
    }
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeFalse
    ($r.Files|Where-Object Id -eq payload).Status|Should -BeExactly $Expected
    Test-Path -LiteralPath (Join-Path $bundleRoot 'ride/ride.ps1')|Should -BeTrue
  }
  It 'recognizes declared architecture mismatch and network-required behavior separately' {
    $manifest.Artifacts[0].Architecture='arm64';$manifest.Artifacts[0].OfflineCapability='NetworkRequired'
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeFalse
    $r.RequirementIssues[0].Reason|Should -BeExactly DeclaredTargetOrArchitectureMismatch
    $r.OfflineGates[0].Reason|Should -BeExactly NetworkRequired
    @($r.Files|Where-Object Status -ne Verified).Count|Should -Be 0
  }
  It 'accepts catalog-neutral archive content for <Architecture> while retaining target and native gates' -ForEach @(@{Architecture='x64'},@{Architecture='x86'}) {
    $manifest.Artifacts[0].Architecture='neutral'
    $manifest.Profiles[0].Architecture=$Architecture
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeTrue
    $r.ActualTargetVerified|Should -BeFalse
    $r.ReadyForMutation|Should -BeFalse
    $manifest.Artifacts[0].Targets=@('Windows Server 2025')
    (Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation).RequirementIssues.Reason|Should -Contain DeclaredTargetOrArchitectureMismatch
  }
  It 'retains native servicing uncertainty even when all declared media metadata matches' {
    $manifest.Files+=New-BundleTestFile $bundleRoot media 'sources/fixture.cab' ServicingSource 'inert media'
    $manifest.ServicingSources=@([pscustomobject]@{Id='fod';Status='Included';OmissionCode=$null;FileIds=@('media');Target='Windows 11';Build=26100;EditionId='Professional';Architecture='x64';Compatibility='Unverified'})
    $manifest.Profiles[0].ServicingSourceIds=@('fod')
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeTrue
    $r.OfflineGates.Reason|Should -Contain NativeServicingCompatibilityUnverified
    $manifest.ServicingSources[0].Build=26200
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeFalse
    $r.RequirementIssues.Reason|Should -Contain DeclaredServicingMetadataMismatch
  }
  It 'works after copying the declared files to a different root without changing identities' {
    $copyRoot=Join-Path $TestDrive 'moved'
    $null=New-Item -ItemType Directory -Path $copyRoot
    foreach($file in $manifest.Files){$dest=Join-Path $copyRoot $file.RelativePath;$null=New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force;Copy-Item -LiteralPath (Join-Path $bundleRoot $file.RelativePath) -Destination $dest}
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $copyRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeTrue
    $r.BundleId|Should -BeExactly test
    ($r|ConvertTo-Json -Depth 15)|Should -Not -Match ([regex]::Escape($bundleRoot))
  }
  It 'handles identities named Keys and Values without treating them as hashtable properties' {
    $manifest.Artifacts[0].Id='Values';$manifest.Profiles[0].ArtifactIds=@('Values')
    $manifest.Files[0].Id='Keys';$manifest.Engine.FileIds=@('Keys')
    (Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation).SelectedDeclaredContentComplete|Should -BeTrue
  }
  It 'refuses <Case> before payload observation' -ForEach @(
    @{Case='Schema'},@{Case='UnknownField'},@{Case='DuplicateFile'},@{Case='CasePath'},@{Case='Traversal'},
    @{Case='Absolute'},@{Case='Ads'},@{Case='Reserved'},@{Case='TrailingDot'},@{Case='PathCollision'},
    @{Case='Hash'},@{Case='NegativeLength'},@{Case='EngineMissing'},@{Case='ProfileMissing'},
    @{Case='UnknownDependency'},@{Case='Cycle'},@{Case='BadSource'},@{Case='CredentialSource'},
    @{Case='MissingLicence'},@{Case='OmittedWithFiles'},@{Case='NoPayload'},@{Case='ByteBound'},@{Case='PrivateReview'}
  ) {
    $maxBytes=137438953472
    switch($Case){
      Schema {$manifest.SchemaVersion=2}
      UnknownField {$manifest|Add-Member Surprise secret}
      DuplicateFile {$manifest.Files+=@($manifest.Files[0])}
      CasePath {$manifest.Files[1].RelativePath='RIDE/RIDE.PS1'}
      Traversal {$manifest.Files[2].RelativePath='../outside.exe'}
      Absolute {$manifest.Files[2].RelativePath='C:/outside.exe'}
      Ads {$manifest.Files[2].RelativePath='payloads/tool.exe:stream'}
      Reserved {$manifest.Files[2].RelativePath='payloads/CON.exe'}
      TrailingDot {$manifest.Files[2].RelativePath='payloads/tool.'}
      PathCollision {$manifest.Files[2].RelativePath='ride/ride.ps1/child'}
      Hash {$manifest.Files[2].Sha256='wrong'}
      NegativeLength {$manifest.Files[2].Length=-1}
      EngineMissing {$manifest.Engine.FileIds=@('absent')}
      ProfileMissing {$manifest.Profiles[0].FileId='absent'}
      UnknownDependency {$manifest.Artifacts[0].DependencyIds=@('unknown')}
      Cycle {$manifest.Artifacts[0].DependencyIds=@('tool')}
      BadSource {$manifest.Artifacts[0].DownloadUri='http://publisher.example/tool.exe'}
      CredentialSource {$manifest.Artifacts[0].DownloadUri='https://secret:password@publisher.example/tool.exe'}
      MissingLicence {$manifest.Artifacts[0].License=''}
      OmittedWithFiles {$manifest.Artifacts[0].Status='Omitted';$manifest.Artifacts[0].OmissionCode='Missing'}
      NoPayload {$manifest.Artifacts[0].FileIds=@('notice')}
      ByteBound {$maxBytes=1}
      PrivateReview {$manifest.Artifacts[0]|Add-Member LicenseReviewStatus Reviewed}
    }
    Mock Get-RideBundleFileObservation -ModuleName RIDE.OfflineBundle {throw 'must not read'}
    {Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation -MaximumBytes $maxBytes}|Should -Throw
    Should -Invoke Get-RideBundleFileObservation -ModuleName RIDE.OfflineBundle -Exactly 0
  }
  It 'keeps a reparse-point observation as an explicit incomplete result' {
    Mock Test-Path -ModuleName RIDE.OfflineBundle {$true}
    # Mock the bounded reader result; native junction creation is outside workstation tests.
    Mock Get-RideBundleFileObservation -ModuleName RIDE.OfflineBundle -ParameterFilter {$File.Id -eq 'payload'} {[pscustomobject]@{Id='payload';RelativePath='payloads/tool.exe';Status='ReparsePoint';Length=$null;Sha256=$null;ErrorId=$null}}
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeFalse
    ($r.Files|Where-Object Id -eq payload).Status|Should -BeExactly ReparsePoint
  }
  It 'does not open a member stream when an ancestor is a reparse point' {
    Mock Get-RideBundlePathAttributes -ModuleName RIDE.OfflineBundle -ParameterFilter {$Path -like '*payloads'} {[IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint}
    Mock Open-RideBundleReadStream -ModuleName RIDE.OfflineBundle -ParameterFilter {$Path -like '*tool.exe'} {throw 'must not follow'}
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    ($r.Files|Where-Object Id -eq payload).Status|Should -BeExactly ReparsePoint
    Should -Invoke Open-RideBundleReadStream -ModuleName RIDE.OfflineBundle -ParameterFilter {$Path -like '*tool.exe'} -Exactly 0
  }
  It 'refuses a reparse root before opening any member stream' {
    Mock Get-RideBundlePathAttributes -ModuleName RIDE.OfflineBundle -ParameterFilter {$Path -eq $bundleRoot} {[IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint}
    Mock Open-RideBundleReadStream -ModuleName RIDE.OfflineBundle {throw 'must not open'}
    {Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation}|Should -Throw '*root ancestry*'
    Should -Invoke Open-RideBundleReadStream -ModuleName RIDE.OfflineBundle -Exactly 0
  }
  It 'marks an inaccessible selected file unavailable without exporting the provider error text' {
    Mock Open-RideBundleReadStream -ModuleName RIDE.OfflineBundle -ParameterFilter {$Path -like '*tool.exe'} {throw 'sensitive fixture detail'}
    $r=Test-RideOfflineBundle -Manifest $manifest -Root $bundleRoot -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeFalse
    ($r.Files|Where-Object Id -eq payload).Status|Should -BeExactly Unavailable
    ($r|ConvertTo-Json -Depth 15)|Should -Not -Match 'sensitive fixture detail'
  }
}

Describe 'Offline bundle CLI and completion' {
  BeforeEach {
    Remove-Module RIDE.Engine -Force -ErrorAction SilentlyContinue
    $bundleRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $manifest=New-BundleFixture $bundleRoot
    $manifestPath=Join-Path $bundleRoot 'manifest.json'
    [IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
    $tool=Join-Path $Repo 'tools/Test-RideOfflineBundle.ps1'
  }
  It 'reads the local manifest and binds its exact bytes without writing any bundle file' {
    $before=@(Get-ChildItem -LiteralPath $bundleRoot -Recurse -File).Count
    $r=& $tool -ManifestPath $manifestPath -ProfileId workstation
    $r.SelectedDeclaredContentComplete|Should -BeTrue
    $r.ManifestSha256|Should -BeExactly ((Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant())
    @(Get-ChildItem -LiteralPath $bundleRoot -Recurse -File).Count|Should -Be $before
  }
  It 'rejects invalid JSON without invoking the verifier' {
    [IO.File]::WriteAllText($manifestPath,'not json secret')
    {& $tool -ManifestPath $manifestPath -ProfileId workstation}|Should -Throw '*not valid UTF-8 JSON*'
  }
  It 'completes CLI and API profile IDs from supplied metadata only' {
    $line="& '$tool' -ManifestPath '$manifestPath' -ProfileId WORK"
    $matches=(TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches
    @($matches|Where-Object ListItemText -eq workstation).Count|Should -Be 1
    $attribute=(Get-Command Test-RideOfflineBundle).Parameters['ProfileId'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $api=@(& $attribute.ScriptBlock '' '' 'work' $null @{Manifest=$manifest})
    $api.Count|Should -Be 1;$api[0].ListItemText|Should -BeExactly workstation
    Get-Module RIDE.Engine|Should -BeNullOrEmpty
  }
}
