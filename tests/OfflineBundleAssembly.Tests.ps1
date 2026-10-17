BeforeAll {
  $Repo=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Repo 'modules/RIDE.OfflineBundle.psm1') -Force
  function New-AssemblyFixture([string]$Root){
    $null=New-Item -ItemType Directory -Path $Root -Force
    $map=@{};$files=@(foreach($entry in @(
      @{Id='engine';Path='ride/ride.ps1';Role='Engine';Text='inert engine fixture'},
      @{Id='profile';Path='ride/profiles/selected.psd1';Role='Profile';Text='inert profile fixture'},
      @{Id='payload';Path='payloads/tool.exe';Role='Payload';Text='inert payload fixture'}
    )){
      $path=Join-Path $Root ($entry.Id+'.source');[IO.File]::WriteAllText($path,$entry.Text,[Text.UTF8Encoding]::new($false));$map[$entry.Id]=$path
      [pscustomobject]@{Id=$entry.Id;RelativePath=$entry.Path;Role=$entry.Role;Sha256=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant();Length=(Get-Item -LiteralPath $path).Length}
    })
    $artifact=[pscustomobject]@{Id='tool';PackageId='package.tool';Variant='installed';Version='1.0';Architecture='x64';Targets=@('Windows 11');Status='Included';OmissionCode=$null;FileIds=@('payload');DependencyIds=@();OfflineCapability='Unverified';ProductUri='https://publisher.example/product';DownloadUri='https://publisher.example/tool.exe';License='Fixture licence';LicenseUri='https://publisher.example/license'}
    $manifest=[pscustomobject]@{SchemaVersion=1;Kind='RideOfflineBundle';BundleId='test';BundleVersion='v1';Engine=[pscustomobject]@{Version='3.0';SourceCommit=('a'*40);FileIds=@('engine')};Files=$files;Artifacts=@($artifact);ServicingSources=@();Profiles=@([pscustomobject]@{Id='workstation';FileId='profile';Target='Windows 11';Build=26100;EditionId='Professional';Architecture='x64';ArtifactIds=@('tool');ServicingSourceIds=@()})}
    @{Manifest=$manifest;SourceFiles=$map}
  }
}
Describe 'Explicit local offline bundle assembly' {
  BeforeEach {
    $fixture=New-AssemblyFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
    $manifest=$fixture.Manifest;$sources=$fixture.SourceFiles
    $destination=Join-Path $TestDrive ('bundle-'+[guid]::NewGuid().ToString('N'))
    $inputData=@{Manifest=$manifest;SourceFiles=$sources;DestinationPath=$destination;Confirm=$false}
  }
  It 'copies verified content and emits transferable metadata without source paths' {
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Completed;$r.VerifiedFileIds.Count|Should -Be 3
    $r.StagingPath|Should -BeNullOrEmpty;$r.ReadyForMutation|Should -BeFalse
    $r.CoverageStatus|Should -BeExactly NotRequested
    $r.EngineSourceCommitVerified|Should -BeFalse;$r.RedistributionApproved|Should -BeFalse
    $saved=Get-Content -LiteralPath (Join-Path $destination manifest.json) -Raw|ConvertFrom-Json
    (Test-RideOfflineBundle -Manifest $saved -Root $destination -ProfileId workstation).SelectedDeclaredContentComplete|Should -BeTrue
    $record=Get-Content -LiteralPath (Join-Path $destination assembly.json) -Raw|ConvertFrom-Json
    $record.Status|Should -BeExactly Complete
    (Get-Content -LiteralPath (Join-Path $destination manifest.json) -Raw)|Should -Not -Match ([regex]::Escape($TestDrive))
    foreach($path in $sources.get_Values()){Test-Path -LiteralPath $path|Should -BeTrue}
  }
  It 'previews without creating staging or output files' {
    $before=@(Get-ChildItem -LiteralPath $TestDrive -Force).Count
    $r=New-RideOfflineBundle @inputData -WhatIf
    $r.Status|Should -BeExactly Preview;$r.StagingPath|Should -BeNullOrEmpty
    Test-Path -LiteralPath $destination|Should -BeFalse
    @(Get-ChildItem -LiteralPath $TestDrive -Force).Count|Should -Be $before
  }
  It 'refuses an earlier staged file changed during a later copy' {
    Mock Copy-RideAssemblyFile -ModuleName RIDE.OfflineBundle {
      param($Source,$Destination,$File)
      [IO.File]::Copy($Source,$Destination,$false)
      if($File.Id -eq 'profile'){
        $earlier=Join-Path (Split-Path -Parent ([IO.Path]::GetDirectoryName($Destination))) 'ride.ps1'
        $text=[IO.File]::ReadAllText($earlier)
        [IO.File]::WriteAllText($earlier,$text.Replace('inert','other'),[Text.UTF8Encoding]::new($false))
      }
    }
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed
    $r.FailureStage|Should -BeExactly ReverifyStagedFiles
    $r.FailedFileId|Should -BeExactly engine
    $r.VerifiedFileIds|Should -Not -Contain engine
    Test-Path -LiteralPath $destination|Should -BeFalse
    Test-Path -LiteralPath $r.StagingPath|Should -BeTrue
    Test-Path -LiteralPath (Join-Path $r.StagingPath manifest.json)|Should -BeFalse
    [IO.File]::ReadAllText((Join-Path $r.StagingPath ride/ride.ps1))|Should -BeExactly 'other engine fixture'
    [IO.File]::ReadAllText($sources.engine)|Should -BeExactly 'inert engine fixture'
  }
  It 'verifies streaming content across multiple buffers and an empty file' {
    $bytes=[byte[]]::new(2MB+13);[Random]::new(42).NextBytes($bytes)
    [IO.File]::WriteAllBytes($sources.payload,$bytes)
    $payload=$manifest.Files|Where-Object Id -eq payload;$payload.Length=$bytes.Length;$payload.Sha256=(Get-FileHash -LiteralPath $sources.payload).Hash
    [IO.File]::WriteAllBytes($sources.engine,[byte[]]::new(0))
    $engine=$manifest.Files|Where-Object Id -eq engine;$engine.Length=0;$engine.Sha256=(Get-FileHash -LiteralPath $sources.engine).Hash
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Completed
    (Get-FileHash -LiteralPath (Join-Path $destination payloads/tool.exe)).Hash|Should -BeExactly $payload.Sha256
    (Get-Item -LiteralPath (Join-Path $destination ride/ride.ps1)).Length|Should -Be 0
  }
  It 'preserves an existing destination <Kind>' -ForEach @(@{Kind='Directory'},@{Kind='File'}) {
    if($Kind -eq 'Directory'){$null=New-Item -ItemType Directory -Path $destination;[IO.File]::WriteAllText((Join-Path $destination sentinel),'keep')}
    else{[IO.File]::WriteAllText($destination,'keep')}
    {New-RideOfflineBundle @inputData}|Should -Throw '*already exists*'
    $path=if($Kind -eq 'Directory'){Join-Path $destination sentinel}else{$destination}
    [IO.File]::ReadAllText($path)|Should -BeExactly keep
  }
  It 'retains failed staging on a changed source digest and reports the file' {
    $path=$sources.payload;$text=[IO.File]::ReadAllText($path);[IO.File]::WriteAllText($path,$text.Replace('inert','other'))
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed;$r.FailureStage|Should -BeExactly CopyAndVerifyFile
    $r.FailedFileId|Should -BeExactly payload;$r.VerifiedFileIds|Should -Contain engine
    Test-Path -LiteralPath $r.StagingPath|Should -BeTrue
    Test-Path -LiteralPath $destination|Should -BeFalse
    Test-Path -LiteralPath (Join-Path $r.StagingPath manifest.json)|Should -BeFalse
    [IO.File]::ReadAllText($path)|Should -BeExactly $text.Replace('inert','other')
  }
  It 'retains incomplete staging on a source length mismatch' {
    [IO.File]::WriteAllText($sources.payload,'changed length')
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed;Test-Path -LiteralPath $r.StagingPath|Should -BeTrue
    Test-Path -LiteralPath $destination|Should -BeFalse
  }
  It 'retains explicit omissions while assembling the available partial bundle' {
    $other=$manifest.Artifacts[0].PSObject.Copy();$other.Id='missing';$other.PackageId='package.missing';$other.Status='Omitted';$other.OmissionCode='TechnicalPending';$other.FileIds=@()
    $manifest.Artifacts+=@($other)
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Completed;$r.DeclaredOmissions.Count|Should -Be 1
    $r.DeclaredOmissions[0].Id|Should -BeExactly missing
    (Test-RideOfflineBundle -Manifest $manifest -Root $destination -ProfileId workstation).SelectedDeclaredContentComplete|Should -BeTrue
  }
  It 'keeps previous versions intact during a new assembly' {
    $old=Join-Path $TestDrive old;$null=New-Item -ItemType Directory -Path $old -Force
    $sentinel=Join-Path $old manifest.json;[IO.File]::WriteAllText($sentinel,'prior version')
    (New-RideOfflineBundle @inputData).Status|Should -BeExactly Completed
    [IO.File]::ReadAllText($sentinel)|Should -BeExactly 'prior version'
  }
  It 'refuses <Case> source mappings before staging' -ForEach @(
    @{Case='Missing'},@{Case='Extra'},@{Case='NonString'},@{Case='MissingFile'},@{Case='Directory'},@{Case='UNC'},@{Case='Traversal'},@{Case='ADS'}
  ) {
    switch($Case){
      Missing {$sources.Remove('payload')}
      Extra {$sources.extra=$sources.payload}
      NonString {$sources.payload=@('a','b')}
      MissingFile {$sources.payload=Join-Path $TestDrive missing}
      Directory {$sources.payload=$TestDrive}
      UNC {$sources.payload='\\server\share\file'}
      Traversal {$sources.payload=$TestDrive+'\..\file'}
      ADS {$sources.payload+=':stream'}
    }
    {New-RideOfflineBundle @inputData}|Should -Throw
    Test-Path -LiteralPath $destination|Should -BeFalse
  }
  It 'bounds the entire bundle before staging' {
    $inputData.MaximumBytes=1
    {New-RideOfflineBundle @inputData}|Should -Throw '*byte bound*'
    Test-Path -LiteralPath $destination|Should -BeFalse
  }
  It 'refuses metadata collisions at <Path>' -ForEach @(@{Path='manifest.json'},@{Path='ASSEMBLY.json'},@{Path='manifest.json/nested'}) {
    $manifest.Files[0].RelativePath=$Path
    {New-RideOfflineBundle @inputData}|Should -Throw '*reserved*'
  }
  It 'refuses unreferenced files instead of copying undeclared extras' {
    $manifest.Files[0].Role='Notice';$manifest.Engine.FileIds=@('profile');$manifest.Files[1].Role='Engine'
    # Keep the profile role valid using a distinct manifest file and then expose the orphan.
    $profileRecord=$manifest.Files[1].PSObject.Copy();$profileRecord.Id='other-profile';$profileRecord.RelativePath='profiles/other.psd1';$profileRecord.Role='Profile'
    $manifest.Files+=@($profileRecord);$manifest.Profiles[0].FileId='other-profile';$sources['other-profile']=$sources.profile
    {New-RideOfflineBundle @inputData}|Should -Throw '*unreferenced*'
  }
  It 'does not create missing destination parents' {
    $inputData.DestinationPath=Join-Path $TestDrive 'nonexistent-parent/bundle'
    {New-RideOfflineBundle @inputData}|Should -Throw
    Test-Path -LiteralPath (Join-Path $TestDrive nonexistent-parent)|Should -BeFalse
  }
  It 'refuses reparse ancestry without creating native junctions' {
    InModuleScope RIDE.OfflineBundle -Parameters @{InputData=$inputData} {
      param($InputData)
      Mock Get-RideBundlePathAttributes {[IO.FileAttributes]::ReparsePoint}
      {New-RideOfflineBundle @InputData}|Should -Throw '*reparse*'
    }
  }
  It 'preserves a competing destination created before the final move' {
    InModuleScope RIDE.OfflineBundle -Parameters @{InputData=$inputData;Destination=$destination} {
      param($InputData,$Destination)
      $script:assemblyCollisionDestination=$Destination
      Mock Get-RideBundleFileObservation {
        $null=[IO.Directory]::CreateDirectory($script:assemblyCollisionDestination)
        [IO.File]::WriteAllText((Join-Path $script:assemblyCollisionDestination sentinel),'competing owner')
        [pscustomobject]@{Status='Verified'}
      }
      $r=New-RideOfflineBundle @InputData
      $r.Status|Should -BeExactly Failed;$r.FailureStage|Should -BeExactly CommitDirectory
      Test-Path -LiteralPath $r.StagingPath|Should -BeTrue
      [IO.File]::ReadAllText((Join-Path $Destination sentinel))|Should -BeExactly 'competing owner'
    }
  }
  It 'does not overwrite an already-created staged file' {
    $existing=Join-Path $TestDrive existing;[IO.File]::WriteAllText($existing,'keep')
    InModuleScope RIDE.OfflineBundle -Parameters @{Source=$sources.payload;Destination=$existing;Record=$manifest.Files[2]} {
      param($Source,$Destination,$Record)
      {Copy-RideAssemblyFile -Source $Source -Destination $Destination -File $Record}|Should -Throw
      [IO.File]::ReadAllText($Destination)|Should -BeExactly keep
    }
  }
  It 'runs the CLI from explicit JSON inputs and honors WhatIf' {
    $manifestPath=Join-Path $TestDrive manifest.json;$mapPath=Join-Path $TestDrive sources.json
    $manifest|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $sources|ConvertTo-Json|Set-Content -LiteralPath $mapPath -Encoding UTF8
    $tool=Join-Path $Repo tools/New-RideOfflineBundle.ps1
    $preview=& $tool -ManifestPath $manifestPath -SourceMapPath $mapPath -DestinationPath $destination -WhatIf
    $preview.Status|Should -BeExactly Preview;Test-Path -LiteralPath $destination|Should -BeFalse
    $r=& $tool -ManifestPath $manifestPath -SourceMapPath $mapPath -DestinationPath $destination -Confirm:$false
    $r.Status|Should -BeExactly Completed
  }
}

Describe 'Offline assembly selected-profile coverage gate' {
  BeforeAll {
    function Set-AssemblySource($Manifest,$Sources,[string]$Id,[string]$Text){
      [IO.File]::WriteAllText($Sources[$Id],$Text,[Text.UTF8Encoding]::new($false))
      $file=$Manifest.Files|Where-Object Id -eq $Id
      $file.Length=(Get-Item -LiteralPath $Sources[$Id]).Length
      $file.Sha256=(Get-FileHash -LiteralPath $Sources[$Id]).Hash.ToLowerInvariant()
    }
  }
  BeforeEach {
    $fixture=New-AssemblyFixture (Join-Path $TestDrive ([guid]::NewGuid().ToString('N')))
    $manifest=$fixture.Manifest;$sources=$fixture.SourceFiles
    $destination=Join-Path $TestDrive ('coverage-'+[guid]::NewGuid().ToString('N'))
    $catalogText="@{SchemaVersion=1;Operations=@(@{Id='package.tool';Kind='Package';Scope='Machine';InstallerType='Exe';Architecture='x64';SupportedTargets=@('Windows 11');ProductUri='https://publisher.example/product';License='Fixture licence';LicenseUri='https://publisher.example/license';DownloadUri='https://publisher.example/tool.exe'});Groups=@()}"
    $profileText="@{SchemaVersion=1;Name='Fixture';Operations=@(@{Id='package.tool';State='Present'})}"
    Set-AssemblySource $manifest $sources engine $catalogText
    Set-AssemblySource $manifest $sources profile $profileText
    $inputData=@{Manifest=$manifest;SourceFiles=$sources;DestinationPath=$destination;CatalogFileId='engine';CoverageProfileId=@('workstation');Confirm=$false}
  }
  It 'records bound selected coverage without implying installation readiness' {
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Completed;$r.CoverageStatus|Should -BeExactly Passed
    $r.FailedProfileId|Should -BeNullOrEmpty;$r.CoverageReports.Count|Should -Be 1
    $r.CoverageReports[0].ProfileCoverage.ParsedBytesBindingVerified|Should -BeTrue
    $r.CoverageReports[0].SelectedPackageContentComplete|Should -BeTrue
    $r.CoverageReports[0].OfflineGates.Count|Should -BeGreaterThan 0
    $r.ReadyForMutation|Should -BeFalse
    $saved=Get-Content -LiteralPath (Join-Path $destination assembly.json) -Raw|ConvertFrom-Json
    $saved.CoverageStatus|Should -BeExactly Passed
    $saved.CoverageProfileIds|Should -Be @('workstation')
    $saved.CatalogFileId|Should -BeExactly engine
    $saved.ReadyForMutation|Should -BeFalse
  }
  It 'retains failed staging when selected package declarations are incomplete' {
    $manifest.Profiles[0].ArtifactIds=@()
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed;$r.FailureStage|Should -BeExactly CheckProfileCoverage
    $r.CoverageStatus|Should -BeExactly Failed;$r.FailedProfileId|Should -BeExactly workstation
    $r.CoverageReports[0].ProfileCoverage.CoverageIssues.Reason|Should -Contain MissingSelectedArtifact
    Test-Path -LiteralPath $destination|Should -BeFalse
    Test-Path -LiteralPath $r.StagingPath|Should -BeTrue
    foreach($name in @('manifest.json','assembly.json')){Test-Path -LiteralPath (Join-Path $r.StagingPath $name)|Should -BeFalse}
    [IO.File]::ReadAllText($sources.payload)|Should -BeExactly 'inert payload fixture'
  }
  It 'checks every explicitly selected profile and identifies the failed one' {
    $second=$manifest.Profiles[0].PSObject.Copy();$second.Id='second';$second.ArtifactIds=@()
    $manifest.Profiles+=@($second);$inputData.CoverageProfileId=@('workstation','second')
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed;$r.FailedProfileId|Should -BeExactly second
    $r.CoverageReports.Count|Should -Be 2
    $r.CoverageReports[0].SelectedPackageContentComplete|Should -BeTrue
    $r.CoverageReports[1].SelectedPackageContentComplete|Should -BeFalse
  }
  It 'allows an unrelated omitted artifact and an unselected incomplete profile' {
    $extra=$manifest.Artifacts[0].PSObject.Copy();$extra.Id='other';$extra.PackageId='package.other';$extra.Status='Omitted';$extra.OmissionCode='Restricted';$extra.FileIds=@()
    $manifest.Artifacts+=@($extra)
    $second=$manifest.Profiles[0].PSObject.Copy();$second.Id='second';$second.ArtifactIds=@('other');$manifest.Profiles+=@($second)
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Completed;$r.DeclaredOmissions.Id|Should -Contain other
    $r.CoverageProfileIds|Should -Be @('workstation')
  }
  It 'refuses selected source mismatch without fetching a replacement' {
    $manifest.Artifacts[0].DownloadUri='https://publisher.example/different.exe'
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed
    $r.CoverageReports[0].ProfileCoverage.CoverageIssues.Reason|Should -Contain CatalogDownloadUriMismatch
    Test-Path -LiteralPath $destination|Should -BeFalse
  }
  It 'refuses executable <Id> content without running it' -ForEach @(@{Id='engine'},@{Id='profile'}) {
    Set-AssemblySource $manifest $sources $Id "throw 'Do not execute bundled code'; @{}"
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed;$r.FailureStage|Should -BeExactly CheckProfileCoverage
    $r.FailedProfileId|Should -BeExactly workstation
    Test-Path -LiteralPath (Join-Path $r.StagingPath manifest.json)|Should -BeFalse
  }
  It 'does not claim coverage or write staging during preview' {
    $manifest.Profiles[0].ArtifactIds=@()
    $before=@(Get-ChildItem -LiteralPath $TestDrive -Force).Count
    $r=New-RideOfflineBundle @inputData -WhatIf
    $r.Status|Should -BeExactly Preview;$r.CoverageStatus|Should -BeExactly Pending
    $r.CoverageReports.Count|Should -Be 0
    @(Get-ChildItem -LiteralPath $TestDrive -Force).Count|Should -Be $before
  }
  It 'refuses an unmatched <Parameter> parameter before creating staging' -ForEach @(@{Parameter='CatalogFileId'},@{Parameter='CoverageProfileId'}) {
    $inputData.Remove($Parameter)
    {New-RideOfflineBundle @inputData}|Should -Throw '*together*'
    Test-Path -LiteralPath $destination|Should -BeFalse
  }
  It 'refuses invalid <Case> selection before staging' -ForEach @(
    @{Case='unknown profile';Field='CoverageProfileId';Value=@('missing')},
    @{Case='duplicate profiles';Field='CoverageProfileId';Value=@('workstation','WORKSTATION')},
    @{Case='unknown catalog';Field='CatalogFileId';Value='missing'},
    @{Case='payload catalog';Field='CatalogFileId';Value='payload'}
  ) {
    $inputData[$Field]=$Value
    {New-RideOfflineBundle @inputData}|Should -Throw
    Test-Path -LiteralPath $destination|Should -BeFalse
  }
  It 'bounds the declared <Id> source before staging' -ForEach @(@{Id='engine';Length=2097153},@{Id='profile';Length=65537}) {
    ($manifest.Files|Where-Object Id -eq $Id).Length=$Length
    {New-RideOfflineBundle @inputData}|Should -Throw '*larger*'
  }
  It 'still detects staged tampering during the optional coverage phase' {
    Mock Test-RideOfflineBundle -ModuleName RIDE.OfflineBundle {
      param($Manifest,$Root)
      [IO.File]::WriteAllText((Join-Path $Root 'payloads/tool.exe'),'changed')
      [pscustomobject]@{SelectedPackageContentComplete=$true}
    }
    $r=New-RideOfflineBundle @inputData
    $r.Status|Should -BeExactly Failed;$r.FailureStage|Should -BeExactly ReverifyStagedFiles
    $r.FailedFileId|Should -BeExactly payload
    Test-Path -LiteralPath (Join-Path $r.StagingPath assembly.json)|Should -BeFalse
  }
  It 'completes <Parameter> IDs read-only in both the module and CLI' -ForEach @(
    @{Parameter='CoverageProfileId';Prefix='WORK';Expected="'workstation'"},
    @{Parameter='CatalogFileId';Prefix='ENG';Expected="'engine'"}
  ) {
    $path=Join-Path $TestDrive 'completion-manifest.json'
    $manifest|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $path -Encoding UTF8
    foreach($command in @('New-RideOfflineBundle',(Join-Path $Repo tools/New-RideOfflineBundle.ps1))){
      $attribute=(Get-Command $command).Parameters[$Parameter].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
      $matches=@(& $attribute.ScriptBlock $command $Parameter $Prefix $null @{Manifest=$manifest;ManifestPath=$path})
      $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly $Expected
      @(& $attribute.ScriptBlock $command $Parameter 'missing' $null @{}).Count|Should -Be 0
    }
    Test-Path -LiteralPath $destination|Should -BeFalse
  }
  It 'runs the CLI with an explicit catalog and selected coverage profile' {
    $manifestPath=Join-Path $TestDrive manifest.json;$mapPath=Join-Path $TestDrive sources.json
    $manifest|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $sources|ConvertTo-Json|Set-Content -LiteralPath $mapPath -Encoding UTF8
    $r=& (Join-Path $Repo tools/New-RideOfflineBundle.ps1) -ManifestPath $manifestPath -SourceMapPath $mapPath -DestinationPath $destination -CatalogFileId engine -CoverageProfileId workstation -Confirm:$false
    $r.Status|Should -BeExactly Completed;$r.CoverageStatus|Should -BeExactly Passed
  }
}
