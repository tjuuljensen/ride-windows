BeforeAll {
  $script:RepoRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepoRoot 'modules/RIDE.OfflineBundle.psm1') -Force
  function New-PlanPackage {
    param([string]$Id,[string]$PackageId,[string]$Version,[string]$Architecture='x64',[string[]]$SupportedTargets=@('Windows 11'),[string[]]$CandidateTargets=@(),[bool]$PendingAcceptance=$false,[string]$PrerequisitePackageId='')
    $op=@{Id=$Id;Kind='Package';PackageId=$PackageId;InstallerType='Exe';PackageVersion=$Version;Architecture=$Architecture;SupportedTargets=$SupportedTargets;CandidateTargets=$CandidateTargets;PendingAcceptance=$PendingAcceptance;ProductUri="https://publisher.example/$PackageId";DownloadUri="https://publisher.example/$PackageId.exe";AssetName="$PackageId.exe";ExpectedSha256=$null}
    if($PrerequisitePackageId){$op.PrerequisitePackageId=$PrerequisitePackageId}
    $op
  }
  function Add-PlanObservation {
    param([string]$Root,[string]$PackageId,[string]$Version,[string]$Variant,[string]$FileName,[string]$Content,[string]$Architecture='x64')
    $path=Join-Path (Join-Path (Join-Path $Root $PackageId) $Version) $FileName
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path,$Content,[Text.UTF8Encoding]::new($false))
    $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    [pscustomobject]@{PackageId=$PackageId;Version=$Version;Variant=$Variant;Architecture=$Architecture;FileName=$FileName;Sha256=$hash;SourceUri="https://publisher.example/$FileName";OriginUri="https://publisher.example/$PackageId"}
  }
}

Describe 'Read-only offline package preparation planning' {
  BeforeEach {
    $script:CacheRoot=Join-Path $TestDrive ('cache-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CacheRoot -Force
    $script:dep=New-PlanPackage -Id 'package.dep' -PackageId 'dep' -Version '1.0'
    $script:main=New-PlanPackage -Id 'package.main' -PackageId 'main' -Version '' -PrerequisitePackageId 'package.dep'
    $script:main.Remove('PackageVersion')
    $script:main.Variants=@{
      installed=@{InstallerType='Exe';AssetName='main-setup.exe'}
      portable=@{InstallerType='Portable';AssetName='main-portable.zip'}
    }
    $script:main.DefaultVariant='installed'
    $script:catalog=@{SchemaVersion=1;Operations=@($dep,$main);Groups=@(@{Id='solution.main';Members=@('package.main')})}
    $script:target=@{Id='win11-26300';Name='Windows 11';Build=26300;EditionId='Professional';Architecture='x64'}
    $script:profile=@{SchemaVersion=1;Name='Selected tools';Operations=@(@{Id='package.main';State='Present';Variant='portable'})}
    $script:profileRecord=@{Id='selected-tools';Data=$profile}
    $script:observations=@(
      (Add-PlanObservation $CacheRoot 'dep' '1.0' 'installed' 'dep.exe' 'dependency bytes'),
      (Add-PlanObservation $CacheRoot 'main' '2.1' 'portable' 'main-portable.zip' 'portable bytes')
    )
  }

  It 'expands selected profile packages and prerequisites in install order from supplied local bytes' {
    $plan=New-RideOfflinePreparationPlan -Mode ProfileSelected -Catalog $catalog -Targets @($target) -Profiles @($profileRecord) -ArtifactObservations $observations -CacheRoots @($CacheRoot)
    @($plan.Packages.OperationId)|Should -Be @('package.dep','package.main')
    @($plan.Packages.Status|Select-Object -Unique)|Should -Be @('PayloadAvailable')
    $plan.Packages[1].Variant|Should -BeExactly 'portable'
    $plan.Packages[1].Version|Should -BeExactly '2.1'
    $plan.Packages[1].ProfileIds|Should -Contain 'selected-tools'
    $plan.PackagePayloadsComplete|Should -BeTrue
    $plan.ReadyForAssembly|Should -BeFalse
    $plan.NetworkUsed|Should -BeFalse
    $plan.NetworkFallbackAllowed|Should -BeFalse
  }

  It 'requires an explicit profile variant instead of silently using the default' {
    $profileNoVariant=@{SchemaVersion=1;Name='Ambiguous';Operations=@(@{Id='package.main';State='Present'})}
    $record=@{Id='ambiguous';Data=$profileNoVariant}
    $plan=New-RideOfflinePreparationPlan -Mode ProfileSelected -Catalog $catalog -Targets @($target) -Profiles @($record) -ArtifactObservations $observations -CacheRoots @($CacheRoot)
    $plan.Issues.Reason|Should -Contain 'ExplicitVariantRequired'
    $plan.Packages.Count|Should -Be 0
  }

  It 'plans every applicable full-set variant and deduplicates shared prerequisites' {
    $installed=Add-PlanObservation $CacheRoot 'main' '2.0' 'installed' 'main-setup.exe' 'installer bytes'
    $observations=@($observations)+@($installed)
    $plan=New-RideOfflinePreparationPlan -Mode FullSet -Catalog $catalog -Targets @($target) -ArtifactObservations $observations -CacheRoots @($CacheRoot)
    @($plan.Packages|Where-Object OperationId -eq 'package.main'|ForEach-Object Variant|Sort-Object)|Should -Be @('installed','portable')
    @($plan.Packages|Where-Object OperationId -eq 'package.dep').Count|Should -Be 1
    @($plan.Packages|Where-Object Status -ne 'PayloadAvailable').Count|Should -Be 0
  }

  It 'keeps multiple cached versions unresolved until the caller pins one' {
    $other=Add-PlanObservation $CacheRoot 'main' '2.2' 'portable' 'main-portable.zip' 'newer portable bytes'
    $ambiguous=@($observations)+@($other)
    $plan=New-RideOfflinePreparationPlan -Mode ProfileSelected -Catalog $catalog -Targets @($target) -Profiles @($profileRecord) -ArtifactObservations $ambiguous -CacheRoots @($CacheRoot)
    ($plan.Packages|Where-Object PackageId -eq 'main').Status|Should -BeExactly 'VersionSelectionRequired'
    $plan.NetworkFallbackAllowed|Should -BeFalse
  }

  It 'uses an explicit version selection to reject bytes with a different digest' {
    [IO.File]::WriteAllText((Join-Path $CacheRoot 'main/2.1/main-portable.zip'),'tampered',[Text.UTF8Encoding]::new($false))
    $plan=New-RideOfflinePreparationPlan -Mode ProfileSelected -Catalog $catalog -Targets @($target) -Profiles @($profileRecord) -ArtifactObservations $observations -CacheRoots @($CacheRoot) -VersionSelections @{ 'main|portable'='2.1' }
    ($plan.Packages|Where-Object PackageId -eq 'main').Status|Should -BeExactly 'LocalHashMismatch'
  }

  It 'rejects a path-like version pin before checking any cache location' {
    {New-RideOfflinePreparationPlan -Mode ProfileSelected -Catalog $catalog -Targets @($target) -Profiles @($profileRecord) -ArtifactObservations $observations -CacheRoots @($CacheRoot) -VersionSelections @{ 'main|portable'='../outside' }} | Should -Throw '*bounded literal token*'
  }

  It 'reports publisher-accepted but technically pending candidates separately from payload availability' {
    $candidate=New-PlanPackage -Id 'package.candidate' -PackageId 'candidate' -Version '1.0' -SupportedTargets @() -CandidateTargets @('Windows 11') -PendingAcceptance $true
    $catalog.Operations+=@($candidate)
    $obs=Add-PlanObservation $CacheRoot 'candidate' '1.0' 'installed' 'candidate.exe' 'candidate bytes'
    $plan=New-RideOfflinePreparationPlan -Mode FullSet -Catalog $catalog -Targets @($target) -ArtifactObservations (@($observations)+@($obs)) -CacheRoots @($CacheRoot)
    $row=$plan.Packages|Where-Object PackageId -eq 'candidate'
    $row.Status|Should -BeExactly 'PayloadAvailable'
    $row.TargetStatus|Should -BeExactly 'PendingAcceptance'
  }

  It 'marks the Defender-reported NirSoft packages excluded before probing their cache paths' {
    $blocked=New-PlanPackage -Id 'package.nirsoft-launcher' -PackageId 'nirsoft-launcher' -Version '1.30.26'
    $catalog.Operations+=@($blocked)
    $obs=[pscustomobject]@{PackageId='nirsoft-launcher';Version='1.30.26';Variant='installed';Architecture='x64';FileName='nirlauncher.zip';Sha256=('a'*64);SourceUri='https://publisher.example/nirlauncher.zip';OriginUri='https://publisher.example/nirsoft-launcher'}
    $plan=New-RideOfflinePreparationPlan -Mode FullSet -Catalog $catalog -Targets @($target) -ArtifactObservations (@($observations)+@($obs)) -CacheRoots @($CacheRoot)
    ($plan.Packages|Where-Object PackageId -eq 'nirsoft-launcher').Status|Should -BeExactly 'DefenderExcluded'
  }

  It 'keeps license review status informational and does not block a matching local payload' {
    $plan=New-RideOfflinePreparationPlan -Mode ProfileSelected -Catalog $catalog -Targets @($target) -Profiles @($profileRecord) -ArtifactObservations $observations -CacheRoots @($CacheRoot) -LicenseReviewStatuses @{main='NeedsReview'}
    $row=$plan.Packages|Where-Object PackageId -eq 'main'
    $row.LicenseReviewStatus|Should -BeExactly 'NeedsReview'
    $row.Status|Should -BeExactly 'PayloadAvailable'
    $plan.LicenseReviewIsInformational|Should -BeTrue
  }

  It 'reports candidate target status without rewriting payload availability' {
    $candidate=New-PlanPackage -Id 'package.candidate' -PackageId 'candidate' -Version '1.0' -SupportedTargets @() -CandidateTargets @('Windows 11') -PendingAcceptance $false -Architecture 'arm64'
    $catalog.Operations+=@($candidate)
    $obs=Add-PlanObservation $CacheRoot 'candidate' '1.0' 'installed' 'candidate.exe' 'candidate bytes' 'arm64'
    $plan=New-RideOfflinePreparationPlan -Mode FullSet -Catalog $catalog -Targets @($target) -ArtifactObservations (@($observations)+@($obs)) -CacheRoots @($CacheRoot)
    $row=$plan.Packages|Where-Object PackageId -eq 'candidate'
    $row.Status|Should -BeExactly 'PayloadAvailable'
    $row.TargetStatus|Should -BeExactly 'CandidateOnly'
  }
}

Describe 'Offline preparation plan command wrapper' {
  It 'loads explicit target and retained observation inputs without querying Windows state' {
    $targetPath=Join-Path $TestDrive 'targets.json'
    $observationPath=Join-Path $TestDrive 'observations.json'
    $targetJson=@(@{Id='win11-command-test';Name='Windows 11';Build=26300;EditionId='Professional';Architecture='x64'})|ConvertTo-Json -Depth 4
    $observationJson=@{SchemaVersion=1;Observations=@()}|ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($targetPath,$targetJson,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($observationPath,$observationJson,[Text.UTF8Encoding]::new($false))
    $tool=Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/New-RideOfflinePreparationPlan.ps1'

    $plan=& $tool -Mode FullSet -TargetMatrixPath $targetPath -ArtifactObservationsPath $observationPath

    $plan.Kind|Should -BeExactly 'RideOfflinePreparationPlan'
    $plan.Mode|Should -BeExactly 'FullSet'
    $plan.NetworkUsed|Should -BeFalse
    $plan.ReadyForAssembly|Should -BeFalse
    $plan.Targets[0].Id|Should -BeExactly 'win11-command-test'
    $plan.Packages.Count|Should -BeGreaterThan 0
  }

  It 'refuses missing profile selections before loading any catalog or cache' {
    $targetPath=Join-Path $TestDrive 'targets-not-read.json'
    $tool=Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/New-RideOfflinePreparationPlan.ps1'
    {& $tool -Mode ProfileSelected -TargetMatrixPath $targetPath} | Should -Throw '*requires at least one ProfilePath*'
  }
}
