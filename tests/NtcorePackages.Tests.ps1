<#
.SYNOPSIS
  Verify pinned NTCore candidates, exact member selection and file recovery.
.DESCRIPTION
  Uses inert ZIP fixtures, or retained reviewed archives when the explicit
  RIDE_NTCORE_FIXTURE_DIRECTORY environment variable is set. All product paths
  are in TestDrive. Does not run tools, patch files, scan input, update signatures
  or invoke network/signature providers.
  PE Detective and CFF Explorer synthetic lifecycle fixtures use neutral member
  names; separate metadata assertions check the real publisher member selection.
  Publisher digest assertions always read the unmodified catalog declaration.
.EXAMPLE
  Invoke-Pester .\tests\NtcorePackages.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture. Windows 11 package file lifecycle is accepted;
  product runtime and activation remain untested.
#>
BeforeAll {
  $repositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:NtcoreCatalog=Import-RideCatalogData (Join-Path $repositoryRoot 'catalog/operations.psd1')
  $script:EvidenceRoot=Join-Path $repositoryRoot 'docs/archive/evidence'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}
Describe 'Explorer Suite publisher version identity' {
  It 'uses the current publisher version and exact artifact digest as the package pin' {
    $operation = $NtcoreCatalog.Operations | Where-Object Id -ceq 'package.ntcore-explorer-suite'
    $source = Get-Content (Join-Path $EvidenceRoot 'ntcore-explorer-suite-publisher-version-reconciliation-2026-10-28-1601.json') -Raw | ConvertFrom-Json

    $operation.PackageVersion | Should -BeExactly 'III-2012-11-18'
    $operation.ExpectedSha256 | Should -BeExactly $source.publisherSource.sha256
    $source.versionDecision.catalogVersion | Should -BeExactly $operation.PackageVersion
    $source.versionDecision.embeddedInstallerLabel | Should -BeExactly 'IV'
    $source.versionDecision.interpretation | Should -Match 'does not override'
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.PendingAcceptance | Should -BeTrue
  }
}

Describe 'NTCore Explorer Suite installer candidate' {
  It 'keeps the full-suite installer, administrative license review, and acceptance boundary explicit' {
    $operation = $NtcoreCatalog.Operations | Where-Object Id -ceq 'package.ntcore-explorer-suite'
    $source = Get-Content (Join-Path $EvidenceRoot 'ntcore-explorer-suite-publisher-version-reconciliation-2026-10-28-1601.json') -Raw | ConvertFrom-Json

    $operation.InstallerType | Should -BeExactly 'Exe'
    $operation.Scope | Should -BeExactly 'Machine'
    $operation.RequiresAdmin | Should -BeTrue
    $operation.InstallerArguments | Should -BeExactly '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
    $operation.UninstallerArguments | Should -BeExactly '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
    $operation.DownloadUri | Should -BeExactly $source.publisherSource.downloadUri
    $operation.PackageVersion | Should -BeExactly $source.versionDecision.catalogVersion
    $operation.ExpectedSha256 | Should -BeExactly $source.publisherSource.sha256
    $operation.License | Should -Match 'NeedsReview record is administrative and does not block migration'
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.CandidateTargets | Should -Contain 'Windows 11'
    $operation.PendingAcceptance | Should -BeTrue
    $operation.Rollback | Should -BeExactly 'Compensating'
    $operation.AcceptanceNotes | Should -Match 'has not been installed'
    $operation.AcceptanceNotes | Should -Match 'Do not launch included analysis utilities'
  }
}

Describe 'NTCore Explorer Suite focused acceptance route' {
  It 'restricts ApplicationsBatch12 to this exact package and a registered controller capability' {
    $applicationRunner = Get-Content (Join-Path $repositoryRoot 'tests/integration/Invoke-RideApplicationBatch.ps1') -Raw
    $guestRunner = Get-Content (Join-Path $repositoryRoot 'tests/integration/Invoke-RideGuestTests.ps1') -Raw
    $vmTask = Get-Content (Join-Path $repositoryRoot 'tests/integration/Invoke-RideVmTestTask.ps1') -Raw
    $controllerModule = Get-Content (Join-Path $repositoryRoot 'tests/integration/RIDE.TestAutomation.psm1') -Raw

    $applicationRunner | Should -Match 'ValidateSet\(''package\.ntcore-explorer-suite''\)\]\[string\] \$PackageId'
    $applicationRunner | Should -Match '\$Batch -eq 12 -and \$PackageId -cne ''package\.ntcore-explorer-suite'''
    $applicationRunner | Should -Match '\$package\.Id -ceq \$PackageId'
    $guestRunner | Should -Match 'ApplicationsBatch12.*-Batch 12 -PackageId package\.ntcore-explorer-suite'
    $vmTask | Should -Match 'Assert-RideAutomationSuiteCapability -Configuration \$config -Suite \$IntegrationSuite'
    $vmTask | Should -Match 'ApplicationsBatch12'
    $controllerModule | Should -Match 'ApplicationsBatch12NtcoreExplorerSuiteV1'
  }
}

Describe 'Reviewed NTCore Windows 11 package <Product>' -ForEach @(@{Product='ntcore-pe-detective'},@{Product='ntcore-cff-explorer'}) {
  BeforeEach {
    $script:Operation=($NtcoreCatalog.Operations|Where-Object Id -eq ('package.'+$Product)).Clone()
    $script:Review=Get-Content (Join-Path $EvidenceRoot ($Product+'-source-review-2026-10-17.json')) -Raw|ConvertFrom-Json
    $script:FixtureSelectedFiles=@($Review.SelectedFiles)
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    $retainedPath=if($env:RIDE_NTCORE_FIXTURE_DIRECTORY){Join-Path $env:RIDE_NTCORE_FIXTURE_DIRECTORY $Review.Archive}else{$null}
    if($retainedPath -and (Test-Path -LiteralPath $retainedPath -PathType Leaf)){
      $path=$retainedPath
      $hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
      if($hash -cne $Review.Sha256 -or $hash -cne $Operation.ExpectedSha256){throw 'Retained archive does not match reviewed/catalog digest'}
    }else{
      # Unit fixtures use neutral names; publisher member identity is checked separately.
      # This does not rename or extract a publisher payload or change Defender settings.
      $fixtureNames=@{}
      $fixtureIndex=0
      foreach($member in @($Review.Members|Where-Object {-not $_.Path.EndsWith('/')})){
        $fixtureNames[$member.Path]='fixture-'+($fixtureIndex++)+[IO.Path]::GetExtension($member.Path)
      }
      if($Operation.PortableMembers){$Operation.PortableMembers=@($Operation.PortableMembers|ForEach-Object {$fixtureNames[$_]})}
      $Operation.RequiredFiles=@($Operation.RequiredFiles|ForEach-Object {$fixtureNames[$_]})
      $script:FixtureSelectedFiles=@($Review.SelectedFiles|ForEach-Object {$fixtureNames[$_]})
      $path=Join-Path $CaseRoot 'inert.zip'
      $zip=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
      try{foreach($member in @($Review.Members|Where-Object {-not $_.Path.EndsWith('/')})){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($fixtureNames[$member.Path]).Open())
        try{$writer.Write('inert lifecycle fixture '+$fixtureNames[$member.Path])}finally{$writer.Dispose()}
      }}finally{$zip.Dispose()}
      $hash=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()
      $Operation.ExpectedSha256=$hash
    }
    $script:UsingRetainedArchive=($env:RIDE_NTCORE_FIXTURE_DIRECTORY -and (Test-Path -LiteralPath $path -PathType Leaf) -and $hash -ceq $Review.Sha256)
    $script:Artifact=[pscustomobject]@{Path=$path;Sha256=$hash;Version=$Operation.PackageVersion}
  }
  It 'binds exact source and content to the recorded Windows 11 package acceptance' {
    $declared=$NtcoreCatalog.Operations|Where-Object Id -eq ('package.'+$Product)
    $guest=Get-Content (Join-Path $EvidenceRoot 'ntcore-win11-guarded-lifecycle-acceptance-2026-10-25-0145.json') -Raw|ConvertFrom-Json
    $case=@($guest.cases|Where-Object id -ceq $declared.Id)[0]
    $declared.ExpectedSha256|Should -BeExactly $Review.Sha256
    $declared.DownloadUri|Should -BeExactly $Review.DownloadUri
    $declared.ProductUri|Should -BeExactly $Review.ProductUri
    $declared.PendingAcceptance|Should -BeFalse;$declared.SupportedTargets|Should -Contain 'Windows 11'
    $case.status|Should -BeExactly 'Passed';$case.lifecycleRecovery|Should -BeTrue;$case.toolExecuted|Should -BeFalse
    $declared.Architecture|Should -Be x86
    @($declared.RequiredFiles|Where-Object {$_ -notin $Review.SelectedFiles}).Count|Should -Be 0
    $declared.RequiredFiles.Count|Should -Be $Review.SelectedFiles.Count
    if($Product -eq 'ntcore-cff-explorer'){$declared.PortableMembers.Count|Should -Be 6;$Review.OmittedFiles.Count|Should -Be 10}
    else{$Review.SelectedFiles.Count|Should -Be 7}
  }
  It 'installs only reviewed members, repeats, removes and exactly restores owned files' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    Install-RidePortablePayload $Operation $Artifact -Offline
    $state=Get-RidePortableState $Operation
    $state.Healthy|Should -BeTrue;$state.Files.Count|Should -Be $Review.SelectedFiles.Count
    @($state.Files|Where-Object {$_.RelativePath -notin $FixtureSelectedFiles}).Count|Should -Be 0
    if($UsingRetainedArchive){
      foreach($file in $state.Files){$expected=$Review.Members|Where-Object Path -ceq $file.RelativePath;$file.Sha256|Should -BeExactly $expected.Sha256}
    }
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'custom-note.txt'),'preserve me')
    Uninstall-RidePortablePayload $Operation
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'custom-note.txt'))|Should -BeExactly 'preserve me'
  }
  It 'preserves edited signature databases and refuses replacement' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    $relative=@($FixtureSelectedFiles|Where-Object {$_ -like '*.xml'})[0]
    $path=Join-Path $Operation.InstallDirectory $relative
    [IO.File]::WriteAllText($path,'custom signatures')
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw '*modified managed*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($path)|Should -BeExactly 'custom signatures'
  }
  It 'refuses an unowned executable collision before creating ownership' {
    $path=Join-Path $Operation.InstallDirectory (@($FixtureSelectedFiles|Where-Object {$_ -like '*.exe'})[0])
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force
    [IO.File]::WriteAllText($path,'unowned content')
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw '*collision*'
    [IO.File]::ReadAllText($path)|Should -BeExactly 'unowned content'
    Test-Path (Join-Path $Operation.InstallDirectory '.ride-package.json')|Should -BeFalse
  }
}

Describe 'Retained NTCore package staging lifecycle <Product> <Variant>' -ForEach @(
  @{ Product='ntcore-driver-list'; Variant='portable' },
  @{ Product='ntcore-driver-list'; Variant='portable-x86' },
  @{ Product='ntcore-rebelnet'; Variant='portable' }
) {
  BeforeEach {
    $script:Operation=($NtcoreCatalog.Operations|Where-Object Id -ceq ('package.'+$Product)).Clone()
    $script:ReviewEvidence=Get-Content (Join-Path $EvidenceRoot 'ntcore-driver-list-rebelnet-candidate-2026-10-23-1047.json') -Raw|ConvertFrom-Json
    $script:Review=@($ReviewEvidence.Products|Where-Object Id -ceq $Operation.Id)[0]
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.SelectedVariant=$Variant;$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    if($Variant -cne $Operation.DefaultVariant){
      $variantDefinition=$Operation.Variants[$Variant]
      $Operation.Architecture=$variantDefinition.Architecture
      $Operation.RequiredFiles=$variantDefinition.RequiredFiles
      $Operation.PortableMembers=$variantDefinition.PortableMembers
    }
    $archiveName=Split-Path -Leaf ([Uri]$Review.DownloadUri).AbsolutePath
    $retainedPath=if($env:RIDE_NTCORE_FIXTURE_DIRECTORY){Join-Path $env:RIDE_NTCORE_FIXTURE_DIRECTORY $archiveName}else{$null}
    $script:UsingRetainedArchive=($retainedPath -and (Test-Path -LiteralPath $retainedPath -PathType Leaf))
    if($UsingRetainedArchive){
      $path=$retainedPath
      $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      if($hash -cne $Review.ArchiveSha256 -or $hash -cne $Operation.ExpectedSha256){throw 'Retained archive does not match reviewed/catalog digest'}
    }else{
      $path=Join-Path $CaseRoot 'inert.zip'
      $zip=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
      try{foreach($member in @($Review.SelectedMembers)){
        $writer=[IO.StreamWriter]::new($zip.CreateEntry($member.Path).Open())
        try{$writer.Write('inert '+$member.Path)}finally{$writer.Dispose()}
      }}finally{$zip.Dispose()}
      $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      $Operation.ExpectedSha256=$hash
    }
    $script:Artifact=[pscustomobject]@{Path=$path;Sha256=$hash;Version=$Operation.PackageVersion}
  }

  It 'matches selected publisher members without launching the utility' {
    $declared=$NtcoreCatalog.Operations|Where-Object Id -ceq ('package.'+$Product)
    $declared.PendingAcceptance|Should -BeFalse
    $declared.SupportedTargets|Should -Contain 'Windows 11'
    $declared.CandidateTargets|Should -BeNullOrEmpty
    $declared.LicenseReviewStatus|Should -BeNullOrEmpty
    $ReviewEvidence.Products|Where-Object Id -ceq $declared.Id|Should -Not -BeNullOrEmpty
    @($Review.SelectedMembers|Where-Object {$_.Path -in $Operation.PortableMembers}|ForEach-Object Path)|Should -Be @($Operation.PortableMembers)
    $Operation.PortableMembers.Count|Should -Be $Operation.RequiredFiles.Count
  }

  It 'installs the selected archive members, repeats, removes and restores owned files' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    Install-RidePortablePayload $Operation $Artifact -Offline
    $state=Get-RidePortableState $Operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be $Operation.PortableMembers.Count
    @($state.Files|Where-Object {$_.RelativePath -notin $Operation.PortableMembers}).Count|Should -Be 0
    if($UsingRetainedArchive){
      foreach($file in $state.Files){
        $expected=$Review.SelectedMembers|Where-Object Path -ceq $file.RelativePath
        $file.Sha256|Should -BeExactly $expected.Sha256
      }
    }
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'),'preserve me')
    Uninstall-RidePortablePayload $Operation
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve me'
  }
}

Describe 'NTCore VirtualReg Manager staging candidate' {
  BeforeEach {
    $script:Operation=($NtcoreCatalog.Operations|Where-Object {$_.Id -CEQ 'package.ntcore-virtualreg-manager'}).Clone()
    $script:ReviewDocument=Get-Content (Join-Path $EvidenceRoot 'ntcore-managed-utility-source-review-2026-10-17.json') -Raw|ConvertFrom-Json
    $script:Review=$ReviewDocument.VirtualRegManager
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    $script:UsingRetainedArchive=$false
    $retainedPath=if($env:RIDE_NTCORE_FIXTURE_DIRECTORY){Join-Path $env:RIDE_NTCORE_FIXTURE_DIRECTORY 'VirtualRegManager.zip'}else{$null}
    if($retainedPath -and (Test-Path -LiteralPath $retainedPath -PathType Leaf)){
      $path=$retainedPath
      $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      if($hash -cne $Operation.ExpectedSha256 -or $hash -cne $Review.Artifact.Sha256){throw 'Retained VirtualReg Manager archive does not match the reviewed/catalog digest.'}
      $script:UsingRetainedArchive=$true
    }else{
      $path=Join-Path $CaseRoot 'inert-virtualreg.zip'
      $zip=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
      try{$stream=$zip.CreateEntry('VirtualReg Manager.exe').Open();try{$bytes=[Text.Encoding]::UTF8.GetBytes('inert VirtualReg Manager fixture');$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}}finally{$zip.Dispose()}
      $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      $Operation.ExpectedSha256=$hash
    }
    $script:Artifact=[pscustomobject]@{Path=$path;Sha256=$hash;Version=$Operation.PackageVersion}
  }

  It 'binds the pending candidate to the exact retained publisher archive' {
    $Operation=$NtcoreCatalog.Operations|Where-Object Id -ceq 'package.ntcore-virtualreg-manager'
    $Operation.PackageVersion|Should -BeExactly $Review.PageVersion
    $Operation.DownloadUri|Should -BeExactly $Review.Artifact.DownloadUri
    $Operation.ExpectedSha256|Should -BeExactly $Review.Artifact.Sha256
    $Operation.ProductUri|Should -BeExactly $Review.ProductUri
    $Operation.PortableMembers|Should -Be @('VirtualReg Manager.exe')
    $Operation.RequiredFiles|Should -Be @('VirtualReg Manager.exe')
    $Operation.SupportedTargets|Should -BeNullOrEmpty
    $Operation.CandidateTargets|Should -Contain 'Windows 11'
    $Operation.PendingAcceptance|Should -BeTrue
    $Operation.License|Should -Match 'non-blocking'
    $Review.Artifact.Members[0].ProductVersion|Should -BeExactly $Operation.PackageVersion
  }

  It 'stages only the executable and restores owned bytes without running the utility' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    Install-RidePortablePayload $Operation $Artifact -Offline
    $state=Get-RidePortableState $Operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be 1
    $state.Files[0].RelativePath|Should -BeExactly 'VirtualReg Manager.exe'
    if($UsingRetainedArchive){$state.Files[0].Sha256|Should -BeExactly $Review.Artifact.Members[0].Sha256}
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'),'preserve')
    Uninstall-RidePortablePayload $Operation
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve'
  }
}

Describe 'NTCore ScreenWriter MSI candidate' {
  BeforeEach {
    $script:Operation=($NtcoreCatalog.Operations|Where-Object {$_.Id -CEQ 'package.ntcore-screenwriter'}).Clone()
    $script:ReviewDocument=Get-Content (Join-Path $EvidenceRoot 'ntcore-managed-utility-source-review-2026-10-17.json') -Raw|ConvertFrom-Json
    $script:Review=$ReviewDocument.ScreenWriter
    $script:RetainedPath=if($env:RIDE_NTCORE_FIXTURE_DIRECTORY){Join-Path $env:RIDE_NTCORE_FIXTURE_DIRECTORY 'ScreenWriter.msi'}else{$null}
  }

  It 'keeps the MSI version, payload version, prerequisite and target boundary explicit' {
    $Operation.PackageVersion|Should -BeExactly $Review.InstallerProductVersion
    $Operation.ExpectedSha256|Should -BeExactly $Review.MsiInspection.Sha256
    $Operation.DownloadUri|Should -BeExactly $Review.MsiInspection.DownloadUri
    $Operation.ProductUri|Should -BeExactly $Review.ProductUri
    $Operation.DisplayNamePattern|Should -BeExactly '^ScreenWriter$'
    $Operation.InstallerType|Should -BeExactly 'Msi'
    $Operation.UninstallerType|Should -BeExactly 'Msi'
    $Operation.PrerequisiteDotNetFramework35|Should -BeTrue
    $Operation.SupportedTargets|Should -BeNullOrEmpty
    $Operation.CandidateTargets|Should -Contain 'Windows 11'
    $Operation.PendingAcceptance|Should -BeTrue
    $Operation.License|Should -Match 'NeedsReview'
    $Review.PageVersion|Should -BeExactly $Review.ExecutableVersion
    $Review.PageVersion|Should -Not -BeExactly $Review.InstallerProductVersion
    @($Review.MsiInspection.Tables.CustomAction|Where-Object {$_.Action -in @('DIRCA_CheckFX','VSDCA_FolderForm_AllUsers')}).Count|Should -Be 2
  }

  It 'confirms the retained MSI digest without starting Windows Installer' {
    if(-not $RetainedPath -or -not (Test-Path -LiteralPath $RetainedPath -PathType Leaf)){Set-ItResult -Skipped -Because 'Set RIDE_NTCORE_FIXTURE_DIRECTORY to enable the retained ScreenWriter MSI check.';return}
    (Get-Item -LiteralPath $RetainedPath).Length|Should -Be $Review.MsiInspection.Length
    (Get-FileHash -LiteralPath $RetainedPath -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $Operation.ExpectedSha256
  }
}

Describe 'NTCore WIM Installer staging candidate' {
  BeforeEach {
    $script:Operation=($NtcoreCatalog.Operations|Where-Object Id -CEQ 'package.ntcore-wim-installer').Clone()
    $script:ReviewDocument=Get-Content (Join-Path $EvidenceRoot 'ntcore-wim-installer-archive-static-review-2026-10-26-1200.json') -Raw | ConvertFrom-Json
    $script:Review=[pscustomobject]@{
      Sha256=$ReviewDocument.source.archiveSha256
      Members=@([pscustomobject]@{
        FileVersion=$ReviewDocument.priorStaticMetadata.fileVersion
        Architecture=$ReviewDocument.priorStaticMetadata.architecture
        Sha256=$ReviewDocument.archiveInventory.members[0].sha256
      })
    }
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    $retainedPath=if($env:RIDE_NTCORE_FIXTURE_DIRECTORY){Join-Path $env:RIDE_NTCORE_FIXTURE_DIRECTORY 'WIM_Installer.zip'}else{$null}
    if($retainedPath -and (Test-Path -LiteralPath $retainedPath -PathType Leaf)){
      $path=$retainedPath
      $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      if($hash -cne $Operation.ExpectedSha256 -or $hash -cne $Review.Sha256){throw 'Retained WIM Installer archive does not match reviewed/catalog digest.'}
      $script:UsingRetainedArchive=$true
    }else{
      $path=Join-Path $CaseRoot 'inert-wim-installer.zip'
      $zip=[IO.Compression.ZipFile]::Open($path,[IO.Compression.ZipArchiveMode]::Create)
      try{$stream=$zip.CreateEntry('WIM Installer.exe').Open();try{$bytes=[Text.Encoding]::UTF8.GetBytes('inert WIM Installer fixture');$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}}finally{$zip.Dispose()}
      $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
      $Operation.ExpectedSha256=$hash
      $script:UsingRetainedArchive=$false
    }
    $script:Artifact=[pscustomobject]@{Path=$path;Sha256=$hash;Version=$Operation.PackageVersion}
  }

  It 'binds the candidate to the exact official archive and records its technical boundary' {
    $Operation=$NtcoreCatalog.Operations|Where-Object Id -ceq 'package.ntcore-wim-installer'
    $Operation.PackageVersion|Should -BeExactly '1.0.0.1'
    $Operation.DownloadUri|Should -BeExactly 'https://ntcore.com/files/WIM_Installer.zip'
    $Operation.ExpectedSha256|Should -BeExactly $Review.Sha256
    $Operation.PortableMembers|Should -Be @('WIM Installer.exe')
    $Operation.SupportedTargets|Should -BeNullOrEmpty
    $Operation.CandidateTargets|Should -Contain 'Windows 11'
    $Operation.PendingAcceptance|Should -BeTrue
    $Operation.License|Should -Match 'NeedsReview'
    $Operation.License|Should -Match 'does not block package migration'
    $Review.Members[0].FileVersion|Should -BeExactly $Operation.PackageVersion
    $Review.Members[0].Architecture|Should -BeExactly 'x86'
  }

  It 'stages only the selected executable and exactly recovers owned files' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    Install-RidePortablePayload $Operation $Artifact -Offline
    $state=Get-RidePortableState $Operation
    $state.Healthy|Should -BeTrue
    $state.Files.Count|Should -Be 1
    $state.Files[0].RelativePath|Should -BeExactly 'WIM Installer.exe'
    if($UsingRetainedArchive){$state.Files[0].Sha256|Should -BeExactly $Review.Members[0].Sha256}
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'),'preserve')
    Uninstall-RidePortablePayload $Operation
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve'
  }
}
