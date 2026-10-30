<#
.SYNOPSIS
  Verify MiTeC EXE Explorer and HexEdit package candidates.
.DESCRIPTION
  Rechecks retained publisher archive/member pins and exercises inert synthetic
  staging, explicit install planning, repeat, removal and snapshot recovery.
  No executable, analyzed file, process memory or raw disk is opened.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCAnalysisTools.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Product behavior and Windows target acceptance remain deferred.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Get-RideCatalog
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-analysis-tools-candidates-2026-10-23.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-analysis-tools'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}

Describe 'MiTeC analysis package candidate <Id>' -ForEach @(
  @{Id='package.mitec-exe-explorer';Name='MiTeC EXE Explorer';Version='3.7.5';Uri='https://www.mitec.cz/exe.html';Download='https://www.mitec.cz/wp/files/EXE.zip';Archive='EXE.zip';Members=@('EXE.exe','EXE64.exe');SelectedFeature='VirusTotal'},
  @{Id='package.mitec-hexedit';Name='MiTeC HexEdit';Version='7.1.0';Uri='https://www.mitec.cz/wp/mhex/';Download='https://www.mitec.cz/wp/files/HEXEdit.zip';Archive='HEXEdit.zip';Members=@('HEXEdit.exe');SelectedFeature='raw-disk'}
) {
  BeforeEach {
    $script:CaseRoot=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot -Force
  }
  AfterEach {
    if(Test-Path -LiteralPath $CaseRoot -PathType Container){
      $resolved=[IO.Path]::GetFullPath($CaseRoot).TrimEnd('\')
      $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
      if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
        throw 'Refusing analysis-tool fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }

  It 'matches catalog package metadata to the reviewed publisher evidence' {
    $row=$Evidence.Products|Where-Object Id -CEQ $Id
    $operation=$Catalog.Operations|Where-Object Id -CEQ $Id
    $row|Should -Not -BeNullOrEmpty
    $operation|Should -Not -BeNullOrEmpty
    $operation.Name|Should -BeExactly $Name
    $operation.ProductUri|Should -BeExactly $Uri
    $operation.DownloadUri|Should -BeExactly $Download
    $operation.ExpectedSha256|Should -BeExactly $row.ArchiveSha256
    $operation.PackageVersion|Should -BeExactly $Version
    $operation.PortableMembers|Should -Be $Members
    $operation.RequiredFiles|Should -Be $Members
    $operation.CandidateTargets|Should -Be @('Windows 11')
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.PendingAcceptance|Should -BeTrue
    $operation.LicenseReviewStatus|Should -BeNullOrEmpty
    $operation.TermsUri|Should -BeExactly 'https://www.mitec.cz/wp/support/'
    @($row.Members.Path)|Should -Be $Members
    @($row.Members|Where-Object {$_.Sha256 -notmatch '^[a-f0-9]{64}$'}).Count|Should -Be 0
    $operation.AcceptanceNotes|Should -Match ([regex]::Escape($SelectedFeature))
  }

  It 'rechecks retained publisher archive and exact selected member hashes when source bytes are staged' {
    $row=$Evidence.Products|Where-Object Id -CEQ $Id
    $archiveRelative=if($Id -ceq 'package.mitec-exe-explorer'){'.local/remaining-collections-20261017/EXE.zip'}else{'.local/remaining-collections-20261017/HEXEdit.zip'}
    $archivePath=Join-Path $RepositoryRoot $archiveRelative
    if(-not (Test-Path -LiteralPath $archivePath -PathType Leaf)){
      Set-ItResult -Skipped -Because 'The retained publisher ZIP is local-only and is not staged in this VM source snapshot.'
      return
    }
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $row.ArchiveSha256
    $zip=[IO.Compression.ZipFile]::OpenRead($archivePath)
    try{
      foreach($expected in $row.Members){
        $entry=@($zip.Entries|Where-Object FullName -CEQ $expected.Path)
        $entry.Count|Should -Be 1
        $stream=$entry[0].Open();$sha=[Security.Cryptography.SHA256]::Create()
        try{$actual=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}finally{$stream.Dispose();$sha.Dispose()}
        $actual|Should -BeExactly $expected.Sha256
      }
    }finally{$zip.Dispose()}
  }

  It 'keeps package install planning available while acceptance stays pending' {
    $plan=@(Get-RideSingleOperationPlan -Id $Id -Action Install -Variant portable)
    $plan.Count|Should -Be 1
    $plan[0].Operation.PackageVersion|Should -BeExactly $Version
    $plan[0].Operation.SelectedVariant|Should -BeExactly 'portable'
    $plan[0].Operation.PendingAcceptance|Should -BeTrue
    $plan[0].State|Should -BeExactly 'Present'
  }

  It 'stages the actual retained archive and restores the exact selected members' {
    $row=$Evidence.Products|Where-Object Id -CEQ $Id
    $archivePath=Join-Path $RepositoryRoot ".local/remaining-collections-20261017/$Archive"
    if(-not (Test-Path -LiteralPath $archivePath -PathType Leaf)){
      Set-ItResult -Skipped -Because 'The retained publisher archive is local acquisition evidence and is unavailable in this checkout.'
      return
    }
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $row.ArchiveSha256
    $operation=($Catalog.Operations|Where-Object Id -CEQ $Id).Clone()
    $operation.SelectedVariant='portable'
    $operation.ResolvedToolsDirectory=Join-Path $CaseRoot 'real-archive'
    $operation.InstallDirectory=Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
    $null=New-Item -ItemType Directory -Path $operation.ResolvedToolsDirectory -Force
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$row.ArchiveSha256;Version=$Version}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    (@($state.Files.RelativePath|Sort-Object) -join '|')|Should -BeExactly ((@($Members|Sort-Object)) -join '|')
    foreach($member in $row.Members){
      (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory $member.Path) -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $member.Sha256
    }

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $CaseRoot 'real-archive-backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve'
  }

  It 'repeats inert staging and restores only owned files with the snapshot' {
    $archivePath=Join-Path $CaseRoot 'fixture.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try{
      foreach($name in @($Members+'ignored.txt')){
        $stream=$zip.CreateEntry($name).Open()
        try{$bytes=[Text.Encoding]::UTF8.GetBytes('inert synthetic '+$name);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
    }finally{$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation=($Catalog.Operations|Where-Object Id -CEQ $Id).Clone()
    $operation.SelectedVariant='portable'
    $operation.ExpectedSha256=$sha
    $operation.ResolvedToolsDirectory=$CaseRoot
    $operation.InstallDirectory=Join-Path $CaseRoot $operation.PackageId
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$sha;Version=$Version}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    @($state.Files.RelativePath|Sort-Object)|Should -Be @($Members|Sort-Object)
    @($state.Manifest.Files|Where-Object AuthenticodeStatus -ne 'NotInspectedOffline').Count|Should -Be 0
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }
}
