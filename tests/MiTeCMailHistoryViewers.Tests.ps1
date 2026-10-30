<#
.SYNOPSIS
  Verify MiTeC mail and history viewer package candidates.
.DESCRIPTION
  Rechecks retained archive and member hashes and exercises only inert synthetic
  package staging, repeat installation, uninstall and snapshot recovery. Product
  behavior against real mail, browser or messaging data is outside this test.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCMailHistoryViewers.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Windows 11 package lifecycle/recovery is accepted; product behavior remains deferred.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Get-RideCatalog
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-mail-history-viewer-candidates-2026-10-23.json') -Raw | ConvertFrom-Json
  $script:WindowsAcceptance=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-mail-history-viewers-win11-lifecycle-acceptance-2026-10-25-0409.json') -Raw | ConvertFrom-Json
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-mail-history'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}

Describe 'MiTeC mail/history package candidate <Id>' -ForEach @(
  @{Id='package.mitec-mail-viewer';Version='2.5.1.0';Uri='https://www.mitec.cz/wp/mmv/';Download='https://www.mitec.cz/wp/files/MailView.zip';Sensitive='Do not open personal mailboxes'},
  @{Id='package.mitec-email-history-browser';Version='1.2.0';Uri='https://www.mitec.cz/ehb.html';Download='https://www.mitec.cz/wp/files/EHB.zip';Sensitive='Use isolated synthetic mail stores'},
  @{Id='package.mitec-internet-history-browser';Version='2.5.0';Uri='https://www.mitec.cz/ihb.html';Download='https://www.mitec.cz/wp/files/IHB.zip';Sensitive='Use disposable synthetic browser stores'},
  @{Id='package.mitec-instant-messaging-history-browser';Version='1.2.1';Uri='https://www.mitec.cz/imhb.html';Download='https://www.mitec.cz/wp/files/IMHB.zip';Sensitive='Use synthetic message databases'}
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
        throw 'Refusing mail/history fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }

  It 'matches catalog package metadata to the reviewed publisher evidence' {
    $row=$Evidence.Products|Where-Object Id -CEQ $Id
    $operation=$Catalog.Operations|Where-Object Id -CEQ $Id
    $row|Should -Not -BeNullOrEmpty
    $operation|Should -Not -BeNullOrEmpty
    $operation.ProductUri|Should -BeExactly $Uri
    $operation.DownloadUri|Should -BeExactly $Download
    $operation.ExpectedSha256|Should -BeExactly $row.ArchiveSha256
    $operation.PackageVersion|Should -BeExactly $Version
    @($operation.PortableMembers|Sort-Object)|Should -Be @($row.Members.Path|Sort-Object)
    foreach($requiredFile in $operation.RequiredFiles){@($row.Members.Path)|Should -Contain $requiredFile}
    $operation.CandidateTargets|Should -BeNullOrEmpty
    $operation.SupportedTargets|Should -Contain 'Windows 11'
    $operation.PendingAcceptance|Should -BeFalse
    $operation.AcceptanceNotes|Should -Match ([regex]::Escape($Sensitive))
    $case=@($WindowsAcceptance.cases|Where-Object Id -CEQ $Id)[0]
    $case.Status|Should -BeExactly 'Passed'
    $case.LifecycleRecovery|Should -BeTrue
    $case.ToolExecuted|Should -BeFalse
  }

  It 'rechecks the retained publisher archive and selected member hashes when source bytes are staged' {
    $row=$Evidence.Products|Where-Object Id -CEQ $Id
    $operation=$Catalog.Operations|Where-Object Id -CEQ $Id
    $archivePath=Join-Path $RepositoryRoot $row.Archive.Replace('/','\')
    if(-not (Test-Path -LiteralPath $archivePath -PathType Leaf)){
      Set-ItResult -Skipped -Because 'The retained publisher ZIP is local-only and is not staged in this VM source snapshot.'
      return
    }
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $row.ArchiveSha256
    @($row.Members.Path|Sort-Object)|Should -Be @($operation.PortableMembers|Sort-Object)
    $zip=[IO.Compression.ZipFile]::OpenRead($archivePath)
    try{
      foreach($expected in $row.Members){
        $entry=@($zip.Entries|Where-Object FullName -CEQ $expected.Path)
        $entry.Count|Should -Be 1
        $stream=$entry[0].Open();$sha=[Security.Cryptography.SHA256]::Create()
        try{$actual=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$stream.Dispose();$sha.Dispose()}
        $actual|Should -BeExactly $expected.Sha256
      }
    }finally{$zip.Dispose()}
  }

  It 'keeps package staging available while product behavior remains untested' {
    $plan=@(Get-RideSingleOperationPlan -Id $Id -Action Install -Variant portable)
    $plan.Count|Should -Be 1
    $plan[0].Operation.PackageVersion|Should -BeExactly $Version
    $plan[0].Operation.SelectedVariant|Should -BeExactly 'portable'
    $plan[0].Operation.PendingAcceptance|Should -BeFalse
    $plan[0].Operation.SupportedTargets|Should -Contain 'Windows 11'
    $plan[0].State|Should -BeExactly 'Present'
  }

  It 'stages only selected files twice and restores the snapshot without losing user files' {
    $archivePath=Join-Path $CaseRoot 'fixture.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try{
      foreach($name in @($Evidence.Products|Where-Object Id -CEQ $Id|ForEach-Object {$_.Members.Path})+'ignored.txt'){
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
    @($state.Files.RelativePath|Sort-Object)|Should -Be @($operation.PortableMembers|Sort-Object)
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'ignored.txt')|Should -BeFalse

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }
}
