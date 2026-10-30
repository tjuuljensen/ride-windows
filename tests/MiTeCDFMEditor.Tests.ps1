<#
.SYNOPSIS
  Verify MiTeC DFM Editor variant selection and inert portable package recovery.
.DESCRIPTION
  Rechecks the retained ZIP and member hashes, then stages synthetic fixture bytes
  for each Delphi runtime variant. No product executable or BPL is loaded.
.EXAMPLE
  Invoke-Pester .\tests\MiTeCDFMEditor.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  DFM/PE behavior and Windows target acceptance remain deferred.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Get-RideCatalog
  $script:Evidence=Get-Content (Join-Path $RepositoryRoot 'docs/archive/evidence/mitec-dfm-editor-candidate-2026-10-23.json') -Raw | ConvertFrom-Json
  $script:Archive=Join-Path $RepositoryRoot '.local/remaining-collections-20261017/DFMEdit.zip'
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-mitec-dfm-editor'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
}

Describe 'MiTeC DFM Editor package variants' {
  It 'matches the retained archive and all exact member hashes' {
    if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) {
      Set-ItResult -Skipped -Because 'The retained publisher archive is local acquisition evidence and is not included in transferred source snapshots.'
      return
    }
    (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $Evidence.Archive.Sha256
    $zip=[IO.Compression.ZipFile]::OpenRead($Archive)
    try {
      $files=@($zip.Entries|Where-Object {-not $_.FullName.EndsWith('/')})
      $files.Count|Should -Be 18
      foreach($expected in $Evidence.Members){
        $entry=$files|Where-Object FullName -CEQ $expected.Path
        $entry.Count|Should -Be 1
        $stream=$entry.Open();$sha=[Security.Cryptography.SHA256]::Create()
        try{$digest=[BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant()}finally{$stream.Dispose();$sha.Dispose()}
        $digest|Should -BeExactly $expected.Sha256
      }
    } finally {$zip.Dispose()}
  }

  It 'resolves both exact Delphi versions and keeps their BPL families disjoint' {
    $operation=$Catalog.Operations|Where-Object Id -CEQ 'package.mitec-dfm-editor'
    $operation|Should -Not -BeNullOrEmpty
    $operation.ExpectedSha256|Should -BeExactly $Evidence.Archive.Sha256
    $operation.ProductUri|Should -BeExactly 'https://www.mitec.cz/wp/mdfme/'
    $operation.DownloadUri|Should -BeExactly 'https://www.mitec.cz/wp/files/DFMEdit.zip'
    $operation.PendingAcceptance|Should -BeTrue
    $operation.SupportedTargets.Count|Should -Be 0
    $operation.LicenseReviewStatus|Should -BeNullOrEmpty
    $d11=Resolve-RidePackageSelection -Operation $operation -Variant 'delphi-11' -MetadataOnly
    $d12=Resolve-RidePackageSelection -Operation $operation -Variant 'delphi-12' -MetadataOnly
    $d11.PackageVersion|Should -BeExactly '8.3.1.0'
    $d12.PackageVersion|Should -BeExactly '8.4.0.0'
    @($d11.PortableMembers).Count|Should -Be 9
    @($d12.PortableMembers).Count|Should -Be 9
    @($d11.PortableMembers|Where-Object {$_ -notlike 'Delphi 11/*'}).Count|Should -Be 0
    @($d12.PortableMembers|Where-Object {$_ -notlike 'Delphi 12/*'}).Count|Should -Be 0
    @($d11.PortableMembers|Where-Object {$_ -match '290\.bpl$'}).Count|Should -Be 0
    @($d12.PortableMembers|Where-Object {$_ -match '280\.bpl$'}).Count|Should -Be 0
  }

  It 'keeps both explicit variants available in pending install plans' {
    foreach($selection in @(@('delphi-11','8.3.1.0'),@('delphi-12','8.4.0.0'))){
      $plan=@(Get-RideSingleOperationPlan -Id 'package.mitec-dfm-editor' -Action Install -Variant $selection[0])
      $plan.Count|Should -Be 1
      $plan[0].Operation.SelectedVariant|Should -BeExactly $selection[0]
      $plan[0].Operation.PackageVersion|Should -BeExactly $selection[1]
      $plan[0].Operation.PendingAcceptance|Should -BeTrue
      $plan[0].State|Should -BeExactly 'Present'
    }
  }
}

Describe 'MiTeC DFM Editor inert lifecycle <Variant>' -ForEach @(
  @{Variant='delphi-11';Version='8.3.1.0';Prefix='Delphi 11'},
  @{Variant='delphi-12';Version='8.4.0.0';Prefix='Delphi 12'}
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
        throw 'Refusing DFM Editor fixture cleanup outside its unique workspace-local directory.'
      }
      Remove-Item -LiteralPath $resolved -Recurse -Force
    }
  }

  It 'stages only the chosen runtime family and restores the owned files exactly' {
    $catalogOperation=$Catalog.Operations|Where-Object Id -CEQ 'package.mitec-dfm-editor'
    $operation=Resolve-RidePackageSelection -Operation $catalogOperation -Variant $Variant -MetadataOnly
    $operation.ResolvedToolsDirectory=$CaseRoot
    $operation.InstallDirectory=Join-Path $CaseRoot $operation.PackageId
    $archivePath=Join-Path $CaseRoot 'synthetic.zip'
    $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
    try{
      foreach($name in @($operation.PortableMembers)+@('Delphi 11/unselected.txt','Delphi 12/unselected.txt')){
        $stream=$zip.CreateEntry($name).Open()
        try{$bytes=[Text.Encoding]::UTF8.GetBytes('inert synthetic '+$name);$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
      }
    }finally{$zip.Dispose()}
    $sha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $operation.ExpectedSha256=$sha
    $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$sha;Version=$Version}

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    @($state.Files.RelativePath|Sort-Object)|Should -Be @($operation.PortableMembers|Sort-Object)
    @($state.Files.RelativePath|Where-Object {$_ -notlike "$Prefix/*"}).Count|Should -Be 0
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'Delphi 11/unselected.txt')|Should -BeFalse
    Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'Delphi 12/unselected.txt')|Should -BeFalse

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $CaseRoot 'backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'user-note.txt'))|Should -BeExactly 'preserve'
  }

  It 'stages the actual retained publisher archive and restores only this Delphi runtime family' {
    if(-not (Test-Path -LiteralPath $Archive -PathType Leaf)){
      Set-ItResult -Skipped -Because 'The retained DFMEdit.zip is local acquisition evidence and is unavailable in this checkout.'
      return
    }
    (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $Evidence.Archive.Sha256
    $operation=Resolve-RidePackageSelection -Operation ($Catalog.Operations|Where-Object Id -CEQ 'package.mitec-dfm-editor') -Variant $Variant -MetadataOnly
    $operation.ResolvedToolsDirectory=Join-Path $CaseRoot 'real-archive'
    $operation.InstallDirectory=Join-Path $operation.ResolvedToolsDirectory $operation.PackageId
    $null=New-Item -ItemType Directory -Path $operation.ResolvedToolsDirectory -Force
    $artifact=[pscustomobject]@{Path=$Archive;Sha256=$Evidence.Archive.Sha256;Version=$Version}
    $expected=@($Evidence.Members|Where-Object Path -like "$Prefix/*")
    $expected.Count|Should -Be 9

    Install-RidePortablePayload $operation $artifact -Offline
    Install-RidePortablePayload $operation $artifact -Offline
    $state=Get-RidePortableState $operation
    $state.Healthy|Should -BeTrue
    (@($state.Files.RelativePath|Sort-Object) -join '|')|Should -BeExactly ((@($expected.Path|Sort-Object)) -join '|')
    foreach($member in $expected){
      (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory $member.Path) -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $member.Sha256
    }
    @($state.Files.RelativePath|Where-Object {$_ -notlike "$Prefix/*"}).Count|Should -Be 0

    $snapshot=Save-RidePortableSnapshot $operation (Join-Path $CaseRoot 'real-archive-backup')
    [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'),'preserve')
    Uninstall-RidePortablePayload $operation
    Restore-RidePortableSnapshot $operation $snapshot
    (Get-RidePortableState $operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'))|Should -BeExactly 'preserve'
  }
}
