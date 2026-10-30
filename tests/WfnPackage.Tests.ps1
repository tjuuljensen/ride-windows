<#
.SYNOPSIS
  Validate the pinned Windows Firewall Notifier package and owned-file lifecycle.
.DESCRIPTION
  Compares all catalog members with the statically reviewed publisher archive inventory and
  exercises the complete 531-member lifecycle using inert synthetic ZIP entries.
.EXAMPLE
  Invoke-Pester .\tests\WfnPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Synthetic fixtures run under .local; no WFN executable, firewall, VM, or Windows state changes.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $RepositoryRoot 'catalog/operations.psd1')
  $script:Evidence=Get-Content -LiteralPath (Join-Path $RepositoryRoot 'docs/archive/evidence/wfn-nightly-static-archive-review-2026-10-24-2354.json') -Raw | ConvertFrom-Json
  $script:Operation=$Catalog.Operations|Where-Object Id -eq 'package.windows-firewall-notifier'
  $script:FixtureRoot=Join-Path $RepositoryRoot '.local/pester-wfn-package'
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
}
Describe 'Pinned Windows Firewall Notifier Nightly package' {
  It 'matches the selected publisher ZIP, complete static inventory and bundled license files' {
    $Operation|Should -Not -BeNullOrEmpty
    $Operation.PackageId|Should -BeExactly 'windows-firewall-notifier'
    $Operation.PackageVersion|Should -BeExactly '20250719-ac02df'
    $Operation.DownloadUri|Should -BeExactly $Evidence.SelectedAsset.DownloadUri
    $Operation.ExpectedSha256|Should -BeExactly $Evidence.SelectedAsset.PublishedSha256
    $Operation.PortableMembers.Count|Should -Be 531
    $evidenceNames=@($Evidence.Verification.ArchiveMembers|ForEach-Object Name)
    [string]::Join("`n",@($Operation.PortableMembers|Sort-Object))|Should -BeExactly ([string]::Join("`n",@($evidenceNames|Sort-Object)))
    $Operation.RequiredFiles|Should -Contain 'WFN.exe'
    $Operation.RequiredFiles|Should -Contain 'LICENSE.txt'
    $Operation.RequiredFiles|Should -Contain 'Resources/IPDatabase/LICENSE.txt'
    $Operation.ProductUri|Should -BeExactly 'https://github.com/wokhan/WFN'
    $Operation.License|Should -Match 'GPL-3.0-or-later'
    $Operation.TermsUri|Should -BeExactly 'https://www.maxmind.com/en/geolite2/eula'
    $Operation.SupportedTargets|Should -BeNullOrEmpty
    $Operation.CandidateTargets|Should -Be @('Windows 11')
    $Operation.PendingAcceptance|Should -BeTrue
    $Operation.Description|Should -Match 'does not launch WFN'
    $Operation.Description|Should -Match 'does not.*change firewall policy'
  }

  It 'repeats owned-file staging and restores exact prior absence with a synthetic archive' {
    $caseRoot=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $caseRoot -Force
    try {
      $archivePath=Join-Path $caseRoot 'wfn-inert-fixture.zip'
      $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
      try {
        $lifecycleMembers=@($Operation.RequiredFiles)
        foreach($member in $lifecycleMembers){
          $entry=$zip.CreateEntry($member)
          $stream=$entry.Open()
          try{$stream.WriteByte(65)}finally{$stream.Dispose()}
        }
      } finally {$zip.Dispose()}
      $fixtureSha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
      $package=$Operation.Clone()
      $package.PortableMembers=$lifecycleMembers
      $package.SelectedVariant='portable'
      $package.ExpectedSha256=$fixtureSha
      $package.ResolvedToolsDirectory=Join-Path $caseRoot 'tools'
      $package.InstallDirectory=Join-Path $package.ResolvedToolsDirectory $package.PackageId
      $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$fixtureSha;Version=$Operation.PackageVersion}
      Install-RidePortablePayload -Operation $package -Artifact $artifact -Offline
      (Get-RidePortableState -Operation $package).Files.Count|Should -Be $lifecycleMembers.Count
      Install-RidePortablePayload -Operation $package -Artifact $artifact -Offline
      (Get-RidePortableState -Operation $package).Files.Count|Should -Be $lifecycleMembers.Count
      $snapshot=Save-RidePortableSnapshot -Operation $package -BackupDirectory (Join-Path $caseRoot 'saved-run')
      Uninstall-RidePortablePayload -Operation $package
      (Get-RidePortableState -Operation $package).Present|Should -BeFalse
      Restore-RidePortableSnapshot -Operation $package -Snapshot $snapshot
      $restored=Get-RidePortableState -Operation $package
      $restored.Present|Should -BeTrue
      $restored.Healthy|Should -BeTrue
      $restored.Files.Count|Should -Be $lifecycleMembers.Count
    } finally {
      if(Test-Path -LiteralPath $caseRoot -PathType Container){
        $resolved=[IO.Path]::GetFullPath($caseRoot).TrimEnd('\')
        $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
        if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
          throw 'Refusing WFN fixture cleanup outside its unique workspace-local directory.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
      }
    }
  }

  It 'repeats the complete 531-member snapshot and restores both prior package states' {
    $caseRoot=Join-Path $FixtureRoot ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $caseRoot -Force
    try {
      $archivePath=Join-Path $caseRoot 'wfn-complete-inert-fixture.zip'
      $zip=[IO.Compression.ZipFile]::Open($archivePath,[IO.Compression.ZipArchiveMode]::Create)
      try {
        foreach($member in $Operation.PortableMembers){
          $entry=$zip.CreateEntry($member)
          $stream=$entry.Open()
          try{$stream.WriteByte(65)}finally{$stream.Dispose()}
        }
      } finally {$zip.Dispose()}
      $fixtureSha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
      $package=$Operation.Clone()
      $package.SelectedVariant='portable'
      $package.ExpectedSha256=$fixtureSha
      $package.ResolvedToolsDirectory=Join-Path $caseRoot 'tools'
      $package.InstallDirectory=Join-Path $package.ResolvedToolsDirectory $package.PackageId
      $artifact=[pscustomobject]@{Path=$archivePath;Sha256=$fixtureSha;Version=$Operation.PackageVersion}
      $priorAbsence=Save-RidePortableSnapshot -Operation $package -BackupDirectory (Join-Path $caseRoot 'before-install')
      Install-RidePortablePayload -Operation $package -Artifact $artifact -Offline
      $first=Get-RidePortableState -Operation $package
      $first.Present|Should -BeTrue
      $first.Healthy|Should -BeTrue
      $first.Files.Count|Should -Be 531
      $operatorFile=Join-Path $package.InstallDirectory 'operator-data.json'
      [IO.File]::WriteAllText($operatorFile,'preserve operator-owned data')
      Install-RidePortablePayload -Operation $package -Artifact $artifact -Offline
      $repeat=Get-RidePortableState -Operation $package
      $repeat.Healthy|Should -BeTrue
      $repeat.Files.Count|Should -Be 531
      $installedSnapshot=Save-RidePortableSnapshot -Operation $package -BackupDirectory (Join-Path $caseRoot 'before-remove')
      Uninstall-RidePortablePayload -Operation $package
      (Get-RidePortableState -Operation $package).Present|Should -BeFalse
      Restore-RidePortableSnapshot -Operation $package -Snapshot $installedSnapshot
      $restored=Get-RidePortableState -Operation $package
      $restored.Present|Should -BeTrue
      $restored.Healthy|Should -BeTrue
      $restored.Files.Count|Should -Be 531
      [IO.File]::ReadAllText($operatorFile)|Should -BeExactly 'preserve operator-owned data'
      Uninstall-RidePortablePayload -Operation $package
      Restore-RidePortableSnapshot -Operation $package -Snapshot $priorAbsence
      (Get-RidePortableState -Operation $package).Present|Should -BeFalse
      [IO.File]::ReadAllText($operatorFile)|Should -BeExactly 'preserve operator-owned data'
    } finally {
      if(Test-Path -LiteralPath $caseRoot -PathType Container){
        $resolved=[IO.Path]::GetFullPath($caseRoot).TrimEnd('\')
        $parent=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
        if([IO.Path]::GetDirectoryName($resolved) -ine $parent -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$'){
          throw 'Refusing WFN fixture cleanup outside its unique workspace-local directory.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
      }
    }
  }

  It 'matches the retained real archive to the pinned complete inventory without launching WFN' {
    if([string]::IsNullOrWhiteSpace($env:RIDE_WFN_FIXTURE_ARCHIVE)){
      Set-ItResult -Skipped -Because 'No explicit retained WFN archive fixture was supplied.'
      return
    }
    $archivePath=[IO.Path]::GetFullPath($env:RIDE_WFN_FIXTURE_ARCHIVE)
    $archive=Get-Item -LiteralPath $archivePath -Force -ErrorAction Stop
    if($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint)){
      throw 'Retained WFN archive fixture must be a regular file.'
    }
    $sha=(Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha|Should -BeExactly $Operation.ExpectedSha256.ToLowerInvariant()
    $zip=[IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
      $actualNames=@($zip.Entries|ForEach-Object FullName|Sort-Object)
      $actualNames.Count|Should -Be 531
      [string]::Join("`n",$actualNames)|Should -BeExactly ([string]::Join("`n",@($Operation.PortableMembers|Sort-Object)))
    } finally {$zip.Dispose()}
  }
}
