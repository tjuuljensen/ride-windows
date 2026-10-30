BeforeDiscovery {
  $root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE-Packages.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE-PortablePackages.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.PublisherSources.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
}

BeforeAll {
  $root = Split-Path -Parent $PSScriptRoot
  $global:RideApplicationPackageTestRoot = $root
  function global:Invoke-RideTestCatalogImport {
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][string]$Path)
    $modulePath = Join-Path $global:RideApplicationPackageTestRoot 'modules/RIDE.CatalogData.psm1'
    $module = Import-Module -Name $modulePath -Force -PassThru
    & $module {
      param($CatalogPath)
      Import-RideCatalogData -Path $CatalogPath
    } $Path
  }
  function global:Invoke-RideTestCatalogValidation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Catalog)
    $modulePath = Join-Path $global:RideApplicationPackageTestRoot 'modules/RIDE.CatalogValidation.psm1'
    $module = Import-Module -Name $modulePath -Force -PassThru
    & $module {
      param($CatalogData)
      Get-RideCatalogValidationErrors -Catalog $CatalogData
    } $Catalog
  }
}

AfterAll {
  Remove-Item -LiteralPath Function:\global:Invoke-RideTestCatalogImport -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath Function:\global:Invoke-RideTestCatalogValidation -ErrorAction SilentlyContinue
  Remove-Variable -Name RideApplicationPackageTestRoot -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Package variant selection' {
  InModuleScope RIDE.PackageSelection {
    BeforeEach {
      Mock Get-RidePackageConfiguration { @{ ToolsDirectory = $TestDrive; PackageVariantPreference = '' } }
      $product = @{ Id='package.app'; Kind='Package'; PackageId='app'; Scope='Machine'; InstallerType='Exe'; DefaultVariant='installed'; Variants=@{ installed=@{}; portable=@{ InstallerType='Portable'; PortableFormat='File' } } }
    }
    It 'keeps the existing product ID and catalog default' {
      $selected = Resolve-RidePackageSelection $product
      $selected.SelectedVariant | Should -Be 'installed'
      $selected.Id | Should -Be 'package.app'
      $product.ContainsKey('SelectedVariant') | Should -BeFalse
    }
    It 'resolves an explicit portable destination without changing catalog data' {
      $selected = Resolve-RidePackageSelection $product portable
      $selected.InstallDirectory | Should -Be (Join-Path $TestDrive 'app')
      $product.InstallerType | Should -Be 'Exe'
    }
    It 'rejects unsupported explicit choices' { { Resolve-RidePackageSelection $product missing } | Should -Throw '*Unsupported variant*' }
    It 'falls back only for an unavailable local preference and explains it' {
      Mock Get-RidePackageConfiguration { @{ToolsDirectory=$TestDrive;PackageVariantPreference='missing'} }
      $selection = Resolve-RidePackageSelection $product
      $selection.SelectedVariant | Should -Be 'installed'
      $selection.SelectionNote | Should -Match 'unavailable'
    }
    It 'lets an explicit selection override a preference' {
      Mock Get-RidePackageConfiguration { @{ToolsDirectory=$TestDrive;PackageVariantPreference='portable'} }
      (Resolve-RidePackageSelection $product installed).InstallerType | Should -Be 'Exe'
    }
    It 'supports old flat package entries' {
      (Resolve-RidePackageSelection @{Kind='Package';Id='package.old';InstallerType='Exe'}).SelectedVariant | Should -Be 'installed'
    }
    It 'rejects package variants on settings' { { Resolve-RidePackageSelection @{Kind='RegistryValue'} portable } | Should -Throw '*package ID*' }

    It 'matches test target eligibility against supported and candidate target metadata' {
      Test-RidePackageTargetEligibility @{SupportedTargets=@('Windows 11');CandidateTargets=@()} 'Windows 11' | Should -BeTrue
      Test-RidePackageTargetEligibility @{SupportedTargets=@();CandidateTargets=@('Windows 11')} 'Windows 11' | Should -BeTrue
      Test-RidePackageTargetEligibility @{SupportedTargets=@();CandidateTargets=@('Windows 11')} 'Windows Server 2025' | Should -BeFalse
    }
    It 'resolves the user destination and installer arguments during planning' {
      $product.Scope='User';$product.LocalAppDataInstallDirectory='Mozilla Thunderbird'
      $product.InstallerArguments='/S /InstallDirectoryPath="{InstallDirectory}"'
      $selected=Resolve-RidePackageSelection $product
      $selected.InstallDirectory | Should -Be (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs/Mozilla Thunderbird')
      $selected.InstallerArguments | Should -Be ('/S /InstallDirectoryPath="'+$selected.InstallDirectory+'"')
      $product.InstallerArguments | Should -Match '\{InstallDirectory\}'
    }
    It 'rejects unsafe or machine-scoped user destinations' {
      $product.LocalAppDataInstallDirectory='../Other'
      {Resolve-RidePackageSelection $product} | Should -Throw '*Invalid current-user*'
      $product.LocalAppDataInstallDirectory='Mozilla Thunderbird'
      {Resolve-RidePackageSelection $product} | Should -Throw '*Invalid current-user*'
    }
  }
}

Describe 'Managed portable lifecycle' {
  InModuleScope RIDE-PortablePackages {
    BeforeEach {
      $fixtureBase=[IO.Path]::GetFullPath((Join-Path (Get-Location).Path '.local/application-package-tests'))
      $null=New-Item -ItemType Directory -Path $fixtureBase -Force
      $script:PackageFixtureRoot=Join-Path $fixtureBase ([guid]::NewGuid().ToString('N'))
      $caseRoot = $script:PackageFixtureRoot
      New-Item -ItemType Directory -Path $caseRoot | Out-Null
      $operation = @{Id='package.app';PackageId='app';Name='App';InstallerType='Portable';SelectedVariant='portable';ResolvedToolsDirectory=$caseRoot;InstallDirectory=(Join-Path $caseRoot 'app');PortableFormat='File';PortableFileName='app.exe';RequiredFiles=@('app.exe')}
      $payload = Join-Path $caseRoot 'payload.exe'
      [IO.File]::WriteAllText($payload, 'version one')
      $artifact = [pscustomobject]@{Path=$payload;Version='1.0';Sha256=(Get-FileHash -LiteralPath $payload).Hash.ToLowerInvariant()}
    }
    AfterEach {
      $fixtureBase=[IO.Path]::GetFullPath((Join-Path (Get-Location).Path '.local/application-package-tests'))
      $fixturePath=[IO.Path]::GetFullPath($script:PackageFixtureRoot)
      $separator=[IO.Path]::DirectorySeparatorChar
      if (-not $fixturePath.StartsWith($fixtureBase.TrimEnd('\','/')+$separator,[StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean portable-package fixture outside '$fixtureBase'."
      }
      if (Test-Path -LiteralPath $fixturePath) { Remove-Item -LiteralPath $fixturePath -Recurse -Force }
    }
    It 'does not adopt arbitrary existing files' {
      New-Item -ItemType Directory -Path $operation.InstallDirectory | Out-Null
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'app.exe'),'user bytes')
      (Get-RidePortableState $operation).Present | Should -BeFalse
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*collision*'
      Get-Content -LiteralPath (Join-Path $operation.InstallDirectory 'app.exe') | Should -Be 'user bytes'
    }
    It 'stages only the selected RawCopy x64 executable and notices with exact recovery' {
      Add-Type -AssemblyName System.IO.Compression
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      $root='RawCopy-0d8d690c0f0fe9d2c68c5fce02d26d0efa53459c/'
      $members=@("${root}RawCopy64.exe","${root}LICENSE.md","${root}readme.txt","${root}changelog.txt")
      $zipPath=Join-Path $caseRoot 'rawcopy-inert.zip'
      $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
      try {
        foreach($name in $members+"${root}RawCopy.exe","${root}RawCopy.au3") {
          $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open());try{$writer.Write("inert $name")}finally{$writer.Dispose()}
        }
      } finally { $zip.Dispose() }
      $operation.PortableFormat='Zip';$operation.RequiredFiles=$members;$operation.PortableMembers=$members
      $operation.ExpectedSha256=(Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
      $artifact.Path=$zipPath;$artifact.Sha256=$operation.ExpectedSha256;$artifact.Version='1.0.0.22'

      Install-RidePortablePayload $operation $artifact
      $state=Get-RidePortableState $operation
      $state.Healthy | Should -BeTrue
      $state.Files.Count | Should -Be 4
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory "${root}RawCopy64.exe") | Should -BeTrue
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory "${root}RawCopy.exe") | Should -BeFalse
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory "${root}RawCopy.au3") | Should -BeFalse
      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'rawcopy-backup')
      Uninstall-RidePortablePayload $operation
      (Get-RidePortableState $operation).Present | Should -BeFalse
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
    }
    It 'stages a hash-pinned repository notice as owned content with the executable' {
      $noticeSource=Join-Path $caseRoot 'upstream-license.txt'
      [IO.File]::WriteAllText($noticeSource,'MIT notice fixture')
      $repositoryRoot=$script:PortableRepositoryRoot
      $sourceRelative=$noticeSource.Substring($repositoryRoot.Length+1).Replace('\','/')
      $noticeHash=(Get-FileHash -LiteralPath $noticeSource -Algorithm SHA256).Hash
      $operation.PortableFormat='File';$operation.PortableFileName='app.exe';$operation.RequiredFiles=@('app.exe','LICENSE.txt')
      $operation.PortableLocalFiles=@(@{Source=$sourceRelative;Destination='LICENSE.txt';Sha256=$noticeHash})
      Install-RidePortablePayload $operation $artifact
      (Get-RidePortableState $operation).Files.Count | Should -Be 2
      Get-Content -LiteralPath (Join-Path $operation.InstallDirectory 'LICENSE.txt') -Raw | Should -Be 'MIT notice fixture'
      Uninstall-RidePortablePayload $operation
      (Get-RidePortableState $operation).Present | Should -BeFalse
    }
    It 'installs, detects, repeats and removes only owned content' {
      Install-RidePortablePayload $operation $artifact
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
      Install-RidePortablePayload $operation $artifact
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'user.json'),'user data')
      Uninstall-RidePortablePayload $operation
      (Get-RidePortableState $operation).Present | Should -BeFalse
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'user.json') | Should -BeTrue
      Test-Path -LiteralPath $caseRoot | Should -BeTrue
    }
    It 'creates an owned portable command copy and restores both upstream files exactly' {
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      Add-Type -AssemblyName System.IO.Compression
      $zipPath=Join-Path $caseRoot 'command-copy.zip'
      $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
      try {
        foreach($entry in @(@('exiftool-13.59_64/exiftool(-k).exe','inert launcher bytes'),@('exiftool-13.59_64/exiftool_files/LICENSE','upstream notice fixture'))) {
          $writer=[IO.StreamWriter]::new($zip.CreateEntry($entry[0]).Open());try{$writer.Write($entry[1])}finally{$writer.Dispose()}
        }
      } finally { $zip.Dispose() }
      $operation.PortableFormat='Zip'
      $operation.RequiredFiles=@('exiftool-13.59_64/exiftool(-k).exe','exiftool-13.59_64/exiftool.exe')
      $operation.PortableCopies=@(@{Source='exiftool-13.59_64/exiftool(-k).exe';Destination='exiftool-13.59_64/exiftool.exe'})
      $operation.ExpectedSha256=(Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
      $artifact.Path=$zipPath;$artifact.Sha256=$operation.ExpectedSha256

      Install-RidePortablePayload $operation $artifact
      $original=Join-Path $operation.InstallDirectory 'exiftool-13.59_64/exiftool(-k).exe'
      $command=Join-Path $operation.InstallDirectory 'exiftool-13.59_64/exiftool.exe'
      (Get-Content -LiteralPath $original -Raw) | Should -Be 'inert launcher bytes'
      (Get-Content -LiteralPath $command -Raw) | Should -Be 'inert launcher bytes'
      (Get-RidePortableState $operation).Files.Count | Should -Be 3

      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'command-backup')
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
      (Get-Content -LiteralPath $command -Raw) | Should -Be 'inert launcher bytes'
    }
    It 'refuses portable command-copy destinations already present in the pinned archive' {
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      Add-Type -AssemblyName System.IO.Compression
      $zipPath=Join-Path $caseRoot 'command-copy-collision.zip'
      $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
      try {
        foreach($name in @('exiftool-13.59_64/exiftool(-k).exe','exiftool-13.59_64/exiftool.exe')) {
          $writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open());try{$writer.Write('archive file')}finally{$writer.Dispose()}
        }
      } finally { $zip.Dispose() }
      $operation.PortableFormat='Zip'
      $operation.RequiredFiles=@('exiftool-13.59_64/exiftool(-k).exe','exiftool-13.59_64/exiftool.exe')
      $operation.PortableCopies=@(@{Source='exiftool-13.59_64/exiftool(-k).exe';Destination='exiftool-13.59_64/exiftool.exe'})
      $operation.ExpectedSha256=(Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
      $artifact.Path=$zipPath;$artifact.Sha256=$operation.ExpectedSha256
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*copy destination already exists*'
      Test-Path -LiteralPath $operation.InstallDirectory | Should -BeFalse
    }
    It 'preserves modified content and refuses overwrite during upgrades' {
      Install-RidePortablePayload $operation $artifact
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'app.exe'),'modified')
      (Get-RidePortableState $operation).Files[0].Modified | Should -BeTrue
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*modified*'
      Uninstall-RidePortablePayload $operation -WarningAction SilentlyContinue
      Get-Content -LiteralPath (Join-Path $operation.InstallDirectory 'app.exe') | Should -Be 'modified'
    }
    It 'reports missing owned content' {
      Install-RidePortablePayload $operation $artifact
      Remove-Item -LiteralPath (Join-Path $operation.InstallDirectory 'app.exe')
      (Get-RidePortableState $operation).Healthy | Should -BeFalse
      (Get-RidePortableState $operation).Files[0].Missing | Should -BeTrue
    }
    It 'restores exact captured bytes without touching user data' {
      Install-RidePortablePayload $operation $artifact
      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      Uninstall-RidePortablePayload $operation
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'notes.txt'),'notes')
      Restore-RidePortableSnapshot $operation $snapshot
      Get-Content -LiteralPath (Join-Path $operation.InstallDirectory 'app.exe') | Should -Be 'version one'
      Get-Content -LiteralPath (Join-Path $operation.InstallDirectory 'notes.txt') | Should -Be 'notes'
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
    }
    It 'retains ownership after a partial restore so the same retained bytes can be retried' {
      Install-RidePortablePayload $operation $artifact
      $extra=Join-Path $operation.InstallDirectory 'extra.txt'
      [IO.File]::WriteAllText($extra,'second owned file')
      $manifestPath=Join-Path $operation.InstallDirectory '.ride-package.json'
      $manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
      $manifest.Files=@($manifest.Files)+@([pscustomobject]@{RelativePath='extra.txt';Sha256=(Get-FileHash -LiteralPath $extra).Hash})
      $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      Uninstall-RidePortablePayload $operation
      $script:failRestore=$true
      Mock Copy-Item {
        if($script:failRestore -and $Destination -like '*extra.txt'){throw 'simulated restore copy failure'}
        [IO.File]::Copy($LiteralPath,$Destination,[bool]$Force)
      }
      { Restore-RidePortableSnapshot $operation $snapshot } | Should -Throw '*simulated restore*'
      $partial=Get-RidePortableState $operation
      $partial.Present | Should -BeTrue
      $partial.Healthy | Should -BeFalse
      $partial.Manifest.Status | Should -Be 'Restoring'
      $script:failRestore=$false
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
      Get-Content -LiteralPath $extra | Should -Be 'second owned file'
    }
    It 'restores original absence by compensating file removal' {
      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      Install-RidePortablePayload $operation $artifact
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Present | Should -BeFalse
    }
    It 'preflights missing recovery bytes before changing the installed product' {
      Install-RidePortablePayload $operation $artifact
      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      Remove-Item -LiteralPath (Join-Path $snapshot.BackupDirectory 'app.exe')
      { Restore-RidePortableSnapshot $operation $snapshot } | Should -Throw '*unavailable*'
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
    }
    It 'does not overwrite modifications made since capture' {
      Install-RidePortablePayload $operation $artifact
      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'app.exe'),'new user modification')
      { Restore-RidePortableSnapshot $operation $snapshot } | Should -Throw '*overwrite*'
    }
    It 'validates recovery without writing' {
      Install-RidePortablePayload $operation $artifact
      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot -ValidateOnly
      (Get-RidePortableState $operation).Present | Should -BeFalse
    }
    It 'refuses to adopt unowned recovery collisions even when the bytes match' {
      Install-RidePortablePayload $operation $artifact
      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      Uninstall-RidePortablePayload $operation
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'app.exe'),'version one')
      { Restore-RidePortableSnapshot $operation $snapshot } | Should -Throw '*unowned content*'
      (Get-RidePortableState $operation).Present | Should -BeFalse
    }
    It 'rejects an artifact changed after acquisition' {
      [IO.File]::WriteAllText($payload,'changed')
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*SHA-256*'
      Test-Path -LiteralPath $operation.InstallDirectory | Should -BeFalse
    }
    It 'rejects traversal, reserved filenames and streams' -TestCases @(
      @{Member='../escape.exe'}, @{Member='/escape.exe'}, @{Member='dir/../escape.exe'}, @{Member='dir\escape.exe'}, @{Member='app.exe:stream'}, @{Member='CON.exe'}, @{Member='dir./app.exe'}
    ) {
      param($Member)
      { Get-RidePortableMemberPath $caseRoot $Member } | Should -Throw '*Unsafe portable member*'
    }
    It 'refuses ZIP traversal before creating a product directory' {
      Add-Type -AssemblyName System.IO.Compression
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      $zipPath=Join-Path $caseRoot 'unsafe.zip'
      $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
      try { $null=$zip.CreateEntry('../escape.exe') } finally { $zip.Dispose() }
      $operation.PortableFormat='Zip';$artifact.Path=$zipPath;$artifact.Sha256=(Get-FileHash -LiteralPath $zipPath).Hash
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*Unsafe portable member*'
      Test-Path -LiteralPath $operation.InstallDirectory | Should -BeFalse
    }
    It 'extracts a ZIP and retains all supplied notices' {
      $src=Join-Path $caseRoot 'source';New-Item -ItemType Directory -Path $src | Out-Null
      [IO.File]::WriteAllText((Join-Path $src 'app.exe'),'binary')
      [IO.File]::WriteAllText((Join-Path $src 'LICENSE.txt'),'license')
      $zipPath=Join-Path $caseRoot 'safe.zip'
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      [IO.Compression.ZipFile]::CreateFromDirectory($src,$zipPath)
      $operation.PortableFormat='Zip';$artifact.Path=$zipPath;$artifact.Sha256=(Get-FileHash -LiteralPath $zipPath).Hash
      Install-RidePortablePayload $operation $artifact
      (Get-RidePortableState $operation).Files.Count | Should -Be 2
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'LICENSE.txt') | Should -BeTrue
    }
    It 'extracts a 7z archive through signed Windows inbox tar and restores its exact file set' -Skip:(-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles '7-Zip\7z.exe') -PathType Leaf)) {
      $src=Join-Path $caseRoot 'seven-source';New-Item -ItemType Directory -Path (Join-Path $src 'sub') -Force | Out-Null
      [IO.File]::WriteAllText((Join-Path $src 'app.exe'),'synthetic executable bytes')
      [IO.File]::WriteAllText((Join-Path $src 'LICENSE.txt'),'upstream notice fixture')
      [IO.File]::WriteAllText((Join-Path $src 'sub/readme.txt'),'nested fixture')
      $archive=Join-Path $caseRoot 'safe.7z';$sevenZip=Join-Path $env:ProgramFiles '7-Zip\7z.exe'
      Push-Location $src
      try { & $sevenZip a -t7z -mx=1 $archive '*' | Out-Null; if($LASTEXITCODE -ne 0){throw 'Could not create the synthetic 7z test archive.'} }
      finally { Pop-Location }
      $operation.PortableFormat='SevenZip';$operation.RequiredFiles=@('app.exe');$artifact.Path=$archive;$artifact.Sha256=(Get-FileHash -LiteralPath $archive).Hash
      Install-RidePortablePayload $operation $artifact
      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      $state=Get-RidePortableState $operation
      $state.Healthy | Should -BeTrue
      $state.Files.Count | Should -Be 3
      Get-Content -LiteralPath (Join-Path $operation.InstallDirectory 'LICENSE.txt') -Raw | Should -Be 'upstream notice fixture'
      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
    }
    It 'rejects unsafe 7z paths before invoking extraction' {
      $archive=Join-Path $caseRoot 'unsafe.7z';[IO.File]::WriteAllText($archive,'fixture')
      $operation.PortableFormat='SevenZip';$artifact.Path=$archive;$artifact.Sha256=(Get-FileHash -LiteralPath $archive).Hash
      Mock Invoke-RidePortableTar { '../escape.exe' }
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*Unsafe portable member*'
      Assert-MockCalled Invoke-RidePortableTar -Times 0 -ParameterFilter { $Action -eq 'Extract' }
      Test-Path -LiteralPath $operation.InstallDirectory | Should -BeFalse
    }
    It 'rejects 7z links and oversized members before extraction' -TestCases @(
      @{Mode='lrwxrwxrwx';Size='4';Expected='links and special files'},
      @{Mode='-rw-r--r--';Size='536870913';Expected='512 MiB'}
    ) {
      param($Mode,$Size,$Expected)
      $archive=Join-Path $caseRoot 'bounded.7z';[IO.File]::WriteAllText($archive,'fixture')
      $operation.PortableFormat='SevenZip';$artifact.Path=$archive;$artifact.Sha256=(Get-FileHash -LiteralPath $archive).Hash
      $verboseLine="$Mode  0 0 0 $Size Jan 01 00:00:00 app.exe"
      Mock Invoke-RidePortableTar { param($Action) if($Action -eq 'List'){ 'app.exe' } elseif($Action -eq 'ListVerbose') { $verboseLine } else { throw 'Unexpected archive extraction.' } }
      { Install-RidePortablePayload $operation $artifact } | Should -Throw "*$Expected*"
      Assert-MockCalled Invoke-RidePortableTar -Times 0 -ParameterFilter { $Action -eq 'Extract' }
      Test-Path -LiteralPath $operation.InstallDirectory | Should -BeFalse
    }
    It 'rejects a file where an archive needs a parent directory before product writes' {
      $src=Join-Path $caseRoot 'source';New-Item -ItemType Directory -Path (Join-Path $src 'sub') -Force | Out-Null
      [IO.File]::WriteAllText((Join-Path $src 'app.exe'),'binary')
      [IO.File]::WriteAllText((Join-Path $src 'sub/other.exe'),'binary')
      $zipPath=Join-Path $caseRoot 'parent.zip';Add-Type -AssemblyName System.IO.Compression.FileSystem
      Add-Type -AssemblyName System.IO.Compression
      $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
      try { $null=$zip.CreateEntry('app.exe'); $null=$zip.CreateEntry('sub/other.exe') } finally { $zip.Dispose() }
      New-Item -ItemType Directory -Path $operation.InstallDirectory | Out-Null
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'sub'),'user file')
      $operation.PortableFormat='Zip';$artifact.Path=$zipPath;$artifact.Sha256=(Get-FileHash -LiteralPath $zipPath).Hash
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*collision*'
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory '.ride-package.json') | Should -BeFalse
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'app.exe') | Should -BeFalse
    }
    It 'keeps a journal after failed copying and can recover original absence' {
      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      Add-Type -AssemblyName System.IO.Compression
      $members=@(1..24|ForEach-Object { 'member-{0:D2}.txt' -f $_ })
      $zipPath=Join-Path $caseRoot 'multi-file.zip'
      $zip=[IO.Compression.ZipFile]::Open($zipPath,[IO.Compression.ZipArchiveMode]::Create)
      try { foreach($member in $members){$writer=[IO.StreamWriter]::new($zip.CreateEntry($member).Open());try{$writer.Write('inert '+$member)}finally{$writer.Dispose()}} } finally {$zip.Dispose()}
      $operation.PortableFormat='Zip';$operation.PortableMembers=$members;$operation.RequiredFiles=@($members[0]);$operation.ExpectedSha256=(Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
      $artifact.Path=$zipPath;$artifact.Sha256=$operation.ExpectedSha256
      Mock Copy-Item { throw 'simulated copy failure' } -ParameterFilter { $Destination -like ($operation.InstallDirectory+'*') }
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*simulated copy failure*'
      $state=Get-RidePortableState $operation
      $state.Present | Should -BeTrue
      $state.Healthy | Should -BeFalse
      $state.Manifest.Status | Should -Be 'Installing'
      $state.Manifest.Files.Count | Should -Be 24
      @($state.Files|Where-Object Missing).Count | Should -Be 24
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Present | Should -BeFalse
    }
    It 'stops when an available signature reports changed signed bytes' {
      Mock Get-AuthenticodeSignature { [pscustomobject]@{Status='HashMismatch';SignerCertificate=$null} }
      { Install-RidePortablePayload $operation $artifact } | Should -Throw '*signature integrity failure*'
      Test-Path -LiteralPath $operation.InstallDirectory | Should -BeFalse
    }
    It 'records COM executable signatures and blocks changed signed COM bytes before product writes' {
      $operation.PortableFileName='app.com';$operation.RequiredFiles=@('app.com')
      Mock Get-AuthenticodeSignature { [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Thumbprint='publisher'}} }
      Install-RidePortablePayload $operation $artifact
      $state=Get-RidePortableState $operation
      $state.Manifest.Files[0].AuthenticodeStatus | Should -Be 'Valid'
      $state.Manifest.Files[0].SignerThumbprint | Should -Be 'publisher'
      Should -Invoke Get-AuthenticodeSignature -Exactly 1 -ParameterFilter {$LiteralPath -like '*.com'}
      Uninstall-RidePortablePayload $operation
      Mock Get-AuthenticodeSignature { [pscustomobject]@{Status='HashMismatch';SignerCertificate=$null} }
      {Install-RidePortablePayload $operation $artifact} | Should -Throw '*signature integrity failure*'
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory 'app.com') | Should -BeFalse
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory '.ride-package.json') | Should -BeFalse
    }
    It 'captures and restores an upgrade including obsolete owned files' {
      Install-RidePortablePayload $operation $artifact
      $snapshot=Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'backup')
      [IO.File]::WriteAllText($payload,'version two');$artifact.Sha256=(Get-FileHash -LiteralPath $payload).Hash;$artifact.Version='2.0'
      Install-RidePortablePayload $operation $artifact
      Restore-RidePortableSnapshot $operation $snapshot
      Get-Content -LiteralPath (Join-Path $operation.InstallDirectory 'app.exe') | Should -Be 'version one'
      (Get-RidePortableState $operation).DisplayVersion | Should -Be '1.0'
    }
  }
}

Describe 'RawCopy retained publisher archive lifecycle' {
  BeforeAll {
    $script:RawCopyRepositoryRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $RawCopyRepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
    Import-Module (Join-Path $RawCopyRepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
    $script:RawCopyCatalog = Invoke-RideTestCatalogImport (Join-Path $RawCopyRepositoryRoot 'catalog/operations.psd1')
    $script:RawCopyFixtureBase = Join-Path $RawCopyRepositoryRoot '.local/rawcopy-current-source-real-archive'
  }

  It 'stages only the pinned x64 executable and notices and restores saved state' {
    if ([string]::IsNullOrWhiteSpace($env:RIDE_RAWCOPY_FIXTURE_ARCHIVE)) {
      Set-ItResult -Skipped -Because 'No explicit retained RawCopy archive fixture was supplied.'
      return
    }
    $archivePath = [IO.Path]::GetFullPath($env:RIDE_RAWCOPY_FIXTURE_ARCHIVE)
    $archive = Get-Item -LiteralPath $archivePath -Force -ErrorAction Stop
    if ($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Retained RawCopy archive fixture must be a regular file.'
    }
    $operation = ($RawCopyCatalog.Operations | Where-Object Id -eq 'package.rawcopy').Clone()
    $sha = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha | Should -BeExactly $operation.ExpectedSha256.ToLowerInvariant()

    $runRoot = Join-Path $RawCopyFixtureBase ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $runRoot -Force
    try {
      $operation.SelectedVariant = 'portable'
      $operation.ResolvedToolsDirectory = $runRoot
      $operation.InstallDirectory = Join-Path $runRoot $operation.PackageId
      $artifact = [pscustomobject]@{ Path = $archivePath; Sha256 = $sha; Version = $operation.PackageVersion }

      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state = Get-RidePortableState $operation
      $state.Healthy | Should -BeTrue
      $state.Files.Count | Should -Be 4
      $root = 'RawCopy-0d8d690c0f0fe9d2c68c5fce02d26d0efa53459c'
      @($state.Files.RelativePath | Sort-Object) | Should -Be @(
        "$root/changelog.txt", "$root/LICENSE.md", "$root/RawCopy64.exe", "$root/readme.txt"
      )
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory "$root/RawCopy32.exe") | Should -BeFalse
      Test-Path -LiteralPath (Join-Path $operation.InstallDirectory "$root/RawCopy.au3") | Should -BeFalse

      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $runRoot 'backup')
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'), 'preserve')
      Uninstall-RidePortablePayload $operation
      (Get-RidePortableState $operation).Present | Should -BeFalse
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
      [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt')) | Should -BeExactly 'preserve'
    }
    finally {
      $resolved = [IO.Path]::GetFullPath($runRoot).TrimEnd('\','/')
      $base = [IO.Path]::GetFullPath($RawCopyFixtureBase).TrimEnd('\','/')
      if ([IO.Path]::GetDirectoryName($resolved) -ine $base -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$') {
        throw 'Refusing RawCopy archive fixture cleanup outside its unique workspace-local directory.'
      }
      if (Test-Path -LiteralPath $resolved -PathType Container) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
  }
}

Describe 'ETL2PCAPNG retained publisher executable lifecycle' {
  BeforeAll {
    $script:Etl2PcapngRepositoryRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $Etl2PcapngRepositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
    Import-Module (Join-Path $Etl2PcapngRepositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
    $script:Etl2PcapngCatalog = Invoke-RideTestCatalogImport (Join-Path $Etl2PcapngRepositoryRoot 'catalog/operations.psd1')
    $script:Etl2PcapngFixtureBase = Join-Path $Etl2PcapngRepositoryRoot '.local/etl2pcapng-current-source-real-artifact'
  }

  It 'stages only the pinned executable and notice and restores saved state' {
    if ([string]::IsNullOrWhiteSpace($env:RIDE_ETL2PCAPNG_FIXTURE_EXECUTABLE)) {
      Set-ItResult -Skipped -Because 'No explicit retained ETL2PCAPNG executable fixture was supplied.'
      return
    }
    $executablePath = [IO.Path]::GetFullPath($env:RIDE_ETL2PCAPNG_FIXTURE_EXECUTABLE)
    $executable = Get-Item -LiteralPath $executablePath -Force -ErrorAction Stop
    if ($executable.PSIsContainer -or ($executable.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'Retained ETL2PCAPNG executable fixture must be a regular file.'
    }
    $operation = ($Etl2PcapngCatalog.Operations | Where-Object Id -ceq 'package.etl2pcapng').Clone()
    $sha = (Get-FileHash -LiteralPath $executablePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $sha | Should -BeExactly $operation.ExpectedSha256.ToLowerInvariant()

    $runRoot = Join-Path $Etl2PcapngFixtureBase ([guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $runRoot -Force
    Push-Location $Etl2PcapngRepositoryRoot
    try {
      $operation.SelectedVariant = 'portable'
      $operation.ResolvedToolsDirectory = $runRoot
      $operation.InstallDirectory = Join-Path $runRoot $operation.PackageId
      $artifact = [pscustomobject]@{ Path = $executablePath; Sha256 = $sha; Version = $operation.PackageVersion }

      Install-RidePortablePayload $operation $artifact -Offline
      Install-RidePortablePayload $operation $artifact -Offline
      $state = Get-RidePortableState $operation
      $state.Healthy | Should -BeTrue
      $state.Files.Count | Should -Be 2
      @($state.Files.RelativePath) | Should -Contain 'LICENSE.txt'
      @($state.Files.RelativePath) | Should -Contain 'etl2pcapng.exe'
      (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory 'etl2pcapng.exe') -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $sha
      (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory 'LICENSE.txt') -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $operation.PortableLocalFiles[0].Sha256.ToLowerInvariant()

      $snapshot = Save-RidePortableSnapshot $operation (Join-Path $runRoot 'backup')
      [IO.File]::WriteAllText((Join-Path $operation.InstallDirectory 'operator-note.txt'), 'preserve')
      Uninstall-RidePortablePayload $operation
      (Get-RidePortableState $operation).Present | Should -BeFalse
      Restore-RidePortableSnapshot $operation $snapshot
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
      [IO.File]::ReadAllText((Join-Path $operation.InstallDirectory 'operator-note.txt')) | Should -BeExactly 'preserve'
    }
    finally {
      Pop-Location
      $resolved = [IO.Path]::GetFullPath($runRoot).TrimEnd('\','/')
      $base = [IO.Path]::GetFullPath($Etl2PcapngFixtureBase).TrimEnd('\','/')
      if ([IO.Path]::GetDirectoryName($resolved) -ine $base -or (Split-Path -Leaf $resolved) -notmatch '^[a-f0-9]{32}$') {
        throw 'Refusing ETL2PCAPNG fixture cleanup outside its unique workspace-local directory.'
      }
      if (Test-Path -LiteralPath $resolved -PathType Container) { Remove-Item -LiteralPath $resolved -Recurse -Force }
    }
  }
}

Describe 'Official publisher resolution' {
  InModuleScope RIDE.PublisherSources {
    Context 'WinSCP portable distribution' {
      BeforeEach {
        $winScpOperation=@{PackageId='winscp';DownloadProvider='WinSCPPortablePage';DownloadUri='https://winscp.net/download/WinSCP-6.5.7-Portable.zip/download';PackageVersion='6.5.7';Architecture='x86';InstallerType='Portable';PortableFormat='Zip';AllowedDownloadHosts=@('cdn.winscp.net')}
        $script:winScpPage=@{Content=('<li>SHA-256: '+('a'*64)+'</li>');Links=@(@{href='https://cdn.winscp.net/files/WinSCP-6.5.7-Portable.zip?secure=abcdefghijklmnopqrstuv==,1791706349'})}
        Mock Invoke-WebRequest { $script:winScpPage }
      }
      It 'binds the declared version to the publisher digest and fresh CDN URL' {
        $artifact=Resolve-RidePublisherArtifact $winScpOperation
        $artifact.Version | Should -Be '6.5.7'
        $artifact.FileName | Should -Be 'WinSCP-6.5.7-Portable.zip'
        $artifact.ProviderDigest | Should -Be ('sha256:'+('a'*64))
        $artifact.PublisherSha256 | Should -Be ('a'*64)
        $artifact.PublisherChecksumUri | Should -Be $winScpOperation.DownloadUri
        $artifact.SourceUri | Should -Be $winScpOperation.DownloadUri
        $artifact.ChecksumUris | Should -Contain $winScpOperation.DownloadUri
        $artifact.Uri | Should -Be $script:winScpPage.Links[0].href
        Should -Invoke Invoke-WebRequest -Exactly 1
      }
      It 'rejects missing or conflicting checksum statements' {
        $script:winScpPage.Content='Download'
        {Resolve-RidePublisherArtifact $winScpOperation} | Should -Throw '*exactly one publisher SHA-256*'
        $script:winScpPage.Content='<li>SHA-256: '+('a'*64)+'</li><li>SHA-256: '+('b'*64)+'</li>'
        {Resolve-RidePublisherArtifact $winScpOperation} | Should -Throw '*exactly one publisher SHA-256*'
      }
      It 'rejects altered hosts, releases, credentials and unexpected CDN queries' {
        $good=$script:winScpPage.Links[0].href
        foreach($bad in @($good.Replace('cdn.winscp.net','example.org'),$good.Replace('6.5.7','6.5.8'),$good.Replace('https://','https://user@'),($good+'&extra=1'),($good+'#fragment'))){
          $script:winScpPage.Links=@(@{href=$bad})
          {Resolve-RidePublisherArtifact $winScpOperation} | Should -Throw
        }
      }
      It 'rejects multiple payloads and oversized metadata' {
        $script:winScpPage.Links+=@{href=$script:winScpPage.Links[0].href.Replace('1791706349','1791706350')}
        {Resolve-RidePublisherArtifact $winScpOperation} | Should -Throw '*exactly one selected CDN*'
        $script:winScpPage.Content='a'*1048577
        {Resolve-RidePublisherArtifact $winScpOperation} | Should -Throw '*exceeds 1 MiB*'
      }
      It 'rejects unsupported distribution choices before a request' {
        $winScpOperation.Architecture='x64'
        {Resolve-RidePublisherArtifact $winScpOperation} | Should -Throw '*Invalid WinSCP*'
        Should -Invoke Invoke-WebRequest -Exactly 0
      }
    }
    BeforeEach {
      $signalHash=[Convert]::ToBase64String([byte[]](1..64))
      $signalFeed="version: 8.30.0`nfiles:`n  - url: signal-desktop-win-x64-8.30.0.exe`n    sha512: $signalHash`npath: signal-desktop-win-x64-8.30.0.exe`nsha512: $signalHash`n"
      $signalOperation=@{PackageId='signal';DownloadProvider='SignalDesktopFeed';DownloadUri='https://updates.signal.org/desktop/latest.yml';Architecture='x64';AllowedDownloadHosts=@('updates.signal.org')}
    }
    It 'binds a Signal x64 versioned artifact to both matching feed checksums' {
      Mock Invoke-WebRequest { @{Content=[Text.Encoding]::UTF8.GetBytes($signalFeed)} }
      $artifact=Resolve-RidePublisherArtifact $signalOperation
      $artifact.Version | Should -Be '8.30.0'
      $artifact.Uri | Should -Be 'https://updates.signal.org/desktop/signal-desktop-win-x64-8.30.0.exe'
      $artifact.ProviderDigest | Should -Be ('sha512:'+([BitConverter]::ToString([byte[]](1..64))).Replace('-','').ToLowerInvariant())
      $artifact.ChecksumUris | Should -Contain $signalOperation.DownloadUri
    }
    It 'refuses a Signal release with conflicting filename, version or checksum' {
      Mock Invoke-WebRequest { @{Content=$script:invalidSignalFeed} }
      foreach($invalid in @($signalFeed.Replace('version: 8.30.0','version: 8.29.0'),$signalFeed.Replace("path: signal-desktop-win-x64-8.30.0.exe`nsha512: $signalHash", "path: signal-desktop-win-x64-8.30.0.exe`nsha512: $([Convert]::ToBase64String([byte[]](64..1)))"),($signalFeed+"version: 8.30.0`n"),$signalFeed.Replace('win-x64-','win-arm64-'))){
        $script:invalidSignalFeed=$invalid
        { Resolve-RidePublisherArtifact $signalOperation } | Should -Throw
      }
    }
    It 'rejects a Signal feed mirror and unsupported architecture before fetching' {
      Mock Invoke-WebRequest { throw 'Must not fetch invalid metadata.' }
      $signalOperation.DownloadUri='https://example.org/desktop/latest.yml'
      { Resolve-RidePublisherArtifact $signalOperation } | Should -Throw '*Invalid Signal*'
      $signalOperation.DownloadUri='https://updates.signal.org/desktop/latest.yml';$signalOperation.Architecture='arm64'
      { Resolve-RidePublisherArtifact $signalOperation } | Should -Throw '*Invalid Signal*'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
    It 'binds VS Code to its publisher SHA-256' {
      Mock Invoke-RestMethod { @{productVersion='1.2.3';url='https://vscode.download.prss.microsoft.com/one/setup.exe';sha256hash=('a'*64)} }
      $artifact=Resolve-RidePublisherArtifact @{PackageId='vscode';DownloadProvider='VSCodeUpdateApi';DownloadUri='https://update.code.visualstudio.com/api/update/win32-x64-user/stable/latest';AllowedDownloadHosts=@('vscode.download.prss.microsoft.com');Architecture='x64'}
      $artifact.ProviderDigest | Should -Be ('sha256:'+('a'*64))
      $artifact.Version | Should -Be '1.2.3'
    }
    It 'binds an explicit UK Mozilla artifact to its exact architecture and checksum member' {
      Mock Invoke-RestMethod { @{LATEST_THUNDERBIRD_VERSION='150.0.1'} }
      Mock Invoke-WebRequest {
        if($Uri -like '*SHA256SUMS'){return @{Content=(('a'*64)+'  win64/en-US/Thunderbird Setup 150.0.1.msi' + "`n" + ('b'*64)+'  win/en-GB/Thunderbird Setup 150.0.1.msi')}}
        @{Links=@()}
      }
      $op=@{DownloadProvider='MozillaVersionsJson';DownloadUri='https://product-details.mozilla.org/1.0/thunderbird_versions.json';MozillaProduct='thunderbird';VersionKey='LATEST_THUNDERBIRD_VERSION';MozillaLocale='en-GB';Architecture='x86';InstallerType='Msi';AllowedDownloadHosts=@('archive.mozilla.org')}
      $artifact=Resolve-RidePublisherArtifact $op
      $artifact.Uri | Should -Be 'https://archive.mozilla.org/pub/thunderbird/releases/150.0.1/win/en-GB/Thunderbird%20Setup%20150.0.1.msi'
      $artifact.ProviderDigest | Should -Be ('sha256:'+('b'*64))
      $op.MozillaLocale='../en-US'
      { Resolve-RidePublisherArtifact $op } | Should -Throw '*Unsafe Mozilla locale*'
    }
    It 'refuses a redirected publisher artifact host' {
      Mock Invoke-RestMethod { @{productVersion='1.2.3';url='https://example.org/setup.exe';sha256hash=('a'*64)} }
      { Resolve-RidePublisherArtifact @{DownloadProvider='VSCodeUpdateApi';DownloadUri='https://update.code.visualstudio.com/api/update/win32-x64-user/stable/latest';AllowedDownloadHosts=@('vscode.download.prss.microsoft.com')} } | Should -Throw '*outside declared*'
    }
    It 'resolves the Firefox stable release to a versioned x64 MSI' {
      Mock Invoke-RestMethod { @{LATEST_FIREFOX_VERSION='157.0.1'} }
      Mock Invoke-WebRequest {
        if($Uri -like '*SHA256SUMS'){ @{Content=(('a'*64)+'  win64/en-US/Firefox Setup 157.0.1.msi')} }
        else { @{Links=@(@{href='SHA256SUMS.asc'})} }
      }
      $artifact=Resolve-RidePublisherArtifact @{DownloadProvider='MozillaVersionsJson';DownloadUri='https://product-details.mozilla.org/1.0/firefox_versions.json';MozillaProduct='firefox';VersionKey='LATEST_FIREFOX_VERSION';InstallerType='Msi';AllowedDownloadHosts=@('archive.mozilla.org')}
      $artifact.Uri | Should -Be 'https://archive.mozilla.org/pub/firefox/releases/157.0.1/win64/en-US/Firefox%20Setup%20157.0.1.msi'
      $artifact.ProviderDigest | Should -Be ('sha256:'+('a'*64))
      $artifact.SignatureUris | Should -Contain 'https://archive.mozilla.org/pub/firefox/releases/157.0.1/SHA256SUMS.asc'
    }
    It 'rejects an unsafe Mozilla release before making checksum requests' {
      Mock Invoke-RestMethod { @{LATEST_FIREFOX_VERSION='../other'} }
      Mock Invoke-WebRequest { throw 'No checksum request is allowed.' }
      { Resolve-RidePublisherArtifact @{DownloadProvider='MozillaVersionsJson';DownloadUri='https://product-details.mozilla.org/1.0/firefox_versions.json';MozillaProduct='firefox';VersionKey='LATEST_FIREFOX_VERSION';InstallerType='Msi';AllowedDownloadHosts=@('archive.mozilla.org')} } | Should -Throw '*Unsafe publisher version*'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
    It 'binds publisher page checksums and signatures to the versioned standalone artifact' {
      Mock Invoke-WebRequest {
        if($Uri -like '*sha256sums'){ @{Content=(('b'*64)+'  w64/putty.exe')} }
        else { @{Links=@(@{href='https://example.org/latest/w64/putty.exe'},@{href='https://example.org/latest/w64/putty.exe.gpg'},@{href='https://example.org/latest/sha256sums'},@{href='https://example.org/latest/sha256sums.gpg'});Content='release 0.85'} }
      }
      $artifact=Resolve-RidePublisherArtifact @{DownloadProvider='PublisherLinkPage';DownloadUri='https://example.org/download';AssetPattern='/w64/putty\.exe$';PageVersionPattern='release (?<version>[0-9.]+)';VersionPattern='/(?<version>[0-9.]+)/w64/';AllowedDownloadHosts=@('example.org');ChecksumAssetPattern='/sha256sums$';ChecksumMember='w64/putty.exe'}
      $artifact.ProviderDigest | Should -Be ('sha256:'+('b'*64))
      $artifact.ChecksumUris | Should -Contain 'https://example.org/0.85/sha256sums'
      $artifact.SignatureUris | Should -Contain 'https://example.org/0.85/w64/putty.exe.gpg'
      $artifact.SignatureUris | Should -Contain 'https://example.org/0.85/sha256sums.gpg'
    }
    It 'rejects a missing or ambiguous publisher checksum for the selected architecture' {
      Mock Invoke-WebRequest { @{Content=(('a'*64)+'  w32/putty.exe')} }
      { Get-RidePublisherChecksum -Uri 'https://example.org/sha256sums' -Member 'w64/putty.exe' } | Should -Throw '*exactly one*'
      Mock Invoke-WebRequest { @{Content=((('a'*64)+'  w64/putty.exe')+"`n"+(('b'*64)+'  w64/putty.exe'))} }
      { Get-RidePublisherChecksum -Uri 'https://example.org/sha256sums' -Member 'w64/putty.exe' } | Should -Throw '*exactly one*'
    }
    It 'reads a binary-content checksum response as UTF-8 publisher text' {
      Mock Invoke-WebRequest { @{Content=[Text.Encoding]::UTF8.GetBytes((('a'*64)+'  w64/putty.exe'))} }
      Get-RidePublisherChecksum -Uri 'https://example.org/sha256sums' -Member 'w64/putty.exe' | Should -Be ('sha256:'+('a'*64))
    }
    It 'does not select the first artifact from an ambiguous publisher page' {
      Mock Invoke-WebRequest { @{Links=@(@{href='https://example.org/app-1.0.exe'},@{href='https://example.org/app-2.0.exe'})} }
      { Resolve-RidePublisherArtifact @{DownloadProvider='PublisherLinkPage';DownloadUri='https://example.org/download';AssetPattern='app-.*exe$';VersionPattern='app-(?<version>[0-9.]+)\.exe';AllowedDownloadHosts=@('example.org')} } | Should -Throw '*found 2*'
    }
  }
}

Describe 'Engine package variant integration' {
  InModuleScope RIDE.Engine {
    BeforeEach {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideRecordedPackageSelection { $null }
    }
    It 'carries the variant through profile planning' {
      $plan=@(Get-RidePlan @{Operations=@(@{Id='package.sharex';State='Present';Variant='portable'})})
      $plan[0].Operation.SelectedVariant | Should -Be 'portable'
      $plan[0].Operation.InstallerType | Should -Be 'Portable'
    }
    It 'rejects unsupported direct variants' { { Get-RideSingleOperationPlan -Id package.sharex -Action Install -Variant missing } | Should -Throw '*Unsupported variant*' }
    It 'removes the recorded edition and destination after preferences change' {
      $saved=Resolve-RidePackageSelection (Get-RideOperation package.sharex) portable
      $saved.InstallDirectory='C:\OriginalTools\sharex';$saved.ResolvedToolsDirectory='C:\OriginalTools'
      Mock Get-RideRecordedPackageSelection { $saved }
      $plan=@(Get-RideSingleOperationPlan -Id package.sharex -Action Remove)
      $plan[0].Operation.SelectedVariant | Should -Be 'portable'
      $plan[0].Operation.InstallDirectory | Should -Be 'C:\OriginalTools\sharex'
      $plan[0].State | Should -Be 'Absent'
    }
    It 'keeps a live recorded destination for the same explicitly selected edition' {
      $saved=Resolve-RidePackageSelection (Get-RideOperation package.sharex) portable
      $saved.InstallDirectory='C:\OriginalTools\sharex';$saved.ResolvedToolsDirectory='C:\OriginalTools'
      Mock Get-RideRecordedPackageSelection { $saved }
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$true} }
      (Resolve-RideLifecycleSelection (Get-RideOperation package.sharex) portable).InstallDirectory | Should -Be 'C:\OriginalTools\sharex'
    }
    It 'previews without downloading, installing or saving state' {
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$false;Healthy=$false} }
      Mock Install-RidePackage { throw 'Must not install.' }
      Mock Save-RideOperationSnapshot { throw 'Must not capture.' }
      $plan=@(Get-RideSingleOperationPlan -Id package.sharex -Action Install -Variant portable)
      $plan[0].Operation.SupportedTargets=@('Windows 11')
      $null=Invoke-RidePlan -Plan $plan -WhatIf
      Should -Invoke Install-RidePackage -Exactly 0
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
    }
    It 'refuses an installed different edition even in preview' {
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=($Operation.InstallerType -eq 'Exe')} }
      $plan=@(Get-RideSingleOperationPlan -Id package.sharex -Action Install -Variant portable)
      $plan[0].Operation.SupportedTargets=@('Windows 11')
      { Invoke-RidePlan -Plan $plan -WhatIf } | Should -Throw '*different edition*'
    }
    It 'treats a modified portable tree as unhealthy rather than matching Present' {
      Test-RideCurrentStateMatch -Operation @{Kind='Package';InstallerType='Portable'} -State Present -CurrentState ([pscustomobject]@{Present=$true;Healthy=$false}) | Should -BeFalse
    }
    It 'uses valid ownership for repeat and removal preview when portable architectures share a directory' {
      $root=Join-Path $TestDrive 'shared-variants'
      $directory=Join-Path $root 'fixture'
      $null=New-Item -ItemType Directory -Path $directory -Force
      $file=Join-Path $directory 'app.exe'
      [IO.File]::WriteAllText($file,'Inert ownership fixture.')
      $base=@{Id='package.fixture';PackageId='fixture';Name='Fixture';Kind='Package';Handler='Package';InstallerType='Portable';Scope='Machine';RequiresAdmin=$true;SupportedTargets=@('Windows 11');ResolvedToolsDirectory=$root;InstallDirectory=$directory;Variants=@{portable=@{};'portable-x86'=@{}}}
      $op=$base.Clone();$op.Remove('Variants');$op.SelectedVariant='portable'
      $manifest=@{SchemaVersion=1;PackageId='fixture';Variant='portable';Version='1';Status='Installed';Files=@(@{RelativePath='app.exe';Sha256=(Get-FileHash $file).Hash})}
      $manifest|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $directory '.ride-package.json')
      Mock Get-RideOperation {$base}
      Mock Resolve-RidePackageSelection {$copy=$Operation.Clone();$copy.Remove('Variants');$copy.SelectedVariant=$Variant;$copy}
      Mock Get-RideInstalledPackage {Get-RidePortableState $Operation}
      Mock Save-RideOperationSnapshot {throw 'Must not save state.'}
      Mock Install-RidePackage {throw 'Must not install.'}
      $output=@(Invoke-RidePlan @([pscustomobject]@{Operation=$op;State='Present'}) -Confirm:$false)
      $output|Should -Contain 'No changes were needed; no state record was created.'
      {Invoke-RidePlan @([pscustomobject]@{Operation=$op;State='Absent'}) -WhatIf}|Should -Not -Throw
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Install-RidePackage -Exactly 0
      $manifest.Variant='portable-x86'
      $manifest|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $directory '.ride-package.json')
      {Invoke-RidePlan @([pscustomobject]@{Operation=$op;State='Present'}) -WhatIf}|Should -Throw '*Invalid portable ownership manifest*'
      $saved=$op.Clone();$saved.SelectedVariant='portable-x86'
      Mock Get-RideRecordedPackageSelection {$saved}
      {Invoke-RidePlan @([pscustomobject]@{Operation=$op;State='Present'}) -WhatIf}|Should -Throw '*different edition*'
    }
    It 'rejects a desktop application on Server Core before changing state' {
      Mock Get-RidePlatform { 'Windows Server 2025' }
      Mock Get-ItemProperty { [pscustomobject]@{InstallationType='Server Core'} }
      $operation=@{Id='package.gui';Kind='Package';Name='GUI';RequiresDesktopExperience=$true;RequiresAdmin=$true;SupportedTargets=@('Windows Server 2025')}
      { Assert-RidePlanAllowed @([pscustomobject]@{Operation=$operation;State='Present'}) } | Should -Throw '*Desktop Experience*'
    }
    It 'rejects a pending package before any installation' {
      Mock Install-RidePackage { throw 'Must not install.' }
      $operation=@{Id='package.pending';Kind='Package';Name='Pending';PendingAcceptance=$true;SupportedTargets=@();RequiresAdmin=$false}
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$false} }
      { Assert-RidePlanAllowed @([pscustomobject]@{Operation=$operation;State='Present'}) } | Should -Throw '*does not support*'
      Should -Invoke Install-RidePackage -Exactly 0
    }
    It 'rejects elevated current-user execution before any capture or installer call' {
      Mock Save-RideOperationSnapshot { throw 'Must not capture.' }
      Mock Install-RidePackage { throw 'Must not install.' }
      $operation=Resolve-RidePackageSelection (Get-RideOperation package.thunderbird)
      $operation.SupportedTargets=@('Windows 11')
      {Invoke-RidePlan @([pscustomobject]@{Operation=$operation;State='Present'}) -Confirm:$false} | Should -Throw '*non-elevated*'
      Should -Invoke Save-RideOperationSnapshot -Exactly 0
      Should -Invoke Install-RidePackage -Exactly 0
    }
    It 'permits read-only preview and a limited user token for the same selection' {
      $operation=Resolve-RidePackageSelection (Get-RideOperation package.thunderbird)
      $operation.SupportedTargets=@('Windows 11')
      {& {$WhatIfPreference=$true;Assert-RidePlanAllowed @([pscustomobject]@{Operation=$operation})}} | Should -Not -Throw
      Mock Test-RideAdministrator {$false}
      {Assert-RidePlanAllowed @([pscustomobject]@{Operation=$operation})} | Should -Not -Throw
    }
    It 'restores using the saved package target and edition after catalog support changes' {
      Mock Get-RidePlatform { 'Windows Server 2025' }
      Mock Get-RideStateRoot { Join-Path $TestDrive $Scope }
      Mock Get-RideCatalog { @{Operations=@(@{Id='package.saved';Kind='Package';Scope='Machine';SupportedTargets=@('Windows 11')})} }
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$true} }
      Mock Uninstall-RidePackage {}
      $runId='12345678901234567890123456789012'
      $directory=Join-Path (Join-Path $TestDrive Machine) $runId
      $null=New-Item -ItemType Directory -Path $directory -Force
      $saved=@{Id='package.saved';Name='Saved edition';Kind='Package';Scope='Machine';InstallerType='Exe';SelectedVariant='installed';SupportedTargets=@('Windows Server 2025')}
      @{SchemaVersion=3;OperationId='package.saved';Kind='Package';Scope='Machine';PackageSelection=$saved;Snapshot=@{Present=$false}} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'package.saved.json') -Encoding UTF8
      Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
      Should -Invoke Uninstall-RidePackage -Exactly 1 -ParameterFilter { $Operation.Name -eq 'Saved edition' -and $Operation.SelectedVariant -eq 'installed' }
    }
    It 'retains an upgraded shared runtime when the captured prior version is below the required minimum' {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideStateRoot { Join-Path $TestDrive $Scope }
      Mock Get-RideCatalog { @{Operations=@(@{Id='package.runtime';Kind='Package';Scope='Machine';SupportedTargets=@('Windows 11')})} }
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$true;DisplayVersion='14.51.36247.0'} }
      Mock Uninstall-RidePackage { throw 'Must retain the working shared runtime.' }
      $runId='22345678901234567890123456789012'
      $directory=Join-Path (Join-Path $TestDrive Machine) $runId
      $null=New-Item -ItemType Directory -Path $directory -Force
      $saved=@{Id='package.runtime';Name='Microsoft Visual C++ v14 Redistributable (x64)';Kind='Package';Scope='Machine';InstallerType='Exe';SelectedVariant='installed';MinimumInstalledVersion='14.50.35710.0';SupportedTargets=@('Windows 11')}
      @{SchemaVersion=3;OperationId='package.runtime';Kind='Package';Scope='Machine';PackageSelection=$saved;Snapshot=@{Present=$false;Version='14.40.33810.0'}} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $directory 'package.runtime.json') -Encoding UTF8
      { Restore-RideRun -RunId $runId -Confirm:$false -WarningAction SilentlyContinue } | Should -Not -Throw
      Should -Invoke Uninstall-RidePackage -Exactly 0
    }
    It 'filters default status using the recorded variant target rather than the product default' {
      Mock Get-RidePlatform { 'Windows Server 2025' }
      $base=@{Id='package.sample';Name='Sample';Category='Software / Sample';Kind='Package';Scope='Machine';SupportedTargets=@('Windows 11')}
      $saved=$base.Clone();$saved.SupportedTargets=@('Windows Server 2025');$saved.SelectedVariant='portable';$saved.InstallerType='Portable'
      $saved.TargetDefaults=@{'Windows Server 2025'=@{DefaultValue='Absent';EffectiveDefault='Not installed'}}
      Mock Get-RideCatalog { @{SchemaVersion=1;Operations=@($base);Groups=@()} }
      Mock Resolve-RideLifecycleSelection { $saved }
      Mock Get-RideCurrentState { [pscustomobject]@{Present=$true;Healthy=$true;DisplayVersion='1.0'} }
      $rows=@(Get-RideStatus -View packages)
      $rows.Count | Should -Be 1
      $rows[0].Id | Should -Be 'package.sample'
      $rows[0].CurrentState | Should -Be 'Present'
    }
  }
}

Describe 'Saved selection access by scope' {
  InModuleScope RIDE.Engine {
    It 'does not probe protected machine state for an unelevated user-only package' {
      Mock Test-RideAdministrator { $false }
      Mock Get-RideStateRoot { if($Scope -eq 'Machine'){throw 'Protected machine state must not be probed.'};$TestDrive }
      Mock Test-Path { $false }
      { Get-RideRecordedPackageSelection @{Id='package.user';Kind='Package';Scope='User'} } | Should -Not -Throw
      Should -Invoke Get-RideStateRoot -Exactly 0 -ParameterFilter { $Scope -eq 'Machine' }
    }
  }
}

Describe 'RIDE-managed PowerShell module prerequisites' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $script:moduleToolsDirectory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $moduleDirectory=Join-Path $script:moduleToolsDirectory 'microsoft-powershell-threadjob'
      $null=New-Item -ItemType Directory -Path $moduleDirectory -Force
      Set-Content -LiteralPath (Join-Path $moduleDirectory 'Microsoft.PowerShell.ThreadJob.psd1') -Value "@{ ModuleVersion = '2.2.0' }" -Encoding ascii
      Mock Get-RidePackageConfiguration { @{ToolsDirectory=$script:moduleToolsDirectory} }
      Mock Get-RidePortableState { [pscustomobject]@{Present=$true;Healthy=$true} }
      $script:moduleConsumer=@{Id='package.psscripttools';PrerequisitePowerShellModuleName='Microsoft.PowerShell.ThreadJob';PrerequisiteModuleDirectory='microsoft-powershell-threadjob';PrerequisitePowerShellModuleMinimumVersion='2.2.0'}
    }
    It 'accepts only a healthy RIDE-owned module package at or above the catalog version' {
      $status=Get-RidePackagePrerequisiteStatus -Operation $script:moduleConsumer
      $status.Satisfied|Should -BeTrue
      $status.Directory|Should -Be (Join-Path $script:moduleToolsDirectory 'microsoft-powershell-threadjob')
    }
    It 'rejects a managed package whose module manifest is below the required version' {
      $manifest=Join-Path (Join-Path $script:moduleToolsDirectory 'microsoft-powershell-threadjob') 'Microsoft.PowerShell.ThreadJob.psd1'
      Set-Content -LiteralPath $manifest -Value "@{ ModuleVersion = '2.1.0' }" -Encoding ascii
      $status=Get-RidePackagePrerequisiteStatus -Operation $script:moduleConsumer
      $status.Satisfied|Should -BeFalse
      $status.Reason|Should -Match 'version 2.2.0 or later'
    }
    It 'rejects a module directory without a healthy RIDE ownership manifest' {
      Mock Get-RidePortableState { [pscustomobject]@{Present=$true;Healthy=$false} }
      $status=Get-RidePackagePrerequisiteStatus -Operation $script:moduleConsumer
      $status.Satisfied|Should -BeFalse
      $status.Reason|Should -Match 'healthy RIDE-managed PowerShell module package'
    }
  }
}

Describe 'Microsoft OpenJDK pinned checksum provider' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $version='21.0.12.1'
      $fileName="microsoft-jdk-$version-windows-x64.msi"
      $downloadUri="https://aka.ms/download-jdk/$fileName"
      $operation=@{PackageId='microsoft-openjdk-21';ProductUri='https://learn.microsoft.com/en-us/java/openjdk/download';PackageVersion=$version;Architecture='x64';InstallerType='Msi';AssetName=$fileName;DownloadUri=$downloadUri;ExpectedSha256Uri="$downloadUri.sha256sum.txt";DownloadProvider='MicrosoftOpenJdk'}
      Mock Invoke-WebRequest { [pscustomobject]@{Content=(('a'*64)+'  '+$fileName)} }
    }
    It 'binds the exact pinned MSI and publisher checksum before artifact download' {
      $artifact=Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -BeExactly '21.0.12.1'
      $artifact.Architecture | Should -BeExactly 'x64'
      $artifact.FileName | Should -BeExactly $fileName
      $artifact.Uri | Should -BeExactly $downloadUri
      $artifact.SourceUri | Should -BeExactly $operation.ExpectedSha256Uri
      $artifact.ProviderDigest | Should -Be ('sha256:'+('a'*64))
      $artifact.ChecksumUris | Should -Contain $operation.ExpectedSha256Uri
      Should -Invoke Invoke-WebRequest -Exactly 1 -ParameterFilter {$Uri -ceq $operation.ExpectedSha256Uri}
    }
    It 'accepts a UTF-8 byte-order mark before the publisher checksum record' {
      Mock Invoke-WebRequest { [pscustomobject]@{Content=([string][char]0xFEFF+(('a'*64)+'  '+$fileName))} }
      $artifact=Resolve-RidePackageArtifact -Operation $operation
      $artifact.ProviderDigest | Should -Be ('sha256:'+('a'*64))
    }
    It 'decodes the publisher checksum returned as UTF-8 bytes' {
      Mock Invoke-WebRequest { [pscustomobject]@{Content=[Text.Encoding]::UTF8.GetBytes(('b'*64)+"`n");Headers=@{'Content-Type'='application/octet-stream'}} }
      $artifact=Resolve-RidePackageArtifact -Operation $operation
      $artifact.ProviderDigest | Should -Be ('sha256:'+('b'*64))
    }
    It 'includes a bounded response sample when the publisher checksum format is unexpected' {
      Mock Invoke-WebRequest { [pscustomobject]@{Content='<!DOCTYPE html><title>Unexpected response</title>'} }
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*content type*=*sample=*Unexpected response*'
    }
    It 'rejects a checksum record naming a different file' {
      Mock Invoke-WebRequest { [pscustomobject]@{Content=(('a'*64)+'  microsoft-jdk-21.0.12.1-windows-arm64.msi')} }
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*different file*'
    }
    It 'rejects source URLs that do not match the exact versioned asset' {
      $operation.DownloadUri=$downloadUri.Replace('21.0.12.1','21.0.12.0')
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exact pinned versioned x64 MSI*'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
  }
}

Describe 'JoeWare AdMod publisher-form package provider' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $operation = @{
        PackageId = 'joeware-admod'; AcquisitionProduct = 'admod'
        ProductUri = 'https://www.joeware.net/freetools/tools/admod/index.htm'
        DownloadUri = 'https://www.joeware.net/freetools/tools/admod/index.htm'
        PackageVersion = '1.29.00'; AssetName = 'AdMod.zip'; InstallerType = 'Portable'
        PortableFormat = 'Zip'; Architecture = 'x86'
        ExpectedSha256 = '45cf050eec76d7f1c736b613616bcbf4c3dea872d3d5f7398fd276b1fc369235'
        PortableMembers = @('AdMod.exe'); RequiredFiles = @('AdMod.exe')
        DownloadProvider = 'JoeWareAdModForm'
      }
      Mock Invoke-WebRequest { throw 'Artifact resolution must not submit the publisher form.' }
    }
    It 'resolves the pinned official product form and archive digest without a request' {
      $artifact = Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -BeExactly '1.29.00'
      $artifact.Architecture | Should -BeExactly 'x86'
      $artifact.FileName | Should -BeExactly 'AdMod.zip'
      $artifact.Uri | Should -BeExactly $operation.ProductUri
      $artifact.ProviderDigest | Should -BeExactly ('sha256:' + $operation.ExpectedSha256)
      $artifact.ChecksumUris | Should -Contain 'https://www.joeware.net/freetools/versions.txt'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
    It 'refuses a different product page before any publisher request' {
      $operation.DownloadUri = 'https://example.invalid/admod.zip'
      { Resolve-RidePackageArtifact -Operation $operation } | Should -Throw '*pinned AdMod publisher page*'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
  }
}

Describe 'JoeWare AdMod catalog declaration' {
  It 'keeps its exact publisher form, archive pin, architecture and pending target acceptance' {
    $catalogPath = Join-Path $root 'catalog/operations.psd1'
    $catalog = Invoke-RideTestCatalogImport -Path $catalogPath
    $operation = @($catalog.Operations | Where-Object Id -ceq 'package.joeware-admod')
    $operation.Count | Should -Be 1
    $operation[0].DownloadProvider | Should -BeExactly 'JoeWareAdModForm'
    $operation[0].PackageVersion | Should -BeExactly '1.29.00'
    $operation[0].ExpectedSha256 | Should -BeExactly '45cf050eec76d7f1c736b613616bcbf4c3dea872d3d5f7398fd276b1fc369235'
    $operation[0].PortableMembers | Should -Be @('AdMod.exe')
    $operation[0].SupportedTargets | Should -BeNullOrEmpty
    $operation[0].CandidateTargets | Should -Contain 'Windows 11'
    $operation[0].PendingAcceptance | Should -BeTrue
    @(Invoke-RideTestCatalogValidation -Catalog $catalog) | Should -BeNullOrEmpty
  }
}

Describe 'JoeWare AdMod retained archive file lifecycle' {
  BeforeAll {
    $script:JoeWareAdModRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $JoeWareAdModRoot 'modules/RIDE.Engine.psm1') -Force
    Import-Module (Join-Path $JoeWareAdModRoot 'modules/RIDE-PortablePackages.psm1') -Force
    $script:JoeWareAdModCatalog = Get-RideCatalog
  }

  It 'stages only the pinned member and restores installed, prior-version and absent states without launching it' {
    $fixturePath = $env:RIDE_JOEWARE_ADMOD_FIXTURE
    if ([string]::IsNullOrWhiteSpace($fixturePath)) {
      Set-ItResult -Skipped -Because 'Set RIDE_JOEWARE_ADMOD_FIXTURE to the retained publisher AdMod.zip to enable actual-archive lifecycle checks.'
      return
    }
    $archive = Get-Item -LiteralPath $fixturePath -Force -ErrorAction Stop
    if ($archive.PSIsContainer -or ($archive.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'The retained AdMod fixture must be a regular file.'
    }

    $operation = ($script:JoeWareAdModCatalog.Operations | Where-Object Id -CEQ 'package.joeware-admod' | Select-Object -First 1).Clone()
    if (-not $operation -or $operation.ExpectedSha256 -cne '45cf050eec76d7f1c736b613616bcbf4c3dea872d3d5f7398fd276b1fc369235') {
      throw 'The AdMod catalog candidate does not match the reviewed archive pin.'
    }
    (Get-FileHash -LiteralPath $archive.FullName -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $operation.ExpectedSha256

    $fixtureBase = [IO.Path]::GetFullPath((Join-Path $script:JoeWareAdModRoot '.local/application-package-tests'))
    $null = New-Item -ItemType Directory -Path $fixtureBase -Force
    $caseName = 'joeware-admod-' + [guid]::NewGuid().ToString('N')
    $caseRoot = [IO.Path]::GetFullPath((Join-Path $fixtureBase $caseName))
    if (Test-Path -LiteralPath $caseRoot) { throw 'Unique AdMod lifecycle fixture already exists.' }
    $null = New-Item -ItemType Directory -Path $caseRoot
    $tempRoot = Join-Path $caseRoot 'temp'
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $previousTemp = $env:TEMP
    $previousTmp = $env:TMP
    $casePassed = $false
    try {
      $env:TEMP = $tempRoot
      $env:TMP = $tempRoot
      $operation['ResolvedToolsDirectory'] = Join-Path $caseRoot 'tools'
      $operation['InstallDirectory'] = Join-Path $operation['ResolvedToolsDirectory'] $operation.PackageId
      $operation['SelectedVariant'] = 'portable'
      $absentSnapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'absent-snapshot')
      $absentSnapshot.Present | Should -BeFalse

      Add-Type -AssemblyName System.IO.Compression
      Add-Type -AssemblyName System.IO.Compression.FileSystem
      $priorArchive = Join-Path $caseRoot 'prior-state.zip'
      $zip = [IO.Compression.ZipFile]::Open($priorArchive, [IO.Compression.ZipArchiveMode]::Create)
      try {
        $writer = [IO.StreamWriter]::new($zip.CreateEntry('AdMod.exe').Open())
        try { $writer.Write('inert previous managed version') } finally { $writer.Dispose() }
      } finally { $zip.Dispose() }
      $priorHash = (Get-FileHash -LiteralPath $priorArchive -Algorithm SHA256).Hash.ToLowerInvariant()
      $operation.ExpectedSha256 = $priorHash
      $priorArtifact = [pscustomobject]@{ Path = $priorArchive; Sha256 = $priorHash; Version = 'prior-state-fixture' }
      Install-RidePortablePayload $operation $priorArtifact -Offline
      $priorState = Get-RidePortableState $operation
      $priorState.Healthy | Should -BeTrue
      $priorSnapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'prior-snapshot')

      $operation.ExpectedSha256 = '45cf050eec76d7f1c736b613616bcbf4c3dea872d3d5f7398fd276b1fc369235'
      $artifact = [pscustomobject]@{ Path = $archive.FullName; Sha256 = $operation.ExpectedSha256; Version = '1.29.00' }
      Install-RidePortablePayload $operation $artifact -Offline
      $installed = Get-RidePortableState $operation
      $installed.Healthy | Should -BeTrue
      $installed.Files.Count | Should -Be 1
      $installed.Files[0].RelativePath | Should -BeExactly 'AdMod.exe'
      (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory 'AdMod.exe') -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly '86c922fc98c115ea21c2053739938234fd90ce626ed227b2c3c122c2484e4d79'
      Install-RidePortablePayload $operation $artifact -Offline
      (Get-RidePortableState $operation).Healthy | Should -BeTrue
      $currentSnapshot = Save-RidePortableSnapshot $operation (Join-Path $caseRoot 'current-snapshot')

      Uninstall-RidePortablePayload $operation
      (Get-RidePortableState $operation).Present | Should -BeFalse
      Restore-RidePortableSnapshot $operation $currentSnapshot
      $restoredCurrent = Get-RidePortableState $operation
      $restoredCurrent.Healthy | Should -BeTrue
      $restoredCurrent.DisplayVersion | Should -BeExactly '1.29.00'

      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $priorSnapshot
      $restoredPrior = Get-RidePortableState $operation
      $restoredPrior.Healthy | Should -BeTrue
      $restoredPrior.DisplayVersion | Should -BeExactly 'prior-state-fixture'
      (Get-FileHash -LiteralPath (Join-Path $operation.InstallDirectory 'AdMod.exe') -Algorithm SHA256).Hash.ToLowerInvariant() | Should -BeExactly $priorState.Files[0].Sha256

      Uninstall-RidePortablePayload $operation
      Restore-RidePortableSnapshot $operation $absentSnapshot
      (Get-RidePortableState $operation).Present | Should -BeFalse
      $casePassed = $true
    } finally {
      $env:TEMP = $previousTemp
      $env:TMP = $previousTmp
      if ($casePassed) {
        $expectedPrefix = $fixtureBase.TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
        if (-not $caseRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $caseRoot) -cne $caseName -or $caseName -notmatch '^joeware-admod-[0-9a-f]{32}$') {
          throw 'Refusing to clean AdMod lifecycle fixture outside its unique workspace root.'
        }
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
      }
    }
  }
}

Describe 'Microsoft OpenJDK registered presence detection' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $operation=@{Id='package.microsoft-openjdk-21';PackageId='microsoft-openjdk-21';Name='Microsoft Build of OpenJDK 21 (x64)';Scope='Machine';InstallerType='Msi';DisplayNamePattern='^Microsoft Build of OpenJDK\s+(?:with Hotspot\s+)?21(?:[.\s]|$)'}
      Mock Resolve-RidePackageSelection { $Operation }
      Mock Get-ItemProperty { @() }
    }
    It 'detects the versioned uninstall name emitted by the pinned MSI' {
      Mock Get-ItemProperty { [pscustomobject]@{DisplayName='Microsoft Build of OpenJDK  21.0.12.1+1 (x64)';DisplayVersion='21.0.12.101';UninstallString='msiexec /x {TEST}'} } -ParameterFilter { $Path -like 'HKLM:*' }
      $installed=Get-RideInstalledPackage -Operation $operation
      $installed.Present | Should -BeTrue
      $installed.DisplayName | Should -BeExactly 'Microsoft Build of OpenJDK  21.0.12.1+1 (x64)'
      $installed.DisplayVersion | Should -BeExactly '21.0.12.101'
    }
    It 'does not confuse another major version with OpenJDK 21' {
      Mock Get-ItemProperty { [pscustomobject]@{DisplayName='Microsoft Build of OpenJDK 210.0.1 (x64)';DisplayVersion='210.0.1'} } -ParameterFilter { $Path -like 'HKLM:*' }
      (Get-RideInstalledPackage -Operation $operation).Present | Should -BeFalse
    }
  }
}

Describe 'Sysmon Modular pinned download-only profile artifacts' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $release='a45dedb13a43'
      $asset='sysmonconfig-with-filedelete.xml'
      $url="https://github.com/olafhartong/sysmon-modular/releases/download/configs-$release/$asset"
      $operation=@{Id='artifact.sysmon-modular-balanced-filedelete-15-21';Kind='Artifact';ArtifactId='sysmon-modular-balanced-filedelete-15-21';ProductUri='https://github.com/olafhartong/sysmon-modular';Repository='olafhartong/sysmon-modular';ReleaseTag="configs-$release";PackageVersion=$release;TargetSysmonVersion='15.21';AssetName=$asset;DownloadUri=$url;ChecksumUri="https://github.com/olafhartong/sysmon-modular/releases/download/configs-$release/SHA256SUMS";DownloadProvider='GitHubReleaseAssetApi';Architecture='neutral'}
      Mock Invoke-WebRequest { [pscustomobject]@{Content=((('a'*64)+'  sysmonconfig.xml')+"`n"+(('b'*64)+'  sysmonconfig-with-filedelete.xml')+"`n"+(('c'*64)+'  sysmonconfig-excludes-only.xml'))} }
    }
    It 'resolves the selected pinned profile from the exact release checksum manifest' {
      $artifact=Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -BeExactly $release
      $artifact.FileName | Should -BeExactly $asset
      $artifact.Uri | Should -BeExactly $url
      $artifact.ProviderDigest | Should -Be ('sha256:'+('b'*64))
      $artifact.ChecksumUris | Should -Contain $operation.ChecksumUri
      Should -Invoke Invoke-WebRequest -Exactly 1 -ParameterFilter {$Uri -ceq $operation.ChecksumUri}
    }
    It 'refuses a missing or duplicated selected checksum record' {
      Mock Invoke-WebRequest { [pscustomobject]@{Content=(('a'*64)+'  sysmonconfig.xml')} }
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exactly one checksum record*'
      Mock Invoke-WebRequest { [pscustomobject]@{Content=((('b'*64)+'  sysmonconfig-with-filedelete.xml')+"`n"+(('c'*64)+'  sysmonconfig-with-filedelete.xml'))} }
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exactly one checksum record*'
    }
    It 'refuses a release, target version or profile outside the pinned choices' {
      $operation.ReleaseTag='latest'
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exact 15.21 configuration release*'
      $operation.ReleaseTag='configs-a45dedb13a43';$operation.AssetName='sysmonconfig-research.xml'
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exact 15.21 configuration release*'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
  }
  It 'declares the three upstream profiles as download-only Sysmon 15.21 choices' {
    $catalog=Invoke-RideTestCatalogImport (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $profiles=@($catalog.Operations|Where-Object {$_.MigrationBatch -eq 'SysmonModularProfiles'}|Sort-Object AssetName)
    $profiles.Count | Should -Be 3
    $profiles.AssetName | Should -Contain 'sysmonconfig.xml'
    $profiles.AssetName | Should -Contain 'sysmonconfig-with-filedelete.xml'
    $profiles.AssetName | Should -Contain 'sysmonconfig-excludes-only.xml'
    foreach($profile in $profiles){
      $profile.Actions | Should -Be @('Download')
      $profile.TargetSysmonVersion | Should -BeExactly '15.21'
      $profile.ReleaseTag | Should -BeExactly 'configs-a45dedb13a43'
    }
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -BeNullOrEmpty
  }
}

Describe 'Pinned GitHub release packages' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $operation = @{
        PackageId='sharphound'; Repository='SpecterOps/SharpHound'; ReleaseTag='v2.17.0'; PackageVersion='2.17.0'
        DownloadUri='https://api.github.com/repos/SpecterOps/SharpHound/releases/tags/v2.17.0'
        DownloadProvider='GitHubReleaseApi'; AssetPattern='^SharpHound_v2\.17\.0_windows_x86\.zip$'
        AssetName='SharpHound_v2.17.0_windows_x86.zip'; ChecksumAssetName='SharpHound_v2.17.0_windows_x86.zip.sha256'
        Architecture='x86'; ProductUri='https://github.com/SpecterOps/SharpHound'
      }
      $release = [pscustomobject]@{
        tag_name='v2.17.0'; html_url='https://github.com/SpecterOps/SharpHound/releases/tag/v2.17.0'
        body=''; assets=@(
          [pscustomobject]@{name='SharpHound_v2.17.0_windows_x86.zip';browser_download_url='https://github.com/SpecterOps/SharpHound/releases/download/v2.17.0/SharpHound_v2.17.0_windows_x86.zip';digest=$null},
          [pscustomobject]@{name='SharpHound_v2.17.0_windows_x86.zip.sha256';browser_download_url='https://github.com/SpecterOps/SharpHound/releases/download/v2.17.0/SharpHound_v2.17.0_windows_x86.zip.sha256';digest=$null}
        )
      }
      Mock Get-RideGitHubReleaseMetadata { [pscustomobject]@{Release=$release;Provenance=[pscustomobject]@{ApiUri=$operation.DownloadUri;AcquisitionKind='Network'}} }
      Mock Invoke-WebRequest { [pscustomobject]@{Content=(('a'*64)+'  SharpHound_v2.17.0_windows_x86.zip') } }
    }
    It 'resolves only the exact tag asset and binds its publisher checksum sidecar' {
      $artifact=Resolve-RidePackageArtifact -Operation $operation
      $artifact.Version | Should -BeExactly '2.17.0'
      $artifact.FileName | Should -BeExactly $operation.AssetName
      $artifact.Uri | Should -BeExactly 'https://github.com/SpecterOps/SharpHound/releases/download/v2.17.0/SharpHound_v2.17.0_windows_x86.zip'
      $artifact.PublisherSha256 | Should -Be ('a'*64)
      $artifact.PublisherChecksumUri | Should -BeExactly 'https://github.com/SpecterOps/SharpHound/releases/download/v2.17.0/SharpHound_v2.17.0_windows_x86.zip.sha256'
      Should -Invoke Get-RideGitHubReleaseMetadata -Exactly 1 -ParameterFilter {$Uri -ceq $operation.DownloadUri}
      Should -Invoke Invoke-WebRequest -Exactly 1 -ParameterFilter {$Uri -ceq 'https://github.com/SpecterOps/SharpHound/releases/download/v2.17.0/SharpHound_v2.17.0_windows_x86.zip.sha256'}
    }
    It 'rejects a release response whose tag differs from the pinned tag' {
      $release.tag_name='v2.17.1'
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*different release tag*'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
    It 'rejects malformed, missing, duplicate or wrong-file checksum records' {
      Mock Invoke-WebRequest { [pscustomobject]@{Content='not a digest'} }
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*valid SHA-256 record*'
      Mock Invoke-WebRequest { [pscustomobject]@{Content=((('a'*64)+'  other.zip')+"`n"+('b'*64)+'  SharpHound_v2.17.0_windows_x86.zip')} }
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*one SHA-256 record*'
      Mock Invoke-WebRequest { [pscustomobject]@{Content=(('a'*64)+'  other.zip')} }
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*names a different file*'
    }
    It 'refuses unpinned asset, repository or tag endpoints before network access' {
      $operation.AssetName='other.zip'
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exact repository, tag, asset and checksum asset*'
      $operation.AssetName='SharpHound_v2.17.0_windows_x86.zip';$operation.Repository='attacker/SharpHound'
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exact repository, tag, asset and checksum asset*'
      $operation.Repository='SpecterOps/SharpHound';$operation.PackageVersion='2.17.1'
      {Resolve-RidePackageArtifact -Operation $operation} | Should -Throw '*exact repository, tag, asset and checksum asset*'
      Should -Invoke Get-RideGitHubReleaseMetadata -Exactly 0
    }
  }
  It 'accepts a portable package pinned to an exact GitHub release and checksum sidecar' {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $operation=$catalog.Operations|Where-Object Id -eq 'package.sysinternals-suite'|Select-Object -First 1
    $operation.DownloadProvider='GitHubReleaseApi'
    $operation.Repository='SpecterOps/SharpHound'
    $operation.ReleaseTag='v2.17.0'
    $operation.PackageVersion='2.17.0'
    $operation.DownloadUri='https://api.github.com/repos/SpecterOps/SharpHound/releases/tags/v2.17.0'
    $operation.AssetName='SharpHound_v2.17.0_windows_x86.zip'
    $operation.ChecksumAssetName='SharpHound_v2.17.0_windows_x86.zip.sha256'
    $operation.AssetPattern='^SharpHound_v2\.17\.0_windows_x86\.zip$'
    $operation.Architecture='x86'
    $operation.ProductUri='https://github.com/SpecterOps/SharpHound'
    (Invoke-RideTestCatalogValidation -Catalog $catalog) | Should -BeNullOrEmpty
  }
  It 'rejects GitHub tag and sidecar metadata that drift from the pinned release' {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $operation=$catalog.Operations|Where-Object Id -eq 'package.sysinternals-suite'|Select-Object -First 1
    $operation.DownloadProvider='GitHubReleaseApi';$operation.Repository='SpecterOps/SharpHound';$operation.ReleaseTag='v2.17.0';$operation.PackageVersion='2.17.0'
    $operation.DownloadUri='https://api.github.com/repos/SpecterOps/SharpHound/releases/tags/v2.17.0'
    $operation.AssetName='SharpHound_v2.17.0_windows_x86.zip';$operation.ChecksumAssetName='SharpHound_v2.17.0_windows_x86.zip.sha256'
    $operation.AssetPattern='^SharpHound_v2\.17\.0_windows_x86\.zip$';$operation.Architecture='x86';$operation.ProductUri='https://github.com/SpecterOps/SharpHound'
    $operation.ChecksumAssetName='other.zip.sha256'
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'Pinned GitHub release package requires'
    $operation.ChecksumAssetName='SharpHound_v2.17.0_windows_x86.zip.sha256'
    $operation.DownloadUri+='?token=not-allowed'
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'without credentials, non-default ports, query or fragment'
  }
}

Describe 'Current-user Mozilla edition safety' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $operation=@{Id='package.thunderbird';Kind='Package';Scope='User';InstallerType='Exe';SelectedVariant='installed';DisplayNamePattern='^Mozilla Thunderbird \(x64 en-GB\)$';ConflictingDisplayNamePattern='^Mozilla Thunderbird(?: |$)';InstallDirectory=$TestDrive;MozillaChannel='release'}
      Mock Get-ItemProperty { @() }
    }
    It 'refuses machine registrations even when architecture and language match' {
      Mock Get-ItemProperty { [pscustomobject]@{DisplayName='Mozilla Thunderbird (x64 en-GB)';InstallLocation=$TestDrive} } -ParameterFilter {$Path -like 'HKLM:*'}
      {Get-RideInstalledPackage $operation} | Should -Throw '*Conflicting existing edition*'
    }
    It 'rejects direct elevated handler calls before acquisition or profile movement' {
      $operation.RequiresUnelevatedUser=$true
      Mock Test-RidePackageAdministrator {$true}
      Mock Save-RidePackageArtifact {throw 'Must not download.'}
      Mock Invoke-RidePreservingPackageOperation {throw 'Must not move profile data.'}
      {Install-RidePackage -Operation $operation -CacheDirectory $TestDrive} | Should -Throw '*non-elevated*'
      {Uninstall-RidePackage -Operation $operation} | Should -Throw '*non-elevated*'
      Should -Invoke Save-RidePackageArtifact -Exactly 0
      Should -Invoke Invoke-RidePreservingPackageOperation -Exactly 0
    }
    It 'refuses a different language or architecture in user scope' {
      Mock Get-ItemProperty { [pscustomobject]@{DisplayName='Mozilla Thunderbird (x86 en-US)';InstallLocation=$TestDrive} } -ParameterFilter {$Path -like 'HKCU:*'}
      {Get-RideInstalledPackage $operation} | Should -Throw '*Conflicting existing edition*'
    }
    It 'refuses an existing user distribution at a different destination' {
      Mock Get-ItemProperty { [pscustomobject]@{DisplayName='Mozilla Thunderbird (x64 en-GB)';InstallLocation='C:\Other'} } -ParameterFilter {$Path -like 'HKCU:*'}
      {Get-RideInstalledPackage $operation} | Should -Throw '*Conflicting existing edition*'
    }
    It 'refuses ESR instead of adopting it as the requested Release edition' {
      Mock Get-ItemProperty { [pscustomobject]@{DisplayName='Mozilla Thunderbird (x64 en-GB)';InstallLocation=$TestDrive} } -ParameterFilter {$Path -like 'HKCU:*'}
      $directory=Join-Path $TestDrive 'defaults/pref'
      $null=New-Item -ItemType Directory -Path $directory -Force
      [IO.File]::WriteAllText((Join-Path $directory 'channel-prefs.js'),'pref("app.update.channel", "esr");')
      {Get-RideInstalledPackage $operation} | Should -Throw '*Mozilla update channel*'
    }
    It 'accepts exactly the declared current-user Release registration' {
      Mock Get-ItemProperty { [pscustomobject]@{DisplayName='Mozilla Thunderbird (x64 en-GB)';InstallLocation=$TestDrive;DisplayVersion='157.0.1'} } -ParameterFilter {$Path -like 'HKCU:*'}
      $directory=Join-Path $TestDrive 'defaults/pref'
      $null=New-Item -ItemType Directory -Path $directory -Force
      [IO.File]::WriteAllText((Join-Path $directory 'channel-prefs.js'),'pref("app.update.channel", "release");')
      (Get-RideInstalledPackage $operation).Present | Should -BeTrue
    }
  }
}

Describe 'Current-user MSI product registration without ARP' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $operation=@{
        Id='package.artcraft-launcher';Kind='Package';PackageId='artcraft-launcher';Name='ArtCraft Launcher'
        Scope='User';InstallerType='Msi';SelectedVariant='installed';RequiresAdmin=$false
        DisplayNamePattern='^ArtCraft Launcher$';UninstallerArguments='/qn /norestart'
        MsiUpgradeCode='1AC08DBF-D4CF-4BA4-A81E-CAA5C1004974';MsiProductName='ArtCraft Launcher'
        MsiInstallDirectoryRegistryKey='HKCU:\Software\Learning Machines LLC\ArtCraft Launcher'
        MsiInstallDirectory='ArtCraft Launcher';MsiExecutable='artcraft-launcher.exe'
      }
      $expectedDirectory=[IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs/ArtCraft Launcher')).TrimEnd('\')
      Mock Get-ItemProperty { @() } -ParameterFilter { $Path -like 'HKCU:*' }
      Mock Get-ItemProperty { [pscustomobject]@{InstallDir=$expectedDirectory} } -ParameterFilter { $LiteralPath -eq $operation.MsiInstallDirectoryRegistryKey }
      Mock Get-RideMsiRelatedProduct { [pscustomobject]@{ProductCode='{1C5DA9B1-600A-49ED-A54F-6CA3958705C2}';DisplayName='ArtCraft Launcher';DisplayVersion='0.2.1';AssignmentType='0'} }
      Mock Test-Path { $true } -ParameterFilter { $LiteralPath -eq (Join-Path $expectedDirectory $operation.MsiExecutable) -and $PathType -eq 'Leaf' }
    }

    It 'detects the exact per-user MSI from Windows Installer registration, marker and executable' {
      $installed=Get-RideInstalledPackage -Operation $operation
      $installed.Present | Should -BeTrue
      $installed.DisplayName | Should -BeExactly 'ArtCraft Launcher'
      $installed.DisplayVersion | Should -BeExactly '0.2.1'
      $installed.InstallLocation | Should -BeExactly $expectedDirectory
      $installed.UninstallString | Should -BeExactly '"msiexec.exe" /x {1C5DA9B1-600A-49ED-A54F-6CA3958705C2}'
      Should -Invoke Get-RideMsiRelatedProduct -Exactly 1 -ParameterFilter { $UpgradeCode -eq $operation.MsiUpgradeCode -and $ProductName -eq $operation.MsiProductName }
    }

    It 'does not claim an advertised or otherwise unregistered product from a marker and executable alone' {
      Mock Get-RideMsiRelatedProduct { $null }
      (Get-RideInstalledPackage -Operation $operation).Present | Should -BeFalse
    }

    It 'does not claim a per-user MSI when its marker points outside the declared Programs directory' {
      Mock Get-ItemProperty { [pscustomobject]@{InstallDir=(Join-Path $expectedDirectory '..\Other')} } -ParameterFilter { $LiteralPath -eq $operation.MsiInstallDirectoryRegistryKey }
      (Get-RideInstalledPackage -Operation $operation).Present | Should -BeFalse
    }

    It 'uses the detected MSI product code for quiet uninstall and verifies absence' {
      $script:uninstallLookups=0
      Mock Get-RideInstalledPackage {
        $script:uninstallLookups++
        if($script:uninstallLookups -eq 1){return [pscustomobject]@{Present=$true;DisplayName='ArtCraft Launcher';UninstallString='"msiexec.exe" /x {1C5DA9B1-600A-49ED-A54F-6CA3958705C2}';QuietUninstallString=$null}}
        [pscustomobject]@{Present=$false}
      }
      Mock Invoke-RidePreservingPackageOperation { [pscustomobject]@{ExitCode=0} }
      Uninstall-RidePackage -Operation $operation
      Should -Invoke Invoke-RidePreservingPackageOperation -Exactly 1 -ParameterFilter { $FilePath -eq 'msiexec.exe' -and $ArgumentList -eq '/x {1C5DA9B1-600A-49ED-A54F-6CA3958705C2} /qn /norestart' }
      Should -Invoke Get-RideInstalledPackage -Exactly 2
    }
  }

  It 'rejects unsafe MSI install-directory metadata' {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $operation=$catalog.Operations | Where-Object Id -eq 'package.artcraft-launcher'
    $operation.MsiInstallDirectory='../outside'
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'MSI product-code detection requires'
  }

  It 'records ArtCraft Launcher Windows 11 lifecycle acceptance and keeps Server support undeclared' {
    $root=Split-Path -Parent $PSScriptRoot
    $operation=@((Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')).Operations | Where-Object Id -ceq 'package.artcraft-launcher')[0]
    @($operation.SupportedTargets) | Should -Be @('Windows 11')
    $operation.PendingAcceptance | Should -BeFalse
    $operation.CandidateTargets | Should -BeNullOrEmpty
  }
}

Describe 'Package variant metadata and completion' {
  It 'completes the selected product variants with case-insensitive prefix filtering' {
    $runner=Join-Path (Split-Path -Parent $PSScriptRoot) 'ride.ps1'
    $line="& '$runner' install package.sharex -Variant P"
    $matches=@((TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText)
    $matches | Should -Contain 'portable'
    $matches | Should -Not -Contain 'installed'
    @($matches | Where-Object {$_ -eq 'portable'}).Count | Should -Be 1
  }
  It 'does not suggest variants for a setting' {
    $runner=Join-Path (Split-Path -Parent $PSScriptRoot) 'ride.ps1'
    $line="& '$runner' show windows.inking-typing-data -Variant P"
    (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Not -Contain 'portable'
  }
  It 'completes variants for exported package commands without invoking handlers' {
    foreach($command in @('Get-RideSingleOperationPlan','Save-RidePackage','Show-RideOperation')) {
      $line="$command -Id package.sharex -Variant P"
      (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain 'portable'
    }
  }
  It 'rejects a missing variant default and identity overrides in catalog validation' {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $package=$catalog.Operations | Where-Object Id -eq 'package.sharex'
    $package.DefaultVariant='missing'
    $errors=@(Invoke-RideTestCatalogValidation -Catalog $catalog)
    ($errors -join ' ') | Should -Match 'variants/default'
    $package.DefaultVariant='installed';$package.Variants.portable.Id='package.changed'
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'override identity'
  }
  It 'rejects unsupported uninstaller formats' {
    $catalog=Invoke-RideTestCatalogImport (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $package=$catalog.Operations | Where-Object Id -eq 'package.firefox'
    $package.UninstallerType='Script'
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'Unsupported uninstaller type'
  }
  It 'accepts neutral portable archives without accepting unspecified installer architectures' {
    $catalog=Invoke-RideTestCatalogImport (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $portable=$catalog.Operations | Where-Object Id -eq 'package.dejsonlz4'
    $portable.Architecture='neutral'
    @(Invoke-RideTestCatalogValidation -Catalog $catalog).Count | Should -Be 0
    $installer=$catalog.Operations | Where-Object Id -eq 'package.vscode'
    $installer.Architecture='neutral'
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'Invalid package architecture: package.vscode'
  }
  It 'accepts a NuGet package as a ZIP-format portable asset and enforces its format' {
    $catalog=Invoke-RideTestCatalogImport (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $package=$catalog.Operations | Where-Object Id -eq 'package.microsoft-powershell-threadjob'
    $package.AssetName | Should -BeExactly 'Microsoft.PowerShell.ThreadJob.2.2.0.nupkg'
    $package.PortableFormat | Should -BeExactly 'Zip'
    @(Invoke-RideTestCatalogValidation -Catalog $catalog).Count | Should -Be 0
    $package.AssetName='Microsoft.PowerShell.ThreadJob.2.2.0.exe'
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'Direct HTTPS packages require.*package.microsoft-powershell-threadjob'
  }
  It 'allows pending package candidates only without a support declaration' {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $package=$catalog.Operations | Where-Object Id -eq 'package.vscode'
    $package.PendingAcceptance=$true;$package.SupportedTargets=@();$package.CandidateTargets=@('Windows 11')
    @(Invoke-RideTestCatalogValidation -Catalog $catalog).Count | Should -Be 0
    $package.SupportedTargets=@('Windows 11')
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'Pending acceptance requires'
    $package.SupportedTargets=@();$package.CandidateTargets=@('Windows 10')
    (@(Invoke-RideTestCatalogValidation -Catalog $catalog) -join ' ') | Should -Match 'explicit candidate targets'
  }
  It 'pins Microsoft OpenJDK LTS MSIs side-by-side without changing shared Java defaults' {
    $catalog=Invoke-RideTestCatalogImport (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $packages=@($catalog.Operations|Where-Object {$_.DownloadProvider -eq 'MicrosoftOpenJdk'}|Sort-Object PackageVersion -Descending)
    $packages.Count | Should -Be 4
    $packages.PackageVersion | Should -Contain '25.0.4.1'
    $packages.PackageVersion | Should -Contain '21.0.12.1'
    $packages.PackageVersion | Should -Contain '17.0.20.1'
    $packages.PackageVersion | Should -Contain '11.0.32.1'
    foreach($package in $packages){
      $package.PendingAcceptance | Should -BeFalse
      $package.SupportedTargets | Should -Contain 'Windows Server 2025'
      $package.CandidateTargets | Should -Not -Contain 'Windows Server 2025'
      $major=[regex]::Match($package.PackageVersion,'^\d+').Value
      $package.CandidateTargets | Should -Contain 'Windows 11'
      $package.TargetDefaults.'Windows Server 2025'.DefaultValue | Should -BeExactly 'Absent'
      $package.TargetDefaults.'Windows Server 2025'.EffectiveDefault | Should -Match 'clean Windows Server 2025 Standard Evaluation test image'
      $package.MigrationBatch | Should -BeExactly 'OpenJDKCompatibility'
      [regex]::IsMatch('Microsoft Build of OpenJDK with Hotspot '+$major+'.0.0.0 (x64)',$package.DisplayNamePattern) | Should -BeTrue
      [regex]::IsMatch('Microsoft Build of OpenJDK  '+$major+'.0.0.0+1 (x64)',$package.DisplayNamePattern) | Should -BeTrue
      [regex]::IsMatch('Microsoft Build of OpenJDK '+$major+' (x64)',$package.DisplayNamePattern) | Should -BeTrue
      $package.InstallDirectory | Should -BeExactly "C:\Program Files\Microsoft\RIDE\OpenJDK\jdk-$major"
      $package.InstallerArguments | Should -Match '^ALLUSERS=1\s'
      $package.InstallerArguments | Should -Match 'ADDLOCAL=FeatureMain'
      $package.InstallerArguments | Should -Not -Match 'FeatureEnvironment|FeatureJarFileRunWith|FeatureJavaHome|INSTALLLEVEL'
      $package.InstallerArguments | Should -Match "jdk-$([regex]::Match($package.PackageVersion,'^\d+').Value)"
    }
    @(Invoke-RideTestCatalogValidation -Catalog $catalog).Count | Should -Be 0
  }

  It 'selects all four OpenJDK package IDs in the Server 2025 acceptance batch' {
    $runnerPath=Join-Path (Split-Path -Parent $PSScriptRoot) 'tests/integration/Invoke-RideApplicationBatch.ps1'
    $runner=Get-Content $runnerPath -Raw
    @(& $runnerPath -Version) | Should -Be @('0.19.4')
    $runner | Should -Match 'microsoft-openjdk-25.*microsoft-openjdk-21.*microsoft-openjdk-17.*microsoft-openjdk-11'
    $runner | Should -Match '\$actualIds=@\(\$scenarios \| ForEach-Object \{\$_.Selected.PackageId\} \| Sort-Object\)'
    $runner | Should -Match '\$package\.MigrationBatch -eq ''OpenJDKCompatibility'''
    $runner | Should -Match '\$catalogVariant\.MigrationBatch -eq ''OpenJDKCompatibility'''
    $runner | Should -Match '\$Batch -in @\(6,7,8,9,10,11,12\)'
    $runner | Should -Match 'OpenJDK uninstall left its managed runtime or compiler executable behind'
  }
  It 'pins Project Maker to its Windows 11 ApplicationsBatch10 lifecycle route' {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $package=$catalog.Operations | Where-Object Id -ceq 'package.mitec-project-maker'
    $package.PackageVersion | Should -BeExactly '1.9.0'
    $package.ExpectedSha256 | Should -BeExactly 'ee2a74e34c0c0ad97c58163b2f4f114876252317cb52fffbf9fa11e2afe13419'
    $package.MigrationBatch | Should -BeExactly 'ApplicationsBatch10'
    $package.CandidateTargets | Should -Contain 'Windows 11'
    $package.SupportedTargets | Should -Be @()
    $package.PendingAcceptance | Should -BeTrue
    $runnerPath=Join-Path $root 'tests/integration/Invoke-RideApplicationBatch.ps1'
    $runner=Get-Content $runnerPath -Raw
    @(& $runnerPath -Version) | Should -Be @('0.19.4')
    $runner | Should -Match "ApplicationsBatch10 must select exactly MiTeC Project Maker 1\.9\.0"
    $runner | Should -Match 'ApplicationsBatch10 is limited to Windows 11'
  }
}

Describe 'NTCore Driver List and Rebel.NET Windows 11 staging support' {
  BeforeAll {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $script:DriverList=$catalog.Operations|Where-Object Id -ceq 'package.ntcore-driver-list'
    $script:RebelNet=$catalog.Operations|Where-Object Id -ceq 'package.ntcore-rebelnet'
    $script:Acceptance=Get-Content (Join-Path $root 'docs/archive/evidence/ntcore-additional-win11-lifecycle-acceptance-2026-10-25-0402.json') -Raw|ConvertFrom-Json
  }
  It 'pins the verified Driver List release and exposes only verified x64 and x86 members' {
    $DriverList.PackageVersion|Should -BeExactly '1.0.2.1'
    $DriverList.ExpectedSha256|Should -BeExactly 'dbc5736808cf7203cf289a269cc27cbcf90a8c69e03eed60ae361ad29da08d28'
    $DriverList.RequiredFiles|Should -Be @('DriverList_x64.exe')
    $DriverList.Variants['portable-x86'].RequiredFiles|Should -Be @('DriverList_x86.exe')
    $DriverList.PortableMembers -join ','|Should -Not -Match 'IA64'
    $DriverList.PendingAcceptance|Should -BeFalse
    $DriverList.SupportedTargets|Should -Contain 'Windows 11'
    $DriverList.CandidateTargets|Should -BeNullOrEmpty
    $cases=@($Acceptance.cases|Where-Object Id -CEQ $DriverList.Id)
    $cases.Count|Should -Be 2
    @($cases|Where-Object {$_.Status -cne 'Passed' -or -not $_.LifecycleRecovery -or $_.ToolExecuted}).Count|Should -Be 0
  }
  It 'pins Rebel.NET and states the synthetic-assembly acceptance boundary' {
    $RebelNet.PackageVersion|Should -BeExactly '1.6.0.1'
    $RebelNet.ExpectedSha256|Should -BeExactly '7bd01e9cb15426642c74f8f3cab45cf7005f7525ab7cb8abc5a32973f383af32'
    $RebelNet.RequiredFiles|Should -Contain 'RebelDotNET.exe'
    $RebelNet.RequiredFiles|Should -Contain 'RebelDotNET.h'
    $RebelNet.AcceptanceNotes|Should -Match 'owned synthetic \.NET assembly'
    $RebelNet.PendingAcceptance|Should -BeFalse
    $RebelNet.SupportedTargets|Should -Contain 'Windows 11'
    $RebelNet.CandidateTargets|Should -BeNullOrEmpty
    $case=@($Acceptance.cases|Where-Object Id -CEQ $RebelNet.Id)[0]
    $case.Status|Should -BeExactly 'Passed'
    $case.LifecycleRecovery|Should -BeTrue
    $case.ToolExecuted|Should -BeFalse
  }
  It 'keeps feature-use and activation pending outside package staging support' {
    $Acceptance.status|Should -BeExactly 'Passed'
    $Acceptance.payloadExecution|Should -BeFalse
    $Acceptance.toolExecuted|Should -BeFalse
    $Acceptance.functionalAcceptance|Should -BeExactly 'Pending'
    $Acceptance.activationAcceptance|Should -BeExactly 'Pending'
    $Acceptance.cleanup|Should -BeExactly 'ResetAndOff'
    $Acceptance.controllerErrors.Count|Should -Be 0
  }
  It 'keeps license review data outside the shared catalog while preserving package planning' {
    foreach($operation in @($DriverList,$RebelNet)){
      $operation.LicenseReviewStatus|Should -BeNullOrEmpty
      $operation.DistributionNotes|Should -BeNullOrEmpty
      $operation.LicenseReviewedAt|Should -BeNullOrEmpty
      $operation.LicenseUri|Should -Match '^https://ntcore\.com/'
    }
  }
}

Describe 'Application timeout diagnostics' {
  It 'retains both machine and limited-user stage records without an open log handle' {
    $root = Split-Path -Parent $PSScriptRoot
    $ast = [Management.Automation.Language.Parser]::ParseFile(
      (Join-Path $root 'tests/integration/Invoke-RideApplicationBatch.ps1'), [ref]$null, [ref]$null)
    $definition = $ast.Find({param($node)
      $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-RideApplicationProgress'
    }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
    $prior = $env:RIDE_TEST_EVIDENCE_PATH
    try {
      $env:RIDE_TEST_EVIDENCE_PATH = $TestDrive
      foreach ($limited in @($false, $true)) {
        $UnelevatedChild = $limited
        Write-RideApplicationProgress -PackageId 'package.mitec-project-maker' -Stage 'Install package'
        Write-RideApplicationProgress -PackageId 'package.mitec-project-maker' -Stage 'Run vendor uninstaller'
        $name = if ($limited) { 'application-user-progress.jsonl' } else { 'application-progress.jsonl' }
        $path = Join-Path $TestDrive $name
        $records = @(Get-Content -LiteralPath $path | ForEach-Object { $_ | ConvertFrom-Json })
        $records.Stage | Should -Be @('Install package','Run vendor uninstaller')
        $records[0].PackageId | Should -Be 'package.mitec-project-maker'
        $stream = [IO.File]::Open($path, 'Open', 'Read', 'None')
        $stream.Dispose()
      }
      $env:RIDE_TEST_EVIDENCE_PATH = $null
      { Write-RideApplicationProgress -PackageId 'package.mitec-project-maker' -Stage 'No evidence directory' } | Should -Not -Throw
    } finally { $env:RIDE_TEST_EVIDENCE_PATH = $prior }
  }

  It 'adds the Project Maker log while preserving all existing silent installer switches' {
    $root = Split-Path -Parent $PSScriptRoot
    $ast = [Management.Automation.Language.Parser]::ParseFile(
      (Join-Path $root 'tests/integration/Invoke-RideApplicationBatch.ps1'), [ref]$null, [ref]$null)
    $branch = $ast.Find({param($node)
      $node -is [Management.Automation.Language.IfStatementAst] -and
      $node.Clauses[0].Item1.Extent.Text -like "*scenario.Id -eq 'package.mitec-project-maker'*"
    }, $true)
    $branch | Should -Not -BeNullOrEmpty
    $scenario = @{ Id = 'package.mitec-project-maker' }
    $operation = @{ InstallerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-' }
    $prior = $env:RIDE_TEST_EVIDENCE_PATH
    try {
      $env:RIDE_TEST_EVIDENCE_PATH = $TestDrive
      . ([scriptblock]::Create($branch.Extent.Text))
      $operation.InstallerArguments | Should -BeExactly ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /LOG="' + (Join-Path $TestDrive 'project-maker-install.log') + '"')
    } finally { $env:RIDE_TEST_EVIDENCE_PATH = $prior }
  }
}

Describe 'Explorer Suite guarded candidate acceptance' {
  It 'executes vendor removal, repeat removal and presence recovery for Batch 12' {
    $root = Split-Path -Parent $PSScriptRoot
    $ast = [Management.Automation.Language.Parser]::ParseFile(
      (Join-Path $root 'tests/integration/Invoke-RideApplicationBatch.ps1'), [ref]$null, [ref]$null)
    $branch = @($ast.FindAll({ param($node)
      $node -is [Management.Automation.Language.IfStatementAst] -and
      $node.Clauses[0].Item1.Extent.Text -like '$userDataFixtures.Count -or $profileFixture*'
    }, $true))
    $branch.Count | Should -Be 1
    $Batch = 12
    $userDataFixtures = @()
    $profileFixture = $null
    $scenario = @{ Id = 'package.ntcore-explorer-suite'; Variant = 'installed' }
    $scenarioResult = @{ Checks = @() }
    $plan = @(@{ Operation = @{ Id = $scenario.Id } })
    $script:explorerPlanCalls = 0
    $script:explorerRecoveryCalls = 0
    function Get-RideSingleOperationPlan { param($Id, $Action, $Variant)
      $Action | Should -Be 'Remove'
      @{ Operation = @{ Id = $Id } }
    }
    function Invoke-RidePlan { param($Plan, [switch]$WhatIf, [switch]$Confirm)
      $script:explorerPlanCalls++
      if ($WhatIf) { return }
      if ($script:explorerPlanCalls -eq 3) { return 'No changes were needed; no state record was created.' }
      'synthetic-removal-run'
    }
    function Get-SavedRunId { param($Output) $Output | Should -Be 'synthetic-removal-run'; $Output }
    function Test-RideDesiredState { param($Operation, $State) $true }
    function Get-RideCurrentState { param($Operation) @{ Present = $false; DisplayVersion = 'observed-version' } }
    function Write-RideApplicationProgress { param($PackageId, $Stage) }
    function Restore-RideRun { param($RunId, [switch]$Confirm)
      $RunId | Should -Be 'synthetic-removal-run'
      $script:explorerRecoveryCalls++
    }
    . ([scriptblock]::Create($branch[0].Extent.Text))
    $script:explorerPlanCalls | Should -Be 3
    $script:explorerRecoveryCalls | Should -Be 1
    $scenarioResult.Checks | Should -Be @('RemovalPreview','RIDERemoval','RepeatRemoval','SavedRemovalRecovery')
    $scenarioResult.RemovalRecoveryVersion | Should -Be 'observed-version'
  }

  It 'admits only the declared Explorer Suite target for Batch <Batch> on <Target>' -ForEach @(
    @{ Batch = 12; Target = 'Windows 11'; Expected = $true }
    @{ Batch = 11; Target = 'Windows 11'; Expected = $false }
    @{ Batch = 12; Target = 'Windows Server 2025'; Expected = $false }
  ) {
    $root = Split-Path -Parent $PSScriptRoot
    $catalogPath = Join-Path $root 'catalog/operations.psd1'
    $testCatalog = Invoke-RideTestCatalogImport $catalogPath
    $beforeHash = (Get-FileHash -LiteralPath $catalogPath).Hash
    $runnerPath = Join-Path $root 'tests/integration/Invoke-RideApplicationBatch.ps1'
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($runnerPath, [ref]$null, [ref]$parseErrors)
    $parseErrors | Should -BeNullOrEmpty
    # Execute the actual in-memory catalog preparation, without running the
    # VM entry point, querying Windows state or invoking an installer.
    $preparation = @($ast.FindAll({ param($node)
      $node -is [Management.Automation.Language.ForEachStatementAst] -and
      $node.Condition.Extent.Text -match '^\$testCatalog\.Operations'
    }, $true))
    $preparation.Count | Should -Be 1
    . ([scriptblock]::Create($preparation[0].Extent.Text))
    $candidate = $testCatalog.Operations | Where-Object Id -eq 'package.ntcore-explorer-suite'
    ($candidate.SupportedTargets -contains $Target) | Should -Be $Expected
    $candidate.PendingAcceptance | Should -Be (-not $Expected)
    $unrelated = $testCatalog.Operations | Where-Object Id -eq 'package.ntcore-virtualreg-manager'
    $unrelated | Should -Not -BeNullOrEmpty
    $unrelated.PendingAcceptance | Should -BeTrue
    $unchanged = (Invoke-RideTestCatalogImport $catalogPath).Operations | Where-Object Id -eq $candidate.Id
    $unchanged.PendingAcceptance | Should -BeTrue
    $unchanged.SupportedTargets | Should -BeNullOrEmpty
    (Get-FileHash -LiteralPath $catalogPath).Hash | Should -BeExactly $beforeHash
  }
}

Describe 'HashCheck Shell Extension Windows 11 acceptance' {
  It 'pins the accepted installer and limits support to the tested Windows 11 workflow' {
    $root=Split-Path -Parent $PSScriptRoot
    $catalog=Invoke-RideTestCatalogImport (Join-Path $root 'catalog/operations.psd1')
    $package=@($catalog.Operations|Where-Object Id -ceq 'package.hashcheck-shell-extension')[0]
    $package.PackageVersion|Should -BeExactly '2.6.3'
    $package.DownloadUri|Should -BeExactly 'https://github.com/idrassi/HashCheck/releases/download/v2.6.3/HashCheckSetup-v2.6.3.0.exe'
    $package.AssetName|Should -BeExactly 'HashCheckSetup-v2.6.3.0.exe'
    $package.ExpectedSha256|Should -BeExactly 'cd890774839177b234a1165fd459ddeb830274ef7d81b289ddb70d43ae5983fa'
    $package.InstallerType|Should -BeExactly 'Exe'
    $package.InstallerArguments|Should -BeExactly '/S'
    $package.Scope|Should -BeExactly 'Machine'
    $package.RequiresAdmin|Should -BeTrue
    $package.CandidateTargets|Should -BeNullOrEmpty
    $package.SupportedTargets|Should -Be @('Windows 11')
    $package.PendingAcceptance|Should -BeFalse
    $package.LicenseReviewStatus|Should -BeNullOrEmpty
    $runnerPath=Join-Path $root 'tests/integration/Invoke-RideApplicationBatch.ps1'
    $runner=Get-Content -LiteralPath $runnerPath -Raw
    @(& $runnerPath -Version)|Should -Be @('0.19.4')
    $runner|Should -Match 'ApplicationsBatch11 must select exactly HashCheck Shell Extension 2\.6\.3'
  }
}
