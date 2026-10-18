<#
.SYNOPSIS
  Verify exact pinned ZIP selection and preservation before portable deployment.
.DESCRIPTION
  Uses inert ZIP members in TestDrive and catalog clones. No network, installer,
  acquired program, machine setting or system integration is invoked.
.EXAMPLE
  Invoke-Pester .\tests\PortableSelection.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture. Native product acceptance remains separate.
#>
BeforeAll {
  $repositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE-PortablePackages.psm1') -Force
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $repositoryRoot 'modules/RIDE.CatalogData.psm1') -Force
  $script:SelectionCatalogPath=Join-Path $repositoryRoot 'catalog/operations.psd1'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  Add-Type -AssemblyName System.IO.Compression
  function New-SelectionZip($Path,$Names) {
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try { foreach($name in $Names){$writer=[IO.StreamWriter]::new($zip.CreateEntry($name).Open());try{$writer.Write('inert '+$name)}finally{$writer.Dispose()}} }finally{$zip.Dispose()}
    [pscustomobject]@{Path=$Path;Version='1';Sha256=(Get-FileHash -LiteralPath $Path).Hash.ToLowerInvariant()}
  }
}
Describe 'Exact portable ZIP selection' {
  BeforeEach {
    $script:Root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $Root
    $script:Artifact=New-SelectionZip (Join-Path $Root 'source.zip') @('App/app.exe','App/NOTICE.txt','SDK/setup.msi','custom.cfg')
    $script:Operation=@{Id='package.fixture';PackageId='fixture';Name='Fixture';InstallerType='Portable';SelectedVariant='portable';ResolvedToolsDirectory=$Root;InstallDirectory=(Join-Path $Root 'fixture');PortableFormat='Zip';RequiredFiles=@('App/app.exe','App/NOTICE.txt');PortableMembers=@('App/app.exe','App/NOTICE.txt');ExpectedSha256=$Artifact.Sha256}
  }
  It 'stages only selected files, preserves an omitted user file, and restores exact owned bytes' {
    $null=New-Item -ItemType Directory -Path $Operation.InstallDirectory
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'custom.cfg'),'local configuration')
    Install-RidePortablePayload $Operation $Artifact -Offline
    Install-RidePortablePayload $Operation $Artifact -Offline
    $state=Get-RidePortableState $Operation
    $state.Healthy|Should -BeTrue;$state.Files.Count|Should -Be 2
    Test-Path (Join-Path $Operation.InstallDirectory 'SDK')|Should -BeFalse
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $Root 'backup')
    Uninstall-RidePortablePayload $Operation
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy|Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'custom.cfg'))|Should -BeExactly 'local configuration'
  }
  It 'refuses a missing selected optional member before touching an existing deployment' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    $manifest=Get-Content (Join-Path $Operation.InstallDirectory '.ride-package.json') -Raw
    $Operation.PortableMembers+=@('missing.txt')
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw '*missing a selected file*'
    (Get-Content (Join-Path $Operation.InstallDirectory '.ride-package.json') -Raw)|Should -BeExactly $manifest
  }
  It 'rejects invalid selection <Case> before product writes' -ForEach @(
    @{Case='empty'},@{Case='scalar'},@{Case='duplicate'},@{Case='traversal'},@{Case='missing-required'},@{Case='wrong-pin'},@{Case='file-format'},@{Case='directory'},@{Case='reserved'}
  ) {
    switch($Case){
      empty {$Operation.PortableMembers=@()}
      scalar {$Operation.PortableMembers='App/app.exe'}
      duplicate {$Operation.PortableMembers+=@('APP/APP.EXE')}
      traversal {$Operation.PortableMembers+=@('../escape')}
      missing-required {$Operation.PortableMembers=@('App/app.exe')}
      wrong-pin {$Operation.ExpectedSha256=('0'*64)}
      file-format {$Operation.PortableFormat='File'}
      directory {$Operation.PortableMembers+=@('App/')}
      reserved {$Operation.PortableMembers+=@('.ride-package.json')}
    }
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw
    Test-Path -LiteralPath $Operation.InstallDirectory|Should -BeFalse
  }
  It 'still rejects unsafe unselected archive members' {
    $Artifact=New-SelectionZip (Join-Path $Root 'unsafe.zip') @('App/app.exe','App/NOTICE.txt','../escape')
    $Operation.ExpectedSha256=$Artifact.Sha256
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw '*Unsafe portable member*'
    Test-Path -LiteralPath $Operation.InstallDirectory|Should -BeFalse
  }
  It 'preserves modified managed bytes when selected membership changes' {
    Install-RidePortablePayload $Operation $Artifact -Offline
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'App/app.exe'),'user edit')
    $Operation.RequiredFiles=@('App/NOTICE.txt');$Operation.PortableMembers=@('App/NOTICE.txt')
    {Install-RidePortablePayload $Operation $Artifact -Offline}|Should -Throw '*modified managed*'
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'App/app.exe'))|Should -BeExactly 'user edit'
  }
}
Describe 'Portable selection catalog contract' {
  It 'rejects malformed selection <Case> without operational imports' -ForEach @(
    @{Case='empty'},@{Case='scalar'},@{Case='duplicate'},@{Case='traversal'},@{Case='required'},@{Case='pin'},@{Case='format'},@{Case='device'}
  ) {
    $catalog=Import-RideCatalogData $SelectionCatalogPath
    $op=$catalog.Operations|Where-Object Id -eq 'package.sysinternals-suite'
    $op.PortableMembers=@($op.RequiredFiles)
    switch($Case){
      empty {$op.PortableMembers=@()}
      scalar {$op.PortableMembers=$op.RequiredFiles[0]}
      duplicate {$op.PortableMembers+=@($op.RequiredFiles[0].ToUpperInvariant())}
      traversal {$op.PortableMembers+=@('../escape')}
      required {$op.PortableMembers=@('unrelated.txt')}
      pin {$op.Remove('ExpectedSha256')}
      format {$op.PortableFormat='File'}
      device {$op.PortableMembers+=@('CON.txt')}
    }
    (@(Get-RideCatalogValidationErrors -Catalog $catalog) -join ' ')|Should -Match 'PortableMembers'
  }
}
