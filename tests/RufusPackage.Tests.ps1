<#
.SYNOPSIS
  Check the pending Rufus package's owned-file and configuration boundaries.
.DESCRIPTION
  Uses the real catalog operation with inert temporary bytes. No Rufus execution,
  download, USB/media access, registration or live machine installation occurs.
.EXAMPLE
  Invoke-Pester .\tests\RufusPackage.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native package acceptance remains pending.
#>
BeforeAll {
  $root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE-PortablePackages.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  $script:RufusOperation=(Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')).Operations | Where-Object Id -eq package.rufus
}
Describe 'Rufus pending portable candidate' {
  BeforeEach {
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    $script:Operation=$RufusOperation.Clone()
    $Operation.SelectedVariant='portable';$Operation.ResolvedToolsDirectory=$CaseRoot
    $Operation.InstallDirectory=Join-Path $CaseRoot $Operation.PackageId
    $script:Payload=Join-Path $CaseRoot 'inert-payload.exe'
    [IO.File]::WriteAllText($Payload,'inert test bytes; never execute')
    $script:Artifact=[pscustomobject]@{Path=$Payload;Version=$Operation.PackageVersion;Sha256=(Get-FileHash -LiteralPath $Payload).Hash.ToLowerInvariant()}
  }
  It 'retains the filename portable-mode trigger and remains outside supported targets/profiles' {
    $Operation.PortableFileName | Should -Match 'p\.exe$'
    $Operation.PendingAcceptance | Should -BeTrue
    $Operation.SupportedTargets.Count | Should -Be 0
    $repo=Split-Path -Parent $PSScriptRoot
    foreach($profile in Get-ChildItem -LiteralPath (Join-Path $repo 'profiles') -Filter '*.psd1') {
      [IO.File]::ReadAllText($profile.FullName) | Should -Not -Match 'package\.rufus'
    }
  }
  It 'stages, repeats and removes only the executable while preserving user settings and logs' {
    $null=New-Item -ItemType Directory -Path $Operation.InstallDirectory
    $ini=Join-Path $Operation.InstallDirectory 'rufus.ini'
    $log=Join-Path $Operation.InstallDirectory 'rufus.log'
    [IO.File]::WriteAllText($ini,"[rufus]`r`nLocale=en-GB`r`n")
    [IO.File]::WriteAllText($log,'user log')
    Install-RidePortablePayload $Operation $Artifact
    Install-RidePortablePayload $Operation $Artifact
    $state=Get-RidePortableState $Operation
    $state.Healthy | Should -BeTrue
    @($state.Manifest.Files).Count | Should -Be 1
    $state.Manifest.Files[0].RelativePath | Should -Be rufusp.exe
    Uninstall-RidePortablePayload $Operation
    [IO.File]::ReadAllText($ini) | Should -Be "[rufus]`r`nLocale=en-GB`r`n"
    [IO.File]::ReadAllText($log) | Should -Be 'user log'
    (Get-RidePortableState $Operation).Present | Should -BeFalse
  }
  It 'restores retained owned bytes without reverting settings changed after capture' {
    Install-RidePortablePayload $Operation $Artifact
    $snapshot=Save-RidePortableSnapshot $Operation (Join-Path $CaseRoot 'backup')
    Uninstall-RidePortablePayload $Operation
    [IO.File]::WriteAllText((Join-Path $Operation.InstallDirectory 'rufus.ini'),'later operator settings')
    Restore-RidePortableSnapshot $Operation $snapshot
    (Get-RidePortableState $Operation).Healthy | Should -BeTrue
    [IO.File]::ReadAllText((Join-Path $Operation.InstallDirectory 'rufus.ini')) | Should -Be 'later operator settings'
  }
  It 'refuses adoption of an existing executable and preserves modified executable bytes' {
    $null=New-Item -ItemType Directory -Path $Operation.InstallDirectory
    $exe=Join-Path $Operation.InstallDirectory $Operation.PortableFileName
    [IO.File]::WriteAllText($exe,'user executable')
    {Install-RidePortablePayload $Operation $Artifact} | Should -Throw '*collision*'
    [IO.File]::ReadAllText($exe) | Should -Be 'user executable'
    Remove-Item -LiteralPath $exe
    Install-RidePortablePayload $Operation $Artifact
    [IO.File]::WriteAllText($exe,'changed after installation')
    {Install-RidePortablePayload $Operation $Artifact} | Should -Throw '*modified*'
    Uninstall-RidePortablePayload $Operation -WarningAction SilentlyContinue
    [IO.File]::ReadAllText($exe) | Should -Be 'changed after installation'
  }
}
