BeforeDiscovery {
  $root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.PackageSelection.psm1') -Force
}

Describe 'Raspberry Pi Imager package candidate' {
  BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
    Import-Module (Join-Path $root 'modules/RIDE.CatalogValidation.psm1') -Force
    Import-Module (Join-Path $root 'modules/RIDE.PackageSelection.psm1') -Force
    $script:catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
    $script:operation = $script:catalog.Operations | Where-Object Id -eq 'package.raspberry-pi-imager' | Select-Object -First 1
  }

  It 'pins the publisher Windows x64 release and declares its combined license notices' {
    $script:operation | Should -Not -BeNullOrEmpty
    $script:operation.PackageVersion | Should -BeExactly '2.0.12'
    $script:operation.Architecture | Should -BeExactly 'x64'
    $script:operation.DownloadUri | Should -BeExactly 'https://github.com/raspberrypi/rpi-imager/releases/download/v2.0.12/imager-v2.0.12.exe'
    $script:operation.ExpectedSha256 | Should -BeExactly '98bff90afe23339d0768915f6f68d35ac254740ec1eac2082ebeaa9ba41bc8e3'
    $script:operation.License | Should -Match 'Apache License 2.0'
    $script:operation.License | Should -Match 'third-party components'
    $script:operation.LicenseUri | Should -BeExactly 'https://github.com/raspberrypi/rpi-imager/blob/v2.0.12/license.txt'
    $script:operation.ProductUri | Should -BeExactly 'https://www.raspberrypi.com/software/'
    (Get-RideCatalogValidationErrors -Catalog $script:catalog) | Should -BeNullOrEmpty
  }

  It 'remains pending disposable install, repeat, uninstall, and checkpoint restoration acceptance' {
    $script:operation.PendingAcceptance | Should -BeTrue
    $script:operation.SupportedTargets | Should -BeNullOrEmpty
    $script:operation.CandidateTargets | Should -Be @('Windows 11')
    $script:operation.RequiresAdmin | Should -BeTrue
    $script:operation.Rollback | Should -BeExactly 'Compensating'
    $script:operation.UninstallerArguments | Should -BeExactly '/VERYSILENT /SUPPRESSMSGBOXES'
    $script:operation.Description | Should -Match 'WinUSB driver'
    $script:operation.Description | Should -Match 'cached OS image'
    $script:operation.Description | Should -Match 'image-customisation credentials'
    $script:operation.Description | Should -Match 'restore its checkpoint'
    $script:operation.Description | Should -Match 'without launching the image writer'
    $selection = Resolve-RidePackageSelection -Operation $script:operation -IgnorePreferences -MetadataOnly
    $selection.PendingAcceptance | Should -BeTrue
    $selection.MigrationBatch | Should -BeExactly 'RequestedV3Additions'
  }
}
