BeforeDiscovery {
  $root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.PackageSelection.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE-Packages.psm1') -Force
}

BeforeAll {
  $root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE-Packages.psm1') -Force
}

Describe 'Gpg4win selected package scope' {
  It 'declares only the accepted current-user command-line and Kleopatra selection' {
    $root = Split-Path -Parent $PSScriptRoot
    $catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
    $operation = $catalog.Operations | Where-Object Id -eq 'package.gpg4win' | Select-Object -First 1

    $operation | Should -Not -BeNullOrEmpty
    $operation.Scope | Should -BeExactly 'User'
    $operation.RequiresUnelevatedUser | Should -BeTrue
    $operation.SupportedTargets | Should -BeNullOrEmpty
    $operation.CandidateTargets | Should -Be @('Windows 11')
    $operation.PendingAcceptance | Should -BeTrue
    $operation.MigrationBatch | Should -BeExactly 'ApplicationsBatch1'
    $operation.InstallerConfiguration.inst_kleopatra | Should -BeTrue
    $operation.InstallerConfigurationSection | Should -BeExactly 'gpg4win'
    foreach ($key in @('inst_okular','inst_gpgpass','inst_gpgoljs','inst_gpgol','inst_gpgex','inst_paperkey','inst_browser','inst_desktop')) {
      $operation.InstallerConfiguration[$key] | Should -BeFalse
    }
    $operation.PreserveRoamingDirectory | Should -BeExactly 'gnupg'
    $operation.PreserveRoamingDirectoryOnInstall | Should -BeTrue
    $operation.PreservationProcessNames | Should -Contain 'gpg-agent'
    $operation.InstallerArguments | Should -Match '/CurrentUser'
    (Get-RideCatalogValidationErrors -Catalog $catalog) | Should -BeNullOrEmpty
  }

  It 'resolves into the conventional Windows installer acceptance batch' {
    $root = Split-Path -Parent $PSScriptRoot
    $catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
    $operation = $catalog.Operations | Where-Object Id -eq 'package.gpg4win' | Select-Object -First 1

    $selection = Resolve-RidePackageSelection -Operation $operation -IgnorePreferences -MetadataOnly
    $selection.MigrationBatch | Should -BeExactly 'ApplicationsBatch1'
    $selection.RequiresUnelevatedUser | Should -BeTrue
    $selection.PendingAcceptance | Should -BeTrue
  }

  It 'rejects unsafe or unbound installer configuration' {
    $root = Split-Path -Parent $PSScriptRoot
    $catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
    $operation = $catalog.Operations | Where-Object Id -eq 'package.gpg4win' | Select-Object -First 1
    $operation.InstallerConfiguration.inst_gpgol = 'enabled'
    (@(Get-RideCatalogValidationErrors -Catalog $catalog) -join ' ') | Should -Match 'Installer configuration'
  }

  It 'rejects missing or unsafe installer configuration sections' {
    $root = Split-Path -Parent $PSScriptRoot
    $catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
    $operation = $catalog.Operations | Where-Object Id -eq 'package.gpg4win' | Select-Object -First 1
    $operation.InstallerConfigurationSection = '[unexpected]'
    (@(Get-RideCatalogValidationErrors -Catalog $catalog) -join ' ') | Should -Match 'Installer configuration'
  }
}

Describe 'Gpg4win installer configuration staging' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $root = Split-Path -Parent $PSScriptRoot
      $catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
      $operation = $catalog.Operations | Where-Object Id -eq 'package.gpg4win' | Select-Object -First 1
      $artifactPath = Join-Path $TestDrive 'gpg4win-5.1.1.exe'
      [IO.File]::WriteAllText($artifactPath, 'inert fixture')
      $script:gpg4winDataRoot = Join-Path $TestDrive 'Roaming'
      $script:gpg4winKeyDirectory = Join-Path $script:gpg4winDataRoot 'gnupg'
      $null = New-Item -ItemType Directory -Path $script:gpg4winKeyDirectory -Force
      [IO.File]::WriteAllText((Join-Path $script:gpg4winKeyDirectory 'gpg.conf'), 'synthetic user setting')
      $script:gpg4winDigest = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash
      $script:gpg4winInstalled = $false
      $script:gpg4winConfigurationPath = $null
      $script:gpg4winConfigurationText = $null
      $script:gpg4winArguments = $null
      Mock Test-RidePackageAdministrator { $false }
      Mock Get-RideRoamingApplicationDataRoot { $script:gpg4winDataRoot }
      Mock Get-Process { $null }
      Mock Save-RidePackageArtifact { [pscustomobject]@{Path=$artifactPath;Sha256=$script:gpg4winDigest;Version='5.1.1'} }
      Mock Get-ItemProperty { @() }
      Mock Invoke-RidePackageInstallerProcess {
        $script:gpg4winArguments = $ArgumentList
        $script:gpg4winDataAbsentDuringInstall = -not (Test-Path -LiteralPath $script:gpg4winKeyDirectory)
        $match = [regex]::Match($ArgumentList, '/C="(?<path>[^"]+)"')
        $match.Success | Should -BeTrue
        $script:gpg4winConfigurationPath = $match.Groups['path'].Value
        $script:gpg4winConfigurationText = [IO.File]::ReadAllText($script:gpg4winConfigurationPath)
        $script:gpg4winInstalled = $true
        [pscustomobject]@{ExitCode=0}
      }
      Mock Get-RideInstalledPackage { [pscustomobject]@{Present=$script:gpg4winInstalled;DisplayName='Gpg4win (5.1.1)';DisplayVersion='5.1.1';InstallLocation=$Operation.InstallDirectory} }
    }

    It 'passes a temporary explicit component config and removes it after the mocked installer returns' {
      Install-RidePackage -Operation $operation -CacheDirectory $TestDrive | Out-Null

      $script:gpg4winArguments | Should -Match '/CurrentUser'
      $expectedInstallDirectory = Join-Path (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs') 'Gpg4win'
      $script:gpg4winArguments | Should -Match ([regex]::Escape('/D="' + $expectedInstallDirectory + '"'))
      $script:gpg4winDataAbsentDuringInstall | Should -BeTrue
      (Get-Content -LiteralPath (Join-Path $script:gpg4winKeyDirectory 'gpg.conf') -Raw) | Should -BeExactly 'synthetic user setting'
      $script:gpg4winConfigurationText | Should -Match '(?m)^inst_kleopatra=true\r?$'
      $script:gpg4winConfigurationText | Should -Match '(?m)^\[gpg4win\]\r?$'
      foreach ($key in @('inst_okular','inst_gpgpass','inst_gpgoljs','inst_gpgol','inst_gpgex','inst_paperkey','inst_browser','inst_desktop')) {
        $script:gpg4winConfigurationText | Should -Match (("(?m)^" + [regex]::Escape($key) + '=false\r?$'))
      }
      Test-Path -LiteralPath $script:gpg4winConfigurationPath | Should -BeFalse
      Should -Invoke Invoke-RidePackageInstallerProcess -Exactly 1
    }

    It 'cleans temporary configuration if the installer process fails' {
      Mock Invoke-RidePackageInstallerProcess {
        $match = [regex]::Match($ArgumentList, '/C="(?<path>[^"]+)"')
        $script:gpg4winConfigurationPath = $match.Groups['path'].Value
        throw 'synthetic process failure'
      }

      { Install-RidePackage -Operation $operation -CacheDirectory $TestDrive } | Should -Throw '*synthetic process failure*'
      Test-Path -LiteralPath $script:gpg4winConfigurationPath | Should -BeFalse
      (Get-Content -LiteralPath (Join-Path $script:gpg4winKeyDirectory 'gpg.conf') -Raw) | Should -BeExactly 'synthetic user setting'
    }
  }
}

Describe 'Gpg4win nested GnuPG ownership and user-data safety' {
  InModuleScope RIDE-Packages {
    BeforeEach {
      $root = Split-Path -Parent $PSScriptRoot
      $catalog = Import-RideCatalogData (Join-Path $root 'catalog/operations.psd1')
      $operation = $catalog.Operations | Where-Object Id -eq 'package.gpg4win' | Select-Object -First 1
      $operation = Resolve-RidePackageSelection -Operation $operation
      $nestedPath = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $operation.InstallDirectory) 'GnuPG'))
      $script:gpg4winRegistryEntries = @()
      Mock Get-ItemProperty {
        if ($Path -like 'HKCU:*') { return $script:gpg4winRegistryEntries }
        @()
      }
    }

    It 'refuses to adopt a separately installed GnuPG registration' {
      $script:gpg4winRegistryEntries = @([pscustomobject]@{DisplayName='GnuPG';InstallLocation=$nestedPath})

      { Get-RideInstalledPackage -Operation $operation } | Should -Throw '*Conflicting existing edition*'
    }

    It 'refuses to let the vendor installer silently replace another Gpg4win version' {
      $script:gpg4winRegistryEntries = @([pscustomobject]@{DisplayName='Gpg4win (5.1.0)';InstallLocation=(Join-Path $TestDrive 'OlderGpg4win')})

      { Get-RideInstalledPackage -Operation $operation } | Should -Throw '*Conflicting existing edition*'
    }

    It 'accepts the nested GnuPG registration only with the matching Gpg4win registration' {
      $script:gpg4winRegistryEntries = @(
        [pscustomobject]@{DisplayName='Gpg4win (5.1.1)';InstallLocation=$operation.InstallDirectory;DisplayVersion='5.1.1';UninstallString='"C:\Gpg4win\gpg4win-uninstall.exe" /S';QuietUninstallString='/S'},
        [pscustomobject]@{DisplayName='GnuPG';InstallLocation=$nestedPath;DisplayVersion='2.5.0'}
      )

      (Get-RideInstalledPackage -Operation $operation).Present | Should -BeTrue
    }

    It 'does not move key data while a declared GnuPG process is running' {
      $dataRoot = Join-Path $TestDrive 'Roaming'
      $keyDirectory = Join-Path $dataRoot 'gnupg'
      $null = New-Item -ItemType Directory -Path $keyDirectory -Force
      [IO.File]::WriteAllText((Join-Path $keyDirectory 'gpg.conf'), 'synthetic user setting')
      Mock Get-RideRoamingApplicationDataRoot { $dataRoot }
      Mock Get-Process { if ($Name -eq 'gpg-agent') { [pscustomobject]@{ProcessName='gpg-agent'} } else { $null } }
      Mock Invoke-RidePackageInstallerProcess { throw 'The uninstaller must not run.' }

      { Invoke-RidePreservingPackageOperation -Operation $operation -FilePath 'unused.exe' -ArgumentList '/S' } | Should -Throw '*Close gpg-agent*'
      (Get-Content -LiteralPath (Join-Path $keyDirectory 'gpg.conf') -Raw) | Should -BeExactly 'synthetic user setting'
      Should -Invoke Invoke-RidePackageInstallerProcess -Exactly 0
    }

    It 'restores the key directory if the mocked vendor uninstaller removes it' {
      $dataRoot = Join-Path $TestDrive 'Roaming'
      $keyDirectory = Join-Path $dataRoot 'gnupg'
      $null = New-Item -ItemType Directory -Path $keyDirectory -Force
      [IO.File]::WriteAllText((Join-Path $keyDirectory 'gpg.conf'), 'synthetic user setting')
      Mock Get-RideRoamingApplicationDataRoot { $dataRoot }
      Mock Get-Process { $null }
      Mock Invoke-RidePackageInstallerProcess { [pscustomobject]@{ExitCode=0} }

      $result = Invoke-RidePreservingPackageOperation -Operation $operation -FilePath 'unused.exe' -ArgumentList '/S'

      $result.ExitCode | Should -Be 0
      (Get-Content -LiteralPath (Join-Path $keyDirectory 'gpg.conf') -Raw) | Should -BeExactly 'synthetic user setting'
      @(Get-ChildItem -LiteralPath $dataRoot -Directory -Force).Count | Should -Be 1
    }

    It 'retains package-created user data separately while restoring the pre-existing key directory' {
      $dataRoot = Join-Path $TestDrive 'Roaming'
      $keyDirectory = Join-Path $dataRoot 'gnupg'
      $null = New-Item -ItemType Directory -Path $keyDirectory -Force
      [IO.File]::WriteAllText((Join-Path $keyDirectory 'gpg.conf'), 'original synthetic setting')
      Mock Get-RideRoamingApplicationDataRoot { $dataRoot }
      Mock Get-Process { $null }
      Mock Invoke-RidePackageInstallerProcess {
        $newDirectory = Join-Path $dataRoot 'gnupg'
        $null = New-Item -ItemType Directory -Path $newDirectory -Force
        [IO.File]::WriteAllText((Join-Path $newDirectory 'generated.conf'), 'installer-created synthetic data')
        [pscustomobject]@{ExitCode=0}
      }

      Invoke-RidePreservingPackageOperation -Operation $operation -FilePath 'unused.exe' -ArgumentList '/S' -WarningAction SilentlyContinue | Out-Null

      (Get-Content -LiteralPath (Join-Path $keyDirectory 'gpg.conf') -Raw) | Should -BeExactly 'original synthetic setting'
      $createdDirectory = Get-ChildItem -LiteralPath $dataRoot -Directory -Filter '.gnupg.ride-created-*' -Force | Select-Object -First 1
      $createdDirectory | Should -Not -BeNullOrEmpty
      (Get-Content -LiteralPath (Join-Path $createdDirectory.FullName 'generated.conf') -Raw) | Should -BeExactly 'installer-created synthetic data'
    }
  }
}
