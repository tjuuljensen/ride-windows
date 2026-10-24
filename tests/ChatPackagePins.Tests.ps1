<#
.SYNOPSIS
  Verify exact Slack and Discord candidate source-pin state without downloading installers.
.DESCRIPTION
  Confirms Slack and Discord source pins without downloading installers.
.EXAMPLE
  Invoke-Pester .\tests\ChatPackagePins.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.7.1.
  No installer or network request is executed.
#>

BeforeDiscovery {
  $repoRoot = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $repoRoot 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $repoRoot 'modules/RIDE-Packages.psm1') -Force
}

Describe 'Slack and Discord package pins and acceptance' {
  BeforeAll {
    $script:chatPackageCatalog = Import-RideCatalogData -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/operations.psd1')
    $script:slackPackage = $script:chatPackageCatalog.Operations | Where-Object Id -eq 'package.slack'
    $script:discordPackage = $script:chatPackageCatalog.Operations | Where-Object Id -eq 'package.discord'
  }

  It 'pins Slack to its verified x64 installer digest' {
    $script:slackPackage.ExpectedSha256 | Should -Match '^[a-fA-F0-9]{64}$'
    $script:slackPackage.ExpectedSha256 | Should -BeExactly 'e42dba9622a297106f16a11f148c86e08beeeea6fe5bfd63de4c606b513ab184'
  }

  It 'pins Discord to its independently verified x64 installer digest' {
    $script:discordPackage.ExpectedSha256 | Should -Match '^[a-fA-F0-9]{64}$'
    $script:discordPackage.ExpectedSha256 | Should -BeExactly '2c79a8eccf972709dc04e014a9ed36d8dcc4ce84179741eb1424e022d4c3625c'
    $script:discordPackage.AcquisitionBlockedReason | Should -BeNullOrEmpty
  }

  It 'lets Slack and Discord vendor uninstallers handle their Roaming data in place' {
    $script:slackPackage.Contains('PreserveRoamingDirectory') | Should -BeFalse
    $script:slackPackage.Contains('PreservationProcessName') | Should -BeFalse
    $script:discordPackage.Contains('PreserveRoamingDirectory') | Should -BeFalse
    $script:discordPackage.Contains('PreservationProcessName') | Should -BeFalse
  }
}

Describe 'Fail-closed direct package acquisition' {
  InModuleScope RIDE-Packages {
    It 'blocks a catalog-declared invalid digest before any network request' {
      Mock Invoke-WebRequest { throw 'Blocked acquisition must not reach the network.' }
      $operation = @{
        PackageId = 'discord'
        DownloadProvider = 'DirectHttps'
        AcquisitionBlockedReason = 'The source manifest does not contain a valid artifact digest.'
      }

      { Resolve-RidePackageArtifact -Operation $operation } | Should -Throw '*Acquisition blocked for discord*'
      Should -Invoke Invoke-WebRequest -Exactly 0
    }
  }
}
