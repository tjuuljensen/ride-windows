<#
.SYNOPSIS
  Accept GitHub discovery and verified download without installing a package.
.DESCRIPTION
  Disposable-VM-only focused suite. Uses the catalog's 7-Zip publisher, records
  network/cache observations and requires a matching publisher SHA-256 digest.
.PARAMETER RunId
  Correlated request ID; PAT selects only its existing run-bound guest lease.
.PARAMETER ResultsPath
  Correlated guest evidence directory; payloads remain outside exported evidence.
.PARAMETER Authentication
  Anonymous (default) or explicitly provisioned PAT.
.PARAMETER Scenario
  Acquire (default), FailAfterDelivery or WaitForTimeout for controlled recovery acceptance.
.PARAMETER Version
  Print the version without reading credentials or contacting GitHub.
.EXAMPLE
  .\Invoke-RideGitHubAuthentication.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  None. Writes github-authentication.json and acquisition observations.
.NOTES
  Windows PowerShell 5.1/7 on disposable Windows 11/Server 2025 guests.
  Requires RIDE_INTEGRATION_VM=1 and the approved guest test runner.
  No installers or Windows setting changes. Host restores the pinned checkpoint.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Focused authenticated discovery, payload and recovery acceptance.
#>

[CmdletBinding()]
param(
  [ValidatePattern('^[0-9a-f]{32}$')][string] $RunId,
  [string] $ResultsPath,
  [ValidateSet('Anonymous','PAT')][string] $Authentication = 'Anonymous',
  [ValidateSet('Acquire','FailAfterDelivery','WaitForTimeout')][string] $Scenario = 'Acquire',
  [switch] $Version
)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if ($env:RIDE_INTEGRATION_VM -ne '1' -or $env:RIDE_TEST_GUEST -ne '1' -or -not $RunId -or -not $ResultsPath) { throw 'Use the correlated disposable-VM guest runner.' }
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $root 'modules/RIDE.GitHubAuthentication.psm1') -Force
Import-Module (Join-Path $root 'modules/RIDE-Packages.psm1') -Force
Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
$parameters = @{ GitHubAuthentication = $Authentication }
if ($Authentication -eq 'PAT') {
  $parameters.GitHubCredentialReference = 'run:' + $RunId
  $context = Get-RideGitHubCredentialContext $parameters.GitHubCredentialReference
  $context.Token.Dispose()
}
$evidence = [ordered]@{ SchemaVersion = 1; RunId = $RunId; AuthenticationMode = $Authentication; Scenario = $Scenario; Phase = 'CredentialReady'; Status = 'Failed' }
$evidencePath = Join-Path $ResultsPath 'github-authentication.json'
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
if ($Scenario -eq 'FailAfterDelivery') { throw 'Expected focused authentication failure after credential delivery.' }
if ($Scenario -eq 'WaitForTimeout') { while ($true) { Start-Sleep -Seconds 5 } }
$catalog = Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
$operation = $catalog.Operations | Where-Object Id -EQ 'package.7zip' | Select-Object -First 1
if (-not $operation -or $operation.DownloadProvider -ne 'GitHubReleaseApi') { throw 'Focused acquisition requires the catalog GitHub 7-Zip operation.' }
$payloadRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('RIDE\AuthenticationPayloads\' + $RunId)
$observationPath = Join-Path $ResultsPath 'authentication-artifact-observations.json'
$first = Save-RidePackageArtifact -Operation $operation -DestinationDirectory $payloadRoot -ObservationPath $observationPath @parameters
$second = Save-RidePackageArtifact -Operation $operation -DestinationDirectory $payloadRoot -ObservationPath $observationPath @parameters
if ($first.ReleaseMetadata.AuthenticationMode -ne $Authentication -or $first.ReleaseMetadata.AcquisitionKind -ne 'Network' -or $second.ReleaseMetadata.AcquisitionKind -ne 'ProcessCache' -or $second.AcquisitionKind -ne 'Cache') { throw 'Expected network discovery followed by metadata and payload cache reuse.' }
if ($first.ProviderDigest -notmatch '^sha256:[0-9a-fA-F]{64}$' -or $first.ProviderDigest.Substring(7) -ne $first.Sha256 -or $second.Sha256 -ne $first.Sha256) { throw 'Focused acquisition requires a matching publisher SHA-256 digest.' }
$evidence.Phase = 'AcquisitionVerified'; $evidence.Status = 'Passed'
$evidence.Network = $first.ReleaseMetadata; $evidence.Cache = $second.ReleaseMetadata
$evidence.Payload = @{ PackageId = $first.PackageId; Version = $first.Version; Sha256 = $first.Sha256; ProviderDigest = $first.ProviderDigest; InstallerInvoked = $false }
$evidence | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
