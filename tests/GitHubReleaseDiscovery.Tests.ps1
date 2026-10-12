<#
.SYNOPSIS
  Verify bounded GitHub release reuse, shared backoff and acquisition provenance.
.DESCRIPTION
  Mock HTTP and time; use isolated payloads. No publisher requests or installers run.
.EXAMPLE
  Invoke-Pester .\tests\GitHubReleaseDiscovery.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.7.1.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
  Recovery: TestDrive and mocks isolate all effects; module cache/backoff is cleared.
#>


BeforeDiscovery {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE-Packages.psm1') -Force
}
BeforeAll {
  Add-Type -AssemblyName System.Net.Http
  if (-not ('RideGitHubTestResponse' -as [type])) {
    Add-Type -TypeDefinition @'
public sealed class RideGitHubTestResponse : System.Net.WebResponse {
  public int StatusCode { get; set; }
  public override System.Net.WebHeaderCollection Headers { get { return headers; } }
  private readonly System.Net.WebHeaderCollection headers = new System.Net.WebHeaderCollection();
}
'@
  }
}

Describe 'Rate-aware GitHub latest release discovery' {
  InModuleScope RIDE-Packages {
    BeforeAll {
      function New-ReleaseHttpFailure([int] $Status, [hashtable] $Headers, [string] $Detail = '') {
        $response = New-Object RideGitHubTestResponse
        $response.StatusCode = $Status
        foreach ($name in $Headers.Keys) { $response.Headers.Add($name, [string]$Headers[$name]) }
        $exception = [Net.WebException]::new('HTTP fixture failure', $null, [Net.WebExceptionStatus]::ProtocolError, $response)
        $record = [Management.Automation.ErrorRecord]::new($exception, 'HttpFixture', [Management.Automation.ErrorCategory]::InvalidOperation, $null)
        if ($Detail) { $record.ErrorDetails = [Management.Automation.ErrorDetails]::new($Detail) }
        return $record
      }
    }
    BeforeEach {
      $script:GitHubReleaseCache = @{}; $script:GitHubReleaseNotBefore = $null; $script:GitHubReleaseRate = $null
      $script:ReleaseNow = [DateTime]::SpecifyKind([DateTime]'2026-10-12 12:00:00', [DateTimeKind]::Utc)
      $script:ReleaseVersion = '1'; $script:ReleaseDigest = $null
      $script:ReleaseHeaders = @{ 'X-RateLimit-Remaining' = '42'; 'X-RateLimit-Reset' = '1791808200' }
      $script:ReleaseOperation = @{ Kind = 'Package'; PackageId = 'app'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/publisher/app/releases/latest'; AssetPattern = '^app\.exe$'; Architecture = 'x64' }
      Mock Get-RideGitHubUtcNow { $script:ReleaseNow }
      Mock Invoke-WebRequest {
        $repository = ([uri]$Uri).AbsolutePath -replace '^/repos/|/releases/latest$', ''
        $release = @{ tag_name = 'v' + $script:ReleaseVersion; html_url = "https://github.com/$repository/releases/tag/v$script:ReleaseVersion"; assets = @(@{ name = 'app.exe'; browser_download_url = "https://github.com/$repository/releases/download/v$script:ReleaseVersion/app.exe"; digest = $script:ReleaseDigest }) }
        [pscustomobject]@{ Content = ($release | ConvertTo-Json -Depth 8); Headers = $script:ReleaseHeaders }
      }
      Mock Start-Sleep { throw 'Release lookup must defer, not sleep or spin.' }
    }
    AfterAll {
      $script:GitHubReleaseCache = @{}; $script:GitHubReleaseNotBefore = $null; $script:GitHubReleaseRate = $null
    }

    It 'records the release endpoint, freshness and quota without authentication headers' {
      $artifact = Resolve-RidePackageArtifact $script:ReleaseOperation
      $artifact.ReleaseMetadata.AcquisitionKind | Should -Be Network
      $artifact.ReleaseMetadata.ApiUri | Should -Be $script:ReleaseOperation.DownloadUri
      $artifact.ReleaseMetadata.RetrievedAtUtc | Should -Be $script:ReleaseNow.ToString('o')
      $artifact.ReleaseMetadata.ExpiresAtUtc | Should -Be $script:ReleaseNow.AddMinutes(5).ToString('o')
      $artifact.ReleaseMetadata.RemainingQuota | Should -Be 42
      Should -Invoke Invoke-WebRequest -Exactly 1 -ParameterFilter { $MaximumRedirection -eq 0 -and $Headers.Count -eq 2 -and -not $Headers.ContainsKey('Authorization') }
    }

    It 'reuses one repository lookup across different package selections' {
      $first = Resolve-RidePackageArtifact $script:ReleaseOperation
      $alias = $script:ReleaseOperation.Clone(); $alias.PackageId = 'another-selection'
      $second = Resolve-RidePackageArtifact $alias
      $second.ReleaseMetadata.AcquisitionKind | Should -Be ProcessCache
      $second.ReleaseMetadata.RetrievedAtUtc | Should -Be $first.ReleaseMetadata.RetrievedAtUtc
      $second.PackageId | Should -Be another-selection
      Should -Invoke Invoke-WebRequest -Exactly 1
    }

    It 'refreshes exactly at expiry and selects the newly published release' {
      $null = Resolve-RidePackageArtifact $script:ReleaseOperation
      $script:ReleaseVersion = '2'; $script:ReleaseNow = $script:ReleaseNow.AddSeconds(299)
      (Resolve-RidePackageArtifact $script:ReleaseOperation).Version | Should -Be 1
      $script:ReleaseNow = $script:ReleaseNow.AddSeconds(1)
      $fresh = Resolve-RidePackageArtifact $script:ReleaseOperation
      $fresh.Version | Should -Be 2
      $fresh.ReleaseMetadata.AcquisitionKind | Should -Be Network
      Should -Invoke Invoke-WebRequest -Exactly 2
    }

    It 'never returns expired metadata when the refresh is rate limited' {
      $null = Resolve-RidePackageArtifact $script:ReleaseOperation
      $script:ReleaseNow = $script:ReleaseNow.AddMinutes(5)
      Mock Invoke-WebRequest { throw (New-ReleaseHttpFailure 403 @{ 'X-RateLimit-Remaining' = '0'; 'X-RateLimit-Reset' = '1791808200' }) }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*acquisition deferred*Remaining quota: 0*'
      Should -Invoke Invoke-WebRequest -Exactly 2
      Should -Invoke Start-Sleep -Exactly 0
    }

    It 'shares primary exhaustion across repositories while allowing already fresh metadata' {
      $script:ReleaseHeaders['X-RateLimit-Remaining'] = '0'
      $null = Resolve-RidePackageArtifact $script:ReleaseOperation
      (Resolve-RidePackageArtifact $script:ReleaseOperation).ReleaseMetadata.AcquisitionKind | Should -Be ProcessCache
      $other = $script:ReleaseOperation.Clone(); $other.DownloadUri = 'https://api.github.com/repos/other/app/releases/latest'
      { Resolve-RidePackageArtifact $other } | Should -Throw '*Remaining quota: 0*reset UTC: 2026-10-12T12:30:00*'
      Should -Invoke Invoke-WebRequest -Exactly 1
    }

    It 'makes one failed request then resumes only after the primary reset deadline' {
      Mock Invoke-WebRequest { throw (New-ReleaseHttpFailure 403 @{ 'X-RateLimit-Remaining' = '0'; 'X-RateLimit-Reset' = '1791808200' }) }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*acquisition deferred*'
      $other = $script:ReleaseOperation.Clone(); $other.DownloadUri = 'https://api.github.com/repos/other/app/releases/latest'
      { Resolve-RidePackageArtifact $other } | Should -Throw '*acquisition deferred*'
      Should -Invoke Invoke-WebRequest -Exactly 1
      $script:ReleaseNow = $script:ReleaseNow.AddMinutes(30).AddSeconds(1)
      Mock Invoke-WebRequest { [pscustomobject]@{ Content = '{"tag_name":"v2","assets":[{"name":"app.exe","browser_download_url":"https://github.com/other/app/releases/download/v2/app.exe"}]}'; Headers = @{ 'X-RateLimit-Remaining' = '59' } } }
      (Resolve-RidePackageArtifact $other).Version | Should -Be 2
      Should -Invoke Invoke-WebRequest -Exactly 2
      Should -Invoke Start-Sleep -Exactly 0
    }

    It 'honors secondary Retry-After across products without waiting for a nonempty primary window' {
      Mock Invoke-WebRequest { throw (New-ReleaseHttpFailure 429 @{ 'Retry-After' = '120'; 'X-RateLimit-Remaining' = '13'; 'X-RateLimit-Reset' = '1791808200' }) }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*Remaining quota: 13*12:02:00*'
      $script:ReleaseNow = $script:ReleaseNow.AddSeconds(119)
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*acquisition deferred*'
      Should -Invoke Invoke-WebRequest -Exactly 1
      $script:ReleaseNow = $script:ReleaseNow.AddSeconds(1)
      Mock Invoke-WebRequest { [pscustomobject]@{ Content = '{"tag_name":"v1","assets":[{"name":"app.exe","browser_download_url":"https://github.com/publisher/app/releases/download/v1/app.exe"}]}'; Headers = @{} } }
      (Resolve-RidePackageArtifact $script:ReleaseOperation).Version | Should -Be 1
      Should -Invoke Invoke-WebRequest -Exactly 2
    }

    It 'backs off secondary 403 without Retry-After for at least one minute' {
      Mock Invoke-WebRequest { throw (New-ReleaseHttpFailure 403 @{ 'X-RateLimit-Remaining' = '12' } '{"message":"You have exceeded a secondary rate limit."}') }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*12:01:00*'
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*acquisition deferred*'
      Should -Invoke Invoke-WebRequest -Exactly 1
    }

    It 'defers with a one-minute deadline when rate timing is unavailable or expired' -ForEach @(
      @{ FailureStatus = 429; FailureHeaders = @{} },
      @{ FailureStatus = 403; FailureHeaders = @{ 'X-RateLimit-Remaining' = '0'; 'X-RateLimit-Reset' = '1'; 'Retry-After' = 'invalid' } }
    ) {
      Mock Invoke-WebRequest { throw (New-ReleaseHttpFailure $FailureStatus $FailureHeaders) }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*acquisition deferred*12:01:00*'
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*acquisition deferred*'
      Should -Invoke Invoke-WebRequest -Exactly 1
      Should -Invoke Start-Sleep -Exactly 0
    }

    It 'does not classify ordinary HTTP errors as quota exhaustion' -ForEach @(
      @{ Status = 403 }, @{ Status = 404 }
    ) {
      Mock Invoke-WebRequest { throw (New-ReleaseHttpFailure $Status @{ 'X-RateLimit-Remaining' = '42' } 'Permission denied') }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*HTTP fixture failure*'
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*HTTP fixture failure*'
      Should -Invoke Invoke-WebRequest -Exactly 2
    }

    It 'preserves transport errors without inventing quota observations' {
      Mock Invoke-WebRequest { throw 'Fixture transport timeout' }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*Fixture transport timeout*'
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw '*Fixture transport timeout*'
      Should -Invoke Invoke-WebRequest -Exactly 2
    }

    It 'treats absent or malformed quota headers as unknown rather than zero' {
      $script:ReleaseHeaders = @{ 'X-RateLimit-Remaining' = 'invalid'; 'X-RateLimit-Reset' = '999999999999999999999' }
      $first = Resolve-RidePackageArtifact $script:ReleaseOperation
      $first.ReleaseMetadata.RemainingQuota | Should -BeNullOrEmpty
      $first.ReleaseMetadata.ResetAtUtc | Should -BeNullOrEmpty
      $other = $script:ReleaseOperation.Clone(); $other.DownloadUri = 'https://api.github.com/repos/other/app/releases/latest'
      $null = Resolve-RidePackageArtifact $other
      Should -Invoke Invoke-WebRequest -Exactly 2
    }

    It 'reads headers from both Windows PowerShell and PowerShell 7 response types' {
      $legacy = [Net.WebHeaderCollection]::new(); $legacy.Add('X-RateLimit-Remaining','0'); $legacy.Add('Retry-After','90')
      $modern = [Net.Http.HttpResponseMessage]::new(); $modern.Headers.Add('X-RateLimit-Remaining','0'); $modern.Headers.Add('Retry-After','90')
      try {
        foreach ($headers in @($legacy,$modern.Headers,@{ 'X-RateLimit-Remaining' = @('0'); 'Retry-After' = @('90') })) {
          $rate = Get-RideGitHubRate $headers
          $rate.Remaining | Should -Be 0
          $rate.RetryAfterSeconds | Should -Be 90
        }
      } finally { $modern.Dispose() }
    }

    It 'rejects unsupported or credential-bearing endpoints before any HTTP request' -ForEach @(
      @{ Endpoint = 'http://api.github.com/repos/publisher/app/releases/latest' },
      @{ Endpoint = 'https://api.github.com:444/repos/publisher/app/releases/latest' },
      @{ Endpoint = 'https://secret@api.github.com/repos/publisher/app/releases/latest' },
      @{ Endpoint = 'https://api.github.com/repos/publisher/app/releases/latest?token=secret' },
      @{ Endpoint = 'https://api.github.com/repos/publisher/app/releases/latest#secret' },
      @{ Endpoint = 'https://api.github.com/repos/publisher/app/releases' }
    ) {
      $operation = $script:ReleaseOperation.Clone(); $operation.DownloadUri = $Endpoint
      { Resolve-RidePackageArtifact $operation } | Should -Throw
      Should -Invoke Invoke-WebRequest -Exactly 0
    }

    It 'does not cache malformed or oversized responses' -ForEach @(
      @{ FixtureContent = '{invalid'; ExpectedFailure = '*' },
      @{ FixtureContent = '{"tag_name":"v1"}'; ExpectedFailure = '*release tag and assets*' },
      @{ FixtureContent = ('x' * (2MB + 1)); ExpectedFailure = '*two MiB*' }
    ) {
      Mock Invoke-WebRequest { [pscustomobject]@{ Content = $FixtureContent; Headers = @{} } }
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw $ExpectedFailure
      { Resolve-RidePackageArtifact $script:ReleaseOperation } | Should -Throw $ExpectedFailure
      Should -Invoke Invoke-WebRequest -Exactly 2
    }

    It 'isolates cached input from returned objects and still checks the selected asset' {
      $first = Get-RideGitHubReleaseMetadata $script:ReleaseOperation.DownloadUri
      $first.Release.assets[0].browser_download_url = 'https://mirror.invalid/app.exe'
      (Resolve-RidePackageArtifact $script:ReleaseOperation).Uri | Should -Be 'https://github.com/publisher/app/releases/download/v1/app.exe'
      $missing = $script:ReleaseOperation.Clone(); $missing.AssetPattern = '^missing\.exe$'
      { Resolve-RidePackageArtifact $missing } | Should -Throw '*Expected one latest*found 0*'
      Should -Invoke Invoke-WebRequest -Exactly 1
    }

    It 'bounds the cache and refetches an evicted endpoint' {
      foreach ($number in 1..65) {
        $operation = $script:ReleaseOperation.Clone(); $operation.DownloadUri = "https://api.github.com/repos/publisher/app$number/releases/latest"
        $null = Resolve-RidePackageArtifact $operation
        $script:ReleaseNow = $script:ReleaseNow.AddSeconds(1)
      }
      $first = $script:ReleaseOperation.Clone(); $first.DownloadUri = 'https://api.github.com/repos/publisher/app1/releases/latest'
      (Resolve-RidePackageArtifact $first).ReleaseMetadata.AcquisitionKind | Should -Be Network
      Should -Invoke Invoke-WebRequest -Exactly 66
    }

    It 'refreshes rather than extending cache life when the clock moves backwards' {
      $null = Resolve-RidePackageArtifact $script:ReleaseOperation
      $script:ReleaseNow = $script:ReleaseNow.AddSeconds(-1); $script:ReleaseVersion = '2'
      (Resolve-RidePackageArtifact $script:ReleaseOperation).Version | Should -Be 2
      Should -Invoke Invoke-WebRequest -Exactly 2
    }

    It 'retains metadata freshness separately from payload caching and still rejects altered bytes' {
      $payload = 'fixture artifact bytes'
      $fixture = Join-Path $TestDrive 'payload'; [IO.File]::WriteAllText($fixture,$payload)
      $script:ReleaseDigest = 'sha256:' + (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
      Mock Invoke-WebRequest { [IO.File]::WriteAllText($OutFile,'fixture artifact bytes') } -ParameterFilter { [bool]$OutFile }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null; TimeStamperCertificate = $null } }
      $destination = Join-Path $TestDrive 'artifacts'; $observations = Join-Path $TestDrive 'observations.json'
      $first = Save-RidePackageArtifact $script:ReleaseOperation $destination -ObservationPath $observations
      $second = Save-RidePackageArtifact $script:ReleaseOperation $destination -ObservationPath $observations
      $records = (Get-Content -LiteralPath $observations -Raw | ConvertFrom-Json).Observations
      $records[0].ReleaseMetadata.AcquisitionKind | Should -Be Network
      $records[1].ReleaseMetadata.AcquisitionKind | Should -Be ProcessCache
      $records[0].AcquisitionKind | Should -Be Download
      $records[1].AcquisitionKind | Should -Be Cache
      $second.ReleaseMetadata.ApiUri | Should -Be $script:ReleaseOperation.DownloadUri
      [IO.File]::AppendAllText($second.Path,'altered')
      { Save-RidePackageArtifact $script:ReleaseOperation $destination -ObservationPath $observations } | Should -Throw '*Provider SHA-256 digest mismatch*'
      Should -Invoke Invoke-WebRequest -Exactly 1 -ParameterFilter { [bool]$OutFile }
      (Get-Content -LiteralPath $observations -Raw | ConvertFrom-Json).Observations.Count | Should -Be 2
    }

    It 'does not download a payload, launch an installer or record successful evidence on exhaustion' {
      Mock Invoke-WebRequest { throw (New-ReleaseHttpFailure 403 @{ 'X-RateLimit-Remaining' = '0' }) }
      Mock Start-Process { throw 'No installer may run.' }
      Mock Add-RideArtifactObservation { }
      $destination = Join-Path $TestDrive 'deferred'
      { Save-RidePackageArtifact $script:ReleaseOperation $destination } | Should -Throw '*acquisition deferred*Remaining quota: 0*reset UTC: unknown*'
      Test-Path -LiteralPath $destination | Should -BeFalse
      Should -Invoke Invoke-WebRequest -Exactly 0 -ParameterFilter { [bool]$OutFile }
      Should -Invoke Add-RideArtifactObservation -Exactly 0
      Should -Invoke Start-Process -Exactly 0
    }
  }
}
