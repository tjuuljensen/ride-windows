<#
.SYNOPSIS
  Isolated credential, authorization, cache and redaction regressions.
.DESCRIPTION
  Uses synthetic secrets, TestDrive, mocked HTTP/time and CurrentUser DPAPI only.
.EXAMPLE
  Invoke-Pester .\tests\GitHubAuthentication.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Windows PowerShell 5.1/7; Pester 5.7.1. Owner: RIDE-Windows maintainers.
  No publisher traffic, installers or real credential enrollment. Version 0.1.0.
#>

BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.GitHubAuthentication.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
}

Describe 'Explicit authentication through engine acquisition paths' {
  InModuleScope RIDE.Engine {
    BeforeEach {
      Mock Get-RideStateRoot { Join-Path $TestDrive $Scope }
      Mock Assert-RidePlanAllowed { }
      Mock Test-RideAdministrator { $false }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Save-RideRunManifest { }
      Mock Save-RideOperationSnapshot { }
      Mock Save-RidePackageSelectionIndex { }
      Mock Test-RideDesiredState { $false }
      Mock Get-RideCurrentState { [pscustomobject]@{ Present = $false } }
      Mock Install-RidePackage { }
      Mock Save-RidePackageArtifact { }
    }
    It 'passes explicit authentication to download only after approval' {
      Save-RidePackage package.7zip -Destination $TestDrive -GitHubAuthentication PAT -GitHubCredentialReference fixture -WhatIf
      Should -Invoke Save-RidePackageArtifact -Exactly 0
      Save-RidePackage package.7zip -Destination $TestDrive -GitHubAuthentication PAT -GitHubCredentialReference fixture -Confirm:$false
      Should -Invoke Save-RidePackageArtifact -Exactly 1 -ParameterFilter { $GitHubAuthentication -eq 'PAT' -and $GitHubCredentialReference -eq 'fixture' }
    }
    It 'passes explicit authentication through plan application without adding it to the plan' {
      $plan = @([pscustomobject]@{ Operation = Get-RideOperation package.7zip; State = 'Present' })
      Invoke-RidePlan $plan -GitHubAuthentication PAT -GitHubCredentialReference fixture -Confirm:$false | Out-Null
      Should -Invoke Install-RidePackage -Exactly 1 -ParameterFilter { $GitHubAuthentication -eq 'PAT' -and $GitHubCredentialReference -eq 'fixture' }
      ($plan | ConvertTo-Json -Depth 15) | Should -Not -Match 'GitHubCredentialReference|GitHubAuthentication|fixture'
    }
    It 'passes explicit authentication to restore reinstallation without changing saved recovery data' {
      Mock Get-RideInstalledPackage { [pscustomobject]@{ Present = $false } }
      $operation = @{ Id = 'package.fixture'; Name = 'Fixture'; Kind = 'Package'; Scope = 'User'; SupportedTargets = @('Windows 11') }
      Mock Get-RideCatalog { @{ Operations = @($operation) } }
      $run = 'c' * 32
      $directory = Join-Path (Join-Path $TestDrive User) $run
      $null = New-Item -ItemType Directory -Path $directory -Force
      $path = Join-Path $directory 'package.fixture.json'
      @{ SchemaVersion = 1; OperationId = 'package.fixture'; Kind = 'Package'; Scope = 'User'; Snapshot = @{ Present = $true } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
      $before = Get-Content -LiteralPath $path -Raw
      Restore-RideRun $run -GitHubAuthentication PAT -GitHubCredentialReference fixture -WhatIf
      Should -Invoke Install-RidePackage -Exactly 0
      Restore-RideRun $run -GitHubAuthentication PAT -GitHubCredentialReference fixture -Confirm:$false | Out-Null
      Should -Invoke Install-RidePackage -Exactly 1 -ParameterFilter { $GitHubAuthentication -eq 'PAT' -and $GitHubCredentialReference -eq 'fixture' }
      Get-Content -LiteralPath $path -Raw | Should -Be $before
    }
  }
}

Describe 'PAT selection stays within release discovery' {
  InModuleScope RIDE-Packages {
    It 'passes selection to metadata while assets and saved evidence remain credential-free' {
      $operation = @{ Kind = 'Package'; PackageId = 'fixture'; DownloadProvider = 'GitHubReleaseApi'; DownloadUri = 'https://api.github.com/repos/publisher/app/releases/latest'; AssetPattern = '^app.exe$' }
      Mock Get-RideGitHubReleaseMetadata {
        [pscustomobject]@{ Release = [pscustomobject]@{ tag_name = 'v1'; assets = @([pscustomobject]@{ name = 'app.exe'; browser_download_url = 'https://github.com/publisher/app/releases/download/v1/app.exe' }) }; Provenance = [pscustomobject]@{ AuthenticationMode = 'PAT' } }
      }
      Mock Invoke-WebRequest { 'fixture payload' | Set-Content -LiteralPath $OutFile }
      Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null; TimeStamperCertificate = $null } }
      $saved = Save-RidePackageArtifact $operation $TestDrive -ObservationPath (Join-Path $TestDrive 'observations.json') -GitHubAuthentication PAT -GitHubCredentialReference dedicated-reference
      $saved.ReleaseMetadata.AuthenticationMode | Should -Be PAT
      Should -Invoke Get-RideGitHubReleaseMetadata -Exactly 1 -ParameterFilter { $GitHubAuthentication -eq 'PAT' -and $GitHubCredentialReference -eq 'dedicated-reference' }
      Should -Invoke Invoke-WebRequest -Exactly 1 -ParameterFilter { $OutFile -and -not $Headers }
      (Get-Content -LiteralPath ($saved.Path + '.ride.json') -Raw -ErrorAction Stop) | Should -Not -Match 'dedicated-reference|GitHubCredentialReference|Authorization'
    }
  }
}

Describe 'Explicit GitHub PAT credentials' {
  InModuleScope RIDE.GitHubAuthentication {
    BeforeEach {
      $script:CredentialRootOverride = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      Mock Get-RideGitHubCredentialRoot { $script:CredentialRootOverride }
      $script:ReleaseCache.Clear(); $script:AccountBackoff.Clear()
      $script:Now = ([datetime]'2026-10-13T12:00:00Z').ToUniversalTime()
      Mock Get-RideGitHubAuthenticationTime { $script:Now }
      $script:Canary = 'syntheticPAT_Canary_1234567890'
      $script:Secret = ConvertTo-SecureString $script:Canary -AsPlainText -Force
      Mock Invoke-RideGitHubAuthenticatedHttp {
        if ($Uri -eq 'https://api.github.com/user') { $json = '{"id":123}' }
        elseif ($Uri -match '/releases/latest$') { $json = '{"tag_name":"v1","assets":[]}' }
        else { $json = '{"private":false}' }
        [pscustomobject]@{ StatusCode = 200; Content = $json; Headers = @{ 'X-RateLimit-Remaining' = '4998' } }
      }
    }
    AfterEach { $script:Secret.Dispose(); $script:CredentialRootOverride = $null }

    It 'seals the token and resolves the enrolled identity without exposing it in listings' {
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $file = Get-Content -LiteralPath (Get-RideGitHubCredentialPath public) -Raw
      $file | Should -Not -Match $script:Canary
      $context = Get-RideGitHubCredentialContext public
      try { $context.AccountId | Should -Be '123'; $context.Token | Should -BeOfType Security.SecureString } finally { $context.Token.Dispose() }
      $info = @(Get-RideGitHubCredentialInfo)
      $info.Count | Should -Be 1
      $info[0].Name | Should -Be public
      ($info | ConvertTo-Json) | Should -Not -Match 'Ciphertext|Token|Revision|AccountId'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 1
    }

    It 'does not prompt, decrypt, request or write during preview' {
      Mock Read-Host { throw 'Unexpected prompt' }
      Set-RideGitHubCredential public -ExpiresAtUtc $script:Now.AddHours(1) -WhatIf
      Test-Path -LiteralPath $script:CredentialRootOverride | Should -BeFalse
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 0
      Should -Invoke Read-Host -Exactly 0
    }

    It 'carries enrollment quota exhaustion into the discovered numeric account context' {
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode=200; Content='{"id":123}'; Headers=@{ 'X-RateLimit-Remaining'='0' } } }
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      { Get-RideAuthenticatedGitHubRelease 'https://api.github.com/repos/publisher/app/releases/latest' public } | Should -Throw '*AcquisitionDeferred*'
      $script:AccountBackoff.ContainsKey('api.github.com/enrollment') | Should -BeFalse
      $script:AccountBackoff.ContainsKey('api.github.com/123') | Should -BeTrue
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 1
    }

    It 'resolves an exact tagged release after confirming its repository is public' {
      Mock Invoke-RideGitHubAuthenticatedHttp {
        if ($Uri -eq 'https://api.github.com/user') { $json = '{"id":123}' }
        elseif ($Uri -eq 'https://api.github.com/repos/publisher/app/releases/tags/v2.17.0') { $json = '{"tag_name":"v2.17.0","assets":[]}' }
        else { $json = '{"private":false}' }
        [pscustomobject]@{ StatusCode = 200; Content = $json; Headers = @{ 'X-RateLimit-Remaining' = '4998' } }
      }
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $result=Get-RideAuthenticatedGitHubRelease 'https://api.github.com/repos/publisher/app/releases/tags/v2.17.0' public
      $result.Release.tag_name | Should -BeExactly 'v2.17.0'
      $result.Provenance.ApiUri | Should -BeExactly 'https://api.github.com/repos/publisher/app/releases/tags/v2.17.0'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 1 -ParameterFilter {$Uri -ceq 'https://api.github.com/repos/publisher/app/releases/tags/v2.17.0'}
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 1 -ParameterFilter {$Uri -ceq 'https://api.github.com/repos/publisher/app'}
    }

    It 'lists metadata without calling DPAPI resolution' {
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      Mock Get-RideGitHubCredentialContext { throw 'Must not decrypt' }
      @(Get-RideGitHubCredentialInfo).Count | Should -Be 1
      Should -Invoke Get-RideGitHubCredentialContext -Exactly 0
    }

    It 'rejects missing, corrupt and tampered credentials with sanitized errors' {
      { Get-RideGitHubCredentialContext missing } | Should -Throw '*CredentialUnavailable*'
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $path = Get-RideGitHubCredentialPath public
      $record = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
      $record.ExpiresAtUtc = $script:Now.AddDays(2).ToString('o')
      $record | ConvertTo-Json | Set-Content -LiteralPath $path
      { Get-RideGitHubCredentialContext public } | Should -Throw '*CredentialUnavailable*'
      Set-Content -LiteralPath $path -Value $script:Canary
      try { Get-RideGitHubCredentialContext public } catch { ($_ | Out-String) | Should -Not -Match $script:Canary }
    }

    It 'rejects wrong executing identity and local expiration' {
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $script:Now = $script:Now.AddHours(2)
      { Get-RideGitHubCredentialContext public } | Should -Throw '*CredentialExpired*'
      $script:Now = $script:Now.AddHours(-2)
      Mock Get-RideGitHubWindowsSid { 'S-1-5-21-1-2-3-999' }
      { Get-RideGitHubCredentialContext public } | Should -Throw
    }

    It 'rotates revision and removes enrollment without decrypting' {
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $old = (Get-Content -LiteralPath (Get-RideGitHubCredentialPath public) -Raw | ConvertFrom-Json).Revision
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(2) -Replace
      (Get-Content -LiteralPath (Get-RideGitHubCredentialPath public) -Raw | ConvertFrom-Json).Revision | Should -Not -Be $old
      Mock Get-RideGitHubCredentialContext { throw 'Must not decrypt' }
      Remove-RideGitHubCredential public -Confirm:$false
      @(Get-RideGitHubCredentialInfo).Count | Should -Be 0
    }

    It 'preserves enrollment after failed replacement' {
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $before = Get-Content -LiteralPath (Get-RideGitHubCredentialPath public) -Raw
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode = 401; Content = $script:Canary; Headers = @{} } }
      { Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(2) -Replace } | Should -Throw '*AuthenticationRejected*'
      Get-Content -LiteralPath (Get-RideGitHubCredentialPath public) -Raw | Should -Be $before
    }

    It 'rejects unsafe reference <Name>' -TestCases @(@{Name='../secret'},@{Name='a/b'},@{Name='run:abc'},@{Name='a b'}) {
      param($Name)
      { Set-RideGitHubCredential $Name -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1) } | Should -Throw '*InvalidCredentialReference*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 0
    }

    It 'rejects foreign ACL grants' {
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $path = Get-RideGitHubCredentialPath public
      $script:foreignAcl = Get-Acl -LiteralPath $path
      $script:foreignAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'), 'Read', 'Allow'))
      Mock Get-Acl { $script:foreignAcl }
      { Get-RideGitHubCredentialContext public } | Should -Throw '*UnsafeCredentialPermissions*'
    }

    It 'rejects a null DACL even though it contains no foreign allow rules' {
      Set-RideGitHubCredential public -Token $script:Secret -ExpiresAtUtc $script:Now.AddHours(1)
      $script:nullDacl = [Security.AccessControl.DirectorySecurity]::new()
      $sid = Get-RideGitHubWindowsSid
      $script:nullDacl.SetSecurityDescriptorSddlForm(('O:' + $sid + 'G:' + $sid + 'D:NO_ACCESS_CONTROL'))
      Mock Get-Acl { $script:nullDacl }
      { Get-RideGitHubCredentialContext public } | Should -Throw '*UnsafeCredentialPermissions*'
    }
  }
}

Describe 'Authenticated public release isolation and failures' {
  InModuleScope RIDE.GitHubAuthentication {
    BeforeEach {
      $script:ReleaseCache.Clear(); $script:AccountBackoff.Clear()
      $script:Now = ([datetime]'2026-10-13T12:00:00Z').ToUniversalTime()
      Mock Get-RideGitHubAuthenticationTime { $script:Now }
      Mock Get-RideGitHubCredentialContext {
        [pscustomobject]@{ WindowsSid = 'S-1'; AccountId = $(if ($Name -eq 'other') { '456' } else { '123' }); Revision = $Name; Token = ConvertTo-SecureString 'syntheticPAT_Canary_1234567890' -AsPlainText -Force }
      }
      Mock Invoke-RideGitHubAuthenticatedHttp {
        $json = if ($Uri -match '/releases/latest$') { '{"tag_name":"v1","assets":[]}' } else { '{"private":false}' }
        [pscustomobject]@{ StatusCode = 200; Content = $json; Headers = @{} }
      }
      $script:Uri = 'https://api.github.com/repos/publisher/app/releases/latest'
    }

    It 'verifies public visibility once per fresh release and returns defensive copies' {
      $first = Get-RideAuthenticatedGitHubRelease $script:Uri first
      $first.Release.tag_name = 'changed'
      $second = Get-RideAuthenticatedGitHubRelease $script:Uri first
      $second.Release.tag_name | Should -Be v1
      $second.Provenance.AcquisitionKind | Should -Be ProcessCache
      $second.Provenance.AuthenticationMode | Should -Be PAT
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 2
      $script:Now = $script:Now.AddMinutes(5)
      (Get-RideAuthenticatedGitHubRelease $script:Uri first).Provenance.AcquisitionKind | Should -Be Network
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 4
    }

    It 'isolates credential revisions even for the same account' {
      $null = Get-RideAuthenticatedGitHubRelease $script:Uri first
      (Get-RideAuthenticatedGitHubRelease $script:Uri second).Provenance.AcquisitionKind | Should -Be Network
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 4
    }

    It 'revalidates local credentials before cache use' {
      $null = Get-RideAuthenticatedGitHubRelease $script:Uri first
      Mock Get-RideGitHubCredentialContext { Stop-RideGitHubAuthentication 'CredentialExpired' }
      { Get-RideAuthenticatedGitHubRelease $script:Uri first } | Should -Throw '*CredentialExpired*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 2
    }

    It 'invalidates an externally held cache after explicit credential testing rejects authentication' {
      $shared = @{}
      $null = Get-RideAuthenticatedGitHubRelease $script:Uri first -Cache $shared
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode = 401; Content = 'syntheticPAT_Canary_1234567890'; Headers = @{} } }
      { Test-RideGitHubCredential first } | Should -Throw '*AuthenticationRejected*'
      { Get-RideAuthenticatedGitHubRelease $script:Uri first -Cache $shared } | Should -Throw '*AuthenticationRejected*'
      $shared.Count | Should -Be 0
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 4
    }

    It 'shares backoff across the same account without affecting another account or fresh cache' {
      $null = Get-RideAuthenticatedGitHubRelease $script:Uri first
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode = 429; Content = 'rate limit'; Headers = @{ 'Retry-After' = '120' } } }
      { Get-RideAuthenticatedGitHubRelease $script:Uri second } | Should -Throw '*AcquisitionDeferred*'
      { Get-RideAuthenticatedGitHubRelease ($script:Uri -replace '/app/', '/next/') first } | Should -Throw '*AcquisitionDeferred*'
      (Get-RideAuthenticatedGitHubRelease $script:Uri first).Provenance.AcquisitionKind | Should -Be ProcessCache
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 3
      { Get-RideAuthenticatedGitHubRelease $script:Uri other } | Should -Throw '*AcquisitionDeferred*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 4
      $script:Now = $script:Now.AddSeconds(121)
      { Get-RideAuthenticatedGitHubRelease $script:Uri second } | Should -Throw '*AcquisitionDeferred*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 5
    }

    It 'does not request releases when the visibility check exhausts quota' {
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode = 200; Content = '{"private":false}'; Headers = @{ 'X-RateLimit-Remaining' = '0' } } }
      { Get-RideAuthenticatedGitHubRelease $script:Uri first } | Should -Throw '*AcquisitionDeferred*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 1
    }

    It 'classifies primary and secondary 403 responses as bounded quota deferrals' -TestCases @(@{Kind='Primary'},@{Kind='Secondary'}) {
      param($Kind)
      $script:rateHeaders = if ($Kind -eq 'Primary') { @{ 'X-RateLimit-Remaining'='0'; 'X-RateLimit-Reset'=[string]([long]($script:Now.AddMinutes(10) - ([datetime]'1970-01-01Z').ToUniversalTime()).TotalSeconds) } } else { @{ 'Retry-After'='120' } }
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode=403; Content='syntheticPAT_Canary_1234567890'; Headers=$script:rateHeaders } }
      { Get-RideAuthenticatedGitHubRelease $script:Uri first } | Should -Throw '*AcquisitionDeferred*'
      { Get-RideAuthenticatedGitHubRelease $script:Uri second } | Should -Throw '*AcquisitionDeferred*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 1
      $expectedSeconds = if ($Kind -eq 'Primary') { 601 } else { 120 }
      $script:AccountBackoff['api.github.com/123'].Deadline | Should -Be $script:Now.AddSeconds($expectedSeconds)
    }

    It 'sanitizes malformed response bodies' {
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode=200; Content='{syntheticPAT_Canary_1234567890'; Headers=@{} } }
      try { Get-RideAuthenticatedGitHubRelease $script:Uri first; throw 'Expected failure' }
      catch { $_.Exception.Message | Should -Match 'InvalidResponse'; ($_ | Out-String) | Should -Not -Match 'syntheticPAT_Canary' }
    }

    It 'rejects private or absent repository visibility' -TestCases @(@{Json='{"private":true}'},@{Json='{}'},@{Json='{"private":"false"}'}) {
      param($Json)
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode = 200; Content = $Json; Headers = @{} } }
      { Get-RideAuthenticatedGitHubRelease $script:Uri first } | Should -Throw '*PublicRepositoryRequired*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 1
    }

    It 'sanitizes HTTP <Status> as <Code>' -TestCases @(@{Status=401;Code='AuthenticationRejected'},@{Status=403;Code='AccessDenied'},@{Status=404;Code='NotFound'},@{Status=302;Code='RedirectRefused'},@{Status=500;Code='HttpFailure'},@{Status=429;Code='AcquisitionDeferred'}) {
      param($Status,$Code)
      Mock Invoke-RideGitHubAuthenticatedHttp { [pscustomobject]@{ StatusCode = $Status; Content = 'syntheticPAT_Canary_1234567890'; Headers = @{} } }
      try { Get-RideAuthenticatedGitHubRelease $script:Uri first; throw 'Expected failure' }
      catch { $_.Exception.Message | Should -Match $Code; ($_ | Out-String) | Should -Not -Match 'syntheticPAT_Canary' }
      $script:ReleaseCache.Count | Should -Be 0
    }

    It 'rejects invalid destinations before resolving a secret' -TestCases @(
      @{Uri='http://api.github.com/repos/p/a/releases/latest'},@{Uri='https://api.github.com:444/repos/p/a/releases/latest'},
      @{Uri='https://secret@api.github.com/repos/p/a/releases/latest'},@{Uri='https://api.github.com/repos/p/a/releases/latest?token=secret'},
      @{Uri='https://api.github.com/repos/p/a/releases/latest#fragment'},@{Uri='https://evil.example/repos/p/a/releases/latest'},@{Uri='https://api.github.com/user'}
    ) {
      param($Uri)
      { Get-RideAuthenticatedGitHubRelease $Uri first } | Should -Throw '*InvalidEndpoint*'
      Should -Invoke Get-RideGitHubCredentialContext -Exactly 0
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 0
    }

    It 'bounds cache entries and invalidates backwards clock changes' {
      1..65 | ForEach-Object { $null = Get-RideAuthenticatedGitHubRelease ("https://api.github.com/repos/p/app$_/releases/latest") first }
      $script:ReleaseCache.Count | Should -Be 64
      $script:Now = $script:Now.AddSeconds(-1)
      $null = Get-RideAuthenticatedGitHubRelease $script:Uri first
      $script:ReleaseCache.Count | Should -Be 1
    }

    It 'refuses additional account contexts without evicting active backoff' {
      1..64 | ForEach-Object { $script:AccountBackoff["api.github.com/$_"] = @{ Deadline = $script:Now.AddHours(1); Rate = @{ Remaining = 0 } } }
      { Get-RideAuthenticatedGitHubRelease $script:Uri first } | Should -Throw '*ContextLimit*'
      Should -Invoke Invoke-RideGitHubAuthenticatedHttp -Exactly 0
      $script:AccountBackoff.Count | Should -Be 64
    }
  }
}

Describe 'Authenticated HttpClient boundary' {
  BeforeAll {
    Add-Type -AssemblyName System.Net.Http
    if (-not ('RideAuthenticationTestHandler' -as [type])) {
      Add-Type -ReferencedAssemblies @([Net.Http.HttpClient].Assembly.Location, [Net.HttpStatusCode].Assembly.Location) -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
public sealed class RideAuthenticationTestHandler : HttpMessageHandler {
  public static string Body = "{}";
  public static int Status = 200;
  public static int Calls;
  public static bool Fail;
  public static string Authorization;
  protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancel) {
    Calls++;
    Authorization = request.Headers.Authorization.ToString();
    if (Fail) throw new InvalidOperationException(Authorization);
    var response = new HttpResponseMessage((HttpStatusCode)Status);
    response.Content = new StringContent(Body);
    response.Headers.Add("X-RateLimit-Remaining", "4999");
    return Task.FromResult(response);
  }
}
'@
    }
  }
  InModuleScope RIDE.GitHubAuthentication {
    BeforeEach {
      [RideAuthenticationTestHandler]::Calls = 0
      [RideAuthenticationTestHandler]::Body = '{"id":123}'
      [RideAuthenticationTestHandler]::Status = 200
      [RideAuthenticationTestHandler]::Fail = $false
      $script:TransportToken = ConvertTo-SecureString 'syntheticTransportCanary_12345' -AsPlainText -Force
      Mock New-RideGitHubHttpClient { [Net.Http.HttpClient]::new([RideAuthenticationTestHandler]::new()) }
    }
    AfterEach { $script:TransportToken.Dispose(); [RideAuthenticationTestHandler]::Authorization = $null }
    It 'uses a request-local Bearer header and reads bounded response headers' {
      $response = Invoke-RideGitHubAuthenticatedHttp 'https://api.github.com/user' $script:TransportToken
      [RideAuthenticationTestHandler]::Calls | Should -Be 1
      [RideAuthenticationTestHandler]::Authorization | Should -Be 'Bearer syntheticTransportCanary_12345'
      $response.Headers['X-RateLimit-Remaining'] | Should -Be '4999'
      ($response | ConvertTo-Json) | Should -Not -Match 'syntheticTransportCanary'
    }
    It 'sanitizes underlying exceptions containing the credential' {
      [RideAuthenticationTestHandler]::Fail = $true
      try { Invoke-RideGitHubAuthenticatedHttp 'https://api.github.com/user' $script:TransportToken; throw 'Expected failure' }
      catch { $_.Exception.Message | Should -Match 'TransportFailure'; ($_ | Out-String) | Should -Not -Match 'syntheticTransportCanary' }
    }
    It 'rejects a body exceeding two MiB' {
      [RideAuthenticationTestHandler]::Body = 'x' * (2MB + 1)
      { Invoke-RideGitHubAuthenticatedHttp 'https://api.github.com/user' $script:TransportToken } | Should -Throw '*InvalidResponse*'
    }
    It 'refuses an unsafe destination before constructing a client' {
      { Invoke-RideGitHubAuthenticatedHttp 'https://evil.example/user' $script:TransportToken } | Should -Throw '*InvalidEndpoint*'
      Should -Invoke New-RideGitHubHttpClient -Exactly 0
    }
  }
}

Describe 'Guest credential lease binding' {
  InModuleScope RIDE.GitHubAuthentication {
    BeforeEach {
      $script:LeaseRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      Mock Get-RideGitHubCredentialPath { Join-Path (Join-Path $script:LeaseRoot $Name.Replace(':','-')) 'credential.json' }
      $script:Now = ([datetime]'2026-10-13T12:00:00Z').ToUniversalTime()
      Mock Get-RideGitHubAuthenticationTime { $script:Now }
      $script:LeaseContext = [pscustomobject]@{ Purpose='VmTest'; AccountId='123'; Revision=('c'*32); ExpiresAtUtc=$script:Now.AddHours(2); Token=ConvertTo-SecureString 'syntheticGuestToken_12345' -AsPlainText -Force }
    }
    AfterEach { $script:LeaseContext.Token.Dispose() }
    It 'seals a guest-local lease bounded by the request deadline and refuses replay' {
      $reference = New-RideGitHubGuestCredential ('a'*32) $script:LeaseContext $script:Now.AddMinutes(30)
      $context = Get-RideGitHubCredentialContext $reference
      try { $context.ExpiresAtUtc | Should -Be $script:Now.AddMinutes(30); $context.WindowsSid | Should -Be (Get-RideGitHubWindowsSid) } finally { $context.Token.Dispose() }
      { New-RideGitHubGuestCredential ('a'*32) $script:LeaseContext $script:Now.AddMinutes(30) } | Should -Throw '*AlreadyExists*'
      Remove-RideGitHubCredential $reference -Confirm:$false
      Test-RideGitHubGuestCredentialAbsent ('a'*32) | Should -BeTrue
    }
    It 'rejects a copied lease under another request ID' {
      $reference = New-RideGitHubGuestCredential ('a'*32) $script:LeaseContext $script:Now.AddMinutes(30)
      $other = Get-RideGitHubCredentialPath ('run:' + ('b'*32))
      Initialize-RideGitHubCredentialDirectory (Split-Path -Parent $other)
      Copy-Item -LiteralPath (Get-RideGitHubCredentialPath $reference) -Destination $other
      # Exercise request binding with a valid file ACL, independent of Copy-Item ownership.
      Set-RideGitHubCredentialFileAcl -Path $other
      Assert-RideGitHubPath $other -CheckAcl
      { Get-RideGitHubCredentialContext ('run:' + ('b'*32)) } | Should -Throw '*CredentialUnavailable*'
    }
    It 'rejects expired deadlines and personal credentials before writing' {
      { New-RideGitHubGuestCredential ('a'*32) $script:LeaseContext $script:Now.AddSeconds(-1) } | Should -Throw '*CredentialExpired*'
      $script:LeaseContext.Purpose = 'Interactive'
      { New-RideGitHubGuestCredential ('a'*32) $script:LeaseContext $script:Now.AddMinutes(30) } | Should -Throw '*GuestCredentialRefused*'
      Test-Path -LiteralPath $script:LeaseRoot | Should -BeFalse
    }
  }
}
