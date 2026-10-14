<#
.SYNOPSIS
  Explicit account-bound GitHub PAT credentials and public release discovery.
.DESCRIPTION
  Uses Windows CurrentUser DPAPI, restricted ACLs and a bounded authenticated
  HTTP boundary. Never discovers ambient tokens or authenticates asset requests.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Executing user's Windows profile; HTTPS access for explicit API work.
  Inputs: LocalApplicationData/RIDE/Credentials/GitHub; no environment credentials.
  Recovery: Remove enrollment locally and revoke compromised credentials at GitHub.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Explicit DPAPI credentials, bounded PAT discovery and guest leases.
#>

$ErrorActionPreference = 'Stop'
$script:ModuleVersion = '0.1.0'
$script:CredentialRootOverride = $null # Pester supplies an isolated TestDrive.
$script:ReleaseCache = @{}
$script:AccountBackoff = @{}
$script:CacheGeneration = [guid]::NewGuid().ToString('N')

function Reset-RideGitHubAuthenticationCache {
  # A scalar generation also invalidates entries held in the package module's
  # shared cache after management commands or an authentication rejection.
  $script:ReleaseCache.Clear()
  $script:CacheGeneration = [guid]::NewGuid().ToString('N')
}

function Stop-RideGitHubAuthentication {
  param([string] $Code, [string] $Detail = '')
  # Only constants and validated quota timestamps may reach this boundary.
  $exception = [InvalidOperationException]::new("GitHub ${Code}. $Detail".Trim())
  throw [Management.Automation.ErrorRecord]::new($exception, "RideGitHub.$Code", 'InvalidOperation', $null)
}

function Get-RideGitHubAuthenticationTime { [datetime]::UtcNow }
function Get-RideGitHubWindowsSid { [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }

function Get-RideGitHubCredentialRoot {
  if ($script:CredentialRootOverride) { return $script:CredentialRootOverride }
  Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE\Credentials\GitHub'
}

function Assert-RideGitHubPath {
  param([string] $Path, [switch] $CheckAcl)
  $itemPath = [IO.Path]::GetFullPath($Path)
  while ($itemPath) {
    if (Test-Path -LiteralPath $itemPath) {
      $item = Get-Item -LiteralPath $itemPath -Force
      if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-RideGitHubAuthentication 'UnsafeCredentialPath' }
    }
    $parent = Split-Path -Parent $itemPath
    if ($parent -eq $itemPath) { break }
    $itemPath = $parent
  }
  if ($CheckAcl -and (Test-Path -LiteralPath $Path)) {
    $allowed = @((Get-RideGitHubWindowsSid), 'S-1-5-18')
    $acl = Get-Acl -LiteralPath $Path
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $descriptor.DiscretionaryAcl -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { Stop-RideGitHubAuthentication 'UnsafeCredentialPermissions' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed) { Stop-RideGitHubAuthentication 'UnsafeCredentialPermissions' }
    }
  }
}

function Initialize-RideGitHubCredentialDirectory {
  param([string] $Path)
  Assert-RideGitHubPath $Path -CheckAcl
  if (-not (Test-Path -LiteralPath $Path)) {
    $null = New-Item -ItemType Directory -Path $Path -Force
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @((Get-RideGitHubWindowsSid), 'S-1-5-18')) {
      $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new((Get-RideGitHubWindowsSid)))
    Set-Acl -LiteralPath $Path -AclObject $acl
  }
  Assert-RideGitHubPath $Path -CheckAcl
}

function Get-RideGitHubCredentialPath {
  param([string] $Name)
  if ($Name -cmatch '^run:[0-9a-f]{32}$') {
    return Join-Path (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('RIDE\TransientCredentials\' + $Name.Substring(4))) 'credential.json'
  }
  if ($Name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$') { Stop-RideGitHubAuthentication 'InvalidCredentialReference' }
  Join-Path (Get-RideGitHubCredentialRoot) ($Name.ToLowerInvariant() + '.json')
}

function Protect-RideGitHubRecord {
  param($Record, [Security.SecureString] $Token)
  $pointer = [IntPtr]::Zero; $bytes = $null
  try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($plain) -or $plain.Length -gt 512 -or $plain -match '[\s\x00-\x1f]') { Stop-RideGitHubAuthentication 'InvalidCredential' }
    $inner = @{}; foreach ($key in $Record.Keys) { $inner[$key] = $Record[$key] }
    $inner.Token = $plain
    $bytes = [Text.Encoding]::UTF8.GetBytes(($inner | ConvertTo-Json -Compress))
    Add-Type -AssemblyName System.Security
    [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))
  } finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    $plain = $null; $inner = $null
  }
}

function Write-RideGitHubCredentialRecord {
  param([string] $Name, [Security.SecureString] $Token, [string] $AccountId, [datetime] $ExpiresAtUtc, [string] $Purpose, [string] $Revision = ([guid]::NewGuid().ToString('N')))
  $path = Get-RideGitHubCredentialPath $Name
  Initialize-RideGitHubCredentialDirectory (Split-Path -Parent $path)
  Assert-RideGitHubPath $path -CheckAcl
  $record = [ordered]@{ SchemaVersion = 1; Name = $Name.ToLowerInvariant(); Revision = $Revision; ExpiresAtUtc = $ExpiresAtUtc.ToUniversalTime().ToString('o'); Purpose = $Purpose; WindowsSid = Get-RideGitHubWindowsSid; AccountId = $AccountId }
  $ciphertext = Protect-RideGitHubRecord $record $Token
  $outer = [ordered]@{ SchemaVersion = 1; Name = $record.Name; Revision = $Revision; ExpiresAtUtc = $record.ExpiresAtUtc; Purpose = $Purpose; Ciphertext = $ciphertext }
  $temp = $path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
  try {
    [IO.File]::WriteAllText($temp, ($outer | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($path)) { [IO.File]::Replace($temp, $path, [NullString]::Value) }
    else { [IO.File]::Move($temp, $path) }
  } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
  Reset-RideGitHubAuthenticationCache
}

function Get-RideGitHubCredentialInfo {
  <#
  .SYNOPSIS
    List nonsecret credential references without decryption or network access.
  .DESCRIPTION
    Reads bounded enrollment metadata for the current Windows account. Fails quietly for completion.
  .EXAMPLE
    Get-RideGitHubCredentialInfo
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Name, Purpose and ExpiresAtUtc only.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. No credential material is returned.
  #>
  [CmdletBinding()] param()
  try {
    $root = Get-RideGitHubCredentialRoot
    Assert-RideGitHubPath $root -CheckAcl
    if (-not (Test-Path -LiteralPath $root)) { return }
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter '*.json' -File | Select-Object -First 256)) {
      try {
        Assert-RideGitHubPath $file.FullName -CheckAcl
        if ($file.Length -gt 16KB) { continue }
        $record = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
        if ($record.SchemaVersion -eq 1 -and $record.Name -eq $file.BaseName -and $record.Name -match '^[a-z0-9][a-z0-9_-]{0,63}$' -and $record.Purpose -in @('Interactive','VmTest')) {
          [pscustomobject]@{ Name = $record.Name; Purpose = $record.Purpose; ExpiresAtUtc = ([datetime]$record.ExpiresAtUtc).ToUniversalTime().ToString('o') }
        }
      } catch { }
    }
  } catch { }
}

function Get-RideGitHubCredentialContext {
  <#
  .SYNOPSIS
    Resolve an explicit credential under the executing account.
  .DESCRIPTION
    Internal acquisition/controller boundary. Validates ACLs, DPAPI, identity and expiry.
    The returned SecureString must never be serialized into evidence or passed to installers.
  .PARAMETER Name
    Enrollment name, or internal run:<request ID> guest lease.
  .EXAMPLE
    $context = Get-RideGitHubCredentialContext -Name public-releases
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Internal account/revision context and SecureString Token; dispose after use.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. No network access.
  #>
  [CmdletBinding()] param([Parameter(Mandatory)][string] $Name)
  $bytes = $null
  try {
    $path = Get-RideGitHubCredentialPath $Name
    Assert-RideGitHubPath (Split-Path -Parent $path) -CheckAcl
    Assert-RideGitHubPath $path -CheckAcl
    if (-not (Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).Length -gt 16KB) { Stop-RideGitHubAuthentication 'CredentialUnavailable' }
    $outer = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($outer.SchemaVersion -ne 1) { Stop-RideGitHubAuthentication 'CredentialUnavailable' }
    Add-Type -AssemblyName System.Security
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($outer.Ciphertext), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $inner = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    if ($inner.SchemaVersion -ne 1 -or $inner.Name -cne $Name.ToLowerInvariant() -or $inner.WindowsSid -ne (Get-RideGitHubWindowsSid) -or $inner.Revision -notmatch '^[0-9a-f]{32}$' -or $inner.AccountId -notmatch '^[1-9][0-9]{0,19}$' -or $inner.Purpose -notin @('Interactive','VmTest')) { Stop-RideGitHubAuthentication 'CredentialUnavailable' }
    foreach ($key in @('Name','Revision','ExpiresAtUtc','Purpose')) { if ([string]$inner.$key -cne [string]$outer.$key) { Stop-RideGitHubAuthentication 'CredentialUnavailable' } }
    $expires = ([datetime]$inner.ExpiresAtUtc).ToUniversalTime()
    if ($expires -le (Get-RideGitHubAuthenticationTime)) { Stop-RideGitHubAuthentication 'CredentialExpired' }
    [pscustomobject]@{ Name = $inner.Name; Revision = $inner.Revision; WindowsSid = $inner.WindowsSid; AccountId = $inner.AccountId; Purpose = $inner.Purpose; ExpiresAtUtc = $expires; Token = ConvertTo-SecureString -String $inner.Token -AsPlainText -Force }
  } catch {
    if ($_.FullyQualifiedErrorId -like 'RideGitHub.*') { throw }
    Stop-RideGitHubAuthentication 'CredentialUnavailable'
  } finally { if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }; $inner = $null }
}

function Assert-RideGitHubApiUri {
  param([string] $Uri)
  $endpoint = $null
  if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$endpoint) -or $endpoint.Scheme -ne 'https' -or $endpoint.Host -ne 'api.github.com' -or -not $endpoint.IsDefaultPort -or $endpoint.UserInfo -or $endpoint.Query -or $endpoint.Fragment -or $endpoint.AbsolutePath -cnotmatch '^/(user|repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/releases/latest)?)$') { Stop-RideGitHubAuthentication 'InvalidEndpoint' }
  $endpoint
}

function New-RideGitHubHttpClient {
  Add-Type -AssemblyName System.Net.Http
  $handler = [Net.Http.HttpClientHandler]::new()
  $handler.AllowAutoRedirect = $false; $handler.UseDefaultCredentials = $false; $handler.UseCookies = $false
  $client = [Net.Http.HttpClient]::new($handler)
  $client.Timeout = [timespan]::FromSeconds(120)
  $client
}

function Invoke-RideGitHubAuthenticatedHttp {
  param([string] $Uri, [Security.SecureString] $Token)
  $endpoint = Assert-RideGitHubApiUri $Uri
  $pointer = [IntPtr]::Zero; $client = $null; $request = $null; $response = $null; $stream = $null; $buffer = $null; $body = $null; $cancel = $null
  try {
    $client = New-RideGitHubHttpClient
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $endpoint)
    $request.Headers.UserAgent.ParseAdd('RIDE-Windows')
    $request.Headers.Accept.ParseAdd('application/vnd.github+json')
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrWhiteSpace($plain) -or $plain.Length -gt 512 -or $plain -match '[\s\x00-\x1f]') { Stop-RideGitHubAuthentication 'InvalidCredential' }
    $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $plain)
    $cancel = [Threading.CancellationTokenSource]::new([timespan]::FromSeconds(120))
    $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
    $headers = @{}
    foreach ($name in @('X-RateLimit-Remaining','X-RateLimit-Reset','Retry-After')) {
      if ($response.Headers.Contains($name)) { $headers[$name] = @($response.Headers.GetValues($name))[0] }
    }
    $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $body = [IO.MemoryStream]::new(); $buffer = New-Object byte[] 8192
    # Cancellation bounds body reads as well as receipt of headers on both runtimes.
    while (($count = $stream.ReadAsync($buffer, 0, $buffer.Length, $cancel.Token).GetAwaiter().GetResult()) -gt 0) {
      if ($body.Length + $count -gt 2MB) { Stop-RideGitHubAuthentication 'InvalidResponse' }
      $body.Write($buffer, 0, $count)
    }
    [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Headers = $headers; Content = [Text.Encoding]::UTF8.GetString($body.ToArray()) }
  } catch {
    if ($_.FullyQualifiedErrorId -like 'RideGitHub.*') { throw }
    Stop-RideGitHubAuthentication 'TransportFailure'
  } finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $plain = $null
    foreach ($item in @($stream, $body, $response, $request, $client, $cancel)) { if ($item) { $item.Dispose() } }
    if ($buffer) { [Array]::Clear($buffer, 0, $buffer.Length) }
  }
}

function Get-RideGitHubAuthenticationRate {
  param($Headers)
  $remaining = 0L; $reset = 0L; $retry = 0L; $resetAt = $null
  $hasRemaining = [long]::TryParse([string]$Headers['X-RateLimit-Remaining'], [ref]$remaining) -and $remaining -ge 0
  if ([long]::TryParse([string]$Headers['X-RateLimit-Reset'], [ref]$reset) -and $reset -ge 0) { try { $resetAt = ([datetime]'1970-01-01Z').ToUniversalTime().AddSeconds($reset) } catch { } }
  $hasRetry = [long]::TryParse([string]$Headers['Retry-After'], [ref]$retry) -and $retry -ge 0
  [pscustomobject]@{ Remaining = $(if ($hasRemaining) { $remaining } else { $null }); ResetAtUtc = $resetAt; RetryAfterSeconds = $(if ($hasRetry) { $retry } else { $null }) }
}

function Invoke-RideGitHubContextRequest {
  param([string] $Uri, $Context)
  $null = Assert-RideGitHubApiUri $Uri
  $now = Get-RideGitHubAuthenticationTime
  foreach ($key in @($script:AccountBackoff.Keys)) { if ($script:AccountBackoff[$key].Deadline -le $now) { $script:AccountBackoff.Remove($key) } }
  $account = 'api.github.com/' + $Context.AccountId
  $backoff = $script:AccountBackoff[$account]
  if ($backoff) { Stop-RideGitHubAuthentication 'AcquisitionDeferred' ("Retry no earlier than {0}; remaining quota: {1}." -f $backoff.Deadline.ToString('o'), $backoff.Rate.Remaining) }
  # Reserve capacity before any request; never evict another user's active deadline.
  if ($script:AccountBackoff.Count -ge 64) { Stop-RideGitHubAuthentication 'ContextLimit' }
  $response = Invoke-RideGitHubAuthenticatedHttp $Uri $Context.Token
  $now = Get-RideGitHubAuthenticationTime
  if ([Text.Encoding]::UTF8.GetByteCount([string]$response.Content) -gt 2MB) { Stop-RideGitHubAuthentication 'InvalidResponse' }
  $rate = Get-RideGitHubAuthenticationRate $response.Headers
  $limited = $response.StatusCode -eq 429 -or ($response.StatusCode -eq 403 -and ($rate.Remaining -eq 0 -or $null -ne $rate.RetryAfterSeconds -or $response.Content -match '(?i)rate limit'))
  if ($limited -or $rate.Remaining -eq 0) {
    $deadline = $now.AddSeconds(60)
    if ($rate.Remaining -eq 0 -and $rate.ResetAtUtc -ge $now) { try { $deadline = $rate.ResetAtUtc.AddSeconds(1) } catch { } }
    if ($null -ne $rate.RetryAfterSeconds) { try { $retryAt = $now.AddSeconds($rate.RetryAfterSeconds); if ($retryAt -gt $deadline) { $deadline = $retryAt } } catch { } }
    $script:AccountBackoff[$account] = @{ Deadline = $deadline; Rate = $rate }
    if ($limited) { Stop-RideGitHubAuthentication 'AcquisitionDeferred' ("Retry no earlier than {0}; remaining quota: {1}." -f $deadline.ToString('o'), $rate.Remaining) }
  }
  switch ($response.StatusCode) {
    200 { }
    401 { Reset-RideGitHubAuthenticationCache; Stop-RideGitHubAuthentication 'AuthenticationRejected' }
    403 { Stop-RideGitHubAuthentication 'AccessDenied' }
    404 { Stop-RideGitHubAuthentication 'NotFound' }
    default { if ($response.StatusCode -ge 300 -and $response.StatusCode -lt 400) { Stop-RideGitHubAuthentication 'RedirectRefused' }; Stop-RideGitHubAuthentication 'HttpFailure' }
  }
  try { $data = $response.Content | ConvertFrom-Json -ErrorAction Stop } catch { Stop-RideGitHubAuthentication 'InvalidResponse' }
  [pscustomobject]@{ Data = $data; Json = $response.Content; Rate = $rate }
}

function Set-RideGitHubCredential {
  <#
  .SYNOPSIS
    Enroll or replace an explicitly supplied PAT using CurrentUser DPAPI.
  .DESCRIPTION
    Validates identity with GitHub before writing; preview never prompts or calls GitHub.
  .PARAMETER Name
    Nonsecret enrollment reference.
  .PARAMETER Token
    SecureString; omitted values prompt securely after ShouldProcess.
  .PARAMETER ExpiresAtUtc
    Required future local cutoff matching or preceding the PAT expiry.
  .PARAMETER Purpose
    Interactive (default) or dedicated VmTest enrollment.
  .PARAMETER Replace
    Replace an existing enrollment atomically.
  .EXAMPLE
    Set-RideGitHubCredential public-releases -ExpiresAtUtc '2026-11-01Z'
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. GitHub token revocation is separate.
  #>
  [CmdletBinding(SupportsShouldProcess)] param([Parameter(Mandatory)][string] $Name, [Security.SecureString] $Token, [Parameter(Mandatory)][datetime] $ExpiresAtUtc, [ValidateSet('Interactive','VmTest')][string] $Purpose = 'Interactive', [switch] $Replace)
  if ($Name -like 'run:*') { Stop-RideGitHubAuthentication 'InvalidCredentialReference' }
  $path = Get-RideGitHubCredentialPath $Name
  if ($ExpiresAtUtc.ToUniversalTime() -le (Get-RideGitHubAuthenticationTime)) { Stop-RideGitHubAuthentication 'CredentialExpired' }
  if (-not $PSCmdlet.ShouldProcess($Name, 'Validate and store account-bound GitHub PAT')) { return }
  Assert-RideGitHubPath $path -CheckAcl
  if ((Test-Path -LiteralPath $path) -ne [bool]$Replace) { Stop-RideGitHubAuthentication 'EnrollmentConflict' }
  $prompted = -not $Token
  try {
    if ($prompted) { $Token = Read-Host 'GitHub PAT (input hidden)' -AsSecureString }
    $context = [pscustomobject]@{ AccountId = 'enrollment'; Token = $Token }
    $response = Invoke-RideGitHubContextRequest 'https://api.github.com/user' $context
    if ([string]$response.Data.id -notmatch '^[1-9][0-9]{0,19}$') { Stop-RideGitHubAuthentication 'InvalidResponse' }
    # Identity is only known after enrollment succeeds. Transfer an observed
    # exhausted quota to that user before subsequent acquisition can start.
    $enrollmentBackoff = $script:AccountBackoff['api.github.com/enrollment']
    if ($enrollmentBackoff) {
      $accountKey = 'api.github.com/' + [string]$response.Data.id
      if (-not $script:AccountBackoff[$accountKey] -or $script:AccountBackoff[$accountKey].Deadline -lt $enrollmentBackoff.Deadline) { $script:AccountBackoff[$accountKey] = $enrollmentBackoff }
      $script:AccountBackoff.Remove('api.github.com/enrollment')
    }
    Write-RideGitHubCredentialRecord $Name $Token ([string]$response.Data.id) $ExpiresAtUtc $Purpose
  } finally { if ($prompted -and $Token) { $Token.Dispose() } }
}

function Remove-RideGitHubCredential {
  <#
  .SYNOPSIS
    Remove local enrollment without revoking the PAT at GitHub.
  .DESCRIPTION
    Does not decrypt the credential. Clears local release cache after removal.
  .PARAMETER Name
    Explicit enrollment or internal guest run reference.
  .EXAMPLE
    Remove-RideGitHubCredential public-releases -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    None.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. Revoke compromised tokens at GitHub.
  #>
  [CmdletBinding(SupportsShouldProcess)] param([Parameter(Mandatory)][string] $Name)
  $path = Get-RideGitHubCredentialPath $Name
  if ($PSCmdlet.ShouldProcess($Name, 'Remove local GitHub credential')) {
    Assert-RideGitHubPath $path -CheckAcl
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    Reset-RideGitHubAuthenticationCache
  }
}

function Test-RideGitHubCredential {
  <#
  .SYNOPSIS
    Explicitly test enrolled authentication against GitHub.
  .DESCRIPTION
    Makes one identity request and checks the enrolled numeric account ID.
  .PARAMETER Name
    Enrollment reference.
  .EXAMPLE
    Test-RideGitHubCredential public-releases
  .INPUTS
    None.
  .OUTPUTS
    Boolean. True on successful identity match; otherwise a sanitized error.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. Consumes one API request.
  #>
  [CmdletBinding()] param([Parameter(Mandatory)][string] $Name)
  $context = Get-RideGitHubCredentialContext $Name
  try {
    $response = Invoke-RideGitHubContextRequest 'https://api.github.com/user' $context
    if ([string]$response.Data.id -ne $context.AccountId) { Stop-RideGitHubAuthentication 'IdentityMismatch' }
    $true
  } finally { $context.Token.Dispose() }
}

function Get-RideAuthenticatedGitHubRelease {
  <#
  .SYNOPSIS
    Resolve public release metadata using an explicitly enrolled PAT.
  .DESCRIPTION
    Checks public repository visibility, isolates revision caches and shares account backoff.
  .PARAMETER Uri
    Exact trusted latest-release API endpoint.
  .PARAMETER CredentialReference
    Enrollment or run-bound guest reference. Never a token.
  .PARAMETER Cache
    Internal shared package-module cache, keeping the aggregate metadata bound at 64.
  .EXAMPLE
    Get-RideAuthenticatedGitHubRelease https://api.github.com/repos/ip7z/7zip/releases/latest public-releases
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Release and nonsecret Provenance, compatible with anonymous discovery.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. No asset downloads or automatic retries.
  #>
  [CmdletBinding()] param([Parameter(Mandatory)][string] $Uri, [Parameter(Mandatory)][string] $CredentialReference, [hashtable] $Cache = $script:ReleaseCache)
  $endpoint = Assert-RideGitHubApiUri $Uri
  if ($endpoint.AbsolutePath -cnotmatch '/releases/latest$') { Stop-RideGitHubAuthentication 'InvalidEndpoint' }
  $context = Get-RideGitHubCredentialContext $CredentialReference
  try {
    $now = Get-RideGitHubAuthenticationTime
    foreach ($key in @($Cache.Keys)) { $entry = $Cache[$key]; if ($now -lt $entry.RetrievedAtUtc -or $now -ge $entry.ExpiresAtUtc) { $Cache.Remove($key) } }
    $key = $context.WindowsSid + '/' + $context.Revision + '/' + $endpoint.AbsoluteUri
    $entry = $Cache[$key]; $kind = 'ProcessCache'
    if ($entry -and $entry.AuthenticationGeneration -ne $script:CacheGeneration) { $Cache.Remove($key); $entry = $null }
    if (-not $entry) {
      $repository = Invoke-RideGitHubContextRequest ($endpoint.AbsoluteUri -replace '/releases/latest$', '') $context
      if ($repository.Data.private -isnot [bool] -or $repository.Data.private -ne $false) { Stop-RideGitHubAuthentication 'PublicRepositoryRequired' }
      $result = Invoke-RideGitHubContextRequest $endpoint.AbsoluteUri $context
      if (-not $result.Data.tag_name -or 'assets' -notin $result.Data.PSObject.Properties.Name) { Stop-RideGitHubAuthentication 'InvalidResponse' }
      $now = Get-RideGitHubAuthenticationTime
      $entry = @{ Json = $result.Json; Rate = $result.Rate; RetrievedAtUtc = $now; ExpiresAtUtc = $now.AddMinutes(5); AuthenticationGeneration = $script:CacheGeneration }
      if ($Cache.Count -ge 64) { $oldest = $Cache.GetEnumerator() | Sort-Object { $_.Value.RetrievedAtUtc } | Select-Object -First 1; $Cache.Remove($oldest.Key) }
      $Cache[$key] = $entry; $kind = 'Network'
    }
    [pscustomobject]@{ Release = ($entry.Json | ConvertFrom-Json); Provenance = [pscustomobject]@{
      ApiUri = $endpoint.AbsoluteUri; AcquisitionKind = $kind; AuthenticationMode = 'PAT'
      RetrievedAtUtc = $entry.RetrievedAtUtc.ToString('o'); ExpiresAtUtc = $entry.ExpiresAtUtc.ToString('o')
      RemainingQuota = $entry.Rate.Remaining; ResetAtUtc = $(if ($entry.Rate.ResetAtUtc) { $entry.Rate.ResetAtUtc.ToString('o') } else { $null })
    } }
  } catch {
    if ($_.FullyQualifiedErrorId -like 'RideGitHub.AuthenticationRejected*') {
      foreach ($cachedKey in @($Cache.Keys)) { if ($cachedKey.StartsWith($context.WindowsSid + '/' + $context.Revision + '/', [StringComparison]::Ordinal)) { $Cache.Remove($cachedKey) } }
    }
    throw
  } finally { $context.Token.Dispose() }
}

function New-RideGitHubGuestCredential {
  <#
  .SYNOPSIS
    Seal a dedicated VM test credential under the guest execution identity.
  .DESCRIPTION
    Internal encrypted-remoting entry point. Writes outside checkout, state and evidence roots.
  .PARAMETER RunId
    Correlated request ID.
  .PARAMETER Context
    Explicit VmTest context delivered through encrypted PowerShell remoting.
  .PARAMETER DeadlineUtc
    Request deadline; the earlier of this and credential expiry is enforced.
  .EXAMPLE
    New-RideGitHubGuestCredential -RunId $request.RunId -Context $context -DeadlineUtc $deadline
  .INPUTS
    None.
  .OUTPUTS
    String. Nonsecret run-bound reference.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. Caller owns finally cleanup and checkpoint reset.
  #>
  [CmdletBinding()] param([ValidatePattern('^[0-9a-f]{32}$')][string] $RunId, $Context, [datetime] $DeadlineUtc)
  if ($Context.Purpose -ne 'VmTest' -or $Context.Token -isnot [Security.SecureString] -or $Context.Revision -notmatch '^[0-9a-f]{32}$' -or $Context.AccountId -notmatch '^[1-9][0-9]{0,19}$') { Stop-RideGitHubAuthentication 'GuestCredentialRefused' }
  $expires = ([datetime]$Context.ExpiresAtUtc).ToUniversalTime()
  if ($DeadlineUtc.ToUniversalTime() -lt $expires) { $expires = $DeadlineUtc.ToUniversalTime() }
  if ($expires -le (Get-RideGitHubAuthenticationTime)) { Stop-RideGitHubAuthentication 'CredentialExpired' }
  $name = 'run:' + $RunId
  if (Test-Path -LiteralPath (Get-RideGitHubCredentialPath $name)) { Stop-RideGitHubAuthentication 'GuestCredentialAlreadyExists' }
  Write-RideGitHubCredentialRecord $name $Context.Token $Context.AccountId $expires 'VmTest' $Context.Revision
  $name
}

function Test-RideGitHubGuestCredentialAbsent {
  <#
  .SYNOPSIS
    Verify that a correlated guest credential file is absent, without decrypting it.
  .PARAMETER RunId
    Correlated request ID.
  .EXAMPLE
    Test-RideGitHubGuestCredentialAbsent -RunId $request.RunId
  .INPUTS
    None.
  .OUTPUTS
    Boolean.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. Read-only cleanup evidence.
  #>
  [CmdletBinding()] param([ValidatePattern('^[0-9a-f]{32}$')][string] $RunId)
  $path = Get-RideGitHubCredentialPath ('run:' + $RunId)
  Assert-RideGitHubPath $path
  -not (Test-Path -LiteralPath $path)
}

function Test-RideGitHubEvidence {
  <#
  .SYNOPSIS
    Scan closed evidence files without disclosing credential matches.
  .DESCRIPTION
    Checks UTF-8/UTF-16 and Base64 representations, encrypted-record markers,
    reparse points and bounded file sizes. Any incomplete read fails closed.
  .PARAMETER Path
    Literal evidence directory. No files are modified.
  .PARAMETER Token
    SecureString held by the host for this request, never printed or persisted.
  .EXAMPLE
    Test-RideGitHubEvidence -Path $results -Token $context.Token
  .INPUTS
    None.
  .OUTPUTS
    Boolean. True only when every file was scanned successfully.
  .NOTES
    Version 0.1.0; Windows PowerShell 5.1/7. Caller gates publication on this result.
  #>
  [CmdletBinding()] param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][Security.SecureString] $Token)
  $pointer = [IntPtr]::Zero
  try {
    Assert-RideGitHubPath $Path
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ([string]::IsNullOrEmpty($plain)) { return $false }
    $patterns = @($plain, [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain)), [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($plain)), [uri]::EscapeDataString($plain))
    $total = 0L; $count = 0
    $directories = [Collections.Generic.Queue[string]]::new(); $directories.Enqueue($Path)
    while ($directories.Count) {
      foreach ($item in Get-ChildItem -LiteralPath $directories.Dequeue() -Force -ErrorAction Stop) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        if ($item.PSIsContainer) { $directories.Enqueue($item.FullName); continue }
        $total += $item.Length; $count++
        if ($item.Length -gt 16MB -or $total -gt 512MB -or $count -gt 10000) { return $false }
        $stream = [IO.File]::Open($item.FullName, 'Open', 'Read', 'Read')
        try {
          $memory = [IO.MemoryStream]::new()
          try { $stream.CopyTo($memory); $bytes = $memory.ToArray() } finally { $memory.Dispose() }
        } finally { $stream.Dispose() }
        foreach ($encoding in @([Text.Encoding]::UTF8, [Text.Encoding]::Unicode, [Text.Encoding]::BigEndianUnicode)) {
          $value = $encoding.GetString($bytes)
          foreach ($pattern in $patterns) { if ($value.IndexOf($pattern, [StringComparison]::Ordinal) -ge 0) { return $false } }
          # Detect serialized credential records without mistaking source code that
          # documents/tests the record format for an exported credential.
          if ($value.TrimStart().StartsWith('{') -and $value -match '"Ciphertext"\s*:') { return $false }
        }
      }
    }
    return ($count -gt 0)
  } catch { return $false }
  finally {
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    $plain = $null; $patterns = $null; $value = $null; $bytes = $null
  }
}

Export-ModuleMember -Function Get-RideGitHubCredentialInfo, Get-RideGitHubCredentialContext, Set-RideGitHubCredential, Remove-RideGitHubCredential, Test-RideGitHubCredential, Get-RideAuthenticatedGitHubRelease, New-RideGitHubGuestCredential, Test-RideGitHubGuestCredentialAbsent, Test-RideGitHubEvidence
