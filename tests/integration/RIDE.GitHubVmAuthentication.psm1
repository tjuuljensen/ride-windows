<#
.SYNOPSIS
  Protected controller helpers for explicit GitHub guest authentication.
.DESCRIPTION
  Resolves a dedicated credential, validates encrypted remoting and seals a
  request-bound guest lease. Evidence publication uses a scanned export directory.
.NOTES
  Compatibility: Windows PowerShell 5.1/7; disposable Windows guests only.
  Owner: RIDE-Windows maintainers. Version 0.1.0.
  Installed alongside the controller and authentication module with recorded hashes.
  Recovery: Finally cleanup and pinned checkpoint reset; GitHub revocation is separate.
#>

$ErrorActionPreference = 'Stop'
$authModule = Join-Path $PSScriptRoot 'RIDE.GitHubAuthentication.psm1'
if (-not (Test-Path -LiteralPath $authModule)) { $authModule = Join-Path $PSScriptRoot '../../modules/RIDE.GitHubAuthentication.psm1' }
Import-Module $authModule -ErrorAction Stop

function Get-RideVmGitHubContext {
  <#
  .SYNOPSIS
    Resolve the protected controller's dedicated VmTest credential.
  .PARAMETER Configuration
    Installed configuration with GitHubPatGuestV1 capability and fixed credential reference.
  .EXAMPLE
    $context = Get-RideVmGitHubContext $config
  .INPUTS
    None.
  .OUTPUTS
    Internal credential context including SecureString; caller disposes Token.
  .NOTES
    Version 0.1.0; no network or guest access. Never serialize the result.
  #>
  [CmdletBinding()] param($Configuration)
  if ($Configuration.SchemaVersion -ne 2 -or 'GitHubPatGuestV1' -notin @($Configuration.Capabilities) -or $Configuration.GuestGitHubCredentialReference -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$') { throw 'Controller lacks the configured GitHubPatGuestV1 capability.' }
  if ($Configuration.HostAccountSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) { throw 'GitHub credential execution identity differs from the registered controller.' }
  $context = Get-RideGitHubCredentialContext $Configuration.GuestGitHubCredentialReference
  if ($context.Purpose -ne 'VmTest') { $context.Token.Dispose(); throw 'Guest authentication requires a dedicated VmTest enrollment.' }
  $context
}

function Assert-RideVmGitHubSession {
  param($Session)
  if ($Session.State -ne 'Opened') { throw 'Guest credential delivery requires an open session.' }
  $connection = $Session.Runspace.ConnectionInfo
  $type = $connection.GetType().Name
  if ($type -eq 'VMConnectionInfo') { return }
  if ($type -ne 'WSManConnectionInfo' -or $connection.NoEncryption -or [string]$connection.AuthenticationMechanism -notin @('Default','Negotiate','Kerberos')) { throw 'Guest credential delivery requires PowerShell Direct or encrypted Negotiate/Kerberos WSMan.' }
}

function New-RideVmGitHubLease {
  <#
  .SYNOPSIS
    Deliver a secure credential through a verified existing guest session.
  .PARAMETER Session
    PowerShell Direct or encrypted authenticated WSMan session.
  .PARAMETER GuestPath
    Verified staged repository path.
  .PARAMETER RunId
    Correlated request ID.
  .PARAMETER Context
    Dedicated host VmTest context, never written to disk or output.
  .PARAMETER DeadlineUtc
    Request deadline, applied to the guest lease.
  .EXAMPLE
    $lease = New-RideVmGitHubLease $session $guestPath $runId $context $deadline
  .INPUTS
    None.
  .OUTPUTS
    Nonsecret guest SID and run-bound reference.
  .NOTES
    Version 0.1.0; token crosses only encrypted PowerShell argument serialization.
  #>
  [CmdletBinding()] param($Session, [string] $GuestPath, [ValidatePattern('^[0-9a-f]{32}$')][string] $RunId, $Context, [datetime] $DeadlineUtc)
  Assert-RideVmGitHubSession $Session
  try {
    Invoke-Command -Session $Session -ArgumentList @($GuestPath, $RunId, $Context, $DeadlineUtc) -ScriptBlock {
      param($Path, $Id, $CredentialContext, $Deadline)
      $ErrorActionPreference = 'Stop'
      Import-Module (Join-Path $Path 'modules/RIDE.GitHubAuthentication.psm1') -ErrorAction Stop
      $reference = New-RideGitHubGuestCredential -RunId $Id -Context $CredentialContext -DeadlineUtc $Deadline
      [pscustomobject]@{ Reference = $reference; WindowsSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    } -ErrorAction Stop
  } catch { throw 'Guest GitHub credential delivery failed; no anonymous fallback was attempted.' }
}

function Remove-RideVmGitHubLease {
  <#
  .SYNOPSIS
    Remove and verify the absence of the correlated guest credential.
  .PARAMETER Session
    Existing guest session.
  .PARAMETER GuestPath
    Verified guest checkout path.
  .PARAMETER RunId
    Request ID identifying the only credential eligible for removal.
  .EXAMPLE
    Remove-RideVmGitHubLease $session $guestPath $runId
  .INPUTS
    None.
  .OUTPUTS
    Boolean. True on verified absence; otherwise throws.
  .NOTES
    Version 0.1.0; checkpoint recovery is still required by the controller.
  #>
  [CmdletBinding()] param($Session, [string] $GuestPath, [ValidatePattern('^[0-9a-f]{32}$')][string] $RunId)
  Assert-RideVmGitHubSession $Session
  try {
    $absent = Invoke-Command -Session $Session -ArgumentList @($GuestPath, $RunId) -ScriptBlock {
      param($Path, $Id)
      Import-Module (Join-Path $Path 'modules/RIDE.GitHubAuthentication.psm1') -ErrorAction Stop
      Remove-RideGitHubCredential -Name ('run:' + $Id) -Confirm:$false
      Test-RideGitHubGuestCredentialAbsent -RunId $Id
    } -ErrorAction Stop
    if ($absent -ne $true) { throw 'Credential still present.' }
    $true
  } catch { throw 'Guest GitHub credential cleanup could not be verified.' }
}

function Publish-RideVmGitHubEvidence {
  <#
  .SYNOPSIS
    Create a scanned, hashed export of closed PAT-run evidence.
  .DESCRIPTION
    Copies only the existing workflow evidence allowlist. A failed scan leaves no
    approval marker, so CI cannot publish raw or incompletely scanned evidence.
  .PARAMETER ResultDirectory
    Correlated controller result root.
  .PARAMETER RunId
    Request ID used in the export approval marker.
  .PARAMETER Token
    Request-owned SecureString for leak detection; never written or printed.
  .PARAMETER Summary
    Final controller summary, staged before terminal result.json is published.
  .EXAMPLE
    Publish-RideVmGitHubEvidence $results $runId $context.Token
  .INPUTS
    None.
  .OUTPUTS
    None. Writes export/ and export-safety.json only after a successful scan.
  .NOTES
    Version 0.1.0; failed/incomplete scans refuse publication. No network access.
  #>
  [CmdletBinding()] param([string] $ResultDirectory, [ValidatePattern('^[0-9a-f]{32}$')][string] $RunId, [Security.SecureString] $Token, $Summary)
  $marker = Join-Path $ResultDirectory 'export-safety.json'
  if (Test-Path -LiteralPath $marker) { throw 'An evidence approval already exists for this request.' }
  $destination = Join-Path $ResultDirectory 'export'
  if (Test-Path -LiteralPath $destination) { throw 'Export destination must be new for this request.' }
  # Retained snapshots and sidecars must also be clean, even though they are not
  # on the upload allowlist. Refuse publication when any retained read is incomplete.
  if (-not (Test-RideGitHubEvidence -Path $ResultDirectory -Token $Token)) { throw 'GitHub evidence safety scan failed or was incomplete.' }
  $null = New-Item -ItemType Directory -Path $destination
  if ($Summary) { $Summary | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $destination 'result.json') -Encoding UTF8 }
  foreach ($file in Get-ChildItem -LiteralPath $ResultDirectory -Force) {
    if ($Summary -and $file.Name -eq 'result.json') { continue }
    if ($file.Name -notin @('result.json','source-files.json','guest-authentication.json','guest') -and $file.Name -notmatch '^(controller|collection).*\.log$') { continue }
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Evidence cannot traverse a reparse point.' }
    # Scan before recursive copying, including all directory descendants.
    if ($file.PSIsContainer) {
      if (-not (Test-RideGitHubEvidence -Path $file.FullName -Token $Token)) { throw 'GitHub evidence safety scan failed or was incomplete.' }
    }
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Recurse -Force
  }
  if (-not (Test-RideGitHubEvidence -Path $destination -Token $Token)) { throw 'GitHub evidence safety scan failed or was incomplete.' }
  $files = @(Get-ChildItem -LiteralPath $destination -Recurse -File | ForEach-Object { @{ Path = $_.FullName.Substring($destination.Length + 1); SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } })
  @{ SchemaVersion = 1; RunId = $RunId; AuthenticationMode = 'PAT'; SafeToExport = $true; Files = $files } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $marker -Encoding UTF8
}

function Test-RideVmGitHubExport {
  <#
  .SYNOPSIS
    Verify correlated approval and every exported file hash before publication.
  .PARAMETER ResultDirectory
    Request result root containing export-safety.json and export/.
  .PARAMETER RunId
    Expected request identity.
  .EXAMPLE
    Test-RideVmGitHubExport $results $runId
  .INPUTS
    None.
  .OUTPUTS
    Boolean. False for missing, changed, extra or unsafe evidence.
  .NOTES
    Version 0.1.0; read-only and credential-free. CI uploads only export/ after success.
  #>
  [CmdletBinding()] param([string] $ResultDirectory, [ValidatePattern('^[0-9a-f]{32}$')][string] $RunId)
  try {
    $marker = Join-Path $ResultDirectory 'export-safety.json'
    if (-not (Test-Path -LiteralPath $marker) -or (Get-Item -LiteralPath $marker).Length -gt 4MB) { return $false }
    $approval = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($approval.SchemaVersion -ne 1 -or $approval.RunId -ne $RunId -or $approval.SafeToExport -ne $true -or $approval.AuthenticationMode -ne 'PAT' -or @($approval.Files).Count -lt 1) { return $false }
    $root = Join-Path $ResultDirectory 'export'
    $expected = @{}
    foreach ($file in $approval.Files) {
      if (-not $file.Path -or [IO.Path]::IsPathRooted($file.Path) -or $file.Path -match '(^|[\\/])\.\.?([\\/]|$)|[:\x00-\x1f]' -or $file.SHA256 -notmatch '^[0-9A-Fa-f]{64}$' -or $expected.ContainsKey($file.Path)) { return $false }
      $expected[$file.Path] = $file.SHA256
    }
    $queue = [Collections.Generic.Queue[string]]::new(); $queue.Enqueue($root)
    while ($queue.Count) {
      $directory = $queue.Dequeue()
      if ((Get-Item -LiteralPath $directory).Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
      foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
        if ($item.PSIsContainer) { $queue.Enqueue($item.FullName); continue }
        $relative = $item.FullName.Substring($root.Length + 1)
        if (-not $expected.ContainsKey($relative) -or (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) { return $false }
        $expected.Remove($relative)
      }
    }
    $expected.Count -eq 0
  } catch { $false }
}

Export-ModuleMember -Function Get-RideVmGitHubContext, New-RideVmGitHubLease, Remove-RideVmGitHubLease, Publish-RideVmGitHubEvidence, Test-RideVmGitHubExport
