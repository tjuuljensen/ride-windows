<#
.SYNOPSIS
  Enroll, test, list or remove an explicit Windows-protected GitHub PAT.
.DESCRIPTION
  Stores CurrentUser DPAPI credentials outside the checkout. Anonymous RIDE
  behavior is unchanged. Add/Replace prompt securely unless Token is supplied.
.PARAMETER Action
  Add, Replace, List, Test or Remove; defaults to List.
.PARAMETER Name
  Nonsecret enrollment name; Tab reads only local enrollment metadata.
.PARAMETER Token
  Optional SecureString from calling PowerShell code. Never pass plaintext tokens.
.PARAMETER ExpiresAtUtc
  Required future local cutoff for Add/Replace; cannot prove GitHub's expiry.
.PARAMETER Purpose
  Interactive (default) or a dedicated VmTest credential.
.PARAMETER Version
  Display the script version without accessing credentials.
.EXAMPLE
  .\tools\Manage-RideGitHubCredential.ps1 Add -Name public-releases -ExpiresAtUtc '2026-11-01T00:00:00Z'
.EXAMPLE
  .\tools\Manage-RideGitHubCredential.ps1 List
.INPUTS
  None.
.OUTPUTS
  Nonsecret enrollment metadata for List; Boolean for Test.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Executing user's profile; Add/Replace/Test require HTTPS GitHub access.
  File inputs: LocalApplicationData/RIDE/Credentials/GitHub. No ambient tokens.
  Recovery: Remove local enrollment and revoke exposed tokens at GitHub separately.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Explicit secure enrollment with preview and metadata completion.
.LINK
  ../docs/github-release-discovery.md
#>

[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Position = 0)][ValidateSet('Add','Replace','List','Test','Remove')][string] $Action = 'List',
  [ArgumentCompleter({
    param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
    try {
      $path = $commandAst.CommandElements[0].Value
      if (-not (Test-Path -LiteralPath $path)) { $path = (Get-Command $commandName -CommandType ExternalScript).Source }
      Import-Module (Join-Path (Split-Path -Parent $path) '../modules/RIDE.GitHubAuthentication.psm1') -ErrorAction Stop
      Get-RideGitHubCredentialInfo | Where-Object { $_.Name.StartsWith([string]$wordToComplete, [StringComparison]::OrdinalIgnoreCase) } | Sort-Object Name -Unique | ForEach-Object { [Management.Automation.CompletionResult]::new($_.Name, $_.Name, 'ParameterValue', $_.Name) }
    } catch { }
  })][string] $Name,
  [Security.SecureString] $Token,
  [datetime] $ExpiresAtUtc,
  [ValidateSet('Interactive','VmTest')][string] $Purpose = 'Interactive',
  [switch] $Version
)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.GitHubAuthentication.psm1') -ErrorAction Stop
if ($Action -eq 'List') { Get-RideGitHubCredentialInfo; return }
if (-not $Name) { throw '-Name is required.' }
if ($Action -in @('Add','Replace') -and -not $PSBoundParameters.ContainsKey('ExpiresAtUtc')) { throw '-ExpiresAtUtc is required.' }
if (-not $PSCmdlet.ShouldProcess($Name, "$Action GitHub credential")) { return }
switch ($Action) {
  { $_ -in @('Add','Replace') } { Set-RideGitHubCredential -Name $Name -Token $Token -ExpiresAtUtc $ExpiresAtUtc -Purpose $Purpose -Replace:($Action -eq 'Replace') -Confirm:$false }
  'Test' { Test-RideGitHubCredential -Name $Name }
  'Remove' { Remove-RideGitHubCredential -Name $Name -Confirm:$false }
}
