<#
.SYNOPSIS
    ssh-copy-id.ps1

.Description
    PowerShell implementation of the Linux ssh-copy-id command.

.Functionality
    Copies a local SSH public key to a remote user's ~/.ssh/authorized_keys file.
    Creates ~/.ssh and authorized_keys if needed.
    Avoids duplicate key entries.
    Uses ssh.exe only; no password or private key material is stored locally.
    Sends the remote shell script through "sh -s" with LF-normalized line endings for Synology/Linux compatibility.
    Passes the public key as a safely shell-quoted argument to avoid stdin/script parsing issues.

.PARAMETER Destination
    SSH destination in the form user@host, host, or any ssh.exe-compatible destination string.

.PARAMETER Port
    SSH port. Defaults to 22.

.PARAMETER IdentityFile
    Path to the local SSH identity file or public key file.
    If a private key path is provided, ".pub" is appended automatically.

.PARAMETER DryRun
    Shows what would be used without making remote changes.

.PARAMETER Help
    Displays this help and exits without making any changes.

.EXAMPLE
    .\ssh-copy-id.ps1 user@server
    .\ssh-copy-id.ps1 user@server -IdentityFile ~/.ssh/id_ed25519.pub
    .\ssh-copy-id.ps1 user@server -Port 2222
    .\ssh-copy-id.ps1 user@server -DryRun
    .\ssh-copy-id.ps1 user@server -WhatIf

    .\ssh-copy-id.ps1 --Help

.Author
    Torsten Juul-Jensen 

.Version
    1.0.3
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidatePattern('^[^-][^`\r\n;&|<>]*$')]
    [string]$Destination,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$Port = 22,

    [Parameter()]
    [string]$IdentityFile,

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ($Help) {
    @"
Usage:
  $([IO.Path]::GetFileName($MyInvocation.MyCommand.Path)) <destination> [options]

Copies a local SSH public key to the remote user's ~/.ssh/authorized_keys file.

Options:
  -IdentityFile <path>  Public key or private key path; defaults to a detected public key.
  -Port <1-65535>       SSH port; defaults to 22.
  -DryRun               Show the selected key and target without making remote changes.
  -WhatIf               Preview the remote installation operation.
  -Help, -h, --Help     Show this help and exit.

Examples:
  $([IO.Path]::GetFileName($MyInvocation.MyCommand.Path)) user@server
  $([IO.Path]::GetFileName($MyInvocation.MyCommand.Path)) user@server -IdentityFile ~/.ssh/id_ed25519.pub
  $([IO.Path]::GetFileName($MyInvocation.MyCommand.Path)) user@server -Port 2222 -DryRun
"@ | Write-Output
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Destination)) {
    throw "Destination is required. Use --Help for usage information."
}

function Resolve-PublicKeyPath {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path
    )

    if ($Path) {
        $expandedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)

        if ($expandedPath -notmatch '\.pub$') {
            $expandedPath = "$expandedPath.pub"
        }

        if (-not (Test-Path -LiteralPath $expandedPath -PathType Leaf)) {
            throw "Public key file not found: $expandedPath"
        }

        return $expandedPath
    }

    $candidatePaths = @(
        '~/.ssh/id_ed25519.pub',
        '~/.ssh/id_ecdsa.pub',
        '~/.ssh/id_rsa.pub'
    )

    foreach ($candidatePath in $candidatePaths) {
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($candidatePath)

        if (Test-Path -LiteralPath $resolvedPath -PathType Leaf) {
            return $resolvedPath
        }
    }

    throw "No default public key found. Specify one with -IdentityFile."
}

function Test-PublicKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    $validKeyTypes = @(
        'ssh-rsa',
        'ssh-ed25519',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'sk-ssh-ed25519@openssh.com',
        'sk-ecdsa-sha2-nistp256@openssh.com'
    )

    $parts = $Key.Trim() -split '\s+'

    if ($parts.Count -lt 2) {
        throw "Invalid SSH public key format."
    }

    if ($validKeyTypes -notcontains $parts[0]) {
        throw "Unsupported or invalid SSH key type: $($parts[0])"
    }

    try {
        [Convert]::FromBase64String($parts[1]) | Out-Null
    }
    catch {
        throw "Invalid SSH public key: key body is not valid Base64."
    }
}

function ConvertTo-LfLineEndings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    return ($Text -replace "`r`n", "`n" -replace "`r", "`n")
}

function ConvertTo-ShellSingleQuotedString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    return "'" + ($Text -replace "'", "'\''") + "'"
}

if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
    throw "ssh.exe was not found in PATH. Install OpenSSH Client first."
}

$keyPath = Resolve-PublicKeyPath -Path $IdentityFile
$publicKey = (Get-Content -LiteralPath $keyPath -Raw).Trim()

Test-PublicKey -Key $publicKey

$remoteCommand = @'
umask 077

key="$1"

if [ -z "$key" ]; then
    echo "No public key received." >&2
    exit 1
fi

mkdir -p "$HOME/.ssh" || exit 1
touch "$HOME/.ssh/authorized_keys" || exit 1

chmod 700 "$HOME/.ssh" 2>/dev/null || true
chmod 600 "$HOME/.ssh/authorized_keys" 2>/dev/null || true

if grep -qxF -- "$key" "$HOME/.ssh/authorized_keys"; then
    echo "Key already exists in authorized_keys."
else
    printf "%s\n" "$key" >> "$HOME/.ssh/authorized_keys"
    echo "Key added to authorized_keys."
fi

chmod 700 "$HOME/.ssh" 2>/dev/null || true
chmod 600 "$HOME/.ssh/authorized_keys" 2>/dev/null || true
'@

$remoteCommand = ConvertTo-LfLineEndings -Text $remoteCommand
$escapedPublicKey = ConvertTo-ShellSingleQuotedString -Text $publicKey

$sshArgs = @(
    '-p', $Port,
    '--',
    $Destination,
    "sh -s -- $escapedPublicKey"
)

Write-Host "Public key: $keyPath"
Write-Host "Target:     $Destination"
Write-Host "Port:       $Port"

if ($DryRun) {
    Write-Host "Dry run enabled. No remote changes made."
    exit 0
}

if ($PSCmdlet.ShouldProcess($Destination, "Install SSH public key")) {
    $remoteCommand | & ssh.exe @sshArgs

    if ($LASTEXITCODE -ne 0) {
        throw "ssh-copy-id operation failed with exit code $LASTEXITCODE."
    }
}
