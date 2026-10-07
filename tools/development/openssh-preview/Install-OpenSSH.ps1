<#
.SYNOPSIS
Use a Windows OpenSSH client that supports the requested KEX algorithm.

.DESCRIPTION
Checks executable OpenSSH clients before installing anything. The default
requirement is the exact ML-KEM algorithm name. If no existing client meets
the requirement, Win32-OpenSSH Preview is installed as a client-only MSI
feature through winget. If the selected compatible client is not already the
one PowerShell resolves, profile wrappers are created when its ssh.exe,
scp.exe, and sftp.exe are all present.

The wrappers apply only to the PowerShell profile selected by $PROFILE for
the current user and host. Other applications may resolve SSH independently.

.PARAMETER RequiredKex
Exact KEX algorithm names. A client meets the requirement if it supports at
least one supplied name. For ML-KEM only, use the default. To accept either
SNTRUP spelling, supply both SNTRUP names.

.PARAMETER RemoveProfileWrappers
Remove this script's managed wrappers from the current $PROFILE and exit.

.NOTES
Examples:
  .\Install-OpenSSH.ps1
  .\Install-OpenSSH.ps1 -RequiredKex @('sntrup761x25519-sha512', 'sntrup761x25519-sha512@openssh.com')
  .\Install-OpenSSH.ps1 -RemoveProfileWrappers
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet(
        'mlkem768x25519-sha256',
        'sntrup761x25519-sha512',
        'sntrup761x25519-sha512@openssh.com'
    )]
    [string[]] $RequiredKex = @('mlkem768x25519-sha256'),

    [Parameter()]
    [switch] $RemoveProfileWrappers
)

$ErrorActionPreference = 'Stop'
$script:ManagedBegin = '# BEGIN ride-windows OpenSSH wrappers'
$script:ManagedEnd = '# END ride-windows OpenSSH wrappers'

function Write-Step {
    param([Parameter(Mandatory)][string] $Message)
    Write-Host "`n=== $Message ==="
}

function Get-NormalizedPath {
    param([Parameter(Mandatory)][string] $Path)

    try {
        return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path)
    } catch {
        return $null
    }
}

function Get-SshCandidates {
    $found = [System.Collections.Generic.List[string]]::new()
    $directPaths = [System.Collections.Generic.List[string]]::new()

    # Application-only lookup deliberately ignores functions and aliases such
    # as wrappers left by previous runs.
    Get-Command ssh.exe -CommandType Application -All -ErrorAction SilentlyContinue |
        ForEach-Object { if ($_.Source) { $directPaths.Add($_.Source) } }

    $whereExe = Join-Path $env:WINDIR 'System32\where.exe'
    if (Test-Path -LiteralPath $whereExe -PathType Leaf) {
        try {
            & $whereExe ssh.exe 2>$null | ForEach-Object { $directPaths.Add([string]$_) }
        } catch {
            Write-Warning "where.exe could not enumerate SSH clients: $($_.Exception.Message)"
        }
    }

    $searchRoots = @(
        (Join-Path $env:ProgramFiles 'OpenSSH'),
        $(if (${env:ProgramFiles(x86)}) { Join-Path ${env:ProgramFiles(x86)} 'OpenSSH' }),
        $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Packages' })
    ) | Where-Object { $_ }

    foreach ($path in $directPaths) {
        if ([System.IO.Path]::GetExtension($path) -ine '.exe' -or
            [System.IO.Path]::GetFileName($path) -ine 'ssh.exe') {
            continue
        }
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $resolved = Get-NormalizedPath -Path $path
            if ($resolved) { $found.Add($resolved) }
        }
    }

    foreach ($root in $searchRoots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        try {
            Get-ChildItem -LiteralPath $root -Filter ssh.exe -File -Recurse -ErrorAction SilentlyContinue |
                ForEach-Object {
                    if ($_.Extension -ieq '.exe' -and $_.Name -ieq 'ssh.exe') {
                        $resolved = Get-NormalizedPath -Path $_.FullName
                        if ($resolved) { $found.Add($resolved) }
                    }
                }
        } catch {
            Write-Warning "Could not search OpenSSH directory '$root': $($_.Exception.Message)"
        }
    }

    $found | Sort-Object -Unique
}

function Get-ExecutableProbe {
    param([Parameter(Mandatory)][string] $SshExe)

    $versionOutput = @()
    $versionExit = -1
    $kexOutput = @()
    $kexExit = -1
    $probeError = $null

    try {
        $versionOutput = @(& $SshExe -V 2>&1 | ForEach-Object { [string]$_ })
        $versionExit = $LASTEXITCODE
        $kexOutput = @(& $SshExe -Q kex 2>&1 | ForEach-Object { [string]$_ })
        $kexExit = $LASTEXITCODE
    } catch {
        $probeError = $_.Exception.Message
    }

    $kexNames = @($kexOutput | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $missing = @($RequiredKex | Where-Object { $kexNames -cnotcontains $_ })

    [pscustomobject]@{
        Path        = $SshExe
        Version     = ($versionOutput -join ' ').Trim()
        VersionExit = $versionExit
        Kex         = $kexNames
        KexExit     = $kexExit
        Supported   = ($null -eq $probeError -and $versionExit -eq 0 -and $kexExit -eq 0 -and (Test-KexRequirement -SupportedKex $kexNames -RequiredKex $RequiredKex))
        ProbeError  = $probeError
        Missing     = $missing
        ProbeOutput = (@($versionOutput) + @($kexOutput)) -join ' | '
    }
}

function Test-KexRequirement {
    param(
        [Parameter(Mandatory)][string[]] $SupportedKex,
        [Parameter(Mandatory)][string[]] $RequiredKex
    )

    foreach ($algorithm in $RequiredKex) {
        if ($SupportedKex -ccontains $algorithm) { return $true }
    }
    return $false
}

function Get-BestClient {
    param([Parameter(Mandatory)][string[]] $Candidates)

    $builtIn = Get-NormalizedPath -Path (Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe')
    $activeExecutables = @(
        Get-Command ssh.exe -CommandType Application -All -ErrorAction SilentlyContinue |
            ForEach-Object { Get-NormalizedPath -Path $_.Source } |
            Where-Object { $_ }
    )

    $results = foreach ($candidate in $Candidates) {
        $probe = Get-ExecutableProbe -SshExe $candidate
        if ($probe.VersionExit -ne 0 -or $probe.KexExit -ne 0) {
            $detail = if ($probe.ProbeError) { $probe.ProbeError } else { $probe.ProbeOutput }
            Write-Warning "SSH probe failed for '$candidate' (ssh -V exit $($probe.VersionExit), ssh -Q kex exit $($probe.KexExit)): $detail"
        }
        $probe
    }

    $sortKeys = @(
        @{ Expression = { if ($builtIn -and $_.Path -ieq $builtIn) { 0 } else { 1 } } }
        @{ Expression = { if ($activeExecutables -icontains $_.Path) { 0 } else { 1 } } }
        @{ Expression = { $_.Path.ToLowerInvariant() } }
    )
    $results | Where-Object Supported | Sort-Object -Property $sortKeys | Select-Object -First 1
}

function Get-WingetPackageState {
    param([Parameter(Mandatory)][string] $WingetPath)

    $output = @(& $WingetPath list --id Microsoft.OpenSSH.Preview --exact --source winget --disable-interactivity --accept-source-agreements 2>&1 | ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "winget list failed with exit code $exitCode. Output: $($output -join ' ')
Check that the winget source is available with 'winget source list', then rerun this script."
    }

    [pscustomobject]@{
        Installed = (($output -join "`n") -match '(?im)Microsoft\.OpenSSH\.Preview')
        Output    = $output
    }
}

function Get-ProfileBlockRegex {
    $begin = [regex]::Escape($script:ManagedBegin)
    $end = [regex]::Escape($script:ManagedEnd)
    "(?ms)^$begin\r?\n.*?^$end(?:\r?\n)?"
}

function Get-LegacyBlockRegex {
    # Migrate/remove the exact unbounded block written by earlier versions.
    '(?ms)^# Win32-OpenSSH preference block\r?\n\$OpenSshPreferredDir = ''[^''\r\n]*''\r?\n(?:function (?:ssh|scp|sftp)\s*\{[^\r\n]*\}\r?\n){3}'
}

function Get-ActiveSshExecutable {
    $command = Get-Command ssh -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $command) { return $null }

    if ($command.CommandType -eq 'Application') {
        if ([System.IO.Path]::GetExtension($command.Source) -ieq '.exe') {
            return Get-NormalizedPath -Path $command.Source
        }
        return $null
    }

    if ($command.CommandType -eq 'Alias') {
        $target = Get-Command $command.Definition -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($target -and [System.IO.Path]::GetExtension($target.Source) -ieq '.exe') {
            return Get-NormalizedPath -Path $target.Source
        }
        return $null
    }

    if ($command.CommandType -eq 'Function' -and $command.Definition -match 'OpenSshPreferredDir') {
        $directory = Get-Variable -Name OpenSshPreferredDir -ValueOnly -ErrorAction SilentlyContinue
        if ($directory) {
            return Get-NormalizedPath -Path (Join-Path $directory 'ssh.exe')
        }
    }
    return $null
}

function Get-ManagedProfileDirectory {
    param([string] $ProfilePath = $PROFILE)

    if (-not $ProfilePath -or -not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) { return $null }
    $content = [System.IO.File]::ReadAllText($ProfilePath)
    $managedBlock = [regex]::Match($content, (Get-ProfileBlockRegex))
    if (-not $managedBlock.Success) { return $null }

    $assignmentPrefix = '$OpenSshPreferredDir = '''
    $directoryLine = $managedBlock.Value -split '\r?\n' |
        Where-Object { $_.StartsWith($assignmentPrefix, [System.StringComparison]::Ordinal) } |
        Select-Object -First 1
    if (-not $directoryLine -or -not $directoryLine.EndsWith("'", [System.StringComparison]::Ordinal)) { return $null }
    $directory = $directoryLine.Substring($assignmentPrefix.Length, $directoryLine.Length - $assignmentPrefix.Length - 1).Replace("''", "'")
    try { return [System.IO.Path]::GetFullPath($directory) } catch { return $null }
}

function Remove-ManagedProfileText {
    param([AllowEmptyString()][string] $Content)
    $Content = [regex]::Replace($Content, (Get-ProfileBlockRegex), '')
    [regex]::Replace($Content, (Get-LegacyBlockRegex), '')
}

function Write-ProfileWrappers {
    param(
        [Parameter(Mandatory)][string] $ClientDirectory,
        [string] $ProfilePath = $PROFILE
    )

    foreach ($name in 'ssh.exe', 'scp.exe', 'sftp.exe') {
        $exe = Join-Path $ClientDirectory $name
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
            throw "Required wrapper executable is missing: '$exe'. No profile changes were made. Verify the winget install, then rerun the script."
        }
    }

    $profilePath = $ProfilePath
    if (-not $profilePath) { throw 'PowerShell did not provide a profile path in $PROFILE.' }
    $parent = Split-Path -Parent $profilePath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $existing = if (Test-Path -LiteralPath $profilePath -PathType Leaf) {
        [System.IO.File]::ReadAllText($profilePath)
    } else { '' }
    $unmanaged = Remove-ManagedProfileText -Content $existing

    $quotedDirectory = $ClientDirectory.Replace("'", "''")
    $block = @"
$($script:ManagedBegin)
`$OpenSshPreferredDir = '$quotedDirectory'
function ssh  { & (Join-Path `$OpenSshPreferredDir 'ssh.exe')  @args }
function scp  { & (Join-Path `$OpenSshPreferredDir 'scp.exe')  @args }
function sftp { & (Join-Path `$OpenSshPreferredDir 'sftp.exe') @args }
$($script:ManagedEnd)
"@

    $prefix = $unmanaged
    if ($prefix.Length -gt 0 -and -not $prefix.EndsWith("`n") -and -not $prefix.EndsWith("`r")) {
        $prefix += [Environment]::NewLine
    }
    $updated = $prefix + $block
    [System.IO.File]::WriteAllText($profilePath, $updated, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Updated managed ssh/scp/sftp wrappers in profile: $profilePath"
}

function Remove-ProfileWrappers {
    param([string] $ProfilePath = $PROFILE)
    $profilePath = $ProfilePath
    if (-not $profilePath -or -not (Test-Path -LiteralPath $profilePath -PathType Leaf)) {
        Write-Host 'No PowerShell profile file exists; there are no managed wrappers to remove.'
        return
    }

    $existing = [System.IO.File]::ReadAllText($profilePath)
    $updated = Remove-ManagedProfileText -Content $existing
    if ($updated -ceq $existing) {
        Write-Host "No managed OpenSSH wrappers found in $profilePath"
        return
    }
    [System.IO.File]::WriteAllText($profilePath, $updated, [System.Text.UTF8Encoding]::new($false))
    Write-Host "Removed managed OpenSSH wrappers from profile: $profilePath"
}

function Write-ClientDiagnostics {
    param([Parameter(Mandatory)][string] $SshExe)

    $quotedExe = $SshExe.Replace("'", "''")
    Write-Host 'Diagnostic example for the selected client (replace ha-host with your configured destination):'
    Write-Host "`$sshExe = '$quotedExe'"
    Write-Host '& $sshExe -V'
    Write-Host '& $sshExe -Q kex'
    Write-Host "& `$sshExe -G ha-host | Select-String '^kexalgorithms '"
    Write-Host "& `$sshExe -vvv ha-host 2>&1 | Select-String 'kex: algorithm:'"
}

if ($RemoveProfileWrappers) {
    Remove-ProfileWrappers
    return
}

Write-Step 'Finding existing ssh.exe clients'
$candidates = @(Get-SshCandidates)
if ($candidates.Count -eq 0) {
    Write-Host 'No ssh.exe executable was found in PATH or the standard OpenSSH/WinGet locations.'
} else {
    $candidates | ForEach-Object { Write-Host $_ }
}

Write-Step 'Checking actual executable KEX support'
$preferred = if ($candidates.Count -gt 0) { Get-BestClient -Candidates $candidates } else { $null }
if ($preferred) {
    Write-Host "Selected existing client: $($preferred.Path)"
    Write-Host "Version: $($preferred.Version)"
    Write-Host "Required KEX supported: $($RequiredKex -join ' OR ')"
    $builtIn = Get-NormalizedPath -Path (Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe')
    $activeSsh = Get-ActiveSshExecutable
    $profileDirectory = Get-ManagedProfileDirectory
    if (($builtIn -and $preferred.Path -ieq $builtIn) -or
        ($activeSsh -and $preferred.Path -ieq $activeSsh) -or
        ($profileDirectory -and (Split-Path -Parent $preferred.Path) -ieq $profileDirectory)) {
        Write-Host 'The selected client is already the active client or the current profile already targets it. No installation or profile changes are needed.'
    } else {
        Write-Step 'Preferring the existing compatible client in this PowerShell profile'
        Write-ProfileWrappers -ClientDirectory (Split-Path -Parent $preferred.Path)
        Write-Host 'Start a new PowerShell session for the wrappers to take effect.'
        Write-Host 'The wrappers apply only to the relevant PowerShell profile; other applications may resolve SSH independently.'
    }
    Write-ClientDiagnostics -SshExe $preferred.Path
    return
}

Write-Step 'Checking winget and installed Preview package state'
$wingetCommand = Get-Command winget.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $wingetCommand) {
    throw 'No existing ssh.exe supports the requested KEX and winget.exe was not found. Install or update a client manually, then rerun. Required exact KEX name(s): ' + ($RequiredKex -join ', ')
}

$packageState = Get-WingetPackageState -WingetPath $wingetCommand.Source
if ($packageState.Installed) {
    throw @"
Microsoft.OpenSSH.Preview is already registered with winget, but its discovered ssh.exe does not satisfy:
  $($RequiredKex -join ' OR ')
The Preview package needs an upgrade or repair. This script stopped before changing it because the package's MSI defaults to installing both Client and Server; an unattended upgrade could alter installed server features. Review the package's installed features and update it deliberately, then rerun this script.
winget output: $($packageState.Output -join ' ')
"@
}

Write-Step 'Installing Win32-OpenSSH Preview client only'
Write-Host 'The Win32-OpenSSH MSI defaults to Client and Server. Passing ADDLOCAL=Client explicitly limits this installation to the client feature.'
$installOutput = @(& $wingetCommand.Source install --id Microsoft.OpenSSH.Preview --exact --source winget --accept-source-agreements --accept-package-agreements --override 'ADDLOCAL=Client' 2>&1 | ForEach-Object { [string]$_ })
$installExit = $LASTEXITCODE
if ($installExit -ne 0) {
    throw "winget install failed with exit code $installExit. Output: $($installOutput -join ' ')
Check winget availability and package details with 'winget show --id Microsoft.OpenSSH.Preview --exact --source winget'. If winget reports the package is already installed, use its upgrade/repair path after reviewing the installed MSI features."
}

Write-Step 'Verifying installed client and KEX support'
$afterInstall = @(Get-SshCandidates)
$preferred = if ($afterInstall.Count -gt 0) { Get-BestClient -Candidates $afterInstall } else { $null }
if (-not $preferred) {
    throw "winget reported success (exit code $installExit), but no discovered ssh.exe supports $($RequiredKex -join ' OR '). Output: $($installOutput -join ' ')
Inspect winget's installation location and run 'ssh.exe -Q kex' on the installed executable before retrying."
}

$clientDirectory = Split-Path -Parent $preferred.Path
Write-ProfileWrappers -ClientDirectory $clientDirectory

Write-Step 'Completed'
Write-Host "Selected client: $($preferred.Path)"
Write-Host "Version: $($preferred.Version)"
Write-Host "Supported KEX: $($preferred.Kex -join ', ')"
Write-Host "Required KEX: $($RequiredKex -join ' OR ')"
Write-Host "Start a new PowerShell session for its profile wrappers. Remove them with: .\Install-OpenSSH.ps1 -RemoveProfileWrappers"
Write-Host 'These wrappers apply only to the relevant PowerShell profile; other applications may resolve SSH independently.'
Write-ClientDiagnostics -SshExe $preferred.Path
