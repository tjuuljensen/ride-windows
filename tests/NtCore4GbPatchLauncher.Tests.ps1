<#
.SYNOPSIS
  Verify fail-closed behavior for the guarded NTCore 4GB Patch launcher.
.DESCRIPTION
  Tests early validation without starting the publisher utility or modifying
  Windows state. Full target behavior requires disposable Windows VM acceptance.
.EXAMPLE
  Invoke-Pester .\tests\NtCore4GbPatchLauncher.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  No external executable is launched by this suite.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  $script:LauncherPath=Join-Path $RepositoryRoot 'tools/Invoke-Ride4GbPatch.ps1'
  function New-LauncherX86Pe {
    $bytes=New-Object byte[] 1024
    $bytes[0]=0x4d;$bytes[1]=0x5a
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x80),0,$bytes,0x3c,4)
    $bytes[0x80]=0x50;$bytes[0x81]=0x45
    $coff=0x84;$optional=$coff+20;$section=$optional+0xe0
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x14c),0,$bytes,$coff,2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]1),0,$bytes,$coff+2,2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0xe0),0,$bytes,$coff+16,2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x0102),0,$bytes,$coff+18,2)
    [Array]::Copy([BitConverter]::GetBytes([uint16]0x10b),0,$bytes,$optional,2)
    for($i=0x200;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*31) -band 0xff)}
    return ,$bytes
  }
}

Describe 'Guarded NTCore 4GB Patch launcher' {
  It 'prints its version without requiring or reading a target' {
    $version=& $LauncherPath -Version
    $version | Should -BeExactly '0.2.0'
  }

  It 'refuses an occupied backup path before reading or launching the patcher' {
    $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $root
    $tool=Join-Path $root 'inert-tool.exe'
    $target=Join-Path $root 'target.exe'
    $backup=$target+'.Backup'
    [IO.File]::WriteAllText($tool,'not an executable; collision must stop before launch')
    [IO.File]::WriteAllBytes($target,[byte[]](1,2,3,4,5,6))
    $sentinel=[Text.Encoding]::UTF8.GetBytes('preserve existing backup')
    [IO.File]::WriteAllBytes($backup,$sentinel)
    $toolHash=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash
    $targetHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    $backupHash=(Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash

    { & $LauncherPath -ToolPath $tool -TargetPath $target -ExpectedToolSha256 $toolHash -Confirm:$false } | Should -Throw '*Backup path already exists; no changes made*'
    (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash | Should -BeExactly $targetHash
    (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash | Should -BeExactly $backupHash
    @(Get-ChildItem -LiteralPath $root -Filter '*.tmp' -File).Count | Should -Be 0
  }

  It 'rejects an invalid PE target before creating an adjacent backup' {
    $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $root
    $tool=Join-Path $root 'inert-tool.exe'
    $target=Join-Path $root 'target.exe'
    [IO.File]::WriteAllText($tool,'not executed by validation')
    [IO.File]::WriteAllBytes($target,[byte[]](1,2,3,4,5,6))
    $toolHash=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash

    { & $LauncherPath -ToolPath $tool -TargetPath $target -ExpectedToolSha256 $toolHash -Confirm:$false } | Should -Throw '*not a valid MZ executable*'
    Test-Path -LiteralPath ($target+'.Backup') | Should -BeFalse
  }

  It 'keeps WhatIf read-only for a valid x86 PE target' {
    $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $root
    $tool=Join-Path $root 'inert-tool.exe'
    $target=Join-Path $root 'target.exe'
    [IO.File]::WriteAllText($tool,'not executed by WhatIf')
    [IO.File]::WriteAllBytes($target,(New-LauncherX86Pe))
    $toolHash=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash
    $targetHash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash

    & $LauncherPath -ToolPath $tool -TargetPath $target -ExpectedToolSha256 $toolHash -WhatIf | Out-Null
    (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash | Should -BeExactly $targetHash
    Test-Path -LiteralPath ($target+'.Backup') | Should -BeFalse
  }
}
