<#
.SYNOPSIS
  Verify uncached portable path validation using native Windows filesystem paths.
.DESCRIPTION
  Uses inert TestDrive files and owned junctions. Missing destinations remain
  eligible, while reparse ancestors, parent-file collisions and access/I/O errors
  fail before staging. No package payload, installer, VM or system setting runs.
.EXAMPLE
  Invoke-Pester ./tests/PortablePathSafety.Tests.ps1
.NOTES
  Compatibility: Native Windows PowerShell 5.1/7, Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE-PortablePackages.psm1') -Force}
Describe 'Portable native path safety' {
  InModuleScope RIDE-PortablePackages {
    BeforeEach {
      $script:caseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $null=New-Item -ItemType Directory -Path $script:caseRoot
      $script:ownedJunction=$null
    }
    AfterEach {
      if($script:ownedJunction){
        $full=[IO.Path]::GetFullPath($script:ownedJunction)
        $expected=[IO.Path]::GetFullPath($script:caseRoot).TrimEnd('\')+'\'
        if(-not $full.StartsWith($expected,[StringComparison]::OrdinalIgnoreCase) -or -not ([IO.File]::GetAttributes($full) -band [IO.FileAttributes]::ReparsePoint)){throw 'Refusing unexpected junction cleanup.'}
        [IO.Directory]::Delete($full,$false)
      }
    }
    It 'accepts an ordinary file and missing descendant without creating anything' {
      $existing=Join-Path $script:caseRoot 'ordinary.txt';[IO.File]::WriteAllText($existing,'inert')
      Assert-RidePortablePath $existing|Should -BeExactly $existing
      $missing=Join-Path $script:caseRoot 'missing/nested/ordinary.txt'
      Assert-RidePortablePath $missing|Should -BeExactly ([IO.Path]::GetFullPath($missing))
      Test-Path -LiteralPath (Join-Path $script:caseRoot 'missing')|Should -BeFalse
    }
    It 'rejects a real junction at the selected root and above a missing descendant' {
      $target=Join-Path $script:caseRoot 'target';$null=New-Item -ItemType Directory -Path $target
      $script:ownedJunction=Join-Path $script:caseRoot 'link'
      $null=New-Item -ItemType Junction -Path $script:ownedJunction -Value $target
      {Assert-RidePortablePath $script:ownedJunction}|Should -Throw '*reparse points*'
      {Assert-RidePortablePath (Join-Path $script:ownedJunction 'missing/file.txt')}|Should -Throw '*reparse points*'
      {Get-RidePortableMemberPath $script:ownedJunction 'file.txt'}|Should -Throw '*reparse points*'
      Test-Path -LiteralPath (Join-Path $target 'file.txt')|Should -BeFalse
    }
    It 'rechecks an ordinary ancestor replaced with a junction between calls' {
      $target=Join-Path $script:caseRoot 'target';$null=New-Item -ItemType Directory -Path $target
      $script:ownedJunction=Join-Path $script:caseRoot 'replaceable';$null=New-Item -ItemType Directory -Path $script:ownedJunction
      $leaf=Join-Path $script:ownedJunction 'file.txt';$null=Assert-RidePortablePath $leaf
      [IO.Directory]::Delete($script:ownedJunction,$false)
      $null=New-Item -ItemType Junction -Path $script:ownedJunction -Value $target
      {Assert-RidePortablePath $leaf}|Should -Throw '*reparse points*'
    }
    It 'retains parent-file collision refusal' {
      [IO.File]::WriteAllText((Join-Path $script:caseRoot 'collision'),'inert')
      {Get-RidePortableMemberPath $script:caseRoot 'collision/file.txt'}|Should -Throw '*parent is a file*'
    }
    It 'propagates <Exception> instead of interpreting an unreadable path as absent' -ForEach @(
      @{Exception='UnauthorizedAccessException'},@{Exception='IOException'}
    ) {
      $script:pathFailure=if($Exception -eq 'UnauthorizedAccessException'){[UnauthorizedAccessException]::new('synthetic access denied')}else{[IO.IOException]::new('synthetic I/O failure')}
      Mock Get-RidePortablePathAttributes {throw $script:pathFailure}
      {Assert-RidePortablePath (Join-Path $script:caseRoot 'missing.txt')}|Should -Throw '*synthetic*'
      Should -Invoke Get-RidePortablePathAttributes -Exactly 1
    }
    It 'retains strict relative member validation for <Member>' -ForEach @(
      @{Member='../outside'},@{Member='a/../outside'},@{Member='file:stream'},@{Member='/rooted'},@{Member='CON.txt'},@{Member='trailing./file'},@{Member='back\slash'}
    ) {{Get-RidePortableMemberPath $script:caseRoot $Member}|Should -Throw '*Unsafe portable member*'}
  }
}
