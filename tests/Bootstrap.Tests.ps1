<#
.SYNOPSIS
  Verify bootstrap source selection, command boundaries, argument handling and exit reporting.
.DESCRIPTION
  Uses mocked download, archive extraction and child process boundaries. It does
  not contact GitHub, elevate, install packages or change Windows state.
.EXAMPLE
  Invoke-Pester .\tests\Bootstrap.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.
#>

BeforeAll {
  $script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
  $script:BootstrapPath = Join-Path $RepositoryRoot 'docs/bootstrap.ps1'
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.Bootstrap.psm1') -Force
  function global:powershell.exe {
    $global:RideBootstrapChildArguments = @($args)
    $global:LASTEXITCODE = $global:RideBootstrapChildExitCode
  }
}

AfterAll {
  Remove-Item Function:\powershell.exe -ErrorAction SilentlyContinue
  Remove-Variable RideBootstrapChildArguments, RideBootstrapChildExitCode, RideBootstrapDownloadedUri -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Bootstrap source selection and execution boundaries' {
  BeforeEach {
    $script:InstallRoot = Join-Path $TestDrive ('bootstrap workspace ' + [guid]::NewGuid().ToString('N'))
    $script:ProfilePath = Join-Path $TestDrive 'profile directory/custom profile.psd1'
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $ProfilePath) -Force
    [IO.File]::WriteAllText($ProfilePath, '@{ Profiles = @() }')
    $global:RideBootstrapChildArguments = @()
    $global:RideBootstrapChildExitCode = 0
    $global:LASTEXITCODE = $null
    $global:RideBootstrapDownloadedUri = $null
    Mock Invoke-WebRequest {
      param($Uri, $OutFile)
      $global:RideBootstrapDownloadedUri = ([uri]$Uri).AbsoluteUri
      [IO.File]::WriteAllText($OutFile, 'synthetic archive placeholder')
    }
    Mock Expand-Archive {
      param($Path, $DestinationPath)
      $source = Join-Path $DestinationPath 'ride source with spaces'
      $null = New-Item -ItemType Directory -Path (Join-Path $source 'profiles') -Force
      [IO.File]::WriteAllText((Join-Path $source 'ride.ps1'), '# synthetic child script')
      [IO.File]::WriteAllText((Join-Path $source 'profiles/default.psd1'), '@{ Profiles = @() }')
    }
    Mock Start-Process { [pscustomobject]@{ ExitCode = 0 } }
  }

  It 'downloads only from the explicitly selected release tag' {
    $output = & $BootstrapPath -Release 'v3.0.0' -NoRun -InstallRoot $InstallRoot

    $global:RideBootstrapDownloadedUri | Should -BeExactly 'https://github.com/tjuuljensen/ride-windows/archive/refs/tags/v3.0.0.zip'
    $output | Should -Match 'No installation tasks performed'
    Should -Invoke Invoke-WebRequest -Exactly 1
    Should -Invoke Expand-Archive -Exactly 1
    Should -Invoke Start-Process -Exactly 0
    $global:RideBootstrapChildArguments.Count | Should -Be 0
  }

  It 'runs from the documented standalone layout when the matching helper is beside it' {
    $standaloneRoot = Join-Path $TestDrive 'standalone bootstrap'
    $standaloneDocs = Join-Path $standaloneRoot 'docs'
    $standaloneModules = Join-Path $standaloneRoot 'modules'
    $null = New-Item -ItemType Directory -Path $standaloneDocs, $standaloneModules -Force
    Copy-Item -LiteralPath $BootstrapPath -Destination (Join-Path $standaloneDocs 'bootstrap.ps1')
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'modules/RIDE.Bootstrap.psm1') -Destination (Join-Path $standaloneModules 'RIDE.Bootstrap.psm1')

    $output = & (Join-Path $standaloneDocs 'bootstrap.ps1') -Release 'v3.0.0' -NoRun -InstallRoot $InstallRoot

    $output | Should -Match 'No installation tasks performed'
    $global:RideBootstrapDownloadedUri | Should -BeExactly 'https://github.com/tjuuljensen/ride-windows/archive/refs/tags/v3.0.0.zip'
  }

  It 'rejects an implicit or conflicting source before download' {
    { & $BootstrapPath -NoRun -InstallRoot $InstallRoot } | Should -Throw '*Select a reviewed release tag*'
    { & $BootstrapPath -Release v3.0.0 -Branch main -NoRun -InstallRoot $InstallRoot } | Should -Throw '*Select exactly one source*'
    Should -Invoke Invoke-WebRequest -Exactly 0
  }

  It 'uses the plan default and preserves branch and profile paths containing spaces' {
    $null = & $BootstrapPath -Branch 'release/test branch' -Profile $ProfilePath -NoAdmin -InstallRoot $InstallRoot

    $global:RideBootstrapDownloadedUri | Should -BeExactly 'https://github.com/tjuuljensen/ride-windows/archive/refs/heads/release/test%20branch.zip'
    $global:RideBootstrapChildArguments[3] | Should -BeExactly '-File'
    $global:RideBootstrapChildArguments[4] | Should -Match 'ride source with spaces\\ride\.ps1$'
    $global:RideBootstrapChildArguments[5] | Should -BeExactly 'plan'
    $global:RideBootstrapChildArguments[7] | Should -BeExactly $ProfilePath
    Should -Invoke Start-Process -Exactly 0
  }

  It 'passes apply only when the operator explicitly selects it' {
    $null = & $BootstrapPath -Release v3.0.0 -Default -Command apply -NoAdmin -InstallRoot $InstallRoot

    $global:RideBootstrapChildArguments[5] | Should -BeExactly 'apply'
    Should -Invoke Start-Process -Exactly 0
  }

  It 'reports the RIDE child process exit code' {
    $global:RideBootstrapChildExitCode = 37

    { & $BootstrapPath -Release v3.0.0 -Profile $ProfilePath -Command list -NoAdmin -InstallRoot $InstallRoot } |
      Should -Throw '*ride.ps1 exited with code 37*'
  }
}

Describe 'Windows process argument quoting' {
  It 'leaves simple arguments unchanged and quotes empty arguments' {
    ConvertTo-RideWindowsCommandLineArgument 'plan' | Should -BeExactly 'plan'
    ConvertTo-RideWindowsCommandLineArgument '' | Should -BeExactly '""'
  }

  It 'doubles trailing backslashes before the closing quote' {
    $quoted = ConvertTo-RideWindowsCommandLineArgument 'C:\Program Files\RIDE\'
    $quoted | Should -BeExactly '"C:\Program Files\RIDE\\"'
  }

  It 'escapes embedded quotes and joins arguments without losing spaces' {
    ConvertTo-RideWindowsCommandLineArgument 'say "hello"' | Should -BeExactly '"say \"hello\""'
    Join-RideWindowsCommandLine @('-File', 'C:\Program Files\RIDE\ride.ps1', 'plan') |
      Should -BeExactly '-File "C:\Program Files\RIDE\ride.ps1" plan'
  }
}
