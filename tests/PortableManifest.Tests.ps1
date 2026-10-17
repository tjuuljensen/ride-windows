<#
.SYNOPSIS
  Verify bounded portable manifest replacement and retained failure evidence.
.DESCRIPTION
  Uses isolated files and injected replacement errors. Does not acquire packages,
  execute payloads or modify installed products. Failure cases preserve staged
  evidence instead of deleting the only remaining journal after a partial replace.
.EXAMPLE
  Invoke-Pester .\tests\PortableManifest.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE-PortablePackages.psm1') -Force
}
Describe 'Portable manifest commit failures' {
  BeforeEach {
    $script:CaseRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path $CaseRoot
    Mock Start-Sleep -ModuleName RIDE-PortablePackages {}
  }
  It 'creates a new manifest without replacement or temporary remnants' {
    InModuleScope RIDE-PortablePackages -Parameters @{Root=$CaseRoot} {
      param($Root)
      Mock Invoke-RidePortableManifestReplace {throw 'Unexpected replacement'}
      Write-RidePortableManifest -Root $Root -Manifest @{Status='Installing';Files=@()}
      (Get-Content -LiteralPath (Join-Path $Root '.ride-package.json') -Raw|ConvertFrom-Json).Status | Should -Be Installing
      @(Get-ChildItem -LiteralPath $Root -Force -Filter '*.tmp').Count | Should -Be 0
      Should -Invoke Invoke-RidePortableManifestReplace -Exactly 0
    }
  }
  It 'retries unchanged files after recoverable error <Code> and commits atomically' -ForEach @(
    @{Code=32},@{Code=33},@{Code=1175}
  ) {
    InModuleScope RIDE-PortablePackages -Parameters @{Root=$CaseRoot;Code=$Code} {
      param($Root,$Code)
      $path=Join-Path $Root '.ride-package.json';[IO.File]::WriteAllText($path,'original')
      $script:ReplaceCalls=0;$script:ErrorCode=$Code
      Mock Invoke-RidePortableManifestReplace {
        $script:ReplaceCalls++
        if($script:ReplaceCalls -le 2){throw [IO.IOException]::new('Injected replacement conflict',(-2147024896+$script:ErrorCode))}
        [IO.File]::Replace($Temporary,$Destination,[NullString]::Value)
      }
      Write-RidePortableManifest -Root $Root -Manifest @{Status='Installed';Files=@()}
      (Get-Content -LiteralPath $path -Raw|ConvertFrom-Json).Status | Should -Be Installed
      $script:ReplaceCalls | Should -Be 3
      Should -Invoke Start-Sleep -Exactly 2
      @(Get-ChildItem -LiteralPath $Root -Force -Filter '*.tmp').Count | Should -Be 0
    }
  }
  It 'bounds a persistent conflict and retains both original and proposed evidence' {
    InModuleScope RIDE-PortablePackages -Parameters @{Root=$CaseRoot} {
      param($Root)
      $path=Join-Path $Root '.ride-package.json';[IO.File]::WriteAllText($path,'original')
      Mock Invoke-RidePortableManifestReplace {throw [IO.IOException]::new('Persistent conflict',-2147023721)}
      {Write-RidePortableManifest -Root $Root -Manifest @{Status='Installing';Files=@()}} | Should -Throw '*Persistent conflict*'
      Should -Invoke Invoke-RidePortableManifestReplace -Exactly 3
      Should -Invoke Start-Sleep -Exactly 2
      [IO.File]::ReadAllText($path) | Should -BeExactly original
      $staged=@(Get-ChildItem -LiteralPath $Root -Force -Filter '*.tmp')
      $staged.Count | Should -Be 1
      (Get-Content -LiteralPath $staged[0].FullName -Raw|ConvertFrom-Json).Status | Should -Be Installing
    }
  }
  It 'does not retry unrelated error <Code>' -ForEach @(@{Code=5},@{Code=87},@{Code=1176},@{Code=1177}) {
    InModuleScope RIDE-PortablePackages -Parameters @{Root=$CaseRoot;Code=$Code} {
      param($Root,$Code)
      [IO.File]::WriteAllText((Join-Path $Root '.ride-package.json'),'original')
      $script:ErrorCode=$Code
      Mock Invoke-RidePortableManifestReplace {throw [IO.IOException]::new('Do not retry',(-2147024896+$script:ErrorCode))}
      {Write-RidePortableManifest -Root $Root -Manifest @{Status='Installing'}} | Should -Throw '*Do not retry*'
      Should -Invoke Invoke-RidePortableManifestReplace -Exactly 1
      Should -Invoke Start-Sleep -Exactly 0
      @(Get-ChildItem -LiteralPath $Root -Force -Filter '*.tmp').Count | Should -Be 1
    }
  }
  It 'retains the proposed journal if a partial replacement removed the old file' {
    InModuleScope RIDE-PortablePackages -Parameters @{Root=$CaseRoot} {
      param($Root)
      $path=Join-Path $Root '.ride-package.json';[IO.File]::WriteAllText($path,'original')
      Mock Invoke-RidePortableManifestReplace {
        [IO.File]::Delete($Destination)
        throw [IO.IOException]::new('Partial replacement',-2147023720)
      }
      {Write-RidePortableManifest -Root $Root -Manifest @{Status='Installing';Files=@('fixture')}} | Should -Throw '*Partial replacement*'
      Test-Path -LiteralPath $path | Should -BeFalse
      $staged=@(Get-ChildItem -LiteralPath $Root -Force -Filter '*.tmp')
      $staged.Count | Should -Be 1
      (Get-Content -LiteralPath $staged[0].FullName -Raw|ConvertFrom-Json).Files[0] | Should -BeExactly fixture
      Should -Invoke Invoke-RidePortableManifestReplace -Exactly 1
    }
  }
  It 'refuses retry when <Target> content changes after a recoverable error' -ForEach @(
    @{Target='destination'},@{Target='staged'}
  ) {
    InModuleScope RIDE-PortablePackages -Parameters @{Root=$CaseRoot;Target=$Target} {
      param($Root,$Target)
      $path=Join-Path $Root '.ride-package.json';[IO.File]::WriteAllText($path,'original')
      $script:ChangedTarget=$Target
      Mock Invoke-RidePortableManifestReplace {
        if($script:ChangedTarget -eq 'destination'){[IO.File]::WriteAllText($Destination,'other writer')}
        else{[IO.File]::WriteAllText($Temporary,'changed staged data')}
        throw [IO.IOException]::new('Changed during conflict',-2147023721)
      }
      {Write-RidePortableManifest -Root $Root -Manifest @{Status='Installing'}} | Should -Throw '*Changed during conflict*'
      Should -Invoke Invoke-RidePortableManifestReplace -Exactly 1
      if($Target -eq 'destination'){[IO.File]::ReadAllText($path) | Should -BeExactly 'other writer'}
      else{[IO.File]::ReadAllText($path) | Should -BeExactly original}
      @(Get-ChildItem -LiteralPath $Root -Force -Filter '*.tmp').Count | Should -Be 1
    }
  }
  It 'refuses retry if a destination disappears despite a nominal recoverable code' {
    InModuleScope RIDE-PortablePackages -Parameters @{Root=$CaseRoot} {
      param($Root)
      $path=Join-Path $Root '.ride-package.json';[IO.File]::WriteAllText($path,'original')
      Mock Invoke-RidePortableManifestReplace {
        [IO.File]::Delete($Destination)
        throw [IO.IOException]::new('Missing during conflict',-2147023721)
      }
      {Write-RidePortableManifest -Root $Root -Manifest @{Status='Installing'}} | Should -Throw '*Missing during conflict*'
      Should -Invoke Invoke-RidePortableManifestReplace -Exactly 1
      Test-Path -LiteralPath $path | Should -BeFalse
      @(Get-ChildItem -LiteralPath $Root -Force -Filter '*.tmp').Count | Should -Be 1
    }
  }
}
