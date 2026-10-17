<#
.SYNOPSIS
  Verify optional user-bin startup blocks with isolated profiles and process-only fixtures.
.DESCRIPTION
  Uses mocked runtime discovery and directory presence. Rendered code is exercised
  only in the test process with PATH restored in finally; no persistent environment,
  real startup profile, directory provisioning or downloaded tool is changed.
.EXAMPLE
  Invoke-Pester .\tests\UserBinProfile.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Version: Repository test fixture. Native startup acceptance remains pending.
#>
BeforeAll {
  $script:RepositoryRoot=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE-ProfileSettings.psm1') -Global
  Import-Module (Join-Path $RepositoryRoot 'modules/RIDE.CatalogValidation.psm1') -Force
  $script:BinOperations=@((Get-RideCatalog).Operations | Where-Object ProfileSetting -eq UserBinPath)
  $script:Runtime=if($PSVersionTable.PSVersion.Major -eq 5){'WindowsPowerShell51'}else{'PowerShell7'}
  $script:BinOperation=$BinOperations | Where-Object ProfileRuntime -eq $Runtime
}
Describe 'User-bin candidate metadata and startup behavior' {
  It 'keeps both runtime candidates optional and outside supported targets and profiles' {
    $BinOperations.Count | Should -Be 2
    foreach($op in $BinOperations){
      $op.SupportedTargets.Count | Should -Be 0
      $op.PendingAcceptance | Should -BeTrue
      $op.Scope | Should -Be User
      $op.RequiresAdmin | Should -BeFalse
      $op.States.Count | Should -Be 2
      $op.BaselineState | Should -Be Default
      $op.UnsetState | Should -Be Default
      $op.SettingPresentation.ReferenceUris.Count | Should -Be 2
      foreach($file in Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'profiles') -Filter '*.psd1'){
        (Get-RideProfile $file.FullName).Operations.Id | Should -Not -Contain $op.Id
      }
    }
    @(Get-RideCatalogValidationErrors @{SchemaVersion=1;Operations=$BinOperations;Groups=@()}).Count | Should -Be 0
  }
  It 'rejects arbitrary states and color metadata on the user-bin renderer' {
    foreach($change in @('state','palette','baseline')){
      $op=$BinOperation.Clone();$op.States=$op.States.Clone()
      switch($change){state{$op.States.Enabled='arbitrary source'} palette{$op.NormalColorScheme='Campbell'} baseline{$op.BaselineState='Enabled'}}
      @(Get-RideCatalogValidationErrors @{SchemaVersion=1;Operations=@($op);Groups=@()}).Count | Should -BeGreaterThan 0
    }
  }
  It 'appends once while preserving existing entries for <Case>' -ForEach @(
    @{Case='normal';Initial='C:\Windows;C:\Tools'},@{Case='separator';Initial='C:\Windows;'},@{Case='empty';Initial=''}
  ) {
    InModuleScope RIDE-ProfileSettings -Parameters @{Operation=$BinOperation;Initial=$Initial} {
      param($Operation,$Initial)
      Mock Test-Path {$true}
      $before=$env:Path
      try {
        $env:Path=$Initial
        $block=Get-RideProfileSettingBlock $Operation Enabled
        $code=[scriptblock]::Create($block)
        & $code
        $bin=[IO.Path]::Combine([Environment]::GetFolderPath('UserProfile'),'bin')
        $separator=if(-not $Initial -or $Initial.EndsWith(';')){''}else{';'}
        $env:Path | Should -BeExactly ($Initial+$separator+$bin)
        & $code
        $env:Path | Should -BeExactly ($Initial+$separator+$bin)
        $block | Should -Not -Match 'SetEnvironmentVariable|New-Item|WindowsApps|ExecutionPolicy'
      } finally{$env:Path=$before}
    }
  }
  It 'preserves a normalized existing entry byte for byte for <Form>' -ForEach @(
    @{Form='case'},@{Form='slash'},@{Form='quotes'},@{Form='environment'},@{Form='dot'}
  ) {
    InModuleScope RIDE-ProfileSettings -Parameters @{Operation=$BinOperation;Form=$Form} {
      param($Operation,$Form)
      Mock Test-Path {$true}
      $before=$env:Path;$oldFixture=$env:RIDE_PROFILE_TEST_ROOT
      try {
        $root=[Environment]::GetFolderPath('UserProfile');$bin=[IO.Path]::Combine($root,'bin')
        $env:RIDE_PROFILE_TEST_ROOT=$root
        $entry=switch($Form){case{$bin.ToUpperInvariant()} slash{$bin.Replace('\','/')+'/'} quotes{'"'+$bin+'\"'} environment{'%RIDE_PROFILE_TEST_ROOT%\bin'} dot{$root+'\bin\.'}}
        $env:Path='C:\Other;'+$entry+';C:\Last';$original=$env:Path
        & ([scriptblock]::Create((Get-RideProfileSettingBlock $Operation Enabled)))
        $env:Path | Should -BeExactly $original
      } finally{$env:Path=$before;$env:RIDE_PROFILE_TEST_ROOT=$oldFixture}
    }
  }
  It 'leaves PATH unchanged when the bin directory is missing or inaccessible' {
    InModuleScope RIDE-ProfileSettings -Parameters @{Operation=$BinOperation} {
      param($Operation)
      $before=$env:Path
      try {
        $env:Path='C:\Unchanged'
        Mock Test-Path {$false}
        & ([scriptblock]::Create((Get-RideProfileSettingBlock $Operation Enabled)))
        $env:Path | Should -BeExactly 'C:\Unchanged'
        Mock Test-Path {throw 'unavailable directory'}
        {& ([scriptblock]::Create((Get-RideProfileSettingBlock $Operation Enabled)))} | Should -Not -Throw
        $env:Path | Should -BeExactly 'C:\Unchanged'
      } finally{$env:Path=$before}
    }
  }
  It 'does not perform directory inspection in a mismatched runtime or remote context' {
    InModuleScope RIDE-ProfileSettings -Parameters @{Operation=$BinOperation} {
      param($Operation)
      Mock Test-Path {throw 'must not inspect'}
      $other=$Operation.Clone();$other.ProfileRuntime=if($Operation.ProfileRuntime -eq 'PowerShell7'){'WindowsPowerShell51'}else{'PowerShell7'}
      & ([scriptblock]::Create((Get-RideProfileSettingBlock $other Enabled)))
      Mock Get-Variable {@{Remote=$true}} -ParameterFilter {$Name -eq 'PSSenderInfo'}
      & ([scriptblock]::Create((Get-RideProfileSettingBlock $Operation Enabled)))
      Should -Invoke Test-Path -Times 0 -Exactly
    }
  }
  It 'completes IDs and only declared states without runtime/profile inspection' {
    Mock Get-RideCurrentState -ModuleName RIDE.Engine {throw 'read-only completion'}
    foreach($line in @('.\ride.ps1 set powershell.powershell7-user-bin-path ','.\ride.ps1 set powershell.powershell7-user-bin-path -State ')){
      $matches=(TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText
      foreach($value in @('Enabled','Default','Baseline')){$matches | Should -Contain $value}
      $matches | Should -Not -Contain 'Recommended'
    }
    $line='.\ride.ps1 show powershell.powershell7-user-bin'
    (TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain 'powershell.powershell7-user-bin-path'
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 0 -Exactly
  }
  It 'describes startup PATH instead of color palettes in effective values' {
    InModuleScope RIDE.Engine -Parameters @{Operation=$BinOperation} {
      param($Operation)
      Get-RideProfileSettingValueText $Operation Enabled | Should -Match 'process PATH only'
      Get-RideProfileSettingValueText $Operation Default | Should -Match 'persistent PATH preserved'
    }
  }
}
Describe 'User-bin managed file ownership and recovery' {
  BeforeEach {
    $script:ProfilePath=Join-Path $TestDrive ([guid]::NewGuid().ToString('N')+'.ps1')
    InModuleScope RIDE-ProfileSettings -Parameters @{Path=$ProfilePath} {
      param($Path)
      $script:BinFixturePath=$Path
      Mock Resolve-RideProfileSettingTarget {[pscustomobject]@{Available=$true;Path=$script:BinFixturePath;OwnerSid='fixture-user'}}
    }
  }
  It 'previews, repeats and restores exact original UTF-16 bytes without changing process PATH' {
    $encoding=[Text.UnicodeEncoding]::new($false,$true)
    $original=[byte[]](@($encoding.GetPreamble())+@($encoding.GetBytes('# existing profile')))
    [IO.File]::WriteAllBytes($ProfilePath,$original)
    $pathBefore=$env:Path
    $before=Get-RideProfileSettingState $BinOperation
    $snapshot=Get-RideProfileSettingSnapshot $BinOperation $before Enabled | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    Set-RideProfileSettingState $BinOperation Enabled -WhatIf
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($ProfilePath)) | Should -BeExactly $before.FileBase64
    Set-RideProfileSettingState $BinOperation Enabled -ExpectedState $before -Confirm:$false
    $applied=Get-RideProfileSettingState $BinOperation
    $applied.State | Should -Be Enabled
    Set-RideProfileSettingState $BinOperation Enabled -Confirm:$false
    (Get-RideProfileSettingState $BinOperation).FileBase64 | Should -BeExactly $applied.FileBase64
    Restore-RideProfileSettingState $BinOperation $snapshot -Confirm:$false
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($ProfilePath)) | Should -BeExactly $before.FileBase64
    $env:Path | Should -BeExactly $pathBefore
  }
  It 'refuses known unmarked legacy writers without adopting or deleting them' {
    $legacy='$UserBinaries = Join-Path ([Environment]::GetFolderPath("USERPROFILE")) "bin"' + "`n" + '$env:Path += ";$UserBinaries"'
    [IO.File]::WriteAllText($ProfilePath,$legacy)
    $before=Get-RideProfileSettingState $BinOperation
    {Get-RideProfileSettingSnapshot $BinOperation $before Enabled} | Should -Throw '*Unmanaged UserBinaries*'
    {Set-RideProfileSettingState $BinOperation Enabled -WhatIf} | Should -Throw '*Unmanaged UserBinaries*'
    Set-RideProfileSettingState $BinOperation Default -Confirm:$false
    [IO.File]::ReadAllText($ProfilePath) | Should -BeExactly $legacy
  }
  It 'does not mistake comments or literal example text for a legacy writer' {
    [IO.File]::WriteAllText($ProfilePath,'# UserBinaries example only' + "`n" + "'`$UserBinaries'")
    Set-RideProfileSettingState $BinOperation Enabled -Confirm:$false
    (Get-RideProfileSettingState $BinOperation).State | Should -Be Enabled
  }
  It 'preserves the color block and unrelated edits through user-bin unset and restore' {
    $color=(Get-RideCatalog).Operations | Where-Object {$_.ProfileSetting -eq 'TerminalColors' -and $_.ProfileRuntime -eq $Runtime}
    Set-RideProfileSettingState $color Recommended -Confirm:$false
    $colorBlock=(Get-RideProfileSettingState $color).Block
    Set-RideProfileSettingState $BinOperation Enabled -Confirm:$false
    $snapshot=Get-RideProfileSettingSnapshot $BinOperation (Get-RideProfileSettingState $BinOperation) Default
    Set-RideProfileSettingState $BinOperation Default -Confirm:$false
    [IO.File]::AppendAllText($ProfilePath,"`r`n# operator addition")
    Restore-RideProfileSettingState $BinOperation $snapshot -Confirm:$false
    (Get-RideProfileSettingState $BinOperation).State | Should -Be Enabled
    (Get-RideProfileSettingState $color).Block | Should -BeExactly $colorBlock
    [IO.File]::ReadAllText($ProfilePath) | Should -Match '# operator addition'
  }
  It 'refuses edited managed startup code and preserves its recovery record' {
    $snapshot=Get-RideProfileSettingSnapshot $BinOperation (Get-RideProfileSettingState $BinOperation) Enabled
    Set-RideProfileSettingState $BinOperation Enabled -Confirm:$false
    $text=[IO.File]::ReadAllText($ProfilePath).Replace("'bin'","'other-bin'")
    [IO.File]::WriteAllText($ProfilePath,$text)
    {Restore-RideProfileSettingState $BinOperation $snapshot -Confirm:$false} | Should -Throw '*modified*'
    [IO.File]::ReadAllText($ProfilePath) | Should -BeExactly $text
    $snapshot.SnapshotVersion | Should -Be 1
  }
}
