<#
.SYNOPSIS
  Check explicit user-language override capture with mocked Windows providers.
.DESCRIPTION
  Covers identity/drift, absence versus failure, bounded/malformed provider data,
  selective queries, completion and exclusive export. No native International,
  registry, language installation, UI refresh, input change or logoff is performed.
.EXAMPLE
  Invoke-Pester .\tests\UserLanguageOverrides.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: Repository test fixture; native provider acceptance pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.UserLanguageInventory.psm1') -Force
  function New-OverrideContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
  }
}
Describe 'Explicit user-language override capture' {
  BeforeEach {
    $script:CaptureArgs=@{Kind=@('DisplayLanguage','DefaultInputMethod');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1}
    Mock Get-RideUserLanguageContext -ModuleName RIDE.UserLanguageInventory {New-OverrideContext}
    Mock Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory {
      param($Kind)
      if($Kind -eq 'DisplayLanguage'){[Globalization.CultureInfo]::GetCultureInfo('en-GB')}
      else{[pscustomobject]@{InputMethodTip='0406:00000406';Name='Danish';PrivateField='omit-me'}}
    }
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {throw 'Must not collect list'}
  }
  It 'captures independently selected override values without querying a language list' {
    $r=Get-RideUserLanguageOverrideInventory @CaptureArgs
    $r.Kind | Should -Be UserLanguageOverrideObservation
    ($r.Providers.Kind -join ',') | Should -BeExactly 'DisplayLanguage,DefaultInputMethod'
    ($r.Providers.Status -join ',') | Should -BeExactly 'Captured,Captured'
    ($r.Providers.Value -join ',') | Should -BeExactly 'en-GB,0406:00000406'
    ($r.Providers.OverrideState -join ',') | Should -BeExactly 'Explicit,Explicit'
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'omit-me|PrivateField'
    Should -Invoke Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory -Exactly 0
  }
  It 'queries only the requested kind, canonicalizing case without implicit selection' {
    $CaptureArgs.Kind=@('defaultinputmethod')
    $r=Get-RideUserLanguageOverrideInventory @CaptureArgs
    $r.Providers.Count | Should -Be 1
    $r.Providers[0].Kind | Should -BeExactly 'DefaultInputMethod'
    Should -Invoke Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory -Exactly 1 -ParameterFilter {$Kind -ceq 'DefaultInputMethod'}
    Should -Invoke Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory -Exactly 0 -ParameterFilter {$Kind -ceq 'DisplayLanguage'}
  }
  It 'refuses duplicate kinds and offers declared completion without providers' {
    $CaptureArgs.Kind=@('DisplayLanguage','displaylanguage')
    {Get-RideUserLanguageOverrideInventory @CaptureArgs} | Should -Throw '*only once*'
    Should -Invoke Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory -Exactly 0
    $completion=[Management.Automation.CommandCompletion]::CompleteInput('Get-RideUserLanguageOverrideInventory -Kind Dis','Get-RideUserLanguageOverrideInventory -Kind Dis'.Length,$null)
    $completion.CompletionMatches.CompletionText | Should -Contain 'DisplayLanguage'
  }
  It 'refuses <Field> mismatch before either provider' -ForEach @(
    @{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedBuild';Value='26101'},@{Field='ExpectedEditionId';Value='Enterprise'},
    @{Field='ExpectedUserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='ExpectedSessionId';Value=2}
  ) {
    $argsCopy=$CaptureArgs.Clone();$argsCopy[$Field]=$Value
    {Get-RideUserLanguageOverrideInventory @argsCopy} | Should -Throw '*target differs*'
    Should -Invoke Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory -Exactly 0
  }
  It 'refuses noninteractive and non-native execution before provider calls' {
    Mock Get-RideUserLanguageContext -ModuleName RIDE.UserLanguageInventory {$c=New-OverrideContext;$c.NativeProcess=$false;$c}
    {Get-RideUserLanguageOverrideInventory @CaptureArgs} | Should -Throw '*target differs*'
    Mock Get-RideUserLanguageContext -ModuleName RIDE.UserLanguageInventory {$c=New-OverrideContext;$c.UserInteractive=$false;$c}
    {Get-RideUserLanguageOverrideInventory @CaptureArgs} | Should -Throw '*target differs*'
    Should -Invoke Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory -Exactly 0
  }
  It 'discards the whole observation after changed <Field>' -ForEach @(
    @{Field='SessionId';Value=2},@{Field='UserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='UpdateBuildRevision';Value=2}
  ) {
    InModuleScope RIDE.UserLanguageInventory -Parameters @{Field=$Field;Value=$Value;Context=(New-OverrideContext)} {
      param($Field,$Value,$Context)
      $script:OverrideContextCalls=0;$script:DriftField=$Field;$script:DriftValue=$Value;$script:OverrideBase=$Context
      Mock Get-RideUserLanguageContext {$script:OverrideContextCalls++;$c=$script:OverrideBase.PSObject.Copy();if($script:OverrideContextCalls -gt 1){$c.($script:DriftField)=$script:DriftValue};$c}
    }
    {Get-RideUserLanguageOverrideInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'distinguishes documented absent display override from unverified no-output input semantics' {
    Mock Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory {}
    $r=Get-RideUserLanguageOverrideInventory @CaptureArgs
    ($r.Providers.Status -join ',') | Should -BeExactly 'Captured,Captured'
    ($r.Providers.ObservationState -join ',') | Should -BeExactly 'NoValueReturned,NoValueReturned'
    $r.Providers[0].OverrideState | Should -Be NotSet
    $r.Providers[1].OverrideState | Should -Be Unverified
    ($null -eq $r.Providers[1].Value) | Should -BeTrue
  }
  It 'retains an empty input string separately without inferring the first language input' {
    Mock Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory {
      param($Kind)
      if($Kind -eq 'DisplayLanguage'){[pscustomobject]@{Name='en-GB'}}else{[pscustomobject]@{InputMethodTip=''}}
    }
    $row=(Get-RideUserLanguageOverrideInventory @CaptureArgs).Providers[1]
    $row.Status | Should -Be Captured
    $row.ObservationState | Should -Be EmptyValueReturned
    $row.OverrideState | Should -Be Unverified
    ($null -eq $row.Value) | Should -BeFalse
    $row.Value | Should -BeExactly ''
  }
  It 'preserves a TSF input identity literally without assuming a KLID-only format' {
    Mock Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory {[pscustomobject]@{InputMethodTip='0409:{11111111-1111-1111-1111-111111111111}{22222222-2222-2222-2222-222222222222}'}}
    $CaptureArgs.Kind=@('DefaultInputMethod')
    $row=(Get-RideUserLanguageOverrideInventory @CaptureArgs).Providers[0]
    $row.Status | Should -Be Captured
    $row.Value | Should -BeExactly '0409:{11111111-1111-1111-1111-111111111111}{22222222-2222-2222-2222-222222222222}'
  }
  It 'keeps one provider failure independent and discards partial values/error text' {
    Mock Get-RideUserLanguageOverrideRows -ModuleName RIDE.UserLanguageInventory {
      param($Kind)
      if($Kind -eq 'DisplayLanguage'){[pscustomobject]@{Name='en-GB'};throw 'private data'}else{[pscustomobject]@{InputMethodTip='0406:00000406'}}
    }
    $r=Get-RideUserLanguageOverrideInventory @CaptureArgs
    $r.Providers[0].Status | Should -Be Unavailable
    $r.Providers[0].Value | Should -BeNullOrEmpty
    $r.Providers[0].ObservationState | Should -BeNullOrEmpty
    $r.Providers[1].Status | Should -Be Captured
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'private data'
  }
  It 'rejects malformed or excessive provider output <Case>' -ForEach @(
    @{Case='missing property';Provider='DisplayLanguage';Rows=@([pscustomobject]@{Other='en-GB'})},
    @{Case='numeric tag';Provider='DisplayLanguage';Rows=@([pscustomobject]@{Name=123})},
    @{Case='empty tag';Provider='DisplayLanguage';Rows=@([pscustomobject]@{Name=''})},
    @{Case='blank tag';Provider='DisplayLanguage';Rows=@([pscustomobject]@{Name='  '})},
    @{Case='invalid tag';Provider='DisplayLanguage';Rows=@([pscustomobject]@{Name='en_GB'})},
    @{Case='multiple rows';Provider='DisplayLanguage';Rows=@([pscustomobject]@{Name='en-GB'},[pscustomobject]@{Name='da-DK'})},
    @{Case='null TIP';Provider='DefaultInputMethod';Rows=@([pscustomobject]@{InputMethodTip=$null})},
    @{Case='control TIP';Provider='DefaultInputMethod';Rows=@([pscustomobject]@{InputMethodTip="bad`nvalue"})},
    @{Case='oversized TIP';Provider='DefaultInputMethod';Rows=@([pscustomobject]@{InputMethodTip=('x'*2049)})}
  ) {
    $CaptureArgs.Kind=@($Provider)
    InModuleScope RIDE.UserLanguageInventory -Parameters @{Rows=$Rows} {param($Rows);$script:OverrideRows=$Rows;Mock Get-RideUserLanguageOverrideRows {$script:OverrideRows}}
    $row=(Get-RideUserLanguageOverrideInventory @CaptureArgs).Providers[0]
    $row.Status | Should -Be Unavailable
    $row.Value | Should -BeNullOrEmpty
  }
}
Describe 'Override export boundaries' {
  BeforeEach {
    $script:ExportArgs=@{Kind=@('DisplayLanguage');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;OutputPath=(Join-Path $TestDrive 'overrides.json')}
    Mock Import-Module {}
    Mock Get-RideUserLanguageOverrideInventory {[pscustomobject]@{SchemaVersion=1;Kind='UserLanguageOverrideObservation';Providers=@([pscustomobject]@{Kind='DisplayLanguage';Status='Captured';ObservationState='NoValueReturned';OverrideState='NotSet';Value=$null})}}
  }
  It 'previews without querying providers or creating output' {
    & (Join-Path $Root 'tools/Export-RideUserLanguageOverrides.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideUserLanguageOverrideInventory -Exactly 0
  }
  It 'exports only the explicit selection and refuses existing evidence' {
    & (Join-Path $Root 'tools/Export-RideUserLanguageOverrides.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    Should -Invoke Get-RideUserLanguageOverrideInventory -Exactly 1 -ParameterFilter {$Kind.Count -eq 1 -and $Kind[0] -ceq 'DisplayLanguage' -and $ExpectedSessionId -eq 1}
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before|ConvertFrom-Json).Providers[0].OverrideState | Should -Be NotSet
    {& (Join-Path $Root 'tools/Export-RideUserLanguageOverrides.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly $before
  }
  It 'preserves a competing output created during collection' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'racing-overrides.json'
    Mock Get-RideUserLanguageOverrideInventory {[IO.File]::WriteAllText((Join-Path $TestDrive 'racing-overrides.json'),'other writer');[pscustomobject]@{Kind='fixture'}}
    {& (Join-Path $Root 'tools/Export-RideUserLanguageOverrides.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
  }
}
