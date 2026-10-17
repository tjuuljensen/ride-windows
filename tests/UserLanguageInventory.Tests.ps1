<#
.SYNOPSIS
  Verify ordered user language observations using mocked providers.
.DESCRIPTION
  Covers intended-user guards, ordered input-method preservation, incomplete fields,
  bounded failures, saved lookup/completion and exclusive JSON export. No Windows
  International provider, live identity, registry, language pack or setter is used.
.EXAMPLE
  Invoke-Pester .\tests\UserLanguageInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native acceptance pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.UserLanguageInventory.psm1') -Force
  function New-LanguageContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
  }
  function New-LanguageRow {
    [pscustomobject]@{LanguageTag='en-GB';InputMethodTips=@('0809:00000809','0406:00000406');Handwriting=$false;Spellchecking=$true}
  }
  function New-LanguageObservation {
    [pscustomobject]@{
      SchemaVersion=1;Kind='UserLanguageObservation';Status='Captured';WindowsContext=New-LanguageContext
      Coverage='Fixture language list';ReadyForMutation=$false;RecoverySupported=$false
      Languages=@([pscustomobject]@{Position=0;LanguageTag='en-GB';IdentityStatus='Identified';InputMethodTips=@('0809:00000809','0406:00000406');Handwriting=$false;Spellchecking=$true;Selected=$false})
    }
  }
}
Describe 'Read-only language capture' {
  BeforeEach {
    $script:CaptureArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1}
    Mock Get-RideUserLanguageContext -ModuleName RIDE.UserLanguageInventory {New-LanguageContext}
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {New-LanguageRow}
  }
  It 'preserves language and input-method order without picking a default or rebuilding the list' {
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {
      $a=New-LanguageRow;$a.LanguageTag='fr-FR';$a.InputMethodTips=@('040c:0000040c');$a
      New-LanguageRow
    }
    $r=Get-RideUserLanguageInventory @CaptureArgs
    $r.Status | Should -Be Captured
    ($r.Languages.LanguageTag -join ',') | Should -BeExactly 'fr-FR,en-GB'
    ($r.Languages.Position -join ',') | Should -BeExactly '0,1'
    ($r.Languages[1].InputMethodTips -join ',') | Should -BeExactly '0809:00000809,0406:00000406'
    $r.Languages[1].Handwriting | Should -BeFalse
    $r.Languages[1].Spellchecking | Should -BeTrue
    $r.Languages[1].Selected | Should -BeFalse
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
  }
  It 'refuses <Field> mismatch before querying the language provider' -ForEach @(
    @{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedBuild';Value='26101'},
    @{Field='ExpectedEditionId';Value='Enterprise'},@{Field='ExpectedUserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='ExpectedSessionId';Value=2}
  ) {
    $argsCopy=$CaptureArgs.Clone();$argsCopy[$Field]=$Value
    {Get-RideUserLanguageInventory @argsCopy} | Should -Throw '*target differs*'
    Should -Invoke Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory -Exactly 0
  }
  It 'refuses noninteractive or non-native execution' {
    Mock Get-RideUserLanguageContext -ModuleName RIDE.UserLanguageInventory {$c=New-LanguageContext;$c.UserInteractive=$false;$c}
    {Get-RideUserLanguageInventory @CaptureArgs} | Should -Throw '*target differs*'
    Mock Get-RideUserLanguageContext -ModuleName RIDE.UserLanguageInventory {$c=New-LanguageContext;$c.NativeProcess=$false;$c}
    {Get-RideUserLanguageInventory @CaptureArgs} | Should -Throw '*target differs*'
    Should -Invoke Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory -Exactly 0
  }
  It 'rejects changed user/session after collection' {
    InModuleScope RIDE.UserLanguageInventory {$script:ContextCalls=0}
    Mock Get-RideUserLanguageContext -ModuleName RIDE.UserLanguageInventory {$script:ContextCalls++;$c=New-LanguageContext;$c.SessionId=$script:ContextCalls;$c}
    {Get-RideUserLanguageInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'keeps missing identity and metadata distinct from empty collections and false' {
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {
      $a=New-LanguageRow;$a.LanguageTag=$null;$a.InputMethodTips=$null;$a.Handwriting=$null;$a.Spellchecking=$null;$a
      $b=New-LanguageRow;$b.InputMethodTips=@();$b
    }
    $r=Get-RideUserLanguageInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Languages[0].IdentityStatus | Should -Be Unavailable
    $r.Languages[0].Handwriting | Should -BeNullOrEmpty
    ($null -eq $r.Languages[0].InputMethodTips) | Should -BeTrue
    ($null -eq $r.Languages[1].InputMethodTips) | Should -BeFalse
    $r.Languages[1].InputMethodTips.Count | Should -Be 0
  }
  It 'preserves literal TSF and duplicate input strings without interpreting or dropping them' {
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {$r=New-LanguageRow;$r.InputMethodTips=@('0409:{11111111-1111-1111-1111-111111111111}{22222222-2222-2222-2222-222222222222}','0406:00000406','0406:00000406');$r}
    $r=Get-RideUserLanguageInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Languages[0].InputMethodTips.Count | Should -Be 3
    $r.Languages[0].InputMethodTips[0] | Should -Match '^0409:\{'
  }
  It 'distinguishes empty completion from partial provider failure and hides error text' {
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {}
    $r=Get-RideUserLanguageInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Languages.Count | Should -Be 0
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {New-LanguageRow;throw 'private provider error'}
    $r=Get-RideUserLanguageInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Languages | Should -BeNullOrEmpty
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'private provider error'
  }
  It 'refuses case-insensitive duplicate language tags' {
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {New-LanguageRow;$r=New-LanguageRow;$r.LanguageTag='EN-gb';$r}
    (Get-RideUserLanguageInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'rejects malformed <Field> metadata' -ForEach @(
    @{Field='LanguageTag';Value='en_GB'},@{Field='LanguageTag';Value=123},
    @{Field='InputMethodTips';Value='0406:00000406'},@{Field='InputMethodTips';Value=@("bad`nvalue")},
    @{Field='InputMethodTips';Value=@($null)},@{Field='InputMethodTips';Value=@(('x'*2049))},
    @{Field='InputMethodTips';Value=@(1..129|ForEach-Object {'0406:00000406'})},
    @{Field='Handwriting';Value='false'},@{Field='Spellchecking';Value=2}
  ) {
    $invalid=New-LanguageRow;$invalid.$Field=$Value
    InModuleScope RIDE.UserLanguageInventory -Parameters @{Invalid=$invalid} {
      param($Invalid)
      $script:InvalidRow=$Invalid;Mock Get-RideUserLanguageRows {$script:InvalidRow}
    }
    (Get-RideUserLanguageInventory @CaptureArgs).Status | Should -Be Unavailable
  }
  It 'bounds unidentified rows at 128' {
    Mock Get-RideUserLanguageRows -ModuleName RIDE.UserLanguageInventory {1..129|ForEach-Object {$r=New-LanguageRow;$r.LanguageTag=$null;$r}}
    (Get-RideUserLanguageInventory @CaptureArgs).Status | Should -Be Unavailable
  }
}
Describe 'Saved language lookup and completion' {
  It 'matches tags case-insensitively after JSON serialization without using display names' {
    $saved=New-LanguageObservation|ConvertTo-Json -Depth 8|ConvertFrom-Json
    (Find-RideUserLanguageObservation $saved 'EN-gb').Status | Should -Be Observed
    (Find-RideUserLanguageObservation $saved 'da-DK').Status | Should -Be NotObserved
    {Find-RideUserLanguageObservation $saved 'English (UK)'} | Should -Throw '*tag*'
    $saved.Status='Unavailable';$saved.Languages=$null
    (Find-RideUserLanguageObservation $saved 'en-GB').Status | Should -Be Unavailable
  }
  It 'rejects saved order drift, duplicate identity, partial failure rows and schema changes' {
    $saved=New-LanguageObservation;$saved.Languages[0].Position=1
    {Find-RideUserLanguageObservation $saved 'en-GB'} | Should -Throw '*order*'
    $saved=New-LanguageObservation;$second=New-LanguageObservation;$second.Languages[0].Position=1;$saved.Languages+=$second.Languages
    {Find-RideUserLanguageObservation $saved 'en-GB'} | Should -Throw '*duplicate*'
    $saved=New-LanguageObservation;$saved.Status='Unavailable'
    {Find-RideUserLanguageObservation $saved 'en-GB'} | Should -Throw '*cannot contain rows*'
    $saved=New-LanguageObservation;$saved.SchemaVersion=2
    {Find-RideUserLanguageObservation $saved 'en-GB'} | Should -Throw '*schema*'
  }
  It 'completes only saved identified tags, filtered and deduplicated' {
    $saved=New-LanguageObservation;$saved.Languages+=@($saved.Languages[0],[pscustomobject]@{LanguageTag='da-DK';IdentityStatus='Unavailable'})
    $attr=(Get-Command Find-RideUserLanguageObservation).Parameters.LanguageTag.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 'EN' $null @{Inventory=$saved})
    $matches.Count | Should -Be 1
    $matches[0].CompletionText | Should -BeExactly "'en-GB'"
    @(& $attr.ScriptBlock '' '' 'da' $null @{Inventory=$saved}).Count | Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count | Should -Be 0
  }
}
Describe 'Language export boundaries' {
  BeforeEach {
    $script:ExportArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;OutputPath=(Join-Path $TestDrive 'languages.json')}
    Mock Import-Module {}
    Mock Get-RideUserLanguageInventory {New-LanguageObservation}
  }
  It 'previews without collecting or writing output' {
    & (Join-Path $Root 'tools/Export-RideUserLanguageInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideUserLanguageInventory -Exactly 0
  }
  It 'exports supplied user/session and refuses existing output' {
    & (Join-Path $Root 'tools/Export-RideUserLanguageInventory.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    Should -Invoke Get-RideUserLanguageInventory -Exactly 1 -ParameterFilter {$ExpectedUserSid -eq 'S-1-5-21-1-2-3-1001' -and $ExpectedSessionId -eq 1}
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before|ConvertFrom-Json).Kind | Should -Be UserLanguageObservation
    {& (Join-Path $Root 'tools/Export-RideUserLanguageInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly $before
  }
  It 'refuses a racing output file' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'racing-language.json'
    Mock Get-RideUserLanguageInventory {[IO.File]::WriteAllText((Join-Path $TestDrive 'racing-language.json'),'other writer');New-LanguageObservation}
    {& (Join-Path $Root 'tools/Export-RideUserLanguageInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
  }
}
