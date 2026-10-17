<#
.SYNOPSIS
  Verify separate regional observations with mocked providers.
.DESCRIPTION
  Checks context binding, process/user/machine distinctions, bounded literal data,
  partial failure, selective queries, completion and exclusive export. No native
  regional provider, setter, UI refresh or default-user copy is invoked.
.EXAMPLE
  Invoke-Pester .\tests\RegionalInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: Repository fixture; native provider acceptance remains pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.RegionalInventory.psm1') -Force
  function New-RegionalTestContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
  }
  function New-RegionalTestCulture {
    $culture=[Globalization.CultureInfo]::new('da-DK',$false)
    $culture.DateTimeFormat.ShortDatePattern='yyyy/MM/dd'
    $culture.NumberFormat.CurrencySymbol='DKK-custom'
    $culture
  }
}
Describe 'Regional provider separation and identity' {
  BeforeEach {
    $script:CaptureArgs=@{Kind=@('FormatCulture','HomeLocation','SystemLocale','TimeZone');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1}
    Mock Get-RideRegionalContext -ModuleName RIDE.RegionalInventory {New-RegionalTestContext}
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {
      param($Kind)
      switch($Kind){
        FormatCulture {New-RegionalTestCulture}
        HomeLocation {[pscustomobject]@{GeoId=61;HomeLocation='Danmark';PrivateField='omit-me'}}
        SystemLocale {[Globalization.CultureInfo]::GetCultureInfo('da-DK')}
        TimeZone {[pscustomobject]@{Id='Romance Standard Time';BaseUtcOffset=[TimeSpan]::FromHours(1);SupportsDaylightSavingTime=$true;PrivateField='omit-me'}}
      }
    }
  }
  It 'preserves separate scope and literal format metadata without choosing a setting' {
    $r=Get-RideRegionalInventory @CaptureArgs
    $r.Kind | Should -Be RegionalObservation
    ($r.Providers.Kind -join ',') | Should -BeExactly 'FormatCulture,HomeLocation,SystemLocale,TimeZone'
    ($r.Providers.Scope -join ',') | Should -BeExactly 'User,User,Machine,Machine'
    ($r.Providers.Status -join ',') | Should -BeExactly 'Captured,Captured,Captured,Captured'
    $r.Providers[0].Value.ShortDatePattern | Should -BeExactly 'yyyy/MM/dd'
    $r.Providers[0].Value.CurrencySymbol | Should -BeExactly 'DKK-custom'
    $r.Providers[1].Value.GeoId | Should -Be 61
    $r.Providers[1].Value.HomeLocation | Should -BeExactly 'Danmark'
    $r.Providers[2].Value.Name | Should -BeExactly 'da-DK'
    $r.Providers[3].Value.BaseUtcOffsetTicks | Should -Be 36000000000
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'PrivateField|omit-me'
  }
  It 'queries only the explicitly requested provider and canonicalizes case' {
    $CaptureArgs.Kind=@('timezone')
    $r=Get-RideRegionalInventory @CaptureArgs
    $r.Providers.Count | Should -Be 1
    $r.Providers[0].Kind | Should -BeExactly 'TimeZone'
    Should -Invoke Get-RideRegionalRows -ModuleName RIDE.RegionalInventory -Exactly 1 -ParameterFilter {$Kind -ceq 'TimeZone'}
  }
  It 'rejects duplicate selection before any observation' {
    $CaptureArgs.Kind=@('TimeZone','timezone')
    {Get-RideRegionalInventory @CaptureArgs} | Should -Throw '*only once*'
    Should -Invoke Get-RideRegionalRows -ModuleName RIDE.RegionalInventory -Exactly 0
    Should -Invoke Get-RideRegionalContext -ModuleName RIDE.RegionalInventory -Exactly 0
  }
  It 'completes declared providers without loading operational state' {
    $line='Get-RideRegionalInventory -Kind Sy'
    $r=TabExpansion2 $line $line.Length
    $r.CompletionMatches.CompletionText | Should -Contain 'SystemLocale'
    Should -Invoke Get-RideRegionalRows -ModuleName RIDE.RegionalInventory -Exactly 0
    Should -Invoke Get-RideRegionalContext -ModuleName RIDE.RegionalInventory -Exactly 0
  }
  It 'refuses wrong target <Field> before provider calls' -ForEach @(
    @{Field='ComputerName';Value='OTHER'},@{Field='Build';Value='26200'},
    @{Field='EditionId';Value='Enterprise'},@{Field='UserSid';Value='S-1-5-21-1-2-3-1002'},
    @{Field='SessionId';Value=2},@{Field='NativeProcess';Value=$false},
    @{Field='UserInteractive';Value=$false},@{Field='UpdateBuildRevision';Value='1'}
  ) {
    $context=New-RegionalTestContext;$context.$Field=$Value
    Mock Get-RideRegionalContext -ModuleName RIDE.RegionalInventory { $context }
    {Get-RideRegionalInventory @CaptureArgs} | Should -Throw
    Should -Invoke Get-RideRegionalRows -ModuleName RIDE.RegionalInventory -Exactly 0
  }
  It 'discards all results when the session or update revision drifts' -ForEach @(
    @{Field='SessionId';Value=2},@{Field='UpdateBuildRevision';Value=2}
  ) {
    $initial=New-RegionalTestContext
    InModuleScope RIDE.RegionalInventory -Parameters @{Initial=$initial;Field=$Field;Value=$Value} {
      param($Initial,$Field,$Value)
      $script:RegionalContextFixture=$Initial;$script:RegionalContextCalls=0
      $script:RegionalDriftField=$Field;$script:RegionalDriftValue=$Value
      Mock Get-RideRegionalContext {
        $script:RegionalContextCalls++
        $copy=$script:RegionalContextFixture.PSObject.Copy()
        if($script:RegionalContextCalls -gt 1){$copy.($script:RegionalDriftField)=$script:RegionalDriftValue}
        $copy
      }
    }
    {Get-RideRegionalInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'keeps provider failure independent and omits raw exception text' {
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {
      param($Kind)
      if($Kind -eq 'HomeLocation'){throw 'private-secret-error'}
      elseif($Kind -eq 'FormatCulture'){New-RegionalTestCulture}
      elseif($Kind -eq 'SystemLocale'){[Globalization.CultureInfo]::GetCultureInfo('en-GB')}
      else{[pscustomobject]@{Id='UTC';BaseUtcOffset=[TimeSpan]::Zero;SupportsDaylightSavingTime=$false}}
    }
    $r=Get-RideRegionalInventory @CaptureArgs
    ($r.Providers.Status -join ',') | Should -BeExactly 'Captured,Unavailable,Captured,Captured'
    $r.Providers[1].Value | Should -BeNullOrEmpty
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'private-secret-error'
  }
  It 'does not treat zero rows as a default or absence' {
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {}
    $r=Get-RideRegionalInventory @CaptureArgs
    @($r.Providers|Where-Object Status -eq Unavailable).Count | Should -Be 4
    @($r.Providers|Where-Object {$null -ne $_.Value}).Count | Should -Be 0
  }
  It 'discards partial output before an error' {
    $CaptureArgs.Kind=@('SystemLocale')
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {[Globalization.CultureInfo]::GetCultureInfo('da-DK');throw 'failure'}
    $r=Get-RideRegionalInventory @CaptureArgs
    $r.Providers[0].Status | Should -Be Unavailable
    $r.Providers[0].Value | Should -BeNullOrEmpty
  }
  It 'refuses multiple rows instead of silently taking the first' {
    $CaptureArgs.Kind=@('SystemLocale')
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {[Globalization.CultureInfo]::GetCultureInfo('da-DK');[Globalization.CultureInfo]::GetCultureInfo('en-GB')}
    (Get-RideRegionalInventory @CaptureArgs).Providers[0].Status | Should -Be Unavailable
  }
  It 'keeps invariant culture explicit without selecting a substitute' {
    $CaptureArgs.Kind=@('FormatCulture')
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {[Globalization.CultureInfo]::InvariantCulture}
    $row=(Get-RideRegionalInventory @CaptureArgs).Providers[0]
    $row.Status | Should -Be Captured
    $row.Value.Name | Should -BeExactly ''
    $row.Value.IsInvariantName | Should -BeTrue
  }
  It 'preserves a negative signed GeoID without guessing a country' {
    $CaptureArgs.Kind=@('HomeLocation')
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {[pscustomobject]@{GeoId=-1;HomeLocation=''}}
    $row=(Get-RideRegionalInventory @CaptureArgs).Providers[0]
    $row.Status | Should -Be Captured
    $row.Value.GeoId | Should -Be -1
    $row.Value.HomeLocation | Should -BeExactly ''
  }
  It 'refuses malformed <Case> data without a partial value' -ForEach @(
    @{Case='GeoID string';Kind='HomeLocation';Data=[pscustomobject]@{GeoId='61';HomeLocation='Denmark'}},
    @{Case='GeoID overflow';Kind='HomeLocation';Data=[pscustomobject]@{GeoId=2147483648L;HomeLocation=''}},
    @{Case='GeoID fraction';Kind='HomeLocation';Data=[pscustomobject]@{GeoId=61.5;HomeLocation=''}},
    @{Case='oversize location';Kind='HomeLocation';Data=[pscustomobject]@{GeoId=61;HomeLocation=('x'*257)}},
    @{Case='missing culture';Kind='SystemLocale';Data=[pscustomobject]@{LCID=1030}},
    @{Case='culture control character';Kind='SystemLocale';Data=[pscustomobject]@{Name="da`nDK";LCID=1030}},
    @{Case='culture boolean LCID';Kind='SystemLocale';Data=[pscustomobject]@{Name='da-DK';LCID=$true}},
    @{Case='culture omitted formats';Kind='FormatCulture';Data=[pscustomobject]@{Name='da-DK';LCID=1030;IsNeutralCulture=$false;UseUserOverride=$false}},
    @{Case='timezone missing ID';Kind='TimeZone';Data=[pscustomobject]@{BaseUtcOffset=[TimeSpan]::Zero;SupportsDaylightSavingTime=$false}},
    @{Case='timezone missing offset';Kind='TimeZone';Data=[pscustomobject]@{Id='UTC';SupportsDaylightSavingTime=$false}},
    @{Case='timezone offset bound';Kind='TimeZone';Data=[pscustomobject]@{Id='custom';BaseUtcOffset=[TimeSpan]::FromHours(15);SupportsDaylightSavingTime=$true}},
    @{Case='timezone string Boolean';Kind='TimeZone';Data=[pscustomobject]@{Id='UTC';BaseUtcOffset=[TimeSpan]::Zero;SupportsDaylightSavingTime='false'}}
  ) {
    $CaptureArgs.Kind=@($Kind)
    Mock Get-RideRegionalRows -ModuleName RIDE.RegionalInventory {$Data}
    $row=(Get-RideRegionalInventory @CaptureArgs).Providers[0]
    $row.Status | Should -Be Unavailable
    $row.Value | Should -BeNullOrEmpty
  }
}
Describe 'Regional export boundaries' {
  BeforeEach {
    $script:ExportArgs=@{Kind=@('HomeLocation');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;OutputPath=(Join-Path $TestDrive 'overrides.json')}
    Mock Import-Module {}
    Mock Get-RideRegionalInventory {[pscustomobject]@{SchemaVersion=1;Kind='RegionalObservation';Providers=@([pscustomobject]@{Kind='HomeLocation';Status='Captured';Value=$null})}}
  }
  It 'previews without querying providers or creating output' {
    & (Join-Path $Root 'tools/Export-RideRegionalInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideRegionalInventory -Exactly 0
  }
  It 'exports only the explicit selection and refuses existing evidence' {
    & (Join-Path $Root 'tools/Export-RideRegionalInventory.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    Should -Invoke Get-RideRegionalInventory -Exactly 1 -ParameterFilter {$Kind.Count -eq 1 -and $Kind[0] -ceq 'HomeLocation' -and $ExpectedSessionId -eq 1}
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before|ConvertFrom-Json).Providers[0].Status | Should -Be Captured
    {& (Join-Path $Root 'tools/Export-RideRegionalInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly $before
  }
  It 'preserves a competing output created during collection' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'racing-overrides.json'
    Mock Get-RideRegionalInventory {[IO.File]::WriteAllText((Join-Path $TestDrive 'racing-overrides.json'),'other writer');[pscustomobject]@{Kind='fixture'}}
    {& (Join-Path $Root 'tools/Export-RideRegionalInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
  }
}
