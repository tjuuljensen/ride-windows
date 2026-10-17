<#
.SYNOPSIS
  Verify owned proxy edit and recovery preparation without Windows calls.
.DESCRIPTION
  Uses supplied records to exercise manual-option preservation, URL validation,
  changed-field conflicts, identity refusal, serialization and snapshot consistency.
.EXAMPLE
  Invoke-Pester .\tests\UserProxyPreparation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture. No filesystem or native networking changes.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.UserProxyPreparation.psm1') -Force
  function New-ProxyPreparationObservation {
    [pscustomobject]@{
      SchemaVersion=1;Kind='UserProxyObservation';Status='Captured';FlagsSource='FlagsUi';UiQueryError=$null
      ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;ConnectionKind='DefaultLan';ConnectionName=$null
      Flags=[uint32]2147483663;ProxyServer='http=old.test:80;https=secure.test:443';ProxyBypass='<local>;*.old.test';AutoConfigUrl='http://pac.test/config.pac'
    }
  }
  function Get-ProxyPreparedObservation($Original,$Patch) {
    $current=$Original|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $current.Flags=$Patch.DesiredValues.Flags;$current.AutoConfigUrl=$Patch.DesiredValues.AutoConfigUrl
    $current
  }
}
Describe 'Narrow proxy edit preparation' {
  BeforeEach {$script:Observation=New-ProxyPreparationObservation}
  It 'disables detection while preserving direct, manual, script and unknown bits plus literal strings' {
    $p=New-RideUserProxyConfigurationPatch $Observation -AutomaticDetection Disabled
    $p.DesiredValues.Flags | Should -Be 2147483655
    $p.Snapshot.OwnedFlagMask | Should -Be 8
    $p.Snapshot.OwnsUrl | Should -BeFalse
    $p.DesiredValues.ProxyServer | Should -BeExactly $Observation.ProxyServer
    $p.DesiredValues.ProxyBypass | Should -BeExactly $Observation.ProxyBypass
    $p.DesiredValues.AutoConfigUrl | Should -BeExactly $Observation.AutoConfigUrl
    $Observation.Flags | Should -Be 2147483663
    $p.ReadyForMutation | Should -BeFalse
    $p.MutationAuthorized | Should -BeFalse
  }
  It 'disables setup script without clearing a malformed retained address' {
    $Observation.AutoConfigUrl='historical opaque address'
    $p=New-RideUserProxyConfigurationPatch $Observation -SetupScript Disabled
    $p.DesiredValues.Flags | Should -Be 2147483659
    $p.DesiredValues.AutoConfigUrl | Should -BeExactly 'historical opaque address'
    $p.Snapshot.OwnsUrl | Should -BeFalse
  }
  It 'enables a retained valid script without implicitly enabling detection' {
    $Observation.Flags=[uint32]3
    $p=New-RideUserProxyConfigurationPatch $Observation -SetupScript Enabled
    $p.DesiredValues.Flags | Should -Be 7
    $p.Snapshot.OwnedFlagMask | Should -Be 4
    $p.Snapshot.OwnsUrl | Should -BeFalse
  }
  It 'preserves URL spelling and treats changed URL as owned even when the flag was already enabled' {
    $url='HTTPS://PAC.TEST:443/a%2Fb.pac?Case=Value#fragment'
    $p=New-RideUserProxyConfigurationPatch $Observation -SetupScript Enabled -ScriptUrl $url
    $p.DesiredValues.AutoConfigUrl | Should -BeExactly $url
    $p.Snapshot.OwnedFlagMask | Should -Be 0
    $p.Snapshot.OwnsUrl | Should -BeTrue
    $p.ChangeRequired | Should -BeTrue
  }
  It 'reports a no-op and owns no already-matching requested fields' {
    $p=New-RideUserProxyConfigurationPatch $Observation -AutomaticDetection Enabled -SetupScript Enabled -ScriptUrl $Observation.AutoConfigUrl
    $p.ChangeRequired | Should -BeFalse
    $p.Snapshot.OwnedFlagMask | Should -Be 0
    $p.Snapshot.OwnsUrl | Should -BeFalse
  }
  It 'normalizes case-insensitive command choices so its snapshot can be recovered' {
    $p=New-RideUserProxyConfigurationPatch $Observation -AutomaticDetection dIsAbLeD -SetupScript uNcHaNgEd
    $p.Snapshot.AutomaticDetection | Should -BeExactly Disabled
    $current=Get-ProxyPreparedObservation $Observation $p
    (Restore-RideUserProxyConfigurationPatch $current $p.Snapshot).DesiredValues.Flags | Should -Be $Observation.Flags
  }
  It 'accepts a JSON numeric round trip and a hashtable observation' {
    $copy=$Observation|ConvertTo-Json|ConvertFrom-Json
    (New-RideUserProxyConfigurationPatch $copy -AutomaticDetection Disabled).DesiredValues.Flags | Should -Be 2147483655
    $table=@{};foreach($property in $Observation.PSObject.Properties){$table[$property.Name]=$property.Value}
    (New-RideUserProxyConfigurationPatch $table -AutomaticDetection Disabled).DesiredValues.Flags | Should -Be 2147483655
  }
  It 'requires Enabled when a new script URL is supplied' {
    {New-RideUserProxyConfigurationPatch $Observation -ScriptUrl 'http://pac.test/a'} | Should -Throw '*only with SetupScript Enabled*'
    {New-RideUserProxyConfigurationPatch $Observation -SetupScript Disabled -ScriptUrl 'http://pac.test/a'} | Should -Throw '*disabling preserves*'
  }
  It 'refuses unsafe or unsupported URL <Url> without clearing the original' -TestCases @(
    @{Url=''},@{Url='relative.pac'},@{Url='file:///C:/config.pac'},@{Url='ftp://pac.test/a'},
    @{Url='https://name:secret@pac.test/a'},@{Url=' https://pac.test/a'},@{Url='https://pac.test/a b'},@{Url="https://pac.test/a`n"}
  ) {
    param($Url)
    {New-RideUserProxyConfigurationPatch $Observation -SetupScript Enabled -ScriptUrl $Url} | Should -Throw '*HTTP/HTTPS URL*'
    $Observation.AutoConfigUrl | Should -BeExactly 'http://pac.test/config.pac'
  }
  It 'refuses script enablement with no retained address' {
    $Observation.AutoConfigUrl=$null
    {New-RideUserProxyConfigurationPatch $Observation -SetupScript Enabled} | Should -Throw '*HTTP/HTTPS URL*'
  }
  It 'refuses incomplete, fallback and mismatched connection observations' {
    $Observation.PSObject.Properties.Remove('ProxyBypass')
    {New-RideUserProxyConfigurationPatch $Observation} | Should -Throw '*Missing*'
    $Observation=New-ProxyPreparationObservation;$Observation.FlagsSource='FlagsFallback';$Observation.UiQueryError=87
    {New-RideUserProxyConfigurationPatch $Observation} | Should -Throw '*FlagsUi*'
    $Observation=New-ProxyPreparationObservation;$Observation.ConnectionName='VPN'
    {New-RideUserProxyConfigurationPatch $Observation} | Should -Throw '*default/LAN*'
  }
  It 'refuses invalid numeric flags <Flags>' -TestCases @(@{Flags=-1},@{Flags='15'},@{Flags=$true},@{Flags=1.5},@{Flags=4294967296}) {
    param($Flags)
    $Observation.Flags=$Flags
    {New-RideUserProxyConfigurationPatch $Observation} | Should -Throw '*unsigned proxy flags*'
  }
}
Describe 'Conflict-aware in-memory recovery' {
  BeforeEach {
    $script:Observation=New-ProxyPreparationObservation
    $script:Patch=New-RideUserProxyConfigurationPatch $Observation -AutomaticDetection Disabled -SetupScript Enabled -ScriptUrl 'https://pac.test/new.pac'
    $script:Current=Get-ProxyPreparedObservation $Observation $Patch
  }
  It 'recovers the changed detection bit and address after snapshot serialization' {
    $snapshot=$Patch.Snapshot|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $r=Restore-RideUserProxyConfigurationPatch $Current $snapshot
    $r.DesiredValues.Flags | Should -Be $Observation.Flags
    $r.DesiredValues.AutoConfigUrl | Should -BeExactly $Observation.AutoConfigUrl
    $r.MutationAuthorized | Should -BeFalse
    $r.ReadyForMutation | Should -BeFalse
  }
  It 'preserves unrelated manual/bypass/unknown-bit and previously matching setup-flag changes' {
    $Current.ProxyServer='http=new.test:3128';$Current.ProxyBypass='<local>;*.new.test'
    $Current.Flags=[uint32]1073741825
    $r=Restore-RideUserProxyConfigurationPatch $Current $Patch.Snapshot
    $r.DesiredValues.Flags | Should -Be 1073741833
    $r.DesiredValues.ProxyServer | Should -BeExactly 'http=new.test:3128'
    $r.DesiredValues.ProxyBypass | Should -BeExactly '<local>;*.new.test'
    $r.DesiredValues.AutoConfigUrl | Should -BeExactly $Observation.AutoConfigUrl
  }
  It 'preserves an unrelated later URL when preparation only changed a flag' {
    $p=New-RideUserProxyConfigurationPatch $Observation -SetupScript Disabled
    $c=Get-ProxyPreparedObservation $Observation $p;$c.AutoConfigUrl='https://other.test/later.pac'
    $r=Restore-RideUserProxyConfigurationPatch $c $p.Snapshot
    $r.DesiredValues.AutoConfigUrl | Should -BeExactly 'https://other.test/later.pac'
    $r.DesiredValues.Flags | Should -Be $Observation.Flags
  }
  It 'refuses a changed owned bit without offering a guessed recovery' {
    $Current.Flags=$Observation.Flags
    {Restore-RideUserProxyConfigurationPatch $Current $Patch.Snapshot} | Should -Throw '*flag conflicts*'
  }
  It 'refuses a changed owned URL including a case-only edit' {
    $Current.AutoConfigUrl='https://PAC.test/new.pac'
    {Restore-RideUserProxyConfigurationPatch $Current $Patch.Snapshot} | Should -Throw '*URL conflicts*'
  }
  It 'restores null distinctly from empty original URL' {
    foreach($originalUrl in @($null,'')){
      $o=New-ProxyPreparationObservation;$o.AutoConfigUrl=$originalUrl
      $p=New-RideUserProxyConfigurationPatch $o -SetupScript Enabled -ScriptUrl 'https://pac.test/new.pac'
      $c=Get-ProxyPreparedObservation $o $p
      $r=Restore-RideUserProxyConfigurationPatch $c $p.Snapshot
      ($null -eq $r.DesiredValues.AutoConfigUrl) | Should -Be ($null -eq $originalUrl)
      if($null -ne $originalUrl){$r.DesiredValues.AutoConfigUrl.Length | Should -Be 0}
    }
  }
  It 'does not acquire ownership when a no-op snapshot is recovered after unrelated edits' {
    $p=New-RideUserProxyConfigurationPatch $Observation -AutomaticDetection Enabled
    $Current.Flags=[uint32]3;$Current.AutoConfigUrl=$null
    $r=Restore-RideUserProxyConfigurationPatch $Current $p.Snapshot
    $r.ChangeRequired | Should -BeFalse
    $r.DesiredValues.Flags | Should -Be 3
    ($null -eq $r.DesiredValues.AutoConfigUrl) | Should -BeTrue
  }
  It 'refuses different <Field> identity' -TestCases @(@{Field='ComputerName';Value='OTHER'},@{Field='UserSid';Value='S-1-5-21-1-2-3-500'},@{Field='SessionId';Value=2}) {
    param($Field,$Value)
    $Current.$Field=$Value
    {Restore-RideUserProxyConfigurationPatch $Current $Patch.Snapshot} | Should -Throw '*identity differs*'
  }
  It 'refuses inconsistent snapshot <Field>' -TestCases @(@{Field='OwnedFlagMask';Value=12},@{Field='OwnsUrl';Value=$false},@{Field='ExpectedFlags';Value=3},@{Field='ExpectedUrl';Value='https://tampered.test/a'}) {
    param($Field,$Value)
    $Patch.Snapshot.$Field=$Value
    {Restore-RideUserProxyConfigurationPatch $Current $Patch.Snapshot} | Should -Throw '*disagrees*'
  }
  It 'rejects incomplete and unknown snapshot schemas' {
    $Patch.Snapshot.PSObject.Properties.Remove('ExpectedUrl')
    {Restore-RideUserProxyConfigurationPatch $Current $Patch.Snapshot} | Should -Throw '*Missing*'
    $p=New-RideUserProxyConfigurationPatch $Observation;$p.Snapshot.SchemaVersion=2
    {Restore-RideUserProxyConfigurationPatch $Current $p.Snapshot} | Should -Throw '*schema*'
  }
  It 'completes detection and setup choices from their declared finite sets' {
    foreach($parameter in @('AutomaticDetection','SetupScript')){
      $line='New-RideUserProxyConfigurationPatch -'+$parameter+' D'
      (TabExpansion2 -inputScript $line -cursorColumn $line.Length).CompletionMatches.CompletionText | Should -Contain Disabled
    }
  }
}
