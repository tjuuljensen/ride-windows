BeforeAll {
  $Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.DesiredConfiguration.psm1') -Force
  function New-ReferenceFixture {
    $op=@{Id='windows.test';Kind='RegistryValue';Scope='User';RegistryPath='HKCU:\Software\RideTest';ValueName='Value';ValueType='DWord';States=@{Enabled=1;Disabled=0;Default=$null};BaselineState='Default';SupportedTargets=@('Windows 11','Windows Server 2025')}
    @{Catalog=@{SchemaVersion=1;Operations=@($op);Groups=@()};Profile=@{SchemaVersion=1;Name='Reference fixture';Operations=@(@{Id='windows.test';State='Enabled'})};CatalogSha256=('A'*64);ProfileSha256=('B'*64);Target='Windows 11';Build=26100;EditionId='Professional';InstallationType='Client';Role='Workstation'}
  }
}

Describe 'Desired reference file safety guards' {
  BeforeAll {
    Import-Module (Join-Path $Root 'modules/RIDE.CatalogData.psm1') -Force
    Import-Module (Join-Path $Root 'modules/RIDE.CatalogValidation.psm1') -Force
    $script:GuardTool=Join-Path $Root 'tools/Export-RideDesiredConfiguration.ps1'
  }
  BeforeEach {
    $script:GuardDestination=Join-Path $TestDrive (([guid]::NewGuid().ToString())+'.json')
    $script:GuardArguments=@{Profile=(Join-Path $Root 'profiles/default.psd1');Target='Windows 11';Build=26100;EditionId='Professional';InstallationType='Client';Role='Workstation';OutputPath=$GuardDestination}
    Mock Import-Module {}
    Mock Import-RideCatalogData {(New-ReferenceFixture).Catalog}
    Mock Get-RideCatalogValidationErrors {}
    Mock Import-PowerShellDataFile {(New-ReferenceFixture).Profile}
  }
  It 'preserves an output created between preview and exclusive creation' {
    Mock ConvertTo-RideDesiredConfiguration {[IO.File]::WriteAllText($GuardDestination,'racing owner');[pscustomobject]@{SchemaVersion=1}}
    {& $GuardTool @GuardArguments}|Should -Throw
    [IO.File]::ReadAllText($GuardDestination)|Should -BeExactly 'racing owner'
  }
  It 'refuses source hash drift before creating output' {
    $script:HashCalls=0
    Mock Get-FileHash {$script:HashCalls++;[pscustomobject]@{Hash=$(if($script:HashCalls -gt 2){'C'*64}else{'A'*64})}}
    {& $GuardTool @GuardArguments}|Should -Throw '*Source changed*'
    Test-Path -LiteralPath $GuardDestination|Should -BeFalse
  }
}

Describe 'Read-only desired configuration reference' {
  BeforeEach {$referenceInput=New-ReferenceFixture}
  It 'binds source and declared target while leaving live state and compliance unknown' {
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Kind|Should -BeExactly RideDesiredConfigurationReference
    $r.Source.CatalogSha256|Should -BeExactly ('a'*64)
    $r.Source.ProfileSha256|Should -BeExactly ('b'*64)
    $r.ConfigurationOwner|Should -BeExactly RIDE
    $r.ConsumerPermission|Should -BeExactly ObserveEvaluateReportOnly
    $r.DeclaredTarget.Observed|Should -BeFalse
    $r.DeclaredTarget.Build|Should -Be 26100
    $r.IncludesLiveState|Should -BeFalse;$r.IncludesMeasurementThresholds|Should -BeFalse
    $r.ReadyForMutation|Should -BeFalse;$r.RecoverySupported|Should -BeFalse
    $r.Selections[0].CurrentState|Should -BeExactly Unknown
    $r.Selections[0].Compliance|Should -BeExactly Unknown
    $r.Selections[0].DeclaredTargetStatus|Should -BeExactly DeclaredSupported
    $r.Selections[0].Mappings[0].Intent|Should -BeExactly SetValue
    $r.Selections[0].Mappings[0].Value|Should -Be 1
  }
  It 'distinguishes zero, empty string, absence and baseline from OS defaults' {
    $op=$referenceInput.Catalog.Operations[0];$op.ValueType='String';$op.States.Empty=''
    $referenceInput.Profile.Operations[0].State='Disabled'
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Selections[0].Mappings[0].Intent|Should -BeExactly SetValue
    $r.Selections[0].Mappings[0].Value|Should -Be 0
    $referenceInput.Profile.Operations[0].State='Empty'
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Selections[0].Mappings[0].Intent|Should -BeExactly SetValue
    $r.Selections[0].Mappings[0].Value|Should -BeExactly ''
    $referenceInput.Profile.Operations[0].State='Baseline'
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Selections[0].RequestedState|Should -BeExactly Baseline
    $r.Selections[0].ResolvedState|Should -BeExactly Default
    $r.Selections[0].Mappings[0].Intent|Should -BeExactly RemoveValue
    $r.Selections[0].Mappings[0].Value|Should -BeNullOrEmpty
  }
  It 'copies ordered multivalue data without expanding environment placeholders' {
    $op=$referenceInput.Catalog.Operations[0];$op.ValueType='MultiString';$op.States.Enabled=@('%USERPROFILE%\bin','literal')
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $op.States.Enabled[0]='changed'
    $r.Selections[0].Mappings[0].Value.Count|Should -Be 2
    $r.Selections[0].Mappings[0].Value[0]|Should -BeExactly '%USERPROFILE%\bin'
    $r.Selections[0].Mappings[0].EnvironmentExpansion|Should -BeExactly NotPerformed
    $r.Selections[0].Mappings[0].RegistryView|Should -BeExactly NotSpecifiedByCatalog
  }
  It 'preserves a one-element array as an array through JSON' {
    $referenceInput.Catalog.Operations[0].States.Enabled=@('single');$referenceInput.Catalog.Operations[0].ValueType='MultiString'
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Selections[0].Mappings[0].Value -is [array]|Should -BeTrue
    $json=$r|ConvertTo-Json -Depth 15|ConvertFrom-Json
    $json.Selections[0].Mappings[0].Value -is [array]|Should -BeTrue
  }
  It 'completes API target names only from the supplied catalog without duplicates' {
    $referenceInput.Catalog.Operations[0].CandidateTargets=@('Windows 11','Windows Server 2025')
    $attribute=(Get-Command ConvertTo-RideDesiredConfiguration).Parameters['Target'].Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attribute.ScriptBlock '' '' 'windows s' $null @{Catalog=$referenceInput.Catalog})
    $matches.Count|Should -Be 1
    $matches[0].ListItemText|Should -BeExactly 'Windows Server 2025'
    @(& $attribute.ScriptBlock '' '' '' $null @{}).Count|Should -Be 0
  }
  It 'preserves coordinated component order and KeepCurrent rather than treating it as deletion' {
    $op=$referenceInput.Catalog.Operations[0];$op.Kind='RegistryValueSet'
    $op.RegistryValues=@(@{Key='Second';RegistryPath=$op.RegistryPath;ValueName='B';ValueType='DWord'},@{Key='First';RegistryPath=$op.RegistryPath;ValueName='A';ValueType='DWord'})
    $op.States=@{Enabled=@{First=$null;Second=@{KeepCurrent=$true}}}
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Selections[0].Mappings[0].Key|Should -BeExactly Second
    $r.Selections[0].Mappings[0].Intent|Should -BeExactly KeepCurrent
    $r.Selections[0].Mappings[1].Intent|Should -BeExactly RemoveValue
  }
  It 'reports target boundary <Case> explicitly' -ForEach @(
    @{Case='Unsupported';Expected='NotApplicable'},@{Case='Pending';Expected='PendingAcceptance'},
    @{Case='MinimumBuild';Expected='NotApplicable'},@{Case='Core';Expected='NotApplicable'},
    @{Case='UnknownDesktop';Expected='Unknown'},@{Case='Desktop';Expected='DeclaredSupported'}
  ) {
    $op=$referenceInput.Catalog.Operations[0]
    switch($Case){
      Unsupported {$referenceInput.Target='Undeclared Windows'}
      Pending {$op.PendingAcceptance=$true;$op.SupportedTargets=@();$op.CandidateTargets=@('Windows 11')}
      MinimumBuild {$op.MinimumBuild=27000}
      Core {$referenceInput.Target='Windows Server 2025';$op.RequiresDesktopExperience=$true;$referenceInput.InstallationType='Server Core'}
      UnknownDesktop {$referenceInput.Target='Windows Server 2025';$op.RequiresDesktopExperience=$true;$referenceInput.InstallationType='Unknown'}
      Desktop {$referenceInput.Target='Windows Server 2025';$op.RequiresDesktopExperience=$true;$referenceInput.InstallationType='Server'}
    }
    (ConvertTo-RideDesiredConfiguration @referenceInput).Selections[0].DeclaredTargetStatus|Should -BeExactly $Expected
  }
  It 'retains unsupported handlers and package variants as ReportOnly without resolving runtime scope' {
    $referenceInput.Catalog.Operations+=@{Id='package.test';Kind='Package';Scope='Machine';SupportedTargets=@('Windows 11');DefaultVariant='installed';Variants=@{installed=@{};user=@{Scope='User'}}}
    $referenceInput.Catalog.Operations+=@{Id='windows.service';Kind='WindowsService';Scope='Machine';SupportedTargets=@('Windows 11');States=@{Disabled=@{SecretFixture='not-exported'}}}
    $referenceInput.Profile.Operations+=@{Id='package.test';State='Present';Variant='user'},@{Id='windows.service';State='Disabled'}
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Selections.Count|Should -Be 3
    $r.Selections[1].ReferenceMode|Should -BeExactly ReportOnly
    $r.Selections[1].Scope|Should -BeNullOrEmpty
    $r.Selections[1].DeclaredTargetStatus|Should -BeExactly Unknown
    $r.Selections[1].Variant|Should -BeExactly user
    $r.Selections[2].ReferenceMode|Should -BeExactly ReportOnly
    $r.Selections[2].Mappings.Count|Should -Be 0
    ($r|ConvertTo-Json -Depth 15)|Should -Not -Match 'SecretFixture|not-exported'
  }
  It 'retains group selections and member order without inventing a group observation or reverse order' {
    $referenceInput.Catalog.Groups=@(@{Id='group.test';Members=@('windows.test')})
    $referenceInput.Profile.Operations=@(@{Id='group.test';State='Absent'})
    $r=ConvertTo-RideDesiredConfiguration @referenceInput
    $r.Selections[0].RecordType|Should -BeExactly GroupSelection
    $r.Selections[0].ReferenceMode|Should -BeExactly ReportOnly
    $r.Selections[0].Members[0]|Should -BeExactly windows.test
    $r.Selections[0].Mappings.Count|Should -Be 0
  }
  It 'rejects invalid or ambiguous data: <Case>' -ForEach @(
    @{Case='Schema'},@{Case='DuplicateCatalog'},@{Case='DuplicateSelection'},@{Case='UnknownId'},@{Case='UnknownState'},
    @{Case='MissingState'},@{Case='UnknownField'},@{Case='SettingVariant'},@{Case='UnknownVariant'},
    @{Case='InvalidDirective'},@{Case='ExcessiveString'},@{Case='ObjectValue'},@{Case='UnknownGroupMember'},
    @{Case='MissingBaseline'},@{Case='WrongRegistryRoot'},@{Case='CoordinatedMissing'},@{Case='ExcessiveSelections'}
  ) {
    $op=$referenceInput.Catalog.Operations[0]
    switch($Case){
      Schema {$referenceInput.Profile.SchemaVersion=2}
      DuplicateCatalog {$referenceInput.Catalog.Operations+=@($op.Clone())}
      DuplicateSelection {$referenceInput.Profile.Operations+=@{Id='WINDOWS.TEST';State='Disabled'}}
      UnknownId {$referenceInput.Profile.Operations[0].Id='windows.unknown'}
      UnknownState {$referenceInput.Profile.Operations[0].State='Bogus'}
      MissingState {$referenceInput.Profile.Operations[0].Remove('State')}
      UnknownField {$referenceInput.Profile.Operations[0].Password='do-not-copy'}
      SettingVariant {$referenceInput.Profile.Operations[0].Variant='installed'}
      UnknownVariant {$op.Kind='Package';$op.Remove('States');$op.Variants=@{installed=@{}};$referenceInput.Profile.Operations[0].State='Present';$referenceInput.Profile.Operations[0].Variant='missing'}
      InvalidDirective {$op.States.Enabled=@{KeepCurrent=$false}}
      ExcessiveString {$op.States.Enabled='x'*16385}
      ObjectValue {$op.States.Enabled=[pscustomobject]@{Private='secret'}}
      UnknownGroupMember {$referenceInput.Catalog.Groups=@(@{Id='group.test';Members=@('missing')});$referenceInput.Profile.Operations=@(@{Id='group.test';State='Present'})}
      MissingBaseline {$op.Remove('BaselineState');$referenceInput.Profile.Operations[0].State='Baseline'}
      WrongRegistryRoot {$op.RegistryPath='HKCR:\unknown'}
      CoordinatedMissing {$op.Kind='RegistryValueSet';$op.RegistryValues=@(@{Key='x';RegistryPath='HKCU:\Software\RideTest';ValueName='v';ValueType='DWord'});$op.States.Enabled=@{wrong=1}}
      ExcessiveSelections {$referenceInput.Profile.Operations=@($referenceInput.Profile.Operations[0])*2001}
    }
    {ConvertTo-RideDesiredConfiguration @referenceInput}|Should -Throw
  }
}

Describe 'Desired configuration export and completion' {
  BeforeAll {
    $script:Tool=Join-Path $Root 'tools/Export-RideDesiredConfiguration.ps1'
    $script:Base=@{Profile=(Join-Path $Root 'profiles/default.psd1');Target='Windows 11';Build=26100;EditionId='Professional';InstallationType='Client';Role='Workstation'}
  }
  It 'WhatIf does not read a nonexistent profile, import the engine or create output' {
    $path=Join-Path $TestDrive 'whatif.json';$p=$Base.Clone();$p.Profile=Join-Path $TestDrive 'missing.psd1'
    & $Tool @p -OutputPath $path -WhatIf
    Test-Path -LiteralPath $path|Should -BeFalse
    Get-Module RIDE.Engine|Should -BeNullOrEmpty
  }
  It 'exports the actual default profile with exact hashes and refuses replacement' {
    $path=Join-Path $TestDrive 'actual.json'
    & $Tool @Base -OutputPath $path|Should -Be $path
    $r=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    $r.Source.ProfileSha256|Should -BeExactly ((Get-FileHash -LiteralPath $Base.Profile).Hash.ToLowerInvariant())
    $r.Source.CatalogSha256|Should -BeExactly ((Get-FileHash -LiteralPath (Join-Path $Root 'catalog/operations.psd1')).Hash.ToLowerInvariant())
    $expected=Import-PowerShellDataFile -LiteralPath $Base.Profile
    $r.Selections.Count|Should -Be $expected.Operations.Count
    @($r.Selections|Where-Object Kind -eq 'Package').Count|Should -Be 3
    @($r.Selections|Where-Object CurrentState -ne 'Unknown').Count|Should -Be 0
    {& $Tool @Base -OutputPath $path}|Should -Throw '*already exists*'
    Get-Module RIDE.Engine|Should -BeNullOrEmpty
  }
  It 'rejects an invalid profile without creating output' {
    $p=$Base.Clone();$p.Profile=Join-Path $TestDrive 'bad.psd1'
    [IO.File]::WriteAllText($p.Profile,"@{SchemaVersion=1;Name='Bad';Operations=@(@{Id='unknown';State='Enabled'})}")
    $dest=Join-Path $TestDrive 'bad.json'
    {& $Tool @p -OutputPath $dest}|Should -Throw '*validation failed*'
    Test-Path -LiteralPath $dest|Should -BeFalse
  }
  It 'completes source profiles and catalog targets read-only with prefix filtering' {
    $line="& '$Tool' -Profile def"
    $r=TabExpansion2 -InputScript $line -CursorColumn $line.Length
    @($r.CompletionMatches|Where-Object ListItemText -eq 'default.psd1').Count|Should -Be 1
    $line="& '$Tool' -Target 'windows s"
    $r=TabExpansion2 -InputScript $line -CursorColumn $line.Length
    @($r.CompletionMatches|Where-Object ListItemText -eq 'Windows Server 2025').Count|Should -Be 1
    @($r.CompletionMatches|Where-Object ListItemText -eq 'Windows 11').Count|Should -Be 0
    Get-Module RIDE.Engine|Should -BeNullOrEmpty
  }
}
