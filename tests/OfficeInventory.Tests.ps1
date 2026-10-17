<#
.SYNOPSIS
  Verify Click-to-Run observation with fake registry handles and mocked context.
.DESCRIPTION
  Checks view separation, redaction, type/size bounds, failure isolation and
  exclusive export. No real Office, registry, account or MSI provider is queried.
.EXAMPLE
  Invoke-Pester .\tests\OfficeInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; native Office target acceptance remains pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.OfficeInventory.psm1') -Force
  function New-OfficeTestContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;Is64BitOperatingSystem=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
  }
  function New-OfficeTestSource {
    $values=[ordered]@{}
    foreach($field in @('VersionToReport','ClientVersionToReport','Platform','ProductReleaseIds','ClientCulture','CDNBaseUrl','UpdateChannel','AudienceId')){
      $data=switch($field){VersionToReport{'16.0.12345.12345'}ClientVersionToReport{'16.0.12345.12346'}Platform{'x86'}ProductReleaseIds{'O365ProPlusRetail,VisioProRetail'}ClientCulture{'en-gb'}
        CDNBaseUrl{'http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6'}
        UpdateChannel{'https://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60'}
        AudienceId{'55336b82-a18d-4dd6-b5f6-9e5095c314a6'}}
      $values[$field]=[pscustomobject]@{Exists=$true;Kind='String';Value=$data}
    }
    [pscustomobject]@{RootExists=$true;Values=[pscustomobject]$values;ProductKey='private-product-key';Account='private-account'}
  }
  function New-OfficeFakeKey {
    $key=[pscustomobject]@{Child=$null;Disposed=$false;Values=@{};ThrowOnRead=$false;ReadCalls=[Collections.Generic.List[object]]::new();OpenCalls=[Collections.Generic.List[object]]::new()}
    $key|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
    $key|Add-Member ScriptMethod OpenSubKey {param($name,$writable);$this.OpenCalls.Add(@{Name=$name;Writable=$writable});$this.Child}
    $key|Add-Member ScriptMethod GetValueNames {$this.Values.Keys}
    $key|Add-Member ScriptMethod GetValueKind {param($name);$this.Values[$name].Kind}
    $key|Add-Member ScriptMethod GetValue {param($name,$default,$options);$this.ReadCalls.Add(@{Name=$name;Options=$options});if($this.ThrowOnRead){throw 'fixture failure'};$this.Values[$name].Value}
    $key
  }
}
Describe 'Click-to-Run source observations' {
  BeforeEach {
    $script:CaptureArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1}
    Mock Get-RideOfficeContext -ModuleName RIDE.OfficeInventory {New-OfficeTestContext}
    Mock Get-RideOfficeSource -ModuleName RIDE.OfficeInventory {New-OfficeTestSource}
  }
  It 'keeps views and channel inputs separate without inferring installed or activated products' {
    $r=Get-RideOfficeInventory @CaptureArgs
    $r.Kind|Should -BeExactly OfficeClickToRunObservation
    ($r.Sources.RegistryView -join ',')|Should -BeExactly 'Registry64,Registry32'
    $r.Sources[0].Values.Platform.Value|Should -BeExactly x86
    $r.Sources[0].Values.ProductReleaseIds.Value|Should -BeExactly 'O365ProPlusRetail,VisioProRetail'
    $r.Sources[0].Values.CDNBaseUrl.MicrosoftChannelGuid|Should -BeExactly '55336b82-a18d-4dd6-b5f6-9e5095c314a6'
    $r.Sources[0].Values.UpdateChannel.MicrosoftChannelGuid|Should -BeExactly '492350f6-3a01-4f97-b9c0-c7c6ddf67d60'
    $r.Sources[0].Values.UpdateChannel.Value|Should -BeNullOrEmpty
    $r.Sources[0].Values.UpdateChannel.ValueRedacted|Should -BeTrue
    $r.InstalledProductsVerified|Should -BeFalse
    $r.EffectiveChannelVerified|Should -BeFalse
    $r.ActivationStatus|Should -BeExactly NotObserved
    $r.ReadyForMutation|Should -BeFalse
    $r.RecoverySupported|Should -BeFalse
    ($r|ConvertTo-Json -Depth 10)|Should -Not -Match 'private-product-key|private-account|https?://'
  }
  It 'queries only Registry32 on a 32-bit operating system' {
    $context=New-OfficeTestContext;$context.Is64BitOperatingSystem=$false
    Mock Get-RideOfficeContext -ModuleName RIDE.OfficeInventory {$context}
    $r=Get-RideOfficeInventory @CaptureArgs
    $r.Sources.Count|Should -Be 1
    $r.Sources[0].RegistryView|Should -BeExactly Registry32
    Should -Invoke Get-RideOfficeSource -ModuleName RIDE.OfficeInventory -Exactly 1 -ParameterFilter {$RegistryView -ceq 'Registry32'}
  }
  It 'keeps absent roots separate from unavailable views' {
    Mock Get-RideOfficeSource -ModuleName RIDE.OfficeInventory {
      param($RegistryView)
      if($RegistryView -eq 'Registry64'){throw 'private-provider-error'}
      [pscustomobject]@{RootExists=$false;Values=$null}
    }
    $r=Get-RideOfficeInventory @CaptureArgs
    $r.Sources[0].Status|Should -BeExactly Unavailable
    $r.Sources[0].RootExists|Should -BeNullOrEmpty
    $r.Sources[1].Status|Should -BeExactly Captured
    $r.Sources[1].RootExists|Should -BeFalse
    $r.InstalledProductsVerified|Should -BeFalse
    ($r|ConvertTo-Json -Depth 10)|Should -Not -Match private-provider-error
  }
  It 'preserves absent and empty fields without inferring a default' {
    $source=New-OfficeTestSource
    $source.Values.Platform=[pscustomobject]@{Exists=$false;Kind=$null;Value=$null}
    $source.Values.ClientCulture.Value=''
    Mock Get-RideOfficeSource -ModuleName RIDE.OfficeInventory {$source}
    $r=Get-RideOfficeInventory @CaptureArgs
    $r.Sources[0].Values.Platform.Exists|Should -BeFalse
    $r.Sources[0].Values.Platform.Value|Should -BeNullOrEmpty
    $r.Sources[0].Values.ClientCulture.Exists|Should -BeTrue
    $r.Sources[0].Values.ClientCulture.Value|Should -BeExactly ''
  }
  It 'retains environment placeholders literally and never expands them' {
    $source=New-OfficeTestSource;$source.Values.ClientCulture.Kind='ExpandString';$source.Values.ClientCulture.Value='%UNRESOLVED%'
    Mock Get-RideOfficeSource -ModuleName RIDE.OfficeInventory {$source}
    (Get-RideOfficeInventory @CaptureArgs).Sources[0].Values.ClientCulture.Value|Should -BeExactly '%UNRESOLVED%'
  }
  It 'redacts <Case> channel URLs without guessing a Microsoft channel' -ForEach @(
    @{Case='custom host';Value='https://private-host/private-path'},
    @{Case='credentials';Value='https://private-user:private-password@officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6'},
    @{Case='query';Value='https://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6?token=private-secret'},
    @{Case='alternate port';Value='https://officecdn.microsoft.com:443/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6'},
    @{Case='empty GUID';Value='http://officecdn.microsoft.com/pr/00000000-0000-0000-0000-000000000000'},
    @{Case='expansion';Value='%PRIVATE_SOURCE%'},@{Case='lookalike host';Value='https://officecdn.microsoft.com.private-host/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6'}
  ) {
    $source=New-OfficeTestSource;$source.Values.UpdateChannel.Value=$Value
    Mock Get-RideOfficeSource -ModuleName RIDE.OfficeInventory {$source}
    $r=Get-RideOfficeInventory @CaptureArgs
    $r.Sources[0].Values.UpdateChannel.UrlClass|Should -BeExactly OtherOrUnrecognized
    $r.Sources[0].Values.UpdateChannel.MicrosoftChannelGuid|Should -BeNullOrEmpty
    ($r|ConvertTo-Json -Depth 10)|Should -Not -Match 'private-host|private-user|private-password|private-secret|PRIVATE_SOURCE'
  }
  It 'refuses wrong context <Field> before reading metadata' -ForEach @(
    @{Field='ComputerName';Value='OTHER'},@{Field='Build';Value='26200'},@{Field='EditionId';Value='Enterprise'},
    @{Field='UserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='SessionId';Value=2},@{Field='NativeProcess';Value=$false},
    @{Field='UserInteractive';Value=$false},@{Field='Is64BitOperatingSystem';Value='true'},@{Field='UpdateBuildRevision';Value=-1}
  ) {
    $context=New-OfficeTestContext;$context.$Field=$Value
    Mock Get-RideOfficeContext -ModuleName RIDE.OfficeInventory {$context}
    {Get-RideOfficeInventory @CaptureArgs}|Should -Throw '*target differs*'
    Should -Invoke Get-RideOfficeSource -ModuleName RIDE.OfficeInventory -Exactly 0
  }
  It 'rejects context type drift even when the textual value is unchanged' {
    InModuleScope RIDE.OfficeInventory -Parameters @{CaptureParameters=$CaptureArgs} {
      param($CaptureParameters)
      $script:OfficeContextCalls=0
      Mock Get-RideOfficeContext {
        $script:OfficeContextCalls++;$revision=if($script:OfficeContextCalls -eq 1){1}else{'1'}
        [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=$revision;NativeProcess=$true;Is64BitOperatingSystem=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
      }
      {Get-RideOfficeInventory @CaptureParameters}|Should -Throw '*context changed*'
    }
  }
  It 'discards source data after <Failure> and continues the other view' -ForEach @(
    @{Failure='PartialThrow'},@{Failure='Multiple'},@{Failure='Empty'},@{Failure='WrongType'},
    @{Failure='Excessive'},@{Failure='ControlCharacter'},@{Failure='AbsentWithValue'},@{Failure='AbsentRootWithValues'}
  ) {
    Mock Get-RideOfficeSource -ModuleName RIDE.OfficeInventory -ParameterFilter {$RegistryView -eq 'Registry64'} {
      if($Failure -eq 'Empty'){return}
      $r=New-OfficeTestSource
      switch($Failure){
        WrongType {$r.Values.Platform.Kind='DWord';$r.Values.Platform.Value=64}
        Excessive {$r.Values.ProductReleaseIds.Value='x'*4097}
        ControlCharacter {$r.Values.Platform.Value="x64`nprivate"}
        AbsentWithValue {$r.Values.Platform.Exists=$false}
        AbsentRootWithValues {$r.RootExists=$false}
      }
      $r
      if($Failure -eq 'PartialThrow'){throw 'private partial error'}
      if($Failure -eq 'Multiple'){$r}
    }
    $r=Get-RideOfficeInventory @CaptureArgs
    $r.Sources[0].Status|Should -BeExactly Unavailable
    $r.Sources[0].Values|Should -BeNullOrEmpty
    $r.Sources[1].Status|Should -BeExactly Captured
  }
}

Describe 'Office registry handle ownership' {
  BeforeEach {
    $base=New-OfficeFakeKey;$child=New-OfficeFakeKey;$base.Child=$child
    $row=New-OfficeTestSource
    foreach($property in $row.Values.PSObject.Properties){$child.Values[$property.Name]=$property.Value}
    $child.Values['PIDKEY']=[pscustomobject]@{Kind='String';Value='never-read'}
    $child.Values['AccountToken']=[pscustomobject]@{Kind='String';Value='never-read'}
    Mock Open-RideOfficeBaseKey -ModuleName RIDE.OfficeInventory {$base}
  }
  It 'reads exactly eight fields without expansion and disposes both read-only handles' {
    InModuleScope RIDE.OfficeInventory {$r=Get-RideOfficeSource -RegistryView Registry64;$r.RootExists|Should -BeTrue}
    $base.OpenCalls[0].Name|Should -BeExactly 'SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $base.OpenCalls[0].Writable|Should -BeFalse
    $base.Disposed|Should -BeTrue;$child.Disposed|Should -BeTrue
    $child.ReadCalls.Count|Should -Be 8
    $child.ReadCalls.Name|Should -Not -Contain PIDKEY
    $child.ReadCalls.Name|Should -Not -Contain AccountToken
    @($child.ReadCalls|Where-Object Options -ne ([Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)).Count|Should -Be 0
  }
  It 'closes both handles when a value read throws' {
    $child.ThrowOnRead=$true
    InModuleScope RIDE.OfficeInventory {{Get-RideOfficeSource -RegistryView Registry32}|Should -Throw '*fixture*'}
    $base.Disposed|Should -BeTrue;$child.Disposed|Should -BeTrue
  }
  It 'returns absent root metadata and closes the base handle' {
    $base.Child=$null
    InModuleScope RIDE.OfficeInventory {$r=Get-RideOfficeSource -RegistryView Registry64;$r.RootExists|Should -BeFalse;$r.Values|Should -BeNullOrEmpty}
    $base.Disposed|Should -BeTrue;$child.Disposed|Should -BeFalse
  }
}

Describe 'Office observation exclusive export' {
  BeforeEach {
    $script:ExportArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;OutputPath=(Join-Path $TestDrive (([guid]::NewGuid().ToString())+'.json'))}
    Mock Import-Module {}
    Mock Get-RideOfficeInventory {[pscustomobject]@{SchemaVersion=1;Kind='OfficeClickToRunObservation';Sources=@();ReadyForMutation=$false}}
  }
  It 'performs no inventory or file creation in WhatIf' {
    & (Join-Path $Root 'tools/Export-RideOfficeInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath|Should -BeFalse
    Should -Invoke Get-RideOfficeInventory -Exactly 0
  }
  It 'exports one new file and refuses an existing output before querying' {
    & (Join-Path $Root 'tools/Export-RideOfficeInventory.ps1') @ExportArgs|Should -Be $ExportArgs.OutputPath
    (Get-Content -LiteralPath $ExportArgs.OutputPath -Raw|ConvertFrom-Json).Kind|Should -BeExactly OfficeClickToRunObservation
    {& (Join-Path $Root 'tools/Export-RideOfficeInventory.ps1') @ExportArgs}|Should -Throw '*already exists*'
    Should -Invoke Get-RideOfficeInventory -Exactly 1
  }
  It 'preserves a racing output instead of overwriting it' {
    Mock Get-RideOfficeInventory {[IO.File]::WriteAllText($ExportArgs.OutputPath,'race');[pscustomobject]@{SchemaVersion=1}}
    {& (Join-Path $Root 'tools/Export-RideOfficeInventory.ps1') @ExportArgs}|Should -Throw
    [IO.File]::ReadAllText($ExportArgs.OutputPath)|Should -BeExactly race
  }
}
