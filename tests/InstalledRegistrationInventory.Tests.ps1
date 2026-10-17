<#
.SYNOPSIS
  Verify uninstall inventory using mocked sources and fake registry handles.
.DESCRIPTION
  No real registry, installed product, installer or state-store query is performed.
  Checks source separation, partial failure, raw types, identity guards and cleanup.
.EXAMPLE
  Invoke-Pester .\tests\InstalledRegistrationInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; native registry-view acceptance remains pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.InstalledRegistrationInventory.psm1') -Force
  function New-RegistrationContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;Is64BitOperatingSystem=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
  }
  function New-RegistrationRow {
    param([string]$Name='Example registration')
    [pscustomobject]@{KeyName=$Name;Values=[pscustomobject]@{
      DisplayName=[pscustomobject]@{Exists=$true;Kind='String';Value='Example product'}
      DisplayVersion=[pscustomobject]@{Exists=$true;Kind='String';Value='1.2.3'}
      Publisher=[pscustomobject]@{Exists=$true;Kind='String';Value='Example publisher'}
      InstallLocation=[pscustomobject]@{Exists=$true;Kind='ExpandString';Value='%LOCALAPPDATA%\Example'}
      WindowsInstaller=[pscustomobject]@{Exists=$true;Kind='DWord';Value=1}
      SystemComponent=[pscustomobject]@{Exists=$false;Kind=$null;Value=$null}
    };UninstallString='never execute or retain';Private='omit'}
  }
  function New-FakeRegistrationHandle {
    $h=[pscustomobject]@{Disposed=$false;Child=$null;Names=@('Example registration');Values=@{};ThrowOnRead=$false;OpenCalls=[Collections.Generic.List[object]]::new();ReadCalls=[Collections.Generic.List[object]]::new()}
    $h|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
    $h|Add-Member ScriptMethod OpenSubKey {param($name,$writable);$this.OpenCalls.Add(@{Name=$name;Writable=$writable});$this.Child}
    $h|Add-Member ScriptMethod GetSubKeyNames {$this.Names}
    $h|Add-Member ScriptMethod GetValueNames {$this.Values.Keys}
    $h|Add-Member ScriptMethod GetValueKind {param($name);$this.Values[$name].Kind}
    $h|Add-Member ScriptMethod GetValue {param($name,$default,$options);$this.ReadCalls.Add(@{Name=$name;Options=$options});if($this.ThrowOnRead){throw 'fixture read failure'};$this.Values[$name].Value}
    $h
  }
}
Describe 'Explicit installed registration sources' {
  BeforeEach {
    $script:CaptureArgs=@{Scope=@('Machine','User');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1}
    Mock Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory {New-RegistrationContext}
    Mock Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory {[pscustomobject]@{RootExists=$true;Entries=@((New-RegistrationRow))}}
  }
  It 'keeps all four scope/view identities without merging identical registration names' {
    $r=Get-RideInstalledRegistrationInventory @CaptureArgs
    ($r.Sources.Scope -join ',')|Should -BeExactly 'Machine,Machine,User,User'
    ($r.Sources.RegistryView -join ',')|Should -BeExactly 'Registry64,Registry32,Registry64,Registry32'
    @($r.Sources|Where-Object Status -eq Captured).Count|Should -Be 4
    @($r.Sources|ForEach-Object {$_.Entries}).Count|Should -Be 4
    $value=$r.Sources[0].Entries[0].Values.InstallLocation
    $value.Value|Should -BeExactly '%LOCALAPPDATA%\Example';$value.Kind|Should -BeExactly ExpandString
    $r.Sources[0].Entries[0].OwnershipVerified|Should -BeFalse
    $r.ReadyForMutation|Should -BeFalse;$r.RecoverySupported|Should -BeFalse
    ($r|ConvertTo-Json -Depth 12)|Should -Not -Match 'UninstallString|never execute|Private|omit'
  }
  It 'selects only the requested scope and only the 32-bit view on a 32-bit OS' {
    $context=New-RegistrationContext;$context.Is64BitOperatingSystem=$false
    Mock Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory {$context}
    $CaptureArgs.Scope=@('user');$r=Get-RideInstalledRegistrationInventory @CaptureArgs
    $r.Sources.Count|Should -Be 1;$r.Sources[0].Scope|Should -BeExactly User
    $r.Sources[0].RegistryView|Should -BeExactly Registry32
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 1 -ParameterFilter {$Scope -ceq 'User' -and $RegistryView -ceq 'Registry32'}
  }
  It 'distinguishes a captured missing root from an unavailable source' {
    Mock Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory {
      param($Scope,$RegistryView)
      if($Scope -eq 'Machine' -and $RegistryView -eq 'Registry64'){throw 'secret fixture error'}
      [pscustomobject]@{RootExists=$false;Entries=@()}
    }
    $r=Get-RideInstalledRegistrationInventory @CaptureArgs
    $r.Sources[0].Status|Should -Be Unavailable;($null -eq $r.Sources[0].RootExists)|Should -BeTrue
    $r.Sources[1].Status|Should -Be Captured;$r.Sources[1].RootExists|Should -BeFalse
    $r.Sources[1].Entries.Count|Should -Be 0
    ($r|ConvertTo-Json -Depth 12)|Should -Not -Match 'secret fixture'
  }
  It 'discards partial source output after a terminating error and continues independent sources' {
    Mock Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory {
      param($Scope)
      [pscustomobject]@{RootExists=$true;Entries=@((New-RegistrationRow))}
      if($Scope -eq 'Machine'){throw 'partial'}
    }
    $r=Get-RideInstalledRegistrationInventory @CaptureArgs
    $r.Sources[0].Entries.Count|Should -Be 0;$r.Sources[0].Status|Should -Be Unavailable
    $r.Sources[2].Entries.Count|Should -Be 1;$r.Sources[2].Status|Should -Be Captured
  }
  It 'preserves explicit empty strings, absent fields and unsigned DWord bits' {
    $row=New-RegistrationRow;$row.Values.DisplayName.Value='';$row.Values.WindowsInstaller.Value=[int]-1
    Mock Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory {[pscustomobject]@{RootExists=$true;Entries=@($row)}}
    $r=Get-RideInstalledRegistrationInventory @CaptureArgs;$values=$r.Sources[0].Entries[0].Values
    $values.DisplayName.Exists|Should -BeTrue;$values.DisplayName.Value|Should -BeExactly ''
    $values.SystemComponent.Exists|Should -BeFalse;($null -eq $values.SystemComponent.Value)|Should -BeTrue
    $values.WindowsInstaller.Value|Should -Be 4294967295
  }
  It 'rejects duplicate scope selection before context or source queries' {
    $CaptureArgs.Scope=@('User','user')
    {Get-RideInstalledRegistrationInventory @CaptureArgs}|Should -Throw '*once*'
    Should -Invoke Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
  }
  It 'refuses wrong target <Field> before source queries' -ForEach @(
    @{Field='ComputerName';Value='OTHER'},@{Field='Build';Value='26200'},@{Field='EditionId';Value='Enterprise'},
    @{Field='UserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='SessionId';Value=2},@{Field='NativeProcess';Value=$false},
    @{Field='UserInteractive';Value=$false},@{Field='UpdateBuildRevision';Value='1'},@{Field='Is64BitOperatingSystem';Value='true'}
  ) {
    $context=New-RegistrationContext;$context.$Field=$Value
    Mock Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory {$context}
    {Get-RideInstalledRegistrationInventory @CaptureArgs}|Should -Throw
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
  }
  It 'refuses context drift after collection' {
    $state=@{Calls=0}
    Mock Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory {$state.Calls++;$c=New-RegistrationContext;if($state.Calls -gt 1){$c.UpdateBuildRevision=2};$c}
    {Get-RideInstalledRegistrationInventory @CaptureArgs}|Should -Throw '*changed*'
  }
  It 'discards invalid source shape <Case>' -ForEach @(
    @{Case='NoOutput'},@{Case='TwoOutputs'},@{Case='MissingEntries'},@{Case='MissingRootWithRows'},@{Case='DuplicateKeys'},@{Case='TooMany'}
  ) {
    Mock Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory {
      switch($Case){
        NoOutput {return}
        TwoOutputs {[pscustomobject]@{RootExists=$false;Entries=@()};[pscustomobject]@{RootExists=$false;Entries=@()}}
        MissingEntries {[pscustomobject]@{RootExists=$true}}
        MissingRootWithRows {[pscustomobject]@{RootExists=$false;Entries=@((New-RegistrationRow))}}
        DuplicateKeys {[pscustomobject]@{RootExists=$true;Entries=@((New-RegistrationRow 'KEY'),(New-RegistrationRow 'key'))}}
        TooMany {[pscustomobject]@{RootExists=$true;Entries=@(for($i=0;$i -lt 2049;$i++){New-RegistrationRow ('key'+$i)})}}
      }
    }
    $CaptureArgs.Scope=@('User');$r=Get-RideInstalledRegistrationInventory @CaptureArgs
    @($r.Sources|Where-Object Status -eq Unavailable).Count|Should -Be 2
    @($r.Sources|ForEach-Object {$_.Entries}).Count|Should -Be 0
  }
  It 'refuses malformed metadata <Case>' -ForEach @(
    @{Case='KeyPath'},@{Case='LongValue'},@{Case='BadKind'},@{Case='AbsentWithData'},@{Case='NonLiteralExists'},@{Case='NumericString'}
  ) {
    $row=New-RegistrationRow
    switch($Case){
      KeyPath {$row.KeyName='a\b'}
      LongValue {$row.Values.Publisher.Value='x'*4097}
      BadKind {$row.Values.DisplayName.Kind='MultiString'}
      AbsentWithData {$row.Values.SystemComponent.Value=1}
      NonLiteralExists {$row.Values.DisplayVersion.Exists='true'}
      NumericString {$row.Values.WindowsInstaller.Value='1'}
    }
    Mock Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory {[pscustomobject]@{RootExists=$true;Entries=@($row)}}
    $r=Get-RideInstalledRegistrationInventory @CaptureArgs
    $r.Sources[0].Status|Should -Be Unavailable;$r.Sources[0].Entries.Count|Should -Be 0
  }
  It 'completes finite scopes without any context or registry query' {
    $line='Get-RideInstalledRegistrationInventory -Scope Ma';$r=TabExpansion2 $line $line.Length
    $r.CompletionMatches.CompletionText|Should -Contain Machine
    Should -Invoke Get-RideInstalledRegistrationContext -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
    Should -Invoke Get-RideInstalledRegistrationSource -ModuleName RIDE.InstalledRegistrationInventory -Exactly 0
  }
}
Describe 'Registry handle ownership with fake objects' {
  BeforeEach {
    $base=New-FakeRegistrationHandle;$rootKey=New-FakeRegistrationHandle;$child=New-FakeRegistrationHandle
    $base.Child=$rootKey;$rootKey.Child=$child
    $row=New-RegistrationRow
    foreach($p in $row.Values.PSObject.Properties){if($p.Value.Exists){$child.Values[$p.Name]=$p.Value}}
    Mock Open-RideInstalledRegistrationBaseKey -ModuleName RIDE.InstalledRegistrationInventory {$base}
  }
  It 'opens child keys read-only, avoids environment expansion and closes every handle' {
    InModuleScope RIDE.InstalledRegistrationInventory {
      $r=Get-RideInstalledRegistrationSource -Scope User -RegistryView Registry64
      $r.Entries[0].Values.InstallLocation.Value|Should -BeExactly '%LOCALAPPDATA%\Example'
    }
    $base.OpenCalls[0].Writable|Should -BeFalse;$rootKey.OpenCalls[0].Writable|Should -BeFalse
    $base.Disposed|Should -BeTrue;$rootKey.Disposed|Should -BeTrue;$child.Disposed|Should -BeTrue
    @($child.ReadCalls|Where-Object Options -ne ([Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)).Count|Should -Be 0
    $child.ReadCalls.Count|Should -Be 5
  }
  It 'closes all opened handles when a value read fails' {
    $child.ThrowOnRead=$true
    InModuleScope RIDE.InstalledRegistrationInventory {{Get-RideInstalledRegistrationSource -Scope Machine -RegistryView Registry32}|Should -Throw '*fixture*'}
    $base.Disposed|Should -BeTrue;$rootKey.Disposed|Should -BeTrue;$child.Disposed|Should -BeTrue
  }
  It 'treats a missing root as captured empty and closes the base' {
    $base.Child=$null
    InModuleScope RIDE.InstalledRegistrationInventory {$r=Get-RideInstalledRegistrationSource -Scope Machine -RegistryView Registry64;$r.RootExists|Should -BeFalse;$r.Entries.Count|Should -Be 0}
    $base.Disposed|Should -BeTrue;$rootKey.Disposed|Should -BeFalse
  }
  It 'refuses a disappearing child instead of quietly dropping it' {
    $rootKey.Child=$null
    InModuleScope RIDE.InstalledRegistrationInventory {{Get-RideInstalledRegistrationSource -Scope User -RegistryView Registry32}|Should -Throw '*disappeared*'}
    $base.Disposed|Should -BeTrue;$rootKey.Disposed|Should -BeTrue
  }
}
Describe 'Exclusive registration export' {
  BeforeEach {
    $script:ExportArgs=@{Scope=@('Machine','User');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;OutputPath=(Join-Path $TestDrive (([guid]::NewGuid().ToString())+'.json'))}
    Mock Import-Module {}
    Mock Get-RideInstalledRegistrationInventory {[pscustomobject]@{SchemaVersion=1;Kind='InstalledRegistrationObservation';Sources=@();ReadyForMutation=$false}}
  }
  It 'performs no query or write in WhatIf' {
    & (Join-Path $Root 'tools/Export-RideInstalledRegistrationInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath|Should -BeFalse
    Should -Invoke Get-RideInstalledRegistrationInventory -Exactly 0
  }
  It 'exports one new JSON file and refuses existing output before collection' {
    & (Join-Path $Root 'tools/Export-RideInstalledRegistrationInventory.ps1') @ExportArgs|Should -Be $ExportArgs.OutputPath
    (Get-Content -LiteralPath $ExportArgs.OutputPath -Raw|ConvertFrom-Json).Kind|Should -Be InstalledRegistrationObservation
    {& (Join-Path $Root 'tools/Export-RideInstalledRegistrationInventory.ps1') @ExportArgs}|Should -Throw '*already exists*'
    Should -Invoke Get-RideInstalledRegistrationInventory -Exactly 1
  }
  It 'retains a racing output instead of overwriting it' {
    Mock Get-RideInstalledRegistrationInventory {[IO.File]::WriteAllText($ExportArgs.OutputPath,'race');[pscustomobject]@{SchemaVersion=1}}
    {& (Join-Path $Root 'tools/Export-RideInstalledRegistrationInventory.ps1') @ExportArgs}|Should -Throw
    [IO.File]::ReadAllText($ExportArgs.OutputPath)|Should -BeExactly race
  }
}
