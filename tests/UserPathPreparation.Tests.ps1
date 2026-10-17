<#
.SYNOPSIS
  Verify literal user PATH observation and entry-owned recovery without host changes.
.DESCRIPTION
  Uses synthetic records and mocked registry/context boundaries. Fake registry
  handles prove raw expansion and disposal; no real hive, PATH or directory changes.
.EXAMPLE
  Invoke-Pester .\tests\UserPathPreparation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; native lifecycle and environment refresh pending.
#>
BeforeDiscovery {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.UserPathPreparation.psm1') -Force
}
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.UserPathPreparation.psm1') -Force
  function New-PathObservation {
    param([AllowNull()][AllowEmptyString()][string]$Value='C:\Tools',[string]$Kind='ExpandString',[bool]$Exists=$true,[bool]$KeyExists=$true)
    [pscustomobject]@{SchemaVersion=1;Kind='UserPathObservation';Status='Captured';ReadyForMutation=$false
      Context=[pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserProfile='C:\Users\Fixture';NativeProcess=$true;UserInteractive=$true}
      Path=[pscustomobject]@{KeyExists=$KeyExists;Exists=$Exists;Kind=if($Exists){$Kind}else{$null};Value=if($Exists){$Value}else{$null}}}
  }
  function New-PathCurrent {
    param($Patch)
    $result=$Patch.Snapshot.Original|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $result.Path=$Patch.DesiredValue|ConvertTo-Json|ConvertFrom-Json
    $result
  }
}
Describe 'Persistent user-bin preparation and recovery' {
  It 'appends an absolute token and preserves every original byte and value kind' {
    $source=New-PathObservation 'C:\Tools;; C:\Other ;'
    $before=$source|ConvertTo-Json -Depth 8 -Compress
    $patch=New-RideUserBinPathPatch $source
    $patch.DesiredValue.Value|Should -BeExactly 'C:\Tools;; C:\Other ;;C:\Users\Fixture\bin'
    $patch.DesiredValue.Kind|Should -BeExactly 'ExpandString'
    $patch.Snapshot.OwnsEntry|Should -BeTrue
    $patch.ReadyForMutation|Should -BeFalse
    $patch.MutationAuthorized|Should -BeFalse
    $patch.DirectoryOwnership|Should -BeFalse
    $patch.EffectivePathVerified|Should -BeFalse
    ($source|ConvertTo-Json -Depth 8 -Compress)|Should -BeExactly $before
    $recovery=Restore-RideUserBinPathPatch (New-PathCurrent $patch) $patch.Snapshot
    $recovery.DesiredValue.Value|Should -BeExactly $source.Path.Value
    $recovery.DesiredValue.Kind|Should -BeExactly 'ExpandString'
  }
  It 'distinguishes absent and empty original value, retaining the Environment key' -ForEach @(
    @{Exists=$false;KeyExists=$false;Kind='String'},@{Exists=$false;KeyExists=$true;Kind='String'},
    @{Exists=$true;KeyExists=$true;Kind='String'},@{Exists=$true;KeyExists=$true;Kind='ExpandString'}
  ) {
    $original=New-PathObservation -Value '' -Exists $Exists -KeyExists $KeyExists -Kind $Kind
    $patch=New-RideUserBinPathPatch $original
    $patch.DesiredValue.Value|Should -BeExactly 'C:\Users\Fixture\bin'
    $patch.DesiredValue.KeyExists|Should -BeTrue
    $recovery=Restore-RideUserBinPathPatch (New-PathCurrent $patch) $patch.Snapshot
    $recovery.DesiredValue.Exists|Should -Be $Exists
    $recovery.DesiredValue.KeyExists|Should -BeTrue
    $recovery.DesiredValue.Value|Should -Be $original.Path.Value
    $recovery.DesiredValue.Kind|Should -Be $original.Path.Kind
  }
  It 'does not own a pre-existing equivalent entry <Value>' -ForEach @(
    @{Value='c:\users\fixture\BIN'},@{Value='"C:\Users\Fixture\bin\"'},
    @{Value=' C:/Users/Fixture/bin/ '},@{Value='%USERPROFILE%\bin'},
    @{Value='C:\Users\Fixture\bin;C:\USERS\FIXTURE\BIN'}
  ) {
    $patch=New-RideUserBinPathPatch (New-PathObservation $Value)
    $patch.Snapshot.OwnsEntry|Should -BeFalse
    $patch.ChangeRequired|Should -BeFalse
    $patch.DesiredValue.Value|Should -BeExactly $Value
    $current=New-PathCurrent $patch;$current.Path.Value+=';D:\New'
    $recovery=Restore-RideUserBinPathPatch $current $patch.Snapshot
    $recovery.ChangeRequired|Should -BeFalse
    $recovery.DesiredValue.Value|Should -BeExactly $current.Path.Value
  }
  It 'removes only its owned token while preserving unrelated edits and order' -ForEach @(
    @{Value='C:\Changed;C:\Users\Fixture\bin;D:\New';Expected='C:\Changed;D:\New'},
    @{Value='C:\Users\Fixture\bin;D:\New';Expected='D:\New'},
    @{Value=';C:\Users\Fixture\bin;';Expected=';'},
    @{Value='C:\One;;C:\Users\Fixture\bin;D:\Two;;';Expected='C:\One;;D:\Two;;'}
  ) {
    $patch=New-RideUserBinPathPatch (New-PathObservation)
    $current=New-PathCurrent $patch;$current.Path.Value=$Value
    $recovery=Restore-RideUserBinPathPatch $current $patch.Snapshot
    $recovery.DesiredValue.Value|Should -BeExactly $Expected
    $recovery.ChangeRequired|Should -BeTrue
    $current.Path.Value|Should -BeExactly $Value
  }
  It 'preserves a new unrelated value when the original PATH was absent' {
    $patch=New-RideUserBinPathPatch (New-PathObservation -Exists $false)
    $current=New-PathCurrent $patch;$current.Path.Value+=';D:\New'
    $recovery=Restore-RideUserBinPathPatch $current $patch.Snapshot
    $recovery.DesiredValue.Exists|Should -BeTrue
    $recovery.DesiredValue.Value|Should -BeExactly 'D:\New'
  }
  It 'is a no-op after prior restoration, external removal or absent current value' {
    $patch=New-RideUserBinPathPatch (New-PathObservation)
    foreach($current in @($patch.Snapshot.Original,(New-PathObservation 'D:\Other'),(New-PathObservation -Exists $false))){
      (Restore-RideUserBinPathPatch $current $patch.Snapshot).ChangeRequired|Should -BeFalse
    }
  }
  It 'refuses changed spelling or equivalent duplicates of an owned entry' -ForEach @(
    @{Value='C:\Tools;c:\users\fixture\bin'},@{Value='C:\Tools;%USERPROFILE%\bin'},
    @{Value='C:\Users\Fixture\bin;C:\Users\Fixture\bin'},@{Value='C:\Users\Fixture\bin;"C:\Users\Fixture\BIN"'}
  ) {
    $patch=New-RideUserBinPathPatch (New-PathObservation)
    $current=New-PathCurrent $patch;$current.Path.Value=$Value
    {Restore-RideUserBinPathPatch $current $patch.Snapshot}|Should -Throw '*conflicts*'
  }
  It 'refuses changing registry kind during recovery' {
    $patch=New-RideUserBinPathPatch (New-PathObservation)
    $current=New-PathCurrent $patch;$current.Path.Kind='String'
    {Restore-RideUserBinPathPatch $current $patch.Snapshot}|Should -Throw '*kind conflicts*'
  }
  It 'refuses unknown expansion, literal percent, malformed quotes and ambiguous path syntax' -ForEach @(
    @{Value='%LOCALAPPDATA%\Tools';Kind='ExpandString'},@{Value='%PATH%';Kind='ExpandString'},
    @{Value='%USERPROFILE%\bin';Kind='String'},@{Value='C:\Tools"';Kind='String'},
    @{Value='C:\Tools.\App';Kind='String'},@{Value='C:\Other\..\bin';Kind='String'},@{Value='C:\Tools:stream';Kind='String'}
  ) {
    {New-RideUserBinPathPatch (New-PathObservation $Value $Kind)}|Should -Throw
  }
  It 'does not resolve references through a poisoned process environment' {
    $prior=$env:USERPROFILE
    try{$env:USERPROFILE='Z:\Wrong';$patch=New-RideUserBinPathPatch (New-PathObservation '%USERPROFILE%\bin');$patch.ChangeRequired|Should -BeFalse}
    finally{$env:USERPROFILE=$prior}
  }
  It 'refuses too-long append and preserves Unicode without truncation' {
    {New-RideUserBinPathPatch (New-PathObservation ('C:\T;'*6550))}|Should -Throw '*limit*'
    $source=New-PathObservation ('C:\Tools\'+[char]0x00e6)
    $patch=New-RideUserBinPathPatch $source
    (Restore-RideUserBinPathPatch (New-PathCurrent $patch) $patch.Snapshot).DesiredValue.Value|Should -BeExactly $source.Path.Value
  }
  It 'refuses invalid raw values, readiness and identities' {
    foreach($alter in @(
      {$args[0].Path.Kind='MultiString'},{$args[0].Path.Value="bad`npath"},{$args[0].Path.Exists='true'},
      {$args[0].Path.KeyExists=$false},{$args[0].SchemaVersion='1'},{$args[0].ReadyForMutation=$true},
      {$args[0].Context.SessionId=0},{$args[0].Context.UserInteractive=$false},{$args[0].Context.NativeProcess=$false},
      {$args[0].Context.UserSid='someone'},{$args[0].Context.UserProfile='\\server\profile'},{$args[0].Context.UserProfile='C:\Users\..\Other'}
    )){$source=New-PathObservation;& $alter $source;{New-RideUserBinPathPatch $source}|Should -Throw}
  }
  It 'binds recovery to the original machine user session and profile' -ForEach @(
    @{Field='ComputerName';Value='OTHER'},@{Field='UserSid';Value='S-1-5-21-1-2-3-1002'},
    @{Field='SessionId';Value=2},@{Field='UserProfile';Value='D:\Users\Fixture'}
  ) {
    $patch=New-RideUserBinPathPatch (New-PathObservation);$current=New-PathCurrent $patch;$current.Context.$Field=$Value
    {Restore-RideUserBinPathPatch $current $patch.Snapshot}|Should -Throw '*identity changed*'
  }
  It 'reconstructs snapshots after JSON round trips and refuses altered ownership' {
    $patch=New-RideUserBinPathPatch (New-PathObservation)
    $saved=$patch.Snapshot|ConvertTo-Json -Depth 8|ConvertFrom-Json
    (Restore-RideUserBinPathPatch (New-PathCurrent $patch) $saved).DesiredValue.Value|Should -BeExactly 'C:\Tools'
    foreach($alter in @({$args[0].OwnsEntry=$false},{$args[0].Entry='D:\Other'},{$args[0].ExpectedValue.Value='D:\Other'},{$args[0].SchemaVersion=2})){
      $saved=$patch.Snapshot|ConvertTo-Json -Depth 8|ConvertFrom-Json;& $alter $saved
      {Restore-RideUserBinPathPatch (New-PathCurrent $patch) $saved}|Should -Throw
    }
  }
}

Describe 'Read-only intended-user PATH observation' {
  BeforeEach {
    $script:sample=New-PathObservation
    Mock Get-RideUserPathContext -ModuleName RIDE.UserPathPreparation { $script:sample.Context }
    Mock Read-RideUserPathValue -ModuleName RIDE.UserPathPreparation { $script:sample.Path }
  }
  It 'captures literal values and rechecks identity without touching process PATH' {
    $processPath=$env:Path
    $result=Get-RideUserBinPathObservation TEST-VM S-1-5-21-1-2-3-1001 1
    $result.Path.Value|Should -BeExactly 'C:\Tools'
    $result.ReadyForMutation|Should -BeFalse
    Should -Invoke Get-RideUserPathContext -ModuleName RIDE.UserPathPreparation -Times 2 -Exactly
    $env:Path|Should -BeExactly $processPath
  }
  It 'refuses wrong expected targets before any registry query' -ForEach @(
    @{Computer='OTHER';Sid='S-1-5-21-1-2-3-1001';Session=1},
    @{Computer='TEST-VM';Sid='S-1-5-21-1-2-3-1002';Session=1},
    @{Computer='TEST-VM';Sid='S-1-5-21-1-2-3-1001';Session=2}
  ) {
    {Get-RideUserBinPathObservation $Computer $Sid $Session}|Should -Throw '*intended*'
    Should -Invoke Read-RideUserPathValue -ModuleName RIDE.UserPathPreparation -Times 0 -Exactly
  }
  It 'refuses context drift and never converts read errors into absence' {
    Mock Read-RideUserPathValue -ModuleName RIDE.UserPathPreparation {$script:sample.Context.SessionId=2;$script:sample.Path}
    {Get-RideUserBinPathObservation TEST-VM S-1-5-21-1-2-3-1001 1}|Should -Throw '*changed during*'
    $script:sample=New-PathObservation
    Mock Read-RideUserPathValue -ModuleName RIDE.UserPathPreparation {throw 'fixture denied'}
    {Get-RideUserBinPathObservation TEST-VM S-1-5-21-1-2-3-1001 1}|Should -Throw '*denied*'
  }
}

Describe 'Literal registry handle contract' {
  InModuleScope RIDE.UserPathPreparation {
    BeforeEach {
      $script:fakeKey=[pscustomobject]@{Disposed=$false;Names=@('Path');Raw='%USERPROFILE%\bin';RawKind='ExpandString';Fail=$false;ReceivedOption=$null}
      $script:fakeKey|Add-Member ScriptMethod GetValueNames {return ,$this.Names}
      $script:fakeKey|Add-Member ScriptMethod GetValueKind {param($name)if($this.Fail){throw 'fixture kind failure'};return $this.RawKind}
      $script:fakeKey|Add-Member ScriptMethod GetValue {param($name,$fallback,$option)$this.ReceivedOption=$option;return $this.Raw}
      $script:fakeKey|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
      Mock Open-RideUserPathKey {$script:fakeKey}
    }
    It 'requests literal data and disposes its readonly handle' {
      $result=Read-RideUserPathValue
      $result.Value|Should -BeExactly '%USERPROFILE%\bin'
      $script:fakeKey.ReceivedOption|Should -Be ([Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      $script:fakeKey.Disposed|Should -BeTrue
    }
    It 'retains missing key versus missing value and empty data' {
      $script:fakeKey.Names=@('OTHER');$missing=Read-RideUserPathValue
      $missing.KeyExists|Should -BeTrue;$missing.Exists|Should -BeFalse
      $script:fakeKey.Names=@('pAtH');$script:fakeKey.Raw='';$empty=Read-RideUserPathValue
      $empty.Exists|Should -BeTrue;$empty.Value|Should -BeExactly ''
      Mock Open-RideUserPathKey {$null};$missing=Read-RideUserPathValue
      $missing.KeyExists|Should -BeFalse;$missing.Exists|Should -BeFalse
    }
    It 'disposes on failed, invalid, duplicate or over-limit reads' {
      $script:fakeKey.Fail=$true;{Read-RideUserPathValue}|Should -Throw '*fixture*';$script:fakeKey.Disposed|Should -BeTrue
      $script:fakeKey.Fail=$false;$script:fakeKey.Disposed=$false;$script:fakeKey.RawKind='DWord'
      {Read-RideUserPathValue}|Should -Throw;$script:fakeKey.Disposed|Should -BeTrue
      $script:fakeKey.Names=@('PATH','Path');{Read-RideUserPathValue}|Should -Throw '*Ambiguous*'
      $script:fakeKey.Names=@('a')*4097;{Read-RideUserPathValue}|Should -Throw '*bound*'
    }
  }
}
