<#
.SYNOPSIS
  Verify proxy observation identity, native memory ownership and export boundaries.
.DESCRIPTION
  Uses fake unmanaged query/write boundaries and mocked identity/policy. No Windows
  proxy query, PAC retrieval, connectivity check, registry query/write or WinINet setter is called.
.EXAMPLE
  Invoke-Pester .\tests\UserProxyInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x, Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture.
  Changelog: Add mocked documented policy-block and fail-closed refusal coverage.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  $source=Get-Content -LiteralPath (Join-Path $Root 'modules/RIDE.UserProxyInventory.psm1') -Raw
  $native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
  $fake=@'
namespace Ride.UserProxyInventoryV1 {
  public sealed class FakeApi : IQueryApi {
    public int Calls; public int Freed; public int Allocated; public int FailCall;
    public bool ChangeFlags; public bool MalformedList; public bool WrongId; public bool ThrowOnFree;
    public bool DuplicatePointers; public bool FailUi;
    public uint Flags=15; public string Server="http=proxy.test:8080;https=secure.test:8081";
    public string Bypass="<local>;*.internal.test"; public string Url="https://pac.test/config.pac?x=1";
    public System.Collections.Generic.List<uint> FlagOptions=new System.Collections.Generic.List<uint>();
    public void ClearServer() {Server=null;}
    private System.Collections.Generic.HashSet<System.IntPtr> outstanding=new System.Collections.Generic.HashSet<System.IntPtr>();
    private System.IntPtr Allocate(string text) {
      if(text==null)return System.IntPtr.Zero;
      var pointer=System.Runtime.InteropServices.Marshal.StringToHGlobalUni(text);
      outstanding.Add(pointer);Allocated++;return pointer;
    }
    public bool Query(ref OptionList list,ref uint length,out int error) {
      Calls++;error=0;
      int size=System.Runtime.InteropServices.Marshal.SizeOf(typeof(Option));
      if(list.Connection!=System.IntPtr.Zero || list.Count!=1 && list.Count!=4)throw new System.Exception("Unexpected query scope/count");
      var first=(Option)System.Runtime.InteropServices.Marshal.PtrToStructure(list.Options,typeof(Option));
      FlagOptions.Add(first.Id);first.Value.Number=ChangeFlags && list.Count==4 ? Flags^8 : Flags;
      System.Runtime.InteropServices.Marshal.StructureToPtr(first,list.Options,false);
      if(list.Count==4) {
        string[] strings=new string[]{Server,Bypass,Url};System.IntPtr previous=System.IntPtr.Zero;
        for(int i=1;i<4;i++) {
          var pointer=System.IntPtr.Add(list.Options,i*size);
          var option=(Option)System.Runtime.InteropServices.Marshal.PtrToStructure(pointer,typeof(Option));
          if(option.Id!=(uint)(i+1))throw new System.Exception("Unexpected string option");
          option.Value.Text=DuplicatePointers && i>1 ? previous : Allocate(strings[i-1]);
          previous=option.Value.Text;if(WrongId)option.Id=99;
          System.Runtime.InteropServices.Marshal.StructureToPtr(option,pointer,false);
        }
        if(MalformedList)list.Count=99;
      }
      if(Calls==FailCall || FailUi && first.Id==10){error=87;return false;}return true;
    }
    public void FreeReturnedString(System.IntPtr text) {
      if(!outstanding.Remove(text))throw new System.Exception("Double/unowned free");
      System.Runtime.InteropServices.Marshal.FreeHGlobal(text);Freed++;
      if(ThrowOnFree && Freed==1)throw new System.Exception("Injected cleanup report");
    }
    public int Outstanding {get{return outstanding.Count;}}
  }
  public sealed class FakeWriteApi : IWriteApi {
    public bool FailSet; public bool FailSettingsChanged; public bool FailRefresh;
    public int SetCalls; public uint Flags; public string Url;
    public System.Collections.Generic.List<uint> OptionIds=new System.Collections.Generic.List<uint>();
    public System.Collections.Generic.List<uint> Notifications=new System.Collections.Generic.List<uint>();
    public bool Set(ref OptionList list,ref uint length,out int error) {
      SetCalls++;error=0;
      int size=System.Runtime.InteropServices.Marshal.SizeOf(typeof(Option));
      if(list.Connection!=System.IntPtr.Zero || length!=list.Size || list.Count<1 || list.Count>2)throw new System.Exception("Unexpected write scope/count");
      var flag=(Option)System.Runtime.InteropServices.Marshal.PtrToStructure(list.Options,typeof(Option));
      if(flag.Id!=1)throw new System.Exception("Writer must restore flags through INTERNET_PER_CONN_FLAGS");
      OptionIds.Add(flag.Id);Flags=flag.Value.Number;
      if(list.Count==2) {
        var url=(Option)System.Runtime.InteropServices.Marshal.PtrToStructure(System.IntPtr.Add(list.Options,size),typeof(Option));
        if(url.Id!=4 || url.Value.Text==System.IntPtr.Zero)throw new System.Exception("Expected an owned PAC URL option");
        OptionIds.Add(url.Id);Url=System.Runtime.InteropServices.Marshal.PtrToStringUni(url.Value.Text);
      }
      error=FailSet?55:0;return !FailSet;
    }
    public bool Notify(uint option,out int error) {
      Notifications.Add(option);error=option==39 && FailSettingsChanged?87:option==37 && FailRefresh?123:0;
      return error==0;
    }
  }
}
'@
  if(-not ('Ride.UserProxyInventoryV1.Reader' -as [type])){Add-Type -TypeDefinition ($native+"`n"+$fake)}
  Import-Module (Join-Path $Root 'modules/RIDE.UserProxyInventory.psm1') -Force
  function New-ProxySnapshot {
    [pscustomobject]@{Flags=[uint32]15;FlagsSource='FlagsUi';UiQueryError=$null;ProxyServer='http=proxy.test:80';ProxyBypass='<local>;*.test';AutoConfigUrl='https://pac.test/a.pac'}
  }
}
Describe 'WinINet default/LAN writer buffer contract with a fake native API' {
  BeforeEach {$script:WriteApi=[Ride.UserProxyInventoryV1.FakeWriteApi]::new()}
  It 'writes only the owned flags and notifies then refreshes' {
    $r=[Ride.UserProxyInventoryV1.Writer]::WriteWithApi($WriteApi,[uint32]7,$null,$false)
    $r.ConfigurationSet|Should -BeTrue
    $r.SettingsChangedNotified|Should -BeTrue
    $r.Refreshed|Should -BeTrue
    ($WriteApi.OptionIds -join ',')|Should -BeExactly '1'
    ($WriteApi.Notifications -join ',')|Should -BeExactly '39,37'
    $WriteApi.Flags|Should -Be 7
    $WriteApi.Url|Should -BeNullOrEmpty
  }
  It 'writes an owned exact PAC URL through the PAC option without touching manual settings' {
    $url='https://proxy.test/å.pac?tenant=one'
    $r=[Ride.UserProxyInventoryV1.Writer]::WriteWithApi($WriteApi,[uint32]13,$url,$true)
    $r.ConfigurationSet|Should -BeTrue
    ($WriteApi.OptionIds -join ',')|Should -BeExactly '1,4'
    $WriteApi.Flags|Should -Be 13
    $WriteApi.Url|Should -BeExactly $url
  }
  It 'does not notify after a failed configuration write and preserves the native error' {
    $WriteApi.FailSet=$true
    $r=[Ride.UserProxyInventoryV1.Writer]::WriteWithApi($WriteApi,[uint32]7,$null,$false)
    $r.ConfigurationSet|Should -BeFalse
    $r.ConfigurationError|Should -Be 55
    $r.SettingsChangedNotified|Should -BeFalse
    $WriteApi.Notifications.Count|Should -Be 0
  }
  It 'reports notification and refresh failures separately after a successful write' {
    $WriteApi.FailSettingsChanged=$true;$WriteApi.FailRefresh=$true
    $r=[Ride.UserProxyInventoryV1.Writer]::WriteWithApi($WriteApi,[uint32]7,$null,$false)
    $r.ConfigurationSet|Should -BeTrue
    $r.SettingsChangedNotified|Should -BeFalse
    $r.SettingsChangedError|Should -Be 87
    $r.Refreshed|Should -BeFalse
    $r.RefreshError|Should -Be 123
    ($WriteApi.Notifications -join ',')|Should -BeExactly '39,37'
  }
  It 'refuses an invalid owned PAC URL before calling the native boundary' {
    { [Ride.UserProxyInventoryV1.Writer]::WriteWithApi($WriteApi,[uint32]7,'',$true) } | Should -Throw '*bounded nonempty string*'
    $WriteApi.SetCalls|Should -Be 0
  }
}
Describe 'ShouldProcess and identity guard for the low-level user proxy writer' {
  BeforeEach {
    Mock Get-RideUserProxyContext -ModuleName RIDE.UserProxyInventory {
      [pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
    }
    Mock Invoke-RideUserProxyNativeWrite -ModuleName RIDE.UserProxyInventory {
      [pscustomobject]@{ConfigurationSet=$true;ConfigurationError=0;SettingsChangedNotified=$true;SettingsChangedError=0;Refreshed=$true;RefreshError=0}
    }
    Mock Get-RideUserProxyPolicyObservation -ModuleName RIDE.UserProxyInventory {
      [pscustomobject]@{KnownPolicyStatus='Clear';InspectedValues=@();BlockingValues=@();UnknownValues=@()}
    }
  }
  It 'refuses a different computer, user or session before the native writer' -TestCases @(
    @{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedUserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='ExpectedSessionId';Value=2}
  ) {
    param($Field,$Value)
    $arguments=@{Flags=13;AutoConfigUrl='https://pac.test/a.pac';OwnsAutoConfigUrl=$true;ExpectedComputerName='TEST-VM';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;Confirm=$false}
    $arguments[$Field]=$Value
    {Set-RideUserProxyNativeConfiguration @arguments}|Should -Throw '*identity differs*'
    Should -Invoke Invoke-RideUserProxyNativeWrite -ModuleName RIDE.UserProxyInventory -Exactly 0
  }
  It 'refuses a noninteractive execution context' {
    Mock Get-RideUserProxyContext -ModuleName RIDE.UserProxyInventory {[pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$false}}
    {Set-RideUserProxyNativeConfiguration -Flags 13 -AutoConfigUrl 'https://pac.test/a.pac' -OwnsAutoConfigUrl $true -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*identity differs*'
    Should -Invoke Invoke-RideUserProxyNativeWrite -ModuleName RIDE.UserProxyInventory -Exactly 0
  }
  It 'does not call WinINet for WhatIf and delegates only after identity validation' {
    $preview=Set-RideUserProxyNativeConfiguration -Flags 13 -AutoConfigUrl 'https://pac.test/a.pac' -OwnsAutoConfigUrl $true -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -WhatIf
    $preview.Status|Should -BeExactly WhatIf
    Should -Invoke Invoke-RideUserProxyNativeWrite -ModuleName RIDE.UserProxyInventory -Exactly 0
    $result=Set-RideUserProxyNativeConfiguration -Flags 13 -AutoConfigUrl 'https://pac.test/a.pac' -OwnsAutoConfigUrl $true -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false
    $result.ConfigurationSet|Should -BeTrue
    Should -Invoke Invoke-RideUserProxyNativeWrite -ModuleName RIDE.UserProxyInventory -ParameterFilter {$Flags -eq 13 -and $AutoConfigUrl -ceq 'https://pac.test/a.pac' -and $OwnsAutoConfigUrl} -Exactly 1
  }
  It 'refuses a documented policy restriction before ShouldProcess or WinINet' {
    Mock Get-RideUserProxyPolicyObservation -ModuleName RIDE.UserProxyInventory {
      [pscustomobject]@{KnownPolicyStatus='Blocked';BlockingValues=@('LocalMachine policy Proxy=1');UnknownValues=@()}
    }
    {Set-RideUserProxyNativeConfiguration -Flags 13 -AutoConfigUrl $null -OwnsAutoConfigUrl $false -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*policy status is Blocked*'
    Should -Invoke Invoke-RideUserProxyNativeWrite -ModuleName RIDE.UserProxyInventory -Exactly 0
  }
  It 'fails closed when documented policy values cannot be read' {
    Mock Get-RideUserProxyPolicyObservation -ModuleName RIDE.UserProxyInventory {throw 'Policy registry access failed.'}
    {Set-RideUserProxyNativeConfiguration -Flags 13 -AutoConfigUrl $null -OwnsAutoConfigUrl $false -ExpectedComputerName TEST-VM -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -Confirm:$false}|Should -Throw '*Policy registry access failed*'
    Should -Invoke Invoke-RideUserProxyNativeWrite -ModuleName RIDE.UserProxyInventory -Exactly 0
  }
}
Describe 'Documented WinINet proxy policy observation' {
  It 'allows only absent or explicitly nonblocking known policies' {
    Mock Read-RideUserProxyPolicyValue -ModuleName RIDE.UserProxyInventory {
      [pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$false;Kind=$null;Value=$null}
    }
    (Get-RideUserProxyPolicyObservation).KnownPolicyStatus|Should -BeExactly 'Clear'
    Should -Invoke Read-RideUserProxyPolicyValue -ModuleName RIDE.UserProxyInventory -Exactly 3
  }
  It 'detects change restrictions and machine-wide proxy scope' -TestCases @(
    @{Hive='CurrentUser';Name='Proxy';Kind='DWord';Value=1},
    @{Hive='LocalMachine';Name='Proxy';Kind='DWord';Value=1},
    @{Hive='LocalMachine';Name='ProxySettingsPerUser';Kind='DWord';Value=0}
  ) {
    param($Hive,$Name,$Kind,$Value)
    $HiveToBlock=$Hive;$NameToBlock=$Name;$KindToBlock=$Kind;$ValueToBlock=$Value
    Mock Read-RideUserProxyPolicyValue -ModuleName RIDE.UserProxyInventory {
      if($Hive -ceq $HiveToBlock -and $Name -ceq $NameToBlock){[pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$true;Kind=$KindToBlock;Value=$ValueToBlock}}
      else{[pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$false;Kind=$null;Value=$null}}
    }
    (Get-RideUserProxyPolicyObservation).KnownPolicyStatus|Should -BeExactly 'Blocked'
  }
  It 'reports malformed policy data as unknown' {
    Mock Read-RideUserProxyPolicyValue -ModuleName RIDE.UserProxyInventory {
      if($Name -ceq 'ProxySettingsPerUser'){[pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$true;Kind='String';Value='0'}}
      else{[pscustomobject]@{Hive=$Hive;SubKey=$SubKey;Name=$Name;Exists=$false;Kind=$null;Value=$null}}
    }
    (Get-RideUserProxyPolicyObservation).KnownPolicyStatus|Should -BeExactly 'Unknown'
  }
}
Describe 'WinINet buffer and observation contract with a fake native API' {
  BeforeEach {$script:Api=[Ride.UserProxyInventoryV1.FakeApi]::new()}
  It 'validates ABI layout without querying the OS' {
    {[Ride.UserProxyInventoryV1.Reader]::ValidateLayout()} | Should -Not -Throw
    $Api.Calls | Should -Be 0
  }
  It 'queries UI flags and preserves complete string values while releasing every allocation' {
    $r=[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)
    $r.FlagsSource | Should -BeExactly FlagsUi
    $r.UiQueryError | Should -BeNullOrEmpty
    $r.Flags | Should -Be 15
    $r.ProxyServer | Should -BeExactly $Api.Server
    $r.ProxyBypass | Should -BeExactly $Api.Bypass
    $r.AutoConfigUrl | Should -BeExactly $Api.Url
    ($Api.FlagOptions -join ',') | Should -BeExactly '10,10'
    $Api.Freed | Should -Be 3
    $Api.Outstanding | Should -Be 0
  }
  It 'retains the native fallback reason without claiming a modern UI observation' {
    $Api.FailUi=$true
    $r=[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)
    $r.FlagsSource | Should -BeExactly FlagsFallback
    $r.UiQueryError | Should -Be 87
    ($Api.FlagOptions -join ',') | Should -BeExactly '10,1,1'
    $Api.Freed | Should -Be 3
  }
  It 'does not fall back after a failed complete query or return partial strings' {
    $Api.FailCall=2
    {[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*query failed*'
    $Api.Calls | Should -Be 2
    $Api.Freed | Should -Be 3
    $Api.Outstanding | Should -Be 0
  }
  It 'throws if both flags queries fail' {
    $Api.FailUi=$true;$Api.FailCall=2
    {[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*query failed*'
    $Api.Calls | Should -Be 2
    $Api.Allocated | Should -Be 0
  }
  It 'preserves null, empty and Unicode strings distinctly' {
    $Api.ClearServer();$Api.Bypass='';$Api.Url="https://pac.test/$([char]0xe6).pac"
    $r=[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)
    ($null -eq $r.ProxyServer) | Should -BeTrue
    ($null -eq $r.ProxyBypass) | Should -BeFalse
    $r.ProxyBypass.Length | Should -Be 0
    $r.AutoConfigUrl | Should -BeExactly $Api.Url
    $Api.Freed | Should -Be 2
  }
  It 'preserves unknown high flag bits' {
    $Api.Flags=[uint32]2147483663
    ([Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)).Flags | Should -Be 2147483663
  }
  It 'refuses observed flag drift and still releases all strings' {
    $Api.ChangeFlags=$true
    {[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*changed during collection*'
    $Api.Outstanding | Should -Be 0
  }
  It 'refuses malformed native <Fault> while freeing requested string slots' -TestCases @(@{Fault='MalformedList'},@{Fault='WrongId'}) {
    param($Fault)
    $Api.$Fault=$true
    {[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw
    $Api.Freed | Should -Be 3
    $Api.Outstanding | Should -Be 0
  }
  It 'releases later strings even if one cleanup reports failure' {
    $Api.ThrowOnFree=$true
    {[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*cleanup failed*'
    $Api.Freed | Should -Be 3
    $Api.Outstanding | Should -Be 0
  }
  It 'bounds retained string length and releases an oversized response' {
    $Api.Server='x'*32769
    {[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*exceeds 32768*'
    $Api.Outstanding | Should -Be 0
  }
  It 'allows the exact string bound' {
    $Api.Server='x'*32768
    ([Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)).ProxyServer.Length | Should -Be 32768
    $Api.Outstanding | Should -Be 0
  }
  It 'does not double-free aliased native string pointers' {
    $Api.DuplicatePointers=$true
    $r=[Ride.UserProxyInventoryV1.Reader]::ReadWithApi($Api)
    $r.ProxyBypass | Should -BeExactly $r.ProxyServer
    $Api.Freed | Should -Be 1
    $Api.Outstanding | Should -Be 0
  }
}
Describe 'Explicit user proxy capture' {
  BeforeEach {
    $script:CaptureArgs=@{ExpectedComputerName='TEST-VM';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;ConnectionKind='DefaultLan'}
    Mock Get-RideUserProxyContext -ModuleName RIDE.UserProxyInventory {[pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}}
    Mock Get-RideUserProxyNativeSnapshot -ModuleName RIDE.UserProxyInventory {New-ProxySnapshot}
  }
  It 'refuses a mismatched <Field> before native collection' -TestCases @(@{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedUserSid';Value='S-1-5-21-1-2-3-500'},@{Field='ExpectedSessionId';Value=2}) {
    param($Field,$Value)
    $CaptureArgs[$Field]=$Value
    {Get-RideUserProxyObservation @CaptureArgs} | Should -Throw '*identity differs*'
    Should -Invoke Get-RideUserProxyNativeSnapshot -ModuleName RIDE.UserProxyInventory -Exactly 0
  }
  It 'refuses noninteractive execution' {
    Mock Get-RideUserProxyContext -ModuleName RIDE.UserProxyInventory {[pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$false}}
    {Get-RideUserProxyObservation @CaptureArgs} | Should -Throw '*identity differs*'
    Should -Invoke Get-RideUserProxyNativeSnapshot -ModuleName RIDE.UserProxyInventory -Exactly 0
  }
  It 'refuses a context change after collection' {
    InModuleScope RIDE.UserProxyInventory {$script:ContextCalls=0}
    Mock Get-RideUserProxyContext -ModuleName RIDE.UserProxyInventory {$script:ContextCalls++;[pscustomobject]@{ComputerName='TEST-VM';UserSid='S-1-5-21-1-2-3-1001';SessionId=$script:ContextCalls;UserInteractive=$true}}
    {Get-RideUserProxyObservation @CaptureArgs} | Should -Throw '*identity changed*'
  }
  It 'retains literal values and does not claim effective routing or recovery' {
    $r=Get-RideUserProxyObservation @CaptureArgs
    $r.ManualProxyFlag | Should -BeTrue
    $r.SetupScriptFlag | Should -BeTrue
    $r.AutoDetectFlag | Should -BeTrue
    $r.ProxyBypass | Should -BeExactly '<local>;*.test'
    $r.PolicyStatus | Should -BeExactly NotInspected
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    $r.DesktopVerified | Should -BeFalse
    $r.EffectiveRoutingVerified | Should -BeFalse
    $r.ConnectionName | Should -BeNullOrEmpty
  }
  It 'preserves high unknown bits and null/empty strings through JSON' {
    Mock Get-RideUserProxyNativeSnapshot -ModuleName RIDE.UserProxyInventory {$r=New-ProxySnapshot;$r.Flags=[uint32]2147483663;$r.ProxyServer=$null;$r.ProxyBypass='';$r}
    $r=Get-RideUserProxyObservation @CaptureArgs|ConvertTo-Json|ConvertFrom-Json
    $r.UnknownFlagBits | Should -Be 2147483648
    ($null -eq $r.ProxyServer) | Should -BeTrue
    ($null -eq $r.ProxyBypass) | Should -BeFalse
    $r.ProxyBypass.Length | Should -Be 0
  }
  It 'propagates native failures without emitting a misleading captured record' {
    Mock Get-RideUserProxyNativeSnapshot -ModuleName RIDE.UserProxyInventory {throw 'Injected query failure'}
    {Get-RideUserProxyObservation @CaptureArgs} | Should -Throw '*Injected query failure*'
  }
  It 'refuses malformed <Field> observations' -TestCases @(@{Field='Flags';Value=-1},@{Field='Flags';Value='15'},@{Field='FlagsSource';Value='Unknown'},@{Field='UiQueryError';Value=5},@{Field='ProxyServer';Value=42}) {
    param($Field,$Value)
    $invalid=New-ProxySnapshot;$invalid.$Field=$Value
    InModuleScope RIDE.UserProxyInventory -Parameters @{Invalid=$invalid} {param($Invalid);$script:InvalidSnapshot=$Invalid;Mock Get-RideUserProxyNativeSnapshot {$script:InvalidSnapshot}}
    {Get-RideUserProxyObservation @CaptureArgs} | Should -Throw '*Invalid proxy*'
  }
  It 'completes the explicit scope without a provider call' {
    $line='Get-RideUserProxyObservation -ConnectionKind Def'
    $r=TabExpansion2 -inputScript $line -cursorColumn $line.Length
    $r.CompletionMatches.CompletionText | Should -Contain DefaultLan
    Should -Invoke Get-RideUserProxyNativeSnapshot -ModuleName RIDE.UserProxyInventory -Exactly 0
  }
}
Describe 'Proxy evidence export' {
  BeforeEach {
    $script:ExportArgs=@{ExpectedComputerName='TEST-VM';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;ConnectionKind='DefaultLan';OutputPath=(Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.json'))}
    Mock Import-Module {}
    Mock Get-RideUserProxyObservation {[pscustomobject]@{Kind='UserProxyObservation';Status='Captured';ProxyServer=$null;ProxyBypass=''}}
  }
  It 'previews without native collection or output' {
    & (Join-Path $Root 'tools/Export-RideUserProxyObservation.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideUserProxyObservation -Exactly 0
  }
  It 'creates JSON preserving null/empty strings and refuses overwriting it' {
    & (Join-Path $Root 'tools/Export-RideUserProxyObservation.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    $before=[IO.File]::ReadAllBytes($ExportArgs.OutputPath)
    $json=[Text.Encoding]::UTF8.GetString($before)|ConvertFrom-Json
    ($null -eq $json.ProxyServer) | Should -BeTrue
    ($null -eq $json.ProxyBypass) | Should -BeFalse
    {& (Join-Path $Root 'tools/Export-RideUserProxyObservation.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($ExportArgs.OutputPath)) | Should -BeExactly ([Convert]::ToBase64String($before))
  }
  It 'refuses a racing file after collection without truncation' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'proxy-race.json'
    Mock Get-RideUserProxyObservation {[IO.File]::WriteAllText((Join-Path $TestDrive 'proxy-race.json'),'other writer');[pscustomobject]@{Status='Captured'}}
    {& (Join-Path $Root 'tools/Export-RideUserProxyObservation.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
    Should -Invoke Get-RideUserProxyObservation -Exactly 1
  }
}
