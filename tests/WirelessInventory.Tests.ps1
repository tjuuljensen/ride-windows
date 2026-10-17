<#
.SYNOPSIS
  Verify WLAN profile-list capture with fake native buffers and mocked identity.
.DESCRIPTION
  Compiles production interop with a fake API. No WLAN native call, network scan,
  profile XML/key export, connect/import/delete operation or live identity query.
.EXAMPLE
  Invoke-Pester .\tests\WirelessInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native/hardware acceptance pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  $source=Get-Content -LiteralPath (Join-Path $Root 'modules/RIDE.WirelessInventory.psm1') -Raw
  $native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
  $fake=@'
namespace Ride.WirelessInventoryV1 {
  public sealed class FakeApi : IReadApi {
    public uint Version=2,OpenError,InterfaceError,ProfileError,CloseError;
    public int Allocated,Freed,OpenCalls,CloseCalls,InterfaceCalls,ProfileCalls;
    public uint InterfaceCount=1,ProfileCount=2,State=4;
    public bool NullHandle,NullInterfaces,NullProfiles,EmptyGuid,DuplicateGuid,DuplicateProfile,Unterminated,InvalidUtf16,FreeFailure;
    public Guid Id=new Guid("11111111-1111-1111-1111-111111111111");
    public Guid LastProfileId;
    public string Description="Fixture wireless adapter";
    public string[] Names=new string[]{"Office","office"};
    public uint[] Flags=new uint[]{0,2147483651};
    private HashSet<IntPtr> outstanding=new HashSet<IntPtr>();
    private IntPtr Allocate(int length) {
      IntPtr memory=Marshal.AllocHGlobal(length);Marshal.Copy(new byte[length],0,memory,length);outstanding.Add(memory);Allocated++;return memory;
    }
    private void Text(IntPtr at,string value) {
      byte[] data=Encoding.Unicode.GetBytes(value);Marshal.Copy(data,0,at,Math.Min(data.Length,510));
    }
    public uint Open(out uint version,out IntPtr handle) {
      OpenCalls++;version=Version;handle=NullHandle ? IntPtr.Zero : new IntPtr(7);return OpenError;
    }
    public uint Interfaces(IntPtr handle,out IntPtr list) {
      InterfaceCalls++;list=IntPtr.Zero;if(NullInterfaces)return InterfaceError;
      uint count=Math.Min(InterfaceCount,64);list=Allocate(8+checked((int)count*532));Marshal.WriteInt32(list,unchecked((int)InterfaceCount));
      // Deliberately irrelevant index: no consumer may infer an active interface.
      Marshal.WriteInt32(list,4,999);
      for(int i=0;i<count;i++) {
        IntPtr row=IntPtr.Add(list,8+i*532);Guid id=EmptyGuid ? Guid.Empty : DuplicateGuid || i==0 ? Id : new Guid("22222222-2222-2222-2222-222222222222");
        Marshal.StructureToPtr(id,row,false);Text(IntPtr.Add(row,16),Description);Marshal.WriteInt32(row,528,unchecked((int)State));
      }
      return InterfaceError;
    }
    public uint Profiles(IntPtr handle,Guid id,out IntPtr list) {
      ProfileCalls++;LastProfileId=id;list=IntPtr.Zero;if(NullProfiles)return ProfileError;
      uint count=Math.Min(ProfileCount,256);list=Allocate(8+checked((int)count*516));Marshal.WriteInt32(list,unchecked((int)ProfileCount));Marshal.WriteInt32(list,4,999);
      for(int i=0;i<count;i++) {
        IntPtr row=IntPtr.Add(list,8+i*516);Text(row,Names[DuplicateProfile ? 0 : i%Names.Length]);
        Marshal.WriteInt32(row,512,unchecked((int)Flags[i%Flags.Length]));
        if(Unterminated)for(int c=0;c<256;c++)Marshal.WriteInt16(row,c*2,65);
        if(InvalidUtf16){Marshal.WriteInt16(row,0,unchecked((short)0xD800));Marshal.WriteInt16(row,2,0);}
      }
      return ProfileError;
    }
    public void Free(IntPtr memory) {
      if(!outstanding.Remove(memory))throw new Exception("Double/unowned free");
      Marshal.FreeHGlobal(memory);Freed++;if(FreeFailure)throw new Exception("Injected release failure");
    }
    public uint Close(IntPtr handle) {CloseCalls++;return CloseError;}
    public int Outstanding {get{return outstanding.Count;}}
  }
}
'@
  if(-not ('Ride.WirelessInventoryV1.Reader' -as [type])){Add-Type -TypeDefinition ($native+"`n"+$fake)}
  Import-Module (Join-Path $Root 'modules/RIDE.WirelessInventory.psm1') -Force
  function New-WirelessContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
  }
  function New-WirelessRow {
    [pscustomobject]@{Id='11111111-1111-1111-1111-111111111111';Description='Fixture';State=[uint32]4;Profiles=@(
      [pscustomobject]@{Position=0;Name='Office';Flags=[uint32]0},[pscustomobject]@{Position=1;Name='office';Flags=[uint32]2147483651}
    )}
  }
  function New-WirelessSaved {
    [pscustomobject]@{SchemaVersion=1;Kind='WirelessProfileObservation';Status='Captured';WindowsContext=New-WirelessContext;Interfaces=@(New-WirelessRow)}
  }
}
Describe 'WLAN memory and API contract' {
  BeforeEach {$script:Api=[Ride.WirelessInventoryV1.FakeApi]::new()}
  It 'validates fixed UTF-16 layouts and preserves name case, preference order and unsigned flags' {
    {[Ride.WirelessInventoryV1.Reader]::ValidateLayout()} | Should -Not -Throw
    $r=[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)
    $r.Count | Should -Be 1
    $r[0].Id | Should -BeExactly $Api.Id.ToString('D')
    ($r[0].Profiles.Name -join ',') | Should -BeExactly 'Office,office'
    ($r[0].Profiles.Position -join ',') | Should -BeExactly '0,1'
    $r[0].Profiles[1].Flags | Should -Be ([uint32]2147483651)
    $Api.LastProfileId | Should -Be $Api.Id
    $Api.Freed | Should -Be 2
    $Api.Outstanding | Should -Be 0
    $Api.CloseCalls | Should -Be 1
  }
  It 'treats empty interface/profile collections as successful, never selecting a default' {
    $Api.InterfaceCount=0
    @([Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)).Count | Should -Be 0
    $Api.ProfileCalls | Should -Be 0
    $Api=[Ride.WirelessInventoryV1.FakeApi]::new();$Api.ProfileCount=0
    $r=[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)
    $r[0].Profiles.Count | Should -Be 0
    $Api.Outstanding | Should -Be 0
  }
  It 'releases allocated buffers and handle after <Stage> failure' -ForEach @(
    @{Stage='Open';Field='OpenError'},@{Stage='Interface';Field='InterfaceError'},@{Stage='Profile';Field='ProfileError'}
  ) {
    $Api.$Field=5
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*code 5*'
    $Api.Outstanding | Should -Be 0
    $Api.CloseCalls | Should -Be 1
  }
  It 'refuses unsupported version and successful null handle' {
    $Api.Version=1
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*version-2*'
    $Api.CloseCalls | Should -Be 1
    $Api=[Ride.WirelessInventoryV1.FakeApi]::new();$Api.NullHandle=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*version-2*'
    $Api.CloseCalls | Should -Be 0
  }
  It 'rejects null successful <Field> buffers' -ForEach @(@{Field='NullInterfaces'},@{Field='NullProfiles'}) {
    $Api.$Field=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*no list buffer*'
    $Api.Outstanding | Should -Be 0
    $Api.CloseCalls | Should -Be 1
  }
  It 'bounds <Field> before traversing returned entries' -ForEach @(@{Field='InterfaceCount';Value=65},@{Field='ProfileCount';Value=257}) {
    $Api.$Field=$Value
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*bound*'
    $Api.Outstanding | Should -Be 0
  }
  It 'rejects missing and duplicate interface identities' {
    $Api.EmptyGuid=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*identity*'
    $Api.Outstanding | Should -Be 0
    $Api=[Ride.WirelessInventoryV1.FakeApi]::new();$Api.InterfaceCount=2;$Api.DuplicateGuid=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*identity*'
    $Api.Outstanding | Should -Be 0
  }
  It 'rejects duplicate profile names without collapsing distinct case variants' {
    $Api.DuplicateProfile=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*Duplicate WLAN profile*'
    $Api.Outstanding | Should -Be 0
  }
  It 'refuses unterminated fixed strings and releases all allocations' {
    $Api.Unterminated=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*not terminated*'
    $Api.Outstanding | Should -Be 0
  }
  It 'preserves Unicode and refuses empty or malformed UTF-16 profile names' {
    $Api.Names=@("Wi-Fi $([char]0xE6)",'Other')
    ([Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api))[0].Profiles[0].Name | Should -BeExactly $Api.Names[0]
    $Api=[Ride.WirelessInventoryV1.FakeApi]::new();$Api.Names=@('')
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*Empty WLAN*'
    $Api.Outstanding | Should -Be 0
    $Api=[Ride.WirelessInventoryV1.FakeApi]::new();$Api.InvalidUtf16=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw
    $Api.Outstanding | Should -Be 0
  }
  It 'still closes the handle when memory release reports failure' {
    $Api.FreeFailure=$true
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*release failure*'
    $Api.Outstanding | Should -Be 0
    $Api.CloseCalls | Should -Be 1
  }
  It 'does not report successful collection if handle close fails' {
    $Api.CloseError=6
    {[Ride.WirelessInventoryV1.Reader]::ReadWithApi($Api)} | Should -Throw '*code 6*'
    $Api.Outstanding | Should -Be 0
  }
}
Describe 'Wireless evidence export' {
  BeforeEach {
    $script:ExportArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1;OutputPath=(Join-Path $TestDrive 'wireless.json')}
    Mock Import-Module {}
    Mock Get-RideWirelessProfileInventory {New-WirelessSaved}
  }
  It 'previews without collecting or writing' {
    & (Join-Path $Root 'tools/Export-RideWirelessProfileInventory.ps1') @ExportArgs -WhatIf
    Test-Path -LiteralPath $ExportArgs.OutputPath | Should -BeFalse
    Should -Invoke Get-RideWirelessProfileInventory -Exactly 0
  }
  It 'exports intended identity and refuses an existing evidence file' {
    & (Join-Path $Root 'tools/Export-RideWirelessProfileInventory.ps1') @ExportArgs | Should -BeExactly $ExportArgs.OutputPath
    Should -Invoke Get-RideWirelessProfileInventory -Exactly 1 -ParameterFilter {$ExpectedUserSid -eq 'S-1-5-21-1-2-3-1001' -and $ExpectedSessionId -eq 1}
    $before=[IO.File]::ReadAllText($ExportArgs.OutputPath)
    ($before|ConvertFrom-Json).Kind | Should -Be WirelessProfileObservation
    {& (Join-Path $Root 'tools/Export-RideWirelessProfileInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly $before
  }
  It 'preserves a competing file created during collection' {
    $ExportArgs.OutputPath=Join-Path $TestDrive 'racing-wireless.json'
    Mock Get-RideWirelessProfileInventory {[IO.File]::WriteAllText((Join-Path $TestDrive 'racing-wireless.json'),'other writer');New-WirelessSaved}
    {& (Join-Path $Root 'tools/Export-RideWirelessProfileInventory.ps1') @ExportArgs} | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($ExportArgs.OutputPath) | Should -BeExactly 'other writer'
  }
}
Describe 'Wireless inventory identity and result boundaries' {
  BeforeEach {
    $script:CaptureArgs=@{ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1}
    Mock Get-RideWirelessContext -ModuleName RIDE.WirelessInventory {New-WirelessContext}
    Mock Get-RideWirelessNativeRows -ModuleName RIDE.WirelessInventory {New-WirelessRow}
  }
  It 'reports profile flags independently, retains unknown bits and never claims mutation readiness' {
    $r=Get-RideWirelessProfileInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Interfaces[0].Profiles[1].GroupPolicyFlag | Should -BeTrue
    $r.Interfaces[0].Profiles[1].PerUserFlag | Should -BeTrue
    $r.Interfaces[0].Profiles[1].UnknownFlagBits | Should -Be ([uint32]2147483648)
    $r.SecretsRequested | Should -BeFalse
    $r.ProfileContentCaptured | Should -BeFalse
    $r.ConnectionVerified | Should -BeFalse
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
  }
  It 'rejects <Field> mismatch before native collection' -ForEach @(
    @{Field='ExpectedComputerName';Value='OTHER'},@{Field='ExpectedBuild';Value='26101'},@{Field='ExpectedEditionId';Value='Enterprise'},@{Field='ExpectedUserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='ExpectedSessionId';Value=2}
  ) {
    $argsCopy=$CaptureArgs.Clone();$argsCopy[$Field]=$Value
    {Get-RideWirelessProfileInventory @argsCopy} | Should -Throw '*target differs*'
    Should -Invoke Get-RideWirelessNativeRows -ModuleName RIDE.WirelessInventory -Exactly 0
  }
  It 'rejects noninteractive and non-native processes' {
    Mock Get-RideWirelessContext -ModuleName RIDE.WirelessInventory {$c=New-WirelessContext;$c.UserInteractive=$false;$c}
    {Get-RideWirelessProfileInventory @CaptureArgs} | Should -Throw '*target differs*'
    Mock Get-RideWirelessContext -ModuleName RIDE.WirelessInventory {$c=New-WirelessContext;$c.NativeProcess=$false;$c}
    {Get-RideWirelessProfileInventory @CaptureArgs} | Should -Throw '*target differs*'
    Should -Invoke Get-RideWirelessNativeRows -ModuleName RIDE.WirelessInventory -Exactly 0
  }
  It 'rejects identity/update drift after collection' {
    InModuleScope RIDE.WirelessInventory {$script:ContextCalls=0}
    Mock Get-RideWirelessContext -ModuleName RIDE.WirelessInventory {$script:ContextCalls++;$c=New-WirelessContext;$c.UpdateBuildRevision=$script:ContextCalls;$c}
    {Get-RideWirelessProfileInventory @CaptureArgs} | Should -Throw '*changed during collection*'
  }
  It 'distinguishes empty collection from provider failure and discards private partial results' {
    Mock Get-RideWirelessNativeRows -ModuleName RIDE.WirelessInventory {}
    $r=Get-RideWirelessProfileInventory @CaptureArgs
    $r.Status | Should -Be Captured
    $r.Interfaces.Count | Should -Be 0
    Mock Get-RideWirelessNativeRows -ModuleName RIDE.WirelessInventory {New-WirelessRow;throw [ComponentModel.Win32Exception]::new(5,'private failure text')}
    $r=Get-RideWirelessProfileInventory @CaptureArgs
    $r.Status | Should -Be Unavailable
    $r.Interfaces | Should -BeNullOrEmpty
    $r.NativeError | Should -Be 5
    ($r|ConvertTo-Json -Depth 8) | Should -Not -Match 'private failure text|Office'
  }
  It 'rejects malformed <Case> metadata' -ForEach @(
    @{Case='GUID';Field='Id';Value='bad'},@{Case='description';Field='Description';Value=123},@{Case='state';Field='State';Value=-1},@{Case='missing profiles';Field='Profiles';Value=$null}
  ) {
    $row=New-WirelessRow;$row.$Field=$Value
    InModuleScope RIDE.WirelessInventory -Parameters @{Row=$row} {param($Row);$script:InvalidRow=$Row;Mock Get-RideWirelessNativeRows {$script:InvalidRow}}
    (Get-RideWirelessProfileInventory @CaptureArgs).Status | Should -Be Unavailable
  }
}
Describe 'Saved wireless profile lookup and completion' {
  It 'uses explicit GUID and case-sensitive profile names after JSON roundtrip' {
    $saved=New-WirelessSaved|ConvertTo-Json -Depth 8|ConvertFrom-Json
    (Find-RideWirelessProfileObservation $saved '{11111111-1111-1111-1111-111111111111}' 'Office').Observation.Flags | Should -Be 0
    (Find-RideWirelessProfileObservation $saved '11111111-1111-1111-1111-111111111111' 'office').Observation.Flags | Should -Be ([uint32]2147483651)
    (Find-RideWirelessProfileObservation $saved '11111111-1111-1111-1111-111111111111' 'OFFICE').Status | Should -Be NotObserved
    (Find-RideWirelessProfileObservation $saved '22222222-2222-2222-2222-222222222222' 'Office').Status | Should -Be InterfaceNotObserved
  }
  It 'refuses duplicate, invalid-order and inconsistent unavailable saved rows' {
    $saved=New-WirelessSaved;$saved.Interfaces+=@($saved.Interfaces[0])
    {Find-RideWirelessProfileObservation $saved '11111111-1111-1111-1111-111111111111' 'Office'} | Should -Throw '*Duplicate*'
    $saved=New-WirelessSaved;$saved.Interfaces[0].Profiles[0].Position=1
    {Find-RideWirelessProfileObservation $saved '11111111-1111-1111-1111-111111111111' 'Office'} | Should -Throw '*order*'
    $saved=New-WirelessSaved;$saved.Status='Unavailable'
    {Find-RideWirelessProfileObservation $saved '11111111-1111-1111-1111-111111111111' 'Office'} | Should -Throw '*partial rows*'
    $saved.Interfaces=$null
    (Find-RideWirelessProfileObservation $saved '11111111-1111-1111-1111-111111111111' 'Office').Status | Should -Be Unavailable
  }
  It 'completes only supplied interfaces and exact names, escaping quote characters' {
    $saved=New-WirelessSaved
    $cmd=Get-Command Find-RideWirelessProfileObservation
    $idAttr=$cmd.Parameters.InterfaceId.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $nameAttr=$cmd.Parameters.ProfileName.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    @(& $idAttr.ScriptBlock '' '' '1111' $null @{Inventory=$saved}).Count | Should -Be 1
    @(& $idAttr.ScriptBlock '' '' '2222' $null @{Inventory=$saved}).Count | Should -Be 0
    $bound=@{Inventory=$saved;InterfaceId='11111111-1111-1111-1111-111111111111'}
    @(& $nameAttr.ScriptBlock '' '' 'off' $null $bound).Count | Should -Be 2
    $saved.Interfaces[0].Profiles[0].Name="Owner's profile"
    $matches=@(& $nameAttr.ScriptBlock '' '' 'own' $null $bound)
    $matches[0].CompletionText | Should -BeExactly "'Owner''s profile'"
    @(& $nameAttr.ScriptBlock '' '' '' $null @{}).Count | Should -Be 0
  }
}
