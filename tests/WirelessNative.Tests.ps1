<#
.SYNOPSIS
  Verify WLAN lifecycle provider calls with allocated fake native buffers.
.DESCRIPTION
  Compiles the production adapter with a fake API; never calls wlanapi.dll,
  imports a profile, connects or reads real profile content or credentials.
.EXAMPLE
  Invoke-Pester ./tests/WirelessNative.Tests.ps1
.NOTES
  Pester 5, native Windows PowerShell 5.1 and PowerShell 7. Version: 0.1.0.
#>
BeforeAll {
  $source=Get-Content -LiteralPath (Join-Path $PSScriptRoot '../modules/RIDE.WirelessNative.psm1') -Raw
  $production=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
  $fake=@'
namespace Ride.WirelessProfileV1 {
  public sealed class FakeApi : IProfileApi {
    public uint Version=2,OpenError,ReadError,ListError,SetError,DeleteError,PositionError,CloseError,InputFlags,OutputFlags,Reason=42,LastPosition;
    public int OpenCalls,CloseCalls,Allocated,Freed,SetCalls,DeleteCalls,PositionCalls;
    public bool NullHandle,NullBuffer,FreeFailure,Overwrite;
    public string Xml="<synthetic>not-a-real-key</synthetic>",LastName,LastSecurity,LastXml;
    public string[] Names=new string[]{"Fixture","fixture"};
    public uint CountOverride=uint.MaxValue;
    public System.Guid LastId;
    public uint Open(out uint version,out System.IntPtr handle) {OpenCalls++;version=Version;handle=NullHandle?System.IntPtr.Zero:new System.IntPtr(7);return OpenError;}
    public uint Close(System.IntPtr handle) {CloseCalls++;return CloseError;}
    public void Free(System.IntPtr buffer) {System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);Freed++;if(FreeFailure)throw new System.InvalidOperationException("Synthetic release failure");}
    public uint List(System.IntPtr handle,System.Guid id,out System.IntPtr buffer) {
      LastId=id;buffer=System.IntPtr.Zero;if(NullBuffer)return ListError;
      int size=8+516*Names.Length;buffer=System.Runtime.InteropServices.Marshal.AllocHGlobal(size);Allocated++;
      System.Runtime.InteropServices.Marshal.Copy(new byte[size],0,buffer,size);
      System.Runtime.InteropServices.Marshal.WriteInt32(buffer,unchecked((int)(CountOverride==uint.MaxValue?(uint)Names.Length:CountOverride)));
      for(int n=0;n<Names.Length;n++) {
        byte[] bytes=System.Text.Encoding.Unicode.GetBytes(Names[n]);System.IntPtr at=System.IntPtr.Add(buffer,8+n*516);
        System.Runtime.InteropServices.Marshal.Copy(bytes,0,at,System.Math.Min(bytes.Length,510));
        System.Runtime.InteropServices.Marshal.WriteInt32(at,512,n==0?0:unchecked((int)0x80000002));
      }
      return ListError;
    }
    public uint Read(System.IntPtr handle,System.Guid id,string name,out System.IntPtr xml,ref uint flags,out uint access) {
      LastId=id;LastName=name;InputFlags=flags;flags=OutputFlags;access=0x00070023;
      xml=System.IntPtr.Zero;if(!NullBuffer){xml=System.Runtime.InteropServices.Marshal.StringToHGlobalUni(Xml);Allocated++;}
      return ReadError;
    }
    public uint Set(System.IntPtr handle,System.Guid id,string xml,string security,bool overwrite,out uint reason) {SetCalls++;LastId=id;LastXml=xml;LastSecurity=security;Overwrite=overwrite;reason=Reason;return SetError;}
    public uint Delete(System.IntPtr handle,System.Guid id,string name) {DeleteCalls++;LastId=id;LastName=name;return DeleteError;}
    public uint Position(System.IntPtr handle,System.Guid id,string name,uint position) {PositionCalls++;LastId=id;LastName=name;LastPosition=position;return PositionError;}
  }
}
'@
  Add-Type -TypeDefinition ($production+"`n"+$fake)
  $script:id=[guid]'11111111-2222-3333-4444-555555555555'
}
Describe 'Bounded WLAN profile lifecycle provider' {
  It 'retains case-sensitive profile identity, order and unknown flag bits' {
    $api=[Ride.WirelessProfileV1.FakeApi]::new()
    $rows=[Ride.WirelessProfileV1.Client]::ListWithApi($api,$script:id)
    @($rows.Name) | Should -Be @('Fixture','fixture')
    $rows[1].Flags | Should -Be 2147483650
    $rows[1].Position | Should -Be 1
    $api.LastId | Should -Be $script:id
    $api.Allocated | Should -Be $api.Freed
    $api.CloseCalls | Should -Be 1
  }
  It 'refuses duplicate or excessive profile lists and frees their buffers' {
    foreach($scenario in @('duplicate','excessive')) {
      $api=[Ride.WirelessProfileV1.FakeApi]::new()
      if($scenario -eq 'duplicate'){$api.Names=@('same','same')}else{$api.CountOverride=257}
      {[Ride.WirelessProfileV1.Client]::ListWithApi($api,$script:id)} | Should -Throw
      $api.Allocated | Should -Be $api.Freed
      $api.CloseCalls | Should -Be 1
    }
  }
  It 'requests encrypted profile XML by default and plaintext only explicitly' {
    foreach($plain in @($false,$true)) {
      $api=[Ride.WirelessProfileV1.FakeApi]::new();$api.OutputFlags=2
      $content=[Ride.WirelessProfileV1.Client]::ReadWithApi($api,$script:id,'Exact Name',$plain)
      $api.InputFlags | Should -Be $(if($plain){4}else{0})
      $api.LastName | Should -BeExactly 'Exact Name'
      $content.Present | Should -BeTrue
      $content.Xml | Should -Be $api.Xml
      $content.Flags | Should -Be 2
      $content.GrantedAccess | Should -Be 458787
      $api.Allocated | Should -Be $api.Freed
      $api.CloseCalls | Should -Be 1
    }
  }
  It 'distinguishes missing profiles from access failures without echoing XML' {
    $api=[Ride.WirelessProfileV1.FakeApi]::new();$api.ReadError=1168
    ([Ride.WirelessProfileV1.Client]::ReadWithApi($api,$script:id,'Fixture',$false)).Present | Should -BeFalse
    $api.Allocated | Should -Be $api.Freed
    $api=[Ride.WirelessProfileV1.FakeApi]::new();$api.ReadError=5
    { [Ride.WirelessProfileV1.Client]::ReadWithApi($api,$script:id,'Fixture',$true) } | Should -Throw '*native code 5*'
    $api.Allocated | Should -Be $api.Freed
    $api.CloseCalls | Should -Be 1
  }
  It 'passes overwrite and security choices explicitly and reports only numeric set errors' {
    $api=[Ride.WirelessProfileV1.FakeApi]::new()
    [Ride.WirelessProfileV1.Client]::SetWithApi($api,$script:id,'<fixture/>',[System.Management.Automation.Language.NullString]::Value,$false)
    $api.Overwrite | Should -BeFalse
    $api.LastSecurity | Should -BeNullOrEmpty
    $api=[Ride.WirelessProfileV1.FakeApi]::new();$api.SetError=87
    $failure=$null;try{[Ride.WirelessProfileV1.Client]::SetWithApi($api,$script:id,'<synthetic-secret/>','D:P(A;;GA;;;SY)',$true)}catch{$failure=$_}
    $failure.Exception.Message | Should -Match 'native code 87 and reason 42'
    $failure.Exception.Message | Should -Not -Match 'synthetic-secret'
    $api.LastSecurity | Should -Be 'D:P(A;;GA;;;SY)'
    $api.Overwrite | Should -BeTrue
    $api.CloseCalls | Should -Be 1
  }
  It 'binds delete and order restoration to one exact interface and name' {
    $api=[Ride.WirelessProfileV1.FakeApi]::new()
    [Ride.WirelessProfileV1.Client]::DeleteWithApi($api,$script:id,'Case Sensitive')
    [Ride.WirelessProfileV1.Client]::PositionWithApi($api,$script:id,'Case Sensitive',3)
    $api.LastId | Should -Be $script:id
    $api.LastName | Should -BeExactly 'Case Sensitive'
    $api.LastPosition | Should -Be 3
    $api.DeleteCalls | Should -Be 1
    $api.PositionCalls | Should -Be 1
    $api.CloseCalls | Should -Be 2
  }
  It 'validates identities and bounded input before opening a handle' {
    $api=[Ride.WirelessProfileV1.FakeApi]::new()
    {[Ride.WirelessProfileV1.Client]::DeleteWithApi($api,[guid]::Empty,'Fixture')} | Should -Throw
    {[Ride.WirelessProfileV1.Client]::ReadWithApi($api,$script:id,('x'*256),$false)} | Should -Throw
    {[Ride.WirelessProfileV1.Client]::SetWithApi($api,$script:id,('x'*262145),$null,$false)} | Should -Throw
    {[Ride.WirelessProfileV1.Client]::SetWithApi($api,$script:id,"<a>`0</a>",$null,$false)} | Should -Throw
    {[Ride.WirelessProfileV1.Client]::PositionWithApi($api,$script:id,'Fixture',256)} | Should -Throw
    $api.OpenCalls | Should -Be 0
  }
  It 'closes handles on provider failure, incompatible negotiation and allocation release failure' {
    foreach($scenario in @('open','version','nullbuffer','free','close')) {
      $api=[Ride.WirelessProfileV1.FakeApi]::new()
      switch($scenario){open{$api.OpenError=5};version{$api.Version=1};nullbuffer{$api.NullBuffer=$true};free{$api.FreeFailure=$true};close{$api.CloseError=6}}
      {[Ride.WirelessProfileV1.Client]::ReadWithApi($api,$script:id,'Fixture',$false)} | Should -Throw
      $api.Allocated | Should -Be $api.Freed
      $api.CloseCalls | Should -Be 1
    }
  }
}
