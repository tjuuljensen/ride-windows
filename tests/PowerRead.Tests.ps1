<#
.SYNOPSIS
  Verify typed power reads and native buffer ownership without querying Windows.
.DESCRIPTION
  Compiles production interop with an injected fake API. Tests GUID allocation,
  numeric errors, AC/DC routing and unsigned values. No native API or setter runs.
.EXAMPLE
  Invoke-Pester .\tests\PowerRead.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native target acceptance remains pending.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  $source=Get-Content -LiteralPath (Join-Path $Root 'modules/RIDE.PowerRead.psm1') -Raw
  $native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
  $fake=@'
namespace Ride.PowerReadV1 {
  public sealed class FakeApi : IReadApi {
    public uint ActiveError, IndexError, Value=4294967295;
    public int ActiveCalls, IndexCalls, Allocated, Freed;
    public bool NullPointer, FreeFailure, LastAc;
    public Guid Scheme=new Guid("381b4222-f694-41f0-9685-ff5bb260df2e");
    public Guid LastScheme, LastSubgroup, LastSetting;
    public uint Active(out IntPtr memory) {
      ActiveCalls++;
      memory=IntPtr.Zero;
      if(!NullPointer){memory=Marshal.AllocHGlobal(16);Allocated++;Marshal.StructureToPtr(Scheme,memory,false);}
      return ActiveError;
    }
    public IntPtr Free(IntPtr memory) {
      Marshal.FreeHGlobal(memory);Freed++;
      return FreeFailure ? new IntPtr(1) : IntPtr.Zero;
    }
    public uint Index(Guid scheme, Guid subgroup, Guid setting, bool ac, out uint value) {
      IndexCalls++;LastScheme=scheme;LastSubgroup=subgroup;LastSetting=setting;LastAc=ac;
      value=Value;return IndexError;
    }
  }
}
'@
  if(-not ('Ride.PowerReadV1.Reader' -as [type])){Add-Type -TypeDefinition ($native+"`n"+$fake)}
  Import-Module (Join-Path $Root 'modules/RIDE.PowerRead.psm1') -Force
}
Describe 'Power read native contract' {
  BeforeEach {
    $script:Api=[Ride.PowerReadV1.FakeApi]::new()
    $script:Scheme=[guid]'381b4222-f694-41f0-9685-ff5bb260df2e'
    $script:Subgroup=[guid]'7516b95f-f776-4464-8c53-06167f40cc99'
    $script:Setting=[guid]'3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e'
  }
  It 'copies the GUID and frees exactly one native allocation' {
    $value=[Ride.PowerReadV1.Reader]::Active($Api)
    $value | Should -Be $Scheme
    $Api.ActiveCalls | Should -Be 1
    $Api.Freed | Should -Be $Api.Allocated
    $Api.Freed | Should -Be 1
    $Api.IndexCalls | Should -Be 0
  }
  It 'frees an allocated pointer when the API reports an error' {
    $Api.ActiveError=5
    {[Ride.PowerReadV1.Reader]::Active($Api)} | Should -Throw '*code 5*'
    $Api.Freed | Should -Be 1
  }
  It 'rejects success without a GUID allocation' {
    $Api.NullPointer=$true
    {[Ride.PowerReadV1.Reader]::Active($Api)} | Should -Throw '*no GUID*'
    $Api.Freed | Should -Be 0
  }
  It 'rejects an empty GUID and still releases the allocation' {
    $Api.Scheme=[guid]::Empty
    {[Ride.PowerReadV1.Reader]::Active($Api)} | Should -Throw '*empty GUID*'
    $Api.Freed | Should -Be 1
  }
  It 'does not report success when allocation release fails' {
    $Api.FreeFailure=$true
    {[Ride.PowerReadV1.Reader]::Active($Api)} | Should -Throw '*release failed*'
    $Api.Freed | Should -Be 1
  }
  It 'passes exact identities and <Source> to the API without signed narrowing' -ForEach @(
    @{Source='AC';Ac=$true},@{Source='DC';Ac=$false}
  ) {
    $r=[Ride.PowerReadV1.Reader]::Read($Api,$Scheme,$Subgroup,$Setting,$Ac)
    $r.Available | Should -BeTrue
    $r.Value | Should -Be ([uint32]4294967295)
    $r.ErrorCode | Should -Be 0
    $Api.LastAc | Should -Be $Ac
    $Api.LastScheme | Should -Be $Scheme
    $Api.LastSubgroup | Should -Be $Subgroup
    $Api.LastSetting | Should -Be $Setting
    $Api.ActiveCalls | Should -Be 0
  }
  It 'retains valid zero as available' {
    $Api.Value=0
    $r=[Ride.PowerReadV1.Reader]::Read($Api,$Scheme,$Subgroup,$Setting,$true)
    $r.Available | Should -BeTrue
    $r.Value | Should -Be 0
  }
  It 'keeps missing configuration separate from successful zero' {
    $Api.IndexError=2
    $r=[Ride.PowerReadV1.Reader]::Read($Api,$Scheme,$Subgroup,$Setting,$true)
    $r.Available | Should -BeFalse
    $r.ErrorCode | Should -Be 2
  }
  It 'throws numeric error <Code> rather than guessing availability' -ForEach @(
    @{Code=5},@{Code=87},@{Code=1168}
  ) {
    $Api.IndexError=$Code
    {[Ride.PowerReadV1.Reader]::Read($Api,$Scheme,$Subgroup,$Setting,$true)} | Should -Throw ('*code '+$Code+'*')
  }
  It 'rejects empty <Field> before a native query' -ForEach @(
    @{Field='Scheme'},@{Field='Subgroup'},@{Field='Setting'}
  ) {
    $values=@{Scheme=$Scheme;Subgroup=$Subgroup;Setting=$Setting};$values[$Field]=[guid]::Empty
    {[Ride.PowerReadV1.Reader]::Read($Api,$values.Scheme,$values.Subgroup,$values.Setting,$true)} | Should -Throw '*nonempty*'
    $Api.IndexCalls | Should -Be 0
  }
  It 'declares finite AC/DC completion without discovery' {
    $attr=(Get-Command Get-RideNativePowerIndex).Parameters.PowerIndex.Attributes|Where-Object {$_ -is [Management.Automation.ValidateSetAttribute]}
    ($attr.ValidValues -join ',') | Should -BeExactly 'AC,DC'
    $Api.IndexCalls | Should -Be 0
    $Api.ActiveCalls | Should -Be 0
  }
}
