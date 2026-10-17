<#
.SYNOPSIS
  Verify visual session observations using fake native calls and mocked identity.
.DESCRIPTION
  Compiles the production interop with an injected API; checks GET routing,
  unsigned/Boolean output, animation layout, partial failure and session binding.
  No live SystemParametersInfo, registry read, session change or GUI refresh runs.
.EXAMPLE
  Invoke-Pester .\tests\VisualEffectsInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: Repository fixture; native target acceptance remains separate.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  $source=Get-Content -LiteralPath (Join-Path $Root 'modules/RIDE.VisualEffectsInventory.psm1') -Raw
  $native=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
  $fake=@'
namespace Ride.VisualEffectsV1 {
  public sealed class FakeApi : IReadApi {
    public uint Value=1, LastAction, LastSize;
    public int Error, Calls, ScalarCalls, AnimationCalls;
    public bool Available=true, CorruptSize;
    public bool Scalar(uint action, out uint value, out int error) {
      Calls++;ScalarCalls++;LastAction=action;value=Value;error=Error;return Available;
    }
    public bool Animation(ref AnimationInfo value, out int error) {
      Calls++;AnimationCalls++;LastSize=value.Size;value.MinAnimate=unchecked((int)Value);
      if(CorruptSize)value.Size=4;
      error=Error;return Available;
    }
  }
}
'@
  if(-not ('Ride.VisualEffectsV1.Reader' -as [type])){Add-Type -TypeDefinition ($native+"`n"+$fake)}
  Import-Module (Join-Path $Root 'modules/RIDE.VisualEffectsInventory.psm1') -Force
  function New-VisualTestContext {
    [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
  }
  function New-VisualTestRow([string]$Kind) {
    $api=[Ride.VisualEffectsV1.FakeApi]::new()
    if($Kind -ceq 'MenuShowDelay'){$api.Value=[uint32]::MaxValue}
    [Ride.VisualEffectsV1.Reader]::Read($api,$Kind)
  }
}

Describe 'Visual GET interop contract' {
  BeforeEach { $script:Api=[Ride.VisualEffectsV1.FakeApi]::new() }
  It 'routes <Kind> to its fixed GET code <Action>' -ForEach @(
    @{Kind='DragFullWindows';Action=0x0026},@{Kind='MenuShowDelay';Action=0x006A},
    @{Kind='UiEffects';Action=0x103E},@{Kind='ClientAreaAnimation';Action=0x1042}
  ) {
    $r=[Ride.VisualEffectsV1.Reader]::Read($Api,$Kind)
    $r.Kind | Should -BeExactly $Kind
    $r.Action | Should -Be $Action
    $Api.LastAction | Should -Be $Action
    $Api.ScalarCalls | Should -Be 1
    $Api.AnimationCalls | Should -Be 0
    $r.Available | Should -BeTrue
  }
  It 'initializes the eight-byte ANIMATIONINFO before requesting animation' {
    [Runtime.InteropServices.Marshal]::SizeOf([type][Ride.VisualEffectsV1.AnimationInfo]) | Should -Be 8
    [Runtime.InteropServices.Marshal]::OffsetOf([type][Ride.VisualEffectsV1.AnimationInfo],'MinAnimate').ToInt32() | Should -Be 4
    $r=[Ride.VisualEffectsV1.Reader]::Read($Api,'MinimizeAnimation')
    $Api.LastSize | Should -Be 8
    $r.Action | Should -Be 0x0048
    $Api.ScalarCalls | Should -Be 0
    $Api.AnimationCalls | Should -Be 1
  }
  It 'retains unsigned values without signed narrowing for <Kind>' -ForEach @(
    @{Kind='MenuShowDelay'},@{Kind='MinimizeAnimation'}
  ) {
    $Api.Value=[uint32]::MaxValue
    $r=[Ride.VisualEffectsV1.Reader]::Read($Api,$Kind)
    $r.RawValue | Should -Be ([uint32]::MaxValue)
  }
  It 'does not confuse a valid zero value with failure' {
    $Api.Value=0;$Api.Error=5
    $r=[Ride.VisualEffectsV1.Reader]::Read($Api,'DragFullWindows')
    $r.Available | Should -BeTrue
    $r.RawValue | Should -Be 0
    $r.ErrorCode | Should -Be 0
  }
  It 'discards out-buffer values on failure with code <Code> for <Kind>' -ForEach @(
    @{Code=0;Kind='MenuShowDelay'},@{Code=5;Kind='DragFullWindows'},
    @{Code=87;Kind='MinimizeAnimation'},@{Code=120;Kind='ClientAreaAnimation'}
  ) {
    $Api.Value=999;$Api.Available=$false;$Api.Error=$Code
    $r=[Ride.VisualEffectsV1.Reader]::Read($Api,$Kind)
    $r.Available | Should -BeFalse
    $r.RawValue | Should -Be 0
    $r.ErrorCode | Should -Be $Code
  }
  It 'rejects a changed native structure size' {
    $Api.CorruptSize=$true
    {[Ride.VisualEffectsV1.Reader]::Read($Api,'MinimizeAnimation')} | Should -Throw '*size changed*'
  }
  It 'rejects unknown observation names before calling the API' {
    {[Ride.VisualEffectsV1.Reader]::Read($Api,'SPI_SETANIMATION')} | Should -Throw '*Unknown*'
    $Api.Calls | Should -Be 0
  }
  It 'rejects null API instances' {
    {[Ride.VisualEffectsV1.Reader]::Read($null,'UiEffects')} | Should -Throw
  }
  It 'rejects setter codes at the native boundary without calling Windows' {
    $native=[Ride.VisualEffectsV1.NativeApi]::new();[uint32]$value=0;[int]$errorCode=0
    {$native.Scalar(0x0025,[ref]$value,[ref]$errorCode)} | Should -Throw '*Only reviewed visual GET*'
  }
  It 'rejects malformed animation input before calling Windows' {
    $native=[Ride.VisualEffectsV1.NativeApi]::new();$info=[Ride.VisualEffectsV1.AnimationInfo]::new();[int]$errorCode=0
    {$native.Animation([ref]$info,[ref]$errorCode)} | Should -Throw '*Invalid ANIMATIONINFO*'
  }
}

Describe 'Visual observation identity and failure isolation' {
  BeforeEach {
    $script:CaptureArgs=@{Kind=@('DragFullWindows','MenuShowDelay','MinimizeAnimation','UiEffects','ClientAreaAnimation');ExpectedComputerName='TEST-VM';ExpectedBuild='26100';ExpectedEditionId='Professional';ExpectedUserSid='S-1-5-21-1-2-3-1001';ExpectedSessionId=1}
    Mock Get-RideVisualEffectsContext -ModuleName RIDE.VisualEffectsInventory {New-VisualTestContext}
    Mock Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory {param($Kind) New-VisualTestRow $Kind}
  }
  It 'keeps session values separate from GUI verification and recovery claims' {
    $r=Get-RideVisualEffectsInventory @CaptureArgs
    $r.Kind | Should -BeExactly VisualEffectsObservation
    $r.SchemaVersion | Should -Be 1
    $r.Providers.Count | Should -Be 5
    @($r.Providers|Where-Object Status -eq Captured).Count | Should -Be 5
    $r.Providers[1].Value | Should -BeOfType ([uint32])
    $r.Providers[1].Value | Should -Be ([uint32]::MaxValue)
    $r.Providers[0].Value | Should -BeOfType ([bool])
    $r.Providers[0].Value | Should -BeTrue
    @($r.Providers|Where-Object GuiEffectVerified).Count | Should -Be 0
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    Should -Invoke Get-RideVisualEffectsContext -ModuleName RIDE.VisualEffectsInventory -Exactly 2
  }
  It 'queries only the requested kind and canonicalizes case' {
    $CaptureArgs.Kind=@('menushowdelay')
    $r=Get-RideVisualEffectsInventory @CaptureArgs
    $r.Providers.Count | Should -Be 1
    $r.Providers[0].Kind | Should -BeExactly MenuShowDelay
    Should -Invoke Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory -Exactly 1 -ParameterFilter {$Kind -ceq 'MenuShowDelay'}
  }
  It 'refuses duplicates before identity or native queries' {
    $CaptureArgs.Kind=@('UiEffects','uieffects')
    {Get-RideVisualEffectsInventory @CaptureArgs} | Should -Throw '*only once*'
    Should -Invoke Get-RideVisualEffectsContext -ModuleName RIDE.VisualEffectsInventory -Exactly 0
    Should -Invoke Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory -Exactly 0
  }
  It 'completes finite kinds without queries' {
    $line='Get-RideVisualEffectsInventory -Kind Mi'
    (TabExpansion2 $line $line.Length).CompletionMatches.CompletionText | Should -Contain MinimizeAnimation
    Should -Invoke Get-RideVisualEffectsContext -ModuleName RIDE.VisualEffectsInventory -Exactly 0
    Should -Invoke Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory -Exactly 0
  }
  It 'refuses wrong context <Field> before any native query' -ForEach @(
    @{Field='ComputerName';Value='OTHER'},@{Field='Build';Value='26200'},
    @{Field='EditionId';Value='Enterprise'},@{Field='UserSid';Value='S-1-5-21-1-2-3-1002'},
    @{Field='SessionId';Value=2},@{Field='SessionId';Value='1'},
    @{Field='NativeProcess';Value=$false},@{Field='UserInteractive';Value=$false},
    @{Field='UpdateBuildRevision';Value='1'}
  ) {
    $context=New-VisualTestContext;$context.$Field=$Value
    Mock Get-RideVisualEffectsContext -ModuleName RIDE.VisualEffectsInventory {$context}
    {Get-RideVisualEffectsInventory @CaptureArgs} | Should -Throw '*target differs*'
    Should -Invoke Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory -Exactly 0
  }
  It 'discards the entire observation when context drifts' {
    InModuleScope RIDE.VisualEffectsInventory -Parameters @{CaptureParameters=$CaptureArgs} {
      param($CaptureParameters)
      $script:VisualContextCalls=0
      Mock Get-RideVisualEffectsContext {
        $script:VisualContextCalls++
        [pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=$script:VisualContextCalls;NativeProcess=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
      }
      {Get-RideVisualEffectsInventory @CaptureParameters} | Should -Throw '*changed during collection*'
    }
  }
  It 'preserves failure code <Code> without exposing a partial value' -ForEach @(@{Code=0},@{Code=5}) {
    Mock Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory -ParameterFilter {$Kind -eq 'MenuShowDelay'} {
      [pscustomobject]@{Kind='MenuShowDelay';Action=[uint32]0x006A;Available=$false;RawValue=[uint32]999;ErrorCode=[int]$Code}
    }
    $r=Get-RideVisualEffectsInventory @CaptureArgs
    $r.Providers[1].Status | Should -Be Unavailable
    $r.Providers[1].Value | Should -BeNullOrEmpty
    $r.Providers[1].RawValue | Should -BeNullOrEmpty
    $r.Providers[1].NativeError | Should -Be $Code
    @($r.Providers|Where-Object Status -eq Captured).Count | Should -Be 4
  }
  It 'maps Win32 nonzero BOOLs to true without losing raw bits' {
    $CaptureArgs.Kind=@('UiEffects')
    Mock Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory {
      [pscustomobject]@{Kind='UiEffects';Action=[uint32]0x103E;Available=$true;RawValue=[uint32]::MaxValue;ErrorCode=0}
    }
    $r=Get-RideVisualEffectsInventory @CaptureArgs
    $r.Providers[0].Value | Should -BeTrue
    $r.Providers[0].RawValue | Should -Be ([uint32]::MaxValue)
  }
  It 'isolates <Failure> without publishing partial or malformed provider data' -ForEach @(
    @{Failure='Empty'},@{Failure='Multiple'},@{Failure='Throws'},@{Failure='WrongAction'},
    @{Failure='ContradictoryError'},@{Failure='WrongType'}
  ) {
    Mock Get-RideVisualEffectsRow -ModuleName RIDE.VisualEffectsInventory -ParameterFilter {$Kind -eq 'MenuShowDelay'} {
      if($Failure -eq 'Empty'){return}
      $r=[pscustomobject]@{Kind='MenuShowDelay';Action=[uint32]0x006A;Available=$true;RawValue=[uint32]400;ErrorCode=0}
      switch($Failure){WrongAction{$r.Action=[uint32]0x0025}ContradictoryError{$r.ErrorCode=5}WrongType{$r.RawValue='400'}}
      $r
      if($Failure -eq 'Multiple'){$r}
      if($Failure -eq 'Throws'){throw 'Do not retain partial value or sensitive provider details'}
    }
    $r=Get-RideVisualEffectsInventory @CaptureArgs
    $r.Providers[1].Status | Should -Be Unavailable
    $r.Providers[1].Value | Should -BeNullOrEmpty
    $r.Providers[1].RawValue | Should -BeNullOrEmpty
    $r.Providers[1].ErrorId | Should -Not -BeNullOrEmpty
    @($r.Providers|Where-Object Status -eq Captured).Count | Should -Be 4
    ($r|ConvertTo-Json -Depth 6) | Should -Not -Match 'sensitive provider details'
  }
}
