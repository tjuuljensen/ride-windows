BeforeAll {
  Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.FastTrackStartup.psm1') -Force
  $script:priorAttestation=$env:RIDE_INTEGRATION_VM
  $script:fixture=Join-Path $TestDrive 'synthetic.exe'
  [IO.File]::WriteAllText($script:fixture,'Inert fixture; must never execute.')
  $script:digest=(Get-FileHash -LiteralPath $script:fixture).Hash
}
AfterAll {$env:RIDE_INTEGRATION_VM=$script:priorAttestation}
Describe 'Primary application startup selection' {
  BeforeEach {$script:members=@('MSIX.exe','GetSys.exe','MSIX64.exe','GetSys64.exe'|ForEach-Object {[pscustomobject]@{RelativePath=$_;Sha256=('a'*64)}})}
  It 'selects both MSIX applications and retains GetSys helpers as explicit deferred evidence' {
    $selection=Get-RideFastTrackStartupSelection 'package.mitec-system-information' $script:members
    @($selection.Executables.RelativePath)|Should -Be @('MSIX64.exe','MSIX.exe')
    @($selection.DeferredExecutables.RelativePath)|Should -Be @('GetSys.exe','GetSys64.exe')
    $selection.DeferredReason|Should -Match 'deferred to v3.1'
    @($selection.Executables.Sha256|Select-Object -Unique)|Should -Be @('a'*64)
  }
  It 'refuses missing or unexpected System Information executables' {
    {Get-RideFastTrackStartupSelection 'package.mitec-system-information' $script:members[0..2]}|Should -Throw '*exact four reviewed*'
    $script:members[0].RelativePath='unknown.exe'
    {Get-RideFastTrackStartupSelection 'package.mitec-system-information' $script:members}|Should -Throw '*exact four reviewed*'
  }
  It 'retains other MiTeC selections and refuses empty executable selections' {
    $selection=Get-RideFastTrackStartupSelection 'package.mitec-other' @([pscustomobject]@{RelativePath='app.exe';Sha256=('b'*64)},[pscustomobject]@{RelativePath='notice.txt';Sha256=('c'*64)})
    @($selection.Executables.RelativePath)|Should -Be @('app.exe')
    $selection.DeferredExecutables.Count|Should -Be 0
    {Get-RideFastTrackStartupSelection 'package.mitec-other' @([pscustomobject]@{RelativePath='notice.txt'})}|Should -Throw '*No selected executable*'
  }
}
Describe 'Bounded fast-track startup evidence' {
  BeforeEach {
    $env:RIDE_INTEGRATION_VM='1'
    Mock Start-Process -ModuleName RIDE.FastTrackStartup {
      $p=[pscustomobject]@{Id=42;SessionId=0;HasExited=$true;ExitCode=0;MainWindowTitle='';MainWindowHandle=[intptr]::Zero;Responding=$true}
      $p|Add-Member ScriptMethod Refresh {}
      $p|Add-Member ScriptMethod Dispose {}
      $p
    }
    Mock Get-WinEvent -ModuleName RIDE.FastTrackStartup { @() }
  }
  It 'records clean early exit without claiming feature acceptance' {
    $r=Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 $script:digest
    $r.Status|Should -Be 'NoErrorObserved'
    $r.ExitCode|Should -Be 0
    $r.Closure|Should -Be 'Exited'
    $r.Boundary|Should -Match 'no feature'
    Should -Invoke Start-Process -ModuleName RIDE.FastTrackStartup -Times 1 -Exactly
  }
  It 'refuses execution outside the attested guest' {
    $env:RIDE_INTEGRATION_VM='0'
    {Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 $script:digest}|Should -Throw '*attested*'
    Should -Invoke Start-Process -ModuleName RIDE.FastTrackStartup -Times 0 -Exactly
  }
  It 'refuses an executable digest mismatch before startup' {
    {Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 ('0'*64)}|Should -Throw '*digest*'
    Should -Invoke Start-Process -ModuleName RIDE.FastTrackStartup -Times 0 -Exactly
  }
  It 'fails on nonzero process exit and disposes the process' {
    Mock Start-Process -ModuleName RIDE.FastTrackStartup {
      $p=[pscustomobject]@{Id=43;SessionId=0;HasExited=$true;ExitCode=7}
      $p|Add-Member ScriptMethod Refresh {}; $p|Add-Member ScriptMethod Dispose {}; $p
    }
    {Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 $script:digest}|Should -Throw '*code 7*'
  }
  It 'fails when a correlated application error is observed' {
    Mock Get-WinEvent -ModuleName RIDE.FastTrackStartup {[pscustomobject]@{Id=1000;ProviderName='Application Error';TimeCreated=Get-Date;Message='Faulting application synthetic.exe'}}
    {Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 $script:digest}|Should -Throw '*error events*'
  }
  It 'ignores an unrelated application event' {
    Mock Get-WinEvent -ModuleName RIDE.FastTrackStartup {[pscustomobject]@{Id=1000;Message='Faulting application unrelated.exe'}}
    (Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 $script:digest).Status|Should -Be 'NoErrorObserved'
  }
  It 'does not turn event provider failure into clean startup evidence' {
    Mock Get-WinEvent -ModuleName RIDE.FastTrackStartup {throw 'Provider unavailable'}
    {Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 $script:digest}|Should -Throw '*Provider unavailable*'
  }
  It 'records an exposed error title and closes only its owned process' {
    Mock Start-Process -ModuleName RIDE.FastTrackStartup {
      $p=[pscustomobject]@{Id=44;SessionId=0;HasExited=$false;MainWindowTitle='Application Error';MainWindowHandle=[intptr]1;Responding=$true}
      $p|Add-Member ScriptMethod Refresh {}; $p|Add-Member ScriptMethod Dispose {}
      $p|Add-Member ScriptMethod CloseMainWindow {return $true}
      $p|Add-Member ScriptMethod WaitForExit {param($milliseconds) return $true}
      $p
    }
    try {Invoke-RideFastTrackStartup -ExecutablePath $script:fixture -ExpectedSha256 $script:digest;throw 'Expected error'}
    catch {
      $_.Exception.Message|Should -Be 'Startup exposed an error window title.'
      $_.Exception.Data['RideStartupEvidence'].ProcessId|Should -Be 44
      $_.Exception.Data['RideStartupEvidence'].Closure|Should -Be 'ClosedWindow'
    }
  }
}
