<#
.SYNOPSIS
  Verify read-only audio inventory, identity guards and saved-data selection.
.DESCRIPTION
  Mocks Core Audio and identity providers. Compiles interop without calling it.
  Tests unknown/missing devices, duplicate IDs, invalid observations, JSON
  round trips, bounded completion and non-overwriting preview export.
.EXAMPLE
  Invoke-Pester .\tests\AudioEndpointInventory.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7.
  No live audio calls, playback, registry writes or service changes.
  Author: RIDE-Windows maintainers. Version: Repository test fixture.
#>
BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.AudioEndpointInventory.psm1') -Force
  function New-AudioObservation {
    [pscustomobject]@{
      SchemaVersion=1; Kind='AudioEndpointObservation'; Flow='Render'
      UserSid='S-1-5-21-1-2-3-1001'; SessionId=1; CompletedAtUtc='2026-10-16T20:00:00Z'
      Endpoints=@([pscustomobject]@{Id='opaque:Speaker-A';Name='Speakers';State=1;NameStatus='Captured';ObservationStatus='Captured';Muted=$false;VolumeScalar=0.4})
      DefaultRoles=@('Console','Multimedia','Communications' | ForEach-Object { [pscustomobject]@{Name=$_;Id='opaque:Speaker-A';Status='Captured'} })
    }
  }
}
Describe 'Explicit audio inventory context' {
  BeforeEach {
    Mock Get-RideAudioInventoryContext -ModuleName RIDE.AudioEndpointInventory { [pscustomobject]@{UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true} }
    Mock Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory { New-AudioObservation }
  }
  It 'refuses a different account before querying Core Audio' {
    { Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-500 -ExpectedSessionId 1 } | Should -Throw '*identity differs*'
    Should -Invoke Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory -Exactly 0
  }
  It 'refuses a different session before querying Core Audio' {
    { Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 2 } | Should -Throw '*identity differs*'
    Should -Invoke Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory -Exactly 0
  }
  It 'refuses noninteractive execution' {
    Mock Get-RideAudioInventoryContext -ModuleName RIDE.AudioEndpointInventory { [pscustomobject]@{UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$false} }
    { Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 } | Should -Throw '*identity differs*'
    Should -Invoke Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory -Exactly 0
  }
  It 'propagates enumeration failure instead of returning an empty successful inventory' {
    Mock Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory { throw 'Enumeration unavailable' }
    { Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 } | Should -Throw '*Enumeration unavailable*'
  }
  It 'retains literal observations without claiming an atomic or verified desktop snapshot' {
    $r=Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
    $r.DesktopVerified | Should -BeFalse
    $r.Consistency | Should -Match 'not atomic'
    $r.Endpoints[0].Muted | Should -BeFalse
    $r.Endpoints[0].VolumeScalar | Should -Be 0.4
    $r.StartedAtUtc | Should -Not -BeNullOrEmpty
    $r.CompletedAtUtc | Should -Not -BeNullOrEmpty
  }
  It 'retains a real empty inventory and unavailable default roles' {
    Mock Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory {
      [pscustomobject]@{Endpoints=@();DefaultRoles=@('Console','Multimedia','Communications' | ForEach-Object { [pscustomobject]@{Name=$_;Id=$null;Status='None'} })}
    }
    $r=Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1
    @($r.Endpoints).Count | Should -Be 0
    @($r.DefaultRoles | Where-Object Status -eq None).Count | Should -Be 3
  }
  It 'detects an execution identity change after collection' {
    InModuleScope RIDE.AudioEndpointInventory { $script:AudioContextCalls=0 }
    Mock Get-RideAudioInventoryContext -ModuleName RIDE.AudioEndpointInventory {
      $script:AudioContextCalls++
      [pscustomobject]@{UserSid='S-1-5-21-1-2-3-1001';SessionId=$script:AudioContextCalls;UserInteractive=$true}
    }
    { Get-RideAudioEndpointInventory -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 } | Should -Throw '*identity changed*'
  }
}
Describe 'Saved endpoint observations' {
  It 'round trips through JSON without creating mutation or recovery authority' {
    $data=New-AudioObservation | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $r=Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A'
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    $r.Endpoint.Muted | Should -BeFalse
  }
  It 'never falls back to a default device or friendly name' {
    $data=New-AudioObservation
    foreach ($id in @('missing','Speakers','opaque:speaker-a')) {
      { Select-RideAudioEndpointObservation -Inventory $data -EndpointId $id } | Should -Throw '*missing or ambiguous*'
    }
  }
  It 'rejects duplicate opaque identities even with different friendly names' {
    $data=New-AudioObservation; $data.Endpoints+= $data.Endpoints[0]
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*duplicate*'
  }
  It 'preserves unavailable mute as unknown rather than false' {
    $data=New-AudioObservation; $data.Endpoints[0].ObservationStatus='Unavailable'; $data.Endpoints[0].Muted=$null; $data.Endpoints[0].VolumeScalar=$null
    $r=Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A'
    $r.Endpoint.Muted | Should -BeNullOrEmpty
    $r.Endpoint.ObservationStatus | Should -Be Unavailable
  }
  It 'rejects a fabricated unmuted state for an unreadable endpoint' {
    $data=New-AudioObservation; $data.Endpoints[0].ObservationStatus='Unavailable'
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*must not invent*'
  }
  It 'rejects a string boolean and out-of-range volume' {
    $data=New-AudioObservation; $data.Endpoints[0].Muted='false'
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*mute or volume*'
    $data=New-AudioObservation; $data.Endpoints[0].VolumeScalar=[double]::NaN
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*mute or volume*'
    $data=New-AudioObservation; $data.Endpoints[0].VolumeScalar=$false
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*mute or volume*'
  }
  It 'rejects capture direction and missing default roles' {
    $data=New-AudioObservation; $data.Flow='Capture'
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*flow*'
    $data=New-AudioObservation; $data.DefaultRoles=@()
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*bounds*'
  }
  It 'refuses excessive inventory before selection' {
    $data=New-AudioObservation; $data.Endpoints=@(1..257 | ForEach-Object {$data.Endpoints[0]})
    { Select-RideAudioEndpointObservation -Inventory $data -EndpointId 'opaque:Speaker-A' } | Should -Throw '*bounds*'
  }
}
Describe 'Audio inventory completion and export' {
  It 'completes from supplied data only with prefix filtering and safe quoting' {
    Mock Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory { throw 'No live query during completion' }
    $data=New-AudioObservation; $data.Endpoints=@([pscustomobject]@{Id="opaque:O'Brien"},[pscustomobject]@{Id="opaque:O'Brien"},[pscustomobject]@{Id='different'})
    $attribute=(Get-Command Select-RideAudioEndpointObservation).Parameters.EndpointId.Attributes | Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $r=@(& $attribute.ScriptBlock 'Select-RideAudioEndpointObservation' 'EndpointId' 'OPAQUE:' $null @{Inventory=$data})
    $r.Count | Should -Be 1
    $r[0].CompletionText | Should -Be "'opaque:O''Brien'"
    Should -Invoke Get-RideAudioEndpointNativeSnapshot -ModuleName RIDE.AudioEndpointInventory -Exactly 0
  }
  It 'fails quietly when completion data is missing' {
    $attribute=(Get-Command Select-RideAudioEndpointObservation).Parameters.EndpointId.Attributes | Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    @(& $attribute.ScriptBlock 'Select-RideAudioEndpointObservation' 'EndpointId' '' $null @{}).Count | Should -Be 0
  }
  It 'previews export without querying audio or creating a file' {
    Mock Get-RideAudioEndpointInventory { throw 'No audio query for preview' }
    $path=Join-Path $TestDrive 'preview.json'
    & (Join-Path $script:Root 'tools/Export-RideAudioEndpointInventory.ps1') -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath $path -WhatIf
    Test-Path -LiteralPath $path | Should -BeFalse
    Should -Invoke Get-RideAudioEndpointInventory -Exactly 0
  }
  It 'refuses existing output without truncation' {
    $path=Join-Path $TestDrive 'existing.json'; [IO.File]::WriteAllText($path,'preserve')
    { & (Join-Path $script:Root 'tools/Export-RideAudioEndpointInventory.ps1') -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath $path } | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($path) | Should -Be preserve
  }
  It 'writes only captured JSON and refuses a file created during collection' {
    Mock Import-Module {}
    Mock Get-RideAudioEndpointInventory { New-AudioObservation }
    $path=Join-Path $TestDrive 'captured.json'
    & (Join-Path $script:Root 'tools/Export-RideAudioEndpointInventory.ps1') -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath $path | Should -Be $path
    $saved=[IO.File]::ReadAllText($path) | ConvertFrom-Json
    $saved.Endpoints[0].Id | Should -Be 'opaque:Speaker-A'
    $script:AudioCollisionPath=Join-Path $TestDrive 'collision.json'
    Mock Get-RideAudioEndpointInventory { [IO.File]::WriteAllText((Join-Path $TestDrive 'collision.json'),'concurrent'); New-AudioObservation }
    { & (Join-Path $script:Root 'tools/Export-RideAudioEndpointInventory.ps1') -ExpectedUserSid S-1-5-21-1-2-3-1001 -ExpectedSessionId 1 -OutputPath $script:AudioCollisionPath } | Should -Throw '*already exists*'
    [IO.File]::ReadAllText($script:AudioCollisionPath) | Should -Be concurrent
  }
  It 'compiles the read-only interop on this PowerShell edition without invoking Core Audio' {
    InModuleScope RIDE.AudioEndpointInventory { Initialize-RideAudioInventoryNative }
    ('Ride.AudioInventoryV1.Reader' -as [type]) | Should -Not -BeNullOrEmpty
  }
}
