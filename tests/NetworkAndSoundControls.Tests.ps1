<#
.SYNOPSIS
  Exercise coupled network recovery and coherent sound-preset handling.
.DESCRIPTION
  All system APIs are mocked. Tests cover identity changes, incomplete snapshots,
  coupled binding changes, native failures and raw sound-value recovery.
.EXAMPLE
  Invoke-Pester ./tests/NetworkAndSoundControls.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.
  Owner: RIDE-Windows maintainers. Version: repository test fixture.
  Changelog: 2026-10-10: Add isolated network and sound recovery checks.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-AdapterBindings.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-NetworkControls.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE-SoundSchemes.psm1') -Force
}
Describe 'GUID-bound coupled adapter recovery' {
  BeforeEach {
    InModuleScope RIDE-AdapterBindings {
      $script:AdapterPresent=$true
      $script:Flags=@{ms_tcpip=$true;ms_server=$true}
      Mock Get-NetAdapter { if($script:AdapterPresent){[pscustomobject]@{InterfaceGuid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Name='Renamed adapter'}} }
      Mock Get-NetAdapterBinding { foreach($id in @($script:Flags.Keys | Sort-Object)){if(-not $ComponentID -or $id -in $ComponentID){New-CimInstance -ClientOnly -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapterBindingSettingData -Property @{ComponentID=$id;Enabled=$script:Flags[$id]}}} }
      Mock Set-NetAdapterBinding {$script:Flags[$InputObject[0].ComponentID]=$Enabled;if($InputObject[0].ComponentID -eq 'ms_tcpip' -and -not $Enabled){$script:Flags.ms_server=$false}}
    }
    $script:BindingOp=@{ComponentIds=@('ms_tcpip')}
  }
  It 'captures non-selected flags and restores coupled changes after an adapter rename' {
    $before=Get-RideAdapterBindingState $script:BindingOp
    $before.RecoveryBindings.Count | Should -Be 2
    $before.Bindings.Count | Should -Be 1
    $before.Bindings[0].Name='Old name';$before.RecoveryBindings | ForEach-Object {$_.Name='Old name'}
    Set-RideAdapterBindingState $script:BindingOp $false
    InModuleScope RIDE-AdapterBindings {$script:Flags.ms_server | Should -BeFalse}
    $snapshot=$before | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    Restore-RideAdapterBindingState $script:BindingOp $snapshot
    InModuleScope RIDE-AdapterBindings {$script:Flags.ms_tcpip | Should -BeTrue;$script:Flags.ms_server | Should -BeTrue}
    Should -Invoke Get-NetAdapterBinding -ModuleName RIDE-AdapterBindings -ParameterFilter {$Name -eq 'Renamed adapter'}
  }
  It 'rejects disappeared adapters and incomplete/redirected snapshots before writes' {
    $before=Get-RideAdapterBindingState $script:BindingOp
    InModuleScope RIDE-AdapterBindings {$script:AdapterPresent=$false}
    {Restore-RideAdapterBindingState $script:BindingOp $before} | Should -Throw '*missing*'
    InModuleScope RIDE-AdapterBindings {$script:AdapterPresent=$true}
    $before.RecoveryBindings=@()
    {Restore-RideAdapterBindingState $script:BindingOp $before} | Should -Throw '*Incomplete*'
    Should -Invoke Set-NetAdapterBinding -ModuleName RIDE-AdapterBindings -Times 0
  }
  It 'reports absent declared bindings without a synthetic enabled state' {
    $state=Get-RideAdapterBindingState @{ComponentIds=@('ms_lldp')}
    $state.Available | Should -BeFalse
    {Set-RideAdapterBindingState @{ComponentIds=@('ms_lldp')} $true} | Should -Throw '*No available*'
  }
}
Describe 'Stable network-control recovery' {
  BeforeEach {
    InModuleScope RIDE-NetworkControls {
      $script:NetbiosFixture=[pscustomobject]@{Exists=$false;Value=$null;ValueType=$null}
      Mock Get-RideNetbiosInterfaceIds {'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'}
      Mock Get-Item {[pscustomobject]@{ReadOnlyKey=$true}}
      Mock Get-RideSettingState {$script:NetbiosFixture}
      Mock Set-RideSettingState {$script:NetbiosFixture=[pscustomobject]@{Exists=$true;Value=$Value;ValueType=$Operation.ValueType}}
      Mock Restore-RideSettingState {$script:NetbiosFixture=[pscustomobject]@{Exists=$Snapshot.Exists;Value=$Snapshot.Value;ValueType=$Snapshot.ValueType}}
    }
    Mock Get-NetFirewallRule -ModuleName RIDE-NetworkControls {[pscustomobject]@{Name='RemoteDesktop-UserMode-In-TCP';Enabled='True'}}
    Mock Set-NetFirewallRule -ModuleName RIDE-NetworkControls {}
  }
  It 'uses the DHCP/default registry preference and recovers original absence and type' {
    $op=@{Kind='NetBios';States=@{Dhcp=0;Disabled=2}}
    $before=Get-RideNetworkControlState $op
    Set-RideNetworkControlState $op Dhcp
    Should -Invoke Set-RideSettingState -ModuleName RIDE-NetworkControls -Times 1 -Exactly -ParameterFilter {$Value -eq 0 -and $Operation.ValueType -eq 'DWord' -and $Operation.RegistryPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'}
    Restore-RideNetworkControlState $op ($before | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
    (Get-RideNetworkControlState $op).Entries[0].Exists | Should -BeFalse
    InModuleScope RIDE-NetworkControls {$script:NetbiosFixture=[pscustomobject]@{Exists=$true;Value='0';ValueType='String'}}
    $before=Get-RideNetworkControlState $op
    Set-RideNetworkControlState $op Dhcp
    (Get-RideNetworkControlState $op).Entries[0].ValueType | Should -Be DWord
    Restore-RideNetworkControlState $op ($before | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
    (Get-RideNetworkControlState $op).Entries[0].ValueType | Should -Be String
  }
  It 'validates every captured interface before writes and leaves new interfaces alone' {
    $op=@{Kind='NetBios'}
    $before=Get-RideNetworkControlState $op
    $bad=$before | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $bad.Entries += [pscustomobject]@{Id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';Value=0;Exists=$true;ValueType='DWord';KeyExisted=$true}
    {Restore-RideNetworkControlState $op $bad} | Should -Throw '*missing*'
    Should -Invoke Restore-RideSettingState -ModuleName RIDE-NetworkControls -Times 0
    Mock Get-RideNetbiosInterfaceIds -ModuleName RIDE-NetworkControls {'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}
    Restore-RideNetworkControlState $op $before
    Should -Invoke Restore-RideSettingState -ModuleName RIDE-NetworkControls -Times 1 -Exactly -ParameterFilter {$Operation.RegistryPath -like '*aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa*'}
    Should -Invoke Restore-RideSettingState -ModuleName RIDE-NetworkControls -Times 0 -ParameterFilter {$Operation.RegistryPath -like '*bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb*'}
    {Restore-RideNetworkControlState $op @{Available=$true;Entries=@(@{Id='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Value=0})}} | Should -Throw '*CIM-only*checkpoint*'
  }
  It 'validates all firewall identities before writes and restores the literal local flag' {
    $op=@{Kind='RemoteDesktopFirewall'}
    $snapshot=@{Available=$true;Entries=@(@{Id='RemoteDesktop-UserMode-In-TCP';Value='False'},@{Id='Unrelated';Value='True'})}
    {Restore-RideNetworkControlState $op $snapshot} | Should -Throw '*missing*'
    Should -Invoke Set-NetFirewallRule -ModuleName RIDE-NetworkControls -Times 0
    $snapshot.Entries=@($snapshot.Entries[0])
    Restore-RideNetworkControlState $op $snapshot
    Should -Invoke Set-NetFirewallRule -ModuleName RIDE-NetworkControls -Times 1 -Exactly -ParameterFilter {$PolicyStore -eq 'PersistentStore' -and $Name -eq 'RemoteDesktop-UserMode-In-TCP' -and $Enabled -eq 'False'}
  }
}
Describe 'Coherent registered sound scheme' {
  BeforeEach {
    InModuleScope RIDE-SoundSchemes {
      Mock Get-RideSoundEvents {[pscustomobject]@{Application='.Default';Event='Notification'}}
      Mock Get-RideSoundValue {
        if($Path -eq 'AppEvents\Schemes'){return [pscustomobject]@{Exists=$true;KeyExisted=$true;Value='custom';ValueType='String'}}
        [pscustomobject]@{Exists=$true;KeyExisted=$true;Value='%SystemRoot%\Media\sound.wav';ValueType='ExpandString'}
      }
      Mock Set-RideSoundValue {}
    }
    $script:SoundOp=@{States=@{NoneScheme='.None';WindowsDefaultScheme='.Default'}}
  }
  It 'writes current events and selector while preserving source presets' {
    Set-RideSoundSchemeState $script:SoundOp WindowsDefaultScheme
    Should -Invoke Set-RideSoundValue -ModuleName RIDE-SoundSchemes -Times 1 -ParameterFilter {$Path -like '*\.Current' -and $Snapshot.ValueType -eq 'String' -and $Snapshot.Value -notmatch '%SystemRoot%'}
    Should -Invoke Set-RideSoundValue -ModuleName RIDE-SoundSchemes -Times 1 -ParameterFilter {$Path -eq 'AppEvents\Schemes' -and $Snapshot.Value -eq '.Default'}
    Should -Invoke Set-RideSoundValue -ModuleName RIDE-SoundSchemes -Times 0 -ParameterFilter {$Path -like '*\.Default' -or $Path -like '*\.None'}
  }
  It 'restores raw event type and original absence from serialized state' {
    $before=Get-RideSoundSchemeState $script:SoundOp
    $snapshot=$before | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    Restore-RideSoundSchemeState $script:SoundOp $snapshot
    Should -Invoke Set-RideSoundValue -ModuleName RIDE-SoundSchemes -Times 1 -ParameterFilter {$Path -like '*\.Current' -and $Snapshot.ValueType -eq 'ExpandString' -and $Snapshot.Value -match '%SystemRoot%'}
  }
  It 'rejects redirected or duplicate event identities before restoring any value' {
    $snapshot=Get-RideSoundSchemeState $script:SoundOp
    $snapshot.Events[0].Event='..\Other'
    {Restore-RideSoundSchemeState $script:SoundOp $snapshot} | Should -Throw '*identity*'
    Should -Invoke Set-RideSoundValue -ModuleName RIDE-SoundSchemes -Times 0
  }
  It 'does not accept a matching selector with mismatched event data' {
    $current=Get-RideSoundSchemeState $script:SoundOp
    $current.Selector.Value='.Default'
    Test-RideSoundSchemeMatch $script:SoundOp WindowsDefaultScheme $current | Should -BeFalse
  }
}
