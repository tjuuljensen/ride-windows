<#
.SYNOPSIS
  Verify explicit client-component and servicing-source preparation without DISM calls.
.DESCRIPTION
  Uses supplied component observations and inspects command outlines only. No
  servicing provider, source folder, policy, network, elevation or reboot is invoked.
.EXAMPLE
  Invoke-Pester .\tests\ClientComponentPreparation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository fixture; native servicing and exact recovery remain pending.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.ClientComponentPreparation.psm1') -Force
  function New-ClientComponentInventory {
    [pscustomobject]@{SchemaVersion=1;Kind='WindowsComponentObservation';ReadyForMutation=$false;RecoverySupported=$false
      WindowsContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';InstallationType='Client';ProductType='WinNT';NativeProcess=$true;UpdateBuildRevision=1}
      Providers=@(
        [pscustomobject]@{Kind='Capability';Status='Captured';Rows=@([pscustomobject]@{Name='OpenSSH.Client~~~~0.0.1.0';StateObserved='NotPresent'});Coverage='fixture'},
        [pscustomobject]@{Kind='OptionalFeature';Status='Captured';Rows=@([pscustomobject]@{Name='TelnetClient';StateObserved='Disabled'});Coverage='fixture'}
      )}
  }
}
Describe 'Independent client servicing preparation' {
  BeforeEach {
    $script:Inventory=New-ClientComponentInventory
    Mock Get-RideComponentWindowsContext -ModuleName RIDE.ComponentInventory {throw 'No native context query'}
    Mock Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory {throw 'No servicing query'}
  }
  It 'lists the two prioritized identities without selecting either' {
    $choices=@(Get-RideClientComponentPreparationChoice -Inventory $Inventory)
    $choices.Count|Should -Be 2
    ($choices.Name -join ',')|Should -BeExactly 'OpenSSH.Client~~~~0.0.1.0,TelnetClient'
    @($choices|Where-Object Selected).Count|Should -Be 0
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'prepares OpenSSH Client online without overriding configured sources or selecting the server' {
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind Capability -Name OpenSSH.Client~~~~0.0.1.0 -DesiredState Present -SourceMode Online
    $r.Command|Should -BeExactly 'Dism\Add-WindowsCapability'
    $r.Parameters.Online|Should -BeTrue;$r.Parameters.Name|Should -BeExactly OpenSSH.Client~~~~0.0.1.0
    $r.Parameters.Contains('Source')|Should -BeFalse;$r.Parameters.Contains('LimitAccess')|Should -BeFalse
    $r.Parameters.Contains('NoRestart')|Should -BeFalse
    $r.ReadyForMutation|Should -BeFalse;$r.RecoverySupported|Should -BeFalse
    $r.SourcePolicy.PolicyOverridesAllowed|Should -BeFalse
    ($r|ConvertTo-Json -Depth 8)|Should -Not -Match 'OpenSSH.Server'
  }
  It 'distinguishes offline payload sources from the DISM running-image Online parameter' {
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind Capability -Name OpenSSH.Client~~~~0.0.1.0 -DesiredState Present -SourceMode Offline -SourcePath D:\Sources\FOD
    $r.SourcePolicy.Mode|Should -BeExactly Offline
    $r.Parameters.Online|Should -BeTrue;$r.Parameters.LimitAccess|Should -BeTrue
    $r.Parameters.Source[0]|Should -BeExactly 'D:\Sources\FOD'
    $r.SourcePolicy.AllowNetworkFallback|Should -BeFalse
    $r.SourcePolicy.SourceValidated|Should -BeFalse;$r.SourcePolicy.NetworkBoundaryVerified|Should -BeFalse
    $r.ReadyForMutation|Should -BeFalse
  }
  It 'prepares Telnet with NoRestart but without automatic parents or payload removal' {
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Offline -SourcePath D:\Sources\Sxs
    $r.Command|Should -BeExactly 'Dism\Enable-WindowsOptionalFeature'
    $r.Parameters.FeatureName[0]|Should -BeExactly TelnetClient
    $r.Parameters.NoRestart|Should -BeTrue
    $r.Parameters.Contains('All')|Should -BeFalse;$r.Parameters.Contains('Remove')|Should -BeFalse
  }
  It 'prepares capability removal without inappropriate source switches and retains recovery requirements' {
    $Inventory.Providers[0].Rows[0].StateObserved='Installed'
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind Capability -Name OpenSSH.Client~~~~0.0.1.0 -DesiredState Absent -SourceMode Offline -SourcePath D:\Sources\FOD
    $r.Command|Should -BeExactly 'Dism\Remove-WindowsCapability'
    $r.Parameters.Contains('Source')|Should -BeFalse;$r.Parameters.Contains('LimitAccess')|Should -BeFalse
    $r.Parameters.Contains('NoRestart')|Should -BeFalse
    ($r.Requirements -join ' ')|Should -Match 'matching payloads to restore'
    $r.SourcePolicy.Path|Should -BeExactly 'D:\Sources\FOD'
  }
  It 'prepares feature disabling with payload retained' {
    $Inventory.Providers[1].Rows[0].StateObserved='Enabled'
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Absent -SourceMode Online
    $r.Command|Should -BeExactly 'Dism\Disable-WindowsOptionalFeature'
    $r.Parameters.NoRestart|Should -BeTrue;$r.Parameters.Contains('Remove')|Should -BeFalse
  }
  It 'returns no command when the declared desired presence is already observed' {
    foreach($case in @(
      @{Index=0;State='Installed';Desired='Present';Kind='Capability';Name='OpenSSH.Client~~~~0.0.1.0'},
      @{Index=0;State='NotPresent';Desired='Absent';Kind='Capability';Name='OpenSSH.Client~~~~0.0.1.0'},
      @{Index=1;State='Enabled';Desired='Present';Kind='OptionalFeature';Name='TelnetClient'},
      @{Index=1;State='Disabled';Desired='Absent';Kind='OptionalFeature';Name='TelnetClient'},
      @{Index=1;State='DisabledWithPayloadRemoved';Desired='Absent';Kind='OptionalFeature';Name='TelnetClient'}
    )){
      $Inventory.Providers[$case.Index].Rows[0].StateObserved=$case.State
      $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind $case.Kind -Name $case.Name -DesiredState $case.Desired -SourceMode Online
      $r.Status|Should -Be NoChangeObserved;$r.ChangeRequired|Should -BeFalse
      ($null -eq $r.Command)|Should -BeTrue
    }
  }
  It 'retains the prior removed-payload distinction without promising exact restore' {
    $Inventory.Providers[1].Rows[0].StateObserved='DisabledWithPayloadRemoved'
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Online
    $r.OriginalState|Should -BeExactly DisabledWithPayloadRemoved
    ($r.Requirements -join ' ')|Should -Match 'Prior feature payload was removed'
    $r.RecoverySupported|Should -BeFalse
  }
  It 'blocks pending and unknown state <State> instead of guessing a transition' -ForEach @(
    @{State='InstallPending'},@{State='UninstallPending'},@{State='EnablePending'},@{State='DisablePending'},@{State='FutureState'}
  ) {
    $Inventory.Providers[0].Rows[0].StateObserved=$State
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind Capability -Name OpenSSH.Client~~~~0.0.1.0 -DesiredState Present -SourceMode Online
    $r.Status|Should -Be BlockedPendingOrUnknownState;($null -eq $r.Command)|Should -BeTrue
  }
  It 'retains missing or unavailable observations without a native fallback query' {
    foreach($status in @('Unavailable','NotApplicable','Missing','Uncollected')){
      $data=New-ClientComponentInventory
      switch($status){
        Missing {$data.Providers[0].Rows=@()}
        Uncollected {$data.Providers=@($data.Providers[1])}
        default {$data.Providers[0].Status=$status;$data.Providers[0].Rows=$null}
      }
      $r=New-RideClientComponentPreparation -Inventory $data -Kind Capability -Name OpenSSH.Client~~~~0.0.1.0 -DesiredState Present -SourceMode Online
      $r.Status|Should -Be NeedsObservation;($null -eq $r.Command)|Should -BeTrue
    }
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'rejects other components, guessed suffixes and wrong provider namespaces' {
    foreach($case in @(
      @{Kind='Capability';Name='OpenSSH.Server~~~~0.0.1.0'},@{Kind='Capability';Name='OpenSSH.Client'},
      @{Kind='Capability';Name='TelnetClient'},@{Kind='OptionalFeature';Name='Microsoft-Hyper-V-All'},
      @{Kind='OptionalFeature';Name='telnetclient'}
    )){{New-RideClientComponentPreparation -Inventory $Inventory -Kind $case.Kind -Name $case.Name -DesiredState Present -SourceMode Online}|Should -Throw '*exact prioritized*'}
  }
  It 'requires a source for offline mode and forbids online overrides' {
    {New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Offline}|Should -Throw '*explicit local*'
    {New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Online -SourcePath D:\Sources}|Should -Throw '*forbids*'
  }
  It 'refuses non-local, expanded, relative or malformed offline path <Path>' -ForEach @(
    @{Path='\\server\share\source'},@{Path='relative'},@{Path='D:relative'},@{Path='D:\a\..\b'},
    @{Path='D:\%SOURCE%'},@{Path='D:\source:stream'},@{Path='https://example.invalid/source'},@{Path='D:\*.cab'}
  ) {
    {New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Offline -SourcePath $Path}|Should -Throw '*local drive path*'
  }
  It 'does not extend client preparation to domain controllers' {
    $Inventory.WindowsContext.ProductType='LanmanNT'
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Online
    $r.Status|Should -Be BlockedDomainController;($null -eq $r.Command)|Should -BeTrue
  }
  It 'copies context and source intent without changing the supplied inventory' {
    $before=$Inventory|ConvertTo-Json -Depth 10 -Compress
    $r=New-RideClientComponentPreparation -Inventory $Inventory -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Online
    $r.WindowsContext.EditionId='changed'
    ($Inventory|ConvertTo-Json -Depth 10 -Compress)|Should -BeExactly $before
    Should -Invoke Get-RideComponentWindowsContext -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'refuses malformed context or mutable inventory claims' {
    foreach($case in @('Schema','Ready','Recovery','Native','Revision','MissingInstallationType')){
      $data=New-ClientComponentInventory
      switch($case){Schema{$data.SchemaVersion='1'}Ready{$data.ReadyForMutation=$true}Recovery{$data.RecoverySupported=$true}Native{$data.WindowsContext.NativeProcess=$false}Revision{$data.WindowsContext.UpdateBuildRevision='1'}MissingInstallationType{$data.WindowsContext.InstallationType=$null}}
      {New-RideClientComponentPreparation -Inventory $data -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Online}|Should -Throw
    }
  }
  It 'completes only observed prioritized identities in the selected namespace' {
    $attr=(Get-Command New-RideClientComponentPreparation).Parameters.Name.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 'OPEN' $null @{Inventory=$Inventory;Kind='Capability'})
    $matches.Count|Should -Be 1;$matches[0].CompletionText|Should -BeExactly "'OpenSSH.Client~~~~0.0.1.0'"
    $Inventory.Providers[0].Rows=@()
    @(& $attr.ScriptBlock '' '' '' $null @{Inventory=$Inventory;Kind='Capability'}).Count|Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count|Should -Be 0
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
  It 'completes finite source modes and desired states without queries' {
    foreach($item in @(@{Text='New-RideClientComponentPreparation -SourceMode Off';Expected='Offline'},@{Text='New-RideClientComponentPreparation -DesiredState Pre';Expected='Present'})){
      (TabExpansion2 $item.Text $item.Text.Length).CompletionMatches.CompletionText|Should -Contain $item.Expected
    }
    Should -Invoke Get-RideComponentProviderRows -ModuleName RIDE.ComponentInventory -Exactly 0
  }
}
