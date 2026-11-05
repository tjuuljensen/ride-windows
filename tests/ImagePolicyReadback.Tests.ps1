<#
.SYNOPSIS
  Verify image policy values and permissions come from the same registry handle.
.DESCRIPTION
  Uses synthetic key methods. Registry provider access is mocked to fail;
  no real registry key is opened or changed.
.EXAMPLE
  Invoke-Pester ./tests/ImagePolicyReadback.Tests.ps1
.NOTES
  Native PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.DefaultLockScreen.psm1')
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.DefaultWallpaper.psm1')
}
Describe 'Image policy handle readback' -ForEach @(
  @{Module='RIDE.DefaultLockScreen';Family='DefaultLock'},
  @{Module='RIDE.DefaultWallpaper';Family='DefaultWallpaper'}
) {
  It '<Family> reads permissions without resolving a second registry provider path' {
    InModuleScope $Module -Parameters @{Family=$Family} {
      param($Family)
      $script:key=[pscustomobject]@{Disposed=$false;SecurityReads=0}
      $script:key|Add-Member ScriptMethod GetValueNames {,'Unrelated'}
      $script:key|Add-Member ScriptMethod GetValueKind {param($Name);'String'}
      $script:key|Add-Member ScriptMethod GetValue {param($Name,$Default,$Options);'retained-value'}
      $script:key|Add-Member ScriptMethod GetSubKeyNames {,'KeptChild'}
      $script:key|Add-Member ScriptMethod GetAccessControl {
        $this.SecurityReads++
        $security=[Security.AccessControl.RegistrySecurity]::new()
        $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $security
      }
      $script:key|Add-Member ScriptMethod Dispose {$this.Disposed=$true}
      Mock "Open-Ride${Family}PolicyKey" {$script:key}
      Mock Get-Acl {throw 'A second provider lookup must not run.'}
      $observed=& "Get-Ride${Family}Registry"
      $observed.Exists|Should -BeTrue
      $observed.Security|Should -BeExactly 'O:BAD:'
      $observed.Rows[0].Value|Should -BeExactly 'retained-value'
      $observed.SubKeys|Should -BeExactly 'KeptChild'
      $script:key.SecurityReads|Should -Be 1
      $script:key.Disposed|Should -BeTrue
      Should -Invoke Get-Acl -Times 0 -Exactly
    }
  }
}
