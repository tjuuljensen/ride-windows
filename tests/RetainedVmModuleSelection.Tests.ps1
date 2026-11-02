<#
.SYNOPSIS
  Verify credential dispatch when installed and checkout modules share a name.
.DESCRIPTION
  Loads a second synthetic automation module and supplies a synthetic lab accessor.
  No lab import, VM access or real credential lookup occurs.
.EXAMPLE
  Invoke-Pester ./tests/RetainedVmModuleSelection.Tests.ps1
.NOTES
  Windows PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {
  $families=@('Font','Sysmon','DefaultLock','DefaultWallpaper','Wireless')
  foreach($family in $families){Import-Module (Join-Path $PSScriptRoot "integration/RIDE.${family}Vm.psm1") -Force}
}
Describe 'Retained host binds the exact imported automation module' -ForEach @(
  @{Family='Font'},@{Family='Sysmon'},@{Family='DefaultLock'},@{Family='DefaultWallpaper'},@{Family='Wireless'}
) {
  BeforeAll {
    $script:expectedPath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'integration/RIDE.TestAutomation.psm1'))
    $script:original=@(Get-Module RIDE.TestAutomation -All|Where-Object Path -EQ $script:expectedPath)[0]
    & $script:original {
      function script:Get-Lab { 'Synthetic-lab' }
      function script:Get-LabVM {
        param($ComputerName)
        if($ComputerName -cne 'Synthetic-guest'){throw 'Unexpected synthetic guest selection.'}
        $machine=[pscustomobject]@{}
        $machine|Add-Member ScriptMethod GetCredential {
          param($Lab)
          if($Lab -cne 'Synthetic-lab'){throw 'Unexpected synthetic lab selection.'}
          [pscredential]::new('Synthetic-user',(ConvertTo-SecureString 'Public-test-fixture-only' -AsPlainText -Force))
        }
        $machine
      }
    }
    $decoyPath=Join-Path $TestDrive 'RIDE.TestAutomation.psm1'
    Set-Content -LiteralPath $decoyPath -Value "function Get-LabVM {throw 'Wrong automation module selected.'}"
    $script:decoy=Import-Module $decoyPath -PassThru -Force
  }
  AfterAll {
    Remove-Module $script:decoy
    & $script:original {Remove-Item Function:Get-Lab,Function:Get-LabVM}
  }
  It '<Family> uses the checkout module despite the same-name installed copy' {
    @(Get-Module RIDE.TestAutomation -All).Count|Should -BeGreaterThan 1
    InModuleScope "RIDE.${Family}Vm" -Parameters @{Family=$Family;Expected=$script:expectedPath} {
      param($Family,$Expected)
      @($script:AutomationModule).Count|Should -Be 1
      $script:AutomationModule.Path|Should -Be $Expected
      $credential=& "Get-Ride${Family}VmCredential" ([pscustomobject]@{VMName='Synthetic-guest'})
      $credential.UserName|Should -BeExactly 'Synthetic-user'
    }
  }
}
