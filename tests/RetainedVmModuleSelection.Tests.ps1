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
BeforeAll { . (Join-Path $PSScriptRoot 'fixtures/Invoke-RideTestInCleanSession.ps1') }
Describe 'Image module lifetime across CLI engine imports' {
  It 'keeps the retained wallpaper caller bound when the CLI reloads the engine' {
    $modulePath=Invoke-RideTestInCleanSession -Arguments $PSScriptRoot -Probe {
      param($testRoot)
      $engine=Join-Path $testRoot '../modules/RIDE.Engine.psm1'
      Import-Module $engine -Force
      $caller=Import-Module (Join-Path $testRoot 'integration/RIDE.WallpaperTestUser.psm1') -PassThru
      Import-Module $engine -Force
      & $caller { (Get-Module RIDE.DefaultWallpaper).Path }
    }
    $modulePath|Should -Be ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../modules/RIDE.DefaultWallpaper.psm1')))
  }
}
Describe 'Retained host binds the exact imported automation module' -ForEach @(
  @{Family='Font'},@{Family='Sysmon'},@{Family='DefaultLock'},@{Family='DefaultWallpaper'},@{Family='Wireless'}
) {
  It '<Family> uses the checkout module despite the same-name installed copy' {
    $decoyPath=Join-Path $TestDrive 'RIDE.TestAutomation.psm1'
    Set-Content -LiteralPath $decoyPath -Value "function Get-LabVM {throw 'Wrong automation module selected.'}"
    $result=Invoke-RideTestInCleanSession -Arguments $PSScriptRoot,$Family,$decoyPath -Probe {
      param($testRoot,$family,$decoyPath)
      $vmModule=Import-Module (Join-Path $testRoot "integration/RIDE.${family}Vm.psm1") -PassThru
      $automation=& $vmModule { $script:AutomationModule }
      & $automation {
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
      Import-Module $decoyPath
      $credential=& $vmModule {
        param($family)
        & "Get-Ride${family}VmCredential" ([pscustomobject]@{VMName='Synthetic-guest'})
      } $family
      [pscustomobject]@{Path=$automation.Path;Count=@(Get-Module RIDE.TestAutomation -All).Count;User=$credential.UserName}
    }
    $result.Path|Should -Be (Join-Path $PSScriptRoot 'integration\RIDE.TestAutomation.psm1')
    $result.Count|Should -BeGreaterThan 1
    $result.User|Should -BeExactly 'Synthetic-user'
  }
}
