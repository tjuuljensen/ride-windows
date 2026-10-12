<#
.SYNOPSIS
  Check the parameterless caffeine fallback without sending desktop input.

.DESCRIPTION
  Mocks COM creation, key delivery and sleeping to verify immediate input, indefinite execution,
  error handling and stop reporting. Reads native help without executing the script.

.EXAMPLE
  Invoke-Pester .\tests\CaffeineLight.Tests.ps1

.INPUTS
  None. Pester invokes the tests.

.OUTPUTS
  Pester test results.

.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Repository caffeine-light script.
  Recovery: Mock teardown; no COM object, real sleep or desktop input is used.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
#>

BeforeAll {
  $script:LightPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'components/scripts/caffeine-light.ps1'
}

Describe 'Caffeine Light fallback' {
  BeforeEach {
    $script:Keys = [System.Collections.Generic.List[string]]::new()
    $keys = $script:Keys
    $script:FakeSender = [pscustomobject]@{}
    $script:FakeSender | Add-Member -MemberType ScriptMethod -Name SendKeys -Value {
      param($InputKeys)
      $keys.Add($InputKeys)
    }.GetNewClosure()
    $sender = $script:FakeSender
    Mock New-Object { $sender }.GetNewClosure() -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Mock Write-Host {}
    Mock Start-Sleep { throw 'Simulated cancellation' }
  }

  It 'has no parameter block and exposes its limits through native help' {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($script:LightPath, [ref]$tokens, [ref]$errors)
    $errors.Count | Should -Be 0
    $ast.ParamBlock | Should -BeNullOrEmpty
    $helpText = Get-Help $script:LightPath -Full | Out-String
    $helpText | Should -Match '60 seconds'
    $helpText | Should -Match 'Version: 0.1.0'
    Should -Invoke New-Object -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
  }

  It 'rejects arguments before any operational work' {
    { & $script:LightPath -StopAfterSeconds 1 } | Should -Throw '*takes no arguments*'
    Should -Invoke New-Object -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Should -Invoke Write-Host -Times 0 -Exactly
    Should -Invoke Start-Sleep -Times 0 -Exactly
  }

  It 'sends immediately and reaches stop reporting after cancellation' {
    { & $script:LightPath } | Should -Throw '*Simulated cancellation*'
    $script:Keys.Count | Should -Be 1
    $script:Keys[0] | Should -Be '{SCROLLLOCK}{SCROLLLOCK}'
    Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 60 }
    Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -eq 'Caffeine Light stopped.' }
  }

  It 'continues indefinitely using one sender until the wait is interrupted' {
    $waitState = [pscustomobject]@{ Count = 0 }
    Mock Start-Sleep {
      $waitState.Count++
      if ($waitState.Count -ge 4) { throw 'Simulated cancellation' }
    }.GetNewClosure()
    { & $script:LightPath } | Should -Throw '*Simulated cancellation*'
    $script:Keys.Count | Should -Be 4
    Should -Invoke New-Object -Times 1 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Should -Invoke Start-Sleep -Times 4 -Exactly -ParameterFilter { $Seconds -eq 60 }
    Should -Invoke Write-Host -Times 2 -Exactly
  }

  It 'fails initialization before announcing a running loop' {
    Mock New-Object { throw 'COM unavailable' } -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    { & $script:LightPath } | Should -Throw '*COM unavailable*'
    Should -Invoke Write-Host -Times 0 -Exactly
    Should -Invoke Start-Sleep -Times 0 -Exactly
  }

  It 'stops on input failure and still reaches the finally block' {
    $script:FakeSender | Add-Member -MemberType ScriptMethod -Name SendKeys -Force -Value { throw 'Input failed' }
    { & $script:LightPath } | Should -Throw '*Input failed*'
    Should -Invoke Start-Sleep -Times 0 -Exactly
    Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -eq 'Caffeine Light stopped.' }
  }
}
