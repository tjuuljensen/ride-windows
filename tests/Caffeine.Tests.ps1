<#
.SYNOPSIS
  Test the caffeine script's scheduling and safe discovery paths without desktop input.

.DESCRIPTION
  Uses a fake clock and key sender to check independent reporting, duration deadlines, indefinite
  execution and failures. COM initialization is mocked for script checks; no real keys are sent
  and no console properties or Windows settings are changed.

.EXAMPLE
  Invoke-Pester .\tests\Caffeine.Tests.ps1

.INPUTS
  None. Pester invokes the test cases.

.OUTPUTS
  Pester test results.

.NOTES
  Compatibility: Pester 5.x on Windows PowerShell 5.1 or PowerShell 7 on Windows.
  Prerequisites: Repository caffeine script; no COM object or interactive desktop is needed.
  Recovery: Mock teardown only; no Windows state is changed.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
#>

BeforeAll {
  $script:CaffeinePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'components/scripts/caffeine.ps1'
  $tokens = $null
  $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($script:CaffeinePath, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors.Count) { throw 'Caffeine did not parse.' }
  $loop = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-CaffeineInputLoop'
  }, $true)
  Invoke-Expression $loop.Extent.Text
}

Describe 'Caffeine input scheduling' {
  BeforeEach {
    $script:TestClock = [pscustomobject]@{ Elapsed = [TimeSpan]::Zero }
    $script:InputEvents = [System.Collections.Generic.List[object]]::new()
    $script:Reports = [System.Collections.Generic.List[object]]::new()
    $script:Waits = [System.Collections.Generic.List[int]]::new()
    $clockObject = $script:TestClock
    $eventList = $script:InputEvents
    $script:TestSender = [pscustomobject]@{}
    $script:TestSender | Add-Member -MemberType ScriptMethod -Name SendKeys -Value {
      param($Keys)
      $eventList.Add([pscustomobject]@{ Seconds = $clockObject.Elapsed.TotalSeconds; Keys = $Keys })
    }.GetNewClosure()
    Mock Start-Sleep {
      $script:Waits.Add($Milliseconds)
      $script:TestClock.Elapsed = $script:TestClock.Elapsed.Add([TimeSpan]::FromMilliseconds($Milliseconds))
    }
    Mock Write-Host {
      $script:Reports.Add([pscustomobject]@{ Seconds = $script:TestClock.Elapsed.TotalSeconds; Text = "$Object" })
    }
  }

  It 'sends immediately and stops before sending a pair on the deadline' {
    Invoke-CaffeineInputLoop -KeySender $script:TestSender -Clock $script:TestClock -IntervalSeconds 30 -StopAfterSeconds 60 -ReportIntervalSeconds 0
    $script:InputEvents.Count | Should -Be 2
    $script:InputEvents[0].Seconds | Should -Be 0
    $script:InputEvents[1].Seconds | Should -Be 30
    $script:InputEvents[0].Keys | Should -Be '{SCROLLLOCK}{SCROLLLOCK}'
    $script:TestClock.Elapsed.TotalSeconds | Should -Be 60
    $script:Reports.Count | Should -Be 0
  }

  It 'honors a duration shorter than the input interval' {
    Invoke-CaffeineInputLoop -KeySender $script:TestSender -Clock $script:TestClock -IntervalSeconds 120 -StopAfterSeconds 7 -ReportIntervalSeconds 3600
    $script:InputEvents.Count | Should -Be 1
    $script:Waits[0] | Should -Be 7000
    $script:TestClock.Elapsed.TotalSeconds | Should -Be 7
  }

  It 'reports independently of the input interval' {
    Invoke-CaffeineInputLoop -KeySender $script:TestSender -Clock $script:TestClock -IntervalSeconds 120 -StopAfterSeconds 65 -ReportIntervalSeconds 20
    $script:InputEvents.Count | Should -Be 1
    $script:Reports.Count | Should -Be 3
    $script:Reports[0].Seconds | Should -Be 20
    $script:Reports[1].Seconds | Should -Be 40
    $script:Reports[2].Seconds | Should -Be 60
  }

  It 'does not burst input or reports after a delayed wake-up' {
    Mock Start-Sleep {
      $script:TestClock.Elapsed = $script:TestClock.Elapsed.Add([TimeSpan]::FromSeconds(40))
    }
    Invoke-CaffeineInputLoop -KeySender $script:TestSender -Clock $script:TestClock -IntervalSeconds 10 -StopAfterSeconds 100 -ReportIntervalSeconds 10
    $script:InputEvents.Count | Should -Be 3
    $script:InputEvents[1].Seconds | Should -Be 40
    $script:InputEvents[2].Seconds | Should -Be 80
    $script:Reports.Count | Should -Be 2
  }

  It 'keeps running with no duration limit until interrupted' {
    Mock Start-Sleep {
      if ($script:InputEvents.Count -ge 4) { throw 'Simulated cancellation' }
      $script:TestClock.Elapsed = $script:TestClock.Elapsed.Add([TimeSpan]::FromMilliseconds($Milliseconds))
    }
    { Invoke-CaffeineInputLoop -KeySender $script:TestSender -Clock $script:TestClock -IntervalSeconds 120 -StopAfterSeconds 0 -ReportIntervalSeconds 0 } | Should -Throw '*Simulated cancellation*'
    $script:InputEvents.Count | Should -Be 4
    $script:InputEvents[3].Seconds | Should -Be 360
  }

  It 'stops on a sender failure rather than continuing to report success' {
    $script:TestSender | Add-Member -MemberType ScriptMethod -Name SendKeys -Force -Value { throw 'Input failure' }
    { Invoke-CaffeineInputLoop -KeySender $script:TestSender -Clock $script:TestClock -IntervalSeconds 30 -StopAfterSeconds 60 -ReportIntervalSeconds 10 } | Should -Throw '*Input failure*'
    $script:Waits.Count | Should -Be 0
    $script:Reports.Count | Should -Be 0
  }

  It 'bounds long waits to the supported millisecond range' {
    Mock Start-Sleep { throw "Wait: $Milliseconds" }
    { Invoke-CaffeineInputLoop -KeySender $script:TestSender -Clock $script:TestClock -IntervalSeconds 2147483647 -StopAfterSeconds 0 -ReportIntervalSeconds 0 } | Should -Throw '*Wait: 2147483647*'
  }
}

Describe 'Caffeine discovery and initialization' {
  BeforeEach {
    # Fail closed if any safe-discovery invocation accidentally reaches COM initialization.
    Mock New-Object { throw 'Simulated COM initialization failure' } -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Mock Write-Host {}
    Mock Clear-Host { throw 'Unexpected screen clearing' }
    Mock Start-Sleep { throw 'Unexpected sleep' }
  }

  It 'returns version without initializing COM' {
    & $script:CaffeinePath -Version | Should -Be '0.2.2'
    Should -Invoke New-Object -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
  }

  It 'documents all new parameters without initializing COM' {
    $helpText = (& $script:CaffeinePath -Help | Out-String)
    foreach ($parameter in @('IntervalSeconds', 'StopAfterSeconds', 'ReportIntervalSeconds', 'NoConsoleCustomization')) {
      $helpText | Should -Match $parameter
    }
    Should -Invoke New-Object -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
  }

  It 'previews without initializing COM or entering the loop' {
    & $script:CaffeinePath -WhatIf
    Should -Invoke New-Object -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Should -Invoke Start-Sleep -Times 0 -Exactly
    Should -Invoke Clear-Host -Times 0 -Exactly
  }

  It 'fails initialization once before changing the console or announcing a running loop' {
    { & $script:CaffeinePath } | Should -Throw '*Simulated COM initialization failure*'
    Should -Invoke New-Object -Times 1 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Should -Invoke Write-Host -Times 0 -Exactly
    Should -Invoke Start-Sleep -Times 0 -Exactly
    Should -Invoke Clear-Host -Times 0 -Exactly
  }

  It 'rejects invalid timing values before initialization' {
    { & $script:CaffeinePath -IntervalSeconds 0 } | Should -Throw
    { & $script:CaffeinePath -StopAfterSeconds -1 } | Should -Throw
    { & $script:CaffeinePath -ReportIntervalSeconds -1 } | Should -Throw
    Should -Invoke New-Object -Times 0 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
  }

  It 'initializes one sender and reaches stop reporting when input fails' {
    $fakeSender = [pscustomobject]@{}
    $fakeSender | Add-Member -MemberType ScriptMethod -Name SendKeys -Value { throw 'Simulated input failure' }
    Mock New-Object { $fakeSender }.GetNewClosure() -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    { & $script:CaffeinePath -NoConsoleCustomization } | Should -Throw '*Simulated input failure*'
    Should -Invoke Clear-Host -Times 0 -Exactly
    Should -Invoke New-Object -Times 1 -Exactly -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -like 'Caffeine stopped.*' }
    Should -Invoke Start-Sleep -Times 0 -Exactly
  }

  It 'reaches stop reporting when the wait is interrupted' {
    $fakeSender = [pscustomobject]@{}
    $fakeSender | Add-Member -MemberType ScriptMethod -Name SendKeys -Value { param($Keys) }
    Mock New-Object { $fakeSender }.GetNewClosure() -ParameterFilter { $ComObject -eq 'WScript.Shell' }
    Mock Start-Sleep { throw 'Simulated cancellation' }
    { & $script:CaffeinePath -NoConsoleCustomization } | Should -Throw '*Simulated cancellation*'
    Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -like 'Caffeine stopped.*' }
  }
}
