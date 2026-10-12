<#
.SYNOPSIS
  Test disposable-VM task orchestration with mocked host and process calls.

.DESCRIPTION
  Tests configuration/watch filtering, snapshot isolation, task principal/actions, request
  correlation, timeout/error/evidence handling, worker serialization, and checkpoint identity. Uses
  mocks and TestDrive rather than provisioning or controlling a real VM. Checks the guest
  entry point's version, workstation guard and read-only preview.
  Verifies partial-evidence copying with locked files and correlated path bounds.

.EXAMPLE
  Invoke-Pester .\tests\TestAutomation.Tests.ps1

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  Pester test results through Invoke-Pester; no standalone CLI output contract.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Pester 5.x on Windows; integration helper module and test fixtures.
  File/environment inputs: TestDrive files, fake process objects, and mocked
  Hyper-V/AutomatedLab/scheduled-task commands.
  Recovery: Pester fixture cleanup and mock teardown; no runtime controller registration occurs.
  Author: RIDE-Windows maintainers.
  Version: Repository test fixture; no independent released version.
  Changelog:
    2026-10-12: Verify controller JSON write failures prevent caller continuation.
    2026-10-11: Cover retained partial evidence and rejection of escaped guest paths.
    2026-10-08: Document test purpose, isolation, and invocation without changing assertions.

  Versioning exception: Pester fixtures are invoked by Pester, not as standalone CLI tools. This
  review does not invent a separate script release or CLI.

#>


BeforeDiscovery {
  Import-Module (Join-Path $PSScriptRoot 'integration\RIDE.TestAutomation.psm1') -Force
}

Describe 'Controller JSON write failures' {
  It 'stops the caller when the destination parent is missing' {
    $path = Join-Path $TestDrive 'missing-parent/result.json'
    $continued = $false
    $writeError = $null
    try {
      Write-RideAutomationJson -Path $path -Value @{ RunId = 'probe' }
      $continued = $true
    }
    catch { $writeError = $_ }
    $continued | Should -BeFalse
    $writeError | Should -Not -BeNullOrEmpty
    Test-Path -LiteralPath $path | Should -BeFalse
  }
}

Describe 'Partial guest evidence with unavailable files' {
  BeforeAll {
    $tokens=$null;$errors=$null
    $collectorAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'integration/Export-RideVmTestEvidence.ps1'),[ref]$tokens,[ref]$errors)
    $copyFunction=$collectorAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Copy-RidePartialGuestEvidence'},$true)
    Invoke-Expression $copyFunction.Extent.Text
    function Invoke-Command {param($Session,$ArgumentList,$ScriptBlock,$ErrorAction)}
    function Copy-Item {param($LiteralPath,$Destination,$FromSession,[switch]$Force,$ErrorAction)}
  }
  It 'retains readable evidence after a locked transcript and reports the omission' {
    Mock Invoke-Command {@('C:\RIDE\TestResults\run\transcript.log','C:\RIDE\TestResults\run\state\saved.json')}
    Mock Copy-Item {
      if($LiteralPath -like '*transcript.log'){throw 'File is locked by another process.'}
      [IO.File]::WriteAllText($Destination,'saved recovery evidence')
    }
    Copy-RidePartialGuestEvidence -Session 'mock' -GuestPath 'C:\RIDE\TestResults\run' -Destination $TestDrive -WarningAction SilentlyContinue
    Get-Content -LiteralPath (Join-Path $TestDrive 'state/saved.json') -Raw | Should -Be 'saved recovery evidence'
    $omissions=@(Get-Content -LiteralPath (Join-Path $TestDrive 'collection-omissions.json') -Raw | ConvertFrom-Json)
    $omissions.Count | Should -Be 1
    $omissions[0].Path | Should -Be 'transcript.log'
    $omissions[0].Error | Should -Match 'locked'
  }
  It 'refuses evidence outside the correlated directory before copying' {
    Mock Invoke-Command {@('C:\RIDE\TestResults\another-run\secret.json')}
    Mock Copy-Item {}
    {Copy-RidePartialGuestEvidence -Session 'mock' -GuestPath 'C:\RIDE\TestResults\run' -Destination $TestDrive} | Should -Throw '*escaped*'
    Should -Invoke Copy-Item -Times 0 -Exactly
  }
}

Describe 'Task configuration and read-only watch selection' {
  It 'completes the declared task source and setup action values' {
    $client = Get-Command (Join-Path $PSScriptRoot 'integration\Invoke-RideVmTestTask.ps1')
    $setup = Get-Command (Join-Path $PSScriptRoot 'integration\Register-RideVmTestTask.ps1')
    ($client.Parameters.Source.Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] }).ValidValues | Should -Be @('Local', 'CI')
    ($client.Parameters.IntegrationSuite.Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] }).ValidValues | Should -Be @('Full', 'SettingsBatch40', 'SettingsBatch60', 'SettingsBatch60Recovery', 'SettingsRemainingBatch1', 'SettingsRemainingBatch2', 'ApplicationsBatch1', 'ApplicationsBatch2')
    ($setup.Parameters.Action.Attributes | Where-Object { $_ -is [Management.Automation.ValidateSetAttribute] }).ValidValues | Should -Be @('Register', 'Remove')
  }

  It 'rejects implicit non-disposable configurations' {
    $path = Join-Path $TestDrive 'configuration.json'
    @{ SchemaVersion = 1; Name = 'RIDETest'; LabName = 'RIDETest'; VMName = 'RIDE-Test'; VMId = [guid]::NewGuid().ToString(); CheckpointName = 'clean'; GuestRepositoryPath = 'C:\RIDE\ride-windows'; LocalRepositoryPath = 'C:\local\ride-windows'; CIRepositoryPath = 'C:\ci\ride-windows'; IsDisposable = $false } | ConvertTo-Json | Set-Content $path
    # Capture expected errors directly to avoid nested exception assertions in guest remoting.
    $configurationError = $null
    try { $null = Read-RideAutomationConfiguration $path }
    catch { $configurationError = $_ }
    $configurationError | Should -Not -BeNullOrEmpty
    $configurationError.Exception.Message | Should -Match 'IsDisposable'
  }

  It 'watches maintained files and their parent directories' -TestCases @(
    @{ Path = 'modules' }, @{ Path = 'catalog/operations.psd1' }, @{ Path = 'tests/TestAutomation.Tests.ps1' }, @{ Path = 'components/fonts/font.otf' }, @{ Path = 'ride.ps1' }, @{ Path = 'docs/bootstrap.ps1' }
  ) {
    param($Path)
    Test-RideAutomationWatchPath $Path | Should -BeTrue
  }

  It 'ignores generated outputs and metadata' -TestCases @(
    @{ Path = '.git/index' }, @{ Path = 'docs/OPERATIONS.md' }, @{ Path = 'testResults.xml' }, @{ Path = 'tests/results/result.json' }, @{ Path = 'modules/.codex/log.txt' }
  ) {
    param($Path)
    Test-RideAutomationWatchPath $Path | Should -BeFalse
  }

  It 'snapshots uncommitted files' {
    $source = Join-Path $TestDrive 'checkout'
    $null = New-Item -ItemType Directory (Join-Path $source 'tools') -Force
    'example' | Set-Content (Join-Path $source 'tools/validate.ps1')
    'uncommitted' | Set-Content (Join-Path $source 'new.ps1')
    $manifest = @(Copy-RideAutomationSnapshot $source (Join-Path $TestDrive 'staged'))
    $manifest.Path | Should -Contain 'new.ps1'
    (Get-Content (Join-Path $TestDrive 'staged/new.ps1')) | Should -Be 'uncommitted'
  }

  It 'reports the guest entry point version before checking the VM marker' {
    & (Join-Path $PSScriptRoot 'integration/Invoke-RideGuestTests.ps1') -Version | Should -Be '0.6.0'
  }

  It 'dispatches <Suite> to its requested scenario without real integration calls' -ForEach @(
    @{ Suite='Full'; Expected='Full' },
    @{ Suite='SettingsBatch40'; Expected='Batch40' },
    @{ Suite='SettingsBatch60'; Expected='Batch60/' },
    @{ Suite='SettingsBatch60Recovery'; Expected='Batch60/Recovery12' },
    @{ Suite='SettingsRemainingBatch1'; Expected='Remaining/1' },
    @{ Suite='SettingsRemainingBatch2'; Expected='Remaining/2' },
    @{ Suite='ApplicationsBatch1'; Expected='Applications/1' },
    @{ Suite='ApplicationsBatch2'; Expected='Applications/2' }
  ) {
    $tokens=$null; $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'integration/Invoke-RideGuestTests.ps1'),[ref]$tokens,[ref]$errors)
    $dispatch=@($ast.FindAll({param($node)
      $node -is [Management.Automation.Language.IfStatementAst] -and
      $node.Clauses[0].Item1.Extent.Text -eq '$IntegrationSuite -eq ''SettingsBatch40'''
    },$true))
    $dispatch.Count | Should -Be 1
    $scripts=Join-Path $TestDrive 'tests/integration'
    $null=New-Item -ItemType Directory -Path $scripts -Force
    '"Full"' | Set-Content (Join-Path $scripts 'Invoke-RideVmSuite.ps1')
    '"Batch40"' | Set-Content (Join-Path $scripts 'Invoke-RideSettingsBatch.ps1')
    'param($Selection); "Batch60/$Selection"' | Set-Content (Join-Path $scripts 'Invoke-RideSettingsBatch60.ps1')
    'param($Batch); "Remaining/$Batch"' | Set-Content (Join-Path $scripts 'Invoke-RideRemainingSettings.ps1')
    'param($Batch); "Applications/$Batch"' | Set-Content (Join-Path $scripts 'Invoke-RideApplicationBatch.ps1')
    $IntegrationSuite=$Suite
    Push-Location $TestDrive
    try { & ([scriptblock]::Create($dispatch[0].Extent.Text)) | Should -Be $Expected }
    finally { Pop-Location }
  }

  It 'refuses the guest entry point outside the VM runner' {
    $previousMarker = $env:RIDE_TEST_GUEST
    try {
      $env:RIDE_TEST_GUEST = $null
      { & (Join-Path $PSScriptRoot 'integration/Invoke-RideGuestTests.ps1') -GuestPath $TestDrive } | Should -Throw '*must not run on a developer workstation*'
    }
    finally { $env:RIDE_TEST_GUEST = $previousMarker }
  }

  It 'previews <Suite> guest tests without starting tests or creating evidence' -ForEach @(@{ Suite = 'Full' }, @{ Suite = 'SettingsBatch40' }, @{ Suite = 'SettingsBatch60' }, @{ Suite = 'SettingsBatch60Recovery' }, @{ Suite = 'SettingsRemainingBatch1' }, @{ Suite = 'SettingsRemainingBatch2' }, @{ Suite = 'ApplicationsBatch1' }, @{ Suite = 'ApplicationsBatch2' }) {
    $source = Join-Path $TestDrive 'guest-preview-checkout'
    $null = New-Item -ItemType Directory -Path (Join-Path $source 'tools') -Force
    'throw "Preview must not run validation"' | Set-Content -LiteralPath (Join-Path $source 'tools/validate.ps1')
    $results = Join-Path $TestDrive 'guest-preview-results'
    $previousMarker = $env:RIDE_TEST_GUEST
    try {
      $env:RIDE_TEST_GUEST = '1'
      & (Join-Path $PSScriptRoot 'integration/Invoke-RideGuestTests.ps1') -GuestPath $source -ResultsPath $results -ResultRunId ('b' * 32) -Integration -IntegrationSuite $Suite -WhatIf
      Test-Path -LiteralPath $results | Should -BeFalse
    }
    finally { $env:RIDE_TEST_GUEST = $previousMarker }
  }

  It 'previews the existing runner without staging or invoking guest operations' {
    $source = Join-Path $TestDrive 'preview-checkout'
    foreach ($file in @('tools/validate.ps1', 'tools/Export-RideCatalog.ps1', 'tests/Catalog.Tests.ps1')) {
      $path = Join-Path $source $file
      $null = New-Item -ItemType Directory (Split-Path -Parent $path) -Force
      '' | Set-Content -LiteralPath $path
    }
    $results = Join-Path $TestDrive 'preview-results'
    & (Join-Path $PSScriptRoot 'integration/Invoke-RideVmTest.ps1') -Transport AutomatedLab -LabName RIDEPilot -VMName RIDE-Pilot -RepositoryPath $source -ResultDirectory $results -WhatIf
    Test-Path -LiteralPath $results | Should -BeFalse
  }

  It 'rejects an integration-suite selection when integration is disabled' {
    $previousMarker = $env:RIDE_TEST_GUEST
    try {
      $env:RIDE_TEST_GUEST = '1'
      { & (Join-Path $PSScriptRoot 'integration/Invoke-RideGuestTests.ps1') -GuestPath $TestDrive -IntegrationSuite SettingsBatch40 } | Should -Throw '*Specify -Integration*'
      { & (Join-Path $PSScriptRoot 'integration/Invoke-RideVmTest.ps1') -Transport AutomatedLab -LabName RIDEPilot -UnitOnly -IntegrationSuite SettingsBatch40 } | Should -Throw '*cannot be selected with UnitOnly*'
      { & (Join-Path $PSScriptRoot 'integration/Invoke-RideVmTestTask.ps1') -UnitOnly -IntegrationSuite SettingsBatch60Recovery } | Should -Throw '*cannot be selected with UnitOnly*'
    }
    finally { $env:RIDE_TEST_GUEST = $previousMarker }
  }

  It 'refuses the forty-setting integration script on a workstation' {
    & (Join-Path $PSScriptRoot 'integration/Invoke-RideSettingsBatch.ps1') -Version | Should -Be '0.1.0'
    $previousMarker = $env:RIDE_INTEGRATION_VM
    try {
      $env:RIDE_INTEGRATION_VM = $null
      { & (Join-Path $PSScriptRoot 'integration/Invoke-RideSettingsBatch.ps1') } | Should -Throw '*only inside a disposable VM*'
    }
    finally { $env:RIDE_INTEGRATION_VM = $previousMarker }
  }

  InModuleScope RIDE.TestAutomation {
    BeforeAll {
      function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory) }
      function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) }
      function New-ScheduledTaskSettingsSet { param($MultipleInstances, $ExecutionTimeLimit, [switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries) }
    }
    It 'uses a fixed hidden action and an interactive highest-privilege principal' {
      Mock New-ScheduledTaskAction { @{ Executable = $Execute; Arguments = $Argument } }
      Mock New-ScheduledTaskPrincipal { @{ UserId = $UserId; LogonType = $LogonType; RunLevel = $RunLevel } }
      Mock New-ScheduledTaskSettingsSet { @{ MultipleInstances = $MultipleInstances } }
      $parameters = Get-RideAutomationTaskParameters ([pscustomobject]@{ Name = 'RIDETest'; HostAccountSid = 'S-1-5-21-1' }) 'C:\configuration.json'
      $parameters.Principal.LogonType | Should -Be 'Interactive'
      $parameters.Principal.RunLevel | Should -Be 'Highest'
      $parameters.Action.Arguments | Should -Match '-NonInteractive -WindowStyle Hidden -File'
      $parameters.Settings.MultipleInstances | Should -Be 'IgnoreNew'
    }
  }
}

Describe 'Correlated execution, failures and VM recovery' {
  InModuleScope RIDE.TestAutomation {
    BeforeAll {
      function Start-VM { [CmdletBinding()] param($VM) }
      function Get-VM { param($Id) }
      function Stop-VM { param($VM, [switch]$TurnOff, [switch]$Force, [switch]$Confirm) }
      function Restore-VMSnapshot { param($VMSnapshot, [switch]$Confirm) }
    }
    BeforeEach {
      $script:testRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      $null = New-Item -ItemType Directory (Join-Path $script:testRoot 'runtime') -Force
      $script:config = [pscustomobject]@{ Name = 'RIDETest'; VMId = [guid]::NewGuid().ToString(); LocalRepositoryPath = 'C:\local\ride-windows'; CIRepositoryPath = 'C:\ci\ride-windows'; LabName = 'RIDETest'; VMName = 'RIDE-Test'; GuestRepositoryPath = 'C:\RIDE\ride-windows' }
      $script:request = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString('N'); Source = 'Local'; UnitOnly = $false; TimeoutMinutes = 90; SubmittedAtUtc = [datetime]::UtcNow.ToString('o') }
      $script:uac = [pscustomobject]@{ EnableLUA = 1; ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 1 }
      Mock Assert-RideAutomationHost { $script:uac }
      Mock Get-RideAutomationUac { $script:uac }
      Mock Import-RideAutomationLab { [pscustomobject]@{ VM = [pscustomobject]@{ State = 'Running' }; Snapshot = 'clean' } }
      Mock Reset-RideAutomationVm { }
      Mock Save-RideAutomationFailureEvidence { }
      Mock Stop-RideAutomationProcess { }
      Mock Get-VM { [pscustomobject]@{ Id = [guid]$script:config.VMId; Name = $script:config.VMName } }
      Mock Start-VM { }
      Mock Copy-RideAutomationSnapshot { @(@{ Path = 'ride.ps1'; SHA256 = 'abc' }) }
      Mock Start-Process {
        $guest = Join-Path $script:testRoot "results\$($script:request.RunId)\guest"
        $null = New-Item -ItemType Directory $guest -Force
        $suite = if ($script:request.PSObject.Properties.Name -contains 'IntegrationSuite') { $script:request.IntegrationSuite } else { 'Full' }
        @{ RunId = $script:request.RunId; Status = 'Passed'; ValidationPassed = $true; IntegrationPassed = $true; IntegrationSuite = $suite; Pester = @{ Total = 3; Failed = 0 } } | ConvertTo-Json | Set-Content (Join-Path $guest 'summary.json')
        '<test-results />' | Set-Content (Join-Path $guest 'pester.xml')
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = 0; Id = 123 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
    }

    It 'restores before and after a successful run and returns only its correlated result' {
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Passed'
      $result.RunId | Should -Be $script:request.RunId
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
      $result.IntegrationSuite | Should -Be 'Full'
      Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $ArgumentList -match ' -IntegrationSuite Full$' }
    }

    It 'forwards <Suite> and correlates its acceptance evidence' -ForEach @(@{ Suite = 'SettingsBatch60Recovery' }, @{ Suite = 'SettingsRemainingBatch1' }, @{ Suite = 'SettingsRemainingBatch2' }, @{ Suite = 'ApplicationsBatch1' }, @{ Suite = 'ApplicationsBatch2' }) {
      $script:request | Add-Member NoteProperty IntegrationSuite $Suite
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Passed'
      $result.IntegrationSuite | Should -Be $Suite
      Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter { $ArgumentList.EndsWith(" -IntegrationSuite $Suite") }
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
    }

    It 'rejects arbitrary suite strings before launching a controller' {
      $script:request | Add-Member NoteProperty IntegrationSuite 'Full -Command arbitrary'
      { Invoke-RideAutomationRequest $script:config $script:request $script:testRoot } | Should -Throw '*Invalid request IntegrationSuite*'
      Should -Invoke Start-Process -Times 0 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }

    It 'rejects focused integration when the request is unit-only' {
      $script:request | Add-Member NoteProperty IntegrationSuite 'SettingsBatch60Recovery'
      $script:request.UnitOnly = $true
      { Invoke-RideAutomationRequest $script:config $script:request $script:testRoot } | Should -Throw '*cannot be selected with UnitOnly*'
      Should -Invoke Start-Process -Times 0 -Exactly
    }

    It 'does not accept a different guest suite as focused acceptance' {
      $script:request | Add-Member NoteProperty IntegrationSuite 'SettingsBatch60Recovery'
      Mock Start-Process {
        $guest = Join-Path $script:testRoot "results\$($script:request.RunId)\guest"
        $null = New-Item -ItemType Directory $guest -Force
        @{ RunId = $script:request.RunId; Status = 'Passed'; ValidationPassed = $true; IntegrationPassed = $true; IntegrationSuite = 'Full'; Pester = @{ Total = 3; Failed = 0 } } | ConvertTo-Json | Set-Content (Join-Path $guest 'summary.json')
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = 0; Id = 123 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Failed'
      $result.Error | Should -Match 'suite does not match'
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
    }

    It 'starts the VM resolved by its pinned ID using the supported VM parameter' {
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Passed'
      Should -Invoke Get-VM -Times 1 -Exactly -ParameterFilter { $Id -eq [guid]$script:config.VMId }
      Should -Invoke Start-VM -Times 1 -Exactly -ParameterFilter { $VM.Id -eq [guid]$script:config.VMId -and $VM.Name -eq $script:config.VMName }
    }

    It 'retains the controller handle before waiting so the successful exit code remains available' {
      $script:request.UnitOnly = $true
      Mock Start-Process {
        $guest = Join-Path $script:testRoot "results\$($script:request.RunId)\guest"
        $null = New-Item -ItemType Directory $guest -Force
        @{ RunId = $script:request.RunId; Status = 'Passed'; ValidationPassed = $true; IntegrationPassed = $false; Pester = @{ Total = 3; Failed = 0 } } | ConvertTo-Json | Set-Content (Join-Path $guest 'summary.json')
        '<test-results />' | Set-Content (Join-Path $guest 'pester.xml')
        $process = [pscustomobject]@{ ExitCode = $null; HandleRetained = $false }
        $process | Add-Member ScriptProperty Handle { $this.HandleRetained = $true; [intptr]1 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) if ($this.HandleRetained) { $this.ExitCode = 0 }; $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
      (Invoke-RideAutomationRequest $script:config $script:request $script:testRoot).Status | Should -Be 'Passed'
      Should -Invoke Save-RideAutomationFailureEvidence -Times 0 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
    }

    It 'reports an explicit failure when the controller exit code is unavailable' {
      Mock Start-Process {
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = $null }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Failed'
      $result.Error | Should -Match 'Could not read the test controller exit code'
    }

    It 'restores the VM even if controller launch fails' {
      Mock Start-Process { throw 'launch failed' }
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Failed'
      $result.Error | Should -Match 'launch failed'
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
    }

    It 'rejects a nonzero controller exit even without a thrown remoting error' {
      Mock Start-Process {
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = 7 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
      (Invoke-RideAutomationRequest $script:config $script:request $script:testRoot).Error | Should -Match 'code 7'
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
    }

    It 'refuses mismatched or missing guest results' {
      Mock Start-Process {
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = 0 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
      (Invoke-RideAutomationRequest $script:config $script:request $script:testRoot).Status | Should -Be 'Failed'
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
    }

    It 'terminates a timed-out controller, attempts evidence collection and restores the VM' {
      Mock Start-Process {
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = 0; Id = 123 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $false }
        $process
      }
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'TimedOut'
      Should -Invoke Stop-RideAutomationProcess -Times 1 -Exactly
      Should -Invoke Save-RideAutomationFailureEvidence -Times 1 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 2 -Exactly
    }

    It 'blocks subsequent runs if a timed-out controller cannot be terminated' {
      Mock Start-Process {
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = 0; Id = 123 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $false }
        $process
      }
      Mock Stop-RideAutomationProcess { throw 'termination failed' }
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Failed'
      $result.CleanupError | Should -Be 'termination failed'
      Test-Path (Join-Path $script:testRoot 'runtime/blocked.json') | Should -BeTrue
    }

    It 'rejects a successful-looking result for another request' {
      Mock Start-Process {
        $guest = Join-Path $script:testRoot "results\$($script:request.RunId)\guest"
        $null = New-Item -ItemType Directory $guest -Force
        @{ RunId = [guid]::NewGuid().ToString('N'); Status = 'Passed'; ValidationPassed = $true; IntegrationPassed = $true; Pester = @{ Total = 3; Failed = 0 } } | ConvertTo-Json | Set-Content (Join-Path $guest 'summary.json')
        $process = [pscustomobject]@{ Handle = [intptr]1; ExitCode = 0 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) return $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
      (Invoke-RideAutomationRequest $script:config $script:request $script:testRoot).Error | Should -Match 'mismatched'
    }

    It 'blocks all subsequent execution after cleanup fails' {
      $script:resets = 0
      Mock Reset-RideAutomationVm { $script:resets++; if ($script:resets -eq 2) { throw 'restore failed' } }
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Status | Should -Be 'Failed'
      $result.CleanupError | Should -Be 'restore failed'
      Test-Path (Join-Path $script:testRoot 'runtime/blocked.json') | Should -BeTrue
      $script:request.RunId = [guid]::NewGuid().ToString('N')
      (Invoke-RideAutomationRequest $script:config $script:request $script:testRoot).Error | Should -Match 'blocked'
      Should -Invoke Start-Process -Times 1 -Exactly
    }

    It 'does not change a VM when the checkpoint preflight fails' {
      Mock Import-RideAutomationLab { throw 'checkpoint missing' }
      $result = Invoke-RideAutomationRequest $script:config $script:request $script:testRoot
      $result.Error | Should -Be 'checkpoint missing'
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }

    It 'expires queued requests without touching the VM' {
      $script:request.SubmittedAtUtc = [datetime]::UtcNow.AddHours(-2).ToString('o')
      (Invoke-RideAutomationRequest $script:config $script:request $script:testRoot).Error | Should -Match 'expired'
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
    }

    It 'reports host UAC drift as a failure' {
      Mock Get-RideAutomationUac { [pscustomobject]@{ EnableLUA = 0; ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 1 } }
      (Invoke-RideAutomationRequest $script:config $script:request $script:testRoot).Error | Should -Match 'UAC settings changed'
    }

    It 'rejects malformed requests before running a controller' {
      $script:request.RunId = '..\escape'
      $requestError = $null
      try { Assert-RideAutomationRequest $script:request }
      catch { $requestError = $_ }
      $requestError | Should -Not -BeNullOrEmpty
      Should -Invoke Start-Process -Times 0 -Exactly
    }

  }
}

Describe 'Failure-evidence collector process results' {
  InModuleScope RIDE.TestAutomation {
    BeforeEach {
      Mock Start-Process {
        $process = [pscustomobject]@{ ExitCode = $null; HandleRetained = $false; CompletedExitCode = $script:collectorExitCode }
        $process | Add-Member ScriptProperty Handle { $this.HandleRetained = $true; [intptr]1 }
        $process | Add-Member ScriptMethod WaitForExit { param($Milliseconds) if ($this.HandleRetained) { $this.ExitCode = $this.CompletedExitCode }; $true }
        $process | Add-Member ScriptMethod Refresh { }
        $process
      }
    }

    It 'recognizes successful evidence collection after retaining the process handle' {
      $script:collectorExitCode = 0
      { Save-RideAutomationFailureEvidence -Root $TestDrive -RunId ('a' * 32) -ResultDirectory $TestDrive } | Should -Not -Throw
    }

    It 'still rejects unsuccessful evidence collection' {
      $script:collectorExitCode = 7
      $collectionError = $null
      try { Save-RideAutomationFailureEvidence -Root $TestDrive -RunId ('a' * 32) -ResultDirectory $TestDrive }
      catch { $collectionError = $_ }
      $collectionError | Should -Not -BeNullOrEmpty
      $collectionError.Exception.Message | Should -Match 'Partial-evidence collection failed'
    }

    It 'rejects an unavailable collector exit code' {
      $script:collectorExitCode = $null
      $collectionError = $null
      try { Save-RideAutomationFailureEvidence -Root $TestDrive -RunId ('a' * 32) -ResultDirectory $TestDrive }
      catch { $collectionError = $_ }
      $collectionError | Should -Not -BeNullOrEmpty
      $collectionError.Exception.Message | Should -Match 'Could not read the partial-evidence collector exit code'
    }
  }
}

Describe 'Queue serialization and exact checkpoint reset' {
  It 'allows only one worker to hold a controller lock' {
    $root = Join-Path $TestDrive 'lock-test'
    $null = New-Item -ItemType Directory (Join-Path $root 'runtime') -Force
    $first = Enter-RideAutomationWorker $root
    try { Enter-RideAutomationWorker $root | Should -BeNullOrEmpty }
    finally { $first.Dispose() }
    $next = Enter-RideAutomationWorker $root
    try { $next | Should -Not -BeNullOrEmpty }
    finally { $next.Dispose() }
  }

  It 'claims queued requests once in submission order and quarantines malformed files' {
    $root = Join-Path $TestDrive 'queue-test'
    foreach ($folder in @('pending', 'running', 'finished')) { $null = New-Item -ItemType Directory (Join-Path $root "queue\$folder") -Force }
    'invalid-json' | Set-Content (Join-Path $root 'queue/pending/invalid.json')
    $ids = @([guid]::NewGuid().ToString('N'), [guid]::NewGuid().ToString('N'))
    for ($index = 0; $index -lt 2; $index++) {
      $path = Join-Path $root "queue\pending\$($ids[$index]).json"
      Write-RideAutomationJson $path @{ RunId = $ids[$index]; Source = 'Local'; UnitOnly = $false; TimeoutMinutes = 90; SubmittedAtUtc = [datetime]::UtcNow.ToString('o') }
      (Get-Item -LiteralPath $path).LastWriteTimeUtc = [datetime]::UtcNow.AddSeconds($index - 10)
    }
    (Get-RideAutomationClaim $root).Request.RunId | Should -Be $ids[0]
    (Get-RideAutomationClaim $root).Request.RunId | Should -Be $ids[1]
    Get-RideAutomationClaim $root | Should -BeNullOrEmpty
    @(Get-ChildItem (Join-Path $root 'queue/running')).Count | Should -Be 2
    @(Get-ChildItem (Join-Path $root 'queue/finished') -Filter 'invalid-*.json').Count | Should -Be 1
  }

  InModuleScope RIDE.TestAutomation {
    BeforeAll {
      function Stop-VM { param($VM, [switch]$TurnOff, [switch]$Force, [switch]$Confirm) }
      function Restore-VMSnapshot { param($VMSnapshot, [switch]$Confirm) }
    }
    It 'stops the verified VM before restoring the verified snapshot' {
      $script:order = [Collections.Generic.List[string]]::new()
      Mock Import-RideAutomationLab { [pscustomobject]@{ VM = [pscustomobject]@{ State = 'Running'; Name = 'pilot' }; Snapshot = 'verified-clean' } }
      Mock Stop-VM { $VM.Name | Should -Be 'pilot'; $script:order.Add('stop') }
      Mock Restore-VMSnapshot { $VMSnapshot | Should -Be 'verified-clean'; $script:order.Add('restore') }
      Reset-RideAutomationVm ([pscustomobject]@{})
      $script:order.ToArray() | Should -Be @('stop', 'restore')
    }
  }
}
