<#
.SYNOPSIS
  Verify coordinated hibernation choices, capture, preview and failure recovery.
.DESCRIPTION
  Native power observation and powercfg calls are mocked. State files and a
  locked-file metadata regression use TestDrive; no live hibernation file is used.
  Compiling interop types verifies layout without invoking the Windows API.
.EXAMPLE
  Invoke-Pester ./tests/Hibernation.Tests.ps1
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; Pester 5.
  Version: repository test fixture. Changelog: 2026-11-01: Add candidate coverage
  and locked-file inspection regression for Windows PowerShell 5.1.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.Engine.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.CatalogValidation.psm1') -Force
}

Describe 'Hibernation file metadata inspection' {
  It 'reads a hidden system file length while its contents are exclusively locked' {
    InModuleScope RIDE-Hibernation -Parameters @{ Root = $TestDrive } {
      param($Root)
      $path = Join-Path $Root 'hiberfil.sys'
      [IO.File]::WriteAllBytes($path, [byte[]]::new(8192))
      $stream = $null
      try {
        [IO.File]::SetAttributes($path, [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System)
        $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        Get-RideHibernationFileLength -Path $path | Should -Be 8192
      } finally {
        if ($stream) { $stream.Dispose() }
        [IO.File]::SetAttributes($path, [IO.FileAttributes]::Normal)
      }
    }
  }
  It 'does not turn genuinely missing file metadata into zero bytes or Off' {
    InModuleScope RIDE-Hibernation -Parameters @{ Root = $TestDrive } {
      param($Root)
      { Get-RideHibernationFileLength -Path (Join-Path $Root 'missing-hiberfil.sys') } | Should -Throw
    }
  }
}

Describe 'Coordinated hibernation handler' {
  BeforeEach {
    $op = Get-RideOperation windows.hibernation
    InModuleScope RIDE-Hibernation -Parameters @{ Operation = $op } {
      param($Operation)
      $script:HiberOperation = $Operation
      $script:HiberObservation = [pscustomobject]@{ Mode = 'Full'; SizePercent = 75; FileBytes = 123456L; HibernateAvailable = $true }
      $script:HiberCalls = [Collections.Generic.List[string]]::new()
      Mock Get-RideHibernationObservation { $script:HiberObservation.PSObject.Copy() }
      Mock Invoke-RideHibernationCommand {
        param($Arguments)
        $script:HiberCalls.Add(($Arguments -join ' '))
        switch ($Arguments[1]) {
          'off' { $script:HiberObservation.Mode = 'Off'; $script:HiberObservation.FileBytes = 0L }
          'on' { if ($script:HiberObservation.Mode -eq 'Off') { $script:HiberObservation.Mode = 'Full' } }
          '/type' {
            $previousMode = $script:HiberObservation.Mode
            $script:HiberObservation.Mode = if ($Arguments[2] -eq 'reduced') { 'Reduced' } else { 'Full' }
            if ($script:HiberObservation.Mode -eq 'Reduced') { $script:HiberObservation.SizePercent = 20 }
            elseif ($previousMode -eq 'Reduced') { $script:HiberObservation.SizePercent = 40 }
          }
          '/size' {
            $script:HiberObservation.SizePercent = if ($Arguments[2] -eq '0') { 40 } else { [int]$Arguments[2] }
          }
        }
      }
    }
  }
  It 'compiles the documented Windows capability layout without querying Windows' {
    InModuleScope RIDE-Hibernation {
      Initialize-RideHibernationApi
      [Runtime.InteropServices.Marshal]::SizeOf([type][Ride.HibernationCapabilities]) | Should -Be 76
      [Runtime.InteropServices.Marshal]::OffsetOf([type][Ride.HibernationCapabilities], 'HiberFileType').ToInt32() | Should -Be 22
      Should -Invoke Get-RideHibernationObservation -Times 0
      Should -Invoke Invoke-RideHibernationCommand -Times 0
    }
  }
  It 'inspects without writes and distinguishes general Full from a specific size' {
    InModuleScope RIDE-Hibernation {
      $current = Get-RideHibernationState $script:HiberOperation
      Test-RideHibernationMatch $script:HiberOperation Full $current | Should -BeTrue
      Test-RideHibernationMatch $script:HiberOperation Size75 $current | Should -BeTrue
      Test-RideHibernationMatch $script:HiberOperation Size50 $current | Should -BeFalse
      Test-RideHibernationMatch $script:HiberOperation Reduced $current | Should -BeFalse
      Should -Invoke Invoke-RideHibernationCommand -Times 0
    }
  }
  It 'resets a custom size before reduced mode, then restores the prior full percentage' {
    InModuleScope RIDE-Hibernation {
      $before = Get-RideHibernationState $script:HiberOperation
      $snapshot = @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = $before.Observation } | ConvertTo-Json | ConvertFrom-Json
      Set-RideHibernationState $script:HiberOperation Reduced $before -Confirm:$false
      ($script:HiberCalls -join '|') | Should -Be '/hibernate on|/hibernate /size 0|/hibernate /type reduced'
      Set-RideHibernationState $script:HiberOperation Reduced (Get-RideHibernationState $script:HiberOperation) -Confirm:$false
      $script:HiberCalls.Count | Should -Be 3
      Restore-RideHibernationState $script:HiberOperation $snapshot -Confirm:$false
      $script:HiberObservation.Mode | Should -Be Full
      $script:HiberObservation.SizePercent | Should -Be 75
      $script:HiberCalls.Count | Should -Be 6
      Restore-RideHibernationState $script:HiberOperation $snapshot -Confirm:$false
      $script:HiberCalls.Count | Should -Be 6
    }
  }
  It 'enables a full file for explicit sizes from an initially disabled configuration' {
    InModuleScope RIDE-Hibernation {
      $script:HiberObservation.Mode = 'Off'
      $before = Get-RideHibernationState $script:HiberOperation
      Set-RideHibernationState $script:HiberOperation Size100 $before -Confirm:$false
      ($script:HiberCalls -join '|') | Should -Be '/hibernate on|/hibernate /type full|/hibernate /size 100'
      Restore-RideHibernationState $script:HiberOperation @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = $before.Observation } -Confirm:$false
      $script:HiberObservation.Mode | Should -Be Off
      $script:HiberCalls[3] | Should -Be '/hibernate off'
    }
  }
  It 'selects full mode without resetting an already full custom-sized file' {
    InModuleScope RIDE-Hibernation {
      Set-RideHibernationState $script:HiberOperation Full (Get-RideHibernationState $script:HiberOperation) -Confirm:$false
      Should -Invoke Invoke-RideHibernationCommand -Times 0
      $script:HiberObservation.Mode = 'Reduced'; $script:HiberObservation.SizePercent = 20
      Set-RideHibernationState $script:HiberOperation Full (Get-RideHibernationState $script:HiberOperation) -Confirm:$false
      ($script:HiberCalls -join '|') | Should -Be '/hibernate on|/hibernate /type full'
    }
  }
  It 'previews both apply and restore without invoking powercfg' {
    InModuleScope RIDE-Hibernation {
      $before = Get-RideHibernationState $script:HiberOperation
      Set-RideHibernationState $script:HiberOperation Off $before -WhatIf
      Restore-RideHibernationState $script:HiberOperation @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = @{ Mode = 'Reduced'; SizePercent = 20 } } -WhatIf
      Restore-RideHibernationState $script:HiberOperation @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = $before.Observation } -ValidateOnly
      Should -Invoke Get-RideHibernationObservation -Times 3 -Exactly
      Should -Invoke Invoke-RideHibernationCommand -Times 0
    }
  }
  It 'refuses unknown, incomplete or changed captured configuration before writes' {
    InModuleScope RIDE-Hibernation {
      $before = Get-RideHibernationState $script:HiberOperation
      $script:HiberObservation.SizePercent = 80
      { Set-RideHibernationState $script:HiberOperation Off $before } | Should -Throw '*drifted*'
      foreach ($percent in @($null, '75', 45, 101)) {
        $script:HiberObservation.SizePercent = $percent
        (Get-RideHibernationState $script:HiberOperation).Available | Should -BeFalse
        { Set-RideHibernationState $script:HiberOperation Off $before } | Should -Throw '*unavailable*'
      }
      $script:HiberObservation.Mode = 'Unknown'
      (Get-RideHibernationState $script:HiberOperation).Available | Should -BeFalse
      Should -Invoke Invoke-RideHibernationCommand -Times 0
    }
  }
  It 'rejects unsafe state values and mismatched snapshots before writes' {
    InModuleScope RIDE-Hibernation {
      $before = Get-RideHibernationState $script:HiberOperation
      foreach ($state in @('Size0', 'Size40', 'Size101', 'Size50;shutdown')) {
        { Set-RideHibernationState $script:HiberOperation $state $before } | Should -Throw '*Unsupported*'
      }
      $bad = $script:HiberOperation.Clone(); $bad.States = @{ Bad = 'Full:101' }
      { Set-RideHibernationState $bad Bad $before } | Should -Throw '*Unsupported*'
      foreach ($snapshot in @(
        @{ SnapshotVersion = 2; OperationId = $script:HiberOperation.Id; Prior = $before.Observation },
        @{ SnapshotVersion = 1; OperationId = 'other.id'; Prior = $before.Observation },
        @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = @{ Mode = 'Full'; SizePercent = '75' } }
      )) { { Restore-RideHibernationState $script:HiberOperation $snapshot } | Should -Throw '*snapshot*' }
      Should -Invoke Invoke-RideHibernationCommand -Times 0
    }
  }
  It 'stops a sequence at a native failure and can recover the intermediate full state' {
    InModuleScope RIDE-Hibernation {
      Mock Invoke-RideHibernationCommand { throw 'native type failure' } -ParameterFilter { $Arguments[1] -eq '/type' -and $Arguments[2] -eq 'reduced' }
      $before = Get-RideHibernationState $script:HiberOperation
      { Set-RideHibernationState $script:HiberOperation Reduced $before -Confirm:$false } | Should -Throw '*native type failure*'
      $script:HiberObservation.SizePercent | Should -Be 40
      Restore-RideHibernationState $script:HiberOperation @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = $before.Observation } -Confirm:$false
      $script:HiberObservation.SizePercent | Should -Be 75
    }
  }
  It 'reports successful native calls with a wrong final state as failure' {
    InModuleScope RIDE-Hibernation {
      Mock Invoke-RideHibernationCommand {}
      { Set-RideHibernationState $script:HiberOperation Off (Get-RideHibernationState $script:HiberOperation) -Confirm:$false } | Should -Throw '*postcondition*'
      { Restore-RideHibernationState $script:HiberOperation @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = @{ Mode = 'Reduced'; SizePercent = 20 } } -Confirm:$false } | Should -Throw '*postcondition*'
    }
  }
  It 'recovers the documented full default through Windows sizing and verifies its percentage' {
    InModuleScope RIDE-Hibernation {
      Restore-RideHibernationState $script:HiberOperation @{ SnapshotVersion = 1; OperationId = $script:HiberOperation.Id; Prior = @{ Mode = 'Full'; SizePercent = 40 } } -Confirm:$false
      $script:HiberCalls[2] | Should -Be '/hibernate /size 0'
      $script:HiberObservation.SizePercent | Should -Be 40
    }
  }
}

Describe 'Hibernation catalog and engine integration' {
  It 'keeps the optional operation gated and out of every bundled profile' {
    $op = Get-RideOperation windows.hibernation
    $op.PendingAcceptance | Should -BeTrue
    $op.SupportedTargets.Count | Should -Be 0
    $op.States.Count | Should -Be 54
    $op.Rollback | Should -Be Conditional
    foreach ($file in Get-ChildItem (Join-Path $PSScriptRoot '../profiles') -Filter *.psd1) {
      (Import-PowerShellDataFile $file.FullName).Operations.Id | Should -Not -Contain $op.Id
    }
    @(Get-RideCatalogValidationErrors (Get-RideCatalog)).Count | Should -Be 0
    { Get-RideSingleOperationPlan -Id windows.hibernation -Action Unset } | Should -Throw '*no declared override-removal state*'
    { Get-RideSingleOperationPlan -Id windows.hibernation -Action Set -State Size101 } | Should -Throw
  }
  It 'completes named and positional percentage states from the catalog without inspection' {
    $path = Join-Path $PSScriptRoot '../ride.ps1'
    foreach ($prefix in @('-State ', '')) {
      $line = "& '$path' set windows.hibernation ${prefix}size5"
      $matches = @([Management.Automation.CommandCompletion]::CompleteInput($line, $line.Length, $null).CompletionMatches.CompletionText)
      $matches.Count | Should -Be 10
      $matches | Should -Contain Size50
      $matches | Should -Contain Size59
      @($matches | Sort-Object -Unique).Count | Should -Be 10
    }
  }
  It 'rejects invalid percentages and unsupported promotion during validation' {
    $catalog = Get-RideCatalog
    $op = @($catalog.Operations | Where-Object Id -eq windows.hibernation)[0]
    $op.States.Size50 = 'Full:101'
    $op.SupportedTargets = @('Windows 11')
    $errors = @(Get-RideCatalogValidationErrors $catalog)
    $errors -join ';' | Should -BeLike '*Invalid hibernation full-file percentage*'
    $errors -join ';' | Should -BeLike '*Hibernation must remain a Windows 11 candidate*'
  }
  It 'blocks normal candidate execution before observation, state creation or writes' {
    InModuleScope RIDE.Engine {
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Get-RideCurrentState { throw 'must not inspect' }
      Mock Set-RideHibernationState {}
      Mock Initialize-RideStateRoot { throw 'must not create state' }
      $plan = @(Get-RideSingleOperationPlan -Id windows.hibernation -Action Set -State Reduced)
      { Invoke-RidePlan -Plan $plan -Confirm:$false } | Should -Throw '*does not support*'
      Should -Invoke Get-RideCurrentState -Times 0
      Should -Invoke Set-RideHibernationState -Times 0
      Should -Invoke Initialize-RideStateRoot -Times 0
    }
  }
  It 'displays the specific current size and saves prior state before a failed command' {
    InModuleScope RIDE.Engine -Parameters @{ Root = (Join-Path $TestDrive 'hiber-engine') } {
      param($Root)
      $script:HiberRoot = $Root
      $op = (Get-RideOperation windows.hibernation).Clone()
      $script:HiberCurrent = [pscustomobject]@{ Available = $true; Reason = ''; Observation = [pscustomobject]@{ Mode = 'Full'; SizePercent = 75; FileBytes = 123456L; HibernateAvailable = $true } }
      Mock Get-RidePlatform { 'Windows 11' }
      Mock Test-RideAdministrator { $true }
      Mock Get-RideStateRoot { $script:HiberRoot }
      Mock Initialize-RideStateRoot { New-Item -ItemType Directory -Path $script:HiberRoot -Force | Out-Null; $script:HiberRoot }
      Mock Get-RideCurrentState { $script:HiberCurrent }
      Mock Set-RideHibernationState {
        $file = @(Get-ChildItem -LiteralPath $script:HiberRoot -Recurse -Filter windows.hibernation.json)[0]
        $snapshot = (Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json).Snapshot
        if ($snapshot.Prior.SizePercent -ne 75 -or $snapshot.OperationId -ne 'windows.hibernation' -or $ExpectedState.Observation.SizePercent -ne 75) { throw 'missing hibernation capture' }
        throw 'fixture hibernation native failure'
      }
      Get-RideCurrentStateName $op $script:HiberCurrent | Should -Be Size75
      Get-RideCurrentValueText $op $script:HiberCurrent | Should -BeLike '*Full*75*123456*'
      $plan = @([pscustomobject]@{ Operation = $op; State = 'Reduced' })
      Invoke-RidePlan -Plan $plan -AllowCandidate -WhatIf -Confirm:$false | Out-Null
      Test-Path $Root | Should -BeFalse
      { Invoke-RidePlan -Plan $plan -AllowCandidate -Confirm:$false } | Should -Throw '*Run ID:*Saved state:*fixture hibernation native failure*'
      Should -Invoke Set-RideHibernationState -Times 1 -Exactly
      $script:HiberEngineOperation = $op
      Mock Get-RideCatalog { @{ Operations = @($script:HiberEngineOperation); Groups = @() } }
      Mock Get-RideStateRoot { param($Scope) if ($Scope -eq 'User') { Join-Path $script:HiberRoot 'unused-user-scope' } else { $script:HiberRoot } }
      Mock Restore-RideHibernationState {
        param($Operation, $Snapshot, [switch] $ValidateOnly)
        if ($Snapshot.Prior.SizePercent -ne 75 -or $Snapshot.OperationId -ne $Operation.Id) { throw 'incorrect recovery routing' }
      }
      $runId = @(Get-ChildItem -LiteralPath $Root -Directory)[0].Name
      Mock Get-RidePlatform { 'Windows Server 2025' }
      { Restore-RideRun -RunId $runId -AllowCandidate -WhatIf } | Should -Throw '*does not support Windows Server 2025*'
      Mock Get-RidePlatform { 'Windows 11' }
      $script:HiberEngineOperation.MinimumBuild = 99999
      Mock Get-ItemProperty { @{ CurrentBuildNumber = '26100' } }
      { Restore-RideRun -RunId $runId -AllowCandidate -WhatIf } | Should -Throw '*requires Windows build 99999*'
      $script:HiberEngineOperation.Remove('MinimumBuild')
      $restoreWarnings = @()
      Restore-RideRun -RunId $runId -WhatIf -Confirm:$false -WarningVariable restoreWarnings | Out-Null
      ($restoreWarnings -join ' ') | Should -Match 'acceptance remains pending'
      Should -Invoke Restore-RideHibernationState -Times 0 -ParameterFilter { -not $ValidateOnly }
      Restore-RideRun -RunId $runId -AllowCandidate -Confirm:$false | Out-Null
      Should -Invoke Restore-RideHibernationState -Times 1 -Exactly -ParameterFilter { -not $ValidateOnly }
    }
  }
}
