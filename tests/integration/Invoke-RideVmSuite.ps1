<#
.SYNOPSIS
  Exercise RIDE settings and package lifecycle behavior on a disposable VM.

.DESCRIPTION
  - Requires an explicit VM environment guard and an elevated session.
  - Applies, verifies, and restores changes; package checks may download installers.
  - Windows 11 scenarios are implemented; Server 2025 remains a separate unvalidated target.
  - Exports acquisition observations before the controller restores the checkpoint.
  - Writes progress and failure details to the pipeline; changes Windows state
  and installs/removes packages as part of the integration scenarios.

.PARAMETER Version
  Print the existing script version and return before module imports or operational checks.

.EXAMPLE
  .\tests\integration\Invoke-RideVmSuite.ps1 -Version

.EXAMPLE
  Get-Help .\tests\integration\Invoke-RideVmSuite.ps1 -Full

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Scenario progress and completion; errors terminate the suite.

.NOTES
  Compatibility: Windows PowerShell 5.1 or PowerShell 7 on Windows 11 or Windows Server 2025.
  Prerequisites: - Administrator session and RIDE checkout in the VM; outbound access is
  required for package installer downloads.
  - Restore the VM's clean checkpoint after the run.
  File/environment inputs: - RIDE_INTEGRATION_VM must be set to '1' inside the disposable VM.
  Recovery: Use the configured clean disposable-VM checkpoint and the linked runbook; no developer
  workstation integration runs.
  Author: RIDE-Windows maintainers.
  Version: 0.8.0
  Changelog:
  - 0.8.0: Add registry round trips for seven optional Explorer folder options.
  - 0.7.0: Verify optional Windows 11 desktop icon visibility.
  - 0.6.0: Verify two additional optional Windows 11 user interface settings.
  - 0.4.0: Verify Git functionality, five additional package lifecycles, two user policies
    and collected acquisition observations.
  - 0.5.0: Verify Defender exclusion apply, repeat-apply, and exact restoration.
    - 0.1.0: Initial versioned integration suite.
  - 0.2.0: Add Windows 11 round-trip checks for network, update, and security settings.
  - 0.3.0: Add exact registry subtree round-trip checks for Explorer folder visibility.

.LINK
  tests/integration/AUTOMATEDLAB-TASKS.md

.LINK
  tests/integration/AUTOMATEDLAB.md

#>


[CmdletBinding()]
param([switch] $Version)

$script:ScriptVersion = '0.8.0'
if ($Version) {
  Write-Output $script:ScriptVersion
  return
}

$ErrorActionPreference = 'Stop'
if ($env:RIDE_INTEGRATION_VM -ne '1') { throw "Set RIDE_INTEGRATION_VM=1 only inside a disposable VM before running integration checks." }
if (-not $env:RIDE_TEST_RUN_ID) { $env:RIDE_TEST_RUN_ID = Get-Variable -Name ResultRunId -ValueOnly -ErrorAction SilentlyContinue }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run the integration suite from an elevated PowerShell session.' }

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $root 'modules/RIDE.Engine.psm1') -Force
$target = Get-RidePlatform
if ($target -notin @('Windows 11', 'Windows Server 2025')) { throw "Unsupported integration VM target: $target" }

if ($target -eq 'Windows 11') {
  foreach ($settingScenario in @(
    @{ Id = 'windows.edge-friendly-url-format'; State = 'PlainText' }
    @{ Id = 'windows.start-run-as-different-user'; State = 'Enabled' }
    @{ Id = 'windows.taskbar-clock-seconds'; State = 'Shown'; BaselineState = 'Hidden' }
    @{ Id = 'windows.recycle-bin-delete-confirmation'; State = 'Enabled'; BaselineState = 'Disabled' }
    @{ Id = 'windows.desktop-icons-visibility'; State = 'Hidden'; BaselineState = 'Visible' }
    @{ Id = 'windows.explorer-title-full-path'; State = 'Shown' }
    @{ Id = 'windows.protected-files-visibility'; State = 'Visible' }
    @{ Id = 'windows.explorer-separate-process'; State = 'Enabled' }
    @{ Id = 'windows.restore-folder-windows'; State = 'Enabled' }
    @{ Id = 'windows.sharing-wizard'; State = 'Disabled' }
    @{ Id = 'windows.item-selection-checkboxes'; State = 'Shown' }
    @{ Id = 'windows.thumbnail-display'; State = 'Disabled' }
  )) {
    $operation = Get-RideOperation -Id $settingScenario.Id
    $original = Get-RideCurrentState -Operation $operation
    $plan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $settingScenario.State)
    $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
    $runId = ($output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' } | Select-Object -Last 1) -replace '^Run ID: ', ''
    if (-not $runId) { throw "No saved run returned for $($operation.Id)." }
    try {
      if (-not (Test-RideDesiredState -Operation $operation -State $settingScenario.State)) { throw "Policy apply failed: $($operation.Id)" }
      $null = Invoke-RidePlan -Plan $plan -Confirm:$false
      Restore-RideRun -RunId $runId -Confirm:$false
      $restored = Get-RideCurrentState -Operation $operation
      if ([bool]$restored.Exists -ne [bool]$original.Exists -or ($original.Exists -and ($restored.Value -ne $original.Value -or $restored.ValueType -ne $original.ValueType))) { throw "Policy exact restore failed: $($operation.Id)" }
      $baselineState = if ($settingScenario.ContainsKey('BaselineState')) { $settingScenario.BaselineState } else { 'WindowsDefault' }
      $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $baselineState) -Confirm:$false
      if (-not (Test-RideDesiredState -Operation $operation -State $baselineState)) { throw "Policy baseline failed: $($operation.Id) ($baselineState)" }
    }
    finally { Restore-RideRun -RunId $runId -Confirm:$false }
  }
  foreach ($exclusionId in @('windows.defender-tools-exclusion', 'windows.defender-bootstrap-exclusion')) {
    $operation = Get-RideOperation -Id $exclusionId
    $original = Get-RideCurrentState -Operation $operation
    $requestedState = if ($original.Present) { 'Absent' } else { 'Present' }
    $plan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $requestedState)
    $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
    $runIdLine = $output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' } | Select-Object -Last 1
    if (-not $runIdLine) { throw "No saved run returned for $exclusionId." }
    $runId = $runIdLine -replace '^Run ID: ', ''
    try {
      if (-not (Test-RideDesiredState -Operation $operation -State $requestedState)) { throw "Defender exclusion apply failed: $exclusionId" }
      $null = Invoke-RidePlan -Plan $plan -Confirm:$false
      Restore-RideRun -RunId $runId -Confirm:$false
      $restored = Get-RideCurrentState -Operation $operation
      if ([bool]$restored.Present -ne [bool]$original.Present -or ($original.Present -and $restored.Path -ne $original.Path)) { throw "Defender exclusion exact restore failed: $exclusionId" }
    }
    finally { Restore-RideRun -RunId $runId -Confirm:$false }
  }

  foreach ($powerCase in @(@{ Id = 'windows.lid-close-action-ac'; State = 'DoNothing' }, @{ Id = 'windows.lid-close-action-dc'; State = 'DoNothing' })) {
    $operation = Get-RideOperation -Id $powerCase.Id
    $original = Get-RideCurrentState -Operation $operation
    if (-not $original.Available) {
      Write-Warning "Skipping $($operation.Id): the disposable VM does not expose a lid-close power setting."
      continue
    }
    $state = if ($original.Index -eq 0) { 'Sleep' } else { $powerCase.State }
    $plan = @(Get-RideSingleOperationPlan -Id $operation.Id -Action Set -State $state)
    $output = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
    $runIdLine = $output | Where-Object { $_ -is [string] -and $_ -match '^Run ID: ' } | Select-Object -Last 1
    if (-not $runIdLine) { throw "No saved run returned for $($operation.Id)." }
    $runId = $runIdLine -replace '^Run ID: ', ''
    try {
      if (-not (Test-RideDesiredState -Operation $operation -State $state)) { throw "Power setting apply failed: $($operation.Id)" }
      $null = Invoke-RidePlan -Plan $plan -Confirm:$false
      Restore-RideRun -RunId $runId -Confirm:$false
      $restored = Get-RideCurrentState -Operation $operation
      if ($restored.SchemeGuid -ne $original.SchemeGuid -or [int]$restored.Index -ne [int]$original.Index) { throw "Power setting exact restore failed: $($operation.Id)" }
    }
    finally { Restore-RideRun -RunId $runId -Confirm:$false }
  }

  $inkingSetting = Get-RideOperation -Id 'windows.inking-typing-data'
  $inkingOriginal = Get-RideCurrentState -Operation $inkingSetting
  $inkingState = if ($inkingOriginal.Exists -and $inkingOriginal.Value -eq 0) { 'Enabled' } else { 'Disabled' }
  $inkingProfile = @{
    SchemaVersion = 1
    Name = 'Inking and typing registry integration'
    Operations = @(@{ Id = $inkingSetting.Id; State = $inkingState })
  }
  $inkingRun = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $inkingProfile) -Confirm:$false | ForEach-Object { $_ })
  $inkingRunIdLine = $inkingRun | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if (-not $inkingRunIdLine) { throw 'Inking and typing integration apply did not return a run ID.' }
  $inkingRunId = $inkingRunIdLine -replace '^Run ID: ', ''
  $inkingCurrent = Get-RideCurrentState -Operation $inkingSetting
  $inkingExpected = $inkingSetting.States[$inkingState]
  if ($null -eq $inkingExpected) {
    if ($inkingCurrent.Exists) { throw 'Enabling inking and typing data did not remove the per-user override.' }
  }
  elseif (-not $inkingCurrent.Exists -or $inkingCurrent.Value -ne $inkingExpected) {
    throw 'Disabling inking and typing data did not set the declared registry value.'
  }
  Restore-RideRun -RunId $inkingRunId -Confirm:$false
  $inkingRestored = Get-RideCurrentState -Operation $inkingSetting
  if ([bool]$inkingRestored.Exists -ne [bool]$inkingOriginal.Exists -or ($inkingOriginal.Exists -and ($inkingRestored.Value -ne $inkingOriginal.Value -or $inkingRestored.ValueType -ne $inkingOriginal.ValueType))) {
    throw 'Inking and typing exact restore did not recover the initial registry value.'
  }

$networkOperation = Get-RideOperation -Id 'windows.current-network-category'
$networkOriginal = Get-RideCurrentState -Operation $networkOperation
if (@($networkOriginal.Profiles).Count -gt 0) {
  $networkCategories = @($networkOriginal.Profiles.NetworkCategory | Select-Object -Unique)
  $networkTestState = if ($networkCategories.Count -eq 1 -and $networkCategories[0] -eq 'Public') { 'Private' } else { 'Public' }
  $networkProfile = @{
    SchemaVersion = 1
    Name = 'Network profile category integration'
    Operations = @(@{ Id = $networkOperation.Id; State = $networkTestState })
  }
  $networkRun = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $networkProfile) -Confirm:$false | ForEach-Object { $_ })
  if (-not (Test-RideDesiredState -Operation $networkOperation -State $networkTestState)) { throw "Network profile apply did not set all eligible profiles to $networkTestState." }
  $networkRunIdLine = $networkRun | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if ($networkRunIdLine) { Restore-RideRun -RunId ($networkRunIdLine -replace '^Run ID: ', '') -Confirm:$false }
  $networkRestored = Get-RideCurrentState -Operation $networkOperation
  $originalProfiles = @($networkOriginal.Profiles | Sort-Object InterfaceIndex, Name | Select-Object InterfaceIndex, Name, NetworkCategory)
  $restoredProfiles = @($networkRestored.Profiles | Sort-Object InterfaceIndex, Name | Select-Object InterfaceIndex, Name, NetworkCategory)
  if ((ConvertTo-Json -InputObject $restoredProfiles -Depth 4 -Compress) -ne (ConvertTo-Json -InputObject $originalProfiles -Depth 4 -Compress)) {
    throw 'Network profile restore did not recover each captured category.'
  }
}
else {
  Write-Warning 'Skipping network profile integration because Windows reports no non-domain connection profiles.'
}

foreach ($settingCase in @(
  @{ Id = 'windows.remote-assistance-policy'; State = 'Disabled' }
  @{ Id = 'windows.bitlocker-encryption-method'; State = 'AesCbc256' }
  @{ Id = 'windows.microsoft-product-updates'; State = 'Enabled' }
)) {
  $operation = Get-RideOperation -Id $settingCase.Id
  $before = Get-RideCurrentState -Operation $operation
  $profile = @{
    SchemaVersion = 1
    Name = "$($operation.Name) integration"
    Operations = @(@{ Id = $operation.Id; State = $settingCase.State })
  }
  $run = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $profile) -Confirm:$false | ForEach-Object { $_ })
  if (-not (Test-RideDesiredState -Operation $operation -State $settingCase.State)) { throw "$($operation.Name) integration apply did not reach '$($settingCase.State)'." }
  $runIdLine = $run | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if ($runIdLine) { Restore-RideRun -RunId ($runIdLine -replace '^Run ID: ', '') -Confirm:$false }
  $after = Get-RideCurrentState -Operation $operation
  if ((ConvertTo-Json -InputObject $after -Depth 4 -Compress) -ne (ConvertTo-Json -InputObject $before -Depth 4 -Compress)) {
    throw "$($operation.Name) integration restore did not recover the original registry state."
  }
}

foreach ($id in @('windows.music-folder-this-pc', 'windows.videos-folder-this-pc', 'windows.3d-objects-folder-this-pc')) {
  $operation = Get-RideOperation -Id $id
  $before = Get-RideCurrentState -Operation $operation
  $originalState = if ($before.PresentCount -eq 0) { 'Hidden' } elseif ($before.PresentCount -eq $before.TotalCount) { 'Visible' } else { 'Mixed' }
  $testState = if ($originalState -eq 'Hidden') { 'Visible' } else { 'Hidden' }
  $profile = @{
    SchemaVersion = 1
    Name = "$($operation.Name) exact registry-tree integration"
    Operations = @(@{ Id = $operation.Id; State = $testState })
  }
  $run = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $profile) -Confirm:$false | ForEach-Object { $_ })
  if (-not (Test-RideDesiredState -Operation $operation -State $testState)) { throw "$($operation.Name) integration apply did not reach '$testState'." }
  $runIdLine = $run | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if (-not $runIdLine) { throw "$($operation.Name) integration apply did not produce saved state for its change." }
  Restore-RideRun -RunId ($runIdLine -replace '^Run ID: ', '') -Confirm:$false
  $after = Get-RideCurrentState -Operation $operation
  $beforeJson = (ConvertTo-Json -InputObject $before.Trees -Depth 40 -Compress) -replace 'D:AI(?=\()', 'D:'
  $afterJson = (ConvertTo-Json -InputObject $after.Trees -Depth 40 -Compress) -replace 'D:AI(?=\()', 'D:'
  if ($afterJson -cne $beforeJson) {
    throw "$($operation.Name) restore did not recover its original registry subtree values and security descriptors. Before: $beforeJson After: $afterJson"
  }
}
}

$setting = Get-RideOperation -Id 'windows.show-known-extensions'
$original = Get-RideCurrentState -Operation $setting
$analystProfile = Get-RideProfile -Path (Join-Path $root 'profiles/analyst-basics.psd1')
$baselineProfile = Get-RideProfile -Path (Join-Path $root 'profiles/baseline.psd1')

try {
  $firstRun = @(Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false | ForEach-Object { $_ })
  $runIdLine = $firstRun | Where-Object { $_ -match '^Run ID: ' } | Select-Object -Last 1
  if (-not $runIdLine) { throw 'First apply did not return a run ID.' }
  $runId = $runIdLine -replace '^Run ID: ', ''

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false
  $status = @(Get-RideStatus -Profile $analystProfile)
  if (@($status | Where-Object { -not $_.InDesiredState }).Count -gt 0) { throw 'Repeated apply did not converge to the requested profile.' }

  Restore-RideRun -RunId $runId -Confirm:$false
  $afterRestore = Get-RideCurrentState -Operation $setting
  if ([bool]$afterRestore.Exists -ne [bool]$original.Exists -or ($original.Exists -and ($afterRestore.Value -ne $original.Value -or $afterRestore.ValueType -ne $original.ValueType))) {
    throw 'Exact setting restore did not recover the initial Explorer value.'
  }

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $baselineProfile) -Confirm:$false
  if (-not (Test-RideDesiredState -Operation $setting -State 'Disabled')) { throw 'Baseline profile did not set the documented Explorer state.' }

  $null = Invoke-RidePlan -Plan @(Get-RidePlan -Profile $analystProfile) -Confirm:$false
  $removePlan = @(Get-RidePlan -Profile $analystProfile -Action Remove)
  $null = Invoke-RidePlan -Plan $removePlan -Confirm:$false
  foreach ($id in @('package.7zip', 'package.notepadpp')) {
    $package = Get-RideOperation -Id $id
    if ((Get-RideCurrentState -Operation $package).Present) { throw "Package removal failed: $id" }
  }

  $gitPackage = Get-RideOperation -Id 'package.git-for-windows'
  if ((Get-RideCurrentState -Operation $gitPackage).Present) { throw 'Git integration requires a clean checkpoint without Git for Windows.' }
  $gitWork = Join-Path ([IO.Path]::GetTempPath()) ('RIDE-Git-' + [guid]::NewGuid().ToString('N'))
  try {
    $gitPlan = @(Get-RideSingleOperationPlan -Id $gitPackage.Id -Action Install)
    $null = Invoke-RidePlan -Plan $gitPlan -Confirm:$false
    $gitState = Get-RideCurrentState -Operation $gitPackage
    if (-not $gitState.Present -or -not $gitState.DisplayVersion) { throw 'Git installation did not report its version.' }
    $gitExe = Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
    $gitVersion = & $gitExe --version
    if ($LASTEXITCODE -ne 0 -or $gitVersion -notmatch '^git version ') { throw 'Installed Git could not report its version.' }
    Write-Output "Git functionality check: $gitVersion"
    New-Item -ItemType Directory -Path $gitWork | Out-Null
    & $gitExe -C $gitWork init
    if ($LASTEXITCODE -ne 0) { throw 'Git repository initialization failed.' }
    'RIDE disposable-VM Git test' | Set-Content -LiteralPath (Join-Path $gitWork 'sample.txt')
    & $gitExe -C $gitWork add sample.txt
    if ($LASTEXITCODE -ne 0) { throw 'Git staging failed.' }
    & $gitExe -C $gitWork -c user.name=RIDE-Test -c user.email=ride-test@example.invalid -c commit.gpgsign=false commit -m 'Verify installed Git'
    if ($LASTEXITCODE -ne 0) { throw 'Git local commit failed.' }
    & $gitExe -C $gitWork rev-parse --verify HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Git commit verification failed.' }
    $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $gitPackage.Id -Action Install) -Confirm:$false
    if ((Get-RideCurrentState -Operation $gitPackage).DisplayVersion -ne $gitState.DisplayVersion) { throw 'Repeated Git installation changed the detected version.' }
    $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $gitPackage.Id -Action Remove) -Confirm:$false
    if ((Get-RideCurrentState -Operation $gitPackage).Present -or (Test-Path -LiteralPath $gitExe)) { throw 'Git uninstall did not remove the package and command executable.' }
  }
  finally {
    if ((Get-RideCurrentState -Operation $gitPackage).Present) { $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $gitPackage.Id -Action Remove) -Confirm:$false }
    if (Test-Path -LiteralPath $gitWork) {
      $resolvedGitWork = (Resolve-Path -LiteralPath $gitWork).Path
      if ($resolvedGitWork -ne [IO.Path]::GetFullPath($gitWork) -or (Split-Path -Leaf $resolvedGitWork) -notmatch '^RIDE-Git-[0-9a-f]{32}$') { throw 'Unexpected Git test cleanup directory.' }
      Remove-Item -LiteralPath $resolvedGitWork -Recurse -Force
    }
  }

  $packageFailures = [Collections.Generic.List[string]]::new()
  foreach ($packageId in @('package.git-lfs', 'package.joplin', 'package.sharex', 'package.windirstat', 'package.powershell')) {
    $package = Get-RideOperation -Id $packageId
    if ((Get-RideCurrentState -Operation $package).Present) { throw "Package scenario requires an absent clean-baseline package: $packageId" }
    try {
      Write-Host "Starting package lifecycle: $packageId"
      if ($packageId -eq 'package.git-lfs') {
        $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $gitPackage.Id -Action Install) -Confirm:$false
      }
      $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $packageId -Action Install) -Confirm:$false
      $packageState = Get-RideCurrentState -Operation $package
      if (-not $packageState.Present -or -not $packageState.DisplayVersion) { throw "Package installation did not report its version: $packageId" }
      Write-Output "Package lifecycle verified installation: $packageId $($packageState.DisplayVersion)"
      if ($packageId -eq 'package.powershell') {
        $powerShellVersion = & (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe') -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
        if ($LASTEXITCODE -ne 0 -or $powerShellVersion -notmatch '^7\.') { throw 'Installed PowerShell 7 did not execute successfully.' }
      }
      $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $packageId -Action Install) -Confirm:$false
      if ((Get-RideCurrentState -Operation $package).DisplayVersion -ne $packageState.DisplayVersion) { throw "Repeated installation changed the version: $packageId" }
      $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $packageId -Action Remove) -Confirm:$false
      if ((Get-RideCurrentState -Operation $package).Present) { throw "Package removal failed: $packageId" }
    }
    catch {
      $packageFailures.Add("${packageId}: $($_.Exception.Message)")
      Write-Warning "Package lifecycle failed: $packageId; $($_.Exception.Message)"
    }
    finally {
      try {
        if ((Get-RideCurrentState -Operation $package).Present) { $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $package.Id -Action Remove) -Confirm:$false }
        if ($packageId -eq 'package.git-lfs' -and (Get-RideCurrentState -Operation $gitPackage).Present) { $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $gitPackage.Id -Action Remove) -Confirm:$false }
      }
      catch { $packageFailures.Add("${packageId} cleanup: $($_.Exception.Message)"); Write-Warning $packageFailures[$packageFailures.Count - 1] }
    }
  }

  $sysmon = Get-RideOperation -Id 'package.sysmon64'
  if ((Get-RideCurrentState -Operation $sysmon).Present) { throw 'Sysmon VM integration requires a clean snapshot without a pre-existing standalone Sysmon install.' }
  try {
    $installSysmon = @(Get-RideSingleOperationPlan -Id $sysmon.Id -Action Install)
    $null = Invoke-RidePlan -Plan $installSysmon -Confirm:$false
    if (-not (Get-RideCurrentState -Operation $sysmon).Present) { throw 'Sysmon installation did not register its service.' }
    $null = Invoke-RidePlan -Plan $installSysmon -Confirm:$false
    $removeSysmon = @(Get-RideSingleOperationPlan -Id $sysmon.Id -Action Remove)
    $null = Invoke-RidePlan -Plan $removeSysmon -Confirm:$false
    if ((Get-RideCurrentState -Operation $sysmon).Present) { throw 'Sysmon uninstallation did not remove its service.' }
  }
  finally {
    if ((Get-RideCurrentState -Operation $sysmon).Present) { $null = Invoke-RidePlan -Plan @(Get-RideSingleOperationPlan -Id $sysmon.Id -Action Remove) -Confirm:$false }
  }

  if ($packageFailures.Count) { throw ($packageFailures -join "`n") }
  Write-Output "VM integration suite passed on $target. Restore the VM checkpoint before reuse."
}
catch {
  Write-Error ("VM integration suite failed on {0}: {1}" -f $target, $_.Exception.Message)
  throw
}
finally {
  # The installed 0.3 runner passes ResultsPath through its caller scope; retain
  # that handoff until updated protected controller copies are registered.
  $evidencePath = $env:RIDE_TEST_EVIDENCE_PATH
  if (-not $evidencePath) { $evidencePath = Get-Variable -Name ResultsPath -ValueOnly -ErrorAction SilentlyContinue }
  if ($evidencePath) {
    Copy-Item -LiteralPath (Join-Path $root 'catalog\artifact-observations.json') -Destination (Join-Path $evidencePath 'artifact-observations.json') -Force -ErrorAction Stop
  }
}
