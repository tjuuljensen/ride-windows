<#
.SYNOPSIS
  Verify custom context-menu authoring and default registry values without writes to Windows.
.DESCRIPTION
  Uses declarative metadata, scripted wizard input, fake registry keys and mocked
  lifecycle handlers. No real registry operation, command or installer is executed.
.EXAMPLE
  Invoke-Pester .\tests\CustomRegistryAuthoring.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Owner: RIDE-Windows maintainers. Version: Repository test fixture.
#>

BeforeAll {
  $script:Root = Split-Path -Parent $PSScriptRoot
  $script:Helper = Join-Path $script:Root 'tools/New-RideLibrary.ps1'
  $script:Example = Join-Path $script:Root 'examples/authoring/certutil-context-menu.psd1'
  foreach ($module in @('RIDE.LibraryAuthoring', 'RIDE.LibrarySchema', 'RIDE.CatalogData', 'RIDE.Libraries', 'RIDE.Engine', 'RIDE-Settings')) {
    Import-Module (Join-Path $script:Root ('modules/' + $module + '.psm1')) -Force
  }
}

Describe 'Scope-explicit registry authoring' {
  BeforeEach {
    $script:Definition = Import-PowerShellDataFile -LiteralPath $script:Example
    $script:ProjectPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  }

  It 'maps <Path> in <Scope> scope to <Expected>' -TestCases @(
    @{ Path = 'HKCR:\*\shell\Example'; Scope = 'User'; Expected = 'HKCU:\Software\Classes\*\shell\Example' }
    @{ Path = 'HKEY_CLASSES_ROOT\*\shell\Example'; Scope = 'Machine'; Expected = 'HKLM:\Software\Classes\*\shell\Example' }
    @{ Path = 'Registry::HKEY_CLASSES_ROOT\*\shell\Example'; Scope = 'User'; Expected = 'HKCU:\Software\Classes\*\shell\Example' }
    @{ Path = 'HKEY_CURRENT_USER\Software\Example'; Scope = 'User'; Expected = 'HKCU:\Software\Example' }
    @{ Path = 'HKEY_LOCAL_MACHINE\Software\Example'; Scope = 'Machine'; Expected = 'HKLM:\Software\Example' }
    @{ Path = 'HKCU:\Software\Example'; Scope = 'User'; Expected = 'HKCU:\Software\Example' }
  ) {
    param($Path, $Scope, $Expected)
    ConvertTo-RideLibraryRegistryPath -Path $Path -Scope $Scope | Should -Be $Expected
  }

  It 'rejects unsupported, incomplete, traversing or wrong-scope paths: <Path>' -TestCases @(
    @{ Path = 'HKLM:\Software\Example' }, @{ Path = 'HKU:\OtherUser\Software\Example' },
    @{ Path = 'HKCR:\' }, @{ Path = 'HKCU:\Software\..\Example' }, @{ Path = 'Software\Example' }
  ) {
    param($Path)
    { ConvertTo-RideLibraryRegistryPath -Path $Path -Scope User } | Should -Throw
  }

  It 'publishes the corrected icon and command in <Scope> scope as one recoverable setting' -TestCases @(
    @{ Scope = 'User'; Hive = 'HKCU'; Admin = $false }, @{ Scope = 'Machine'; Hive = 'HKLM'; Admin = $true }
  ) {
    param($Scope, $Hive, $Admin)
    $script:Definition.Operations[0].Scope = $Scope
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:Definition -Confirm:$false
    $operation = (Get-RideCatalogContext -Root $script:Root -Library $project.Manifest).Catalog.Operations | Where-Object Id -eq 'example.context-menu.sha256-certutil'
    $operation.Kind | Should -Be 'RegistryValueSet'
    $operation.RequiresAdmin | Should -Be $Admin
    $operation.RegistryValues[0].RegistryPath | Should -Be ($Hive + ':\Software\Classes\*\shell\SHA-256 with Certutil')
    $operation.RegistryValues[0].ValueName | Should -BeExactly 'Icon'
    $operation.RegistryValues[1].ValueName | Should -BeExactly ''
    $operation.States.Enabled.Menu | Should -BeExactly 'shell32.dll,-152'
    $operation.States.Enabled.Command | Should -BeExactly 'cmd.exe /k certutil -hashfile "%1" SHA256'
    $operation.States.WindowsDefault.Menu | Should -BeNullOrEmpty
    (Import-PowerShellDataFile -LiteralPath $project.Profile).Operations.Count | Should -Be 1
  }

  It 'appends coordinated values and retains the original catalog for recovery' {
    $initial = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:Definition -Confirm:$false
    $script:Definition.Version = '0.1.3'
    $script:Definition.Operations[0].Id = 'another-menu'
    foreach ($member in $script:Definition.Operations[0].RegistryValues) { $member.RegistryPath = $member.RegistryPath.Replace('with Certutil', 'with Certutil 2') }
    $updated = Add-RideLibraryOperation -Path $script:ProjectPath -Definition $script:Definition -Confirm:$false
    (Import-PowerShellDataFile -LiteralPath $updated.Profile).Operations.Count | Should -Be 2
    (Get-RideCatalogContext -Root $script:Root -Library $updated.PreviousManifest).Libraries[0].Version | Should -Be '0.1.2'
  }

  It 'rejects malformed value sets before publication: <Failure>' -TestCases @(
    @{ Failure = 'Duplicate' }, @{ Failure = 'WrongScope' }, @{ Failure = 'WrongType' }, @{ Failure = 'Incomplete' }, @{ Failure = 'MissingName' }
  ) {
    param($Failure)
    $entry = $script:Definition.Operations[0]
    switch ($Failure) {
      Duplicate { $entry.RegistryValues[1].Key = 'Menu' }
      WrongScope { $entry.RegistryValues[0].RegistryPath = 'HKLM:\Software\Example' }
      WrongType { $entry.States.Enabled.Command = 7 }
      Incomplete { $entry.States.Enabled.Remove('Command') }
      MissingName { $entry.RegistryValues[1].Remove('ValueName') }
    }
    { New-RideLibraryProject -Path $script:ProjectPath -Definition $script:Definition -Confirm:$false } | Should -Throw
    Test-Path -LiteralPath $script:ProjectPath | Should -BeFalse
  }

  It 'refuses merged HKCR paths in already-published metadata rather than changing recovery identity' {
    $project = New-RideLibraryProject -Path $script:ProjectPath -Definition $script:Definition -Confirm:$false
    $catalogPath = Join-Path $project.Path 'catalog/operations.psd1'
    $text = [IO.File]::ReadAllText($catalogPath).Replace('HKCU:\Software\Classes', 'HKCR:')
    [IO.File]::WriteAllText($catalogPath, $text, [Text.UTF8Encoding]::new($false))
    { Get-RideCatalogContext -Root $script:Root -Library $project.Manifest } | Should -Throw '*component or scope*'
  }

  It 'guides both supplied registry values with literal HKCR, empty data and an unnamed command value' {
    $global:RideRegistryPrompt = @{ Index = 0; Responses = @('example.context-menu', '', '3', 'sha256-certutil', 'SHA-256 with Certutil', 'Custom menu fixture', '1', '1', '',
      'Menu', 'HKEY_CLASSES_ROOT\*\shell\SHA-256 with Certutil', 'shell32.dll,-152', '1', '',
      'Command', 'HKCR:\*\shell\SHA-256 with Certutil\command', '', '1', 'cmd.exe /k certutil -hashfile "%1" SHA256', '1',
      'No custom menu without registration', '', '', '1') }
    Mock Read-Host {
      $state = $global:RideRegistryPrompt
      if ($state.Index -ge $state.Responses.Count) { throw 'Unexpected registry authoring prompt.' }
      $answer = $state.Responses[$state.Index]; $state.Index++; $answer
    }
    try {
      $project = & $script:Helper -Path $script:ProjectPath -Confirm:$false
      $entry = (Import-RideCatalogData -Path (Join-Path $project.Path 'catalog/operations.psd1')).Operations[0]
      $entry.RegistryValues[1].ValueName | Should -BeExactly ''
      $entry.States.Enabled.Menu | Should -BeExactly ''
      $entry.States.Enabled.Command | Should -BeExactly 'cmd.exe /k certutil -hashfile "%1" SHA256'
      $global:RideRegistryPrompt.Index | Should -Be $global:RideRegistryPrompt.Responses.Count
    } finally { Remove-Variable RideRegistryPrompt -Scope Global -ErrorAction SilentlyContinue }
  }
}

Describe 'Custom coordinated registry lifecycle' {
  BeforeEach {
    $definition = Import-PowerShellDataFile -LiteralPath $script:Example
    $script:Project = New-RideLibraryProject -Path (Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))) -Definition $definition -Confirm:$false
    Set-RideLibraryContext -Library $script:Project.Manifest
    $script:StateDirectory = Join-Path $TestDrive ('state-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $script:StateDirectory
    $script:SetCurrent = [pscustomobject]@{ Values = @(
      [pscustomobject]@{ Key = 'Menu'; Exists = $false; Value = $null; ValueType = $null; KeyExisted = $false },
      [pscustomobject]@{ Key = 'Command'; Exists = $true; Value = '%SystemRoot%\old.exe'; ValueType = 'ExpandString'; KeyExisted = $true }
    ) }
    Mock Get-RidePlatform -ModuleName RIDE.Engine { 'Windows 11' }
    Mock Test-RideAdministrator -ModuleName RIDE.Engine { $true }
    Mock Get-RideStateRoot -ModuleName RIDE.Engine { $script:StateDirectory }
    Mock Initialize-RideStateRoot -ModuleName RIDE.Engine { $script:StateDirectory }
    Mock Get-RideCurrentState -ModuleName RIDE.Engine { $script:SetCurrent }
    Mock Set-RideRegistryValueSetState -ModuleName RIDE.Engine {
      $script:SetCurrent = [pscustomobject]@{ Values = @($Operation.RegistryValues | ForEach-Object {
        [pscustomobject]@{ Key = $_.Key; Exists = $true; Value = $Operation.States[$State][$_.Key]; ValueType = $_.ValueType; KeyExisted = $true }
      }) }
    }
    Mock Restore-RideRegistryValueSetState -ModuleName RIDE.Engine { $script:SetCurrent = $Snapshot }
  }
  AfterEach { Set-RideLibraryContext }

  It 'previews without writes, applies idempotently and restores both saved values and original kinds' {
    $plan = @(Get-RideSingleOperationPlan -Id 'example.context-menu.sha256-certutil' -Action Set -State Enabled)
    Invoke-RidePlan -Plan $plan -WhatIf -Confirm:$false | Out-Null
    Should -Invoke Initialize-RideStateRoot -ModuleName RIDE.Engine -Times 0 -Exactly
    Should -Invoke Set-RideRegistryValueSetState -ModuleName RIDE.Engine -Times 0 -Exactly
    $messages = @(Invoke-RidePlan -Plan $plan -Confirm:$false)
    $runId = ([string]($messages | Where-Object { $_ -like 'Run ID:*' })).Substring(8)
    Invoke-RidePlan -Plan $plan -Confirm:$false | Out-Null
    Should -Invoke Set-RideRegistryValueSetState -ModuleName RIDE.Engine -Times 1 -Exactly
    $record = Get-Content -LiteralPath (Join-Path $script:StateDirectory "$runId/example.context-menu.sha256-certutil.json") -Raw | ConvertFrom-Json
    $record.Library.Handler | Should -Be 'RegistryValueSet'
    $record.Snapshot.Values[1].ValueType | Should -Be 'ExpandString'
    Restore-RideRun -RunId $runId -WhatIf -Confirm:$false | Out-Null
    Should -Invoke Restore-RideRegistryValueSetState -ModuleName RIDE.Engine -Times 0 -Exactly
    Restore-RideRun -RunId $runId -Confirm:$false | Out-Null
    $script:SetCurrent.Values[0].Exists | Should -BeFalse
    $script:SetCurrent.Values[1].Value | Should -Be '%SystemRoot%\old.exe'
    $script:SetCurrent.Values[1].ValueType | Should -Be 'ExpandString'
  }

  It 'offers the custom state through metadata completion without invoking a handler' {
    $inputLine = ".\ride.ps1 set example.context-menu.sha256-certutil -Library '$($script:Project.Manifest)' -State En"
    $result = TabExpansion2 $inputLine $inputLine.Length
    $result.CompletionMatches.CompletionText | Should -Contain 'Enabled'
    Should -Invoke Get-RideCurrentState -ModuleName RIDE.Engine -Times 0 -Exactly
  }
}

Describe 'Unnamed default registry value handler' {
  BeforeEach {
    $script:Operation = @{ RegistryPath = 'HKCU:\Software\Classes\*\shell\Test\command'; ValueName = ''; ValueType = 'String' }
    $global:RideDefaultKeyState = @{ Names = @(''); Value = 'old'; Type = 'ExpandString'; Writes = @(); Deletes = @(); Disposed = 0 }
    $script:FakeKey = [pscustomobject]@{}
    $script:FakeKey | Add-Member ScriptMethod GetValueNames { ,$global:RideDefaultKeyState.Names }
    $script:FakeKey | Add-Member ScriptMethod GetSubKeyNames { ,@() }
    $script:FakeKey | Add-Member ScriptMethod GetValue { param($name, $fallback, $options) $global:RideDefaultKeyState.Value }
    $script:FakeKey | Add-Member ScriptMethod GetValueKind { param($name) [Microsoft.Win32.RegistryValueKind]$global:RideDefaultKeyState.Type }
    $script:FakeKey | Add-Member ScriptMethod SetValue { param($name, $value, $kind) $global:RideDefaultKeyState.Writes += @{ Name = $name; Value = $value; Type = $kind.ToString() } }
    $script:FakeKey | Add-Member ScriptMethod DeleteValue { param($name, $throwOnMissing) $global:RideDefaultKeyState.Deletes += @{ Name = $name; ThrowOnMissing = $throwOnMissing } }
    $script:FakeKey | Add-Member ScriptMethod Dispose { $global:RideDefaultKeyState.Disposed++ }
    Mock Open-RideWritableRegistryKey -ModuleName RIDE-Settings { $script:FakeKey }
    Mock Get-Item -ModuleName RIDE-Settings { $script:FakeKey }
    Mock Test-Path -ModuleName RIDE-Settings { $true }
    Mock New-Item -ModuleName RIDE-Settings {}
    Mock New-ItemProperty -ModuleName RIDE-Settings { throw 'Unnamed values cannot use named-property binding.' }
    Mock Remove-ItemProperty -ModuleName RIDE-Settings { throw 'Unnamed values cannot use named-property binding.' }
    Mock Remove-Item -ModuleName RIDE-Settings {}
  }
  AfterEach { Remove-Variable RideDefaultKeyState -Scope Global -ErrorAction SilentlyContinue }

  It 'reads unnamed values as raw data with their captured kind, distinguishing empty from absent' {
    $current = Get-RideSettingState -Operation $script:Operation
    $current.Exists | Should -BeTrue
    $current.ValueType | Should -Be 'ExpandString'
    $global:RideDefaultKeyState.Value = ''
    (Get-RideSettingState -Operation $script:Operation).Exists | Should -BeTrue
    $global:RideDefaultKeyState.Names = @()
    (Get-RideSettingState -Operation $script:Operation).Exists | Should -BeFalse
  }

  It 'writes empty default data with the declared kind and disposes the writable key' {
    Set-RideSettingState -Operation $script:Operation -Value ''
    $global:RideDefaultKeyState.Writes[0].Name | Should -BeExactly ''
    $global:RideDefaultKeyState.Writes[0].Value | Should -BeExactly ''
    $global:RideDefaultKeyState.Writes[0].Type | Should -Be 'String'
    $global:RideDefaultKeyState.Disposed | Should -Be 1
  }

  It 'restores the previous default value and its original kind' {
    Restore-RideSettingState -Operation $script:Operation -Snapshot @{ Exists = $true; Value = '%SystemRoot%\old.exe'; ValueType = 'ExpandString'; KeyExisted = $true }
    $global:RideDefaultKeyState.Writes[0].Type | Should -Be 'ExpandString'
    $global:RideDefaultKeyState.Writes[0].Value | Should -Be '%SystemRoot%\old.exe'
  }

  It 'deletes only the unnamed value when originally absent and preserves unrelated named values' {
    $global:RideDefaultKeyState.Names = @('Unrelated')
    Restore-RideSettingState -Operation $script:Operation -Snapshot @{ Exists = $false; KeyExisted = $false }
    $global:RideDefaultKeyState.Deletes[0].Name | Should -BeExactly ''
    $global:RideDefaultKeyState.Deletes[0].ThrowOnMissing | Should -BeFalse
    Should -Invoke Remove-Item -ModuleName RIDE-Settings -Times 0 -Exactly
  }

  It 'restores serialized original <Kind> data using its native registry type' -TestCases @(
    @{ Kind = 'Binary'; Value = @(0, 1, 255); NativeType = 'System.Byte[]' },
    @{ Kind = 'MultiString'; Value = @('first', 'second'); NativeType = 'System.String[]' },
    @{ Kind = 'DWord'; Value = -1; NativeType = 'System.Int32' },
    @{ Kind = 'QWord'; Value = 4294967296L; NativeType = 'System.Int64' }
  ) {
    param($Kind, $Value, $NativeType)
    $snapshot = @{ Exists = $true; Value = $Value; ValueType = $Kind; KeyExisted = $true } | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    Restore-RideSettingState -Operation $script:Operation -Snapshot $snapshot
    $written = $global:RideDefaultKeyState.Writes[0]
    $written.Type | Should -Be $Kind
    $written.Value.GetType().FullName | Should -Be $NativeType
    $written.Value | Should -Be $Value
  }

  It 'removes a newly-created declared command key only when it is empty' {
    $global:RideDefaultKeyState.Names = @()
    Restore-RideSettingState -Operation $script:Operation -Snapshot @{ Exists = $false; KeyExisted = $false }
    Should -Invoke Remove-Item -ModuleName RIDE-Settings -Times 1 -Exactly -ParameterFilter { $LiteralPath -eq $script:Operation.RegistryPath }
  }
}
