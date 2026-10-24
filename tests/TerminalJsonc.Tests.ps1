<#
.SYNOPSIS
  Verify pure Terminal JSONC field ownership and recovery with synthetic byte arrays.
.DESCRIPTION
  Exercises strict bounded syntax, comments, exact Unicode/BOM/newline retention,
  declared profile identity and conflict recovery. No Terminal settings file,
  application, process environment or Windows state is read or changed.
.EXAMPLE
  Invoke-Pester .\tests\TerminalJsonc.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7; Pester 5.x.
  Version: Repository test fixture; file integration and native acceptance are separate.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.TerminalJsonc.psm1') -Force
  $script:First='{11111111-1111-1111-1111-111111111111}'
  $script:Second='{22222222-2222-2222-2222-222222222222}'
  $script:Third='{33333333-3333-3333-3333-333333333333}'
  $script:ProfileJson='"profiles":{"defaults":{},"list":[{"guid":"'+$First+'","name":"Original"},{"guid":"'+$Second+'","name":"Next"}]}'
  function Get-TerminalFixtureBytes {
    param([string]$Text,[switch]$Bom)
    $codec=[Text.UTF8Encoding]::new([bool]$Bom,$true)
    ,([byte[]](@($codec.GetPreamble())+@($codec.GetBytes($Text))))
  }
  function Get-TerminalFixtureText {
    param([byte[]]$Bytes)
    [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xfeff)
  }
}
Describe 'Terminal JSONC inspection' {
  It 'inspects root identity independently of nested fields and quoted comments' {
    $text='/* banner */ {"defaultProfile":"'+$First+'","unknown":{"defaultProfile":"nested","url":"https://host/path/*literal*/","escape":"quote: \""},'+$ProfileJson+',} // footer'
    $result=Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)
    $result.DefaultProfile | Should -BeExactly $First
    $result.Profiles.Count | Should -Be 2
    $result.MutationAuthorized | Should -BeFalse
    $result.AvailabilityVerified | Should -BeFalse
    $result.InstanceVerified | Should -BeFalse
  }
  It 'decodes escaped root keys and valid Unicode surrogate pairs without rewriting them' {
    $text='{"\u0064efaultProfile":"'+$First+'","label":"\uD83D\uDE80",'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    (Get-TerminalFixtureText $patch.Bytes) | Should -BeExactly $text.Replace('"\u0064efaultProfile":"'+$First+'"','"\u0064efaultProfile":"'+$Second+'"')
  }
  It 'supports old profile arrays without converting their schema' {
    $text='{"profiles":[{"guid":"'+$First+'","name":"Original"}],"defaultProfile":"Original"}'
    $result=Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)
    $result.Profiles[0].Id | Should -BeExactly $First
    $result.DefaultProfile | Should -BeExactly 'Original'
  }
  It 'retains source declarations without claiming dynamic profile availability' {
    $text='{"profiles":{"list":[{"guid":"'+$First+'","source":"Windows.Terminal.Wsl"}]}}'
    $result=Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)
    $result.Profiles[0].Source | Should -BeExactly 'Windows.Terminal.Wsl'
    $result.Profiles[0].AvailabilityVerified | Should -BeFalse
  }
  It 'rejects malformed or unsupported syntax: <Case>' -ForEach @(
    @{Case='unterminated comment';Text='{/* never closes'},
    @{Case='unterminated string';Text='{"x":"'},
    @{Case='single quotes';Text="{'x':1}"},
    @{Case='unquoted key';Text='{x:1}'},
    @{Case='missing comma';Text='{"x":1 "y":2}'},
    @{Case='multiple commas';Text='{"x":1,,}'},
    @{Case='leading zero';Text='{"x":01}'},
    @{Case='NaN';Text='{"x":NaN}'},
    @{Case='invalid escape';Text='{"x":"\q"}'},
    @{Case='unpaired surrogate';Text='{"x":"\uD800"}'},
    @{Case='trailing content';Text='{} true'},
    @{Case='nonobject root';Text='[]'},
    @{Case='duplicate key';Text='{"x":1,"x":2}'},
    @{Case='escaped duplicate';Text='{"defaultProfile":"a","\u0064efaultProfile":"b"}'},
    @{Case='nested duplicate';Text='{"unknown":{"x":1,"x":2}}'},
    @{Case='invalid default type';Text='{"defaultProfile":false}'},
    @{Case='invalid profiles type';Text='{"profiles":"wrong"}'},
    @{Case='invalid list type';Text='{"profiles":{"list":{}}}'},
    @{Case='invalid hidden type';Text='{"profiles":{"list":[{"hidden":"false"}]}}'}
  ) {
    {Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $Text)} | Should -Throw
  }
  It 'accepts JSON number forms, literals and trailing array commas in unknown fields' {
    $text='{"unknown":[0,-0,1.25,1e+20,-4E-2,true,false,null,],'+$ProfileJson+'}'
    (Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $text)).Profiles.Count | Should -Be 2
  }
  It 'refuses invalid UTF-8, UTF-16 and the size/depth/node limits' {
    {Get-RideTerminalDefaultProfileDocument ([byte[]]@(255,255,255))} | Should -Throw '*UTF-8*'
    {Get-RideTerminalDefaultProfileDocument ([Text.Encoding]::Unicode.GetBytes('{}'))} | Should -Throw
    {Get-RideTerminalDefaultProfileDocument ([byte[]]::new(1048577))} | Should -Throw '*1 MiB*'
    $deep='{"x":'+('['*66)+'0'+(']'*66)+'}'
    {Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $deep)} | Should -Throw '*limit*'
    $wide='{"x":['+('0,'*32769)+'0]}'
    {Get-RideTerminalDefaultProfileDocument (Get-TerminalFixtureBytes $wide)} | Should -Throw '*limit*'
  }
}

Describe 'Current-user packaged Terminal instance discovery' {
  It 'keeps Stable and Preview package identities bound to separate paths while marking injected records unverified' {
    $localRoot=Join-Path $TestDrive 'LocalAppData'
    New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
    $stableFamily='Microsoft.WindowsTerminal_8wekyb3d8bbwe'
    $previewFamily='Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe'
    $stablePath=Join-Path $localRoot "Packages/$stableFamily/LocalState/settings.json"
    $previewPath=Join-Path $localRoot "Packages/$previewFamily/LocalState/settings.json"
    New-Item -ItemType Directory -Path (Split-Path -Parent $stablePath) -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $previewPath) -Force | Out-Null
    $text='{'+$ProfileJson+ ',"defaultProfile":"'+$First+'"}'
    [IO.File]::WriteAllBytes($stablePath,(Get-TerminalFixtureBytes $text))
    [IO.File]::WriteAllBytes($previewPath,(Get-TerminalFixtureBytes ('{"defaultProfile":"'+$Second+'",'+$ProfileJson+'}')))
    $packages=@(
      [pscustomobject]@{Name='Microsoft.WindowsTerminal';PackageFamilyName=$stableFamily;PackageFullName='Microsoft.WindowsTerminal_1.0.0.0_x64__8wekyb3d8bbwe';Version='1.0.0.0'},
      [pscustomobject]@{Name='Microsoft.WindowsTerminalPreview';PackageFamilyName=$previewFamily;PackageFullName='Microsoft.WindowsTerminalPreview_1.0.0.0_x64__8wekyb3d8bbwe';Version='1.0.0.0'}
    )

    $instances=@(Get-RideTerminalInstalledInstances -LocalAppDataPath $localRoot -AppxPackages $packages)

    $instances.Count|Should -Be 2
    ($instances|Where-Object PackageName -eq 'Microsoft.WindowsTerminal').SettingsPath|Should -BeExactly ([IO.Path]::GetFullPath($stablePath))
    ($instances|Where-Object PackageName -eq 'Microsoft.WindowsTerminal').DefaultProfile|Should -BeExactly $First
    ($instances|Where-Object PackageName -eq 'Microsoft.WindowsTerminalPreview').SettingsPath|Should -BeExactly ([IO.Path]::GetFullPath($previewPath))
    ($instances|Where-Object PackageName -eq 'Microsoft.WindowsTerminalPreview').DefaultProfile|Should -BeExactly $Second
    foreach($instance in $instances){
      $instance.InventorySource|Should -BeExactly 'InjectedUnverified'
      $instance.InstanceVerified|Should -BeFalse
      $instance.ProfileAvailabilityVerified|Should -BeFalse
      $instance.MutationAuthorized|Should -BeFalse
      $instance.SettingsFilePresent|Should -BeTrue
    }
  }

  It 'reports an installed package without creating its absent settings file' {
    $localRoot=Join-Path $TestDrive 'LocalAppData'
    New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
    $family='Microsoft.WindowsTerminalCanary_8wekyb3d8bbwe'
    $path=Join-Path $localRoot "Packages/$family/LocalState/settings.json"
    $package=[pscustomobject]@{Name='Microsoft.WindowsTerminalCanary';PackageFamilyName=$family;PackageFullName='Microsoft.WindowsTerminalCanary_1.0.0.0_x64__8wekyb3d8bbwe';Version='1.0.0.0'}

    $instance=Get-RideTerminalInstalledInstances -LocalAppDataPath $localRoot -AppxPackages @($package)

    $instance.SettingsFilePresent|Should -BeFalse
    $instance.SettingsPath|Should -BeExactly ([IO.Path]::GetFullPath($path))
    $instance.Profiles|Should -BeNullOrEmpty
    Test-Path -LiteralPath $path|Should -BeFalse
  }

  It 'ignores package registrations outside the documented Terminal package names' {
    $localRoot=Join-Path $TestDrive 'LocalAppData'
    New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
    $package=[pscustomobject]@{Name='Microsoft.WindowsTerminalExperimental';PackageFamilyName='Microsoft.WindowsTerminalExperimental_8wekyb3d8bbwe';PackageFullName='unexpected';Version='1.0.0.0'}

    @(Get-RideTerminalInstalledInstances -LocalAppDataPath $localRoot -AppxPackages @($package)).Count|Should -Be 0
  }

  It 'rejects a known package name paired with an unexpected family identity' {
    $localRoot=Join-Path $TestDrive 'LocalAppData'
    New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
    $package=[pscustomobject]@{Name='Microsoft.WindowsTerminal';PackageFamilyName='UnexpectedTerminal_8wekyb3d8bbwe';PackageFullName='unexpected';Version='1.0.0.0'}

    {Get-RideTerminalInstalledInstances -LocalAppDataPath $localRoot -AppxPackages @($package)}|Should -Throw '*does not match the documented Windows Terminal identity*'
  }

  It 'rejects duplicate current-user records for the same packaged distribution' {
    $localRoot=Join-Path $TestDrive 'LocalAppData'
    New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
    $family='Microsoft.WindowsTerminal_8wekyb3d8bbwe'
    $package=[pscustomobject]@{Name='Microsoft.WindowsTerminal';PackageFamilyName=$family;PackageFullName='Microsoft.WindowsTerminal_1.0.0.0_x64__8wekyb3d8bbwe';Version='1.0.0.0'}

    {Get-RideTerminalInstalledInstances -LocalAppDataPath $localRoot -AppxPackages @($package,$package)}|Should -Throw '*More than one current-user package record*'
  }

  It 'refuses settings data above the inspection size limit' {
    $localRoot=Join-Path $TestDrive 'LocalAppData'
    New-Item -ItemType Directory -Path $localRoot -Force | Out-Null
    $family='Microsoft.WindowsTerminal_8wekyb3d8bbwe'
    $path=Join-Path $localRoot "Packages/$family/LocalState/settings.json"
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    [IO.File]::WriteAllBytes($path,(New-Object byte[] (1MB+1)))
    $package=[pscustomobject]@{Name='Microsoft.WindowsTerminal';PackageFamilyName=$family;PackageFullName='Microsoft.WindowsTerminal_1.0.0.0_x64__8wekyb3d8bbwe';Version='1.0.0.0'}

    {Get-RideTerminalInstalledInstances -LocalAppDataPath $localRoot -AppxPackages @($package)}|Should -Throw '*reparse point or exceeds the 1 MiB inspection limit*'
  }
}

Describe 'Live packaged Terminal instance selection for the guarded writer' {
  BeforeEach {
    $script:TerminalInventoryRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TerminalInventoryRoot | Out-Null
    $script:TerminalInventoryFamily = 'Microsoft.WindowsTerminal_8wekyb3d8bbwe'
    $script:TerminalInventoryPackage = [pscustomobject]@{
      Name='Microsoft.WindowsTerminal'
      PackageFamilyName=$script:TerminalInventoryFamily
      PackageFullName='Microsoft.WindowsTerminal_1.0.0.0_x64__8wekyb3d8bbwe'
      Version='1.0.0.0'
    }
    $script:TerminalInventorySettingsPath = Join-Path $script:TerminalInventoryRoot "Packages/$script:TerminalInventoryFamily/LocalState/settings.json"
    New-Item -ItemType Directory -Path (Split-Path -Parent $script:TerminalInventorySettingsPath) -Force | Out-Null
    $script:TerminalInventoryText = '{"defaultProfile":"'+$First+'",'+$ProfileJson+'}'
    $script:TerminalInventorySettingsBytes = Get-TerminalFixtureBytes $script:TerminalInventoryText
    $script:TerminalInventorySnapshotPath = Join-Path $script:TerminalInventoryRoot 'recovery.json'
    $script:TerminalInventoryComputerName = $env:COMPUTERNAME
    $script:TerminalInventoryUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  }

  It 'selects one live package identity and restores exact settings bytes' {
    [IO.File]::WriteAllBytes($script:TerminalInventorySettingsPath,$script:TerminalInventorySettingsBytes)
    Mock Get-AppxPackage -ModuleName RIDE.TerminalJsonc { @($script:TerminalInventoryPackage) }

    $applied=Set-RideTerminalInstalledInstanceDefaultProfile -PackageName 'Microsoft.WindowsTerminal' -LocalAppDataPath $script:TerminalInventoryRoot -ExpectedComputerName $script:TerminalInventoryComputerName -ExpectedUserSid $script:TerminalInventoryUserSid -ProfileId $Second -SnapshotPath $script:TerminalInventorySnapshotPath -Confirm:$false

    $applied.InstanceVerified|Should -BeTrue
    $applied.ProfileAvailabilityVerified|Should -BeFalse
    $applied.PackageFullName|Should -BeExactly $script:TerminalInventoryPackage.PackageFullName
    $applied.SettingsPath|Should -BeExactly ([IO.Path]::GetFullPath($script:TerminalInventorySettingsPath))
    $applied.Applied|Should -BeTrue
    $applied.ReadbackVerified|Should -BeTrue
    (Get-RideTerminalDefaultProfileDocument ([IO.File]::ReadAllBytes($script:TerminalInventorySettingsPath))).DefaultProfile|Should -BeExactly $Second

    $restored=Restore-RideTerminalDefaultProfileFile -SettingsPath $script:TerminalInventorySettingsPath -ExpectedComputerName $script:TerminalInventoryComputerName -ExpectedUserSid $script:TerminalInventoryUserSid -SnapshotPath $script:TerminalInventorySnapshotPath -Confirm:$false
    $restored.Restored|Should -BeTrue
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:TerminalInventorySettingsPath))|Should -BeExactly ([Convert]::ToBase64String($script:TerminalInventorySettingsBytes))
  }

  It 'honors WhatIf without writing settings or recovery data' {
    [IO.File]::WriteAllBytes($script:TerminalInventorySettingsPath,$script:TerminalInventorySettingsBytes)
    Mock Get-AppxPackage -ModuleName RIDE.TerminalJsonc { @($script:TerminalInventoryPackage) }

    $result=Set-RideTerminalInstalledInstanceDefaultProfile -PackageName 'Microsoft.WindowsTerminal' -LocalAppDataPath $script:TerminalInventoryRoot -ExpectedComputerName $script:TerminalInventoryComputerName -ExpectedUserSid $script:TerminalInventoryUserSid -ProfileId $Second -SnapshotPath $script:TerminalInventorySnapshotPath -WhatIf

    $result.Applied|Should -BeFalse
    $result.Changed|Should -BeTrue
    $result.ReadbackVerified|Should -BeFalse
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:TerminalInventorySettingsPath))|Should -BeExactly ([Convert]::ToBase64String($script:TerminalInventorySettingsBytes))
    Test-Path -LiteralPath $script:TerminalInventorySnapshotPath|Should -BeFalse
  }

  It 'refuses a live package registration without an existing settings file' {
    Mock Get-AppxPackage -ModuleName RIDE.TerminalJsonc { @($script:TerminalInventoryPackage) }

    {Set-RideTerminalInstalledInstanceDefaultProfile -PackageName 'Microsoft.WindowsTerminal' -LocalAppDataPath $script:TerminalInventoryRoot -ExpectedComputerName $script:TerminalInventoryComputerName -ExpectedUserSid $script:TerminalInventoryUserSid -ProfileId $Second -SnapshotPath $script:TerminalInventorySnapshotPath -Confirm:$false} | Should -Throw '*does not create it*'
    Test-Path -LiteralPath $script:TerminalInventorySettingsPath|Should -BeFalse
    Test-Path -LiteralPath $script:TerminalInventorySnapshotPath|Should -BeFalse
  }

  It 'requires an exact unique package registration' {
    Mock Get-AppxPackage -ModuleName RIDE.TerminalJsonc { @() }

    {Set-RideTerminalInstalledInstanceDefaultProfile -PackageName 'Microsoft.WindowsTerminal' -LocalAppDataPath $script:TerminalInventoryRoot -ExpectedComputerName $script:TerminalInventoryComputerName -ExpectedUserSid $script:TerminalInventoryUserSid -ProfileId $Second -SnapshotPath $script:TerminalInventorySnapshotPath -Confirm:$false} | Should -Throw '*found 0*'
    Test-Path -LiteralPath $script:TerminalInventorySnapshotPath|Should -BeFalse
  }

  It 'validates the current computer and user even when previewing' {
    [IO.File]::WriteAllBytes($script:TerminalInventorySettingsPath,$script:TerminalInventorySettingsBytes)
    Mock Get-AppxPackage -ModuleName RIDE.TerminalJsonc { @($script:TerminalInventoryPackage) }

    {Set-RideTerminalInstalledInstanceDefaultProfile -PackageName 'Microsoft.WindowsTerminal' -LocalAppDataPath $script:TerminalInventoryRoot -ExpectedComputerName 'OTHER-HOST' -ExpectedUserSid $script:TerminalInventoryUserSid -ProfileId $Second -SnapshotPath $script:TerminalInventorySnapshotPath -WhatIf} | Should -Throw '*computer name*'
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($script:TerminalInventorySettingsPath))|Should -BeExactly ([Convert]::ToBase64String($script:TerminalInventorySettingsBytes))
    Test-Path -LiteralPath $script:TerminalInventorySnapshotPath|Should -BeFalse
  }
}

Describe 'Terminal settings file writer and recovery' {
  BeforeEach {
    $script:TerminalFixtureDirectory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TerminalFixtureDirectory | Out-Null
    $script:TerminalSettingsPath = Join-Path $script:TerminalFixtureDirectory 'settings.json'
    $script:TerminalSnapshotPath = Join-Path $script:TerminalFixtureDirectory 'terminal-recovery.json'
    $script:TerminalInitialText = '{"defaultProfile":"'+$First+'",'+$ProfileJson+',"unrelated":1}'
    [IO.File]::WriteAllBytes($script:TerminalSettingsPath,(Get-TerminalFixtureBytes $script:TerminalInitialText -Bom))
    $script:TerminalComputerName = $env:COMPUTERNAME
    $script:TerminalUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  }
  It 'writes after a durable snapshot and restores exact prior bytes' {
    $initial=[Convert]::ToBase64String([IO.File]::ReadAllBytes($TerminalSettingsPath))
    $applied=Set-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath $TerminalSnapshotPath -Confirm:$false
    $applied.Applied | Should -BeTrue
    $applied.ReadbackVerified | Should -BeTrue
    (Test-Path -LiteralPath $TerminalSnapshotPath) | Should -BeTrue
    (Get-RideTerminalDefaultProfileDocument ([IO.File]::ReadAllBytes($TerminalSettingsPath))).DefaultProfile | Should -BeExactly $Second
    $restored=Restore-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -SnapshotPath $TerminalSnapshotPath -Confirm:$false
    $restored.Restored | Should -BeTrue
    $restored.ReadbackVerified | Should -BeTrue
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($TerminalSettingsPath)) | Should -BeExactly $initial
    (Test-Path -LiteralPath $TerminalSnapshotPath) | Should -BeTrue
  }
  It 'preserves unrelated settings edits during restoration' {
    $null=Set-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath $TerminalSnapshotPath -Confirm:$false
    $current=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($TerminalSettingsPath)).TrimStart([char]0xfeff)
    [IO.File]::WriteAllBytes($TerminalSettingsPath,(Get-TerminalFixtureBytes $current.Replace('"unrelated":1','"unrelated":2') -Bom))
    $null=Restore-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -SnapshotPath $TerminalSnapshotPath -Confirm:$false
    $final=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($TerminalSettingsPath)).TrimStart([char]0xfeff)
    $expectedPattern='"defaultProfile":"'+[regex]::Escape($First)+'"'
    $final | Should -Match $expectedPattern
    $final | Should -Match '"unrelated":2'
  }
  It 'refuses identity mismatches and previews without writing or saving' {
    {Set-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName 'OTHER-HOST' -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath $TerminalSnapshotPath -Confirm:$false} | Should -Throw '*computer name*'
    $initial=[Convert]::ToBase64String([IO.File]::ReadAllBytes($TerminalSettingsPath))
    $null=Set-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath $TerminalSnapshotPath -WhatIf
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($TerminalSettingsPath)) | Should -BeExactly $initial
    (Test-Path -LiteralPath $TerminalSnapshotPath) | Should -BeFalse
  }
  It 'refuses restore when the owned profile value has changed' {
    $null=Set-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath $TerminalSnapshotPath -Confirm:$false
    $current=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($TerminalSettingsPath)).TrimStart([char]0xfeff)
    $current=$current.Replace('"defaultProfile":"'+$Second+'"','"defaultProfile":"'+$Third+'"')
    [IO.File]::WriteAllBytes($TerminalSettingsPath,(Get-TerminalFixtureBytes $current -Bom))
    {Restore-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -SnapshotPath $TerminalSnapshotPath -Confirm:$false} | Should -Throw '*conflict*'
  }
  It 'refuses a tampered snapshot and an already locked settings file' {
    $null=Set-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath $TerminalSnapshotPath -Confirm:$false
    $record=[IO.File]::ReadAllText($TerminalSnapshotPath) | ConvertFrom-Json
    $record.ExpectedSha256='0000000000000000000000000000000000000000000000000000000000000000'
    [IO.File]::WriteAllText($TerminalSnapshotPath,(ConvertTo-Json -InputObject $record -Depth 12 -Compress),[Text.UTF8Encoding]::new($false))
    {Restore-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -SnapshotPath $TerminalSnapshotPath -Confirm:$false} | Should -Throw '*snapshot byte hash*'

    $lockedPath=Join-Path $TerminalFixtureDirectory 'locked-settings.json'
    [IO.File]::WriteAllBytes($lockedPath,(Get-TerminalFixtureBytes $TerminalInitialText))
    $lock=[IO.File]::Open($lockedPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
      {Set-RideTerminalDefaultProfileFile -SettingsPath $lockedPath -ExpectedComputerName $TerminalComputerName -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath (Join-Path $TerminalFixtureDirectory 'locked-recovery.json') -Confirm:$false} | Should -Throw
    } finally {$lock.Dispose()}
    (Test-Path -LiteralPath (Join-Path $TerminalFixtureDirectory 'locked-recovery.json')) | Should -BeFalse
  }
  It 'matches Windows computer names and settings paths without case sensitivity' {
    $snapshotPath=Join-Path $TerminalFixtureDirectory 'case-recovery.json'
    $null=Set-RideTerminalDefaultProfileFile -SettingsPath $TerminalSettingsPath -ExpectedComputerName $TerminalComputerName.ToLowerInvariant() -ExpectedUserSid $TerminalUserSid -ProfileId $Second -SnapshotPath $snapshotPath -Confirm:$false
    $lowerPath=$TerminalSettingsPath.ToLowerInvariant()
    $restored=Restore-RideTerminalDefaultProfileFile -SettingsPath $lowerPath -ExpectedComputerName $TerminalComputerName.ToLowerInvariant() -ExpectedUserSid $TerminalUserSid -SnapshotPath $snapshotPath -Confirm:$false
    $restored.Restored | Should -BeTrue
  }
}
Describe 'Terminal narrow patch and recovery' {
  It 'preserves exact bytes through replacement and recovery for BOM <Bom> and <NewlineName>' -ForEach @(
    @{Bom=$false;NewlineName='LF';Newline="`n"},@{Bom=$true;NewlineName='LF';Newline="`n"},
    @{Bom=$false;NewlineName='CRLF';Newline="`r`n"},@{Bom=$true;NewlineName='CRLF';Newline="`r`n"}
  ) {
    $text='// caf'+[char]233+$Newline+'{'+$Newline+'  "defaultProfile" /* keep */ : "Original",'+$Newline+'  '+$ProfileJson+','+$Newline+'  "number":1e+05,'+$Newline+'}'+$Newline
    $bytes=Get-TerminalFixtureBytes $text -Bom:$Bom
    $originalBase64=[Convert]::ToBase64String($bytes)
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $patch.Changed | Should -BeTrue
    $patch.MutationAuthorized | Should -BeFalse
    (Get-TerminalFixtureText $patch.Bytes) | Should -BeExactly $text.Replace(': "Original",',': "'+$Second+'",')
    [Convert]::ToBase64String($bytes) | Should -BeExactly $originalBase64
    $snapshot=$patch.Snapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $restored=Restore-RideTerminalDefaultProfilePatch $patch.Bytes $snapshot
    [Convert]::ToBase64String($restored.Bytes) | Should -BeExactly $originalBase64
  }
  It 'does not rewrite an already selected GUID spelling or escaped literal' {
    $text='{"defaultProfile":"\u007b11111111-1111-1111-1111-111111111111}",'+$ProfileJson+'}'
    $bytes=Get-TerminalFixtureBytes $text
    $patch=New-RideTerminalDefaultProfilePatch $bytes $First
    $patch.Changed | Should -BeFalse
    [Convert]::ToBase64String($patch.Bytes) | Should -BeExactly ([Convert]::ToBase64String($bytes))
    (Restore-RideTerminalDefaultProfilePatch $bytes $patch.Snapshot).Changed | Should -BeFalse
  }
  It 'inserts and removes only its new property while preserving unrelated comments and edits' {
    $text='/* lead */ {'+"`r`n"+' // retain this comment'+"`r`n"+$ProfileJson+',"unknown":1,} // tail'
    $bytes=Get-TerminalFixtureBytes $text -Bom
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $patch.Snapshot.Mode | Should -Be Insert
    (Get-RideTerminalDefaultProfileDocument $patch.Bytes).DefaultProfile | Should -BeExactly $Second
    $edited=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"unknown":1','"unknown":2')) -Bom
    $restored=Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot
    (Get-TerminalFixtureText $restored.Bytes) | Should -BeExactly $text.Replace('"unknown":1','"unknown":2')
    (Restore-RideTerminalDefaultProfilePatch $restored.Bytes $patch.Snapshot).Changed | Should -BeFalse
  }
  It 'preserves unrelated field edits while restoring a previous root string' {
    $text='{"defaultProfile":"'+$First+'","unknown":{"defaultProfile":"nested"},'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    $edited=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"nested"','"changed"'))
    $restored=Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot
    (Get-TerminalFixtureText $restored.Bytes) | Should -BeExactly $text.Replace('"nested"','"changed"')
  }
  It 'refuses modified or removed owned values and tampered snapshots' {
    $text='{"defaultProfile":"'+$First+'",'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    $edited=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"defaultProfile":"'+$Second+'"','"defaultProfile":"operator"'))
    {Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot} | Should -Throw '*conflict*'
    $removed=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    {Restore-RideTerminalDefaultProfilePatch $removed $patch.Snapshot} | Should -Throw '*conflict*'
    $snapshot=$patch.Snapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $snapshot.OriginalLiteral='"other"'
    {Restore-RideTerminalDefaultProfilePatch $patch.Bytes $snapshot} | Should -Throw '*snapshot content*'
  }
  It 'refuses insertion recovery after owned formatting or BOM changes' {
    $bytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $changed=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"defaultProfile": ','"defaultProfile" : '))
    {Restore-RideTerminalDefaultProfilePatch $changed $patch.Snapshot} | Should -Throw '*conflict*'
    {Restore-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes (Get-TerminalFixtureText $patch.Bytes) -Bom) $patch.Snapshot} | Should -Throw '*BOM changed*'
  }
  It 'refuses absent or hidden chosen profiles and duplicate GUIDs' {
    $bytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    {New-RideTerminalDefaultProfilePatch $bytes $Third} | Should -Throw '*visible declaration*'
    {New-RideTerminalDefaultProfilePatch $bytes 'Next'} | Should -Throw '*GUID in braces*'
    $hidden=Get-TerminalFixtureBytes ('{'+$ProfileJson.Replace('"name":"Next"','"name":"Next","hidden":true')+'}')
    {New-RideTerminalDefaultProfilePatch $hidden $Second} | Should -Throw '*visible declaration*'
    $duplicate=Get-TerminalFixtureBytes ('{'+$ProfileJson.Replace($Second,$First)+'}')
    {Get-RideTerminalDefaultProfileDocument $duplicate} | Should -Throw '*Duplicate declared*'
  }
  It 'honors default hidden configuration with an explicit per-profile override' {
    $text='{'+$ProfileJson.Replace('"defaults":{}','"defaults":{"hidden":true}').Replace('"name":"Next"','"name":"Next","hidden":false')+'}'
    $bytes=Get-TerminalFixtureBytes $text
    {New-RideTerminalDefaultProfilePatch $bytes $First} | Should -Throw '*visible declaration*'
    (New-RideTerminalDefaultProfilePatch $bytes $Second).Changed | Should -BeTrue
  }
  It 'refuses recovery when the previous profile disappeared or its name became ambiguous' {
    $text='{"defaultProfile":"Original",'+$ProfileJson+'}'
    $patch=New-RideTerminalDefaultProfilePatch (Get-TerminalFixtureBytes $text) $Second
    $missing=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"name":"Original"','"name":"Renamed"'))
    {Restore-RideTerminalDefaultProfilePatch $missing $patch.Snapshot} | Should -Throw '*Prior default profile*'
    $ambiguous=Get-TerminalFixtureBytes ((Get-TerminalFixtureText $patch.Bytes).Replace('"name":"Next"','"name":"Original"'))
    {Restore-RideTerminalDefaultProfilePatch $ambiguous $patch.Snapshot} | Should -Throw '*Prior default profile*'
  }
  It 'requires a resolvable prior default before creating a recoverable patch' {
    $bytes=Get-TerminalFixtureBytes ('{"defaultProfile":"unknown",'+$ProfileJson+'}')
    {New-RideTerminalDefaultProfilePatch $bytes $Second} | Should -Throw '*Prior default profile*'
  }
  It 'restores inserted-property absence after unrelated properties were prepended' {
    $bytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
    $text=Get-TerminalFixtureText $patch.Bytes
    $edited=Get-TerminalFixtureBytes ('{"newSetting":true,'+$text.Substring(1))
    $restored=Restore-RideTerminalDefaultProfilePatch $edited $patch.Snapshot
    (Get-TerminalFixtureText $restored.Bytes) | Should -BeExactly ('{"newSetting":true,'+$ProfileJson+'}')
  }
  It 'preserves unusual comments, Unicode and layout over multiple synthetic round trips' {
    foreach($separator in @('',"`n","`r`n",'/* : , } [ "/ */',"// nested-looking {`n")){
      $unknown='"opaque":{"quoted":"defaultProfile // not a key","unicode":"'+[char]0x00e6+'","number":-1.2300e+04,}'
      $text='{'+$separator+'"defaultProfile"'+$separator+':'+$separator+'"Original",'+$separator+$ProfileJson+','+$separator+$unknown+'}'+$separator
      $bytes=Get-TerminalFixtureBytes $text
      $patch=New-RideTerminalDefaultProfilePatch $bytes $Second
      $restored=Restore-RideTerminalDefaultProfilePatch $patch.Bytes $patch.Snapshot
      [Convert]::ToBase64String($restored.Bytes) | Should -BeExactly ([Convert]::ToBase64String($bytes))
    }
  }
  It 'completes only supplied visible GUID declarations and filters case-insensitively' {
    $global:RideTerminalTestBytes=Get-TerminalFixtureBytes ('{'+$ProfileJson+'}')
    try {
      $line='New-RideTerminalDefaultProfilePatch -Bytes $global:RideTerminalTestBytes -ProfileId '
      $matches=(TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText
      $matches | Should -Contain ("'"+$First+"'")
      $matches | Should -Contain ("'"+$Second+"'")
      $line+='''{222'
      $matches=(TabExpansion2 -InputScript $line -CursorColumn $line.Length).CompletionMatches.CompletionText
      $matches | Should -Contain ("'"+$Second+"'")
      $matches | Should -Not -Contain ("'"+$First+"'")
    } finally {Remove-Variable -Name RideTerminalTestBytes -Scope Global}
  }
}
