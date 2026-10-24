<#
.SYNOPSIS
  Verify guarded client-component servicing and saved state without calling DISM.
.DESCRIPTION
  Mocks fresh component observations, pending-reboot checks and the native transition.
  All snapshot writes use Pester TestDrive; no system component or registry is changed.
.EXAMPLE
  Invoke-Pester .\tests\ClientComponentLifecycle.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Native DISM, source/network boundary and payload recovery require disposable Windows acceptance.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.ClientComponentLifecycle.psm1') -Force
  function New-LifecycleInventory {
    param([string]$Kind,[string]$Name,[string]$State,[string]$InstallationType='Client',[string]$ProductType='WinNT')
    $row=if($Kind -eq 'Capability'){[pscustomobject]@{Name=$Name;StateObserved=$State;DependenciesVerified=$false;SourceAvailability='Unknown';Selected=$false}}else{[pscustomobject]@{Name=$Name;StateObserved=$State;DependenciesVerified=$false;SourceAvailability='Unknown';Selected=$false}}
    [pscustomobject]@{SchemaVersion=1;Kind='WindowsComponentObservation';ReadyForMutation=$false;RecoverySupported=$false;WindowsContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';InstallationType=$InstallationType;ProductType=$ProductType;NativeProcess=$true;UpdateBuildRevision=$global:RideLifecycleUpdateBuildRevision};Providers=@([pscustomobject]@{Kind=$Kind;Status='Captured';Rows=@($row);Coverage='synthetic'})}
  }
}
Describe 'Guarded OpenSSH Client and Telnet Client lifecycle candidate' {
  BeforeEach {
    $global:RideLifecycleKind='Capability'
    $global:RideLifecycleName='OpenSSH.Client~~~~0.0.1.0'
    $global:RideLifecycleState='NotPresent'
    $global:RideLifecycleNativeCalls=0
    $global:RideLifecycleSourceMode=$null
    $global:RideLifecycleStateDirectory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
    $global:RideLifecycleInstallationType='Client'
    $global:RideLifecycleProductType='WinNT'
    $global:RideLifecycleUpdateBuildRevision=123
    $global:RideLifecycleArchitecture='amd64'
    $global:RideLifecyclePackageBuild='26100'
    Mock Get-RideWindowsComponentInventory -ModuleName RIDE.ClientComponentLifecycle {
      New-LifecycleInventory -Kind $global:RideLifecycleKind -Name $global:RideLifecycleName -State $global:RideLifecycleState -InstallationType $global:RideLifecycleInstallationType -ProductType $global:RideLifecycleProductType
    }
    Mock Test-RideClientComponentPendingReboot -ModuleName RIDE.ClientComponentLifecycle {$false}
    Mock Get-RideClientComponentSourceArchitecture -ModuleName RIDE.ClientComponentLifecycle {$global:RideLifecycleArchitecture}
    Mock Get-RideClientComponentSourcePackageMetadata -ModuleName RIDE.ClientComponentLifecycle {
      [pscustomobject]@{PackageName="OpenSSH-Client-Package~31bf3856ad364e35~$global:RideLifecycleArchitecture~~10.0.$global:RideLifecyclePackageBuild.1"}
    }
    Mock Get-RideClientComponentStateDirectory -ModuleName RIDE.ClientComponentLifecycle {$global:RideLifecycleStateDirectory}
    Mock Initialize-RideClientComponentStateDirectory -ModuleName RIDE.ClientComponentLifecycle {
      $root=$global:RideLifecycleStateDirectory;New-Item -ItemType Directory -Path $root -Force|Out-Null;$root
    }
    Mock Invoke-RideClientComponentNativeTransition -ModuleName RIDE.ClientComponentLifecycle {
      $global:RideLifecycleNativeCalls++
      $global:RideLifecycleSourceMode=$SourceMode
      if($Kind -eq 'Capability'){$global:RideLifecycleState=if($DesiredState -eq 'Present'){'Installed'}else{'NotPresent'}}
      elseif($RestoreRemovedPayload){$global:RideLifecycleState='DisabledWithPayloadRemoved'}
      else{$global:RideLifecycleState=if($DesiredState -eq 'Present'){'Enabled'}else{'Disabled'}}
      [pscustomobject]@{RestartNeeded=$false}
    }
  }
  AfterAll {
    Remove-Variable RideLifecycleKind,RideLifecycleName,RideLifecycleState,RideLifecycleNativeCalls,RideLifecycleSourceMode,RideLifecycleStateDirectory,RideLifecycleInstallationType,RideLifecycleProductType,RideLifecycleUpdateBuildRevision,RideLifecycleArchitecture,RideLifecyclePackageBuild -Scope Global -ErrorAction SilentlyContinue
  }
  It 'retains the saved state and blocks removal when restoring prior absence lacks a validated recovery source' {
    $result=Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $result.Status|Should -BeExactly Applied
    $result.BeforeState|Should -BeExactly NotPresent
    $result.AfterState|Should -BeExactly Installed
    $result.PostStateVerified|Should -BeTrue
    $result.ExactPayloadRecoverySupported|Should -BeFalse
    (Test-Path -LiteralPath $result.SnapshotPath)|Should -BeTrue
    $nativeCallsBeforeRestore=$RideLifecycleNativeCalls
    {Restore-RideClientComponentTransition -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*without a validated matching recovery source*'
    $RideLifecycleNativeCalls|Should -Be $nativeCallsBeforeRestore
    $RideLifecycleState|Should -BeExactly Installed
    (Test-Path -LiteralPath $result.SnapshotPath)|Should -BeTrue
  }
  It 'performs no servicing or snapshot write for WhatIf and observed no-change' {
    $whatIf=Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -WhatIf
    $whatIf.Status|Should -BeExactly WhatIf
    $RideLifecycleNativeCalls|Should -Be 0
    (Test-Path -LiteralPath $RideLifecycleStateDirectory)|Should -BeFalse
    $global:RideLifecycleState='Installed'
    $same=Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $same.Status|Should -BeExactly NoChange
    $same.RunId|Should -BeNullOrEmpty
    $RideLifecycleNativeCalls|Should -Be 0
  }
  It 'refuses servicing with a pending reboot' {
    Mock Test-RideClientComponentPendingReboot -ModuleName RIDE.ClientComponentLifecycle {$true}
    {Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*restart is pending*'
    $RideLifecycleNativeCalls|Should -Be 0
    (Test-Path -LiteralPath $RideLifecycleStateDirectory)|Should -BeFalse
  }
  It 'refuses Server targets until their support is declared' {
    $global:RideLifecycleInstallationType='Server'
    $global:RideLifecycleProductType='ServerNT'
    {Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*Server targets are not declared*'
    $RideLifecycleNativeCalls|Should -Be 0
    (Test-Path -LiteralPath $RideLifecycleStateDirectory)|Should -BeFalse
  }
  It 'refuses client targets older than Windows 11 before inventory or state capture' {
    {Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 19045 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*limited to Windows 11 builds*'
    Should -Invoke Get-RideWindowsComponentInventory -ModuleName RIDE.ClientComponentLifecycle -Times 0
    $RideLifecycleNativeCalls|Should -Be 0
    (Test-Path -LiteralPath $RideLifecycleStateDirectory)|Should -BeFalse
  }
  It 'validates the exact OpenSSH LocalSource CAB identity and target build before servicing' {
    {Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode LocalSource -SourcePath 'D:\Missing-FOD-Source' -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*does not exist*'
    $RideLifecycleNativeCalls|Should -Be 0
    $sourceRoot=Join-Path $TestDrive 'fod';New-Item -ItemType Directory -Path $sourceRoot|Out-Null
    {Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode LocalSource -SourcePath $sourceRoot -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*must contain the exact OpenSSH Client CAB*'
    $cabPath=Join-Path $sourceRoot 'OpenSSH-Client-Package~31bf3856ad364e35~amd64~~.cab'
    [IO.File]::WriteAllBytes($cabPath,[byte[]](1,2,3))
    $result=Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode LocalSource -SourcePath $sourceRoot -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $result.Status|Should -BeExactly Applied
    $result.SourceValidated|Should -BeTrue
    $result.NetworkBoundaryVerified|Should -BeFalse
    $RideLifecycleNativeCalls|Should -Be 1
    $record=Get-Content -LiteralPath $result.SnapshotPath -Raw|ConvertFrom-Json
    $record.SourcePackageName|Should -BeExactly 'OpenSSH-Client-Package~31bf3856ad364e35~amd64~~10.0.26100.1'
    $record.SourceSha256|Should -Match '^[0-9a-f]{64}$'
    $record.SourceValidated|Should -BeTrue
  }
  It 'refuses an OpenSSH LocalSource CAB for a different Windows build before state capture' {
    $sourceRoot=Join-Path $TestDrive 'wrong-build';New-Item -ItemType Directory -Path $sourceRoot|Out-Null
    [IO.File]::WriteAllBytes((Join-Path $sourceRoot 'OpenSSH-Client-Package~31bf3856ad364e35~amd64~~.cab'),[byte[]](1,2,3))
    $global:RideLifecyclePackageBuild='26000'
    {Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode LocalSource -SourcePath $sourceRoot -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*does not match target build*'
    $RideLifecycleNativeCalls|Should -Be 0
    (Test-Path -LiteralPath $RideLifecycleStateDirectory)|Should -BeFalse
  }
  It 'keeps Telnet LocalSource servicing blocked until its source requirements are verified' {
    $global:RideLifecycleKind='OptionalFeature'
    $global:RideLifecycleName='TelnetClient'
    $global:RideLifecycleState='Disabled'
    $sourceRoot=Join-Path $TestDrive 'telnet-source';New-Item -ItemType Directory -Path $sourceRoot|Out-Null
    {Invoke-RideClientComponentTransition -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode LocalSource -SourcePath $sourceRoot -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*only for the non-satellite OpenSSH Client capability*'
    $RideLifecycleNativeCalls|Should -Be 0
    (Test-Path -LiteralPath $RideLifecycleStateDirectory)|Should -BeFalse
  }
  It 'revalidates the same OpenSSH LocalSource CAB before restoring Present' {
    $sourceRoot=Join-Path $TestDrive 'restore-source';New-Item -ItemType Directory -Path $sourceRoot|Out-Null
    $cabPath=Join-Path $sourceRoot 'OpenSSH-Client-Package~31bf3856ad364e35~amd64~~.cab'
    [IO.File]::WriteAllBytes($cabPath,[byte[]](1,2,3))
    $sha=(Get-FileHash -LiteralPath $cabPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $runId='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    New-Item -ItemType Directory -Path $RideLifecycleStateDirectory -Force|Out-Null
    $record=[pscustomobject]@{SchemaVersion=1;Kind='ClientComponentState';ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=123;ProductType='WinNT';ProviderKind='Capability';Name=$RideLifecycleName;BeforeState='Installed';DesiredState='Absent';ExpectedState='NotPresent';SourceMode='LocalSource';SourcePath=$sourceRoot;SourceValidated=$true;SourceArchitecture='amd64';SourcePackageName='OpenSSH-Client-Package~31bf3856ad364e35~amd64~~10.0.26100.1';SourceSha256=$sha;ExactPayloadRecoverySupported=$false}
    [IO.File]::WriteAllText((Join-Path $RideLifecycleStateDirectory ($runId+'.json')),($record|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    $result=Restore-RideClientComponentTransition -RunId $runId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $result.Status|Should -BeExactly Restored
    $RideLifecycleNativeCalls|Should -Be 1
    $RideLifecycleState|Should -BeExactly Installed
  }
  It 'retains the saved OpenSSH state when its LocalSource CAB hash changed' {
    $sourceRoot=Join-Path $TestDrive 'changed-source';New-Item -ItemType Directory -Path $sourceRoot|Out-Null
    $cabPath=Join-Path $sourceRoot 'OpenSSH-Client-Package~31bf3856ad364e35~amd64~~.cab'
    [IO.File]::WriteAllBytes($cabPath,[byte[]](1,2,3))
    $oldSha=(Get-FileHash -LiteralPath $cabPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllBytes($cabPath,[byte[]](4,5,6))
    $runId='cccccccccccccccccccccccccccccccc'
    New-Item -ItemType Directory -Path $RideLifecycleStateDirectory -Force|Out-Null
    $record=[pscustomobject]@{SchemaVersion=1;Kind='ClientComponentState';ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=123;ProductType='WinNT';ProviderKind='Capability';Name=$RideLifecycleName;BeforeState='Installed';DesiredState='Absent';ExpectedState='NotPresent';SourceMode='LocalSource';SourcePath=$sourceRoot;SourceValidated=$true;SourceArchitecture='amd64';SourcePackageName='OpenSSH-Client-Package~31bf3856ad364e35~amd64~~10.0.26100.1';SourceSha256=$oldSha;ExactPayloadRecoverySupported=$false}
    [IO.File]::WriteAllText((Join-Path $RideLifecycleStateDirectory ($runId+'.json')),($record|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    {Restore-RideClientComponentTransition -RunId $runId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*CAB changed since the saved run*'
    $RideLifecycleNativeCalls|Should -Be 0
    $RideLifecycleState|Should -BeExactly NotPresent
    (Test-Path -LiteralPath (Join-Path $RideLifecycleStateDirectory ($runId+'.json')))|Should -BeTrue
  }
  It 'refuses LocalSource restore to Present when an older saved record lacks validation' {
    $global:RideLifecycleKind='OptionalFeature'
    $global:RideLifecycleName='TelnetClient'
    $global:RideLifecycleState='Disabled'
    $runId='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    New-Item -ItemType Directory -Path $RideLifecycleStateDirectory -Force|Out-Null
    $record=[pscustomobject]@{SchemaVersion=1;Kind='ClientComponentState';ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=123;ProductType='WinNT';ProviderKind='OptionalFeature';Name='TelnetClient';BeforeState='Enabled';DesiredState='Absent';ExpectedState='Disabled';SourceMode='LocalSource';SourcePath='D:\Sources\FOD';ExactPayloadRecoverySupported=$false}
    [IO.File]::WriteAllText((Join-Path $RideLifecycleStateDirectory ($runId+'.json')),($record|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    {Restore-RideClientComponentTransition -RunId $runId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*validated matching LocalSource*'
    $RideLifecycleNativeCalls|Should -Be 0
    $RideLifecycleState|Should -BeExactly Disabled
    (Test-Path -LiteralPath (Join-Path $RideLifecycleStateDirectory ($runId+'.json')))|Should -BeTrue
  }
  It 'blocks removal until a matching recovery source can be validated' {
    $global:RideLifecycleState='Installed'
    {Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Absent -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*matching recovery source is validated*'
    $RideLifecycleNativeCalls|Should -Be 0
    (Test-Path -LiteralPath $RideLifecycleStateDirectory)|Should -BeFalse
  }
  It 'blocks Telnet payload removal when restoring a payload-removed prior state without validation' {
    $global:RideLifecycleKind='OptionalFeature'
    $global:RideLifecycleName='TelnetClient'
    $global:RideLifecycleState='DisabledWithPayloadRemoved'
    $result=Invoke-RideClientComponentTransition -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $result.Status|Should -BeExactly Applied
    $result.AfterState|Should -BeExactly Enabled
    $nativeCallsBeforeRestore=$RideLifecycleNativeCalls
    {Restore-RideClientComponentTransition -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*without a validated matching recovery source*'
    $RideLifecycleNativeCalls|Should -Be $nativeCallsBeforeRestore
    $RideLifecycleState|Should -BeExactly Enabled
    (Test-Path -LiteralPath $result.SnapshotPath)|Should -BeTrue
  }
  It 'restores a disabled Telnet feature without removing its payload' {
    $global:RideLifecycleKind='OptionalFeature'
    $global:RideLifecycleName='TelnetClient'
    $global:RideLifecycleState='Disabled'
    $result=Invoke-RideClientComponentTransition -Kind OptionalFeature -Name TelnetClient -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $result.Status|Should -BeExactly Applied
    $result.AfterState|Should -BeExactly Enabled
    $restored=Restore-RideClientComponentTransition -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $restored.Status|Should -BeExactly Restored
    $restored.State|Should -BeExactly Disabled
    Should -Invoke Invoke-RideClientComponentNativeTransition -ModuleName RIDE.ClientComponentLifecycle -ParameterFilter {$DesiredState -eq 'Absent' -and -not $RestoreRemovedPayload} -Times 1
  }
  It 'refuses restore after component state drift' {
    $result=Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $global:RideLifecycleState='NotPresent'
    {Restore-RideClientComponentTransition -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*state drifted*'
  }
  It 'refuses restore after the target servicing revision changes' {
    $result=Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $callsBeforeRestore=$RideLifecycleNativeCalls
    $global:RideLifecycleUpdateBuildRevision=124
    {Restore-RideClientComponentTransition -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*target revision or literal state drifted*'
    $RideLifecycleNativeCalls|Should -Be $callsBeforeRestore
    $RideLifecycleState|Should -BeExactly Installed
  }
  It 'previews restore without changing the component or consuming its saved state' {
    $global:RideLifecycleKind='OptionalFeature'
    $global:RideLifecycleName='TelnetClient'
    $global:RideLifecycleState='Disabled'
    $result=Invoke-RideClientComponentTransition -Kind OptionalFeature -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $callsBeforeRestore=$RideLifecycleNativeCalls
    $preview=Restore-RideClientComponentTransition -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -WhatIf
    $preview.Status|Should -BeExactly WhatIf
    $RideLifecycleNativeCalls|Should -Be $callsBeforeRestore
    $RideLifecycleState|Should -BeExactly Enabled
    (Test-Path -LiteralPath $result.SnapshotPath)|Should -BeTrue
  }
  It 'refuses a modified saved provider/name identity before calling DISM' {
    $result=Invoke-RideClientComponentTransition -Kind Capability -Name $RideLifecycleName -DesiredState Present -SourceMode Online -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false
    $record=Get-Content -LiteralPath $result.SnapshotPath -Raw|ConvertFrom-Json
    $record.Name='UnapprovedComponent'
    [IO.File]::WriteAllText($result.SnapshotPath,(ConvertTo-Json -InputObject $record -Depth 10 -Compress),[Text.UTF8Encoding]::new($false))
    $callsBeforeRestore=$RideLifecycleNativeCalls
    {Restore-RideClientComponentTransition -RunId $result.RunId -ExpectedComputerName TEST-VM -ExpectedBuild 26100 -ExpectedEditionId Professional -LogDirectory $TestDrive -Confirm:$false}|Should -Throw '*supported provider, client identity, source and state schema*'
    $RideLifecycleNativeCalls|Should -Be $callsBeforeRestore
  }
}
