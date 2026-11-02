<#
.SYNOPSIS
  Verify guarded Sysmon fixture and three-profile orchestration using fake providers.
.DESCRIPTION
  No Sysmon process, service or event mutation occurs. Real TestDrive files retain
  inert XML and private user-scoped evidence; native and machine-state providers
  are mocked. A fixture preparation result never becomes native acceptance.
.EXAMPLE
  Invoke-Pester ./tests/SysmonAcceptance.Tests.ps1
.NOTES
  Compatibility: Pester 5 on native PowerShell 5.1 and 7. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.SysmonAcceptance.psm1') -Force}
Describe 'Guarded Sysmon configuration acceptance' {
  InModuleScope RIDE.SysmonAcceptance {
    BeforeEach {
      $script:request=[guid]::NewGuid().ToString('N')
      $script:baselinePath=Join-Path $TestDrive 'baseline.xml'
      [IO.File]::WriteAllText($script:baselinePath,'<Sysmon schemaversion="4.91"><HashAlgorithms>SHA256</HashAlgorithms></Sysmon>',[Text.UTF8Encoding]::new($false))
      $script:baselineHash=(Get-FileHash $script:baselinePath).Hash
      $script:environment=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';InstallationType='Client';NativeProcess=$true;Architecture='AMD64';Administrator=$true;Manufacturer='Microsoft Corporation';Model='Virtual Machine';GuestMarker='1';IntegrationMarker='1';RunMarker=$script:request}
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';ServiceState='Running';ExecutableSha256=('A'*64)}
      $script:current=[pscustomobject]@{RecordId=100L;Sha256=$script:baselineHash;ConfigurationPath=$script:baselinePath}
      $script:errorId=0L;$script:nextId=0;$script:events=[Collections.Generic.List[string]]::new()
      $script:profiles=@(1..3|ForEach-Object {[pscustomobject]@{ArtifactId=('profile-'+$_);Path=('source-'+$_+'.xml');Sha256=([string]$_*64);Bytes=100}})
      $script:parameters=@{RunId=$script:request;InputDirectory=$TestDrive;BaselineConfigurationPath=$script:baselinePath;BaselineConfigurationSha256=$script:baselineHash;ExecutablePath='C:\Windows\Sysmon64.exe';ExpectedExecutableSha256=('A'*64);ExpectedSysmonVersion='15.21';ExpectedComputerName=$script:environment.ComputerName;ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';EvidenceRoot=$TestDrive;DisposableVm=$true;Confirm=$false}
      Mock Get-RideSysmonAcceptanceEnvironment {$script:environment}
      Mock Read-RideSysmonAcceptanceSources {[pscustomobject]@{ReleaseTag='fixture';Configurations=$script:profiles}}
      Mock Get-RideSysmonAcceptanceSnapshot {[pscustomobject]@{Context=$script:context;ConfigurationEvent=$script:current;LastErrorRecordId=$script:errorId}}
      Mock Assert-RideSysmonAcceptanceRecords {}
      Mock New-RidePrivateFileStream {param($Path,$Scope) & (Get-Module RIDE.PrivateFiles) {param($path) New-RidePrivateFileStream -Path $path -Scope User} $Path}
      Mock Set-RideSysmonConfiguration {
        param($ConfigurationSha256,$StateDirectory,$WhatIf)
        if($WhatIf){$script:events.Add('Preview');return}
        if($script:current.Sha256 -ceq $ConfigurationSha256){$script:events.Add('Repeat');return [pscustomobject]@{SchemaVersion=1;Status='AlreadyDesired'}}
        $script:events.Add('Apply');$script:nextId++;$id=$script:nextId.ToString('x32')
        [IO.File]::WriteAllText((Join-Path $StateDirectory ($id+'.sysmon.intent.json')),'inert test intent')
        $script:current=[pscustomobject]@{RecordId=($script:current.RecordId+1);Sha256=$ConfigurationSha256;ConfigurationPath=(Join-Path $StateDirectory ($id+'.sysmon.after.xml'))}
        [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$id}
      }
      Mock Restore-RideSysmonConfigurationRun {
        param($RunId,$StateDirectory)
        if($script:current.Sha256 -ceq $script:baselineHash){$script:events.Add('RepeatRestore');return [pscustomobject]@{SchemaVersion=1;Status='AlreadyRestored';RunId=$RunId}}
        $script:events.Add('Restore')
        $script:current=[pscustomobject]@{RecordId=($script:current.RecordId+1);Sha256=$script:baselineHash;ConfigurationPath=(Join-Path $StateDirectory ($RunId+'.sysmon.before.xml'))}
        [pscustomobject]@{SchemaVersion=1;Status='Restored';RunId=$RunId}
      }
    }
    It 'requires all three profiles and fifteen checks before reporting native success' {
      $result=Invoke-RideSysmonAcceptance @script:parameters
      $result.Status|Should -Be Passed
      $result.Profiles.Count|Should -Be 3
      @($result.Profiles|Where-Object {-not $_.Restored -or $_.Checks.Count -ne 5}).Count|Should -Be 0
      $result.RecoveryRequired|Should -BeFalse
      $result.RuleDetectionCoverageClaimed|Should -BeFalse
      $result.ArchiveCleanupPerformed|Should -BeFalse
      $script:events.Count|Should -Be 15
      Should -Invoke Assert-RideSysmonAcceptanceRecords -Times 3 -Exactly
      Should -Invoke New-RidePrivateFileStream -Times 2 -Exactly -ParameterFilter {$Scope -ceq 'Machine'}
      (Get-Acl (Join-Path $result.EvidenceDirectory 'result.json')).AreAccessRulesProtected|Should -BeTrue
    }
    It 'previews without mutation or creating evidence, even without elevation' {
      $script:environment.Administrator=$false
      (Invoke-RideSysmonAcceptance @script:parameters -WhatIf).Status|Should -Be Preview
      Test-Path (Join-Path $TestDrive $script:request)|Should -BeFalse
      $script:events.Count|Should -Be 0
    }
    It 'refuses workstation, uncorrelated marker and wrong target' {
      $script:environment.Model='Workstation'
      {Invoke-RideSysmonAcceptance @script:parameters}|Should -Throw '*disposable Hyper-V*'
      $script:environment.Model='Virtual Machine';$script:environment.RunMarker='other'
      {Invoke-RideSysmonAcceptance @script:parameters}|Should -Throw '*correlated*'
      $script:environment.RunMarker=$script:request;$script:parameters.ExpectedBuild='26100'
      {Invoke-RideSysmonAcceptance @script:parameters}|Should -Throw '*target differs*'
      $script:events.Count|Should -Be 0
    }
    It 'returns NotRun for missing elevation or an unestablished baseline' {
      $script:environment.Administrator=$false
      (Invoke-RideSysmonAcceptance @script:parameters).Reason|Should -Be ExistingElevationRequired
      $script:environment.Administrator=$true;$script:current.Sha256='F'*64
      (Invoke-RideSysmonAcceptance @script:parameters).Reason|Should -Be KnownBaselineNotLoaded
      $script:events.Count|Should -Be 0
    }
    It 'preserves existing evidence and requires a distinct baseline' {
      $script:profiles[0].Sha256=$script:baselineHash
      {Invoke-RideSysmonAcceptance @script:parameters}|Should -Throw '*baseline must differ*'
      $null=New-Item -ItemType Directory -Path (Join-Path $TestDrive $script:request)
      {Invoke-RideSysmonAcceptance @script:parameters}|Should -Throw '*already exists*'
      $script:events.Count|Should -Be 0
    }
    It 'stops before later profiles when new Sysmon errors appear' {
      Mock Assert-RideSysmonAcceptanceRecords {$script:errorId=101L}
      $result=Invoke-RideSysmonAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be 'profile-1:Apply'
      $result.Profiles.Count|Should -Be 1
      $result.RecoveryRequired|Should -BeTrue
      $result.StateRunIds.Count|Should -Be 1
      Should -Invoke Restore-RideSysmonConfigurationRun -Times 0 -Exactly
    }
    It 'does not accept successful restore output without the matching native event' {
      Mock Restore-RideSysmonConfigurationRun {[pscustomobject]@{SchemaVersion=1;Status='Restored';RunId='00000000000000000000000000000001'}}
      $result=Invoke-RideSysmonAcceptance @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be 'profile-1:Restore'
      $result.Profiles[0].Restored|Should -BeFalse
      $result.NativeAcceptancePassed|Should -BeFalse
    }
    It 'rejects an incomplete profile set before any mutation' {
      $script:profiles=@($script:profiles[0])
      {Invoke-RideSysmonAcceptance @script:parameters}|Should -Throw '*all three distinct*'
      $script:events.Count|Should -Be 0
    }
    It 'requires unchanged service identity and a newer source-bound event' {
      $before=[pscustomobject]@{Context=$script:context;ConfigurationEvent=$script:current;LastErrorRecordId=0L}
      $after=$before|ConvertTo-Json -Depth 8|ConvertFrom-Json
      {Assert-RideSysmonAcceptanceTransition $before $after $script:baselineHash $script:baselinePath}|Should -Throw '*expected transition*'
      $after.ConfigurationEvent.RecordId=101L;$after.Context.ServiceState='Stopped'
      {Assert-RideSysmonAcceptanceTransition $before $after $script:baselineHash $script:baselinePath}|Should -Throw '*service/target changed*'
    }
  }
}
Describe 'Disposable known-baseline Sysmon fixture preparation' {
  InModuleScope RIDE.SysmonAcceptance {
    BeforeEach {
      $script:request=[guid]::NewGuid().ToString('N')
      $script:exe=Join-Path $TestDrive 'Sysmon64.exe';[IO.File]::WriteAllText($script:exe,'inert non-executable test fixture')
      $script:exeHash=(Get-FileHash $script:exe).Hash
      $script:fixtureHash=(Get-FileHash (Join-Path (Split-Path (Get-Module RIDE.SysmonAcceptance).Path -Parent) '../fixtures/sysmon-baseline.synthetic.xml')).Hash
      $script:environment=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';InstallationType='Client';NativeProcess=$true;Architecture='AMD64';Administrator=$true;Manufacturer='Microsoft Corporation';Model='Virtual Machine';GuestMarker='1';IntegrationMarker='1';RunMarker=$script:request}
      $script:footprint=[pscustomobject]@{Existing=$false;ServiceNames=@();DriverNames=@();Files=@();ConfigurationRecordId=0L;LastErrorRecordId=0L;InstalledExecutablePath='C:\Windows\Sysmon64.exe'}
      $script:parameters=@{RunId=$script:request;ExecutablePath=$script:exe;ExpectedExecutableSha256=$script:exeHash;ExpectedSysmonVersion='15.21';ExpectedComputerName=$script:environment.ComputerName;ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';EvidenceRoot=$TestDrive;DisposableVm=$true;Confirm=$false}
      Mock Get-RideSysmonAcceptanceEnvironment {$script:environment}
      Mock Get-RideSysmonFixtureFootprint {$script:footprint}
      Mock Get-RideSysmonExecutableIdentity -ModuleName RIDE.SysmonConfiguration {param($ExecutablePath,$ExpectedExecutableSha256,$ExpectedSysmonVersion) [pscustomobject]@{Path=$ExecutablePath;Sha256=$ExpectedExecutableSha256;Version=$ExpectedSysmonVersion}}
      Mock Wait-RideSysmonConfigurationEvent -ModuleName RIDE.SysmonConfiguration {}
      Mock New-RidePrivateFileStream {param($Path,$Scope) & (Get-Module RIDE.PrivateFiles) {param($path) New-RidePrivateFileStream -Path $path -Scope User} $Path}
      Mock New-RidePrivateFileStream -ModuleName RIDE.SysmonConfiguration {param($Path,$Scope) & (Get-Module RIDE.PrivateFiles) {param($path) New-RidePrivateFileStream -Path $path -Scope User} $Path}
      Mock Invoke-RideSysmonFixtureInstall {}
      Mock Get-RideSysmonAcceptanceSnapshot {[pscustomobject]@{Context=$script:environment;ConfigurationEvent=[pscustomobject]@{RecordId=1L;Sha256=$script:fixtureHash;ConfigurationPath=(Join-Path (Join-Path $TestDrive $script:request) 'baseline.xml')};LastErrorRecordId=0L}}
    }
    It 'retains private baseline and intent but never calls preparation a native pass' {
      $result=Initialize-RideSysmonAcceptanceFixture @script:parameters
      $result.Status|Should -Be Prepared
      $result.NativeAcceptancePassed|Should -BeFalse
      $result.FixtureRemovalPerformed|Should -BeFalse
      $result.BaselineConfigurationSha256|Should -BeExactly $script:fixtureHash
      (Get-FileHash $result.BaselineConfigurationPath).Hash|Should -BeExactly $script:fixtureHash
      (Get-Acl $result.BaselineConfigurationPath).AreAccessRulesProtected|Should -BeTrue
      Should -Invoke Invoke-RideSysmonFixtureInstall -Times 1 -Exactly
    }
    It 'refuses existing service, driver or destination footprints without changing them' {
      $script:footprint.Existing=$true
      (Initialize-RideSysmonAcceptanceFixture @script:parameters).Reason|Should -Be ExistingSysmonFootprint
      Test-Path (Join-Path $TestDrive $script:request)|Should -BeFalse
      Should -Invoke Invoke-RideSysmonFixtureInstall -Times 0 -Exactly
    }
    It 'previews without files or an installer process' {
      $script:environment.Administrator=$false
      (Initialize-RideSysmonAcceptanceFixture @script:parameters -WhatIf).Status|Should -Be Preview
      Test-Path (Join-Path $TestDrive $script:request)|Should -BeFalse
      Should -Invoke Invoke-RideSysmonFixtureInstall -Times 0 -Exactly
    }
    It 'retains evidence and reports recovery needed after an installer failure' {
      Mock Invoke-RideSysmonFixtureInstall {throw 'Synthetic installer error'}
      $result=Initialize-RideSysmonAcceptanceFixture @script:parameters
      $result.Status|Should -Be Failed
      $result.Stage|Should -Be Install
      $result.RecoveryRequired|Should -BeTrue
      Test-Path (Join-Path $result.EvidenceDirectory 'intent.json')|Should -BeTrue
    }
    It 'holds executable and XML against writes during fixture installation' {
      Mock Invoke-RideSysmonFixtureInstall {
        param($ExecutablePath,$BaselinePath)
        foreach($path in @($ExecutablePath,$BaselinePath)){ {[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)}|Should -Throw }
      }
      (Initialize-RideSysmonAcceptanceFixture @script:parameters).Status|Should -Be Prepared
      Should -Invoke Invoke-RideSysmonFixtureInstall -Times 1 -Exactly
    }
  }
}
Describe 'Sysmon acceptance fixture source gate' {
  InModuleScope RIDE.SysmonAcceptance {
    BeforeEach {
      [IO.File]::WriteAllText((Join-Path $TestDrive 'license.md'),'inert license fixture')
      Mock Get-FileHash {[pscustomobject]@{Hash='FD80A26FBB3F644AF1FA994134446702932968519797227E07A1368DEA80F0BC'}}
      Mock Read-RideSysmonSource -ModuleName RIDE.SysmonConfiguration {param($Path,$ExpectedSha256) [pscustomobject]@{Path=$Path;Sha256=$ExpectedSha256;Bytes=[byte[]]@(1,2)}}
    }
    It 'binds all three source identities to the real declarative catalog' {
      $sources=Read-RideSysmonAcceptanceSources $TestDrive
      $sources.Configurations.Count|Should -Be 3
      $sources.ReleaseTag|Should -BeExactly 'configs-a45dedb13a43'
      $sources.TargetSysmonVersion|Should -BeExactly '15.21'
      @($sources.Configurations.ArtifactId)|Should -Contain 'sysmon-modular-balanced-filedelete-15-21'
      Should -Invoke Read-RideSysmonSource -ModuleName RIDE.SysmonConfiguration -Times 3 -Exactly
    }
    It 'refuses an altered retained license before reading profile sources' {
      Mock Get-FileHash {[pscustomobject]@{Hash=('F'*64)}}
      {Read-RideSysmonAcceptanceSources $TestDrive}|Should -Throw '*license differs*'
      Should -Invoke Read-RideSysmonSource -ModuleName RIDE.SysmonConfiguration -Times 0 -Exactly
    }
    It 'refuses a fixture whose artifact identities no longer match the catalog' {
      Mock Import-RideCatalogData {@{Operations=@()}}
      {Read-RideSysmonAcceptanceSources $TestDrive}|Should -Throw '*catalog identity differ*'
      Should -Invoke Read-RideSysmonSource -ModuleName RIDE.SysmonConfiguration -Times 0 -Exactly
    }
  }
}
