<#
.SYNOPSIS
  Verify source-bound Sysmon configuration recovery without invoking Sysmon.
.DESCRIPTION
  Uses inert XML and real TestDrive files/ACLs. Target, service, signature, event
  and process providers are mocked; machine state uses current-user private files.
.EXAMPLE
  Invoke-Pester ./tests/SysmonConfiguration.Tests.ps1
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.SysmonConfiguration.psm1') -Force}
Describe 'Source-bound Sysmon configuration lifecycle' {
  InModuleScope RIDE.SysmonConfiguration {
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $script:root
      $script:state=Join-Path $script:root 'state';$null=New-Item -ItemType Directory -Path $script:state
      $script:beforePath=Join-Path $script:root 'before.xml';$script:afterPath=Join-Path $script:root 'after.xml'
      [IO.File]::WriteAllText($script:beforePath,'<Sysmon schemaversion="4.91"><HashAlgorithms>SHA256</HashAlgorithms><EventFiltering /></Sysmon>',[Text.UTF8Encoding]::new($false))
      [IO.File]::WriteAllText($script:afterPath,'<Sysmon schemaversion="4.91"><HashAlgorithms>*</HashAlgorithms><EventFiltering /></Sysmon>',[Text.UTF8Encoding]::new($false))
      $script:beforeHash=(Get-FileHash $script:beforePath).Hash;$script:afterHash=(Get-FileHash $script:afterPath).Hash
      $script:context=[pscustomobject]@{ComputerName='RIDE-Synthetic-VM';Build='26300';EditionId='EnterpriseEval';Revision=9711;InstallationType='Client';NativeProcess=$true;Architecture='AMD64';UserSid='S-1-5-21-1-2-3-4';Administrator=$true;ExecutablePath='C:\Windows\Sysmon64.exe';ExecutableSha256=('A'*64);SysmonVersion='15.21';ServicePathName='C:\Windows\Sysmon64.exe';ServiceStartMode='Auto';ServiceState='Running'}
      $script:event=[pscustomobject]@{RecordId=100L;Sha256=$script:beforeHash;ConfigurationPath=$script:beforePath}
      $script:parameters=@{ConfigurationPath=$script:afterPath;ConfigurationSha256=$script:afterHash;PriorConfigurationPath=$script:beforePath;PriorConfigurationSha256=$script:beforeHash;ExecutablePath=$script:context.ExecutablePath;ExpectedExecutableSha256=$script:context.ExecutableSha256;ExpectedSysmonVersion='15.21';ExpectedComputerName=$script:context.ComputerName;ExpectedBuild='26300';ExpectedEditionId='EnterpriseEval';StateDirectory=$script:state;AllowCandidate=$true;Confirm=$false}
      Mock Get-RideSysmonConfigurationContext {$script:context}
      Mock Get-RideSysmonConfigurationEvent {$script:event}
      Mock New-RidePrivateFileStream {param($Path,$Scope) & (Get-Module RIDE.PrivateFiles) {param($path) New-RidePrivateFileStream -Path $path -Scope User} $Path}
      Mock Read-RidePrivateFileBytes {param($Path,$MaximumBytes,$Scope) & (Get-Module RIDE.PrivateFiles) {param($path,$maximum) Read-RidePrivateFileBytes -Path $path -Scope User -MaximumBytes $maximum} $Path $MaximumBytes}
      Mock Invoke-RideSysmonConfigurationCommand {
        param($ExecutablePath,$ConfigurationPath)
        $script:event=[pscustomobject]@{RecordId=($script:event.RecordId+1);Sha256=(Get-FileHash -LiteralPath $ConfigurationPath).Hash;ConfigurationPath=$ConfigurationPath}
      }
    }
    It 'applies once, preserves exact prior bytes and restores without duplicate changes' {
      $result=Set-RideSysmonConfiguration @script:parameters
      $result.Status|Should -Be Applied
      (Set-RideSysmonConfiguration @script:parameters).Status|Should -Be AlreadyDesired
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 4
      $path=Get-RideSysmonRunPath $script:state $result.RunId before.xml
      (Get-FileHash -LiteralPath $path).Hash|Should -BeExactly $script:beforeHash
      (Get-Acl -LiteralPath $path).AreAccessRulesProtected|Should -BeTrue
      (Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false).Status|Should -Be Restored
      (Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false).Status|Should -Be AlreadyRestored
      $script:event.Sha256|Should -BeExactly $script:beforeHash
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 2 -Exactly
      Should -Invoke New-RidePrivateFileStream -Times 4 -Exactly -ParameterFilter {$Scope -ceq 'Machine'}
      (Get-FileHash $script:beforePath).Hash|Should -BeExactly $script:beforeHash
      (Get-FileHash $script:afterPath).Hash|Should -BeExactly $script:afterHash
    }
    It 'previews without state files, a process or elevation' {
      $script:context.Administrator=$false;$script:parameters.AllowCandidate=$false
      Set-RideSysmonConfiguration @script:parameters -WhatIf
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 0
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 0 -Exactly
    }
    It 'requires explicit candidate opt-in, elevation and exact target' {
      $script:parameters.AllowCandidate=$false
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*AllowCandidate*'
      $script:parameters.AllowCandidate=$true;$script:context.Administrator=$false
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*existing elevation*'
      $script:context.Administrator=$true;$script:parameters.ExpectedBuild='26100'
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*target differs*'
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 0 -Exactly
    }
    It 'refuses a prior source that does not match the current configuration evidence' {
      $script:event.Sha256='B'*64
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*no recoverable source*'
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 0
    }
    It 'refuses changed input digests, unsupported XML and DTDs before state capture' {
      $script:parameters.ConfigurationSha256='B'*64
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*source hash differs*'
      foreach($xml in @('<Sysmon schemaversion="4.82" />','<!DOCTYPE Sysmon [<!ENTITY sample "value">]><Sysmon schemaversion="4.91">&sample;</Sysmon>')){
        [IO.File]::WriteAllText($script:afterPath,$xml)
        $script:parameters.ConfigurationSha256=(Get-FileHash $script:afterPath).Hash
        {Set-RideSysmonConfiguration @script:parameters}|Should -Throw
      }
      @(Get-ChildItem -LiteralPath $script:state -File).Count|Should -Be 0
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 0 -Exactly
    }
    It 'retains intent and exposes the run ID when native application fails' {
      Mock Invoke-RideSysmonConfigurationCommand {throw 'Synthetic process failure'}
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*Run ID:*'
      @(Get-ChildItem $script:state -Filter '*.sysmon.intent.json').Count|Should -Be 1
      @(Get-ChildItem $script:state -Filter '*.sysmon.applied.json').Count|Should -Be 0
      $id=(Get-ChildItem $script:state -Filter '*.sysmon.intent.json').Name.Split('.')[0]
      {Restore-RideSysmonConfigurationRun -RunId $id -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 1 -Exactly
    }
    It 'does not mutate if persistence fails or the event changes during capture' {
      Mock Save-RideSysmonRecord {throw 'Synthetic persistence failure'}
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*did not complete*'
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 0 -Exactly
    }
    It 'rejects concurrent configuration updates before its process starts' {
      $script:reads=0
      Mock Get-RideSysmonConfigurationEvent {$script:reads++;[pscustomobject]@{RecordId=(100L+$script:reads);Sha256=$script:beforeHash;ConfigurationPath=$script:beforePath}}
      {Set-RideSysmonConfiguration @script:parameters}|Should -Throw '*Run ID:*'
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 0 -Exactly
    }
    It 'holds checked source bytes against writes while the native reader runs' {
      Mock Invoke-RideSysmonConfigurationCommand {
        param($ExecutablePath,$ConfigurationPath)
        {[IO.File]::Open($ConfigurationPath,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)}|Should -Throw
      }
      Invoke-RideSysmonPinnedConfiguration 'unused.exe' $script:afterPath $script:afterHash
      {Invoke-RideSysmonPinnedConfiguration 'unused.exe' $script:afterPath ('F'*64)}|Should -Throw '*changed before use*'
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 1 -Exactly
    }
    It 'refuses recovery when configuration evidence or captured bytes changed' {
      $result=Set-RideSysmonConfiguration @script:parameters
      $originalEvent=$script:event
      $script:event=[pscustomobject]@{RecordId=500L;Sha256=('F'*64);ConfigurationPath='another.xml'}
      {Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*recovery conflict*'
      $script:event=$originalEvent
      [IO.File]::AppendAllText((Get-RideSysmonRunPath $script:state $result.RunId before.xml),'changed')
      {Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*prior Sysmon XML differs*'
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 1 -Exactly
    }
    It 'requires fresh recovery opt-in and refuses context drift' {
      $result=Set-RideSysmonConfiguration @script:parameters
      {Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $script:state -Confirm:$false}|Should -Throw '*fresh -AllowCandidate*'
      $script:context.ExecutableSha256='B'*64
      {Restore-RideSysmonConfigurationRun -RunId $result.RunId -StateDirectory $script:state -AllowCandidate -Confirm:$false}|Should -Throw '*context changed*'
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 1 -Exactly
    }
    It 'requires a fresh matching event and detects log continuity loss' {
      $script:event=[pscustomobject]@{RecordId=101L;Sha256=$script:afterHash;ConfigurationPath=$script:afterPath}
      (Wait-RideSysmonConfigurationEvent 100 $script:afterHash $script:afterPath).RecordId|Should -Be 101
      {Wait-RideSysmonConfigurationEvent 100 $script:beforeHash $script:afterPath}|Should -Throw '*newer configuration event*'
      {Wait-RideSysmonConfigurationEvent 200 $script:afterHash $script:afterPath}|Should -Throw '*continuity changed*'
    }
    It 'parses exact event source identity and rejects ambiguity or absent SHA-256' {
      $xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>16</EventID><EventRecordID>123</EventRecordID></System><EventData><Data Name="Configuration">C:\synthetic.xml</Data><Data Name="ConfigurationFileHash">SHA1='+('A'*40)+',SHA256='+('B'*64)+'</Data></EventData></Event>'
      $event=ConvertFrom-RideSysmonConfigurationEvent $xml
      $event.RecordId|Should -Be 123
      $event.Sha256|Should -BeExactly ('B'*64)
      {ConvertFrom-RideSysmonConfigurationEvent ($xml.Replace(',SHA256='+('B'*64),''))}|Should -Throw '*SHA-256*'
      {ConvertFrom-RideSysmonConfigurationEvent ($xml.Replace('</EventData>','<Data Name="Configuration">duplicate</Data></EventData>'))}|Should -Throw '*identity is unavailable*'
      {ConvertFrom-RideSysmonConfigurationEvent ($xml.Replace('<EventID>16</EventID>','<EventID>1</EventID>'))}|Should -Throw '*configuration-change event*'
    }
    It 'completes saved run IDs without querying Windows or invoking Sysmon' {
      $result=Set-RideSysmonConfiguration @script:parameters
      $line='Restore-RideSysmonConfigurationRun -StateDirectory "'+$script:state+'" -RunId '+$result.RunId.Substring(0,6)
      $completion=[Management.Automation.CommandCompletion]::CompleteInput($line,$line.Length,$null)
      @($completion.CompletionMatches.CompletionText)|Should -Contain $result.RunId
      Should -Invoke Get-RideSysmonConfigurationContext -Times 3 -Exactly
      Should -Invoke Invoke-RideSysmonConfigurationCommand -Times 1 -Exactly
    }
  }
}
