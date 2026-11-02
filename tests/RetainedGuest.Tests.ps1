<#
.SYNOPSIS
  Check retained guest ownership without changing a controller or VM.
.DESCRIPTION
  Uses TestDrive private user files and real exclusive handles; host, Hyper-V,
  scheduled-task and installed configuration boundaries are mocked.
.EXAMPLE
  Invoke-Pester ./tests/RetainedGuest.Tests.ps1
.NOTES
  Native Windows PowerShell 5.1/7 and Pester 5. Version: 0.1.0.
#>
BeforeDiscovery {Import-Module (Join-Path $PSScriptRoot 'integration/RIDE.RetainedGuest.psm1') -Force}
Describe 'Retained guest hold and phase ownership' {
  InModuleScope RIDE.RetainedGuest {
    BeforeEach {
      $script:root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
      foreach($child in @('runtime','queue/pending','queue/running')){$null=New-Item -ItemType Directory -Path (Join-Path $script:root $child) -Force}
      $script:lockPath=Join-Path $script:root 'runtime/worker.lock';[IO.File]::WriteAllText($script:lockPath,'')
      $script:blockPath=Join-Path $script:root 'runtime/blocked.json'
      $script:configPath=Join-Path $script:root 'configuration.json';[IO.File]::WriteAllText($script:configPath,'inert configuration fixture')
      $script:id='a'*32
      $script:config=[pscustomobject]@{Name='Synthetic';VMName='RIDE-Test';VMId='11111111-1111-1111-1111-111111111111';CheckpointId='22222222-2222-2222-2222-222222222222';HostAccountSid='S-1-5-21-1-2-3-1000'}
      $script:hostIdentity=[pscustomobject]@{Sid=$script:config.HostAccountSid;Elevated=$true;NativeDesktop=$true}
      $script:vmState='Off';$script:taskState='Ready'
      Mock Read-RideAutomationConfiguration {$script:config}
      Mock Get-RideAutomationRoot {$script:root}
      Mock Get-RideRetainedHostIdentity {$script:hostIdentity}
      Mock Assert-RideAutomationHost {}
      Mock Import-RideAutomationLab {[pscustomobject]@{VM=[pscustomobject]@{State=$script:vmState};Snapshot=[pscustomobject]@{Id=$script:config.CheckpointId}}}
      Mock Get-ScheduledTask {[pscustomobject]@{State=$script:taskState}}
      Mock New-RidePrivateFileStream {param($Path,$Scope);if($Scope -cne 'Machine'){throw 'Machine scope required.'};& (Get-Module RIDE.PrivateFiles) {param($p) New-RidePrivateFileStream -Path $p -Scope User} $Path}
      Mock Read-RidePrivateFileBytes {param($Path,$Scope,$MaximumBytes);if($Scope -cne 'Machine'){throw 'Machine scope required.'};& (Get-Module RIDE.PrivateFiles) {param($p,$n) Read-RidePrivateFileBytes -Path $p -Scope User -MaximumBytes $n} $Path $MaximumBytes}
      $script:parameters=@{ConfigurationPath=$script:configPath;RunId=$script:id;Confirm=$false}
      function New-TestRecoveryReceipt {
        param($Hold)
        $record=[pscustomobject]@{SchemaVersion=1;Kind='RetainedGuestRecovery';RunId=$Hold.RunId;LeaseId=$Hold.LeaseId;VMId=$Hold.VMId;CheckpointId=$Hold.CheckpointId;ConfigurationSha256=$Hold.ConfigurationSha256;EvidenceExportVerified=$true;CheckpointResetVerified=$true;Status='ResetAndOff'}
        $path=Join-Path $script:root ([guid]::NewGuid().ToString('N')+'.json')
        Write-RideRetainedRecord $path $record
        $path
      }
      function Assert-TestWorkerLockReleased {
        $handle=[IO.File]::Open($script:lockPath,'Open','Read','None');$handle.Dispose()
      }
    }
    It 'reserves only the pinned idle guest and keeps a private durable block after releasing the process lock' {
      $hold=New-RideRetainedGuestHold @script:parameters
      $hold.Status|Should -Be Reserved;$hold.Kind|Should -Be RetainedGuestAcceptance
      $hold.LeaseId|Should -Match '^[a-f0-9]{32}$';$hold.NativeAcceptancePassed|Should -BeFalse
      (Read-RideRetainedRecord $script:blockPath).RunId|Should -BeExactly $script:id
      (Get-Acl -LiteralPath $script:blockPath).AreAccessRulesProtected|Should -BeTrue
      Assert-TestWorkerLockReleased
    }
    It 'previews without privilege, locks, host dependency checks, VM inspection or writes' {
      $script:hostIdentity.Elevated=$false
      (New-RideRetainedGuestHold @script:parameters -WhatIf).Status|Should -Be Preview
      Test-Path -LiteralPath $script:blockPath|Should -BeFalse
      Should -Invoke Import-RideAutomationLab -Times 0 -Exactly
      Should -Invoke Assert-RideAutomationHost -Times 0 -Exactly
      Should -Invoke Get-ScheduledTask -Times 0 -Exactly
    }
    It 'refuses another host identity, non-native shell, missing elevation and unpinned checkpoint' {
      $script:hostIdentity.Sid='different'
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*registered account*'
      $script:hostIdentity.Sid=$script:config.HostAccountSid;$script:hostIdentity.NativeDesktop=$false
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*native Windows*'
      $script:hostIdentity.NativeDesktop=$true;$script:hostIdentity.Elevated=$false
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*Existing elevation*'
      $script:hostIdentity.Elevated=$true;$script:config.CheckpointId=[guid]::Empty.ToString()
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*Exact VM*'
      Test-Path -LiteralPath $script:blockPath|Should -BeFalse
    }
    It 'refuses configurations outside the registered root' {
      $script:parameters.ConfigurationPath=Join-Path $script:root 'different.json'
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*installed controller*'
    }
    It 'refuses existing failure blocks without replacing their bytes' {
      [IO.File]::WriteAllText($script:blockPath,'existing recovery failure')
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*already exists*'
      [IO.File]::ReadAllText($script:blockPath)|Should -BeExactly 'existing recovery failure'
    }
    It 'refuses a held worker lock and never inspects or changes the guest' {
      $handle=[IO.File]::Open($script:lockPath,'Open','Read','None')
      try{{New-RideRetainedGuestHold @script:parameters}|Should -Throw}finally{$handle.Dispose()}
      Should -Invoke Import-RideAutomationLab -Times 0 -Exactly
      Test-Path -LiteralPath $script:blockPath|Should -BeFalse
    }
    It 'refuses queued requests, a busy task or a running VM and releases its lock' {
      $pending=Join-Path $script:root 'queue/pending/request.json';[IO.File]::WriteAllText($pending,'inert')
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*idle*'
      [IO.File]::Delete($pending);$script:taskState='Running'
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*idle*'
      $script:taskState='Ready';$script:vmState='Running'
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*Off disposable*'
      Assert-TestWorkerLockReleased
      Test-Path -LiteralPath $script:blockPath|Should -BeFalse
    }
    It 'retains a newly written hold when its readback fails' {
      Mock Read-RideRetainedRecord {throw 'Synthetic readback failure.'}
      {New-RideRetainedGuestHold @script:parameters}|Should -Throw '*readback failure*'
      Test-Path -LiteralPath $script:blockPath|Should -BeTrue
      Assert-TestWorkerLockReleased
    }
    It 'opens a retained phase with an exclusive handle without clearing the durable hold' {
      $null=New-RideRetainedGuestHold @script:parameters;$script:vmState='Running'
      $phase=Open-RideRetainedGuestPhase -ConfigurationPath $script:configPath -RunId $script:id
      try{
        $phase.Hold.RunId|Should -BeExactly $script:id
        {[IO.File]::Open($script:lockPath,'Open','Read','None')}|Should -Throw
        Test-Path -LiteralPath $script:blockPath|Should -BeTrue
      }finally{$phase.Lock.Dispose()}
      Assert-TestWorkerLockReleased
    }
    It 'refuses stale configuration or a different request and retains recovery ownership' {
      $null=New-RideRetainedGuestHold @script:parameters
      {Open-RideRetainedGuestPhase -ConfigurationPath $script:configPath -RunId ('b'*32)}|Should -Throw '*ownership*'
      [IO.File]::AppendAllText($script:configPath,'changed')
      {Open-RideRetainedGuestPhase -ConfigurationPath $script:configPath -RunId $script:id}|Should -Throw '*ownership*'
      Test-Path -LiteralPath $script:blockPath|Should -BeTrue
      Assert-TestWorkerLockReleased
    }
    It 'requires a private correlated reset and export receipt rather than treating Off as recovery' {
      $hold=New-RideRetainedGuestHold @script:parameters
      $path=New-TestRecoveryReceipt $hold
      $record=Read-RideRetainedRecord $path;$record.EvidenceExportVerified=$false
      [IO.File]::WriteAllText($path,($record|ConvertTo-Json))
      {Remove-RideRetainedGuestHold @script:parameters -RecoveryReceiptPath $path}|Should -Throw '*receipt is required*'
      Test-Path -LiteralPath $script:blockPath|Should -BeTrue
    }
    It 'previews release without a lock or removing the hold' {
      $hold=New-RideRetainedGuestHold @script:parameters;$path=New-TestRecoveryReceipt $hold
      $script:hostIdentity.Elevated=$false
      (Remove-RideRetainedGuestHold @script:parameters -RecoveryReceiptPath $path -WhatIf).Status|Should -Be Preview
      Test-Path -LiteralPath $script:blockPath|Should -BeTrue
      Should -Invoke Import-RideAutomationLab -Times 1 -Exactly
    }
    It 'refuses release while the VM is running and releases only the matching recovered hold' {
      $hold=New-RideRetainedGuestHold @script:parameters;$path=New-TestRecoveryReceipt $hold
      $script:vmState='Running'
      {Remove-RideRetainedGuestHold @script:parameters -RecoveryReceiptPath $path}|Should -Throw '*must be Off*'
      Test-Path -LiteralPath $script:blockPath|Should -BeTrue
      $script:vmState='Off'
      $result=Remove-RideRetainedGuestHold @script:parameters -RecoveryReceiptPath $path
      $result.Status|Should -Be Released;$result.NativeAcceptancePassed|Should -BeFalse
      Test-Path -LiteralPath $script:blockPath|Should -BeFalse
      Test-Path -LiteralPath $path|Should -BeTrue
      Assert-TestWorkerLockReleased
    }
    It 'rejects an old recovery receipt when a request ID is reused for a new reservation' {
      $hold=New-RideRetainedGuestHold @script:parameters;$old=New-TestRecoveryReceipt $hold
      $null=Remove-RideRetainedGuestHold @script:parameters -RecoveryReceiptPath $old
      $next=New-RideRetainedGuestHold @script:parameters
      $next.LeaseId|Should -Not -BeExactly $hold.LeaseId
      {Remove-RideRetainedGuestHold @script:parameters -RecoveryReceiptPath $old}|Should -Throw '*different reservation*'
      Test-Path -LiteralPath $script:blockPath|Should -BeTrue
    }
    It 'completes only the retained run without querying native host dependencies' {
      $null=New-RideRetainedGuestHold @script:parameters
      $suggestions=@(& $script:RetainedRunCompleter 'Open-RideRetainedGuestPhase' 'RunId' 'aa' $null @{ConfigurationPath=$script:configPath})
      $suggestions.Count|Should -Be 1;$suggestions[0].CompletionText|Should -BeExactly $script:id
      Should -Invoke Import-RideAutomationLab -Times 1 -Exactly
      Should -Invoke Get-RideRetainedHostIdentity -Times 1 -Exactly
    }
  }
}
Describe 'Ordinary request handling respects retained guest blocks' {
  InModuleScope RIDE.TestAutomation {
    It 'refuses a blocked guest before host preparation or automatic checkpoint reset' {
      $root=Join-Path $TestDrive 'blocked-controller';$null=New-Item -ItemType Directory -Path (Join-Path $root 'runtime') -Force
      [IO.File]::WriteAllText((Join-Path $root 'runtime/blocked.json'),'{"Kind":"RetainedGuestAcceptance"}')
      Mock Assert-RideAutomationHost {throw 'Unexpected host call.'}
      Mock Reset-RideAutomationVm {throw 'Unexpected reset.'}
      $request=[pscustomobject]@{SchemaVersion=1;RunId=[guid]::NewGuid().ToString('N');Source='Local';UnitOnly=$true;TimeoutMinutes=10;SubmittedAtUtc=[datetime]::UtcNow.ToString('o')}
      $result=Invoke-RideAutomationRequest -Configuration ([pscustomobject]@{}) -Request $request -Root $root
      $result.Status|Should -Be Failed;$result.Error|Should -Match 'cleanup is blocked'
      Should -Invoke Assert-RideAutomationHost -Times 0 -Exactly
      Should -Invoke Reset-RideAutomationVm -Times 0 -Exactly
      Test-Path -LiteralPath (Join-Path $root 'runtime/blocked.json')|Should -BeTrue
    }
  }
}
