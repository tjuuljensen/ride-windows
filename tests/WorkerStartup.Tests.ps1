<#
.SYNOPSIS
  Reproduce a worker startup interrupted during configuration validation.
.DESCRIPTION
  Runs the repository worker in separate PowerShell runspaces against a private
  TestDrive queue. Only the CommonApplicationData path in the fixture copy of
  the module is redirected. No scheduled task, VM or installed queue is used.
.EXAMPLE
  Invoke-Pester .\tests\WorkerStartup.Tests.ps1
.NOTES
  Version 0.1.0. Windows PowerShell 5.1 or PowerShell 7 on Windows; Pester 5.7.1.
#>
Describe 'Interrupted worker startup' {
  It 'leaves the stale request intact before the scan and detects it on a fresh start' {
    $source=Join-Path $PSScriptRoot 'integration'
    $worker=Join-Path $TestDrive 'Invoke-RideVmTestTaskWorker.ps1'
    Copy-Item -LiteralPath (Join-Path $source 'Invoke-RideVmTestTaskWorker.ps1') -Destination $worker
    $module=Join-Path $TestDrive 'RIDE.TestAutomation.psm1'
    $code=[IO.File]::ReadAllText((Join-Path $source 'RIDE.TestAutomation.psm1'))
    $original='Join-Path ([Environment]::GetFolderPath(''CommonApplicationData'')) "RIDE\TestAutomation\$Name"'
    $code.Contains($original)|Should -BeTrue
    [IO.File]::WriteAllText($module,$code.Replace($original,'Join-Path $PSScriptRoot "RIDE\TestAutomation\$Name"'))
    $root=Join-Path $TestDrive 'RIDE/TestAutomation/RIDEStartupTest'
    foreach($folder in 'runtime','queue/running','queue/pending','queue/finished'){
      $null=New-Item -ItemType Directory -Path (Join-Path $root $folder) -Force
    }
    $id=[guid]::NewGuid().ToString('N')
    $stale=Join-Path $root "queue/running/$id.json"
    [IO.File]::WriteAllText($stale,(@{RunId=$id;Simulation='InterruptedWorker'}|ConvertTo-Json))
    $hash=(Get-FileHash -LiteralPath $stale).Hash
    $config=Join-Path $root 'configuration.json'
    $data=@{SchemaVersion=2;Name='RIDEStartupTest';LabName='RIDEStartupTest';VMName='RIDE-Synthetic'
      VMId=[guid]::NewGuid().ToString();CheckpointName='Unused';IsDisposable=$true
      GuestRepositoryPath='C:\RIDE\ride-windows';LocalRepositoryPath='C:\Local';CIRepositoryPath='C:\CI'
      HostAccountSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
    [IO.File]::WriteAllText($config,($data|ConvertTo-Json))
    $block=Join-Path $root 'runtime/blocked.json'
    $workerLock=Join-Path $root 'runtime/worker.lock'
    $arrived=[Threading.ManualResetEventSlim]::new()
    $shell=[powershell]::Create()
    try {
      # Stop after the real JSON parse, before the first validation loop.
      $line=@(Select-String -LiteralPath $module -SimpleMatch 'foreach ($key in @(''SchemaVersion'', ''Name'', ''LabName''')
      $line.Count|Should -Be 1
      $shell.Runspace.SessionStateProxy.SetVariable('startupReached',$arrived)
      $null=$shell.AddScript({
        param($module,$line,$worker,$config)
        $null=Set-PSBreakpoint -Script $module -Line $line -Action {
          $startupReached.Set()
          Start-Sleep -Seconds 60
        }
        & $worker -ConfigurationPath $config
      }.ToString()).AddArgument($module).AddArgument($line[0].LineNumber).AddArgument($worker).AddArgument($config)
      $async=$shell.BeginInvoke()
      $arrived.Wait(30000)|Should -BeTrue
      $shell.Stop()
      $shell.InvocationStateInfo.State.ToString()|Should -Be 'Stopped'
      $async.IsCompleted|Should -BeTrue
    } finally {$shell.Dispose();$arrived.Dispose()}
    Test-Path -LiteralPath $workerLock|Should -BeFalse
    Test-Path -LiteralPath $block|Should -BeFalse
    (Get-FileHash -LiteralPath $stale).Hash|Should -BeExactly $hash

    $fresh=[powershell]::Create()
    try {
      $null=$fresh.AddCommand($worker).AddParameter('ConfigurationPath',$config)
      $null=$fresh.Invoke()
      $fresh.HadErrors|Should -BeFalse -Because ($fresh.Streams.Error -join ' ')
    } finally {$fresh.Dispose()}
    $reason=Get-Content -LiteralPath $block -Raw|ConvertFrom-Json
    Test-Path -LiteralPath $workerLock|Should -BeTrue
    @($reason.Requests)|Should -Be @("$id.json")
    $reason.Error|Should -Match 'previous worker stopped'
    (Get-FileHash -LiteralPath $stale).Hash|Should -BeExactly $hash
    @(Get-ChildItem (Join-Path $root 'queue/finished') -File).Count|Should -Be 0
  }
}
