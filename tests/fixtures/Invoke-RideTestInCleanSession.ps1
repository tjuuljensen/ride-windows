function Invoke-RideTestInCleanSession {
  <#
  .SYNOPSIS
    Run a test probe with an independent PowerShell module table.
  .DESCRIPTION
    Pass paths and fixture data explicitly. The new runspace has no access to
    the caller's mocks or TestDrive provider. Errors fail the calling test.
  .PARAMETER Probe
    Self-contained script block to execute.
  .PARAMETER Arguments
    Positional arguments for the probe, including any resolved fixture paths.
  .PARAMETER RequireEngineAbsent
    Fail if the probe loaded the operational engine.
  .EXAMPLE
    Invoke-RideTestInCleanSession { param($path) & $path -Version } -Arguments $tool -RequireEngineAbsent
  .NOTES
    Version 0.1.0. Windows PowerShell 5.1 and PowerShell 7.
  #>
  param([scriptblock]$Probe, [object[]]$Arguments, [switch]$RequireEngineAbsent)
  $shell = [powershell]::Create()
  try {
    $null = $shell.AddScript('$ErrorActionPreference = "Stop"').AddStatement()
    $null = $shell.AddScript($Probe.ToString())
    foreach ($argument in $Arguments) { $null = $shell.AddArgument($argument) }
    if ($RequireEngineAbsent) {
      $null = $shell.AddStatement().AddScript("if (Get-Module RIDE.Engine -All) { throw 'Probe loaded RIDE.Engine.' }")
    }
    $result = $shell.Invoke()
    if ($shell.HadErrors) { throw $shell.Streams.Error[0] }
    $result
  } finally { $shell.Dispose() }
}
