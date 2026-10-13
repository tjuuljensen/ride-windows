<#
.SYNOPSIS
  Capture scoped file, registry and startup inventories in a disposable guest.
.DESCRIPTION
  Hashes files under explicitly named roots, reads selected registry trees in the
  current PowerShell registry view, and exports scheduled-task definitions and
  startup-folder inventories. Does not change those locations. This instrumentation
  reads files and writes an evidence JSON: run outside timed memory/write phases.
  Reparse-point entries are recorded without traversing their targets.
.PARAMETER FileRoot
  Explicit absolute directories to inventory, including missing candidate paths.
.PARAMETER RegistryRoot
  Explicit PowerShell registry-provider paths. Include WOW6432Node where applicable.
.PARAMETER OutputPath
  New JSON file on the guest evidence volume. Existing paths are rejected.
.PARAMETER ExpectedComputerName
  Exact disposable guest computer name.
.PARAMETER DisposableVm
  Attest that the target is a disposable VM.
.PARAMETER Version
  Print tooling version without accessing inventories.
.EXAMPLE
  .\tests\integration\Export-RideScreenLockSnapshot.ps1 -ExpectedComputerName RIDE-Win11-Test -DisposableVm -FileRoot C:\RIDE\inputs,$env:TEMP,$env:LOCALAPPDATA -RegistryRoot HKCU:\Software -OutputPath E:\evidence\before.json
.INPUTS
  None.
.OUTPUTS
  String. Saved evidence path.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 parser/help verified;
  real guest capture pending. CIM and ScheduledTasks required.
  Limits: Scoped inventories miss out-of-scope and transient changes; use Procmon.
  Reads can trigger antivirus/access artifacts. Account paths stay in local evidence.
  Author: RIDE-Windows maintainers. Version: 0.1.0
  Recovery: Keep evidence; restore the disposable measurement checkpoint.
  Changelog: 0.1.0: Add scoped before/after inventories without following reparse points.
.LINK
  ../../docs/screen-lock-impact.md
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string[]] $FileRoot, [string[]] $RegistryRoot = @(), [string] $OutputPath,
  [string] $ExpectedComputerName, [switch] $DisposableVm, [switch] $Version
)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $DisposableVm -or -not $ExpectedComputerName -or $env:COMPUTERNAME -ine $ExpectedComputerName) { throw 'Matching disposable guest attestation is required.' }
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine|VMware|VirtualBox|KVM|QEMU') { throw 'A recognized VM is required.' }
if (-not $OutputPath -or -not $FileRoot) { throw 'OutputPath and explicit FileRoot values are required.' }
if (Test-Path -LiteralPath $OutputPath) { throw 'Use a new evidence path.' }
foreach ($path in $FileRoot) {
  if (-not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path).TrimEnd('\') -eq [IO.Path]::GetPathRoot($path).TrimEnd('\')) { throw 'FileRoot must be an absolute directory below a volume root.' }
}
if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Read scoped guest inventories and save evidence')) { return }
$errors = [Collections.Generic.List[object]]::new()
$files = [Collections.Generic.List[object]]::new()
$pending = [Collections.Generic.Stack[string]]::new()
foreach ($path in $FileRoot) {
  if (Test-Path -LiteralPath $path) { $pending.Push($path) }
  else { $files.Add(@{ Path = $path; Exists = $false }) }
}
$visited = @{}
while ($pending.Count) {
  $path = $pending.Pop()
  if ($visited.ContainsKey($path)) { continue }
  $visited[$path] = $true
  try {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      $files.Add(@{ Path = $item.FullName; Exists = $true; ReparsePoint = $true }); continue
    }
    if ($item.PSIsContainer) {
      foreach ($child in Get-ChildItem -LiteralPath $path -Force) { $pending.Push($child.FullName) }
    }
    else {
      $files.Add(@{ Path = $item.FullName; Exists = $true; Bytes = $item.Length; LastWriteUtc = $item.LastWriteTimeUtc.ToString('o'); Sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash })
    }
  }
  catch { $errors.Add(@{ Path = $path; Error = $_.Exception.Message }) }
}
$registry = [Collections.Generic.List[object]]::new()
foreach ($path in $RegistryRoot) {
  if ($path -notmatch '^HK(LM|CU):\\') { throw 'RegistryRoot must use HKLM: or HKCU:.' }
  if (-not (Test-Path -LiteralPath $path)) { $registry.Add(@{ Path = $path; Exists = $false }); continue }
  $enumerationErrors = @()
  $keys = @(Get-Item -LiteralPath $path) + @(Get-ChildItem -LiteralPath $path -Recurse -ErrorAction SilentlyContinue -ErrorVariable enumerationErrors)
  foreach ($errorRecord in $enumerationErrors) { $errors.Add(@{ Path = $path; Error = $errorRecord.Exception.Message }) }
  foreach ($key in $keys) {
    try {
      $values = foreach ($name in $key.GetValueNames()) {
        @{ Name = $name; Kind = $key.GetValueKind($name).ToString(); Value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
      }
      $registry.Add(@{ Path = $key.Name; Exists = $true; Values = @($values) })
    } catch { $errors.Add(@{ Path = $key.Name; Error = $_.Exception.Message }) }
  }
}
$tasks = @(Get-ScheduledTask | ForEach-Object {
  @{ TaskPath = $_.TaskPath; TaskName = $_.TaskName; Xml = (Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath) }
})
$startup = foreach ($path in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
  @{ Path = $path; Entries = @(Get-ChildItem -LiteralPath $path -Force -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTimeUtc) }
}
[ordered]@{
  SchemaVersion = 1; ToolingVersion = $script:ScriptVersion; CapturedAtUtc = [datetime]::UtcNow.ToString('o'); ComputerName = $env:COMPUTERNAME
  Is64BitProcess = [Environment]::Is64BitProcess; FileRoots = $FileRoot; RegistryRoots = $RegistryRoot
  Files = @($files.ToArray()); Registry = @($registry.ToArray()); Tasks = $tasks; Startup = @($startup); Errors = @($errors.ToArray())
} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
$OutputPath
