<#
.SYNOPSIS
  Probe real Windows Terminal colors in an unlocked disposable guest desktop.
.DESCRIPTION
  Coordinator registers uniquely named Interactive limited/high guest tasks.
  Worker temporarily uses a controlled Terminal profile with elevate=false,
  launches both PowerShell editions, measures screenshot backgrounds and collects
  optional OSC color responses,
  and closes only its own windows. Probe executes inside the real Terminal shell.
  Original Terminal settings bytes and Recommended profile blocks are recovered.
.PARAMETER Role
  Coordinator, Worker or Probe; default Coordinator.
.PARAMETER ExpectedComputerName
  Exact disposable guest identity.
.PARAMETER EvidencePath
  Guest evidence beneath C:\RIDE\ProfileAcceptance.
.PARAMETER CasePath
  Worker/probe case JSON beneath the evidence directory.
.PARAMETER DisposableVm
  Required explicit VM attestation.
.PARAMETER Version
  Print the version without launching anything.
.EXAMPLE
  .\Invoke-RideProfileVisualAcceptance.ps1 -Version
.INPUTS
  None.
.OUTPUTS
  JSON and PNG evidence; task/appearance failures throw.
.NOTES
  Compatibility: Windows PowerShell 5.1 coordinator; PowerShell 5.1/7 probes.
  Prerequisites: Disposable Windows 11/Server 2025 desktop, UAC enabled, installed Terminal/PS7.
  Recovery: Finally blocks restore configuration; host restores the clean VM checkpoint.
  Author: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add token-correlated interactive Terminal acceptance.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidateSet('Coordinator','Worker','Probe')][string]$Role = 'Coordinator',
  [string]$ExpectedComputerName, [string]$EvidencePath, [string]$CasePath,
  [switch]$DisposableVm, [switch]$Version
)
$script:ScriptVersion = '0.1.0'
if ($Version) { $script:ScriptVersion; return }
$ErrorActionPreference = 'Stop'
if (-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or $env:COMPUTERNAME -ine $ExpectedComputerName -or
    (Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine') { throw 'Visual acceptance is restricted to the attested disposable guest.' }
$evidence = [IO.Path]::GetFullPath($EvidencePath)
if (-not $evidence.StartsWith('C:\RIDE\ProfileAcceptance\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected visual evidence directory.' }
if ($CasePath -and -not [IO.Path]::GetFullPath($CasePath).StartsWith($evidence + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Case must belong to the evidence directory.' }
if (-not $PSCmdlet.ShouldProcess($ExpectedComputerName, "Run $Role Terminal acceptance")) { return }

if ($Role -eq 'Probe') {
  $case = Get-Content -LiteralPath $CasePath -Raw | ConvertFrom-Json
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $admin = [Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $response = [ordered]@{}
  foreach ($resource in @(10,11,12)) {
    while ([Console]::KeyAvailable) { $null = [Console]::ReadKey($true) }
    [Console]::Write(([string][char]27 + ']' + $resource + ';?' + [char]7))
    $buffer = New-Object Text.StringBuilder
    $deadline = [datetime]::UtcNow.AddSeconds(1)
    while ([datetime]::UtcNow -lt $deadline) {
      if ([Console]::KeyAvailable) {
        $null = $buffer.Append([Console]::ReadKey($true).KeyChar)
        if ($buffer.ToString() -match ('\]' + $resource + ';rgb:([0-9a-fA-F]+)/([0-9a-fA-F]+)/([0-9a-fA-F]+)(?:\x07|\x1b\\)')) { break }
      } else { Start-Sleep -Milliseconds 20 }
    }
    $response[[string]$resource] = $buffer.ToString()
  }
  $Host.UI.RawUI.WindowTitle = $case.Title
  Write-Host "RIDE profile acceptance - PowerShell $($PSVersionTable.PSVersion)"
  Write-Host "Actual administrator token: $admin; case: $($case.Id)"
  Write-Host 'Ordinary output and prompt text'
  Write-Warning 'Warning text must remain readable'
  Write-Error 'Sample error text must remain readable' -ErrorAction Continue
  Write-Host 'Get-Process ' -ForegroundColor Yellow -NoNewline
  Write-Host '-Name ' -ForegroundColor DarkGray -NoNewline
  Write-Host "'example'" -ForegroundColor Cyan
  $result = [pscustomobject]@{
    Id = $case.Id; Runtime = $PSVersionTable.PSVersion.ToString(); Sid = $identity.User.Value
    Elevated = $admin; HostName = $Host.Name; Interactive = [Environment]::UserInteractive
    Redirected = [Console]::IsOutputRedirected; TerminalSession = $env:WT_SESSION
    SessionId = (Get-Process -Id $PID).SessionId; ProcessId = $PID; Responses = $response
    RawForeground = [string]$Host.UI.RawUI.ForegroundColor; RawBackground = [string]$Host.UI.RawUI.BackgroundColor
  }
  $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence ($case.Id + '-probe.json')) -Encoding UTF8
  return
}

if ($Role -eq 'Coordinator') {
  if ((Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA -ne 1) { throw 'Normal/elevated acceptance requires guest UAC enabled and a completed reboot.' }
  $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $rows = [Collections.Generic.List[object]]::new()
  foreach ($level in @('Limited','Highest')) {
    $taskName = 'RIDE-ProfileVisual-' + [guid]::NewGuid().ToString('N')
    $taskCase = Join-Path $evidence ($taskName + '.json')
    @{ Id = $taskName; Level = $level } | ConvertTo-Json | Set-Content -LiteralPath $taskCase -Encoding UTF8
    $command = '$env:RIDE_INTEGRATION_VM=''1''; & ' + "'$($PSCommandPath.Replace("'","''"))' -Role Worker -ExpectedComputerName '$ExpectedComputerName' -EvidencePath '$evidence' -CasePath '$taskCase' -DisposableVm -Confirm:`$false *> '$evidence/$taskName.log'"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe') -Argument ('-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel $level
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    try {
      $task = Register-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -Action $action -Principal $principal -Settings $settings
      Start-ScheduledTask -InputObject $task
      $deadline = [datetime]::UtcNow.AddMinutes(10)
      $resultPath = Join-Path $evidence ($taskName + '-worker.json')
      while (-not (Test-Path -LiteralPath $resultPath) -and [datetime]::UtcNow -lt $deadline) {
        $info = Get-ScheduledTaskInfo -TaskName $taskName -TaskPath '\RIDE\'
        if ($info.LastTaskResult -gt 65535 -and $info.LastTaskResult -notin @(267009,267011)) { throw "Interactive worker could not start: $($info.LastTaskResult)" }
        $state = (Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\').State
        if ($info.LastRunTime.Year -gt 2000 -and $state -notin @('Running','Queued') -and $info.LastTaskResult -ne 267009) { throw "Interactive worker exited without evidence: $($info.LastTaskResult); see $taskName.log" }
        Start-Sleep -Seconds 1
      }
      if (-not (Test-Path -LiteralPath $resultPath)) { throw 'Interactive worker timed out; collect its log before checkpoint recovery.' }
      $worker = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
      if ($worker.Status -ne 'Passed') { throw "Interactive worker failed: $($worker.Error)" }
      foreach ($row in $worker.Cases) { $rows.Add($row) }
    }
    finally {
      if (Get-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -TaskPath '\RIDE\' -Confirm:$false
      }
    }
  }
  $rows.ToArray() | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'visual-cases.json') -Encoding UTF8
  return
}

if (-not [Environment]::UserInteractive -or (Get-Process -Id $PID).SessionId -eq 0) { throw 'The visual worker must run in the signed-in guest desktop.' }
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class RideProfileWindows {
  public delegate bool Callback(IntPtr window, IntPtr data);
  [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left,Top,Right,Bottom; }
  [DllImport("user32.dll")] public static extern bool EnumWindows(Callback callback, IntPtr data);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr window, StringBuilder text, int count);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr window, out Rect rect);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window, uint message, IntPtr wparam, IntPtr lparam);
  [DllImport("user32.dll")] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
  [DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr desktop);
  public static IntPtr Find(string title) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((window,data)=>{var text=new StringBuilder(1024); GetWindowText(window,text,1024);
      if(text.ToString().Contains(title)){found=window;return false;} return true;},IntPtr.Zero);
    return found;
  }
}
'@
$desktop = [RideProfileWindows]::OpenInputDesktop(0,$false,1)
if ($desktop -eq [IntPtr]::Zero) { throw 'Unlock the disposable guest desktop before visual acceptance.' }
$null = [RideProfileWindows]::CloseDesktop($desktop)
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE-ProfileSettings.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../modules/RIDE.CatalogData.psm1') -Force
$operations = @((Import-RideCatalogData (Join-Path $PSScriptRoot '../../catalog/operations.psd1')).Operations | Where-Object Kind -eq ProfileSetting)
$workerCase = Get-Content -LiteralPath $CasePath -Raw | ConvertFrom-Json
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin -ne ($workerCase.Level -eq 'Highest')) { throw 'Interactive worker did not receive the requested token level.' }
$package = Get-AppxPackage Microsoft.WindowsTerminal | Select-Object -First 1
if (-not $package) { throw 'Windows Terminal is not registered for the interactive test user.' }
$terminal = Join-Path $package.InstallLocation 'WindowsTerminal.exe'
$settingsPath = Join-Path $env:LOCALAPPDATA 'Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json'
$settingsExisted = [IO.File]::Exists($settingsPath)
$settingsBytes = if ($settingsExisted) { [IO.File]::ReadAllBytes($settingsPath) } else { [byte[]]@() }
$profileId = '{720a4c6f-3d7a-4f57-9d1a-a153a0163882}'
$settingsText = @{ defaultProfile = $profileId; confirmCloseAllTabs = $false; actions = @(@{ command = 'selectAll'; keys = 'ctrl+shift+a' }); profiles = @{ list = @(@{ guid = $profileId; name = 'RIDE-Acceptance-Normal'; commandline = 'powershell.exe'; elevate = $false; background = '#101820'; foreground = '#E0E0E0'; cursorColor = '#FFFFFF'; selectionBackground = '#FFFFFF'; font = @{ face = 'Cascadia Mono'; size = 13 }; opacity = 100 }) } } | ConvertTo-Json -Depth 8
$null = [IO.Directory]::CreateDirectory((Split-Path -Parent $settingsPath))
$cases = [Collections.Generic.List[object]]::new()
$windows = [Collections.Generic.List[string]]::new()
$failure = $null
try {
  [IO.File]::WriteAllText($settingsPath,$settingsText,(New-Object Text.UTF8Encoding($false)))
  foreach ($operation in $operations) {
    $executable = if ($operation.ProfileRuntime -eq 'PowerShell7') { Join-Path $env:ProgramFiles 'PowerShell/7/pwsh.exe' } else { Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe' }
    $variants = @('Recommended','AdminBlue','Default','NoProfile','BlockedProfile')
    if ($admin) { $variants += 'Inherited' }
    foreach ($variant in $variants) {
      $state = if ($variant -in @('NoProfile','BlockedProfile','Inherited')) { 'Recommended' } else { $variant }
      Set-RideProfileSettingState $operation $state -Confirm:$false
      $caseId = $operation.ProfileRuntime + '-' + $workerCase.Level + '-' + $variant
      $title = 'RIDE Profile ' + $caseId
      $windowName = 'RIDE-' + [guid]::NewGuid().ToString('N')
      $windows.Add($title)
      $caseFile = Join-Path $evidence ($caseId + '.json')
      @{ Id = $caseId; Title = $title } | ConvertTo-Json | Set-Content -LiteralPath $caseFile -Encoding UTF8
      if ($variant -eq 'Inherited') {
        $seedTitle = $title + '-seed'; $windows.Add($seedTitle)
        $seed = '-w "' + $windowName + '" new-tab -p RIDE-Acceptance-Normal --title "' + $seedTitle + '" --suppressApplicationTitle powershell.exe -NoLogo -NoProfile -NoExit'
        Start-Process -FilePath $terminal -ArgumentList $seed | Out-Null
        $deadline = [datetime]::UtcNow.AddSeconds(30)
        while ([RideProfileWindows]::Find($seedTitle) -eq [IntPtr]::Zero -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
      }
      $arguments = '-w "' + $windowName + '" new-tab -p RIDE-Acceptance-Normal --title "' + $title + '" --suppressApplicationTitle "' + $executable + '" -NoLogo -NoExit '
      if ($variant -eq 'NoProfile') { $arguments += '-NoProfile ' }
      if ($variant -eq 'BlockedProfile') {
        # Encoded probe runs despite Restricted startup policy; no file-policy bypass
        # is applied to the startup profile, which must retain host appearance.
        $command = '& ([scriptblock]::Create([IO.File]::ReadAllText(' + "'$($PSCommandPath.Replace("'","''"))'))) -Role Probe -ExpectedComputerName '$ExpectedComputerName' -EvidencePath '$evidence' -CasePath '$caseFile' -DisposableVm -Confirm:`$false"
        $arguments += '-ExecutionPolicy Restricted -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
      } else {
        $arguments += '-ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Role Probe -ExpectedComputerName "' + $ExpectedComputerName + '" -EvidencePath "' + $evidence + '" -CasePath "' + $caseFile + '" -DisposableVm'
      }
      Start-Process -FilePath $terminal -ArgumentList $arguments | Out-Null
      $probeFile = Join-Path $evidence ($caseId + '-probe.json')
      $deadline = [datetime]::UtcNow.AddSeconds(60)
      while (-not (Test-Path -LiteralPath $probeFile) -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 200 }
      if (-not (Test-Path -LiteralPath $probeFile)) { throw "Terminal probe did not finish: $caseId" }
      $probe = Get-Content -LiteralPath $probeFile -Raw | ConvertFrom-Json
      if ($probe.Elevated -ne $admin -or -not $probe.Interactive -or $probe.Redirected -or -not $probe.TerminalSession) { throw 'Terminal shell token/host evidence mismatch.' }
      $expected = if ($variant -in @('Default','NoProfile','BlockedProfile') -or ($variant -eq 'AdminBlue' -and -not $admin)) { '#101820' } elseif ($admin) { '#012456' } elseif ($operation.ProfileRuntime -eq 'PowerShell7') { '#282C34' } else { '#0C0C0C' }
      $raw = [string]$probe.Responses.'11'
      $rgb = if ($raw -match 'rgb:([0-9a-fA-F]+)/([0-9a-fA-F]+)/([0-9a-fA-F]+)') { '#' + $Matches[1].Substring(0,2) + $Matches[2].Substring(0,2) + $Matches[3].Substring(0,2) } else { '<no response>' }
      $window = [RideProfileWindows]::Find($title)
      if ($window -eq [IntPtr]::Zero) { throw 'Could not locate this test Terminal window.' }
      $null = [RideProfileWindows]::SetForegroundWindow($window); Start-Sleep -Milliseconds 800
      if ([RideProfileWindows]::GetForegroundWindow() -ne $window) { throw 'Test Terminal could not receive foreground input safely.' }
      # Leave an unexecuted command at the real PSReadLine prompt for contrast review.
      [Windows.Forms.SendKeys]::SendWait("Get-Process -Name 'example'")
      Start-Sleep -Milliseconds 500
      $rect = New-Object RideProfileWindows+Rect; $null = [RideProfileWindows]::GetWindowRect($window,[ref]$rect)
      $image = New-Object Drawing.Bitmap ($rect.Right-$rect.Left),($rect.Bottom-$rect.Top)
      $graphics = [Drawing.Graphics]::FromImage($image)
      try {
        $graphics.CopyFromScreen($rect.Left,$rect.Top,0,0,$image.Size)
        $image.Save((Join-Path $evidence ($caseId + '.png')),[Drawing.Imaging.ImageFormat]::Png)
        # Sample unused viewport space, excluding window chrome, text and taskbar.
        # Terminal versions need not expose OSC query replies as Console key events.
        $counts = @{}; $sampleCount = 0
        for ($y = [int]($image.Height * 0.55); $y -lt [int]($image.Height * 0.80); $y += 5) {
          for ($x = [int]($image.Width * 0.15); $x -lt [int]($image.Width * 0.85); $x += 5) {
            $pixel = $image.GetPixel($x,$y)
            $color = '#{0:X2}{1:X2}{2:X2}' -f $pixel.R,$pixel.G,$pixel.B
            $counts[$color] = 1 + [int]$counts[$color]; $sampleCount++
          }
        }
        $dominant = $counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
        $measured = [string]$dominant.Key
        $coverage = [double]$dominant.Value / $sampleCount
      } finally { $graphics.Dispose(); $image.Dispose() }
      $cases.Add([pscustomobject]@{ Id = $caseId; ExpectedBackground = $expected; MeasuredBackground = $measured; BackgroundCoverage = $coverage; ReportedBackground = $rgb; Elevated = $probe.Elevated; Sid = $probe.Sid; TerminalVersion = [string]$package.Version; RuntimeVersion = $probe.Runtime; Screenshot = $caseId + '.png'; ProfileElevate = $false })
      if ($measured -ine $expected -or $coverage -lt 0.75) { throw "Background mismatch in ${caseId}: expected $expected, measured $measured (coverage $coverage)" }
      [Windows.Forms.SendKeys]::SendWait('^+a')
      Start-Sleep -Milliseconds 400
      $selection = New-Object Drawing.Bitmap ($rect.Right-$rect.Left),($rect.Bottom-$rect.Top)
      $selectionGraphics = [Drawing.Graphics]::FromImage($selection)
      try {
        $selectionGraphics.CopyFromScreen($rect.Left,$rect.Top,0,0,$selection.Size)
        $selection.Save((Join-Path $evidence ($caseId + '-selection.png')),[Drawing.Imaging.ImageFormat]::Png)
        # Terminal 1.18 overlays selection at 50 percent opacity; 1.24 renders
        # opaque white with dark text. Accept either observed renderer behavior,
        # retaining screenshots for human review of text and PSReadLine contrast.
        $selectionColor = [Drawing.ColorTranslator]::FromHtml($expected)
        $expectedSelection = @($selectionColor.R,$selectionColor.G,$selectionColor.B) | ForEach-Object { [int][Math]::Round(($_ + 255) / 2,[MidpointRounding]::AwayFromZero) }
        $matching = 0; $selectionSamples = 0
        for ($y = [int]($selection.Height * 0.55); $y -lt [int]($selection.Height * 0.80); $y += 5) {
          for ($x = [int]($selection.Width * 0.15); $x -lt [int]($selection.Width * 0.85); $x += 5) {
            $pixel = $selection.GetPixel($x,$y)
            $selectionSamples++
            if ([Math]::Abs($pixel.R - $expectedSelection[0]) -le 2 -and [Math]::Abs($pixel.G - $expectedSelection[1]) -le 2 -and [Math]::Abs($pixel.B - $expectedSelection[2]) -le 2) { $matching++ }
          }
        }
        $white = 0; $dark = 0; $textSamples = 0
        for ($y = [int]($selection.Height * 0.12); $y -lt [int]($selection.Height * 0.50); $y += 3) {
          for ($x = [int]($selection.Width * 0.05); $x -lt [int]($selection.Width * 0.85); $x += 3) {
            $pixel = $selection.GetPixel($x,$y); $textSamples++
            if ($pixel.R -eq 255 -and $pixel.G -eq 255 -and $pixel.B -eq 255) { $white++ }
            if ($pixel.R -lt 50 -and $pixel.G -lt 50 -and $pixel.B -lt 50) { $dark++ }
          }
        }
        $rendering = if ($matching / $selectionSamples -ge 0.75) { 'Translucent white overlay' } elseif ($white / $textSamples -ge 0.20 -and $dark -ge 10) { 'Opaque white with dark selected text' } else { throw "Configured selection was not observed: $caseId" }
        $cases[$cases.Count - 1] | Add-Member NoteProperty SelectionScreenshot ($caseId + '-selection.png')
        $cases[$cases.Count - 1] | Add-Member NoteProperty SelectionRendering $rendering
      } finally { $selectionGraphics.Dispose(); $selection.Dispose() }
      [Windows.Forms.SendKeys]::SendWait('{ESC}')
      $null = [RideProfileWindows]::PostMessage($window,16,[IntPtr]::Zero,[IntPtr]::Zero)
      Start-Sleep -Milliseconds 300
    }
  }
} catch { $failure = $_.Exception.Message }
finally {
  foreach ($title in $windows) { $window = [RideProfileWindows]::Find($title); if ($window -ne [IntPtr]::Zero) { $null = [RideProfileWindows]::PostMessage($window,16,[IntPtr]::Zero,[IntPtr]::Zero) } }
  foreach ($operation in $operations) { try { Set-RideProfileSettingState $operation Recommended -Confirm:$false } catch { $failure = [string]$failure + '; ' + $_.Exception.Message } }
  if ($settingsExisted) { [IO.File]::WriteAllBytes($settingsPath,$settingsBytes) } elseif ([IO.File]::Exists($settingsPath)) { [IO.File]::Delete($settingsPath) }
  @{ Status = if ($failure) { 'Failed' } else { 'Passed' }; Error = $failure; Cases = $cases.ToArray() } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence ($workerCase.Id + '-worker.json')) -Encoding UTF8
}
if ($failure) { throw $failure }
