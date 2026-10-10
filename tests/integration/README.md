# Windows VM integration test runbook (draft)

This runbook is intended for an advanced first-time contributor setting up a disposable Windows 11 test VM with Hyper-V. Please use it as the first pilot and report any step that is unclear, stale, or fails on your host.

The VM is for integration tests that change Windows state. Routine validation and mocked Pester tests remain available through the repository's GitHub Actions workflow and do not require a VM.

## What this pilot covers

The forty-setting follow-up has a package-free acceptance suite. Select it
explicitly with `Invoke-RideVmTest.ps1 -IntegrationSuite SettingsBatch40` and
the normal VM transport/evidence parameters; the default remains `Full`.
`-UnitOnly` cannot be combined with this integration selection. The new script
`Invoke-RideSettingsBatch.ps1` covers all 81 explicit states, preview, repeat
apply, baseline removal and exact registry restore. UI and feature behavior
remain separate acceptance checks; see the
[batch ledger](../../docs/MIGRATION-PLAN.md#forty-setting-follow-up-2026-10-09).

The 9 October optional-settings migration adds 20 registry round trips across
UI, privacy, service and Explorer families. They check every explicit state,
apply/restore preview, repeat apply, override-removal baseline, and exact prior
value/type recovery. These checks do not exercise visual refresh, sensor or
biometric hardware, app access, network peer transfers, hibernation, sign-out
history deletion or actual crash recovery. See the
[migration results](../../docs/MIGRATION-PLAN.md#optional-windows-settings-session-2026-10-09)
for executed evidence and remaining acceptance limits.

The current VM suite checks Explorer settings; install, idempotence, and removal for 7-Zip, Notepad++, and Sysmon; the inking and typing setting; network category apply/restore for all non-domain profiles; Remote Assistance policy; the Microsoft product updates preference; and the BitLocker encryption-method policy on Windows 11. Git for Windows installation is not yet covered. The suite does **not yet** perform real-Windows round-trip tests for the service, UWP per-app override, or boot configuration handlers.

The optional [God Mode folder](../../docs/GOD-MODE.md) scenario checks preview,
repeat apply and exact saved-run restore on Windows 11. Use a clean VM desktop;
the scenario refuses a nonempty God Mode folder. Manually open the folder in
Explorer to verify that it displays Control Panel tasks. The folder lifecycle
scenario passed in the Windows 11 VM on 9 October
2026 (run `959e8b4c2a374041a792497f42dd2588`); the manual visual check remains
pending.

The package checks download installers from their declared upstream sources, so the guest needs outbound internet access while the suite runs. The VM does not need access to shared host folders or production credentials.

The host runner launches `Invoke-RideGuestTests.ps1` in a fresh Windows
PowerShell process inside the VM. This keeps Pester's mock call stack outside
the remoting thread. The guest entry point requires the host runner's VM marker;
use the host runner or registered task rather than invoking it on a workstation.
Refresh an installed controller through registration while its worker is idle
after reviewing runner changes; see [task setup](AUTOMATEDLAB-TASKS.md#2-register-once).

When using AutomatedLab, the runner waits up to five minutes for a guest PowerShell remoting session before staging files. A timeout indicates the guest is still starting or its WinRM listener/network firewall is unavailable; no RIDE test code runs until that session is established.

## 1. Check the Hyper-V host

Use a Windows Pro, Enterprise, Education, or Windows Server host with hardware virtualization enabled. Hyper-V is not included with Windows Home. You need permission to create Hyper-V VMs and enough free storage for the ISO and VM disk. A practical starting allocation is 4 virtual processors, 8 GB of guest memory, and a dynamically expanding 100 GB virtual disk; reduce these only if the host is resource constrained.

In one elevated PowerShell session on the host, run this complete block to check whether Hyper-V is available. Paste or run the entire block together; `elseif` and `else` belong to the same `if` statement and cannot be entered as separate commands after it has executed.

```powershell
if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
    Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
} elseif (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
    Get-WindowsFeature -Name Hyper-V
} else {
    throw 'Hyper-V management commands are unavailable on this host.'
}
```

If the feature is disabled, enable it through **Turn Windows features on or off** on Windows client, or install the Hyper-V role on Windows Server, then restart when Windows asks. Follow Microsoft's [Hyper-V installation requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v).

## 2. Register and download the Windows evaluation ISO

For a key-free test VM, use Microsoft's [Windows 11 Enterprise Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise): register, choose the x64 ISO, and complete the download form. Microsoft describes it as a 90-day evaluation and says a product key is not required. Windows 11 Enterprise requires a Microsoft account sign-in; use a dedicated test account rather than a work or production identity.

You can also download a standard 64-bit Windows 11 ISO from [Microsoft's Danish Windows 11 download page](https://www.microsoft.com/da-dk/software-download/windows11). Microsoft describes this as a multi-edition ISO and says a product key is needed to unlock the matching edition. The ISO download itself does not ask for a key, but installation and activation still require the applicable license or digital entitlement. Use this option if you have a license for the edition you want to test; otherwise use the evaluation ISO. Microsoft provides instructions to [verify the ISO hash](https://www.microsoft.com/da-dk/software-download/windows11).

Save the ISO in a location you control, for example `D:\VMs\RIDE-Test\ISO\Windows11-Enterprise-Eval.iso`. Create the folder first. Use another drive/path if `D:` is unavailable. Do not choose ARM64 unless your Hyper-V host is Windows on Arm.

## 3. Create the VM in Hyper-V Manager

On the host, open **Hyper-V Manager** and use **New > Virtual Machine**:

1. Name it `RIDE-Win11-Test` and store its files under a dedicated VM folder, for example `D:\VMs\RIDE-Test\Windows11`.
2. Select **Generation 2**.
3. Assign 8192 MB startup memory if available. Dynamic Memory can be enabled.
4. Connect it to **Default Switch** during setup and integration testing. This gives the guest outbound network access for Windows setup, Pester, and package downloads. Do not join it to a domain or sign into production services.
5. Create a new dynamically expanding VHDX, with a maximum size of 100 GB.
6. Select **Install an operating system from a bootable image file** and point to the ISO downloaded in step 2.
7. Finish the wizard. Before starting the VM, open **Settings > Security** and confirm Secure Boot is enabled with the Microsoft Windows template. Enable **Trusted Platform Module** if the host supports it and Windows setup requires it. Set the processor count to 4 if the host has capacity.

Start the VM, connect with **VMConnect**, and complete Windows setup. Install the Windows 11 Enterprise evaluation. After first sign-in, run Windows Update and restart until no further updates are offered. Keep the VM off your domain and avoid storing personal or production data in it.

For the Hyper-V wizard and PowerShell alternatives, see Microsoft's [create a virtual machine guide](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/Create-a-virtual-machine-in-Hyper-V).

### Optional: provision this VM with AutomatedLab

The Hyper-V Manager flow above remains the primary setup path. For repeatable, host-driven provisioning, use the [AutomatedLab setup guide](AUTOMATEDLAB.md) and its OS-selectable script. The script checks host permissions and lab prerequisites, installs Pester through `Invoke-LabCommand`, creates the clean checkpoint, and performs the AutomatedLab copy step. AutomatedLab is an external dependency and is not installed by RIDE.

## 4. Install the test dependency in the guest

Open **PowerShell as Administrator inside the guest VM**. Install the same Pester version used by CI:

```powershell
Install-PackageProvider -Name NuGet -MinimumVersion '2.8.5.201' -Scope CurrentUser -Force
Install-Module -Name Pester -RequiredVersion 5.7.1 -Repository PSGallery -Scope CurrentUser -Force -SkipPublisherCheck
Get-Module Pester -ListAvailable | Where-Object Version -eq '5.7.1'
```

Windows includes Pester 3.4.0 signed by Microsoft; Pester 5.7.1 has a different signing publisher. The Pester project recommends `-SkipPublisherCheck` for this side-by-side installation. Keep the install pinned to version 5.7.1 and review the [Pester Gallery listing](https://www.powershellgallery.com/packages/Pester/5.7.1) before installing. This setup currently supports Windows PowerShell and PowerShell 7; using Windows PowerShell is sufficient for this first pilot.

## 5. Create a clean checkpoint

Shut down the guest after updates and Pester installation. In Hyper-V Manager, select the VM and choose **Checkpoint**. Rename it `RIDE-clean-test-base`.

Restore this checkpoint after each integration run. The integration suite changes settings and installs/removes software; the VM checkpoint is the broad recovery boundary if a test fails before RIDE can restore an individual operation. Because this checkpoint is taken before copying the checkout into the guest, copy the current working tree again after each restore.

## 6. Copy this working tree into the guest

Run the copy from PowerShell with the current directory set anywhere inside this Git checkout. `git rev-parse` finds the checkout root, so you do not need to enter your Windows profile name.

### 6A. If the VM was created with AutomatedLab

AutomatedLab's `Copy-LabFileItem` copies files and directory trees to a lab VM using its lab connection context. Import the lab with its actual lab name; the current example uses `RIDEWin11Test`. The VM name is `RIDE-Win11-Test`.

```powershell
$labName = 'RIDEWin11Test' # Change only if your existing lab has a different name.
$vmName = 'RIDE-Win11-Test'
$repoRootOutput = & git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0 -or -not $repoRootOutput) {
  throw 'Run this command from inside the ride-windows Git checkout.'
}
$repoPath = $repoRootOutput.Trim()

Import-Lab -Name $labName -NoValidation
Invoke-LabCommand -ComputerName $vmName -ScriptBlock {
  New-Item -ItemType Directory -Path 'C:\RIDE' -Force | Out-Null
}
Copy-LabFileItem -Path $repoPath -ComputerName $vmName -DestinationFolderPath 'C:\RIDE' -Recurse
Invoke-LabCommand -ComputerName $vmName -ScriptBlock {
  Test-Path 'C:\RIDE\ride-windows\tools\validate.ps1'
} -PassThru
```

The final command should return `True`. Here, `-NoValidation` avoids rechecking installation-media paths after the VM has already been provisioned; it skips all lab-definition validators, so do not use it to provision a new lab. AutomatedLab's [Import-Lab reference](https://automatedlab.org/en/latest/AutomatedLabCore/en-us/Import-Lab/) documents the switch. Its [file-copy command](https://automatedlab.org/en/stable/AutomatedLabCore/en-us/Copy-LabFileItem/) supports recursive directory copies, and [Invoke-LabCommand](https://automatedlab.org/en/stable/AutomatedLabCore/en-us/Invoke-LabCommand/) runs the directory checks inside the guest. This path reuses the lab's guest access; it does not prompt for the guest username again.

### 6B. If the VM was created manually in Hyper-V Manager

PowerShell Direct copies files without enabling PowerShell remoting over the VM network. Run this on the host from anywhere inside the checkout; `git rev-parse` supplies the repo path automatically. This fallback prompts once for the guest's local account credentials:

```powershell
$vmName = 'RIDE-Win11-Test'
$repoRootOutput = & git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0 -or -not $repoRootOutput) {
  throw 'Run this command from inside the ride-windows Git checkout.'
}
$repoPath = $repoRootOutput.Trim()
$guestPath = 'C:\RIDE\ride-windows'
$credential = Get-Credential
$session = New-PSSession -VMName $vmName -Credential $credential
Invoke-Command -Session $session -ScriptBlock {
  New-Item -ItemType Directory -Path 'C:\RIDE\ride-windows' -Force | Out-Null
}
Copy-Item -Path (Join-Path $repoPath '*') -Destination $guestPath -ToSession $session -Recurse -Force
Remove-PSSession $session
```

If PowerShell Direct cannot connect, confirm the VM is running, the guest has completed setup, and Hyper-V integration services are enabled. Microsoft's [PowerShell Direct guide](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct) lists requirements and troubleshooting steps.

## 7. Run validation and the integration suite

For an opt-in elevated task, local watcher and GitHub Actions entry point that
keep host UAC enabled, follow [the task controller runbook](AUTOMATEDLAB-TASKS.md).
The existing direct commands below retain their default behavior. Validate the
new controller on a separate pilot before agreeing a cutover.

You can run the checks from the Hyper-V host after copying the current checkout into the guest (step 6). The shared script block regenerates the catalog documentation, runs validation and Pester, then runs the guarded integration suite. It checks Pester's returned result and stops if any tests failed.

For repeated runs, the repository includes a production-test runner that copies the current working tree into the VM, regenerates `docs/OPERATIONS.md`, runs validation and Pester, and then runs the integration suite. It supports both VM setup paths above. The default run changes VM settings and installs/removes test packages, so use it only with the disposable test VM and restore the clean checkpoint afterward.

From the repository root, run one of these on the host:

```powershell
# AutomatedLab-provisioned VM
.\tests\integration\Invoke-RideVmTest.ps1 -Transport AutomatedLab -LabName 'RIDEWin11Test' -VMName 'RIDE-Win11-Test'

# VM created manually in Hyper-V Manager; prompts for a guest administrator credential
.\tests\integration\Invoke-RideVmTest.ps1 -Transport PowerShellDirect -VMName 'RIDE-Win11-Test'
```

Add `-UnitOnly` to copy the current checkout and run validation plus Pester without applying real Windows changes or installing packages. The detailed remote script below shows each test command separately; use it when learning the process or troubleshooting the runner.

```powershell
$remoteScript = {
  $ErrorActionPreference = 'Stop'
  Set-Location -LiteralPath 'C:\RIDE\ride-windows'

  & .\tools\Export-RideCatalog.ps1
  & .\tools\validate.ps1

  $pesterResult = Invoke-Pester -Path .\tests -PassThru
  if ($pesterResult.FailedCount -gt 0) {
    throw "Pester reported $($pesterResult.FailedCount) failing test(s)."
  }

  $env:RIDE_INTEGRATION_VM = '1'
  & .\tests\integration\Invoke-RideVmSuite.ps1
}
```

### If the VM was created with AutomatedLab

Run the following from the host after importing the lab. `Invoke-LabCommand -PassThru` returns the guest output to the host:

```powershell
$labName = 'RIDEWin11Test' # Change only if your existing lab uses another name.
$vmName = 'RIDE-Win11-Test'
Import-Lab -Name $labName -NoValidation
Invoke-LabCommand -ComputerName $vmName -ScriptBlock $remoteScript -PassThru
```

### If the VM was created manually in Hyper-V Manager

PowerShell Direct runs the same block without requiring guest network remoting. Enter the guest's local administrator credentials when prompted:

```powershell
$vmName = 'RIDE-Win11-Test'
$credential = Get-Credential -Message 'Enter the local administrator account for the guest VM'
$session = New-PSSession -VMName $vmName -Credential $credential
try {
  Invoke-Command -Session $session -ScriptBlock $remoteScript
}
finally {
  Remove-PSSession $session
}
```

The integration script checks that it is running as an administrator inside the guest, and that the guest is Windows 11 or Windows Server 2025. If the remote session fails that administrator check, run the commands in an elevated PowerShell window inside the guest. You can also run the commands interactively inside the guest:

```powershell
Set-Location C:\RIDE\ride-windows
& .\tools\Export-RideCatalog.ps1
& .\tools\validate.ps1
$pesterResult = Invoke-Pester -Path .\tests -PassThru
if ($pesterResult.FailedCount -gt 0) { throw "Pester reported $($pesterResult.FailedCount) failing test(s)." }
$env:RIDE_INTEGRATION_VM = '1'
& .\tests\integration\Invoke-RideVmSuite.ps1
```

The integration suite has a deliberate environment-variable guard and an administrator check. It will exercise the current integration paths and may download/install then uninstall 7-Zip and Notepad++. Leave the VM connected to Default Switch while these package checks run. Do not run the suite on your daily workstation.

If validation or Pester fails, capture the complete error and test summary. If the integration suite fails, keep the VM powered off before investigating, and retain any reported RIDE run ID so the saved state can be inspected. Restore `RIDE-clean-test-base` before another attempt.

## 8. Report the first-run result

Please send back:

- whether each numbered step worked, and the step number for any failure;
- Windows edition, version, and build from `winver`;
- host Windows edition and Hyper-V availability;
- PowerShell and Pester versions;
- the final output from `tools/validate.ps1`, Pester, and the integration suite;
- any run ID printed after an integration failure.

Do not include passwords, Microsoft account details, or unrelated personal data in the report.

## Windows Server 2025 follow-up

After the Windows 11 pilot is successful, repeat the VM checks on Windows Server 2025 for operations whose catalog metadata declares server support. Microsoft provides an official [Windows Server 2025 evaluation ISO and VHD](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025); the evaluation is time-limited and requires internet activation. Keep that VM separate from the Windows 11 VM and use a clean checkpoint for each run.
