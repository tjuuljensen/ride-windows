# AutomatedLab setup for RIDE integration VMs

This guide uses the host-side script [New-RideAutomatedLabVm.ps1](New-RideAutomatedLabVm.ps1) to provision and prepare a disposable VM through the AutomatedLab equivalent of runbook steps 1 through 6A. It supports any guest OS that AutomatedLab discovers from an ISO in LabSources. The RIDE integration suite itself still declares its supported Windows targets separately.

For repeatable on-demand, watcher and CI testing while keeping **host UAC
enabled**, use the opt-in [task controller runbook](AUTOMATEDLAB-TASKS.md).
Validate it on a separate pilot before redirecting an active lab.

## Host and lab prerequisites

- A Windows Pro, Enterprise, Education, or Windows Server host with hardware virtualization enabled and the Hyper-V role/feature installed. Hyper-V is not included with Windows Home.
- Hyper-V management tools and the Hyper-V Virtual Machine Management service (`vmms`) installed and running.
- An elevated host PowerShell session, or an account in **Hyper-V Administrators** with effective Hyper-V CIM access. After changing group membership, sign out and back in before retrying.
- AutomatedLab installed and configured, including its LabSources directory. Follow the upstream [AutomatedLab installation guide](https://automatedlab.org/en/stable/Wiki/Basic/install/) and [Getting Started](https://automatedlab.org/en/stable/Wiki/Basic/gettingstarted/) guide first.
- The ISO for the selected guest OS in the `ISOs` directory under the configured LabSources location. For reference, Microsoft provides the [Windows 11 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) and [Windows Server 2025 evaluation](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025) downloads.
- Enough host storage for the ISO and VM files. The script reports available space and recommends at least 120 GB. The initial guest allocation is 8 GB and 4 virtual processors; adjust it with `-MemoryGB` and `-ProcessorCount` for the host and guest.
- Host internet access and a working outbound NAT path for the guest. The script creates an AutomatedLab NAT network named `RIDE-Internet` and reports existing host WinNAT networks for review.

AutomatedLab is an external dependency. This repository script does not install AutomatedLab or download/register OS media. Do not use production credentials or join the disposable VM to a domain.

## Check host access and choose an OS

Open PowerShell on the Hyper-V host and import the module if needed:

```powershell
Import-Module AutomatedLab
$isoDirectory = Join-Path (Get-LabSourcesLocation) 'ISOs'
Get-LabAvailableOperatingSystem -Path $isoDirectory |
    Format-Table OperatingSystemName, Version, IsoPath -AutoSize
```

Use the exact `OperatingSystemName` from that list. Run a read-only preflight before provisioning:

```powershell
.\tests\integration\New-RideAutomatedLabVm.ps1 `
    -OperatingSystemName 'Windows 11 Enterprise Evaluation' `
    -PreflightOnly
```

Replace the example OS name with the exact entry for the ISO you plan to install. A Server 2025 ISO may expose a different name, such as a specific edition or installation mode; use its listed value. Choose a distinct lab and VM name for each OS. VM computer names must be 15 characters or fewer.

The preflight checks the current privilege token, AutomatedLab commands, Hyper-V CIM access, the `vmms` service, the LabSources ISO list, VM storage, existing WinNAT state, and host HTTPS access to PowerShell Gallery. It does not create resources. Fix all required failures before proceeding.

## Provision through checkpoint and step 6A

Run the script from the repository root. It creates a NAT-backed lab, installs the selected guest, checks guest network access through `Invoke-LabCommand`, installs Pester 5.7.1 through `Invoke-LabCommand`, shuts down the VM and creates a clean checkpoint, starts it, and copies the current checkout into `C:\RIDE\ride-windows` (the AutomatedLab branch of runbook step 6).

```powershell
.\tests\integration\New-RideAutomatedLabVm.ps1 `
    -OperatingSystemName 'Windows 11 Enterprise Evaluation' `
    -LabName 'RIDEWin11Test' `
    -VMName 'RIDE-Win11-Test' `
    -VMPath 'D:\VMs\RIDE-Win11-Test' `
    -WhatIf
```

Review the target and parameters from the `-WhatIf` output, then repeat without `-WhatIf` to create the lab. The script prompts for a local administrator account for the guest. It uses `-UseNat` on the lab network so the guest has outbound access without joining the physical LAN. TPM and Secure Boot are enabled by default for Windows 11 and Server 2025; use `-DisableTpm` or `-DisableSecureBoot` only when the selected OS requires different VM settings.

Windows Update is not automated because update and reboot behavior differs across guest releases and editions. By default, the script pauses after installation so you can complete Windows Update in the guest, including restarts, then press Enter on the host. To proceed without waiting, specify `-WindowsUpdateMode Continue`; the script warns that the checkpoint will capture the guest's current update state.

The checkpoint name is consistently `RIDE-clean-test-base` for each VM. Checkpoints belong to an individual VM, so using the same name for separate Windows 11 and Server 2025 VMs does not collide. Restore the checkpoint before each integration run, then copy the current checkout again because the checkpoint is created before the checkout copy.

The script can be run again in `-PreflightOnly` mode to diagnose host access. Do not rerun provisioning against an existing lab name; use a new lab and VM name for another guest OS or a clean installation.

## Hyper-V access errors and recovery

The preflight calls `Get-VMHost` using the current PowerShell token instead of
assuming that group membership grants usable access. Earlier restricted-shell
checks reported unavailable CIM access and an absent `vmms` service. A native
host inspection on 2026-10-08 found VMMS and WinRM running, accessible VM
inventory, and host UAC at Windows defaults, while the process itself remained
unelevated. Restricted-shell failures therefore do not establish that Hyper-V
is missing. AutomatedLab still requires an actually elevated controller token;
verify from the elevated host session before changing installation or policies.

For a CIM access error:

1. Open a new PowerShell window with **Run as administrator** and rerun `-PreflightOnly`.
2. If using group membership instead, add the account to **Hyper-V Administrators** from an elevated administrative session, then sign out and back in so the new token includes the group. Rerun preflight to confirm `Get-VMHost` succeeds.
3. If the `vmms` service is missing or stopped, enable/install the Hyper-V role/feature and management tools, reboot if requested, and rerun preflight. A group change cannot replace the Hyper-V role or service.
4. Check firmware virtualization and host storage if Hyper-V cannot start or create the VM. Review any existing WinNAT networks reported by preflight for address-prefix conflicts; do not remove host NAT entries automatically because other VMs or applications may depend on them.

Hyper-V Manager is a partial workaround when the AutomatedLab CIM path is unavailable: create and install a VM manually, then use the **PowerShellDirect** transport in [the main runbook](README.md#7-run-validation-and-the-integration-suite). This does not make `New-RideAutomatedLabVm.ps1` usable; that script requires working Hyper-V CIM access to provision through AutomatedLab.

After the script finishes, continue with [step 7 of the main integration runbook](README.md#7-run-validation-and-the-integration-suite). The integration suite has its own Windows target checks and should only run on a disposable VM.
