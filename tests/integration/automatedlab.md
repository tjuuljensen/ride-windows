# AutomatedLab setup for RIDE integration VMs

This guide uses the host-side script [New-RideAutomatedLabVm.ps1](New-RideAutomatedLabVm.ps1) to provision and prepare a disposable VM through the AutomatedLab equivalent of runbook steps 1 through 6A. It supports any guest OS that AutomatedLab discovers from an ISO in LabSources. The RIDE integration suite itself still declares its supported Windows targets separately.

For repeatable on-demand, watcher and CI testing while keeping **host UAC
enabled**, use the opt-in [task controller runbook](automatedlab-tasks.md).
Validate it on a separate pilot before redirecting an active lab.

## Host and lab prerequisites

- A Windows Pro, Enterprise, Education, or Windows Server host with hardware virtualization enabled and the Hyper-V role/feature installed. Hyper-V is not included with Windows Home.
- Hyper-V management tools and the Hyper-V Virtual Machine Management service (`vmms`) installed and running.
- An elevated host PowerShell session. Hyper-V Administrators membership can grant Hyper-V access but does not satisfy AutomatedLab's administrator-token checks.
- AutomatedLab installed and configured, including its LabSources directory. Follow the upstream [AutomatedLab installation guide](https://automatedlab.org/en/stable/Wiki/Basic/install/) and [Getting Started](https://automatedlab.org/en/stable/Wiki/Basic/gettingstarted/) guide first.
- The ISO for the selected guest OS in the `ISOs` directory under the configured LabSources location. For reference, Microsoft provides the [Windows 11 Enterprise Evaluation](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise) and [Windows Server 2025 evaluation](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025) downloads.
- Enough host storage for the ISO and VM files. The script reports available space and recommends at least 120 GB. The initial guest allocation is 8 GB and 4 virtual processors; adjust it with `-MemoryGB` and `-ProcessorCount` for the host and guest.
- Host internet access and a working outbound NAT path for the guest. `NetworkMode NewNat` (default) creates a new NAT; `ExistingNat` reuses an explicitly reviewed Internal switch and NAT with static guest addressing.

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

Run the script from the repository root. It creates a NAT-backed lab using either a new or reviewed existing network, installs the selected guest, checks guest network access through `Invoke-LabCommand`, installs Pester 5.7.1 through `Invoke-LabCommand`, shuts down the VM and creates a clean checkpoint, starts it, and copies the current checkout into `C:\RIDE\ride-windows` (the AutomatedLab branch of runbook step 6).

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

The checkpoint defaults to `RIDE-clean-test-base`; customize it with `-CheckpointName`. Checkpoints belong to an individual VM, so separate VMs may use the same checkpoint name. Restore before each integration run and stage the current checkout again because the clean checkpoint precedes staging.

After restarting, the script waits up to 10 minutes for PowerShell remoting,
then prepares and verifies the checkout directory before copying source. A guest
at the login screen can accept remote commands; no console sign-in is required
for these steps. Progress messages identify the checkpoint, startup, directory
preparation, copy and verification stages.

### Recover an interrupted checkout preparation

In script versions before 0.3.3, directory preparation returned no output.
AutomatedLab 5.61.0's worker uses returned objects' `RunspaceId` to recognize
completion, so that silent command could repeat 20 times with 30-second pauses
even when directory creation succeeded. Shutting down the guest during those
retries can produce `New-LabPSSession ... port is closed after 2 retries`.
The outer `Invoke-LabCommand -Retries 20` does not increase the worker's separate
session-recreation retry count. Version 0.3.3 returns directory readiness and
waits for remoting after the checkpoint restart.

If Pester installation succeeded and the clean checkpoint already exists,
keep the existing lab. From an elevated host PowerShell session, inspect it:

```powershell
Import-Module AutomatedLab
Import-Lab -Name 'RIDESrv2025Test' -NoValidation
Get-LabVMStatus -ComputerName 'RIDE-S25-Test'
Get-LabVMSnapshot -ComputerName 'RIDE-S25-Test'
```

Confirm that `RIDE-clean-test-base` exists, then finish checkout staging using
[runbook step 6A](README.md#6a-if-the-vm-was-created-with-automatedlab), substituting
the lab and VM names above and your configured guest path if it differs from
`C:\RIDE\ride-windows`. That step starts the VM, waits for remoting, returns
directory readiness and verifies the copied checkout. If remoting still fails
after startup, inspect guest networking and WinRM before copying; this error
alone does not establish a Windows installation failure.

Do not rerun `New-RideAutomatedLabVm.ps1` against this existing lab: its collision
checks deliberately reject it. An interrupted run has not produced the final
ready message and may not have written `AutomationSeedPath`; staging recovery
does not generate that seed or register a controller. Keep controller
registration separate as described below.

## Local configuration and downstream inheritance

Copy `provisioning.win11.example.psd1`, `provisioning.server2025.example.psd1`,
or `provisioning.server2025.shared-network.example.psd1`
outside the checkout, for example to `C:\RIDE-Automation\server2025.psd1`.
Choose the exact OS name and distinct lab, VM and storage values. NewNat also
requires an unused network name; ExistingNat uses the existing switch name.
The Server template deliberately requires the real ISO entry before use.

```powershell
.\tests\integration\New-RideAutomatedLabVm.ps1 `
    -ConfigurationPath 'C:\RIDE-Automation\server2025.psd1' -PreflightOnly
.\tests\integration\New-RideAutomatedLabVm.ps1 `
    -ConfigurationPath 'C:\RIDE-Automation\server2025.psd1' -WhatIf
# After reviewing preflight/preview, repeat without -WhatIf to provision.
```

Explicit CLI values override the local file; omitted values use the file and
then documented defaults. For example, `-MemoryGB 12` overrides the file's 8 GiB.
Tab completes `WindowsUpdateMode` and `NetworkMode`; `OperatingSystemName` completion reads only
an already imported AutomatedLab ISO cache, silently returning no suggestions
when unavailable. It never imports AutomatedLab or scans media for completion.

| Field | Meaning and downstream use |
| --- | --- |
| `OperatingSystemName`, optional `IsoPath` | Exact ISO image/edition/install mode; IsoPath disambiguates multiple media. The selected OS object, including its ISO path, is passed to AutomatedLab so it cannot select a newer duplicate silently. Registration records the ISO hash. |
| `LabName` | AutomatedLab definition imported by the controller for every request. |
| `VMName` | Guest computer/Hyper-V name, at most 15 characters. Provisioning discovers its GUID; registration verifies name and GUID together. |
| `VMPath` | New or empty host storage for this lab; not a guest path or test source path. |
| `NetworkName` | New switch name for NewNat, or existing Internal switch name for ExistingNat. Switches are never replaced. |
| `NetworkMode` | NewNat (default) requires no existing host NAT. ExistingNat validates the shared topology and does not create or reconfigure its switch/NAT. |
| `NatName` | Exact existing host WinNAT name; required with ExistingNat. It may differ from NetworkName. |
| `GuestIpv4Address` | Explicit reserved guest address/prefix, such as 192.168.11.50/24; required with ExistingNat. Its subnet must exactly match the NAT prefix. |
| `Ipv4Gateway` | Existing host switch gateway, with the same prefix as the guest; required with ExistingNat. |
| `Ipv4DnsServers` | Explicit IPv4 resolvers reachable from the guest; required with ExistingNat. WinNAT does not provide DHCP or DNS. |
| `MemoryGB`, `ProcessorCount` | Provisioning resources; registration records actual VM settings. Defaults: 8 GiB and 4 processors. |
| `DisableTpm`, `DisableSecureBoot` | Boolean provisioning choices. Both default false; the existing Windows 11 VM is not reconfigured. |
| `WindowsUpdateMode` | `Wait` requires operator confirmation after updates; `Continue` preserves the current update state. Tests do not update Windows. |
| `GuestRepositoryPath` | Actual staged checkout inside the guest; must end with `ride-windows`. Used unchanged by test requests. |
| `CheckpointName` | Clean baseline created before source staging. Registration pins its discovered GUID. |
| `AutomationName` | Controller name/task/result namespace; defaults to LabName. One configuration per VM. |
| `CIRepositoryPath` | Separate host CI checkout used only for `-Source CI`; Local uses the provisioning checkout. |
| `AutomationSeedPath` | New local `.json` registration seed; requires CIRepositoryPath. Existing files are not overwritten. |

The inheritance path is **local provisioning PSD1 → provisioned VM → generated
controller JSON seed → registered protected configuration → test request**.
No values are inherited from whichever lab happens to be imported in a shell.
Registration remains explicit:

```powershell
.\tests\integration\Register-RideVmTestTask.ps1 `
    -ConfigurationPath 'C:\RIDE-Automation\server2025-controller.json' -WhatIf
# Review, then register from elevated PowerShell without -WhatIf.
```

The generated seed includes discovered VM identity and source/guest paths.
Registration pins checkpoint identity, account, dependencies, ISO hash and
installed controller hashes. Each request selects that registered configuration;
it cannot substitute another VM. Guest credentials stay in AutomatedLab's
existing lab storage and are never emitted into the seed.

The existing Server 2025 lab passed the applicable direct AutomatedLab suite
on 2026-10-11; see the [recorded runtime evidence](automatedlab-tasks.md#server-2025-direct-automatedlab-evidence-2026-10-11).
Acceptance of the reusable provisioning workflow and registered Server task
controller remains pending. Each selected ISO must pass preflight before
deployment. Other future
ISO images may be provisioned, but the integration suite and operation support
declarations remain independently limited to tested targets.

Windows supports one WinNAT internal subnet prefix per host. Distinct network
names do not remove that limit. NewNat blocks when any host NAT already exists.
For a second lab on the same host, use ExistingNat as described below.
[Microsoft's NAT limitations](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/setup-nat-network#multiple-nat-networks-are-not-supported).

The script can be run again in `-PreflightOnly` mode to diagnose host access. Do not rerun provisioning against an existing lab name; use a new lab and VM name for another guest OS or a clean installation.

## Add a second lab using the existing NAT

For the inspected RIDE host, `RIDE-Win11-Test` uses the Internal switch
`RIDE-Internet`, NAT `RIDE-Internet` has prefix `192.168.11.0/24`, and the host
switch gateway is `192.168.11.1/24`. The shared-network Server template uses
these values and proposes `192.168.11.50/24` for the new guest. Reserve that
address after reviewing existing assignments; change it if already allocated.
The template uses public DNS resolvers; substitute resolvers required by the
local network. It never assumes that the NAT gateway also provides DNS.

From `tests/integration`, preview the template before creating resources:

```powershell
.\New-RideAutomatedLabVm.ps1 `
    -ConfigurationPath .\provisioning.server2025.shared-network.example.psd1 -PreflightOnly
.\New-RideAutomatedLabVm.ps1 `
    -ConfigurationPath .\provisioning.server2025.shared-network.example.psd1 -WhatIf
# After reviewing the addressing and preview, repeat without -WhatIf.
```

For ongoing use, copy the template to a local file outside the checkout and
adjust the path in these commands. SchemaVersion 1 files remain compatible;
the new fields are optional unless ExistingNat is selected.

Preflight requires exactly one host WinNAT, the named existing Internal switch,
an exactly matching subnet and an existing host gateway on that switch.
It checks the proposed guest address against host addresses, Hyper-V-reported
guest addresses and saved AutomatedLab machine definitions, including stopped
VMs. Reading definitions does not call Import-Lab or replace the active lab
context. If a VM on the shared switch has neither reported IPv4 addresses nor
saved static reservations, preflight stops rather than assuming its addresses
are free. Unreadable saved definitions also stop provisioning. Silent unmanaged
devices and DHCP leases outside AutomatedLab require operator review; absence
of a known conflict is not proof that an address is unallocated.

The script explicitly passes `UseNat = false` to AutomatedLab and supplies the
guest's address, gateway and DNS. The installed AutomatedLab 5.61.0 network
worker skips configuration of a switch that already exists; the script checks
the inventory again before definition and deployment. No NAT, switch or host
gateway is removed or reconfigured by the shared-network path. AutomatedLab
still creates the new lab and guest, and the checkpoint, staging and controller
seed workflow is unchanged. Host deployment and guest connectivity remain
pending until the elevated preflight/preview and disposable-VM pilot succeed.

The VMs share a subnet and can communicate with each other. This is suitable
for these workgroup test VMs; it does not establish an isolated domain/DHCP lab.
Keep the shared switch/NAT's ownership metadata with its original lab. When
retiring a lab, review its network dependencies first: do not delete the shared
switch, its gateway or NAT while another lab uses it. AutomatedLab's installed
removal code checks ownership and connected VMs, but this is not a general
shared-resource lifecycle guarantee across versions. Do not force removal.

After successful provisioning, register the generated Server controller seed
using the commands above in the registration section. Each VM retains its own
lab, checkpoint and controller identity even though they share a network.

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
