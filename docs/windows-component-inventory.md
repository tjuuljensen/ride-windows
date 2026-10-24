# Windows component inventory

Collect exact names and literal states before planning a Windows component change.
RIDE provides separate read-only observations for DISM optional features,
capabilities and Server Manager roles/features. This does not enable or remove a
component, acquire payloads, select servicing media or reboot Windows.

The inventory and saved-data lookup have isolated tests on Windows PowerShell 5.1
and PowerShell 7. Native collection still needs acceptance on each intended Windows
11 and Windows Server target. No component installer or supported-target claim is
introduced by these tools.

## Collect on an explicitly identified target

Start in the repository root in an **already elevated**, native-bitness PowerShell
process on the intended Windows computer. Use a local evidence directory you own.
The tool does not request elevation. While elevation is unavailable, postpone live
collection; saved JSON inspection and preview can run without elevation.

Inspect the intended target and independently confirm it is the right computer:

```powershell
[Environment]::MachineName
Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
    Select-Object EditionID, CurrentBuildNumber, UBR, InstallationType
```

Create an evidence directory explicitly if needed, then replace the placeholders
with that target's values and preview:

```powershell
.\tools\Export-RideComponentInventory.ps1 -Kind OptionalFeature,Capability `
    -ExpectedComputerName '<computer name>' -ExpectedBuild '<build number>' `
    -ExpectedEditionId '<edition ID>' -LogDirectory 'C:\Evidence' `
    -OutputPath 'C:\Evidence\components.json' -WhatIf
```

After verifying those values, omit `-WhatIf` to collect. Preview performs no native
query and creates no files. Collection checks the machine, edition and build before
querying, then checks again, including the update revision, before returning. A
changed context rejects the observation; diagnostic logs may remain.

Use `-Kind ServerFeature` for a separately requested Server Manager inventory.
The explicit client OS product type yields `NotApplicable` for that provider without
calling Server Manager. Missing modules or denied provider queries yield
`Unavailable`, not a claim that there are no components. Providers are never retried
through a different namespace or remote computer.

Collection writes uniquely named DISM diagnostic logs and may use scratch files in
the supplied local evidence directory. It does not use the default Windows DISM log
path. Server Manager does not receive a DISM log. Keep diagnostics alongside JSON
when reporting a failed provider; JSON reports the exception type without embedding
arbitrary error text. Existing JSON is refused, including a file created during
collection. A write failure can leave incomplete JSON; resolve the error and choose
a new filename. Retain or explicitly delete only your own evidence files.

## Read and select captured data

```powershell
Import-Module .\modules\RIDE.ComponentInventory.psm1
$inventory = Get-Content -LiteralPath 'C:\Evidence\components.json' -Raw | ConvertFrom-Json
$inventory.WindowsContext
$inventory.Providers | Select-Object Kind, Status, Coverage, ErrorId, LogPath
Find-RideWindowsComponentObservation -Inventory $inventory -Kind OptionalFeature -Name 'TelnetClient'
```

`Kind` completes its declared provider names. `Name` completes only names from the
selected, successfully captured provider in the supplied inventory, filtering by
the typed prefix without a Windows query. Provide `Inventory` and `Kind` before
completing `Name`. Exact lookup preserves identifier casing and never uses wildcards.
Importing the module and inspecting saved data do not query servicing or create logs.

| Lookup result | Meaning |
| --- | --- |
| `Observed` | Exact name was present in a completed provider observation. Its literal state is retained. |
| `NotObserved` | Exact name was absent within that completed provider's stated coverage. This is not proof of platform inapplicability. |
| `Unavailable` | Selected provider failed; partial rows are discarded. Consult its diagnostic log where available. |
| `NotApplicable` | Server Manager provider was intentionally not queried on an observed client OS. |
| `NotCollected` | That provider was not selected for this inventory. |

Optional-feature collection covers the Windows Foundation Package. Features in
other packages need their own explicitly scoped investigation. Capability names
include their native identity/version suffix; do not shorten them. A Server feature
with a similar name is a separate resource. Unknown future native states remain
literal observations rather than being converted to installed or absent.

## Limits before any servicing

The inventory is sequential, not atomic. There is a 4096-row bound per provider;
native DISM/Server Manager query duration has no hard timeout. A provider error or
invalid/duplicate row discards that provider's whole result, while other explicitly
requested providers may still complete. Saved files can be stale or edited and are
not authorization or recovery records.

Every result keeps `ReadyForMutation=false` and `RecoverySupported=false`. Payload
availability, parents/dependencies, management policy, pending reboot, hardware,
consumer data and matching source media are not established. Even an installed
component does not prove its files can be restored after removal. Installation,
removal and data recovery need an individually reviewed component procedure and
disposable-target acceptance. No whole-machine checkpoint is created by inventory.

Microsoft documents the provider boundaries in
[Get-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/get-windowsoptionalfeature?view=windowsserver2025-ps),
[Get-WindowsCapability](https://learn.microsoft.com/en-us/powershell/module/dism/get-windowscapability?view=windowsserver2025-ps)
and [Get-WindowsFeature](https://learn.microsoft.com/en-us/powershell/module/servermanager/get-windowsfeature?view=windowsserver2025-ps).
For future source selection, consult the
[Features on Demand guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11).

## Prepare the first client components

The accepted first choices are OpenSSH Client and Telnet Client, independently
selected and neither enabled by default. Larger components remain separate.
OpenSSH Server is also in v3 scope as a separate optional outcome, selected by
the user on 2026-10-24. It remains off by default and requires independent review
of its service, firewall rules, host keys, configuration ownership and recovery.
The Client's implementation, state and acceptance do not cover the Server.
RIDE.ClientComponentPreparation 0.3.0 consumes saved inventory only. From the
repository root in native PowerShell, without elevation:

```powershell
Import-Module .\modules\RIDE.ClientComponentPreparation.psm1
Get-RideClientComponentPreparationChoice -Inventory $inventory
$proposal = New-RideClientComponentPreparation -Inventory $inventory -Kind Capability -Name 'OpenSSH.Client~~~~0.0.1.0' -DesiredState Present -SourceMode LocalSource -SourcePath 'D:\Sources\FOD'
$proposal | Select-Object Status,Command,Parameters,Requirements
```

For Telnet use Kind OptionalFeature and exact Name TelnetClient. Name completion
uses the supplied captured provider; DesiredState and SourceMode complete their
declared choices. Present and Absent refer to each component independently.
Unknown/pending states, missing observations and domain controllers have no command
outline. Already desired literal states report NoChangeObserved.

Select Online explicitly to respect configured servicing sources and organizational
policy; it forbids SourcePath overrides. Select LocalSource explicitly with a local
drive source; UNC, device paths, traversal and expansion are refused. For OpenSSH
Client only, the lifecycle candidate checks a direct-child `OpenSSH-Client-Package`
CAB for the native architecture and reads its package identity before servicing.
Other LocalSource paths are not accepted by the lifecycle candidate. LocalSource
installation outlines include Source and LimitAccess. The DISM Online parameter
still selects the running OS; it does not select the RIDE network-source mode.

Microsoft documents LimitAccess as preventing Windows Update lookup. LocalSource
blocks that lookup only; configured-source fallback remains uninspected, so this
mode does not establish network isolation. Preparation records
`WindowsUpdateLookupBlocked` and reports `ConfiguredSourceFallback = NotInspected`;
it makes no overall `AllowNetworkFallback = false` claim. `SourceValidated` and
`NetworkBoundaryVerified` therefore remain false. The OpenSSH LocalSource preflight
requires the exact official CAB filename for the native architecture, reads one
matching CBS package identity whose Windows build matches the target build, and
records the CAB SHA-256. Restore to Present repeats those checks and requires the
same package identity, architecture and hash from the saved record. Microsoft's
inventory identifies this capability as non-satellite, so no language CAB is
required for this package. This preflight does not validate configured-source
fallback or establish Windows behavior. An existing directory or older saved
record alone is insufficient. The candidate remains unregistered and unsupported
pending native source, dependency, recovery and Windows acceptance.

Microsoft's Windows 11 Features on Demand inventory identifies OpenSSH Client as
the non-satellite `OpenSSH.Client~~~~0.0.1.0` capability, with an
`OpenSSH-Client-Package` CAB on the Windows 11 Languages and Optional Features
media. The media must match the Windows image version. Microsoft's source-order
guidance says DISM may check configured Group Policy locations after an explicit
source misses content; `LimitAccess` blocks Windows Update lookup but does not by
itself rule out a policy-configured network source. Telnet's `TelnetClient`
identity is an optional feature, and its source requirements need a separate
target-specific inventory; Telnet LocalSource apply/restore remains blocked. The
OpenSSH preflight verifies the selected CAB identity, architecture, build and hash,
but not servicing dependencies or source precedence. See the [OpenSSH requirement and policy
troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/cant-install-openssh-features),
[Windows 11 Features on Demand inventory](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod?view=windows-11),
and [DISM source order](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11).

Telnet outlines use NoRestart, omit All and never use Remove to delete payloads.
Capability cmdlets do not expose NoRestart; future execution must inspect restart
results without initiating a reboot. A prior DisabledWithPayloadRemoved feature
cannot be exactly restored just by disabling it. Removing a capability requires
separate reacquisition/dependency and recovery evidence.

### Removal recovery gate

On 2026-10-23, the user decided to restrict removal of OpenSSH Client and Telnet
Client to cases with a validated recovery source. Do not offer an `Absent`
transition when the original payload may be removed and cannot be reliably
reacquired and restored. The current runner is unregistered and does not yet
validate source identity, completeness, dependency coverage, or all network
fallback paths; it must not be treated as satisfying this gate. Disposable-target
acceptance must demonstrate source-matched apply and exact recovery before a
removal operation can be exposed. See the [decision record](migrations/decision-session-2026-10-17.md#deferred-package-and-client-component-recovery-decisions-2026-10-23).

### Local transition runner candidate

`RIDE.ClientComponentLifecycle.psm1` adds an unregistered candidate runner for these
two exact client components. It takes a fresh local inventory, checks computer,
build and edition, refuses Server installations and pending reboots, saves the literal
prior state under `%ProgramData%\RIDE\State\ClientComponents`, calls the selected
DISM transition only after `ShouldProcess`, and reads the resulting state back. It
never starts a restart. Restore refuses target/revision changes and state drift.
It also refuses a captured-state restore that would remove OpenSSH or discard
Telnet's payload-removed state without a validated matching recovery source; the
saved snapshot remains available. Restore to Telnet's Disabled state remains
available when the payload is present. The machine snapshot ACL is limited to
SYSTEM and Administrators.

From an elevated native PowerShell session on an intended disposable Windows VM,
use its freshly recorded identity and an existing local evidence directory to run
`Invoke-RideClientComponentTransition` with `-WhatIf` first. Online mode respects
configured servicing sources. LocalSource mode requires an explicit local source
path. For OpenSSH Client, the lifecycle candidate checks the exact architecture-
specific CAB filename and rejects a reparse point or empty file. It reads the CBS
package identity, requires the expected publisher package and target Windows build,
and records the CAB SHA-256. Restore repeats the checks and requires the same
package identity, architecture and hash. This preflight does not validate servicing
dependencies or prove every required payload member is present. `LimitAccess` blocks
Windows Update lookup, but policy-configured source fallback is not inspected, so
`NetworkBoundaryVerified` remains false. Telnet LocalSource validation is not
implemented. Absent transitions remain blocked until source completeness, dependency
coverage, network behavior and exact payload recovery are validated. The runner
rejects pre-Windows 11 client builds and is not connected to a catalog operation or
supported target.
Do not treat a local regression as Windows servicing acceptance. See the [dated
candidate record](migrations/remaining-migrations-follow-up.md#b06-client-component-guarded-lifecycle-candidate-2026-10-23).

These are data-only outlines, not executable plans: ReadyForMutation and
RecoverySupported stay false. No supported catalog target or profile is added.
The runner candidate does not prove policy/dependency readiness, source boundaries,
exact payload recovery or native target behavior. Retain the original inventory;
no Windows rollback is needed for local preparation. See the [dated validation](migrations/remaining-migrations-follow-up.md#b06-client-component-source-preparation-2026-10-17).

Parameter boundaries are documented by Microsoft for
[Add-WindowsCapability](https://learn.microsoft.com/en-us/powershell/module/dism/add-windowscapability?view=windowsserver2025-ps),
[Remove-WindowsCapability](https://learn.microsoft.com/en-us/powershell/module/dism/remove-windowscapability?view=windowsserver2025-ps),
[Enable-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature?view=windowsserver2025-ps)
and [Disable-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/disable-windowsoptionalfeature?view=windowsserver2025-ps).

## OpenSSH Server component boundary

OpenSSH Server is a distinct optional v3 outcome, individually selected and off
by default. Its capability identity is
`OpenSSH.Server~~~~0.0.1.0`; Windows Server 2025 installs it by default, so a
Server 2025 target may already have the capability without the user selecting it.
Capability presence must not start or automatically enable `sshd` or open inbound
SSH access. Microsoft documents that installing the capability creates and
enables the `OpenSSH-Server-In-TCP` firewall rule for TCP port 22. A RIDE install
candidate must capture the prior service/firewall state and disable only a rule
that installation newly creates, while leaving pre-existing service, firewall,
configuration and host-key state intact.

Starting `sshd` is a separate activation step. Its first start generates host
keys under `%ProgramData%\ssh` and generates `sshd_config` if that file is
missing. Never start the service as an installation side effect, copy private
host keys into RIDE snapshots, or delete keys/configuration during generic
component removal. A future explicit activation workflow needs its own
`ShouldProcess` boundary and reversible service/firewall state. Removal must
preserve unowned host keys/configuration and refuse if exact feature recovery
cannot be established or if the owned firewall rule has drifted.

Microsoft's Server 2025 default installation and UI enablement model means the
capability state alone does not express whether SSH is enabled. Readiness and
acceptance must record capability, service start mode/status, exact firewall
rule identity and enabled state, and the existence/hash/ownership of server
configuration and host-key files as separate evidence. The generic Windows
component provider captures only the capability. An unregistered
`RIDE.OpenSshServerObservation.psm1` candidate now records service, firewall and
bounded server-data observations separately; it does not capture private-key
bytes or establish atomic state, ownership, source completeness or recovery. Its
observation always remains not ready for mutation. No OpenSSH Server catalog
operation or supported target is added by this candidate.

An unregistered `RIDE.OpenSshServerLifecycle.psm1` candidate now handles only
explicit service activation and the enabled state of an already existing,
exact local inbound TCP/22 rule. It requires an already elevated session and
an installed capability; capability installation/removal and target support
remain separate work. The caller must choose `Manual` or `Automatic` service
startup and `Keep`, `Enabled` or `Disabled` for the firewall rule. `Keep` retains
the observed rule, so starting `sshd` while that rule is already enabled allows
inbound SSH. The operation does not create a firewall rule, start a service as a
capability-install side effect, or copy private-key bytes. It saves the prior
service and rule literals under the protected machine state directory before
mutation, verifies their post-state and refuses restore after target or literal
drift. Restore leaves any host keys or configuration generated by first start
in place and reports the difference; exact server-data recovery is unsupported.
All native lifecycle, first-start, network exposure and recovery acceptance on
Windows 11 and Windows Server 2025 remains deferred. The focused mocked
activation suite passes 11/11 on PowerShell 7.6.5, and both candidate files parse
under Windows PowerShell 5.1. This candidate remains unregistered and adds no
catalog operation, profile selection or supported target. See the
[activation regression evidence](archive/evidence/openssh-server-activation-lifecycle-local-candidate-2026-10-24-0816.json).

See [Microsoft's install and first-use guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse),
[Windows Server OpenSSH configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration),
[host-key management](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement),
the [source review](archive/evidence/openssh-server-current-source-review-2026-10-24-0412.json),
and [observer regression evidence](archive/evidence/openssh-server-observation-candidate-2026-10-24-0413.json).
