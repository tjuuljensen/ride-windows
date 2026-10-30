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
selected and neither enabled by default. RSAT, Hyper-V, Windows Sandbox and WSL
are also selected for v3 migration review as separate, individually selectable
outcomes. Their review does not enable them or add them to default profiles.
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
drive source; UNC, mapped network drives, device paths, traversal and expansion are
refused. For OpenSSH
Client only, the lifecycle candidate checks a direct-child `OpenSSH-Client-Package`
CAB for the native architecture and reads its package identity before servicing.
Other LocalSource paths are not accepted by the lifecycle candidate. OpenSSH Client
removal is refused in Online mode and allowed by the candidate only with that
validated LocalSource CAB retained; restoring a LocalSource removal revalidates
its recorded identity, architecture and digest. LocalSource
installation outlines include Source and LimitAccess. The DISM Online parameter
still selects the running OS; it does not select the RIDE network-source mode.

Microsoft documents the source order for DISM capability installation:
explicit Source locations are searched first, Group Policy-configured sources
are checked if the required files are not found there, and Windows Update is
checked only when LimitAccess is not supplied. LimitAccess prevents Windows
Update/WSUS lookup; it does not disable policy-configured source fallback.
Preparation records WindowsUpdateLookupBlocked and
ConfiguredSourceFallback = NotInspected because outline generation does not
inspect machine policy. Before a LocalSource lifecycle transition, the runner
reads `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath`;
it refuses servicing when that value is nonempty and fails closed if policy
cannot be inspected. This prevents the documented Group Policy fallback from
being used after an explicit source misses required files. RIDE does not override
policy or claim complete network isolation. During a LocalSource lifecycle
transition, `SourceValidated` means only that the expected CAB identity,
architecture, Windows build and recorded hash were checked; it does not
establish repository completeness, dependency availability or network
isolation. `ConfiguredSourceFallback = InspectedAbsent` records that the policy
value was checked and absent for that transition. `NetworkBoundaryVerified`
remains false. The OpenSSH LocalSource preflight
requires a ready non-network drive, the exact official CAB filename for the native
architecture, rejects a path that traverses reparse points, reads one matching CBS
package identity whose Windows build matches the target build, and records the CAB
SHA-256. Restore repeats those checks and requires the same package
identity, architecture and hash from the saved record, including when restoring a
prior NotPresent state. Microsoft's inventory identifies this capability as
non-satellite, so no language CAB is required for this package. A matching CAB
does not prove repository completeness, dependency availability, exact
payload/version recovery or native Windows behavior. An
existing directory or older saved record alone is insufficient. The candidate
remains unregistered and unsupported pending those checks and Windows acceptance.

See Microsoft's [DISM capability source-order documentation](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-capabilities-package-servicing-command-line-options), [Configure a Windows repair source](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-a-windows-repair-source?view=windows-11), and [Add-WindowsCapability source parameter](https://learn.microsoft.com/en-us/powershell/module/dism/add-windowscapability?view=windowsserver2025-ps).

Microsoft's Windows 11 Features on Demand inventory identifies OpenSSH Client as
the non-satellite `OpenSSH.Client~~~~0.0.1.0` capability, with an
`OpenSSH-Client-Package` CAB on the Windows 11 Languages and Optional Features
media. The media must match the Windows image version. Microsoft's source-order
guidance says DISM may check configured Group Policy locations after an explicit
source misses content; `LimitAccess` blocks Windows Update lookup but does not by
itself rule out a policy-configured network source. The OpenSSH LocalSource
lifecycle now blocks when this target policy is configured or cannot be read;
the Telnet candidate has no equivalent guard because its source validation is
not implemented. Telnet's `TelnetClient`
identity is an optional feature, and its source requirements need a separate
target-specific inventory; all four registered LabSources ISOs have no Telnet-named entry, and the checked SoftwarePackages/OSUpdates roots contain no separate matching Languages and Optional Features source. Telnet LocalSource apply/restore remains blocked pending that media and package identity; see [UDF listing evidence](archive/evidence/telnet-fod-iso-udf-listing-recheck-2026-10-26-0603.json). The
OpenSSH preflight verifies the selected CAB identity, architecture, build and hash,
and the Group Policy fallback guard, but not servicing dependencies or complete
network isolation. See the [OpenSSH requirement and policy
troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/cant-install-openssh-features),
[Windows 11 Features on Demand inventory](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-non-language-fod?view=windows-11),
and [DISM source order](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11).

On 2026-10-27, the two Microsoft Features on Demand references were rechecked
for `Telnet`: neither identifies a Telnet package name or source layout. The
general media guidance requires release-matched Languages and Optional Features
media and a complete metadata-backed repository for satellite packages; it does
not establish that Telnet is a satellite feature. Keep Telnet LocalSource blocked
until target-specific package identity and source completeness are demonstrated.
See the [dated source-boundary evidence](archive/evidence/telnet-microsoft-fod-source-boundary-recheck-2026-10-27-0521.json).

On 2026-10-27 08:18 UTC, a recursive read-only scan of the existing Z:\LabSources share found no OpenSSH-Client-Package CAB, Languages and Optional Features source, or FOD-named file. Its four setup ISOs remain unverified as matching OpenSSH Client FOD media; OSUpdates and SoftwarePackages contain README files only. Keep OpenSSH Client source-matched lifecycle and Telnet LocalSource blocked. OpenSSH Server is an inbox capability and is handled separately. See [current source and VM access evidence](archive/evidence/b06-labsources-recursive-fod-source-recheck-and-vm-access-2026-10-27-0818.json).

On 2026-10-28 16:55 UTC, the LocalSource guard also checks the target's Group Policy `LocalSourcePath` before CAB metadata inspection, state capture or servicing; a configured fallback or policy-read error fails closed. The fallback inspection result is retained in the run snapshot, and restore repeats the guard. Source review and mocked tests cover the source-order edge case; PowerShell parsing is the available local validation, with Pester assertions and Windows servicing acceptance still unverified. No real registry, CAB, DISM, VM or Defender state was accessed or changed. Full source completeness, dependencies, exact payload recovery and network isolation remain unproven. See [dated guard evidence](archive/evidence/b06-openssh-local-source-gpo-fallback-guard-2026-10-28-1655.json).

On 2026-10-28 17:03 UTC, the configured-source inspection state is also exposed in preview, applied, restored and already-restored results; no-change paths report that no source inspection occurred. A focused mocked test checks that restore refuses a newly configured policy fallback before native servicing. The module and test file parse, but Pester assertions and Windows servicing acceptance remain unverified. See [result-reporting evidence](archive/evidence/b06-openssh-local-source-fallback-result-reporting-2026-10-28-1703.json).

On 2026-10-28 17:09 UTC, the module help was corrected to describe the policy guard and the lifecycle module version was bumped to 0.4.4. The module and focused test file parse, and repository validation passes; Pester assertions, catalog integration and Windows acceptance remain open. See [help/version evidence](archive/evidence/b06-client-component-help-version-reconciliation-2026-10-28-1709.json).

On 2026-10-28 16:24 UTC, the LocalSource path guard was extended to reject mapped network drives and reparse-point components from the drive root through the source folder; the direct path helper probe and PowerShell parser checks passed. Pester assertions remain unverified, and no native servicing or VM acceptance ran. See [path-guard evidence](archive/evidence/b06-openssh-local-source-reparse-path-guard-2026-10-28-1624.json).

On 2026-10-27 12:58 UTC, the current-source OpenSSH Client/Telnet preparation, lifecycle and inventory suites passed 67/67 on PowerShell 7.6.5 and 67/67 on Windows PowerShell 5.1.26100.9711. Microsoft FOD references were rechecked: OpenSSH Client remains a non-satellite CAB with release-matched media, while Telnet's package identity is not established. The LocalSource network boundary and exact payload/dependency recovery remain unproven; the candidate stays unregistered and unsupported. Latest host VM inspection at 12:51 UTC failed at CIM before dispatch. See [regression evidence](archive/evidence/b06-client-component-cross-shell-current-source-regression-and-vm-block-2026-10-27-1258.json) and [VM access evidence](archive/evidence/ride-win11-test-cim-access-recheck-2026-10-27-1251.json).

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
and records the CAB SHA-256 and configured-source-fallback inspection result in
the run snapshot. Restore repeats the checks and requires the same package
identity, architecture and hash, and repeats the Group Policy fallback guard.
This preflight does not validate servicing dependencies or prove every required
payload member is present. Microsoft documents that Group Policy-configured
sources may be checked after an explicit source misses required files;
`LimitAccess` blocks Windows Update/WSUS lookup, while the new policy guard
refuses LocalSource servicing if that configured fallback exists. Full network
isolation remains unverified, so `NetworkBoundaryVerified` remains false. Telnet LocalSource validation is not
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
component removal. The `windows.openssh-server-service` operation has
its own `ShouldProcess` boundary and controls only service state. The pending
`windows.openssh-server-firewall` setting controls only the already-existing
local OpenSSH inbound rule; it checks the capability and exact rule identity,
does not create rules, and does not start `sshd`. Removal must preserve unowned
host keys/configuration and refuse if exact feature recovery cannot be
established or if the owned firewall rule has drifted.

Microsoft's Server 2025 default installation and UI enablement model means the
capability state alone does not express whether SSH is enabled. Readiness and
acceptance must record capability, service start mode/status, exact firewall
rule identity and enabled state, and the existence/hash/ownership of server
configuration and host-key files as separate evidence. The catalog exposes
`component.openssh-server-capability` for capability lifecycle and
`windows.openssh-server-service` for explicit service state. The service
operation requires the Server capability to be installed and does not change
firewall exposure. `windows.openssh-server-firewall` separately controls only
the exact existing TCP/22 inbound rule. All three operations are registered, but remain pending native acceptance and have no supported target until disposable Windows 11 and Windows Server 2025 acceptance passes.

The source-only `RIDE.OpenSshServerObservation.psm1` candidate records service,
firewall and bounded server-data observations separately; it does not capture
private-key bytes or establish atomic state, ownership, source completeness or
recovery. The source-only `RIDE.OpenSshServerLifecycle.psm1` candidate still
combines explicit service activation with the enabled state of an already
existing exact local inbound TCP/22 rule. It is not wired as a catalog
operation. Its firewall behavior must not be inferred from the catalog service
operation; the catalog firewall setting is implemented through the bounded
network-control handler and does not use that combined candidate.

Starting `sshd` while an inbound rule is already enabled allows incoming SSH.
The capability operation does not start the service or open the firewall.
First-start host keys and configuration are not exactly restored by current
catalog operations. All native lifecycle, first-start, network exposure and
recovery acceptance remains deferred. The latest OpenSSH lifecycle, observer
and capability suites passed 34/34 focused tests. The catalog and network
control suites discovered 109 tests: 108 passed, none failed or skipped, and
one WindowsIntegration test was not run. Native providers were mocked and no
Windows state changed. The component, service and firewall operations remain
unsupported until native acceptance. Read-only VM access previously failed at
CIM before inspection; no VM acceptance ran. See [current regression evidence](archive/evidence/openssh-server-current-winps51-regression-2026-10-28-0358.json),
the [current firewall regression and VM access evidence](archive/evidence/openssh-server-independent-firewall-setting-and-vm-block-2026-10-27-1103.json),
the [service regression](archive/evidence/openssh-server-service-component-catalog-current-regression-and-vm-block-2026-10-27-1047.json),
the [capability integration evidence](archive/evidence/openssh-server-engine-catalog-integration-2026-10-27-1031.json),
and the [source-only lifecycle evidence](archive/evidence/openssh-server-current-regression-and-vm-access-2026-10-24-2344.json).

On 2026-10-25, the current-source focused regression passed 44/44 across
OpenSSH Server lifecycle, OpenSSH Server observation, ComponentInventory and
F1Help Pester suites; Windows PowerShell 5.1 parsed all seven candidate and test
files. Tests used mocks and repository-local temporary files. A repeat read-only
`Get-VM` query failed at CIM before VM or checkpoint inspection. No candidate was
registered, no Windows or Defender state changed, and no fresh elevation was
requested. Native OpenSSH, client FoD servicing and physical F1 acceptance remain
deferred. See [current regression and VM access evidence](archive/evidence/component-candidate-current-regression-and-vm-access-2026-10-25-0524.json).

See [Microsoft's install and first-use guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse),
[Windows Server OpenSSH configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration),
[host-key management](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement),
the [source review](archive/evidence/openssh-server-current-source-review-2026-10-24-0412.json),
and [observer regression evidence](archive/evidence/openssh-server-observation-candidate-2026-10-24-0413.json).

### User decision: unattended installation with separate activation, 2026-10-27

The user selected OpenSSH Server as an explicit option available to unattended
RIDE setup, with installation separate from activation. Model capability
installation independently from starting `sshd` and enabling inbound firewall
access. The selected installation operation must not activate the service or
expose TCP 22 as a side effect. Keep activation and firewall exposure separately
selectable and off in defaults; profiles may request either state deliberately.
Continue to preserve pre-existing service, firewall, configuration, and host-key
state. This records scope and workflow intent only: the current candidates remain
unregistered, native lifecycle and recovery acceptance remain open, and no
supported Windows target is declared.

The user confirmed on 2026-10-27 that the guarded removal boundary remains in
force: RIDE-managed removal is unavailable when service, firewall or
`%ProgramData%/ssh` state existed before RIDE installed the capability. The
generic lifecycle must not remove a pre-existing OpenSSH Server installation.

### OpenSSH Server capability installation candidate, 2026-10-27 06:37 UTC

An unregistered RIDE.OpenSshServerCapabilityLifecycle.psm1 candidate now
installs only OpenSSH.Server~~~~0.0.1.0. It requires an already elevated,
explicitly identified native Windows target, checks servicing-restart and
pre-install observations, previews through ShouldProcess, supports an
explicit local source with -LimitAccess, and records the pre-install service,
firewall and server-data observation in a protected state directory. It never
starts sshd. Microsoft documents that capability installation creates and
enables OpenSSH-Server-In-TCP; the candidate restores an absent/disabled
pre-install rule to disabled after servicing, preserves a pre-existing enabled
rule, and verifies the exact service and firewall identities. The prior
RIDE decision was to keep activation and network access separately selectable.
An already enabled firewall rule is preserved by the install-only workflow;
users must review that existing exposure separately.

The focused install suite passed 6/6; the combined capability-install, observer and activation suites passed 24/24 on PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711/Pester 5.7.1. Repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. The combined run disabled TestRegistry and TestResult plugins. All native calls were mocked.
The first two attempts stopped before test discovery because the optional
Pester TestRegistry plugin could not create its HKCU fixture in the sandbox;
the configured run with the plugin disabled completed. No capability, service,
firewall, VM, Windows or Defender state changed. The candidate does not yet
support exact capability removal/recovery or catalog/engine registration.
Native Windows 11 and Server 2025 acceptance remains required, including
verification of servicing's firewall effect and preservation of existing
server data. See [focused evidence](archive/evidence/openssh-server-capability-install-candidate-2026-10-27.json)
and Microsoft's [OpenSSH Server installation guidance](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse).

### OpenSSH guarded removal candidate and cross-shell regression, 2026-10-27 06:50 UTC

The install candidate now writes a completed snapshot containing the exact post-install capability, service, firewall and server-data observations. Remove-RideOpenSshServerCapability requires that snapshot and refuses if any recorded surface has drifted or sshd is running. It supports reversal only when no sshd service, OpenSSH firewall rule or ProgramData\ssh file existed before installation. The remover validates that servicing leaves the service and capability absent, removes only a disabled TCP/22 rule shown by the snapshot to have been created during install if DISM leaves it behind, and records repeatable removal after the full post-state is verified. Removal remains unregistered pending native acceptance.

The combined install, observer and activation suites passed **30/30** on PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711/Pester 5.7.1 with native providers mocked and optional Pester registry/result plugins disabled. Repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. No capability, service, firewall, VM, Windows or Defender state changed. Catalog integration, native Windows 11 and Server 2025 acceptance, and handling of pre-existing service/firewall/data remain deferred. See [structured evidence](archive/evidence/openssh-server-capability-install-candidate-2026-10-27.json) and [Microsoft Remove-WindowsCapability reference](https://learn.microsoft.com/en-us/powershell/module/dism/remove-windowscapability?view=windowsserver2025-ps).

### Current-source rerun, 2026-10-27 06:55 UTC

The capability install/remove, observation and activation suites passed **30/30** on PowerShell 7.6.5/Pester 5.7.1 after disabling optional TestRegistry and TestResult plugins. The first invocation failed before discovery because the sandbox denies Pester's HKCU fixture; the rerun completed all assertions. Repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. The run used mocked native providers and changed no VM or Windows state. The candidate remains unregistered; native Windows 11 and Server 2025 acceptance remain open. See [structured regression evidence](archive/evidence/openssh-server-capability-current-regression-2026-10-27-0655.json).


### OpenSSH candidate current-source rerun and VM access, 2026-10-27 07:14 UTC

The install/remove, observation and activation candidate suites passed **30/30** on PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9711/Pester 5.7.1; repository validation passed for 429 operations, 8 groups, 5 profiles and 294 PowerShell files. Native providers were mocked. VM and registered-task access failed at CIM before inspection, leaving native Windows 11/Server 2025 acceptance deferred. The candidate remains unregistered with no supported targets. See [structured evidence](archive/evidence/openssh-candidate-cross-shell-regression-and-vm-access-2026-10-27-0714.json).

### OpenSSH Server current-source regression, 2026-10-27 07:44 UTC

The install/remove, observation and activation suites passed **30/30** on
PowerShell 7.6.5/Pester 5.7.1 with TestRegistry and TestResult disabled.
Repository validation passed for 429 operations, 8 groups, 5 profiles and 294
PowerShell files. All native providers were mocked. No VM, Windows, service,
firewall, capability or Defender state changed. The candidate remains
unregistered; catalog integration and Windows 11/Server 2025 acceptance remain
open. The latest VM/task inspection remains blocked at CIM before inspection or
dispatch. No legacy outcome closed and estimates remain unchanged. See
[structured evidence](archive/evidence/openssh-server-current-source-regression-and-repository-validation-2026-10-27-0744.json).

### Telnet Client official identity and source-boundary recheck, 2026-10-27 07:48 UTC

Microsoft's current OptionalFeatureList example confirms `TelnetClient` as the
exact optional-feature name and demonstrates its `NotPresent` and `Installed`
states. The current non-language Features on Demand list does not identify
Telnet Client as a capability or provide a matching CAB/package name. Matching
media, package identity, architecture/build/language fit, dependencies, source
precedence, recovery and native acceptance remain open; keep `LocalSource`
blocked. No servicing or VM action occurred. See [structured source evidence](archive/evidence/telnetclient-official-optional-feature-identity-current-review-2026-10-27-0748.json),
Microsoft's [optional-feature example](https://learn.microsoft.com/en-us/powershell/dsc/reference/resources/microsoft/windows/optionalfeaturelist/examples/get-optional-feature?view=dsc-3.0),
[available Features on Demand](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-features-on-demand-non-language-fod?view=windows-11),
and [Features on Demand guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11).

### OpenSSH Server caller-owned run ID adapter, 2026-10-27 09:01 UTC

The guarded capability installer now accepts a caller-owned RIDE run ID and uses it for both prepared and completed snapshots. This is a recovery-contract prerequisite for engine integration; it does not register or expose the operation. The combined install/remove, observation and activation candidate suites passed **31/31** on PowerShell 7.6.5/Pester 5.7.1 with native providers mocked and optional TestRegistry/TestResult plugins disabled. No capability, service, firewall, VM, Windows or Defender state changed. The candidate remains unregistered: the engine has no Windows capability lifecycle kind yet, its current-state/apply/generic-restore paths still need adapter wiring, and activation and inbound firewall access must become separately selectable. Keep supported targets empty pending native Windows 11 and Server 2025 acceptance. No legacy outcome closed and estimates remain unchanged. See [structured evidence](../archive/evidence/openssh-server-caller-runid-adapter-regression-2026-10-27-0901.json) and [latest VM/task access evidence](../archive/evidence/ride-win11-test-cim-and-task-access-recheck-2026-10-27-0856.json).

### OpenSSH Server engine/catalog integration, 2026-10-27 10:31 UTC

The OpenSSH Server capability now has a catalog operation and engine adapter for inspection, install, guarded RIDE-owned removal and saved-run recovery. It is classified as a Windows component rather than a setting/package and is available in the components discovery view. The operation has no supported targets until native Windows 11 and Windows Server 2025 acceptance passes. The three mocked OpenSSH candidate suites passed 32/32; focused catalog projection passed 2/2; repository validation passed for 430 operations, 8 groups, 5 profiles and 294 PowerShell files. The existing VM/controller access blocker prevents target acceptance. Capability installation does not start `sshd` or open TCP 22; service activation and firewall exposure remain separate choices and are not registered by this capability operation. See [structured evidence](archive/evidence/openssh-server-engine-catalog-integration-2026-10-27-1031.json).


### VM/controller access recheck, 2026-10-27 10:34 UTC

Read-only `Get-VM -Name RIDE-Win11-Test` and registered-task enumeration both failed at CIM before inspection. No checkpoint or guest state was read, no acceptance was dispatched, and no host, guest, Defender or UAC state changed. Windows 11 and Server 2025 support remains undeclared. See [structured VM/task access evidence](archive/evidence/ride-win11-test-vm-and-task-cim-access-recheck-2026-10-27-1034.json).

### OpenSSH capability preacceptance engine regression, 2026-10-27 10:38 UTC

Catalog/engine tests passed 3/3; the mocked capability, observation and activation candidate suites passed 32/32. The CLI components view surfaces the capability with no supported targets. An install plan is available for review but apply refuses before installer invocation pending native acceptance. The latest VM/task queries failed at CIM before inspection. See [structured evidence](archive/evidence/openssh-server-preacceptance-engine-regression-2026-10-27-1038.json) and [VM/task access blocker](archive/evidence/ride-win11-test-vm-and-task-cim-access-recheck-2026-10-27-1034.json).

### OpenSSH independent firewall setting and VM access, 2026-10-27 11:03 UTC

Added the exact existing OpenSSH inbound rule as its own pending setting. It requires the OpenSSH Server capability, validates the existing local PersistentStore inbound allow rule for TCP/22, and changes/restores only its enabled flag. It does not install the capability, start sshd, create rules or change other rules. The Catalog and NetworkAndSoundControls suites passed 108 tests with 0 failures and one live-registry case not run. Repository validation passed for 432 operations, 8 groups, 5 profiles and 294 PowerShell files; CLI settings listing shows the pending candidate. Read-only RIDE-Win11-Test VM/task checks failed at CIM before inspection; no acceptance or machine change. Native Windows 11/Server 2025 behavior, service/firewall interaction, and first-start data recovery remain deferred. See [structured evidence](archive/evidence/openssh-server-independent-firewall-setting-and-vm-block-2026-10-27-1103.json).


### OpenSSH Client/Telnet and component-inventory current-source regression, 2026-10-28 05:01 UTC

The current preparation, lifecycle and inventory suites passed 70/70 on Windows PowerShell 5.1.26100.9711/Pester 5.7.1 (28/23/19), with TestRegistry and TestResult disabled. Servicing and inventory providers were mocked; CAB cases used synthetic fixtures. No DISM command, Windows provider query, registry, VM, Defender or Windows state was accessed or changed. This is source-level regression evidence only. OpenSSH Client/Telnet remain unregistered and unsupported pending media/source completeness, dependencies, effective target policy, exact recovery and disposable Windows acceptance. See [structured evidence](archive/evidence/client-components-current-source-winps51-regression-2026-10-28-0501.json) and the [latest VM access record](archive/evidence/ride-win11-test-cim-access-recheck-2026-10-28-0453.json).

### Focused current-source regression, 2026-10-28 17:51 UTC

The component inventory, client preparation/lifecycle and OpenSSH Server capability/lifecycle/observation suites passed 109/109 in PowerShell 7.6.5/Pester 5.7.1. TestRegistry and TestResult plugins were disabled and all servicing/provider boundaries were mocked or synthetic. No DISM command or VM was accessed. No Defender-blocked utility was selected or touched. This confirms local regression only; OpenSSH Client/Telnet remain unregistered and unsupported pending exact source completeness, dependencies, recovery and disposable Windows acceptance. OpenSSH Server support remains pending native Windows 11/Server 2025 acceptance. See [structured evidence](archive/evidence/component-current-source-pester-regression-ps7-2026-10-28-1751.json).

### Windows PowerShell 5.1 cross-shell regression, 2026-10-28 18:04 UTC

The six component suites passed in the 145/145 Windows PowerShell 5.1.26100.9711/Pester 5.7.1 run, alongside BitLocker workflow, drive-method policy and F1 suites. Pester loaded under process-only ExecutionPolicy Bypass; persistent policy remained unchanged. TestRegistry/TestResult were disabled, and native servicing/provider calls were mocked or synthetic. No VM or Windows state changed. This verifies source behavior in a second PowerShell edition; OpenSSH Client/Telnet and OpenSSH Server native acceptance remains open. See [structured evidence](archive/evidence/component-settings-cross-shell-pester-regression-ps51-2026-10-28-1804.json).

### OpenSSH Server focused current-source regression, 2026-10-29 02:10 UTC

`OpenSshServerCapabilityLifecycle.Tests.ps1` passed 16/16 in Windows PowerShell 5.1.26100.9818/Pester 5.7.1 with native capability, service, firewall, administrator and reboot providers mocked. It covers exact capability identity, stopped `sshd`, disabled TCP/22 rule, run-owned removal/recovery, ShouldProcess and explicit LocalSource behavior. No servicing command or VM was used, and no Windows, Defender or elevation state changed. OpenSSH Server remains unsupported pending native Windows 11 and Windows Server 2025 acceptance. See [structured evidence](archive/evidence/openssh-server-capability-winps51-focused-regression-2026-10-29-0210.json).
