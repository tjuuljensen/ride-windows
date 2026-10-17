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
RIDE.ClientComponentPreparation 0.1.0 consumes saved inventory only. From the
repository root in native PowerShell, without elevation:

```powershell
Import-Module .\modules\RIDE.ClientComponentPreparation.psm1
Get-RideClientComponentPreparationChoice -Inventory $inventory
$proposal = New-RideClientComponentPreparation -Inventory $inventory -Kind Capability -Name 'OpenSSH.Client~~~~0.0.1.0' -DesiredState Present -SourceMode Offline -SourcePath 'D:\Sources\FOD'
$proposal | Select-Object Status,Command,Parameters,Requirements
```

For Telnet use Kind OptionalFeature and exact Name TelnetClient. Name completion
uses the supplied captured provider; DesiredState and SourceMode complete their
declared choices. Present and Absent refer to each component independently.
Unknown/pending states, missing observations and domain controllers have no command
outline. Already desired literal states report NoChangeObserved.

Select Online explicitly to respect configured servicing sources and organizational
policy; it forbids SourcePath overrides. Select Offline explicitly with a matching
local drive source; UNC, device paths, traversal and expansion are refused. The
path is not opened or checked for content. Offline installation outlines include
Source and LimitAccess. The DISM Online parameter still selects the running OS;
it does not select the RIDE network-source mode.

Microsoft documents LimitAccess as preventing Windows Update lookup. That flag
alone does not establish the accepted requirement of no network fallback through
any configured source. SourceValidated and NetworkBoundaryVerified therefore remain
false. Before servicing, prove matching build, edition, architecture, language,
required payloads and complete offline behavior without changing servicing policy.
Missing or incompatible source content must fail visibly.

Telnet outlines use NoRestart, omit All and never use Remove to delete payloads.
Capability cmdlets do not expose NoRestart; future execution must inspect restart
results without initiating a reboot. A prior DisabledWithPayloadRemoved feature
cannot be exactly restored just by disabling it. Removing a capability requires
separate reacquisition/dependency and recovery evidence.

These are data-only outlines, not executable plans: ReadyForMutation and
RecoverySupported stay false. No supported catalog target or profile is added.
Fresh target/elevation checks, policy and dependency preflight, durable capture,
explicit diagnostic paths, post-state verification and native consumer/recovery
acceptance remain required. Retain the original inventory; no Windows rollback is
needed for preparation. See the [dated validation](migrations/remaining-migrations-follow-up.md#b06-client-component-source-preparation-2026-10-17).

Parameter boundaries are documented by Microsoft for
[Add-WindowsCapability](https://learn.microsoft.com/en-us/powershell/module/dism/add-windowscapability?view=windowsserver2025-ps),
[Remove-WindowsCapability](https://learn.microsoft.com/en-us/powershell/module/dism/remove-windowscapability?view=windowsserver2025-ps),
[Enable-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/enable-windowsoptionalfeature?view=windowsserver2025-ps)
and [Disable-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/disable-windowsoptionalfeature?view=windowsserver2025-ps).
