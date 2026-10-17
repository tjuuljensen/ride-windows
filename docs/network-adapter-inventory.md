# Read-only network adapter inventory

The adapter inventory observes local visible and hidden network adapter identities.
It prepares explicit resource selection for later network work; it does not select
an adapter, change bindings, disable devices, set network categories or alter IP,
DNS, proxy, firewall or routes. Existing catalog network operations keep their
current behavior. Native provider acceptance remains pending per Windows target.

## Collect an identified target

Start in the repository root in native Windows PowerShell 5.1 or PowerShell 7.
The target needs the NetAdapter module and permission to query it. The tool does
not prompt for elevation. Supply the intended computer name, Windows build and
EditionID independently, and create the evidence directory explicitly first.
These values identify the intended local context; they are not hardware attestation.

```powershell
.\tools\Export-RideAdapterInventory.ps1 `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -OutputPath 'C:\Evidence\adapters.json' -WhatIf

# Remove -WhatIf only to perform this read-only provider query and create JSON.
```

Preview queries no Windows provider and creates no file. Collection compares the
machine/build/edition before querying and checks context again afterward, including
the update revision and native process architecture. A mismatch or context drift
refuses the observation. There is no remote CIM session. The existing output path
must be unused; exclusive creation also refuses a file created during collection.
Retain partial output after a failed write and choose a new filename after resolving
the error. Output includes adapter names/descriptions, so keep it with local evidence.

The provider is [Get-NetAdapter with IncludeHidden](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter?view=windowsserver2025-ps).
At most 512 rows are retained. Native query duration has no hard timeout. The
inventory includes literal status, interface index, hardware/virtual/connector
flags when present, display labels and GUID. It does not collect addresses,
credentials, traffic, driver files, binding configuration or connection profiles.

| Observation | Meaning |
| --- | --- |
| `Status = Captured`, empty Adapters | Provider completed and returned no rows in its declared coverage. |
| `Status = Unavailable`, null Adapters | Provider failed, returned invalid/duplicate identities or exceeded a bound. Partial rows are discarded; this is not evidence of no adapters. |
| Row `IdentityStatus = Identified` | Nonempty GUID was observed and normalized; later live presence is not verified. |
| Row `IdentityStatus = Unavailable` | Missing/empty GUID; descriptive metadata is retained but cannot be selected by alias/index instead. |
| Null hardware/virtual/connector field | Provider did not supply that Boolean observation; it is not converted to false. |

The result is a sequential observation. Device arrival/removal, driver reinstall
and configuration can change after capture. Hidden, disconnected and virtual
adapters are observations, not implicit mutation targets. No management, routing,
remote-access dependency or current network role is inferred from these flags.

## Inspect saved identities

```powershell
Import-Module .\modules\RIDE.AdapterInventory.psm1
$saved = Get-Content -LiteralPath 'C:\Evidence\adapters.json' -Raw | ConvertFrom-Json
$saved.Adapters | Select-Object InterfaceGuid, IdentityStatus, Name, InterfaceIndex
Find-RideNetworkAdapterObservation -Inventory $saved -InterfaceGuid '<observed-guid>'
```

Tab completes identified GUIDs from the supplied saved inventory only. Prefix
matching ignores case and duplicate suggestions are removed. No provider or
operational engine is invoked during completion. Lookup accepts GUIDs in their
normal or braced form, validates schema/identity uniqueness and never falls back
to the active adapter or a matching name. `Observed`, `NotObserved` and `Unavailable`
remain distinct. A renamed alias or recycled interface index cannot substitute
for the requested GUID.

`ReadyForMutation` and `RecoverySupported` are always false. A saved match is
historical data, not confirmation that a device remains present or safe to change.
GUIDs do not establish permanent hardware identity across reinstall/replacement
or cloned systems. A future operation must bind the intended machine, freshly
re-resolve the GUID, check dependencies/current state and refuse disappearance,
drift or ambiguous matches before a saved-state mutation.

## Acceptance and recovery

Source validation uses mocked provider/context results and isolated output files.
`tests/AdapterInventory.Tests.ps1` covers target mismatch, update drift, missing/
duplicate identifiers, partial failures, output bounds, lookup/completion and
exclusive output creation. Native collection on the declared Windows targets,
virtual/hidden/disconnected coverage and renamed/disappeared-adapter scenarios
remain separate acceptance work. No workstation networking test is required.

This observation requires no network-state recovery and cannot be used as a RIDE
restore snapshot. Preserve its output as dated evidence. D10/Q30's actual resource
selection and later adapter binding, NetBIOS, category and dependency behavior
remain open; this inventory neither accepts those decisions nor widens support.
See the [migration record](migrations/settings-post-migration-review.md#b02-network-adapter-identity-inventory-2026-10-16).
