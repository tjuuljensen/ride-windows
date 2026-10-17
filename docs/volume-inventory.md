# Read-only volume inventory

This inventory records local volume GUID paths and a small set of literal
metadata for later explicit selection. It does not format, mount, unlock,
encrypt, clean or change a volume. Native provider acceptance remains pending
on each Windows target; existing storage and recovery operations are unchanged.

## Capture an identified target

Start in the repository root in native Windows PowerShell 5.1 or PowerShell 7.
The target needs the CIM cmdlets and permission to query local Win32_Volume.
Supply the intended machine name, Windows build and EditionID independently.
Create an evidence directory first; use an unused output filename.

```powershell
.\tools\Export-RideVolumeInventory.ps1 `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -OutputPath 'C:\Evidence\volumes.json' -WhatIf

# Remove -WhatIf only for read-only provider collection and new JSON output.
```

Preview queries no provider and creates no output. Collection checks the expected
local context before querying, then verifies it again including update revision
and native process architecture. No remote CIM session or elevation prompt is
used. Exclusive creation refuses existing files, including one created during
collection. Preserve partial output after a write failure and select a new path
after resolving the error. Volume labels and serials can identify local media;
keep the output with local evidence.

The [Win32_Volume provider](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vdswmi/win32-volume)
covers local volumes, including unformatted and offline volumes. This collector
retains only DeviceID as VolumeGuidPath, DriveLetter, Label, FileSystem, DriveType
and SerialNumber. It calls no provider methods and opens no volume or file tree.
It does not enumerate physical disks, partitions, folder mount points, boot/system
roles, BitLocker protectors, protection status or restore points. At most 512 rows
are retained; native query duration has no hard timeout.

| Observation | Meaning |
| --- | --- |
| Captured with empty Volumes | Provider completed and returned no rows. |
| Unavailable with null Volumes | Provider failed, emitted invalid/duplicate identities or exceeded the bound. All partial rows are discarded. |
| Identified row | A nonempty volume GUID path was observed and normalized. |
| Unavailable row identity | Missing/empty GUID; metadata remains visible but cannot substitute as selection identity. |
| Null metadata | Provider did not supply the field; null is not zero, false or an empty string. |

The GUID path must include its trailing backslash. Drive letters and labels are
observations, never fallback selection keys. Serial numbers are also metadata,
not an alternate identity. Numeric drive types remain literal; the collector
does not infer writable, removable, boot-critical or safe-to-modify status.

## Inspect saved identities

```powershell
Import-Module .\modules\RIDE.VolumeInventory.psm1
$saved = Get-Content -LiteralPath 'C:\Evidence\volumes.json' -Raw | ConvertFrom-Json
$saved.Volumes | Select-Object VolumeGuidPath, IdentityStatus, DriveLetter, Label
Find-RideVolumeObservation -Inventory $saved -VolumeGuidPath '\\?\Volume{<observed-guid>}\'
```

Completion reads only identified paths from the supplied observation, filters
prefixes without case sensitivity and suppresses duplicates. Lookup validates
schema and identity uniqueness without querying the computer. Observed,
NotObserved and Unavailable remain distinct. A changed drive letter or identical
label cannot redirect a request. This is saved-data lookup, not live resolution.

[Microsoft's volume naming reference](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume)
explains that a volume may have multiple GUID paths and receives a path when
installed or formatted. Therefore distinct observed paths are not proof of
distinct physical media, and a saved path is not permanent hardware identity
across formatting, reinstall, cloning or replacement. The inventory is sequential;
media arrival/removal or configuration changes can make it stale immediately.

ReadyForMutation and RecoverySupported are always false. Future operations must
re-resolve the requested path on the intended machine, check current state and
dependencies, and refuse absence or conflicts. No current-system-volume default
or Q30 resource selection is approved by this observation.

## Acceptance and recovery

The focused tests mock all Windows providers and context. They cover target
mismatch/drift, malformed and missing identities, partial failures, bounds,
saved lookup/completion, JSON round trips and exclusive output creation.
Native collection on disposable Windows targets remains pending, including
volumes without letters, offline/removable media, multiple GUID paths and changed
letters. Boot-role, recovery, protection and encrypted-volume investigations
remain separate and subject to D06's independent recovery requirements.

No storage-state recovery is needed for collection, and its JSON is not an engine
restore manifest. Preserve output as dated evidence. See the
[migration record](migrations/settings-post-migration-review.md#b02-volume-identity-inventory-2026-10-16).
