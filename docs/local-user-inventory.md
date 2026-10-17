# Read-only local user inventory

Use this collector to record local account SIDs before planning account ownership.
It captures names, enabled flags and principal-source labels without changing an
account. Native provider acceptance remains pending. It neither selects an account
nor establishes that an administrator can sign in, recover data or approve changes.

## Capture an identified target

Start in the repository root in native Windows PowerShell 5.1 or PowerShell 7.
The Windows target needs Microsoft.PowerShell.LocalAccounts and permission to
enumerate local users. Supply the independently known machine, build and EditionID.
Create an evidence directory first and choose an unused output filename.

```powershell
.\tools\Export-RideLocalUserInventory.ps1 `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -OutputPath 'C:\Evidence\local-users.json' -WhatIf

# Remove -WhatIf only for local provider collection and new JSON output.
```

Preview queries no provider and writes nothing. Collection checks local context
before and after enumeration, including update revision and native process bitness.
The module is unavailable in 32-bit PowerShell on 64-bit Windows. Missing-module,
provider and access failures return Unavailable rather than successful empty data.
No remote account enumeration, elevation prompt or credential request is performed.
Provider duration has no hard timeout; retained rows are bounded to 1024.

[Get-LocalUser](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1)
includes built-in, created and Microsoft-connected local accounts. The collector
exports only SID, Name, Enabled and PrincipalSource, plus identity/status fields.
Names may contain personal information; retain evidence locally. It excludes full
names, descriptions, password dates and account objects. It does not enumerate
group membership, domain/Entra directories, profiles, credentials or recovery keys.
PrincipalSource is a literal provider label, not a membership or entitlement claim.

| Result | Meaning |
| --- | --- |
| Captured, empty Users | Provider completed without rows; no account existence is inferred beyond that provider result. |
| Unavailable, null Users | Provider failed, returned malformed/duplicate SIDs or exceeded the bound. Partial rows are discarded. |
| Identified row | An account-form SID was captured and normalized. |
| Unavailable row identity | No SID was supplied; the name cannot substitute as an identity. |
| Enabled null | Provider supplied no enabled flag; this differs from false. |

The accepted SID form is S-1-5-21 followed by three authority components and an
account RID, each bounded to UInt32. Group, service and cloud-only SID forms are
outside this local-user contract. The shape alone does not prove local ownership;
the provider and recorded target context are part of the observation.

## Inspect saved identities

```powershell
Import-Module .\modules\RIDE.LocalUserInventory.psm1
$saved = Get-Content -LiteralPath 'C:\Evidence\local-users.json' -Raw | ConvertFrom-Json
$saved.Users | Select-Object Sid, IdentityStatus, Name, Enabled, PrincipalSource
Find-RideLocalUserObservation -Inventory $saved -Sid 'S-1-5-21-111-222-333-1001'
```

Replace the example SID with one captured from the intended target. Completion
reads only valid identified SIDs in the supplied observation, filters prefixes
and suppresses duplicates. Lookup validates schema/identity uniqueness without
querying Windows. Observed, NotObserved and Unavailable remain distinct.

An account rename retains its SID; recreating a name does not recover the deleted
account's identity. See Microsoft's [SID explanation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).
No name, built-in account name, RID or enabled flag is used as a fallback selection.
No last-viable-administrator, current desktop, group membership, password readiness
or profile-file ownership conclusion is made. Saved data can become stale immediately.
ReadyForMutation and RecoverySupported always remain false.

## Acceptance and recovery

Focused tests use mocked providers and isolated JSON files, including context
mismatch/drift, malformed SID components, nullable metadata, failures, bounds,
rename/recreation and completion. Native LocalAccounts behavior on disposable
targets, connected accounts, access denial and unavailable providers remains pending.
Account changes additionally require explicit SID selection, current identity and
membership checks, independent viable access, credentials and a recovery design.

Export exclusively creates the output, refusing existing or racing files. Preserve
partial JSON after a write failure and use a new filename after resolving the error.
The observation is not a password backup or engine restore manifest; it cannot undo
account deletion. Collection requires no account recovery. See the
[migration record](migrations/remaining-migrations-follow-up.md#b02-local-user-identity-inventory-2026-10-17).
