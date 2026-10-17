# Read-only user language inventory

This collector records the intended Windows user's ordered language list and
input-method strings. It supports preparation for regional settings without
discarding existing languages or keyboards. It changes no Windows state and
does not install a language pack, choose an input method or apply a regional preset.
Native provider acceptance remains pending.

## Capture the intended user

Start in the repository root in native Windows PowerShell 5.1 or PowerShell 7,
in the intended user's interactive process session. The target needs the Windows
International module and permission to read that user's language list. Supply
machine/build/EditionID and user SID/session independently; the collector never
loads another user's hive or switches accounts. Create an evidence directory first.

```powershell
.\tools\Export-RideUserLanguageInventory.ps1 `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -ExpectedUserSid 'S-1-5-21-1-2-3-1001' `
  -ExpectedSessionId 1 -OutputPath 'C:\Evidence\user-languages.json' -WhatIf

# Substitute the intended identity. Remove -WhatIf only to collect and create JSON.
```

Preview queries no provider and creates no output. Collection requires matching
native machine/build/edition and interactive execution SID/session, then rechecks
that context, including update revision. A matching process session is an identity
guard, not proof that it is the current active desktop or that another account's
settings are accessible. No elevation prompt or network call is used.

[Get-WinUserLanguageList](https://learn.microsoft.com/en-us/powershell/module/international/get-winuserlanguagelist?view=windowsserver2025-ps)
returns the current user's language list. RIDE records its order, LanguageTag,
InputMethodTips and available Handwriting/Spellchecking flags. Names derived from
language databases and unknown provider properties are not exported. Up to 128
languages and 128 input strings per language are retained; each input string is
limited to 2048 characters. Provider duration has no hard timeout.

| Result | Meaning |
| --- | --- |
| Captured with empty Languages | Provider completed without rows. No default language is invented. |
| Unavailable with null Languages | Failure, malformed/duplicate language identity or exceeded bound; partial results are discarded. |
| Identified row | A bounded language-tag shape was observed; installed capabilities remain unknown. |
| Unavailable identity | No tag was supplied. Position cannot substitute as identity. |
| Null InputMethodTips | No collection was supplied; distinct from a captured empty array. |
| Null flag | Provider supplied no value; distinct from false. |

Tags preserve spelling and are compared without case sensitivity. The syntax
check is conservative and is not a full BCP-47 validator or installed-language
resolver. Input strings preserve spelling, order and duplicates. They are not
interpreted as registry paths or verified against installed keyboard/TSF providers.
Language order alone proves neither the active input method nor effective display
language. This observation omits regional formats/custom overrides, home location,
UI override, system locale, time zone, policy, installed capabilities and welcome/
new-user defaults. It is not a complete international-settings backup.

## Inspect saved data

```powershell
Import-Module .\modules\RIDE.UserLanguageInventory.psm1
$saved = Get-Content -LiteralPath 'C:\Evidence\user-languages.json' -Raw | ConvertFrom-Json
$saved.Languages | Select-Object Position, LanguageTag, InputMethodTips, Handwriting
Find-RideUserLanguageObservation -Inventory $saved -LanguageTag en-GB
```

Use a tag from the intended observation. Saved lookup validates schema, list order
and tag uniqueness. Completion reads only identified supplied tags and filters
prefixes, suppressing duplicates; it performs no live query. Observed, NotObserved
and Unavailable remain distinct. No first-row fallback or default selection occurs.
ReadyForMutation and RecoverySupported remain false; observations may become stale.

## Observe display and default-input overrides separately

Language-list priority does not capture an explicit display-language or input
override. Use the separate exporter in the same intended user's interactive
session, starting in the repository root. It requires no elevation prompt:

```powershell
.\tools\Export-RideUserLanguageOverrides.ps1 `
  -Kind DisplayLanguage,DefaultInputMethod `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -ExpectedUserSid '<intended-user-sid>' `
  -ExpectedSessionId 1 -OutputPath 'C:\Evidence\language-overrides.json' -WhatIf
```

Remove WhatIf only for the read-only query and new evidence file. Kind completes
from its declared choices. Select one or both providers; duplicates refuse and
unselected providers are not queried. Machine/build/edition/update/SID/session
must remain unchanged across collection. Import and preview query nothing.
The exporter exclusively creates a new UTF-8 JSON file. Existing/racing files
refuse; retain partial evidence on failure and use a new name.

The separate `UserLanguageOverrideObservation` schema keeps per-provider Status,
ObservationState, OverrideState and literal Value. The existing ordered-list
schema and priority snapshot are unchanged. Each provider accepts at most one
row; failures discard its partial value without discarding a successful different
provider. Unavailable differs from a successful query returning no value.

Microsoft's [UI override reference](https://learn.microsoft.com/en-us/powershell/module/international/get-winuilanguageoverride?view=windowsserver2025-ps)
documents that no returned value means no override, and a returned value can be
pending until sign-out/restart. The record does not claim that a captured override
is the language currently displayed. Empty/malformed display rows refuse.

The [input override reference](https://learn.microsoft.com/en-us/powershell/module/international/get-windefaultinputmethodoverride?view=windowsserver2025-ps)
describes default input derived from the language list when no override is used.
The exact native empty/no-output representation still needs target evidence;
those two observations remain distinct and their OverrideState is Unverified.
A literal nonempty TIP is retained without treating every TIP as a keyboard-layout
ID. No current input, installed method, effective policy or desktop ownership is
verified, and no first-list input is substituted.

`ReadyForMutation` and `RecoverySupported` remain false. These records neither
install languages nor change overrides, list order, keyboard state, format,
system locale, welcome-screen/default-user settings or logon state. They are not
a complete regional backup. Keep private evidence locally. Native acceptance
must compare both explicit and absent overrides, pending UI changes and a TSF
input method in the intended user's disposable session before adding a setter.
The [dated override record](migrations/remaining-migrations-follow-up.md#b09-user-language-override-inventory-2026-10-17)
tracks that boundary and the focused mocked tests.

## Prepare an existing language priority in memory

`RIDE.UserLanguagePreparation.psm1` accepts a supplied captured observation and
proposes moving one existing tag to first position. It preserves every other tag's
relative order. It returns only the desired tag order and a version-1 snapshot;
it does not rebuild native language objects or write any field.

```powershell
Import-Module .\modules\RIDE.UserLanguagePreparation.psm1
$patch = New-RideUserLanguagePriorityPatch -Inventory $saved -LanguageTag en-GB
$patch.DesiredOrder
# Use only a tag already present in $saved. This performs no live change.
```

Every row must have a unique tag and valid position, with an explicit native
interactive machine/build/edition/SID/session context. Unknown/empty lists are
refused. Completion reads only supplied identified tags. An already-first tag is
an unowned no-op. No missing language, pack or keyboard is created, and no default
tag is selected for the caller. Language priority is distinct from a display
override, regional format and default input-method choice.

`Restore-RideUserLanguagePriorityPatch -Inventory $current -Snapshot $patch.Snapshot`
prepares the original order only when current order matches the expected edit.
An already restored order is a no-op. Added/removed languages or a third order
require review; recovery never drops those changes. A proposal that changed
nothing owns nothing and leaves later order/membership untouched. Identity drift,
including a changed session/build/update revision, refuses recovery in this narrow
preparation contract. Snapshot fields are checked against the reconstructed edit,
but this consistency check does not authenticate supplied data.

Input methods, handwriting, spellchecking and other per-language fields are not
in the order snapshot. A future writer must use the current rows and preserve
those fields, rather than replacing them with old or newly generated defaults.
ReadyForMutation and MutationAuthorized remain false. Durable state, fresh live
comparison, ShouldProcess, native field reconstruction and setter/GUI acceptance
are still required before operational integration.

## Observe regional providers separately

`tools/Export-RideRegionalInventory.ps1` collects explicitly selected providers
with the same expected machine/build/edition/SID/session boundary. Start in the
repository root with an existing private evidence directory and the International
module available. There is no elevation prompt or implicit provider selection.

```powershell
.\tools\Export-RideRegionalInventory.ps1 `
  -Kind FormatCulture,HomeLocation,SystemLocale,TimeZone `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -ExpectedUserSid '<intended-user-sid>' `
  -ExpectedSessionId 1 -OutputPath 'C:\Evidence\regional-observation.json' -WhatIf
```

Preview performs no provider query or export. After verifying identity and output
location, omit `-WhatIf` for the read-only observation. Tab completes `-Kind` from
its declared provider set. Select each once; missing/malformed output is
Unavailable, not a default or an empty setting. A failed provider does not erase
successful separate providers. Identity drift discards the complete collection.

| Provider | Scope and captured metadata | Boundary |
| --- | --- | --- |
| FormatCulture | Observing process's culture name/LCID, flags and selected literal separators/date/time/currency fields | A culture name does not capture every custom format. A stored change can require a new PowerShell session; this is not a fresh persisted-user-settings read. |
| HomeLocation | Current user GeoId and localized HomeLocation text | Preserve signed numeric identity; do not guess a country from language or description. This is home-region preference, not physical location or time zone. |
| SystemLocale | Machine system-locale name and LCID | Non-Unicode compatibility setting, separate from display language and user formats. UTF-8 compatibility mode and restart state are not captured. |
| TimeZone | Machine time-zone ID, base UTC-offset ticks and daylight-support flag | Base offset is not the current seasonal offset. Dynamic daylight-disabled configuration and adjustment rules are not captured or inferred. |

Each provider must return one bounded row; partial output followed by an error is
discarded. Only expected fields are exported, with error type rather than raw
exception text. Invariant culture remains an explicit empty name, not an assumed
replacement. Records include collection timestamps and remain sequential rather
than atomic. These values are not complete recovery snapshots or mutation-ready
selection records. No regional setter, language installation, time change,
default-user copy, restart or GUI refresh occurs.

References: [Get-Culture](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-culture),
[subsequent-session culture changes](https://learn.microsoft.com/en-us/powershell/module/international/set-culture),
[home location](https://learn.microsoft.com/en-us/powershell/module/international/get-winhomelocation),
[system locale](https://learn.microsoft.com/en-us/powershell/module/international/get-winsystemlocale)
and [time zone](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-timezone).
Native output/availability and GUI correlation remain pending. Preserve old
exports and use a new filename on retry; no Windows rollback is required.

## Acceptance and recovery

Focused mocked tests cover identity mismatch/drift, order, nullable fields,
literal input strings, bounds, failures, saved lookup/completion and exclusive
JSON creation. Disposable native collection must verify module availability,
mixed languages/keyboards, TSF input, access failures and observed field types.
GUI/default-input/managed behavior is separate acceptance.

Future list changes must preserve unrelated entries and establish ownership,
current-user identity, exact input/flag recovery and conflict handling before
calling [Set-WinUserLanguageList](https://learn.microsoft.com/en-us/powershell/module/international/set-winuserlanguagelist?view=windowsserver2025-ps).
Language installation, format changes and welcome/new-user copying are distinct
operations. No writer or catalog operation is introduced by this collector.

Export exclusively creates a new file and refuses an existing or racing output.
Preserve partial output after failure and choose a new filename after resolving
the error. Keep SID/language evidence locally. Collection needs no settings
rollback, and the JSON is not an engine restore record. See the
[migration record](migrations/remaining-migrations-follow-up.md#b09-user-language-list-inventory-2026-10-17).
