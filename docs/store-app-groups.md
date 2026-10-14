# Store app groups and reinstall boundaries

RIDE's planned app workflow exposes optional groups for intended-user uninstall
and explicit reinstall. The user accepted the membership below. Adding a group
does not select it in a default profile or authorize removing apps now. Packages
remain paused. All five groups have guarded candidate declarations; native
lifecycle acceptance remains pending.

The [separate disposable test desktop](migrations/store-test-desktop.md) now has
native unelevated worker/Explorer and read-only Plan evidence. This resolves the
desktop resource prerequisite; full launcher and uninstall/reinstall acceptance
remain separate.

## Batch 1 commands

The catalog declares app.clipchamp, app.news, app.weather and app.solitaire,
with the ordered solution.store-consumer-apps group. Discover them through
`ride.ps1 list store-apps` or the separate tool below. Profile apply/remove and
ordinary downloadable-package commands refuse this Store workflow.

The later groups use solution.store-core-utilities, solution.store-multimedia,
solution.store-productivity and solution.store-gaming, through the same tool.
They retain independent app prerequisites and pending target acceptance.

```powershell
.\tools\Invoke-RideStoreApps.ps1 List
.\tools\Invoke-RideStoreApps.ps1 Plan solution.store-consumer-apps -ExpectedUserSid <your-SID>
.\tools\Invoke-RideStoreApps.ps1 Uninstall app.news -ExpectedUserSid <your-SID> -WhatIf
.\tools\Invoke-RideStoreApps.ps1 Reinstall app.news -ExpectedUserSid <your-SID> -RemovalRunId <saved-Store-removal-ID> -WhatIf
```

Use `whoami /user` in the intended user's own unelevated desktop console. Command,
action, app/group ID and saved removal-run parameters offer read-only completion.
For an alternate administrator, explicitly select `-UserContext Desktop` and the
expected desktop SID. It starts a separate Windows PowerShell 5.1 process through
the existing unelevated shell in this session. The parent reads no app registrations
or target-user recovery files. The child checks owner/session/shell/source before
live inspection and app actions, and keeps its own Store records. Launch receipts
do not prove completion; read actual results in the child window. Native GUI/session
acceptance remains pending. Other/no desktop sessions are refused, with no fallback
to the administrator's registrations.

Published targets remain empty. Plans expose target, identity/session, policy,
protection/type, dependency and retained-source refusals; actual mutation is blocked
pending acceptance. Existing inventories have unknown IsPartOfSystem flags. The
handler keeps them unknown and refuses removal, including on otherwise matched
consumer identities. A passing native preflight cannot promote removal support.

The read-only runtime descriptor uses the current SID and exact full package name
with PackageManager.FindPackageForUser on Windows PowerShell 5.1 to inspect type,
stub and certificate category. Unavailable SDK fields remain unknown. Store
signature category describes a certificate; it does not prove IsPartOfSystem=false.
Bundle removal and main-manifest source capture are separate identities.
Client management registration uses the documented read-only MDM API, without
collecting a UPN; generic enrollment keys alone are not treated as active client
enrollment. Server has no supported counterpart in that API and remains pending.

The tool reports Completed, AlreadyMatching, Refused, Failed or NotApplied for each
app. Intent is saved before a native change, with all group outcomes retained in
LocalApplicationData/RIDE/State/StoreApps/RunId/manifest.json. These schema-1 Store
records are separate from setting restore records; use the explicit Reinstall
action with an owned removal ID. A retained manifest may disappear after removal,
in which case the source is unavailable and no download occurs. Interrupted intent
and failed/partial removals remain inspectable; recovery still checks actual absence,
source integrity and the current owner/session rather than assuming completion.

The [device removal policy](migrations/store-app-removal-review.md#policy-and-applicability)
is a separate machine workflow. Both workflows use reviewed app identities and
link to each other, but uninstall/reinstall never silently changes that policy.

## Accepted groups

| Batch | Group | Apps |
| --- | --- | --- |
| 1 | Consumer apps | Clipchamp, News, Weather, Solitaire |
| 2A | Core utilities | Calculator, Notepad, Snipping Tool, Terminal |
| 2B | Multimedia | Photos, Paint, Camera, Media Player, Sound Recorder |
| 2C | Assistance and personal productivity | Quick Assist, Sticky Notes, Outlook, To Do |
| 3 | Xbox and gaming | Xbox app, Game Bar, Xbox TCUI, Xbox Identity Provider, Xbox Speech to Text Overlay; shared dependencies inspected together |

The groups are optional compositions. Each app needs its own identity, current
presence, prerequisites and per-app result; a group is not a single atomic change.
The membership supports shared uninstall/reinstall composition without silently
adding apps from a historical list. Teams, Copilot, Office Hub and other unlisted
apps remain outside these accepted groups.

## Exact identities to implement

These names come from the captured reference inventory and inspected policy
crosswalk. Refresh exact package families/full names at execution; do not query
with broad wildcards or substitute a similarly named app.

| Batch | App | Package name |
| --- | --- | --- |
| 1 | Clipchamp | Clipchamp.Clipchamp |
| 1 | News | Microsoft.BingNews |
| 1 | Weather | Microsoft.BingWeather |
| 1 | Solitaire | Microsoft.MicrosoftSolitaireCollection |
| 2A | Calculator | Microsoft.WindowsCalculator |
| 2A | Notepad | Microsoft.WindowsNotepad |
| 2A | Snipping Tool | Microsoft.ScreenSketch |
| 2A | Terminal | Microsoft.WindowsTerminal |
| 2B | Photos | Microsoft.Windows.Photos |
| 2B | Paint | Microsoft.Paint |
| 2B | Camera | Microsoft.WindowsCamera |
| 2B | Media Player | Microsoft.ZuneMusic |
| 2B | Sound Recorder | Microsoft.WindowsSoundRecorder |
| 2C | Quick Assist | MicrosoftCorporationII.QuickAssist |
| 2C | Sticky Notes | Microsoft.MicrosoftStickyNotes |
| 2C | Outlook | Microsoft.OutlookForWindows |
| 2C | To Do | Microsoft.Todos |
| 3 | Xbox app | Microsoft.GamingApp |
| 3 | Game Bar | Microsoft.XboxGamingOverlay |
| 3 | Xbox TCUI | Microsoft.Xbox.TCUI |
| 3 | Xbox Identity Provider | Microsoft.XboxIdentityProvider |
| 3 | Xbox Speech to Text Overlay | Microsoft.XboxSpeechToTextOverlay |

Media Player and Sound Recorder are the two apps previously described as media
apps. This group does not include legacy Windows Media Player, Movies & TV, codecs,
HEIF/HEVC/AV1 extensions or shared frameworks. Those require separate decisions.
Microsoft lists the two app choices in its
[policy guide](https://learn.microsoft.com/en-us/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal).
Package-name mappings above remain tied to the inspected crosswalk and inventories.

## Xbox dependencies and protected components

Review gaming apps and consumers together. Inspect current dependency identities
and other registrations referencing them before planning ordered actions. Shared
frameworks/resources are not automatically removed with a gaming group.
Microsoft.XboxGameCallableUI is marked non-removable in the captured Windows 11
reference; retain it and report the limitation. Additional Gaming Services or
release-specific packages require observed identities and separate review rather
than guessed names. Missing components report Not installed/Not applicable.

Game Bar is observed, but XboxGamingOverlay is absent from the inspected static
policy template. Do not imply identical coverage for the app group and policy;
validate actual serviced schema/PFN capability before offering that policy choice.

## Uninstall, reinstall and recovery

Uninstall targets the explicit intended user's registrations. Use the explicit
current-desktop handoff and identity checks; native handoff acceptance remains
pending. Refuse another/no desktop session.
Never switch to AllUsers removal or image deprovisioning as a fallback. Inspect
protection, dependencies and intended-user consumers before mutation; unavailable
IsPartOfSystem remains unknown, not false. For the 22 explicitly reviewed catalog
identities, ReviewedIdentityRemovabilityV1 requires known NonRemovable=false and
complete framework/resource/bundle/stub observations. Known system/protected
flags still block removal; missing review metadata, incomplete required flags
identity mismatches and unverified/conflicting runtime observations also block it. Certificate category cannot substitute
for the unknown system flag. These references do not establish Home/Pro or
every build's behavior.

Reinstall is an explicit best-effort app action with a declared available source,
identity/version/dependency checks and per-app results. Re-registering a retained
manifest is a distinct available-payload route; it is not a guaranteed reinstall.
Uninstall also waits for a usable local reinstall source, as explicitly selected
by the user. Stub News/Weather registrations in the Windows 11 reference remain
blocked. Missing payloads report Source unavailable. Acquisition-dependent Store/download
routes remain deferred while packages are paused. No bulk AllUsers manifest scan
or silent download is planned.

Refuse reinstall when an effective removal policy blocks the selected app; show
the [separate policy workflow](migrations/store-app-removal-review.md#proposed-ride-workflows)
instead of clearing it automatically. Deselecting policy does not restore an app.
Neither reinstall nor policy restore promises recovery of local app data or the
previous version. Saved removal records must report actual completion and these
limits rather than Exact recovery; VM checkpoint cleanup is separate evidence.

Groups declare reviewed dependency ordering; uninstall follows reverse order and
reinstall follows forward order. Per-app records preserve completed, absent,
refused, failed and pending actions after partial failure. Do not pretend that
one failed app rolled back the whole group. Discoverable group/app parameters
will complete from the implemented catalog, not another hard-coded list.

## Implementation batches

Start with batch 1 and prove preview, intended-user identity, repeat inspection,
partial removal and an available-source reinstall/refusal path on disposable VMs.
All five groups are implemented as candidates. Accept 2A, 2B, 2C and 3 in turn
with matching preservation/consumer/dependency checks.
Utility removal must account for the tools used by RIDE's session and recovery;
personal-data effects stay visible in the plan. Do not select these groups in
recommended profiles by default. Native interactive handoff acceptance and
app-specific protection/source proofs precede removal fixtures.

The device policy has its own implementation/acceptance batch and independently
validated capture/restore contract. Reuse approved identity definitions, not app
action execution. See the [accepted inventory decisions](migrations/store-app-inventory-review.md#accepted-group-decisions),
[policy review](migrations/store-app-removal-review.md) and
[migration plan](migrations/store-app-inventory-plan.md).
