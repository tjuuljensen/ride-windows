# Setting scope, behavior and requirements

RIDE setting IDs have fixed scope. `Scope = User` uses the current Windows
execution account, including when PowerShell was started as a different
administrator. `Scope = Machine` selects device configuration. `RequiresAdmin`
describes the privilege needed to apply a change; it does not describe who
receives the change or whether Windows enforces it.

Discovery and search expose the same presentation fields as individual details,
group member details, profile plans and status. Setting plans and status use list
formatting so long requirements and GUI effects remain visible; package-only
plans and package status views retain table formatting. The underlying
discovery and status commands continue to return pipeline-friendly objects.
Group and profile discovery directs readers to the individual members instead
of assigning one behavior or requirement set to a mixed selection.

| Field | Meaning |
| --- | --- |
| `AppliesTo` | Feature-specific audience, or the declared execution-user/device scope with unverified coverage identified |
| `Behavior` | Preference, enforced policy, recommended policy, feature configuration, or unverified |
| `GuiEffect` | State-dependent editability or restrictions; never inferred from scope, elevation or a policy-looking registry path |
| `GuiPath` | Related native interface, when reviewed; not a promise that it exists on every supported target |
| `RequiresAdmin` | Administrator privilege required to apply the operation |
| `Requirements` | Reviewed edition/build, component, account, license, membership, hardware or connectivity prerequisites; gaps stay explicit |
| `OtherSupportedChoices` | Useful alternate scope/level and whether RIDE actually implements it |
| `EffectivePolicy` | Currently reports that policy and source are not inspected; configured values do not prove active enforcement |
| `ExecutionIdentity` | Live user-scope views identify the execution account and SID, with intended-user verification explicitly pending |

`EffectiveDefault` in status describes a declared platform default, not observed
effective policy. Managed precedence, tamper protection, disabled components and
GUI outcomes require separate acceptance. Discovery, search, completion and
documentation generation do not query execution identity or invoke handlers.

## Service startup and running state

The telemetry, WAP Push, SysMain, Search indexing, SSDP Discovery and UPnP Device
Host controls expose the exact named service, startup choice and runtime effect.
Enabling SSDP or UPnP requests Manual startup and starts the service now; it does
not restore a factory-default stopped state. The legacy UPnP enable selector only
set Manual. That difference is retained explicitly in the current operation's
details rather than changing a published state silently.

WAP Push and Search offer separate startup-only and delayed-start choices; see
[service settings](service-settings.md). Their legacy enable selectors explicitly
requested delayed start, while AutomaticRunning preserves the existing delay.
Service defaults, dependent workloads, policy and GUI behavior need their own
evidence. These controls neither remove an override with unset nor promise reversal
of effects in applications or dependent services.

## Scheduled-task enablement

The thirteen Windows and Office task controls identify the exact existing task
and change only its enabled flag. They do not create a missing task, change its
actions or triggers, send a Start/Stop request, or delete history. Enabling permits
existing triggers to run; disabling does not reverse work already done.

The old telemetry selector combined nine task switches with several separate
registry policies. Feedback combined two tasks with notification/frequency controls;
error reporting combined QueueReporting with its registry preference. Individual
task states do not reproduce those complete bundles. Office Click-to-Run service
monitoring is maintenance, separate from the Office 2016 telemetry tasks. Review
installed task actions and current product/build applicability before activation.

Saved-run restore recovers the captured enabled flag of the same task identity.
It does not restore a changed task definition, history, generated files or network
effects. Neither Enabled nor Disabled is a platform-default restoration.
Inspection rejects a missing or non-Boolean enabled flag instead of interpreting
it as Disabled. Apply and restore re-read the same task after a change. If the
task disappears, inspection is denied, or the flag differs, the operation fails;
the write may already have happened. Inspect the task and saved run before retrying.
Verification is a point-in-time observation and does not prevent a later external
change to task enablement or definition.

## Defaults and recovery

`status` reports catalog-declared literal and effective platform defaults beside
live state. Image-dependent defaults appear as `<platform-defined>` and their
`MatchesDefault` result is unknown. A configured registry value does not prove
which policy takes effect or what a GUI currently displays.

A profile's `Baseline` applies the catalog's documented baseline; it is not a
Windows default or a saved-state restore. `unset` removes only the declared
overrides when supported. `restore -RunId <id>` recovers captured prior values
and types. Coordinated value sets retain the complete pre-change record even
when an individual write fails. Native settings without a meaningful override
removal do not expose `unset`.

### Explorer folder options

The folder merge prompt, navigation tree, title path, separate-process, logon
restoration, sharing interface, selection checkbox and thumbnail controls are
independent current-user preferences. Inspect their details with `show <id>`
before composing a profile. A broader folder tree does not enable automatic
expansion; suppressing folder merge prompts does not decide duplicate-file
replacement; thumbnail display does not clear or disable its cache.

For these eight IDs, `WindowsDefault`, `Baseline` and `unset` remove the declared
override. Explicit Off/Hidden choices write a value instead. This matters for
older selectors that reversed a change by deleting the value. Saved-run restore
recovers the captured type, data or absence rather than choosing either preset.
RIDE does not restart Explorer or sign out. Native GUI, sign-in, touch, process
grouping and managed-policy behavior still require acceptance; the detailed
metadata identifies which Microsoft references document a registry mapping and
which describe only the option.

## Catalog authoring and compatibility

The optional `SettingPresentation` table extends catalog schema 1 additively.
Existing catalogs and external libraries without the table still load; their
setting behavior, GUI effects and prerequisites display as unverified. IDs,
states, physical registry roots, handlers and saved-run schemas remain unchanged.
Removing an override remains distinct from restoring captured pre-change state.

```powershell
SettingPresentation = @{
  AppliesTo = 'Current Windows execution user: the reviewed feature'
  Behavior = 'Preference'
  GuiPath = 'Verified native interface path'
  GuiEffect = 'Describe each declared state and applicable policy restrictions'
  Requirements = @('Reviewed requirements, including explicit remaining gaps')
  OtherSupportedChoices = @('Describe supported alternatives and RIDE coverage')
  ReferenceUris = @('https://learn.microsoft.com/<verified-reference>')
}
```

The example URI is a placeholder, not a usable reference. Authors must verify
Microsoft references, fragments, supported scope, privilege, current targets,
reverse semantics and GUI behavior before declaring metadata. A behavior
reference does not establish an undocumented registry mapping. Validation rejects
unknown behavior labels, blank requirement/choice entries, missing references,
invalid reference URLs, machine settings without elevation, and scalar registry
roots inconsistent with scope. Built-in references use Microsoft Learn or Support;
external libraries may provide their own authoritative HTTPS sources.

Reviewed metadata includes file-name extensions, hidden/protected file visibility,
Explorer recent/frequent shortcuts, Control Panel opening view, sound-scheme editing,
Edge startup boost/background mode and Defender cloud-delivered protection. Their feature/GUI
acceptance remains tracked in the
[post-migration review](migrations/settings-post-migration-review.md).

The Explorer shortcut IDs retain their published `Visible` state as override
removal, rather than an explicit On write. Control Panel's explicit Categories
choice still differs from removing both preferences. Hidden and protected files
remain independent preferences, and the Edge background-mode ID keeps its existing
machine mandatory policy path. Presentation describes these contracts without
changing values, physical scope, defaults or saved recovery.

The Defender `Advanced` state retains its published value and recovery contract.
The catalog explains built-in protection versus separately licensed enterprise
services, required Antivirus availability/connectivity, and the inferred absence
of a separate account/onboarding step. Local-account VM acceptance remains pending.

## Input and audio choices

The following controls describe stored preferences. Their related native UI
paths help locate the feature; they do not establish that a registry write has
changed the running session or overridden managed policy.

| Control | Explicit choice | Default and recovery meaning |
| --- | --- | --- |
| `windows.keyboard-repeat-delay` | Positions 0-3, using the retained state names Shortest, LegacyAppearance, Position2 and Longest | Baseline, WindowsDefault and unset remove the override. The image-dependent default remains unknown; saved restore retains prior type/value/absence. Actual delay is hardware dependent; repeat speed is separate. |
| `windows.mouse-pointer-precision` | Enabled writes the legacy 1/6/10 acceleration tuple; Disabled writes 0/0/0 | Baseline, WindowsDefault and unset remove all three overrides. Enabled does not restore custom thresholds. Saved restore recovers the captured tuple and types; default and current GUI equivalence remain unverified. |
| `windows.registered-sound-scheme` | NoneScheme uses the registered .None preset; WindowsDefaultScheme uses .Default | A preset may be customized. WindowsDefaultScheme is neither a factory reset nor saved restore; no baseline or unset is declared. Saved restore recovers the selector and captured event mappings. |
| `windows.startup-sound` | Enabled writes 0 to DisableStartupSound; Disabled writes 1, with machine scope and elevation | Baseline writes Enabled, while the catalog's literal Windows default is absence. No unset state is declared; saved restore can recover absence. The configured preference does not prove startup playback. |

Keyboard and pointer references describe the native feature/API, not validation
of these registry mappings. Sound references describe personalization and event
configuration; the startup-sound reference does not document its value or
checkbox. The catalog keeps those evidence limits visible beside its choices.

Sound presets preserve existing source customizations, so even a customized
.None mapping can play a sound. Scheme selection, its editing policy, startup
sound, [playback-device mute](audio-service.md#mute-a-selected-playback-device)
and the Windows Audio service remain separate choices. GUI, boot/session,
managed-policy and hardware acceptance are tracked in the
[post-migration review](migrations/settings-post-migration-review.md).

## Media and privacy choices

These controls retain their existing states and physical scope. Their presentation
separates preference, policy and override removal; it does not establish live GUI
or managed-policy acceptance.

| Control | Setting meaning | Reverse and recovery boundary |
| --- | --- | --- |
| `windows.autoplay-policy` | Current-user AutoPlay preference despite the published ID/name. It does not change per-media default actions or defeat machine policy. Microsoft documents the UI, not this registry mapping. | Disabled=1, Enabled=0, Baseline=Enabled; no unset state. Restore recovers the prior value/type/absence. |
| `windows.autorun-policy` | Machine drive-type policy with all types disabled by mask 255. It is separate from the default autorun-command policy and manual file execution. | Enabled/Baseline/unset remove the override, rather than enabling every drive. Other restrictions remain relevant; shell/session refresh and media behavior need acceptance. |
| `windows.clipboard-history` | Current-user history preference, separate from sync and machine AllowClipboardHistory policy. | Enabled=1, Disabled=0; WindowsDefault/Baseline/unset remove the override. Legacy DisableClipboardHistory used removal. Restore recovers configuration, never clipboard contents or pins. |
| `windows.location-service-policy` | Machine restriction on the Windows location feature, separate from service startup, app permissions and other ways to infer location. | Disabled=1; Enabled/Baseline/unset remove the restriction and do not force app access on. Recovery owns only this policy value. |
| `windows.location-scripting-policy` | Advanced legacy scripting restriction. Microsoft maps the device policy; a useful current consumer still needs evidence. No general browser/script-blocking claim. | Disabled=1; Enabled/Baseline/unset remove the override. The legacy location bundle changed both location values; each stable ID retains independent recovery. |
| `windows.advertising-id-policy` | Machine policy preventing apps from using the Windows advertising ID, rather than an all-advertising or tracking switch. | Disabled=1; Enabled/Baseline/unset remove machine enforcement so user choice may apply. Restoring policy does not restore a prior identifier or app data. |

The existing default profile still selects both location policies. The scripting
consumer and that recommendation remain under review; this presentation batch does
not silently change profile selection. Existing target declarations likewise remain
unchanged. Microsoft policy applicability lists and local template inspection are
reference evidence, not proof of every edition's current behavior.

The catalog links the exact device-level location mapping under System/AllowLocation;
the ADMX_Sensors page's DisableLocation_1 is user-scoped and is not substituted for
the machine operation. CSP input numbers are not interchangeable with registry
values. Location scripting uses the separate DisableLocationScripting_2 mapping.
The [batch ledger](migrations/settings-post-migration-review.md#b01-media-and-privacy-presentation-2026-10-16)
records references, legacy reconciliation and the remaining GUI/managed acceptance.

## Screen-off, sleep and button choices

Seven reviewed controls distinguish the legacy bundles' individual effects.
The six power-plan controls configure one index in the active scheme; they are
feature configuration, not enforced policy. Each AC/DC choice is independent.

| Controls | Existing choices | Recovery and acceptance |
| --- | --- | --- |
| Sleep-button action, AC/DC | DoNothing=0 or Sleep=1 for the dedicated sleep button | No baseline/unset. Restore the captured index in the captured scheme. Hibernate/Shut Down are documented platform choices but not yet exposed by these IDs. Missing indexes remain Unavailable. |
| Display idle timeout, AC/DC | Never=0; TenMinutes=600 on AC or FiveMinutes=300 on DC | Values are seconds. These are screen-off timers, separate from screen saver, sign-in and sleep. Legacy durations are not Windows defaults. |
| Sleep idle timeout, AC/DC | Never=0; ThirtyMinutes=1800 on AC or FifteenMinutes=900 on DC | Never affects this idle timer, not all sleep transitions. Preserve custom captured indexes exactly; no rounding or factory-plan restore. |
| Sleep menu option | Hidden=0, Shown=1, WindowsDefault/Baseline/unset remove the override | Advanced legacy preference; no hardware capability or button-action change. Microsoft documents a separate policy path, not the migrated FlyoutMenuSettings mapping. |

The power handler commits apply by reactivating the same plan. Restore writes the
saved scheme and commits only if that scheme is still active, preserving another
selected plan. Effective policy, plan-switch races, physical button behavior and
actual idle/resume transitions still need evidence. Modern Standby, traditional
sleep, battery presence and power requests matter; registry/index round trips
alone establish none of those outcomes.

The legacy DisableSleepButton/EnableSleepButton bundle combined menu visibility
with both button indexes. DisableSleepTimeout/EnableSleepTimeout combined four
timers and wrote explicit preset durations on reverse. Current IDs keep each
choice independently useful. Additional GUI/custom durations and button actions
remain accepted design work with capability and target validation pending.
See the [batch record](migrations/settings-post-migration-review.md#b01-power-control-presentation-2026-10-16).

### Power index record compatibility

PowerSetting capture and engine inspection now preserve indexes from 0 through
4294967295 without signed narrowing. This storage range does not add catalog
choices or establish that every value is meaningful for every setting. Existing
named choices and completion are unchanged; unfamiliar live values remain Custom.

New saved power snapshots carry SnapshotVersion=1, IndexEncoding=UInt32 and the
AC/DC identity. The outer run-record schema is unchanged. Restore validates the
encoding, index, scheme GUID and supplied AC/DC field before a native write.
Unknown versions/encodings, fractions, strings, nulls, overflow and mismatched
power sources refuse. Marked unsigned snapshots cannot contain negative indexes.

The old reader used signed hexadecimal conversion. For an unmarked historical
snapshot only, a negative Int32-range index is recovered as its original 32-bit
pattern: -1 becomes 4294967295 and -2147483648 becomes 2147483648. Positive older
captures remain compatible. Conversion happens in memory; original records are
not rewritten. Keep the original run and restore with PowerSettings 0.2.0/Engine
0.20.3 or a later compatible version. Reverting to the older engine does not
provide recovery for unsigned values above Int32.MaxValue; retain the corrected
release until such runs are recovered. Do not hand-edit records to force a retry.

PowerSettings 0.3.0 reads indexes through the typed PowrProf APIs, independent of
localized powercfg labels. It reads the active GUID before and after an active-plan
index query and refuses drift; saved-scheme inspection uses the explicit GUID.
File-not-found is Unavailable configuration, not a hardware diagnosis. Access
denied and other native errors throw numeric diagnostics. Native API/locale and
effective managed-policy acceptance remain pending. Boundary, record and
recovery-command tests mock PowrProf and powercfg, not actual high-index transitions.
Native acceptance must use a disposable target and a captured reversible fixture;
do not change a workstation to test these boundaries. Ordinary preview through
`set ... -WhatIf` and saved `restore -RunId` remain the operator entry points.

The read bridge uses [PowerGetActiveScheme](https://learn.microsoft.com/en-us/windows/win32/api/powersetting/nf-powersetting-powergetactivescheme)
with documented allocation release and
[PowerReadACValueIndex](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-powerreadacvalueindex)/[PowerReadDCValueIndex](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-powerreaddcvalueindex)
for literal scheme values. It does not inspect effective policy or physical sleep
capabilities. Existing powercfg writes/commit and their saved recovery remain;
read-time drift detection does not make a later apply/restore atomic. Retain
original snapshots and a compatible reader/handler for recovery. A full native
revalidation should precede release activation of this backend change.

## App Privacy device policies

Seventeen controls have reviewed device-policy presentation. Camera and microphone
offer ForceDeny=2, ForceAllow=1, UserControl=0 and WindowsDefault (remove). The
other fifteen retain Disabled=2 and Enabled (remove). Baseline/unset remove the
declared override; saved-run restore recovers its original data/type/absence.
An Enabled removal is not an explicit ForceAllow. Per-app policy exception lists
can override the default for the fifteen non-voice controls; RIDE leaves those
separately owned lists intact. Voice activation has two related policies, with
locked-session activation dependent on general activation being permitted.

Policy names appear under Local Group Policy Editor > Computer Configuration >
Administrative Templates > Windows Components > App Privacy. Windows 11 Pro,
Enterprise, Education or IoT Enterprise is required for these policies; their
presence does not prove current GUI editability or effective managed precedence.
App refresh can be required. RIDE does not restart apps or the device.

Reading notifications, making phone calls, controlling radios, communicating
with unpaired devices and accessing diagnostics about other apps have distinct
effects. They do not respectively disable all banners, configure phone hardware,
switch radios directly, control cloud synchronization or set device telemetry.
The stable IDs retain their names even where display names now clarify scope.

The background-app policy owns only its device default. The legacy enable bundle
also removed user per-app background flags, which remain separate pending work.
The legacy voice bundle changed both policies together; the split permits a
useful additional restriction while locked, with its general-activation dependency
visible. Review and recover each captured operation independently.
See the [source and acceptance record](migrations/settings-post-migration-review.md#b01-app-privacy-policy-presentation-2026-10-17).

## Update offering, restart sign-in and maintenance wake

Eight controls now distinguish device policy, preference and unverified legacy
values. Driver quality-update exclusion, device-metadata application downloads,
AUOptions and automatic restart sign-in describe their independent scope and
policy prerequisites. AUOptions alone does not configure NoAutoUpdate or trigger
an update. Automatic restart sign-in locks the session and depends on separate
join-state, sign-out and encryption conditions.

MSRT offering and the two historical maintenance-wake values remain Unverified.
The current Windows template maps AUPowerManagement outside the historical AU
subkey and declares an older-release range. The documented Task Scheduler WakeUp
policy is another mapping. RIDE preserves its existing values and saved recovery;
it does not silently substitute either policy. The non-policy maintenance value
has only a feature-behavior reference. Neither value proves that all wake is off.

AllowMUUpdateService is a documented preference, but its registry round trip does
not establish the legacy Microsoft Update service-registration outcome. Likewise,
the old driver bundle included a separate SearchOrderConfig value not migrated by
these operations. Explicit 0/3 states differ from legacy reverse removal where
recorded. Baseline/unset remove overrides; saved-run restore recovers captured
data, type and absence. No update, restart, service or wake action runs here.

Both experimental maintenance controls remain in the current default profile.
Their recommendation and consumer effect still need review; this presentation
change does not remove them or imply that the profile is newly accepted.
See the [source and acceptance record](migrations/settings-post-migration-review.md#b01-update-and-maintenance-presentation-2026-10-17).

## Security control boundaries

Eight additional controls describe Shell SmartScreen, the legacy firewall value,
memory integrity, sample submission, the paired UAC choice, two path exclusions
and Controlled Folder Access. A configured value is separate from an active
consumer, managed precedence and current GUI behavior. The legacy StandardProfile
firewall value stays Unverified for current effective-profile behavior even though
Microsoft documents its exact registry mapping.

The paired UAC choice changes administrator consent and the shared secure desktop.
The latter can affect standard-user prompt placement; standard-user credentials
and EnableLUA remain separately configured. HVCI owns its Enabled request only,
without configuring VBS, drivers, locks or WasEnabledBy. Restoring a sample
preference cannot retract uploads. Exclusion recovery owns path membership only,
leaving created folders and content intact; both exclusions remain in the default
profile with managed visibility and identity acceptance pending. Controlled Folder
Access owns its mode, not protected-folder or allowed-app lists; no baseline is
declared for that ID. Review the [batch record](migrations/settings-post-migration-review.md#b01-security-control-presentation-2026-10-17)
before the corresponding isolated acceptance run.

### Defender exclusion capture and recovery

From the repository root, inspect the resolved target with
`powershell.exe -NoProfile -File .\ride.ps1 show windows.defender-tools-exclusion`
or the bootstrap exclusion ID. Apply requires elevation, operational Defender
cmdlets and the intended account/path configuration. Preview first with
`powershell.exe -NoProfile -File .\ride.ps1 set windows.defender-tools-exclusion -State Present -WhatIf`.
Choose the real mutation separately; the default profile still includes both
exclusions, which requires its own recommendation review.

The engine captures literal path and visible membership before mutation. The
handler compares both again before any directory preparation. An add rechecks
membership after directory preparation, and every add/remove verifies the
reported result. Failure retains the engine run ID and capture; it does not
trigger an unrecorded replacement or delete a newly created folder. These checks
detect observed drift but cannot provide an atomic transaction with Defender.

New records use `SnapshotVersion=1`, operation ID, resolver, captured path,
original Boolean membership and expected membership. Restore uses the saved path
even if the tools/Downloads configuration changed. Valid older Boolean/path
records remain readable without rewriting them. Unknown versions, mismatched
identities, non-Boolean membership and missing paths refuse recovery before
provider/writer calls. A versioned no-change capture owns no later membership.

Paths must be fully qualified literal subdirectories. Drive/share roots, device
paths, relative paths, wildcards, alternate streams and unresolved variables are
refused. If an old record lacks a usable path or contains an unsupported broad
path, preserve it and reconstruct its original intent from independent evidence
for a separate manual recovery; do not replace its path with today's configuration.

Use `restore -RunId <saved-run-id> -WhatIf`, then the same command without
`-WhatIf` only after reviewing the captured target and current policy. Restore
verifies visible membership and is repeatable when that membership already
matches. It does not recover raw exclusion-list spelling, delete directories,
undo file contents or prove effective scanning. Managed/hidden exclusions can
make the reported list incomplete; alias/wildcard policy and native visibility
acceptance remain open. Missing provider objects/properties are errors, while a
valid null list means no entries were visible, not proof that none are managed.

## Desktop and Explorer visibility

Fourteen additional controls distinguish individual system icons, the all-icons
view, desktop version labels, empty drives, navigation expansion/Libraries,
sync-provider messages, the landing page and two legacy cache requests. Removing
an override differs from writing a Boolean or selecting Home; neither replaces
exact saved recovery. A hidden icon or namespace entry does not delete content.

The cache controls and PaintDesktopVersion remain Unverified. In particular,
the retained network-thumbnail value uses Explorer/Advanced, whereas Microsoft's
documented policy uses Software/Policies/Microsoft/Windows/Explorer. The stable
ID is not silently remapped. Existing target/default declarations and default-profile
cache choices are preserved, with their behavioral/recommendation gaps recorded.
The [review and acceptance procedure](migrations/settings-post-migration-review.md#b01-desktop-and-explorer-visibility-presentation-2026-10-17)
separates literal recovery from actual GUI/cache behavior.

## Visual effects and first sign-in

Seven visual preferences expose their individual scope and retained legacy
values. They do not recreate the complete Performance/Appearance selector:
packed mask ownership, the shared VisualFXSetting value and keyboard delay are
separate. Selection transparency, desktop-label shadows, Peek and taskbar animation
remain Unverified. Direct registry edits do not establish the active session state.

First-sign-in policy has a separate machine scope and affects service opt-in
prompts as well as animation. Explicit Enabled differs from the legacy Enable
selector, which removed the value. Inspect the [review and acceptance procedure](migrations/settings-post-migration-review.md#b01-visual-effects-and-first-sign-in-presentation-2026-10-17)
before composing an outcome; existing sessions and saved-run recovery are separate.

## Read-only session visual observations

From the repository root, import modules/RIDE.VisualEffectsInventory.psm1 and
call Get-RideVisualEffectsInventory as the intended interactive Windows user.
Supply independently established expected machine, build, edition, SID and session.
Use native Windows PowerShell 5.1 or PowerShell 7; elevation is not required.

```powershell
Import-Module .\modules\RIDE.VisualEffectsInventory.psm1
Get-RideVisualEffectsInventory -Kind DragFullWindows,MenuShowDelay,MinimizeAnimation -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid '<user-SID>' -ExpectedSessionId 1
```

Replace every placeholder and session number with the intended target identity.
Kind also offers UiEffects and ClientAreaAnimation, with read-only tab completion.
These five fixed [SystemParametersInfo GET requests](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow)
return session observations, not stored registry values or proof of actual GUI
rendering. MenuShowDelay remains an unsigned millisecond value; the other results
include Boolean interpretations and raw bits. No generic native-action parameter
or SET request is exposed.

Inspect each provider's Status. Unavailable results have no value; NativeError
retains an error code when supplied, including zero for an unsuccessful request
that supplied no error. A malformed provider affects only its own result; changed
machine/user/session context discards the entire collection. Reads are sequential.
The module writes no file, refreshes no session and provides no recovery snapshot.
Native target acceptance remains pending; the [test record](migrations/settings-post-migration-review.md#b01-read-only-session-visual-observations-2026-10-17)
uses only fake native calls and mocked context.

## Network controls

Inspect each machine setting's complete description before selecting it. The
Internet Connection Sharing prohibition policy covers configuration access and
service permission; the retained Hidden/Available state names are historical.
The handler itself does not stop or start SharedAccess. Network namespace visibility,
device auto-setup and the fixed unidentified-network signature remain Unverified.

LLMNR is separate from mDNS. WinHTTP WPAD is separate from other applications'
proxy discovery. NCSI's local configuration and policy are separate inputs to
connectivity detection; they do not form two completed legacy outcomes. Remote
Desktop permission does not include its firewall prerequisites, and Remote
Assistance does not install or remove Quick Assist. Administrative-share changes
need separate service/peer acceptance. No network reconfiguration, credential use
or service restart is invoked as part of discovery.

See the [network review](migrations/settings-post-migration-review.md#b01-network-control-presentation-2026-10-17)
for reverse-state differences, reference limitations and disposable acceptance.

## Logon and boot controls

Read the literal effect before choosing a boot state: published Standard for F8
and OptIn for DEP remove overrides rather than explicitly writing those values.
Sign-in acrylic Enabled also removes its policy. Secure-attention and lock-screen
policies have distinct effects; disabling the lock-screen display does not remove
authentication. Fast startup requires independent hibernation/hardware support.
No discovery operation triggers boot, sign-out, shutdown or crash. See the
[logon and boot review](migrations/settings-post-migration-review.md#b01-logon-and-boot-presentation-2026-10-17)
for legacy differences, recovery boundaries and remaining native acceptance.

## Experimental suggestions and input preferences

The ContentDeliveryManager channels and legacy input preferences show their literal
writes with Unverified behavior. Related Windows UI documentation does not prove an
individual registry mapping. Some published enable states write 1 while the legacy
reverse removed an override; TIPC Enabled itself removes the value. Registry restore
cannot recover deleted learned words. See the [suggestion/input review](migrations/settings-post-migration-review.md#b01-suggestion-and-input-presentation-2026-10-17)
before selecting these experimental controls.

## Application feature controls

OneDrive policy can restrict app/file-picker access as well as synchronization.
Legacy Media Player UserChoice permits user settings rather than starting sharing
or downloads. Development preference values are documented, but the full Developer
Mode UI may manage companion OS state. Gaming preferences remain experimental on
the declared Windows 11 target. See the [application review](migrations/settings-post-migration-review.md#b01-application-feature-presentation-2026-10-17)
for exact writes, legacy reverse differences and native acceptance.

## Start, taskbar and notification controls

Published Visible/Always names often remove an override; inspect the literal effect
before relying on them. Current search and Alt+Tab choices can differ from retained
legacy numeric labels. People, Chat and tray promotion remain experimental mappings.
Notification Center and banners are separate controls. No display change restarts
Explorer automatically. See the [shell review](migrations/settings-post-migration-review.md#b01-start-taskbar-and-notification-presentation-2026-10-17).

## Remaining implementation and acceptance

Audit the remaining settings before filling their presentation fields. Add
observable effective-policy/source inspection per feature, not a generic registry
heuristic. The [intended-user handoff](intended-user-handoff.md) now implements
explicit user-only actions for the current desktop session. Its native interactive
acceptance remains pending; automatic mixed-scope ordering and recovery are still
separate work. The default Current context continues to use the execution account.

The first increment's focused Pester and catalog/reference checks passed on
native Windows PowerShell 5.1 and PowerShell 7 after the concurrent application
migration finished; the post-migration review records results and fixture retries.
GUI/sign-in/reboot, managed precedence and Windows Server acceptance remain
disposable-VM work.
