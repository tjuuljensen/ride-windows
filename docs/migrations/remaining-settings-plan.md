# Remaining settings migration plan and decisions

Current handoff, 2026-10-17: [all batch dispositions and completion order](remaining-migrations-follow-up.md#archive-handoff-and-closure-order-2026-10-17).
Presentation review is complete at 279/279; see the [final evidence](settings-post-migration-review.md#b01-presentation-review-completion-2026-10-17). Source presentation and native/user-visible
acceptance are separate. B03 startup fixtures pass, with native acceptance blocked by denied Hyper-V access. Q01-Q31
policy choices and subsequent refinements are recorded; BitLocker/recovery setup
and new deployment profiles are explicitly deferred, not awaiting repeated prompts.
The thirty rows below retain partial outcomes and their exact acceptance gates.

Source review: **2026-10-24 11:58 UTC**. This source-only recheck leaves D05 pending: Microsoft's general F1 shortcut guidance and a 2022 community report do not confirm File Explorer behavior on the current Windows 11 build. See the [source evidence](../archive/evidence/f1-file-explorer-current-source-recheck-2026-10-24.json). No catalog, profile or Windows state changed in that source review. Latest implementation update: **2026-10-24 12:52 UTC**; packaged Terminal selection-to-writer now checks the expected computer/SID before `-WhatIf`, and all 281 setting/control operations have explicit presentation metadata. Live AppX, profile launchability and disposable-VM acceptance remain open. The current catalog has 408 operations; B01 presentation review remains complete at 279/279. B01 adds reviewed presentation for keyboard delay,
pointer precision, registered sound schemes and startup sound, plus manual
playback-device mute guidance. B02 read-only playback-endpoint capture contracts
are source-ready; see the [B02 record](settings-post-migration-review.md#b02-read-only-playback-endpoint-contract-2026-10-16).
The B03 existing user-bin startup renderer is also source-ready as two pending runtime candidates; see the [profile contract](../powershell-profiles.md#existing-user-bin-startup-path-candidate). Retain GUI, startup and hardware acceptance separately. Native proxy,
Terminal profile and local password-complexity work follow after their recovery
contracts are demonstrated. E08 now has an inert, unregistered template builder/parser; focused Pester passes 8/8 and Windows PowerShell 5.1 parsing passes. Native secedit isolation, managed precedence and exact rollback remain unproven. Small registry changes with uncertain current effects
remain investigations, even when their code would be short.

This is the follow-up requested while the user is away. It covers all 30 entries
in the remaining-settings ledger, earlier accepted setting reviews, shared engine
gaps and the separate acceptance backlog. It collects decisions and test resources
without reopening accepted designs. Implementation priorities remain in
[TODO.md](../../TODO.md); legacy counts remain in
[MIGRATION-PLAN.md](../MIGRATION-PLAN.md). This document owns the consolidated
settings analysis and questions, not a second catalog or release plan.

Regional preparation also has [separate process/user/machine observations](remaining-migrations-follow-up.md#b09-regional-provider-inventory-2026-10-17); they are not complete recovery snapshots or setters.

## Current implementation and validation

The catalog has 408 operations: 281 setting/control declarations, 97 package
operations (67 PendingAcceptance), 22 Store app declarations, four PowerShell
profile settings, and four standalone artifacts. It has eight groups and five
profiles.
These are declarations, not counts of remaining legacy outcomes.
All 281 setting/control operations have explicit `SettingPresentation` metadata,
enforced by a catalog regression test. Unverified mappings,
obsolete behavior and native acceptance gaps remain identified within that metadata;
coverage does not certify behavior or close legacy outcomes. Twenty-one settings,
including the two startup settings, remain pending candidates. Do not widen
published support from a lifecycle result alone.
The retained BitLocker `EncryptionMethod` mapping needs a separate compatibility
migration or retirement decision; it is not established as a current Windows 11
cipher policy. Whole accessibility Flags presets likewise need narrower ownership
and live-session evidence before being recommended as prompt controls.

All five accepted Store groups have guarded declarations and a separate
current-user/desktop-handoff tool. App-specific native acceptance remains pending;
[Store follow-up decisions and resources](store-app-follow-up-decisions.md) owns
the approved reviewed-identity guard, interactive actor and retained-payload boundaries.

The completed [validation matrix](settings-validation-resume.md) includes stored
keyboard delay, WAP Push/Search startup/runtime/delay, update-notification policy,
CEIP, all local firewall profiles, conditional media policies, Server Manager,
Shutdown Event Tracker, local SAM maximum age and guarded Windows Audio service.
It includes controlled failure recovery where recorded, not universal OS-denial
or managed-policy acceptance.

All three owned plans passed creation, repeat apply, metadata-drift refusal and
compensation on Windows 11 and Server 2025. The shared Balanced handler also passed
active-copy refusal with separate selection recovery, real setting-drift refusal
and interrupted creation retaining Intent on both targets. Drift and interruption
have **checkpoint-only cleanup**, not RIDE recovery. The first interruption fixture
compared preliminary random inspection IDs with the actual creation IDs; its failed
run remains archived. The corrected capture comparison passed. Fixture 0.7.2 fixes
the generic progress sentence to describe guard acceptance accurately; this last
reporting edit has parser evidence, not another VM run.

The earlier package pause is lifted for the authorized overnight implementation window. No GitHub publisher request or package acquisition is
needed for this analysis. The shared controller remains the installed 0.4.6
baseline; concurrent PAT/controller source is separate work.

## Recommended implementation order

The order below uses accepted designs. An item described as ready still needs its
focused diff review and validation; it is not a promise that its runtime behavior
has already passed.

| Order | Work that can start without another product decision | Prerequisite and completion boundary |
| --- | --- | --- |
| E01 | First six-control batch implemented 2026-10-14: hidden/protected files, Explorer recent/frequent items, Control Panel view and Edge background mode | Metadata-only contract comparison passed; generated documentation current; 122 tests passed on each native PowerShell edition. The initial 5.1 authorization deferral was resolved using README's process-only launch. Broader metadata review and actual GUI/managed acceptance remain open |
| E01 follow-up | B01 input/audio presentation implemented 2026-10-16 for four existing controls | Whole-catalog comparison permits only four new presentation blocks; baseline, unset and saved recovery stay distinct. See the [batch record](settings-post-migration-review.md#b01-input-and-audio-presentation-review-2026-10-16); GUI, boot, managed and hardware evidence remains open |
| E01 Start/taskbar presentation follow-up | Sixteen controls reviewed on 2026-10-17 | Removal states and legacy shell limitations explicit; actual UI/multi-display acceptance remains. See the [record](settings-post-migration-review.md#b01-start-taskbar-and-notification-presentation-2026-10-17) |
| E01 Application presentation follow-up | Nine controls reviewed on 2026-10-17 | Development references and complete-UI limits clarified; gaming remains unverified. See the [record](settings-post-migration-review.md#b01-application-feature-presentation-2026-10-17) |
| E01 Suggestion/input presentation follow-up | Nineteen experimental controls reviewed on 2026-10-17 | Numeric channels remain unnamed/unverified; legacy reverse and diagnostic-data limits are explicit. See the [record](settings-post-migration-review.md#b01-suggestion-and-input-presentation-2026-10-17) |
| E01 Logon/boot presentation follow-up | Twelve existing controls reviewed on 2026-10-17 | BCD removal states and sign-in acrylic wording corrected; native boot/logon acceptance remains. See the [record](settings-post-migration-review.md#b01-logon-and-boot-presentation-2026-10-17) |
| E01 Network presentation follow-up | Thirteen existing controls gained presentation on 2026-10-17 | ICS service-policy wording corrected; LLMNR/mDNS, WinHTTP, NCSI and remote-access component boundaries retained. See the [record](settings-post-migration-review.md#b01-network-control-presentation-2026-10-17) |
| E01 Session visual observations | Five fixed native GET contracts implemented on 2026-10-17 | Fake interop and mocked identity tests passed; stored registry, actual GUI and target acceptance remain separate. See the [record](settings-post-migration-review.md#b01-read-only-session-visual-observations-2026-10-17) |
| E01 Visual effects follow-up | Eight existing controls gained presentation on 2026-10-17 | Seven visual requests and first-sign-in policy reviewed; four remain Unverified, whole-bundle and new-user GUI acceptance open. See the [record](settings-post-migration-review.md#b01-visual-effects-and-first-sign-in-presentation-2026-10-17) |
| E01 Desktop/Explorer follow-up | Fourteen existing controls gained presentation on 2026-10-17 | Legacy reverse differences, icon content ownership and two unverified cache mappings retained; the network-cache policy path differs from the stable legacy ID. See the [record](settings-post-migration-review.md#b01-desktop-and-explorer-visibility-presentation-2026-10-17) |
| E01 Exclusion recovery follow-up | Captured-path apply and versioned recovery repaired on 2026-10-17 | 109 focused tests per edition, one integration exclusion; valid older paths supported, hidden/managed/native membership still pending. See the [record](settings-post-migration-review.md#b01-defender-exclusion-capture-and-recovery-2026-10-17) |
| E01 Security follow-up | Eight existing controls gained presentation on 2026-10-17 | UAC shared secure-desktop effect, HVCI prerequisites, sample and exclusion recovery limits and legacy firewall scope reviewed; native acceptance remains. See the [record](settings-post-migration-review.md#b01-security-control-presentation-2026-10-17) |
| E01 Update/maintenance follow-up | Eight existing controls gained presentation on 2026-10-17 | Wake-path discrepancy, MSRT uncertainty, driver-search omission and Microsoft Update service-enrollment gap retained; native/GUI/profile recommendation remains pending. See the [record](settings-post-migration-review.md#b01-update-and-maintenance-presentation-2026-10-17) |
| E01 App Privacy follow-up | Seventeen existing device controls gained presentation on 2026-10-17 | Default versus per-app policy, Enabled removal and voice/background legacy bundles reviewed; native app/GUI/managed acceptance remains open. See the [record](settings-post-migration-review.md#b01-app-privacy-policy-presentation-2026-10-17) |
| E01 Explorer follow-up | Eight existing folder-option controls gained presentation on 2026-10-17 | Reverse removal versus explicit values and adjacent features are documented. GUI, touch, logon, process and sharing acceptance remain open; see the [record](settings-post-migration-review.md#b01-explorer-folder-options-presentation-2026-10-17) |
| E01 power follow-up | Seven power-control presentation reviews implemented 2026-10-16 | Dedicated button, screen-off, idle sleep and advanced menu effects/reverse are separate. Unsigned capture/legacy recovery and typed read backend implemented 2026-10-17; additional states, native API/locale and transition evidence remain open; see the [batch record](settings-post-migration-review.md#b01-power-control-presentation-2026-10-16) |
| E02 | Reconcile current acceptance pointers and history | Keep failed evidence and older holds as dated history. Current summaries must point to the later accepted runs. Distinguish implementation, lifecycle, guard, consumer/GUI and target acceptance. This closes no legacy outcome by itself |
| E03 | Terminal default-profile [native guidance](../windows-terminal-profile.md) and selected [playback-device mute guidance](../audio-service.md#mute-a-selected-playback-device) implemented | Manual workflows retain prior selection/mute and same-device recovery; GUI/playback acceptance remains pending. Terminal file editing and automated endpoint mute still need separate ownership, identity/session and conflict contracts. Acquire no components |
| E04 | Extend focused maximum-age boundary evidence | NoExpiry/90/999 and 1/2/998-day repeat/reverse/fault recovery passed on both targets. MinimumAgeConflict guard passed on both targets with a one-day fixture seed, zero primary native writes and separate exact seed recovery. GUI, managed/default and complexity-backend acceptance remain pending. Preserve all other fields; no user passwords change |
| E05 | Add isolated intended-user and managed-source validation designs | Capture expected SID/session before changing a user setting; refuse mismatched account recovery. Plan mixed-scope and alternate-administrator cases before any profile recommendation. Decision D01 governs an explicit cross-account route |
| E06 | JSONC preparation, guarded exact-path writer and current-user packaged-instance inventory/selection implemented | The [preparation API](../terminal-jsonc-preparation.md) preserves supplied bytes and refuses conflicts; `Set-RideTerminalInstalledInstanceDefaultProfile` re-queries current-user AppX inventory, binds the chosen package identity to its exact settings path and delegates to the identity-bound writer. Only a live query sets `InstanceVerified`; injected records cannot authorize writes. Full regression passes 57/57; Windows PowerShell 5.1 parsing and repository validation pass. Live AppX query, profile availability/launchability, unpackaged/portable discovery and disposable native acceptance remain open. Q09 selection behavior is accepted; each target still requires an actual instance/profile choice; no Terminal installation or default-terminal-host change |
| E07 | Default/LAN capture and in-memory edit/recovery proof source-ready; bind live state next | The [proxy APIs](../user-proxy-inventory.md) preserve literal flags/manual/bypass/PAC values with 31 capture and 39 preparation tests per edition plus x86/x64 layout proof. Fresh policy/identity binding, durable native writes/refresh, partial failures, RAS and GUI acceptance remain open. WinHTTP stays separate |
| E08 | Investigate a focused local complexity backend | Existing maximum-age code does not supply a complexity setter. The 2026-10-23 source review found `NetUserModalsSet` has no complexity field; an inert UTF-16LE one-setting `secedit` template builder and bounded local/merged export parser are implemented, while generated rollback remains unproven. Verify local versus merged effective policy, unrelated-field preservation, and exact Enabled/Disabled/Not defined recovery on Windows 11 and Server 2025 before catalog integration. See the [dated investigation](settings-post-migration-review.md#e08-local-password-complexity-backend-investigation-2026-10-23) and [structured evidence](../archive/evidence/local-password-complexity-secedit-backend-investigation-2026-10-23-1804.json) |
| E09 | Click to Do per-user policy candidate implemented | `windows.click-to-do-policy` maps the documented `DisableClickToDo` user policy to `Blocked=1`, `Allowed=0` and exact override removal. The user's local toggle, conflicting device policy, Copilot+ hardware, Policy CSP Insider Preview applicability and visible effect remain separate. The focused catalog test passed 1/1; no profile selects the candidate and `SupportedTargets` remains empty pending Windows 11 acceptance. See the [dated implementation record](settings-post-migration-review.md#click-to-do-policy-candidate-implementation-2026-10-24). |

**E01's first batch and D01's explicit user-only handoff are implemented.** Native
interactive handoff acceptance and mixed-profile recovery remain pending; see the
[handoff guide](../intended-user-handoff.md). Continue the other independent work.
E06-E09 now have distinct preparation/candidate records; Click to Do is the only
one of these four with a catalog candidate. Terminal's read-only packaged
inventory and exact-path writer remain separate until their instance-to-writer
selection is tied together and accepted on Windows. None has target support until
its specific file/API/registry recovery and visible behavior are accepted.

The first concrete batch is `windows.hidden-files-visibility`,
`windows.protected-files-visibility`, `windows.explorer-recent-shortcuts`,
`windows.explorer-frequent-shortcuts`, `windows.control-panel-view` and
`application.edge-background-mode`. All six now have explicit presentation
metadata. Hidden files uses 1/2, while protected files uses 1/0/removal; preserve
that difference. Both Explorer shortcut controls' published `Visible` state removes
the override, rather than writing an explicit On value. Control Panel is already
one paired setting with four named choices. Edge background mode is a machine
policy with distinct Enabled/Disabled/removal semantics. Metadata must describe
those contracts accurately, not rewrite them to make the labels look uniform.

Microsoft documents separate Terminal default-profile and default-terminal-host
choices. Its [installation and configuration guide](https://learn.microsoft.com/en-us/windows/terminal/install)
also lists several settings-file locations. Discover the applicable installed
instance rather than assume one Store path. Preserve the user's file syntax when
editing it.

The [WinINet connection options](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optiona)
identify detection flags and setup-script URL, while
[query/set guidance](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)
defines the connection list and returned-string ownership. This provides a backend
candidate, not current Settings GUI or managed-policy acceptance. A service account
or SYSTEM test does not establish intended-user behavior.

[NetUserModalsSet](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset)
lists maximum-age and related modal fields but no focused complexity information
level. The [SAMR domain information classes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/3e8738b2-5df6-499f-907d-ac2471bf0281)
describe protocol structures; that alone does not make an undocumented local DLL
export an approved Win32 backend. Evaluate a supported narrow route instead of
replaying a whole security export.

## Complete remaining ledger triage

The following numbers correspond to every current remaining-ledger row. Multiple
controls within a row keep separate evidence and recovery boundaries. These 30
rows do not replace the 38-58 remaining-feature estimate. R30 evaluates an already
counted built-in app/component outcome rather than adding another legacy count.

| Row | Outcome and current state | Next work and edge cases | Classification |
| --- | --- | --- | --- |
| R01 | Existing-plan selection, owned creation and desktop Power plans access | Creation and shared guards now have two-target evidence. Keep Ultimate activation separate; earlier native activation failed. Inspect menu installation-path ownership and intended-user scope before deploying a reversible helper. Physical device/power-mode effects and template absence remain separate | Implemented core; menu and physical acceptance pending |
| R02 | Proxy detection, setup script and WinHTTP | E07/B04. Default/LAN capture and owned-field preparation/recovery are source-ready. Durable writes, refresh, native/UI/policy and partial-failure acceptance remain; preserve manual proxy and unrelated fields. RAS and WinHTTP stay separate. A PAC test needs a controlled local server | Partial source preparation; native setter/recovery pending |
| R03 | Telemetry mirrors, Windows CEIP and conditional App-V CEIP | Windows CEIP typed lifecycle is done. Verify an actual App-V client, policy mapping and consumer before availability. Leave Native/Wow telemetry mirrors untouched and unexposed; do not infer effect from duplicate values | Conditional consumer evidence; D04 |
| R04 | Paired feedback frequency | Existing native guidance is available. Confirm current GUI choices, both value kinds and time units before exposing executable states. Preserve mixed/custom prior pairs and unrelated Rules values; exact paired restore needs partial-write evidence | Mapping investigation; D02 |
| R05 | Windows RE registration lifecycle | Read-only registration/OS/image/partition capture first. Existing readiness guide covers independent recovery. The [volume inventory](../volume-inventory.md) provides GUID-path observation only, without boot-role or protection inference. Prove restoring a prior registration association, not merely calling the opposite command. Refuse identity/servicing conflicts; no image or partition changes | High dependency recovery work; D06 |
| R06 | Browser service Hidden override | Accepted retirement is complete. Preserve legacy source and existing values. Network discovery guidance is implemented; peer/profile acceptance is separate | Retired selector; modern outcome partial |
| R07 | Retired MusNotification interception and supported update interruption control | Interception remains retired and untouched. Notification literal lifecycle/fault recovery and guidance are implemented. Validate visible warnings, active-hours combinations, deadlines and effective policy without promising no reboot | Consumer/restart acceptance; D03 |
| R08 | System protection | Native guidance and read-only GUID-path inventory exist. Prove enabled-volume inspection, system-drive coupling, storage allowance and asynchronous completion. Off may destroy history; restoring configuration cannot restore deleted points | Recovery/volume investigation; D06 |
| R09 | Storage Sense | Existing On/Off and guide preserve cleanup preferences. Verify actual switch, policy precedence, default/removal and cleanup-choice meanings using disposable test files. Never restore a deleted-file outcome by claiming registry recovery | GUI/content acceptance; D02 |
| R10 | Windows-native F1 suppression | Test the accepted per-user TypeLib candidate against current Explorer/Desktop help and other apps. Preserve typed values and owned keys. Do not substitute IFEO, file ACL changes, AutoHotkey or a download | Experimental mapping; D05 |
| R11 | Taskbar sizing and Terminal profile | Native taskbar choices and rollout must be observed; no TaskbarSmallIcons assumption or feature-enablement forcing. E03/E06 cover Terminal selection separately, preserving existing profiles and broader normal-launch effect | Taskbar GUI investigation; Terminal backend candidate |
| R12 | Shortcut arrow appearance | Verify the actual resource and rendering before Hide availability. Retain machine/admin scope, typed value 29 and unrelated overlays. No guessed resource index or forced Explorer restart | Cosmetic mapping investigation; D02 |
| R13 | Sign-in and post-sign-in NumLock | Compare the two accepted registry preferences with the user's reliable combined legacy result on real boot/sign-in hardware. Preserve type/encoding and unrelated lock-key state. Do not silently reintroduce SendKeys | Hardware/session evidence; D05 |
| R14 | Compressed/encrypted file-name colors | Observe the current GUI mapping before selecting ShowCompColor versus the legacy value. Test ordinary/compressed/EFS names and themes; preserve file attributes. Existing EFS capability is a prerequisite, not permission to acquire it | Read-only GUI mapping first; D02/D04 |
| R15 | Explorer start location and experimental Home hiding | Preserve the existing start-location ID and states. Test HubMode independently of LaunchTo and user/machine precedence. No namespace reconstruction, pin/history reset or forced restart | Home-hiding mapping investigation; D02 |
| R16 | Include in Library, Give access to and Share menus | Three accepted outcomes. Identify physical roots/views and all bindings before suppression. Prefer bounded reversible binding changes; if subtree deletion is unavoidable, typed content/subkeys/ACLs and conflict-safe recovery must be proved | Multi-binding ownership work; D07 |
| R17 | Five desktop icons and ClassicStartMenu mirrors | Preserve the five published IDs. Compare independent/conflicting mirrors with the GUI and rendering before adding or retiring a mirror. A coordinated handler must read old scalar snapshots without inventing omitted history | Mapping/compatibility investigation; D02 |
| R18 | Server Manager and Shutdown Event Tracker | Both pending candidates now have Server 2025 literal/fault-recovery evidence. Logon/console precedence and actual shutdown prompt remain open. Desktop Experience and Core are distinct applicability cases | Feature/session acceptance; D03/D04 |
| R19 | Local complexity, maximum age and IE ESC | Maximum age has both-target native evidence; E04 adds bounded cases. E08 investigates complexity. IE ESC needs real Server component/class/profile-effect evidence and separate admin/user controls; no Edge/IE-mode equivalence | Complexity backend; conditional ESC evidence; D04 |
| R20 | Audio service and selected playback endpoint mute | Audiosrv lifecycle/fault recovery passed both targets. More dependencies/triggers remain. E03 provides mute UI guidance; direct mute needs stable endpoint identity, saved boolean and session/device-loss recovery without volume/default-device changes | Endpoint/session backend; D04/D08 |
| R21 | BitLocker encryption/decryption and TPM+PIN enrollment | Guided policy, protectors, secure input/redaction and staged nonsecret records first. Preserve current methods/protectors. Encryption progress and added PIN do not prove boot/unlock. No implicit hardware-test skip, reboot or protection suspension | Staged security workflow; D06 |
| R22 | Recovery protector backup, creation and selected-key display | Existing guide separates backup, creation and display. Choose by protector type/ID, reuse existing keys for backup, and use an accessible off-device destination. Never put recovery secrets in routine state/logs | Secure presentation/retrieval work; D06 |
| R23 | Failed-sign-in machine lockout | Confirm mapping and real counting/recovery behavior with protected OS volume and retrievable backup first. Separate Windows sign-ins from TPM PIN/Hello/account lockout; policy restore cannot undo enacted transitions | Recovery-dependent security experiment; D06 |
| R24 | Photo Viewer Open with registration and default-app handoff | Verify an installed native consumer and exact quoting/extensions. Intended-user registration must preserve existing entries; default-app selection is a separate native UI step. No UserChoice hash bypass or component download | Component/registration ownership work; D04 |
| R25 | Conditional radio and Windows Media DRM | Both typed policies and interruption/recovery passed where applicable. Player presence is not radio consumer behavior; WMDRM client/backend/license effects remain unresolved. No installation or license-store repair | Conditional consumer investigation; D04 |
| R26 | Keyboard effective delay and packed visual effects | All stored delay positions and typed recovery passed. Compare native active delay with stored state before backend changes. For effects, reconcile each GUI feature independently and preserve custom masks; no fixed broad preset | Session/native comparison; D02 |
| R27 | WAP Push/Search delayed and startup-only states | Implementation, stored/runtime lifecycle and controlled recovery passed. Test boot scheduling, workload, dormant flags and trigger/dependency effects. No reboot or fixed-delay guarantee is implicit | Boot/workload acceptance; D03 |
| R28 | Windows Security startup icon | Guide and policy presentation exist. Verify intended-user startup entry, overflow and managed precedence. Native handoff remains pending user work; no historical Run-entry reconstruction | GUI/session acceptance; D02 |
| R29 | User .NET assemblies: bookkeeping closed | Q31/D09 accepts closure of the unsubstantiated label; retain the bounded audit and reopen on identified source/use case. No guessed assembly action or migrated-feature claim | Closed 2026-10-17; no numeric outcome deduction |
| R30 | Reviewed Store app selection, policy and user uninstall | [Five optional uninstall/reinstall groups](../store-app-groups.md) accepted, with Media Player/Sound Recorder in multimedia and Xbox dependencies reviewed together. Device policy stays a separate linked workflow. Both references collected; reviewed protection/source rule retained. Solitaire basic native registration lifecycle accepted; policy schema, interruption, app/data recovery and sign-in acceptance remain open | All five groups implemented as guarded candidates; Clipchamp next when elevation available; GUI/full handoff/group/policy and other targets pending; components owner; D11 |

## Earlier accepted controls that still need evaluation

The remaining-ledger table is not the whole acceptance backlog. The earlier
[post-migration review](settings-post-migration-review.md) contains the following
families. Preserve its accepted designs while adding evidence. A catalog-supported
operation may still have unresolved GUI meaning or an incomplete legacy bundle.

| Family | Required follow-up before complete acceptance |
| --- | --- |
| Promotions and numbered suggestion channels | Keep useful individual controls and optional Reduce Windows promotions guidance. Establish each numeric channel's effect; unknown channels remain experimental and outside recommended profiles |
| Input personalization, diagnostics and recognition data | Reconcile multiple local preferences and policies with current GUI/consumer behavior. Separate personalization, uploads and clearing data; no blanket privacy claim |
| Activity history | Verify current supported surfaces and the distinction between local storage, publishing and upload; reconcile removed or conditional behavior without reusing old labels |
| Location, voice activation and app file access | Check global versus per-app, user versus machine, component availability and permission enforcement. Preserve app-specific choices and distinguish consent from enterprise policy |
| Administrative shares and .NET strong cryptography | Validate actual consumers, native/Wow views, service/boot timing and compatibility. Do not equate a flag with complete sharing security or all-runtime cryptography |
| Driver updates and device metadata | Separate update-source inclusion from metadata retrieval; validate effective policy and real update/metadata effects without triggering broad maintenance |
| Maintenance wake and SSDP/UPnP | Verify timers, power/hardware support and service dependencies. Network discovery behavior needs a peer/profile fixture; service state is partial evidence |
| Notifications and accessibility shortcuts | Match actual per-user choices, runtime notifications and shortcuts while preserving unrelated accessibility settings; preference recovery does not undo notifications already delivered |
| Taskbar grouping and This PC folders | Verify current GUI, modern surface and build capability; reconcile namespace/policy scope, omitted branches and exact ownership of removed keys |
| Hidden/protected files and Explorer recent/frequent items | E01 metadata first, followed by GUI/default and policy-precedence checks. Preserve independent controls and existing reverse-state semantics |
| Background apps | Verify current app eligibility and per-app override ownership; global flags do not establish that every app stopped running |
| Power, sleep button/menu/timeouts and hardware clock | Keep system plan, power mode, hardware-dependent actions and menu visibility distinct. Capture concrete resource identity and prove compatible recovery on actual devices |
| Control Panel view and mouse precision | Validate visible mode and effective session values. Registry-only round trips do not establish current runtime behavior |
| UAC | Accepted four slider positions require the exact coordinated values and actual prompt behavior on both targets. Preserve EnableLUA. Mixed-user evidence and reboot behavior remain separate; D01/D03 |
| Fullscreen optimization and visual effects | Verify feature-specific semantics and current GUI before broad presets. Preserve per-app overrides and custom masks |
| Defender cloud, samples, CFA, memory integrity and SmartScreen | Confirm prerequisites, effective modes and real protected/blocked behavior with harmless controlled fixtures. Built-in versus separately licensed services remains visible; do not acquire or disable components to obtain a pass |
| Search web results and automatic network-device setup | Determine current consumer, policy precedence and actual visible result. Background references do not prove an undocumented value's mapping |
| Developer Mode, trusted sideloading and Xbox/media metadata | Separate independently useful features and installed consumers; distinguish policy from prerequisite installation and app acquisition |
| Boot recovery, diagnostics/Office tasks and drive optimization | Existing task identity/schedule tests do not establish payload or workload suppression. Missing tasks/components remain unavailable; preserve automatic recovery and maintenance meanings |
| Start most-used list and Ctrl+Alt+Delete | Validate positive GUI labels, disabling policy inversion, launch tracking, credential/accessibility effects and managed precedence; no implicit sign-out |
| Adapter bindings, LLTD, NetBIOS, NCSI and network profile | The [adapter inventory](../network-adapter-inventory.md) provides a source-ready GUID observation contract; native acceptance and selection remain open. Add paired flags, DHCP/static/VPN behavior, GUI refresh and peer evidence. Preserve GUID-bound restore and new-adapter exclusion; D04/D10 |
| SMB and Remote Desktop | Local flag/rule evidence is partial. Verify prerequisites, exact local/effective sources, authenticated/rejected peers, firewall scope and real session behavior. Missing SMB1 is unavailable, not accepted enablement |
| Sound scheme, startup sound and Edge policies | Preserve customized presets and existing files; test GUI/playback and managed behavior. Edge installation-shortcut policy requires an applicable installer/version and cannot reverse a shortcut already created |
| Scope, enforcement and intended-user execution | E01/E05. Audit roots, account/license/build/hardware prerequisites, configured versus effective sources and all discovery/detail/plan/status surfaces. Displaying the execution account alone is not a target guard |

## Questions and follow-up decisions

Leave answers beside the IDs or provide an ID and answer in chat. No answer is
required while the user is away. Work with an accepted design and independent
evidence can continue. A question about a test resource does not authorize installing
it or acquiring a package.

| ID | Question | Proposed course while awaiting an answer |
| --- | --- | --- |
| D01 | Answered 2026-10-14 and clarified 2026-10-24: use a separate process handoff to the intended user; mixed-scope profiles are valid and expected | First delivery targets the signed-in user in the current desktop session; other sessions or no desktop are refused. Preserve user-owned saved recovery and explicit identity/session checks; no fallback to another administrator's HKCU. Do not block profiles that combine user and machine settings. A mixed-scope overview/report is optional future work, not a migration prerequisite |
| D02 | Answered Q28: Explorer/icons and keyboard/input first | Preserve other GUI checks as pending; use independently authorized disposable targets and defer unavailable resources |
| D03 | Answered Q28: Server sign-in/shutdown next | Application-dependent checks then hardware/peer checks; retain explicit credentials, elevation and recovery gates |
| D04 | Answered 2026-10-24: defer unavailable resources explicitly and proceed with independent acceptance; a standalone Lenovo Windows 11 Pro laptop will be prepared for the TPM/boot test | Match each acceptance case to the available target. Defer only checks that require unavailable resources, and request another scenario when its evidence need is concrete. The dedicated physical laptop is a scoped TPM/boot acceptance target; document why this hardware scenario uses it alongside the disposable-VM validation model |
| D05 | Partially answered 2026-10-24: user wants an option to disable File Explorer F1 Help and wants it in the default profile if current Windows behavior is confirmed. Historical NumLock build/hardware/boot conditions remain unknown | Microsoft's current keyboard tips page describes F1 as a common Help shortcut but cautions behavior can differ by app; a 2022 Microsoft Community answer reports Explorer F1 opening a browser help page but does not establish current build behavior. Verify on an authorized Windows 11 target; if confirmed, prepare a clearly named setting and include it in the default profile with exact restore. Do not use SendKeys, IFEO, or a remapper. Keep NumLock historical evidence open. See the [source review](settings-post-migration-review.md#f1-current-keyboard-source-recheck-2026-10-24) and [structured evidence](../archive/evidence/f1-file-explorer-current-source-recheck-2026-10-24.json) |
| D06 | Updated 2026-10-24: the user will prepare a standalone Lenovo Windows 11 Pro laptop; USB storage and a password manager are both acceptable recovery-key destinations | Before a recovery-changing step, ask the user to confirm the key was saved and can be retrieved, unless the procedure verified that it saved the key to portable storage. Do not require an independent verifier or a particular destination, and do not record recovery secrets. Keep testing deferred until the laptop and confirmation are available |
| D07 | Answered Q29: visible but unavailable until reliable recovery | Explain the limitation and provide accurate manual guidance. No guessed content/ACL reconstruction or retirement |
| D08 | Answered Q30: explicit endpoint plus separately selected current-default option | Resolve/capture actual identity before mutation and restore that same endpoint; no fallback when missing |
| D09 | Answered Q31: close unsubstantiated bookkeeping | Retain bounded audit and reopen on evidence; no assembly deployment/removal or feature-completion claim |
| D10 | Answered Q30: explicit stable adapter/volume identities | Friendly selection display, same captured identity for recovery, report disappearance. Existing all-visible adapter compatibility scope remains explicit |
| D11 | Answered: modern v3 scope; five optional uninstall/reinstall groups; device policy separate | [Accepted membership](../store-app-groups.md) includes 22 apps, with Media Player/Sound Recorder in 2B. All five groups implemented as candidates. Reviewed identity/removability rule approved; usable local reinstall source required. Start native acceptance with Clipchamp/Solitaire after desktop acceptance. Current apps stay installed; packages paused; no automatic policy changes or v2 replay |

## Testing and elevation while the user is away

Use Windows-native parser/catalog/profile/generated-document checks and focused
mocked Pester tests. Keep TestRegistry disabled and WindowsIntegration excluded on
the workstation. Data inspection and plan/completion checks must not invoke setters.

Authorized disposable settings tests can use the existing unattended controller
when both controllers are idle, queues empty, locks available, pins and installed
hashes match and no competing request exists. Use current Local source with the
relevant uncommitted implementation, a bounded explicit fixture and a retained
source hash manifest. Serialize runs; inspect collection and checkpoint recovery
before another submission. No Full/default-profile or package-acquiring suite.

If a task requires an interactive elevation prompt, enrollment/credential entry,
approval response or workstation administration, postpone it and add its exact
action and dependency below. The existing authorized controller can run elevated
inside a disposable guest without an interactive UAC response; that does not
authorize a new host configuration or an unattended security transition.

| Deferred resource or action | Why it cannot be counted as accepted now | Independent work available |
| --- | --- | --- |
| Interactive elevated host/controller configuration | User is AFK; existing installed controller is sufficient and must be preserved | Read installed evidence; prepare changes for later review without applying |
| GUI/interactive session and alternate-user fixtures | WinRM/SYSTEM or a registry value does not establish visible intended-user behavior | Prepare observation/assertion checklist and identity boundaries |
| Physical keyboard, firmware/Fast Startup and power behavior | Disposable VM lifecycle does not represent the user's historical NumLock/power outcome | Design controlled boot comparisons and record D05 resources |
| Office/App-V/legacy media/ESC consumers and installation-time Edge effect | Required installed versions may be absent; package acquisition remains paused | Read source and official prerequisites; retain explicit unavailable dispositions |
| Peer network/domain/managed policy and vendor adapters | Local PersistentStore or a single synthetic NIC is incomplete acceptance | Define restrictive peer scenarios, inventory requirements and source comparison |
| BitLocker secure input, key retrieval and actual boot/unlock | Requires usable independent recovery, secret handling and a representative boot route | Design nonsecret records, ownership, staged failure and native handoffs |
| System protection deletion/history and Windows RE association mutation | Configuration restore cannot recover lost history or an unverified boot/image state | Implement read-only capture proposals and conflict checks before writes |

[SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow)
documents keyboard delay 0-3 and hardware variation. A future delay fixture should
compare its read-only effective value with stored state before changing the stable
registry backend. [Core Audio endpoint volume](https://learn.microsoft.com/en-us/windows/win32/api/endpointvolume/nn-endpointvolume-iaudioendpointvolume)
documents hardware versus software mute and exclusive-mode limitations. A no-endpoint
VM or software-only exclusive stream cannot prove universal audio silence.

## Other migration groups and estimate boundaries

This plan triages the remaining **settings** agenda. Package implementation is
authorized for the extended overnight window; individual runtime/ownership gates remain.
Keep the other four groups visible so prerequisites are assigned to their actual
owner instead of being counted twice as settings.

| Group | Current remaining range | Planning boundary |
| --- | ---: | --- |
| Windows and application settings | 38-58 | The 30 remainder rows and earlier accepted-control families above; implementation and acceptance tracked separately, with R30's app lifecycle counted under components |
| Packages, portable tools and artifacts | 56-71 | Q17/Q20 retire two planned products. Independent source migration is authorized; preserve GitHub backoff and postpone native/interactive acceptance |
| Components and optional features | 20-25 | App-V/SMB1/IE-related consumers, RSAT, WSL/Hyper-V/Sandbox/OpenSSH and app management need their own component applicability and recovery; no automatic provisioning here |
| Accounts, configuration and assets | 25-35 | Alternate users, Wi-Fi, region/language, fonts/wallpapers, PATH/bin and application configuration belong here when they are deployed configuration. Browser/Sysmon and traditional Python association/ownership reviews remain separate from package installation |
| Maintenance and operational actions | 8-12 | Hostname, updates, cleanup, Sysprep and runtime/rule updates remain distinct actions. Preserve the yielded quota bridge and held controller/default-branch delivery work |
| Total rounded | 145-200 | About 175 for planning after two explicit package retirements; summed endpoints 147-201 rounded to nearest five |

## Next handoff

The earlier validation follow-up remains distinct from the authorized overnight
migration continuation through 08:00 Copenhagen on 2026-10-17. Pending implementation
and feature acceptance remain below and in TODO.md; no acceptance evidence is discarded.

E01's first six-control batch is implemented; see its
[evidence and limitations](../archive/evidence/settings-presentation-batch1-2026-10-14.md).
The selected same-session intended-user process handoff is implemented for explicit
user-only actions; see the [batch evidence](../archive/evidence/intended-user-handoff-batch1-2026-10-14.md).
Read-only native readiness outside the sandbox resolved the CIM access issue.
User-authorized WinRM preparation, both Store reference captures and grouped
app review have passed. All five groups are implemented as guarded candidates.
[Solitaire basic native registration lifecycle](../archive/evidence/store-solitaire-validation-2026-10-14.md)
passed; Clipchamp is next when fresh elevation is available. Interruption,
GUI/data, group behavior and the full intended-user handoff remain pending;
inventory collection and the isolated worker do not prove the full handoff.
Mixed-profile completion, ordering and cross-store recovery remain separate work.
E02-E03 can follow independently.
Prepare E04-E05 fixtures without repeating completed matrices. Investigate E06-E08
one at a time, keeping D01 and resource questions visible. Mapping-dependent R10-R17
remain unavailable until their actual feature evidence supports the backend.

D11's first group and later group membership are answered and implemented as candidates.
The [full remaining migration follow-up](remaining-migrations-follow-up.md)
collects all five groups and questions for the user's return. Packages stay
paused and elevation-dependent work is postponed while AFK.
Next interactive decisions are D02 and D04;
D01's mixed-profile ordering/completion still needs design. D06 precedes security/recovery
experiments. D07 is conditional on failed bounded-menu recovery, and D09 is the
provenance issue. A final migration walkthrough still waits for every retained
setting to be implemented or explicitly replaced/retired with remaining acceptance
clearly assigned.

Source authority: [remaining decisions](remaining-settings-decisions.md),
[accepted reviews](settings-post-migration-review.md),
[implementation handoff](settings-implementation-handoff.md),
[validation resume](settings-validation-resume.md),
[catalog](../../catalog/operations.psd1) and historical
[selectors](../../legacy/v2/default.preset). Stable IDs, prior recovery and accepted
decisions in those records take precedence over a shortened row here.

## Decision-session reconciliation, 2026-10-17

Q07-Q12 now accept interactive administrator enrollment, separate startup/persistent
user PATH, existing-profile Terminal selection, separate browser preferences and
policies, scoped reviewed assets and per-user Wi-Fi/import boundaries. See the
[authoritative reconciliation](remaining-migrations-follow-up.md#reconciled-decision-session-answers-2026-10-17).
These choices remove design questions, not identity/ownership/recovery or native
acceptance. No settings changed; presentation remains 102/279 with 177 open.

Persistent user PATH now has [literal observation, entry recovery and an internal guarded write boundary](../powershell-profiles.md#persistent-user-path-preparation).
The focused suite passes 50/50 in each native edition using mocked registry
handles. The startup renderer remains separate; the RIDE engine does not dispatch
the writer, and durable run recovery, refresh and native acceptance are pending.
No legacy outcome or presentation count changed.

## Accepted remaining decisions, 2026-10-17

The [Q25-Q31 decision record](decision-session-2026-10-17.md) accepts configuration
ownership, static Store-first ordering, explicit destructive-action recovery with
a disposable-cache exception, GUI/Server/hardware acceptance order, unavailable
menu controls where recovery is absent, and stable resource identity. R29/D09 is
closed as unsubstantiated bookkeeping; the bounded audit remains authoritative
and a source/use case reopens it. No legacy estimate is deducted because the
audit did not establish an extra outcome. Actual implementation/GUI/native
acceptance remains separate; all five ranges remain 38-58 / 56-71 / 20-25 /
25-35 / 8-12, rounded 145-200/about 175.

## B01 service startup and runtime presentation, 2026-10-17

See the [dated review](settings-post-migration-review.md#b01-service-startup-and-runtime-presentation-2026-10-17). Presentation is 185/279, 94 open. Both editions passed 122 focused checks (one integration exclusion); native/GUI/whole-outcome acceptance stays separate. All five ranges remain unchanged; continue independent source batches.

## B01 scheduled-task presentation, 2026-10-17

See the [dated review](settings-post-migration-review.md#b01-scheduled-task-presentation-2026-10-17). Presentation is 198/279, 81 open. Both editions passed 122 focused checks (one integration exclusion); native/GUI/whole-outcome acceptance stays separate. All five ranges remain unchanged; continue independent source batches.

## B01 scheduled-task observation and readback, 2026-10-17

See the [repair evidence](settings-post-migration-review.md#b01-scheduled-task-observation-and-readback-2026-10-17). Twenty selected task tests passed per edition; native workload acceptance remains pending. Presentation is 198/279, 81 open. Existing profiles remain unchanged under the new explicit profile-selection deferral. All five ranges remain unchanged.

## Mixed-scope profiles and acceptance resources, 2026-10-24

The user confirmed that mixed-scope profiles are expected because RIDE users
commonly apply settings from both user and machine scopes. Mixed scope is not a
design or migration blocker. A report or analysis view that summarizes scope
within a profile may be considered as separate future functionality; it is not
required before completing profile work. D01 remains answered for intended-user
handoff and identity-safe recovery; its mixed-scope follow-up is closed.

Unavailable acceptance resources are explicitly deferred while independent
checks proceed. A standalone Lenovo laptop running Windows 11 Pro is the selected
target for the TPM/boot recovery scenario, and the user will prepare it. This is
a focused hardware acceptance case alongside the repository's disposable-VM
validation model, not a general change to that model.

The user clarified on 2026-10-24 that either USB storage or a password manager
may hold the recovery key. Before a recovery-changing test, ask whether the key
has been saved and can be retrieved, unless the procedure itself verified the
key was saved to portable storage. Do not require a specific destination or an
independent verifier. Never record the key in repository evidence. The laptop
and this confirmation remain prerequisites; no recovery-changing test is
authorized by this clarification. See the [follow-up decision record](remaining-migrations-follow-up.md#mixed-scope-profiles-and-tpm-boot-acceptance-2026-10-24)
and the [authoritative decision ledger](decision-session-2026-10-17.md#joeware-latest-download-and-acceptance-resource-decisions-2026-10-24).

## RIDE v3 Windows AI, passkey and presence controls, 2026-10-24

The user added the following recent Windows controls to the RIDE v3 candidate
scope. They are new feature work, not legacy outcomes; do not change migration
estimates or count these as completed legacy selectors. Click to Do now has an
unregistered, pending catalog candidate; no profile selection or Windows
behavior is claimed by recording this scope.

| Candidate | Intended RIDE control | Implementation and acceptance boundary |
| --- | --- | --- |
| Click to Do | Per-user `Blocked`/`Allowed`/`WindowsDefault` policy candidate implemented; keep independent from Copilot and Recall | `windows.click-to-do-policy` maps the documented `DisableClickToDo` DWORD. `Allowed` does not force the user's local toggle on, and a conflicting device policy remains outside this operation. The CSP lists Insider Preview applicability. Verify current target policy behavior, visible entry points and exact saved-state restore before declaring support. It is not selected in any default profile. |
| Passkey app access | Keep per-app access and user choice; do not default-deny all applications | Windows 11 24H2 exposes per-app passkey privacy consent. Microsoft documents policy controls for app lists, but currently marks them Insider Preview. Model package-family-specific allow/deny/user-control decisions and preserve each app's prior choice; a global Boolean registry operation is not equivalent. Verify sign-in and registration recovery for each selected app. |
| Presence sensing | Keep app access at user control by default; offer OS lock-on-leave separately as a security control | Microsoft documents the app-access policy and hardware-dependent presence behaviors. Do not combine app access, lock-on-leave and wake-on-approach into one switch. Verify exact policy consumers, sensor availability, supported builds, lock timing, wake behavior and prior-state restore. |
| Administrator protection | Offer an explicit enable choice; consider it for a hardened profile after acceptance | Microsoft documents a LocalPoliciesSecurityOptions CSP and restart requirement. The current CSP target is Insider Preview, and Windows Server is not supported by the feature documentation. Implement through a supported local security-policy backend, not an inferred registry value; verify prompt behavior, restart and exact restoration on a disposable Windows 11 VM. |
| Smart App Control | Inspect Off/Evaluation/Enforcement and offer enablement only where Windows exposes a supported transition | Microsoft says registry configuration is for testing and may compromise protection. Its documented Settings transition is one-way outside Evaluation on the current guidance; verify the new on/off rollout and a supported recovery route before adding a state-changing operation. Test app compatibility and restart requirements in a disposable VM. |

Click to Do's source-backed candidate has state observation, apply and exact
saved-run restore through the existing `RegistryValue` handler; target
applicability and visible effects remain unaccepted. The other four remain
source-review and implementation candidates until their state, apply,
saved-run restore, target applicability and visible effects meet RIDE's
lifecycle contract. The default-profile recommendations above remain deferred;
none of these controls is selected in `profiles/default.psd1`.
Authoritative references: [WindowsAI Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai),
[passkeys in Windows](https://learn.microsoft.com/en-us/windows/security/identity-protection/passkeys/),
[Privacy Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy),
[Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection),
and [Smart App Control testing and configuration](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control).
