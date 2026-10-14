# Remaining settings migration plan and decisions

Reviewed: **2026-10-13**. The next implementation should extend reviewed setting
presentation to a small set of well-understood existing controls. Native proxy,
Terminal profile and local password-complexity work follow after their recovery
contracts are demonstrated. Small registry changes with uncertain current effects
remain investigations, even when their code would be short.

This is the follow-up requested while the user is away. It covers all 29 entries
in the remaining-settings ledger, earlier accepted setting reviews, shared engine
gaps and the separate acceptance backlog. It collects decisions and test resources
without reopening accepted designs. Implementation priorities remain in
[TODO.md](../../TODO.md); legacy counts remain in
[MIGRATION-PLAN.md](../MIGRATION-PLAN.md). This document owns the consolidated
settings analysis and questions, not a second catalog or release plan.

## Current implementation and validation

The catalog has 318 operations: 277 setting/control declarations, 40 packages and
one artifact. These are declarations, not counts of remaining legacy outcomes.
Twenty-two settings have explicit `SettingPresentation` metadata; the other 255
still require individual review before the fallback display can be replaced with
specific behavior, GUI effects and requirements. Fifteen settings are pending
candidates. Do not widen their published support from a lifecycle result alone.

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

Packages remain paused. No GitHub publisher request or package acquisition is
needed for this analysis. The shared controller remains the installed 0.4.6
baseline; concurrent PAT/controller source is separate work.

## Recommended implementation order

The order below uses accepted designs. An item described as ready still needs its
focused diff review and validation; it is not a promise that its runtime behavior
has already passed.

| Order | Work that can start without another product decision | Prerequisite and completion boundary |
| --- | --- | --- |
| E01 | Extend explicit scope, behavior, GUI-effect and prerequisite metadata for known existing controls, starting with hidden/protected files, Explorer recent/frequent items, Control Panel view and the remaining reviewed Edge policy | Read the existing accepted section and exact Microsoft reference for each control. Keep IDs, values, handlers, defaults and recommended selections unchanged. Generate OPERATIONS.md; validate display, references and catalog-derived completion with mocked native calls |
| E02 | Reconcile current acceptance pointers and history | Keep failed evidence and older holds as dated history. Current summaries must point to the later accepted runs. Distinguish implementation, lifecycle, guard, consumer/GUI and target acceptance. This closes no legacy outcome by itself |
| E03 | Complete native UI handoffs for accepted outcomes that still lack guidance, starting with Terminal default profile and selected playback-device mute | Show installed-component and intended-user prerequisites. Treat the manual UI step as pending user work, not captured RIDE apply. Reuse existing guides where present; do not add installers or acquire a component |
| E04 | Extend focused maximum-age boundary evidence | Current NoExpiry/90/999-day and reverse/fault recovery evidence is complete. A narrow 1/2/998-day selection and conflicting minimum-age refusal can add boundary evidence. Verify untouched fields and native readback; never exercise all generated day choices or create/change user passwords |
| E05 | Add isolated intended-user and managed-source validation designs | Capture expected SID/session before changing a user setting; refuse mismatched account recovery. Plan mixed-scope and alternate-administrator cases before any profile recommendation. Decision D01 governs an explicit cross-account route |
| E06 | Implement Terminal default-profile selection after an isolated file-preservation proof | Enumerate existing installed profiles, choose by identity and update only the root default-profile field. Preserve JSON-with-comments, unknown fields and unrelated concurrent edits. Bound saved recovery and refuse profile disappearance or restore conflict. No Terminal installation or default-terminal-host change |
| E07 | Implement coherent user proxy detection/setup-script controls after query/capture proof | Use the documented connection API, not guessed packed bytes. Preserve manual proxy, bypass and unrelated flags; capture connection identity and prior URL/flags. Separate WinHTTP machine settings. Prove user context, partial failures and refresh before connectivity acceptance |
| E08 | Investigate a focused local complexity backend | Existing maximum-age code does not supply a complexity setter. Prove a narrowly owned policy mutation and unrelated-field preservation before implementation. Refuse domain controllers and distinguish local definition from effective managed policy |

**Start with E01.** It advances the accepted common presentation contract without
adding another system-mutation backend. E06-E08 are the strongest candidates for
the next new controls, but they have real file/API/recovery work and should not be
classified as simple registry edits.

The first concrete batch is `windows.hidden-files-visibility`,
`windows.protected-files-visibility`, `windows.explorer-recent-shortcuts`,
`windows.explorer-frequent-shortcuts`, `windows.control-panel-view` and
`application.edge-background-mode`. All six currently lack explicit presentation
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
controls within a row keep separate evidence and recovery boundaries. These 29
rows do not replace the 38-58 remaining-feature estimate.

| Row | Outcome and current state | Next work and edge cases | Classification |
| --- | --- | --- | --- |
| R01 | Existing-plan selection, owned creation and desktop Power plans access | Creation and shared guards now have two-target evidence. Keep Ultimate activation separate; earlier native activation failed. Inspect menu installation-path ownership and intended-user scope before deploying a reversible helper. Physical device/power-mode effects and template absence remain separate | Implemented core; menu and physical acceptance pending |
| R02 | Proxy detection, setup script and WinHTTP | E07. Query flags/URL for the selected connection; retain manual proxy and VPN/dial-up fields. Capture typed/structural prior state and explicit managed scope. A PAC test must use a controlled local server, not a publisher endpoint | Backend investigation, then implementation |
| R03 | Telemetry mirrors, Windows CEIP and conditional App-V CEIP | Windows CEIP typed lifecycle is done. Verify an actual App-V client, policy mapping and consumer before availability. Leave Native/Wow telemetry mirrors untouched and unexposed; do not infer effect from duplicate values | Conditional consumer evidence; D04 |
| R04 | Paired feedback frequency | Existing native guidance is available. Confirm current GUI choices, both value kinds and time units before exposing executable states. Preserve mixed/custom prior pairs and unrelated Rules values; exact paired restore needs partial-write evidence | Mapping investigation; D02 |
| R05 | Windows RE registration lifecycle | Read-only registration/OS/image/partition capture first. Existing readiness guide covers independent recovery. Prove restoring a prior registration association, not merely calling the opposite command. Refuse identity/servicing conflicts; no image or partition changes | High dependency recovery work; D06 |
| R06 | Browser service Hidden override | Accepted retirement is complete. Preserve legacy source and existing values. Network discovery guidance is implemented; peer/profile acceptance is separate | Retired selector; modern outcome partial |
| R07 | Retired MusNotification interception and supported update interruption control | Interception remains retired and untouched. Notification literal lifecycle/fault recovery and guidance are implemented. Validate visible warnings, active-hours combinations, deadlines and effective policy without promising no reboot | Consumer/restart acceptance; D03 |
| R08 | System protection | Native guidance exists. Prove enabled-volume inspection, system-drive coupling, storage allowance and asynchronous completion. Off may destroy history; restoring configuration cannot restore deleted points | Recovery/volume investigation; D06 |
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
| R29 | User .NET assemblies | No identified source outcome. Keep the existing provenance issue separate from NumLock's Forms load, strong-crypto policy and wallpaper conversion. Finding a duplicate or bookkeeping error needs an explicit evidenced disposition | Source question D09 |

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
| Adapter bindings, LLTD, NetBIOS, NCSI and network profile | Add explicit resource-selection design, paired flags, DHCP/static/VPN behavior, GUI refresh and peer evidence. Preserve GUID-bound restore and new-adapter exclusion; D04/D10 |
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
| D01 | For an explicitly requested alternate-administrator mixed-scope run, should RIDE offer a separate intended-user process handoff, or refuse user changes and require rerunning them as that user? | Prefer refusal plus clear separate-user instructions first. Do not target another HKCU implicitly. Existing fixed-scope IDs and recovery remain unchanged |
| D02 | Which visible GUI checks should we walk through first when you return: Explorer/icons, feedback/Storage Sense, or keyboard/input? | Prepare a short checklist for each; start with Explorer because several small remaining controls depend on observed mappings. Do not request screenshots while AFK |
| D03 | Which visible sign-in/reboot/shutdown outcomes should be prioritized when usable interactive test sessions are available: service boot behavior, UAC/sign-in, update prompts or Server logon/tracker? | Design separate fixtures and recovery routes. Existing unattended disposable testing remains authorized; postpone cases needing interactive credentials, elevation responses or unavailable recovery resources |
| D04 | Which pre-existing test resources can be provided: Office/App-V/Edge Update client, Server Core/Desktop Experience, usable audio endpoint, EFS-capable user, and two peers/adapters? | Use the existing Windows 11/Server 2025 settings targets where applicable. Mark unavailable components and physical/peer coverage deferred; packages stay paused |
| D05 | Can the earlier reliable NumLock setup's build/hardware/boot conditions or notes be identified, and is there a specific current Explorer/Desktop F1 behavior to suppress? | Preserve the historical result. Investigate the accepted native candidates without SendKeys, IFEO or a remapper. Return for a material design decision only if current evidence contradicts the accepted outcome |
| D06 | For later BitLocker/Windows RE acceptance, which disposable TPM/boot setup and off-device recovery destination can be used, and who will verify retrieval/unlock? | Continue staged design and native UI guidance. Defer encryption/decryption, failed-sign-in lockout and recovery-changing experiments needing keys, interactive secure input or independent boot recovery. Do not collect secrets in this document |
| D07 | If current menu evidence requires subtree removal and complete ACL/conflict-safe recovery cannot be proved, should that specific menu control remain unavailable or be considered for retirement? | Keep it unavailable. First test bounded binding suppression; do not use fixed CLSID reconstruction or weaken the recovery contract |
| D08 | Should direct playback mute initially require an explicit endpoint ID, or allow selecting a currently observed default endpoint and capture its ID at apply time? | Prefer explicit selection with a discoverable list, then restore exactly that endpoint. Device disappearance is an explicit failure; no fallback to a different endpoint |
| D09 | Can the original source or intent behind User .NET assemblies be identified, or may it be reconciled as an evidenced duplicate/bookkeeping correction once the bounded source audit is attached? | Preserve the unresolved outcome and estimates. Do not invent a deployment action from the label |
| D10 | Which adapter-selection experience should the later binding/NetBIOS work use: explicit adapter identities each time, or a reviewed named selection saved in local configuration? | Preserve existing all-visible compatibility scope and make it visible. Prefer explicit adapter identity for new controls; do not silently change stable IDs or follow new adapters during recovery |

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

This pass fully triages the remaining **settings** agenda. It does not authorize
resuming packages or claim a complete new inventory of every application and asset.
Keep the other four groups visible so prerequisites are assigned to their actual
owner instead of being counted twice as settings.

| Group | Current remaining range | Planning boundary |
| --- | ---: | --- |
| Windows and application settings | 38-58 | The 29 remainder rows and earlier accepted-control families above; implementation and acceptance tracked separately |
| Packages, portable tools and artifacts | 58-73 | Paused. Conditional settings tests use pre-existing consumers; no anonymous GitHub request, download, install or replacement package |
| Components and optional features | 20-25 | App-V/SMB1/IE-related consumers, RSAT, WSL/Hyper-V/Sandbox/OpenSSH and app management need their own component applicability and recovery; no automatic provisioning here |
| Accounts, configuration and assets | 25-35 | Alternate users, Wi-Fi, region/language, fonts/wallpapers, PATH/bin and application configuration belong here when they are deployed configuration. Browser/Sysmon and traditional Python association/ownership reviews remain separate from package installation |
| Maintenance and operational actions | 8-12 | Hostname, updates, cleanup, Sysprep and runtime/rule updates remain distinct actions. Preserve the yielded quota bridge and held controller/default-branch delivery work |
| Total rounded | 150-205 | About 180 for planning; no legacy feature closes from this analysis |

## Next handoff

The scheduled validation follow-up is paused after completion of the focused
matrix and this requested planning pass. The chat remains open. Pending migration
implementation and feature acceptance are still recorded below and in TODO.md;
the pause does not change the package hold or dispose of their evidence.

E01 is ready for a small implementation batch. E02-E03 can follow independently.
Prepare E04-E05 fixtures without repeating completed matrices. Investigate E06-E08
one at a time, keeping D01 and resource questions visible. Mapping-dependent R10-R17
remain unavailable until their actual feature evidence supports the backend.

When the user returns, begin with D01, D02 and D04; D06 precedes security/recovery
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
