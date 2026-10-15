# Remaining Windows and application settings: decisions and blockers

Reviewed: **2026-10-14**. This ledger complements the implementation and estimate
entries in [MIGRATION-PLAN.md](../MIGRATION-PLAN.md) and the behavioral acceptance
work in [settings-post-migration-review.md](settings-post-migration-review.md).
It is a follow-up agenda, not a declaration that the last setting is migrated.

For a concise resume point and durable validation notes, see the
[settings implementation handoff](settings-implementation-handoff.md).
The current disposable validation sequence and owned-export failure investigation
are recorded in [settings validation resume](settings-validation-resume.md).
The [remaining settings plan and questions](remaining-settings-plan.md) consolidates
all 30 remainder rows, earlier accepted-control families, the next implementation
batch and deferred interactive/resource decisions after the completed guard matrix.

## Decisions implemented in the two batches

Batch 1 adds 17 optional operations: 13 exact existing task identities and four
registry policies. Batch 2 adds 19: seven adapter binding operations (the LLTD
mapper/responder are one feature), two SMB protocol flags, Controlled Folder
Access, existing power-scheme selection, NCSI policy, NetBIOS, two Remote Desktop
controls, one coherent sound scheme and three current Edge policies.

No recommended profile selects these settings automatically. Explicit native
states are separate from saved-run restore; no universal platform default or
native baseline is invented. Registry WindowsDefault removes the override.
Task absence, unavailable power-scheme variants and missing device capabilities
remain separate from successful lifecycle evidence.

| Legacy outcome | Design decision | Remaining acceptance or omitted behavior |
| --- | --- | --- |
| Telemetry task bundle | Each identifiable existing task gets a schedule flag; no creation or execution | Task availability and payload vary by build. API references document enablement, not complete diagnostic-data suppression |
| Office task bundle | Keep exact Office task names and distinguish service monitoring from telemetry | Requires installed-version coverage; Click-to-Run monitoring is maintenance |
| Application impact and inventory | Retain exact documented AppCompat policies | CEIP/diagnostic policy dependencies and actual collection remain to be tested |
| Start most-used list | User accepted advanced policy presentation; a normal GUI preference remains deferred pending mapping | Earlier obsolete disposition is superseded; verify gray toggle/list, higher-precedence ShowOrHideMostUsedApps and launch tracking. Allowed does not force display |
| Ctrl+Alt+Delete sign-in | User accepted positive GUI naming and policy inversion; Required=0, NotRequired=1 for DisableCAD | Actual sign-in, credential-type/accessibility effects and managed-policy precedence; resolve differing official defaults. No implicit sign-out or target-support expansion |
| LLTD | User accepted one optional combined legacy action with both GUI components, distinct roles and mixed states visible | Verify current topology behavior and both-component completeness; a missing component is partial coverage. Independent role controls need useful current outcomes before introduction |
| Adapter protocol bindings | User accepted advanced GUI-mapped controls with explicit adapter selection as follow-up; preserve GUID/coupled-flag recovery and existing scope compatibility | Current all-visible scope must be explicit. Bounded recovery, missing bindings, collateral flags and connectivity require acceptance; new adapters stay untouched. IPv4/IPv6 disabling stays outside recommended profiles; physical/VPN/vendor-driver coverage remains |
| SMB server | User accepted separate advanced SMB1 server, combined SMB2/3 server and sharing-binding controls, plus Secure Windows file sharing / Stop hosting SMB shares guidance | Legacy enable leaves SMB1 unchanged. Absent srv/srv2 drivers stay unavailable; components/client state need independent inspection. Authentication, permissions, firewall, signing/encryption and peer/session evidence remain gaps before any complete security profile; preserve global versus adapter scope and exact recovery |
| NetBIOS | User accepted three GUI-aligned choices with adapter selection as follow-up; legacy EnableNetBIOS maps to DHCP/default=0, not explicit Enabled=1; Disabled=2 | Preserve SnapshotVersion 2 raw value/type/absence; earlier CIM-only recovery limitation remains. Verify DHCP/fallback, static-IP, GUID-key versus visible-adapter scope, GUI refresh and peer connectivity. Method/unattend references explain modes, not this registry mapping |
| NCSI | User accepted one advanced feature view with the policy as main control and existing local preference as compatibility detail; retain IDs and distinct reverse semantics | Exact local mapping now documented; verify policy/preference combinations, inverse CSP labels, effective probing and removal. No automatic two-value rewrite. Test status/application/proxy/VPN/captive-portal effects; keep suppression outside recommended security/performance profiles |
| Remote Desktop | User accepted individual GUI-related incoming permission and advanced local rule flags plus optional trusted-network guided setup; reconcile legacy wildcard and complete prerequisites | Hosting edition/admin/account requirements visible; NLA, authorized users and restrictive firewall scope remain gaps/manual prerequisites. Verify local/effective policy, actual authorized/rejected connections, GUI side effects, value removal and mixed-rule recovery. Server/RDS licensing and public exposure are separate scope |
| Controlled Folder Access | User accepted GUI-aligned On/Off with advanced Audit, plus optional protected-folder/app-compatibility/recovery guidance; retain literal mode recovery | Verify Active Defender/real-time readiness, standalone account and edition requirements, actual blocked/allowed writes, GUI mapping and mode enum/defaults. Folder/app list management and recovery remain separate gaps/manual prerequisites; no automatic allowances, exclusions, uploads or protection bypass. Server acceptance remains separate |
| Power scheme | Select existing Balanced and High Performance schemes by GUID; query exact GUIDs for inspection and saved-run restore rather than depending only on list visibility | Ultimate Performance's legacy GUID was queryable but activation failed in the VM; its selection/creation remains deferred. No creation/duplication or localized name parsing. Query failure stops writes; successful activation must also match the active GUID |
| Sound scheme | User accepted one GUI-aligned No Sounds / Windows Default choice coordinating selector and current events; startup sound and advanced editing policy stay separate | Preserve registered preset customizations; warn about nonempty .None mappings and avoid factory-reset/all-audio claims. Verify GUI refresh/playback, source gaps/types, mixed mappings, missing-event recovery and policy scope/reverse differences; retain stable states and exact saved configuration |
| Edge preload | User accepted two GUI-related controls with machine-wide mandatory policy scope explicit, plus optional Reduce Edge background activity disabling both; cross-cutting scope presentation remains follow-up | Current replacements differ from EdgeHTML and legacy override removal. Verify effective policy/locked GUI, defaults, standalone account/edition/management requirements and actual process behavior; no forced termination or update/WebView2 changes. Server availability remains separate |
| Edge desktop shortcut | User accepted separate advanced Create Microsoft Edge desktop shortcut during installation policy, preserving states and local-policy recovery | Requires applicable Edge Update version; verify channel precedence and disposable installation outcomes. No effect on already installed Edge or existing shortcuts; legacy update-suppression parity remains partial. Policy restore does not reverse installer-created artifacts |
| Cross-cutting scope and enforcement | User accepted consistent Applies to, preference/enforced/recommended behavior, GUI editability, privilege and effective policy presentation; preserve fixed scope per published ID and add alternate choices only where useful/supported | Source declarations are internally consistent in the dated scalar audit, but status/group displays and structured enforcement metadata have gaps. Audit official scope/precedence/requirements, add validation/display checks, and verify intended user identity under mixed-scope/elevated execution before declaring complete consistency |
| Windows Firewall profiles | User accepted modern Domain/Private/Public whole-device/admin controls, explicit On/advanced Off, plus optional enable-all composition; local PersistentStore configuration subject to managed policy, with no cloud subscription or domain join required to configure a profile. Earlier accepted StandardProfile legacy/deprecated disposition preserves its ID and compatibility/recovery access | Modern controls are new scope. Verify local versus effective ActiveStore state, active networks, StandardProfile key-existence precedence and mixed-state recovery; flag overrides without automatic cleanup. Setter NotConfigured is GPO-only, so no generic local WindowsDefault/reset or copying effective policy into local recovery. Capture all three before enable-all and report per-profile partial results; preserve rules/services/other fields and connect exposure guidance. GUI/connection, exact lifecycle and Server evidence remain pending |

The current Edge references are focused pages for
[startup boost](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/startupboostenabled),
[background mode](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/backgroundmodeenabled)
and [installation shortcuts](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies#createdesktopshortcutdefault).
The old browser-policy overview fragments no longer identify the individual
policies; these links were checked against the current page structure.

## Lifecycle evidence

Batch 1 VM run `60bfde39fdaf433fb12d03c0d69fae8e` passed 851 guest tests and
12 available operations across 28 named states, including preview, repeat apply
and exact saved-run restoration. Five identities were absent: Compatibility
Appraiser, ProgramDataUpdater, Office ClickToRun Service Monitor and the two
Office 2016 telemetry tasks. These remain unavailable and require representative
installed-build testing. Clean-checkpoint recovery passed; host UAC was unchanged.
This evidence does not close task payload, policy enforcement or UI acceptance.

The first batch 2 attempt, `9bef62def39c430f919728b5ae8a3fb4`, passed 857 guest
tests and nine live operation scenarios (all seven bindings, SMB2/3 and Controlled
Folder Access). SMB1 enablement failed because its service was absent; the captured
flag was unchanged and restored. Power-scheme list visibility changed after
selecting Balanced, and restoring the captured High Performance GUID failed the
list-based availability check. **That scheme was recovered only by checkpoint, not
by RIDE saved-run restore.** The scenario stopped there, so the later settings had
no runtime acceptance in this attempt. Collection and pinned-checkpoint cleanup
succeeded, and host UAC was unchanged. No pass is claimed for this attempt.

The corrections use a read-only `Win32_SystemDriver` identity check for SMB and
`powercfg /query <GUID>` for scheme availability. Microsoft identifies the protocol
drivers in its [SMB troubleshooting reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/smb-server-unresponsive)
and documents scheme querying in the [powercfg reference](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options).
Nine focused mocked tests pass on both native PowerShell versions.

The next attempt, `6a66423e3a6447168487bd607b363548`, passed 859 guest tests and
ten live operation scenarios, and correctly reported missing SMB1 as unavailable.
NetBIOS failed while requesting DHCP/default mode: the CIM method returned 100,
which Microsoft documents as DHCP not enabled on the adapter in its
[method reference](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration).
The original mode could not be recovered through that method. Checkpoint recovery
and evidence collection succeeded, with host UAC unchanged; RIDE exact NetBIOS
restore is not claimed for this attempt. Later scenarios, including the revised
power-scheme check, had not run.

The NetBIOS correction follows the actual legacy per-interface registry preference,
capturing GUID, value, kind and absence before writes. It avoids guessing a raw
value from a CIM-only snapshot. Earlier pre-publication CIM-only VM records retain
their checkpoint recovery boundary and are rejected by this typed restore path;
the operation ID remains stable. All identities are checked before writes and new
interface keys are untouched. Eighty-five focused lifecycle/recovery tests pass on
both native PowerShell versions.

The third attempt, `71a08b75572e4066af64b2f2f335e096`, passed all 860 guest
tests and 17 completed live operation lifecycles. It exercised 43 named states,
including two in the power scenario before that scenario failed. NetBIOS raw-value recovery,
Remote Desktop, sound and the three Edge policies passed. SMB1 remained
unavailable. Power-scheme activation emitted a native diagnostic which Windows
PowerShell 5.1 promoted to a terminating error before the wrapper could inspect
the exit code. This attempt failed integration acceptance, but exact saved-run
power recovery, evidence collection and pinned-checkpoint cleanup passed; host
UAC was unchanged. No complete batch pass is claimed.

The wrapper now captures both native streams with a local error preference,
preserves the native exit code and restores the caller's error preference. A
nonzero exit still fails. After a successful activation it also queries and
verifies the active GUID, so diagnostic handling cannot conceal a no-op. Eleven
isolated managed-setting tests pass on both native PowerShell versions, including
real child-process stderr/exit-code fixtures without Windows setting changes.
Queryability does not promise that a scheme is
activatable on every device or under every policy; such failures remain explicit.

The fourth attempt, `e52953bb09784998bc2e850ac9844068`, passed 862 guest tests,
17 complete setting lifecycles and 43 named-state checks (including Balanced
and High Performance before the power scenario failed). The native exit code
confirmed that Windows rejected the Ultimate Performance GUID with "Attempted
to write to unsupported setting". The wrapper correctly reported that failure;
RIDE recovered the original High Performance scheme exactly. Evidence collection,
checkpoint cleanup and unchanged host UAC passed. Full batch acceptance remains
failed for this attempt.

The pre-publication operation now exposes only Balanced and HighPerformance;
SetPowerSchemeUltimate is explicitly deferred with creation/ownership work.
Neither the stable operation ID nor typed saved-run GUID recovery changes.
This is a migration scope correction based on actual activation evidence, not
an assertion that queryability proves writability. The estimate stays unchanged
because the power creation/selection bundle was already counted as partial.
Final acceptance of the revised scope passed in run
`5b66779b3628494a814b061bc1ce07a9` (`SettingsRemainingBatch2`): all **862 guest
tests**, **18/19 available operation lifecycles** and **43 named states** passed
on Windows 11 Enterprise Evaluation build 26300, PowerShell 5.1.26100.9444 and
Pester 5.7.1. Apply preview, repeat apply, restore preview and exact saved-run
recovery passed, including Balanced/High Performance selection and recovery.
SMB1 was unavailable because its driver was absent; it remains unvalidated.
The controller collected evidence, restored the pinned clean checkpoint and
stopped the VM, with no collection/cleanup errors and unchanged host UAC
(EnableLUA=1, ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1).

Across the two batches, **30/36 operations and 71 named states** have lifecycle
evidence. The five absent task identities and SMB1 remain six resource gaps.
This does not establish feature/UI/restart acceptance. The 40-60 remaining
Windows/application outcome estimate and final-walkthrough milestone remain
unchanged. Native PowerShell 7 and 5.1 catalog/parser/generated-document checks
pass for 270 operations, two groups and four profiles; state completion passes
for all 36 new settings and resource search remains read-only.

Collected final batch 2 evidence:
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\5b66779b3628494a814b061bc1ce07a9`.
The earlier failed attempts remain in this ledger rather than being overwritten.

## Retired legacy controls for the current Windows 11 migration

Retirement here preserves historical source and existing published catalog IDs.
It means no new operation is added for the obsolete or unverified legacy implementation.

| Legacy selectors | Disposition and authoritative evidence |
| --- | --- |
| DisableWiFiSense / EnableWiFiSense | Retire the old suggested-hotspot control. Microsoft lists removal of the suggested-open-hotspot option in [removed Windows features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features) |
| DisableHomeGroups / EnableHomeGroups | Retire HomeGroup service switches for current Windows; HomeGroup was removed, while ordinary file/printer sharing remains. See [removed features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features) |
| DisableAdobeFlash / EnableAdobeFlash | Retire integrated Flash controls; Microsoft documents permanent removal in its [Flash lifecycle announcement](https://learn.microsoft.com/en-us/lifecycle/announcements/update-adobe-flash-support) |
| DisableIEFirstRun / EnableIEFirstRun | Retire IE desktop first-run configuration on the Windows 11 target; IE mode configuration is a different outcome. See [removed features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features) |
| DisableMapUpdates / EnableMapUpdates | Retire the default Maps-app update tweak from this migration; Microsoft lists Maps deprecation, Store removal and end of support in [deprecated features](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features). Maps platform APIs are separately deprecated, not claimed removed |
| ShowTaskManagerDetails / HideTaskManagerDetails | User accepted retirement of the legacy expanded/compact byte-28 tweak on 2026-10-11. Preserve historical source and leave presentation choices in Task Manager's GUI. The [22H2 redesign reference](https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-11-version-22h2#improvements-to-task-manager) documents UI evolution, not the private binary layout; no maintained catalog ID requires remapping. New current preferences need their own mapping/recovery evidence |

AllowBuildPreview is documented only through Windows 10 1703 in the
[System policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowbuildpreview).
Its obsolete value is omitted from the still-partial telemetry bundle.
NoGenTicket concerns activation/licensing and is not reproduced as privacy.
Defender Application Guard is absent starting with Windows 11 24H2 according to
[removed features](https://learn.microsoft.com/en-us/windows/whats-new/removed-features);
its optional-feature disposition belongs to the component backlog, not a second
settings count.

## Still awaiting implementation or a design decision

These items remain in the migration estimate. A registry round trip or an
existing partial operation does not close the omitted outcome. Several rows
represent multiple independently useful outcomes; the rounded settings estimate
is **38-58** in the current migration overview, not the number of table rows.

| Remaining outcome / selectors | Implementation status and remaining decision/evidence |
| --- | --- |
| Ultimate Performance selection/creation and desktop selection menu | User accepted separate existing-plan selection, explicit advanced machine/admin owned plan-copy creation and optional desktop Power plans access. Ultimate stays conditional: legacy GUID query succeeded but activation failed; duplication is a separate untested scenario, not an assumed fix. Identify by GUID, preserve existing stable states and separate Settings power mode, never silently create/fallback or match English names. Record new destination/ownership before creation, avoid repeat duplicates and delete only proven unchanged owned inactive plans after usable selection recovery. Prefer native Power Options menu handoff initially; direct quick-selection requires maintained capture/recovery workflow and stable installed path, with physical intended-user scope verified separately from machine plan actions. Current edition/hardware/license availability, GUI/activation, partial recovery, menu scope and Server evidence remain pending; bundle stays partial without estimate closure 2026-10-13: explicit owned creation is implemented as pending candidates; existing selection is unchanged. Export reproducibility and target acceptance remain open; desktop menu deployment stays deferred. |
| IE proxy autoconfiguration packed connection data | User accepted separate GUI detection and coherent setup-script/address controls through documented connection APIs, advanced WinHTTP configuration and optional discovery-off guidance with both scopes explicit. Preserve unrelated flags/manual/VPN settings and saved URL; retain existing scalar IDs as compatibility controls. Verify managed scope, refresh, connectivity, exact recovery and default-profile implications before implementation |
| Telemetry non-policy mirrors, CEIP and App-V CEIP | User accepted separate advanced machine/admin Windows CEIP and conditional installed/enabled-client App-V CEIP participation policies, matching actual Group Policy names and showing opposite Enabled wording. Opted out/in differ from Not configured and exact saved-state restore; legacy enable removed both policy overrides. Show OS/client edition/license requirements and managed precedence without RIDE membership/cloud-account requirements or automatic App-V enablement. Current App-V support policy now states server support through October 2029 and client/sequencer follow Windows; correct earlier retirement implication. Exact current client-policy/preference mapping and collection remain pending. Native/Wow6432Node AllowTelemetry copies remain deferred, unexposed and untouched until independent effect/GUI/precedence is established; no guessed labels, old 0/3 writes or default claims. Retain accepted diagnostic policy/guidance and compatibility dependencies; feature evidence, typed recovery and Server applicability remain open, telemetry bundle partial and estimates unchanged 2026-10-13: the Windows CEIP policy is implemented as a pending candidate with typed recovery. App-V consumer/mapping and non-policy mirror evidence remain deferred. |
| Feedback NumberOfSIUFInPeriod / PeriodInNanoSeconds | User accepted follow-up to accepted combined GUI-aligned preference: intended-user/no-admin scope, only current-build verified dropdown choices, no extra RIDE membership/cloud license requirement. Microsoft candidate mapping coordinates both values; DWORD/large-period inconsistency and units remain unresolved, so no guessed QWORD, truncation or executable payload. Distinguish explicit Automatically, two-value override removal and exact typed paired restore, including mixed/custom prior state. Capture pair before mutation and report partial recovery; preserve unrelated Rules values. Separate machine/admin request policy and tasks with managed precedence visible; no silent all-user enforcement or task/app changes. Interim native Settings guidance remains a user action, not captured apply success. Current GUI/types/units, feature evidence, partial recovery and Server applicability stay pending; bundle partial and estimates unchanged |
| Windows RE enable/disable in DisableRecoveryAndReset | User accepted follow-up to accepted separate Windows RE lifecycle: normal Enable and advanced Disable for known running-OS registration, machine/admin scope; Advanced startup Restart now is a separate entry action. No universal recovery/reset/security claim or extra RIDE subscription/account requirement; tools may need credentials, volume keys or networking. Require localized inspection, OS/boot identity, image/staged location and stable partition capture; unknown is not Disabled and repeat satisfied states do not cycle disable/enable. Preserve custom/OEM configuration, verify native results and stage partial recovery; opposite command alone is insufficient. Bound restore to verified native prior association/enablement, refuse servicing/image/partition identity conflicts and do not claim Exact without evidence. No image download/delete, partition/BCD-wide repair, forced reboot or protection suspension. Require independent recovery route before Disable and keep readiness guidance; nondestructive boot/encrypted recovery, lifecycle and Server/Core applicability remain deferred, outcome partial and estimates unchanged |
| Browser service Hidden override | User accepted retirement of paired selectors from maintained migration candidates; preserve historical source and pre-existing values, no published ID or automatic cleanup. Retain modern GUI Network discovery guidance separately, with actual profile/machine/admin scope, sharing/security boundaries and future backend/peer evidence; no equivalent Hidden migration or network-invisibility claim. One legacy outcome resolved by retirement; all five rounded estimate groups reviewed unchanged, recorded in the dated plan |
| Windows Update MusNotification debugger override | User accepted retirement of IFEO interception with separate supported outcomes: one advanced machine/admin Group Policy-aligned notification display feature (default, keep restart warnings, advanced hide including warnings, Not configured), coordinated gate/enum/active-hours checkbox and exact typed recovery. Verify payload and keep policy Disabled/default/removal distinct; show edition/build/managed precedence, no extra RIDE membership/Intune requirement for local policy. Preserve original restart intent through Reduce Windows Update interruptions guidance: active hours, explicit restart scheduling and deadline/grace inspection; native user Notify me when a restart is required remains separate. Notification suppression does not prevent restart; no universal no-reboot promise, AUOptions rewrite, obsolete policy import or Windows component interception. Existing debugger values remain untouched/conflicts reported; cleanup separate. GUI/notification/reboot/Server evidence and retained outcome remain partial and counted; no additional estimate reduction |
| System Restore enable/disable | User accepted GUI-aligned System protection with normal On, advanced potentially destructive Off and explicit affected-volume scope; Windows 11 only pending acceptance, no Server port. Verify read-only enabled-volume inspection, backend system-drive coupling, point deletion/retention, asynchronous completion and defaults. Preserve storage allowance; point creation is separate. Configuration recovery cannot recreate deleted history and must not be mislabeled Exact |
| Storage Sense bundle reverse | User accepted GUI-aligned current-user On/Off preserving cleanup choices; retire recursive preference deletion as disable behavior and omit the unverified notification marker. Keep published ID/state recovery; WindowsDefault is value removal, not a full reset. Verify 01 mapping, actual defaults, policy precedence and content effects. Additional GUI choices/guidance and distinct advanced machine enforcement remain future scope; registry restore cannot recover deleted files |
| F1 help TypeLib override | User approved retaining Windows-native Explorer/Desktop suppression for investigation, with the per-user two-value TypeLib method as an advanced experimental candidate. The supplied articles instead block HelpPane.exe or use AutoHotkey; neither verifies this GUID on current Windows 11. Require actual Help behavior, other-app F1 preservation, collateral consumers and typed prior-value/owned-key recovery; no recursive reverse, automatic file ACL/IFEO changes, package dependency or published ID remapping |
| Taskbar small-icon and Win+X shell selectors | User accepted separate current-GUI sizing and Windows Terminal default-profile controls, including the profile's broader effect beyond Win+X. Verify actual icon-sizing/height choices and gradual-rollout availability; no assumed TaskbarSmallIcons mapping. Old Win+X registry branches are not modern mappings; host selection stays distinct. Require installed-profile identity, intended-user context, visible Win+X/normal launch outcomes and bounded recovery preserving unrelated preferences; both outcomes remain pending |
| Shortcut-arrow icon resource index | User accepted optional advanced cosmetic Hide / Use Windows default control, retaining machine/admin scope and recommended visible arrows. Verify Shell Icons value 29, literal type/expansion, imageres resource and actual current Windows 11 rendering; behavior docs do not verify the mapping. Saved Restore must preserve custom prior type/data/existence and unrelated overlays; value removal is a separate default choice. No guessed DLL number, IsShortcut deletion, forced Explorer restart or automatic scope flip; keep Hide unavailable without evidence |
| NumLock startup and SendKeys | User accepted separate advanced sign-in-screen (machine/admin) and post-sign-in (intended user) startup preferences and removing the automatic keypress, subject to verified type/encoding and visible outcome. User recalls extensive early Windows 11 testing where the combined legacy solution was the only consistent approach they found; preserve this evidence and compare registry-only with combined behavior before claiming equivalence. .DEFAULT is the system profile, not the new-user template. Keep current-session observation separate; no implicit SendKeys, live enforcement, Fast Startup/firmware changes or other-user hive edits. Preserve prior type/data/existence and unrelated lock-key state. If the session action remains necessary for reliable behavior, return for a design decision rather than ship an ineffective replacement; implementation and acceptance remain pending |
| Explorer encrypted/compressed color preference | User accepted one normal current-user GUI control, Show encrypted or compressed NTFS files in color, with explicit On/Off and exact saved recovery. Verify the GUI's current type/state and ShowCompColor versus legacy ShowEncryptCompressedColor before choosing a backend; no dual-write fallback, automatic legacy cleanup or packed Shell-state preset. Presentation only; preserve file attributes, unrelated preferences and intended-user scope. Establish actual ordinary/compressed/EFS file-name rendering, refresh/default behavior and theme/edition coverage in disposable targets before implementation; no automatic Server support or estimate closure |
| Explorer Quick Access / Home HubMode | User accepted retaining normal current-user Open File Explorer to separately from an optional advanced experimental Hide Home navigation candidate, preserving legacy machine/admin scope pending actual multi-user evidence. Keep windows.explorer-start-location ID/state recovery; explicit Home differs from legacy LaunchTo removal. Verify HubMode's current surface/effect, startup interactions and typed prior-state recovery before availability; no implicit LaunchTo change, namespace deletion/reconstruction, ACL changes, pin/history reset or forced Explorer restart. GUI Home/This PC selection is partial coverage of the hiding outcome, not completion; keep omitted scope in the estimate |
| Include in Library, Give access to and Share context menus | User accepted three independent optional advanced menu-visibility controls, leaving Windows menu availability in recommended profiles. Presentation only; preserve libraries, shares, permissions and other sharing routes. Resolve HKCR merged roots/views and use explicit physical scope; proposed machine/admin implementation must expose per-user precedence, with no silent user-scope fallback. Verify classic/modern/command-bar effects and prefer bounded reversible binding suppression. If subtree removal is needed, capture typed contents/subkeys/ACLs and prove exact recovery; no fixed-CLSID reconstruction, global COM removal, forced ownership or broad tree reset. Multi-binding preflight, partial failures and restore conflicts need explicit handling. All outcomes remain pending implementation and feature acceptance |
| Five desktop icon ClassicStartMenu mirrors | User accepted five normal optional current-user controls matching Desktop Icon Settings, retaining published per-icon IDs and explicit Shown/Hidden/WindowsDefault semantics. Verify GUI/current rendering and independent/conflicting mirror states before adding or retiring omitted ClassicStartMenu writes. If needed, coordinate both values within one icon operation with captured typed prior state and partial-failure recovery; preserve old scalar saved records without inventing mirror history. Keep the all-icons switch and policy effects visible and separate; no implicit enabling, policy removal, file deletion or forced Explorer restart. Mirror disposition and feature acceptance remain pending |
| Server Manager and shutdown tracker | User accepted two separate advanced machine/admin policies aligned with Group Policy choices. Server Manager automatic startup is distinct from its console preference; suppression/explicit startup/default removal need verified precedence and logon behavior. Shutdown Event Tracker is one coordinated control for Disabled, Always, Server Only, Workstation Only and Windows default, preserving/restoring paired On/UI values and unrelated logging. Local ADMX evidence is not target acceptance. Windows Server 2025 media/VM remains unavailable; no new Server/client support, implicit policy refresh, task/feature changes or host shutdown testing. Implementation and actual target outcomes remain pending 2026-10-13: both focused policy controls are implemented as pending Server 2025 candidates. Tracker Disabled preserves the display choice; exact paired recovery is retained. Actual Server/Core/logon/prompt and managed precedence acceptance remain open. |
| Server password policy and IE Enhanced Security | User accepted independent advanced local-account complexity and maximum-age controls matching Local Security Policy, machine/admin with explicit scope and initial domain-controller refusal. Replace fixed-string 42-day presets with verified explicit values; preserve minimum-age and unrelated policies, distinguish local/effective sources, and prove focused recovery without full-export replay or password capture. No universal expiration baseline or generic deletion-as-default. User accepted retaining conditional Server IE ESC investigation with two GUI-aligned Administrators/Users On/Off controls, both machine/admin. Current Server Manager documentation still lists ESC despite standalone IE removal in Server 2025; verify actual component effect, GUID/class mapping, profile activation and derived-state recovery before availability. No Windows 11 control, automatic disable, broad historical script replay or claims of Edge/IE-mode equivalence. Server acceptance remains unavailable; implementation and feature acceptance remain pending, with no retirement or estimate closure accepted 2026-10-13: maximum age is implemented as a pending focused local SAM candidate with NoExpiry/Days1..Days999 and context-bound raw recovery; complexity and IE ESC remain deferred. |
| Windows Audio service and endpoint mute | User accepted separate advanced machine/admin Audiosrv control (Automatic/running or legacy Manual/stopped) and normal selected playback-device Mute/Unmute using native Core Audio. Manual is not Disabled; preflight/refuse undeclared dependency changes rather than force-stopping or silently configuring AudioEndpointBuilder. Capture service configuration/runtime and endpoint ID/prior mute separately; restore the original device, preserve volume, app/microphone/default-device state, and report missing endpoints without fallback. Endpoint control runs in the intended interactive user's context but affects a potentially shared endpoint; resolve metadata/execution scope and verify GUI roles, session boundaries, exclusive-mode limits and actual playback. No implicit service start, continuous enforcement or universal audio-silence claim. Implementation, feature acceptance and Server audio coverage remain pending 2026-10-13: the advanced Audiosrv service control is implemented as a pending candidate with dependency refusal and primary-only exact recovery. Endpoint mute remains deferred at the native endpoint/session and GUI-role mapping boundary. |
| BitLocker encryption/decryption and TPM+PIN enrollment | User accepted GUI-aligned guided machine/admin OS-volume setup connecting reviewed policy, TPM-only or TPM+startup PIN, recovery backup, encryption and real boot verification. Separate advanced Turn off BitLocker (decrypt) from suspend, PIN removal and ordinary restore. Preserve existing methods/protectors; no silent alternate-unlock removal, AES-CBC preset, used-space-only assumption, hardware-test skip, reboot, media ejection or plaintext/env-var PIN. Expose edition/admin/TPM and backend-specific account/license prerequisites. Require secure input/output redaction, nonsecret staged records, explicit protector ownership and compensating recovery; encrypted percentages and added PIN alone do not prove the complete outcome. Detailed recovery export/retrieval remains separate follow-up. Lifecycle implementation, actual feature acceptance and Server coverage remain pending |
| BitLocker recovery protector creation and password display | User accepted guided recovery area with normal Back up, advanced Create additional, and explicit selected-key Show. Select RecoveryPassword by type and ID, never array position; backup reuses existing protectors without implicit rotation/duplicates. Require an explicit off-device-accessible destination, native GUI/portal handoff where secure custom handling is unproven, nonsecret staged reports and output redaction; no recovery secret in routine status/state/logs, auto upload/clipboard/print or cleanup of existing protectors/backups. Expose distinct offline, Microsoft-account, AD DS and Entra prerequisites; future Graph secret retrieval needs consent/owner-or-role checks and audit, not local admin alone. Actual backup retrieval/unlock, failure recovery, secure presentation and Server acceptance remain pending |
| MaxDevicePasswordFailedAttempts lockout | User accepted optional advanced machine/admin Interactive logon: Machine account lockout threshold, with explicit zero or supported threshold and visible 1-3 effective-as-4 semantics. Intended local GUI/legacy registry mapping remains unverified; failed Windows sign-ins can cause reboot/BitLocker recovery, distinct from TPM startup-PIN retries, Hello or ordinary account lockout. No automatic ten-attempt preset or mobile-wipe label. Initial positive-threshold availability requires verified OS-volume protection and accessible 48-digit recovery backup; show managed precedence/restart/availability impact. Reconcile current versus archived non-BitLocker behavior in disposable targets; policy restore does not undo enacted lockout/protector transitions. Implementation, actual recovery/counting and Server evidence remain pending |
| Photo Viewer associations and Open with registration | User accepted separate advanced Make Windows Photo Viewer available in Open with and normal Choose default photo app through supported Windows UI. Prefer bounded intended-user HKCU registration, explicitly changing ambiguous legacy HKCR scope, without elevation or machine fallback; native component/current-build behavior remains unverified. Registration does not select defaults; no built-in ProgID hijack, UserChoice/hash bypass, IE reconstruction, DLL download or Photos removal. Capture owned registration changes and preserve existing entries; GUI default recovery is a separate verified user step, never protected-registry replay. Show component/managed restrictions without invented cloud/license prerequisites. Exact extension coverage, quoting, Open with/Default apps discovery, rendering, recovery and Server evidence remain pending |
| Media radio/WMDRM leftovers | User accepted separate conditional advanced Prevent Radio Station Preset Retrieval (user/no-admin) and Prevent Windows Media DRM Internet Access (machine/admin) investigations, excluded from normal/recommended selections until actual component effects are verified. Current CSP mappings and local ADMX exist; radio ADMX has pre-Vista applicability, and DRM deprecation does not prove universal Windows 11 removal. Correct blanket retired wording in later catalog follow-up. No all-traffic/PlayReady block or automatic DRM inclusion in metadata guide. Distinguish Blocked, explicit policy disabled and override removal; exact typed policy restore cannot revive servers/licenses. Expose component, edition/backend and managed-policy prerequisites; no automatic player installation or license-store changes. Current feature evidence and Server coverage remain pending; bundle stays partial without retirement or estimate closure 2026-10-13: both independent policy components are implemented as pending user/machine candidates; blanket retirement wording is corrected. Current consuming component/effective-policy and feature acceptance remain open. |
| Visual effects packed mask and mismatched KeyboardDelay type | User accepted full Keyboard repeat delay positions 0-3, retaining Shortest=0 and LegacyAppearance=1 compatibility and adding reviewed positions 2/3; earlier accepted individual GUI effects and separate timing controls remain in force. Fixed packed masks/whole presets stay deferred; no repeat-rate/Filter Keys changes or guaranteed intermediate timing. Catalog already uses String; prefer focused native API after proving effective-versus-stored state, persistence and exact recovery of legacy DWORD/String/absent/unexpected snapshots, with versioned compatibility for existing runs. No broad UI-effects master switch, silent backend change, forced restart or unrelated mask edits. Current-user/no-admin and active-session requirements; taskbar/Peek, mask mapping, GUI/runtime recovery and Server evidence remain pending; bundle stays partial 2026-10-13: stored keyboard positions 0-3 and typed compatible recovery are implemented. Native backend change, packed masks and current GUI/session acceptance remain deferred. |
| Delayed-auto-start overrides for WAP/Search | Implemented 2026-10-13 from the accepted design: AutomaticDelayedRunning and four startup-only choices on each stable existing service ID, reconciling legacy delayed enable while preserving AutomaticRunning's existing delay and Disabled's dormant flag. Earlier accepted GUI startup/runtime separation remains in force. One coordinated machine/admin SCM handler; startup-only choices do not request runtime actions. Capture literal/effective delay, startup and runtime; preserve snapshot compatibility and prove exact restoration despite SCM normalization. No raw registry catalog twin, reboot, fixed-delay guarantee, forced dependent stop, index repair or implicit enrollment/sync. Show Search and managed-device effects; actual GUI/SCM/boot/workload, partial-failure recovery and Server evidence remain pending; legacy coverage stays partial without estimate closure |
| Security icon startup remainder | User accepted guided Show the Windows Security icon outcome, with earlier accepted focused machine/admin tray-icon policy separate from intended-user Settings/Task Manager startup handoff and user-controlled refresh; no automatic historical Run-entry reconstruction. Verify exact startup entry, effective user/machine scope, managed precedence, component and actual icon appearance; GUI handoff is pending user action, not successful reversible apply. Preserve alerts/protection/services; no binary download, duplicate registration, process kill/launch or implicit repair. Any later direct startup backend needs separate exact recovery/ownership review. Implementation, feature evidence and Server support remain pending; omitted startup mutations stay explicit partial scope |
| User .NET assemblies (source identification pending) | Open provenance issue, not a known feature or proposed executable setting. No identified deployment/cache selector in legacy/v2, maintained modules/tools/components, local v1.337/v2.5.1 script/data files or the bounded all-ref identifier search. NumLock's System.Windows.Forms loads, machine strong-crypto policies and wallpaper bitmap conversion are separate outcomes. Possible bookkeeping error/duplicate remains unconfirmed. Preserve audit evidence for final walkthrough; does not block other identified work. Resolve by finding/assigning the real source outcome, linking a duplicate, or documenting an explicit agreed bookkeeping correction. No guessed mutation, migrated/retired claim or additional numeric component solely from this label; estimates unchanged |
| Store app removal policy and v2 uninstall | New evaluation requested 2026-10-14. [Joint review](store-app-removal-review.md) covers RemoveDefaultMicrosoftStorePackages and UninstallMsftBloat/UninstallThirdPartyBloat, including their incomplete re-registration reverses. Recommend distinct selected device-policy and intended-user uninstall workflows; provisioning, reinstall and app-data recovery remain separate. Exact PFNs, edition/servicing/schema, intended user, dependencies and sign-in effects require acceptance. This is an evaluated candidate rather than an implemented or approved removal list. Built-in app management remains counted under components; all five ranges unchanged; packages paused. |

English keyboard configuration, BitLocker desktop shortcut deployment, hosts
files, app removal, Windows components and optional-feature installation retain
their existing accounts/configuration, files/assets or component ownership.
They are not silently completed or counted again as setting operations.

## Implementation and acceptance queue

Design checkpoint: **2026-10-11**. All 28 identified entries in the preceding
remaining-settings table now have user accepted designs or retirement
dispositions. The 29th row, User .NET assemblies, remains an open provenance
issue. These table rows are not an exact count of remaining settings; several
contain multiple outcomes, and implemented settings have separate acceptance
work. This checkpoint does not mark the last setting migrated.

Use the following work order, applying the detailed accepted decisions in the
post-migration review rather than treating this summary as a new mapping source:

| Order | Work | Completion evidence / boundary |
| --- | --- | --- |
| 1 | Consistent scope, enforcement and prerequisites | Catalog-backed Applies to, preference/policy distinction, GUI editability, privilege, supported edition/build, account/license/hardware requirements and configured versus effective state. Preserve fixed scope and IDs; verify intended user under elevated mixed-scope execution |
| 2 | Focused implementation and saved recovery | Implement controls with established mappings; reconcile accepted coherent value sets, service startup/runtime/delay, concrete resource identities and reverse/default states. Version snapshots where required; preserve older recovery paths and unrelated data. Do not substitute a normal GUI state for an exact saved snapshot |
| 3 | Uncertain mappings before executable availability | Verify numbered suggestion channels, input personalization, feedback frequency kinds/units, packed visual effects, NumLock, F1, shell/menu/icon mappings and conditional CEIP/media components. Keep unverified mappings experimental/deferred rather than assign invented names or claim failed/absent behavior succeeded |
| 4 | Guided complete outcomes | Deliver reviewed promotions, diagnostics, security/sharing, recovery, BitLocker and update-interruption guidance from the catalog's actual controls. Explain order, dependencies, tradeoffs, manual steps and partial coverage; do not publish a runnable recommended profile before its prerequisites/components are verified |
| 5 | Disposable target acceptance | Separate mocked structure/lifecycle checks from GUI, sign-in, reboot, actual peer/security/workload behavior and managed precedence. Check Windows 11 and each declared Server target independently; retain unavailable resources and partial failures. Never use the developer workstation for state-changing acceptance |
| 6 | Final outstanding-issue walkthrough | Review all remaining semantic, recovery, target and provenance questions once the last-setting milestone is reached; retain unresolved User .NET assemblies until an evidenced disposition is agreed |

For each outcome, track design accepted, implementation delivered, lifecycle
evidence, feature/GUI evidence and target limitations independently. Accepted
retirement is a disposition, not a feature test. Browser visibility resolves one
legacy outcome; Windows Update interception is retired as an implementation
technique while its supported interruption-management replacement remains partial
and counted. All rounded migration estimates remain unchanged at this checkpoint.
Refresh them after every actual batch and record the outcome adjustment or why
rounded ranges stay unchanged. Do not repeat chat approvals for already accepted
designs unless new evidence requires a material design change.

## Service implementation increment, 2026-10-13

The accepted WAP Push/Search design is implemented on the two stable service IDs:
explicit `AutomaticDelayedRunning`, plus startup-only Automatic, Automatic
(Delayed Start), Manual and Disabled choices. Existing `AutomaticRunning` and
`Disabled` retain delay-preservation and combined runtime semantics. Completion
uses the same catalog states. State matching and display now distinguish SCM
delay, stored literal delay and preserved runtime. Version-2 snapshots retain
service identity, literal type/value/absence and the SCM flag; unversioned recovery
remains available. Failures identify stages and retain engine saved-run records.

See [service settings](../service-settings.md) for choices, native API references,
recovery boundaries and the acceptance checklist. This advances implementation,
not legacy-outcome closure: GUI/SCM normalization, boot, triggers/dependencies,
actual workloads and Server evidence remain open. No profile or target is added.
All five estimate ranges remain unchanged because these outcomes are still partial.

Final focused native mocked checks passed **38 per edition** on Windows PowerShell
5.1 and PowerShell 7; the preceding broader settings run passed **235**. Parser,
catalog/profile and generated-reference checks passed on both editions. Native API
compilation alone opens no service handles. The final suite covers exact typed
serialized recovery, Disabled-but-running recovery, startup-only runtime
preservation, preview/idempotence, failure records and public show/plan/status plus
catalog-derived completion. These checks do not establish real feature acceptance.

The user explicitly holds **all disposable VM tests until manual confirmation**
that testing may resume after the GitHub cache/backoff investigation. Local mocked
checks may proceed; this increment launches or schedules no VM tests. Do not infer
permission from cache freshness, quota reset or elapsed time.

## Keyboard range and service recovery follow-up, 2026-10-13

Keyboard repeat delay now declares all stored positions 0-3, retaining Shortest
and LegacyAppearance plus the stable ID, RegistryValue handler, override removal
and typed saved recovery. `Position2` and `Longest` add no guaranteed timing or
immediate-runtime claims. The [keyboard guide](../keyboard-repeat-delay.md)
identifies the existing stored-state boundary and the native effective-state,
persistence, user/session and versioned recovery work still deferred for VM
acceptance. Packed visual-effect presets remain deferred; no legacy outcome closes.

Service module 0.3.1 corrects the preceding key-existence capture mismatch. The
generic registry reader omits `KeyExisted`; service capture now records it
explicitly and refuses unavailable service keys. Older unversioned records missing
that field retain named-value recovery without inferring service-key absence or
deleting that key. New regression checks model the actual reader contract.

Local validation passed **51 focused mocked tests per edition** on Windows
PowerShell 5.1 and PowerShell 7.6.5; parser/catalog/profile/reference checks also
passed on both editions. Detailed scope is recorded in the dated migration-plan
entry. All five estimate
ranges remain unchanged, with both areas partial. No recommended profile or target
support is added. All disposable VM tests remain held until manual user
confirmation; this continuation starts or schedules none and leaves packages paused.

## Modern firewall implementation, 2026-10-13

Implemented the accepted modern design as three independent controls and one
captured enable-all composition. Only local Enabled in PersistentStore is changed;
ActiveStore state/source availability, active networks and legacy-key presence
remain separate inspection data. Complete preflight capture, drift/readback checks
and profile-stage failure reports preserve bounded mixed-state recovery. No local
NotConfigured/default/reset or automatic legacy cleanup is offered, and the
original StandardProfile recovery remains intact.

See [modern firewall profiles](../firewall-profiles.md) for IDs and boundaries.
New records are pending with empty SupportedTargets. The migration-plan entry
records local checks; GUI/connection/managed-policy and independent Server
acceptance remain open. No legacy outcome closes; all five estimates stay
unchanged. Packages stay paused. No VM test is started/scheduled while the
manual-confirmation hold is active.

## Update notification implementation, 2026-10-13

Implemented a pending three-value display-policy candidate from the accepted
design. Gate, enum and active-hours checkbox remain coordinated; explicit default,
disabled local gate and all-value override removal are distinct. Existing typed
value-set snapshots retain complete mixed/custom prior state. Read-only legacy
Debugger observations are separate from mutation and recovery. The minimum build
guard is 22621 and supported targets remain empty. Source evidence and gaps are
in the [notification guide](../update-notifications.md).

Effective organization policy/source inspection, GUI payload normalization,
notification/reboot behavior and independent Server applicability remain pending.
Native active-hours/restart/deadline guidance preserves the original interruption
intent without a no-reboot claim. No legacy outcome closes and all five ranges
stay unchanged. The migration-plan entry records local checks. No VM test, update
or live policy change occurs while manual confirmation is outstanding.

## Windows CEIP policy implementation, 2026-10-13

Implemented the accepted advanced Windows participation policy as a pending
scalar registry candidate: OptedOut=0, OptedIn=1 and WindowsDefault removal,
preserving the negative Group Policy wording and exact typed legacy recovery.
Local ICM.admx and the exact Microsoft reference confirm key/gate orientation;
the [CEIP guide](../ceip-policies.md) records source hash and current-consumer,
effective-policy/source and edition/Server gaps. No recommended profile, current
GUI label, collection guarantee or new supported target is asserted.

App-V CEIP remains separate pending relevant installed/enabled-client consumption
and precedence evidence; no client activation is performed. Undocumented native/
Wow6432Node telemetry mirrors remain deferred and untouched. The telemetry bundle
remains partial and all five estimates stay unchanged. Local evidence is in the
migration-plan entry. No VM tests start without manual user confirmation.

## Windows Security icon guide implementation, 2026-10-13

The accepted [guided startup workflow](../security-icon-startup.md) is delivered
with catalog presentation distinguishing machine/admin hiding policy from
intended-user startup, overflow, component readiness and user-controlled refresh.
Published states and exact policy-only recovery remain unchanged. Manual GUI
choices are not captured RIDE changes. No historical Run reconstruction, process/
service repair or protection mutation is introduced. Appearance/multi-user and
Server evidence remain pending, with all five estimates unchanged. Local
catalog/parser/reference checks are recorded in the migration plan; no VM test
is started/scheduled without manual user confirmation.

## Registry lifecycle reporting repair, 2026-10-13

Shared registry inspection now distinguishes real missing keys from denied or
unavailable inspection and captures key existence with raw value/type. Named-value
removal skips genuine absence; provider writes/removal and empty-key cleanup
propagate failures. Value sets and scalar saved records reuse authoritative key
capture, with earlier object/snapshot compatibility retained. This repairs
pre-change and partial-failure reporting for migrated controls without claiming
new GUI/provider/feature acceptance. Local evidence is in the dated migration-plan
entry; no live setting or VM test runs and all five estimate ranges stay unchanged.

## Walkthrough milestone

The requested final walkthrough starts after every retained current setting is
implemented or has an explicit accepted replacement/retirement. **That milestone
has not been reached.** The table above distinguishes blocked target coverage,
unfinished recovery design and undocumented behavior from already implemented
settings' acceptance work. When it is reached, walk through this ledger and the
post-migration review together, including suggestion channels, Cortana-derived
options, profile composition, missing resources, reboot/UI checks and all partial
legacy bundles. Do not treat a smaller estimate as closure of those decisions.

## Implementation started, 2026-10-11

The first increment of work item 1 is implemented: shared scope/behavior/GUI and
requirement presentation, explicit unknown/effective-policy gaps, scalar
scope/root validation and four initial reviewed catalog entries. Defender
Advanced-state requirements are now visible. IDs, states, handlers and saved-run
recovery are preserved. See [the presentation contract](../setting-presentation.md)
and the implementation entry in the post-migration review.

Tests were held until application migration and its tests completed. The first
increment then covered 149 passing unit checks on each native PowerShell edition,
including two targeted retries with workspace-local temporary fixtures. Parser,
catalog/profile and generated-reference validation also passed on both editions.
Intended-user enforcement under alternate administrators, effective policy/source
inspection and the remaining catalog audits are still pending. The other
implementation queue items remain open.
No additional legacy outcome is counted complete and the final walkthrough
milestone has not been reached.

## Owned power-plan implementation review, 2026-10-13

The accepted explicit machine/admin creation outcome now has pending Balanced,
High Performance and conditional Ultimate template-copy operations, separate
from existing-plan selection. Saved capture identifies the new GUID and owner
before duplication; intent and export-proven Ready ownership are distinct.
Only unchanged inactive finalized owned copies can be recovered automatically.
Incomplete creation, lost/mismatched ownership, active copies and changed exports
require review. Inspectors write nothing and do not claim configuration equality.
Existing selection states/recovery remain intact; no implicit activation, reset,
English-name matching, adoption or fallback is introduced. Native Power Options
handoff is guidance, not a deployed intended-user menu.

30 focused mocked checks passed on each native PowerShell edition; target
acceptance is still empty. Native export reproducibility (including hidden values
and name changes), hardware/edition/Ultimate availability, GUI and Server tests
remain pending. See [owned power-plan copies](../owned-power-plans.md). The bundle
remains partial, with no new legacy closure or estimate reduction. No live change,
package action or VM test occurs; manual VM confirmation remains required.

## Conditional media policy implementation review, 2026-10-13

Separate radio-preset and WMDRM online policies now use exact local ADMX
User/Machine scopes and DWORD 1/0 mappings, with explicit override removal matching
the legacy reverse. Saved restore retains literal prior type/data/absence.
Existing music-metadata retirement wording is corrected: the omitted components
remain conditional investigations with no blanket retirement accepted. No current
player/backend behavior is inferred from CSP delivery or local template presence;
radio's pre-Vista applicability and WMDRM/backend deprecation remain material
acceptance gaps. No player install, playback/license acquisition or license-store
changes occur; DRM is excluded from automatic metadata outcome guidance.

See [conditional media policies](../media-policies.md). Effective policy/source,
GUI/content consequences, intended-user execution and target/Server acceptance
remain open. Supported targets stay empty; the whole legacy bundle remains
partial and estimates unchanged. Local mocked results are recorded in the
migration plan. No disposable VM tests occur without manual user confirmation.

## Server Manager startup implementation review, 2026-10-13

The accepted advanced machine/admin policy now exposes suppression, explicit
policy-disabled startup and override removal, with exact typed prior-state
recovery. Local ServerManager.admx mapping is confirmed; console preference,
logon behavior and effective source remain distinct. No task/console/component
mutation occurs. Windows Server 2025 is a pending candidate with no supported
targets or recommended selection. Desktop/Core, current logon/precedence and
Server acceptance remain open. See [server policies](../server-policies.md).
The legacy outcome remains partial and estimates unchanged. Local mocked
results are recorded in the migration plan; no VM runs without manual confirmation.

## Shutdown Event Tracker implementation review, 2026-10-13

The accepted display policy is now one paired operation with Disabled, Always,
ServerOnly, WorkstationOnly and WindowsDefault. Reliability.admx confirms exact
1/2/3 display choices with gate 1/0. Disabled preserves any prior display type/data/
absence; enabled choices write display before gate. WindowsDefault removes both
explicit overrides and documents its difference from the narrower legacy reverse.
Exact saved recovery retains the entire typed pair; new KeepCurrent metadata is
validated before writes and rendered clearly. No shutdown/logging/timestamp/
reporting or forced refresh occurs. Generated managed-target tables now include
modern firewall profiles and owned-plan source identities.

See [server policies](../server-policies.md). Windows Server 2025 remains a pending
candidate; actual prompt routes, managed source/precedence, desktop/Core, client
applicability and exact/partial target recovery remain open. The outcome is partial
and all estimates stay unchanged. Local mocked evidence is recorded in the plan;
no package or disposable VM runs occur, and manual VM confirmation remains required.

## Windows Audio service implementation review, 2026-10-13

The accepted optional advanced Audiosrv control now exposes Automatic/running
and legacy Manual/stopped, with no Disabled substitution. Bounded related-service
and load-order group inspection preflights before configuration and rechecks before
runtime. Required services must already run, active dependents block stop, and
post-transition drift is reported. No Force or related-service write/recovery is
owned. The primary exact configuration/runtime plus SCM and typed literal delay
capture retains snapshot v2; dependency conflicts remain manual review rather
than invented recovery. Current-user playback-device mute remains a separate
pending native endpoint-ID/session implementation. No device, volume, microphone,
app or default-device setting is changed.

See [Windows Audio service](../audio-service.md). Normal apply stays blocked for
pending Windows 11/Server 2025 candidates. Actual render/capture, dependency/group,
trigger, GUI, session and Server feature acceptance remain open. The legacy bundle
stays partial and all five estimates unchanged. Local mocked results are recorded
in the plan; no live service/audio, package or VM changes occur. Manual user
confirmation remains required before disposable VM execution.

## Windows Update interruption guide implementation review, 2026-10-13

The accepted guided restart-interruption outcome now has concrete Windows 11
active-hours, schedule-restart, personal notification and managed deadline/grace
steps. It references current Microsoft documentation without GitHub quota use.
The guide does not silently apply a profile, change policies or capture manual
GUI actions. Existing machine display policy and old IFEO conflict observation
stay separate. Actual feature/GUI/reboot and Server evidence remain pending;
legacy coverage and all estimates remain partial/unchanged. See
[update guide](../update-notifications.md#reduce-windows-update-interruptions).
No package or disposable VM action occurs.

## Local maximum password age implementation review, 2026-10-13

The accepted independent Maximum password age control is implemented as a pending
local SAM candidate, using native field-specific level 1002 and exact raw-seconds
capture/recovery. Never expires and explicit Days1..Days999 are sourced from
bounded catalog range metadata; no universal 42-day or definition-removal baseline
is invented. Minimum age/unrelated modal fields remain untouched. Domain-controller,
unknown authority/role, context and stale-recovery conflicts are explicit. The
native reader reports applied SAM data; local GPO definitions and managed source
are not inferred. Existing IDs/states/snapshots keep their prior contracts.

54 selected mocked checks passed per native PowerShell edition; parser/catalog/
profile/reference checks passed (318/3/5, 121 PowerShell files). No native policy,
VM, package or anonymous GitHub action occurred. See
[local password policy](../local-password-policy.md). Complexity remains separate;
actual native/GUI, management/member/DC and Server expiry/recovery evidence remains
pending. The legacy bundle and all estimates remain partial/unchanged.

## BitLocker recovery handoff implementation review, 2026-10-13

The accepted guided recovery area now has concrete native backup and explicit-ID
retrieval instructions with volume/type selection and independently accessible
destinations. Only nonsecret IDs/types appear in optional inspection examples;
no example was executed and no key/account was accessed. Multiple or absent
protectors and unclear native GUI ID selection remain explicit pending steps.
Personal, Entra/work/school, AD DS, file/USB and print access requirements differ;
local admin is not cloud secret-read permission. Creation/custom display stays
advanced/deferred until secure output/ownership/partial recovery is proven.

See [BitLocker recovery handoff](../bitlocker-recovery.md). The guide records no
secret, creates no protector/profile and captures no manual GUI mutation. Actual
retrieval/unlock, backend mapping/permission, redaction and Server acceptance remain
pending. The whole outcome and estimates stay partial/unchanged; no package, VM or
anonymous GitHub action occurs.

## Windows recovery readiness implementation review, 2026-10-13

Implemented the accepted Windows recovery readiness and native Advanced startup
handoff in `docs/recovery-readiness.md`. Independent media/backup retrieval and
credentials/encrypted access are separate readiness stages; unknown status is
pending, not Disabled or verified. No native command or reboot was run. Entry,
registered-image enablement, BCD automatic recovery and reset remain distinct.
No universal recovery/security promise, destructive repair or forced-boot test
was introduced. OEM/association capture and native bounded recovery remain
deferred; boot, encrypted access, media, client GUI and Server/Core acceptance
remain open. No whole legacy outcome closed; all five rounded ranges unchanged.

## Network discovery handoff implementation review, 2026-10-13

Implemented `docs/network-discovery.md` for the accepted modern discovery handoff
following Computer Browser Hidden selector retirement. Explicit connection and
profile selection, machine/admin/managed scope and separate sharing permissions
are visible; no invisibility, broad firewall-rule, guest/Everyone, service-start
or SMB1 behavior is introduced. Existing Hidden values remain untouched.
Native peer, GUI, profile/multi-user and Server/Core evidence stays pending.
The existing retirement is not counted twice and no legacy outcome closes in
this prose-only batch. Focused references/whitespace reviewed; all five rounded
migration ranges remain unchanged. No system, VM, package or GitHub request.
Concurrent documentation/index changes are preserved; recovery readiness now
uses the recorded lowercase topic convention, with its inbound links updated.

## Storage Sense guidance implementation review, 2026-10-13

Implemented `docs/storage-sense.md` with intended-user native cleanup choices,
preserved unrelated preferences and separate immediate/content actions. Stable
ID, stored state and captured type/absence recovery remain unchanged. Value
removal is not recursive reset; restored configuration cannot recover deleted
files or automatically rehydrate cloud content. No new guessed channel, marker,
machine enforcement or executable profile was added. Current GUI/value/default,
managed/content and Server evidence remain pending, keeping the legacy outcome
partial and all five rounded ranges unchanged. Focused document checks passed;
no Windows state, content, VM, package or GitHub request was used.

## System protection guidance implementation review, 2026-10-13

Implemented native `docs/system-protection.md` guidance for explicit machine/admin
volume selection, normal On and advanced Off with visible potentially destructive
history effects. Storage allowance is preserved; point creation/application and
Delete stay separate. System-drive coupling requires verified whole affected
scope; no wildcard/script backend is introduced. Exact prior configuration does
not recreate deleted history. Traditional System Restore differs from current
point-in-time restore, including personal-file behavior. Enabled-volume/native
inspection, GUI/defaults, completion, coupling/history and recovery evidence
remain pending; accepted scope remains Windows 11, with no Server port. No
legacy outcome closes and all five rounded ranges stay unchanged. Focused prose
checks passed; no native action, VM, package or GitHub request was performed.

## Feedback frequency guidance implementation review, 2026-10-13

Implemented `docs/feedback-frequency.md`: normal intended-user Settings handoff,
only actually displayed choices, managed/unavailable control reporting and prior
label recording. This manual route does not capture mixed/custom registry state
or prove prompt suppression. Machine feedback-request policy, diagnostic-data
collection and task/app/service changes stay separate. Paired literal types,
large interval encoding/units, current-build dropdown mapping, typed partial
recovery and Server evidence remain deferred; no executable payload/profile is
invented. Existing policy ID/state recovery stays stable; the legacy outcome
remains partial and all five ranges unchanged. Focused prose checks passed with
no system, VM, package or anonymous GitHub request.

## Non-VM settings continuation review review, 2026-10-13

Non-VM continuation review: local maximum-age implementation and accepted native
handoffs were recorded separately from current feature/GUI/target acceptance.
Power Options native access was already present; clarified its canonical/full
Windows path, with desktop deployment and direct selection still deferred rather
than introducing an unowned shortcut/registry tree. Remaining mapping, native
recovery, history, secret and session boundaries are retained; no guessed states
or supported-target additions. No whole legacy closure, new retirement/exclusion
or count subtraction; all five ranges unchanged. Latest quota bridge Full result
remains failed, with inconsistent stale status/loop lines insufficient for idle
acceptance. This chat's conditional heartbeat stays active and has submitted no
VM work. Packages paused; no GitHub request, native settings action or external
account operation. Concurrent documentation/code preserved and guides indexed.

## Settings validation gate deferral at 08:49 UTC review, 2026-10-13

08:49 UTC read-only heartbeat deferral: dependency active/preparing another Full request; local latest acceptance remains quota-failed. Preflight quota or prior idle inspection does not satisfy verified VM acceptance plus explicit resource backoff/yield. Settings tests not submitted, packages paused, no GitHub/native change or dependency interference. All pending implementation/GUI/target evidence and all five migration ranges remain unchanged; no legacy closure/retirement/exclusion. Conditional follow-up stays active.

## Settings validation gate deferral at 09:04 UTC review, 2026-10-13

09:04 UTC validation deferral: compact dependency status and both local bridge records confirm active competing Full Windows 11 request 2ceab6f49e6d408d86f713fc5ba4b28b. Verified acceptance and explicit shared-resource yield remain absent; no settings VM submitted, no GitHub/package/native change or dependency interference. Pending GUI/native/target evidence retained; no legacy closure/retirement/exclusion and all five rounded ranges unchanged. Conditional heartbeat stays active.

## Settings validation gate deferral at 09:19 UTC review, 2026-10-13

09:19 UTC read-only gate deferral: dependency revision 5 and both local records still show active competing request 2ceab6f49e6d408d86f713fc5ba4b28b. No verified completion/yield; no settings VM or GitHub/package/native action. Pending acceptance, all five ranges and existing legacy partial outcomes unchanged. Heartbeat active, dependency untouched.

## Settings validation gate deferral at 09:34 UTC review, 2026-10-13

09:34 UTC gate deferral: dependency and local loop record one verified Full Windows11 acceptance, including evidence/recovery/UAC and reported idle. Dependency remains active and plans further consecutive target tests; explicit backoff/yield and independently verified idle/no competing work are absent. Settings VM gate remains closed. No settings outcome closes or target expands; all five ranges unchanged. No GitHub/package/native change or dependency interference; heartbeat remains active.

## Settings validation gate deferral at 09:49 UTC review, 2026-10-13

09:49 UTC read-only deferral: verified first Full Windows 11 pass retained, dependency active/preparing second Full submission. No current explicit yield or independently verified idle/no competing work; settings gate remains closed. Pending setting acceptance and all five ranges unchanged, no legacy closure/retirement/exclusion. No VM/GitHub/package/native change or dependency interference; heartbeat active.

## Settings validation gate deferral at 10:04 UTC review, 2026-10-13

10:04 UTC read-only deferral: compact thread status and both local bridge records confirm active second Full Windows 11 request dbfd74b1bfca4e0a91c4f6b088f2ee23. Prior verified result does not establish current completion or yield; gate closed. No VM/GitHub/package/native action or dependency interference. Pending settings evidence, legacy partial scope and all five ranges unchanged; conditional heartbeat active.

## Settings validation gate deferral at 10:19 UTC review, 2026-10-13

10:19 UTC read-only dependency revision 9 and both local records still show active second Full Windows 11 request dbfd74b1bfca4e0a91c4f6b088f2ee23. Integration result and cleanup remain pending; no explicit resource yield. Settings validation deferred, packages paused; all five ranges unchanged.

## Settings validation gate deferral at 10:34 UTC review, 2026-10-13

10:34 UTC gate review: dependency Windows 11 pair verified 2/2 with recovery/UAC and reported idle, backoff deadline10:44:07UTC honored. Two Server passes remain and next competing Full is scheduled12:47Copenhagen; no current independent idle/no-competing-work evidence or settings resource yield. Settings submission deferred; no target expansion or legacy closure. All five ranges unchanged; no GitHub/package/native change or dependency interference, heartbeat active.

## Settings validation gate deferral at 10:49 UTC review, 2026-10-13

10:49 UTC read-only gate deferral: Windows11 2/2 acceptance retained; relevant recent read reveals new dependency heartbeat preparing competing Server Full. Stale local prior-idle records do not prove current yield/no competing work. No settings VM or GitHub/package/native action, dependency untouched. Pending migration evidence and all five ranges unchanged, no legacy closure/retirement/exclusion; conditional heartbeat active.

## Settings validation gate deferral at 11:04 UTC review, 2026-10-13

11:04 UTC read-only dependency revision 12 and both local bridge records confirm active first Server 2025 Full request 9f3c92ba97da41d4b88de8c86e380ab4. Windows 11 pair remains verified; Server completion and resource yield remain absent. Settings validation deferred, packages paused; all five ranges unchanged.

## Settings validation gate deferral at 11:19 UTC review, 2026-10-13

11:19 UTC read-only snapshot and both local records verify first Server Full pass: Windows 11 2/2, Server 2025 1/2, evidence/recovery/UAC and reported idle. Settings remain deferred behind recorded 11:44:22 UTC backoff and final competing Server run at 13:47 Copenhagen. Packages paused; all five ranges unchanged.

## Settings validation gate deferral at 11:34 UTC review, 2026-10-13

11:34 UTC read-only dependency revision 13 is unchanged. Windows 11 2/2 and Server 1/2 passes remain verified; recorded backoff through 11:44:22 UTC and final competing Server run at 13:47 Copenhagen remain. Settings tests deferred, packages paused; all five ranges unchanged.

## Settings validation gate deferral at 11:49 UTC review, 2026-10-13

11:49 UTC read-only dependency revision 14 and both local bridge records confirm active second Server Full request 420c567aea0b44118862ecfcf1de35a5. Final result/recovery and resource yield are pending; prior Windows 11 2/2 and Server 1/2 retained. Settings validation deferred, packages paused; all five ranges unchanged.

## Settings validation gate deferral at 12:04 UTC review, 2026-10-13

12:04 UTC read-only dependency revision 15 and both local records still show active second Server Full request 420c567aea0b44118862ecfcf1de35a5. Final export/recovery and resource yield are pending. Settings validation deferred; packages paused; all five ranges unchanged.

## Settings validation gate deferral at 12:19 UTC review, 2026-10-13

12:19 UTC read-only review confirms bridge gate complete: Windows 11 2/2 and Server 2025 2/2, evidence/recovery/UAC, loop paused and resources explicitly yielded. A new separately authorized dependency turn now plans controller validation/refresh and VM acceptance. Settings remain deferred behind competing work; packages paused and all five ranges unchanged.

## Settings validation gate deferral at 12:34 UTC review, 2026-10-13

12:34 UTC read-only dependency revision 17 reports local controller checks passed and active preparation of protected controller 0.4.6 refresh/live acceptance. Bridge pair gate remains complete and paused, but competing controller work prevents settings submission. Packages paused; all five ranges unchanged.

## Settings validation gate deferral at 12:49 UTC review, 2026-10-13

12:49 UTC read-only dependency snapshot and release status confirm active Server UnitOnly acceptance request 20186578684e4716a1f633a99393fe9d on refreshed controller 0.4.6. Bridge gate remains complete/paused; current controller result/recovery and resource yield pending. Settings deferred, packages paused; all five ranges unchanged.

## Settings validation gate deferral at 13:04 UTC review, 2026-10-13

13:04 UTC read-only dependency revision 19 and release status still show pending Server controller 0.4.6 acceptance request 20186578684e4716a1f633a99393fe9d. Installation checks alone do not verify retained guest evidence/result format/checkpoint recovery. Settings deferred; packages paused; all five ranges unchanged.

## Settings validation gate deferral at 13:19 UTC review, 2026-10-13

13:19 UTC read-only review records Server controller 0.4.6 normal acceptance passed, followed by active Windows 11 UnitOnly request 3c0a98c38c5b42b5991f9a5f8f150e0d. Bridge pair gate remains complete/paused; shared resources remain occupied. Settings deferred, packages paused; all five ranges unchanged.

## Settings validation gate deferral at 13:34 UTC review, 2026-10-13

13:34 UTC read-only review records both controller 0.4.6 normal runs accepted, followed by active deliberate Server timeout request e9dbd5a238914edea6915bb6de7eeea7. Bounded evidence/recovery and resource yield remain pending. Settings deferred, packages paused; all five ranges unchanged.

## Settings validation gate deferral at 13:49 UTC review, 2026-10-13

13:49 UTC read-only review records normal/timeout controller 0.4.6 cases accepted. Active missing-checkpoint/expired-request probes now hold both worker locks, preventing settings use despite idle VMs. Final evidence/resource yield pending; packages paused; all five migration ranges unchanged.

## Focused settings fixture preparation review, 2026-10-13

Validation gate satisfied after completed bridge/controller checks and independent native idle/queue/lock/checkpoint/hash verification. Implemented request-bound single-setting fixtures without changing the protected controller or published SupportedTargets. WAP Push lifecycle is first; packages and broad suites stay paused. All five ranges unchanged pending actual evidence.

## WAP Push focused fixture baseline repair review, 2026-10-13

WAP Push first focused VM fixture passed seven named states/repeat apply and exact captured recovery, but overall validation failed at its baseline alias. Fixture 0.1.1 now applies the declared baseline directly; focused retry required. Evidence/checkpoint cleanup clean. Packages paused; all five ranges unchanged.

## WAP Push focused lifecycle validation review, 2026-10-13

WAP Push focused lifecycle passed on disposable Windows 11: seven states/repeat, startup-only runtime preservation, preview, declared baseline and exact typed/SCM recovery. All273 source hashes matched; evidence/checkpoint cleanup and independent both-VM idle verified. GUI/boot/workload/native-fault evidence remains partial; all five ranges unchanged, packages paused. Windows Search follows.

## Windows Search focused lifecycle validation review, 2026-10-13

Windows Search has Windows 11 lifecycle evidence for all seven states, repeat apply, baseline, preview and exact raw/effective service recovery. [Evidence](../archive/evidence/settings-search-lifecycle-2026-10-13.md). The startup-only variants preserved the running service, including DisabledStartup. Search/indexing user outcome, GUI/session and boot behavior, default/managed precedence and deliberate native failures remain pending. No Server applicability or support widening is inferred; no whole legacy outcome closes.

## Keyboard repeat delay Windows 11 lifecycle passed review, 2026-10-13

Request `2771dbd781814f6db578520e5796dd51` for `windows.keyboard-repeat-delay` on Windows 11: passed; 5 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-keyboard-repeat-delay-win11-2771dbd7-2026-10-13.md). Controller: ; cleanup: ; collection: ; guest: ; fixture: ; recovery: . GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Update-notification policy Windows 11 lifecycle passed review, 2026-10-13

Request `8ca9c85022ee40c8bda98b1850297c6e` for `windows.update-notification-display-policy` on Windows 11: passed; 7 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-update-notification-display-policy-win11-8ca9c850-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## CEIP policy controlled-failure attempt Windows 11 lifecycle failed or incomplete review, 2026-10-13

Request `85e70971f142431bac40fc8d250caf4d` for `windows.ceip-participation-policy` on Windows 11: failed or incomplete; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-ceip-participation-policy-win11-85e70971-2026-10-13.md). Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Controlled native-write interruption did not trigger.. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## CEIP policy Windows 11 lifecycle failed or incomplete review, 2026-10-13

Request `aa2bcd713bc74c1f8bdad36d134c7e92` for `windows.ceip-participation-policy` on Windows 11: failed or incomplete; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-ceip-participation-policy-win11-aa2bcd71-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## CEIP policy source-reconciled Windows 11 lifecycle passed review, 2026-10-13

Request `aa2bcd713bc74c1f8bdad36d134c7e92` for `windows.ceip-participation-policy` on Windows 11: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-ceip-participation-policy-win11-aa2bcd71-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Firewall enable-all seed-recovery attempt Windows 11 lifecycle failed or incomplete review, 2026-10-13

Request `ffca76b53da744bfbe200daaeaec271f` for `windows.firewall-all-profiles` on Windows 11: failed or incomplete; 1 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-all-profiles-win11-ffca76b5-2026-10-13.md). Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: The term 'Restore-RideFirewallProfileState' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Firewall enable-all Windows 11 lifecycle failed or incomplete review, 2026-10-13

Request `fd277d27cf694ad7a764005e804e37fd` for `windows.firewall-all-profiles` on Windows 11: failed or incomplete; 1 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-all-profiles-win11-fd277d27-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Firewall enable-all source-reconciled Windows 11 lifecycle passed review, 2026-10-13

Request `fd277d27cf694ad7a764005e804e37fd` for `windows.firewall-all-profiles` on Windows 11: passed; 1 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-all-profiles-win11-fd277d27-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Firewall enable-all Windows Server 2025 lifecycle passed review, 2026-10-13

Request `a9529e92f9a04790b96ef69e3c33701b` for `windows.firewall-all-profiles` on Windows Server 2025: passed; 1 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-all-profiles-winserver-2025-a9529e92-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Public firewall profile Windows 11 lifecycle passed review, 2026-10-13

Request `75c16478a8d04d66ad1a4614b49b7698` for `windows.firewall-public-profiles` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-public-profiles-win11-75c16478-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Public firewall profile Windows Server 2025 lifecycle passed review, 2026-10-13

Request `c3ab9d4cb70a46059f946983919c70ce` for `windows.firewall-public-profiles` on Windows Server 2025: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-public-profiles-winserver-2025-c3ab9d4c-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Domain firewall profile Windows 11 lifecycle passed review, 2026-10-13

Request `087701dce1ba484795bf59765e980074` for `windows.firewall-domain-profiles` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-domain-profiles-win11-087701dc-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Domain firewall profile Windows Server 2025 lifecycle passed review, 2026-10-13

Request `02e343a038694f88bb01294a24c18dcd` for `windows.firewall-domain-profiles` on Windows Server 2025: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-domain-profiles-winserver-2025-02e343a0-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Private firewall profile Windows 11 lifecycle passed review, 2026-10-13

Request `e7e35109260b46aa886b6eb540a6ad35` for `windows.firewall-private-profiles` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-private-profiles-win11-e7e35109-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Private firewall profile Windows Server 2025 lifecycle passed review, 2026-10-13

Request `7e3dea5bf4df48c485077c4df9e274c8` for `windows.firewall-private-profiles` on Windows Server 2025: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-firewall-private-profiles-winserver-2025-7e3dea5b-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced power plan Windows 11 lifecycle failed or incomplete review, 2026-10-13

Request `7a00278ac82a41ef9d47cd2a59186df2` for `windows.owned-balanced-power-plan` on Windows 11: failed or incomplete; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-win11-7a00278a-2026-10-13.md). Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Owned copy changed or native export is not reproducible; refusing deletion.. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned-plan export diagnostic implemented; VM submission deferred review, 2026-10-13

Implemented retained consecutive-export diagnostics in fixture 0.6.3; native PowerShell 5.1 and 7 parser checks passed. No product fingerprint/deletion guard, SupportedTargets or profiles changed. Approval review blocked VM submission twice before queueing; direct authorization is pending. Owned copy recovery remains failed/pending, with prior checkpoint cleanup evidence retained. No feature closure or estimate adjustment; packages paused.

## Owned Balanced export diagnostic Windows 11 lifecycle failed or incomplete review, 2026-10-13

Request `94297e8f3d5646308f11e786355584bf` for `windows.owned-balanced-power-plan` on Windows 11: failed or incomplete; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-win11-94297e8f-2026-10-13.md). Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Owned copy changed or native export is not reproducible; refusing deletion.. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Conditional radio policy Windows 11 lifecycle passed review, 2026-10-13

Request `9cbb0b2a72e94a9ea14900842e5faac3` for `windows.media-radio-preset-retrieval-policy` on Windows 11: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-media-radio-preset-retrieval-policy-win11-9cbb0b2a-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Conditional Windows Media DRM policy Windows 11 lifecycle passed review, 2026-10-13

Request `aca17a85e3ab46a1bf4664b93cd40c3e` for `windows.media-drm-online-access-policy` on Windows 11: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-media-drm-online-access-policy-win11-aca17a85-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Server Manager startup policy Windows Server 2025 lifecycle passed review, 2026-10-13

Request `cce2df896ad047a6b71d9df6aa4f8230` for `windows.server-manager-startup-policy` on Windows Server 2025: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-server-manager-startup-policy-winserver-2025-cce2df89-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Shutdown Event Tracker Windows Server 2025 lifecycle passed review, 2026-10-13

Request `2479f56603b1464598f23d47ab7a5363` for `windows.shutdown-event-tracker-policy` on Windows Server 2025: passed; 5 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-shutdown-event-tracker-policy-winserver-2025-2479f566-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Local SAM maximum password age Windows Server 2025 lifecycle failed or incomplete review, 2026-10-13

Request `acf7c02d919c40208548d1cdf93fa9b7` for `windows.local-password-maximum-age` on Windows Server 2025: failed or incomplete; 3 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-local-password-maximum-age-winserver-2025-acf7c02d-2026-10-13.md). Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: Local maximum age or related policy context changed; refusing stale recovery.. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Maximum-age fixture reverse recovery repaired review, 2026-10-13

Fixture 0.6.4 reverses maximum-age saved-run recovery order, preserving expected-post-write drift refusal. Server request acf7c02d919c40208548d1cdf93fa9b7 failed recovery with clean checkpoint/source-hash evidence; native retry pending. Both PowerShell editions passed 20 focused mocked tests. No product drift-guard relaxation or support widening. Packages paused; estimates unchanged.

## Local SAM maximum password age Windows Server 2025 lifecycle failed or incomplete review, 2026-10-13

Request `4486e991080b404f9cb60f5fb1b8ec10` for `windows.local-password-maximum-age` on Windows Server 2025: failed or incomplete; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-local-password-maximum-age-winserver-2025-4486e991-2026-10-13.md). Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: ; recovery: The term 'Set-RideLocalPasswordAgeState' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Maximum-age fault binding repaired after exact recovery review, 2026-10-13

Maximum-age exact reverse-chain recovery passed in request 4486e991080b404f9cb60f5fb1b8ec10, but controlled-fault lookup failed before injection. Fixture 0.6.5 resolves the direct engine-retained handler. Read-only binding and both parsers passed. Full retry remains pending; failed evidence retained, no target promotion or estimate closure.

## Local SAM maximum password age Windows Server 2025 lifecycle passed review, 2026-10-13

Request `9dd8005663cc4a5894c97b6ec04bb047` for `windows.local-password-maximum-age` on Windows Server 2025: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-local-password-maximum-age-winserver-2025-9dd80056-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Local SAM maximum password age Windows 11 lifecycle passed review, 2026-10-13

Request `95845a6e61344116bc5684aae0ec18b7` for `windows.local-password-maximum-age` on Windows 11: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-local-password-maximum-age-win11-95845a6e-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## WAP Push controlled startup recovery Windows 11 lifecycle passed review, 2026-10-13

Request `a7f221f3b078422690a7abd6b2623873` for `windows.wap-push-service` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-wap-push-service-win11-a7f221f3-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Search controlled startup recovery Windows 11 lifecycle passed review, 2026-10-13

Request `826e79723cf8457d8b0279e5fd355fd9` for `windows.search-indexing-service` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-search-indexing-service-win11-826e7972-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Keyboard delay controlled write recovery Windows 11 lifecycle passed review, 2026-10-13

Request `5195b4e734dc4d9ea37ad8a1dcdb79e5` for `windows.keyboard-repeat-delay` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-keyboard-repeat-delay-win11-5195b4e7-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Update notification controlled paired-write recovery Windows 11 lifecycle passed review, 2026-10-13

Request `5803c01cb50543a29982e8d6d9a9dc86` for `windows.update-notification-display-policy` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-update-notification-display-policy-win11-5803c01c-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Guarded Windows Audio service Windows Server 2025 lifecycle passed review, 2026-10-13

Request `7fe176404e774e75bee47b169b5e7094` for `windows.audio-service` on Windows Server 2025: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-audio-service-winserver-2025-7fe17640-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned logical-export comparison implemented review, 2026-10-13

Owned handler 0.2.0/LogicalExportV1 preserves stable logical exported data with bounded read-only application-hive access. Existing v1 raw-hash contract remains. Three retained exports compared equally; 29 mocked tests passed per native edition and catalog/docs/parser checks passed. Fixture 0.6.6 adds real owned-copy label drift refusal and seed recovery. Native retry, source-template availability, hidden-setting drift, partial-failure and actual feature/default/GUI acceptance remain pending. No target promotion, package work or whole-outcome closure; estimates unchanged.

## Guarded Windows Audio service Windows 11 lifecycle passed review, 2026-10-13

Request `3134e804661844108b9ed894cde274a2` for `windows.audio-service` on Windows 11: passed; 2 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-audio-service-win11-3134e804-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced logical-export recovery Windows Server 2025 lifecycle passed review, 2026-10-13

Request `365e4b4da29e4fcbb4762463f276ea35` for `windows.owned-balanced-power-plan` on Windows Server 2025: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-winserver-2025-365e4b4d-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced logical-export recovery Windows 11 lifecycle passed review, 2026-10-13

Request `cbb7a29d7111435da5b83cb7203f24b8` for `windows.owned-balanced-power-plan` on Windows 11: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-win11-cbb7a29d-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned High Performance logical-export recovery Windows Server 2025 lifecycle passed review, 2026-10-13

Request `6021fbd5f4254fc1932e6828ee35fdfc` for `windows.owned-high-performance-power-plan` on Windows Server 2025: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-high-performance-power-plan-winserver-2025-6021fbd5-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned High Performance logical-export recovery Windows 11 lifecycle passed review, 2026-10-13

Request `0e7add1b8e1c483fbab35f23a74f808c` for `windows.owned-high-performance-power-plan` on Windows 11: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-high-performance-power-plan-win11-0e7add1b-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Conditional owned Ultimate Performance Windows Server 2025 lifecycle passed review, 2026-10-13

Request `2cd90b3981df499c8f4b499dc9a87117` for `windows.owned-ultimate-performance-power-plan` on Windows Server 2025: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-ultimate-performance-power-plan-winserver-2025-2cd90b39-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Conditional owned Ultimate Performance Windows 11 lifecycle passed review, 2026-10-13

Request `38e4646949c7439ca9f74c1e45e0dc92` for `windows.owned-ultimate-performance-power-plan` on Windows 11: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-ultimate-performance-power-plan-win11-38e46469-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Explicit owned-plan guard fixtures implemented review, 2026-10-13

Implemented explicit owned guard modes in fixture 0.7.0 and compatible schema-2 data validation. Active selection has its own capture/recovery; deliberate setting drift and incomplete Intent retain the copy for checkpoint-only cleanup. Both native editions passed 18 pure data tests and parser checks. Native acceptance pending, published catalog targets/states unchanged, packages paused and estimates unchanged.

## Owned Balanced active-copy refusal Windows Server 2025 ActiveRefusal guard passed review, 2026-10-13

Request `4c1579dfc525486a9812979ca8b05a20` for `windows.owned-balanced-power-plan` on Windows Server 2025: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-winserver-2025-4c1579df-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced ActiveRefusal Windows 11 ActiveRefusal guard passed review, 2026-10-13

Request `76fbb477b11142288f90531093e6f833` for `windows.owned-balanced-power-plan` on Windows 11: passed; 1 states completed, lifecycle=True, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-win11-76fbb477-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced SettingDrift Windows Server 2025 SettingDrift guard passed review, 2026-10-13

Request `8889c7171a8f4a9ebac14a5e456c271b` for `windows.owned-balanced-power-plan` on Windows Server 2025: passed; 1 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-winserver-2025-8889c717-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced SettingDrift Windows 11 SettingDrift guard passed review, 2026-10-13

Request `75c3d9e2ece44fb9ad98a2a385cade8a` for `windows.owned-balanced-power-plan` on Windows 11: passed; 1 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-win11-75c3d9e2-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced InterruptedCreation Windows Server 2025 InterruptedCreation guard failed or incomplete review, 2026-10-13

Request `77ef1aa1c89240ddbb7d70e9dc4045f7` for `windows.owned-balanced-power-plan` on Windows Server 2025: failed or incomplete; 0 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-winserver-2025-77ef1aa1-2026-10-13.md). Controller: Test controller exited with code 1. See controller-errors.log.; cleanup: ; collection: ; guest: Settings fixture failed with exit code 1; inspect settings-fixture.json.; fixture: Interrupted creation did not retain the exact captured inactive Intent copy.; recovery: . GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Interrupted ownership capture fixture repaired review, 2026-10-13

The failed assertion compared preliminary absent inspection random proposals rather than the actual captured creation contract. Retained saved snapshot and version-2 Intent have identical destination/token identities. Fixture 0.7.1 verifies the saved run correlation and retains observed Intent. No ownership guard was relaxed; no interrupted-copy deletion or compensation is claimed. Both targets require retry.

## Owned Balanced InterruptedCreation Windows Server 2025 InterruptedCreation guard passed review, 2026-10-13

Request `bf89d6e09ab8448e8e5a2e3cf3312bc3` for `windows.owned-balanced-power-plan` on Windows Server 2025: passed; 0 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-winserver-2025-bf89d6e0-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Owned Balanced InterruptedCreation Windows 11 InterruptedCreation guard passed review, 2026-10-13

Request `6573f64481da4770b783f33e6d7a04ad` for `windows.owned-balanced-power-plan` on Windows 11: passed; 0 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-owned-balanced-power-plan-win11-6573f644-2026-10-13.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Remaining settings analysis and decision plan complete review, 2026-10-13

All three owned refusal modes passed both targets; retained structured records distinguish active selection recovery/compensation from checkpoint-only drift/Intent cleanup. The failed interruption fixture remains archived; corrected creation capture passed. Fixture 0.7.2 fixes only progress wording and has parser evidence. [Full settings analysis and numbered questions](remaining-settings-plan.md) retains every current remainder row, earlier accepted families and independent work. Published targets, profiles, package pause and all five ranges remain unchanged.

## Store app removal policy and v2 evaluation review, 2026-10-14

Reviewed RemoveDefaultMicrosoftStorePackages together with UninstallMsftBloat/InstallMsftBloat and UninstallThirdPartyBloat/InstallThirdPartyBloat. [Joint review](store-app-removal-review.md) separates sustained device policy, direct intended-user removal, provisioning and later reinstall. Snapshotting/restoring policy does not recover removed apps or local app data. Static/dynamic capability, standalone local policy and current PFNs need acceptance; no new support declaration or executable bulk preset. Components own the already-counted app lifecycle; the settings plan links R30/D11. All five ranges unchanged; packages paused; no Windows state or VM change.

## Six control presentation batch implemented review, 2026-10-14

First six-control presentation batch implemented with unchanged values, scopes, targets, defaults and recovery. [Evidence](../archive/evidence/settings-presentation-batch1-2026-10-14.md) retains completed checks and sandbox deferrals. Explicit presentation coverage is now 28/277 controls. D01 is answered: separate intended-user process handoff, initially current desktop session only. No runtime handoff or mixed-scope recovery is claimed yet; the next matching batch must bind user/session, preserve user-owned state and report partial execution.

## Explicit desktop-user handoff implemented with native acceptance deferred review, 2026-10-14

D01 explicit same-session user-only handoff implemented; [guide](../intended-user-handoff.md) and [dated evidence](../archive/evidence/intended-user-handoff-batch1-2026-10-14.md) retain 65 mocked tests on each native PowerShell edition and pending native GUI/session/alternate-admin acceptance. Mixed-profile ordering and interrupted cross-store recovery are deferred. VM readiness currently denied CIM access, no submission; elevated work postponed per user instruction. E01 PowerShell 5.1 runtime deferral resolved with 122 passing tests and validation. D11 answered: both device removal policy and one-time intended-user uninstall, explicitly separate, with old app lists reconciled against current identities; removal choices still require an explicit selection. No whole legacy closure or supported-target widening; all five ranges unchanged; packages paused.

## Store app inventory and list reconciliation implemented review, 2026-10-14

D11 workflow selection answered: both separate device policy and one-time intended-user uninstall, with evolving app-list reconciliation. [Full matrix](store-app-list-reconciliation.md) and [read-only tools](../store-app-inventory.md) retain119 names, all106 historical removal queries and102 registration entries, four reverse gaps,25 local template mappings and unfamiliar current apps. Sixteen tests passed on each native edition; validation passed137files. Exact PFN matches are review evidence, not removal approval. No executable uninstall/policy control or live Appx collection; concrete app selections, policy schema/servicing, dynamic-list identity and reinstall/data limitations remain pending. Current native readiness denied CIM access, no VM submission/elevation. Mixed-profile user handoff and GUI/session acceptance remain independent. Components own app lifecycle; no new legacy closure; all five ranges unchanged; packages paused.

## Store inventory context implemented and native collection refused review, 2026-10-14

D11 now explicitly keeps all apps until current-user inventories are collected. Preserve Windows 10 historical queries and require edition/release/provenance evidence before retirement; no initial removal set approved. [Collection and retirement plan](store-app-inventory-plan.md) separates actual-user registrations, image provisioning, serviced policy capability and lifecycle notices. Collector0.1.1 retains edition/build context; 20 review tests and78 combined tests passed per native edition. [Native refusal](../archive/evidence/store-app-inventory-refusal-2026-10-14.md): request3dfba9fd4b6f4e61bf24de7e8613777e refused before VM use because host WinRM is stopped;342-file preflight snapshot, no worker seal/guest result. Current idle/pin/hash checks pass outside sandbox without UAC; host service preparation postponed per user instruction. No inventory, app retirement/selection/removal, package acquisition or native lifecycle claim. Installed controller/support targets remain unchanged. All five ranges unchanged; no whole legacy closure; native desktop handoff/mixed recovery remain separate.

## Modern Store app scope accepted and reference collection prepared review, 2026-10-14

D11 accepted modern v3 scope and representative October2026 references, with both explicit removal workflows still pending. [Archive](../archive/migrations/store-app-v2-historical-coverage-2026-10-14.md) preserves all v2 lists and priorcrosswalk; no historical-only entry is an active per-app implementation requirement. Default comparison covers25 template candidates plus observed unknown apps; optional history remains unselected. Separate online provisioning collector and schema4 reference fixture preserve raw identities/scopes and partial failure. 85 focused tests pass on each native edition; validator passes138files. All apps kept until inventories have been reviewed; native collection remains pending existing host WinRM prerequisite. No new VM, state/elevation or acquisition action. Blanket bulk remove/register replay retired as requirements, not individual app retirement or accepted replacement. No whole legacy outcome closed; all five ranges unchanged; packages paused.

## Store reference collection awaiting approved host prerequisite review, 2026-10-14

Current proceed request reached the host prerequisite: both controllers idle/pins/hashes unchanged, but host WinRM stopped and current token unelevated. A bounded service-only start action is prepared and user UAC authorization is pending due to the earlier elevation-postponement instruction. No service/startup/configuration/UAC/VM action performed. Both schema4 reference selections are identity-validated; collection remains pending. No app selections or native evidence; all apps kept until inventory review, packages paused and all five ranges unchanged.

## Windows 11 Store reference collection review, 2026-10-14

Run cdfee696816b4ce480cfce9371832b98 accepted read-only collection, not app-removal or policy acceptance. Guest Windows PowerShell 5.1 passed 155 focused Pester tests, zero failed; one registry WindowsIntegration test intentionally excluded. The configured reference user and online image provisioning have separate JSON/provenance/hashes. Raw registry ProductName reports Windows 10 Enterprise Evaluation while guest CIM reports Windows 11; edition/build are retained without rewriting observations. No fresh baseline, interactive desktop handoff or other edition/user coverage is claimed. No legacy outcome resolved, retired or excluded in this run; selected-app implementation, policy applicability, intended-user session behavior, protection/dependencies and recovery remain deferred or partial. All five ranges and rounded total stay unchanged because inventory evidence closes no removal lifecycle. See [dated collection evidence](../archive/evidence/store-app-reference-collection-2026-10-14.md).

## Server Store reference collection and grouped review review, 2026-10-14

Server run c1a950c3c611407d845efdf31aea1fb8 passed read-only StoreReferenceInventory with 57 current-user and five online provisioning rows. All 348 current-source snapshot hashes match actual bytes and preflight; the extra file versus Windows 11 is its dated evidence report. Guest validation/Pester/native collection and checkpoint cleanup passed with no error; both controllers idle and unchanged. Separate user and image scopes, account/SID provenance and hashes verified. The [dated evidence](../archive/evidence/store-app-reference-collection-2026-10-14.md) and [grouped review](store-app-inventory-review.md) retain both captures. The review has 110 names including 25 template candidates, all Keep/unapproved. IsPartOfSystem is unavailable on every captured registration and remains null. Actual app protection/dependencies, user choices, interactive desktop handoff, policy capability/sign-in effects and removal/data/reinstall recovery remain partial or deferred. No whole legacy feature resolved, retired or excluded; no support target expanded. All five ranges and total stay unchanged because native collection is not app lifecycle acceptance. Packages paused; no app change, acquisition or GitHub request. Earlier WinRM refusal retained as history; directly authorized host start completed with Manual startup unchanged.

## Store app groups and workflow decisions review, 2026-10-14

The [accepted group contract](../store-app-groups.md) records the user choices and follow-up adding Media Player/Sound Recorder to multimedia. User uninstall/reinstall compositions and device policy share reviewed identities, with links both ways; they retain distinct actions, scope and recovery. Gaming frameworks/protected/shared components require guard/consumer review, not automatic removal; XboxGamingOverlay policy capability stays pending. Actual install-state selection, intended-user handoff, protection/source proof, partial failure and reinstall/data limits remain implementation/acceptance work. Acquisition-dependent reinstall stays deferred while packages are paused. No whole legacy outcome resolved or retired; codecs/extensions/legacy media and unlisted apps remain excluded from these group compositions, without declaring them globally retired. All five estimate ranges remain unchanged because this is an accepted design, not executable lifecycle acceptance. No app, policy, package, VM or host service action occurred. See [dated decisions](../archive/evidence/store-app-group-decisions-2026-10-14.md).

## Store consumer batch 1 candidate implementation review, 2026-10-14

StoreApps 0.1.0 and Invoke-RideStoreApps 0.1.0 implement the first accepted group as pending candidates, with four stable app IDs, exact family metadata, an ordered group and user-owned schema-1 Store records. Uninstall reverses order; retained-manifest registration uses owned removal intent/failed/completed records, original source/identity/hash and existing dependencies. No exact app-data/version recovery or automatic downloads/policy changes. Store rows have their own discovery view; profiles and generic package commands refuse routing. Parser/catalog/profile/generated docs validation passed on both native editions: 322 operations, four groups, five profiles, 141 PowerShell files. Initial regression failures exposed a completion path lookup, test module scoping/isolation and catalog test assumptions; corrected and verified, with no Windows mutation. Fixture data 0.7.0/schema 5 and native fixture 0.9.0 prepare StoreAppPreflight; this cannot open target support or accept uninstall/reinstall. No legacy outcome resolved/retired; later groups, protection/full-payload proof, actual user desktop/handoff, app lifecycle/partial native failures, managed policy and acquisition-dependent recovery remain partial/deferred. All five ranges unchanged because implementation is not acceptance. See [batch evidence](../archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Store batch 2A candidate implementation review, 2026-10-14

Accepted group 2A is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](../store-app-groups.md).

## Store batch 2B candidate implementation review, 2026-10-14

Accepted group 2B is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](../store-app-groups.md).

## Store batch 2C candidate implementation review, 2026-10-14

Accepted group 2C is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](../store-app-groups.md).

## Store batch 3 candidate implementation review, 2026-10-14

Accepted group 3 is now declared in the authoritative catalog and exposed by read-only discovery/completion and the guarded tool. Exact families matched the saved current-user reference; per-app type/source/session/policy and consumer guards remain required. Dependency inspection never deletes shared frameworks or protected Xbox Game Callable UI. Game Bar has no invented static policy ID; its separate policy capability stays pending. No whole legacy outcome resolved, retired or excluded; actual app-specific native removal/reinstall and source/desktop/protection acceptance remain partial/deferred. Rounded ranges stay unchanged because these are pending candidates sharing the tested backend, not accepted lifecycle outcomes. See [group guide](../store-app-groups.md).

## Store guard acceptance and native evidence follow-up review, 2026-10-14

The initial Windows 11 source manifest FA33C7269DEBB6794FD9F6251EBAF1D1248665E9776C927B28843318526FA087 and fixture 56525BF13808F033A09E113B82BB7871D6F0CC377C2AC3E980C97E00CC2DD7D8 are retained with guard-only acceptance. Native evidence shows no desktop, incomplete protection/type, generic enrollment uncertainty and unavailable retained source; no uninstall/reinstall or GUI/management acceptance. The follow-up enriches observation without relaxing unknown system guards. Store certificate category does not establish system protection. The documented MDM API is client-only; Server remains conservative. All 22 app/group declarations match accepted scope and exact captured families, with no shared framework/protected Xbox membership. Native getter changes justify a new current-source diagnostic rather than presenting the older source result as their acceptance. No legacy outcome resolved/retired; actual protection model, intended-user Store handoff, desktop and app/partial-failure/recovery acceptance remain partial or deferred. All five ranges unchanged because guards are not app lifecycle acceptance. See [batch evidence](../archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Store SDK inspection accepted and desktop handoff implemented review, 2026-10-14

Run b581ad67f44b4a87a5fb3a7307f96d6c used current Local source including uncommitted declarations, module 0.1.2, fixture 3315E13A06A116EE3ED017C265B1282F24735ADE1301A9B5FC3F43A5ED26DA4D and source manifest CB1E1CDD6EE00787C3238A0BBE012EB9064F7BCFAF7533F170B394658A9B146E. SDK identity/type observations and client management query worked; missing system-protection flags remain null, not inferred from Store certificates. All actions refused with no Store records. Current desktop unavailable in unattended WinRM; published support remains empty. The later source handoff is covered by mocked tests, not this earlier native snapshot; Server validation follows with current source. Native uninstall/reinstall, partial failure, GUI/session, effective management, source survival and later app-specific acceptance remain deferred/partial. No legacy outcome resolved or retired; all five ranges unchanged because guard/API inspection is not lifecycle acceptance. [Follow-up decisions](store-app-follow-up-decisions.md) records protection and stub/source choices; [batch evidence](../archive/evidence/store-consumer-apps-batch1-2026-10-14.md) retains hashes and limits.

## Server Store guard and absence preflight accepted review, 2026-10-14

Run 8de2401ea49c49cfb82b47a1073d1904 completed at 2026-10-14T11:01:04Z using current Local source with uncommitted changes, fixture DAAC889E55A866227F199117DE12B8DB0DC6B2F4782332357B6FEE5E9243BF83 and source manifest 8635BDED9CC26EDB31CC46232655FF339F78E04E8E6284976E84CF76E260AA67. Native absence, target refusal and no-record/no-mutation behavior passed. Unknown Server enrollment source and unavailable WinRM desktop remain explicit refusals. Both VMs Off/tasks Ready, empty queues, available locks, pins/installed hashes/clean CI verified unchanged at 11:03:19Z. This earlier snapshot excludes the newly approved ReviewedIdentityRemovabilityV1 rule. No legacy outcome resolved, retired or excluded; native lifecycle, partial failure, retained-payload, interactive user and policy consumer acceptance remain deferred/partial. All five ranges and rounded total unchanged because absence/refusal evidence closes no app lifecycle. See [Store follow-up tasks](store-app-follow-up-decisions.md) and [dated evidence](../archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Reviewed Store protection and source decisions implemented review, 2026-10-14

The user approved ReviewedIdentityRemovabilityV1 for the 22 reviewed catalog identities: known NonRemovable=false, complete runtime-verified type/stub evidence and exact identity/family/source/consumer checks, while IsPartOfSystem remains null/Unknown. Known system/protected flags still refuse. The user also chose to wait for usable local reinstall source; stub News/Weather remain blocked and acquisition stays paused. Run 0341ac971c5a4c8ba7a12b15bd51b68e finished 2026-10-14T11:18:23Z on Local source including uncommitted changes, StoreApps 0.3.0/fixture 0.9.1, fixture hash 07FDE2B4B692DEE5E18496D911E97DE5ABF998382509DA8DF60F992DEC4F663C and source manifest FE2399CC69E9D2F8B5843010E29ADF645580F13662FC3C6D64F3FD0CB176A2AF. All 11 registration rows have verified runtime types and explicit Unknown system observations. Clipchamp/Solitaire only retain desktop/target refusals; News/Weather also retain stub/source refusals. All four actions refused without records or mutations; source bytes, identity/XML/checkpoint and final idle/pins/installed hashes/CI verified at 11:20:20Z. The later 0.3.1 repair requires runtime verification even when native fields are populated; it is covered by 31 mocked checks on both editions and PS7 repository validation, not that earlier VM snapshot. Full 174-check host matrix and both-edition parser/catalog validation passed before this last repair; overlapping subsets are not summed. No legacy outcome resolved, retired or excluded; native interactive/partial/recovery/policy/Server evidence remains deferred or partial. All five ranges and rounded total unchanged because guard acceptance does not close an app lifecycle. [Active tasks and answered choices](store-app-follow-up-decisions.md), [dated evidence](../archive/evidence/store-consumer-apps-batch1-2026-10-14.md).

## Read-only Store desktop probe prepared review, 2026-10-14

Schema 6 admits exactly seven identity/request/target/scenario keys and refuses action, app selection and target-widening controls. Existing schemas remain unchanged. Probe shell observations do not verify active connection, elevation, actual desktop or handoff completion. [Desktop actor preparation](store-app-follow-up-decisions.md#desktop-actor-preparation-proposal) records the next isolated resource and deferred sign-in/UAC/credentials. Native request 2f461c696aea46f18a36277740ab14af uses Local source with fixture hash 0344DB41A93958C2A237462F4444200490CF7BF10C44A345E699E90B9E3C4B82 and 356 preflight files; final source, identity, XML, checkpoint and idle/pin audits remain required. All five ranges unchanged because resource observation resolves no legacy app lifecycle. No outcome retired/excluded/resolved; desktop, app recovery/partial behavior and separate policy remain deferred or partial. Catalog/generated descriptions now explicitly distinguish required removability/type/source evidence from visibly unknown IsPartOfSystem.

## Store desktop resource probe accepted review, 2026-10-14

Run 2f461c696aea46f18a36277740ab14af finished 2026-10-14T11:40:52Z with fixture 0344DB41A93958C2A237462F4444200490CF7BF10C44A345E699E90B9E3C4B82 and source manifest 7CD8422790EF30FF70072239E0BB9FB74B41ADCE94908F8CBB5A646CE4110235. The actor resource probe observed one expected-SID shell, PID 5768/session 1; actual desktop/token/connection and source-bound worker remain unverified. No session/process/task/app was started by the probe and no Windows configuration changed. Native guest validation and mocked regressions include StoreApps 0.3.1, data 0.8.0 and fixture 0.10.0. Source bytes/preflight/correlation/XML/checkpoint and final both-idle/pins/installed hashes/CI audited at 11:44:11Z. Continue with isolated Plan-only desktop actor before uninstall. No legacy outcome resolved/retired/excluded; desktop, actual app recovery/partial failure, later groups and policy remain partial/deferred. All five ranges stay unchanged because resource availability closes no app lifecycle. See [actor preparation](store-app-follow-up-decisions.md#desktop-actor-preparation-proposal).

## Isolated Store desktop Plan actor implemented review, 2026-10-14

Schema 7 preserves the earlier schemas and admits only an identity-bound declared pending Store group, no action/command/target-widening switches. The test-only worker exercises read-only Plan and Invoke-RideStoreDesktopRequest, preserving source-bound current-session checks; it does not exercise the production shell launcher or alternate administrator and cannot uninstall/reinstall. Task definition ownership, bounded timeout, failure artifact copy and cleanup are explicit. Native request 99adcc9ee9df4f85953f37cf058ca9f7 uses Local source with uncommitted changes, 357 preflight files and fixture CF894B8320728A3F3ECC773264DB3E8B359E01CA2FBF983396FC47446203E5C5. Source is sealed; final actor, task/checkpoint, XML, identity and idle/pin/hash audits remain required. No legacy outcome resolved/retired/excluded; full handoff/alternate-admin, app lifecycle/source recovery/partial failure and policy acceptance remain partial/deferred. All five ranges stay unchanged because implementation is not native acceptance. The [follow-up document](store-app-follow-up-decisions.md#first-app-lifecycle-fixture-design) prepares Solitaire as the first applicable isolated lifecycle, gated on desktop evidence.

## Native Store desktop actor startup failure and diagnostics repair review, 2026-10-14

Run 99adcc9ee9df4f85953f37cf058ca9f7 completed Failed at 2026-10-14T12:03:35Z, with fixture CF894B8320728A3F3ECC773264DB3E8B359E01CA2FBF983396FC47446203E5C5 and source manifest C3F740C9A4D20FD50106FFCF012A22A33234FA2B7AAF4722242D2D7AB53DBACA. Parser/catalog and 204 mocked guest tests passed; real task returned 1 without actor.json. The cause is not established by that exit code. No app changed. Owned task removed, controller collection/cleanup errors empty; source bytes/preflight, final checkpoint and idle/pin/hash/CI audit passed at 12:06:04Z. Failed selection removed only after matching its receipt hash. The diagnostic repair creates a RunId-owned user-local test directory and captures bounded console output including bootstrap/worker startup failures; it preserves partial bytes and validates copied hashes after owned task cleanup. Current 0.11.1/actor 0.1.1 source passes parser/catalog validation; normal policy and production handoff unchanged. Native Plan/full launcher/alternate-admin/removal/recovery remain pending. No legacy outcome resolved/retired/excluded, all five ranges unchanged because a failed native worker grants no acceptance. [Active tasks](store-app-follow-up-decisions.md) retain this failure and gated Solitaire design.

## Store desktop identity guard refusal isolated review, 2026-10-14

Run b2615b9d390447dc906a3a50b490cf78 completed Failed at 2026-10-14T12:15:34Z. Fixture 379319C1F22BF7062E0483A6A29B9EF76041559441CDF839B28E24F9FB6EC908; source manifest 982217E678EB07C627AB0D60F9849FD93023508826761958951E296B91661EB6. Console A9747DA7B24176C41EF503A029589C46D66E3DA6FAED4508B5511F4D70383675 proves actor.ps1 ran and refused its initial owner/session/elevation predicate; this does not identify which term failed. No app queried/changed. Owned task removed, all source hashes verified and final checkpoint/idle/pins/installed hashes/CI audited at 12:19:12Z. Failure audit and console retained before removal of the matching temporary selection. Actor 0.1.2 adds exact observations and read-only EnableLUA/consent/secure-desktop prerequisites to the existing captured console without changing UAC, logon configuration or production guards. Parser/catalog validation passes. Another focused identity diagnostic is authorized; native desktop/full launcher/alternate-admin and app lifecycle remain pending. No legacy outcome resolved/retired/excluded; all five ranges unchanged because guarded refusal grants no acceptance. [Follow-up tasks](store-app-follow-up-decisions.md) keep the gated Solitaire design.

## Terminal default-profile native guidance implemented review, 2026-10-14

[Terminal profile guide](../windows-terminal-profile.md) implements the accepted native UI handoff documentation while the Store actor diagnostic runs. It distinguishes defaultProfile (existing profile GUID/name) from the OS default-terminal-host choice and restored window layouts; it selects neither a profile nor a host on the workstation. Prior manual selection and missing-profile recovery remain explicit. E06 file ownership, syntax/comment preservation, conflict recovery and GUI acceptance remain deferred. No supported target or catalog operation is added, and no legacy outcome resolved/retired/excluded by documentation. All five ranges unchanged because guidance is not captured/native feature acceptance; selected playback endpoint guidance and its native endpoint/session backend remain separate. Local links/reference headings reviewed, no VM/package/GitHub request for this independent documentation work.

## Unelevated desktop resource prerequisite identified and deferred review, 2026-10-14

Run d62ee7a8b55c4c2aa0b2352147901e87 finished Failed at 2026-10-14T12:27:12Z, fixture C56726427B33E35C007873A9DF83CE1F46F91DD0B3DB686EEFA72B345CBD3614, source manifest 0ED8737500063870F9AF6B44E5972CB2FE0AB0C10A47C4C43CE6DBEC9B48291C and console 484FEA918F831FB53A2B5B4748EFD79F1C5293C95F0ED07B999889A7A5867679. The identity predicate correctly refused an administrative token on the UAC-disabled guest despite a Limited task and correct session. This failure accepts no desktop/worker/full launcher/alternate-admin or app lifecycle. All source bytes/preflight, failure/console correlation, task cleanup and final checkpoint/idle/pins/installed hashes/CI verified at 12:29:53Z; only matching selection removed. No app queried/changed, no UAC or pin change. [Postponed resource decision](store-app-follow-up-decisions.md#desktop-resource-decision---postponed-while-afk) requires a genuine unelevated desktop on a separately reviewed fixture resource; honor the user instruction to postpone interactive elevation/credentials while AFK. No legacy outcome resolved/retired/excluded; all five ranges unchanged because this is failed resource acceptance. Preserve actual app source/recovery/GUI/managed and policy evidence as deferred/partial. Continue independent authorized machine-setting boundaries.

## Local maximum-age 1/2/998-day boundaries Windows 11 lifecycle passed review, 2026-10-14

Request `d17b3ecf49084aac8fa0bf45ed8eaa0c` for `windows.local-password-maximum-age` on Windows 11: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-local-password-maximum-age-win11-d17b3ecf-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Local maximum-age 1/2/998-day boundaries Windows Server 2025 lifecycle passed review, 2026-10-14

Request `8da4114c2f504c5d8adb4b7321482641` for `windows.local-password-maximum-age` on Windows Server 2025: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-local-password-maximum-age-winserver-2025-8da4114c-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Maximum-age boundary follow-up and minimum-age guard implemented review, 2026-10-14

The fixed schema-2 MinimumAgeConflict admits only windows.local-password-maximum-age/Days1 with explicit target approval. Test-only level 1003 sets captured-zero minimum to one day; production backend remains level-1002 maximum-only. SAM/unrelated context, preview and refusal state are checked, native maximum setter counted, failed intent restored without a maximum write, and the exact fixture minimum seed separately recovered. Drift refuses replay. LifecyclePassed/ExactRecovery remain false for this guard; ExactFixtureSeed is not successful primary apply. The existing local security/password scope is unchanged; no passwords, domain controllers, UAC, app/package or GitHub work. Current source includes uncommitted changes; request 660dac2bfa0d45f3ac8d6e1f46dcc7eb has 360 preflight files and fixture 9454FD88FDC370A36FCCC1691B124A1D42583F698D88BBC728CDC915C8C47CA6. Native and checkpoint acceptance pending. No legacy outcome resolved/retired/excluded; GUI, managed/default/complexity and unelevated desktop resources remain partial/deferred, all five ranges unchanged. [Fixture contract](../../tests/integration/settings-fixtures.md) documents the focused scope; [desktop prerequisite](store-app-follow-up-decisions.md#desktop-resource-decision---postponed-while-afk) remains held.

## Local maximum-age conflicting minimum Windows 11 MinimumAgeConflict guard passed review, 2026-10-14

Request `660dac2bfa0d45f3ac8d6e1f46dcc7eb` for `windows.local-password-maximum-age` on Windows 11: passed; 0 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-local-password-maximum-age-win11-660dac2b-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Local maximum-age conflicting minimum Windows Server 2025 MinimumAgeConflict guard passed review, 2026-10-14

Request `9921cbfc65c44a718fb1f872213e82f0` for `windows.local-password-maximum-age` on Windows Server 2025: passed; 0 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-local-password-maximum-age-winserver-2025-9921cbfc-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Two-target password-age boundary and conflict follow-up accepted review, 2026-10-14

Completed follow-up source snapshots include current uncommitted code. Boundary runs: d17b3ecf49084aac8fa0bf45ed8eaa0c (Win11, 358 files, manifest EFB957614927236F75FC3B9AB9C186F166EBB354EAA36E85EB1824CCC9AA3F81) and 8da4114c2f504c5d8adb4b7321482641 (Server, 359 files, CD8E07D1970415711BA38BA6EABA58F9C747BB5EE8A005707DD0DF7A4658B001). Refusal runs: 660dac2bfa0d45f3ac8d6e1f46dcc7eb (Win11, 360 files, BCA0DF413CDF2804F8C24A7DEBB43B7DBA4703E4F7559DCC753A1CC4113054EE) and 9921cbfc65c44a718fb1f872213e82f0 (Server, 361 files, 3C82509E36F2E0417CB6A2634E68AB6EF9A21B3428220EE30F9A610636470EA7). All hashes/preflight entries, correlated guest/XML evidence, native recovery and final both-idle/pins/installed hashes/CI validated. MinimumAgeConflict uses test-only local minimum level 1003, while production maximum setter remains 1002 only; no successful primary apply is inferred from zero-write refusal. Current fixture/data 0.12.0/0.10.0; 178 host mocked checks passed on each edition, one registry case excluded. [Validation handoff](settings-validation-resume.md#password-age-boundary-and-refusal-follow-up-2026-10-14) links exact scope; [desktop resource follow-up](store-app-follow-up-decisions.md#desktop-resource-decision---postponed-while-afk) remains postponed under the AFK elevation instruction. Published support, UAC, pins, profiles and package pause unchanged; no whole legacy outcome resolved/retired/excluded. GUI/default/managed, complexity/file-editor and app lifecycle remain partial/deferred, so all five ranges and rounded total stay unchanged.

## Separate Store desktop and read-only Plan accepted review, 2026-10-14

Separate UAC-enabled offline disposable Store desktop prepared under direct user authorization. Read-only Plan 080d9d9404274f349857f1e06166fe80 passed current-source hash correlation, actual same-user/session unelevated worker and Explorer, transient task cleanup and separate checkpoint recovery. The original VMs/pins/controllers and clean CI are unchanged. [Dated evidence](../archive/evidence/store-test-desktop-2026-10-14.md) and the [resource runbook](store-test-desktop.md) retain exact identities and boundaries. This resolves only the resource prerequisite and read-only worker Plan; full production launcher, alternate administrator, uninstall/reinstall/policy and additional edition/Server desktop acceptance remain pending. No legacy outcome is resolved, retired or excluded. All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; apps kept and packages paused.

## Isolated Solitaire lifecycle fixture implementation review, 2026-10-14

Implemented the isolated Solitaire fixture using only an exact private Windows 11 target edit and existing production Store guards. Original source/catalog and candidate hashes remain distinct; previews, repeat actions, native removal/re-registration, source survival, owned schema-1 records and unrelated registrations are checked in the actual unelevated desktop. Both editions passed 36 focused mocked tests, and read-only repository validation passed. Native validation follows on the separate offline UAC desktop; original pins/controllers remain unchanged. No whole legacy outcome resolves, retires or excludes; app/GUI/launcher/policy acceptance remains partial. All five ranges unchanged: 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; packages paused.

## Solitaire first native lifecycle failure and diagnostics review, 2026-10-14

Solitaire run dfd6c2c94edd4eb09bd6457194f3bb82 failed reinstall acceptance after successful preview/removal/repeat and an immediately successful local-source Plan; reinstall preview was refused before native registration. Current source/isolated catalog hashes, owned schema-1 removal record, task cleanup and separate checkpoint recovery were retained; original VM pins/controllers unchanged. Basic removal evidence is partial, not full lifecycle acceptance or published support. Precise source refusal and delayed stability diagnostics added without relaxing protection, identity or source guards; investigate only Solitaire before moving to another app. No whole legacy outcome resolved/retired/excluded; all five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Packages remain paused.

## Solitaire diagnostic failure and WhatIf projection repair review, 2026-10-14

Solitaire diagnostic run 10a640b3ab10400ba06eb99f0aefa3e5 proved unchanged manifest hash, complete registered dependencies and unchanged unrelated registrations after removal. The preview failure is the production read-only ForEach-Object member projection suppressed under WhatIf, not proven payload loss. Handler 0.3.3 uses Select-Object to preserve read-only inspection while retaining real missing-dependency refusals; source/session/type/protection/policy guards and schema-1 records unchanged. Native reinstall remains pending until the repaired same-app run. Owned task, child exit observation, source hashes and separate checkpoint recovery are retained; original pins unchanged. No whole legacy outcomes resolved/retired/excluded. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; packages paused.

## Solitaire result and repaired rerun elevation deferral review, 2026-10-14

Solitaire validation is partial: successful preview/removal/repeat with owned schema-1 removal records, but reinstall preview failed from a read-only WhatIf projection defect. Native diagnostics proved source/dependencies retained and unrelated registrations unchanged. Handler 0.3.3 fixes the projection and all 37 focused mocked checks pass on both editions. The repaired VM rerun was canceled at elevation before launch, leaving native registration/repeat pending. [Evidence](../archive/evidence/store-solitaire-validation-2026-10-14.md) and [same-app follow-up](store-app-follow-up-decisions.md#solitaire-native-validation-follow-up) retain the operational elevation requirement and acceptance boundaries. Task cleanup, both source manifests and separate checkpoint recovery were verified for both failed runs; original pins/controllers unchanged. No next app started, no whole legacy outcome resolved/retired/excluded; all five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180; packages paused.

## Solitaire basic native registration lifecycle accepted review, 2026-10-14

Solitaire basic native registration lifecycle accepted in 3899597cd74e477195a35b280b201308: real expected unelevated desktop; both previews, uninstall/reinstall and repeat actions; retained manifest/dependencies; owned schema-1 Completed records; unchanged unrelated registrations; source/evidence hashes, task cleanup and separate checkpoint recovery verified. The current snapshot includes handler 0.3.3 WhatIf projection repair and uncommitted migration work. Original pins/controllers unchanged. [Dated evidence](../archive/evidence/store-solitaire-validation-2026-10-14.md) preserves earlier failures/cancellation and exact acceptance scope. Registration recovery is best effort, not app-data/exact version or GUI proof. Interruption, full launcher, alternate administrator, other apps/editions/Server remain pending; published support closed. No whole legacy outcome resolves/retires/excludes, so all five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Packages paused; no next app started before this result.

## Full remaining migration analysis and AFK handoff review, 2026-10-14

The [full remaining migration follow-up](remaining-migrations-follow-up.md) collects all-five-group scope, matching batches and Q01-Q31 for the user's return. All 30 settings remainder rows and earlier accepted-control families were reviewed, preserving D01/D11 and the remaining D02-D10 decisions. Current R30/handoff pointers now reflect accepted Solitaire basic native registration lifecycle and the postponed Clipchamp elevation; GUI/data, interruption, policy/groups and full handoff remain pending. B01 presentation/native guidance is the first suggested implementation batch. Packages are still paused; current-source/pin/hash/recovery test boundaries remain unchanged. No state-changing validation occurred and no new disposition, target or legacy outcome was accepted. All five ranges reviewed and unchanged: 38-58 / 58-73 / 20-25 / 25-35 / 8-12; rounded 150-205/about 180, because source/question coverage does not establish completed feature acceptance.
