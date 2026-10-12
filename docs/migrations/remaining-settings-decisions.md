# Remaining Windows and application settings: decisions and blockers

Reviewed: **2026-10-11**. This ledger complements the implementation and estimate
entries in [MIGRATION-PLAN.md](../MIGRATION-PLAN.md) and the behavioral acceptance
work in [settings-post-migration-review.md](settings-post-migration-review.md).
It is a follow-up agenda, not a declaration that the last setting is migrated.

For a concise resume point and durable validation notes, see the
[settings implementation handoff](settings-implementation-handoff.md).

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
is **40-60**, not the number of table rows.

| Remaining outcome / selectors | Required decision or evidence before implementation |
| --- | --- |
| Ultimate Performance selection/creation and desktop selection menu | User accepted separate existing-plan selection, explicit advanced machine/admin owned plan-copy creation and optional desktop Power plans access. Ultimate stays conditional: legacy GUID query succeeded but activation failed; duplication is a separate untested scenario, not an assumed fix. Identify by GUID, preserve existing stable states and separate Settings power mode, never silently create/fallback or match English names. Record new destination/ownership before creation, avoid repeat duplicates and delete only proven unchanged owned inactive plans after usable selection recovery. Prefer native Power Options menu handoff initially; direct quick-selection requires maintained capture/recovery workflow and stable installed path, with physical intended-user scope verified separately from machine plan actions. Current edition/hardware/license availability, GUI/activation, partial recovery, menu scope and Server evidence remain pending; bundle stays partial without estimate closure |
| IE proxy autoconfiguration packed connection data | User accepted separate GUI detection and coherent setup-script/address controls through documented connection APIs, advanced WinHTTP configuration and optional discovery-off guidance with both scopes explicit. Preserve unrelated flags/manual/VPN settings and saved URL; retain existing scalar IDs as compatibility controls. Verify managed scope, refresh, connectivity, exact recovery and default-profile implications before implementation |
| Telemetry non-policy mirrors, CEIP and App-V CEIP | User accepted separate advanced machine/admin Windows CEIP and conditional installed/enabled-client App-V CEIP participation policies, matching actual Group Policy names and showing opposite Enabled wording. Opted out/in differ from Not configured and exact saved-state restore; legacy enable removed both policy overrides. Show OS/client edition/license requirements and managed precedence without RIDE membership/cloud-account requirements or automatic App-V enablement. Current App-V support policy now states server support through October 2029 and client/sequencer follow Windows; correct earlier retirement implication. Exact current client-policy/preference mapping and collection remain pending. Native/Wow6432Node AllowTelemetry copies remain deferred, unexposed and untouched until independent effect/GUI/precedence is established; no guessed labels, old 0/3 writes or default claims. Retain accepted diagnostic policy/guidance and compatibility dependencies; feature evidence, typed recovery and Server applicability remain open, telemetry bundle partial and estimates unchanged |
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
| Server Manager and shutdown tracker | User accepted two separate advanced machine/admin policies aligned with Group Policy choices. Server Manager automatic startup is distinct from its console preference; suppression/explicit startup/default removal need verified precedence and logon behavior. Shutdown Event Tracker is one coordinated control for Disabled, Always, Server Only, Workstation Only and Windows default, preserving/restoring paired On/UI values and unrelated logging. Local ADMX evidence is not target acceptance. Windows Server 2025 media/VM remains unavailable; no new Server/client support, implicit policy refresh, task/feature changes or host shutdown testing. Implementation and actual target outcomes remain pending |
| Server password policy and IE Enhanced Security | User accepted independent advanced local-account complexity and maximum-age controls matching Local Security Policy, machine/admin with explicit scope and initial domain-controller refusal. Replace fixed-string 42-day presets with verified explicit values; preserve minimum-age and unrelated policies, distinguish local/effective sources, and prove focused recovery without full-export replay or password capture. No universal expiration baseline or generic deletion-as-default. User accepted retaining conditional Server IE ESC investigation with two GUI-aligned Administrators/Users On/Off controls, both machine/admin. Current Server Manager documentation still lists ESC despite standalone IE removal in Server 2025; verify actual component effect, GUID/class mapping, profile activation and derived-state recovery before availability. No Windows 11 control, automatic disable, broad historical script replay or claims of Edge/IE-mode equivalence. Server acceptance remains unavailable; implementation and feature acceptance remain pending, with no retirement or estimate closure accepted |
| Windows Audio service and endpoint mute | User accepted separate advanced machine/admin Audiosrv control (Automatic/running or legacy Manual/stopped) and normal selected playback-device Mute/Unmute using native Core Audio. Manual is not Disabled; preflight/refuse undeclared dependency changes rather than force-stopping or silently configuring AudioEndpointBuilder. Capture service configuration/runtime and endpoint ID/prior mute separately; restore the original device, preserve volume, app/microphone/default-device state, and report missing endpoints without fallback. Endpoint control runs in the intended interactive user's context but affects a potentially shared endpoint; resolve metadata/execution scope and verify GUI roles, session boundaries, exclusive-mode limits and actual playback. No implicit service start, continuous enforcement or universal audio-silence claim. Implementation, feature acceptance and Server audio coverage remain pending |
| BitLocker encryption/decryption and TPM+PIN enrollment | User accepted GUI-aligned guided machine/admin OS-volume setup connecting reviewed policy, TPM-only or TPM+startup PIN, recovery backup, encryption and real boot verification. Separate advanced Turn off BitLocker (decrypt) from suspend, PIN removal and ordinary restore. Preserve existing methods/protectors; no silent alternate-unlock removal, AES-CBC preset, used-space-only assumption, hardware-test skip, reboot, media ejection or plaintext/env-var PIN. Expose edition/admin/TPM and backend-specific account/license prerequisites. Require secure input/output redaction, nonsecret staged records, explicit protector ownership and compensating recovery; encrypted percentages and added PIN alone do not prove the complete outcome. Detailed recovery export/retrieval remains separate follow-up. Lifecycle implementation, actual feature acceptance and Server coverage remain pending |
| BitLocker recovery protector creation and password display | User accepted guided recovery area with normal Back up, advanced Create additional, and explicit selected-key Show. Select RecoveryPassword by type and ID, never array position; backup reuses existing protectors without implicit rotation/duplicates. Require an explicit off-device-accessible destination, native GUI/portal handoff where secure custom handling is unproven, nonsecret staged reports and output redaction; no recovery secret in routine status/state/logs, auto upload/clipboard/print or cleanup of existing protectors/backups. Expose distinct offline, Microsoft-account, AD DS and Entra prerequisites; future Graph secret retrieval needs consent/owner-or-role checks and audit, not local admin alone. Actual backup retrieval/unlock, failure recovery, secure presentation and Server acceptance remain pending |
| MaxDevicePasswordFailedAttempts lockout | User accepted optional advanced machine/admin Interactive logon: Machine account lockout threshold, with explicit zero or supported threshold and visible 1-3 effective-as-4 semantics. Intended local GUI/legacy registry mapping remains unverified; failed Windows sign-ins can cause reboot/BitLocker recovery, distinct from TPM startup-PIN retries, Hello or ordinary account lockout. No automatic ten-attempt preset or mobile-wipe label. Initial positive-threshold availability requires verified OS-volume protection and accessible 48-digit recovery backup; show managed precedence/restart/availability impact. Reconcile current versus archived non-BitLocker behavior in disposable targets; policy restore does not undo enacted lockout/protector transitions. Implementation, actual recovery/counting and Server evidence remain pending |
| Photo Viewer associations and Open with registration | User accepted separate advanced Make Windows Photo Viewer available in Open with and normal Choose default photo app through supported Windows UI. Prefer bounded intended-user HKCU registration, explicitly changing ambiguous legacy HKCR scope, without elevation or machine fallback; native component/current-build behavior remains unverified. Registration does not select defaults; no built-in ProgID hijack, UserChoice/hash bypass, IE reconstruction, DLL download or Photos removal. Capture owned registration changes and preserve existing entries; GUI default recovery is a separate verified user step, never protected-registry replay. Show component/managed restrictions without invented cloud/license prerequisites. Exact extension coverage, quoting, Open with/Default apps discovery, rendering, recovery and Server evidence remain pending |
| Media radio/WMDRM leftovers | User accepted separate conditional advanced Prevent Radio Station Preset Retrieval (user/no-admin) and Prevent Windows Media DRM Internet Access (machine/admin) investigations, excluded from normal/recommended selections until actual component effects are verified. Current CSP mappings and local ADMX exist; radio ADMX has pre-Vista applicability, and DRM deprecation does not prove universal Windows 11 removal. Correct blanket retired wording in later catalog follow-up. No all-traffic/PlayReady block or automatic DRM inclusion in metadata guide. Distinguish Blocked, explicit policy disabled and override removal; exact typed policy restore cannot revive servers/licenses. Expose component, edition/backend and managed-policy prerequisites; no automatic player installation or license-store changes. Current feature evidence and Server coverage remain pending; bundle stays partial without retirement or estimate closure |
| Visual effects packed mask and mismatched KeyboardDelay type | User accepted full Keyboard repeat delay positions 0-3, retaining Shortest=0 and LegacyAppearance=1 compatibility and adding reviewed positions 2/3; earlier accepted individual GUI effects and separate timing controls remain in force. Fixed packed masks/whole presets stay deferred; no repeat-rate/Filter Keys changes or guaranteed intermediate timing. Catalog already uses String; prefer focused native API after proving effective-versus-stored state, persistence and exact recovery of legacy DWORD/String/absent/unexpected snapshots, with versioned compatibility for existing runs. No broad UI-effects master switch, silent backend change, forced restart or unrelated mask edits. Current-user/no-admin and active-session requirements; taskbar/Peek, mask mapping, GUI/runtime recovery and Server evidence remain pending; bundle stays partial |
| Delayed-auto-start overrides for WAP/Search | User accepted additional Automatic (Delayed Start) + Start now preset for each stable existing service ID, candidate AutomaticDelayedRunning, reconciling legacy delayed enable while preserving AutomaticRunning's existing delay and Disabled's dormant flag. Earlier accepted GUI startup/runtime separation remains in force. One coordinated machine/admin SCM handler; startup-only choices do not request runtime actions. Capture literal/effective delay, startup and runtime; preserve snapshot compatibility and prove exact restoration despite SCM normalization. No raw registry catalog twin, reboot, fixed-delay guarantee, forced dependent stop, index repair or implicit enrollment/sync. Show Search and managed-device effects; actual GUI/SCM/boot/workload, partial-failure recovery and Server evidence remain pending; legacy coverage stays partial without estimate closure |
| Security icon startup remainder | User accepted guided Show the Windows Security icon outcome, with earlier accepted focused machine/admin tray-icon policy separate from intended-user Settings/Task Manager startup handoff and user-controlled refresh; no automatic historical Run-entry reconstruction. Verify exact startup entry, effective user/machine scope, managed precedence, component and actual icon appearance; GUI handoff is pending user action, not successful reversible apply. Preserve alerts/protection/services; no binary download, duplicate registration, process kill/launch or implicit repair. Any later direct startup backend needs separate exact recovery/ownership review. Implementation, feature evidence and Server support remain pending; omitted startup mutations stay explicit partial scope |
| User .NET assemblies (source identification pending) | Open provenance issue, not a known feature or proposed executable setting. No identified deployment/cache selector in legacy/v2, maintained modules/tools/components, local v1.337/v2.5.1 script/data files or the bounded all-ref identifier search. NumLock's System.Windows.Forms loads, machine strong-crypto policies and wallpaper bitmap conversion are separate outcomes. Possible bookkeeping error/duplicate remains unconfirmed. Preserve audit evidence for final walkthrough; does not block other identified work. Resolve by finding/assigning the real source outcome, linking a duplicate, or documenting an explicit agreed bookkeeping correction. No guessed mutation, migrated/retired claim or additional numeric component solely from this label; estimates unchanged |

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
recovery are preserved. See [the presentation contract](../SETTING-PRESENTATION.md)
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
