# Settings post-migration review

Current disposable validation sequence, accepted lifecycle scopes and the owned
power-plan export failure: [settings validation resume](settings-validation-resume.md).

## B01 appearance preference presentation, 2026-10-17

Four existing current-user controls now expose independent preferences and their
limits: title-bar shake, title-bar accent color, app color mode and Windows color
mode. Presentation advances from **198/279 to 202/279; 77 remain**. Stable IDs,
literal states, scope, targets, baseline/default declarations and profiles are
unchanged. Generated OPERATIONS documentation was rebuilt from the catalog.

The [Microsoft shake behavior reference](https://support.microsoft.com/en-gb/accessibility/windows/make-it-easier-to-focus-on-tasks)
documents the Multitasking option, not DisallowShaking. Legacy DisableAeroShake
wrote 1 and EnableAeroShake removed the override; the published Enabled=0 remains
explicit and WindowsDefault retains legacy removal. The color controls' broad
settings reference is replaced by the focused [Microsoft color guide](https://support.microsoft.com/en-us/windows/experience/personalization/personalize-your-colors-in-windows).
It describes UI behavior and application exceptions, not the three retained
registry mappings. The legacy color selectors use the same explicit 1/0 values.
App and Windows modes remain separate; neither selects a full theme. Title-bar
accent does not select a new accent color or enable taskbar coloring. No shell/app
restart or sign-out is initiated. Exact restore owns registry type/value/absence,
not application preferences, window positions or the full theme.

Native Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 each passed **122**
presentation/catalog/search checks, with zero failures or skips and one intentionally
excluded WindowsIntegration case. Repository validation passed **358 operations,
eight groups, five profiles and 227 PowerShell files** on both editions; generated
documentation is current. Logs are `.local/closure-appearance-*.log`. No Windows
setting was applied. GUI readback, current-build registry mapping, contrast/theme
precedence, app exceptions and exact native recovery remain separate acceptance.
Whole-catalog semantic comparison permits only the four new presentation blocks
and their reference changes; all other catalog data matches HEAD 87893c6. The
[source/result index](../archive/evidence/appearance-presentation-2026-10-17.json)
retains hashes and both edition results.

Next procedure: continue the 77 unreviewed presentation entries in focused feature
families, preserving literal behavior and identifying legacy reverse differences.
For this family, use an isolated Windows 11 desktop to capture prior values and
UI, preview, apply each declared choice separately, inspect supported/independent
apps and shell surfaces, repeat, then restore captured state. Retain evidence and
recover the pinned checkpoint. Denied Hyper-V access defers this session's native
case; metadata/source validation does not substitute for it.

Resolved: four presentation reviews only. No whole legacy outcome resolved,
retired or excluded. Native feature outcomes remain partial/deferred. All five
ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about
175**, because presentation is tracked separately from completed legacy outcomes.

## Hashing context-menu follow-up, 2026-10-11

The requested additions are tracked in the
[v3 inclusion backlog](../candidate-tools.md#requested-v3-additions-2026-10-11).
The supplied multi-algorithm Hash value submenu is retained unchanged as source
material; algorithm/runtime availability, quoting, console lifetime and reuse
terms remain to be reviewed before implementation. HashCheck's idrassi fork is
a separate optional package outcome, with installer and Explorer acceptance pending.

The Certutil authoring example 0.1.1 corrected the value to
`Icon = 'shell32.dll,-152'`. Version 0.1.2 adopts the requested
`SHA-256 with Certutil` verb key and display name while retaining `SHA256` as
the command argument and preserving operation/component IDs. Keep generated
0.1.0/0.1.1 libraries and manifests to restore earlier runs against their original
registry destinations before applying 0.1.2. The standalone `.reg` now exactly
matches the requested snippet and makes no deletions; both examples leave old
verb keys untouched, so migration must account for duplicate entries.
The definition manages the icon and command together. Saved-run restore
recovers captured values; unset removes declared overrides. Neither action is
an assurance of complete menu removal when unrelated content remains in the key.
Icon rendering, actual hashing, unusual filenames and Windows 11 menu visibility
remain pending disposable-VM acceptance. No default profile or Windows Server
support is added. These new outcomes and an example correction do not complete a
legacy migration batch; the dated estimates remain unchanged.

Validation: repository checks and all **32 custom-registry authoring tests**
passed in Windows PowerShell 5.1 and PowerShell 7. Pester's TestRegistry was
disabled and its temporary storage placed inside the workspace; registry
lifecycle calls were mocked. No registry import or Certutil execution occurred.

## Application batch context

Application batches reviewed 2026-10-11: package migration did not accept
adjacent VMware preferences, browser profile files, EdgeHTML prediction,
OneDrive policy or Teams autostart semantics. Those outcomes are explicitly
assigned and deferred in the [application ledger](application-migration-review.md).
Managed portable removal preserves application/user data; file lifecycle tests
do not establish the user-visible effects of those settings. No additional
setting or Defender-exclusion acceptance is inferred from the application runs.

Reviewed 10 October 2026 against the current catalog and the historical
`legacy/v2/lib-windows.psm1`. This is a usability and semantic review of existing
migrations, not another implementation batch or a compatibility preset.

## Decision

Atomic implementation is useful when the user can explain and select each
independent outcome. A registry value alone is not necessarily a useful setting.
Several values that implement one feature should remain inside one focused
operation. A profile can compose understood operations into a user-facing goal,
with its scope, tradeoffs and partial coverage visible in the plan.

The app-suggestions split does not currently meet that standard: nine channel
numbers have no verified individual meaning. Mark these experimental and hold
them out of recommended profiles and any proposed app-suggestions bundle. They
remain addressable to preserve IDs and exact saved-run recovery; this review
does not add an execution block. Keep the unresolved distinction visible in
discovery, descriptions and generated documentation. Do not count a successful
registry round trip as completion of their feature evaluation.

The Cortana split contains possible input-personalization preferences, not an
Enable Cortana replacement. Microsoft's [Cortana retirement notice](https://support.microsoft.com/en-us/cortana/end-of-support-for-cortana)
rules out presenting those preferences as restoration of that retired product.

### Accepted guidance for complete outcomes, 2026-10-10

The user explained that legacy bundles made the settings needed for a complete
solution discoverable. Preserve that purpose throughout the review: individual
GUI-aligned controls must be accompanied by guided, named outcomes when several
controls or lifecycle steps are needed together. Users must not have to infer
the combination from registry names. This requirement complements the earlier
individual-controls and optional-profile decisions.

For each proposed outcome, explain the intended scenario, required versus
optional components, dependencies, ordering, edition/license/account/hardware
requirements, usability costs, recovery and how to verify the result. Compose
verified controls through catalog-backed profiles/groups as appropriate to their
lifecycle; do not build a parallel source of setting mappings. Explain manual
or deferred prerequisites alongside the available controls. Mark partial,
unsupported and unverified coverage visibly instead of presenting a partially
applied bundle as a completed solution.

Security guidance must describe the threat and resulting protection, rather than
assign a universal Really secure label or equate a higher setting count with
greater security. Discovery and planning should lead users from the outcome to
its component choices; status should distinguish configured policy from effective
protection and identify missing requirements. These are accepted design
requirements for follow-up implementation, not new runtime evidence or profiles.

## App suggestions: individual evaluation

The catalog retains the fifteen values copied from `DisableAppSuggestions`.
Their intended areas follow legacy source and value names unless the table says
otherwise; they are not verified Windows 11 UI mappings. All fifteen now have
an explicit experimental name and an individual description. Their states
retain the previous mappings and `WindowsDefault` removes the override.

| Operation | What can be stated | Legacy EnableAppSuggestions | Disposition |
| --- | --- | --- | --- |
| `windows.content-delivery` | Broad legacy ContentDeliveryAllowed gate; not an established all-advertising switch | Write 1 | Experimental; prove which experiences depend on it |
| `windows.oem-preinstalled-app-suggestions` | OEM-specific preference, inferred from OemPreInstalledAppsEnabled; does not uninstall existing apps | Write 1 | Experimental; establish OEM/image dependency |
| `windows.preinstalled-app-suggestions` | Non-OEM-specific PreInstalledAppsEnabled preference; separate from historical bookkeeping | Write 1 | Experimental; distinguish promotion from actual installation |
| `windows.silent-app-installation` | Legacy intent is automatic suggested-app installation; not a universal installer block | Write 1 | Experimental; verify on a fresh image and distinguish existing apps |
| `windows.suggested-content-310093` | HOBL includes this value among notification suppression writes; the individual notification is unidentified | Remove override | Unresolved; no specific feature name justified |
| `windows.suggested-content-314559` | No reviewed primary source establishes an individual feature | Remove override | Unresolved; do not label as Start, lock-screen or tips without evidence |
| `windows.suggested-content-338387` | No reviewed primary source establishes an individual feature | Remove override | Unresolved; evaluate independently of neighboring subscription numbers |
| `windows.suggested-content-338388` | No reviewed primary source establishes an individual feature | Write 1 | Unresolved; a numeric neighbor does not imply the same experience |
| `windows.suggested-content-338389` | HOBL includes this value among notification suppression writes; the individual notification is unidentified | Write 1 | Unresolved; sample usage is not a per-channel specification |
| `windows.suggested-content-338393` | No reviewed primary source establishes an individual feature | Remove override | Unresolved; do not claim the Settings switch maps to this alone |
| `windows.suggested-content-353694` | No reviewed primary source establishes an individual feature | Write 1 | Unresolved; distinguish from 353696 before any combined control |
| `windows.suggested-content-353696` | No reviewed primary source establishes an individual feature | Write 1 | Unresolved; distinguish from 353694 before any combined control |
| `windows.suggested-content-353698` | No reviewed primary source establishes an individual feature | Remove override | Unresolved; needs its own mapping and current-build evidence |
| `windows.settings-pane-suggestions` | Intended Settings promotion area from SystemPaneSuggestionsEnabled; not an established one-value mapping to the visible switch | Write 1 | Experimental; compare with the Settings suggested-content control |
| `windows.post-setup-suggestions` | Intended finish-setting-up prompt area from ScoobeSystemSettingEnabled; notification usage supported by HOBL | Remove override | Experimental; reproduce the actual prompt and check related notification settings |

For numbered channels, Disabled writes 0 and Enabled writes 1. **Enabled is
not the legacy reverse action for five channels**: 310093, 314559, 338387,
338393 and 353698 used value removal. Use WindowsDefault for that action, and
saved-run restore to recover the exact original state. Removal does not promise
that the corresponding Windows feature becomes enabled.

The legacy bundle also changed PreInstalledAppsEverEnabled, an Ink Workspace
suggestion policy and a binary CloudStore cache, and terminated a shell process.
Those components remain excluded. Selecting all fifteen operations therefore
does not reproduce the complete legacy function. No broad app-suggestions
profile is added by this review.

### Accepted presentation decision, 2026-10-10

The user selected individual feature controls plus an optional **Reduce Windows
promotions** profile. This accepts the product design; implementation and feature
acceptance remain outstanding.

- Present independently useful, understandable feature outcomes as individual
  controls. Candidate areas include suggestions in Settings, the welcome
  experience after updates, Windows tips and third-party Spotlight suggestions.
  Several values implementing one verified feature belong inside one operation.
- Compose verified, target-applicable controls in the optional profile. Describe
  its actual coverage, dependencies and tradeoffs; do not promise suppression of
  every promotion or suggested-app installation. Preserve individual selection.
- Keep the existing fifteen raw preferences experimental, retaining stable IDs
  and exact saved-run recovery. Unidentified channels remain outside recommended
  composition; do not silently redirect an existing ID to a different policy.
- Verify current-build feature effects, edition support, policy precedence and
  reverse-state semantics before recommending either a control or the profile.
  Documented feature behavior alone does not verify the legacy registry mapping.
- Distinguish explicit enablement, override removal (WindowsDefault) and exact
  saved-run restore in the user-facing descriptions.

Follow-up: establish the feature mappings, implement the reviewed controls and
profile with focused references, and perform disposable-VM feature acceptance.
This discussion changes documentation only; no catalog state, profile selection
or migration estimate changes, and no new runtime evidence is claimed.

## References and their limits

The former `#25-windows-spotlight` fragment belongs to an older layout of the
large Windows privacy article. Section 25 is now Personalized Experiences;
the old fragment does not identify the intended current section. The catalog
now uses the focused [Configure Windows spotlight](https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight)
page for general content-delivery background. It explains the family of
experiences and supported policy controls, **not SubscribedContent number
assignments**. No reviewed Microsoft Learn or Support page provided a definitive
per-channel reference. Community replies hosted on Microsoft Q&A are not an
official mapping specification.

Use these more focused behavior references for the corresponding feature areas:

- [Recommendations & offers privacy settings](https://support.microsoft.com/en-us/windows/privacy/privacy-settings-for-recommendations-offers-in-windows-11)
  describes the visible Settings suggested-content control. Older builds use
  [General privacy settings](https://support.microsoft.com/en-us/windows/privacy/general-privacy-settings-in-windows).
- [Notifications and Do Not Disturb](https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows)
  explains notification and welcome options. It does not specify the Scoobe value.
- [Speech, inking, typing and privacy](https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy)
  explains the personal word list and its removal. It does not specify the three
  individual input-personalization values migrated from Cortana.
- Microsoft's [HOBL preparation source](https://github.com/microsoft/HOBL/blob/main/docs/support/docs/HOBL_Prep.md)
  groups ScoobeSystemSettingEnabled, 338389 and 310093 with notification
  suppression. This supports their use in that sample, not unique channel names
  or a guarantee for current Windows 11 builds.

Prefer the documented Spotlight policies for future user-facing controls when
their scope, edition support and behavior match the requested outcome. Do not
silently repoint existing IDs to those policies: the value, scope and restore
contract would change. That requires a separate reviewed migration.

## Cortana-derived preferences

| Operation | Individual intended outcome | Assessment |
| --- | --- | --- |
| `windows.implicit-text-personalization` | Limit implicit learning from typed words through RestrictImplicitTextCollection | Experimental; distinguish personal dictionary learning from sending diagnostics |
| `windows.implicit-ink-personalization` | Limit implicit learning from handwriting through RestrictImplicitInkCollection | Experimental; handwriting and typing may participate in one visible preference |
| `windows.input-personalization-contact-harvesting` | HarvestContacts suggests contact-name learning in the training store | Experimental; purpose inferred from the name, not verified; unrelated to app contacts-access permission |

Legacy EnableCortana wrote 0 for the two restriction values, but removed
HarvestContacts. Its app registration, AllowCortana policy, button preference,
privacy-consent bookkeeping and PolicyManager default-store changes are not
implemented by these three preferences. Do not compose them into an Enable
Cortana profile. Determine which values implement the current personalization
UI before implementing the combined control agreed below. Exact registry recovery
does not recover learned words if Windows clears them as a feature side effect.

### Accepted personalization decision, 2026-10-10

The user selected one combined **Inking and typing personalization** control as
the normal user-facing choice. Verify the current UI mapping and include only
values proven necessary for that coherent feature; this decision does not
establish that the two legacy restriction values alone implement it.

Keep the three existing IDs experimental and preserve their exact saved-run
recovery contracts. Leave HarvestContacts out of the combined control until its
meaning and relevance are established. Do not present any of these preferences
as enabling Cortana or as the policy for sending recognition samples to Microsoft.

Follow-up: establish the mapping, implement the combined operation with reviewed
states and focused documentation, and verify the UI and feature on disposable
Windows targets. Explain before apply that disabling the documented feature
clears the custom word list and that restoring preference values cannot recreate
learned words. This is an accepted design decision, not new feature acceptance;
catalog implementation, profile selections and migration estimates are unchanged.

### Accepted diagnostic and recognition-data decision, 2026-10-10

The user accepted separate **Windows diagnostic data level** and **Send inking
and typing samples to Microsoft** controls. Use the latter as the clearer
presentation name for windows.linguistic-data-collection-policy while retaining
its stable ID. This records the naming decision; catalog presentation changes
remain implementation follow-up.

Legacy source confirms overlapping choices rather than fully independent
selectors. DisableInkingAndTypingData separately wrote the per-user TIPC Enabled
value to 0. DisableTelemetry also blocked recognition-data sharing through the
machine AllowLinguisticDataCollection value, alongside diagnostic levels,
handwriting-sharing policy, additional policies and scheduled tasks.
EnableTelemetry removed both the diagnostic and linguistic policy overrides,
wrote diagnostic mirror values to 3 and enabled tasks. It did not restore a
captured prior state or reverse the separate per-user TIPC preference.

Follow-up: distinguish machine enforcement from the existing per-user sharing
preference, verify their precedence and effective behavior, and keep word-list
personalization separate from sample sharing. Preserve explicit-state, override
removal and exact-restore distinctions. Describe edition-dependent diagnostic
levels and partial legacy coverage; do not label these controls as a complete
DisableTelemetry replacement. No runtime evidence or estimate adjustment is
claimed by this documentation-only decision.

### Activity-history evidence review, 2026-10-10

Legacy DisableActivityHistory wrote 0 to EnableActivityFeed,
PublishUserActivities and UploadUserActivities together; EnableActivityHistory
removed all three overrides. The current three operations preserve those writes
and removals, but their Enabled states mean override removal, not explicit 1.

Microsoft still lists the three policies with [focused policy references](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#enableactivityfeed).
Disabling the feed prevents publishing and cloud sync, so the choices are coupled.
Policy documentation alone does not establish current feature relevance.
[Activity-history support](https://support.microsoft.com/en-us/windows/privacy/windows-activity-history-and-your-privacy)
documents deprecation of sending history from Windows 11 22H2/23H2 with the
23 January 2024 update, while still describing local storage controls.
The [connected-experiences guide](https://learn.microsoft.com/en-us/windows/privacy/essential-services-and-connected-experiences)
describes Activity History as discontinued in newer Windows versions. Reconcile
this scope on each supported build before recommending any replacement control.

Accepted user decision, 2026-10-10: retain the existing IDs and recovery as legacy
advanced controls, hold them out of recommended composition on current builds,
and add one combined feature control only where active behavior is demonstrated.
Do not equate these policies with Recall, browser history, recent-file lists or deletion
of existing history. No new runtime evidence or catalog change is claimed.

### Accepted location decision, 2026-10-10

The user accepted **Windows location services** as the normal user-facing
control, with **Location scripting** retained separately as an advanced control
pending verification of its current consumers and behavior. Preserve both IDs
and recovery contracts; do not combine the narrower scripting choice into the
main control merely to reproduce the legacy selector.

Follow-up: clarify feature effects, supported editions, policy precedence and
the relationship between device location and app permissions. Explain the
impact on location-dependent features such as automatic time zone and Find my
device without promising to prevent every method of location inference.
Use the documented machine DisableLocation mapping and the focused
DisableLocationScripting_2 reference for the respective operations.
Both current Enabled states remove an override; they do not force location on
or grant app permission. Make that distinction clear in presentation while
preserving existing states and saved-run recovery. This records the design;
catalog changes and feature acceptance remain follow-up work.

### Accepted voice-activation decision, 2026-10-10

The user accepted two separate normal controls: **App voice activation** and
**App voice activation while locked**. The latter is a useful narrower choice
when general activation is permitted; explain that dependency in discovery,
plans and descriptions. The legacy selector blocked or removed overrides for
both policies together, but that does not justify combining the user choices.

Clarify that the current Enabled state removes the override and returns choice
to the user rather than forcing permission. Preserve existing IDs, states and
exact saved-run recovery when improving presentation. Describe the covered-app
scope and distinguish voice-keyword activation from microphone access and
speech recognition. The existing focused policy links support those boundaries.
Feature acceptance with a supported voice-activated app, both unlocked and
locked, and policy/permission dependencies remains outstanding. No catalog or
runtime change is claimed by this design decision.

### Accepted app-file-access decision, 2026-10-10

The user accepted four separate choices with clearer presentation names:
**App access to Documents**, **App access to Pictures**, **App access to Videos**
and **Broad app filesystem access**. Preserve the existing IDs, including
windows.uwp-broad-file-system-access-access, and their exact recovery contracts.
The legacy disable/enable selectors wrote Deny/Allow to all four machine consent
values together; the split provides independently understandable capability
choices rather than a universal filesystem block.

Explain broad access separately, including its overlap with the named libraries
and the limits of covered-app privacy settings. Microsoft documents capability
behavior, not these exact machine consent-store mappings. Keep the controls out
of recommended profiles until current Settings effects, actual capability-based
file access, existing per-app permissions and alternative access routes have
been evaluated on supported builds. Verify rather than assume that machine
Allow grants individual app access or that override removal restores user
control. This is an accepted design; presentation changes and feature acceptance
remain follow-up work, with no new runtime evidence or estimate adjustment.

### Accepted administrative-share decision, 2026-10-10

The user accepted retaining the workstation/server IDs while presenting the
applicable operation in normal target-specific views as **Automatic
administrative shares**. Preserve explicit platform scope rather than writing
both values on every target. Disabling remains opt-in.

Explain the effect on remote administration and that automatic administrative
shares are distinct from all file sharing. Microsoft's Server reference excludes
IPC$ and manually created shares from AutoShareServer suppression. Keep the
workstation mapping qualification until its own feature acceptance is available.
Track required Server-service restart separately from registry equality; do not
silently restart the service as part of a presentation change. Verify actual
shares after the restart and recovery on disposable supported targets. Existing
Enabled states remove overrides; preserve IDs, states and saved-run recovery.
This records the agreed design, with presentation and feature acceptance still
outstanding and no new runtime evidence or migration estimate adjustment.

### Accepted .NET Framework cryptography decision, 2026-10-10

The user accepted one normal **.NET Framework 4.x strong cryptography** control
covering the 32-bit and 64-bit registry views, with the existing individual IDs
retained for advanced selection and exact saved-run recovery. Both values
implement the same normal feature outcome; the legacy selector changed them
together. The combined operation must capture and restore each prior value and
kind independently, including mixed starting states.

Present Enable strong cryptography and Use framework defaults as the normal
choices. The legacy DisableDotNetStrongCrypto action removed both overrides,
rather than explicitly writing 0. Preserve existing operation states and IDs
when introducing the combined control.

Correct descriptions and effective-default guidance: SchUseStrongCrypto affects
applicable .NET Framework outgoing TLS connections, and its effective default
depends on the application's target framework, not merely the installed runtime.
Explicit application protocol configuration can override this preference.
Do not imply coverage of modern .NET, all system TLS settings, the separate
SystemDefaultTlsVersions preference or .NET Framework 3.5 registry keys.
Follow-up: implement the combined control and verify both architecture paths,
representative application behavior and exact mixed-state recovery. This records
design only; implementation and feature acceptance remain outstanding.

### Accepted driver-update and device-metadata decision, 2026-10-10

The user accepted **Drivers in Windows quality updates** as a normal control,
with **Device-associated application downloads** retained separately as an
advanced legacy option. Keep their stable IDs and recovery contracts. The first
controls driver-classified quality updates; the second controls applications
associated with device metadata, not driver packages.

Microsoft has deprecated device metadata for future removal. Keep the metadata
control outside recommended profiles until its active behavior on current
targets is verified; do not assume it controls the replacement metadata system.
Clarify supported editions, Device Installation Settings precedence and the
difference between user choice and enforced prevention.

The legacy DisableUpdateDriver selector bundled these two values with
DriverSearching/SearchOrderConfig, which remains deferred. Its reverse removed
all three overrides. Do not describe either migrated operation as blocking all
driver updates, searches or manual/vendor installation. This records the agreed
design; presentation and feature acceptance remain follow-up work, with no new
runtime evidence or estimate adjustment.

### Maintenance-wake evidence review, 2026-10-10

The existing maintenance-wake-policy operation writes WindowsUpdate/AU
AUPowerManagement, while the [AutomaticMaintenanceWakeUp policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#automaticmaintenancewakeup)
maps to Task Scheduler/Maintenance WakeUp under a different policy key. Do not
use that reference as proof of the migrated AUPowerManagement mapping.
Microsoft's [Windows Update policy guide](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/4-configure-group-policy-settings-for-automatic-updates)
separately describes waking from hibernation for scheduled update installations.
The local WindowsUpdate.admx AUPowerManagement_Title definition was inspected
read-only: it maps AUPowerManagement to WindowsUpdate without the AU subkey and
declares SUPPORTED_Windows7ToVistaAndWindows10. That adds a key/support mismatch
requiring investigation; it is not proof of effective behavior on Windows 11.

The other operation writes the non-policy Schedule/Maintenance WakeUp preference.
Its [Task Scheduler reference](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-maintenence)
describes maintenance behavior and hardware/power prerequisites, rather than
that exact registry mapping. Neither current operation has demonstrated all-wake
suppression. The legacy selector wrote both values to 0; its reverse removed
both overrides rather than explicitly enabling wake behavior.

Accepted user decision, 2026-10-10: retain both IDs as advanced experimental
controls, outside recommended profiles, and defer a normal combined control.
Resolve the references, current update/maintenance consumers, sleep-state and
power-plan dependencies, UI mapping and actual wake behavior before recommending
these controls or combining them. Preserve existing saved-run recovery and use
a reviewed migration for any replacement rather than silently redirecting an ID.
This records the agreed disposition and reference evidence, not new runtime
acceptance or a catalog implementation change.

### Accepted notification-controls decision, 2026-10-10

The user accepted keeping Notification Center visibility separate from
notification delivery. Preserve windows.action-center-policy and
windows.toast-notifications-policy and their recovery contracts. The legacy
selector changed both together, but hiding the center and controlling delivery
are different user outcomes.

Keep the second control's final scope and presentation name pending feature
verification. Microsoft describes a global notification switch, per-app banners
and center storage separately; the reviewed reference does not establish that
ToastEnabled is a banners-only preference. Test its actual effect on banners,
sounds, center delivery and existing per-app choices before recommending it.
Keep the unverified mapping outside recommended composition.

For center visibility, explain missed-notification review and the documented
reboot requirement, and verify behavior after restart on supported editions.
Both current Enabled states remove overrides rather than force explicit values.
No ID is silently redirected to Do Not Disturb or another notification setting.
This records design and acceptance work, not a new catalog or runtime change.

### Accepted accessibility-shortcut decision, 2026-10-10

The user accepted three separate keyboard-shortcut controls for Sticky Keys,
Toggle Keys and Filter Keys. Each should change shortcut activation while
preserving feature activation, sounds and all other accessibility preferences.
Use the presentation names Sticky Keys keyboard shortcut, Toggle Keys keyboard
shortcut and Filter Keys keyboard shortcut after confirming the mapping.

The legacy and current catalog pairs 506/510, 58/62 and 122/126 differ only by
0x4. Microsoft documents that bit as HOTKEYACTIVE in the
[STICKYKEYS](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-stickykeys),
[TOGGLEKEYS](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-togglekeys)
and [FILTERKEYS](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-filterkeys)
API structures, separately from the confirmation-dialog flag. Those references
document API flags rather than the persisted registry encoding. Verify the
registry/API/UI relationship on supported Windows builds before presenting this
as an accepted functional mapping.

Replace the fixed whole-bitfield presets with a focused implementation selected
after that verification. Capture and restore the exact prior configuration;
verify that existing feature activation and customized preferences survive,
including refresh and sign-in behavior. Preserve windows.sticky-keys-prompts,
windows.toggle-keys-prompts and windows.filter-keys-prompts and their recovery
contracts through an explicit reviewed migration; do not silently change a
published operation's behavior. This is a design decision and future acceptance
work, not a handler change or new runtime evidence.

### Accepted taskbar-grouping decision, 2026-10-10

The user accepted two independent controls, presented as **Combine taskbar
buttons - main display** and **Combine taskbar buttons - other displays**.
Retain windows.taskbar-combine-primary and windows.taskbar-combine-secondary
and their exact saved-run recovery. The legacy commands changed both values
together, but separate selection permits useful mixed display preferences.
Microsoft's [feature introduction](https://blogs.windows.com/windows-insider/2023/08/10/announcing-windows-11-insider-preview-build-23521/)
describes separate settings for the main and other taskbars; it is historical
feature evidence rather than a reference for the exact registry encoding.

Make **Use Windows default** distinct from an explicit **Always combine** choice.
Both current Always states remove overrides, matching the legacy selector.
Preserve those published semantics and recovery contracts; any explicit-state
addition or presentation migration must be reviewed rather than silently
replacing override removal with a write. Verify values, actual grouping and
labels for every state on supported builds, including mixed choices with two
displays, other-display taskbar visibility and refresh behavior. A single-display
registry round trip cannot establish secondary-display effects. This records
the design; implementation and feature acceptance remain outstanding.

### Hidden/protected-file source correction, 2026-10-10

Reinspection of legacy/v2/lib-windows.psm1 confirms that ShowSuperHiddenFiles
and HideSuperHiddenFiles change only ShowSuperHidden. ShowHiddenFiles and
HideHiddenFiles separately change Hidden. The earlier table incorrectly called
the protected-file selector a combined command; these are separate legacy
preferences whose effective visibility can interact.

Microsoft's [GlobalFolderOptions reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f)
documents both registry paths and the protected-file option. Verify the current
Explorer UI and all combinations using disposable ordinary-hidden and
hidden/system test files, including refresh and exact restore. File visibility
does not change attributes or permissions. The catalog's hidden-file reference
now describes a combined Show hidden and system files UI, so prefer a focused
reference for the distinct controls and do not assume it proves their current
individual behavior. This correction does not record an accepted new design.

### Accepted hidden/protected-file decision, 2026-10-10

The user accepted two separate controls: **Show hidden files and folders** and
**Show protected operating-system files**. Present the latter as an advanced,
opt-in choice. Retain windows.hidden-files-visibility and
windows.protected-files-visibility, their existing states and exact recovery.

Explain that hidden-file visibility can affect the protected-file outcome.
Selecting either operation leaves the other preference unchanged; surface an
unmet dependency in the plan rather than silently applying a second setting.
Neither operation changes file attributes or permissions. Verify all preference
combinations, actual Explorer visibility, refresh and recovery on supported
builds before considering the feature accepted. Improve the individual names,
descriptions and focused references during implementation. This records the
design and future acceptance work, not a catalog or runtime change.

### Accepted Explorer-recent/frequent decision, 2026-10-10

The user accepted two independent controls: **Show recent files in File Explorer
Home** and **Show frequently used folders in File Explorer Home**. Retain
windows.explorer-recent-shortcuts and windows.explorer-frequent-shortcuts and
their exact saved-run recovery. Legacy HideRecentShortcuts wrote 0 to both
ShowRecent and ShowFrequent; ShowRecentShortcuts removed both overrides.
The legacy comment explicitly describes a UI-only change, distinct from
DisableRecentFiles and broader recent-item tracking controls.

Describe list visibility accurately, without promising history deletion or
disabling tracking elsewhere. Distinguish Use Windows default from explicit
visibility: both current Visible states remove overrides. Preserve published
state semantics through a reviewed presentation or state-addition migration.

Verify each preference independently and in mixed combinations on supported
builds, including pinned folders, cloud content, Explorer refresh and the broader
recent-items setting affecting Start, File Explorer and Jump Lists. Use focused
references for the individual effects; the current Windows Backup catalog
documents the broader UI switch rather than the exact ShowRecent/ShowFrequent
mapping. This records accepted design and future feature acceptance, not a
catalog change or new runtime evidence.

### Accepted background-app decision, 2026-10-10

The user accepted **Windows app background activity** as the normal policy
control and **Reset per-app background restrictions** as a separate, opt-in
advanced action. Preserve windows.background-apps-policy and
windows.uwp-background-app-user-overrides and their exact saved-run recovery.
The current policy Enabled state removes the device override, returning choice
to users without clearing their individual app preferences. Explain that
behavior rather than implying force-allow. Reset removes existing Disabled and
DisabledByUser values and must never run implicitly when the policy is removed.

Legacy EnableUWPBackgroundApps both removed the device policy and cleared those
current-user values; its reverse action was broader than a simple enable. The
separate reset preserves access to that behavior with explicit scope and prior
state capture. Keep it outside recommended composition until its actual effects
on current supported builds are verified; registry recovery alone does not
establish current app permission behavior.

Use the [focused policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy#letappsruninbackground)
for covered Windows apps, edition support, policy exceptions and the need to
restart an already-open app or device. Explain possible notification and email
sync effects without promising to stop every background process. Verify device
policy, per-app policy exceptions and user preferences together; do not assume
the policy reference documents the raw current-user reset mapping. This records
the accepted design and remaining acceptance, not a catalog or runtime change.

### SSDP/UPnP evidence review, 2026-10-10

The legacy selectors already controlled SSDPSRV and upnphost independently.
EnableSSDPdiscovery selected Manual and started SSDPSRV, whereas
EnableUniversalPlugAndPlay selected Manual with Start-Service commented out.
Both current catalog Enabled states select Manual and Running, so UPnP enable
has an additional runtime effect. Preserve published IDs and saved-run recovery;
resolve any revised state contract through an explicit reviewed migration.

Microsoft's [service descriptions](https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)
distinguish SSDP discovery/announcement from hosting UPnP devices on the computer.
That guidance is for Server 2016, not new acceptance of Windows 11 or Server
2025. Current [SystemServices policy documentation](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-systemservices#configuressdpdiscoveryservicestartupmode)
lists Manual as the startup default for both services, but does not establish
the catalog's Stopped or trigger-start assertions on each declared target.
The handler uses service commands, not these CSP policies; their applicability
must not be substituted for handler target acceptance.

Verify installed services, startup/runtime defaults, dependencies, dependent
service stop/start behavior, actual discovery/hosting and exact recovery on
supported disposable targets. Explain startup configuration separately from an
immediate start or stop; do not promise disabling all network discovery or
router UPnP. Review the existing default profile's blanket disabling separately
from service lifecycle evidence.

### Accepted SSDP/UPnP decision, 2026-10-10

The user accepted two separate advanced, opt-in controls: **SSDP device discovery
and announcements** and **Host UPnP devices on this computer**. Preserve
windows.ssdp-discovery-service and windows.upnp-device-host-service and their
saved-run recovery. Explain actual service effects and dependencies without
claiming to control all network discovery or router UPnP.

Distinguish startup configuration from immediate start/stop behavior. Resolve
the UPnP legacy/current enable mismatch described above through a reviewed
state/presentation migration rather than silently changing published Enabled
semantics. Verify actual defaults and dependencies on each declared target.
Reconcile the existing default profile's automatic disabling with the accepted
opt-in presentation during implementation; do not equate lifecycle evidence
with a general recommendation to disable either service. This records accepted
design and follow-up work, not a service, catalog or profile change.

### This PC folder evidence review, 2026-10-10

The Music and Videos This PC controls each manage two namespace registrations
inside one RegistryKeySet operation; 3D Objects manages one. These are one
folder outcome per operation, not separate user choices for registry entries.
The separately migrated shell-policy controls keep native/32-bit ThisPCPolicy
values together and must not be conflated with namespace registration or Home
pins. Preserve their existing IDs and exact recovery contracts.

Microsoft's [current Explorer guide](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows)
states that standard known folders, including Music and Videos, moved from This
PC to pinned Quick access/Home locations starting with Windows 11 22H2. This
does not establish whether the legacy namespace registrations still affect each
supported build. The namespace-extension reference documents registration
mechanics, not current acceptance of these exact folder entries. Test actual
This PC appearance, Home pins and native/32-bit file dialogs independently.

Legacy Show3DObjectsInExplorer removed both ThisPCPolicy overrides, whereas its
current shell-policy Visible state writes Show; WindowsDefault now preserves
the legacy reverse behavior. Retain that distinction in presentation. The This
PC Visible states create missing registration roots, rather than restoring a
captured subtree or asserting the Windows default. Verify mixed starting states,
typed values, subtree/security recovery, partial failure and preserved folder
contents. No catalog or runtime change is made by this evidence review.

### Accepted folder-visibility decision, 2026-10-10

The user accepted one control per folder and placement, with all registry entries
implementing that choice kept together. Retain the Music, Videos and 3D Objects
This PC operations and separate shell-policy operations as advanced legacy
controls pending current feature verification. Keep their stable IDs and exact
recovery, and hold unverified controls outside recommended composition.

Descriptions must distinguish This PC registration, experimental shell-policy
preferences and Home/Quick access pins. Hiding an entry preserves the physical
folder and contents; do not claim that registering a key guarantees current
Explorer visibility. Verify the effects and reverse-state distinctions in the
preceding evidence review, including native/32-bit dialogs and mixed starting
states. Apply the same per-folder/per-placement design to the other migrated
known-folder controls. This records design and acceptance follow-up only.

### Accepted power-controls decision, 2026-10-10

The user accepted separate **When plugged in** and **On battery** controls for
lid actions and applicable timeouts, with **Active power plan** selection kept
separate. Retain the existing operation IDs and exact recovery contracts.
Changing one individual preference affects its selected AC/DC value in the
active scheme, not every plan or the other power source.

When a selection combines power-plan activation and individual preferences,
activate the chosen existing plan first, then apply its preferences. Preview
must identify the affected scheme and ordering. Coordinate snapshot capture
with that ordering so each value is recovered to the scheme actually changed;
restore the saved active-plan selection separately and use reverse dependency
order for recovery. Verify plan changes, mixed AC/DC values and intervening plan
switches without altering unrelated plans or inventing absent schemes.

Balanced/High Performance selection is currently implemented for existing plans;
creation and Ultimate Performance remain deferred. Hardware capability, managed
policy, unsupported indexes and actual lid/suspend/timeout behavior still require
acceptance on representative disposable targets. Saved powercfg equality alone
does not prove those effects. This records the accepted design; coordinated
planning, presentation and feature verification remain follow-up work.

### Accepted Control Panel view decision, 2026-10-10

The user accepted one combined **Control Panel opening view** control with
**Category**, **Large icons**, **Small icons** and **Use Windows default** choices.
Keep StartupPage and AllItemsIconView together inside windows.control-panel-view
and preserve its stable ID, published states and exact per-value recovery.

Explain the reverse-state distinction: legacy SetControlPanelCategories removed
both overrides, reproduced by WindowsDefault; current Categories writes explicit
0 values. Do not describe override removal as forcing the Category view or
silently replace one behavior with the other. Improve presentation names and
individual state descriptions while retaining the existing state identifiers.

The current Microsoft reference documents general Control Panel implementation,
not these exact preference mappings. Verify actual opening view for each state,
reopening/refresh, mixed prior values and exact restoration on supported builds.
This records the accepted design and future acceptance work, not a catalog or
runtime change.

### Accepted mouse-precision decision, 2026-10-10

The user accepted one combined **Enhance pointer precision** control, keeping
MouseSpeed and both mouse thresholds together inside
windows.mouse-pointer-precision. Preserve its stable ID, states and exact
per-value saved-run recovery; leave unrelated pointer speed, other mouse
preferences and touchpad-driver configuration unchanged.

Explain that Enabled applies the legacy preset 1/6/10 and Disabled applies
0/0/0. Enabling is not restoration of a customized prior configuration.
WindowsDefault removes all three overrides; saved-run restore recovers each
actual previous value and type, including custom thresholds. Keep these
workflows distinct in descriptions and plans.

Use the [mouse settings guide](https://support.microsoft.com/en-us/windows/hardware/input-devices/change-mouse-settings)
for the user-visible feature and the existing SystemParametersInfo reference
for acceleration/threshold API behavior. Neither establishes that direct
registry writes immediately update the current Windows UI or pointer behavior.
Verify the UI, actual acceleration, refresh/sign-in requirements, customized
starting states and unchanged unrelated preferences on disposable supported
targets. This records accepted design and remaining acceptance, not a handler
change or new runtime evidence.

### UAC prompt evidence review, 2026-10-10

Legacy SetUACLow wrote ConsentPromptBehaviorAdmin=0 and
PromptOnSecureDesktop=0; SetUACHigh wrote 5 and 1. The combined
windows.uac-admin-consent operation preserves those pairs. Microsoft's
[focused configuration reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)
defines 5 as consent for non-Windows binaries, not the strictest always-prompt
setting. NoPrompt permits administrator elevation without consent; neither
state changes EnableLUA or creates an elevated RIDE process.

Correct the current description's broad assertion that standard-user elevation
does not change: ConsentPromptBehaviorUser remains untouched, but the secure
desktop preference affects where both administrator and standard-user prompts
appear. Verify both account scenarios and managed-policy precedence on a
disposable target. Keep WindowsDefault override removal distinct from writing
the documented default values or recovering a saved state. The GUI-aligned
presentation decision is recorded below; this is reference evidence, not
permission to alter host consent or a catalog/runtime change.

### Accepted GUI-aligned UAC decision, 2026-10-10

The user accepted one combined control but requested that its choices match the
four positions of the classic Windows UAC dialog, supplying screenshots of each.
The screenshots and Microsoft client guide identify the third position from the
bottom (second from the top) as default. The user explicitly requested testing
that position on both Windows 11 and Windows Server; target defaults remain
unverified rather than being inferred from those screenshots.
Use **User Account Control notification level** as the presentation name and
GUI-aligned labels/descriptions, rather than Low/High or Enable/Disable UAC.

| GUI position from bottom | User-facing choice | ConsentPromptBehaviorAdmin | PromptOnSecureDesktop |
| --- | --- | --- | --- |
| 4 | Always notify | 2 | 1 |
| 3 | Notify only when apps make changes (default) | 5 | 1 |
| 2 | Notify only when apps make changes (do not dim desktop) | 5 | 0 |
| 1 | Never notify | 0 | 0 |

Microsoft's [UAC dialog guide](https://support.microsoft.com/en-us/windows/security/user-account-control-settings)
documents these four user-visible choices. Its
[configuration reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)
documents the policy values used in the intended mapping above. Verify each
pair against the actual slider and administrator/standard-user prompt scenarios
on supported disposable Windows targets before claiming functional acceptance.
Keep EnableLUA and ConsentPromptBehaviorUser unchanged; explain the separate
secure-desktop effect on standard-user prompt location and managed-policy limits.

Required default-level acceptance on disposable Windows 11 and Windows Server
2025 with Desktop Experience:

- Before any setting change, record the clean image's literal registry values,
  absence, slider position, account type, edition/build and applicable policy.
  Distinguish an image's initial configuration from Microsoft's documented
  default; do not infer that clients and servers share an identical setup.
- Confirm whether selecting the third-from-bottom GUI position produces 5/1
  and whether explicitly applying 5/1 selects that position on each target.
- Exercise an administrator consent prompt for a non-Windows executable and
  Windows-setting changes, plus standard-user credential prompts and secure
  desktop behavior. Record relevant built-in Administrator/Admin Approval Mode
  differences rather than treating an absent prompt as successful acceptance.
- Verify exact restoration of the prior values and GUI/prompt behavior. Keep
  registry lifecycle results separate from these interactive feature checks.

Both platforms remain pending for this default-level feature acceptance. The
current operation declares Windows 11 only; testing Server does not expand that
support declaration until its applicable acceptance checks pass. This review
records required tests; it does not start a VM run or alter host UAC settings.

Retain windows.uac-admin-consent and existing state/recovery contracts. Preserve
SecureConsent=5/1 and NoPrompt=0/0, using the corresponding GUI labels; add the
two missing GUI levels through reviewed state additions. Selecting the displayed
default explicitly writes 5/1. Existing WindowsDefault removes the two overrides
and should be presented separately as **Remove RIDE overrides**, an advanced
maintenance choice outside the four slider levels. Do not silently redefine it
to write 5/1 or imply removal guarantees the slider's default state. Saved-run
restore remains a separate workflow recovering actual prior values and types.

Explain the security tradeoffs using GUI wording, keep lowering notification
protection opt-in, and do not add it implicitly to recommended profiles. The
legacy RIDE selectors covered only the bottom and default levels, despite the
Windows dialog having four. This records the accepted revised design;
implementation and prompt/UI acceptance remain follow-up work. No host UAC,
catalog or profile setting is changed by this review.

### Fullscreen-optimization evidence review, 2026-10-10

The four GameConfigStore values in windows.fullscreen-optimizations reproduce
the legacy DisableFullscreenOptims/EnableFullscreenOptims presets as one
coordinated operation. Enabled writes three zeros and removes GameDVR_FSEBehavior;
WindowsDefault removes all four overrides. Neither is exact prior-state restore.
Keep the existing ID and state/recovery contracts; current feature acceptance
is not established by successful registry round trips.

Microsoft's [fullscreen-optimization explanation](https://devblogs.microsoft.com/directx/demystifying-full-screen-optimizations/)
describes the fullscreen feature and the per-executable Compatibility checkbox
Disable fullscreen optimizations. It is a more focused behavior reference than
the current catalog link, but does not document these four registry values or
prove a global equivalent to that checkbox on current Windows 11.
The [windowed-game optimization guide](https://support.microsoft.com/en-us/windows/hardware/display-graphics/optimizations-for-windowed-games-in-windows-11)
describes a separate Windows 11 graphics preference for compatible DirectX 10/11
windowed and borderless games. Do not map the legacy operation to that GUI
switch, Game Mode or recording preferences simply because the names overlap.

Carry forward the user's preference for GUI-aligned settings: any verified
normal control must identify the actual GUI feature, affected executable or
global scope and current build applicability. A replacement requires reviewed
migration rather than silently repointing the existing operation. Compare
representative games, fullscreen/windowed modes, GUI choices, restart behavior
and actual presentation effects; performance benefits must be measured rather
than inferred. The legacy bundle remains experimental and outside recommended
profiles pending that evidence. This records findings for the next design
decision; no catalog, profile or runtime change is made.

### Accepted fullscreen-optimization decision, 2026-10-10

The user accepted retaining windows.fullscreen-optimizations as one advanced
experimental control, with all four legacy values kept together and excluded
from recommended profiles until current effects are verified. Preserve the
stable ID, published preset states and exact saved-run recovery.

Treat the per-executable Disable fullscreen optimizations checkbox and Windows
11 Optimizations for windowed games as distinct GUI features. Neither mapping
is established by the existing registry bundle. Any normal GUI-aligned control
requires verified scope, current-build behavior and reviewed implementation;
do not silently redirect the existing ID. Improve the feature reference using
the fullscreen explanation while stating that it does not document the four
values. Follow the preceding evidence review for game/restart/presentation
acceptance. This records design, not a catalog or runtime change.

### Visual-effects evidence review, 2026-10-10

Legacy SetVisualFXPerformance/SetVisualFXAppearance changed eight separately
migrated preferences alongside UserPreferencesMask and VisualFXSetting. The
individual operations cover dragging contents, menu delay, minimize/restore
animation, keyboard repeat delay, selection-rectangle translucency, desktop
label shadows, taskbar animation and Peek. Both legacy presets also wrote the
same VisualFXSetting=3; their names do not establish equivalence to the Windows
dialog's Best performance/Best appearance radio choices.

Microsoft's [performance guide](https://support.microsoft.com/en-us/windows/experience/performance-optimization/tips-to-improve-pc-performance-in-windows)
describes the Visual Effects dialog. Match individual controls to verified GUI
checkboxes and preserve unrelated effects; do not claim that selecting the
currently migrated preferences reproduces a complete Windows or legacy preset.
Packed-mask changes and whole-preset composition remain deferred pending current
bit meanings, dependencies, exact typed recovery and actual visual acceptance.
Taskbar animation and Peek need current-build feature evidence before normal
presentation or recommended composition.

Menu opening delay and keyboard repeat delay are independently useful timing
preferences and should be reviewed separately from appearance composition.
KeyboardDelay is already String in the current catalog, correcting the legacy
DWORD write; verify native GUI representation and typed prior-state recovery.
Its two current non-default states cover only indexes 0 and 1, while the
[documented API](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow)
supports four repeat-delay positions, 0 through 3. Consider GUI-aligned complete
choices through reviewed state additions, retaining existing IDs and states;
repeat delay is distinct from repeat speed. Verify actual effects and refresh
requirements without signing out or restarting the host. This records findings,
not an accepted new design or a catalog/runtime change.

### Accepted visual-effects decision, 2026-10-10

The user accepted independently useful effects presented through verified Windows
GUI checkbox names, with keyboard repeat delay and menu opening delay retained as
separate timing preferences. Keep taskbar animation and Peek experimental and
outside recommended profiles until their current-build behavior is established.
Defer a complete performance/appearance preset and packed-mask composition until
the entire mapping is understood; the legacy presets do not establish equivalence
to the Windows radio choices.

Preserve published IDs, existing state meanings and exact typed saved-run recovery,
including custom, absent and mixed prior values. Review additional keyboard-delay
states against all four GUI slider positions without confusing delay with speed.
Acceptance must verify GUI mapping, actual effects, dependencies and refresh in
disposable Windows environments; registry round trips alone are insufficient.
This records design, not catalog/profile implementation or runtime acceptance.

### Defender cloud and sample-submission evidence review, 2026-10-10

Legacy DisableDefenderCloud wrote SpynetReporting=0 and SubmitSamplesConsent=2
together; EnableDefenderCloud removed both overrides. The migrated
windows.defender-cloud-membership and windows.defender-sample-submission keep
these outcomes separately selectable. Preserve their published IDs, state
meanings and exact typed recovery; removing overrides is distinct from forcing
cloud protection or automatic submission on.

Use the GUI areas Cloud-delivered protection and Automatic sample submission
under Windows Security > Virus & threat protection > Manage settings as the
normal presentation. Microsoft's [configuration guide](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure)
states that Basic and Advanced reporting are equivalent on Windows 10/11 and
that managed policy can disable local GUI editing. Present the existing Advanced
cloud state as the enabled preference without suggesting a separate protection
strength. The cloud-blocking level is a different setting and is not migrated
by this operation. Verify the policy-to-GUI mapping before claiming equivalence.

The [sample-submission policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent)
documents four values: always prompt (0), send safe samples automatically (1),
never send (2) and send all samples automatically (3). Retain these explicit
policy choices with clear explanations; verify how each appears against the
GUI toggle instead of assuming every non-automatic choice means the same Off
behavior. Keep override removal separately described. The [sample analysis
guide](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission)
explains that safe-sample submission can still prompt for potentially personal
files, metadata can be sent with sample submission disabled, and never sending
samples disables sample-based block at first sight. Recovery cannot retract
previously submitted data.

Acceptance needs disposable Windows testing of the GUI, effective Defender
preferences, active/passive provider state, managed-policy precedence and tamper
protection. A registry write or round trip does not prove enforcement. Report
blocked or ineffective changes clearly; do not disable tamper protection or
submit test files implicitly. No Server support expansion is established by
these Windows 11 operations. This records evidence and a proposed design, not
an accepted decision, implementation or runtime acceptance.

### Accepted Defender cloud and samples decision, 2026-10-10

The user accepted separate GUI-named Cloud-delivered protection and Automatic
sample submission controls, with all four explicit sample-submission policy
choices retained and explained. Preserve the published IDs, state meanings,
override-removal distinction and exact saved-run recovery. GUI mapping and
effective protection remain acceptance work described above.

The user additionally required clearly visible license, account and membership
requirements for the existing Advanced state. Future catalog descriptions and
generated operation documentation must explain the following next to that
choice, rather than leaving readers to interpret the word membership:

- Advanced is the legacy Microsoft Active Protection Service (MAPS) reporting
  label for enabled cloud protection, not a premium protection or paid membership
  tier. Basic and Advanced have the same effect on Windows 11.
- Standalone cloud protection is part of built-in Windows Security/Defender
  Antivirus on Windows 11. No separate Microsoft 365 or Defender for Endpoint
  subscription is required for that built-in setting. This conclusion follows
  from Microsoft's [home-security guidance](https://support.microsoft.com/en-us/security/keep-your-computer-secure-at-home)
  explicitly including cloud protection in Windows Security and the local
  configuration procedures. It does not grant subscription-based enterprise
  features or management rights. The separately licensed [Microsoft Defender
  consumer app](https://support.microsoft.com/en-us/defender/getting-started-with-microsoft-defender)
  is a different product boundary.
- Microsoft's local [configuration procedures](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-configure)
  list no Microsoft-account sign-in, separate membership registration or Defender
  for Endpoint onboarding step for this setting. Treat the absence of an account
  requirement as an inference from those procedures; verify with a local-account
  Windows 11 VM without Microsoft 365/Endpoint enrollment before final acceptance.
  Selecting the state configures device participation in MAPS; RIDE must not
  create an account or enroll the device into a paid service.
- Cloud protection needs operational Defender Antivirus and [connectivity to
  Microsoft's cloud endpoints](https://learn.microsoft.com/en-us/defender-endpoint/configure-network-connections-microsoft-defender-antivirus).
  Changing this machine policy requires elevation; tamper protection and managed
  policy can block or override it. Show configured preference and effective
  availability separately when Defender is inactive or connectivity is absent.

Microsoft's enterprise configuration guide also contains subscription tables for
Defender for Endpoint capabilities. Do not present those enterprise entitlements
as requirements of the standalone Windows toggle or promise them by setting
Advanced. Keep enterprise licensing and optional management enrollment separate.
This records the accepted design and required wording; catalog implementation,
generated-document refresh and disposable-VM acceptance remain pending. No host
setting, subscription or account is changed by this review.

### SmartScreen, web search and Security icon evidence review, 2026-10-10

These are three separate user outcomes. Retain their published IDs and exact
saved-run recovery; do not compose them into a general security/privacy switch.
The following is proposed design, pending the user's decision and feature
acceptance. No catalog, profile or Windows state changes are made by this review.

For windows.smartscreen-shell-policy, prefer the Windows Security name Check
apps and files (SmartScreen), under App & browser control > Reputation-based
protection settings. Microsoft's [GUI explanation](https://support.microsoft.com/en-us/windows/security/windows-security/app-browser-control-in-the-windows-security-app)
identifies the downloaded-app/file reputation toggle; the [Shell policy
reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-smartscreen#enablesmartscreeninshell)
documents EnableSmartScreen at the catalog's path. Explain that this is machine
policy for that GUI area, with possible managed presentation, rather than a
literal user-preference toggle. Enabled and Disabled are explicit values;
WindowsDefault removes the override, matching legacy EnableSmartScreen for the
Shell portion. Preserve browser SmartScreen, Store-app checks, Smart App Control,
antivirus and existing warning-override policy as separate boundaries. Legacy
EdgeHTML EnabledV9 writes stay deliberately omitted; do not redirect them to
Chromium Edge silently. Prefer the Security category in future presentation.
Verify the actual GUI and safe downloaded-file reputation behavior, policy
precedence, refresh and applicable editions before recommending this control.

For windows.search-web-policy, keep an advanced legacy web-search policy outside
recommended profiles pending current-build evidence. Its current
policy-csp-search#disablewebsearch reference has no matching section/value in
the page read during this review. Replace that reference during implementation
with Microsoft's [Cortana and Search policy mapping](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services#21-cortana-and-search-group-policies),
which directly lists DisableWebSearch=1 as Do not allow web search. This is not
evidence of a universal Windows 11 Bing-results switch: the guide discusses
Server/Enterprise, legacy Cortana and further network controls. The current
[DoNotUseWebResults policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-search#donotusewebresults)
uses ConnectedSearchUseWeb, a different value, and excludes Pro in its CSP
applicability table. Do not substitute this mapping under the stable ID or
transfer its edition table to the existing registry control without evidence.

GUI-aligned search control also requires region/build review: Microsoft's
[web-search provider documentation](https://learn.microsoft.com/en-us/windows/apps/develop/search/search-providers)
describes enabling/disabling installed providers in Settings in the EEA. That
provider choice is not established as the DisableWebSearch mapping. Keep cloud
content search, highlights, browser search and local indexing distinct. The
omitted BingSearchEnabled and CortanaConsent values remain explicit partial
legacy coverage: legacy enable removed DisableWebSearch but wrote CortanaConsent=1.
Allowed=0 is not override removal. Verify real local/web results, provider GUI,
query behavior, managed policy, edition and region before proposing a normal
replacement; retain existing recovery and review migration separately.

For windows.security-notification-icon, retain a focused Windows Security tray
icon policy. The [exact policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsdefendersecuritycenter#hidewindowssecuritynotificationareacontrol)
maps HideSystray and specifies sign-out/sign-in or reboot for effect. Make that
refresh requirement visible in future descriptions/plans; do not restart or
sign out automatically. Hidden=1 and Shown=0 are explicit policy states;
WindowsDefault removes the override, matching the policy portion of legacy show.
Legacy startup-entry deletion/creation stays omitted. Do not promise Shown will
repair a missing or disabled startup process, and do not equate hiding the icon
with disabling Defender protection or all notifications. Verify icon appearance
after the documented refresh, startup-disabled cases, policy precedence and
unchanged protection/notification settings on disposable Windows targets.

### Accepted SmartScreen, web search and Security icon decision, 2026-10-10

The user accepted separate controls: GUI-named Check apps and files (SmartScreen)
for the Shell policy, an advanced legacy web-search policy pending current-build
mapping, and a focused Windows Security tray icon policy. Keep the web-search
control outside recommended profiles until effective behavior is verified.
Preserve published IDs, existing states, explicit-value versus override-removal
semantics and exact saved-run recovery.

Follow the preceding evidence review for correcting the missing web-search
reference, region/edition/provider acceptance, SmartScreen feature boundaries
and the icon's documented sign-out/sign-in or reboot requirement. Keep obsolete
EdgeHTML and legacy startup-entry mutations deliberately omitted and visible as
partial coverage. Do not silently remap IDs or restart/sign out a user. This
records accepted design; implementation and Windows feature acceptance remain
pending.

### Hardware clock and automatic network-device setup evidence review, 2026-10-10

Keep these as two separate advanced experimental preferences outside recommended
profiles pending current-build evidence. Preserve windows.hardware-clock-time-basis
and windows.network-device-auto-setup, their published states and typed saved-run
recovery. Neither legacy selector pair split one feature into multiple controls.
This is a proposed disposition, not an accepted design or runtime change.

The hardware-clock operation retains RealTimeIsUniversal: UTC writes DWORD 1,
Local writes DWORD 0 and WindowsDefault removes the override. Legacy
SetBIOSTimeLocal removed the value, so WindowsDefault preserves that reverse
behavior; Local is an explicit preference. Explain the intended choice as how
Windows interprets the hardware real-time clock, primarily for reviewed dual-boot
configuration, rather than claiming it sets firmware time directly. Do not map
it to Set time automatically, time-zone selection or a UTC display setting.
Microsoft's [System Time reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/system-time)
explains system-time behavior, not this registry preference. A [historical
Microsoft AskDS warning](https://techcommunity.microsoft.com/blog/askds/unresponsive-servers-due-to-dst-and-an-unsupported-registry-key/399923)
identified RealTimeIsUniversal as undocumented/unsupported and discussed DST
failures. Its historical scope does not establish Windows 11 support or a current
failure on that target; do not omit this evidence or infer that a registry round
trip resolves it. No current Microsoft-supported GUI mapping was established in
this review.

Acceptance must evaluate restart/cold boot, suspend/resume, time-zone/DST changes,
both operating systems in the intended dual-boot configuration, and interference
from Windows Time or hypervisor time synchronization. Confirm actual clock
interpretation rather than allowing synchronization to conceal a wrong result.
Registry restore recovers the preference, not an earlier physical clock reading
or another OS's configuration. A Windows-only VM cannot establish all dual-boot
or physical RTC behavior. Do not change the workstation's clock or add Server
support based on this review.

The network-device operation retains AutoSetup under NcdAutoSetup\Private:
Disabled writes DWORD 0, Enabled writes DWORD 1 and WindowsDefault removes the
override, matching legacy EnableNetDevicesAutoInst. Prefer a normal GUI name
such as Set up network connected devices automatically only after verifying its
exact current Settings checkbox and bidirectional registry mapping on Windows
11. Keep the present experimental designation until then. Automatic setup is
distinct from device discovery, network profile selection, file/printer sharing,
driver-update policy and device removal; do not alter those implicitly.

The current generic File Explorer reference is too broad. Microsoft's [network
setup guide](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/set-up-your-small-business-network)
mentions automatic device setup but includes older UI instructions. Microsoft's
[NcdAutoSetup service explanation](https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/optimize/services)
is a more focused feature reference: the service discovers/installs qualified
network devices and manual addition remains separate. It does not document the
AutoSetup value, and its IoT service-disabling guidance is not approval to change
services on every Windows edition. Improve the catalog reference with that
qualification during implementation; do not claim Microsoft verifies the value.

Acceptance needs an isolated private test network with a suitable discoverable
device, comparing automatic setup and manual addition with the checkbox both
ways. Record current services, discovery/firewall prerequisites, refresh and
private/public behavior without silently enabling them. Distinguish discovered
entries from installed devices and preserve existing devices. Restoring the
preference cannot undo device installations that already occurred; test any
cleanup separately in the disposable environment. Keep both explicit/default
states and exact prior registry recovery distinct from these external effects.

### Accepted hardware-clock and network-device setup decision, 2026-10-10

The user accepted two separate advanced experimental preferences outside
recommended profiles until current behavior is verified. Preserve published IDs,
state meanings, exact saved-run recovery and explicit Local/Enabled versus
legacy override-removal distinctions. Use the network-device GUI name only
after verifying the current checkbox and registry mapping.

Follow the preceding evidence review for historical hardware-clock support
concerns, actual RTC/restart/DST/dual-boot acceptance, a more focused network
feature reference, and isolated actual device-setup tests. Explain registry
recovery separately from physical clock or installed-device side effects. This
records accepted design; catalog implementation and functional acceptance remain
pending, with no workstation clock/network changes or Server support expansion.

### Service startup and delayed-start evidence review, 2026-10-10

Review windows.telemetry-service (DiagTrack), windows.wap-push-service
(dmwappushservice), windows.sysmain-service (SysMain) and
windows.search-indexing-service (WSearch) as separate advanced service controls.
Prefer current Services display names with service IDs alongside them; do not
group them as one telemetry/performance switch. Startup type and current runtime
state are separate concepts in the Services GUI. Proposed future presentation
offers Automatic, Automatic (Delayed Start), Manual and Disabled where supported,
with an explicit, separately described start/stop-now choice. Preserve existing
combined states as published presets; do not silently change their behavior or
claim selecting Automatic alone starts a service immediately.

Current Disabled means Disabled startup plus Stopped; AutomaticRunning means
Automatic startup plus Running while preserving the existing DelayedAutoStart
value. Consequently AutomaticRunning does not guarantee the GUI's non-delayed
Automatic choice. Get/status/plan should expose both effective delay and runtime
state instead of hiding that distinction. Legacy EnableWAPPush and EnableIndexing
set Automatic, start the service and explicitly write DelayedAutoStart=1; the
current catalog omits that deliberate delay override. Reconcile this partial
coverage with reviewed explicit delayed-start states, retaining published IDs,
states and recovery; do not redefine AutomaticRunning to erase or force a delay.

The [Microsoft delayed-start API reference](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info)
explains that the flag matters only for automatic services, takes effect at next
system start, and does not guarantee a fixed startup time. An explicit start
request can start the service without waiting for the boot delay. Treat automatic
versus delayed automatic as one coordinated service configuration, using the
supported service-manager interface for new behavior rather than a competing raw
registry operation. Keep dormant flags for Manual/Disabled unless a reviewed
choice deliberately changes them. Verify SCM effective configuration alongside
literal registry preservation, including custom types/absence and compatibility
with saved snapshots predating the delay field.

Windows defaults cannot be represented by simply removing a service registry
value. AutomaticRunning is the current explicit RIDE baseline, not a factory
Windows default. Retain separate exact saved-run restore and documented,
target-specific baseline application. Verify literal/effective defaults on clean
images per edition/build; a missing service is unavailable/error, not a successful
apply or fabricated default. Manual may still start on demand/through triggers;
Stopped is an observation or immediate action, not proof it will remain stopped.

Descriptions must show individual effects and dependencies. Microsoft's [Intune
sync troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-management/cannot-sync-windows-10-devices)
identifies disabling dmwappushservice as a management/sync failure cause; its
Windows 10 scope is not a completed Windows 11 workload test. Windows Search
affects [indexed search](https://support.microsoft.com/en-US/Windows/Experience/Performance-Optimization/search-indexing-in-windows),
not the web-search setting or index deletion. Disabling DiagTrack is not a zero
telemetry guarantee, and disabling SysMain is not an established general speed
improvement. The existing shared [service reference](https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)
targets Server 2016 Desktop Experience. Prefer focused current feature references
in future metadata, qualifying edition-specific background such as Microsoft's
[IoT service guidance](https://learn.microsoft.com/en-us/windows/iot/iot-enterprise/optimize/services).
No broad service-disable recommendation follows from those edition-specific lists.

Keep service changes advanced and opt-in. Acceptance must verify the Services
GUI, actual SCM startup/delay, reboot scheduling, explicit runtime actions,
trigger/dependency behavior, managed-device sync and actual indexed search in
disposable applicable Windows environments. Test repeat apply and exact recovery
of Automatic/Manual/Disabled, delayed/absent flags, Running/Stopped and supported
Paused cases; report unsupported states and partial failures rather than claiming
success. Do not stop dependent services implicitly or restart the workstation.
This records evidence and proposed design; user acceptance, catalog/handler
implementation and runtime verification remain pending.

### Accepted service startup and runtime decision, 2026-10-10

The user accepted separate advanced, opt-in service controls, with GUI-aligned
startup choices (Automatic, Automatic (Delayed Start), Manual and Disabled where
supported) and explicit runtime actions described separately. Preserve published
IDs and combined presets, including AutomaticRunning's existing delay-preservation
semantics; add reviewed explicit delayed-start choices to reconcile partial WAP
Push/Search legacy reverse behavior instead of redefining the existing state.

Follow the preceding review for effective delay/status presentation, coordinated
SCM configuration, next-boot scheduling, platform defaults versus RIDE baselines,
managed-device dependencies and focused references. Retain exact saved-run recovery
and compatibility with older snapshots. Test GUI/startup/runtime, actual workloads,
triggers and partial failures in disposable Windows environments. This is accepted
design; catalog/handler implementation and functional acceptance remain pending.

### Sleep button, menu visibility and timeout evidence review, 2026-10-10

Extend the accepted power-controls design with separate GUI-aligned outcomes for
the hardware sleep button, Sleep menu visibility, screen-off timeout and sleep
timeout. Keep When plugged in and On battery independent and retain the accepted
active-plan ordering, scheme-specific capture and reverse recovery. This is a
proposed refinement, not an accepted new decision or catalog/runtime change.

Legacy DisableSleepButton/EnableSleepButton changed ShowSleepOption plus both
SBUTTONACTION indexes. Retain windows.sleep-menu-option separately from
windows.sleep-button-action-ac/dc: hiding a menu entry does not disable hardware
buttons or idle sleep, and a button action does not determine menu visibility.
Legacy enable explicitly wrote ShowSleepOption=1 and button indexes=1; it did
not remove these overrides. Preserve current published states and stable IDs.
Microsoft's [sleep-button reference](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action)
documents Do nothing (0), Sleep (1), Hibernate (2) and Shut down (3). Add the
missing button choices only through reviewed states and capability checks,
matching the current applicable GUI. The dedicated sleep button is distinct from
the power button and lid. Do not enable hibernation or manufacture absent indexes
to make a choice appear available. The previous VM lacked both sleep-button
indexes; those two unavailable operations still lack lifecycle/physical acceptance.

Use a focused menu-visibility reference instead of the current button-action page.
The [Show sleep in the power options menu policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer#showsleepoption)
describes the visible effect and hardware dependency, but maps a different path
(Software\Policies\Microsoft\Windows\Explorer) from the catalog's legacy
Explorer\FlyoutMenuSettings preference. Qualify it as behavior/policy background,
not documentation of the migrated value. Keep the legacy menu preference advanced
and outside recommended profiles until verified against the current Power Options
checkbox and Start power menu, with managed-policy precedence and refresh recorded.
Do not replace its path or reinterpret WindowsDefault under the published ID.
Override removal is distinct from explicitly showing the entry and cannot create
hardware sleep support.

Present windows.display-idle-timeout-ac/dc and windows.sleep-idle-timeout-ac/dc
as Turn my screen off after and Make my device sleep after, with the power source
clearly visible. Microsoft's [Windows 11 power-settings guide](https://support.microsoft.com/en-us/windows/experience/power-battery/power-settings-in-windows-11)
locates these choices under Screen, sleep, & hibernate timeouts. Current catalog
states cover Never plus just one legacy duration each: screen 10 minutes plugged
in / 5 minutes battery, sleep 30 minutes plugged in / 15 minutes battery. These
are legacy preset values, not Windows defaults. Propose reviewed additional GUI
durations and a validated custom duration without changing existing states or
silently rounding custom live values.

The [display](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-display-idle-timeout)
and [sleep](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout)
index references use seconds and define 0 as Never for their respective idle
timers; legacy powercfg /change used minutes. Validate range and conversion while
showing understandable durations and retaining the exact captured index. Never
idle sleep does not disable manual/button/lid sleep or all other power transitions.
Screen-off and sleep remain independently selectable; do not silently change one
to enforce the other. Keep hibernation timers, display brightness, sign-in/lock
timeouts and power-mode settings as separate outcomes.

Acceptance must compare the relevant GUI and effective active-scheme indexes,
then prove actual screen-off, idle sleep/resume and button/menu effects on
representative disposable hardware. Microsoft's [idle-timer explanation](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers)
distinguishes traditional S3 sleep from Modern Standby; record the platform's
power capabilities, battery presence and blocking requests/policy instead of
declaring a saved value proof of suspend behavior. Report missing capabilities
or indexes as Unavailable; do not hide them as successful tests. Verify mixed
AC/DC choices, custom indexes, existing plan switches and exact recovery to the
scheme actually changed. Do not suspend, shut down or restart the workstation.

### Accepted sleep-button, menu and timeout decision, 2026-10-10

The user accepted separate GUI-aligned controls for the dedicated sleep-button
action, screen-off timeout and device-sleep timeout, with independent When plugged
in and On battery choices. Add reviewed supported button actions and GUI/custom
durations while preserving published IDs, states and exact recovery. Retain the
accepted active-plan ordering and recovery to the scheme actually changed.

Keep Sleep menu visibility separate and advanced outside recommended profiles
until current checkbox mapping is verified. Improve its feature reference while
qualifying the different policy path. Missing hardware/indexes remain Unavailable;
do not enable hibernation, create capabilities or change another preference
implicitly. Follow the preceding review for current GUI, actual suspend/menu/
timeout effects, S3/Modern Standby and exact custom-state acceptance on disposable
targets. This records accepted design; implementation and runtime acceptance
remain pending.

### BitLocker preferences and memory integrity evidence review, 2026-10-10

Propose a separate GUI-aligned Memory integrity control and advanced BitLocker
policy controls whose names match the applicable Group Policy dialogs. These
are different features with different prerequisites. Preserve published IDs,
states and typed recovery; this is proposed design, not functional acceptance.

Memory integrity belongs under Windows Security > Device security > Core
isolation details. Microsoft's [device-security guide](https://support.microsoft.com/en-us/windows/security/windows-security/device-security-in-the-windows-security-app)
describes its On/Off control, firmware virtualization and incompatible drivers.
The existing windows.memory-integrity-request writes only Enabled in the
HypervisorEnforcedCodeIntegrity scenario. Microsoft's [enablement reference](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#enable-memory-integrity-using-registry)
also documents VBS/platform-security and lock configuration. Do not silently
expand this ID to write those values, change firmware/UEFI locks or remove
drivers. A normal GUI-aligned control requires readiness and precedence checks,
with any additional provisioning explicitly reviewed and separately captured.
Keep the request outside recommended profiles until that acceptance is complete.

Show configured request, effective protection and restart requirement separately.
The same reference distinguishes Win32_DeviceGuard SecurityServicesConfigured
from SecurityServicesRunning and VirtualizationBasedSecurityStatus; saving 1 is
not proof that HVCI is running. Validate supported hardware/VM configuration,
driver compatibility, managed policy and existing locks. Use the built-in feature
without inventing an account/membership requirement; separately explain any
optional licensed enterprise-management service and verify the local-account
workflow. Do not claim a successful restore bypasses an existing UEFI lock.

Legacy EnableCIMemoryIntegrity wrote this scenario's Enabled=1, but
DisableCIMemoryIntegrity removed Enabled. Thus WindowsDefault preserves that
reverse behavior; explicit Disabled=0 is a different choice and override removal
does not guarantee Off on a platform that enables protection by default. The
older EnableMemoryIntegrity/DisableMemoryIntegrity pair used a different value
directly under Scenarios. Record that discrepancy for reconciliation; do not
copy that mapping or claim both pairs are covered without current evidence.

Present windows.bitlocker-enhanced-pin as Allow enhanced PINs for startup in
advanced policy views. Microsoft's [focused policy reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure#allow-enhanced-pins-for-startup)
permits nonnumeric characters and calls for a preboot hardware check. The
policy does not create/change a protector or existing PIN. Replace the legacy
interactive keyboard comparison with visible prerequisites and representative
preboot testing; installed Windows language alone does not prove usable input.
Legacy EnableEnhancedPIN/DisableEnhancedPIN explicitly wrote 1/0, distinct from
removing the policy override. Retain those distinctions and exact recovery.

windows.bitlocker-additional-startup-auth changes only UseAdvancedStartup, one
gate within [Require additional authentication at startup](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure#require-additional-authentication-at-startup).
The full dialog also chooses permitted/required TPM, PIN and startup-key methods.
Keep the partial gate advanced and describe its coverage. A future complete
control should match that one policy dialog with validated option combinations,
not present unexplained registry values as independent protection benefits.
Changing policy is distinct from enrolling TPM+PIN. The legacy reverse function
is named DisableAdditionaAuthAtStart and explicitly writes UseAdvancedStartup=0;
reconcile that omitted selector in the migration ledger without renaming IDs.

Review windows.bitlocker-encryption-method alongside these preferences. It uses
the old EncryptionMethod value, with explicit 3/4 states; legacy AES128 is not
the current Windows default. Read-only inspection of the installed Microsoft
VolumeEncryption.admx/adml identifies separate older EncryptionMethod,
EncryptionMethodNoDiffuser and modern EncryptionMethodWithXtsOs/Fdv/Rdv policies.
The modern policy help describes fallback to older cipher-strength policies.
Therefore neither ignore the old value nor promise that it enforces AES-CBC on
Windows 11 without acceptance. Record ADMX version/build and test precedence.

Propose the modern [Choose drive encryption method and cipher strength](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/configure#choose-drive-encryption-method-and-cipher-strength)
dialog as a future advanced control with independent drive-type choices in one
policy presentation. Method changes concern future encryption, not conversion
of existing drives. Retain the legacy ID/path/states and recovery separately;
do not redirect it silently or label AES-CBC 128 as Use Windows default. Improve
the catalog reference with an explicit legacy/fallback qualification rather
than implying the modern page documents EncryptionMethod itself.

Make edition, account and technical prerequisites visible in show/plan/help.
Microsoft's [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/#windows-edition-and-licensing-requirements)
lists Pro, Enterprise and Education enablement, while Device encryption is a
separate capability also available on eligible Home devices. Its automatic
protection/online recovery workflow has account/join requirements; do not apply
those requirements indiscriminately to local BitLocker policy configuration.
The [BitLocker CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp)
specifies additional Enterprise E3/E5 or Education A3/A5 entitlements for CSP
management except its stated exceptions. RIDE currently writes local registry
policy, not CSP. Confirm licensing applicability for that path before stating
that it requires an enterprise subscription; distinguish local use from managed
deployment and show the actual TPM/protector/preboot prerequisites separately.

Keep encryption/decryption, protector enrollment and recovery-secret handling in
the deferred lifecycle work recorded in remaining-settings-decisions.md. Policy
restore does not restore drive encryption or protector ownership. Acceptance
requires bidirectional GUI checks, effective policy, repeat application, mixed
prior values and exact restore; HVCI restart/running checks and BitLocker preboot/
future-encryption checks belong on disposable capable targets. Current IDs
declare Windows 11 only; documentation mentioning Server does not expand support.
Do not encrypt, change firmware, restart or test protection on the workstation.
This documentation-only review does not change migration estimates.

### Accepted BitLocker, memory integrity and outcome-guidance decision, 2026-10-10

The user accepted the preceding GUI-aligned Memory integrity control and separate
advanced BitLocker policy controls, with the additional requirement that RIDE
guide users to a complete security outcome. Retain published IDs/state meanings,
the legacy encryption fallback review, typed recovery and the licensing/account
qualifications. GUI mapping, prerequisites and actual protection remain acceptance
work; do not treat this approval as completed enrollment or Windows support.

Add reviewed security recipes/profile candidates that state the threat being
addressed and show the entire path to protection. For example, distinguish drive
protection against loss/theft from requiring an additional factor before Windows
starts. Microsoft's [BitLocker countermeasures](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures)
describes TPM-only and TPM+PIN tradeoffs and additional power-state measures for
physical attacks. A TPM+PIN outcome must account for compatible platform/firmware,
the complete startup-authentication policy, actual PIN protector enrollment,
active nonsuspended encryption and tested recovery access. Enhanced characters
are a reviewed optional choice dependent on preboot input, not automatically
required for every user. Cipher strength alone does not establish that outcome.

Explain unattended restart/remote-management consequences before recommending
preboot input, especially for servers. Where the scenario calls for reducing
memory exposure during physical access, review shutdown/hibernation versus sleep
and actual S3/Modern Standby behavior together with the accepted power-controls
design. Never infer that hiding Sleep or setting an idle timeout to Never has
disabled standby. The recipe must not silently rewrite independently selected
power preferences; show the additional measures and applicability explicitly.

Treat running Memory integrity as a separate runtime-protection outcome, with
VBS/driver readiness, restart and running-state evidence from the preceding review.
It may be composed into a broader reviewed recipe, but is not proof of BitLocker
encryption or preboot authentication. Compare the resulting protections and
costs so users can choose the appropriate scenario without discovering hidden
dependencies themselves.

Enrollment, encryption/decryption and recovery-secret workflows remain deferred
implementation scope. Until implemented and verified, expose those missing steps
in guidance and readiness/status rather than label a registry-only profile Secure
or Complete. Do not put PINs/recovery secrets in normal snapshots, profiles or
logs. Follow-up must verify both the component controls and the complete outcome
on disposable capable targets. This records accepted design only; no catalog,
profile, handler or migration-estimate change is made.

### Developer Mode and trusted sideloading evidence review, 2026-10-10

Propose one normal Developer Mode control matching the current Settings toggle,
with trusted app sideloading retained separately in advanced views where its
independent effect is verified. Microsoft's [developer-settings reference](https://learn.microsoft.com/en-us/windows/advanced-settings/developer-mode)
locates the toggle under System > Advanced > For developers on Windows 11 25H2
and later; earlier builds use For developers. It documents the catalog's two
AppModelUnlock value mappings. This reference is more specific than a feature-
only page, but still requires current-build GUI/effect and precedence acceptance.

Legacy EnableDeveloperMode wrote both AllowDevelopmentWithoutDevLicense and
AllowAllTrustedApps to 1; DisableDeveloperMode removed both. The current IDs
windows.developer-mode-preference and windows.trusted-app-sideload-preference
retain individual values. Explicit Disabled=0 is not the legacy reverse action.
Preserve those IDs/states/recovery. Determine which values the current GUI changes
and which are necessary for local development before deciding the focused
operation's writes; do not mechanically reproduce two values or claim one scalar
proves the complete legacy outcome. Recover mixed prior values exactly.

Microsoft distinguishes local development from remote deployment. Its registry
enablement steps do not enable the SSH server or remote deployment; Device Portal
and Device discovery have separate controls. Developer Mode replaces the former
developer-license requirement, requires administrator access and can be blocked
by organizational policy. Home lacks gpedit but the reference provides direct
registry configuration. Make those requirements visible without inventing a paid
developer membership or conflating optional development tools/store publishing
accounts with local mode enablement.

Use the [sideloading reference](https://learn.microsoft.com/en-us/windows/application-management/sideload-apps-in-windows)
for the independent trusted-app setting, with signing/certificate trust and
deployment requirements visible. It says Windows 10/11 do not require sideload
license keys or domain join. Do not present this as permission to run all unsigned
software, bypass managed policy, or install certificates/apps implicitly. Verify
current defaults and effective deployment behavior; the guide's older GUI/default
wording is not proof of a separate toggle or disabled default on current builds.

Following the accepted outcome-guidance requirement, document a candidate Develop
apps locally recipe showing required mode, applicable tooling and a successful
local deployment/debug check. Keep remote deployment a separately reviewed
workflow with its capability, service, firewall and access prerequisites. Do not
silently enable Device Portal, discovery or remote services for the local outcome.
Preference restoration alone does not uninstall provisioned capabilities or undo
network/service changes from other workflows. Developer features remain opt-in,
outside general security recommendations; acceptance must check the GUI, managed
policy, representative signed deployment and mixed-state recovery in disposable
Windows 11 environments. This is a proposal awaiting the user's design decision.

### Accepted Developer Mode and trusted sideloading decision, 2026-10-10

The user accepted one normal GUI-aligned Developer Mode control, separate advanced
trusted-app sideloading and a Develop apps locally guide. Keep remote deployment
as a separate explicit workflow. Determine the current toggle's necessary writes
through the preceding acceptance work; preserve published IDs, state meanings,
mixed prior values and exact recovery. Make administrator, managed-policy,
signing/certificate and license/account prerequisites visible without inventing
a developer-membership requirement. Do not enable remote services, discovery or
Device Portal implicitly. This accepts design only; implementation, current-build
feature acceptance and the complete local-development recipe remain pending.

### Media metadata and Xbox controls evidence review, 2026-10-10

Propose separate understandable controls for Windows Media Player Legacy media
information retrieval and library sharing, and current GUI-aligned Game Mode and
capture features. Add outcome guidance where combinations are useful, following
the accepted complete-outcome requirement. Do not revive broad Disable Xbox or
Disable media online access labels for a partial set of preference writes.

The media controls target Windows Media Player Legacy, not the modern Media
Player app or every media application. Retain windows.media-player-disc-metadata
and windows.media-player-music-metadata as independent controls for disc versus
music-file information retrieval. Microsoft's focused [disc](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventcddvdmetadataretrieval)
and [music-file](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventmusicfilemetadataretrieval)
policy references identify the actual values and privacy checkboxes. Blocking
is a policy-enforced choice, while UserChoice=0 permits the user's preference;
it does not force downloads. Use descriptions that explain missing automatic
album/track information and distinguish policy state from the checkbox state.

Keep windows.media-player-library-sharing separate. Its [policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventlibrarysharing)
covers machine-wide prevention of the Player's network sharing and dependent
programs. UserChoice permits sharing configuration, not automatic service startup
or working peer access. Verify the installed player/component, relevant UI,
effective policy and actual peer behavior before recommending the control. Do not
change other applications, firewall rules or discovery services implicitly.

Legacy EnableMediaOnlineAccess and EnableMediaSharing removed their overrides;
WindowsDefault corresponds to that reverse action, not explicit UserChoice=0.
Preserve published IDs and typed recovery. DisableMediaOnlineAccess also wrote
PreventRadioPresetsRetrieval and WMDRM DisableOnline; these remain deferred in
remaining-settings-decisions.md. Do not infer modern applicability from an old
value or declare the whole bundle migrated. Verify current service availability
and installed-player behavior: a failed metadata lookup with an unavailable
upstream service is not proof that policy blocked it. No new backend retirement
claim is established by this review.

Propose optional Reduce online metadata retrieval in Windows Media Player Legacy
guidance/profile composition from verified applicable disc/music controls, with
network sharing an independent choice. Explain remaining online features and
omitted radio/WMDRM behavior; do not promise offline operation or a universal
network/telemetry block. Show installed-component and edition/policy prerequisites
and qualify CSP edition tables for RIDE's local registry path. Recipe readiness
must distinguish absent/not applicable from effective prevention.

For windows.game-mode-preference, Microsoft's [Windows 11 settings reference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-windows-11#gaming-game-bar-game-mode-gaming-shortcuts)
maps HKCU\Software\Microsoft\GameBar\AutoGameModeEnabled to Settings > Gaming >
Game Mode. Replace the current broad background reference with that focused
mapping in follow-up. The page describes reading settings for portability, not
a complete write/refresh contract; retain experimental/recommended-profile
restrictions until bidirectional GUI and actual behavior acceptance. Present
Game Mode as its own normal control after verification, without promising a
performance gain or claiming it removes apps or stops capture.

Keep windows.game-recording-user-preference (GameDVR_Enabled) advanced pending
current GUI mapping. Do not relabel it Record what happened or assume it controls
background recording alone. The machine windows.game-recording-policy uses
AllowGameDVR; its [exact policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationmanagement#allowgamedvr)
still limits enforcement to Windows 10 desktop. Retain it as experimental outside
recommended Windows 11 profiles; a catalog target and registry round trip do not
override that limitation. Distinguish the permitted feature from recording
actively running, and verify per-user/machine precedence and absent overrides.

Map current capture choices separately before adding normal controls. Microsoft's
[Game Bar capture guide](https://support.microsoft.com/en-us/accessibility/windows/use-a-screen-reader-to-record-your-screen-with-xbox-game-bar)
documents manual recording; do not assume an old registry flag represents all
current capture options. A candidate Stop background game recording guide must
identify the current background-capture choice, dependencies and effects on
manual capture, microphone/audio and shortcuts. Keep Game Mode and app removal
independent of that outcome; leave existing recordings untouched.

Legacy DisableXboxFeatures removed six Appx packages in addition to changing
Game Mode and two recording values. EnableXboxFeatures attempted to re-register
remaining installed payloads, removed Game Mode/machine policy overrides and
explicitly set GameDVR_Enabled=1. Re-registration is not acquisition of an absent
payload. Preserve these reverse-state distinctions and mark package restoration
as separate deferred lifecycle work. Explain account/subscription requirements
for any future Xbox service/package workflow separately from built-in Windows
preferences; verify local-account capture rather than invent a Game Pass
requirement for the settings. Do not remove or register packages during this review.

Acceptance requires representative installed components and capable disposable
Windows 11 targets, current GUI/default/refresh checks, independent mixed choices,
real metadata/sharing/capture effects and exact recovery. No network sharing,
recording, package change or workstation integration test is performed here.
The proposed design and guidance remain pending approval; migration estimates
are unchanged by this documentation-only review.

### Accepted media metadata and Xbox-controls decision, 2026-10-10

The user accepted separate Windows Media Player Legacy disc metadata, music-file
metadata and network-sharing controls, with optional guidance to reduce online
metadata retrieval. Present Game Mode as its own GUI-aligned control after the
preceding acceptance, and map current capture controls before adding a Stop
background game recording guide. Keep Xbox app removal/restoration as a separate
lifecycle workflow with prerequisites and recovery visible. Preserve published
IDs, reverse-state distinctions and saved-run recovery; retain older recording
policy experimental on Windows 11 and unresolved radio/WMDRM scope as deferred.
This accepts design only. Current-build feature tests, recipes/profile composition
and catalog/reference changes remain pending; no migration estimates change.

### Automatic recovery and Windows RE evidence review, 2026-10-10

Propose retaining automatic recovery suppression as an advanced, opt-in BCD
control, separate from Windows Recovery Environment enablement and automatic
restart after a crash. Add a Prepare Windows recovery guide that explains the
components needed for usable recovery. This is proposed design, not a new
state-changing workflow or completed recovery acceptance.

windows.boot-failure-recovery-policy changes bootstatuspolicy for the current
boot entry. Microsoft's [boot-settings reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set#boot-settings)
documents that IgnoreAllFailures suppresses automatic failover for failed boot,
shutdown and checkpoint events, not just boot failure. Improve the name/description
to expose that scope while retaining the ID and existing states. Present the
choice as Suppress automatic recovery versus Use Windows default, not as a general
On/Off recovery switch. This does not repair failures, disable Windows RE or
remove manual/external recovery routes. No exact equivalent Settings toggle is
established; do not map it to Advanced startup or invent a normal GUI control.

Legacy DisableBootRecovery set IgnoreAllFailures and EnableBootRecovery removed
the BCD value. Preserve WindowsDefault as override removal, not an explicit
DisplayAllFailures policy or a guarantee that automatic recovery works. The
Microsoft reference names a Windows 8 default; it does not establish the effective
Windows 11 image default. Determine current effective behavior and dependencies
on the applicable build. Disabling automatic recovery is not a general security
improvement and remains outside recommended recovery/security recipes.

Read-only handler inspection found Get-RideBootConfigurationState captures only
Exists/Value, while set/restore resolve {current} at execution time. Follow-up
must capture and validate the concrete boot-entry identity so recovery addresses
the entry actually changed, with a versioned snapshot migration/recovery path
for older runs. Preserve unrelated BCD elements, custom values and absence;
reject missing/ambiguous target identity rather than write a different entry.
Check localized discovery and native failures as part of that work. Successful
same-entry value restoration alone is not proof of recovery after a boot failure.

Legacy DisableRecoveryAndReset/EnableRecoveryAndReset used reagentc /disable and
/enable separately. Microsoft's [REAgentC reference](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11)
describes disabling the registered online Windows RE image and inspecting its
status with /info. Those are not BCD bootstatuspolicy operations. Keep enablement
deferred until reliable localized inspection, image/location/BCD capture, safe
repeat application and compensating recovery are designed. Do not label it
Disable all recovery and factory reset or claim it prevents recovery from external
media. Do not create/delete partitions, acquire images or perform a reset as
implicit parts of a preference change.

Microsoft's [Windows RE reference](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-recovery-environment--windows-re--technical-reference?view=windows-11)
distinguishes automatic and manual entry, including recovery media, and explains
that available tools depend on platform. Desktop reset and Server recovery are
different outcomes. No catalog Server support is added here. Show usable local
recovery separately from automatic entry and external recovery readiness; a
registered Enabled flag does not prove the image boots or every tool succeeds.

The Prepare Windows recovery guide should show the applicable boot-status policy,
registered usable Windows RE image, supported manual entry, independently
accessible BitLocker recovery information where needed, backups and appropriate
external media. Explain what each supplies and verify a nondestructive recovery
entry and return to Windows on disposable targets before recommending the recipe.
Show unavailable components and manual/deferred steps instead of reporting a
registry-only configuration Complete. Keep actual reset, image restore and
recovery-media creation as explicit workflows; do not conflate configuration
restore with recovering files or a damaged installation.

Make elevation and BitLocker/firmware prerequisites visible before boot changes.
Do not suspend protection or alter Secure Boot implicitly to make BCDEdit succeed.
For recovery access, explain the administrator credentials, volume-unlock keys
and any workflow-specific account/network requirements. Do not invent a paid
membership for the built-in local environment or assume every tool has identical
authentication. Never copy recovery secrets into routine logs or snapshots.
Automatic restart after a system failure (windows.auto-reboot-on-crash), F8 boot
menu policy and newer online recovery features remain distinct controls/workflows.

Acceptance requires disposable Windows 11 reboot/failure scenarios, current
default/explicit/custom policies, Windows RE enabled/disabled/unavailable cases,
manual entry, encrypted-volume recovery and exact boot-entry restoration. Protect
lab checkpoints and retain an independent recovery route for those tests. No BCD,
Windows RE, firmware or workstation restart change is performed by this review;
functional acceptance and implementation remain pending, with estimates unchanged.

### Accepted automatic recovery and Windows RE decision, 2026-10-10

The user accepted advanced, opt-in automatic recovery suppression, separate
Windows RE enablement and separate automatic restart after a crash. Add a Prepare
Windows recovery guide covering usable local recovery, manual entry, backups,
external media and BitLocker recovery access as applicable. Retain published IDs
and default/removal semantics; make startup/shutdown/checkpoint scope and actual
recovery readiness explicit. Resolve concrete boot-entry capture and versioned
saved-run recovery before claiming exact restoration across boot-entry changes.
Windows RE lifecycle implementation and nondestructive/reboot/failure acceptance
remain pending under the preceding review. This records design acceptance only;
no BCD/Windows RE/profile change or migration-estimate adjustment is made.

### Scheduled diagnostics, Office tasks and drive optimization review, 2026-10-10

Propose individually selectable advanced task controls matching Task Scheduler's
Enable/Disable action, with exact path/name and a clear target-area description.
Use verified normal feature policies and outcome guidance to explain privacy
choices; do not require users to infer a privacy solution from thirteen task
names or compose every task from the legacy Telemetry bundle automatically.
Drive optimization is an independent maintenance outcome. This is proposed
design for the remaining-settings batch 1 review, not new acceptance evidence.

Microsoft's [Disable-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps)
and [Enable-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps)
references document enablement and exact TaskPath/TaskName addressing. They do
not establish what a legacy Windows/Office task collects on a current build.
Qualify the API links accordingly and add focused behavior references where
available. Show the matching Task Scheduler location and actual installed
identity so the user can inspect the GUI without guessing which task is meant.

Keep these boundaries visible in descriptions and any optional guidance:

| Task area | Intended scope and acceptance boundary |
| --- | --- |
| Compatibility Appraiser / ProgramDataUpdater | Application compatibility and upgrade-readiness-related scheduling; verify installed payload and compatibility impact before recommending suppression |
| Autochk Proxy / DiskDiagnostic collector | Named diagnostic scheduling; disabling a task does not disable disk checking, repair or every diagnostic service |
| CEIP Consolidator / UsbCeip | Legacy customer-experience scheduling; keep CEIP policy and actual current collection separate from the task flag |
| Feedback DmClient / DmClientOnScenarioDownload | Named feedback scheduling; feedback frequency and notification policy remain separate, with current prompt behavior unverified |
| Windows Error Reporting QueueReporting | Queue-task scheduling; do not equate it with error-reporting policy, every application's reporting or deletion of queued reports |
| Office tasks | Identify installed version, agent/monitor role and destination of data; do not label every task as Microsoft telemetry or as maintenance with no diagnostic effect |
| ScheduledDefrag | Scheduled Windows drive optimization, independently selectable from diagnostics/privacy controls |

Legacy reverse selectors explicitly enabled these existing tasks; that is not
removal of an override or a universal Windows default. Preserve the current
Enabled/Disabled states, IDs and captured enablement flag. Do not invent a
WindowsDefault state by deleting/re-registering task definitions. Inspection
and completion remain read-only; apply/restore must not start or stop instances,
replace definitions, change triggers/actions/principals or clear history/data.
Distinguish scheduling enablement from any current running instance and the
user-visible outcome. Exact flag recovery does not reverse previously collected
or transmitted data.

Keep absent tasks Unavailable with the expected identity visible; do not create
them or substitute a similarly named task. Require the installed Windows/Office
component and relevant permissions. Servicing may replace tasks or payloads;
follow-up should identify version/definition changes when determining acceptance
and recovery applicability rather than assuming a familiar path proves the
same workload. No blanket persistent-disable enforcement is introduced.

Microsoft's [Office Telemetry Dashboard guide](https://learn.microsoft.com/en-us/office/compatibility/compatibility-and-telemetry-in-office)
distinguishes organisational compatibility inventory/usage/health collection
from Office diagnostic data sent to Microsoft. Review the two 2016-named agent
tasks against their installed payload and configuration, not just their names.
Its [removal notice](https://learn.microsoft.com/en-us/office/compatibility/telemetry-dashboard-removal)
records removal from newer Microsoft 365 Apps for enterprise, and end of support
for the listed older perpetual versions. Retain these IDs as advanced legacy
choices, not current Microsoft 365 privacy defaults or an invitation to install
unsupported Office to obtain the tasks. Task absence does not establish that
current Office diagnostic collection is disabled.

Keep Office ClickToRun Service Monitor separate from that legacy agent pair.
Verify its monitoring/diagnostic payload and maintenance consequences on the
installed version before recommending any change. Current [Office privacy
controls](https://learn.microsoft.com/en-us/microsoft-365-apps/privacy/overview-privacy-controls)
distinguish diagnostic levels, connected experiences and required service data.
Any future Office privacy guide must map those actual supported controls and
show product/license/account and organisational-policy applicability. Do not
invent a premium privacy membership or claim these task flags replace Office
privacy settings. Keep service monitoring out of a generic privacy recipe.

For windows.task-drive-optimization, prefer Scheduled drive optimization and
the [Optimize Drives schedule](https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/defragment-optimize-your-data-drives-in-windows)
GUI reference over a Disable defragmentation label. Windows optimization depends
on drive type, including HDD defragmentation and SSD trimming. Verify the task
flag against Run on a schedule and actual media-specific maintenance before
exposing a normal GUI-aligned control. The current operation does not configure
frequency, drive selection or missed-run behavior; do not overwrite those choices
or run optimization implicitly. Keep manual optimization separate, preserve
existing scheduling unless deliberately selected, and exclude this task from
privacy/security suppression bundles.

Following the accepted outcome-guidance requirement, a candidate Reduce optional
diagnostics guide should explain supported normal policies first, then any
verified, independently justified task choices and lost troubleshooting or
compatibility capabilities. Make build/edition, installed-component, privilege
and policy dependencies visible, report partial coverage and show remaining
collection. Unknown payloads stay outside recommended composition. The
application-impact/inventory and unresolved telemetry/feedback policy values
require the subsequent policy review; this task review does not approve them.

Retain the earlier five missing-task acceptance gaps (two compatibility tasks
and three Office tasks). Verify GUI enablement, task-definition preservation,
mixed prior flags, managed/servicing behavior and actual task/feature effects in
disposable current-build environments. Do not execute diagnostic tasks or
collect/transmit test data on the workstation. This documentation-only review
does not change catalog, profiles, handlers or remaining migration estimates.

### Accepted scheduled-task and optimization decision, 2026-10-10

The user accepted separate advanced Task Scheduler Enable/Disable controls with
exact identities and purposes, plus a Reduce optional diagnostics guide using
verified policies first and justified task choices with their tradeoffs. Keep
legacy Office agents distinct from current Office privacy and ClickToRun service
monitoring. Scheduled drive optimization remains an independent maintenance
control, presented normally only after its GUI mapping is accepted. Preserve
task definitions, prior flags and published IDs; missing tasks are unavailable.
Installed-payload, servicing, GUI and actual outcome acceptance remain pending.
This records design acceptance only, without implementation or an estimate
adjustment.

### Application telemetry, feedback and omitted bundle review, 2026-10-10

Propose separate advanced application-compatibility policies, a clearly named
feedback-request policy and one combined GUI-aligned feedback frequency control.
Compose accepted, verified controls through outcome guidance rather than
recreating every value from DisableTelemetry or DisableFeedback. Preserve stable
IDs and captured prior state; this is proposed design, not feature acceptance.

Microsoft's [application telemetry policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-appcompat#appcompatturnoffapplicationimpacttelemetry)
describes tracking application use of Windows components. Name the operation
Application telemetry (Windows component usage) and identify the Group Policy
Turn off Application Telemetry. Policy Enabled turns collection off, whereas
the existing RIDE Disabled state writes AITEnable=0. Keep this inversion visible.
Changes affect newly launched applications; restarting covers existing ones.

The separate [inventory policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-appcompat#appcompatturnoffprograminventory)
covers application, file, device and driver inventory for compatibility. Name it
Application compatibility inventory and identify Turn off Inventory Collector.
The existing Disabled state writes DisableInventory=1. Suppression also affects
Program Compatibility Assistant installation-data collection. Do not describe
it as disabling the compatibility engine or every inventory mechanism. CEIP
opt-out overrides both collectors. Neither policy is the normal diagnostic-data
level toggle; show their policy paths, privileges, edition support and effective
dependencies. The legacy enable selector removed these policy overrides; it did
not request the existing explicit Enabled states.

For windows.feedback-notifications-policy, prefer Windows feedback requests
with the precise effect Prevent Windows from asking for feedback. Microsoft's
[feedback notification policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience#donotshowfeedbacknotifications)
maps DoNotShowFeedbackNotifications: prevention is distinct from user frequency.
Allowed or override removal permits requests, without forcing them. It does not
uninstall Feedback Hub, prevent voluntary feedback or disable error reporting.
Show managed-policy precedence and supported edition/build requirements;
do not infer local registry support from the CSP applicability table alone.

Correct the earlier undocumented assessment of NumberOfSIUFInPeriod.
Microsoft's [feedback frequency reference](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
documents it together with PeriodInNanoSeconds under `HKCU\Software\Microsoft\Siuf\Rules`.
The legacy script changed only the count and removed only that count on reversal.
That cannot establish a complete Never/Automatically mapping or remove a remaining
period override. Propose one Feedback frequency setting matching choices actually
available in Settings > Privacy & security > Diagnostics & feedback on each
accepted build. Capture and restore both values, their types and absence
independently, including mixed/custom prior states. Keep explicit Automatically,
override removal and saved-state restore semantics distinguishable.

The reference calls both values REG_DWORD but includes day/week period numbers
larger than a DWORD can hold. Validate types, units and complete GUI transitions
in disposable Windows 11/declared Server environments before choosing payloads;
do not copy that table blindly or promise every listed choice on every target.
Its stated Enterprise/older Server scope does not establish all current editions.
This evidence improves the reference, without closing the deferred migration.

Propose Stop automatic feedback requests guidance using the supported policy,
with frequency where applicable. Explain the resulting managed GUI behavior and
partial coverage. The accepted task controls remain advanced and require their
own payload evidence; do not require disabling both DmClient tasks to claim the
policy outcome. Reduce optional diagnostics guidance should keep diagnostic
level, recognition samples, these compatibility collectors and feedback requests
distinct, showing required data that remains and compatibility/troubleshooting
tradeoffs. This is not a claim that every connection to Microsoft stops.

Reconcile the omitted telemetry scope explicitly:

| Legacy component | Proposed disposition / remaining evidence |
| --- | --- |
| Windows CEIPEnable | An exact [CEIP policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm#ceipenable) now identifies the SQMClient policy/value. Consider an advanced Customer Experience Improvement Program participation control after current collection, inverse Group Policy wording, edition/target applicability and override-removal behavior are verified. Do not invent a current normal Settings checkbox. It remains unmigrated |
| App-V CEIPEnable | Keep deferred for installed-client relevance, exact current mapping and effective collection evidence. Microsoft's [App-V support policy](https://learn.microsoft.com/en-us/microsoft-desktop-optimization-pack/app-v/appv-support-policy) distinguishes client/sequencer Windows lifecycle from server-component end of support; server retirement alone does not retire the client control |
| Native/Wow6432Node non-policy AllowTelemetry mirrors | Keep deferred until precedence/current effect is established. Legacy reversal wrote 3 while removing the official policy; neither action establishes a universal platform default. Do not add redundant privacy controls without independent meaning |
| NoGenTicket / AllowBuildPreview | Retain the earlier exclusion: activation/licensing behavior is not privacy, and the documented preview value applies only through Windows 10 1703. Do not reproduce these in the diagnostic guide |

Verify user-visible collection/prompt outcomes and policy precedence separately
from registry lifecycle, without invoking collectors on the workstation. Preserve
the accepted diagnostic-level and recognition-sample design. No catalog,
handler, profile or migration-estimate change is made by this documentation review.

### Accepted telemetry and feedback decision, 2026-10-10

The user accepted separate advanced application telemetry and compatibility
inventory policies, a separate feedback-request policy, and one GUI-aligned
feedback frequency control coordinating both underlying values. Add Reduce
optional diagnostics and Stop automatic feedback requests guidance explaining
required controls, dependencies, remaining collection and tradeoffs. Preserve
published IDs and reverse-state distinctions. CEIP current behavior, App-V client
relevance and non-policy telemetry mirrors remain deferred; verify the frequency
reference's type/number inconsistency and current GUI before implementation.
This is design acceptance only. No operation or profile changes, new feature
acceptance or migration-estimate adjustment are recorded.

### Start most-used list and secure-attention sign-in review, 2026-10-10

Propose two independent controls named for their user-visible effects. These
legacy pairs do not compose one outcome: Start list presentation and sign-in
security have different scope, policy dependencies and acceptance scenarios.

For windows.start-most-used-policy, retain an advanced machine policy named
Hide most-used apps in Start (policy), showing the related Show most used apps
GUI toggle and the enforced/managed distinction. Microsoft's
[HideFrequentlyUsedApps reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start#hidefrequentlyusedapps)
maps NoStartMenuMFUprogramsList to Remove frequent programs list from the Start
Menu. It documents hiding the list and checking the grayed-out Settings toggle
after Explorer restart/reboot. This supersedes the legacy comment claiming the
policy was obsolete after Windows 10 1703; current-build acceptance remains open.

Preserve Hidden=1, Allowed=0 and WindowsDefault=override removal. Allowed means
this policy permits display, not that it turns the user's preference on. The
legacy ShowMostUsedApps removed the override, so its name did not guarantee
visibility either. Keep exact saved-state recovery and machine scope; do not
silently convert the existing ID into a current-user preference.

Microsoft's current [Start policy guide](https://learn.microsoft.com/en-us/windows/configuration/start/policy-settings)
also documents Show or hide "Most used" list from Start menu, which takes
precedence over HideFrequentlyUsedApps. Show the controlling policy when known;
do not report successful visible hiding from this registry value alone. Do not
silently replace the existing operation with that newer policy or introduce
two normal controls claiming the same effect. A future normal current-user Show
most used apps control requires a verified GUI mapping and clear policy conflict
reporting before implementation.

Keep app-launch tracking separate. Microsoft's [Start and search personalization
guidance](https://support.microsoft.com/en-us/windows/privacy/privacy-settings-for-recommendations-offers-in-windows-11)
identifies Let Windows improve Start and search results by tracking app launches
under Privacy & security > Recommendations & offers. Explain this dependency
using the actual label/location on the accepted build; hiding a list is not a
claim that launch tracking stops or its history is deleted. Do not implicitly
enable tracking to populate the list. Recently added apps, recent files,
advertising and suggested promotions remain their own controls; keep this list
out of Reduce Windows promotions unless a future review justifies inclusion.

For windows.secure-attention-logon, prefer Require Ctrl+Alt+Delete before sign-in
with explicit Required, Not required and Remove local override presentation.
Microsoft's [interactive-logon reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-do-not-require-ctrl-alt-del)
documents the GUI policy under Local Security Policy > Local Policies > Security
Options > Interactive logon: Do not require CTRL+ALT+DEL. Its negative wording
inverts the result: policy Disabled requires the sequence. Preserve Required=0,
NotRequired=1 for DisableCAD and WindowsDefault=override removal. Both legacy
selectors wrote explicit values, unlike override removal or saved-state restore.

The reference identifies a trusted password-entry path and a smart-card exception;
this is not a general guarantee against credential theft. It states that policy
changes need no device restart and that reverting the policy also requires
removing DisableCAD. Preserve raw prior state and distinguish local configuration
from effective managed policy; do not promise that removing the value disables
the requirement. Treat any User Accounts/netplwiz checkbox mapping as acceptance
work, using the documented Security Options policy location in the meantime.

The older reference's effective-default table differs from the current
[LocalPoliciesSecurityOptions CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions)
InteractiveLogon_DoNotRequireCTRLALTDEL section. Record this discrepancy rather
than asserting one universal default. Verify literal absence/value and effective
behavior on clean, local-account and managed/domain configurations separately.
Show admin privilege and applicable Windows edition/policy-tool requirements;
do not infer Home support or Server operation support from the client CSP table.
The catalog currently declares only Windows 11 for both operations. A Server
declaration requires applicable tests, including Desktop Experience for Start.

Verify sign-in/lock behavior for the account and credential types actually
supported, including Hello/biometrics and remote-session sequences where relevant.
Do not equate a VM host's key combination with delivery inside the guest. Explain
the extra interaction and accessibility impact. Security outcome guidance should
place this optional control alongside the relevant authentication/lock choices
and their prerequisites, without presenting it as a complete secure-sign-in
solution or silently changing PIN, password, automatic sign-in, UAC or remote
authentication. Sign-out/lock/reboot testing belongs only in disposable VMs and
is never an implicit apply action.

This documentation review makes no catalog, handler, profile or migration-count
change. Verify GUI and effective behavior separately from registry lifecycle;
retain IDs, state meanings and saved-run recovery.

### Accepted Start list and secure-attention decision, 2026-10-10

The user accepted separate controls: an advanced Hide most-used apps in Start
policy with GUI/effective-policy explanation, and Require Ctrl+Alt+Delete before
sign-in with positive wording and the inverse Windows policy mapping. A normal
current-user Start preference remains pending GUI mapping. Preserve existing
IDs, scope, explicit states, override removal and saved-run recovery. Resolve
policy precedence, platform defaults, credential-type/accessibility effects and
actual GUI/sign-in behavior before feature acceptance or target expansion.
Security guidance must explain the sign-in control's limited benefit and
dependencies. This records design acceptance only; no implementation or estimate
adjustment is made.

### Network adapter binding review, 2026-10-10

Propose advanced, opt-in controls mapped to each adapter's Properties > Networking
component checkboxes. Show the installed DisplayName, stable component ID,
adapter name/description and GUID; use English catalog names while preserving
localized Windows labels. Microsoft's [Get-NetAdapterBinding reference](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapterbinding?view=windowsserver2025-ps)
identifies the visible binding list with this GUI. Its
[Set-NetAdapterBinding reference](https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapterbinding?view=windowsserver2025-ps)
documents binding enablement and coupling with other flags. These API references
do not establish every component's current functional effect; supplement them
with focused behavior references and disposable-VM GUI/peer acceptance.

| Existing operation / component | Proposed presentation and scope |
| --- | --- |
| windows.adapter-lldp-binding / ms_lldp | Microsoft LLDP adapter binding; separate from LLTD. Identify the installed driver label and verify actual link-neighbor behavior |
| windows.adapter-lltd-binding / ms_lltdio + ms_rspndr | LLTD topology discovery (mapper and responder); one optional combined legacy action, with both component labels, roles and individual states visible |
| windows.adapter-microsoft-network-client-binding / ms_msclient | Client for Microsoft Networks; access to Microsoft network resources, separate from hosting shares |
| windows.adapter-file-printer-sharing-binding / ms_server | File and Printer Sharing for Microsoft Networks; adapter sharing binding, separate from SMB protocol versions, shares, permissions and firewall |
| windows.adapter-qos-packet-scheduler-binding / ms_pacer | QoS Packet Scheduler; packet scheduling component, with applicable application/policy dependencies |
| windows.adapter-ipv4-binding / ms_tcpip | Internet Protocol Version 4 (TCP/IPv4); adapter binding, not the machine's entire IPv4 configuration |
| windows.adapter-ipv6-binding / ms_tcpip6 | Internet Protocol Version 6 (TCP/IPv6); adapter binding, distinct from IPv6 prefix preference, transition components and global configuration |

Microsoft's [LLTD topology protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lltd/dcd232d5-8454-44fc-a037-c226f4bc39cd)
distinguishes mapper requests and responder participation. Do not call their
flags interchangeable or technically inseparable. Retain the existing combined
ID as an explicit action affecting both related roles, not two claimed security
benefits. Show mixed states and restore each prior flag independently. Require
both components for a complete combined result; one missing component is partial
coverage, not verified LLTD disablement. Consider individual controls only after
current-build evidence establishes a useful independent outcome. The older
[LLTD feature reference](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/qos/link-layer-topology-discovery-protocol)
describes Vista Network Map; it does not establish an equivalent Windows 11 GUI
feature or prove that disabling LLTD stops all Windows network discovery.

Keep LLDP separate. Microsoft's [NetLldpAgent module reference](https://learn.microsoft.com/en-us/powershell/module/netlldpagent/?view=windowsserver2025-ps)
requires DataCenterBridging for that module; it does not establish that the
existing ms_lldp binding operation installs that feature or controls every LLDP
agent. Verify the binding's current driver/payload and network-peer effects.
Do not silently substitute agent commands or infer component presence from an
unrelated feature. Missing bindings are unavailable, not an installation request.

For QoS, the [policy architecture reference](https://learn.microsoft.com/en-us/windows-server/networking/technologies/qos/qos-policy-architecture)
explains Pacer packet scheduling. It supports a focused behavior description,
not a promised bandwidth increase from disabling the binding or a universal
reservation percentage. Verify relevant traffic/policy behavior separately from
the checkbox; qualify the reference's Server applicability for client acceptance.

Microsoft's [IPv6 configuration guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows)
maps unbinding to the IPv6 GUI checkbox and advises against doing so without a
justifiable need. It distinguishes IPv4 preference from disabling IPv6. Make
connectivity/dependent-feature effects visible before selection; do not put
IPv4/IPv6 disablement in a recommended performance or security profile. Keep
both controls advanced, with local recovery access explained. Do not silently
apply prefix-policy changes or treat one binding flag as complete stack removal.

The current handler changes matching components on all currently visible
adapters, matching the legacy wildcard intent. Add explicit adapter selection
as a follow-up before recommending these controls for routine use. Plans must
show each affected adapter/component, including virtual/VPN interfaces and mixed
flags, and make All currently visible adapters an explicit advanced scope. Do
not silently retarget published IDs, existing profiles or saved runs. Any future
selector requires documented schema/default migration, exact GUID targeting and
the repository's read-only completion contract. Newly attached adapters remain
unchanged; absence of a binding on some targets must be reported per adapter.

Preserve captured GUIDs and all reported coupled flags on affected adapters.
Restore mixed prior states, tolerate renames by identity and fail clearly for
missing identities or nonconvergence. Validate collateral flag changes, adapter
restart/connectivity interruption, intervening changes and partial failures;
do not promise transactional network recovery. Retain state-schema/recovery
compatibility when adding selection or improving completeness checks. A Boolean
binding round trip does not establish restored peer communication.

Provide guidance for reviewing adapter components by purpose, required network
resources and scope. Later networking security guidance must reconcile SMB,
firewall, authentication and discovery controls before offering a complete
outcome; this review does not approve those additional areas or an indiscriminate
disable-all recipe. Require administrator rights, installed components and
applicable platform support. The catalog declares Windows 11 only; Server and
physical/Wi-Fi/VPN/vendor-driver coverage remain acceptance work. No adapter,
catalog, handler or profile change is made here, and migration estimates remain
unchanged for this documentation-only review.

### Accepted adapter-binding decision, 2026-10-10

The user accepted advanced controls mapped to adapter Properties checkboxes,
with LLDP, client access, sharing, QoS, IPv4 and IPv6 independently explained.
Retain an optional combined LLTD action with both roles and individual states
visible. Add explicit adapter selection as a follow-up; retain existing scope
and saved-run compatibility, and clearly preview all affected adapters. Keep
IPv4/IPv6 disablement outside recommended profiles. GUI, component completeness,
peer behavior and recovery acceptance remain pending. This records design
acceptance only; no adapter, implementation or migration-estimate change occurs.

### SMB server controls and file-sharing outcomes review, 2026-10-10

Propose separate advanced controls for SMB 1 server compatibility, SMB 2/3 server
protocols and the already-reviewed File and Printer Sharing adapter binding.
Complement them with Secure Windows file sharing and Stop hosting SMB shares on
this PC guidance. These are distinct outcomes; a user should not have to guess
whether selecting one protocol flag completes either one.

The legacy DisableSMBServer wrote both server protocol flags false and disabled
ms_server on all matching adapters. EnableSMBServer enabled SMB2/3 and the binding,
leaving SMB1 unchanged. DisableSMB1/EnableSMB1 independently wrote the SMB1 server
flag. Preserve those distinctions, published IDs and captured prior flags. Do
not define a reverse recipe that enables every protocol, removes existing shares
or substitutes a presumed Windows default for saved-state recovery.

Microsoft's [SMB protocol reference](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
documents Set-SmbServerConfiguration and the shared SMB2/3 stack. Keep
windows.smb2-server-protocol as one control: Enabled allows SMB2/3 server
connections; it does not force a specific negotiated dialect or require signing
or encryption. Disabled affects hosting globally, unlike an adapter binding.
Identify the advanced cmdlet setting rather than inventing a matching normal
Settings checkbox. The reference recommends retaining SMB2/3 and avoiding SMB1;
SMB1 enablement remains an explicit advanced legacy compatibility choice, outside
recommended profiles, with the dependency and security implications visible.

Distinguish the SMB1 server flag from optional-feature installation/removal and
from the SMB client. The Windows Features GUI is component management, not an
exact replacement for this server flag. The current handler requires the exact
srv/srv2 driver identity and does not install components. An absent driver stays
Unavailable for the operation; do not turn it into a successful flag change or
install SMB1 to make a test pass. Outcome inspection must independently establish
component/client state before claiming SMB1 is absent everywhere. No assumption
about client disablement follows from either server operation.

Show the adapter Properties binding location separately from Settings > Network
& internet > Advanced sharing settings, share permissions and firewall rules.
Microsoft's [file-sharing GUI guide](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/file-sharing-over-a-network-in-windows)
describes user-facing sharing controls, but is not an exact mapping for these
protocol flags. Its troubleshooting suggestions are not automatically a security
recipe; do not silently turn off password protection or enable every discovery
service. A binding alone does not establish an accessible, authorized share.

For Secure Windows file sharing guidance, explain and check the complete outcome:

| Required area | Evidence / behavior to show |
| --- | --- |
| Role and scope | Whether the PC hosts shares, accesses remote shares, or both; distinguish global server protocol flags from selected adapter bindings |
| Supported modern protocols | SMB1 avoided; SMB2/3 available for hosting when required, with the actual negotiated dialect reported separately |
| Reachability | Required service/component, intended adapters and trusted network profile; firewall rules restricted to intended profiles/peers rather than broad exposure |
| Authorization | Intended authenticated identities plus share and filesystem permissions; guest access and password protection explained, not silently relaxed |
| Integrity and confidentiality | Effective signing/encryption requirements for the relevant client/server/share scope, compatible peers and actual session protection |
| Verification and recovery | Successful authorized access, rejected unauthorized access and saved recovery for every changed control; report missing capabilities and incomplete coverage |

Microsoft's [signing reference](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
distinguishes inbound/server and outbound/client requirements. Its edition/role
default examples differ from broader Windows release summaries, including Home
and Server defaults; verify the target's effective settings instead of assuming
all Windows 11/Server installations match. Signing protects message integrity
and authenticity; it is distinct from confidentiality through encryption.
The [guest-access reference](https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3)
explains that guest logons do not support signing/encryption. Do not weaken those
protections automatically when an older NAS or printer cannot connect.

The [SMB encryption reference](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
requires compatible SMB3 peers and distinguishes share/server encryption from
data-at-rest protection. Where confidentiality is required, verify encryption and
rejection of unencrypted access rather than just SMB3 availability. The separate
[outbound client encryption mandate](https://learn.microsoft.com/en-us/windows-server/storage/file-server/configure-smb-client-require-encryption)
requires Windows 11 24H2 or Server 2025 or later and administrative privileges;
it can reject incompatible destinations. Make target/build, credentials,
management-policy rights and peer support visible. Explain local/workgroup
authentication separately from domain/Kerberos prerequisites; domain membership
or a paid cloud security subscription is not inferred from the current flag
operations. Qualify any future feature-specific requirements independently.

Signing, encryption, authenticated sharing/permissions and SMB firewall controls
are not implemented by these two protocol operations. Track their catalog and
acceptance gaps explicitly before publishing a runnable security profile; manual
prerequisites must be labeled. This design does not add new operations or mark
the complete security outcome implemented. Keep the guide focused on stated
protection goals and compatibility/performance tradeoffs, not a universal
"really secure" setting or a count of enabled switches.

For Stop hosting SMB shares on this PC, compose the reviewed global server
protocol controls and explicit adapter-binding scope, explaining affected
applications and remote administration. Retain outbound client access unless
the user separately chooses to change it. Preserve existing share definitions,
data, permissions and services; disabling hosting does not delete them. Reconcile
firewall exposure as a separate step after its review. Restrict sharing on one
adapter is a different outcome and must not silently disable global SMB2/3.
Do not label this recipe as disabling every Windows sharing or printing route.

Validate real peers, mixed binding states, negotiated protocol/protection,
unavailable SMB1 and exact saved recovery in disposable environments. The
protocol cmdlet reference does not require a reboot; adapter changes can interrupt
connections, and captured flags do not restore broken sessions or application
work. Preserve partial-failure reporting and prior schema recovery. The catalog
declares Windows 11 only; Server support requires its applicable integration
checks. Existing SMB1 resource acceptance remains open. This documentation-only
review changes no protocol, adapter, firewall, catalog, handler, profile or estimate.

### Accepted SMB controls and sharing-guidance decision, 2026-10-10

The user accepted separate advanced SMB1 server, combined SMB2/3 server and
adapter sharing-binding controls, plus Secure Windows file sharing and Stop
hosting SMB shares on this PC guidance. Keep SMB1 enablement outside recommended
profiles. Preserve the legacy enable selector's unchanged SMB1 state and exact
saved recovery. Explain global versus adapter scope and all required protections;
track authentication, permissions, firewall, signing/encryption and peer evidence
gaps before publishing a runnable security profile. This records design
acceptance only; no implementation, feature acceptance or estimate change occurs.

### NetBIOS and Internet connectivity checks review, 2026-10-10

Propose a NetBIOS over TCP/IP control matching the three adapter GUI choices and
one advanced Windows Internet connectivity checks (NCSI active probes) feature
view. These are separate functions: legacy name-resolution/transport behavior
and Internet-status detection. Neither is a substitute for the accepted SMB
security outcome or a reason to disable every networking component.

For windows.netbios-over-tcpip, show the adapter Properties > Internet Protocol
Version 4 (TCP/IPv4) > Advanced > WINS location. Microsoft's
[DHCP/NetBIOS guide](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-netbios-tcp-ip-using-dhcp)
explicitly describes that route for Windows 10/11. Present these choices with
the actual GUI labels verified on the accepted build:

| Catalog state / value | Intended GUI choice and distinction |
| --- | --- |
| Dhcp / 0 | Default / Use NetBIOS setting from the DHCP server; this is not explicit enablement and does not change the adapter's IP allocation mode |
| Enabled / 1 | Enable NetBIOS over TCP/IP explicitly |
| Disabled / 2 | Disable NetBIOS over TCP/IP explicitly |

Microsoft's [NetbiosOptions reference](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-netbt-interfaces-interface-netbiosoptions)
documents these modes and an enabled fallback when DHCP is unavailable. Verify
the effective fallback and DHCP options on current builds without rewriting the
captured literal mode. This reference describes unattended configuration, and
the existing [CIM method reference](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration)
describes its method; neither should be presented as an exact reference for the
handler's registry implementation.

The legacy EnableNetBIOS wrote 0; DisableNetBIOS wrote 2. Make that reversal
visible instead of treating the newer explicit Enabled=1 state as legacy parity.
Dhcp=0 is a declared mode, not deletion of an override or saved-state recovery.
Do not add a WindowsDefault removal state without verified semantics. Preserve
raw prior value/type/absence and SnapshotVersion 2 recovery. The earlier CIM-only
snapshot cannot reconstruct that raw state; retain its documented checkpoint
recovery limitation rather than claiming it has become exactly restorable.

Add adapter selection as a follow-up consistent with the accepted binding
design. The current handler targets every existing GUID-named NetBT interface
key, which can differ from the visible adapter list. Before writes, show resolved
adapter identities, missing/stale associations and mixed modes; do not silently
apply a normal GUI choice to hidden or disconnected records. Preserve published
scope and saved-run compatibility through an explicit migration. New identities
remain untouched during restore; missing captured keys fail clearly.

Microsoft's [direct-hosted SMB reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/direct-hosting-of-smb-over-tcpip)
distinguishes NetBIOS transport from modern SMB over TCP. Explain possible legacy
name-resolution/application effects; disabling NetBIOS is not disabling SMB2/3,
DNS, LLMNR or every discovery protocol. Include an optional dependency check in
networking security guidance, with actual peer name resolution/access acceptance
before recommending removal. Do not label it a complete sharing hardening recipe.

For NCSI, use windows.ncsi-active-probe-policy as the main advanced policy control
and retain windows.ncsi-active-probing as a compatibility/local-preference detail.
Show both values together in the feature view, with their sources and effective
result. They are two configuration routes to one behavior, not two independent
privacy benefits. Do not automatically write both or silently redefine either
published ID. Any future combined writable operation needs reviewed state and
recovery semantics first.

The [Connectivity policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-connectivity#disallownetworkconnectivityactivetests)
identifies Turn off Windows Network Connectivity Status Indicator active tests
and the exact NoActiveProbe policy path. Microsoft's
[client workaround reference](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network)
documents NoActiveProbe=1 and EnableActiveProbing=0 as ways to suppress active
probes. Keep the policy Disabled=1 meaning probes off and Enabled=0 meaning this
policy allows them clear; do not equate the latter with guaranteed live probing.
Legacy EnableNCSIProbe removed only NoActiveProbe. It did not set the local
preference to 1. Policy removal, explicit permission and restoring a mixed prior
configuration remain distinct.

The CSP's Allow/Block labels can be confusing for a negatively named setting;
use the documented local registry mapping and verify local ADMX/current-build
behavior rather than copying labels into a payload. Prefer the focused policy
link for this operation and the [NCSI troubleshooting reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-ncsi-guidance)
for EnableActiveProbing, which it documents explicitly. Correct the earlier
feature-only characterization of that local registry mapping when implementing
metadata changes. Explain edition/management requirements without inferring
registry support solely from the CSP table.

Microsoft's [NCSI overview](https://learn.microsoft.com/en-us/windows-server/networking/ncsi/ncsi-overview)
distinguishes active requests from passive monitoring and advises against
disabling probes to fix connectivity. Their suppression does not block Internet
access, stop passive monitoring, hide the taskbar icon or prevent every network
request. The client reference describes potential Outlook/Windows Update effects;
keep this advanced and opt-in, outside recommended security/performance profiles.
Do not carry forward the legacy zero-click-protection claim without current
threat/build evidence. There is a Group Policy mapping, not a verified normal
Settings toggle for disabling active tests.

The current [NCSI FAQ](https://learn.microsoft.com/en-us/windows-server/networking/ncsi/ncsi-frequently-asked-questions)
distinguishes Windows 11's Network List Service from earlier NLA ownership while
retaining the NlaSvc configuration path. It also describes Windows 11 HTTP
probing and DNS resolution. Avoid copying older service names, fixed probe IPs
or DNS-only behavior into the description. Verify the actual build/configuration;
do not change service startup, passive polling or probe destinations as part of
this control. The network icon is an outcome indication, not proof of Internet
access or complete traffic suppression.

Acceptance must compare GUI/effective NetBIOS behavior across DHCP, static-IP,
mixed adapters and legacy/modern peers. For NCSI, test policy/preference
combinations, removal and saved recovery, then actual status, application access,
proxy/VPN and captive-portal behavior in disposable environments. Establish
refresh/restart needs without restarting adapters or services on the workstation.
Keep the literal settings distinct from effective behavior and platform defaults.
Both catalog areas currently declare Windows 11 only; Server support requires
its own applicable checks. No catalog, handler, profile, network state or
migration-estimate change is made by this documentation-only review.

### Accepted NetBIOS and NCSI decision, 2026-10-10

The user accepted three GUI-aligned NetBIOS choices with adapter selection as a
follow-up, including the legacy enable selector's DHCP/default meaning. Add one
advanced NCSI feature view showing policy and local preference together, with
the policy as main control and no automatic two-value rewrite. Preserve IDs,
raw recovery and distinct reversal semantics. Keep NCSI suppression outside
recommended security/performance profiles. GUI, effective behavior and network
acceptance remain pending. This records design acceptance only; no network,
catalog, handler, profile or migration-estimate change is made.

### Remote Desktop permission, firewall and guided setup review, 2026-10-10

Propose individual incoming connection permission and advanced local firewall
controls, plus an optional Allow Remote Desktop on a trusted network guided
setup. Explain the complete outcome and its prerequisites, rather than requiring
the user to discover that selecting one setting might leave connections blocked
or insufficiently protected. Preserve published IDs and saved recovery.

For windows.remote-desktop-connections, prefer Allow incoming Remote Desktop
connections, with the related Settings > System > Remote Desktop location.
Microsoft's [GUI guide](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/how-to-use-remote-desktop)
documents that setup route. Verify the isolated permission operation against the
GUI without implying it reproduces every side effect of toggling Remote Desktop
in Settings. The [troubleshooting reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/rdp-error-general-troubleshooting)
documents fDenyTSConnections=0/1 and local versus Group Policy configuration.
Prefer that exact mapping reference alongside the feature/prerequisite guide
when updating metadata. A permitted local value is not proof of a usable host
or a policy that allows access.

Retain Enabled=0, Disabled=1 and WindowsDefault=local value removal. Present the
last state as Remove local setting (advanced), pending verification; do not
promise it disables connections or restores the GUI/platform default. Saved
restore recovers literal prior value/type/absence. Both legacy selectors wrote
explicit values, and also enabled/disabled firewall rules; neither removed the
permission value or captured a prior configuration.

For windows.remote-desktop-firewall, retain an advanced Existing local Remote
Desktop firewall rule flags control, linked to Windows Defender Firewall with
Advanced Security. Its current handler matches RemoteDesktop-* in PersistentStore;
the legacy wildcard was RemoteDesktop*. Reconcile actual identities and omitted
matches on accepted builds before claiming whole-bundle parity. A familiar prefix
does not establish direction, purpose, port, profiles or allowed peers: preview
those details and verify intended inbound rules, including transport/shadowing
roles where present. Do not silently narrow/widen the published operation scope.

Microsoft's [firewall inspection reference](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps)
distinguishes local PersistentStore from the resultant ActiveStore. Show effective
managed rules and policy restrictions separately from local flags. Local enabled
rules do not guarantee access, and local disabled rules do not prove all inbound
RDP traffic is blocked. Preserve each captured rule's exact enablement flag,
including mixed states; absent rules remain unavailable, without creation or
replacing definitions. New rule identities remain untouched on saved restore;
missing captured identities fail clearly. Changing rule profiles/peer filters
would require expanded versioned capture and reviewed recovery, not a Boolean
flag change presented as complete firewall hardening.

The [Remote Desktop prerequisites guide](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access)
identifies Windows Pro/Enterprise/Education and Windows Server as hosting-capable;
Home can be a client but cannot host built-in Remote Desktop. Show the detected
edition and privilege requirement before offering host setup, with unsupported
hosting unavailable rather than a successful registry write. It also recommends
Network Level Authentication (NLA), which authenticates before session creation.
Show effective NLA and authorized-user requirements; never silently disable NLA,
relax authentication or add users to resolve a failed connection.

Make license/account distinctions visible. This guide concerns the existing
Windows host feature, not installation of a multi-user Remote Desktop Services
deployment. Server session-host deployments have separate
[RDS CAL requirements](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-client-access-license)
and require their own scope/licensing review. Do not infer a Microsoft 365,
Endpoint or cloud membership requirement from these Windows 11 settings. State
the credentials and permissions needed for the chosen local/workgroup or managed
account scenario; Microsoft/Entra accounts, Hello/PIN and domain policy need
their own applicable connection evidence. No credential storage or licensing
provisioning is added by this review.

The optional guided setup should present this readiness checklist and assemble
only reviewed changes whose recovery is supported:

| Area | Required outcome / remaining scope |
| --- | --- |
| Host readiness | Supported edition, required service/listener, powered/reachable host and a supported client |
| Authorization | Intended permitted users and usable authentication; no automatic account/group changes |
| Authentication protection | Effective NLA and supported credential/client scenario; separate missing control or manual prerequisite is visible |
| Network exposure | Intended trusted profiles/peers and effective firewall access; preserve Public restrictions rather than enable every matching rule indiscriminately |
| Connection permission | Apply explicit permission after the protection prerequisites are ready; show local versus effective policy |
| Outcome evidence | An authorized connection succeeds, unauthorized/unintended network access is rejected, and local recovery remains available |

For off-network access, Microsoft's [outside-access guide](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-outside-access/)
describes VPN access without exposing the PC directly to the public Internet.
Prefer an existing reviewed VPN/gateway path in guidance; router forwarding,
gateway/VPN installation and public exposure are separate explicit workflows.
Do not add them to this setup implicitly. Network trust, NLA and user permission
are complementary; none alone establishes a complete security level.

The current catalog pair does not implement NLA, authorized users or restrictive
firewall scoping. Keep those gaps/manual prerequisites visible before publishing
a runnable guided profile; no blanket "secure" label follows from two successful
flag writes. Individual settings remain useful for inspecting/changing an
already prepared host. A Disable incoming Remote Desktop guided outcome may
compose explicit denial and reviewed firewall flags, with active-session/local
recovery impact explained. It is distinct from uninstalling a client, Remote
Assistance, Quick Assist or WinRM, and must not stop/delete those features.

Verify GUI side effects, local/managed precedence, actual authorized/rejected
connections, mixed firewall flags, missing rules and saved restoration in
disposable environments. Disabling/restore can interrupt the connection used to
administer the machine; captured configuration does not recover an active session.
Do not test lockout, restart services or connect remotely to the workstation.
The catalog currently declares Windows 11 only; Server hosting and licensing
scope require their own applicable acceptance before support expansion. This is
documentation-only design review, with no system, catalog, handler, profile or
migration-estimate change.

### Accepted Remote Desktop decision, 2026-10-11

The user accepted individual GUI-related incoming permission and advanced local
firewall controls, plus optional Allow Remote Desktop on a trusted network
guidance. Show hosting edition, administrator and account requirements, effective
NLA, authorized users and restrictive network exposure together. Keep missing
controls/manual prerequisites visible before a runnable profile is offered.
Reconcile the legacy firewall wildcard, preserve IDs and literal/mixed-state
recovery, and verify GUI side effects and actual authorized/rejected connections.
Server/RDS licensing and public exposure remain separate scope. This records
design acceptance only; no system, catalog, handler, profile or migration-estimate
change is made.

### Controlled folder access and ransomware readiness review, 2026-10-11

Propose one normal Controlled folder access control with On and Off, matching
Windows Security > Virus & threat protection > Manage ransomware protection.
Keep Audit (record attempts without blocking) advanced, plus optional Protect
important folders from unauthorized changes guidance. Preserve the published
windows.controlled-folder-access ID and states Enabled=1, Disabled=0 and Audit=2.
The legacy EnableCtrldFolderAccess/DisableCtrldFolderAccess selectors only selected
the mode; they did not configure folders, allow apps or prepare recovery. Their
errors were suppressed. The maintained handler propagates cmdlet errors, but a
successful preference write still does not establish effective protection.

Microsoft's [configuration reference](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure)
maps Windows Security On/Off to Enabled/Disabled; Audit and disk-only modes use
other configuration methods. Retain that focused metadata link, alongside the
[Windows Security guide](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/virus-and-threat-protection-in-the-windows-security-app)
for the GUI. Protected folders and Allow an app through Controlled folder access
are related choices, distinct from the mode. Allowing a compromised app can put
protected data at risk. Use modification protection wording; do not imply this
is a universal file-read restriction, all-disk encryption or a backup.

The [feature requirements](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-overview)
require Defender Antivirus in Active mode with real-time protection on. The
built-in feature is available on editions including Windows 11 Home and does not
require Microsoft 365 E5; enterprise management/reporting has separate licensing.
Show detected antivirus readiness, elevation, policy restrictions and applicable
management requirements before apply. Do not infer an Endpoint subscription,
cloud account or organizational membership prerequisite from the article's
enterprise product heading. Verify standalone local-account behavior separately.
No automatic replacement of another antivirus, tamper-protection bypass, cloud
submission changes or organizational enrollment is part of this operation.

Show actual default and additional protected locations on the accepted build;
do not assume every important folder is covered. Show explicit allowed apps
separately from Defender's automatically trusted apps. An empty explicit list
does not mean no apps are trusted. Never allow all recently blocked apps or add
antivirus exclusions as a compatibility fix. Folder/app changes need separate
reviewed metadata, versioned capture and exact recovery before RIDE offers them.
The present mode operation leaves those lists intact, including when switched
off; saved restore recovers its prior literal mode rather than those lists.

Suggested guided readiness sequence:

1. Inspect effective Defender readiness and list important data locations,
   coverage and existing explicit allowances.
2. Offer a deliberate audit period to find application conflicts. Clearly show
   that Audit is an assessment stage and does not deliver blocking protection.
3. Review needed applications individually, with manual Windows Security steps
   until list management has a reviewed recovery contract.
4. Enable blocking and verify both a denied benign write by an untrusted test
   app and permitted normal work by an intended trusted app in a disposable VM.
5. Present a separately verified recovery method, retention and restore exercise.
   Guidance should include backups recoverable independently of the working PC;
   a successful CFA preference write cannot establish recovery readiness.

OneDrive recovery is an optional separate account/service workflow. Show the
chosen recovery feature's subscription and account requirements from its
[official restore guide](https://support.microsoft.com/en-us/onedrive/restore-your-onedrive)
before offering it; do not create an account, upload files or assume a subscription
through CFA. The complete outcome is protected selected data plus usable apps
and tested recovery, without a blanket ransomware-immunity or security-level
claim. Missing inspection/list-management/recovery controls remain visible manual
prerequisites before any runnable profile is presented as achieving that outcome.

The handler accepts numeric values 0 through 6 for literal recovery, while the
current feature/configuration references enumerate a narrower mode set and the
cmdlet reference summarizes only the three main modes. Validate actual enum
values on each accepted build before expanding choices or narrowing recovery.
Do not relabel disk-only or unknown captured modes as normal On, silently coerce
them, or treat every integer in the handler range as a supported public state.
The documented Off default is not a captured prior value or effective managed
default; review the current generic TargetDefaults metadata during implementation.

Verify GUI correspondence, audit versus actual denied writes, redirected/custom
folders, app compatibility, managed restrictions and exact mode restoration.
Previously recorded lifecycle tests establish mode round trips only. The catalog
declares Windows 11; Server requires its own applicable feature acceptance before
support expansion. No workstation integration test, catalog, handler, profile or
migration-estimate change is made by this documentation-only proposal.

### Accepted Controlled folder access decision, 2026-10-11

The user accepted GUI-aligned On/Off, advanced Audit with its nonblocking effect
explicit, and optional Protect important folders from unauthorized changes
guidance. Show active Defender/real-time protection, administrator and applicable
edition/account/management requirements; distinguish built-in protection from
licensed management and optional recovery services. Make actual folder coverage,
app compatibility, blocking evidence and tested recovery part of the guided
outcome. Preserve the stable ID, existing states and literal mode recovery.
Folder/app list management, effective inspection, enum/default validation and
Server feature acceptance remain follow-up work. This records design acceptance
only; no system, catalog, handler, profile or migration-estimate change is made.

### Sound scheme, startup sound and editing policy review, 2026-10-11

Propose one normal Sound scheme control with GUI choices No Sounds and Windows
Default, corresponding to Sound control panel > Sounds > Sound Scheme. Keep the
selector and existing program-event mappings together: those values implement
one user choice, not independently useful toggles. Retain the published
windows.registered-sound-scheme ID, NoneScheme=.None and
WindowsDefaultScheme=.Default, with captured prior configuration as a separate
restore workflow. Neither state removes overrides or restores a saved custom
scheme. Defer additional custom-scheme choices until discovery, completion,
validation and recovery are designed together.

Microsoft's [Windows themes guide](https://support.microsoft.com/en-us/windows/experience/personalization/personalize-your-windows-experience-with-themes)
provides a Windows-wide reference for the Sounds customization area. Prefer it
over a Surface-specific page in normal feature guidance. The existing
[Surface sound guide](https://support.microsoft.com/en-us/surface/audio/surface-sound-volume-and-audio-accessories)
does document Settings > System > Sound > More sound settings > Sounds and
individual Program Events/Test/Apply, but its product scope and broad page title
should be clear. Neither reference establishes the complete AppEvents registry
copy/refresh implementation. Do not invent a fragment or imply a GUI behavior
guide documents every registry value; current-build GUI evidence remains needed.

Both legacy selectors selected the preset and copied every existing event into
.Current. They also created missing preset keys and normalized source preset
values to String. The maintained handler instead preserves source keys/types,
expands environment variables for the copied current paths and maps absent source
values to empty strings. Record this deliberate recovery-friendly difference;
verify that it matches the visible outcome before claiming full legacy/GUI parity.

Keep source customizations intact. Windows Default means the registered .Default
preset, which may have been customized; it is not a factory reset. No Sounds
selects the registered .None preset. If that preset contains nonempty mappings,
preview the affected events and flag that the selected preset will still contain
sounds. Do not silently erase the source or force all current mappings empty
under an unchanged published state. A future guaranteed-silent event preset
would require a distinct reviewed choice and recovery contract. An empty mapped
path, missing sound file and missing source event are different diagnostic facts.

Show the selected preset alongside whether actual current event mappings match
it; a selector alone does not prove success. Display custom/mixed current mappings
without coercing them. Preview affected applications/events and lost current
customizations before apply. An unavailable or empty event registration remains
unavailable; do not manufacture registrations or install audio components. The
operation affects the current user and requires no elevation, subscription or
cloud account. Audio hardware/output readiness is needed for playback evidence,
not for a successful registry write. Themes or later application installation
may change mappings; this is not continuous enforcement.

Keep Windows startup sound separate, with its related Play Windows Startup sound
checkbox mapping verified on each accepted build. Its current machine-scoped
operation requires elevation; the user-scoped scheme does not. Likewise retain
Changing the sound scheme as a separate advanced editing policy, not a muting
option. Microsoft's [exact policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_nosoundschemeui)
documents a user policy and supported Pro/Enterprise/Education/IoT editions.
The catalog corrects the legacy HKLM write to HKCU; verify effective policy and
managed precedence. Legacy enable removed the override, whereas current Allowed
writes zero and WindowsDefault removes it. Preserve that distinction, IDs and
saved restore; do not automatically unlock the GUI as part of choosing a scheme.

Explain that scheme selection covers registered program-event sounds. Media,
calls, independently generated app audio, startup sound and device volume are
separate controls. Removing audible cues can affect how the user notices events;
do not advertise No Sounds as a universal silent-PC or performance/security
outcome. No combined all-audio preset is proposed in this review.

Acceptance must compare both choices with the GUI, refresh behavior and actual
event playback in a disposable Windows 11 environment. Cover custom presets,
expanded paths, absent/malformed source values, mixed current mappings and
partial-write reporting. Verify saved restoration of raw types, values and
absence without rewriting source presets or newly registered events. The current
restore loop can recreate captured event paths that disappeared; decide and
validate the missing-event recovery policy before claiming safe behavior across
application uninstall/reinstall. Prior mocked/lifecycle tests do not establish
audible outcome. Server/audio availability requires separate acceptance before
support expansion. This is documentation-only review with no system, catalog,
handler, profile or migration-estimate change.

### Accepted sound-scheme decision, 2026-10-11

The user accepted one combined GUI-aligned Sound scheme choice with No Sounds
and Windows Default, keeping startup sound separate and scheme-editing permission
as an advanced policy. Preserve registered preset customizations and saved prior
configuration; show a warning for nonempty No Sounds preset mappings and avoid
factory-reset/all-audio claims. GUI refresh/playback, missing-event recovery,
source-value handling and policy/reverse-state differences remain acceptance
work. This records design acceptance only; no system, catalog, handler, profile
or migration-estimate change is made.

### Current Edge background activity and installation shortcut review, 2026-10-11

Propose two individually useful controls, Startup boost and Continue running
background apps after Microsoft Edge closes, plus an optional Reduce Edge
background activity guided choice that explicitly disables both. Keep Create
Microsoft Edge desktop shortcut during installation as a separate advanced
installation policy. Preserve all three published application.edge-* IDs and
their Enabled=1, Disabled=0 and WindowsDefault=value-removal states. Name removal
Use Edge/user configuration (remove this local policy), rather than implying a
forced On/Off default. Saved restore recovers the literal prior value/type/absence.

The current catalog uses mandatory HKLM policies, not personal browser preference
edits. Keep that distinction visible beside the GUI-related names: these changes
apply across users and may lock the corresponding GUI choices. Do not silently
switch the stable IDs to user scope or Recommended policy paths. A future normal
user-editable preference workflow requires its own mapping, migration and exact
recovery review. Show local policy, effective Edge policy and underlying user
choice separately wherever inspection can establish them.

Microsoft's [StartupBoostEnabled reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/startupboostenabled)
documents early/background process startup and interaction with background mode.
Its unconfigured initial state can be On or Off. The
[BackgroundModeEnabled reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/backgroundmodeenabled)
documents background apps/session retention after the last window closes; its
unconfigured initial state is Off, with user choice allowed. Both policies support
mandatory/recommended forms, dynamic refresh and Microsoft-account profiles;
neither is per-profile. Review current generic TargetDefaults using those
distinct documented defaults, without treating an initial product default as
the live user preference or an effective managed default.

The [startup boost GUI guide](https://support.microsoft.com/en-us/edge/get-help-with-startup-boost)
now identifies edge://settings/system/manageSystem; policy pages still mention
edge://settings/system. Verify the destination and exact labels on the accepted
browser version. The guide describes resource/extension conditions and excludes
servers in its availability/default heuristic discussion; do not extrapolate
Server feature support from a successful policy write. Disabling startup boost
can trade faster launch for less background activity. Disabling background apps
can stop intended app/session work after closing the browser. Neither setting
is an Edge uninstall, update-disable control or guarantee of zero Edge-related
processes, including independently hosted WebView2 applications.

Legacy DisableEdgePreload wrote AllowPrelaunch and AllowTabPreloading for
EdgeHTML. Legacy enable removed both overrides. The current pair addresses
related intent in current Edge, not equivalent tab preloading or a literal port
of those values. Explicit current Enabled states therefore differ from the
legacy reverse selector's removal semantics. Leave historical keys untouched;
cleanup requires separate evidence and recovery. The optional combined outcome
must display both controls and effective applicability, with partial coverage
if either is unavailable or overridden. No implicit browser termination, session
discard, update/service/task changes or automatic profile inclusion is proposed.

The [exact shortcut policy section](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies#createdesktopshortcutdefault)
documents Edge Update 1.3.128.0+, installation-only creation, default creation
when unconfigured and channel-specific precedence. Name and describe that timing
clearly: it has no effect on an already installed browser. Legacy shortcut
suppression targeted an Explorer value described as affecting certain Windows
updates; this replacement has narrower, different behavior. Existing-shortcut
deletion and later update/reboot removal are separate workflows. Do not add
RemoveDesktopShortcut policies or delete user-created shortcuts implicitly.
Restoring the creation-policy value does not undo a shortcut created by an
intervening installer; preview this configuration-versus-artifact boundary.

Show detected Edge/Edge Update versions, channel, machine scope, required admin
rights and effective managed restrictions. The individual browser policy pages
allow Microsoft-account profiles, but this does not prove standalone local-account
registry applicability or every Windows edition. Microsoft's
[configuration guide](https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge)
describes registry deployment in AD-joined/Intune-managed contexts and separate
local Group Policy setup. Reconcile that guidance with actual standalone/Home,
local-account and managed behavior before declaring membership/edition coverage.
Do not infer a paid subscription or enroll/join a machine to make a write apply;
any required management/license/account prerequisite must be shown explicitly.

Acceptance needs edge://policy source/level/status, locked GUI behavior, all four
startup/background combinations, normal close/reopen/sign-in process behavior
and policy removal with an existing user preference. Do not equate dynamic
refresh metadata with immediate termination of existing work. Test shortcut
creation only in disposable installation scenarios, including preexisting Edge,
channel overrides and user/system installation scope. Previously recorded
lifecycle tests establish registry recovery, not browser or installer outcomes.
Keep Windows 11-only declarations until applicable additional-target evidence
exists. This documentation-only proposal changes no system, catalog, handler,
profile or migration estimate.

### Accepted Edge decision and scope follow-up, 2026-10-11

The user accepted individual Startup boost/background-app controls, optional
Reduce Edge background activity and a separate advanced installation-shortcut
policy, while asking whether user/machine enforcement scope is clear and
consistent throughout RIDE. Preserve the existing machine-wide policy contracts,
IDs, explicit/removal states and captured recovery. Treat the cross-cutting
presentation and applicability audit below as follow-up to this acceptance.
Browser/installer behavior, standalone/managed requirements and GUI acceptance
remain open. No system, catalog, handler, profile or migration-estimate change
is made by this design acceptance.

### User/machine scope versus enforcement audit, 2026-10-11

The user's question exposes two independent dimensions: who the setting applies
to, and whether it is a preference or a policy. A current-user policy can enforce
and lock a choice; a machine setting can be an ordinary preference. Elevation is
a third dimension. Do not imply User means user-editable, Machine means enforced,
or administrator rights establish policy precedence.

Read-only source audit of the current catalog found 260 setting operations:
101 User and 159 Machine. All 193 scalar RegistryValue operations matched their
declared HKCU/HKLM scope, and every machine setting declared RequiresAdmin=true.
These checks establish internal declaration consistency, not effective platform
scope, correct Microsoft policy applicability or tested current-user identity.
The audit parsed individual catalog AST literals without importing handlers or
reading/changing workstation configuration. Counts are a dated catalog snapshot,
not legacy migration estimates or a classification by enforcement.

Discovery objects expose Scope and RequiresAdmin. Individual show includes all
catalog metadata, plans include Scope, and generated operations documentation has
Scope/Admin columns. Default status rows and group member show rows omit scope;
plans omit a separate administrator field. There is no standardized catalog
field for preference/mandatory/recommended behavior, supported alternative scopes,
GUI editability or effective policy source. Descriptions sometimes explain these,
but readers cannot compare them consistently. Generic scalar RegistryValue
validation also lacks the root-versus-scope check already present for coordinated
RegistryValueSet components. Record that validation gap for implementation.

For example, current Edge startup boost is a machine policy, Explorer file-name
extension visibility is a current-user preference, sound-scheme editing is a
current-user policy, and startup sound is a machine preference. Microsoft's
[Edge configuration guide](https://learn.microsoft.com/en-us/deployedge/configure-microsoft-edge)
separates computer/user configuration from mandatory/recommended levels; mandatory
overrides user choices, while recommended settings remain overridable. Do not
generalize Edge's precedence rules to every Windows feature.

Propose a consistent setting presentation in list/search, show, plan/preview,
status, group/profile details and generated documentation:

| Dimension | User-facing information |
| --- | --- |
| Applies to | Current Windows user, whole device/all applicable users, or explicit feature-specific scope; show the actual user identity where relevant |
| Behavior | Preference, enforced policy, recommended policy, or another explained configuration method; unresolved behavior stays unverified |
| GUI effect | Whether the related GUI remains editable, becomes locked, or depends on higher policy; no assumption from registry location alone |
| Privilege | Administrator required or current-user context; distinguish privilege from who receives the setting |
| Effective result | Local value versus effective policy, precedence/source when observable, and unavailable/unknown results |
| Other supported choices | Documented alternate scope/level and whether RIDE implements it; show gaps rather than implying a runtime switch exists |

A catalog ID currently fixes its scope; RIDE has no generic setting -Scope option.
Do not change scope based on elevation or silently move existing IDs between
HKCU/HKLM or mandatory/recommended paths. Prefer the reviewed GUI/user intent when
designing new controls; machine enforcement must be explicit. If both scopes are
useful and officially supported, introduce distinguishable reviewed operations
or an explicit versioned selection contract, with independent recovery. Do not
duplicate every setting simply because a second registry location is possible.

Before metadata/display implementation, audit each policy's official supported
scope, privilege, edition/build, account requirements, reverse semantics and
precedence. Add focused validation for declared scope/path/handler consistency,
and meaningful tests for all affected display paths. In disposable environments,
verify user policies, mixed-scope plans, same-account elevation and alternate-admin
identity, ensuring User operations affect the intended user rather than silently
using the elevated administrator's profile. Preserve existing saved-state stores
and recovery contracts; any schema extension needs a documented compatibility
path. This is a proposed cross-cutting rule and implementation agenda, not a
claim that catalog semantics or user-visible presentation have already changed.

### Accepted scope and enforcement presentation rule, 2026-10-11

The user accepted separate visible Applies to, Behavior, GUI effect and
Administrator required labels throughout setting discovery, details, planning,
status and documentation. Distinguish current-user policies from preferences and
machine preferences from enforcement. Preserve each published ID's fixed scope
and saved recovery; introduce alternate scope/level choices only where supported
and independently useful, with clear contracts. Effective policy/source,
requirements, scalar validation and intended-user execution checks remain
implementation/acceptance work. This acceptance changes no catalog, handler,
profile, display code, system state or migration estimate.

### Windows Firewall profiles and legacy policy review, 2026-10-11

Propose normal GUI-aligned Windows Firewall controls for Domain, Private and
Public profiles, with an optional Enable Windows Firewall for all network types
guided choice. Retain windows.firewall-standard-profile-policy as an advanced
legacy policy with stable states/recovery, outside recommended composition
pending effective behavior evidence. Do not replace that ID's narrow registry
contract with a modern all-profile command. These proposed modern controls are
new implementation scope, not already available or functionally accepted.

The legacy DisableFirewall wrote StandardProfile/EnableFirewall=0; EnableFirewall
removed that value. The catalog also offers explicit Enabled=1, so its
WindowsDefault removal corresponds to legacy enable more closely than Enabled.
Explain that removal relinquishes this override; it does not force protection
on or restore a saved prior value. Preserve literal value/type/absence recovery.

Microsoft's [exact value reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2100c552-7f37-4a7f-9fa0-2a864ab87212)
documents EnableFirewall under the policy profile keys. The
[profile processing specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/abe4eb0f-e3a0-48cc-bde3-5dc89b81b40b)
states that StandardProfile applies to Private/Public only when neither modern
profile key exists; if either exists, StandardProfile is ignored. It does not
control Domain. Prefer these focused references over the current broad overview
when updating legacy metadata. Verify current-build effective behavior, including
key existence without an EnableFirewall value, rather than marking it entirely
obsolete or reporting a scalar match as complete firewall protection.

Microsoft's [Windows Security GUI guide](https://support.microsoft.com/en-us/windows/security/windows-security/firewall-and-network-protection-in-the-windows-security-app)
shows Firewall & network protection > Domain/Private/Public network > Microsoft
Defender Firewall On/Off. The [Set-NetFirewallProfile reference](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps)
provides profile-specific configuration corresponding to the advanced console.
Design the new normal controls around explicit local per-profile enablement,
with reviewed GUI parity and independent recovery. Show Applies to: whole device,
selected network profile; Behavior: local firewall profile configuration subject
to managed policy; Administrator required: yes. This is distinct from a per-user
policy, and from the retained enforced-policy override. Do not change the network
category, create rules or write GPO/MDM policy to make local configuration effective.

Use [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps)
to distinguish local PersistentStore settings from resultant ActiveStore policy.
Show each configured profile, its effective enablement and active network(s).
Inactive Domain does not mean an unavailable setting or a requirement to join a
domain. Show applicable edition/build/component requirements independently of
network membership. Capture local values before changes, including any supported
unset/native state, and verify precise restoration without coercing a managed
result into local configuration. An effective read must not be used as the sole
pre-change local snapshot.

The optional all-network-types choice should enable the three reviewed profile
controls and retain mixed prior states for recovery. Successful enabling is only
one part of network protection: rules, allowed applications, profiles/peers and
service readiness still determine exposure. Offer clear links to the previously
reviewed Remote Desktop/file-sharing guidance rather than silently broadening
exceptions. Keep Off an explicit advanced choice with affected profile and
exposure stated, outside recommended security composition. Microsoft's
[overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)
recommends keeping the firewall enabled and says stopping MpsSvc is unsupported.
Do not stop that service, reset/delete rules or use Restore firewalls to default
as saved-run recovery.

Acceptance requires GUI/effective-state checks, legacy-key precedence, mixed
profiles, managed overrides, repeat apply and exact local recovery, plus benign
allowed/blocked connections in disposable environments. Preserve rule definitions
and unrelated profile settings. A profile change can disrupt remote administration;
prepare independent local recovery before connection tests. Windows 11 and any
proposed Server targets need separate applicable evidence; existing registry
round trips are not that evidence. This documentation-only proposal changes no
firewall, catalog, handler, profile or migration estimate.

### StandardProfile necessity clarification, 2026-10-11

The user asked what StandardProfile does and whether RIDE needs it. It is a
compatibility policy location for non-domain firewall configuration, not a
fourth modern network category. The profile-processing specification linked
above applies its settings to Private and Public only when both corresponding
modern policy keys are absent; existence of either modern key suppresses it.
The legacy disable selector wrote EnableFirewall=0; its enable selector removed
that override rather than explicitly turning on every firewall profile.

Revised recommendation: mark the existing operation legacy/deprecated and keep
it out of normal configuration choices and recommended profiles. Modern
Domain/Private/Public controls can express the desired fresh-machine outcome
without StandardProfile. Preserve the published ID and literal saved recovery;
retain explicit inspection/compatibility access while defining a retirement
path. Existing legacy overrides may still affect protection, so do not delete
them automatically or assert they are always inert. Flag a relevant override
and explain its potential precedence effect when inspecting modern readiness.
Any cleanup must be explicit, previewed and recoverable. This supersedes the
earlier recommendation to retain it as a generally useful advanced setting,
but remains a proposed disposition pending the user's decision. No operation
is removed, scope changed or system state altered by this clarification.

### Accepted StandardProfile disposition, 2026-10-11

The user accepted marking StandardProfile legacy/deprecated and excluding it
from normal choices and recommended profiles. Preserve the existing ID,
inspection/compatibility access and literal saved recovery while defining its
retirement path. Existing overrides may still matter; flag their applicability
and require explicit, previewed, recoverable cleanup. Modern Domain/Private/Public
controls remain a proposed replacement requiring implementation and acceptance.
This acceptance does not remove an operation or change the catalog, system,
handler, profiles or migration estimate.

### Proxy detection, setup scripts and WinHTTP review, 2026-10-11

Propose separate normal Automatically detect settings and Use setup script
controls, mapped to Settings > Network & internet > Proxy, with advanced WinHTTP
automatic proxy discovery and optional Turn off automatic proxy discovery
guidance. The guided scope must show current-user Windows proxy detection plus
device-wide WinHTTP detection; it is not all users/all applications. Treat the
setup-script switch and required address as one feature, distinct from discovery,
manual proxy servers and VPN-specific settings. These normal controls are new
implementation scope and require mapping/recovery acceptance first.

Microsoft's [Windows proxy guide](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/use-a-proxy-server-in-windows)
distinguishes detection, script address, manual proxy and separate VPN proxy
configuration. Explain each effect and whether managed settings override or
lock it. Normal current-user preferences should not silently become machine
policies or configure other users. Detect intended user identity and effective
scope before offering changes, including managed per-machine arrangements;
unverified applicability stays visible. Required organizational proxy details
are configuration prerequisites, not an inferred Microsoft subscription or
account-membership requirement. Do not bypass management or clear a needed
corporate proxy as an automatic troubleshooting step.

Legacy DisableIEProxyAutoconfig/EnableIEProxyAutoconfig replace byte 8 of
DefaultConnectionSettings with 1/9. They do not preserve individual choices in
that byte. Do not reproduce that packed overwrite or equate the function names
with disabling every proxy mechanism. Microsoft's
[WinINet option reference](https://learn.microsoft.com/en-us/windows/win32/api/wininet/ns-wininet-internet_per_conn_optionw)
defines separate detection, script, manual-proxy and direct connection flags;
its [connection API guide](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)
describes querying/setting a selected connection. Prefer those documented APIs
over fixed byte mutation, preserving unrelated options. The API documentation
does not establish the legacy byte layout or guarantee Windows 11 GUI parity.
Verify LAN versus named/VPN connection identity, effective policy and refresh
before choosing the handler and versioned recovery contract.

For Use setup script, Off should preserve the configured address for later use;
On needs a valid specified or retained address. Do not invent a PAC address,
download/test its content on discovery, or automatically enable discovery to
compensate for a missing address. Capture prior flags and address separately;
verify exact prior configuration and partial-failure recovery. New address input
needs appropriate validation and help. Manual proxy settings and exclusions
remain intact, and no generic proxy reset is included.

The existing windows.proxy-autoconfig-url operation only writes an empty
AutoconfigURL or removes it. Its Enabled state removes the override; it does not
enable Use setup script or restore a previous address. Present it as an advanced
Clear saved proxy setup-script address compatibility operation with exact state
descriptions, retaining ID/state/recovery semantics. Do not silently turn that
published operation into the new normal toggle. Its current broad Server-focused
reference does not document its exact scalar mapping; add the current GUI/API
references with that limitation explicit when implementing presentation changes.

The existing windows.winhttp-wpad-policy controls machine DisableWpad, with
Disabled=1 and Enabled=value removal. The misleading legacy *AutoProxySvc names
and messages did not actually stop/start a service. Prefer advanced WinHTTP
automatic proxy discovery configuration wording; this is not a user GUI-locking
policy or universal proxy switch. Microsoft's
[exact reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features)
documents this value for WinHTTP API discovery and separately advises turning
off discovery in Windows Settings. Direct DNS resolution of WPAD can still occur.
Preserve the declared machine scope/admin requirement and saved literal recovery;
no service changes or proxy-authentication changes are part of the control.

Optional discovery-off guidance should inspect existing proxy dependencies,
offer the reviewed current-user detection and WinHTTP controls together, and
verify intended connectivity through an explicitly configured path where needed.
It must not clear a PAC address, remove manual proxies, change DNS or claim that
all WPAD-related traffic/attacks are prevented. Show partial coverage for other
users, per-application overrides and VPNs. The existing default profile already
clears the script address and disables WinHTTP discovery; review those selections
and their connectivity implications before recommending that profile broadly.
They are not changed or accepted by this proposal.

Acceptance requires GUI/API correspondence, mixed flags, managed restrictions,
local/alternate-admin user identity, missing data, named connections, URL
preservation and exact recovery. Verify actual discovery and representative
browser/WinHTTP connectivity in disposable environments, including corporate
proxy requirements. WinINet desktop-client scope is distinct from WinHTTP service
use; declared Server coverage needs its own applicable checks. No proxy, network,
profile, catalog, handler or migration estimate changes in this documentation-only
review. The packed-data outcome remains deferred until implementation and feature
acceptance, even if this design is approved.

### Accepted proxy configuration decision, 2026-10-11

The user accepted separate GUI-aligned Automatically detect settings and coherent
Use setup script/address controls, with advanced machine WinHTTP discovery and
optional discovery-off guidance showing both scopes. Preserve the script address
when toggling its use off, unrelated manual/VPN options, fixed published IDs and
literal saved recovery. Existing scalar URL-clear/removal semantics remain
compatibility controls, not a normal script enable switch. Documented API mapping,
managed scope, connectivity, intended-user identity, default-profile selections
and exact recovery remain implementation/acceptance work. The packed-data outcome
is not complete. No proxy, system, catalog, handler, profile or estimate change
is made by this design acceptance.

### System Protection and restore-point review, 2026-10-11

Propose a GUI-aligned System protection control, initially for the Windows 11
system volume, with protection On as the normal recovery choice and Off as an
advanced explicit choice. Show the actual affected volumes before applying;
do not promise an isolated per-drive toggle until the selected backend proves
that boundary. This is machine configuration requiring administrator rights,
not a per-user preference or automatically enforced policy. Organizational
restrictions and unavailable volumes must remain visible. No separate paid
subscription, cloud account or membership is proposed for this local feature.
Windows Server is excluded: the legacy functions explicitly exclude Server and
Microsoft's [SystemRestore API](https://learn.microsoft.com/en-us/windows/win32/sr/systemrestore)
declares no supported server. Windows 11 handler support still requires VM checks.

Legacy DisableRestorePoints/EnableRestorePoints call the Windows PowerShell
ComputerRestore cmdlets with the system drive. They do not execute their
commented shadow deletion or 10 GB storage-resize commands, or create a manual
restore point. Their system-drive wording does not establish actual scope:
Microsoft's [Disable method](https://learn.microsoft.com/en-us/windows/win32/sr/disable-systemrestore)
says disabling the system drive stops monitoring all drives, while its
[Enable method](https://learn.microsoft.com/en-us/windows/win32/sr/enable-systemrestore)
describes enabling the system drive as monitoring all drives and returning
before enablement completes. Verify these older API semantics on current builds
and reconcile them with the cmdlet and GUI behavior before selecting a handler.
Capture every affected volume's prior configuration and report partial outcomes.

Use System Properties > System Protection > Configure wording and show protection
status separately from disk-space allowance and existing restore points.
Microsoft's [current GUI guide](https://support.microsoft.com/en-us/windows/experience/backup-recovery/system-protection)
describes enablement, storage allocation and manual creation separately. Enabling
protection alone is not evidence that a usable point exists. Do not silently
resize storage, create a point or run System Restore when toggling protection.
Storage allocation and explicit Create a restore point can be later distinct
choices with their own lifecycle contracts, rather than hidden enable side effects.

The legacy comment claims disabling preserves existing points. Do not carry that
claim into RIDE: Microsoft's [older System Restore troubleshooting instructions](https://learn.microsoft.com/en-us/troubleshoot/windows-hardware/drivers/disabling-fbwf-causes-crash)
describe a deletion warning for turning the feature off. That older product
reference is a risk signal, not Windows 11 cmdlet acceptance. Verify point
retention/deletion for the chosen backend in a disposable Windows 11 VM. Until
then treat Off as potentially destructive and exclude it from recommended
profiles. Re-enabling protection cannot reconstruct deleted restore history.

Recovery must distinguish restoring configuration from recovering historical
points. Obtain a reliable read-only enabled-volume inspection method; absence
of points, a zero allowance or a generic VSS snapshot list is not sufficient
evidence of protection state. Capture volume identity, enabled state and relevant
storage configuration without changing unrelated backup-owned shadows. Missing
volumes and managed restrictions need explicit reporting. If a change destroys
points, configuration recovery is compensating, not Exact. Restoring a previously
Off state after enabling also needs review for loss of points created meanwhile;
ordinary saved-run restoration must not conceal that destructive consequence.

Extend the proposed Prepare Windows recovery guidance with optional System
Protection checks: inspect protection and allowance, explicitly offer point
creation, then verify the point exists. Explain its limits alongside independent
file backups, recovery media, Windows RE and BitLocker recovery access. A RIDE
snapshot, restore point and full backup are different recovery assets; guidance
must not present any one of them as a complete substitute for the others.

Defaults remain evidence work: the current Support guide says protection is not
enabled by default, whereas the older [Enable-ComputerRestore reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/enable-computerrestore?view=powershell-5.1)
describes enablement on eligible drives by default. Do not invent a universal
default or confuse RIDE's preferred On choice with a platform default. Acceptance
requires current GUI/native parity, mixed-volume scope, asynchronous completion,
policy restrictions, idempotence, actual point retention/deletion and honest
recovery reporting. This is a proposed design only; no host Windows changes,
catalog/profile implementation or estimate reduction accompanies the review.

### Accepted System Protection decision, 2026-10-11

The user accepted GUI-aligned System protection with normal On, advanced Off,
explicit affected-volume scope and machine/admin requirements. Preserve storage
allowance; manual point creation is a distinct action. Extend recovery guidance
without implying that restore points replace backups or recovery media. Initial
implementation targets Windows 11 subject to acceptance; no Server port is
proposed. Enabled-volume inspection, system-drive coupling, completion, actual
point deletion/retention and platform defaults remain evidence work. Restoring
configuration cannot recreate deleted history; any destructive recovery must be
reported honestly rather than labeled Exact. No Windows, catalog, profile,
handler or estimate changes accompany this design acceptance.

### Storage Sense preferences and legacy reset review, 2026-10-11

Propose a normal GUI-aligned Storage Sense On/Off preference for the current
user, preserving their cleanup schedule and content choices when turned off.
Keep windows.storage-sense, its published states and literal saved recovery.
Verify that its StoragePolicy value 01 matches the current Windows 11 master
switch / Automatic user content cleanup before updating the presentation.
The existing Microsoft reference documents behavior, not this numeric registry
mapping. Do not claim that Off prevents every Windows temporary-file cleanup,
or that this user-scoped setting configures other accounts or all volumes.

Legacy EnableStorageSense writes 01=1 and StoragePoliciesNotified=1; its reverse
recursively deletes the whole StoragePolicy tree. The maintained operation
already writes only 01=1/0 or removes that value. Retire the legacy broad reset
as normal disable behavior: Off should write the explicit disabled preference
once verified, leaving other settings intact. Do not add an all-preferences
reset operation without a separate demonstrated need and bounded recovery
design. Omit the notification-marker write; no documented independent user
outcome has been established for it. WindowsDefault removes only the enablement
value; it does not reset all cleanup options or guarantee that Windows stays Off.

Use Settings > System > Storage > Storage Sense terminology, with understandable
separate choices for schedule, temporary files, Recycle Bin retention, Downloads
retention and locally available cloud content where current GUI mappings can
be verified. These additional choices are future scope, not already migrated
controls. Distinguish time in the Recycle Bin from time since a Downloads file
was opened; do not apply one generic retention rule to both. Preserve existing
choices on enablement, including Downloads and cloud settings. Do not silently
replace a user's cleanup configuration with a preset.

Microsoft's [user guide](https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/manage-drive-space-with-storage-sense)
describes user-specific choices and system-drive scope. Cloud content can become
online-only without deleting the cloud file; pinned content is exempt. Explain
the resulting offline-access limitation separately from permanent local file
deletion. Cloud controls depend on a signed-in supported cloud provider and
applicable content; normal local cleanup has no proposed cloud membership or
subscription requirement. Inspect availability rather than assuming OneDrive
or manufacturing another provider's settings. The guide includes both general
opt-in wording and a Windows 11 22H2 cloud-default qualification, so current-build
defaults and existing account configuration need explicit evidence.

Optional Configure automatic storage cleanup guidance should walk through the
individual GUI choices, summarize what may be deleted or made online-only and
offer changes only to understood settings. Do not pick a Downloads retention
period, evict cloud content or run cleanup automatically. Run Storage Sense now,
manual file deletion and removal of previous Windows installations are distinct
actions requiring their own review; none is an implicit part of this setting.

Keep a possible advanced machine enforcement control separate from the normal
preference and existing published ID. Microsoft's
[AllowStorageSenseGlobal policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-storage#allowstoragesenseglobal)
forces On or Off and prevents users changing that toggle; Not configured returns
choice to users, not a guaranteed Off state. Its device policy lists Pro,
Enterprise, Education and IoT Enterprise editions, not Home. Show supported
edition, machine/admin scope and GUI lock explicitly; local policy deployment
must not inherit Intune/cloud membership requirements. Any actual Intune workflow
has separate prerequisites. Report effective management and blocked preferences;
do not bypass higher-priority policy or silently promote the user control to
machine enforcement. Advanced enforcement remains separate proposed scope.

Saved-run restoration can recover the captured preference value/type/absence;
it cannot recover files subsequently removed by Windows. Keep that boundary
explicit even where registry rollback is Exact. Read-only show/plan should
eventually display effective enablement and relevant cleanup choices, with
unknown data reported honestly. Verify GUI/native parity, intended-user identity,
policy precedence, low-space activation, preservation of other values, literal
recovery and actual content effects in disposable Windows 11 environments.
Microsoft's [configuration overview](https://learn.microsoft.com/en-us/windows/configuration/storage/storage-sense)
and user guide differ in default wording; separate initial, low-space and managed
behavior before adding default metadata. No automatic profile selection, Server
support expansion, host cleanup, catalog/handler changes or estimate reduction
accompanies this proposed design. Broader options and remaining feature evidence
stay tracked rather than being closed by a registry round trip.

### Accepted Storage Sense decision, 2026-10-11

The user accepted a normal GUI-aligned current-user On/Off preference that
preserves cleanup choices, retirement of recursive preference deletion as
disable behavior, and omission of the unverified notification-marker write.
Keep the published ID, states and literal saved recovery; WindowsDefault is
enablement-value removal, not a full reset. Individual GUI choices and optional
configuration guidance remain future scope, with advanced machine enforcement
kept separate and its requirements/GUI lock explicit. Explain permanent file
deletion versus cloud content becoming online-only. Current Windows 11 mapping,
effective policy, defaults, content outcomes and configuration preservation
remain acceptance work. Saved preference recovery cannot recover deleted files.
No host cleanup, catalog, profile, handler or estimate changes accompany this
design acceptance.

### Task Manager details selector review, 2026-10-11

Propose retiring ShowTaskManagerDetails/HideTaskManagerDetails as migration
targets for current Windows 11. Preserve their historical source and record
their intended expanded/compact presentation outcome; do not add a catalog
operation that changes byte 28 of the private Preferences blob. No maintained
catalog operation or profile selection for this tweak was found, so there is
no published RIDE ID or saved-run format to remap or remove for this decision.

The legacy Show function starts a hidden Task Manager instance, polls for up
to 30 seconds to obtain its Preferences value, stops the returned process and
sets byte 28 to 0. Hide reads the existing blob and sets byte 28 to 1, doing
nothing if it is absent. Neither demonstrates a supported layout or guards the
byte offset against a different version/short value. This initialization and
process lifecycle must not become part of setting inspection or application.
Do not launch, poll or terminate Task Manager to manufacture missing preferences,
delete its configuration tree, or overwrite unrelated preferences with a template.

Microsoft's [2021 Windows 11 announcement](https://blogs.windows.com/windows-insider/2021/09/02/announcing-windows-11-insider-preview-build-22000-176/)
describes More details as an expansion control. Its
[Windows 11 22H2 release documentation](https://learn.microsoft.com/en-us/windows/whats-new/whats-new-windows-11-version-22h2#improvements-to-task-manager)
records a redesigned Task Manager experience, and the
[redesign announcement](https://blogs.windows.com/windows-insider/2022/02/16/announcing-windows-11-insider-preview-build-22557/)
describes navigation and a settings page. These references establish UI evolution,
not the private binary layout or a current equivalent for byte 28. Do not label
this tweak Show the Details page, show more process columns, always on top,
default start page or a security restriction. Those are distinct potential
preferences and would need their own GUI mapping and user intent.

Leave presentation choices in Task Manager's GUI, with optional usage guidance
identifying the controls available on the actual build. New RIDE preferences
should be considered only for a demonstrated useful current outcome, bounded
mapping and recovery contract; none is an automatic replacement for this legacy
selector. A whole-blob registry round trip would not prove UI correctness and
could overwrite unrelated changes made after capture. Any future implementation
must address concurrent Task Manager writes, missing/changed layouts, current
user identity and preservation of unrelated choices without controlling a running
Task Manager instance. Do not invent default metadata, license requirements or
Windows Server support for an unimplemented replacement.

This is a proposed legacy-retirement disposition, not proof that every Windows
11 build lacks an expanded/compact UI or evidence that a binary mapping can never
be established. The outcome remains in the ledger pending the user's decision;
no implementation, host process changes or migration estimate reduction are
made in this documentation-only review.

### Accepted Task Manager retirement decision, 2026-10-11

The user accepted retirement of ShowTaskManagerDetails/HideTaskManagerDetails
from the current Windows 11 migration. Preserve historical source; add no
byte-28 operation, process launch/poll/stop sequence or preference reset. Leave
presentation choices in the actual Task Manager GUI. Any future RIDE preference
requires its own useful current outcome, verified mapping and bounded recovery;
it is not an automatic equivalent of the old expanded/compact selector. No
published catalog ID or saved-run format requires a migration for this retirement.
Move this one paired legacy outcome to the retired ledger. The settings range
remains 40-60 and the rounded overall estimate 160-215, about 190: one resolved
outcome falls within their existing uncertainty. Other partial settings and
acceptance work remain counted. No host or implementation change is made.

### F1 help TypeLib override review, 2026-10-11

Status: the initial retirement proposal below was not accepted. The user's
Windows-native preference supersedes it in the follow-up after this section.

Propose retiring DisableF1HelpKey/EnableF1HelpKey as direct setting migrations.
Preserve the historical implementation and its stated Explorer/Desktop intent;
add no COM override or keyboard hook to the maintained engine. No maintained
catalog operation or profile selection for this GUID/control was found, so no
published operation ID or saved-run schema requires remapping. This disposition
does not claim that accidental F1 help activation is no longer a useful concern.

Legacy DisableF1HelpKey creates current-user Classes\TypeLib overrides under
{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32 and win64, then writes empty
default strings. EnableF1HelpKey recursively deletes the entire 1.0\0 branch,
including any other registration data there; it does not restore captured prior
values or prove that Help is enabled. This is registration interference, not
a keyboard preference, hardware F1 disablement or verified all-application
behavior. Current-user writes must not be presented as machine-wide enforcement.

Microsoft's [type-library registration reference](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/automat/registering-a-type-library)
describes version/language/platform registration and the type-library file path.
Its [registry-view reference](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)
describes merged user/machine Classes views. Neither documents this GUID's blank
path as an Explorer F1 preference, its exact consumers or current Windows 11
behavior. The review found no authoritative GUI/policy mapping for the legacy
effect; that is an evidence limitation, not proof that no replacement can exist.
Do not invent a Microsoft settings-page link, default, security benefit or
Windows Server support for it.

Optional guidance for users who still want to avoid accidental F1 activation
can point to [PowerToys Keyboard Manager](https://learn.microsoft.com/en-us/windows/powertoys/keyboard-manager).
It documents F1-F12 remapping, app-specific shortcuts and the need for PowerToys
to run with Keyboard Manager enabled. Key remapping and targeted shortcuts have
different scopes; do not claim a global key remap reproduces Explorer/Desktop-only
suppression. Verify whether the requested single-key/app-scoped configuration is
actually available and test Explorer, Desktop and unrelated applications before
publishing a concrete recipe. Explain elevated-window and password-screen limits.
No implicit package installation, autostart change, global remap or prerequisite
cloud membership is part of this retirement; package and configuration workflows
remain distinct. A keyboard alternative is optional new scope, not accepted
feature-equivalent migration evidence.

Do not automatically remove old TypeLib overrides from a user's machine. Any
later explicit inspection/cleanup workflow needs bounded capture of the affected
registration, types, values, key existence and permissions, accurate ownership
and user identity, preview and recovery. If original pre-legacy data was never
captured, deleting an override cannot be called exact restoration of that data.
Do not run the legacy reverse selector as a repair or manufacture default paths.
Current help activation and collateral registration consumers would require
disposable-VM checks for any proposed replacement or cleanup workflow.

This is a proposed retirement of an unverified implementation, with the user
intent preserved for optional future guidance. The F1 outcome remains in the
migration ledger pending the user's decision. No host registration, keyboard,
package, catalog/profile changes or further estimate reduction accompanies this
documentation-only review.

### F1 help Windows-native preference and source comparison, 2026-10-11

The user wants to retain a solution for annoying F1 Help activation and prefers
one without third-party tools. Withdraw the proposed retirement of the outcome;
keep it pending native implementation/evidence review. Use the legacy
Explorer/Desktop scope as the initial intent, with preserving other applications'
F1 behavior as an explicit acceptance requirement. Do not infer acceptance of
any particular workaround or start applying one to the developer's workstation.

The user's [first article](https://learn.microsoft.com/en-us/answers/questions/2389836/how-can-i-stop-the-f1-key-from-opening-up-the-help)
suggests changing HelpPane.exe ownership/execution permissions or assigning an
IFEO Debugger value pointing to a nonexistent executable. It does not use the
legacy TypeLib override. Blocking HelpPane launches is a different scope from
intercepting the F1 key, potentially affecting other HelpPane callers. The
question also mentions media-key behavior; disabling Help does not make F1 a
volume key or resolve Fn-lock configuration. Do not silently reproduce these
file-permission, process-termination or machine debugger changes in RIDE.

The user's [second article](https://learn.microsoft.com/en-au/answers/questions/5857682/how-to-disable-the-application-based-f1-help-page)
uses a running AutoHotkey script conditional on the active explorer.exe window.
That targets the same stated Explorer scope through key interception, not COM
registration. It also reports the single-key/app-targeting limitation of its
PowerToys configuration. Neither answer establishes current Windows 11 acceptance
for the legacy GUID. Treat these Q&A answers as attributed troubleshooting
suggestions, not a Microsoft-supported GUI/policy contract for the workarounds.

Retain the two-value current-user TypeLib method as an advanced experimental
candidate for Stop F1 opening Windows Help in Explorer and on the desktop.
No third-party package or persistent background application is required by that
registry candidate. Its actual effectiveness, HelpPane relationship, supported
builds and collateral consumers remain unverified. Do not present it as an
official Windows toggle, all-application key disablement or recommended profile
choice. Microsoft's [IFEO documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/running-a-program-in-a-debugger)
describes launching programs in a debugger, not a supported Help preference;
the proposed nonexistent-debugger method is not an automatic fallback.

Before migration, verify Explorer and Desktop Help activation with and without
the candidate in a disposable Windows 11 VM, and confirm F1 still works in
unrelated applications. Check other uses of the affected registration, mixed
32/64-bit data, current-user identity and refresh requirements. Capture both
default values' prior type/data/existence and the keys created by the operation;
restore those values and remove only owned empty keys created by the operation.
Do not recursively delete the 1.0\0 branch on reverse. Existing legacy overrides
without captured prior data cannot be called exact pre-legacy recovery.

Windows also provides [Keyboard Filter](https://learn.microsoft.com/en-us/windows/configuration/keyboard-filter/)
on Enterprise, Education and IoT editions, with optional-feature prerequisites
and broader key filtering. It is not established here as an Explorer-only
replacement on Home/Pro, so do not substitute it or silently install a feature.
A custom Windows keyboard hook would require a persistent process and its own
application/lifecycle review; no such helper is included in this setting proposal.
Keep keyboard-remapping tools as optional alternatives, not dependencies of the
preferred native solution. No catalog, profile, handler, host settings or migration
estimate changes accompany this revised investigation direction.

### F1 current keyboard-source recheck, 2026-10-24

Microsoft Support's current [keyboard tips and tricks](https://support.microsoft.com/en-us/windows/hardware/input-devices/windows-keyboard-tips-and-tricks)
lists F1 as a common app shortcut for Help and cautions that common shortcuts
may not work in every app. It does not identify File Explorer or confirm its
behavior on Windows 11 build 26300. A 2022 Microsoft Community answer says F1
in File Explorer opens a browser help page, but that answer is a community
observation rather than current product documentation. Together with the user's
reported experience, these sources justify a targeted Windows 11 observation;
they do not replace it. Preserve Explorer behavior and unrelated-application F1
as separate assertions. Do not add a catalog operation or default-profile entry
until the disposable-target behavior and a safe, exact-restore control pass.
See the [structured source recheck](../archive/evidence/f1-file-explorer-current-source-recheck-2026-10-24.json).

### Accepted Windows-native F1 investigation decision, 2026-10-11

The user approved retaining Stop F1 opening Windows Help in Explorer and on the
desktop as an advanced Windows-native candidate. Keep the per-user two-value
TypeLib method pending actual Windows 11 behavior and collateral-consumer checks;
no third-party package or persistent helper is required by that candidate.
Preserve F1 in unrelated applications. Replace the legacy destructive reverse
with captured type/data/existence restoration and removal only of owned empty
keys created by the operation. This is design/investigation approval, not proof
of a supported mapping or runtime acceptance. No automatic IFEO, file-permission,
keyboard-filter or package fallback is accepted. Historical overrides without
prior capture cannot be claimed exactly restored. The outcome remains in the
migration estimate until implementation and feature acceptance; no host changes
or catalog/profile/handler changes accompany this approval.

### Taskbar sizing and Win+X shell review, 2026-10-11

Propose retaining smaller taskbar presentation and preferred-shell selection as
two independent GUI-aligned outcomes, replacing only verified current behavior
rather than reproducing the old registry selectors. No maintained catalog IDs
for these legacy selectors were found. Both proposed preferences are for the
intended current user; no automatic machine policy, elevated process, package
installation or recommended-profile selection is included.

Legacy ShowSmallTaskbarIcons writes TaskbarSmallIcons=1; ShowLargeTaskbarIcons
removes that value. Removal is not an explicit large-size choice or saved-state
restoration. Microsoft's [taskbar customization guide](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows)
contains separate Windows 11 and Windows 10 sections; its Use small taskbar
buttons switch is in the Windows 10 section. Do not use that section to claim
the old value is a verified Windows 11 setting.

The [June 2025 Windows 11 update](https://support.microsoft.com/en-gb/servicing/os/windows-11/2025/06/june-26-2025-kb5060829-os-build-26100-4484-preview)
documents Show smaller taskbar buttons with Never, Always and When taskbar is
full behavior. The [August 2026 update](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120998-windows-11-24h2-25h2-update)
documents Taskbar size, with Small reducing both icon size and taskbar height.
These release notes describe gradual rollout and user-visible behavior, not a
registry mapping. Establish which controls coexist or replace one another on
the actual build before selecting a schema. Expose independent icon-sizing and
height choices only where the GUI offers independently useful settings. Do not
collapse conditional sizing into a legacy Small/Large boolean or invent missing
GUI choices, numeric values or a universal default.

Detect applicable capability as well as Windows build/update evidence; an absent
GUI feature is unavailable, not a successful no-op. Verify visible effects with
full/unfilled taskbars, display scaling and multiple monitors, preserving other
taskbar choices and exact captured preference recovery. No forced feature rollout,
preview-update installation, third-party taskbar replacement or automatic Explorer
termination is part of migration. Document any actual refresh requirement.
These preferences have no proposed paid account/membership requirement; feature
availability remains the prerequisite, with no Server support declaration.

Legacy SetWinXMenuPowerShell/SetWinXMenuCmd write or remove
DontUsePowerShellOnWinX depending on whether the OS build is at most 14393. Those
old branches do not establish a current Windows 11 menu switch. Retire that
implementation as the normal preferred-shell control, retaining the outcome for
the modern Terminal UI. Propose Windows Terminal default profile as an explicitly
named new setting, choosing a real available profile such as Command Prompt,
Windows PowerShell or an installed PowerShell version. This affects Terminal
more broadly than Win+X; do not describe it as a Win+X-only replacement or promise
that a menu label changes. Menu-specific behavior remains acceptance work.

Microsoft's [Terminal installation/configuration guide](https://learn.microsoft.com/en-us/windows/terminal/install#set-your-default-terminal-profile)
separates Default profile from Default terminal application. The
[startup reference](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/startup#default-profile)
documents defaultProfile and separately says the terminal-application selection
is an OS setting outside settings.json. Keep host selection a distinct choice;
do not change it automatically when choosing a shell. Neither setting installs
PowerShell, adds profiles, selects the shell used by every script, changes
execution policy or grants elevation. Optional Azure/WSL/custom profiles retain
their own dependencies; they are not prerequisites for choosing an existing
local shell. Terminal must be installed for the intended user, with the selected
profile available; no cloud subscription or membership is proposed for that.

Use actual profile identity, preferably GUID, rather than hard-coded display
names; completion must come from the same bounded profile discovery used by
execution. Preserve unrelated Terminal properties, comments, profiles, commands,
launch behavior and existing elevation choices. Missing/malformed settings,
dynamic profiles, stable/preview installations and other-admin user identity
need explicit handling. Capture prior field presence and value; restoration must
not overwrite unrelated or concurrent file changes. Inspect Win+X and normal
Terminal launch behavior in a disposable Windows 11 VM, including normal versus
admin-account settings context. Do not launch an elevated Terminal on the host
to test a preference. No native default or whole-file reset is inferred.

Earlier migration-plan deferrals remain implementation/evidence gaps, not a
claim that smaller taskbar presentation or preferred-shell selection has no
current use. This proposed design keeps both outcomes pending; no taskbar,
Terminal, catalog/profile/handler or migration-estimate change is made.

### Accepted taskbar sizing and Terminal profile decision, 2026-10-11

The user accepted separate current-user taskbar sizing and Windows Terminal
default-profile controls. Taskbar choices must match the actual available GUI,
including conditional button sizing and height only where independently exposed;
verify rollout, mappings and visible effects without forcing feature enablement.
Terminal profile selection intentionally affects Terminal beyond Win+X. Default
terminal application remains distinct and is not changed implicitly. Use existing
installed-profile identity, preserve unrelated settings/elevation choices and
capture bounded prior configuration for recovery. Actual Win+X behavior, alternate
admin-user context, defaults and current-build acceptance remain work. The old
registry branches are not accepted as modern mappings. No host, package, catalog,
profile or handler changes accompany approval. Both legacy outcomes remain
counted pending implementation and feature acceptance; estimates are unchanged.

### PowerShell profile appearance request, 2026-10-12

The user requested elevated-session blue formatting under v3 PowerShell profile
settings and is considering separate colors for Windows PowerShell 5.1 and
PowerShell 7. The subsequent implementation request accepts the recommended
palette and reversible profile handler; title customization remains deferred.
This is an optional new
outcome, separate from Terminal default-profile selection and RIDE's declarative
operation-selection profiles. It is not a migrated legacy selector.

Windows Terminal's
[elevation reference](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/profile-general#automatically-run-as-administrator)
explains that a profile with elevate=false still runs elevated when opened in an
elevated window. Its
[color schemes](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/color-schemes)
are selected by Terminal profile; choosing Campbell PowerShell for an explicitly
named administrator profile alone does not cover elevation inherited by a
normal-profile tab. Inspect the actual shell token at startup, not profile names,
account group membership alone or the Terminal profile's elevate flag.

The subsequent implementation request accepts the recommended colors: Campbell
for normal 5.1, One Half Dark for normal 7, and the same Campbell PowerShell blue
for elevated sessions in both. Recommended applies those presets; AdminBlue
preserves normal-session appearance. Optional titles and distinct administrator
shades remain deferred. Default/unset remove only the managed block; Baseline
selects Default, while saved-run restore recovers the predecessor.

The earlier proposed startup snippet changes foreground and background through
terminal escape sequences; it does not select an entire named Terminal color
scheme. A scheme also defines the ANSI palette, cursor and selection colors.
The implemented renderer manages reviewed ANSI, foreground/background and cursor
colors; it preserves configured selection colors and other appearance. Check
error, warning, PSReadLine, selection and cursor contrast on each supported combination.

Implementation and recovery requirements:

- Resolve the intended user's CurrentUserCurrentHost ConsoleHost profile
  independently for Windows PowerShell 5.1 and installed PowerShell 7, using
  runtime-reported paths with profiles disabled during discovery. Do not assume
  an unredirected Documents directory or use the invoking edition's path for
  both. Missing optional runtimes and alternate administrator credentials need
  explicit availability/context reporting. Microsoft's
  [profile guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
  describes the host-specific paths, execution order and loading limitations.
- Use a versioned identifiable managed block and focused handler. Preserve
  existing content, encoding and line endings; do not replace or source an
  existing profile during inspection. Reject ambiguous blocks and conflicting
  edits before mutation. The legacy Write-Profile-File.ps1 helper has no v3
  preview/state/recovery contract and must not be called as the handler.
- Capture prior managed-block content and file presence. Repeat apply must not
  duplicate content. Unset removes only the managed customization; saved-run
  restore recovers its captured predecessor while preserving unrelated changes.
  Delete a newly created profile only if it still contains exclusively the
  content created by the operation. Later edits inside the managed block require
  an explicit conflict report rather than silent replacement.
- Guard local interactive Windows Terminal ConsoleHost startup and actual
  elevation detection. An inherited WT_SESSION variable alone is insufficient
  to establish a suitable host. Preserve configured appearance for normal
  sessions unless separately requested. Do not change elevation, the default
  shell, execution policy, unrelated prompt functions or other host profiles.
- Expose live managed configuration and baseline removal through show, plan and
  status; distinguish installed configuration from observed session appearance.
  A missing RIDE block is not a universal Windows color default. Complete finite
  states and runtime/scheme choices from the execution data, read-only. If named
  scheme selection is introduced, discover built-in and user-defined schemes
  from the applicable Terminal configuration instead of a second hard-coded list.
- Document that NoProfile, blocked profile execution, other shells and later
  application/profile color overrides prevent an unconditional "always blue"
  guarantee. Existing tabs need a new shell to load startup changes; do not
  restart them automatically.

Acceptance remains open: Windows-native mocked lifecycle checks for both editions
must cover missing/existing profiles, redirected paths, encoding, preview, repeat
apply, partial failure, conflicting edits and bounded restore. Disposable Windows
VMs must prove normal and explicitly elevated launches, normal-profile tabs in an
elevated window, both editions, alternate-user elevation and visible text/selection
contrast. Claim Windows 11 or Server support only after applicable target checks.
The implemented ProfileSetting handler and two optional catalog entries follow
this design; see [architecture, migration dispositions and recovery](../powershell-profiles.md).
The renderer applies the ANSI palette, foreground/background and cursor; selection
color and other host appearance remain configured. It never modifies workstation
profiles during tests. Candidate targets are Windows 11/Server 2025 with no support
declaration before applicable VM/visual acceptance. Legacy user-bin and WindowsApps
writers remain deferred, not connected to the engine. No migration estimate is
reduced by this requested new outcome.

Validation: 36 isolated profile tests and 172 related catalog, discovery,
presentation, CLI-preview and Shell-folder tests passed in each of Windows
PowerShell 5.1.26100.9549 and PowerShell 7.6.5 (208 checks per edition). The live
WindowsIntegration test was intentionally excluded. Native parser/catalog/profile
and generated-reference checks passed in both editions. A read-only plan resolved
the intended user's actual OneDrive-redirected paths for both runtimes; no startup
profile was executed or changed. Pester's optional XML environment export needed
to be disabled because CIM access is unavailable in this sandbox. Target/visible
acceptance was not run here; pending entries remain blocked for application.

Follow-up acceptance on 2026-10-12 passed on disposable Windows 11 and Windows
Server 2025 Desktop Experience: real lifecycle and partial-failure saved runs,
exact recovery, redirected Documents, alternate-account identity/recovery and
22 actual-token Terminal cases per target, including inherited elevation,
NoProfile, blocked startup, PSReadLine and selected text. Both operations now
declare supported targets and explicit no-override defaults. The profile module
is 0.1.2; cold discovery allows thirty seconds and restore recovers original
absence after unset. Local regression passed 215 checks per PowerShell edition.
The [dated acceptance record](../archive/migrations/powershell-profile-acceptance.md) retains run IDs,
tested versions, harness failures/corrections and additional cloud/alternate-launch
work. Host UAC and workstation profiles were unchanged; both VMs were reset and
Off. All five dated migration group estimates and the rounded total remain
unchanged: this requested addition resolves no legacy PATH/provisioning outcome.

### Shortcut-arrow appearance review, 2026-10-11

Propose retaining shortcut-arrow hiding as one optional advanced cosmetic outcome,
with Hide and Use Windows default choices, subject to actual Windows 11 evidence.
Keep the normal Windows arrow as the recommended presentation. No documented GUI
toggle or direct policy mapping was established in this review; do not invent a
Settings page, present it as a normal GUI preference, or add a performance/security
claim. There is no maintained catalog ID for this legacy tweak to remap.

Legacy HideShortcutArrow writes the string
%SystemRoot%\System32\imageres.dll,-1015 to machine Explorer\Shell Icons value 29,
creating the key if necessary. ShowShortcutArrow removes only that value. That
reverse discards a pre-existing custom overlay value; it does not restore it.
The legacy implementation is machine configuration requiring administrator rights,
not a current-user setting. Keep that scope visible and verify actual coverage
across users and any competing overrides. Do not silently change to a hypothetical
HKCU equivalent or offer a generic scope selector without independent evidence.
This is an appearance override, not an enforced organizational policy.

Microsoft's [Shell Links reference](https://learn.microsoft.com/en-us/windows/win32/shell/links#shortcut-icons)
describes the arrow as a system-defined shortcut overlay, separate from the
shortcut's base icon. Its
[overlay interface reference](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nn-shlobj_core-ishelliconoverlay)
describes the arrow as a visual indication that an object is a shortcut. These
are behavior references, not documentation of Shell Icons value 29 or the
specific imageres resource. Do not equate changing a shortcut's own icon through
the Properties GUI with configuring the system shortcut overlay.

The [icon extraction reference](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-extracticonexw)
distinguishes a negative resource identifier from a zero-based icon index in
that API. It does not establish how this registry consumer resolves the legacy
string, that resource 1015 is transparent, or that the resource remains suitable
on current builds. Verify literal type, environment expansion, resource availability
and rendered result. Do not guess another DLL number, label a missing resource
as a verified transparent icon or promise that an update preserves the mapping.
If a reliable native resource cannot be established, keep Hide unavailable;
any separately owned icon asset needs its own deployment/ownership/recovery
design before it can become a replacement. No third-party tweak tool is proposed.

Use Windows default should remove the declared machine override after capturing
it, allowing Windows/other applicable configuration to determine presentation.
It is distinct from saved-run Restore, which reinstates the actual previous
type/data/existence, including custom values. Capture key existence; remove only
owned empty keys created by RIDE and preserve other Shell Icons entries. Do not
delete the whole key, change shortcut files/targets/names, remove IsShortcut
registration, replace system DLLs or clear unrelated icon caches as a fallback.

Feature acceptance requires visible Desktop and Explorer results, multiple
users, light/dark backgrounds, different icon sizes/display scaling, repeated
apply and exact recovery, including an existing custom value and missing key.
Verify shortcut launch behavior and other overlays remain intact; a registry
round trip alone does not establish hiding. Record any refresh/sign-in requirement
and never automatically terminate Explorer or sign out the user. No paid account
or membership is proposed; machine privilege and verified build capability are
the prerequisites. No Server support declaration or recommended-profile hiding
is included. This proposed design leaves the outcome pending implementation and
acceptance, with no host, catalog/profile/handler or estimate change.

### Accepted shortcut-arrow decision, 2026-10-11

The user accepted retaining Hide shortcut arrows as an optional advanced cosmetic
control, with visible arrows in recommended profiles. Preserve the legacy
machine/admin scope explicitly; no normal GUI toggle or organizational policy
is claimed. Verify the current Windows 11 registry/resource mapping and actual
rendering before making Hide available. Use Windows default removes the declared
override; saved Restore recovers the captured prior custom type/data/existence.
Preserve other entries, shortcut registration/files and unrelated overlays;
no guessed resource, scope flip or forced Explorer restart is accepted. The
outcome remains pending implementation and feature acceptance, with no host,
catalog/profile/handler or migration-estimate changes accompanying approval.

### NumLock startup, sign-in and current-session review, 2026-10-11

Propose retaining NumLock startup behavior as an optional advanced preference,
with separate NumLock at the Windows sign-in screen and NumLock after sign-in
controls only where their respective mappings and effects are verified. The
first is machine/system-logon configuration requiring administrator rights; the
second is for the intended current user. Do not hide both behind one generic
startup toggle, label system-profile writes as an all-users personal preference,
or automatically apply both scopes. No maintained catalog ID for this legacy
pair was found; new controls need explicit identities and recovery contracts.

Legacy EnableNumlock/DisableNumlock write InitialKeyboardIndicators as a DWORD
in HKEY_USERS\.DEFAULT\Control Panel\Keyboard, using 2147483650/2147483648.
They then inspect Control.IsKeyLocked and use WScript.Shell.SendKeys to toggle
NumLock if the active-session state differs. They do not write the current user's
startup preference, configure firmware or capture a prior value. Their live
toggle is a separate effect from the startup registry write; an immediate
successful toggle does not establish behavior at the next Windows sign-in.

Microsoft's [system-profile explanation](https://devblogs.microsoft.com/oldnewthing/20070302-00/?p=27783)
identifies .DEFAULT as the Local System profile used by logon components, not
the template for newly created users. This documents the scope distinction,
not the NumLock registry mapping. Establish the current supported native type
and encoding on Windows 11; do not copy the legacy DWORD assumption or assign
new meanings to the high numeric values without evidence. Preserve unrelated
CapsLock/ScrollLock information where relevant; unknown encodings/types must
stay visible and must not be silently normalized or overwritten.

Offer positive On/Off startup choices only after verifying their mapping, with
saved Restore reinstating actual prior type/data/existence. Any Windows-default
choice must describe exactly which override it removes and remain distinct from
restoring a captured value. Do not invent a universal effective default: firmware,
keyboard hardware, remembered state and Windows startup/session paths require
separate observation. Do not turn off Fast Startup, change hibernation, load
other users' hives, edit the new-user template or install a logon task/service
as an implicit dependency or workaround.

Current-session NumLock state may be reported as a separate observation where
reliable session inspection is available. Microsoft's
[GetKeyState reference](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getkeystate)
describes a toggle bit and thread/message-queue state; it is not a registry
startup test or universal hardware LED/remote-session observation. A controller
or service must not report its own context as the user's state. Headless or
ambiguous session context is unknown/unavailable. RIDE should not simulate
keystrokes, set keyboard state, install hooks or continually enforce NumLock.
Manual use of the NumLock key remains distinct from configuring future startup.

No matching Windows startup GUI toggle was established in this review. The
[Accessibility keyboard guide](https://support.microsoft.com/en-us/accessibility/windows/make-your-mouse-keyboard-and-other-input-devices-easier-to-use)
describes Toggle Keys sounds and the On-Screen Keyboard; neither is a NumLock
startup preference. Use a scope/behavior reference with the registry-mapping
limitation explicit until a focused Microsoft reference is found. Optional
guidance can explain firmware NumLock options where available, without assuming
a vendor-specific option, changing firmware or promising that it controls the
later Windows state. No paid account or membership is proposed for these local
preferences; verified target/session applicability and privilege are prerequisites.

Acceptance must separately observe pre-sign-in and post-sign-in behavior across
restart, cold/fast startup, lock/unlock and different users, then restore the
captured configuration. Verify actual keypad input and unrelated lock-key state,
with hardware/remote-session coverage where applicable; VM registry round trips
alone do not prove physical keyboard behavior. Preserve alternate-admin identity
boundaries. Initial investigation is Windows 11; Server coverage needs independent
evidence and is not added automatically. This proposed design leaves the outcome
pending implementation and acceptance. No host keyboard/startup changes, catalog,
profile, handler or migration-estimate changes accompany the review.

### Accepted NumLock design and historical testing evidence, 2026-10-11

The user accepted separate optional startup controls for the Windows sign-in
screen and the intended user's post-sign-in session, and removing the automatic
simulated keypress from the proposed implementation. The user also recalls
extensive testing on the first Windows 11 releases, where the implemented legacy
solution was the only consistently working approach they found. Retain this
first-hand testing history as evidence supporting the legacy combined approach;
it is not a fresh test of current builds or proof of which component produced
the reliable result. Do not dismiss the live toggle as unnecessary merely
because it is separate from the registry preference.

The registry-only replacement must demonstrate the intended startup outcome
before it can be considered complete. Compare registry-only and legacy combined
behavior in an appropriate disposable test environment, with physical keyboard
coverage where needed, recording build, startup path, sign-in/session context,
value type/encoding and actual keypad behavior. A one-time live toggle must not
be mistaken for persistence across subsequent boots or sign-ins. If reliable
behavior still depends on the session action, return that dependency for a design
decision with the observed evidence; do not silently reinstate SendKeys, add a
logon task/service or ship an ineffective replacement. The proposed separation
and removal are accepted design direction, not established functional equivalence.

Both outcomes remain pending implementation and current-target acceptance. No
host keyboard changes, catalog/profile/handler edits or migration-estimate
reduction accompany this acceptance and historical evidence record.

### Explorer encrypted/compressed file-name color review, 2026-10-11

Propose one normal GUI-aligned preference named Show encrypted or compressed
NTFS files in color. It applies to the intended current user's File Explorer,
does not require elevation for that user's preference, and remains optional.
Keep encrypted and compressed name coloring together because the GUI exposes
one checkbox, not two independently selectable effects. Description: Use
different file-name colors in File Explorer to identify NTFS-encrypted or
NTFS-compressed files and folders. This changes presentation, not their
encryption, compression, permissions or visibility. It is not a general
indicator of BitLocker, ZIP, cloud or application-level protection.

The [current Microsoft settings reference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic)
lists colorEncryptedCompressedFiles under Folder Options, View, Advanced
settings, and also describes Shell/Advanced showCompColor state. This is a
GUI/state reference rather than a specification of the write path or registry
type. The older [GlobalFolderOptionsVista specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca)
maps showCompColor to HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowCompColor
and defines the preference's 1/0 enabled/disabled choices. Its historical
mapping still needs verification against the current Windows 11 GUI.

Legacy ShowEncCompFilesColor instead writes ShowEncryptCompressedColor as DWORD
1; HideEncCompFilesColor removes that value. No maintained operation for either
value was found. Do not assume the legacy value is a current alias, declare it
ineffective without testing, write both names as a fallback, or automatically
remove a pre-existing legacy value whose ownership/prior contents are unknown.
Observe the actual values and types changed by the GUI and check whether the
legacy spelling affects rendering. If necessary, evaluate the documented
[Shell state field](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/ns-shlobj_core-shellstatew)
and [SHGetSetSettings](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetsetsettings)
as a focused backend candidate; the API has a version-availability caveat, so
documentation alone does not establish current behavior. Preserve unrelated
Shell flags rather than replacing a packed state blob with a preset.

Offer explicit On and Off matching checked/unchecked GUI behavior once verified.
Do not equate the legacy reverse selector's value removal with explicit Off.
Saved Restore must recover the prior value type/data/existence and any other
state actually changed by the selected backend. A Windows-default choice is
separate: define its override-removal effect and establish the effective default
on a clean target before advertising it. Do not force Explorer termination,
reset Folder Options or other colors, change file attributes, or enroll/create
encryption keys as part of this preference.

Acceptance requires a disposable current Windows 11 desktop: toggle the GUI,
compare backend state, apply both choices repeatedly, observe actual ordinary,
NTFS-compressed and EFS-encrypted test file/folder names, and restore the captured
state. Check relevant folder views and light/dark/high-contrast rendering without
promising fixed blue/green colors across every theme. Test files are lab-owned;
do not alter workstation files. Verify refresh needs, intended-user identity,
unrelated preferences and absent/custom prior values. Registry round trips alone
do not establish the rendered result; Server support needs its own desktop tests.

No paid account or membership is proposed for the display preference. EFS test
coverage depends on filesystem/edition/key availability: Microsoft's
[file-encryption guide](https://support.microsoft.com/en-us/windows/security/encryption/how-to-encrypt-a-file-or-folder)
says file encryption is unavailable in Windows Home. That limits EFS creation,
not an established blanket edition restriction on the color preference.
The outcome remains proposed and pending implementation/feature acceptance;
no catalog/profile/handler, host-state or migration-estimate changes accompany
this review.

### Accepted encrypted/compressed file-name color decision, 2026-10-11

The user accepted one normal optional GUI-aligned Show encrypted or compressed
NTFS files in color control for the intended current user, without elevation.
Keep both effects together and provide verified explicit On/Off choices with
saved recovery of prior type/data/existence and any other backend state changed.
This changes presentation only. Establish the actual current GUI mapping and
file-name rendering before implementation; the legacy value spelling is not
assumed equivalent to Microsoft's older documented mapping. Preserve unrelated
preferences and file attributes, and distinguish Windows-default removal from
explicit Off and saved Restore. Implementation and target feature acceptance
remain pending; no host changes or migration-estimate reduction accompany this
design acceptance.

### Explorer Home navigation visibility and start-location review, 2026-10-11

Propose retaining two distinct outcomes: the normal GUI-aligned Open File
Explorer to preference, and an optional advanced experimental Hide Home from
the File Explorer navigation pane candidate. The latter preserves the legacy
intent for investigation rather than treating a different startup location as
completion of hiding. Keep it outside recommended profiles and unavailable for
normal application until its effect, scope and recovery are verified. Do not
promise a current GUI checkbox for hiding Home: none was established here.

Microsoft's [File Explorer guide](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows)
describes Home as the renamed landing page from Windows 11 22H2, distinguishes
pinned Quick access folders from that page, and documents selecting This PC in
See more, Options, Open File Explorer to. Choosing the startup location does
not constitute removal of Home or unpinning folders. Keep recent-file visibility,
frequent-folder visibility, pins, cloud content and the whole navigation pane
as separate choices. This guide documents user-visible behavior, not HubMode.

The maintained windows.explorer-start-location operation is user-scoped without
admin rights and writes LaunchTo under HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced:
ThisPC = 1 and Home = 2. Retain its stable ID, existing state meanings and saved
recovery. Legacy SetExplorerThisPC writes 1, while SetExplorerQuickAccess removes
LaunchTo; removal and explicit Home must not be conflated. Verify GUI transitions,
literal/effective defaults, typed recovery and launch paths on current targets.
The [Microsoft settings reference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic)
also lists a signed-in OneDrive location as a conditional GUI choice. Any
expansion to that choice needs verified availability, account/installed-client
identity and mapping; no new guessed LaunchTo number or implicit account setup.

Legacy HideQuickAccess writes DWORD 1 to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HubMode;
ShowQuickAccess removes it. No maintained HubMode operation was found. Preserve
the machine/admin boundary in the candidate description and verify multi-user
effects rather than relabeling it as a current-user preference or an enforcement
policy. Establish whether it hides Home, a Quick access surface, both or neither
on the actual build, and whether other navigation/launch behavior is affected.
No authoritative current HubMode mapping was established; Microsoft behavior
documentation must not be presented as verification of this numeric value.

Do not automatically change LaunchTo when hiding Home. Surface any observed
conflict with Home as the startup destination in the plan, and require a separate
explicit compatible selection where tests show one is needed. Saved Restore
recovers the captured HubMode type/data/existence. Use Windows default removes
only that override; it does not reconstruct missing namespace registration or
force Home visible regardless of other configuration. Do not add registry-tree
deletion, namespace reconstruction, ACL/ownership changes, pin/history resets,
Explorer termination or a per-user scope change as an automatic fallback. If
the legacy candidate is insufficient, review a current alternative and its
recovery separately before declaring replacement or retirement.

Acceptance must use disposable current Windows 11 desktops and independent
startup/hiding combinations. Observe navigation entries, pinned known/custom
folders, Home contents, direct Home navigation, Win+E/taskbar and explicit-path
launches, relevant file dialogs, refresh/sign-in persistence and at least two
users for the machine candidate. Check unavailable/unknown and custom prior
states, repeat application and saved recovery without changing unrelated
settings. No paid account or membership is proposed for local Home/This PC
selection or hiding; conditional cloud choices have separately visible account
requirements. Server support needs independent desktop evidence. The omitted
hiding outcome remains in the estimate pending implementation/acceptance; this
proposal changes no catalog/profile/handler or host state.

### Accepted Explorer Home/start-location decision, 2026-10-11

The user accepted retaining normal current-user Open File Explorer to separately
from optional advanced experimental Hide Home from the navigation pane. Preserve
the existing start-location ID and state recovery. Investigate the legacy hiding
outcome with its machine/admin boundary explicit, outside recommended profiles
and unavailable for normal application until current effect and recovery are
verified. Changing the opening location is not completion of hiding. Preserve
pins/history and other preferences; surface any startup conflict without silently
changing LaunchTo. No automatic namespace, ACL or scope fallback is accepted.
The hiding outcome remains pending implementation/feature acceptance and counted
in remaining work. No host or catalog/profile/handler changes accompany approval.

### Explorer library/access/share context-menu review, 2026-10-11

Propose three separate optional advanced menu-visibility controls: Include in
library, Give access to, and Share. Each represents a distinct action; keep
their labels and tested menu surfaces explicit rather than combining them into
a generic disable sharing operation. Leave normal Windows menu availability in
recommended profiles. No GUI visibility checkbox for these individual commands
was established; GUI alignment here means identifying the actual menu action,
not claiming a corresponding Settings toggle. Keep candidates unavailable until
current behavior, physical registry scope and recovery are verified.

The intended descriptions are: Include in library controls the folder command
for adding a location to a Windows library; Give access to controls the network
access menu; Share controls the Windows sharing command on verified surfaces.
These are presentation choices, not security enforcement. Applying them must
not edit libraries or their contents, existing shares, NTFS/share permissions,
SMB/service/firewall settings, Nearby sharing, cloud access or app privacy.
Keep windows.sharing-wizard separate; its interface preference is not proof of
equivalent menu suppression. Other routes to the same action may remain available.

Microsoft's [network-sharing guide](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/file-sharing-over-a-network-in-windows)
places Give access to under Show more options on Windows 11. The
[sharing guide](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/share-files-in-windows)
describes Share through both right-click and the command bar. The
[Explorer guide](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows)
distinguishes the modern menu from Show more options. Do not imply that changing
a classic handler necessarily hides the modern Share command, the command-bar
action or a OneDrive-owned action. Microsoft's
[library programming reference](https://learn.microsoft.com/en-us/windows/win32/shell/library-be-library-aware)
documents libraries as organization of content across folders; it does not
verify the legacy menu GUID or its current suppression mapping.

Legacy HideIncludeInLibraryMenu removes the Folder\ShellEx\ContextMenuHandlers\Library Location
registration. HideGiveAccessToMenu removes Sharing registrations under *,
Directory\Background, Directory and Drive. HideShareMenu removes ModernSharing
under *. Their Show selectors create those keys and write fixed default REG_SZ
CLSID values: {3dad6c5d-2167-4cae-9914-f99e41c12cfa},
{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}, and
{e2bf9676-5f8f-435c-97eb-11607a5bedf7}, respectively. These selectors do not
capture prior registration, additional values/subkeys or ACLs and therefore do
not establish exact reversal. No maintained operation for these outcomes was found.

All six legacy selectors target HKCR. Microsoft's
[HKCR reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key)
explains its merged machine/user Classes view and directs writes to explicit
physical roots for the desired scope. Do not infer one consistent machine or
user scope from the legacy drive. Proposed initial scope is an explicitly
declared machine Classes registration change requiring admin rights, with
per-user precedence and effective limitations reported. Establish each binding's
actual roots and registry views before implementation. Do not delete per-user
overrides to force a machine result. A possible current-user implementation
needs its own verified mapping and scope decision rather than an implicit flip;
alternate-admin identity must not become the intended user's context.

Prefer bounded reversible suppression of the specific menu binding over deleting
an entire COM class or handler tree. The backend is unresolved. If removing a
registration subtree is necessary, capture all affected physical keys, typed
values, subkeys and security descriptors and prove their bounded restoration
before claiming Exact. Treat literal * as a path component, not a wildcard.
Preflight every binding in a multi-binding operation, report partial failures,
and retain a recovery record for each successful change. Preserve unrelated
registrations and refuse unrecognized layouts rather than replacing them with
legacy constants. Do not silently take ownership or grant permissions to force
a change. Concurrent changes during recovery need visible conflict handling,
not broad tree replacement.

Saved Restore reinstates actual captured prior state. A future Show/Windows-default
choice must separately define whether it removes a RIDE suppression or applies
a verified current registration; it must not promise recovery of previously
missing/custom registrations using a guessed CLSID. Microsoft's
[handler-registration reference](https://learn.microsoft.com/en-us/windows/win32/shell/reg-shell-exts)
documents ContextMenuHandlers and Shell change notification generally, not these
three built-in CLSIDs or their Windows 11 coverage. Verify any focused refresh
notification and account/session applicability; do not force Explorer termination.

Acceptance needs disposable current Windows 11 desktops: observe each control
independently and in mixed combinations, modern and classic menus, files,
folders, folder backgrounds, drives, relevant dialogs and the Share command
bar. Verify libraries/shares/permissions remain unchanged, other menu entries
remain usable, and alternate routes behave as described. Cover two users,
per-user overrides, physical registry views, absent/custom registrations, repeat
application, preview, partial failure and typed/ACL recovery. No paid account
or membership is proposed for menu visibility; using individual cloud sharing
destinations may have separate requirements. Server support requires independent
desktop evidence. All three outcomes remain proposed and counted pending
implementation/feature acceptance; no host changes or estimate reduction occur.

### Accepted library/access/share context-menu decision, 2026-10-11

The user accepted three independent optional advanced visibility controls for
Include in library, Give access to and Share, with normal Windows menu
availability retained in recommended profiles. Preserve libraries, shares,
permissions and alternate routes. The proposed initial machine/admin scope
must use verified explicit physical registration roots and expose per-user
precedence; no silent scope fallback is accepted. Verify actual Windows 11 menu
surfaces and use bounded reversible suppression where possible. Saved recovery
must restore captured registration rather than fixed legacy defaults, including
typed contents/subkeys/ACLs if removal is required. All three outcomes remain
pending implementation and feature acceptance. No host changes, catalog/profile/
handler edits or migration-estimate reduction accompany this design acceptance.

### Desktop namespace icons and legacy mirror review, 2026-10-11

Propose five independent normal GUI-aligned desktop preferences: This PC
(Computer in Desktop Icon Settings), User's Files, Network, Recycle Bin and
Control Panel. Each controls one namespace icon for the intended current user,
without administrator rights or a paid account/membership. Preserve the five
published windows.desktop-*-icon IDs and their Shown, Hidden and WindowsDefault
state meanings. Keep these optional and keep the all-icons visibility preference
separate. Do not expose ClassicStartMenu/NewStartPanel as two user-facing choices
for the same icon. A registry mirror is an implementation detail, not a separate
feature or a second outcome for the estimate.

Microsoft's [desktop-icon guide](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows)
documents Personalization, Themes, Desktop icon settings and separately the
desktop View, Show desktop icons switch. Use this focused reference for the
visible choice, with the registry-mapping limitation explicit. The page does
not verify either registry branch or current mirror necessity. Compare actual
GUI labels and checkbox transitions on the supported build; use familiar
This PC naming with the Computer GUI label explained in discovery/help.

The legacy selectors write or remove the same icon GUID under both HKCU
Explorer\HideDesktopIcons\ClassicStartMenu and NewStartPanel. Their reverse
semantics are not symmetric explicit choices: HideRecycleBinFromDesktop writes
1 while ShowRecycleBinOnDesktop removes both values; the other four Show
selectors write 0 and their Hide selectors remove both values. Removal follows
effective defaults and other configuration, not necessarily the stated Show/Hide
intent. The maintained five operations currently write only NewStartPanel,
with explicit Shown = 0, Hidden = 1 and WindowsDefault = value removal; the
sixty-setting batch intentionally excluded ClassicStartMenu. Preserve these
published semantics instead of copying the legacy reverse selectors.

Verify which values the current GUI changes and which influence actual desktop
visibility, using independent and conflicting mirror states. Do not add the
second write merely because the legacy function used it, or declare the branch
irrelevant just from its name. If both are required for one reliable GUI outcome,
manage them as one coordinated per-icon operation, capturing each prior type,
data and existence and handling partial failure. If the mirror is unnecessary,
record an evidence-based disposition of the omitted legacy write and leave
pre-existing mirror values untouched. An observed current dependency on an old
mirror must remain visible rather than being silently normalized.

Any change from the scalar handler to coordinated values requires a documented
catalog/state-record migration and recovery path. Old saved runs captured only
NewStartPanel; restore only what they actually recorded and do not invent prior
ClassicStartMenu state. Newly captured records must identify every value they
change. WindowsDefault removes only the operation's verified declared overrides;
saved Restore reinstates captured prior configuration. Do not claim a universal
literal default for all images or substitute the baseline for a Windows default.

Status and plans must distinguish the individual icon preference from effective
visibility when Show desktop icons is off or a policy blocks it. Explain that
dependency without enabling all icons or removing policy implicitly. Hiding an
icon changes presentation and must not delete desktop files/shortcuts, empty
Recycle Bin, hide personal data from other locations, disable networking or
block access to Control Panel. Preserve icon artwork, the theme-controlled icon
preference, layout, unrelated GUIDs, other users' settings and namespace
registration. No forced Explorer restart or machine-scope enforcement is added.

Acceptance requires a disposable current Windows 11 desktop: each GUI checkbox
and RIDE Shown/Hidden choice independently, mixed icon selections, both mirror
branches absent/present/conflicting, custom typed prior values, the all-icons
switch on/off, policy restrictions, refresh and sign-in persistence. Verify
actual desktop appearance and icon activation as well as registry state,
repeat apply, preview, exact recovery and old-record compatibility. Record
effective defaults from a clean image separately from customized images. Server
desktop support needs its own evidence and is not inferred. This remains a
proposed design; the legacy mirror disposition and feature acceptance remain
open, with no host/catalog/profile/handler changes or estimate reduction.

### Accepted desktop namespace-icon decision, 2026-10-11

The user accepted five independent optional normal current-user desktop-icon
controls matching Desktop Icon Settings, without elevation. Preserve published
IDs and explicit Shown/Hidden/WindowsDefault states and saved recovery; the
all-icons switch remains separate with its effect explained. Establish whether
ClassicStartMenu is necessary on current Windows 11 before adding or retiring
the omitted mirror write. If needed, coordinate both values within the same
per-icon operation, capturing each actual prior state and retaining old scalar
record recovery without invented mirror history. Preserve files, other icon
preferences and policy boundaries. Mirror disposition and visible feature
acceptance remain pending; no host/catalog/profile/handler changes or estimate
reduction accompany this design approval.

### Server Manager startup and Shutdown Event Tracker review, 2026-10-11

Propose two independent optional advanced administrative controls: Server
Manager automatic startup at logon (machine policy), and Display Shutdown Event
Tracker (machine policy). Both require administrator rights. Match their Group
Policy choices and describe the effect in positive user terms. Keep default
profile selection separate; neither suppression is recommended implicitly by
migrating the legacy selectors. No maintained catalog operation for either
legacy outcome was found. Windows Server 2025 acceptance media/VM remains
unavailable in the migration ledger; this review does not add target support.

Legacy HideServerManagerOnLogin writes DWORD 1 to HKLM\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager\DoNotOpenAtLogon;
ShowServerManagerOnLogin removes that value. Microsoft's
[Server Manager guide](https://learn.microsoft.com/en-us/windows-server/administration/server-manager/server-manager)
documents the console's Manage, Server Manager Properties startup checkbox and
the Computer Configuration, Administrative Templates, System, Server Manager
policy as distinct configuration routes. Its default automatic launch applies
when administrators log on to a server. The
[ADMX policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-servermanager#donotlaunchservermanager)
documents the policy's registry path/value, automatic-launch suppression when
enabled and automatic display when disabled. Not configured follows normal
behavior, including the console's separate startup choice; manual access to
Server Manager remains available. Do not label policy removal as force-start.

Offer Do not start automatically, Start automatically, and Use Windows default
(remove local policy override) once verified on the target. Make the machine
policy effect and precedence over personal/console choice visible. Preserve
the separate console preference and existing launch task; do not disable tasks,
close Server Manager, uninstall it, change remote-management configuration or
simulate a logon. A future personal preference control requires independently
verified identity/scope/mapping and is not silently substituted for the legacy
machine outcome. Local policy writes are not a claim that a domain policy or
MDM source was edited; report effective managed precedence and refresh limits.

Legacy DisableShutdownTracker writes DWORD 0 to HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability\ShutdownReasonOn;
EnableShutdownTracker removes only that value. It leaves any ShutdownReasonUI
selection unchanged. Microsoft's
[Display Shutdown Event Tracker policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-reliability#shutdownreason)
defines Disabled, enabled with Always / Server Only / Workstation Only, and
Not configured, which follows platform defaults. Use those choices within one
operation instead of independent On and UI-selector toggles. Explain the
conditional modes on the selected platform and distinguish explicit enabled
behavior from the legacy reverse selector's override removal.

A read-only inspection of this workstation's Reliability.admx/adml on 2026-10-11
found ShutdownReasonOn enabled/disabled = DWORD 1/0, with ShutdownReasonUI enum
Always = 1, Workstation Only = 2 and Server Only = 3. ServerManager.admx defines
DoNotOpenAtLogon enabled/disabled = 1/0. These are local template evidence, not
Server 2025 runtime acceptance. Reconcile the target's own policy GUI/templates,
types, defaults and actual behavior before using them. Establish the paired
Disabled/Not configured behavior rather than inventing a ShutdownReasonUI = 0
state or clearing unrelated reliability configuration. Capture both values for
coordinated changes, restore each prior type/data/existence, and recover/report
partial failures. Unknown or partial configurations must remain visible.

Shutdown Event Tracker governs the displayed reason-collection workflow;
[Microsoft's behavior reference](https://learn.microsoft.com/en-us/windows/win32/shutdown/shutdown-event-tracker)
describes event-log reason records and application shutdown reason codes. Hiding
the prompt must not be described as disabling all shutdown logging, telemetry
or audit events. Preserve system event logs, custom reason definitions, the
separate System State Data feature, shutdown rights and existing scheduled or
remote shutdown behavior. Applying this setting must not shut down/restart the
machine, submit a reason or clear an unexpected-shutdown marker.

For both controls, saved Restore reinstates captured local configuration rather
than policy-source history or already-produced events. Use Windows default is
override removal, not a guarantee of a specific effective state under managed
policy. Verify any required policy-store/refresh integration separately rather
than calling global policy refresh or editing policy files implicitly. Server
Manager's local GUI absence, Server Core and Windows 11 RSAT installation must
be treated explicitly; no automatic feature installation or broad client
support follows from the presence of an ADMX/CSP entry. The shutdown policy may
have client applicability, but Windows 11 editions need independent acceptance.

Acceptance requires appropriate disposable target VMs: Server Manager launch
on fresh administrator logon across each policy/console-preference combination,
manual access and a second administrator; actual Shutdown Event Tracker UI and
reason/event behavior across policy modes, managed precedence and planned/
unexpected paths. Shutdown/restart scenarios belong only to these lab targets.
Include clean/custom/absent values, repeat apply, preview, paired partial failure
and saved restore. Requirements are applicable Windows edition/installation,
administrative rights and verified feature presence; no paid cloud membership
is proposed for local policy configuration. Both outcomes remain proposed and
pending implementation/target acceptance, with no host changes or estimate
reduction accompanying this review.

### Accepted Server Manager/shutdown-tracker decision, 2026-10-11

The user accepted two separate optional advanced machine/admin policies for
Server Manager automatic startup and Display Shutdown Event Tracker, aligned
with Group Policy choices. Keep the console's separate startup preference and
managed-policy precedence visible. Explicit startup/enabled behavior remains
distinct from local override removal. The tracker uses one coordinated control
for its policy modes with captured paired-value recovery, preserving unrelated
logging. Neither suppression enters recommended profiles automatically. Actual
Server behavior and implementation remain pending; Server 2025 media/VM
acceptance is still unavailable. No host changes or estimate reduction accompany
this approval.

### Local-account password complexity and expiration review, 2026-10-11

Propose replacing the generic legacy Enable/DisablePasswordPolicy presentation
with two independent optional advanced machine/admin controls for local
accounts: Password must meet complexity requirements (Enabled/Disabled), and
Maximum password age (Never expires or an explicit supported number of days).
Match Local Security Policy, Account Policies, Password Policy. These are
machine-wide account policies, not current-user preferences. They are not a
complete secure-password setup, and neither weakening complexity nor changing
expiration enters recommended profiles automatically. Domain policy management
requires a distinct explicit workflow; initially exclude domain controllers
from mutation by these local-account operations.

Legacy DisablePasswordPolicy exports security settings using secedit, replaces
the exact strings PasswordComplexity = 1 with 0 and MaximumPasswordAge = 42
with -1, then reimports SECURITYPOLICY through the system local.sdb. Enable
reverses complexity 0 to 1 and maximum age -1 to 42. Both reapply a broad exported
template and delete the temporary file without retaining a recovery record.
An existing age such as 60 or 90 days is not changed by these substitutions;
Enable is a fixed preset, not saved Restore or a universal platform baseline.
Do not copy brittle string matching, broad policy reapplication or 42-day
default assumptions into the new controls. No maintained operation for this
legacy policy bundle was found.

Microsoft's [complexity reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements)
documents checking passwords when created or changed. Enabling it does not
prove existing passwords meet the rule or reset them. Keep minimum length,
history, lockout, reversible encryption and account-specific settings separate.
The [maximum-age reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-password-age)
documents 0 as no expiration and 1-999 as day choices, with a minimum-age
dependency. The [security-template specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/0b40db09-d95d-40a6-8467-32aedec8140c)
uses -1 for no expiration. Present one understandable Never expires choice;
verify backend-specific translation rather than writing the GUI number into
every representation. Reject an invalid maximum/minimum-age combination
without silently changing minimum age. State the selected value in the plan.

The maximum-age reference explains why the Microsoft baseline omits periodic
expiration alongside modern mitigations and retains caveats for environments
without them. Do not label either 42-day expiration or no expiration universally
more secure. Guided local-account security follow-up must connect these choices
with password length/quality, compromised-password response, account lockout,
privilege, recovery and the authentication controls actually available for the
account. Do not imply an Entra/MFA product protects local SAM password sign-in
merely because the device or user has a cloud account. Baseline recommendations
need their own target/environment review and explicit profile selection.

Microsoft's [account-policy overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-policies)
describes domain versus member-computer local account effects. Discover role,
account authority and effective managed precedence before changes. A local
operation must not claim to change AD, Entra/Microsoft account passwords,
Windows Hello PIN rules, LAPS rotation or machine-account password age. On a
member computer, expose local versus effective values and refuse mutation when
an external policy makes the requested local result unsupported or ambiguous;
do not edit a domain GPO, fine-grained policy or another authority to force it.

Prefer a supported focused account-policy backend. If secedit is selected,
parse and validate only the declared fields and use a minimal template with an
isolated operation-owned database, verified exit codes and readback. Microsoft's
[export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
and [configure](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-configure)
references distinguish merged-policy export and the broad SECURITYPOLICY area;
an export alone is not proof of original local GPO definitions or policy-source
ownership. Never replay a full old export as focused recovery or turn merged
effective domain values into new local configuration. Preserve all undeclared
policies and report partial failures with bounded recovery records.

Saved Restore must recover captured local values and relevant definition/source
semantics that the backend actually changed. Do not offer generic WindowsDefault
as registry-like value deletion: establish supported reset semantics and a
target-specific baseline separately. Restoring policy does not restore passwords
changed in the meantime or erase password history. Shortening maximum age can
make existing passwords expired; explain this in the preview. Account-level
never-expire flags and managed rotation may affect the outcome and must remain
unchanged. Do not reset passwords, log off users, change clocks, disable
accounts, or save credentials in ordinary state records.

Acceptance requires disposable standalone/member Windows targets and lab-owned
accounts: GUI/policy comparison, actual allowed/rejected password creation and
change, age/never-expire behavior, custom age values and minimum-age dependencies,
managed precedence, repeat apply, preview, partial failure and focused recovery
with unrelated policy unchanged. Keep test credentials out of ordinary logs.
Verify domain-controller refusal and role/edition applicability. Server 2025
coverage remains blocked by the existing unavailable media/VM; client coverage
also needs independent evidence. No paid cloud license or membership is proposed
for these local policies. This design remains proposed and counted pending
implementation/feature acceptance, with no host or catalog/profile/handler changes.

### IE Enhanced Security applicability evidence for separate review, 2026-10-11

Legacy Disable/EnableIEEnhancedSecurity writes IsInstalled = 0/1 to two HKLM
Active Setup component registrations, {A509B1A7-37EF-4b3f-8CFC-4F3A74704073}
and {A509B1A8-37EF-4b3f-8CFC-4F3A74704073}. Microsoft's
[Server removed-features reference](https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server?tabs=ws25)
says standalone Internet Explorer is removed from Server 2025 and points to
Edge IE mode for legacy sites. The archived
[IE ESC FAQ](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/browsers/security-privacy/enhanced-security-configuration-faq)
is historical feature evidence, not proof that these registrations implement
useful current Server 2025 protection. Retain this as a separate applicability/
disposition decision; do not equate IE ESC with Edge IE mode or auto-migrate the
two values merely because residual registrations exist. No retirement decision,
estimate reduction or host change is made by collecting this evidence.

### Accepted local-account password-policy decision, 2026-10-11

The user accepted two independent optional advanced machine/admin controls:
Password must meet complexity requirements and Maximum password age, matching
Local Security Policy. Keep Never expires and explicit day choices, validated
against minimum age, without a universal 42-day preset or automatic weakening
in recommended profiles. Preserve unrelated policies and distinguish local
account authority, local definitions and effective managed precedence. Initially
refuse domain-controller mutation. Use a focused backend and captured recovery,
not full-export replay; policy recovery does not restore changed passwords.
Guidance for a secure local-account outcome remains required. Implementation and
disposable-target acceptance remain pending, including unavailable Server 2025
coverage. This approval makes no host changes or migration-estimate reduction.

### IE Enhanced Security Configuration review, 2026-10-11

Propose retaining this legacy outcome for conditional Server investigation,
with two independently useful optional advanced controls matching the GUI:
IE Enhanced Security Configuration for Administrators, and IE Enhanced Security
Configuration for Users, each On/Off. Both are machine/admin configuration for
the selected account class, not a preference for only the invoking user.
Verify current class membership behavior, including existing and new profiles,
before describing the affected users. A reviewed profile may select both to
express the legacy combined outcome. No Windows 11 control or automatic Off
selection is proposed. No extra cloud license, account or paid membership is
proposed for these local Server settings; expose OS/component prerequisites.

The legacy pair writes both Active Setup IsInstalled markers together, without
captured prior state. No maintained IE ESC operation was found. Microsoft's
[archived GUI reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd883248(v=ws.10))
documents independent Administrators and Users choices. Its account-class
explanation is historical; the current mapping of each GUID still needs proof.
The [archived FAQ](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/browsers/security-privacy/enhanced-security-configuration-faq)
documents browser restrictions and possible effects on web applications and
embedded help. Its script includes the same two markers but also additional
registry views, IEHarden values and refresh actions for old Server versions.
It does not establish that the legacy two writes alone produce the GUI outcome
on current targets. Do not automatically copy the broader historical script.

The [Server Manager reference](https://learn.microsoft.com/en-us/windows-server/administration/server-manager/manage-the-local-server-and-the-server-manager-console)
still lists the IE ESC property and includes Server 2025 in its applicability
header. However, it retains older-version content and is not current-build
acceptance evidence. The [Server removed-features reference](https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server?tabs=ws25)
confirms standalone IE removal in Server 2025. These references justify keeping
applicability unresolved: neither the removal nor remaining registry markers
prove whether current components still consume IE ESC. Do not present IE ESC
as Edge enhanced security, IE-mode configuration or general browser protection.
Any claim about an embedded component or IE mode needs its own observed evidence.

Plans must identify the account class, verified affected feature, observed
configuration/effect and any deferred activation. Keep protection enabled in
recommended outcomes where verified; disabling is an explicit advanced choice
with a concrete explanation of the restrictions being relaxed. Preserve trusted
sites, custom zone settings and externally managed policy; do not silently add
sites or weaken unrelated browser/security controls to fix an application.

Capture typed prior configuration before mutation and verify any derived
per-user changes made by the chosen backend. A marker round trip alone cannot
establish exact recovery of browser/zone state. Bound and capture every changed
component or report the recovery limitation before availability. Preserve Active
Setup versions, stubs and unrelated registrations; no implicit all-user hive
edits, registration deletion, historical rundll32 calls, browser termination,
logoff or forced refresh. Missing components must produce an applicability
result rather than fabricated registry configuration. Explicit On, Off, saved
Restore and any verified platform-default workflow remain distinct; absence of
IsInstalled is not an established Windows default.

Acceptance requires disposable supported Server builds: GUI/backend comparison,
all four On/Off combinations, administrators versus non-administrators with
existing/new profiles, actual restrictions in a relevant installed component,
activation timing, managed precedence, repeat apply, preview, partial failure
and captured recovery preserving custom sites/settings. Verify installation
option applicability separately. If Server 2025 has no useful effect, return
with evidence for a target-specific retirement decision rather than silently
shipping an inert setting or adding older Server support. Server 2025 media/VM
acceptance remains unavailable. The proposal is pending user acceptance and
implementation; no host changes, retirement or estimate closure accompanies it.

### Accepted IE Enhanced Security Configuration decision, 2026-10-11

The user accepted retaining IE ESC for conditional Server investigation, with
independent optional advanced Administrators and Users On/Off controls matching
the GUI. Both configure a machine-wide account class and require administrator
rights. Preserve the legacy combined outcome through a reviewed selection of
both controls; do not disable protection automatically. Verify current Server
component effect, GUID/class mapping, activation and captured configuration plus
derived-state recovery before availability. Standalone IE removal does not by
itself establish ESC retirement, and remaining markers do not establish useful
protection. No Windows 11 control, Edge/IE-mode equivalence or broad historical
script replay is accepted. Implementation and Server acceptance remain pending;
this approval makes no host changes, retirement or estimate reduction.

### Windows Audio service and playback mute review, 2026-10-11

Propose two separate optional controls with explicit target and effect:
an advanced machine/admin Windows Audio service control matching Services,
and a normal playback-output Mute/Unmute control matching the selected device's
Windows sound/volume UI. Service configuration is not an understandable substitute
for a speaker mute button. Neither control is a microphone privacy feature or
a guarantee that every possible audio route is silent. Do not compose them into
a generic Disable audio choice or add either automatically to setup profiles.

Legacy EnableAudio sets Audiosrv to Automatic and starts it. DisableAudio
force-stops Audiosrv and sets Manual, not Disabled. Propose retaining the two
explicit coordinated choices Automatic startup and running, and Manual startup
and stopped. Display both startup type and current status. Manual permits later
startup; do not describe it as permanent disablement. A true Disabled startup
choice would be separately reviewed rather than silently replacing the legacy
outcome. If Windows immediately restarts a Manual service, report the unmet
runtime state rather than forcing ongoing enforcement. No maintained Audiosrv
operation was found.

Microsoft's [Set-Service reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-5.1)
distinguishes Manual from Disabled startup. The
[audio architecture reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/audio/windows-audio-architecture)
distinguishes Windows Audio from Audio Endpoint Builder. Preflight dependencies,
management precedence and running dependents before service changes. Initially
refuse a transition requiring undeclared dependency changes; do not copy legacy
force-stop behavior or silently configure/start AudioEndpointBuilder. If a
verified Server enablement outcome needs additional services, return with a
focused ordered group proposal and captured recovery for those components.
Preserve delayed-start metadata, triggers, service account/security and unrelated
configuration. Capture startup type and stable runtime state, verify completion
and report partial failures. Restoring configuration/runtime does not resume
interrupted playback, recordings or application audio sessions. Establish actual
target defaults separately; AutomaticRunning is not proof of a Windows default.

Legacy AudioMute/AudioUnmute uses Core Audio GetDefaultAudioEndpoint(eRender,
eMultimedia) and SetMute(true/false). It selects the default multimedia output at
call time; it does not mute capture devices, every output or individual apps.
It duplicates a compiled interop type and retains no prior mute/device identity.
Use one maintained native Core Audio binding with documented signatures, proper
COM lifetime handling and error checking, preserving source attribution where
adapted. No third-party audio tool or package is proposed.

Microsoft's [endpoint mute API](https://learn.microsoft.com/en-us/windows/win32/api/endpointvolume/nf-endpointvolume-iaudioendpointvolume-setmute)
documents explicit mute/unmute, including successful no-change results. Its
[endpoint-control guidance](https://learn.microsoft.com/en-us/windows/win32/coreaudio/endpoint-volume-controls)
connects the API to the system device volume UI and distinguishes endpoint from
application-session controls. Software mute can be bypassed by exclusive-mode
streams when the device lacks hardware mute support. Explain the applicable
limitation without claiming universal silence. The
[Windows sound guidance](https://support.microsoft.com/en-us/windows/hardware/audio/fix-sound-or-audio-problems-in-windows)
provides the user-facing output-device and mute context; current Windows 11 GUI
agreement still needs actual acceptance evidence.

Resolve the selected output once, show its friendly name and role in preview,
and capture its opaque [endpoint ID](https://learn.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-immdevice-getid)
plus prior mute state before mutation. Restore only that captured endpoint,
never whichever device happens to be default later. Preserve volume level,
app-session settings, default-device selection and microphone state. Explicit
Unmute is not saved Restore and must not raise volume. No universal unmuted
baseline, persistent startup enforcement or automatic service start is proposed.
Missing/unplugged endpoints or unavailable user sessions must produce clear
inapplicability/failure with retained recovery, not success or a device fallback.

Run endpoint control in the intended interactive user's audio context, with no
proposed elevation requirement. The affected resource is an endpoint, not an
isolated per-user registry preference: other applications and potentially users
sharing that endpoint can be affected. Verify and display actual session/device
boundaries, including RDP, fast user switching and elevated alternate credentials.
Separate execution/state ownership from affected resource in metadata and UI;
resolve the engine's existing user/machine scope contract before implementation.
Any needed metadata addition must preserve schema/saved-run recovery. Do not
infer endpoint identity from the administrator running a machine profile or
access another session silently. Microsoft's
[default-endpoint API](https://learn.microsoft.com/en-us/windows/win32/api/mmdeviceapi/nf-mmdeviceapi-immdeviceenumerator-getdefaultaudioendpoint)
selects by direction and role. Verify the modern GUI's selected/default output
against legacy eMultimedia; do not silently substitute eConsole or communications
roles, change the default device, or follow default changes during one apply.

Acceptance requires disposable Windows targets with usable audio endpoints:
GUI mute/readback, actual playback behavior and limits, distinct output roles,
volume preservation, default-device changes, hot-plug, repeat apply, preview,
partial failures and recovery of the original endpoint. Service tests must prove
startup/runtime transitions, dependency refusal, preservation and bounded recovery.
Test non-admin execution and session/resource boundaries separately. Server 2025
coverage remains unavailable and needs actual audio-stack/installation-option
evidence; an API minimum-server version does not establish RIDE target support.
No additional cloud license/membership or driver installation is proposed. These
designs remain proposed, counted pending implementation/feature acceptance,
with no host changes, catalog changes or migration-estimate adjustment.

### Accepted Windows Audio decision, 2026-10-11

The user accepted separate optional Windows Audio service and playback-device
mute controls. Keep the service advanced machine/admin, with explicit Automatic/
running and legacy Manual/stopped choices; do not silently replace Manual with
Disabled or force-stop dependents. Playback Mute/Unmute uses native Windows APIs
in the intended interactive user's context, with the affected endpoint and
sharing boundaries visible. Preserve volume, microphone and app/default-device
settings; capture prior mute plus device ID and recover that original endpoint.
Resolve metadata scope, prerequisites and GUI role mapping before implementation.
Actual audio effects, session boundaries, recovery and Server coverage remain
pending. This approval makes no host changes or migration-estimate adjustment.

### BitLocker encryption and TPM+PIN enrollment review, 2026-10-11

Propose retaining these outcomes as guided machine/admin workflows, with explicit
selected-volume scope and GUI terminology from Manage BitLocker: Turn on
BitLocker, Change how the operating-system drive is unlocked at startup, and
Turn off BitLocker (decrypt). Keep the advanced policy controls already accepted
separate, but connect them through a reviewed setup that checks recovery access,
policy compatibility, protector enrollment, encryption and actual boot protection.
Do not ask users to infer a secure outcome from several unrelated registry IDs.
Initial scope is the explicitly selected OS volume; data/removable-drive workflows
need separate design rather than an implicit all-drive expansion.

Legacy EnableBitlocker requests AES-CBC 256, used-space-only encryption, skips
the hardware test and creates a recovery-password protector. EnableBitlockerTPMandPIN
instead requests TPM+PIN, also skips the test, and does not ensure a saved recovery
protector. It takes PIN input from a process environment variable or prompt,
compares plaintext conversions and may eject VM optical media. DisableBitlocker
decrypts the system volume. None captures an enrollment/conversion recovery plan.
Do not copy the plaintext/env-var PIN handling, automatic media ejection, skipped
test, recovery omission or a fixed legacy cipher into the guided replacement.

Offer reviewed startup choices TPM-only (normal automatic startup) and TPM plus
a BitLocker startup PIN (advanced preboot input), both with verified recovery
access. The startup PIN is distinct from Windows Hello/sign-in PIN. Show existing
protectors and effective startup-authentication policy, including conflicting
managed requirements and alternate normal boot routes. Microsoft's
[protector API](https://learn.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector?view=windowsserver2025-ps)
adds protectors rather than converting existing combinations. Adding TPM+PIN
must not be reported as requiring a PIN while TPM-only or another applicable
unlock route remains. Never silently remove unmanaged/existing protectors: show
the proposed transition, retain verified recovery and refuse ambiguous ownership.
Treat managed Network Unlock exceptions explicitly, not as failed PIN enforcement
or permission to rewrite organization policy. Microsoft describes their context
in [BitLocker countermeasures](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/countermeasures).

Preflight edition, installed BitLocker feature/cmdlets, ready compatible TPM,
boot/partition readiness, effective policy, volume identity, lock/conversion/
protection state and recovery destination. Do not initialize/clear a TPM, install
features, alter firmware, eject media, reboot or weaken managed policy implicitly.
Microsoft's [overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
lists Pro, Enterprise and Education enablement; Home Device encryption is a
distinct capability and workflow. Local manual BitLocker use does not inherently
require a Microsoft/Entra account, domain membership or an Intune subscription;
account/join/license requirements depend on the chosen recovery or management
backend. Display those separately from local edition/admin/TPM prerequisites.
Server needs installed-feature and independently verified target coverage.

Use native supported BitLocker APIs/cmdlets through a new reviewed lifecycle
contract. Microsoft's [enable reference](https://learn.microsoft.com/en-us/powershell/module/bitlocker/enable-bitlocker?view=windowsserver2025-ps)
distinguishes enablement from protector changes on already encrypted volumes.
Inspect existing Device encryption too; encrypted percentages alone do not prove
active protection. Preserve an existing method and protector configuration unless
the selected workflow explicitly changes it. Resolve new-encryption method against
the accepted modern/fallback policy review; no AES-CBC 256 preset or automatic
decrypt/re-encrypt to change method. Keep published policy IDs and saved recovery.

Match the wizard's Encrypt used disk space only versus Encrypt entire drive
choices with explicit drive-history guidance. Microsoft's
[operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
explains the exposure of previously deleted plaintext with used-space-only
encryption. Do not equate a newly installed OS on a reused drive with a never-used
disk or wipe free space automatically. Retain the hardware/system check and show
when a user-directed reboot/preboot test is pending. Status must distinguish
scheduled, converting, paused, encrypted but suspended, protected and failed
states; conversion initiation is not completion. Reapply resumes only supported
explicit workflows, without duplicate protectors, PIN rotation or hidden restarts.

Recovery must be saved to an explicitly selected usable destination before the
workflow commits to protection; ordinary RIDE state records are not a recovery-key
backup. Record only nonsecret volume identity, stages, protector types/IDs,
ownership and backup outcome. Sanitize cmdlet output and nested objects, which
can contain recovery passwords. PIN entry uses a secure interactive channel;
no secrets in profiles, command history, environment, logs, transcripts or generic
snapshots. Unattended secret acquisition and recovery export/retrieval remain
separate follow-up design, including the next ledger item; missing secure input
or failed backup prevents further enrollment rather than inventing success.

Microsoft's [disable reference](https://learn.microsoft.com/en-us/powershell/module/bitlocker/disable-bitlocker?view=windowsserver2025-ps)
states that disabling removes protectors and starts decryption. Present it as
explicit advanced Turn off BitLocker (decrypt), distinct from suspending protection,
removing a PIN, clearing a policy or saved Restore. Do not clear auto-unlock keys
on other drives to bypass a refusal. Ordinary unset/run restore must not decrypt
a volume or promise exact reconstruction of removed protectors/PINs. Define
versioned staged recovery and safe compensating actions before integration;
preserve pre-existing protection during enrollment/recovery and never remove
the last usable protector as a cleanup action.
Interrupted conversion, enrollment or backup must retain an actionable report,
with no blanket rollback by decryption or false Exact recovery label.

The reviewed security guide must state the threat, tradeoffs and entire accepted
outcome: actual nonsuspended protection, required normal startup authentication,
usable recovery and observed boot behavior. Connect relevant power-state guidance
without silently changing it; explain the preboot-input cost for remote/unattended
Server operation. Acceptance requires disposable TPM-capable targets, real restart/
PIN/recovery access, existing encrypted/suspended/converting volumes, managed-policy
conflicts, repeated apply, failed escrow, output redaction, volume identity and
partial-failure recovery. VM checkpoints are lab recovery, not evidence of RIDE
exact rollback. Server 2025 acceptance remains unavailable. These proposals remain
pending user acceptance, lifecycle implementation and feature evidence; no host
encryption, catalog/profile changes, new target support or estimate reduction.

### Accepted BitLocker enrollment/lifecycle decision, 2026-10-11

The user accepted guided machine/admin BitLocker setup for the explicitly selected
OS volume, connecting prerequisites, policy, TPM-only or TPM+startup PIN, saved
recovery and actual encryption/boot verification. Keep GUI-aligned startup choices
and advanced policies visible without leaving dependencies hidden. Turn off
BitLocker (decrypt) remains a separate advanced action, never implicit unset or
ordinary saved-run restore. Preserve existing protectors/methods except for an
explicit reviewed transition; no silent hardware-test skip, media ejection,
firmware/restart changes or plaintext PIN handling. Expose edition, TPM and
backend-specific account/license requirements. Lifecycle implementation, detailed
recovery handling and disposable-target evidence remain pending; no host encryption,
new support declaration or migration-estimate reduction accompanies this approval.

### BitLocker recovery creation, backup and display review, 2026-10-11

Propose one guided recovery area tied to the accepted encryption workflow, with
distinct actions: Back up your recovery key (normal), Create an additional
recovery key (advanced), and Show the selected recovery key (explicit secret
access). Use the familiar GUI recovery-key wording while identifying the actual
protector type in technical views. Microsoft's
[recovery overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview)
distinguishes the 48-digit recovery password from a .bek recovery-key file.
Initial scope covers RecoveryPassword protectors for the selected OS volume;
do not silently convert another protector type or claim support for .bek/key
packages, data drives or offline repair through this initial workflow.

Legacy AddBitlockerRecoveryPswd calls Add-BitLockerKeyProtector and returns its
volume object without a backup destination or captured lifecycle. Display uses
KeyProtector[1], assumes the second item is relevant, and emits RecoveryPassword
to ordinary output. No maintained recovery workflow was found. Select by
RecoveryPassword type and explicit protector ID, with volume identity checked;
never use array position or the first arbitrary protector. List nonsecret IDs
for selection; multiple recovery protectors require an unambiguous choice.
CLI ID/destination choices need read-only completion using the actual data source,
with no secret retrieval, key creation or backup during completion.

Back up reuses the selected existing protector. Create is separate, including
creation when required by the enrollment guide; repeated backup must not create
duplicates. Creating an additional protector does not rotate/revoke existing
recovery access. Any future rotation needs its own staged ownership, verified new
backup and explicit old-protector disposition. Preserve unmanaged/pre-existing
protectors, never remove the last usable protector, and do not delete cloud
copies or exported files during ordinary Restore. A backup cannot be undisclosed
or undone like a registry value. Record nonsecret IDs, stages and outcomes; if
creation succeeds but backup fails, retain the protector and report the partial
result without enabling encryption or silently deleting recovery access.

Match Manage BitLocker, Back up your recovery key. Microsoft's
[backup guidance](https://support.microsoft.com/en-us/windows/security/encryption/back-up-your-bitlocker-recovery-key)
describes account, USB/file and print choices. The user must select a destination;
no automatic cloud upload, clipboard copy, printing or workspace export. Prefer
the native wizard/portal handoff for options whose supported implementation and
secret handling have not been established. Opening a wizard alone is not verified
backup. A file export is an explicit secret artifact, distinct from a RIDE report;
identify that it contains the recovery secret, validate its destination/ownership
and successful write, and preserve existing files rather than silently overwrite.
Exclude repository, normal state/cache/report locations and the protected source
volume; guide the user to a backup accessible if the original computer cannot
boot. Do not assume a synced folder or an inaccessible encrypted destination
provides usable recovery. Keep the copy separately accessible from the device.

Declare backup backends accurately: native
[AD DS backup](https://learn.microsoft.com/en-us/powershell/module/bitlocker/backup-bitlockerkeyprotector?view=windowsserver2025-ps)
and [Entra backup](https://learn.microsoft.com/en-us/powershell/module/bitlocker/backuptoaad-bitlockerkeyprotector?view=windowsserver2025-ps)
target different authorities by protector ID. Neither is personal Microsoft
account backup or arbitrary file export. Expose actual join/tenant, service,
permissions and effective recovery-policy prerequisites before offering a backend;
do not enroll the device, install Graph modules or request broad consent implicitly.
Preserve configured mandatory escrow. Local protector creation/secret access is
machine/admin; offline backup does not require a cloud membership or subscription.
Account options depend on the selected account and backend, not local elevation.
Use the [retrieval guidance](https://support.microsoft.com/en-us/windows/security/encryption/find-your-bitlocker-recovery-key)
to explain account ownership and matching the key ID from the recovery screen.

Show is an explicit secret workflow outside routine show/status/list, previews,
completion and saved-run serialization. Display only the requested key in a
tested native/local presentation that avoids ordinary console/pipeline, transcript,
debug/error, clipboard and chat output. If that boundary cannot be established,
keep native GUI/portal access and the custom reveal action unavailable pending
implementation; do not reproduce the legacy stdout leak. Export/print/copy must
be distinct user-selected destinations. Sanitize nested native cmdlet objects
and failures before recording them. Do not store the password, a reusable key
package, token or a secret-bearing object in generic state records, or use a
local machine-protected snapshot as the only off-device backup.

Remote retrieval is a separate optional backend, not implied by being local
administrator. A future delegated Entra Graph implementation must expose
BitlockerKey.Read.All with administrator consent plus qualifying device ownership
or a supported Entra role, and applicable tenant restrictions. The
[permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
distinguishes metadata-only BitlockerKey.ReadBasic.All from secret access.
The [stable retrieval API](https://learn.microsoft.com/en-us/graph/api/bitlockerrecoverykey-get?view=graph-rest-1.0)
documents owner/role restrictions, no delegated personal-account support and
auditing when the key is requested. Do not request secret access for discovery,
promise that any work account suffices, bypass tenant audit, or assume an Intune/
Enterprise subscription is required for every local recovery action. Resolve
backend-specific licensing/role requirements before enabling it; no unattended
or app-wide tenant key retrieval is proposed here.

Distinguish backup submitted/saved from recovery access verified. A successful
local cmdlet call or cloud metadata listing alone does not prove the chosen key
can be retrieved from another device and unlock this volume. Acceptance requires
disposable encrypted targets and lab accounts: zero/one/multiple/reordered
protectors, exact-ID selection, preview and repeated backup without duplicates,
failed destinations/permissions/escrow, output redaction, native presentation,
retained recovery after partial failure and actual recovery-screen ID matching
plus unlock using the selected backup. Test each offered file/account backend
separately, with no secrets in ordinary test results. Server coverage and a secure
presentation remain unverified. These designs are proposed and remain counted
pending user acceptance, implementation and feature evidence; no host key access,
creation/export, catalog/profile changes or migration-estimate adjustment.

### Accepted BitLocker recovery-handling decision, 2026-10-11

The user accepted one guided recovery area with normal Back up your recovery
key, advanced Create an additional recovery key and explicit Show the selected
recovery key. Select the RecoveryPassword protector by type and ID, preserving
existing access; backup reuses the selected key without implicit rotation or
duplicates. Require an explicit usable destination and keep secrets outside
routine output, saved state and logs. Prefer native GUI/portal access where
secure custom handling remains unproven. Expose local versus account/join/role/
consent requirements and distinguish saved backup from verified recovery access.
Implementation, secure presentation, actual retrieval/unlock and Server evidence
remain pending. This approval makes no host key access, creation/export or
migration-estimate adjustment.

### Failed Windows sign-in device lockout review, 2026-10-11

Propose retaining this legacy outcome as an optional advanced machine/admin
control matching Local Security Policy, Local Policies, Security Options:
Interactive logon: Machine account lockout threshold. Explain its effect as
requiring BitLocker recovery after failed Windows sign-ins, subject to verified
target behavior. It is not a BitLocker startup-PIN retry counter, Windows Hello
PIN setting or ordinary user Account lockout threshold. Do not automatically
select the legacy ten-attempt preset in recommended profiles or the guided
BitLocker setup. This is a separate deliberate security/availability choice.

Legacy EnableLockOutThreshold writes DWORD 10 to
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts;
Disable writes explicit DWORD 0, not deletion or saved recovery. No maintained
operation was found. The intended GUI mapping needs bidirectional proof on the
current target; a matching DeviceLock CSP leaf name is not documentation of this
direct registry implementation. Prefer the exact local policy reference for
presentation and mark registry mapping unverified until GUI/backend evidence
establishes it. Preserve the original type/data/existence if that backend is used.

Microsoft's [current BitLocker recovery-screen reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/preboot-recovery-screen)
describes device lockout after failed Windows sign-ins, automatic reboot and
BitLocker recovery, and names this Security Options policy. The
[archived policy reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-machine-account-lockout-threshold)
documents 0 as disabled, thresholds 1-999 with 1-3 interpreted as 4, required
restart and the risk of unwanted lockout from excessive retries. Propose explicit
Disabled (0) or a chosen supported threshold, showing literal and effective
values for 1-3 rather than silently coercing them. Coordinate guidance with
account-lockout policy and authentication workload, preserving those independent
settings instead of changing them implicitly.

The archived reference says the threshold can also reboot a machine without
BitLocker, while the current
[LocalPoliciesSecurityOptions CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions)
states enforcement requires BitLocker protecting the OS volume. Retain this
documentation difference as target/backend acceptance work; do not promise
either universal non-BitLocker enforcement or harmlessness. Its CSP edition/build
requirements concern that management path, not proof of local-registry support
or a reason to introduce MDM automatically. The
[DeviceLock CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock)
also distinguishes mobile wipe from desktop BitLocker recovery. Do not label
the Windows desktop control Wipe after failed attempts or port mobile semantics.

Microsoft's [TPM lockout reference](https://learn.microsoft.com/en-us/windows/security/hardware-security/tpm/manage-tpm-lockout)
describes distinct TPM anti-hammering behavior relevant to TPM+PIN. Do not modify
TPM authorization/lockout values, clear/reset the TPM or claim this Windows
sign-in threshold configures that protection. Identify which sign-in attempts
count through actual tests, including locked-session password failures and
local/domain account behavior. Do not generalize to remote/network, Hello,
biometric or preboot attempts without evidence.

Initially offer positive thresholds only on verified supported BitLocker-protected
OS-volume configurations with usable, verified 48-digit recovery-password backup
and recovery access. Expose affected machine, effective policy source, current
threshold, activation/restart status and the fact that another user's failures
can affect machine availability. Refuse conflicting managed policy or missing
recovery readiness; do not enable encryption, create/print secrets, alter account
lockout settings or restart implicitly. Show the same edition/backend/account
qualifications as the accepted BitLocker guide, with no added cloud membership
requirement for the local policy itself. Server and role-specific support still
need independent evidence before availability.

Saved Restore recovers the captured policy configuration; it cannot undo a
triggered reboot, failed-attempt history or recovery-mode/protector transitions.
Keep explicit zero, local policy reset and saved recovery distinct. Establish
supported default/reset semantics before offering WindowsDefault; do not treat
registry deletion or a documented historical disabled default as proof of current
effective behavior. Never replay broad security templates, clear counters or
remove recovery protection as a recovery shortcut. Policy readback alone is
insufficient to label activation complete.

Acceptance requires disposable capable Windows targets with lab sign-in accounts
and separately accessible recovery: GUI/registry/policy mapping, chosen threshold
and 1-3 interpretation, reboot activation, actual counting/automatic recovery,
successful recovery unlock, policy restoration after activation and preservation
of unrelated account/TPM settings. Test managed precedence, explicit zero,
partial failure and repeat apply; keep passwords/recovery secrets out of logs.
Any non-BitLocker applicability investigation also stays inside disposable targets.
Server coverage remains unavailable. The design is proposed and counted pending
user acceptance, implementation and feature evidence; no host policy mutation,
failed sign-in testing, reboot, new support declaration or estimate reduction.

### Accepted failed-sign-in device lockout decision, 2026-10-11

The user accepted the optional advanced machine/admin Interactive logon: Machine
account lockout threshold control, with explicit Disabled or a supported chosen
threshold rather than an automatic ten-attempt preset. Initial positive-threshold
availability requires verified OS-volume BitLocker protection and usable verified
recovery access. Show restart, managed precedence, effective threshold and machine
availability consequences; distinguish Windows sign-in failures from TPM startup
PIN, Hello and ordinary account lockout. GUI/backend mapping, actual counting and
recovery, documentation differences and Server evidence remain pending. Saved
policy recovery cannot undo an enacted lockout or protector transition. This
approval changes no host state, support declaration or migration estimate.

### Photo Viewer registration and default photo app review, 2026-10-11

Propose two separate outcomes: optional advanced Make Windows Photo Viewer
available in Open with, and normal Choose default photo app through Settings >
Apps > Default apps or the supported Open with choice. Registration offers a
candidate; it does not select the default. Keep the legacy viewer outcome under
investigation rather than retire it solely because its registration is hidden or
old. No maintained Photo Viewer operation was found in the focused source review.

Legacy SetPhotoViewerAssociation changes open verbs for Paint.Picture, giffile,
jpegfile and pngfile through merged HKCR. Although its message mentions TIFF,
the actual loop contains no TIFF ProgID. It invokes PhotoViewer.dll through
rundll32 with an unquoted %1, and does not establish a modern per-user default
choice. Unset recursively deletes three open-verb trees and reconstructs an
Internet Explorer GIF command/DelegateExecute rather than restoring saved state.
AddPhotoViewerOpenWith registers Applications\photoviewer.dll with an open
command and DropTarget CLSID; Remove deletes its entire open tree. Neither pair
captures existing registrations. Do not port these destructive reverse selectors,
global built-in ProgID rewrites or historical IE reconstruction as current defaults.

Microsoft's [default-app platform reference](https://learn.microsoft.com/en-us/windows/apps/develop/windows-integration/default-apps-platform)
separates handler registration from user selection and requires ordinary app
default changes through Windows system UI. It documents ms-settings:defaultapps
as the Settings handoff and does not support direct registry modification of
protected default choices. The [Default apps instructions](https://support.microsoft.com/en-us/windows/apps/change-default-apps-in-windows)
describe choosing by file extension or application. Propose explicit user choice
for the desired extensions; no UserChoice/hash bypass, broad association XML
replay, implicit Photos replacement or claim that opening Settings completes the
choice. Managed default-association policy is a separate future workflow, with
its own authority and scope, rather than a shortcut for this user control.

The [application-registration reference](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration)
documents general shell registration, while the
[HKCR merged-view reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/merged-view-of-hkey-classes-root)
explains the physical user and machine sources. These references do not prove
that the legacy DLL-named registration, ImageView_Fullscreen entry point or
DropTarget still provides the intended Photo Viewer behavior on current builds.
The specific native implementation remains experimental until component and
feature evidence establishes it. Do not claim the viewer exists on every Windows
11 installation or supports every photo format merely because a DLL is present.

Prefer a bounded registration in the intended user's physical HKCU classes store,
using a reviewed owned registration/ProgID without overwriting built-in open
verbs. This is an explicit proposed scope change from legacy merged-HKCR writes.
Run in that user's context without proposed elevation, no other-user hive edits
or silent machine fallback. If current behavior requires machine registration,
bring that evidence back for an explicit machine/admin design decision. Default
app selection also belongs to the intended user; expose managed restrictions.
Local registration/choice has no proposed cloud account, subscription or special
membership requirement, but requires a verified installed native viewer. Do not
download DLLs, replace system binaries or uninstall Photos to supply it. Server
GUI/component availability and support require separate evidence.

Capture original type/data/existence for every changed registration value and
preserve pre-existing unrelated subkeys. Define ownership, conflicts, bounded
cleanup, repeat apply and partial-failure recovery before implementation; do not
recursively remove an unknown shared registration. Restore registration changes
independently from GUI default selection. Observe the previous default per type
for recovery guidance, but do not replay protected UserChoice data as a saved
restore. A user-selected default needs supported UI recovery and verification.
Before removing a registration on which the current default depends, guide the
user to choose a usable replacement; do not leave a dangling default or silently
assign another app. Profiles must distinguish registration from a pending user
choice instead of reporting an enforced default after a GUI handoff.

Acceptance requires disposable clean and upgraded Windows 11 targets: native
component identity/availability, reviewed registration path, modern/classic Open
with visibility, Default apps discovery, actual double-click rendering and each
claimed extension. Test bmp, gif, jpg/jpeg, png and tif/tiff separately before
declaring coverage, including animation where claimed, filenames with spaces and
Unicode, command quoting and process/DLL architecture. Prove unrelated app
defaults and other users remain unchanged, existing registrations survive,
repeat/partial operations recover, and the original GUI choice can be recovered
through the supported interface. Registry readback alone proves none of these
outcomes. Server evidence remains unavailable. This is a proposed design pending
user acceptance, implementation and feature evidence; no host registration or
default changes, target-support expansion or migration-estimate reduction.

### Accepted Photo Viewer registration/default-app decision, 2026-10-11

The user accepted two separate outcomes: optional advanced Make Windows Photo
Viewer available in Open with, and normal Choose default photo app through the
supported Windows interface. Prefer bounded intended-user registration without
elevation, subject to current native-component evidence; no implicit machine
fallback. Preserve existing registrations and distinguish captured registration
recovery from the separate user step to recover a default-app choice. Keep the
legacy viewer under investigation without copying destructive reverse selectors
or bypassing protected default choices. Implementation, actual rendering and
GUI discovery, extension coverage and Server evidence remain pending. This
approval changes no host registration/default, support declaration or estimate.

### Media radio-preset and WMDRM remainder review, 2026-10-11

Propose retaining these omitted legacy outcomes as two separate conditional
advanced policy investigations, excluded from normal/recommended selections
until current component behavior is established. Use the Group Policy names
Prevent Radio Station Preset Retrieval and Prevent Windows Media DRM Internet
Access, with plain descriptions of their individual effects. They have different
scope and dependencies and are not interchangeable privacy controls. Preserve
the accepted separate disc/music metadata and library-sharing designs and the
optional Reduce online metadata retrieval guide; do not silently add DRM blocking
to that guide or present the partial bundle as Disable all media online access.

Legacy DisableMediaOnlineAccess writes DWORD 1 to the user policies
PreventCDDVDMetadataRetrieval, PreventMusicFileMetadataRetrieval and
PreventRadioPresetsRetrieval under HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer,
and machine policy DisableOnline under HKLM:\SOFTWARE\Policies\Microsoft\WMDRM.
Enable removes all four overrides, not explicit DWORD 0. The maintained disc
and music operations cover only two parts of this bundle. The current music
description calls the remaining controls retired; that blanket wording needs
correction in implementation follow-up because available sources establish
deprecation and historical applicability, not universal removal on current targets.
No new published operation ID or retirement is decided by this proposal.

Microsoft's [radio-preset policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer#preventradiopresetsretrieval)
maps the user policy and documents preventing preset downloads/updates and
display of user-added presets. This is not a block on playing internet radio,
Bluetooth radios or all player traffic. The local windowsmediaplayer.admx has
class User, this same path/value and enabled 1/disabled 0, but its supportedOn
reference is SUPPORTED_WindowsPreVista. The current CSP page lists Windows 11
availability. Retain this applicability discrepancy: an exposed management policy
does not demonstrate that modern Legacy-player UI still consumes it or that its
preset service operates. Do not invent a current Privacy-tab checkbox equivalent
or promise restored online presets after removing the override.

Microsoft's [WMDRM policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediadrm#disableonline)
maps machine DisableOnline and describes blocking internet/intranet license
acquisition, security-component upgrades and restoration of backed-up licenses.
Its documented behavior permits already locally licensed content and locally
protected CD content; verify remaining behavior rather than generalize it to
current builds. The local windowsmediadrm.admx confirms class Machine and
enabled 1/disabled 0. This control can affect applications using Windows Media
DRM beyond the Legacy player. It does not disable PlayReady, all DRM, modern
streaming subscriptions or remove content protection. Show the possible loss
of protected-content access and component upgrades before this opt-in choice.

Microsoft's [deprecation notice](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)
lists legacy DRM services from September 2024 and consequences of full retirement
for named Windows 7, Windows 8 and Silverlight scenarios. It does not establish
that every Windows 11 WMDRM component/policy is absent, nor a current successful
service endpoint. Keep service retirement, installed-component availability and
actual local policy effect separate. A failing or retired server is not evidence
that RIDE blocked access; deleting a policy cannot bring that server back.

Retain user/no-admin scope for radio presets and machine/admin scope for WMDRM.
Use the intended user's context and never redirect HKCU to an elevated alternative
account. Show installed component, effective policy source and managed precedence.
The CSP pages list Pro, Enterprise, Education and IoT Enterprise variants for
their management path; validate local policy applicability separately rather than
impose an MDM enrollment requirement. No new RIDE membership, cloud account or
subscription is proposed for local policy changes. Playback remains subject to
existing content rights and usable licenses/services; setting a policy cannot
grant those rights. Do not install a player/Media Feature Pack, acquire licenses,
repair DRM stores or enable services implicitly. Server support requires its own
component/role evidence and remains unavailable here.

Proposed states are Blocked (policy enabled), Policy disabled (explicit 0) and
Not configured (override removed), with language explaining that the latter two
permit the component's behavior rather than ensure connectivity or playback.
Verify literal/effective defaults per target before treating override removal as
a Windows default. Saved Restore recovers exact original type/data/existence
of each policy; it cannot recover expired/deleted licenses, missed upgrades,
retired services or changed application content. Do not touch DRM license stores,
media files, caches, player preferences, network/firewall rules or unrelated
policies. No whole-tree removal or broad security/template replay.

Acceptance needs disposable targets with verified applicable components and
controlled licensed test content: bidirectional Group Policy mapping, actual
radio-preset UI/service applicability, WMDRM request/effect evidence, unrelated
modern-player/DRM preservation, separate user/machine contexts, managed
precedence, repeat/partial operations and exact typed policy recovery. Read-only
ADMX inspection in this review establishes mapping, not feature acceptance.
If no active explainable outcome exists on supported targets, return with that
evidence for a retirement decision rather than publishing a cosmetic registry
toggle. This proposal keeps the bundle partial pending user acceptance,
implementation and feature evidence; no host change, retirement, new supported
target or migration-estimate adjustment.

### Accepted media radio-preset/WMDRM remainder decision, 2026-10-11

The user accepted separate conditional advanced investigations for Prevent Radio
Station Preset Retrieval (current user/no admin) and Prevent Windows Media DRM
Internet Access (machine/admin), withheld from normal/recommended selections
until actual current-component effects are established. Keep DRM blocking out
of the optional metadata-reduction guide, show content-access/upgrade effects
and preserve override-removal versus explicit-disabled semantics. Correct the
blanket retired description in later implementation follow-up; current policy
documentation and deprecation do not prove universal removal. Exact typed policy
recovery cannot restore retired services or licenses. Feature evidence and Server
coverage remain pending, with no host change, retirement or estimate adjustment.

### Visual-effects remainder and full keyboard repeat-delay review, 2026-10-11

The accepted 2026-10-10 visual-effects decision already selects independent
GUI-aligned effects, separate timing preferences and deferral of complete
appearance/performance presets. Retain that decision. This follow-up proposes
completing Keyboard repeat delay with all four native positions, while keeping
UserPreferencesMask and VisualFXSetting out of normal selection until their
remaining feature mapping and lifecycle are understood. No automatic bundle
of input changes belongs in a visual-appearance selection.

Legacy SetVisualFXPerformance writes the entire eight-byte UserPreferencesMask
as 90 12 03 80 10 00 00 00; SetVisualFXAppearance writes 9E 1E 07 80 12 00 00 00.
Both also set VisualFXSetting DWORD 3 and eight other preferences. The legacy
comment claims retained font smoothing and thumbnails, but it is not current
evidence of which mask bits or other preferences establish those effects.
Neither selector captures prior values or represents exact saved recovery, and
the common VisualFXSetting value does not prove equivalence to Windows' Best
performance or Best appearance choices. Do not publish those fixed masks as
verified profiles or expose an unexplained numeric mask setting to normal users.

Prefer the individual native feature APIs where Microsoft documents them,
subject to bidirectional GUI/actual-effect validation, instead of copying a
whole packed value. Microsoft's [SystemParametersInfo reference](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow)
documents individual UI-effect and keyboard-delay actions, along with profile
persistence and change notification. Its broad SPI_SETUIEFFECTS action must not
substitute for a single selected checkbox or a complete Performance Options
preset. The [performance guide](https://support.microsoft.com/en-us/windows/experience/performance-optimization/tips-to-improve-pc-performance-in-windows)
identifies the Visual Effects dialog but does not document the legacy byte masks.
Do not infer bit names from the two fixed byte arrays alone. Trace every omitted
effect against one GUI choice at a time on disposable current builds, recording
dependencies and preserving unknown bits and unrelated preferences.

For windows.keyboard-repeat-delay, propose Control Panel > Keyboard > Speed >
Repeat delay presentation with positions 0 (Shortest), 1, 2 and 3 (Longest),
verifying that GUI mapping on each target. Explain that this controls how long
a held key waits before repeating; repeat rate, Filter Keys, keyboard layout,
menu delay and animation remain independent. The documented API range is 0-3,
with approximately 250 ms and one second at the endpoints, hardware dependent.
Do not label intermediate positions with guaranteed milliseconds or present 0
as no delay. Retain Shortest=0 and LegacyAppearance=1 for compatibility; show
the latter as position 1 with its legacy alias visible. Add reviewed states for
positions 2 and 3 without renaming published IDs or reinterpreting existing
profiles/saved runs. Complete all declared states from the catalog as usual.

The current catalog already declares KeyboardDelay as String, while both legacy
selectors wrote DWORD 0/1. That type correction does not finish GUI or runtime
acceptance. Prefer focused SPI_GETKEYBOARDDELAY/SPI_SETKEYBOARDDELAY inspection
and application once persistence, session context and saved recovery are proven.
Keep literal registry state and effective live delay distinct: a stored value
need not describe the current interactive setting. Any handler/schema change
must retain a versioned recovery path for existing RegistryValue snapshots;
do not silently reroute the stable ID or claim the generic handler already
refreshes Windows. Until that contract is proven, retain current limitations.

Recovery must capture both exact original stored type/data/existence and the
effective delay where a native setter is used. Preserve legacy DWORD, valid
String, absent and unexpected prior representations, reporting ambiguity rather
than coercing them. Restore the captured effective delay and exact storage
without letting a persistence call normalize away the captured type or recreate
an originally absent value. Establish and test the sequence before claiming
exact recovery. Application/saved recovery notifications are part of the focused
handler's declared effect; no synthetic keystrokes, forced process restart,
sign-out or reboot. Inspection and completion never invoke a setter.

Keep intended-user/no-admin scope for these personal preferences and show
active-session requirements and relevant managed/accessibility overrides. No
special account, subscription or membership is proposed. Do not edit another
user's hive or machine defaults, disable accessibility aids, or promise every
application/hardware combination honors the preference. Where a current setting
has no verified independent feature outcome, keep it experimental rather than
give it an invented GUI name. Taskbar animation and Peek remain experimental
under the existing accepted decision. Server GUI/session support still needs
independent target evidence.

Acceptance requires disposable Windows 11 targets for all four slider positions,
API/effective-state readback, persistence across a later sign-in, actual held-key
repeat timing and preservation of repeat rate/Filter Keys/other effects. Include
String, legacy DWORD, absent and unexpected snapshots, native/persistence partial
failures, repeat apply and saved-run compatibility. Packed-effect research needs
single-choice GUI observations, actual rendering, dependencies and preservation
of unrelated/custom bits before any preset proposal. No host setting test was
run here. This follow-up is a proposed range/backend design pending acceptance,
implementation and feature evidence; the legacy visual bundle remains partial,
with no target-support expansion, retirement or estimate reduction.

### Accepted full keyboard repeat-delay decision, 2026-10-11

The user accepted all four keyboard repeat-delay positions, matching the native
GUI after target verification, with repeat rate and appearance controls separate.
Retain published IDs, Shortest=0 and LegacyAppearance=1 compatibility; add
reviewed positions 2/3 without guaranteeing intermediate timing. Prefer focused
native inspection/application only after proving persistence and recovery of
both effective delay and exact stored DWORD/String/absent/unexpected prior state,
including existing saved runs. Packed visual-effects presets remain deferred.
Implementation, GUI/runtime recovery and Server evidence remain pending. This
approval changes no host input preference, support declaration or migration estimate.

### Keyboard stored range implementation, 2026-10-13

The stable keyboard-delay ID now includes `Position2='2'` and `Longest='3'`, with
`Shortest='0'`, `LegacyAppearance='1'`, WindowsDefault removal and the existing
RegistryValue backend unchanged. This follows the accepted range while respecting
the conditional native-backend decision: stored registry state does not establish
effective interactive delay, GUI position or persistence. Description and the
[keyboard guide](../keyboard-repeat-delay.md) state these limits explicitly.

Local mocked checks cover catalog-driven selection/completion and serialized
DWORD, String, unexpected String/binary and absent-state literal recovery,
including unrelated key data and pre-change capture before partial failure.
Native application, effective-state/versioned recovery, actual held-key behavior,
later-sign-in persistence and independent Server applicability remain deferred.
Packed masks and the whole visual-effects bundle remain partial; no profile or
target support is added and no outcome is removed from migration estimates.

The user's explicit VM-testing hold remains in effect until manual confirmation.
No disposable VM or live input preference is changed by this increment. The
dated migration-plan entry records **51 passing focused mocked checks per edition**
on Windows PowerShell 5.1 and PowerShell 7.6.5, with parser/catalog/profile/reference
validation passing too. Those results do not establish GUI or effective-session
acceptance.

### WAP Push/Search explicit delayed-start remainder review, 2026-10-11

The accepted service design already separates Services GUI startup choices from
explicit runtime actions and preserves published presets. Propose one additional
clearly named combined preset for each existing WAP Push/Search operation:
Automatic (Delayed Start) + Start now, with candidate state AutomaticDelayedRunning.
It deliberately configures automatic startup with delayed boot scheduling and
requests Running now, reconciling the omitted legacy enable outcome. It is not
a new standalone registry operation or a default recommended service choice.
Selecting startup type alone remains a separate outcome under the accepted design.

Legacy EnableWAPPush sets dmwappushservice Automatic, starts it, then writes
DelayedAutoStart DWORD 1; EnableIndexing sets WSearch Automatic, writes that
flag, then starts it. Their Disable selectors stop the service and set Disabled
without explicitly resetting delay. The current windows.wap-push-service and
windows.search-indexing-service capture and preserve delay around applying
AutomaticRunning, and capture it for saved recovery. Thus preservation is already
implemented; the missing part is deliberate selection of delayed startup.
Do not redefine AutomaticRunning or Disabled to force/erase the flag. In
presentation explain the former as Automatic + Start now (preserve delay), so
users can distinguish it from a deliberately immediate or delayed startup choice.

Keep one coordinated service handler for startup and its delay option, with
machine/admin scope for both services. Query effective SCM configuration with
the supported service-manager interface and retain literal typed registry
capture for exact recovery. Microsoft's [configuration API](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
documents SERVICE_CONFIG_DELAYED_AUTO_START_INFO and querying optional service
configuration. Do not introduce a competing RegistryValue catalog control for
DelayedAutoStart. Existing snapshots and published state meanings require a
versioned compatibility path if handler/state schema changes.

The [delayed-start reference](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info)
states that delay only matters for automatic services, takes effect at the next
system start and has no guaranteed duration; dependencies or demand start may
cause earlier startup. Start now requests immediate runtime activation despite
the future boot delay. Report startup configured and observed runtime status
separately; do not claim boot scheduling was tested or enforce continuous Running
from one successful start. A trigger-started service may later stop normally.
No implicit reboot or artificial fixed startup-delay promise.

GUI-aligned startup-only Automatic explicitly selects non-delayed automatic;
Automatic (Delayed Start) explicitly selects delayed automatic. Manual and
Disabled preserve dormant captured delay metadata unless a separately reviewed
choice changes it. Startup-only choices do not also start/stop the service;
show Start now/Stop now as explicit runtime effects, while keeping current
published combined presets available. The new combined preset must preflight
both supported configuration and runtime activation, capture before either
mutation, configure startup/delay before requesting Running, and report or
recover partial stages without inventing an atomic SCM transaction.

Saved recovery must reconcile effective SCM startup/delay with exact original
delay type/data/existence and the supported prior runtime state. An SCM setter
may normalize the backing value; define and verify the restoration sequence
before promising exact storage and effective behavior together. Unexpected
representations or unsupported paused/transitional cases require an explicit
limitation/refusal instead of silently coercing a snapshot. Older snapshots
without the delay field cannot recover a value they never captured; preserve
current compatible behavior, report that limitation and never assume zero.
Preserve triggers, dependencies, failure actions, service accounts/security and
unrelated configuration; no force-stop of dependent services or whole service
registry-tree replay. Restoring runtime cannot undo missed indexing/sync work.

Use Services display names with dmwappushservice/WSearch identifiers. For WAP
Push, show that disabling can impair device-management synchronization.
Microsoft's [Intune troubleshooting reference](https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-management/cannot-sync-windows-10-devices)
describes that failure on Windows 10; current Windows 11 management acceptance
remains separate. For Search, the [focused performance reference](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/windows-search-performance-issues)
identifies Automatic (Delayed Start) and Running as troubleshooting checks.
That is not proof of every target's factory default or an instruction to replay
its index-repair steps. Preserve indexed content, search scope and web-search
preferences; no index deletion/rebuild or background sync request here.

Local service configuration requires elevation and the actual installed service,
with no special subscription/account/membership requirement. Intune workload
validation needs an appropriately enrolled managed test device and authorized
tenant access; do not enroll, change licenses or query tenant secrets implicitly.
Show managed-policy/workload restrictions. A missing service is unavailable,
not a successful setting or a reason to install components. RIDE's existing
AutomaticRunning baseline is an explicit selection, not WindowsDefault; no
service-value deletion can stand in for restoring an image-defined default.
Do not broaden existing Windows 11 declarations to Server without feature tests.

Acceptance needs disposable applicable Windows targets for GUI/SCM/literal
configuration, immediate start versus actual later boot behavior, dependencies/
triggers and workload checks. Test the new preset from Automatic delayed/non-
delayed, Manual and Disabled; preserve old AutomaticRunning behavior and recovery
of DWORD/absent/unexpected delay metadata and older snapshots. Cover failures
between startup, delay and runtime stages, repeat apply and read-only inspection/
completion. No service mutation or boot/workload test was run here. This is a
proposed explicit preset/refinement pending acceptance, implementation and
functional evidence; delayed legacy coverage remains partial and estimates unchanged.

### Accepted WAP Push/Search delayed-start preset decision, 2026-10-11

The user accepted an explicit Automatic (Delayed Start) + Start now preset for
each existing WAP Push/Search service control, with candidate state
AutomaticDelayedRunning. Retain published AutomaticRunning delay-preservation
and Disabled dormant-delay behavior, and the earlier accepted separation of GUI
startup choices from runtime actions. Use one coordinated machine/admin service
handler, with captured literal/effective delay, startup and runtime, staged failure
reporting and compatible saved recovery. No fixed-delay guarantee, automatic
reboot or competing raw-registry control. Implementation, GUI/SCM/boot/workload
tests and Server evidence remain pending; approval changes no host service,
support declaration or migration estimate.

### WAP Push/Search implementation and VM acceptance hold, 2026-10-13

The accepted delayed-start/service design now has a focused implementation on
`windows.wap-push-service` and `windows.search-indexing-service`. Both expose
`AutomaticDelayedRunning` plus four startup-only choices. Published presets,
baseline meanings, IDs and existing target declarations are retained; recommended
profiles remain unchanged. The coordinated handler configures startup/SCM delay
before explicit runtime actions, preserves dormant literal flags for compatibility
presets, and verifies readback. New snapshots capture exact identity, SCM flag and
literal value/type/absence; older snapshots keep their raw-only recovery boundary.
Stage failures remain partial with engine pre-change records available.

The [service guide](../service-settings.md) documents native API references,
startup/runtime distinctions and Disabled-but-running recovery. Local mocked
validation is separate from GUI/SCM normalization, boot scheduling, dependency,
trigger and workload evidence. Windows 11 feature acceptance and independent
Server applicability remain pending, so neither legacy outcome is closed.

Final focused mocked Pester passed **38 tests per edition** on Windows PowerShell
5.1 and PowerShell 7, after correcting a new display-test assertion to the existing
`InDesiredState` output property. The preceding broader mocked settings regression
passed **235 tests**. Parser/catalog/profile/generated-reference validation passed
on both editions (303 operations, three groups, five profiles, 108 PowerShell
files). Native declarations compile without opening service handles. These results
prove the mocked contract and metadata, not GUI/boot/SCM normalization or workloads.

The user prohibits starting disposable VM tests until their manual confirmation
after the GitHub cache/backoff investigation. No such tests are launched or
scheduled by this increment; elapsed time or quota recovery is not approval.

### Service registry-reader compatibility correction, 2026-10-13

Follow-up review found that the preceding service implementation's restore
validation required key existence, but the real generic registry reader returns
only named-value existence, data and type. Earlier mocked fixtures supplied the
extra field, hiding that mismatch. Module 0.3.1 captures the exact service key
separately, refuses an unavailable key and includes `KeyExisted` in new snapshots.
Unversioned service records created before this increment can omit that field;
their recovery conservatively retains the service key while restoring named-value
type/data/absence. It does not infer missing key-state history or delete the key.

Regression fixtures now model the reader's real output and missing-field legacy
records. This is a local recovery repair, not VM/feature acceptance or a closed
legacy outcome. Manual confirmation is still required before any VM testing.
Final local evidence is recorded in the dated migration-plan follow-up.

### Security notification icon startup remainder review, 2026-10-11

The accepted icon-policy design already keeps legacy startup mutations omitted.
Propose resolving the remaining user outcome with a guided Show the Windows
Security icon workflow: inspect/explain the existing machine policy, guide the
intended user to the existing Windows Security notification icon entry in
Settings > Apps > Startup or Task Manager > Startup apps when present, and verify
appearance after the required refresh. Keep startup choice distinct from the
existing Hide/Show policy. Prefer this supported GUI handoff initially; do not
copy the legacy Run-entry recreation or claim a one-click repair. Automatic
startup management, if later needed, requires its own reviewed scope/backend
and recovery contract rather than being hidden in windows.security-notification-icon.

Legacy HideDefenderTrayIcon sets HideSystray DWORD 1 and removes the machine Run
value WindowsDefender on build 14393 or SecurityHealth on builds >=15063. Show
removes the policy override and writes build-selected REG_EXPAND_SZ commands:
MSASCuiL.exe for older branches, SecurityHealthSystray.exe from build 17763.
DisableDefender/EnableDefender repeat those Run edits alongside DisableAntiSpyware.
None captures the original command/type/existence or the user's startup-app
choice. Do not reconstruct these historical values as saved recovery, make tray
startup part of antivirus configuration, or assume broad build >= matching proves
the appropriate registration on every current Windows image.

Microsoft's [exact tray policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsdefendersecuritycenter#hidewindowssecuritynotificationareacontrol)
maps HideSystray to Hide Windows Security Systray and requires sign-out/sign-in
or reboot for effect. Keep the current stable ID and Hidden=1, Shown=0 and
override-removal state meanings. Describe Shown as permitting display subject
to startup/component readiness, rather than repairing an absent launcher. Show
policy configured separately from appearance pending refresh. Leave sign-out
or reboot to the user; no process launch/kill, service changes or forced refresh.
Exact saved policy recovery remains bounded to the captured policy value.

Microsoft's [startup-app instructions](https://support.microsoft.com/en-US/Windows/Experience/Startup-Boot/configure-startup-applications-in-windows)
describe Settings and Task Manager choices and distinguish machine Run sources
from current-user Run sources. This general documentation does not prove a
particular current SecurityHealth command, approval-store representation or its
GUI enablement scope. Verify that exact entry and effective startup decision on
each target before claiming a direct backend or per-user/all-users effect.
The legacy HKLM Run registration was machine-wide; do not silently replace it
with HKCU, duplicate it or use an elevated alternate account's startup settings.
GUI handoff does not itself constitute a successful RIDE apply or a captured,
automatically reversible startup change. Retain pending/user-step reporting.

The [Windows Security architecture reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/windows-defender-security-center/windows-defender-security-center)
describes the interface separately from individual protection features. Icon
visibility is not evidence of antivirus effectiveness; its absence is not proof
that protection is off. Preserve Defender, third-party security providers,
notifications, tamper protection and SecurityHealthService/wscsvc. Do not suppress
security alerts, modify binary permissions or remove protection to achieve an
appearance outcome. A complete guide explains missing/disabled startup,
managed hiding, taskbar overflow and missing component as distinct possibilities,
without inventing a universal repair or all-clear security status.

Retain machine/admin scope for the policy. Run GUI guidance in the intended
interactive user's context, exposing any actual GUI permission/managed-policy
restriction rather than promising an unverified startup toggle's scope. No
special account, cloud membership or subscription is proposed for local icon
configuration. If an expected startup entry or signed native component is absent,
report it and point to a separately reviewed Windows repair path; no DLL/binary
download, blanket app reset/reinstall, arbitrary Run command or old command
substitution. Server UI/component support remains independently unverified.

Acceptance requires disposable Windows 11 targets: policy/GUI mapping, existing
startup-enabled/disabled cases, absent/custom Run entries, current component and
actual appearance after user-controlled sign-in/reboot. Verify effective startup
scope with multiple users, managed precedence, taskbar overflow, unchanged
protection/alerts and exact policy recovery. Any future startup backend also
needs exact command/approval-state capture, conflict handling, partial failures
and bounded recovery, without replaying unknown startup-store trees. No host
startup/policy change or runtime test occurred here. The guide is proposed
pending acceptance/implementation/evidence; omitted automatic legacy startup
mutation remains explicit partial coverage without retirement or estimate closure.

### Unidentified user .NET assemblies ledger entry, 2026-10-11

Split this unresolved entry from Security icon startup: no source evidence in
this review connects the two. Searches of all five legacy/v2 files, including
hidden/ignored-source checks, found no selector installing/removing user .NET
assemblies or native images. The System.Windows.Forms assembly loads in the
NumLock functions are in-process dependencies, not an identified assembly
deployment outcome. The accepted machine .NET strong-crypto registry controls
are a separate reviewed family. The repository's script walkthrough mentions
native-image conversion follow-up but does not establish this ledger entry's
specific selector, paths, user scope, purpose or recovery semantics.

Keep this as source identification pending, not an accepted retirement or a
new guessed operation. Establish exact selector/source version, intended app
outcome and affected resources first. If assembly deployment/cache maintenance
is identified, give it the appropriate artifact/application/maintenance owner
and separate acquisition, licensing, runtime and recovery review; never hide
file/cache mutations behind a registry setting or count the same outcome twice.
No assembly execution, cache change, source deletion or estimate adjustment.

### Accepted Security icon startup-guide decision, 2026-10-11

The user accepted the guided startup checks for showing the Windows Security
icon, with the existing focused machine/admin policy separate from intended-user
Settings/Task Manager startup choice and user-controlled refresh. Preserve
protection, alerts, services and current policy state/recovery meanings; no
automatic historical Run-command reconstruction or implicit repair. Any later
direct startup backend still requires its own scope/ownership/recovery review.
Implementation, actual multi-user startup/appearance and Server evidence remain
pending. This approval changes no host startup or policy, support declaration
or migration estimate.

### Windows Security icon guide implementation, 2026-10-13

Delivered the accepted [guided workflow](../security-icon-startup.md), linked from
README, with catalog-backed scope, GUI effect, prerequisites and reference
metadata. The existing stable ID/Hidden/Shown/removal states and policy-only
recovery are preserved. Shown permits display subject to startup/component
readiness; appearance after user-controlled refresh remains a separate observation.
Intended-user startup/overflow checks and GUI changes are manual user steps, not
captured apply/restore success. Missing/managed entries remain pending rather
than invoking a guessed repair or historical Run command. Protection/alerts and
services remain independent. No target support is added.

Local source/reference validation is recorded in the migration-plan entry; actual
startup identity/scope, multi-user appearance and independent Server evidence are
still open. No host change or VM test is made, the manual-confirmation hold stays
active, and no legacy estimate is reduced.

### Unidentified-entry source audit and closure path, 2026-10-11

In response to the user's question, retain User .NET assemblies as a provenance
issue requiring investigation, not an executable catalog setting or a known
unimplemented feature. Follow-up searches found no relevant deployment/cache
selector in maintained modules/tools/components or in script/data files at the
local v1.337 and v2.5.1 tags. The local all-ref history search for ngen,
native-image and user-assembly identifiers also yielded no relevant change;
the exact ledger phrase has no tracked documentation history. These searches
are bounded evidence, not proof that no older external/custom source exists.

The script walkthrough's native image conversion item refers to wallpaper
conversion: components/wallpaper/make-wallpaper-files.ps1 uses ImageMagick and
loads System.Drawing for a bitmap. It does not identify .NET native-image cache
generation or user assembly deployment. Together with the in-process NumLock
assembly loads and separately reviewed machine strong-crypto family, this
removes those candidate interpretations from the unidentified entry. A mistaken
or duplicate ledger entry is plausible, but is not yet an accepted conclusion.

Keep the exact unresolved label and audit evidence in the decision ledger for
the final walkthrough; it does not prevent implementing other identified
settings. Do not ask the user to reconstruct forgotten implementation details
as the only recovery route. Resolve through source/selector/version evidence
or a documented disposition review:

- If a distinct legacy outcome is found, record its source, purpose, affected
  resources and scope, assign the correct settings/application/artifact/
  maintenance owner and review its prerequisites and recovery before migration.
- If it duplicates an already tracked outcome, link that canonical entry and
  close only the duplicate, preserving the original acceptance gaps.
- If the review establishes a bookkeeping error with no identifiable intended
  outcome, record that evidence and an explicit agreed correction; do not call
  it a retired feature or a migrated setting.

Until resolved, status is Source identification pending, with no catalog ID,
handler, guessed cache/file mutation or successful-migration claim. Do not add
an extra legacy component to numeric counts solely because this label exists,
or reduce estimates as if a feature were retired. Existing rounded estimates
remain unchanged. Source audit and approval recording changed documentation
only; no assembly execution, licensing acquisition or cache changes occurred.

### Modern firewall replacement decision follow-up, 2026-10-11

The accepted StandardProfile disposition preserves that legacy ID and recovery
access while excluding it from normal choices. It did not accept the proposed
modern replacement. Bring that remaining design forward now: three independent
Windows Firewall controls for Domain network, Private network and Public network,
plus optional Enable Windows Firewall for all network types composition. Each
offers explicit On and advanced opt-in Off, mapped to the Windows Security
Firewall & network protection profile page. All three apply to the whole device,
require administrator rights and configure local profile state subject to managed
policy. They are new focused scope, not a remapping of the legacy registry ID.

The [Windows Security guide](https://support.microsoft.com/en-us/windows/security/windows-security/firewall-and-network-protection-in-the-windows-security-app)
names these three network types and their On/Off controls. Preserve this GUI
terminology and show which profiles are currently active, including concurrent
networks. Configuring the Domain profile does not require RIDE to join the device
to a domain; its use depends on Windows' domain-network classification. Local
configuration has no proposed cloud account, Defender for Endpoint subscription
or special membership requirement beyond administrator access and supported
installed Windows components. Show actual target/edition and managed restrictions;
separate Windows 11 and Server acceptance remains required before availability.

Use a focused native handler writing only the selected profile's Enabled field
in explicit PersistentStore. Inspect local configured state separately from
effective ActiveStore state through the
[Get-NetFirewallProfile reference](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps).
Readback of the local write is insufficient to report effective protection if
managed policy disagrees. Show the conflict and effective source when known,
without writing GPO/MDM policy, modifying network category or removing a legacy
override to force agreement. Preserve the earlier documented StandardProfile
key-existence precedence and flag applicable overrides without automatic cleanup.

The [setter reference](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps)
documents profile-specific Enabled True/False. It explicitly restricts Enabled
NotConfigured to GPO configuration. Therefore do not offer a generic local
WindowsDefault or implement local reset by writing NotConfigured/deleting
registry data. This qualifies the earlier suggestion to capture any supported
unset/native state: prove support in the selected store, preserve its exact
representation and refuse mutation when exact recovery cannot be established.
Saved Restore returns the captured local profile value, never a resultant
managed value copied into local configuration. Historical StandardProfile
snapshots continue through their original typed registry recovery path.

The optional all-types action sets these three independently reviewed controls
On, capturing all three local values before any mutation. Preserve mixed prior
states and report per-profile completion/partial failure; the native command is
not a transaction. Recover only changed declared fields using saved state, with
conflicts/intervening changes visible. This action is an explicit enablement
choice, not Windows' factory default, a rule reset or a claim of complete network
hardening. Connect the guide to reviewed Remote Desktop/file-sharing exposure
checks and explain effective rules and service readiness. Never silently enable
exceptions or broad access to make application connectivity succeed.

The [firewall overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/)
recommends keeping Windows Firewall enabled and warns against stopping its
service. Preserve MpsSvc/BFE, all rule definitions, app exceptions, logging,
inbound/outbound defaults, IPsec and unrelated profile settings. Off stays
advanced and explicit, with affected network-type exposure shown. No disable-all
security recipe, automatic service repair, reset/import of full firewall policy
or implicit remote session management. Apply/Restore preview must be read-only;
capture and readback stay bounded to declared profile fields and relevant
effective inspection.

Acceptance follows the earlier full firewall review: disposable targets with
GUI/local/effective comparisons, unmanaged and managed precedence, inactive and
simultaneously active profiles, mixed-state exact recovery, partial failure and
benign allowed/blocked traffic checks. Preserve independent lab-console access
for connection disruption and verify existing rules are unchanged. No host
firewall mutation or feature test was run here. The modern three-control plus
enable-all design remains proposed pending acceptance, implementation and target
evidence; existing estimates and final-walkthrough milestone are unchanged.

### Accepted modern firewall replacement decision, 2026-10-11

The user accepted separate Domain, Private and Public Windows Firewall controls
matching the Windows Security GUI, plus optional Enable firewall for all network
types composition. Each configures local whole-device state with admin rights,
showing configured versus effective managed behavior; Off stays advanced. Preserve
existing rules/services and all three captured local values, including mixed-state
and partial-failure recovery. No generic local NotConfigured/default reset or
automatic legacy override cleanup. Keep the deprecated StandardProfile ID and
its original recovery path. Implementation, connection/GUI/lifecycle tests and
Server evidence remain pending; approval changes no host firewall or estimates.

### Modern firewall implementation with acceptance hold, 2026-10-13

The accepted design now has a focused FirewallProfile handler: Domain, Private
and Public On/advanced Off, plus enable-all captured as one operation. Complete
pre-change snapshots, local-versus-effective/active-network/source inspection and
per-profile drift/readback checks preserve bounded mixed-state recovery and
partial-completion reporting. Original StandardProfile registry recovery remains
intact. No local default/reset/NotConfigured mutation, rule/service repair or
automatic legacy cleanup is added. See the [firewall guide](../firewall-profiles.md).

New records have empty supported targets pending acceptance, with explicit
candidate Windows 11/Server 2025 targets. Normal apply is blocked before live
inspection/mutation. Local mocked evidence is recorded in the migration-plan
entry; GUI, traffic, precedence and separate Server installation-type evidence
remain open. No legacy estimate is reduced. Manual confirmation is required
before disposable VM testing; none is started/scheduled here and packages stay paused.

### Ultimate Performance, plan creation and desktop menu review, 2026-10-11

Propose three independent outcomes: select an existing power plan, explicitly
create a supported plan copy, and optionally add desktop access to power-plan
selection. Retain windows.active-power-scheme and its published Balanced/
HighPerformance selection and saved active-GUID recovery. Ultimate Performance
is an advanced conditional candidate, not a universally available setting or
recommended performance preset. Selection never silently creates a missing plan;
creation does not implicitly activate it. A reviewed guided Create and select
workflow may compose both steps with capture and failure reporting visible.

Legacy SetPowerSchemeBalanced, SetPowerSchemeHighPerf and SetPowerSchemeUltimate
search localized powercfg /list output for English names. If absent they duplicate
a hard-coded source GUID without specifying a destination, then activate the
source GUID instead of the newly returned GUID. Microsoft's
[powercfg reference](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options)
documents that duplication creates a new GUID unless an explicit destination
is supplied, separately from activation/deletion. Do not port the source/destination
confusion, localized-name matching, unchecked activation or runner-wide Exit.
A familiar plan name is not proof of template identity, installed availability
or successful activation; custom/OEM and duplicate names must remain distinct.

The recorded batch-2 VM evidence could query the legacy Ultimate GUID
e9a42b02-d5df-448d-aa00-03f14749eb61, but activation failed with Windows' unsupported
setting error. Creating a distinct copy is a separate untested scenario, not an
assumed fix. Report unavailable/failed activation honestly; no fallback to High
Performance or success claim from queryability. Discovery/status/completion must
not probe availability by switching plans, duplicate templates or change settings.

Match plan selection to Control Panel > Hardware and Sound > Power Options.
Do not label Ultimate Performance or High Performance as the modern Settings
Power mode choice Best performance. Microsoft's
[power-mode guide](https://support.microsoft.com/en-us/windows/change-the-power-mode-for-your-windows-pc-c2aff038-22c9-f46d-5ca0-78696fdf2de8)
describes the separate Settings choice and notes custom plans can prevent changing
that mode. Preserve power-mode/overlay and AC/DC preferences unless explicitly
selected in their own reviewed operations. The existing accepted ordering still
applies: activate a plan before changing its individual preferences and recover
those values to the actual affected scheme before restoring active-plan selection.

Microsoft's [2018 Ultimate Performance announcement](https://blogs.windows.com/windows-insider/2018/02/14/announcing-windows-10-insider-preview-build-17101-fast-build-17604-skip-ahead/)
describes Windows 10 Pro for Workstations, non-battery availability then, and
increased power use compared with Balanced. Treat this as historical intent,
not a current Windows 11/Server edition/license/support matrix or guaranteed
speed improvement. Verify current edition/build, hardware/sleep model, battery
and management restrictions. Show supported availability and power-use tradeoffs;
no special RIDE membership/cloud account is proposed, but do not invent a license
bypass or recommend an OS edition upgrade without current evidence. No firmware,
Modern Standby/hibernate override, thermal-limit change or forced feature enablement
to make a plan selectable. Server coverage remains independently pending.

Plan creation is an explicit advanced machine/admin resource lifecycle. Identify
the verified source, reserve a fresh destination GUID and record creation intent
before duplication; refuse collisions and verify the created GUID/content after
the command. Retain the actual GUID in a versioned ownership record for repeated
runs/recovery. Never identify ownership by English display name alone, overwrite
an existing plan or create another duplicate on every apply. Preserve pre-existing
plans and activation. Report source unavailable, creation pending/complete and
activation pending/failed separately; a process exit code alone is insufficient.

Restore selection from its captured active GUID. Creation recovery may remove
only the proven RIDE-created plan, after recovering explicit preference changes
and selecting the saved usable plan where required. Never delete an active plan,
the source template, an unowned plan, or a created plan with unexplained later
user modifications. If the saved plan is missing/unactivatable or ownership/
content has changed, stop cleanup and report the recoverable partial state rather
than guessing Balanced. Define record/schema compatibility, crash recovery and
bounded change detection before claiming exact creation lifecycle. Full factory
power-plan reset is not saved-run restore; no bulk deletion or policy import.

Legacy SetPwrSchemeDesktopMenu creates a Switch Power Plan submenu through merged
HKCR using only matching English names present in /list at creation time; its
entries run powercfg directly with captured GUIDs. Remove recursively deletes
the whole named menu without prior-state capture. The menu can become stale and
bypasses RIDE capture/reporting when clicked. Preserve this as a separate optional
convenience outcome, never a prerequisite for plan selection/creation.

Prefer desktop Power plans access opening the native Power Options page initially,
with actual selection made there; report it as GUI access, not an applied plan.
Direct quick-selection entries remain advanced follow-up, available only after
they can invoke the maintained selection workflow with saved-state capture and
current GUID validation, appropriate privilege and stable installed-runner paths.
Do not embed legacy code, silent creation or arbitrary script commands. Installing/
removing a menu never changes the active plan; removing it does not undo choices
made through the GUI. A missing/stale target is a reported unavailable action,
not a reason to create a plan or select a different one.

Resolve the [merged HKCR sources](https://learn.microsoft.com/en-us/windows/win32/sysinfo/merged-view-of-hkey-classes-root)
before choosing physical menu scope. Prefer a new intended-user convenience
registration, explicitly documenting that scope choice rather than implying
legacy HKCR was per-user. Verify current-user/no-admin menu installation separately
from machine/admin plan actions; no silent all-users fallback or elevation under
another user's hive. General [cascading-menu documentation](https://learn.microsoft.com/en-us/windows/win32/shell/how-to--create-cascading-menus-with-the-subcommands-registry-entry)
does not establish this exact desktop registration or Windows 11 modern-menu
placement. Use a bounded owned key, preserving captured types/subkeys/security
if changed, with conflict detection and exact menu recovery. Do not delete an
existing similarly named menu or force Explorer restart.

Acceptance needs disposable capable Windows targets: existing-plan identity,
localized names, same-name custom plans, explicit duplication/new GUID, repeat
creation, crash/partial stages, actual activation and exact active-GUID recovery.
Test creation from verified templates separately from the recorded failing GUID,
changed/active/removed plans and safe cleanup refusal. Verify current GUI/mode
interactions, hardware/edition/policy availability and meaningful workload/power
effects without promising performance gains. Menu acceptance includes modern/
classic visibility, scope, missing/moved runner, quoting, stale GUIDs and bounded
recovery. No host power or menu mutation occurred here. This design remains
proposed; implementation, feature evidence and Server coverage remain pending,
with the legacy outcome still partial and migration estimates unchanged.

### Accepted power-plan separation decision, 2026-10-11

The user accepted separate existing-plan selection, explicit advanced owned
plan-copy creation, and optional desktop Power plans access initially opening
native Power Options. Retain published selection states and saved active-GUID
recovery. Ultimate Performance remains conditional because the recorded VM could
query its legacy GUID but could not activate it; duplication is a separate
untested scenario. Never silently create, activate, fall back or match English
names. Creation requires machine/admin scope, recorded destination ownership and
bounded recovery of only an unchanged owned inactive copy after usable selection
recovery. Verify intended-user menu scope separately; future quick selection
must use maintained capture/recovery. Implementation, hardware/edition/GUI and
Server acceptance remain pending. No migration-estimate adjustment is recorded.

### Remaining telemetry mirrors and CEIP review, 2026-10-11

Propose two separate advanced conditional controls: Windows Customer Experience
Improvement Program participation (policy), and App-V Customer Experience
Improvement Program participation (policy). Keep the native/Wow6432Node
AllowTelemetry copies deferred and absent from recommended profiles. Preserve
the accepted Reduce optional diagnostics guidance and existing diagnostic-data
policy ID; these additional controls do not constitute a universal telemetry-off
switch or independent proof that every legacy bundle component was migrated.

For Windows CEIP, Microsoft's [exact policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm#ceipenable)
identifies Turn off Windows Customer Experience Improvement Program at Computer
Configuration > Administrative Templates > System > Internet Communication
Management > Internet Communication settings, with `SQMClient\Windows` CEIPEnable.
Enabling the negatively named policy opts out all users; disabling opts them in.
The local ICM.admx read-only inspection agrees: Machine class, enabled value 0,
disabled value 1. Use Opted out=0, Opted in=1 and Not configured=override removal,
showing the Group Policy inversion. Legacy EnableTelemetry removed this value;
it did not explicitly opt in. Not configured leaves applicable preference/policy
decisions in place, and saved-state restore reinstates the actual prior value,
type or absence rather than assuming either participation state.

This is a whole-device/admin policy, separate from Settings > Privacy & security >
Diagnostics & feedback. The CSP lists Windows 11 Pro, Enterprise, Education
and IoT Enterprise; this is not evidence of a current collection mechanism on
every listed build, local Home support or Server acceptance. Its older Problem
Reports and Solutions GUI wording must not be presented as a verified Windows 11
checkbox. No RIDE membership, Microsoft account, domain join or Intune enrollment
is proposed for local policy configuration. Show edition/build applicability,
managed conflicts and current collection limitations before offering the control.

For App-V, prefer the actual Computer Configuration > Administrative Templates >
System > App-V > CEIP policy, Microsoft Customer Experience Improvement Program
(CEIP). Local appv.admx/adml read-only inspection identifies Machine class,
`SOFTWARE\Policies\Microsoft\AppV\CEIP` CEIPEnable, Enabled=1 and Disabled=0.
This policy has the opposite wording/value orientation to Windows' Turn off
policy. Proposed Opted out=0, Opted in=1 and Not configured=override removal must
identify the App-V client specifically. Legacy reversal removed its policy
override; opt-in and removal are distinct. A policy write is not proof that an
installed client consumed it or transmitted/stopped data.

Microsoft's [App-V cmdlet reference](https://learn.microsoft.com/en-us/powershell/module/appvclient/set-appvclientconfiguration?view=windowsserver2025-ps#-experienceimprovementoptin)
documents ExperienceImprovementOptIn and refusal to change Group Policy-owned
configuration. Its described policy root differs from the inspected template;
the [App-V 5.1 configuration reference](https://learn.microsoft.com/en-us/microsoft-desktop-optimization-pack/appv-v5/about-client-configuration-settings51)
documents a non-policy CEIPEnable location. Neither proves the complete current
policy-to-client mapping or precedence. Keep policy enforcement distinct from
native client preference; do not silently replace the legacy policy with an
opt-in cmdlet, write both stores or replay unrelated client configuration.
Prefer native focused inspection for effective configuration where available,
with exact policy-value capture/recovery and managed-source conflict reporting.

Require a relevant installed/enabled App-V client and verified edition/build.
Microsoft's [supported configurations](https://learn.microsoft.com/en-us/microsoft-desktop-optimization-pack/app-v/appv-supported-configurations)
identify the Windows Enterprise/Education in-box client and Windows Server 2016
Standard/Datacenter RDS client; do not infer every newer Server or other edition
from that historical list. Explain the existing OS/client licensing requirement
separately from local admin rights. No extra RIDE membership/cloud account is
proposed for changing local CEIP participation. An absent/disabled client yields
not applicable, not successful privacy enforcement; do not enable App-V, deploy
servers, publish applications or acquire licenses to make this setting applicable.

Correct the earlier server-retirement implication in the telemetry reconciliation:
the [App-V support policy](https://learn.microsoft.com/en-us/microsoft-desktop-optimization-pack/app-v/appv-support-policy),
updated October 6, 2026, now states server extended support through October 9,
2029 and client/sequencer support follows their Windows version. Older broad
retirement statements are not grounds to discard this client outcome. This
support update still does not establish current CEIP collection or backend use.

For the extra AllowTelemetry locations, legacy DisableTelemetry wrote 0 to both
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection` and its
Wow6432Node counterpart. EnableTelemetry wrote 3 there while removing the
official policy. Microsoft's [diagnostic policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#allowtelemetry)
maps the policy to `SOFTWARE\Policies\Microsoft\Windows\DataCollection` and
describes the Settings relationship; it does not document these two extra
locations as independently useful current controls. Retain the existing machine
policy and native GUI guidance. Do not invent separate privacy labels, copy old
0/3 writes, delete pre-existing copies, normalize views or describe 3 as a Windows
default. This is deferral, not accepted retirement or demonstrated redundancy.

Acceptance needs disposable Windows 11 and applicable declared Server targets:
actual CEIP consumers, current policy/GUI names, edition/client availability,
opposite Group Policy wording, local versus managed precedence, both explicit
participation states and override removal, repeat apply and exact typed restore.
Test App-V policy versus client preference and unrelated reporting separately;
absence of network activity alone does not prove opt-out. Evaluate native and
32-bit diagnostic copies against policy and GUI transitions before considering
any maintained mapping. Do not invoke collectors or change privacy settings on
the workstation. Retain the accepted compatibility-collector dependency guidance,
required diagnostic data limits and separate Office/task coverage. Restore cannot
recall information already sent. Proposed design, implementation and feature
evidence remain open; the telemetry bundle stays partial and estimates unchanged.

### Accepted remaining CEIP and telemetry-mirror decision, 2026-10-11

The user accepted separate advanced machine/admin Windows CEIP participation
and conditional App-V client CEIP participation policies, matching actual Group
Policy names and showing their opposite Enabled wording. Opt-in, opt-out,
Not configured and exact prior-state recovery remain distinct. Show OS/client
edition and licensing requirements; do not enable App-V or require a RIDE
membership/cloud account to change local participation. Retain the current App-V
support-policy correction and pending client-consumption/precedence evidence.
Native/Wow6432Node AllowTelemetry copies stay deferred, unexposed and untouched
until their independent current effect is established. This accepts design,
not implementation, feature behavior, Server coverage or retirement. The legacy
telemetry bundle remains partial and migration estimates are unchanged.

### Windows CEIP candidate implementation, 2026-10-13

The accepted Windows participation policy now has one pending scalar registry
record, separate from App-V and diagnostic-data controls. OptedOut=0 corresponds
to enabling the negatively named policy; OptedIn=1 corresponds to disabling it.
WindowsDefault removes the override, preserving the legacy reverse distinction
and generic typed saved recovery. Read-only local ICM.admx inspection confirms
the mapping; the [CEIP guide](../ceip-policies.md) records source hash and references.

Current CEIP consumers, managed effective-policy/source, editions/GUI and Server
acceptance remain unverified. The record is experimental, has empty supported
targets and is excluded from recommended profiles; no collection guarantee is
claimed. App-V requires its own relevant installed/enabled-client and consumption
evidence, so it remains deferred. Native/Wow6432Node AllowTelemetry mirrors are
untouched. No host privacy change, collector, package acquisition or VM test is
run here. The telemetry outcome remains partial; all estimates stay unchanged.
The migration-plan entry records local checks, and the manual VM-confirmation
hold continues to apply.

### Feedback frequency GUI and coordinated-state follow-up, 2026-10-11

Retain the already accepted single Feedback frequency control. Propose a
current-user/no-admin preference matching Settings > Privacy & security >
Diagnostics & feedback > Feedback frequency, with only choices verified on the
affected Windows build. Microsoft's [current user guide](https://support.microsoft.com/en-us/windows/privacy/diagnostics-feedback-and-privacy-in-windows)
documents this Windows 11 location and its purpose: how often Windows asks for
user feedback. It does not establish a complete current dropdown or registry
payload. This choice does not change diagnostic-data level or prevent voluntary
Feedback Hub submissions. No RIDE membership or additional cloud account/license
is proposed for the local preference; sending feedback through an app is separate.

Microsoft's [registry mapping reference](https://learn.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services)
documents two values under `HKCU\Software\Microsoft\Siuf\Rules`. Treat its entries
as acceptance candidates, not ready-to-apply payloads:

| GUI candidate | PeriodInNanoSeconds | NumberOfSIUFInPeriod |
| --- | --- | --- |
| Automatically | Remove value | Remove value |
| Never | 0 | 0 |
| Always | 100000000 | Remove value |
| Once a day | 864000000000 | 1 |
| Once a week | 6048000000000 | 1 |

The source labels both values REG_DWORD. Its daily/weekly values exceed the
unsigned DWORD maximum of 4294967295. Neither the value name nor these numbers
establishes the actual time unit. Do not truncate, reinterpret signed values,
guess QWORD, silently convert units or infer a payload from a tweak website.
Observe actual GUI transitions and typed registry state in disposable targets
before assigning supported values/types, including Never and Automatically.
Keep unsupported or absent choices unavailable rather than importing an older
five-choice UI into every current edition/build or Server installation.

Legacy DisableFeedback wrote only the count as DWORD 0, then separately set
machine notification policy and disabled two tasks. EnableFeedback removed only
the count and that policy, then enabled the tasks. It never reconciled the period.
Preserve the whole-bundle intent through the accepted guidance, but do not call
this one-value reversal equivalent to a complete GUI Automatically transition.
There is no maintained frequency operation yet; do not repurpose the published
notification-policy or task IDs as a user preference or expose two raw controls.

Explicit Automatically selects a verified GUI state; Remove override removes
the two maintained preference values. The documented candidates share removal,
but equality on current targets needs verification before treating them as
aliases. Saved-run Restore is a third workflow: reinstate both exact prior
values, types and independent absence, including count-only, period-only,
mixed/custom or unexpected states. Do not normalize an unusual snapshot to
Automatically or Never. Show literal state and interpreted/effective behavior
separately, and do not substitute a RIDE baseline for a measured Windows default.

Use one focused coordinated handler if automation is accepted. Capture both
values before either mutation, validate the entire requested state first and
present both changes in preview. Record per-value progress/failure and recover
the captured pair after partial failure; do not claim a registry transaction.
Modify only these owned values, preserve unrelated Rules data, and define safe
handling of a newly created empty key rather than recursive subtree deletion.
Run in the intended user's context without elevation or writes into another
user's hive. No automatic sign-out, reboot, task execution or forced feedback
prompt to refresh or demonstrate the setting.

Keep the existing whole-device/admin [Do not show feedback notifications policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience#donotshowfeedbacknotifications)
separate. It can prevent requests; disabling/removing it permits user control
without guaranteeing a prompt. Inspect and report a managed/disabled GUI and
controlling policy when known; do not bypass enforcement or clear policy merely
to make a chosen frequency effective. Show the supported policy edition/build
requirements separately from the user preference. Existing DmClient tasks remain
independent advanced controls; enabling requests does not recreate missing tasks,
force their execution, reinstall Feedback Hub or change diagnostic collection.

Until the complete mapping is accepted, provide native Settings guidance as an
interim option. Report that as a user action awaiting completion, not an applied
captured RIDE setting. Recovery of a choice made manually there is also a user
action unless a maintained capture/recovery workflow was explicitly used.
Retain Stop automatic feedback requests guidance: explain current-user Never
versus the applicable machine policy for all users and any managed restrictions.
Do not silently select the machine policy or disable both tasks when a user asks
only to change their preference.

Acceptance needs disposable Windows 11 targets covering supported editions,
current dropdown names, localized presentation, every supported transition,
GUI readback/refresh, actual value kinds/units, both-absent and mixed/custom
states, repeat apply, partial writes and exact paired recovery. Distinguish
configured frequency from effective policy suppression and natural prompt
availability; a quiet session alone is not feature evidence. Check representative
Server/Desktop Experience availability separately; an unavailable GUI does not
prove a supported headless registry mapping. No host preference or policy was
changed. This follow-up remains proposed, with automation and feature evidence
pending; the feedback bundle stays partial and estimates unchanged.

### Accepted feedback-frequency refinement, 2026-10-11

The user accepted one GUI-aligned current-user/no-admin Feedback frequency
preference coordinating both values, with only current-build verified choices.
Resolve the documented DWORD/large-period and unit inconsistency before enabling
automation; use native Settings guidance meanwhile without reporting captured
apply success. Explicit Automatically, override removal and exact typed paired
restore remain distinct until equivalence is verified. Preserve mixed/custom
prior states and report partial recovery. The whole-device/admin notification
policy and advanced tasks remain separate, with managed restrictions visible.
Implementation, GUI/type/unit and Server acceptance remain pending; the feedback
bundle stays partial and migration estimates are unchanged.

### Windows RE enablement and recovery-registration follow-up, 2026-10-11

Retain the accepted separation of Windows Recovery Environment enablement from
automatic boot-recovery policy and crash restart. Propose Windows Recovery
Environment (Windows RE) with normal Enable and advanced Disable, both explicitly
whole-device/admin changes for the running Windows installation. Do not call
Disable a security preset or Disable all recovery and factory reset. The legacy
DisableRecoveryAndReset/EnableRecoveryAndReset selectors simply ran reagentc
/disable or /enable, suppressed output and did not capture registration or
verify results. Preserve their local recovery-enablement outcome without copying
those lifecycle omissions or overstating the scope.

Relate this control to Settings > System > Recovery > Advanced startup, but
explain that Restart now enters recovery; it is not an enablement toggle. The
[Windows RE reference](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-recovery-environment--windows-re--technical-reference?view=windows-11)
documents Windows 11 entry through that area and external recovery media, desktop
push-button reset versus Server image recovery, and encrypted-volume key needs.
Disabling the local registered image does not establish that external recovery,
OEM recovery or every reset/reinstallation route is blocked. Keep Enter recovery,
Reset this PC, recovery media creation and newer online recovery services as
separate explicit workflows. No automatic reboot or next-boot recovery request.

Microsoft's [REAgentC reference](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11)
documents /info inspection, /enable, /disable and separate image-location
registration. Enable may attempt the default image when none is specified.
The maintained design must verify the intended usable image/location before
calling it; do not allow a guessed fallback to select another installation's
image. Initial scope is the running OS only, without an offline /target,
Windows PE /osguid or audit-mode override. Recognize these unsupported contexts
and decline mutation rather than silently extend the target.

Inspection must distinguish Enabled, Disabled, image missing/unavailable and
Unknown or inconsistent registration. Unknown is not Disabled. Obtain reliable
localized native state and concrete OS/boot-entry identity, image location and
stable volume/partition identity before changing anything. Do not parse English
Enabled text alone or treat a native exit code as feature proof. Structured
configuration may corroborate discovery, but do not assume private XML is a
supported writable API or edit it to force apparent success. A disabled system
may lack a displayed registered location; capture the relevant staged image and
registration information or report recovery prerequisites unresolved.

Capture a versioned pre-change registration snapshot and per-stage progress.
Preserve existing custom image/OEM configuration, unrelated BCD entries and the
actual OS target. An already satisfied state is a no-op: do not disable/re-enable
an enabled image to refresh it. After native mutation, verify registration and
the expected image association independently, recording partial failures even
when one native step reports success. Explain any tool-managed file relocation
or BCD change discovered in acceptance rather than describing this as a scalar
registry preference.

Recovery must aim to reinstate the captured prior enablement and supported image
association through native facilities. Replaying only the opposite command is
insufficient. Resolve changed/missing disks, image locations, OS identities and
custom registration before compensation; do not guess drive numbers or restore
a whole BCD store. Do not label recovery Exact until the actual registration,
image movement, generated boot identifiers and failure cases establish what can
be restored. If exact physical restoration is unavailable, declare the bounded
configuration recovery and remaining manual steps before implementation, with
an appropriate recovery reference and report semantics.

Windows servicing can replace the image or change its recovery partition; keep
this conflict visible. Restoring a RIDE setting must not overwrite a newer image
with an older snapshot, undo security servicing or silently redirect registration
after partition changes. Image repair/update and partition work remain separate
reviewed workflows. Microsoft's [Windows RE servicing guide](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre?view=windows-11)
also demonstrates image-staging checks and error handling around disable/enable.
It is evidence of a richer lifecycle, not authorization to import its repartition
script into a toggle. Do not acquire/delete images, resize/delete partitions,
change ACLs, reset the OS or suspend BitLocker/Secure Boot to make the toggle work.

Require a known registration/image state before Enable and a documented usable
independent recovery route before advanced Disable. The accepted Prepare Windows
recovery guide should expose backups, recovery media and independently accessible
BitLocker recovery information where applicable. Do not store recovery secrets
in normal snapshots/logs or impose a paid RIDE membership. Built-in local Windows
RE has no proposed additional subscription/account requirement; individual tools
can have credentials, key or network requirements which must be shown separately.
An Enabled registration is not proof the image boots or the recovery tools work.

Acceptance requires disposable Windows 11 and each proposed Server target:
localized discovery, clean/OEM/custom images, initially enabled/disabled/missing
states, native failures, repeat apply, staged-image relocation, registration/BCD
capture, changed boot entries/partitions, servicing conflicts and bounded recovery.
Verify nondestructive manual entry and return to Windows separately, including
encrypted-volume access with a retained external route and VM checkpoint. Do not
test reset or repair automatically. Server image recovery and Desktop Experience/
Core behavior need their own applicability evidence; the documented platform
presence alone does not add catalog support. No host REAgentC, BCD, image, partition
or reboot action was performed. This refinement remains proposed; implementation
and functional recovery evidence remain deferred, and migration estimates stay
unchanged because the omitted Windows RE outcome is not yet closed.

### Accepted Windows RE lifecycle refinement, 2026-10-11

The user accepted normal Enable and advanced Disable for Windows RE, separately
from boot-failure recovery policy, crash restart and entering recovery. Both
changes are machine/admin operations for the running OS. Require reliable
localized inspection and image/registration/OS/partition capture; preserve custom
configuration and report staged failures. Restore the supported prior association
and enablement rather than merely replaying the opposite command. Do not claim
Exact without lifecycle evidence or undo newer image servicing. Keep independent
recovery-route prerequisites, encrypted-volume access and recovery-readiness
guidance visible. No implicit partition/image repair, protection suspension or
reboot. Implementation, recovery behavior and Server applicability remain pending;
the omitted Windows RE outcome stays partial and estimates are unchanged.

### Legacy Computer Browser visibility disposition, 2026-10-11

Propose retiring DisableBrowserSvcView/EnableBrowserServiceView from the new
catalog's migration candidates for maintained Windows targets. Preserve their
historical source and record the disposition explicitly; no maintained operation
ID exists for this Hidden override, so no published-ID retirement or saved-run
schema change is proposed. Modern network discovery is a separately understood
outcome, not a renamed equivalent or automatic replacement of this registry tweak.

Legacy DisableBrowserSvcView writes DWORD Hidden=1 under
`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` to suppress old
browse announcements. EnableBrowserServiceView removes the value; it does not
write an explicit Visible=0 state or restore captured prior data. Its printed
administrative-shares message is unrelated to its actual mutation. Neither
selector changes the Browser service startup mode or administrative-share
AutoShare values. Treat this as a historical whole-device/admin server visibility
preference, not a current-user Explorer presentation preference.

Microsoft's [archived registry guidance](https://learn.microsoft.com/fr-fr/security-updates/security/20141711)
documents Hidden under that LanmanServer path for suppressing browse-list
announcements. The accessible reference is French, dated 2005 and scoped to
older Windows security templates; summarize its meaning in English without
presenting its historical default or custom MSS editor entry as current Windows
11/Server GUI support. The English page could not be retrieved in this review.
The [server-information API reference](https://learn.microsoft.com/en-us/windows/desktop/api/lmserver/ns-lmserver-server_info_102)
also documents a hidden/visible server property. API existence and minimum-OS
requirements do not establish this exact registry value's effect on current
Explorer discovery or justify a new API handler without applicable peer evidence.

Microsoft's [current SMB1 guidance](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
states that Computer Browser relies on SMB1 and is removed with it. Clean Windows
11 and Windows Server 2019 and later lack SMB1 by default. It describes modern
Explorer discovery using Function Discovery/WS-Discovery instead. This supports
retiring the old migration outcome from the maintained catalog, not claiming
every upgraded/OEM/Server installation lacks the service or that Hidden has no
effect anywhere. A specifically requested supported legacy compatibility target
would require a separate scope decision and real browse-announcement/peer tests.
Never install SMB1 or resurrect Browser merely to make this candidate applicable.

Do not label Hidden as Hide this PC from the network, Disable network discovery,
Disable SMB sharing or a complete security measure. Omission from a browse list
does not establish that direct-name/IP share access, DNS, other discovery methods
or remote administration are blocked. Preserve the accepted Secure Windows file
sharing and Stop hosting SMB shares guidance, including authentication, share
permissions, protocol/binding scope, firewall and signing/encryption gaps. Hiding
a UI Network node is another independent presentation outcome.

For present-day discoverability, propose native guidance for Manage advanced
sharing settings > the applicable network profile > Network discovery, verifying
the current GUI/profile mapping rather than adding another raw Hidden control.
Microsoft's [Windows sharing guide](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/file-sharing-over-a-network-in-windows)
identifies the Private networks Network discovery choice. Show discovery and
File and printer sharing separately even where an Explorer prompt combines them.
Do not copy its broad troubleshooting sequence into a security recipe or silently
disable password-protected sharing, change network category, open firewall rules,
start unrelated services or enable UPnP. Direct or mapped authenticated share
access may be useful without Explorer browsing; the intended outcome decides.

Any future automated modern discovery operation must declare its actual
machine/network-profile scope, admin needs, service/firewall dependencies,
managed precedence, independent states and saved recovery. Do not infer physical
scope from where the GUI appears or use current-user wording for a machine change.
No extra RIDE membership/cloud subscription is proposed for native local discovery;
domain classification and access credentials are separate prerequisites. Initial
guidance is a manual action, not captured apply success. Windows 11 and each
declared Server/Core target need independent GUI/backend and peer acceptance
before automation or a recommended discoverability profile is added.

Retirement does not clean up existing Hidden values. Leave host and pre-existing
configuration untouched; a future explicit cleanup would need typed prior-state
capture, managed-source checks, current effect evidence and its own recovery.
No catalog/profile/service/firewall or host changes occurred in this review.
The paired selectors count as one legacy outcome: record that one disposition
and review all rounded estimate groups after user acceptance. Until accepted,
the Browser visibility outcome remains open and migration estimates unchanged;
modern discovery guidance/automation is separate follow-up, not proof of an
equivalent migrated control.

### Accepted Computer Browser visibility retirement, 2026-10-11

The user accepted retirement of DisableBrowserSvcView/EnableBrowserServiceView
from maintained catalog migration candidates, preserving historical source and
pre-existing Hidden values. Retain modern Network discovery as separate native
GUI guidance with actual profile/scope and future feature evidence; do not call
it an equivalent migration, network invisibility or blocked share access.
No legacy service/SMB1 installation or automatic cleanup is authorized by this
disposition. One paired legacy outcome is resolved by retirement. All five
rounded migration groups were reviewed and remain unchanged, including settings
40-60 and total 160-215/about 190; the dated plan records this adjustment.
Other accepted designs still awaiting implementation/acceptance remain counted.

### Windows Update executable interception and supported outcomes review, 2026-10-11

Propose retiring the MusNotification.exe IFEO debugger interception while
retaining the user's interruption-management intent through supported controls
and guidance. This is a replacement design, not a claim that a notification
policy implements Disable automatic restart. The legacy function name and its
comment encompass both notifications and restart scheduling; reconcile these
different outcomes explicitly before closing the migration candidate.

Legacy DisableUpdateRestart writes String Debugger=cmd.exe under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe`.
EnableUpdateRestart removes that value without capturing a prior debugger.
Blocking one executable is not a supported contract preventing all Windows
Update restarts. Do not reproduce IFEO interception, rename/deny execution of
Windows components, modify services/tasks or claim the reverse selector enables
every automatic-restart path. Preserve source history; no published catalog ID
exists for this override. Leave existing debugger values untouched: unrelated
debugging configurations must not be deleted by applying a modern policy.

For notifications, propose one advanced machine/admin Windows Update notification
display policy matching Group Policy Display options for update notifications:

| Policy choice | User-facing effect |
| --- | --- |
| Default notifications | Use Windows' normal notification behavior |
| Keep restart warnings | Suppress other update notifications, retain restart warnings |
| Hide notifications including restart warnings | Advanced choice for explicitly reviewed unattended/kiosk scenarios |
| Not configured | Remove the maintained local policy override; effective behavior follows other policy/preferences |

Microsoft's [UpdateNotificationLevel reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#updatenotificationlevel)
documents levels 0/1/2 and distinguishes notification display from download and
installation. Its CSP applicability lists Pro, Enterprise, Education and IoT
Enterprise. Match the actual Computer Configuration > Administrative Templates >
Windows Components > Windows Update > Manage end user experience policy, not the
personal Settings restart-notification switch. Show supported build/edition and
whole-device scope. No RIDE membership, domain join or Intune subscription is
proposed for local policy use; managed deployments can impose their own policy.

Treat the policy enable gate, notification choice and optional Apply only during
active hours checkbox as one coordinated feature. Read-only local WindowsUpdate.admx
inspection identifies Machine class at SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:
SetUpdateNotificationLevel is the policy gate (Enabled=1, Disabled=0),
UpdateNotificationLevel is the enum (0/1/2), and NoUpdateNotificationsDuringActiveHours
is the checkbox. The CSP page's mapping names the gate, not the complete local
payload. Do not write a level into the gate or expose three indistinguishable
registry toggles. Verify numeric/type and Not configured/Disabled behavior against
current Group Policy before implementation. Policy Disabled, explicit Default
notifications and removal have different literal states and recovery semantics.

Offer the checkbox only on accepted builds; the [restart guide](https://learn.microsoft.com/en-us/windows/deployment/update/waas-restart)
dates it to Windows 11 22H2 and documents deadline-related notification exceptions.
It limits when suppression applies, not the active-hours schedule itself. Changing
notification display must not overwrite a user's active hours or compliance
deadlines. Default notifications remain the recommended normal experience;
suppression including restart warnings is not a general desktop/security preset.
Neither a hidden toast nor absence of a prompt proves that restarts are blocked.

For the original restart intent, propose Reduce Windows Update interruptions
guidance using native active hours, explicit restart scheduling and inspection of
applicable deadline/grace policies. The [active-hours guide](https://support.microsoft.com/en-us/windows/deployment/updates-lifecycle/keep-your-pc-up-to-date-with-active-hours)
identifies Settings > Windows Update > Advanced options > Active hours. Preserve
the existing windows.update-download-mode ID and states; AUOptions/download
choices are not universal restart prevention. Do not silently change them,
disable updates, extend deadlines or configure an endless no-reboot promise.
Future automated restart scheduling/policy needs separate lifecycle and acceptance.

Keep Notify me when a restart is required to finish updating as a separate native
user choice. Microsoft's [current update policy guide](https://learn.microsoft.com/en-us/windows/deployment/update/waas-wufb-csp-mdm#end-user-settings-for-notifications)
documents that choice under Settings > Windows Update > Advanced options as
end-user controlled. Off can still allow automatic restart outside active hours;
On provides advance notice and a limited preparation period on applicable builds.
Deadlines can change these effects. Do not model it as a machine enforcement
switch, guess its physical registry scope or add an undocumented value. Native
handoff remains a user action, not captured RIDE apply/restore success.

Avoid importing obsolete restart policies wholesale. The restart guide marks
several old notification/schedule policies inapplicable to Windows 11 and
qualifies No auto-restart with logged on users by scheduled-update configuration
and active session behavior. Server maintenance/reboot coordination is a separate
scenario with explicit installation mode and maintenance-window prerequisites;
do not infer its solution from a desktop notification mode or claim Server
support from the locally installed ADMX supportedOn label alone.

Capture all maintained notification policy values, types and independent absence
before any write; preview the complete chosen state and preserve mixed/custom
snapshots and unrelated update policy. Report managed conflicts and per-stage
partial failure, and restore the exact captured local values rather than copy
an effective organization policy into local configuration. No update scan,
download, installation, task run, policy-refresh restart or imminent-reboot probe
is an implicit side effect. Configuration restore cannot undo an update/reboot
that occurred meanwhile. Existing IFEO interception, if identified read-only,
is a separate reported conflict; cleanup would need explicit scoped authorization,
prior-value recovery and evidence, not wholesale key deletion.

Acceptance needs disposable Windows 11 builds/editions and each proposed Server
target: Group Policy payload/GUI states, gate/enum/checkbox coordination, mixed
typed restore, repeat apply, managed precedence, pending-restart notifications,
active-hours/deadline exceptions and actual reboot behavior under explicit lab
scenarios. Keep suitable checkpoints and protect workload state. Verify user
preference separately from machine policy; do not use quiet sessions as proof.
No host update, debugger or reboot changes occurred. This design remains proposed;
the unsupported technique's retirement and supported replacement acceptance are
distinct. The original interruption-management outcome stays partial and counted
until its approved retained scope/guidance and applicable feature evidence are
resolved; no additional estimate reduction is recorded here.

### Accepted Windows Update replacement design, 2026-10-11

The user accepted retirement of the MusNotification.exe debugger interception
and separate supported notification/restart outcomes. Add one advanced
machine/admin Group Policy-aligned notification display feature coordinating
its gate, enum and supported active-hours checkbox, with Default notifications,
Keep restart warnings, advanced suppression including restart warnings and
Not configured clearly distinguished. Preserve exact typed local recovery and
report effective managed-policy conflicts. Keep the personal restart-notification
GUI preference separate, without an undocumented machine override.

Retain Reduce Windows Update interruptions guidance for active hours, explicit
restart scheduling and deadline/grace requirements. Silencing notifications does
not prevent restarts; no universal no-reboot guarantee, implicit AUOptions rewrite,
component interception or automatic cleanup of existing debugger values. This
accepts the replacement design, not feature acceptance or completed parity with
the legacy restart claim. Implementation and Windows 11/Server notification/reboot
evidence remain pending. The retained interruption-management outcome stays
partial and counted; no further migration-estimate adjustment is made.

### Update notification candidate implementation, 2026-10-13

The accepted display-policy design is implemented as one pending RegistryValueSet
candidate with gate, enum and active-hours checkbox. Local read-only ADMX/ADML
inspection confirms identities and gate/enum payload; Microsoft documents the
checkbox 0/1 and minimum Windows 11 22H2 applicability. Candidate states distinguish
explicit default, restart-warning preservation, advanced suppression, active-hours
variants, gate-disabled with subordinate removal, and all-value override removal.
PolicyDisabled's cleanup is declared RIDE behavior; editor normalization remains
acceptance work. Supported targets are empty and a minimum-build guard is retained.

Complete typed snapshots precede writes and reverse-order recovery preserves
mixed/custom values. A separate legacy Debugger read-only observation is excluded
from mutation/recovery; interception cleanup is not authorized here. No AUOptions,
scan/update/reboot/task change is made. The [guide](../update-notifications.md)
documents source evidence and supported native interruption guidance. Effective
managed policy/source, GUI/notification/reboot behavior and Server applicability
remain pending; the original retained outcome remains partial, with estimates
unchanged. Local validation is recorded in the migration-plan entry. All VM tests
remain held until manual user confirmation; none is started/scheduled here.

### Remaining-settings design checkpoint and implementation handoff, 2026-10-11

The identified outcomes in the remaining-settings decision table now have user
accepted designs or retirement dispositions. This closes the initial chat design
pass for that table, not all behavioral issues in this document or the settings
migration. Preserve prior evidence gaps and decisions throughout implementation;
do not convert an accepted design into a passed GUI or lifecycle result.

The separate User .NET assemblies label remains a provenance issue with no
identified source outcome. Retain the bounded source audit and resolve by real
source identification, an evidenced duplicate or an explicit agreed bookkeeping
correction. It neither blocks identified work nor authorizes a guessed setting,
additional phantom component count or retirement claim.

Use the [implementation and acceptance queue](remaining-settings-decisions.md#implementation-and-acceptance-queue)
as the next work order. Start with consistent scope/enforcement/prerequisite
presentation and complete-outcome guidance, then implement focused compatible
controls with their approved recovery boundaries. Investigate uncertain GUI/value
mappings before making executable replacements available. Keep new profiles
conditional on verified components and expose manual or deferred prerequisites.

Maintain distinct ledger states for accepted design, implementation delivered,
lifecycle evidence, actual GUI/feature evidence, unavailable/deferred target and
accepted retirement. Refresh dated group estimates after actual migration batches
using legacy outcomes, with adjustment reasons; additional IDs, design acceptance
and registry round trips are not additional completed feature outcomes.

The final walkthrough requested after the last setting remains pending. Once
retained scope is implemented or its approved replacement/retirement is delivered,
walk through outstanding semantic, recovery and target-evidence issues together,
including numeric suggestion channels, Cortana-derived personalization, unknown
provenance, security outcome composition and partial legacy bundles. Agreement on
a replacement proposal alone does not establish that milestone. This checkpoint
changes documentation only; no host changes, new runtime tests or implementation
claims are made.

### Shared registry capture/error-reporting repair, 2026-10-13

Migration implementation review corrected a shared lifecycle gap: silent registry
reads could turn denied access into apparent absence, while provider mutations
and empty-key cleanup could return despite nonterminating errors. Module 0.3.0
distinguishes actual missing keys, propagates read/write failures and returns
KeyExisted with raw value/type. Value-set capture 0.2.1 and engine 0.17.1 reuse it,
with older reader/snapshot compatibility retained. Genuine absent-value removal
is idempotent; mixed typed recovery and unrelated-data preservation remain in force.

Focused mocked evidence and adjusted post-apply recovery fixtures are recorded in
the migration-plan entry. No live registry, VM, package or controller change runs.
This improves implementation safety/reporting without closing a legacy outcome
or establishing GUI/target acceptance; manual VM confirmation remains required.

## Review of other existing splits

The source review matched literal registry paths and values across the maintained
catalog and legacy function ASTs without importing or executing the legacy
module, then inspected the additional service, background-app and registry-tree
operations. These sixteen registry split families include both reverse selectors;
the following table records an explicit decision for each. It evaluates the
choice to split, not new proof of every feature's Windows integration acceptance.

| Legacy family | Current operations / boundary | Evaluation and remaining work |
| --- | --- | --- |
| DisableTelemetry / EnableTelemetry | `windows.diagnostic-data-policy`, `windows.linguistic-data-collection-policy` | User accepted separate diagnostic level and recognition-data sharing controls, with the latter named Send inking and typing samples to Microsoft. Clarify machine/per-user precedence. Partial legacy coverage; no promise of zero telemetry, task changes or Office controls. Off depends on edition. |
| DisableCortana / EnableCortana | Three preferences in the preceding section | User selected one combined Inking and typing personalization control, pending mapping and feature acceptance. Existing IDs remain experimental; reject Cortana enablement terminology and keep unverified contact learning out. |
| DisableAppSuggestions / EnableAppSuggestions | Fifteen preferences in the preceding table | Experimental; numbered channels unresolved. Defer a user-facing bundle until feature evidence exists. |
| DisableActivityHistory / EnableActivityHistory | `windows.activity-history-feed-policy`, `windows.activity-history-publish-policy`, `windows.activity-history-upload-policy` | User accepted legacy advanced controls with stable IDs and recovery, excluded from recommended composition on current builds pending feature evidence. Any combined replacement requires active behavior on its targets; do not present three verified independent privacy benefits. |
| DisableLocation / EnableLocation | `windows.location-service-policy`, `windows.location-scripting-policy` | User accepted location services as the normal control and location scripting as a separate advanced control pending current behavior evidence. Clarify dependencies, side effects and override-removal states; retain IDs and recovery. |
| DisableUWPVoiceActivation / EnableUWPVoiceActivation | `windows.uwp-voice-activation`, `windows.uwp-voice-activation-above-lock` | User accepted two separate normal controls, with clearer override-removal wording and the general/locked dependency explained. Retain IDs and states; feature acceptance remains outstanding. |
| DisableUWPFileSystem / EnableUWPFileSystem | `windows.uwp-documents-library-access`, `windows.uwp-pictures-library-access`, `windows.uwp-videos-library-access`, `windows.uwp-broad-file-system-access-access` | User accepted four separate controls with clearer names and individual scope descriptions, excluded from recommended profiles until feature behavior is verified. Review machine/per-app consent, broad-access overlap and alternative access routes; no universal filesystem block claim. |
| DisableAdminShares / EnableAdminShares | `windows.admin-share-server`, `windows.admin-share-workstation` | User accepted platform-specific IDs with only the applicable choice in normal target-specific views, named Automatic administrative shares. Disabling remains opt-in; explain restart, remote-management impact and coverage limits. Workstation feature evidence remains open. |
| EnableDotNetStrongCrypto / DisableDotNetStrongCrypto | `windows.dotnet-strong-crypto-64bit`, `windows.dotnet-strong-crypto-32bit` | User accepted one combined normal .NET Framework 4.x strong cryptography control, retaining architecture-specific IDs for advanced selection and recovery. Correct application-target-dependent defaults and outgoing TLS scope; implementation and feature acceptance remain open. |
| DisableUpdateDriver / EnableUpdateDriver | `windows.update-driver-policy`, `windows.device-metadata-downloads` | User accepted driver inclusion as a normal control and metadata-associated app downloads as a separate advanced legacy option, outside recommended profiles pending current behavior evidence. Device metadata is deprecated; SearchOrderConfig remains deferred and coverage is partial. |
| DisableMaintenanceWakeUp / EnableMaintenanceWakeUp | `windows.maintenance-wake-policy`, `windows.maintenance-wake-timer` | User accepted advanced experimental controls outside recommended profiles and deferred a normal combined control. Resolve reference and local ADMX key/support mismatches, actual wake behavior and hardware/power dependencies; retain IDs and recovery. |
| DisableActionCenter / EnableActionCenter | `windows.action-center-policy`, `windows.toast-notifications-policy` | User accepted separate center visibility and notification delivery controls, with ToastEnabled scope and final name pending verification. Do not assume banners-only behavior; verify restart, sounds, center delivery and per-app interactions. |
| DisableAccessibilityKeys / EnableAccessibilityKeys | `windows.sticky-keys-prompts`, `windows.toggle-keys-prompts`, `windows.filter-keys-prompts` | User accepted three separate shortcut controls preserving feature activation, sounds and other preferences. Verify the registry/API/UI mapping, replace fixed flag presets through a reviewed migration, and preserve IDs and exact recovery. |
| SetTaskbarCombineAlways / WhenFull / Never | `windows.taskbar-combine-primary`, `windows.taskbar-combine-secondary` | User accepted two independent display controls and clear Windows-default versus explicit Always presentation. Preserve existing override-removal semantics and IDs; verify grouping, labels and mixed choices on two displays. |
| ShowSuperHiddenFiles / HideSuperHiddenFiles; ShowHiddenFiles / HideHiddenFiles | `windows.protected-files-visibility`, `windows.hidden-files-visibility` | User accepted separate controls, with protected-file visibility advanced and opt-in. Explain the dependency in plans without changing the other preference; preserve IDs and recovery and verify all UI combinations. Separate legacy preferences, not one selector split. |
| HideRecentShortcuts / ShowRecentShortcuts | `windows.explorer-recent-shortcuts`, `windows.explorer-frequent-shortcuts` | User accepted independent recent-file and frequent-folder visibility controls with clear UI-only scope and default-state wording. Preserve IDs and recovery; verify mixed choices, pins, cloud content and broader recent-items interactions. |

Additional cases that do not appear as multiple scalar registry matches:

- Background apps: `windows.background-apps-policy` and
  `windows.uwp-background-app-user-overrides`: user accepted a normal policy
  control and a separate, opt-in advanced reset. Preserve individual preferences
  when removing policy; verify current reset effects before recommending it.
- `windows.ssdp-discovery-service` and `windows.upnp-device-host-service` are
  separate advanced, opt-in controls by user decision. Explain discovery versus
  hosting, startup versus runtime, and dependencies. Reconcile the UPnP enable
  mismatch and default-profile selection; retain IDs and saved-run recovery.
- The Music, Videos and 3D Objects This PC operations use RegistryKeySet because
  registration keys implement one folder choice. User accepted one operation
  per folder and placement, retaining these and separate shell-policy controls
  as advanced legacy choices pending current effects; keep pins and contents
  distinct and preserve IDs and recovery.
- AC and battery lid actions are independently useful power outcomes. Their
  original migration did not implement a whole power scheme. The later
  windows.active-power-scheme operation selects existing Balanced/High
  Performance schemes separately; creation and Ultimate Performance remain
  deferred. Individual power preferences affect the active scheme, so plan
  ordering and recovery must identify the scheme involved. User accepted
  separate AC/DC controls and separate plan selection, with plan activation
  preceding individual preferences and recovery tied to the changed scheme.

No existing profile is rewritten by this review. Some earlier mappings already
occur in profiles; the further-review dispositions above remain explicit
acceptance work, not an assertion that those settings are functionally approved.

## Sixty-setting batch review, 2026-10-10

The [sixty-setting session](../MIGRATION-PLAN.md#sixty-setting-session-2026-10-10)
records all 60 new IDs, 86 selectors, individual states and omitted scope. This
review adds acceptance work; the earlier review's validation counts describe its
174-operation snapshot, not the expanded catalog.

| Legacy area | Decision | Remaining acceptance |
| --- | --- | --- |
| Native/32-bit folder visibility | Combine architecture mirrors into one operation per folder | Compare Explorer and a 32-bit file dialog on current builds; distinguish This PC registration, Home and pinned shortcuts |
| Control Panel view | User accepted one combined control with Category, Large icons, Small icons and Use Windows default | Open Control Panel in each state; distinguish explicit Categories from legacy override removal and preserve IDs/recovery |
| Mouse precision | User accepted one combined control with explicit legacy preset, Windows-default and saved-restore distinctions | Compare UI and actual acceleration, verify refresh/sign-in, preserve unrelated speed/touchpad settings and recover custom thresholds |
| UAC level | User accepted one combined notification-level control matching all four Windows slider positions, with default third from bottom; override removal stays separate | Add missing levels without redefining existing states, verify slider and both account prompt scenarios on a disposable VM, clarify secure-desktop effects; leave EnableLUA and host consent untouched |
| Fullscreen optimizations | User accepted one advanced experimental legacy control outside recommended profiles; treat fullscreen Compatibility and windowed-game GUI features separately | Verify representative games/builds, GUI mappings, scope and restart; improve reference without claiming it documents the four legacy values |
| Visual effects | User accepted individual GUI-aligned effects and separate timing controls; defer a complete preset and keep taskbar/Peek experimental | Verify GUI mappings, actual effects and refresh; KeyboardDelay is already String, with typed recovery/full slider range pending; keep packed masks deferred and preserve IDs/state meanings |
| Defender cloud and samples | User accepted separate GUI-named controls and four explicit sample choices; make Advanced's license/account/MAPS requirements visible | Verify GUI/effective protection, local-account Windows 11 without Endpoint enrollment, connectivity and policy/tamper limits; do not transmit test files implicitly |
| SmartScreen, search, security icon | User accepted separate GUI-named Shell SmartScreen and focused tray-icon policy; keep web-search policy advanced outside recommended profiles pending current mapping | Replace missing web-search fragment with exact legacy policy reference; verify GUI/results, editions/regions, managed policy and icon sign-in/reboot; preserve IDs and explicit/default states, omit obsolete/startup mutations |
| Hardware clock and network-device setup | User accepted separate advanced experimental preferences outside recommended profiles; use a network GUI name only after mapping verification | Verify RTC/reboot/DST/dual-boot and actual automatic device setup; retain historical clock support concerns, improve network reference and distinguish registry recovery from clock/device side effects |
| Service startup | User accepted separate advanced opt-in service controls with GUI startup choices and runtime actions distinguished; retain existing presets/delay preservation | Add reviewed explicit delayed choices for partial WAP/Search reverse behavior; verify GUI/SCM/reboot, triggers/dependencies, actual workloads, platform defaults and saved-state recovery |
| Sleep button and timeouts | User accepted separate GUI-aligned button/timeout choices with independent AC/DC and reviewed duration/actions; keep menu visibility separate and advanced pending mapping | Add reviewed missing button/duration choices, improve menu reference with path qualification, verify hardware/S3/Modern Standby and real timeout/menu effects; unavailable indexes remain pending |
| BitLocker preferences and memory integrity | User accepted GUI-aligned Memory integrity and advanced GUI-named BitLocker policies, plus guidance for complete security outcomes; preserve partial/legacy IDs and recovery | Verify VBS/driver/restart, preboot/protector/encryption/recovery readiness, legacy encryption precedence, complete policy mapping, scenario/power tradeoffs, edition/account/licensing scope and exact recovery on disposable capable targets |
| Developer Mode and trusted sideloading | User accepted normal GUI-aligned Developer Mode, separate advanced trusted-app preference and a local-development guide; preserve legacy IDs/reverse semantics | Verify current GUI/value combinations, signed deployment, defaults/managed precedence, visible license/account/prerequisites and mixed-state recovery; remote deployment remains separate |
| Media metadata and Xbox controls | User accepted independent Legacy-player metadata/sharing, GUI-aligned Game Mode and verified capture controls, with optional outcome guidance; broad legacy bundles remain partial | Verify installed-player/backend effects, Game Mode's focused mapping and current capture controls; retain recording policy experimental on Windows 11, reconcile reverse states, radio/WMDRM and separate Xbox package lifecycle |
| Automatic boot recovery | User accepted advanced opt-in boot-status recovery suppression, separate Windows RE lifecycle and crash restart, plus complete recovery-readiness guidance | Verify startup/shutdown/checkpoint scope, effective defaults, concrete boot-entry snapshot/recovery, actual automatic/manual recovery and encrypted-volume access; Windows RE implementation remains deferred |

Experimental or behavior-unverified mappings remain outside recommended
profiles. The migration estimate removes resolved implementation scope only;
these behavioral checks remain a separate backlog. No numbered content-channel
mapping from the earlier batch is considered resolved by this session.

### Lifecycle evidence follow-up, 2026-10-10

The focused `SettingsBatch60Recovery` run
`78b3734bfb0e4c179f0dfd7119a7aff1` supplies the twelve previously pending
lifecycle results on Windows 11 Enterprise Evaluation build 26300. The repaired
BCD recovery policy and all eleven coordinated registry settings passed their
36 named states, apply/restore preview, repeat apply and exact prior-state
recovery. All 718 guest Pester tests passed; correlated transcript, XML, summary
and saved state were collected. Clean-checkpoint recovery succeeded, and host
UAC values were unchanged. See the [batch ledger](../MIGRATION-PLAN.md#sixty-setting-session-2026-10-10)
for the evidence path and full validation record.

Confirmed lifecycle acceptance is now 58 of the 60 settings; the VM lacks two
sleep-button indexes. The table's user-visible acceptance remains outstanding:
Explorer/file-dialog behavior, Control Panel appearance, actual acceleration,
game behavior, UAC consent UI and boot-failure/restart scenarios were not tested
by these value/BCD round trips. Experimental mappings keep their existing
disposition and remain outside recommended profiles. No legacy implementation
scope or estimate is subtracted by this evidence-only rerun.

## Completion criteria for subsequent batches

Before declaring a split migrated, record the individual outcome, mapping
evidence, current target relevance, policy/feature dependencies, exact meaning
of reverse and baseline states, and omitted parts of the legacy bundle. Choose
retain, combine, replace with a documented control, defer, or retire. Confirm
feature behavior separately from mocked tests and registry lifecycle acceptance.

For unresolved content channels, use a clean representative Windows 11 VM:
compare registry changes from one UI action at a time; record build, edition and
related preferences; restore the checkpoint; vary each candidate independently;
and reproduce the actual suggestion or notification. Several channels changing
under one switch is evidence for one coherent operation, not several independent
controls. An absent event does not prove suppression. Account, network and
rollout dependencies must be recorded. Until then, leave exact feature labels
unassigned and keep the experimental entries out of recommended composition.

The earlier 174-operation presentation review changed presentation, references
and migration acceptance guidance. It preserved IDs, values, states, supported
targets and saved-run schemas. That review did not run Windows changes, start a
VM, request elevation or claim new UI tests. The subsequent sixty-setting
implementation and its validation are recorded in the batch ledger.

That presentation review passed validation on Windows PowerShell 5.1 and PowerShell 7 for all 174
operations, 2 groups, 4 profiles and 52 maintained PowerShell files. Generated
documentation is current and the focused diff has no whitespace errors. A
comparison with the catalog staged for the successful forty-setting VM run
confirms that only names, descriptions and references changed in 22 entries;
all other operation metadata is identical. The unresolved channels remain
outside every profile. No additional lifecycle tests were needed for these
presentation changes; the unresolved feature checks remain outstanding.

## Remaining-settings batch 1 design review, 2026-10-10

| Outcome | Decision | Follow-up acceptance / omitted scope |
| --- | --- | --- |
| Existing diagnostic, feedback and error-reporting tasks | User accepted separate advanced Task Scheduler-aligned enablement controls plus guidance using verified normal policies first; preserve exact identities and definitions | Verify installed payload, behavior/side effects and servicing per current build; absence is unavailable and disabling does not prove all diagnostics or prompts stop |
| Office tasks | User accepted advanced version-specific legacy agent controls, with service monitoring separate; current Office privacy requires its own supported controls | Distinguish organisational Dashboard collection from Microsoft diagnostics, retired/version-dependent agents and monitor payload/maintenance effects; expose product/license/account/policy requirements before recommending composition |
| Application-impact telemetry and inventory | User accepted separate advanced policies named for Windows component usage and compatibility inventory, with explicit inverse Group Policy wording | Verify CEIP precedence, new-application/restart effects, current collection and supported editions/targets; legacy override removal differs from explicit Enabled |
| Start most-used list | User accepted advanced Hide most-used apps in Start policy with GUI/effective-policy explanation; defer a normal user preference until its mapping is verified | Supersedes earlier obsolete disposition. Verify gray toggle/list after refresh, higher-precedence ShowOrHideMostUsedApps and app-launch tracking; Allowed does not force display or enable tracking |
| Secure-attention sign-in | User accepted one Require Ctrl+Alt+Delete before sign-in control with GUI policy inversion and explicit Required=0, NotRequired=1, override removal and saved recovery | Verify actual sign-in, credential-type/accessibility effects and managed-policy precedence. Resolve differing Microsoft default references; no implicit sign-out/restart or support expansion |
| Drive optimization | User accepted independent GUI-aligned Scheduled drive optimization after mapping acceptance; preserve frequency/media choices and exclude from privacy suppression | Verify Run on a schedule mapping, supported media and actual maintenance; manual optimization and frequency changes remain separate |
| Telemetry legacy bundle | User accepted composition of verified policies through Reduce optional diagnostics guidance; retain partial scope | CEIP has an exact reference but needs current effect acceptance; App-V client relevance and non-policy mirror precedence remain deferred. Exclude NoGenTicket and obsolete AllowBuildPreview; preserve distinct reverse semantics |
| Feedback legacy bundle | User accepted separate request policy and one combined GUI-aligned frequency control, with Stop automatic feedback requests guidance | Microsoft documents a two-value frequency mapping; resolve source type/number inconsistency and current GUI behavior. Legacy changed/reversed only the count. Task and policy lifecycle evidence remains partial |

Native mocked lifecycle and failure checks pass. VM run
`60bfde39fdaf433fb12d03c0d69fae8e` passed 851 guest tests and 12 available
operation lifecycles across 28 named states with exact restoration. Compatibility
Appraiser, ProgramDataUpdater and the three Office tasks were absent; those five
do not have runtime acceptance. Host UAC remained unchanged and checkpoint
cleanup passed. Feature acceptance remains separate. No profile defaults or
published IDs are changed.

## Remaining-settings batch 2 design review, 2026-10-10

The [decision and blocker ledger](remaining-settings-decisions.md) records the
whole-bundle reconciliation, reverse states, precise current Edge references,
retirements and unfinished setting outcomes for these two batches.

Batch 2 adds 19 optional settings. LLTD's two flags stay together; sound selector
and event mappings stay together. SMB protocol flags and adapter bindings have
different dependencies and clearly named effects. Adapter snapshots include all
reported coupled flags on affected GUIDs; recovery checks every identity before
writes and reports nonconvergence. NetBIOS DHCP/default is distinct from explicit
enablement. Its per-interface registry preference captures raw type and absence,
because the CIM default-mode setter could not recover the static-IP VM. The
reference documents modes rather than the registry mapping; effective behavior
after adapter restart/reboot remains unverified. Remote Desktop permission and existing local firewall flags remain
separate, with hosting-edition, service, authentication and GPO dependencies.
Controlled Folder Access exposes blocking, audit and disabled states with policy
limits. SMB requires the corresponding existing protocol driver; absence is
unavailable rather than an enablement pass. Existing power scheme selection
queries exact GUIDs and does not own/create missing schemes.
Sound source presets and unrelated values are preserved; raw current mappings
and kinds are captured for exact restoration.

Current Edge controls replace obsolete EdgeHTML mappings with documented startup
boost and background-app policies. Their independent meanings are explicit;
they do not claim identical old/new process behavior. Edge Update desktop
shortcut policy applies during installation and has no effect on already
installed Edge. Its link identifies that exact policy; the two browser policies
use current focused pages because old overview fragments no longer locate them.

VM round trips remain separate from actual peer networking, topology, Defender
blocking, Remote Desktop/NLA, sound playback, Edge processes/installation,
physical devices, vendor bindings and reboot acceptance. Missing Office tasks
and unavailable power schemes retain explicit acceptance gaps. No recommended
profile was changed by these batches. The last-setting milestone remains open;
the final walkthrough agenda is stored, not claimed complete.

The first batch 2 VM attempt failed SMB1 enablement and power-scheme saved-run
recovery after 857 guest tests and nine other operation lifecycles passed. The
controller recovered the pinned checkpoint without cleanup errors or host UAC
changes. The [decision ledger](remaining-settings-decisions.md#lifecycle-evidence)
retains this failed attempt and the capability/query corrections; it is not
counted as completed batch acceptance.

The second attempt passed 859 guest tests and ten other operation scenarios, but
NetBIOS mode 0 failed with CIM return code 100 (DHCP not enabled). Its original
value was recovered only through the clean checkpoint. The typed registry
preference replacement and rejected CIM-only snapshot format are recorded in the
decision ledger; 85 focused checks pass on both native PowerShell versions.

The third attempt passed 860 guest tests and 17 complete live operation lifecycles,
including typed NetBIOS recovery, sound, Remote Desktop and Edge policies. It
exercised 43 named states, including two in the failed power scenario. SMB1
remained unavailable. Power-scheme native stderr caused
Windows PowerShell 5.1 to terminate before exit-code inspection; exact saved-run
recovery passed, but this remains a failed acceptance attempt. Collection,
checkpoint cleanup and unchanged host UAC are recorded in the decision ledger.
The native wrapper correction preserves exit codes and verifies the active GUID;
eleven focused tests pass on both native PowerShell versions.

The fourth attempt passed 862 guest tests and the same 17 complete lifecycles.
The native exit code confirmed that Ultimate Performance activation genuinely
failed; Balanced/High Performance and exact saved-run restore worked. The new
operation now exposes only those two states. Ultimate Performance remains with
the deferred scheme-creation/ownership scope; no installed-scheme identity or
writability is inferred from a successful query. Collection, checkpoint cleanup
and unchanged host UAC passed.

Final run `5b66779b3628494a814b061bc1ce07a9` passed all **862 guest tests** and
**18/19 available operation lifecycles across 43 named states**, including exact
saved-run restore and the revised Balanced/High Performance scope. SMB1 was
unavailable because its driver was absent. Evidence collection, clean-checkpoint
restore and VM shutdown passed without errors, with host UAC unchanged.
Together with batch 1, **30/36 operations across 71 named states** have lifecycle
acceptance. Five absent task identities and SMB1 retain resource gaps. Native
PowerShell 7/5.1 catalog, parser, generated documentation and completion checks
pass. Peer networking, sign-in, UI, sound playback, Edge behavior, policy
precedence and restart checks remain open, as do the deferred migration outcomes
and requested final walkthrough. See the decision ledger for the evidence path.

### Scope and requirements implementation increment, 2026-10-11

The user authorized implementation of the accepted decisions, with new tests
held until the concurrent application migration and its tests finish. The first
increment adds a shared, data-only presentation contract to discovery/search,
individual and group-member details, profile previews and both status modes.
Long GUI effects and prerequisites remain visible in list-formatted live views.
Group/profile discovery points to individual member requirements rather than
claiming one scope or enforcement rule for the whole selection.

The optional catalog `SettingPresentation` table preserves schema 1, published
IDs, states, handlers, physical registry paths and saved-run recovery. Existing
and external catalogs without it explicitly display unverified behavior,
editability and requirements. Scalar registry validation now rejects a root
inconsistent with scope; machine settings must declare administrator privileges.
Presentation validation requires recognized behavior and authoritative evidence.
See [the presentation contract](../setting-presentation.md) for fields and limits.

Initial reviewed metadata covers file-name extension visibility, sound-scheme
editing, Edge startup boost and Defender cloud-delivered protection. This makes
the accepted Defender Advanced-state license/account/membership explanation
visible in catalog descriptions and generated documentation without changing its
value or recovery. Account requirements inferred from local procedures and
current GUI behavior still need the agreed disposable-VM evidence.

Live user views identify the execution account/SID and explicitly flag intended
user verification as pending. Effective policy/source is not inspected and is
reported separately from configured values and declared effective defaults.
This increment does not implement an alternate-user selector or claim that
alternate-administrator execution targets the interactive user's profile.

The test hold was respected until the application chat completed its migration,
tests and VM recovery. Native Windows PowerShell 5.1.26100.9549 and PowerShell
7.6.5 then covered **149 passing tests per edition** across setting presentation,
search, catalog and library compatibility. Each initial run passed 147 tests;
two unrelated temporary download-fixture checks hit sandbox permissions and
passed on targeted retry with process-local scratch data inside the workspace.
The state-changing WindowsIntegration test was excluded. Pester's automatic
registry fixture was disabled; system handlers and execution identity were
mocked for the presentation tests. No elevated Windows process was required.

Parser/catalog/profile/generated-reference validation passed on both editions:
287 operations, two groups, four profiles and 87 PowerShell files. Evidence is
in local `.local/setting-presentation-ps51.json`,
`.local/setting-presentation-ps7.json`, their `-fixture-retry.json` records and
`.local/setting-presentation-validation-ps51.log` / `-ps7.log`.
Generated documentation was refreshed and whitespace reviewed. Remaining setting
audits, effective-policy inspection, intended-user protection, focused handlers
and feature/GUI/Server acceptance remain open; this is not the last-setting
milestone. No Windows settings were applied. No legacy outcome is newly closed,
so migration estimates remain unchanged.

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

Run d62ee7a8b55c4c2aa0b2352147901e87 finished Failed at 2026-10-14T12:27:12Z, fixture C56726427B33E35C007873A9DF83CE1F46F91DD0B3DB686EEFA72B345CBD3614, source manifest 0ED8737500063870F9AF6B44E5972CB2FE0AB0C10A47C4C43CE6DBEC9B48291C and console 484FEA918F831FB53A2B5B4748EFD79F1C5293C95F0ED07B999889A7A5867679. The identity predicate correctly refused an administrative token on the UAC-disabled guest despite a Limited task and correct session. This failure accepts no desktop/worker/full launcher/alternate-admin or app lifecycle. All source bytes/preflight, failure/console correlation, task cleanup and final checkpoint/idle/pins/installed hashes/CI verified at 12:29:53Z; only matching selection removed. No app queried/changed, no UAC or pin change. [Postponed resource decision](store-app-follow-up-decisions.md#desktop-resource-decision---separate-resource-authorized) requires a genuine unelevated desktop on a separately reviewed fixture resource; honor the user instruction to postpone interactive elevation/credentials while AFK. No legacy outcome resolved/retired/excluded; all five ranges unchanged because this is failed resource acceptance. Preserve actual app source/recovery/GUI/managed and policy evidence as deferred/partial. Continue independent authorized machine-setting boundaries.

## Local maximum-age 1/2/998-day boundaries Windows 11 lifecycle passed review, 2026-10-14

Request `d17b3ecf49084aac8fa0bf45ed8eaa0c` for `windows.local-password-maximum-age` on Windows 11: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-local-password-maximum-age-win11-d17b3ecf-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Local maximum-age 1/2/998-day boundaries Windows Server 2025 lifecycle passed review, 2026-10-14

Request `8da4114c2f504c5d8adb4b7321482641` for `windows.local-password-maximum-age` on Windows Server 2025: passed; 3 states completed, lifecycle=True, exact recovery=True. [Evidence](../archive/evidence/settings-local-password-maximum-age-winserver-2025-8da4114c-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Maximum-age boundary follow-up and minimum-age guard implemented review, 2026-10-14

The fixed schema-2 MinimumAgeConflict admits only windows.local-password-maximum-age/Days1 with explicit target approval. Test-only level 1003 sets captured-zero minimum to one day; production backend remains level-1002 maximum-only. SAM/unrelated context, preview and refusal state are checked, native maximum setter counted, failed intent restored without a maximum write, and the exact fixture minimum seed separately recovered. Drift refuses replay. LifecyclePassed/ExactRecovery remain false for this guard; ExactFixtureSeed is not successful primary apply. The existing local security/password scope is unchanged; no passwords, domain controllers, UAC, app/package or GitHub work. Current source includes uncommitted changes; request 660dac2bfa0d45f3ac8d6e1f46dcc7eb has 360 preflight files and fixture 9454FD88FDC370A36FCCC1691B124A1D42583F698D88BBC728CDC915C8C47CA6. Native and checkpoint acceptance pending. No legacy outcome resolved/retired/excluded; GUI, managed/default/complexity and unelevated desktop resources remain partial/deferred, all five ranges unchanged. [Fixture contract](../../tests/integration/settings-fixtures.md) documents the focused scope; [desktop prerequisite](store-app-follow-up-decisions.md#desktop-resource-decision---separate-resource-authorized) remains held.

## Local maximum-age conflicting minimum Windows 11 MinimumAgeConflict guard passed review, 2026-10-14

Request `660dac2bfa0d45f3ac8d6e1f46dcc7eb` for `windows.local-password-maximum-age` on Windows 11: passed; 0 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-local-password-maximum-age-win11-660dac2b-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Local maximum-age conflicting minimum Windows Server 2025 MinimumAgeConflict guard passed review, 2026-10-14

Request `9921cbfc65c44a718fb1f872213e82f0` for `windows.local-password-maximum-age` on Windows Server 2025: passed; 0 states completed, lifecycle=False, exact recovery=False. [Evidence](../archive/evidence/settings-local-password-maximum-age-winserver-2025-9921cbfc-2026-10-14.md). Controller, cleanup, collection, guest, fixture and recovery errors were absent. GUI/feature, component presence/applicability, boot/workload, managed/default and deliberate native-failure evidence remain pending. No supported-target widening or whole legacy closure.

## Two-target password-age boundary and conflict follow-up accepted review, 2026-10-14

Completed follow-up source snapshots include current uncommitted code. Boundary runs: d17b3ecf49084aac8fa0bf45ed8eaa0c (Win11, 358 files, manifest EFB957614927236F75FC3B9AB9C186F166EBB354EAA36E85EB1824CCC9AA3F81) and 8da4114c2f504c5d8adb4b7321482641 (Server, 359 files, CD8E07D1970415711BA38BA6EABA58F9C747BB5EE8A005707DD0DF7A4658B001). Refusal runs: 660dac2bfa0d45f3ac8d6e1f46dcc7eb (Win11, 360 files, BCA0DF413CDF2804F8C24A7DEBB43B7DBA4703E4F7559DCC753A1CC4113054EE) and 9921cbfc65c44a718fb1f872213e82f0 (Server, 361 files, 3C82509E36F2E0417CB6A2634E68AB6EF9A21B3428220EE30F9A610636470EA7). All hashes/preflight entries, correlated guest/XML evidence, native recovery and final both-idle/pins/installed hashes/CI validated. MinimumAgeConflict uses test-only local minimum level 1003, while production maximum setter remains 1002 only; no successful primary apply is inferred from zero-write refusal. Current fixture/data 0.12.0/0.10.0; 178 host mocked checks passed on each edition, one registry case excluded. [Validation handoff](settings-validation-resume.md#password-age-boundary-and-refusal-follow-up-2026-10-14) links exact scope; [desktop resource follow-up](store-app-follow-up-decisions.md#desktop-resource-decision---separate-resource-authorized) remains postponed under the AFK elevation instruction. Published support, UAC, pins, profiles and package pause unchanged; no whole legacy outcome resolved/retired/excluded. GUI/default/managed, complexity/file-editor and app lifecycle remain partial/deferred, so all five ranges and rounded total stay unchanged.

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

## B01 input and audio presentation review, 2026-10-16

Status: **source-ready; runtime acceptance pending**. This is the user-authorized
B01 batch from [the remaining migration handoff](remaining-migrations-follow-up.md#matching-batches).
Source baseline: `f53ce6ab102a` plus this focused uncommitted patch. Existing unrelated
AGENTS/README/TODO/documentation-model and Ninite comparison edits are preserved.

### Scope, mapping and ownership

The authoritative input is `catalog/operations.psd1`, compared with the existing
RegistryValue/RegistryValueSet engine and `modules/RIDE-SoundSchemes.psm1`.
RIDE maintainers own presentation and source acceptance; the operator supplies
intended-user, GUI and hardware observations in an authorized disposable target.
The existing review decisions remain authoritative; this batch adds no setter.

| Legacy intent | Existing mapping | Reviewed distinction |
| --- | --- | --- |
| Keyboard portion of SetVisualFXPerformance / SetVisualFXAppearance | `windows.keyboard-repeat-delay` | Stored positions 0-3; baseline/unset remove the override; effective session delay remains separate. Other visual-effects bundle components are not closed. |
| DisableEnhPointerPrecision / EnableEnhPointerPrecision | `windows.mouse-pointer-precision` | Three coordinated legacy acceleration values; explicit Enabled is not recovery of custom thresholds. |
| SetSoundSchemeNone / SetSoundSchemeDefault | `windows.registered-sound-scheme` | Registered preset and current event mappings; customized .None may contain sound. No baseline/unset or factory reset is implied. |
| DisableStartupSound / EnableStartupSound | `windows.startup-sound` | Machine preference; baseline Enabled differs from absent literal default; no unset is declared. |
| Accepted selected playback-device Mute/Unmute replacement | [Manual native workflow](../audio-service.md#mute-a-selected-playback-device) | Intended desktop, identified device, unchanged volume/default roles and explicit prior-mute recovery; no automated endpoint operation or RIDE snapshot. |

Consumers are discovery/search, show/group details, plan/status and generated
`docs/OPERATIONS.md`; they already consume the additive SettingPresentation table.
Coverage was re-counted at 28/277 before and 32/277 after. The remaining 245
settings require their own metadata review. Microsoft references were opened and
reviewed; feature-only references remain labelled, particularly the themes page,
which documents neither DisableStartupSound nor the startup checkbox. No UI
mapping is promoted from a registry or API description to verified behavior.

### Procedure, validation and recovery

On the Windows filesystem checkout, using native Windows PowerShell 5.1.26100.9711
and PowerShell 7.6.5 without elevation:

1. Capture the parsed catalog before editing; compare the complete before/after
   data after removing only the four new presentation blocks. **Passed**: all
   IDs, state values/types, scopes, target defaults, handlers, support declarations,
   groups, baselines and recovery contracts are unchanged. An initial comparison
   helper treated deserialized ArrayLists as scalars; correcting its recursive
   canonicalization resolved ordering-only differences without a source change.
2. Generate `docs/OPERATIONS.md` through `tools/Export-RideCatalog.ps1`.
   Run `tools/validate.ps1` on both editions. **Passed** on each: 340 operations,
   eight groups, five profiles and 146 maintained PowerShell files; generated
   reference is current and both editions agree.
3. Run `SettingPresentation.Tests.ps1`, `Catalog.Tests.ps1` and `Search.Tests.ps1`
   with installed Pester 5.7.1, TestRegistry disabled, WindowsIntegration excluded
   and separate workspace-local TEMP/TMP per child process. **122 passed, zero
   failed, zero skipped per edition**; one integration test excluded. No test
   dependencies or payloads were acquired. Supplementary results are in ignored
   `.local/b01-presentation-5/result.json` and `.local/b01-presentation-7/result.json`.
4. Focused source/generated/documentation diff review and `git diff --check`
   passed. All 437 local links in the touched Markdown files passed after repairing
   eight stale anchor/path references. LF and the command-launcher policy are
   preserved. No persistent environment,
   registry, service, audio device, VM/controller or package state is changed.

No runtime activation is part of B01. Source recovery is to remove this batch's
four metadata blocks and focused prose, then regenerate the catalog reference,
while preserving unrelated edits. Existing saved runs keep their prior semantics.
Manual mute recovery uses the same identified endpoint and recorded prior boolean;
if it disappears or becomes ambiguous, leave recovery pending instead of choosing
another output. Those manual actions cannot be undone by `restore -RunId`.

### Remaining acceptance and next action

GUI/managed-policy behavior, keyboard sign-in and actual delay, mouse/driver effects,
customized sound-scheme playback, startup boot behavior and intended-user identity
remain pending. Mute acceptance requires a usable endpoint, unchanged volume/app/
microphone/default roles, repeat choice, prior-state recovery and disappearance
refusal. A no-audio VM or indicator-only observation cannot prove playback.
Automated endpoint identity/session/conflict handling remains deferred under D08/Q30.
Support and recommended profiles are unchanged; packages remain paused.

Next source batch: **B02**, beginning with a bounded read-only playback-endpoint
identity and capture contract plus isolated fixtures. Document ambiguity, missing
devices, session ownership and prior mute separately from any setter. Do not choose
a device or settle D08/Q30 implicitly. Interactive acceptance is a separate authorized
disposable-target step; Clipchamp remains the next Store candidate when elevation
is available. Broader presentation review stays open.

Resolved: four presentation gaps and selected-device manual guidance. No whole
legacy outcome resolved, retired or excluded. Partial: existing setting outcomes
still need user-visible acceptance. Deferred: endpoint backend, hardware/GUI/boot
and managed checks, package work and elevation-dependent Store acceptance. All five
ranges were reviewed and remain **38-58 / 58-73 / 20-25 / 25-35 / 8-12**; rounded
**150-205, about 180**. Source readiness adds no completed feature/product outcome,
so neither individual ranges nor the rounded estimate decrease.

## B02 read-only playback endpoint contract, 2026-10-16

Source: `f53ce6ab102a` plus the B01/B02 working patch. This implements the first
resource slice of B02 for the R20 selected-playback mute investigation. It neither
settles D08/Q30 nor adds an operation. RIDE maintainers own the observation schema
and module; the intended desktop operator still supplies device and audible evidence.

`modules/RIDE.AudioEndpointInventory.psm1` enumerates Core Audio render endpoints
with opaque IDs, friendly-name availability, state and available mute/volume values.
Default Console, Multimedia and Communications roles are observations, never
fallback selections. Empty inventory, unavailable role, inactive endpoint and failed
volume access remain distinct. A maximum of 256 endpoints bounds data processing;
native COM/driver calls have no hard timeout. Collection is sequential, not atomic.

Explicit SID/session checks precede and follow collection, refusing mismatches and
noninteractive execution. They do not establish the intended desktop; the output
reports `DesktopVerified=false`. Exact ordinal ID selection works on saved JSON and
refuses missing or duplicate IDs. It always reports `ReadyForMutation=false` and
`RecoverySupported=false`. Completion reads only the supplied inventory, handles
quoting and prefix filtering, and never queries native devices. Import is inert.

Microsoft's MMDevice enumeration, opaque ID, property-store and endpoint-volume
references and the Windows SDK interface slots were checked. The
[operator guide](../audio-service.md#read-only-endpoint-inventory) links the primary
references and explains capture, explicit selection, limitations and file handling.
`tools/Export-RideAudioEndpointInventory.ps1` previews without a query and uses
exclusive CreateNew output, preserving both pre-existing and concurrent files.
Exported SID/device names are local observations, not saved engine recovery records.

### Procedure and acceptance

From the Windows-hosted checkout, use native PowerShell 5.1 and 7. Run the focused
`AudioEndpointInventory.Tests.ps1` with Pester 5.7.1, TestRegistry disabled,
WindowsIntegration excluded and process-local workspace TEMP/TMP. **21 tests passed
on each edition**. They cover identity-before-query and post-capture drift, native
query failure, empty/unavailable/inactive observations, exact case-sensitive IDs,
duplicate/missing IDs, invalid direction/counts/roles/booleans/volume, saved JSON,
completion, preview and non-overwriting export. C# interop compiles in both editions
without executing Core Audio. An initial collision test used a mock-invisible script
variable; the corrected TestDrive fixture verifies the expected existing-file error
and preserved concurrent bytes. This was a test-fixture correction, not live evidence.

Repository validation passed both editions: 340 operations, eight groups, five
profiles and 149 maintained PowerShell files. Generated catalog remains current.
No live Core Audio query, playback, endpoint/service mutation, package acquisition
or VM submission was performed. Existing settings and saved recovery are unchanged.

Acceptance still requires the intended interactive desktop, real endpoints and
driver combinations, default-role/device disappearance during observation, correct
friendly names and mute/volume readings, and clear unavailable states. These are
postponed while the user is away. No supported-target metadata or profile changes
are justified by mocked/native-compilation evidence. Future mutation needs separate
fresh identity/conflict checks and exact prior mute recovery; this file cannot serve
as its recovery record.

Recovery for this source-only slice is to remove the new standalone module/tool/test
and focused guide links while retaining unrelated changes. Export has no audio undo;
retain or explicitly delete its own JSON. A disk-write failure can leave incomplete
JSON, which must not be treated as captured evidence; use a new output name after
addressing the error. Do not replace the operator's files automatically.

Resolved: endpoint observation, saved selection and safe export source contracts.
Retired/excluded: none. Partial: R20 and other B02 resource families. Deferred:
desktop/hardware acceptance, mute setter decisions and elevation-dependent Store
work. Package implementation is resumed under the user's overnight authorization.
All five ranges reviewed and unchanged: **38-58 / 58-73 / 20-25 / 25-35 / 8-12**;
rounded **150-205/about 180**. No whole legacy feature/product outcome has completed
acceptance. Next independent batches: B06 conditional-component inventory and B08
individual portable review; retain unresolved ownership/product questions.

## B03 startup closure fixture, 2026-10-17

The successor closure batch reviewed both pending UserBinPath operations and the
shared profile writer. Added explicit absent-profile recovery and capture/write
race fixtures; existing exact UTF-16 restore, legacy-writer refusal, modified-block
preservation and color-block coexistence checks remain. The serialized profile VM
runner now selects `-Scenario UserBinPath` and stages the new guarded
`Invoke-RideUserBinAcceptance.ps1` with the current source manifest. Its Windows 11
case requires installed 5.1/7 runtimes and an absent bin directory, checks real
ConsoleHost process startup, missing/existing bin, normalized duplicate, NoProfile,
repeat apply, Default and saved-run restore, and preserves sentinel contents.
No prerequisite installation, UAC change or production target bypass is added.

Validation: UserBinProfile and ProfileAcceptanceAutomation passed **28/28 on each
native edition** (5.1 and 7), with no skipped tests. Two stale pre-existing color
worker version assertions were corrected from 0.1.0 to their actual 0.1.1;
the initial run's two failures were fixture expectations, not runtime acceptance.
The [source/check index](../archive/evidence/startup-closure-fixture-2026-10-17.json)
binds these checks to their source hashes. Logs: `.local/closure-startup-powershell.log` and
`.local/closure-startup-pwsh.log`. The first 5.1 launch was blocked by process
execution policy; retry used process-only ExecutionPolicy Bypass.

Exact native blocker: this host token is not elevated; a read-only `Get-VM`
request returned `Access to a CIM resource was not available to the client.`
No VM was started, controller/pin changed or interactive elevation requested.
The scenario still needs actual source-correlated Windows 11 acceptance in the
intended account; alternate-user/redirected-path behavior and existing unmarked
snippets retain their explicit review/recovery boundaries. Run through the existing
idle controller with its guest credential and fresh evidence directory when access
is available, retain evidence, and require checkpoint recovery before promotion.

Resolved legacy outcomes: none. Retired/excluded: none. Partial: startup user-bin.
Deferred: native startup acceptance; persistent PATH, directory provisioning and
WindowsApps remain separate. All five ranges remain **38-58 / 56-71 / 20-25 /
25-35 / 8-12**, rounded **145-200/about 175**. Fixture completion is not a legacy
closure. Advance to B08/R06 while this resource gate remains.

## B03 existing user-bin startup candidate, 2026-10-16

Source f53ce6ab102a plus the overnight patch. Two pending operations represent the
Windows PowerShell 5.1 and PowerShell 7 forms of one partial legacy startup outcome:
powershell.windows-powershell51-user-bin-path and powershell.powershell7-user-bin-path.
The [profile contract](../powershell-profiles.md#existing-user-bin-startup-path-candidate)
owns operator behavior, prerequisites, acceptance and recovery. This preparation
does not answer Q08's persistent-PATH choice or admit a recommended selection.

Reconciled both legacy writers: AddUserBinToPath combines a flawed directory check,
immediate process PATH and unmarked profile append; Write-Profile-File.ps1 also
appends WindowsApps. The candidate covers only selected-runtime startup for an
existing UserProfile/bin. Applying the profile block does not change RIDE's PATH.
Directory provisioning, persistent PATH, WindowsApps repair and Terminal default
profile remain separate. No unmarked code is adopted or deleted; executable
UserBinaries references cause enable/snapshot refusal, while comments/literal
examples alone do not. Unknown custom PATH writers still need operator review.

Enabled appends only when an existing directory has no normalized equivalent in
process PATH. Case, trailing slash, quoted and environment-expanded forms are
recognized while other bytes/order and pre-existing duplicates are preserved.
Missing/unreadable directories and oversized results do nothing. Local matching
ConsoleHost and runtime guards apply; no Terminal, network or tool installation
dependency. Default/unset/Baseline remove only the RIDE block; saved-run restore
uses unchanged snapshot version 1 and exact predecessor content. Existing or child
process environments are outside file recovery. Review fresh parent inheritance
explicitly during acceptance rather than assuming a new child shell is clean.

Shared file mechanics retain bounded input, encoding, exclusive byte checks,
ShouldProcess and conflict recovery. The original canonical color renderer is
text-identical to HEAD; both marker and snapshot versions stay 1. Color acceptance
runners now explicitly select TerminalColors, preventing accidental application
of the new pending renderer. Catalog validation rejects arbitrary user-bin states
or color metadata; engine/reference output distinguishes startup PATH from palettes.
Completion remains catalog-driven and does not query a runtime or profile.

Validation passed on native Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5:
140 focused tests per edition, zero failures/skips, one WindowsIntegration excluded.
The focused set covers new generated-code behavior in a restored test-process PATH,
inert profile fixtures, existing color lifecycle, catalog and presentation. Real
startup profiles and persistent environment data were not read or changed by the
fixtures; runtime discovery and bin directory presence were mocked. Both editions
passed repository validation: 344 operations, eight groups, five profiles and
155 PowerShell files. Generated documentation is current. A scratch comparison
initially used Import-PowerShellDataFile directly and hit its large-data restriction;
it produced no comparison evidence. The successful source comparison used Git's
original renderer text and the focused tests use the bounded catalog loader.

SupportedTargets stays empty, CandidateTargets Windows 11, PendingAcceptance true.
No startup, intended-desktop, execution-policy, Server or cloud-profile behavior
is claimed accepted. Next procedure: in an explicitly scoped disposable Windows 11
fixture, verify intended SID/runtime paths; snapshot profile bytes and parent PATH;
preview/apply/repeat; launch matching fresh shells with existing and missing bin;
check normalized entries, NoProfile, blocked startup and inherited PATH; retain
unmarked-writer/conflict evidence; unset and restore exact profile content, then
recover the VM checkpoint. Do not enable dependencies or modify the workstation.

Source recovery removes only the two pending declarations, renderer-specific
extensions/tests/docs and regenerated reference; preserve prior work and accepted
color behavior. After eventual activation, saved-run recovery restores managed
profile content with intact snapshot bytes and reports conflicts; do not execute
captured text as a shortcut. Bin data and already running processes are not owned.

Resolved: bounded source renderer and isolated lifecycle/duplicate evidence.
Retired/excluded: none. Partial: one legacy user-bin outcome, not two completed
features; directory and immediate-session scope remain separate. Deferred: native
startup/identity/GUI acceptance, persistent PATH choice, provisioning and Terminal
JSONC ownership. Catalog presentation now covers 34/279 settings; 245 still need
individual review. All five legacy ranges remain 38-58 / 58-73 / 20-25 / 25-35 /
8-12, rounded 150-205/about 180. New declarations do not reduce legacy acceptance
counts; packages/components/maintenance gain no runtime evidence from this batch.
Continue independent source work under the overnight authorization.

## B03 Terminal JSONC preparation, 2026-10-16

Source f53ce6ab102a plus the overnight patch. E06's first field-preservation proof
is source-ready in modules/RIDE.TerminalJsonc.psm1, independently of Q09's actual
profile choice. The [API contract](../terminal-jsonc-preparation.md) owns limits,
examples, recovery and next integration; the [native operator workflow](../windows-terminal-profile.md)
remains the available live path. No catalog operation, target support or real
settings-file writer is introduced.

Three exported commands inspect supplied bytes, prepare an explicit declared-GUID
selection and reconstruct recovery bytes. All operate in memory and return
MutationAuthorized false. The bounded UTF-8 JSONC parser retains spans, comments,
unknown fields, number spelling, Unicode, BOM and line endings. It accepts trailing
commas, rejects decoded duplicate keys/invalid syntax, and limits bytes, nesting,
nodes and declared profiles. Existing root string replacement owns only the value;
absent-property insertion owns its exact new fragment. Recovery validates snapshot
version 1 against a reconstructed edit, preserves unrelated current edits and
refuses changed owned text/BOM or missing/hidden/ambiguous prior identity.

Declared GUIDs, exact names, hidden defaults/overrides and dynamic source labels
are inspected without claiming installed or launchable profiles. Completion reads
only supplied bytes. No path, process, instance, registry or desktop discovery;
no live file reads/writes, package acquisition or profile launch. Microsoft's root
defaultProfile reference accepts GUID/name; profile GUID/source metadata is under
profile-advanced, not profile-general. The guide uses the verified heading link.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed **41 focused tests**, zero
failures/skips/exclusions. Coverage includes malformed/duplicate/escaped syntax,
resource bounds, old/new profile arrays, hidden/incomplete identities, UTF-8/BOM/
CRLF round trips, nested lookalike fields, unrelated prepended edits, tampered
snapshots and completion. Initial runs passed 38/39: one test mistakenly replaced
both the root GUID and its profile declaration in its expected string. The actual
patch correctly changed only the root value. Correcting that fixture and adding
two preservation cases produced clean final runs. Both editions passed repository
validation: 346 operations/eight groups/five profiles/158 PowerShell files.

Next procedure: bind one installed instance, intended desktop SID/session and
exact file path; prove live profile availability; implement exclusive byte compare,
ShouldProcess and saved-state persistence; then use a disposable target for preview,
apply/repeat, concurrent editor changes, disappearance/conflict restore and new-tab
behavior. Q09 selection and native GUI acceptance remain deferred. The in-memory
snapshot alone has no trusted file/instance/user identity and must not be passed to
an ad hoc live writer. Full bytes may contain private configuration; state-store
ACL and retention remain part of integration.

Recovery for this preparation removes only the new module/test/API guide and
associated links/records, preserving other edits. There is no live state to undo.
Future file recovery must retain the verified original bytes and refuse conflicts;
neither a file round trip nor a declared profile proves native launch behavior.

Resolved: E06 narrow JSONC byte-edit/recovery proof. Retired/excluded: none.
Partial: Terminal default-profile outcome; no runtime activation. Deferred: file/
instance/identity binding, actual availability, writer/GUI acceptance and Q09.
Settings/accounts remain partial; packages/components/actions gain no acceptance.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180. Preparation closes no legacy outcome; presentation stays 34/279 with 245
reviews remaining. Continue other independent batches under the overnight window.

## B02 network adapter identity inventory, 2026-10-16

Source f53ce6ab102a plus the overnight patch. The [adapter inventory contract](../network-adapter-inventory.md)
implements explicit local machine/build/edition capture, normalized nonempty
adapter GUIDs and saved-observation lookup. Names and interface indexes remain
labels, never fallback identity. Missing GUIDs remain unselectable; invalid or
duplicate identities, partial provider failure and the 512-row bound produce
Unavailable with no partial rows. Captured-empty is distinct. Nullable Boolean
metadata remains unknown when absent. Post-capture context includes update revision.

The exporter supports query-free WhatIf and exclusive CreateNew JSON output.
Completion reads only supplied saved GUIDs. No adapters are selected or changed;
existing handlers retain their behavior. This is historical evidence, not an engine
restore record, permanent hardware identity or permission to mutate. Import and
completion perform no provider queries. No live NetAdapter query was performed.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed **23 focused tests**, zero
failures/skips/exclusions. Initial runs passed 22/23 because the output race fixture
reused the preceding test's filename and never reached collection. A unique race
path and explicit collector-call assertion corrected that fixture. Both editions
also passed validation of 346 operations/eight groups/five profiles/161 PowerShell
files. Tests mock context/providers and use isolated temporary files; they do not
establish native target support or live networking behavior.

Next procedure: collect an explicitly identified disposable Windows target; verify
visible/hidden, virtual/disconnected and missing-ID coverage; compare GUID identity
across rename/disappearance without a setting change. Later mutation must re-resolve
the selected GUID, refuse context/dependency drift and capture narrowly owned state.
D10/Q30's selection experience and actual binding/NetBIOS/category behavior remain
deferred. No all-visible compatibility operation is silently narrowed.

Recovery removes only this preparation's module/tool/tests/guide and links if
required; preserve dated output and other work. No network-state recovery exists
or is needed. Failed output writes may leave partial evidence; never overwrite it.

Resolved: B02 adapter observation and saved-identity contract. Retired/excluded:
none. Partial: adapter-related settings; no native or user-visible acceptance.
Deferred: target provider acceptance, Q30/D10 and mutation/dependency recovery.
Packages/components/accounts/actions gain no legacy acceptance. All five ranges
remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180: preparation
closes no legacy outcome. Presentation remains 34/279 with 245 reviews open.

## B04 default/LAN proxy observation, 2026-10-16

Source f53ce6ab102a plus the overnight patch. E07's default/LAN capture prerequisite
is source-ready in modules/RIDE.UserProxyInventory.psm1 and its exclusive JSON
exporter. The [operator/API guide](../user-proxy-inventory.md) owns scope, usage,
privacy, limitations and the next acceptance procedure. No catalog setting or
supported target is added, and no existing proxy handler changes.

Microsoft's current INTERNET_PER_CONN_OPTIONW, option-list, query and option-flags
references and published WinSDK header were checked. The reader uses option 75,
UI flags 10 with a recorded legacy-flags 1 fallback on native failure, and literal
proxy/bypass/PAC options 2/3/4. A flags preflight precedes the complete query and
refuses observed drift. This is sequential evidence, not an atomic snapshot.
It keeps unknown uint32 bits and distinguishes null/empty Unicode strings. All
returned string slots are released using GlobalFree, including partial failures;
the option array has separate ownership. Each string is bounded at 32,768 chars.

Explicit machine/SID/nonzero interactive session checks bracket collection.
DefaultLan is an explicit null connection-name scope, not a selected NIC or every
VPN. No RAS enumeration, registry blob decoding, PAC fetch, auto-discovery, network
request, WinHTTP query, setter or refresh occurs. Desktop ownership, managed policy,
connection identity and effective routing remain visibly unverified. Completion
uses the one supported declared scope without inspecting Windows. Output may hold
private hostnames/URL tokens and remains local evidence, not a recovery snapshot.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed **31 focused tests**, with no
skips/exclusions, and validation of 346 operations/eight groups/five profiles/164
PowerShell files. Fake unmanaged allocations exercise native failure/fallback,
drift, malformed buffers/IDs, cleanup continuation, duplicate pointers and bounds.
No WinINet query was executed. Separate compile/layout probes verified x86 option/
list sizes 12/20 under Windows PowerShell 5.1 and x64 sizes 16/32 under PowerShell 7.

Initial runs passed 25/31. One fixture assigned PowerShell null to a typed C# string
field, which coerced it to empty; an explicit C# null setter corrected the test.
Five invalid-data fixtures called an out-of-scope factory from InModuleScope;
passing prepared objects into that scope corrected them. These were fixture defects;
the clean final runs retain distinct null/empty checks and malformed-data refusal.

Next procedure: inspect an explicit disposable user's default/LAN UI and capture
without mutation, including disabled retained values and managed/alternate-account
limitations. Then prove owned flags/URL preservation, managed-source refusal,
same-user/scope recovery, partial failures and documented refresh before a setter.
PAC consumer tests need a controlled local fixture. Named RAS/phonebook identity and
machine WinHTTP are separate work; current capture is not their acceptance.

Recovery for this source preparation removes only the new module/tool/tests/guide
and links, preserving other work and evidence. No live proxy state was changed.
Resolved: E07 bounded default/LAN observation and native memory-ownership proof.
Retired/excluded: none. Partial: user proxy migration. Deferred: native/UI/policy
acceptance, named RAS, owned mutation/refresh/recovery and WinHTTP scope.
No package/component/account/action outcome closes. All five ranges remain
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180, because backend
preparation is not accepted legacy behavior. Presentation stays 34/279, 245 open.

## B01 media and privacy presentation, 2026-10-16

Source f53ce6ab102a plus the overnight patch. Added explicit presentation to six
existing IDs: windows.autoplay-policy, windows.autorun-policy,
windows.clipboard-history, windows.location-service-policy,
windows.location-scripting-policy and windows.advertising-id-policy. See the
[operator comparison](../setting-presentation.md#media-and-privacy-choices).
Presentation coverage is now **40/279**, leaving **239** individual reviews.
No IDs, names, states, handlers, scope, defaults, recovery, support or profiles change.

AutoPlay is a user preference despite its published policy ID/name; its native UI
reference does not document DisableAutoplay. Its Enabled and Baseline explicitly
write zero and no unset exists. AutoRun's all-drive mask 255 is machine policy;
Enabled removes it, allowing other restrictions/defaults, rather than enabling
every drive or autorun command. Default autorun-command policy and per-media
handlers remain separate. The local AutoPlay.admx has masks 181/255; only the
published 255/removal states remain in RIDE. No Explorer restart or media insertion.

Clipboard history separates explicit Disabled=0 from WindowsDefault/removal;
legacy DisableClipboardHistory removed the value. Sync/account/content actions
are separate and saved preference recovery does not restore clipboard entries.
Machine AllowClipboardHistory may restrict the UI; it is not the user value.

The complete legacy location pair writes both DisableLocation and
DisableLocationScripting to one, then removes both on reverse. The accepted
normal location/advanced scripting split remains. Current Sensors.admx confirms
both machine mappings; the online device DisableLocation_2 mapping is under
System/AllowLocation, while ADMX_Sensors/DisableLocation_1 is user-scoped.
Focused reference links correct that ambiguity without substituting CSP input
numbers for registry values. Scripting's current consumer remains unverified;
the existing default profile still selects it, and recommendation review is
explicitly retained rather than silently claiming it is excluded.

Advertising-ID policy limits one Windows identifier; it is not all tracking or
all advertising. Removing machine enforcement allows user choice and does not
force enablement or recover a previous identifier. All six retain managed-source,
GUI/session, edition/target and feature-specific acceptance limitations.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed **122 existing presentation,
catalog and search tests**, with one WindowsIntegration test excluded. Initial
repository validation then caught four new Behavior values using the rendered
label instead of the schema identifier. Corrected EnforcedPolicy, regenerated
documentation and checked the six actual rendered classifications on both
editions. Final validation passed 346 operations/eight groups/five profiles/164
PowerShell files. Whole-catalog comparison permits only six new presentation
blocks and their focused DocumentationUri updates relative to this batch's
baseline; the cumulative check retains earlier additions unchanged.

Next procedure: inspect an intended-user disposable target for AutoPlay media
choices without auto-executing payloads; test both policy/preference scopes and
shell refresh; compare local clipboard history with a managed block without
syncing private contents; verify location/provider/app effects and scripting's
actual consumer; verify advertising policy versus user choice. Recover captured
configuration separately from any nonrecoverable content or identifier changes.
Current target declarations are not widened by static references or templates.

Recovery removes only these presentation/reference additions and regenerates
OPERATIONS.md; no live state was changed. Resolved: six explicit presentation
reviews and exact scope/reference clarification. Retired/excluded: none.
Partial: affected legacy media/privacy outcomes, including the full location
bundle. Deferred: GUI, managed, hardware/session and recommendation acceptance.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180. Presentation review reduces its separate backlog, not legacy outcome counts.
The [static evidence](../archive/evidence/media-privacy-and-deferred-tool-review-2026-10-16.json)
also records the intervening deferred package checks; no new package was admitted.

## B04 proxy edit and recovery preparation, 2026-10-16

Source f53ce6ab102a plus the overnight patch. The separate
modules/RIDE.UserProxyPreparation.psm1 adds supplied-data detection/setup-script
patch and recovery commands. See the [API procedure](../user-proxy-inventory.md#prepare-an-edit-and-recovery-in-memory).
No catalog setting, native query/setter, registry write, output file, PAC fetch,
refresh, routing request or state-store activation is introduced.

Each explicit choice owns only its changed flag. Setup-script Off preserves the
saved address; On validates a supplied or retained HTTP/HTTPS address without
retrieving it. Whitespace, embedded credentials and unsupported schemes refuse
enablement. Exact URL spelling is retained. A malformed historical address can
still be retained while disabling. Manual server/bypass, direct and unknown flag
bits are preserved. No implicit direct/discovery fallback is invented. Finite
choice completion performs no discovery. FlagsFallback observations refuse this
first preparation contract; FlagsUi still does not establish effective behavior.

Schema-1 preparation snapshots retain the original typed observation, canonical
request and expected changed fields. Recovery reconstructs the edit, checks same
machine/SID/session/default-LAN context and refuses conflicting changed bits/URL.
Unrelated current manual/bypass/flag/address edits remain. Already-matching fields
are unowned, including a previously enabled script flag when only its URL changed.
Null and empty URL recovery are distinct. Snapshot consistency is not authenticity;
ReadyForMutation and MutationAuthorized are always false.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed **39 focused tests**, zero
failures/skips/exclusions. Cases exercise preservation, URL syntax, serialization,
mixed-case choices, malformed/incomplete inputs, identity drift, no-op ownership,
concurrent unrelated changes and tampered snapshots. Both editions passed repository
validation: 346 operations/eight groups/five profiles/166 PowerShell files.
These are in-memory fixtures, not connectivity or native setting acceptance.

Next procedure: bind fresh same-user native observations to a durable engine
manifest, inspect managed/per-machine source, implement previewed setters and
documented refresh, retain partial-failure recovery and prove actual consumers in
disposable targets with a controlled local PAC fixture. Track completed recovery;
do not infer a second write when owned values no longer match the prepared edit.
Cross-session recovery and named RAS/phonebook identity remain separate contracts.
No operation should consume these preparation snapshots as live authorization.

Recovery for this source batch removes only its module/tests and guide updates;
no live proxy state changed. Resolved: E07 narrow in-memory ownership/conflict proof.
Retired/excluded: none. Partial: user proxy outcome. Deferred: native/UI/policy,
durable state/setter/refresh/partial-failure behavior, RAS and WinHTTP. All five
ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180: no
legacy behavior accepted. Presentation stays 40/279, 239 open. The concurrent
YARA availability recheck adds no package, and other groups gain no acceptance.

## B02 volume identity inventory, 2026-10-16

Source f53ce6ab102a plus the overnight patch. New RIDE.VolumeInventory module and
Export-RideVolumeInventory tool provide a local Win32_Volume observation contract.
The [operator procedure](../volume-inventory.md) covers prerequisites, preview,
explicit machine/build/edition, output, lookup, limitations and recovery.
Pre/post context checks include update revision and native process architecture.
At most 512 rows are retained; failed, malformed, duplicate or overflowing
provider results discard partial rows. Missing GUIDs remain visible/unselectable.
Captured-empty and Unavailable differ. No provider method or volume file is opened.

DeviceID becomes a normalized trailing-backslash VolumeGuidPath. Drive letter,
label, filesystem, literal drive type and serial are observations, not fallback
identity. A GUID path is not permanent media identity: multiple paths may refer
to one volume, and formatting/reinstall can change it. Saved-only lookup and
completion perform no discovery. ReadyForMutation and RecoverySupported stay
false. No boot-role, physical-disk, mount-folder, protection or BitLocker inspection
is claimed. Q30 selection and D06 independent recovery requirements remain open.

Native PowerShell 5.1.26100.9711 and 7.6.5 each passed **48 tests**: 25 volume and
23 adapter tests, zero failures/skips/exclusions. All providers/context are mocked;
no workstation volume query or state change occurred. Adapter malformed-input
fixtures were corrected to pass prepared rows into module scope, removing a
false-positive path where a missing test factory could itself cause Unavailable.
Both editions passed validation of 346 operations/eight groups/five profiles/
169 PowerShell files. No catalog or support declarations changed.

Next acceptance: collect native disposable-target observations including missing
letters, offline/removable media and changed letters; investigate multiple GUID
paths before any multi-volume action. Fresh live resolution, boot/system roles,
dependencies, protection/recovery state and mutation remain separate work.
Recovery: retain collected evidence; source rollback removes this module/tool/test
and its guide links. No storage state needs restoration. The active package design
guide was reconciled with overnight authorization, without resolving Q01-Q04.

Resolved: narrow volume observation contract and adapter fixture accuracy.
Retired/excluded: none. Partial: resource identity preparation; no legacy outcome
accepted. Deferred: native provider/selection/boot/protection and all storage
mutations. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded
150-205/about 180. Presentation stays 40/279, 239 open. Other group outcomes and
controller/VM pins remain unchanged; continue independent batches.

## B01 power-control presentation, 2026-10-16

Source f53ce6ab102a plus the overnight patch. Seven existing IDs now describe
dedicated sleep-button AC/DC, display idle AC/DC, sleep idle AC/DC and advanced
Sleep-menu visibility separately. See [operator semantics](../setting-presentation.md#screen-off-sleep-and-button-choices).
The six PowerSetting entries are Configuration, not EnforcedPolicy; the menu is
a machine-scoped preference. Values, states, defaults, scope, handlers, profiles
and supported targets are unchanged. The menu reference/description now identify
the distinct documented policy path instead of citing sleep-button behavior.

The legacy button selectors combined menu plus two indexes; their reverse wrote
explicit Shown/Sleep. Timeout selectors combined four indexes, with reverse
10/5-minute display and 30/15-minute sleep presets. Index units are seconds while
legacy powercfg /change used minutes. None is a universal Windows default.
Never idle sleep does not prevent every sleep transition. The current handler
commits apply by reactivating the same plan; recovery retains the captured scheme
and does not switch away from a different currently selected plan. Screen saver,
sign-in/lock, brightness, hibernation and power-mode choices are separate.

Verified references: Microsoft [button indexes](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/power-button-and-lid-settings-sleep-button-action),
[display timer](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/display-settings-display-idle-timeout),
[sleep timer](https://learn.microsoft.com/en-us/windows-hardware/customize/power-settings/sleep-settings-sleep-idle-timeout),
[Windows 11 UI](https://support.microsoft.com/en-us/windows/experience/power-battery/power-settings-in-windows-11),
[idle-transition distinctions](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/display--sleep--and-hibernate-idle-timers)
and [ShowSleepOption policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsexplorer#showsleepoption).
The final page maps Software/Policies/Microsoft/Windows/Explorer, not the retained
FlyoutMenuSettings value. No current checkbox mapping or effective policy claim.
The menu ID remains outside the current profiles. No native power query or write.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed 122 existing presentation,
catalog and search tests; one WindowsIntegration case was excluded. Whole-catalog
comparison permits only seven presentation blocks and the menu description/link.
Generated operations are current; repository validation passed 346 operations,
eight groups, five profiles and 169 PowerShell files in each edition.

Next: implement the previously accepted additional button/duration choices with
capability checks, validate active-plan ordering and exact custom-state recovery,
then prove GUI/policy/physical transitions on suitable disposable targets. The
existing parser also depends on English powercfg labels; localized output and
unsigned index bounds need focused handler follow-up before broader claims.
Missing button indexes and S3/Modern Standby differences stay explicit, not pass.
Source recovery reverts only the seven presentation blocks/menu prose and
regenerates documentation; no Windows-state recovery is required.

Resolved: seven presentation reviews and whole-bundle reverse reconciliation.
Retired/excluded: none. Partial: power controls' user-visible evaluation. Deferred:
additional states, parser/index follow-up, GUI/policy/hardware/transition evidence.
Presentation is now 47/279, with 232 remaining. All five legacy ranges stay
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180: no legacy outcome
newly accepted, and packages/components/accounts/actions gain no runtime evidence.

## Power index capture and recovery repair, 2026-10-17

Source f53ce6ab102a plus the overnight patch. PowerSettings 0.2.0 replaces signed
hexadecimal conversion with UInt32 capture. Engine 0.20.3 no longer narrows live
indexes during named-state comparison or snapshot creation. New nested power
snapshots are version 1 with UInt32 encoding and AC/DC identity; outer run schema
stays unchanged. See [compatibility and recovery](../setting-presentation.md#power-index-record-compatibility).
Microsoft's [AC index API](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-powerreadacvalueindex)
declares a DWORD output; a full index is not a signed Int32.

The previous parser could encode high-bit hexadecimal values as negative values.
Unmarked historical Int32-range negatives are explicitly reinterpreted to their
original unsigned bits during recovery; original JSON remains untouched. New
marked negative values, unknown encodings/versions, invalid GUIDs, AC/DC mismatch,
strings, booleans, nulls, fractions and overflow refuse before native writes.
Commands format invariant unsigned decimal. Existing choices, profile selections,
support declarations, active-plan commit and saved-scheme recovery are unchanged.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed **44 focused tests**: 30 power
and 14 presentation cases, zero failures/skips/exclusions. Coverage includes
0/Int32.MaxValue/high-bit/UInt32.MaxValue capture, marked/unmarked JSON recovery,
different active-plan preservation, malformed-record rejection, Custom inspection
and isolated on-disk engine snapshots. Powercfg was mocked throughout. Both
editions passed repository validation: 346 operations/eight groups/five profiles/
169 PowerShell files. No workstation power query, write or suspend occurred.

Recovery: preserve original records and the corrected handler/engine until high
unsigned snapshots are recovered. The old engine cannot safely recover these
new high values; do not remove the corrected implementation as a substitute for
state recovery. Native reversible boundary fixtures, English-output replacement,
plan-switch races and physical transitions remain follow-up work. No arbitrary
high index should be written merely to prove parser range. Additional requested
button/duration choices remain separate from capturing custom values accurately.

Resolved: signed-narrowing defect and explicit compatible recovery path. Retired/
excluded: none. Partial: power lifecycle preparation. Deferred: native unsigned
recovery, locale-independent reads, GUI/hardware and expanded choices. All five
ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180;
no legacy outcome closes. Presentation stays 47/279, 232 open. Other groups gain
no new acceptance; controller and VM state remain untouched.

## Typed power read backend, 2026-10-17

Source f53ce6ab102a plus the overnight patch. PowerSettings 0.3.0 now uses the
internal RIDE.PowerRead 0.1.0 bridge for explicit GUID/UInt32 reads. It removes
English powercfg query-label parsing; powercfg remains only for existing writes
and commits. See the [operator/recovery contract](../setting-presentation.md#power-index-record-compatibility).
Production interop uses documented
[PowerGetActiveScheme](https://learn.microsoft.com/en-us/windows/win32/api/powersetting/nf-powersetting-powergetactivescheme),
[PowerReadACValueIndex](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-powerreadacvalueindex)
and [PowerReadDCValueIndex](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nf-powrprof-powerreaddcvalueindex).
Active GUID memory is released with LocalFree; imports restrict DLL search to
System32. Module import invokes no native query. No setter exists in the bridge.

The handler compares active GUID before/after a current-plan read and refuses
drift. Explicit saved-scheme inspection makes no current-plan query/selection.
Missing configuration (numeric file-not-found) stays Unavailable with its error;
it is not an inference about hardware. Access-denied/other failures throw numeric
diagnostics. The earlier UInt32/signed-record compatibility remains. Read-time
checks do not close later apply/commit races or establish effective managed policy.

Both native PowerShell 5.1.26100.9711 and 7.6.5 passed **63 focused tests**: 16 native
bridge, 33 power handler/engine and 14 presentation cases; zero failures/skips/
exclusions. Production C# compiled with an injected fake API. Tests release
allocated GUIDs on success/error/empty GUID, reject failed cleanup/null pointers,
preserve uint32/zero, route AC/DC/identities, distinguish missing/denied/other errors,
detect plan drift and retain existing snapshot recovery. No real PowrProf or
powercfg call occurred. Both editions passed repository validation: 346 operations,
eight groups, five profiles and 171 PowerShell files. Catalog/support unchanged.

Next: disposable native read comparison on applicable Windows targets and display
languages, missing-setting/error classification, same/different-plan recovery,
managed policy and real hardware acceptance. Keep the backend change source-ready
until those checks precede release activation. Do not run arbitrary high values
or suspend the workstation. Recovery preserves original runs and a compatible
UInt32 handler/engine; reverting the reader does not undo any setting or repair
an old engine's signed narrowing. No Windows state changed in this batch.

Resolved: language-dependent query parsing in source and active-read drift proof.
Retired/excluded: none. Partial: power inspection/recovery. Deferred: native API,
localized-target, hardware/GUI and write-race/extra-choice acceptance. Five ranges
stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180: no accepted
legacy closure. Presentation remains 47/279, 232 open; other groups and controller
pins are unchanged. Continue independent migration batches.

## B01 Explorer folder options presentation, 2026-10-17

Source f53ce6ab102a plus the overnight patch. Added preference presentation to
eight existing IDs: folder-merge-conflicts, navigation-pane-all-folders,
explorer-title-full-path, explorer-separate-process, restore-folder-windows,
sharing-wizard, item-selection-checkboxes and thumbnail-display (windows prefix).
No states, values, defaults, handlers, profiles or supported targets changed.
The checkbox DocumentationUri now points to Microsoft's focused
[File Explorer Classic reference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic).
It describes the option, not AutoCheckSelect. The older protocol's UseCheckBoxes
mapping was not substituted. FullPath, SeparateProcess and PersistBrowsers map
in GlobalFolderOptions; SharingWizardOn and IconsOnly map in its Vista variant.
These references do not establish current Windows 11 GUI or process semantics.

Legacy reconciliation against lib-windows.psm1: reverse selectors for folder
merge, all-folders, title path, restored windows and Sharing Wizard remove their
override. The current explicit Hidden/Disabled/Enabled alternatives remain stable;
WindowsDefault is the matching deletion path. Separate-process, checkboxes and
thumbnail pairs write explicit opposing values. Baseline/unset remove each
declared override; saved restore preserves captured data/type/absence. These are
independent controls, not an implicit Explorer bundle. Navigation expansion,
namespace icons, duplicate-file prompts, sharing permissions, thumbnail caching
and preview handlers are separate. No omitted adjacent behavior is declared done.

Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 each passed 122 focused
presentation/catalog/search tests, one WindowsIntegration case excluded. Whole-
catalog comparison admits only eight presentation blocks and one checkbox reference
since the prior batch. Repository validation passed on both editions: 347 operations,
eight groups, five profiles and 173 PowerShell files. Generation is current.
Tests use mocked/preview paths; no workstation registry, Explorer restart, file
copy/merge, share, sign-out or package acquisition occurred.

Next: in an intended-user disposable Windows 11 session, capture prior state,
preview/apply one control, compare actual GUI and reopening behavior, then restore
the exact run and verify both GUI and saved bytes. Use separate reversible fixtures
for duplicate-file/folder prompts, touch selection, local/virtual-folder titles,
multiwindow/tab process grouping, logon restoration, sharing UI and thumbnail
providers. Do not perform file replacement, permission changes, process termination
or sign-out without that scenario's authorization. Managed/default behavior remains
separate; no new Server scope is inferred. Source rollback removes only these
metadata blocks/reference edit and regenerates docs; it does not change Windows.

Resolved: eight presentation reviews and legacy reverse distinctions. Retired/
excluded: none. Partial: Explorer outcomes. Deferred: native GUI, managed, touch,
sign-in, process and provider acceptance. Presentation is now 55/279, 224 open;
this is separate from legacy closure. All five ranges stay 38-58 / 58-73 / 20-25 /
25-35 / 8-12, rounded 150-205/about 180, because no legacy behavior was accepted.

## B01 App Privacy policy presentation, 2026-10-17

Source f53ce6ab102a plus the overnight patch. Reviewed 17 existing machine-scoped
AppPrivacy controls: camera, microphone, background apps, voice activation and
voice activation while locked, notifications, account info, contacts, calendar,
phone calls, call history, email, tasks, messaging, radios, unpaired devices and
other-app diagnostic information. Added EnforcedPolicy presentation, corrected
15 descriptions that obscured policy/default coverage, clarified four display
names and focused 13 broad DocumentationUri links. Stable IDs, states, defaults,
handlers, profiles, targets and registry mappings are unchanged.

Read the local Windows AppPrivacy ADMX/English ADML as static policy evidence;
all 17 entries are Machine policies at the catalog key. Their enum data defines
0/1/2; fifteen have separate per-app lists, while the two voice policies do not.
Fetched the official [Privacy CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-privacy)
once and verified each exact value-name fragment. Local source/reference hashes
and mapping checks are retained in the [evidence](../archive/evidence/app-privacy-presentation-review-2026-10-17.json).
This establishes reference/mapping context, not current native behavior.

Legacy disable/enable pairs generally write 2/remove. Camera/microphone already
offer explicit 0/1 alternatives; other IDs remain two-state, without silently
adding choices. The voice selector wrote/removed both values. General and locked
activation are useful separate controls, with the latter dependent on the former.
The background selector's older-build branch changed HKCU per-app flags, and its
enable path removed those flags even when deleting the device policy. Current
operation owns only HKLM: historical user cleanup remains partial, not accepted.
Per-app exceptions, other privacy layers and desktop-program coverage are not
inferred from the stored default. No assistant installation, radio switching,
message deletion, cloud synchronization or telemetry outcome is claimed.

Both native Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 passed 122
focused presentation/catalog/search tests, one WindowsIntegration case excluded.
Whole-catalog comparison allows only these 17 presentation blocks and declared
reference/name/description changes. Both editions validated 347 operations/eight
groups/five profiles/181 PowerShell files; generated documentation is current.
No policy was applied, app restarted or native provider queried.

Next: on a disposable supported-edition Windows 11 target, capture one policy's
prior value and applicable exception lists without adopting those lists. Preview,
apply and compare a known covered app plus a separately chosen desktop app; verify
GUI editability, policy refresh and exact saved-run restore. Test per-app override
precedence separately. Voice acceptance needs a compatible installed app and
separate locked-session authorization. Background acceptance must distinguish
device default from existing user flags. Do not clear user flags as implicit
recovery. Baseline removal and exact captured restore are different scenarios.
Source rollback reverts only this metadata and regenerates OPERATIONS; saved runs
remain compatible. Windows recovery is unnecessary for this source-only batch.

Resolved: 17 presentation reviews and bundle/reverse semantics. Retired/excluded:
none. Partial: App Privacy/background outcomes. Deferred: covered-app, GUI,
managed-precedence, locked-session and user-flag acceptance. Presentation is now
72/279, 207 open. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180; no accepted legacy closure or expanded target support.

## B01 update and maintenance presentation, 2026-10-17

Source f53ce6ab102a plus the overnight patch. Eight existing controls gained
presentation: MSRT offering, driver quality-update exclusion, device metadata,
automatic-update download mode, automatic restart sign-in, two historical
maintenance-wake values and Microsoft-product updates. Four are EnforcedPolicy,
one Preference and three Unverified. Two wake display names now say experimental;
three descriptions and one reference were clarified. Stable IDs, registry paths,
states, defaults, profiles, handlers and targets remain unchanged.

The local WindowsUpdate ADMX maps AUPowerManagement to WindowsUpdate directly,
while RIDE retains the historical WindowsUpdate/AU subkey. The template places
that policy in PreSV with an older-release support declaration. The current
[AutomaticMaintenanceWakeUp policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#automaticmaintenancewakeup)
instead uses Policies/Microsoft/Windows/Task Scheduler/Maintenance/WakeUp. Neither
is silently substituted. Microsoft's [maintenance guide](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-maintenence)
documents behavior and wake prerequisites, not the historical non-policy value.
The MSRT reference describes the tool, without documenting DontOfferThroughWUAU.
All three current-build effects remain unverified. Both wake IDs are still in
profiles/default.psd1: preserve that unresolved recommendation/consumer gap.

The legacy driver bundle also wrote DriverSearching/SearchOrderConfig=0 and
removed it on reverse; device metadata and quality-update exclusion do not cover
that missing component. Local DeviceSetup ADMX retains the separate 0/1/2 search
choice. AUOptions=2/3 are only elements of Configure Automatic Updates; RIDE
does not own NoAutoUpdate. Legacy enabling removed AUOptions, not explicit 3.
MSRT Allowed=0 and restart-sign-in Enabled=0 likewise differ from reverse removal.
The restart-sign-in policy does not restart or unlock a machine; join state,
prior sign-out and separate mode/BitLocker conditions remain relevant.

The documented [AllowMUUpdateService preference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common)
is not proof of the old Microsoft.Update.ServiceManager AddService2/RemoveService
lifecycle. Legacy used service ID 7971f918-a847-4430-9279-4a52d1efe18d. The current
registry setting remains partial for service enrollment and does not invoke COM.
The wake bundle wrote both historical values to 0 and removed both on reverse;
each current capture/recovery remains independently owned.

Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 each passed 122 focused
presentation/catalog/search tests, with one WindowsIntegration exclusion. Both
validated 347 operations/eight groups/five profiles/186 maintained PowerShell
files. Whole-catalog comparison permits only eight presentation blocks and the
declared metadata edits; generated operation documentation is current. No native
update, wake, sign-in, service enrollment, VM or workstation change occurred.

Next: use a disposable, explicitly selected supported-edition target to capture
the prior values and relevant governing policy. Verify a known consumer and GUI
effect, repeat application, baseline removal and exact saved restore separately.
For wake, first resolve the key/consumer applicability and default-profile
recommendation; physical wake requires hardware/power-source acceptance. For
Microsoft Update, observe registration and checkbox correlation separately before
designing a service owner. Do not install updates or restart as an implicit test.
Source recovery reverts only this metadata and regenerates OPERATIONS; saved
state remains compatible. There is no runtime cleanup for this source-only run.

Resolved: eight presentation reviews and reverse/bundle/reference distinctions.
Retired/excluded: none. Partial: driver bundle, maintenance wake and Microsoft
Update enrollment. Deferred: MSRT/current-build consumer, GUI, managed, physical
wake and default-profile acceptance. Presentation is 80/279, 199 open. All five
ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180;
no accepted legacy closure or supported-target expansion.

## B01 security control presentation, 2026-10-17

Source f53ce6ab102a plus overnight changes. Added presentation for eight existing
controls: Shell SmartScreen, StandardProfile firewall, memory-integrity request,
Defender sample submission, UAC consent pair, tools/bootstrap path exclusions and
Controlled Folder Access. Corrected the UAC description and focused the firewall
reference on Microsoft's exact [EnableFirewall mapping](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpfas/2100c552-7f37-4a7f-9fa0-2a864ab87212).
IDs, states, handlers, defaults, target declarations and profiles are unchanged.

Legacy review: SmartScreen enabling removed the Shell override; explicit 1 is an
additional current choice. The historical EdgeHTML value remains excluded.
Firewall enabling removed the StandardProfile override; its modern effective
profile/merge outcome remains Unverified and separate from the modern profile
handler. Memory-integrity disabling also removed Enabled rather than writing 0.
The current request does not provision VBS or compatible drivers and does not own
UEFI locks or WasEnabledBy; running protection and GUI editability need evidence.
See Microsoft's [HVCI configuration](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#enable-memory-integrity-using-registry).

The cloud legacy selector paired reporting=0 with sample Never=2 and removed
both on reverse. The independently useful sample operation retains all four
existing literal choices. It owns preference only, not previously transmitted
files. The paired UAC low/high selectors match 0/0 and 5/1 exactly. The shared
secure-desktop setting can affect standard users' prompt placement; their
credential policy and EnableLUA are separate. SecureConsent is not maximum
always-notify. These distinctions follow the [UAC reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration).

Legacy tools-exclusion removal hard-coded C:\Tools even when adding used a custom
path. Current saved-path membership recovery avoids re-resolving that destination.
Directory creation is separate from membership; recovery does not delete folders
or tool-created content. Bootstrap resolves the executing account's Downloads,
which needs intended-user acceptance under alternate-account elevation. Current
default profile still requests both exclusions. Hidden/managed exclusion lists
are a retained observability gap, not proof of absence or accepted broad scanning
exemptions. Microsoft describes [exclusion visibility and management](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure).
Controlled Folder Access keeps the legacy explicit 1/0 plus existing audit=2;
allowed apps and protected folders remain independent, and it declares no baseline.

Both native PowerShell editions passed 122 focused presentation/catalog/search
tests (one WindowsIntegration exclusion) and validation of 347 operations/eight
groups/five profiles/186 PowerShell files. Full catalog comparison permits eight
presentation blocks, one description and one reference only. No protection,
firewall, prompt, exclusion, upload, reboot or other Windows state changed.

Next: disposable Windows 11 acceptance must inspect governing policy and intended
identity before selecting one control. Capture prior state, preview, apply, verify
the covered GUI/consumer, repeat, and restore the exact capture; test removal of
registry overrides separately. HVCI needs compatible hardware/boot recovery and
an explicitly authorized restart. Use harmless controlled test data for protection
checks. Never submit personal data merely to prove sample behavior. Exclusion
acceptance must establish visibility and preserve unrelated membership/content.
Source recovery reverts only this metadata and regenerates OPERATIONS; existing
saved-state formats remain unchanged.

Resolved: eight presentation reviews and bundle/reverse semantics. Retired/excluded:
no new outcome (existing EdgeHTML exclusion retained). Partial: legacy firewall,
HVCI request and exclusion ownership/visibility. Deferred: native GUI, effective
protection, hardware/boot, managed and default-profile acceptance. Presentation
88/279, 191 open. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180; no accepted legacy closure or target expansion.

## B01 Defender exclusion capture and recovery, 2026-10-17

Source f53ce6ab102a plus overnight changes. Review found that the engine captured
one resolved path, while the handler independently resolved it later without
comparing the capture. A changed tools/Downloads configuration could therefore
write a different exclusion from the saved recovery path. RIDE-Defender 0.2.0 and
engine 0.20.4 now compare captured path and Boolean membership before directory
preparation. Add rechecks membership after preparation; add/remove and restore
verify the provider's reported membership and propagate errors.

New inner snapshots use SnapshotVersion=1, OperationId, PathResolver, Path,
Present and ExpectedPresent; the outer run-record schema remains unchanged.
Restore validates identity/version and uses the literal saved path without
re-resolving current configuration. A no-change versioned capture owns no later
membership. Valid older Boolean/path captures remain readable. Missing paths,
non-Boolean flags, unknown versions and redirected identities refuse mutation.
Fully qualified literal directory validation also rejects drive/share roots,
device/relative/wildcard/alternate-stream paths and unresolved variables. Old
unsupported broad/pathless records stay intact for separately evidenced manual
recovery, rather than silently adopting today's resolved path.

The provider wrapper distinguishes a missing object/property from a valid null
visible list. Hidden/managed lists are still an observability gap; the change
does not establish absence of managed membership, raw list-token ownership,
effective scanning, reparse-target identity or an atomic provider transaction.
No automatic policy changes are introduced to expose hidden data. Folder creation
can precede an add failure and remains outside membership recovery; no content is
deleted. Existing default-profile exclusions and target declarations are preserved.

Both native Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 passed 109
focused recovery/catalog tests (one WindowsIntegration exclusion). Cases cover
capture-to-write path/membership drift, directory-preparation drift, ignored
writes, exact captured-path recovery, JSON round-trip, idempotent retry, unsafe
paths, malformed versions/identities/provider shapes, engine snapshot fields and
ShouldProcess forwarding. Older catalog mocks were adjusted to model successful
membership changes so post-write checks test real state transitions. Validation
passed for 347 operations/eight groups/five profiles/187 PowerShell files in both
editions. No Defender provider or writer ran against the workstation.

Next: use the [operator procedure](../setting-presentation.md#defender-exclusion-capture-and-recovery)
on a disposable target with an independently verified visible local exclusion
list. Select a harmless temporary subdirectory, capture, preview, apply, repeat,
remove and restore; verify both native membership and preservation of unrelated
entries/content. Exercise a configuration-path change between capture/write and
an ignored/tamper-managed write without disabling protection. Keep alternate
account, hidden-list and wildcard/alias semantics separate. Do not use a broad
tools exclusion as an automatic prerequisite for package acceptance.

Source recovery must revert module/engine together. Existing valid old records
remain usable; retain new records and a compatible reader before any downgrade.
Resolved: captured-target gap and reported-success verification in source.
Retired/excluded: none. Partial: exclusion ownership and native observability.
Deferred: native/managed/GUI/default-profile acceptance. Presentation remains
88/279, 191 open. All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12,
rounded 150-205/about 180; no accepted legacy closure or support expansion.

## B01 desktop and Explorer visibility presentation, 2026-10-17

Source f53ce6ab102a plus overnight changes. Fourteen existing operations gained
presentation: five system desktop icons, PaintDesktopVersion, all desktop icons,
empty drives, navigation auto-expansion/Libraries, sync-provider notifications,
Explorer start location and two thumbnail-cache requests. Three names and three
descriptions now identify uncertain behavior or reverse semantics; four reference
URLs were focused. Registry paths, states, baselines, defaults, targets, profiles
and saved-state contracts are unchanged. Presentation is 102/279, 177 open.

Legacy comparison uses legacy/v2/lib-windows.psm1. Recycle Bin Shown removed the
override; the other four icon Hidden selectors removed it. Current explicit 0/1
choices differ, while WindowsDefault preserves removal. ClassicStartMenu remains
excluded; NewStartPanel rendering is still subject to the separate all-icons
switch. Its Visible=0/Hidden=1 pair matches the legacy, and baseline explicitly
writes 0. The [Microsoft desktop guide](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-desktop-icons-in-windows)
describes GUI choices rather than GUID registry mappings. PaintDesktopVersion
1/0 matches the legacy, but the About reference does not establish label rendering;
the control is now explicitly experimental/Unverified.

Empty-drive Hidden and Libraries Hidden now write 1 and 0 respectively; legacy
reverse removed each override. WindowsDefault remains the removal choice. Navigation
auto-expansion retains 1/removal. These are independently useful views; none
removes drives, library definitions or files. The [settings schema](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic)
documents the options, while the [namespace property reference](https://learn.microsoft.com/en-us/windows/win32/properties/props-system-ispinnedtonamespacetree)
defines Boolean pinning, not the exact Libraries CLSID registration. Sync-provider
Visible removes its override whereas legacy Show wrote 1; default-profile Hidden
is retained. This does not stop provider sync or all Windows notifications.

Explorer Home=2 is the current explicit baseline, unlike the legacy QuickAccess
reverse removal. The [Explorer guide](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows)
explains the Home rename and GUI landing-page choice, not numeric LaunchTo mapping.
No additional location was assigned a guessed numeric state or added to a profile.

Both cache selectors retain legacy 1/removal, but actual current cache behavior
is Unverified. The [Group Policy Preferences specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f)
names DisableThumbnailCache under Explorer/Advanced; its XML-attribute wording
does not establish current consumer behavior or polarity. For network thumbnails,
the [documented ADMX policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-thumbnails#disablethumbsdbonnetworkfolders)
uses Software/Policies/Microsoft/Windows/Explorer, unlike the retained Advanced
path. A read-only inspection of the workstation Thumbnails.admx agrees on that
policy path; this is template evidence, not runtime acceptance. The same value
name does not establish equivalent behavior. Stable IDs and captured paths cannot
be silently reassigned. Both cache controls remain in the existing default profile;
this is an explicit recommendation/behavior gap, not approval of effectiveness.
Their TargetDefaults are retained historical declarations requiring later evidence.

Native Windows PowerShell 5.1 and PowerShell 7 each passed 122 focused
presentation/catalog/search tests (one integration exclusion) and validation of
347 operations/eight groups/five profiles/190 PowerShell files. Whole-catalog
comparison permits only these fourteen metadata blocks and the declared name,
description and reference edits. No desktop, Explorer, cache, network share,
profile, process, sign-in or Windows state was changed.

Next procedure: on the intended disposable Windows 11 account, capture a single
operation, preview/apply, inspect the matching GUI and actual view, repeat and
restore the saved value/type/absence. Test explicit baseline versus override
removal separately where declared. Check all-icons interaction with an individual
system icon, removable media for empty drives and provider participation for
notifications. Do not restart Explorer or sign out without separate acceptance.
Cache investigations need disposable content and traceable reads/writes; literal
registry round trips do not close the outcome. Decide a distinct documented
network-cache policy migration/retirement with preserved legacy recovery before
changing its mapping or profile recommendation. Source recovery reverts only this
metadata and regenerates OPERATIONS; runtime recovery remains the existing capture.

Resolved: fourteen presentation reviews and whole-selector reverse analysis.
Retired/excluded: no new outcome; ClassicStartMenu exclusion retained. Partial:
sync/start reverse differences, version labels and both cache consumers. Deferred:
GUI/media/provider/native cache and default-profile acceptance. All five ranges
remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180 because
no remaining legacy outcome received native acceptance or new target support.

## B03 persistent user PATH observation and recovery, 2026-10-17

Accepted Q08 distinguishes the existing runtime-specific startup renderer from
persistent user PATH, with folder/content preservation on removal. Added
RIDE.UserPathPreparation 0.1.0: explicit machine/SID/session observation of literal
HKCU Environment/Path and in-memory append/recovery. No setter, process PATH
mutation, machine environment access, broadcast, directory action or catalog ID.

Capture keeps missing/empty/kind distinctions, reads without expansion, disposes
handles on errors and rechecks identity/profile. Append preserves raw original
text and owns only a newly appended absolute bin token. Equivalent pre-existing
tokens remain unowned. Unknown expansions are review cases, never resolved using
the developer process. Recovery reconstructs snapshot version 1, restores exact
original value when unchanged, preserves unrelated token edits, and refuses
modified/equivalent-duplicate ownership conflicts. It never deletes the Environment
key, directory or contents. Native existence, effective PATH and durable mutation
are not established; ReadyForMutation remains false.

All 44 distinct focused tests passed on each native PowerShell edition. Initial
runs discovered 41 tests because an InModuleScope block ran before module import;
that container failure is retained and was not accepted as a clean run. Windows
PowerShell also rejected one test's oversized single path during normalization
before its intended total-PATH limit assertion. The fixture now uses many short
entries and imports during discovery. The four affected/missing cases then passed
on both editions; previously passed unrelated cases were not rerun. Static
validation passed 347 operations/eight groups/five profiles/205 maintained files.
No actual user PATH/registry observation or Windows mutation was performed; mocked
handles and synthetic records supplied all runtime inputs.

Next: bind authenticated durable state and live compare/write/post-state guards,
verify existing bin and inherited/machine PATH coexistence, implement bounded
environment refresh and partial-failure recovery, then disposable lifecycle and
new-process acceptance. Keep startup-only migration independent. Current API
recovery is preparation only; source rollback removes module/tests/guidance with
no Windows rollback. Operator procedure is in [profile guidance](../powershell-profiles.md#persistent-user-path-preparation).

Resolved: literal observation and entry ownership/recovery contract. Retired or
excluded: none. Partial: persistent user PATH; deferred: durable native lifecycle,
refresh, filesystem identity and acceptance. No legacy closure. All five ranges
stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180. Presentation
remains 102/279, 177 open.

## B01 visual effects and first sign-in presentation, 2026-10-17

Source f53ce6ab102a plus overnight changes. Eight existing operations gained
presentation: drag contents, menu delay, minimize/restore animation, selection
rectangle, desktop-label shadows, Peek, taskbar animation and first-sign-in policy.
One name, one description and two reference URLs changed. Registry paths, state
values/types, baselines, target/default declarations, profiles and recovery remain
unchanged. Presentation is 110/279, 169 open; eighty additions in this window.

Compared both complete SetVisualFXPerformance/SetVisualFXAppearance selectors.
Their seven visual values match the explicit current choices. Baseline/unset and
WindowsDefault remove each override instead of selecting Appearance. Keyboard
delay was reviewed separately; the packed UserPreferencesMask and common
VisualFXSetting=3 remain outside these controls. No whole-bundle equivalence,
performance benefit or accessibility recommendation follows from seven writes.
Four values without current mapping evidence remain Unverified; Peek's name now
also identifies the experimental legacy request.

The [SystemParametersInfo reference](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow)
and [ANIMATIONINFO](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-animationinfo)
describe drag, cascading-menu delay and minimize/restore behavior, not these
direct registry writes. The [DWM overview](https://learn.microsoft.com/en-us/windows/win32/dwm/dwm-overview)
does not document EnableAeroPeek. The current taskbar support page places the
Peek workflow in its Windows 10 section; it supplies no Windows 11 acceptance.

The exact [first-sign-in policy mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowslogon#enablefirstlogonanimation)
replaces a broad ADMX link. It covers animation and Microsoft-account service
prompts; Server has no animation. Legacy Enable removed the value, whereas
current Enabled writes 1. WindowsDefault preserves removal, whose behavior
differs between initial setup and later added users. Existing generic defaults
remain a separate evidence gap; the CSP default is not proof of literal registry
presence on every supported image. No account or session was changed.

Validation: both Windows PowerShell 5.1 and PowerShell 7 passed 122 focused
presentation/catalog/search tests, with one WindowsIntegration exclusion. Both
passed repository validation: 348 operations, eight groups, five profiles and
206 PowerShell files. Whole-catalog comparison permits only the eight new
presentation blocks and declared metadata changes. Cumulative comparison retains
the eight pending additions and eighty reviewed presentation blocks; every other
baseline catalog field/group is unchanged. Generated OPERATIONS was refreshed.

Next procedure: in a disposable Windows 11 desktop, capture each original value
and active visual behavior, preview/apply each explicit state, compare immediate
and subsequent-session effects, and restore exact prior type/value/absence. Cover
contrast/theme and independently rendered applications; do not restart the shell
on the developer workstation. For first-sign-in, use disposable new local and
Microsoft-account scenarios only when their account/credential use is authorized;
verify managed precedence and initial-versus-later user behavior separately.
Record unresolved mappings rather than closing them on registry round trips.
Source recovery reverts only this metadata and regenerates OPERATIONS.

Resolved: eight presentation reviews and whole-selector reverse analysis.
Retired/excluded: none in this batch; Q17/Q20 product retirements remain counted.
Partial: visual session effects, packed-bundle coverage and new-user behavior.
Deferred: GUI, policy precedence, account and target acceptance. All five ranges
remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175. No native
legacy outcome or new supported target was accepted.

## B01 read-only session visual observations, 2026-10-17

Implemented RIDE.VisualEffectsInventory 0.1.0. Five explicit kinds cover
DragFullWindows, MenuShowDelay, MinimizeAnimation, UiEffects and
ClientAreaAnimation. The C# bridge accepts only reviewed GET actions, including
at its native entry; System32 DLL search is fixed. Scalar calls use zero parameter
and flags; ANIMATIONINFO initializes both its size and the corresponding native
size argument. The eight-byte structure and four-byte second-field offset were
verified with fake calls. No setter, registry fallback, refresh or shell launch.

Schema-1 observations bind the expected native machine/build/edition/user/session
before and after sequential collection. A changed context discards all output.
Per-provider errors retain unavailable status and null value; native failure
with error zero remains failure. Nonzero Win32 Boolean bits are preserved and
interpreted as true; menu delay retains UInt32 through its maximum. Failed or
malformed/partial output cannot become a successful zero. No GUI/effective-policy,
recovery or mutation readiness claim is added; imports and completion make no
native visual calls. Documentation includes explicit invocation and interpretation.

Validation: 40 focused tests passed in each of Windows PowerShell 5.1 and
PowerShell 7. These cover the real compiled interop with an injected fake API,
fixed actions, layout, unsigned values, no-error failure, wrong context, drift,
duplicate/selected providers, completion and malformed/partial failure isolation.
No SystemParametersInfo request or live registry observation ran. Both editions
passed repository validation for 348 operations/eight groups/five profiles/208
PowerShell files. Existing presentation tests were not rerun without a relevant
presentation change. Presentation remains 110/279, 169 open.

Next: invoke selected GETs in the authorized disposable user's native desktop,
compare with independent GUI behavior and separately captured registry values,
repeat across the target's session lifecycle, and retain all unavailable or
disagreeing observations. Actual API and Windows-build acceptance remain open.
Do not turn a successful GET into acceptance of the corresponding registry
setter or full visual-effects bundle. Source recovery removes this unused module
and its fixture/documentation; it has changed no runtime state.

Resolved: read-only session observation and failure contracts. Retired/excluded:
none. Partial: visual-effects migration and whole-bundle review. Deferred: native,
GUI, policy and refresh acceptance. All five ranges remain 38-58 / 56-71 / 20-25 /
25-35 / 8-12, rounded 145-200/about 175, because no legacy outcome closed.

## B01 network control presentation, 2026-10-17

Thirteen existing controls gained presentation: unidentified-network category,
private-network device setup, ICS, Explorer Network enumeration, both NCSI inputs,
LLMNR, Server/workstation administrative shares, linked UAC drive mappings, WinHTTP
WPAD, Remote Assistance and Remote Desktop. Two names, three descriptions and
five reference URLs changed. Registry mappings, declared states, baselines,
defaults, profiles, support and recovery are unchanged. Presentation is 123/279,
156 open; ninety-three additions in this window.

The [ICS policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-networkconnections#nc_showsharedaccessui)
documents both configuration and service restrictions. This supersedes earlier
UI-only descriptions. Read-only inspection of installed Microsoft
NetworkConnections.admx (SHA-256
31B755D0DEC40ACF3C9B7260A2087379E3C75AE5C0BDC965BF9973EE4B77E3FB)
confirmed Machine scope, the existing key/value and policy-enabled=0/disabled=1.
No live policy or service was queried. The stable Hidden/Available states remain,
but their broader meaning is visible. Actual enforcement is still unaccepted.

Legacy Public-network, Enable-device-setup, Show-Network, Enable-ICS,
Enable-NCSI and Disable-linked-drive selectors removed their values. Current
explicit states instead write 0/1; WindowsDefault preserves those old reverses.
LLMNR, WPAD and administrative-share reverses already match removal. The fixed
network signature, device AutoSetup and NonEnum mappings remain Unverified.
The Network List Manager link redirects to archived Windows 10 guidance; no
Windows 11 applicability is inferred from it.

The [LLMNR mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient#turn_off_multicast)
corrects the misleading legacy MulticastDNS selector name; mDNS is separate.
The [WinHTTP reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features#how-to-disable-wpad)
retains other-application and direct-DNS boundaries. The [NCSI reference](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network)
documents both values; legacy/v2 contains NoActiveProbe but no EnableActiveProbing
write. Treat the pair as separate controls within an incomplete outcome, not two
resolved legacy items. Passive probing is outside both controls.

The [administrative-share troubleshooting reference](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/problems-administrative-shares-missing)
actually names AutoShareWks, correcting the prior claim that Microsoft only
documents its Server analogue. Its Server scope still does not prove Windows 11
behavior. Legacy paired both values; published target-specific IDs retain their
split. Service interruption, actual shares and dependent administration remain
acceptance work. The [server removal guide](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/remove-administrative-shares)
excludes IPC$ and manually created shares. The [linked-drive reference](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/mapped-drives-not-available-from-elevated-command)
does not cover unrelated credential sessions; no restart or drive mapping occurred.

Remote Assistance's [unattended-setting reference](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-remoteassistance-exe-fallowtogethelp)
describes behavior rather than the retained registry location. Its new name avoids
claiming a managed policy. Legacy also added/removed Quick Assist capability;
that behavior remains separate. Remote Desktop legacy toggled RemoteDesktop*
firewall rules as well as fDenyTSConnections. The current setting implements only
the latter; [host prerequisites](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access)
remain explicit, including edition, service, authentication and firewall.

Validation: 122 presentation/catalog/search tests passed in each native PowerShell
edition with one WindowsIntegration exclusion. Both repository validations passed:
348 operations/eight groups/five profiles/208 PowerShell files. Whole-catalog
comparison allows only these thirteen presentation blocks and declared metadata
changes; cumulative comparison retains eight pending additions and ninety-three
presentation blocks with all other baseline fields/groups unchanged. Generated
OPERATIONS was refreshed. No native network, service, share, remote connection,
credential, installer or VM action occurred.

Next: use isolated disposable targets and an independent recovery path. Capture
typed values and actual policy/service/UI/peer behavior; preview each explicit
state and exact saved restore, including managed conflict. Keep credentials and
remote enablement under explicit acceptance, test service restarts only where
authorized, and do not disable the sole management connection. Record LLMNR versus
mDNS and WinHTTP versus other proxy behavior independently. Source recovery reverts
only metadata and regenerates OPERATIONS; runtime recovery retains existing captures.

Resolved: thirteen presentation reviews, ICS description and documented reference
gaps. Retired/excluded: none. Partial: bundled discovery/sharing/remote access and
current mapping effects. Deferred: network/GUI/managed/service/peer acceptance.
All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about
175, because no additional legacy outcome was completed.

## Accepted remaining decisions and R29 bookkeeping closure, 2026-10-17

Reconciled [Q25-Q31](decision-session-2026-10-17.md) into the active settings and
remaining-migration plans. ADR 0001 now accepts RIDE as sole configuration writer
and LoggingBaseline as read-only consumer; no other repository was changed.
Reviewed Store groups stay first; dynamic lists are a deferred extension.
Destructive maintenance is explicit and previewed with backup/checkpoint where
required; only specifically defined disposable-cache cleanup may omit backup.
Explorer/input, then Server sign-in/shutdown, then app/hardware acceptance is the
selected order. Menu controls lacking reliable content/ACL recovery remain visible
but unavailable with guidance. Audio/adapter/volume selection captures stable
identity; explicit current-default audio resolves and retains its actual device.
Missing resources never cause fallback during mutation or recovery.

Q31/D09 closes R29 User .NET assemblies as unsubstantiated bookkeeping. The
[bounded source audit](#unidentified-entry-source-audit-and-closure-path-2026-10-11)
is retained without claiming all historical/custom sources were exhausted. Reopen
on a source or defined use case. This is neither feature retirement nor successful
migration. The audit explicitly prevented adding a numerical legacy outcome from
the label, so no estimate subtraction is justified. No assembly/runtime/data was
changed. Resolved: decision dispositions and this bookkeeping issue. Retired or
excluded: none. Other settings remain partial/deferred pending implementation and
native/GUI/resource recovery. Presentation stays 123/279, 156 open. All five ranges
remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## B10 read-only desired-configuration reference, 2026-10-17

Implemented RIDE.DesiredConfiguration 0.1.0 and Export-RideDesiredConfiguration
0.1.0 for accepted Q25/ADR 0001. The schema-1 reference binds exact built-in catalog
and explicit profile hashes, retains stable IDs/source order and declared target
platform/build/edition/role/installation type, and marks the consumer read-only.
RegistryValue/RegistryValueSet retain declared path/name/type and distinct
SetValue/RemoveValue/KeepCurrent intent, with explicit baseline resolution and no
environment expansion. Other handlers and groups remain ReportOnly; package
variants/destinations/scope are not resolved. No raw handler/property/store data
is copied. All live state/compliance is Unknown; target metadata comparisons are
not native availability or policy precedence. Measurement thresholds remain separate.

The standalone exporter validates source data, refuses source hash drift, bounds
profile/output sizes and creates output exclusively. WhatIf reads no source or live
state. Completions use repository profiles and the same catalog's target names;
the API completes from its supplied catalog. Role/installation choices use their
declared sets. No engine/handler, Windows query, network, installer, local preference
or private review store is invoked. Existing state/recovery schemas are untouched.
See the [operator procedure and schema](../desired-configuration-reference.md).

Validation: 37 distinct tests passed per native PowerShell edition. Initial test
fixture misuse of PowerShell's automatic args variable and script completion path
resolution caused failures; the fixture was renamed and completers now resolve
the observed command AST path. Three initial passing export cases were retained;
31 corrected/affected cases, two new race/drift cases and one API completion case
passed in focused follow-ups. No unrelated passed suite was rerun. Tests cover
actual default-profile export, exact hashes, zero/empty/absence, array identity,
KeepCurrent, unsupported/pending/Core/minimum-build status, invalid/duplicate
selections, redaction-by-omission, no-query preview, exclusive output races, source
drift and completion. Repository validation passed on both editions for 348
operations/eight groups/five profiles/216 PowerShell files; final additive completion
was parsed and tested in both editions. Local links/diff whitespace were checked.

Next: review this versioned contract with the separately maintained read-only
consumer, bind its intended target/user and registry views, and test observation/
comparison in disposable Windows targets. Unknown mappings must remain visible
and never execute reference contents. Actual security/logging operation selection
and writers require their own lifecycle/recovery work. No other repository was
edited. ReadyForMutation/RecoverySupported remain false; partial files are retained
and a fresh output name is the recovery path. Unsupported future schema versions
must be refused, with pinned source retained to reproduce old reference meaning.

Resolved: source export/completion contract. Retired/excluded: none. Partial:
configuration ownership integration. Deferred: consumer/native mapping, additional
handlers and actual logging/security selection. Presentation stays 123/279, 156
open. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded
145-200/about 175; a read-only export closes no legacy outcome.

## B01 logon and boot presentation, 2026-10-17

Twelve existing controls gained presentation: boot-status recovery, lock screen,
verbose status, attachment zones, sign-in network selection, shutdown before logon,
Fast startup, crash restart, sign-in acrylic background, F8 boot menu, DEP and secure
attention. Presentation is 135/279, 144 open; 105 additions in this window. Two names,
four descriptions and four focused reference URLs changed. Stable IDs, states,
baselines, defaults, target declarations, profiles and handlers remain unchanged.

The published F8 Standard and DEP OptIn states remove their BCD overrides; neither
explicitly writes its namesake. Legacy DisableF8BootMenu and SetDEPOptIn did write
Standard/OptIn. Descriptions now expose this difference. The [BCD reference](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set)
documents each explicit choice, but historical default tables do not prove all
current image defaults. Existing target-default metadata is retained for separate
native evaluation. IgnoreAllFailures also covers failed shutdown/checkpoints and
does not disable Windows RE. Boot-status write/removal matches the legacy pair.

The [acrylic policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon#disableacrylicbackgroundonlogon)
has an exact current Microsoft mapping; the initial page lookup missed its section,
and the focused recheck found it. Read-only Logon.admx inspection confirmed machine
scope and key/value (SHA-256 C29C524C23659AB3D7F7CB46E23BB18657648D4B17E4239DE4EC78CF365E4827).
The display name now says sign-in background. Published Enabled and its baseline
remove the policy; effective blur is not guaranteed. No ADMX or live policy changed.

Legacy verbose-status behavior branches on ProductType: client Enable writes 1,
Disable removes; Server Enable removes, Disable writes 0. Current explicit 0/1
states differ from those removal branches. WindowsDefault retains removal, and no
Server support is added. The [verbose policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-logon#verbosestatus)
can be suppressed by the separate remove-status-messages policy.

Legacy Enable-lock-screen, Enable-download-blocking and Show-sign-in-network
removed overrides; current explicit Enabled, Preserve and Shown write 0, 2 and 0.
Their WindowsDefault states retain removal. The RS1 lock-screen task is not restored.
Attachment-zone policy affects future metadata, not existing MOTW or SmartScreen.
Shutdown, Fast startup, crash restart and Ctrl+Alt+Delete retain their legacy numeric
pairs. The [secure-attention reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions#interactivelogon_donotrequirectrlaltdel)
now points to the current policy and makes reversed label polarity visible.
Hibernation/hardware/policy prerequisites, dump configuration and signed-in rights
remain separate from these individual controls.

Validation: 122 presentation/catalog/search tests passed in each native PowerShell
edition, with one WindowsIntegration exclusion each. Both repository validations
passed for 348 operations/eight groups/five profiles/219 PowerShell files. Focused
whole-catalog comparison allows only the twelve presentation blocks and declared
metadata changes; cumulative comparison retains eight pending additions and 105
presentation blocks with every other baseline field/group unchanged. Generated
OPERATIONS refreshed. No BCD, registry, sign-in, boot, crash or VM action occurred.

Next: use separately authorized disposable Windows 11 targets with independent
recovery media/access and encrypted-volume keys. Capture literal values and actual
effective policy/UI; test repeat apply, baseline versus exact saved restore, absent
overrides and managed conflicts. Schedule boot/sign-in/crash acceptance explicitly;
never infer it from registry round trips or automatically disable security controls.
Source recovery reverts only this metadata and regenerates OPERATIONS; runtime
recovery retains existing versioned captures. Review native BCD defaults separately.

Resolved: twelve presentation reviews and misleading state descriptions. Retired
or excluded: none. Partial: legacy reverse equivalence and native user-visible
outcomes. Deferred: boot/sign-in/managed-policy/hardware acceptance. All five ranges
remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no additional
legacy outcome is complete.

## B01 suggestion and input presentation, 2026-10-17

Nineteen existing controls gained explicit Unverified presentation: four broad
ContentDeliveryManager preferences, nine numeric subscription channels, Settings
pane and post-setup suggestions, three input-personalization preferences and the
TIPC diagnostic-sample preference. Presentation is 154/279, 125 open; 124 additions
this window. Only TIPC's name, description and reference changed beyond adding
presentation. Stable IDs, states, baselines, defaults, targets, profiles and
handlers remain unchanged. No numeric channel received an invented feature label.

The [Spotlight reference](https://learn.microsoft.com/en-us/windows/configuration/windows-spotlight)
describes the feature area, not these CDM mappings. The [recommendations reference](https://support.microsoft.com/en-us/windows/privacy/privacy-settings-for-recommendations-offers-in-windows-11)
and [notification reference](https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows)
likewise describe related UI without proving SystemPaneSuggestionsEnabled or
ScoobeSystemSettingEnabled. Keep these experimental settings outside recommended
profiles pending current-build comparisons and independently useful effects.

The whole legacy DisableAppSuggestions/EnableAppSuggestions pair was reconciled.
Five channels (310093, 314559, 338387, 338393, 353698) and Scoobe were removed by the
legacy reverse; current Enabled=1 differs, while WindowsDefault retains removal.
The other four channels and broad CDM preferences used explicit 0/1 pairs. Omitted
PreInstalledAppsEverEnabled bookkeeping, machine Windows Ink Workspace suggestions,
CloudStore binary trimming and ShellExperienceHost termination are not implicitly
restored by these individual settings. Their combined historical outcome remains
partial; nineteen presentation rows are not nineteen completed legacy outcomes.

The Cortana bundle used RestrictImplicitTextCollection/RestrictImplicitInkCollection
1/0, matching current numeric pairs. Its HarvestContacts reverse removed the value;
current Enabled=1 differs, WindowsDefault matches removal. Cortana app registration,
search UI, speech policies and other bundle actions remain separate. The
[personalization reference](https://support.microsoft.com/en-us/windows/privacy/speech-voice-activation-inking-typing-and-privacy)
documents learned-word behavior without verifying each mapping. Registry restoration
cannot recover training data Windows may delete; acceptance must consider that effect.

TIPC's previous description promised that all relevant data stopped being sent.
It now describes the actual write and its uncertainty. Disabled writes Enabled=0;
published Enabled and baseline remove the value, not write 1. Legacy
DisableInkingAndTypingData supplied that write without a paired reverse. The
[focused diagnostics reference](https://support.microsoft.com/en-us/windows/privacy/diagnostics-feedback-and-privacy-in-windows)
documents the related Improve inking and typing UI, not the registry mapping.
Personal dictionaries and diagnostic sampling remain distinct. Community answers
were not treated as authoritative proof of the mapping.

Validation: 122 presentation/catalog/search tests passed in each native PowerShell
edition with one WindowsIntegration exclusion each; both repository validations
passed for 349 operations/eight groups/five profiles/223 PowerShell files. Focused
whole-catalog comparison permits only these nineteen blocks and the one operation's
three metadata changes. Cumulative comparison retains nine pending additions and
124 presentation blocks, with other baseline fields/groups unchanged. OPERATIONS
was regenerated. No registry, cache, process, training data or machine state changed.

Next: use an explicitly selected disposable Windows 11 account/build to compare
literal values, related UI and observable outcomes, including absent overrides and
managed conflicts. Evaluate whether split channels represent useful independent
controls before recommendation. Preserve source/learned-data recovery boundaries;
do not execute the legacy bundle. Source recovery reverts only this presentation
and three TIPC metadata fields, then regenerates OPERATIONS; runtime recovery uses
existing captured registry values and cannot restore deleted training data.

Resolved: nineteen presentation reviews and overstated diagnostic wording. Retired
or excluded: none newly. Partial: whole legacy bundles and numeric-channel meaning.
Deferred: current UI, managed-policy and training-data acceptance. All five ranges
remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no additional
legacy outcome is complete.

## B01 application feature presentation, 2026-10-17

Nine controls gained presentation: OneDrive file-storage policy, three legacy Media
Player policies, two local development preferences and three gaming controls.
Presentation is 163/279, 116 open; 133 additions this window. Two development
descriptions and reference URLs changed; stable IDs, states, baselines, defaults,
target declarations, profiles and handlers remain unchanged.

The [OneDrive policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system#disableonedrivefilesync)
documents the exact mapping and effects beyond sync, including app/Explorer access.
Legacy EnableOneDrive removed the override; Allowed=0 is explicit, WindowsDefault
matches removal. Existing client configuration, tenant controls and cloud/local data
remain separate. No OneDrive client or content was changed.

The [Media Player policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-windowsmediaplayer)
documents sharing and the two metadata restrictions. UserChoice=0 permits user
control rather than forcing sharing or retrieval. Legacy reverses removed these
values; WindowsDefault retains that behavior. The whole online-access bundle also
changed radio presets and WMDRM; their existing experimental candidates retain
separate acceptance. Modern Media Player, component presence and upstream retrieval
service availability are not established by these policy writes.

A focused [Microsoft development-security reference](https://learn.microsoft.com/en-us/windows/apps/dev-tools/winapp-cli/security#what-enabling-it-changes)
now directly documents AllowDevelopmentWithoutDevLicense and AllowAllTrustedApps.
The former permits development package registration from folders; the latter permits
trusted signed packages outside the Store. Their literal configuration is now
distinguished from the full Developer Mode UI, companion values, certificate trust
and OS component state. The [current Settings guide](https://learn.microsoft.com/en-us/windows/advanced-settings/developer-mode)
places the controls under System > Advanced from Windows 11 25H2. Microsoft recommends
the Settings workflow for disabling associated state; an isolated registry write
must not claim equivalent cleanup. Legacy Enable wrote both values as 1; Disable
removed both. Current Disabled=0 differs, WindowsDefault retains removal.

The whole Xbox bundle removed/re-registered six Appx identities as well as changing
Game Mode, the user recording value and machine recording policy. Game Mode's reverse
removed its value; user recording used 0/1; machine policy reverse removed its value.
Current explicit Enabled/Allowed therefore differ for two of the three controls.
App registration remains separate. The [AllowGameDVR reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationmanagement#allowgamedvr)
still expressly limits enforcement to Windows 10 desktop despite its broader table.
All three gaming mappings retain Unverified presentation on declared Windows 11;
the user preference and Game Mode lack direct mapping references. Newer Xbox mode
is not inferred to be the same feature.

Validation: 122 presentation/catalog/search checks passed per native PowerShell
edition, with one WindowsIntegration exclusion each. Both repository validations
passed for 355 operations/eight groups/five profiles/224 PowerShell files. Focused
catalog comparison allows only nine presentation blocks and the four development
metadata fields. Cumulative comparison permits fifteen pending additions and 133
presentation blocks, preserving every other baseline field/group. OPERATIONS updated.

Next: compare app/UI behavior on explicitly selected disposable Windows 11 builds,
with relevant components and managed conflicts. Capture original registry type/value/
absence, distinguish override removal from explicit reverse and protect app/cloud
data. Test development feature state/cleanup separately before recommending a full
workflow. Source recovery reverts only this presentation/metadata and regenerates
OPERATIONS; saved registry restore is not application-data or component-state recovery.

Resolved: nine presentation reviews and development-reference ambiguity. Retired or
excluded: none newly. Partial: whole bundle equivalence and native app behavior.
Deferred: policy/GUI/component/cloud-data acceptance. All five ranges remain 38-58 /
56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no new legacy outcome closed.

## B01 Start, taskbar and notification presentation, 2026-10-17

Sixteen existing controls gained presentation. Coverage is 179/279, 100 open;
149 presentation additions this window. Three names, 9 descriptions and two
reference URLs changed to expose legacy removal states and uncertain current UI.
Stable IDs, state values, baselines, defaults, targets, profiles and handlers did
not change. No Explorer restart, sign-out, application launch or pin change occurred.

The [taskbar guide](https://support.microsoft.com/en-us/windows/experience/personalization/customize-the-taskbar-in-windows)
describes visible alignment, search, Task View and combining choices, not the retained
registry mappings. Current search has an icon-and-label choice absent from the three
legacy values; Box=2 is not assumed to prove the current box label. Task View and
Widgets visibility is separate from the feature's keyboard access/content. Primary
and secondary combining remain separate operations, with multi-display prerequisites.

Legacy center alignment removed TaskbarAl; current Centered=1 differs and
WindowsDefault preserves removal. Legacy primary/secondary Always, Task View/People/
Widgets/Chat Visible, tray Automatic and clock Hidden used removal, matching their
current published states. Metadata now makes that literal effect visible instead of
implying a forced positive/negative value. Both Task View selector pairs were aliases
of one value; this does not represent two independent virtual-desktop features.

PeopleBand, TaskbarMn and NoAutoTrayNotify are named as legacy experimental controls.
The reviewed current references do not establish a present People/Chat feature or a
supported Windows 11 show-all-tray mapping. The [People Bar policy](https://learn.microsoft.com/en-us/windows/configuration/taskbar/policy-settings)
is distinct from PeopleBand. These retained IDs do not recreate old shell features,
install Teams, change current app pins or redefine a contacts feature.

Alt+Tab state names preserve the legacy 3/1/2/0 writes for none/five/three/all tabs.
The [multitasking reference](https://support.microsoft.com/en-us/windows/how-to-multitask-in-windows-b4fa0333-98f8-ef43-e25c-06d4fb1d6960)
does not verify each current numeric count. AllRecentTabs must not imply an unlimited
current-build mode. Clock-seconds removal similarly does not force a literal zero.

The [Start policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-start)
documents recently-added/most-used mappings and applicable editions/refresh needs.
Legacy Show removed each override; current UserChoice/Allowed=0 differs, while
WindowsDefault matches. Other usage-tracking and policy choices can still suppress
the most-used list. The [Run as policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-startmenu#showrunasdifferentuserinstart)
confirms user scope. The current HKCU operation intentionally differs from legacy
HKLM; it does not own or remove an old machine-hive write or launch another identity.

The [Notification Center policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-taskbar#disablenotificationcenter)
is separate from notification banners. Legacy DisableActionCenter wrote both it and
ToastEnabled, and the reverse removed both. The individual operations preserve those
literal choices, while ToastEnabled remains an unverified preference mapping. Do not
equate hiding the center with stopping banners or every app's notifications.

Validation: 122 presentation/catalog/search checks passed per native PowerShell
edition with one WindowsIntegration exclusion each. Both repository validations
passed for 355 operations/eight groups/five profiles/224 PowerShell files. Focused
whole-catalog comparison permits only sixteen presentation blocks and the declared
metadata fields; cumulative comparison permits fifteen pending additions and 150
presentation blocks, preserving every other baseline field/group. OPERATIONS updated.

Next: compare literal state and actual UI on selected disposable Windows 11 builds,
including multi-display conditions, managed conflicts, absent overrides and current
search/Alt+Tab choices. Keep shell refresh explicitly scheduled; do not infer feature
presence from successful registry writes. Preserve published states until an explicit
migration/recovery decision changes semantics. Source recovery reverts only this
metadata and regenerates OPERATIONS; runtime recovery uses captured registry state.

Resolved: sixteen presentation reviews and misleading positive-state wording.
Retired/excluded: none newly. Partial: legacy bundle equivalence and current shell
behavior. Deferred: UI/build/multi-display/managed acceptance. All five ranges remain
38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175; no legacy closure.

Final count reconciliation, 2026-10-17: direct catalog enumeration found sixteen, not seventeen, members in the last Start/taskbar batch. Presentation is 179/279, 100 open, with 149 additions this window. The earlier prose tally was corrected; no operation, state, test outcome, target or legacy estimate changed. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.

## Morning settings handoff, 2026-10-17

The [consolidated handoff](remaining-migrations-follow-up.md#morning-handoff-2026-10-17) records the closed 08:00 window. Presentation is 179/279, 100 open, with 149 additions this window; latest 122 checks passed per edition and final repository validation covers 358 operations/eight groups/five profiles/224 PowerShell files. No new native/GUI/hardware acceptance or legacy closure is inferred. All five ranges remain 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175. Retain partial bundles, exact state recovery and the accepted next validation order.

## B01 service startup and runtime presentation, 2026-10-17

Six existing service controls gained presentation; coverage moves from 179 to
185/279 (94 open). SysMain naming now identifies its historical Superfetch name.
UPnP wording exposes a legacy reverse difference; SSDP/UPnP documentation links
now point to focused startup-policy sections. No handler, state, default, target,
scope or profile changed. A whole-catalog comparison permits only the six blocks
and declared name/description/reference edits.

Legacy DiagTrack, SysMain and SSDP reverse intent matches the explicit current
automatic/start or manual/start choices. Legacy WAP Push and Search reverses
also wrote DelayedAutoStart=1: AutomaticDelayedRunning represents that intent,
whereas published AutomaticRunning preserves delay. Legacy UPnP enable selected
Manual with Start-Service commented out; current Enabled starts now. That startup-
only alternative remains unimplemented for this ID, without silently changing its
published state. Explicit presets are not defaults or saved-state restoration.

Microsoft's [delayed-start API](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info)
supports the scheduling distinction; its [service overview](https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server)
is Server 2016 guidance, not proof of Windows 11 defaults or a performance/privacy
recommendation. The [UPnP/SSDP policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-systemservices)
documents startup controls, not live workloads. The [Intune sync issue](https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-management/cannot-sync-windows-10-devices)
documents a Windows 10 WAP Push dependency; current managed-client acceptance
remains separate. No service, task, policy or developer-machine configuration ran.

Procedure: inspect show/plan and the generated operation details before selecting
an explicit state. Use saved-run restore for captured state; no unset or factory-
default claim is introduced. Recovery of this source-only batch is a focused
metadata revert plus regenerated OPERATIONS; runtime recovery remains the existing
versioned handler contract and does not undo unowned workload side effects.

Both native PowerShell editions passed 122 focused presentation/catalog/search
checks with one WindowsIntegration exclusion. Source comparison proves unrelated
catalog behavior unchanged. No new native, GUI, boot, workload or policy acceptance.
Resolved: six service presentations; total 185/279, 94 open.
Retired/excluded: none. Partial: broader legacy bundles/current workload meaning.
Deferred: actual target/GUI/dependency acceptance and outstanding product choices.
Next: continue remaining presentation and independent source integration, preserving
unresolved meanings and published lifecycle semantics. All five ranges were reviewed
unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.
Presentation review closes no additional whole legacy outcome.

## B01 scheduled-task presentation, 2026-10-17

Thirteen existing scheduled-task controls gained presentation identifying exact
Task Scheduler locations, the enablement flag, missing-task behavior and recovery.
Actions, triggers, definitions, task identities, state values, targets and profiles
did not change. Existing semantic uncertainty remains explicit: task names and
API success do not establish a complete current privacy or maintenance outcome.

The nine task members of DisableTelemetry/EnableTelemetry are independent from
their registry companions: AllowTelemetry in three paths, preview-build and
licensing-ticket overrides, SQM/AppV CEIP, AIT/inventory and handwriting/linguistic
policies. The reverse enabled all nine tasks; it removed most registry overrides
but wrote 3 to two legacy AllowTelemetry paths. No full bundle equivalence is
claimed. Office service monitoring remains maintenance, separately from both
Office 2016 telemetry tasks and current Office policy/installation acceptance.
Feedback's two tasks are separate from frequency and notification policy; error
queue scheduling is separate from WER policy/service; ScheduledDefrag enablement
does not select a disk or request optimization now. Those legacy task directions
used enable/disable, not definition deletion or captured-state restoration.

The [disable](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/disable-scheduledtask?view=windowsserver2025-ps),
[enable](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/enable-scheduledtask?view=windowsserver2025-ps)
and [Enabled property](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasksettings-enabled)
references establish the control API, not the current payload of each named task.
Bare cmdlet pages were unavailable to the reader; the explicit documented view
was available. Generated references use that verified view. Enabling permits
existing triggers; it is not a no-execution guarantee. RIDE sends no Start/Stop
request and captures only enablement, not definitions, history or workload output.

Procedure: inspect show/plan and the generated operation details before selecting
an explicit state. Use saved-run restore for captured state; no unset or factory-
default claim is introduced. Recovery of this source-only batch is a focused
metadata revert plus regenerated OPERATIONS; runtime recovery remains the existing
versioned handler contract and does not undo unowned workload side effects.

Both native PowerShell editions passed 122 focused presentation/catalog/search
checks with one WindowsIntegration exclusion. Source comparison proves unrelated
catalog behavior unchanged. No new native, GUI, boot, workload or policy acceptance.
Resolved: thirteen task presentations; total 198/279, 81 open.
Retired/excluded: none. Partial: broader legacy bundles/current workload meaning.
Deferred: actual target/GUI/dependency acceptance and outstanding product choices.
Next: continue remaining presentation and independent source integration, preserving
unresolved meanings and published lifecycle semantics. All five ranges were reviewed
unchanged at 38-58 / 56-71 / 20-25 / 25-35 / 8-12, rounded 145-200/about 175.
Presentation review closes no additional whole legacy outcome.

## B01 scheduled-task observation and readback, 2026-10-17

RIDE-ScheduledTasks 0.2.0 rejects missing/non-Boolean live enablement before capture
or mutation, rejects non-Boolean availability in recovery snapshots, and re-reads
the exact task identity after enable/disable and restore. Disappearance, denied
inspection, unexpected identity or a mismatched flag cannot silently report success.
Idempotent matching states make no write. No task creation, deletion, Start or Stop
request is introduced. Existing snapshot structure remains unchanged; correctly
typed serialized snapshots remain usable.

Two regressions were reproduced against an isolated HEAD module copy with corrected
inert fixtures: missing Enabled was coerced to false, and an ignored disable call
returned success. The repaired source passes all 20 selected tests per native
edition (16 new recovery checks plus four existing exact-task checks). Seven
unrelated system-preference cases were not selected. Initial harness failures were
corrected: Pester path-option concatenation failed before discovery; fixture state
was initialized in a different script scope; one unfiltered PS7 run also could not
resolve the unrelated Get-MpPreference mock target. No host Defender or task change
was attempted. Final focused validation does not claim the unrelated suite passed.

Both Windows PowerShell 5.1 and PowerShell 7 passed repository validation for
358 operations/eight groups/five profiles/225 PowerShell files. The task handler
has no new native acceptance: these are mocked source checks. A readback error can
follow an actual write at deployment; inspect state and the engine's saved run
before retrying or restoring. Readback is point-in-time and cannot undo workload
effects or prevent later definition/enablement changes. Source recovery is a
focused revert; retain versioned pre-change state for real target recovery.

Latest decision reconciliation: CCleaner-family installed distributions are primary,
reviewed official portable choices are separate, and unavailable variants have no
substitution. The common shared-installer/licence-tier decision supersedes earlier
edition wording: entitlement-only tiers do not require separate installation
variants or mandatory tier selection; preserve activation unless an explicit
supported change is requested. Apply this to TMOG, CCleaner-family and WinHex when
publisher evidence establishes shared artifacts/behavior. TMOG startup/screensaver
remain separate; Kernel PST/OST viewers remain separate with mailbox preservation;
WinHex and historical tools retain their explicit scope and technical gates.
BitLocker/recovery test setup and new deployment-profile selection are explicitly
deferred. Preserve existing profiles and do not infer forensic-first defaults.
The separate decision ledger remains authoritative for product-specific details.

Resolved: malformed-state refusal and verification after task writes/restores.
Retired/excluded: no additional whole legacy outcome in this run. Partial:
task workload/policy meaning, full offline source/dependency/install integration
and remaining collection migration. Deferred: native/GUI/driver tests and the
explicit profile, recovery-resource and CE-backend decisions. Next: remaining
81 setting presentations and reviewed collection/source integration; run native
acceptance only with the required disposable-target resources and authority.
All five ranges were reviewed unchanged: 38-58 / 56-71 / 20-25 / 25-35 / 8-12,
rounded 145-200/about 175. Shared handler hardening closes no whole legacy outcome.

## B01 remaining presentation review: explorer-namespace, 2026-10-17

Sixteen controls: seven This PC namespace registrations, seven mirrored ThisPCPolicy preferences, shortcut suffix and the All Tasks desktop folder. Namespace roots and actual folder contents remain separate. ThisPCPolicy and binary shortcut naming remain Unverified. Legacy 3D Objects show removes overrides; published Visible writes Show. Empty-folder recovery includes ACL and timestamps and refuses content/redirection conflicts. Microsoft namespace/known-folder/link references were reviewed as mechanism or background evidence, not proof of current CLSID rendering.

Catalog schema validation passed. Presentation is **218/279; 61 remain**.
Runtime behavior, IDs, targets, defaults and profile selections are unchanged.
Native VM acceptance remains blocked: this session has no elevated Hyper-V CIM
access. No controller, VM pin, Windows setting or package was changed. Acceptance
requires a disposable declared target: capture prior state, preview, exercise each
state and repeat, inspect the actual feature and managed precedence, restore the
saved run and verify the original state, then recover the pinned checkpoint.
Retain feature-specific limits above; registry round trips do not prove GUI effects.

Resolved: source presentation only. No whole legacy outcome resolved, retired or
excluded. Native outcomes remain partial/deferred. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**;
presentation coverage is a separate counter. Next: Review the twelve network profile, binding, SMB, NetBIOS and firewall controls.

## B01 remaining presentation review: network-controls, 2026-10-17

Twelve controls: seven adapter bindings, current network category, SMB1 and SMB2/3 flags, NetBIOS and local RDP firewall rules. Legacy SMB server enable leaves SMB1 unchanged; NetBIOS enable writes DHCP/default 0, not explicit 1. Binding changes may restart adapters and couple other flags. Private/Public applies to all reported non-domain profiles. Local rule flags do not establish effective policy, RDP host support or reachability. Native peer, disconnect/reconnect, mixed-state and stable-identity recovery tests remain pending.

Catalog schema validation passed. Presentation is **230/279; 49 remain**.
Runtime behavior, IDs, targets, defaults and profile selections are unchanged.
Native VM acceptance remains blocked: this session has no elevated Hyper-V CIM
access. No controller, VM pin, Windows setting or package was changed. Acceptance
requires a disposable declared target: capture prior state, preview, exercise each
state and repeat, inspect the actual feature and managed precedence, restore the
saved run and verify the original state, then recover the pinned checkpoint.
Retain feature-specific limits above; registry round trips do not prove GUI effects.

Resolved: source presentation only. No whole legacy outcome resolved, retired or
excluded. Native outcomes remain partial/deferred. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**;
presentation coverage is a separate counter. Next: Review privacy, diagnostic data, app access and activity-history controls.

## B01 remaining presentation review: privacy-and-history, 2026-10-17

Twenty-one controls: diagnostic/linguistic data, feedback/WER, sensors/biometrics, recent history, four app capability consent stores, background overrides, tailored experiences, three activity policies, website language/shared experiences and two AppCompat policies. ConsentStore and legacy user mappings remain Unverified. Local StartMenu/Biometrics ADMX confirms scope/mapping without claiming runtime behavior. Activity cloud-upload UI deprecation is explicit. Whole telemetry/background/history legacy bundles remain distinct; policy restoration cannot recover deleted history or transmitted data. Four capability references moved to the current Microsoft package-and-deploy page; focused activity/tailored anchors were verified.

Catalog schema validation passed. Presentation is **251/279; 28 remain**.
Runtime behavior, IDs, targets, defaults and profile selections are unchanged.
Native VM acceptance remains blocked: this session has no elevated Hyper-V CIM
access. No controller, VM pin, Windows setting or package was changed. Acceptance
requires a disposable declared target: capture prior state, preview, exercise each
state and repeat, inspect the actual feature and managed precedence, restore the
saved run and verify the original state, then recover the pinned checkpoint.
Retain feature-specific limits above; registry round trips do not prove GUI effects.

Resolved: source presentation only. No whole legacy outcome resolved, retired or
excluded. Native outcomes remain partial/deferred. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**;
presentation coverage is a separate counter. Next: Review power, BitLocker and compatibility/platform controls.

## B01 remaining presentation review: power-and-bitlocker, 2026-10-17

Seven controls: hardware-clock interpretation, enhanced PIN permission, startup-authentication gate, legacy encryption method, AC/DC lid actions and existing scheme selection. Local VolumeEncryption.admx/ADML restricts EncryptionMethod to Vista/Windows 7-era targets; presentation is Unverified and its description no longer promises Windows 11 encryption behavior. Stable ID, target declaration and saved recovery identity remain for a separate compatibility/migration correction. No encryption/recovery setup is authorized by this review. Legacy local-clock reverse removes the override; Local=0 is explicit. Lid acceptance requires physical hardware; a VM alone is insufficient.

Catalog schema validation passed. Presentation is **258/279; 21 remain**.
Runtime behavior, IDs, targets, defaults and profile selections are unchanged.
Native VM acceptance remains blocked: this session has no elevated Hyper-V CIM
access. No controller, VM pin, Windows setting or package was changed. Acceptance
requires a disposable declared target: capture prior state, preview, exercise each
state and repeat, inspect the actual feature and managed precedence, restore the
saved run and verify the original state, then recover the pinned checkpoint.
Retain feature-specific limits above; registry round trips do not prove GUI effects.

Resolved: source presentation only. No whole legacy outcome resolved, retired or
excluded. Native outcomes remain partial/deferred. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**;
presentation coverage is a separate counter. Next: Review the eleven remaining platform and compatibility preferences.

## B01 remaining presentation review: platform-compatibility, 2026-10-17

Eleven controls: fullscreen GameConfigStore bundle, Storage Sense, Recycle Bin, Delivery Optimization, swap file, Windows Script Host, PAC URL, long paths, account warning and two .NET Framework views. Internal mappings remain Unverified. Storage Sense no longer implies legacy recursive preference deletion; Recycle Bin reversal cannot recover deleted content. Empty versus absent PAC URL does not restore a prior URL. .NET descriptions now distinguish application target-framework defaults from installed runtime versions. Long-path application opt-in and refresh limits remain explicit. UWP suspension reference moved to its current Microsoft path.

Catalog schema validation passed. Presentation is **269/279; 10 remain**.
Runtime behavior, IDs, targets, defaults and profile selections are unchanged.
Native VM acceptance remains blocked: this session has no elevated Hyper-V CIM
access. No controller, VM pin, Windows setting or package was changed. Acceptance
requires a disposable declared target: capture prior state, preview, exercise each
state and repeat, inspect the actual feature and managed precedence, restore the
saved run and verify the original state, then recover the pinned checkpoint.
Retain feature-specific limits above; registry round trips do not prove GUI effects.

Resolved: source presentation only. No whole legacy outcome resolved, retired or
excluded. Native outcomes remain partial/deferred. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**;
presentation coverage is a separate counter. Next: Review the final ten shell, accessibility, search and Edge controls.

## B01 remaining presentation review: shell-accessibility-and-edge, 2026-10-17

Reviewed ten controls. Accessibility IDs retain whole Flags presets, not verified prompt-only switches: their paired values differ by API hotkey bit 0x4 while retaining 0x8 and omitting feature-on bit 0x1; API documentation is not proof of the registry-string contract. Corrected new-app notification meaning and linked exact Store lookup/deletion-confirmation policy mappings. Repaired the missing Search CSP fragment with Microsoft connection-management guidance. Edge URL formatting uses the mandatory user policy and excludes Microsoft-account profiles; Edge installation shortcuts have separate channel overrides and no effect on existing installations. Source review is complete; no runtime accessibility, search, shell or installer behavior was exercised.

Catalog schema validation passed. Presentation is **279/279; 0 remain**.
Runtime behavior, IDs, targets, defaults and profile selections are unchanged.
Native VM acceptance remains blocked: this session has no elevated Hyper-V CIM
access. No controller, VM pin, Windows setting or package was changed. Acceptance
requires a disposable declared target: capture prior state, preview, exercise each
state and repeat, inspect the actual feature and managed precedence, restore the
saved run and verify the original state, then recover the pinned checkpoint.
Retain feature-specific limits above; registry round trips do not prove GUI effects.

Resolved: source presentation only. No whole legacy outcome resolved, retired or
excluded. Native outcomes remain partial/deferred. All five estimates remain
**38-58 / 56-71 / 20-25 / 25-35 / 8-12**, rounded **145-200/about 175**;
presentation coverage is a separate counter. Next: Generate the catalog reference, validate both native PowerShell editions and retain feature-specific VM acceptance gates.

## B01 presentation review completion, 2026-10-17

Completed the authorized remaining **77 setting presentation reviews**, moving
coverage from **202/279 to 279/279**. The six batches above cover namespace (16),
network (12), privacy/history (21), power/BitLocker (7), platform compatibility
(11), and shell/accessibility/Edge (10). The [machine-readable evidence](../archive/evidence/remaining-presentation-reviews-2026-10-17.json)
records every reviewed ID, behavior classification, reference, source hash,
description/reference correction and native gate. Unverified classifications are
review outcomes, not successful feature acceptance.

Semantic comparison against the captured start-of-turn catalog passed: exactly
77 presentation additions and the declared description/reference corrections.
IDs, states, handlers, targets, defaults, profiles and prior presentations remain
unchanged. The existing default profile still selects the legacy BitLocker
EncryptionMethod value; its modern-target compatibility/recommendation requires
a separate correction preserving recovery identity. Accessibility presets still
replace complete Flags strings. Neither issue is hidden by completed coverage.

Validation on native Windows PowerShell **5.1.26100.9711** and PowerShell **7.6.5**:

- SettingPresentation, Catalog and Search: **122 distinct checks pass per edition**;
  one WindowsIntegration test is excluded. Initial runs each passed 121 and failed
  the obsolete BitLocker description assertion. Corrected that existing assertion
  to require Unverified behavior and the legacy/current-target caveat. Catalog
  reruns passed all 70 checks per edition; the other 52 passing checks are retained.
- Generated docs/OPERATIONS.md through tools/Export-RideCatalog.ps1. Both validators
  passed **358 operations, eight groups, five profiles and 227 PowerShell files**,
  including generated-reference consistency. The test-only assertion correction
  was subsequently parsed and executed by both Pester runtimes.
- Catalog schema validation passed after each batch. The final semantic comparison
  and focused diff review preserve pre-existing unrelated working-tree changes.

**Blocked native acceptance:** the previously observed non-elevated Hyper-V CIM
access denial still prevents the disposable-target run. No retry, elevation bypass,
controller/pin change, VM mutation, workstation setting change or installation was
performed. Physical lid/sleep acceptance needs suitable hardware even after VM
access is available. BitLocker/recovery resource setup and new profile composition
remain explicitly deferred; no further permission was requested for these reviews.

Next procedure, from the repository root with Windows-native tools: use the
[existing validation resume matrix](settings-validation-resume.md) and the individual
catalog requirements to select a declared target and one feature family. Once an
authorized elevated disposable target is available, verify its identity and pinned
checkpoint, capture prior values and managed state, preview the chosen operation,
apply each relevant state and repeat, inspect the actual UI/consumer, then restore
the captured run and compare exact prior state. Exercise partial failure and
identity changes where the family requires them. Recover the checkpoint after the
scenario. Record target/build/edition, actor, observed effects and recovery evidence
before changing acceptance. Registry readback alone does not pass this gate.
For networks retain console access and a controlled peer; for deletion/history
use disposable data; for Edge use the relevant profile/channel/installation case.
Compatibility corrections need their own reviewed mapping and recovery migration.

Resolved: all 77 requested source presentations. Retired/excluded: no additional
legacy outcome. Partial: native behavior, managed precedence and exact target
recovery. Deferred: unavailable VM/hardware acceptance and the explicit resource/
profile decisions. All five ranges remain **38-58 / 56-71 / 20-25 / 25-35 / 8-12**,
rounded **145-200/about 175**. No whole legacy outcome was deducted. The overview
and active continuation documents now distinguish completed presentation from the
remaining implementation and acceptance queue.

## B03 user-bin native prerequisite attempt, 2026-10-17

The authorized continuation ran the existing `UserBinPath` scenario on
RIDE-Win11-Test with its unchanged registered checkpoint. Host access is now
available. Run **be21c647ec6247d0be626b4ddd45e019** reached guest preparation and
refused because **C:\Program Files\PowerShell\7\pwsh.exe is absent** in the clean
checkpoint. The scenario requires both installed runtimes and explicitly does
not acquire/install prerequisites. No profile/startup case ran; this is not a
profile-handler failure or acceptance pass.

The host retained the source manifest and failure result, then reported
**ResetAndOff**. Raw evidence is
`.local/user-bin-vm-acceptance-20261017/be21c647ec6247d0be626b4ddd45e019/result.json`
and `.local/user-bin-vm-20261017T101645Z.log`. Existing VM/checkpoint pins and
controller registration were preserved; no Defender-blocked tool was selected.
The earlier non-elevated Hyper-V diagnosis is superseded for this attempt by the
missing guest-runtime prerequisite. Prepare both runtimes in an explicitly scoped
disposable prerequisite workflow before repeating the same startup case; no new
checkpoint or production profile is implied.

Resolved: concrete prerequisite diagnosis and successful checkpoint recovery.
Whole legacy outcomes resolved/retired/excluded: **none**. User-bin startup stays
partial; PowerShell 7 prerequisite and native startup remain pending. Persistent
PATH, directory provisioning, WindowsApps and explicit profile/resource deferrals
remain separate. All five ranges stay **38-58 / 56-71 / 20-25 / 25-35 / 8-12**,
rounded **145-200/about 175**; this failed prerequisite closes no legacy outcome.

## B03 user-bin local prerequisite runner preparation, 2026-10-22

Updated the checkpoint-backed profile runner so `-Scenario UserBinPath` may use
the same optional `-PowerShellArtifactPath` as the Colors scenario. When the
Windows 11 guest lacks PowerShell 7, the guest validates that the artifact and
MSI are under the current run directory, the URI is an official PowerShell
GitHub release MSI, its SHA-256 matches, and Authenticode identifies Microsoft
Corporation. It then uses quiet `msiexec` with `/norestart` and `ADD_PATH=1`.
The controller retains the prerequisite result and follows its existing reboot,
evidence collection and pinned-checkpoint recovery path. No guest UAC policy is
changed and no network acquisition is available in this path. If PowerShell 7
is already installed, no prerequisite is installed; if absent and no local
artifact is supplied, preparation fails before startup acceptance.

The three edited PowerShell files parsed successfully. The focused UserBinPath
profile lifecycle, profile metadata and runner boundary suites passed **65/65**;
these are local checks, not VM acceptance.
The session cannot inspect RIDE-Win11-Test through Hyper-V CIM or write its
protected registered queue, so this runner was not executed in the VM and no
startup behavior is accepted. Existing checkpoint state is unverified. No
whole legacy outcome was resolved, retired or excluded; B03 remains partial.
All five estimate ranges remain **38-58 / 54-69 / 20-25 / 25-35 / 8-12**,
exact **145-199**, rounded **145-200/about 170**. The former prerequisite
failure evidence remains available above as the reason for adding this path.

Evidence: [sanitized runner preparation record](../archive/evidence/user-bin-local-prerequisite-runner-preparation-2026-10-22.json).
## Hash value context-menu source follow-up, 2026-10-22

The [upstream tutorial](https://www.elevenforum.com/t/add-hash-value-to-context-menu-of-files-in-windows-11.22212/)
was updated 2026-09-25. It describes an all-user file verb, requires
administrator approval for adding or removing it, and notes that Windows 11
places it under Show more options. Its forum thread documents a double-space
issue in an earlier command form and an apostrophe regression in a suggested
workaround; the author updated the tutorial. The retained commands still
rebuild the path from echoed text, so unusual file-name behavior needs direct
Explorer testing. They also keep each command window open for one hour.

A synthetic local probe passed a filename containing double spaces, an
apostrophe, ampersand, percent sign and Unicode directly to
`Get-FileHash -LiteralPath`. Windows PowerShell 5.1 accepts all seven listed
algorithms. PowerShell 7.6.5 accepts MD5, SHA1, SHA256, SHA384 and SHA512, and
rejects MACTripleDES and RIPEMD160 at parameter validation. The supplied command
invokes `powershell`, which selected Windows PowerShell 5.1 in the test
environment. This proves local cmdlet handling only; it does not validate
Explorer substitution or menu behavior. The attached `.reg` was not executed,
no user file was read, and no registry or VM was changed.

Resolved: current upstream scope/placement claims, local cmdlet algorithm
availability, and adaptation source requirements. Partial: the new candidate
implementation; current Explorer path behavior remains unverified.
Deferred: Windows 11 GUI acceptance, including Shell path substitution, unusual
filenames, menu placement, repeat apply, removal and exact saved-run restore.
No supported target is claimed. This requested v3 setting is additional scope,
not a completed legacy migration. The five migration ranges remain
**38-58 / 53-68 / 20-25 / 25-35 / 8-12**, exact **144-198**, rounded
**145-200/about 170**. See the [sanitized evidence](../archive/evidence/hash-value-submenu-source-review-2026-10-22.json)
and [source notes](../../examples/hash-context-menu/README.md).

## Hash value context-menu candidate implementation, 2026-10-22

Added `tools/Get-RideHashValue.ps1` and candidate operation
`windows.hash-value-context-menu`. The helper receives the selected path through
an argument and calls `Get-FileHash -LiteralPath`; Windows PowerShell 5.1 is
explicitly selected because it supports the requested MACTripleDES and
RIPEMD160 algorithms that PowerShell 7 rejects. Results appear together in one
message box, including errors, without the upstream one-hour console sleep or
writing a report. The operation uses 17 coordinated per-user registry values
through `RegistryValueSet`, with the existing exact saved-state capture and
restore behavior. All dynamic command-path tokens are restricted and resolved
by the handler; the disabled state is an empty registry set.

The export check passed and repository validation passed for 373 operations,
eight groups, five profiles and 243 PowerShell files. The focused Pester suite
passed 5 tests with one skip in PowerShell 7 and 6/6 in Windows PowerShell 5.1.
Pester's optional TestRegistry plugin was disabled because sandbox policy denied
its HKCU test fixture. A fresh `Get-VM -Name RIDE-Win11-Test` call returned CIM
access denied; no registry or GUI action was performed. Explorer placement,
argument substitution, unusual filenames, repeat, removal and exact restore
remain unverified, so the operation has no supported target.

Resolved: owned helper, explicit runtime, per-user candidate mapping and local
handler/unit coverage. Retired/excluded: none. Partial: additional requested v3
setting candidate. Deferred: complete Windows 11 GUI and registry lifecycle
acceptance. This adds no completed legacy outcome and is outside the legacy
279-presentation count; all migration estimates remain unchanged. See the
[sanitized implementation evidence](../archive/evidence/hash-value-submenu-candidate-implementation-2026-10-22.json).

## Certutil SHA-256 context-menu candidate implementation, 2026-10-22

Added `windows.sha256-certutil-context-menu` as the optional single-command
counterpart to the multi-algorithm submenu. It registers a per-user icon and
command under `HKCU:\Software\Classes`, keeps the corrected icon resource
declaration, uses the supplied Certutil command, and restores exact prior values
through the `RegistryValueSet` handler. The default state removes only the two
declared values. The catalog marks it a Windows 11 candidate with no supported
targets until native acceptance.

The focused context-menu Pester suite now passes 7 tests with one PowerShell 7
skip and 8/8 in Windows PowerShell 5.1. Catalog validation passes for 374
operations, eight groups, five profiles and 243 PowerShell files; the generated
operation reference is current. The optional Pester TestRegistry plugin was
disabled because sandbox policy denied HKCU fixture access. `Get-VM -Name
RIDE-Win11-Test` returned CIM access denied. No registry write, command launch or
GUI test occurred. Icon rendering, placement, percent/apostrophe/Unicode path
handling, repeat, unset and exact saved-run restore remain pending.

Resolved: candidate catalog mapping and local handler coverage. Retired/excluded:
none. Partial: this requested optional v3 setting. Deferred: Windows 11 GUI and
registry lifecycle acceptance. It closes no legacy outcome and leaves all five
estimate ranges unchanged; it is outside the 279-item legacy presentation count.
See the [sanitized candidate evidence](../archive/evidence/certutil-context-menu-candidate-implementation-2026-10-22.json).

## Context-menu candidate cross-edition regression, 2026-10-22

The focused ExampleLibrary, CustomRegistryAuthoring and HashValueContextMenu
suites passed 50 tests with one skip in PowerShell 7 and 51/51 in Windows
PowerShell 5.1. Pester's optional TestRegistry plugin was disabled, and TEMP/TMP
were rooted under `.local/pester-temp` in the writable repository. These tests
cover example parsing, custom-library authoring and mocked registry handler
capture for both context-menu candidates; they do not exercise Explorer UI or
write Windows registry values.

An initial 122-test combined run that also included `Catalog.Tests.ps1` used the
sandbox's protected Windows Temp path: 110 passed, 11 failed and one skipped.
Failures were environment exceptions for HKCU security-descriptor access,
package artifact fixture writes and atomic library moves. The isolated rerun did
not include `Catalog.Tests.ps1`; full catalog Pester acceptance therefore
remains open even though catalog export and repository validation pass. The
Hyper-V VM remains inaccessible, so GUI and native registry lifecycle remain
deferred. No legacy outcome closed and estimates remain unchanged. See the
[cross-edition test evidence](../archive/evidence/context-menu-candidate-cross-edition-regression-2026-10-22.json).

## B03 persistent user PATH guarded write preparation, 2026-10-23

Extended `RIDE.UserPathPreparation` to 0.2.0 with an internal
`Set-RideUserPathValue` boundary. It requires the expected literal value and
explicit current computer/SID/profile/session, rechecks identity and current registry
data, honors `ShouldProcess`, writes only `HKCU\Environment\Path` with the
captured `String` or `ExpandString` kind, and verifies a literal read-back. It
does not create or delete the Environment key during ordinary writes, touch
machine/process PATH, broadcast `WM_SETTINGCHANGE`, delete the Environment key,
create/delete the bin directory, or claim the value is active in existing processes.
It creates the Environment key only when it is absent and a value must be written.

The expanded focused suite passed 50/50 in PowerShell 7 and 50/50 in Windows
PowerShell 5.1. It exercises the write boundary with mocked handles, including
stale-value refusal, writable-handle use, type/text read-back, identity binding
and `-WhatIf`. No actual registry value was read or changed. The optional Pester
TestRegistry plugin was disabled because it requires a sandbox-denied HKCU test
key; test TEMP/TMP used `.local/userpath-regression-2026-10-23`.

Resolved: a local typed compare/write/read-back primitive and its mock-based
contract. Retired/excluded: none. Partial: persistent user PATH; engine dispatch,
authenticated durable run state, complete conflict/interruption recovery,
environment refresh, inherited/machine PATH coexistence and disposable native
acceptance remain. This closes no legacy outcome and changes none of the five
migration estimate ranges. See [focused evidence](../archive/evidence/user-path-guarded-write-regression-2026-10-23.json).

## B03 persistent user PATH engine lifecycle integration, 2026-10-23

Added `windows.user-bin-persistent-path` as an explicit pending-acceptance
candidate with no supported targets. The engine now exposes its literal current
state for status and planning, captures the pre-change PATH value and owned-entry
recovery token in saved run state, and routes apply/restore through identity-bound,
ShouldProcess-gated helpers. `unset` is unsupported; exact recovery uses the saved
run and removes only RIDE's appended entry. The setting remains separate from
PowerShell startup PATH and does not create or remove the bin folder.

Repository validation passed for 375 operations, eight groups, five profiles and
247 PowerShell files. The focused user PATH helper suite passed 52/52 in both PowerShell editions. Combined Pester discovered 203 tests: 202 passed, none failed
and one registry integration case was excluded because the sandbox denies
registry access. The Pester TestRegistry plugin was disabled for the same reason.
No host registry value was read or changed. Native Windows 11 acceptance,
environment refresh and effective-path behavior remain unverified. The operation's
empty `SupportedTargets` list prevents apply until acceptance adds a supported
target.

Resolved: engine/catalog planning and saved-run recovery wiring, locally tested.
Retired/excluded: none. Partial: persistent user PATH; disposable Windows 11
apply, repeat, status, exact restore, process refresh and effective behavior
remain. No legacy outcome closed and all five migration estimate ranges remain
unchanged. See [dated integration evidence](../archive/evidence/user-path-engine-lifecycle-integration-2026-10-23.json).

## B03 Terminal JSONC guarded file writer and recovery candidate, 2026-10-23

`RIDE.TerminalJsonc.psm1` now includes `Set-RideTerminalDefaultProfileFile` and
`Restore-RideTerminalDefaultProfileFile`. Both require an exact `settings.json`
path and matching current computer/user SID. Apply creates a new snapshot of the
original and expected bytes before mutation, locks the file exclusively, honors
`ShouldProcess`, flushes and verifies readback, and attempts byte rollback after a
write failure. Restore validates snapshot identity and hashes, preserves unrelated
settings edits, refuses changed owned values and retains the snapshot. File ACLs
are not captured or changed, and a visible profile declaration does not verify
that the profile is installed or launchable.

The synthetic file suite passed **47/47** on PowerShell 7.6.5 with Pester 5.7.1;
it covers preview, exact apply/restore, unrelated edits, identity mismatch,
tampered snapshot hashes and a competing exclusive lock. Pester's optional
TestRegistry fixture was disabled. Windows PowerShell 5.1 parsed the changed
module and test file with zero parser errors, but Pester 5.7.1 could not load
because its format files failed the host AuthorizationManager check; direct
module import was also denied by that host policy. A read-only `Get-VM -Name
RIDE-Win11-Test` recheck at 06:51 UTC returned CIM access denied, so no checkpoint
query or guest run occurred. No Terminal settings file was read, no snapshot was
created outside TestDrive, and no Windows state changed. No catalog operation or
supported target was added.

Resolved: guarded candidate writer and conflict-aware byte recovery. Retired or
excluded: none. Partial: Terminal default-profile setting. Deferred: installed
instance/path binding, actual profile availability and disposable Windows 11
preview/apply/repeat, editor locking, concurrent edits, failure rollback, restore
and new-tab acceptance. No legacy outcome closed; estimates remain **38-58 /
52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**.
See [candidate evidence](../archive/evidence/terminal-jsonc-file-writer-candidate-2026-10-23.json)
and the [VM access recheck](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0651.json).

## B04 default/LAN WinINet native write-boundary candidate, 2026-10-23

Added a low-level writer to RIDE.UserProxyInventory 0.2.0. It writes the
INTERNET_PER_CONN_FLAGS value and writes INTERNET_PER_CONN_AUTOCONFIG_URL only
when the caller marks that URL as owned. It leaves manual proxy and bypass fields
untouched, then reports the INTERNET_OPTION_SETTINGS_CHANGED and
INTERNET_OPTION_REFRESH results separately. The exported wrapper requires the
expected current computer, user SID and interactive session, and honors
ShouldProcess.

The focused UserProxyInventory.Tests.ps1 and UserProxyPreparation.Tests.ps1 suites
passed 80/80 on PowerShell 7.6.5. Fake API tests cover the current process ABI layout,
selected option IDs/values, Unicode URL preservation, native error propagation
and notification/refresh failures. Both native PowerShell parsers accepted all
four changed source/test files. No WinINet call, registry change, PAC fetch or
connectivity test occurred.

This is only a writer boundary, not a complete setting lifecycle: policy refusal,
fresh compare-and-set, durable saved state, post-write observation, partial-failure
compensation, conflict-aware restore and RIDE engine/catalog integration remain.
The 07:39 UTC read-only VM query returned CIM access denied, so Windows UI/routing
acceptance remains deferred. Resolved: local native writer boundary. Retired or
excluded: none. Partial: B04 default/LAN proxy configuration. Deferred: complete
lifecycle and target acceptance. No legacy outcome closed; estimates remain
38-58 / 52-67 / 19-24 / 25-35 / 8-12, exact 142-196, rounded 145-200/about 170.
See structured evidence at ../archive/evidence/userproxy-native-write-boundary-2026-10-23-0745.json.

## B04 documented proxy-policy refusal guard, 2026-10-23

RIDE.UserProxyInventory 0.3.0 now reads the documented `Proxy` restriction from
the current-user and local-machine Internet Explorer Control Panel policy keys,
and the machine `ProxySettingsPerUser` policy. The low-level setter refuses a
detected restriction, machine-wide scope, malformed known value or registry read
failure before ShouldProcess and before WinINet. The read-only result is scoped
to these documented registry mappings; `Clear` is not a complete effective-policy
inventory and does not establish which applications consume WinINet.

The `UserProxyInventory.Tests.ps1` and `UserProxyPreparation.Tests.ps1` suites
passed **87/87** on PowerShell 7.6.5 with Pester 5.7.1 and TestRegistry disabled;
the inventory suite accounts for 48 tests. Windows PowerShell 5.1 parsed both
modules and both test files cleanly. Tests mock the policy reader; no registry query,
WinINet query/setter, PAC retrieval, network access or Windows state change
occurred. Microsoft documents the [DisableProxyChange mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-internetexplorer#disableproxychange)
and [per-user versus machine-wide proxy scope](https://learn.microsoft.com/en-us/windows/client-management/mdm/networkproxy-csp#proxysettingsperuser).

Resolved: refusal for the documented policy states above. Partial: B04 proxy
configuration. Deferred: complete effective-policy coverage, fresh compare-and-set,
durable saved state, post-write readback, partial-failure compensation,
conflict-aware live recovery, engine/catalog integration and disposable Windows
acceptance. No legacy outcome closed; estimates remain **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [focused
evidence](../archive/evidence/userproxy-policy-guard-regression-2026-10-23.json)
and the [B04 guide](../user-proxy-inventory.md#native-write-boundary-candidate).

## B04 guarded proxy apply/restore lifecycle candidate, 2026-10-23

Added the unregistered RIDE.UserProxyLifecycle candidate. Apply reconstructs the
preparation snapshot, checks the explicit interactive identity and full current
literal values, refuses documented policy blockers, uses the ShouldProcess-gated
setter, and verifies the native readback. Restore reuses the preparation module's
owned-bit/URL conflict check, retains unowned flags/manual proxy/bypass/URL, and
verifies its result. If a setter exception is followed by values exactly matching
the desired edit, or the native setter succeeds but notifications fail, the
candidate rechecks state and attempts compensation to the pre-operation values.
Conflicting current values and repeated readback failure do not trigger an
overwrite. The comparison is still non-atomic.

The three focused suites passed **97/97** on PowerShell 7.6.5 with Pester 5.7.1 and
TestRegistry disabled. Windows PowerShell 5.1 parsed all three modules and three
test files cleanly. All observations, policies and setters were mocked; no
registry or WinINet call occurred. No RIDE engine/catalog state persistence is
implemented, so snapshots are not durable/authenticated and the candidate is not
registered as an active setting.

Resolved: local apply/readback, notification compensation and conflict-aware
restore candidate. Partial: B04 user-proxy configuration. Deferred: durable
pre-change state, engine integration, complete effective-policy coverage,
concurrent write safety and Windows target acceptance. No legacy outcome closed;
estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See [structured evidence](../archive/evidence/userproxy-lifecycle-candidate-2026-10-23.json)
and the [lifecycle guide](../user-proxy-inventory.md#guarded-apply-and-restore-candidate).

## B04 durable proxy state candidate follow-up, 2026-10-23

`RIDE.UserProxyLifecycle` 0.2.0 persists the preparation snapshot in a create-new user-scope JSON record before the candidate WinINet setter. Apply returns a saved RunId; restore can load that record after checking machine, SID and session identity. A store failure prevents the setter, and `WhatIf` creates no record. The record is user-writable and schema-validated, not authenticated; the engine still needs to track restore completion. This does not solve external-process races or guarantee atomic compare-and-set.

The combined inventory/preparation/lifecycle regression passed 100/100 on PowerShell 7.6.5 with Pester 5.7.1 and TestRegistry disabled. All native calls were mocked. No registry, WinINet, network, proxy or Windows state was touched. The 08:40 UTC VM access recheck again returned CIM access denied; checkpoint state remains unknown. Engine/catalog integration, full policy coverage, native Windows acceptance and supported-target status remain open; no legacy outcome closed. See the [structured run evidence](../archive/evidence/userproxy-durable-snapshot-regression-2026-10-23.json), [B04 operator guide](../user-proxy-inventory.md), and [VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0840.json).

## B04 restore-completion sidecar candidate regression, 2026-10-23

`RIDE.UserProxyLifecycle` 0.3.0 now writes a create-new user-scope completion record after a verified `-RunId` restore. Repeated restoration returns `AlreadyRestored` only when the owned flags and URL still match the captured pre-change state; if they drift, the candidate refuses to overwrite them. A completion-store failure after successful readback is returned as `AppliedCompletionUntracked` for inspection. This tracks completion in the standalone candidate only; RIDE engine/catalog persistence remains separate.

The combined inventory/preparation/lifecycle Pester suites passed **103/103** on PowerShell 7.6.5 with Pester 5.7.1 and TestRegistry disabled. Mocked cases cover marker creation, idempotent repeat, drift refusal and completion-store failure. No registry, WinINet, network, proxy or Windows state was touched. Engine/catalog integration, file authenticity, cross-process compare/write safety, full policy coverage, controlled PAC-consumer testing and native Windows acceptance remain deferred. No legacy outcome closed; all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured evidence](../archive/evidence/userproxy-restore-completion-regression-2026-10-23.json), [B04 guide](../user-proxy-inventory.md), and [latest VM access evidence](../archive/evidence/ride-win11-test-access-recheck-2026-10-23-0840.json).

## B04 auto-detection engine integration, 2026-10-23 11:04 UTC

Added `windows.proxy-auto-detect` as an independent current-user default/LAN
WinINet setting with Enabled and Disabled states. Engine status, planning,
saved-state capture and conflict-aware restore are wired to the existing
inventory, preparation and lifecycle modules. Only the automatic-detection flag
is owned; the PAC address and enablement, manual proxy/bypass values, named
VPN/RAS and WinHTTP stay separate.

The catalog lists Windows 11 as a candidate and leaves `SupportedTargets` empty,
so actual apply and restore remain unavailable pending native acceptance. The
repository validator passed for 379 operations, 8 groups, 5 profiles and 251
PowerShell files. Catalog, inventory and preparation tests passed 162/163 discovered (one not run), plus the separately recorded 16/16 lifecycle suite. All tests used synthetic
observations or mocks. No native proxy, registry, VM, Defender or Windows-state
action occurred.

Resolved: independent automatic-detection catalog/engine candidate and saved-run
recovery wiring. Retired/excluded: none. Deferred: Windows 11 lifecycle and exact
restore, complete effective-policy coverage, PAC-consumer tests and the separate
PAC-address setting. Partial: the broader B04 proxy outcome remains open; no
legacy outcome closed. Estimates remain unchanged at **38-58 / 52-67 / 19-24 /
25-35 / 8-12**, exact **142-196**, rounded **145-200/about 170**. See the
[structured evidence](../archive/evidence/b04-proxy-auto-detect-engine-integration-2026-10-23-1104.json),
[operator guide](../user-proxy-inventory.md), and the [migration plan](../MIGRATION-PLAN.md#b04-auto-detection-engine-integration-2026-10-23-1104-utc).

## B04 engine/proxy RunId consolidation, 2026-10-23 11:12 UTC

The RIDE engine now forwards its saved RunId to the proxy lifecycle before the setter. The snapshot is created under that identity, and engine restore reads it by the same RunId and shares the restore-completion marker. A snapshot write failure prevents the setter call.

Focused Catalog, inventory, preparation and lifecycle Pester passed 179/180 discovered tests (one not run); the lifecycle suite passed 16/16. Repository validation passed 379 operations, 8 groups, 5 profiles and 251 PowerShell files. No native WinINet, VM, Defender or Windows state change occurred. An unrelated registry round-trip integration test was excluded after sandbox HKCU access was denied.

Windows 11 native apply, repeat apply, exact restore, drift refusal, effective policy and controlled PAC-consumer checks remain deferred. No legacy outcome closed; estimates are unchanged. See [structured evidence](../archive/evidence/b04-proxy-engine-runid-consolidation-2026-10-23-1112.json), [migration plan](../MIGRATION-PLAN.md) and [operator guide](../user-proxy-inventory.md).
## E08 local password-complexity backend investigation, 2026-10-23 18:04 UTC

The existing `NetUserModalsSet` backend does not expose a password-complexity
field; its documented focused levels cover fields such as password length, age,
history and lockout. Complexity is a separate local security policy setting in
Account Policies. Microsoft's `secedit` documentation describes exporting local
or merged policy, configuring settings defined in a security database, and
creating rollback templates. A minimal database/template containing only
`[System Access] PasswordComplexity` is a plausible local writer, but exact
isolation and recovery are not established by those command references. This is
a design inference, not implementation or acceptance.

Next implementation work can test that one-setting template on disposable
Windows 11 and Server 2025: capture local policy separately from merged
effective policy; apply/repeat; preserve unrelated account-policy values; detect
managed precedence; generate and validate rollback; and restore prior Enabled,
Disabled and Not defined states. Do not add a catalog operation or supported
target until those cases prove exact ownership and recovery. No `secedit`, local
policy read, VM, elevation or Windows change occurred in this investigation.
Resolved: current NetUserModals backend lacks the setting. Retired/excluded:
none. Deferred: candidate implementation and Windows acceptance. Partial: no
legacy outcome closes. All five ranges remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See [structured
research evidence](../archive/evidence/local-password-complexity-secedit-backend-investigation-2026-10-23-1804.json),
[NetUserModalsSet](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset),
[password complexity policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements),
[`secedit /configure`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-configure),
and [`secedit /generaterollback`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-generaterollback).
## E08 one-setting template and export parser candidate, 2026-10-23 18:10 UTC

Added an inert, unregistered PowerShell candidate that builds UTF-16LE INF bytes
with exactly one `[System Access] PasswordComplexity` entry and parses only the
same field from supplied local or merged exports. It distinguishes a missing
local value (`NotDefined`) from a missing merged observation (`NotReported`)
and never claims an observation is effective. The module neither reads policy
nor invokes `secedit`; no catalog operation or target support was added.

The focused Pester suite passed **8/8** on PowerShell 7.6.5/Pester 5.7.1 with
TestRegistry disabled. The initial 6/8 assertion run exposed a CRLF regex issue
in the tests; after correcting the assertions, all eight passed. Windows
PowerShell 5.1 parsed both new files. Runtime import/test execution in Windows
PowerShell 5.1 remains unavailable because the host AuthorizationManager rejects
module and Pester format imports; no bypass was attempted. Native template
validation, local/merged policy behavior, unrelated-setting preservation,
managed precedence and exact rollback remain deferred until Windows 11 and
Server 2025 VM acceptance is possible. Resolved: source-ready template/observation
preparation. Retired/excluded: none. Partial: no legacy outcome closes. All five
ranges remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**,
rounded **145-200/about 170**. See [candidate evidence](../archive/evidence/local-password-complexity-candidate-template-implementation-2026-10-23-1810.json)
and [Microsoft security template rollback documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-generaterollback).

## Hash value context-menu v3 scope confirmed, 2026-10-24

The user confirmed that the multi-algorithm hash value context-menu setting
should be retained in v3. The candidate helper, explicit Windows PowerShell 5.1
runtime and per-user registry mapping are already prepared; Windows 11 Explorer
placement and substitution, unusual filenames, repeat apply, removal and exact
saved-state restore remain unaccepted. No supported target or legacy outcome is
claimed. This confirms requested v3 scope only; estimates remain unchanged at
**38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact **142-196**, rounded
**145-200/about 170**. See the [decision record](decision-session-2026-10-17.md#hash-submenu-package-requirements-and-qemu-validation-targets-2026-10-24)
and [candidate implementation evidence](../archive/evidence/hash-value-submenu-candidate-implementation-2026-10-22.json).
## B03 UserBinPath current-source regression, 2026-10-24 03:28 UTC

The focused local regression passed **84/84** on PowerShell 7.6.5/Pester 5.7.1
with Pester's `TestRegistry` plugin disabled and temporary files rooted under
repository `.local`. It covered `UserBinProfile`, `UserPathEngine`,
`UserPathPreparation` and `ProfileAcceptanceAutomation`. The first attempt used
the default Pester configuration and failed before running tests because its
registry plugin was denied access to HKCU; the corrected configuration matched
the repository's sandbox-safe runner. No guest runner, profile, PATH, VM or
Windows state changed. This proves current mocked lifecycle and runner-boundary
behavior only; native ConsoleHost startup and checkpoint recovery remain pending
until the registered disposable Windows 11 VM is accessible. No setting or
legacy outcome closed. See [structured regression evidence](../archive/evidence/b03-user-bin-current-source-regression-2026-10-24-0328.json).

## Local password-complexity template current-source regression, 2026-10-24 06:33 UTC

The current inert candidate suite passed 8/8 on PowerShell 7.6.5/Pester 5.7.1 with the unused TestRegistry plugin disabled and an isolated .local temp root removed after execution. Coverage is limited to the one-field Unicode template and supplied-export parser. No local policy was queried or changed and no secedit command ran. Native application, exact rollback, managed-policy precedence and disposable-VM behavior remain deferred. This regression resolves no legacy setting outcome and does not change estimates. See [structured evidence](../archive/evidence/local-password-complexity-template-regression-2026-10-24-0633.json).

## Hash value and Certutil context-menu settings routed to remaining batch 1, 2026-10-24 07:18 UTC

The per-user `windows.hash-value-context-menu` and
`windows.sha256-certutil-context-menu` operations now join
`2026-10-10-remaining-settings-1`. The batch count increases from 17 to 19;
`Invoke-RideRemainingSettings.ps1` now expects 19 operations for either remaining
settings batch and reports version 0.2.0. This preserves the existing runner's
exact-state apply, idempotence and saved-run restore sequence. The focused context
menu suite passed 8/8 with one existing skip, including selection of both
operations in the 19-entry batch. Catalog export and repository validation passed.

This route prepares registry lifecycle and exact-recovery checks only. It does
not establish Explorer placement, menu visibility, command quoting, or the
hash-helper behavior from Explorer. Both operations remain unsupported pending
their disposable Windows 11 acceptance. The registered queue remains empty after
its protected request-file creation denial; no guest or user registry state was
changed. No legacy outcome closed and estimates remain unchanged. See [structured
evidence](../archive/evidence/context-menu-settings-batch1-routing-2026-10-24-0718.json).

## Click to Do policy candidate implementation, 2026-10-24

Added `windows.click-to-do-policy` as a user-scoped `RegistryValue` candidate
using Microsoft's documented `DisableClickToDo` policy mapping under
`HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI`.

Its states are intentionally policy-specific: `Blocked=1` removes the Click to
Do component and entry points; `Allowed=0` permits the feature but does not
override the user's local Click to Do toggle; `WindowsDefault` removes the RIDE
policy override and preserves Windows/user choice. Saved-run restore is exact.
The operation is independent of Recall and other Copilot controls. It is not
selected in a profile and has no `SupportedTargets` until acceptance.

Microsoft's management page describes Click to Do as a Copilot+ PC feature,
requires eligible hardware, and documents both the policy and the user-facing
Settings toggle. The WindowsAI Policy CSP lists `DisableClickToDo` applicability
as Insider Preview. Therefore the candidate remains pending acceptance for
current Windows 11 policy behavior, user/device-policy precedence, visible
entry points and exact restore on the test target. The policy reference is
[Microsoft's WindowsAI CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableclicktodo);
the feature boundary is in [Manage Click to Do](https://learn.microsoft.com/en-us/windows/client-management/manage-click-to-do).

Catalog generation and repository validation passed for 408 operations, eight
groups, five profiles and 272 PowerShell files. The focused catalog Pester case
passed 1/1 on PowerShell 7.6.5/Pester 5.7.1. No registry, profile or Windows
state changed; no VM test was started because the registered ApplicationsBatch1
request still owns the active VM queue. This new v3 candidate closes no legacy
outcome and does not change the estimate ranges. See the [implementation
evidence](../archive/evidence/click-to-do-policy-candidate-implementation-2026-10-24-1222.json).

## Windows Terminal packaged-instance inventory, 2026-10-24 12:28 UTC

Added `Get-RideTerminalInstalledInstances` to the Terminal JSONC module. It
queries only the current user's documented Windows Terminal Stable, Preview and
Canary package registrations and derives each distribution's separate
`LocalState/settings.json` path from its exact package-family identity. Existing
files are read under the JSONC module's 1 MiB bound; absent files are reported
without being created. The result distinguishes an installed package instance
from a declared profile. The follow-up provenance guard below ensures
`InstanceVerified` is true only after the live current-user AppX query, while
`ProfileAvailabilityVerified` and `MutationAuthorized` remain false. It rejects
family mismatches, duplicate registrations, reparse-point settings files and
oversized files. It does not enumerate other users,
unpackaged/portable installs, dynamic profiles or launchability.

The focused synthetic discovery cases passed 6/6. The full
`TerminalJsonc.Tests.ps1` suite passed 53/53 on PowerShell 7.6.5/Pester 5.7.1;
Windows PowerShell 5.1 parsed the module and test file. The tests injected
synthetic current-user package records and settings files; no live AppX inventory
was queried, and no Terminal file, package, registry, profile or Windows state
changed. The existing writer still accepts an explicit path and SID, so a
reviewed user selection must connect an inventory row to the exact-path writer
before declaring the operation end-to-end. Unpackaged/portable path handoff,
real profile availability, editor/concurrent-write behavior and disposable VM
acceptance remain open. The registered ApplicationsBatch1 VM request remained
active with no result file at 12:28 UTC. This E06 implementation closes no legacy
setting outcome and does not change the migration ranges. See [structured
evidence](../archive/evidence/terminal-jsonc-packaged-instance-inventory-2026-10-24-1228.json),
Microsoft's [Terminal FAQ](https://learn.microsoft.com/en-us/windows/terminal/faq)
and [distribution guide](https://learn.microsoft.com/en-us/windows/terminal/distributions).

## Terminal inventory verification-source guard, 2026-10-24 12:35 UTC

Review caught that the test-injection parameter initially made synthetic package
records report `InstanceVerified=true`. That overclaim is corrected: the result
now carries `InventorySource`, and only an actual `Get-AppxPackage` query in the
current user's context can set `InstanceVerified=true`. Injected records remain
`InjectedUnverified`/false. The tests assert this boundary; no live AppX query is
needed for local coverage.

After the correction, the full Terminal JSONC regression passed **53/53** on
PowerShell 7.6.5/Pester 5.7.1, Windows PowerShell 5.1 parsed the module and
tests, and repository validation passed for 408 operations, eight groups, five
profiles and 272 PowerShell files. No VM, Windows setting, Terminal file,
package or profile state changed. The current-user inventory-to-writer handoff,
profile launchability and disposable-VM behavior remain unaccepted. No legacy
outcome closes and estimates are unchanged. See the [corrected implementation
evidence](../archive/evidence/terminal-jsonc-packaged-instance-inventory-2026-10-24-1228.json).

## B03 packaged Terminal selection-to-writer handoff, 2026-10-24 12:45 UTC

Added `Set-RideTerminalInstalledInstanceDefaultProfile`. It re-queries current-
user AppX registrations, accepts only one exact documented Stable/Preview/Canary
package name, requires a live verified registration and existing settings file,
then delegates to the identity-bound exclusive writer. It validates a declared
visible profile before prompting; `ShouldProcess`/`-WhatIf` remains active, and
the result explicitly leaves profile availability unverified. Synthetic package
records cannot authorize this path; unpackaged/portable settings retain the
explicit-path writer. No Terminal launch, profile, setting or Windows state was
changed.

The focused full Terminal JSONC suite passed **57/57** on PowerShell 7.6.5/Pester
5.7.1 with Pester TestRegistry disabled. AppX registration results were mocked;
all files were synthetic under TestDrive, so the run does not establish live
package registration or profile launchability. Windows PowerShell 5.1 parsing
passed, and repository validation passed for 408 operations, eight groups, five
profiles and 272 PowerShell files. The packaged inventory-to-writer code path is
implemented, while actual AppX discovery, launchability, GUI effect, disposable
VM acceptance and catalog integration remain open. No legacy outcome closes;
all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 / 8-12**, exact
**142-196**, rounded **145-200/about 170**. See the [structured regression
evidence](../archive/evidence/terminal-jsonc-packaged-instance-selection-writer-2026-10-24-1245.json).

## B03 identity-checked preview and setting-presentation coverage, 2026-10-24 12:52 UTC

The packaged Terminal selector now checks the expected current computer, current
user SID and regular existing settings file before previewing or writing. A new
test refuses a mismatched computer under `-WhatIf`; the complete synthetic
Terminal JSONC suite passes **58/58**. The prior 57/57 run is preserved as dated
history; the final regression also requires identity checks before preview.

The catalog audit found `windows.sha256-certutil-context-menu` was missing its
user-facing `SettingPresentation`. Added text for its all-file per-user scope,
Certutil command/console behavior, exact removal/recovery, file-read boundary and
unverified Windows 11 menu/filename behavior. Added a catalog regression test
requiring presentation metadata on all 281 setting/control operations. That
focused test passed **1/1**; catalog export regenerated `docs/OPERATIONS.md`,
repository validation passed for 408 operations, eight groups, five profiles and
272 PowerShell files, and Windows PowerShell 5.1 parsing passed. No live AppX
query, file, profile, menu, registry or VM behavior was exercised. Terminal
profile launchability, Certutil menu placement/quoting and their disposable-VM
acceptance remain open; the Certutil candidate remains unsupported. No legacy
outcome closes and all five estimates remain **38-58 / 52-67 / 19-24 / 25-35 /
8-12**, exact **142-196**, rounded **145-200/about 170**. See the [Terminal
regression](../archive/evidence/terminal-jsonc-packaged-instance-writer-identity-2026-10-24-1252.json)
and [catalog coverage evidence](../archive/evidence/sha256-certutil-setting-presentation-2026-10-24-1252.json).
