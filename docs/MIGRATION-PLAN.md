# Legacy-to-v3 Migration Plan

## Purpose and inventory

This is the batch inventory for migrating the selectable commands in `legacy/v2/default.preset` to the v3 catalog and profiles. It includes active and commented selectors. The inventory below contains **732 distinct legacy function names** referenced by the preset across **30 family groups**. Active selectors are marked **default**. Paired legacy commands should become states of one v3 operation only when inspection confirms that they control the same setting or package.

The catalog supports `RegistryValue`, `RegistryKeySet`, `Package`, `DefenderExclusion`, `WindowsService`, `BackgroundAppOverrides`, `BootConfiguration`, `NetworkProfile`, `PowerSetting`, and `ShellFolder`. Migration of the other groups requires the minimum additional operation kinds and focused handlers for Windows components, account/configuration changes, files/assets, and system tasks. Each handler must participate in planning, `ShouldProcess`, state capture or declared compensating behavior, status/reporting, and partial-failure reporting.

The optional [God Mode desktop folder](GOD-MODE.md) uses the focused `ShellFolder`
handler. It is a separately requested option, not a migrated legacy selector;
it does not change the upstream preset inventory or implement general file deployment.

## Estimated remaining migration work

Last reviewed: **2026-10-10**, after the forty-setting batch and the settings
usability review below. Approximately **230-280 distinct legacy work items**
remain; use **about 250** for planning. These are candidates for migration,
retirement, combination or replacement, not a commitment to implement all of them.

| Group | Approximate remaining items | Examples |
| --- | ---: | --- |
| Windows and application settings | 100-120 | UI and Explorer options, security, networking, services, Server settings and BitLocker controls |
| Packages, portable tools and downloadable artifacts | 80-90 | Roughly 29 forensic tools, 14 system-tool entries, 22 general software/artifact entries, plus AD tools, browsers and other products |
| Windows components and optional features | 20-25 | WSL, Hyper-V, Sandbox, OpenSSH, printing features and built-in app management |
| Accounts, configuration and deployed files/assets | 25-35 | Users and administrator membership, Wi-Fi, regional settings, language packs, browser preferences, fonts and wallpapers |
| Maintenance and operational actions | 8-12 | Cleanup, updates, Sysprep, hostname and execution helpers |
| **Total, rounded** | **230-280** | **About 250 for planning** |

The estimate reconciles the family lists in the [migration inventory](#migration-inventory)
with implemented equivalents and the
[software disposition ledger](migrations/install-programs-dispositions.md).
Count an enable/disable pair as one feature and install/remove as one product
lifecycle. Count independently useful variants separately. A split into several
catalog operations does not by itself resolve several legacy work items; omitted
parts of a legacy bundle remain pending. Assign each item to one group to avoid
counting a product's installer and deployed files twice. The group ranges are
rough estimates, and their sum is rounded for the headline total.

Do not subtract the catalog operation count from the 732 legacy selector names:
paired states, one-to-many splits and separately requested additions such as God
Mode make those units different. This estimate excludes the separate
[custom library backlog](migrations/custom-ride-dispositions.md) and the 23 helper
functions outside the upstream preset.

Already implemented settings have a separate **evaluation and acceptance backlog**
in the [settings post-migration review](migrations/settings-post-migration-review.md),
including the nine numbered suggestion channels and Cortana-derived preferences.
They are not additional migration items in this table. Implementation counts do
not establish understood user-visible behavior or complete acceptance.

After **every migration batch**, refresh the review date, all group ranges and
the rounded total against the updated family and disposition records. Record
which legacy outcomes were completed, retired, deferred or remain partial in the
batch entry below, together with any estimate adjustment. Remove only resolved
scope from the migration estimate; retain omitted or deferred scope and update
the separate evaluation backlog. If rounding leaves a range unchanged, record
that it was reviewed and why it remains unchanged.

## Custom library review, 2026-10-09

The separate `custom-ride` library is reconciled in the
[custom library disposition ledger](migrations/custom-ride-dispositions.md).
Its 21 module functions include two ISL functions excluded immediately at the
user's request; the remaining 19 functions, supporting scripts, bootstrap
artifacts, README candidates and desktop content have explicit dispositions.
`custom-config.ini` was not opened. This supplemental inventory does not change
the 732-selector/30-family count for the upstream legacy preset.

These are planned migrations, not new supported operations. Retain the existing
catalog IDs and the package variant/source decisions below. Do not import
`lib-custom.psm1`, restore the legacy `-include` runner, or copy bundled vendor
binaries and analyst desktop content into RIDE.

| Work item | Migration boundary and acceptance |
| --- | --- |
| FTK Imager | Prioritize one optional package with an official release-page resolver and installed lifecycle. Exterro's public [8.3 release page](https://www.exterro.com/ftk-downloads/ftk-imager-8-3) exposes the 8.3.0.27 ZIP without registration; unauthenticated HEAD returned 200. Add safe ZIP/member selection, artifact/signature evidence, actual installer arguments, detection, repeat/upgrade/removal and recovery tests. Do not carry forward the 4.7.1 EXE or copied system-DLL workaround. |
| Managed portable pilot | After the shared managed-file lifecycle exists, use Microsoft's `etl2pcapng` as a small pilot. Current v1.11.0 is a standalone EXE. Select the exact asset, record version and owned files, and validate WhatIf, modified-file preservation, removal and recovery. Acquisition tooling never runs packet collection implicitly. |
| Memory acquisition | Evaluate current Magnet DumpIt first; Process Capture 1.3 and RAM Capture 1.20 remain conditional alternatives. Implement supplied-artifact acquisition for form-gated downloads. Require modern Windows driver/VBS compatibility evidence; deployment never starts a capture. EDD 3.10 and USB Detective remain held for current-source, version, edition and distribution review. |
| RawCopy | Keep as a conditional specialist candidate. The legacy latest-release lookup selects a Windows 2000/NTFS 3.0 build. Choose the modern upstream binary at an immutable revision, review evidence and compatibility, then use the shared portable handler. |
| Analyst analysis tools | Reuse the existing YARA, capa, FLOSS, KAPE, Zimmerman, Sysinternals and Volatility work items. Add optional Detect It Easy, x64dbg, HxD, ExifTool, Thumbcache Viewer and separately evaluated Volatility Workbench; review peStudio licensing/source and named NirSoft tools individually. No default broad tool suite or replacement package IDs. |
| Active power scheme | Reconcile both `Set-PowerPlan` scripts with the Power Scheme Settings family. Add a dedicated active-scheme lifecycle or explicit extension to the power handler; capture prior GUID, distinguish scheme creation from selection, own only created schemes, and offer completion from discovered schemes. Current lid-close operations do not implement scheme selection. |
| Wi-Fi and BitLocker | Reconcile Wi-Fi import with `AddWiFi`; add secret-safe profile capture/import and exact recovery. Separate BitLocker policy from OS-volume TPM+PIN enrollment and verified recovery escrow. Reuse the BitLocker family, never treat the existing encryption-method policy as protector enrollment. Test on disposable, representative Windows targets. |
| Fonts/backgrounds | Reuse the Customization family for generic handlers if needed. SOC/organization storage owns font/branding assets; retain font licensing. The custom wallpaper/lock-screen wrappers call the wrong function and are discarded. |
| Analyst desktop material and helpers | External ownership: private SOC manifests/runbooks and controlled content storage. No SANS PDFs, incident tracker, identity/audit helpers, broad Atomic execution scripts, mailbox writers, or organization signature templates enter RIDE as custom operations. See the ledger for alternatives and individual exclusions. |

Start with FTK acquisition/lifecycle review and the shared portable pilot; follow
with distinct opt-in acquisition and analysis profiles. Keep memory capture,
forensic imaging and adversary simulation in SOC runbooks, outside setup apply.
Future profile composition may reference RIDE IDs, but must not create a second
Windows settings writer or assume an external catalog extension is already
supported. Each implementation batch requires the existing mocked/VM acceptance
rules; no new Windows support is established by this documentation review.

## PowerShell model and script follow-ups

Repository-specific models belong in `docs/models/`; `docs/repository-portfolio/`
is reserved for network-devices governance. Maintained PowerShell scripts and
exported commands follow the [native help and version contract](models/script-repository-model.md).

The [8 October 2026 PowerShell walkthrough](migrations/powershell-script-walkthrough.md)
records every script's disposition, preserved upstream/legacy exceptions, and
validation evidence. Its **Remaining operational work and exceptions** section
is the follow-up inventory for bootstrap argument handling and safety, disk
helpers, AutomatedLab guest-path staging, decoder provenance, profile/image/OpenSSH
helpers, and VM-only validation. Those repairs remain open; completion of the
help rewrite does not complete them or establish additional Windows support.

That walkthrough passed 102 isolated tests and excluded one live-registry test
for disposable-VM execution. These results supplement the batch-specific
evidence below; no new state-changing integration run occurred in the walkthrough.

## Batch rules

- Migrate active default selectors first, in the order shown, then commented selectors within each family. A single migration request may cover several consecutive batches or complete low-risk family groups; preserve each type/family boundary and review batch results before moving to a new handler type.
- Keep each batch within one operation type and family. Use **up to 10 new v3 operations** for the pilot batch. After an established handler and its mocked tests pass, allow up to **25 operations** in homogeneous, low-risk settings batches. Keep packages, Windows components, account/configuration changes, files/assets, system tasks, and any batch using a new handler at 10 or fewer until their behavior is proven. Keep related state pairs and multi-state settings together.
- Add stable catalog IDs, per-operation supported Windows targets, scope, privilege, actions, rollback behavior, and target defaults as each operation is migrated. Do not infer support from the legacy preset header.
- Mark existing v3 equivalents complete instead of re-adding them: `ShowKnownExtensions` → `windows.show-known-extensions`; `DisableAutoplay` → `windows.autoplay-policy`; `DisableAutorun` → `windows.autorun-policy`; `Install7Zip` → `package.7zip`; and the commented `InstallNotepadPlusPlus` → `package.notepadpp`.
- Keep detailed type metadata in the operation catalog and generate `docs/OPERATIONS.md` through its exporter. This plan is the migration inventory, not a second catalog.
- Before closing each batch, refresh the [remaining-work estimate](#estimated-remaining-migration-work), record the batch's effect on legacy outcomes and estimates, and update the separate post-migration evaluation backlog.

## Migration inventory

### Post-migration usability review, 2026-10-10

The [settings post-migration review](migrations/settings-post-migration-review.md)
evaluates the existing one-to-many splits, including all fifteen app-suggestion
preferences and three personalization preferences retained from Cortana.
Implementation and registry lifecycle acceptance do not mean their user-visible
behavior is understood. The nine numbered content channels remain unresolved;
the catalog now names their app-suggestions area and experimental status, gives
individual literal/state descriptions, and replaces the stale Spotlight fragment.
No unknown channel is recommended for a profile or combined app-suggestions
control. IDs and saved-run recovery remain stable. Other combined settings have
explicit retain, partial, or further-review dispositions in the review.

### Forty-setting follow-up, 2026-10-09

This request adds **40 optional registry operations** with **81 explicit states**
and references **44 distinct legacy selectors**. The family boundaries are
Privacy Tweaks (22), Network Tweaks (1), Service Tweaks (7), UI Tweaks (2),
Security Tweaks (2), and Explorer UI Tweaks (6). This is the user's explicit
forty-setting session; it uses the proven scalar handler and does not increase
the pilot limit for new handlers. All entries declare Windows 11 only and remain
outside profiles. No Windows Server target is added.

| Family | Legacy selectors | Catalog operation | Explicit states |
| --- | --- | --- | --- |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.content-delivery` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.oem-preinstalled-app-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.preinstalled-app-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.silent-app-installation` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-310093` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-314559` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338387` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338388` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338389` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-338393` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-353694` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-353696` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.suggested-content-353698` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.settings-pane-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableAppSuggestions`, `EnableAppSuggestions` | `windows.post-setup-suggestions` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableCortana`, `EnableCortana` | `windows.implicit-text-personalization` | `Restricted=1`, `Allowed=0` |
| privacy-tweaks | `DisableCortana`, `EnableCortana` | `windows.implicit-ink-personalization` | `Restricted=1`, `Allowed=0` |
| privacy-tweaks | `DisableCortana`, `EnableCortana` | `windows.input-personalization-contact-harvesting` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableTelemetry`, `EnableTelemetry` | `windows.diagnostic-data-policy` | `Off=0`, `Required=1`, `Optional=3` |
| privacy-tweaks | `DisableTelemetry`, `EnableTelemetry` | `windows.linguistic-data-collection-policy` | `Disabled=0`, `Enabled=1` |
| privacy-tweaks | `DisableFeedback`, `EnableFeedback` | `windows.feedback-notifications-policy` | `Disabled=1`, `Allowed=0` |
| privacy-tweaks | `DisableErrorReporting`, `EnableErrorReporting` | `windows.error-reporting` | `Disabled=1`, `Enabled=0` |
| network-tweaks | `DisableNCSIProbe`, `EnableNCSIProbe` | `windows.ncsi-active-probing` | `Disabled=0`, `Enabled=1` |
| service-tweaks | `DisableUpdateMSRT`, `EnableUpdateMSRT` | `windows.msrt-update-offering` | `Disabled=1`, `Allowed=0` |
| service-tweaks | `DisableUpdateDriver`, `EnableUpdateDriver` | `windows.update-driver-policy` | `Excluded=1`, `Included=0` |
| service-tweaks | `DisableUpdateDriver`, `EnableUpdateDriver` | `windows.device-metadata-downloads` | `Prevented=1`, `UserChoice=0` |
| service-tweaks | `DisableUpdateAutoDownload`, `EnableUpdateAutoDownload` | `windows.update-download-mode` | `NotifyDownload=2`, `AutoDownload=3` |
| service-tweaks | `DisableAutoRestartSignOn`, `EnableAutoRestartSignOn` | `windows.automatic-restart-sign-on` | `Disabled=1`, `Enabled=0` |
| service-tweaks | `EnableStorageSense`, `DisableStorageSense` | `windows.storage-sense` | `Enabled=1`, `Disabled=0` |
| service-tweaks | `DisableRecycleBin`, `EnableRecycleBin` | `windows.recycle-bin-policy` | `Bypass=1`, `UseRecycleBin=0` |
| ui-tweaks | `DisableLockScreen`, `EnableLockScreen` | `windows.lock-screen-policy` | `Disabled=1`, `Enabled=0` |
| ui-tweaks | `EnableVerboseStatus`, `DisableVerboseStatus` | `windows.verbose-logon-status` | `Enabled=1`, `Disabled=0` |
| security-tweaks | `EnableSharingMappedDrives`, `DisableSharingMappedDrives` | `windows.linked-mapped-drives` | `Enabled=1`, `Disabled=0` |
| security-tweaks | `DisableDownloadBlocking`, `EnableDownloadBlocking` | `windows.attachment-zone-information` | `Discard=1`, `Preserve=2` |
| explorer-ui-tweaks | `ShowRecycleBinOnDesktop`, `HideRecycleBinFromDesktop` | `windows.desktop-recycle-bin-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowThisPCOnDesktop`, `HideThisPCFromDesktop` | `windows.desktop-this-pc-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowUserFolderOnDesktop`, `HideUserFolderFromDesktop` | `windows.desktop-user-files-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowControlPanelOnDesktop`, `HideControlPanelFromDesktop` | `windows.desktop-control-panel-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowNetworkOnDesktop`, `HideNetworkFromDesktop` | `windows.desktop-network-icon` | `Shown=0`, `Hidden=1` |
| explorer-ui-tweaks | `ShowBuildNumberOnDesktop`, `HideBuildNumberFromDesktop` | `windows.desktop-build-number` | `Shown=1`, `Hidden=0` |

These are independently selectable settings, not a compatibility runner for
the legacy functions. Every entry has a Microsoft reference, a scope/elevation
requirement, `WindowsDefault` baseline, and exact captured-value restore.
`unset` removes only the declared override; it does not mean the opposite
explicit state and does not restore a prior value. Image-dependent literal
defaults remain `<platform-defined>`.

**Partial replacements and deferred behavior:**

- App suggestions: migrate the fourteen independent ContentDeliveryManager
  values and post-setup preference. Internal subscription numbers are identified
  literally rather than assigned guessed feature names. Their Microsoft links
  describe feature behavior, not those values. Current-build effects require
  review. Do not migrate `PreInstalledAppsEverEnabled` (historical bookkeeping),
  the obsolete Ink Workspace suggestion flag, CloudStore binary truncation or
  ShellExperienceHost termination. The legacy function is only partly covered.
- Cortana: expose text/ink personalization and contact harvesting as their own
  preferences. Their mappings remain subject to behavior review. Cortana app
  installation/removal, retired taskbar controls, privacy-consent bookkeeping
  and PolicyManager default-store mutations remain excluded. These settings do
  not resurrect Cortana.
- Telemetry: migrate diagnostic-data policy and linguistic-data collection.
  Diagnostic Off is edition-dependent and is not a guarantee of zero network
  traffic. Do not copy redundant non-policy/Wow6432Node mirrors, retired
  preview-build controls, licensing overrides, old AppCompat/App-V controls or
  Office/Windows scheduled-task changes. The broader function remains partial.
- Feedback and error reporting: migrate their scalar settings; SIUF frequency
  and scheduled tasks remain deferred. The [Windows Maps retirement](https://learn.microsoft.com/en-us/windows/uwp/maps-and-location)
  excludes its old automatic-update preference from this batch.
- Driver updates: keep quality-update drivers separate from device metadata
  application downloads. The legacy driver-search ordering value is deferred.
  Automatic Updates retains two supported download modes; no IFEO debugger
  workaround, implicit update installation, or reboot behavior is copied.
- Storage Sense: change only its enablement value; preserve other cleanup
  preferences and notification bookkeeping. No recursive subtree removal.
  RIDE does not run cleanup. Restoring a preference cannot recover content
  later deleted by Windows; the same limit applies to Recycle Bin bypass.
- Desktop namespace icons: migrate the Windows 11 NewStartPanel values only.
  Legacy ClassicStartMenu writes are excluded on this target. Each icon has
  explicit Shown/Hidden states, while the all-icons preference remains separate.
  No icon files are deleted and no shell restart occurs. Visible icon and
  desktop-version-label behavior still requires review.
- Mapped-drive links do not alter UAC consent settings. Attachment zone
  information is modeled accurately as Preserve/Discard, not as a universal
  download blocker; existing file metadata is not changed.

**Validation:** Catalog generation and parser validation pass for 174 operations,
2 groups, 4 profiles and 52 maintained PowerShell files. All 570 isolated tests
pass on both Windows PowerShell 5.1 and PowerShell 7; the live-registry test is
reserved for the disposable VM. Settings-only run
`2ab1773b3c5944819fcff8dab44342d0` passed all 571 Pester tests and all 40
registry lifecycle scenarios on Windows 11 Enterprise Evaluation, build 26300.
The suite exercised all 81 explicit states, preview, repeat apply, baseline
removal, and prior value/type/existence restore. Evidence collection and clean
checkpoint recovery succeeded, leaving the VM off. This batch did not request
host UAC elevation; the host's UAC consent values remained unchanged.
Feature effects, UI refresh, restart,
actual update acquisition, network probing and deferred multi-component
behavior remain separate acceptance work.

### Optional Windows settings session, 2026-10-09

This migration adds **20 optional registry operations** covering **41 legacy
selectors** in consecutive family batches: UI Tweaks (9), Privacy Tweaks (7),
Service Tweaks (3), and Explorer UI Tweaks (1). All use the established
`RegistryValue` lifecycle, preserve state pairs, declare Windows 11 only, and
stay outside the workstation default profile.

| Family | Legacy selectors | Catalog operation | Explicit states |
| --- | --- | --- | --- |
| ui-tweaks | `HideNetworkFromLockScreen`, `ShowNetworkOnLockScreen` | `windows.lock-screen-network-selection` | `Hidden=1`, `Shown=0` |
| ui-tweaks | `HideShutdownFromLockScreen`, `ShowShutdownOnLockScreen` | `windows.shutdown-without-logon` | `Disabled=0`, `Enabled=1` |
| ui-tweaks | `DisableAeroShake`, `EnableAeroShake` | `windows.title-bar-shake` | `Disabled=1`, `Enabled=0` |
| ui-tweaks | `HideRecentlyAddedApps`, `ShowRecentlyAddedApps` | `windows.start-recently-added-apps` | `Hidden=1`, `UserChoice=0` |
| ui-tweaks | `EnableTitleBarColor`, `DisableTitleBarColor` | `windows.title-bar-accent-color` | `Enabled=1`, `Disabled=0` |
| ui-tweaks | `SetAppsDarkMode`, `SetAppsLightMode` | `windows.app-color-mode` | `Dark=0`, `Light=1` |
| ui-tweaks | `SetSystemDarkMode`, `SetSystemLightMode` | `windows.system-color-mode` | `Dark=0`, `Light=1` |
| ui-tweaks | `DisableChangingSoundScheme`, `EnableChangingSoundScheme` | `windows.sound-scheme-change-policy` | `Blocked=1`, `Allowed=0` |
| ui-tweaks | `SetTaskbarAlignmentLeft`, `SetTaskbarAlignmentMiddle` | `windows.taskbar-alignment` | `Left=0`, `Centered=1` |
| privacy-tweaks | `DisableSensors`, `EnableSensors` | `windows.sensors-policy` | `Disabled=1`, `Allowed=0` |
| privacy-tweaks | `DisableBiometrics`, `EnableBiometrics` | `windows.biometrics-policy` | `Disabled=0`, `Allowed=1` |
| privacy-tweaks | `DisableCamera`, `EnableCamera` | `windows.app-camera-policy` | `ForceDeny=2`, `ForceAllow=1`, `UserControl=0` |
| privacy-tweaks | `DisableMicrophone`, `EnableMicrophone` | `windows.app-microphone-policy` | `ForceDeny=2`, `ForceAllow=1`, `UserControl=0` |
| privacy-tweaks | `SetP2PUpdateLocal`, `SetP2PUpdateInternet`, `SetP2PUpdateDisable` | `windows.delivery-optimization-download-mode` | `HttpOnly=0`, `LocalNetwork=1`, `Internet=3` |
| privacy-tweaks | `EnableClearRecentFiles`, `DisableClearRecentFiles` | `windows.clear-recent-documents-on-exit` | `Enabled=1`, `Disabled=0` |
| privacy-tweaks | `DisableRecentFiles`, `EnableRecentFiles` | `windows.recent-document-history-policy` | `Disabled=1`, `Allowed=0` |
| service-tweaks | `DisableFastStartup`, `EnableFastStartup` | `windows.fast-startup` | `Disabled=0`, `Enabled=1` |
| service-tweaks | `DisableAutoRebootOnCrash`, `EnableAutoRebootOnCrash` | `windows.auto-reboot-on-crash` | `Disabled=0`, `Enabled=1` |
| service-tweaks | `EnableClipboardHistory`, `DisableClipboardHistory` | `windows.clipboard-history` | `Enabled=1`, `Disabled=0` |
| explorer-ui-tweaks | `ShowNavPaneLibraries`, `HideNavPaneLibraries` | `windows.navigation-pane-libraries` | `Shown=1`, `Hidden=0` |

Every operation also provides `WindowsDefault` and uses it as its baseline:
remove the override without assuming that removal is the opposite explicit
state. `unset` removes the override; saved-run restore recovers the original
value, type and absence. In particular, the legacy reverse selectors for network
selection, shake, recently added apps, sound changes, sensors, biometrics,
camera/microphone, recent history, clipboard history, taskbar alignment and
Libraries often removed values. Their new explicit reverse states write a
declared value; use `WindowsDefault` to reproduce override removal.

The sound-scheme restriction and clear-recent-documents policy use Microsoft's
documented **HKCU user scope**, correcting legacy HKLM writes. The recent-history
restriction retains the machine scope permitted by `StartMenu.admx`. The
biometric framework mapping is confirmed by `Biometrics.admx`; its reference
documents policy-controlled framework enablement rather than the exact registry
value. Camera and microphone policies control supported Windows apps, with
per-app exceptions; they are not universal hardware switches. No enrollment,
credential changes, sign-out, crash, shutdown, hibernation enablement or Explorer
restart is performed by the migration or handler.

Delivery Optimization `LocalNetwork=1` now selects LAN peering explicitly.
`HttpOnly=0` replaces the legacy `SetP2PUpdateDisable` branch's retired
`Bypass=100` mode on Windows 11; it disables peering while retaining update
downloads. `Internet=3` remains available only through explicit selection.
See the [Microsoft reference](https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-reference).
Restoring policy cannot recover history later deleted by Windows or recreate
clipboard content; recovery is exact for the captured registry setting.

**Literal defaults:** Schema 1 now permits `DefaultValueExists = $null`,
`DefaultValue = $null` when images/themes/user profiles do not have one
universal literal default. Status and generated documentation render
`<platform-defined>`; `MatchesDefault` remains null, including when the live
value is absent. Boolean true/false still mean a known present/absent literal
default, and zero remains an explicit value. Effective defaults explain
dependencies independently of the baseline. Use the updated engine, generator
and validator with this catalog; older readers render null existence as absent.
Tagged releases retain their own catalog/tools, and saved-run schemas are
unchanged. Keep the current catalog and handlers available when restoring runs
containing the newly added IDs.

**Validation:** Catalog/parser/generated-document checks pass for 134 operations,
2 groups, 4 profiles and 51 PowerShell files. All 327 isolated tests pass on
Windows PowerShell 5.1 and PowerShell 7 (324 full-suite checks plus 3 new guest
runner checks), including 123 tests for this batch. Tab completion resolves the
new IDs and multi-state selections from the catalog. The tests found and fixed
an elevation check that did not recognize a singleton machine plan on Windows
PowerShell 5.1. An existing God Mode fixture now adds a separate Delete grant
without reconstructing Windows generic ACL rights, and compares permissions
when Windows recalculates the DACL auto-inherited bookkeeping flag.

The VM runner now launches tests in a fresh guest PowerShell process after
Pester hit the remoting thread's call-depth limit. The disposable-VM scenarios
cover all explicit states, preview, repeat apply, baseline and exact restore.
Run `959e8b4c2a374041a792497f42dd2588` on Windows 11 Enterprise Evaluation,
build 26300, passes all 328 guest Pester tests and all 20 registry lifecycle
scenarios, including the 43 explicit states. The broader package suite was
interrupted after a prolonged Joplin acquisition; Joplin completed shortly before
interruption, and the run is not a full-suite pass. The completed transcript and
Pester XML are retained with the run's interruption record. The controller
restored the clean checkpoint without cleanup errors; host UAC values were
unchanged. Registry round trips do not prove visible
shell refresh, sensor/biometric hardware behavior, app access, peer transfer,
hibernation or crash recovery. Those scenarios remain separately required;
Windows Server support is not added.

The obsolete Most used list policy, Win+X shell replacement, small taskbar icons,
NumLock SendKeys, packed visual effects, shortcut icon resource overrides and
multi-value Control Panel/pointer settings remain deferred. Taskbar desktop
selectors are existing `windows.task-view-button` equivalents; do not add
duplicate operations.

### Unattended migration session, 2026-10-08

Git for Windows now passed installation, repeat installation, local repository
init/add/commit/HEAD verification and uninstall in the Windows 11 VM (run
`20cb460af8be447dafcfc62662f99d35`, 103 guest tests passed). Latest patch releases
with four-part installer filenames are supported. The Git publisher's exact
release-note SHA-256 is checked separately from GitHub's asset digest.

The accepted batch adds standalone Git LFS, Joplin, ShareX, WinDirStat and PowerShell
7. New MSI support handles quiet install/removal and the declared restart-needed
exit code without rebooting implicitly. User packages query HKCU instead of
mistaking a machine installation for current-user presence. Git LFS requires
Git; the ordered `solution.git-development` group expresses install/removal
order. Full Windows 11 request `9744844940fd4ca498ef6486092ac831` passed 128
guest tests and integration, including all five install/repeat/remove scenarios
and the installed PowerShell executable/version check. Both new user policies
passed apply/repeat/exact-restore/WindowsDefault checks. Collection and checkpoint
recovery succeeded; the VM is off at the pinned clean baseline and host UAC is
unchanged. Native host checks passed 127 isolated tests on PowerShell 5.1 and 7.
See [the session results](migrations/2026-10-08-unattended-results.md) for run IDs,
corrected failures, coverage limits and remaining work.

All **53 Install programs selectors** are individually reconciled in
[the disposition ledger](migrations/install-programs-dispositions.md), including
specific deferred work. Reconciliation does not mean every selector is
implemented. No portable tool tree, Defender exclusion, license acceptance or
replacement community Sysmon policy is applied implicitly.

The Windows Configuration family gains `windows.edge-friendly-url-format`
and `windows.start-run-as-different-user`, selected in `profiles/default.psd1`.
They cover `DisableFriendlyURLFormat`/`UnconfigureFriendlyURLFormat` and
`EnableRunAsInStartMenu`/`DisableRunAsInStartMenu`. The Start policy uses the
documented **HKCU user scope**, correcting the legacy HKLM write. Its Disabled
state is explicit zero; WindowsDefault removes the override. Both operations
capture exact prior values; VM tests cover repeat, baseline and restore.
Other selectors in that family remain pending.

Follow-up Windows 11 run `64be8db70ffc45d79d9a1ae02ba4c64c` passed validation,
132 Pester tests, and the full integration suite. It verified both Defender
exclusions through apply, repeat-apply, and exact restoration. The two lid-close
operations also passed handler tests; integration correctly reported them as
unavailable because the disposable Windows 11 VM exposes no lid-close setting.
The VM returned to its clean checkpoint and off state, and host UAC was
unchanged. The registered VM runbook remains usable from an unelevated prompt.
The final unit-only run `b03644c4e24e4d9091e0275586370f00` then passed all
134 guest Pester tests after adding engine plan/state assertions.

Follow-up Windows 11 run `48ce9b4de1d64daa9d9812273035b01a` passed catalog
validation, all 136 Pester tests, and the full integration suite. It verified
the optional taskbar clock seconds, Recycle Bin delete-confirmation, and desktop
icon visibility settings through apply, repeat-apply, declared baseline, and
exact restoration. Git LFS, Joplin, ShareX, WinDirStat, and PowerShell package
lifecycle checks also passed. The two lid-close integration checks were skipped
because the disposable VM does not expose lid settings. The runner restored the
VM to its pinned clean checkpoint with no cleanup or collection errors; host UAC
was unchanged.

The larger catalog exceeds PowerShell 5.1's whole-file safe-data complexity
limit. A bounded metadata reader evaluates each literal operation/group with
SafeGetValue, rejects executable entries and preserves schema 1. Execution,
validation, generation and read-only completion use that same reader.

Provisioning now accepts a local PSD1 and generates a per-VM controller seed;
the runbook explains every field and downstream inheritance. Server 2025 media
is unavailable, so its creation and runtime acceptance remain pending.
Concurrent multi-lab networking also requires a reviewed shared-NAT design:
the script now blocks creating a second host NAT instead of risking the
working Windows 11 network. Unique VM/controller names do not solve WinNAT's
one-network limitation.

Publisher/signature investigations and the evidence workflow are maintained in
[PACKAGE-VERIFICATION-MATRIX.md](PACKAGE-VERIFICATION-MATRIX.md). The shared
library contains observations, not an approval policy or automatic signer gate.

Each group lists exact legacy function names found in the preset. Test demand is required for every batch; complex Windows integration checks are deferred to the later VM phase.

**Batch 1 implemented:** Settings / Privacy configurations migrates `DisableInkingAndTypingData` to `windows.inking-typing-data` and adds it to the workstation default profile. Catalog validation and the Pester 5.7 unit suite pass; the Windows 11 disposable-VM check remains deferred. The reverse `EnableInkingAndTypingData` selector has no legacy implementation and remains unresolved below.

**Batch 2 implemented:** Settings / Defender configuration migrates the two active default selectors `ExcludeToolsDirDefender` and `ExcludeBootstrapDirDefender` to `windows.defender-tools-exclusion` and `windows.defender-bootstrap-exclusion`. Both are in the workstation default profile. Catalog validation and the Pester 5.7 mocked unit suite pass; disposable Windows 11 VM verification remains deferred.

**Low-risk family 1/5 complete:** Network Functions maps the scalar registry selectors `DisableAutoconfigURL` and `DisableMulticastDNS` to `windows.proxy-autoconfig-url` and `windows.llmnr-policy`, both selected in the workstation default profile. The legacy `DisableIEProxyAutoconfig` selector mutates a packed binary value and remains deferred. The `DisableMulticastDNS` name is misleading: the implementation changes the LLMNR policy value.

**Low-risk family 2/5 complete:** Privacy Tweaks maps eight scalar registry values from `DisableTailoredExperiences`, `DisableActivityHistory`, `DisableLocation`, `DisableAdvertisingID`, and `DisableWebLangList` to eight reversible operations in the default profile. Telemetry's task changes, service changes, app removal/cache mutation, feedback/error-reporting tasks, and legacy Wi-Fi Sense/Maps settings remain deferred for complexity or current-Windows applicability review.

**Low-risk family 3/5 complete:** Service Tweaks maps four scalar registry values from `DisableMaintenanceWakeUp`, `DisableSharedExperiences`, and `EnableNTFSLongPaths` to reversible operations. The existing Autoplay and Autorun selectors remain complete; COM-based update enrollment and the Windows Update debugger override are deferred.

**Low-risk family 4/5 complete:** UI Tweaks maps 19 scalar registry operations to the default workstation profile in three reviewable batches (9, 9, and 1 operation). A follow-up optional batch adds the taskbar clock seconds and Recycle Bin delete-confirmation selectors as exact-rollback Windows 11 user settings; neither is added to the default profile. This includes Action Center/toast behavior, accessibility prompts, taskbar controls, startup sound, and the Alt+Tab Edge-tab filter. The binary shortcut-name value, Task Manager process/polling behavior, packed visual-effects value, dynamic sound-scheme changes, and OS-branching or special-key settings remain deferred. Catalog/profile validation and mocked Pester checks pass (31 tests total); disposable-VM checks remain required before broadening declared Windows support.

**Low-risk family 5/5 complete:** Explorer UI Tweaks adds eight scalar registry operations in one batch for hidden files, navigation-pane expansion, sync notifications, recent/frequent shortcuts, Explorer start location, and thumbnail cache behavior. A follow-up optional batch adds the desktop icon visibility selector as an exact-rollback Windows 11 user setting, outside the default profile. The already-migrated Show Known Extensions operation remains the existing equivalent. The initial scalar batch deferred the three This PC folder visibility selectors; those were later migrated under Family 12 using a reversible registry key-set handler.

**Family 11/30 active defaults migrated:** UI Tweaks maps the active scalar registry defaults into the workstation profile. The binary shortcut-name value, Task Manager process/polling behavior, packed visual-effects value, dynamic sound-scheme changes, and OS-branching or special-key settings remain deferred. Catalog/profile validation and mocked Pester checks pass; full disposable-VM coverage remains outstanding.

**Family 12/30 migrated and validated:** Explorer UI Tweaks includes eight reversible scalar registry settings, the optional `windows.desktop-icons-visibility` setting, and `windows.music-folder-this-pc`, `windows.videos-folder-this-pc`, and `windows.3d-objects-folder-this-pc`. The desktop icon selector remains outside the default profile. The new allowlisted `RegistryKeySet` handler captures recursive key values, registry types, and security descriptors before changing registration keys, so restore can reconstruct the prior tree. Windows may recalculate the DACL auto-inherited control flag when a key is recreated; validation confirms the restored owner, group, ACL entries, registry values, and value kinds. All active default selectors are represented in the default profile. Catalog validation, all 55 Pester tests, and Windows 11 disposable-VM round trips pass.

**Family 6/30 migrated:** Hardening Windows maps the active defaults `DisableSSDPdiscovery`, `DisableUniversalPlugAndPlay`, and `DisableWinHttpAutoProxySvc`. The first two use a reversible Windows service handler that captures and restores startup mode and running state; both are disabled and stopped by the default workstation profile. Enabled means Manual and Running for both services. The WPAD selector maps to the documented `DisableWpad` WinHTTP registry value; despite its legacy name, it does not disable the WinHTTP Auto-Proxy service. Catalog validation passes. Pester could not run in the restricted execution session because its framework's temporary registry keys are denied; mocked checks and disposable Windows 11 and Server 2025 VM checks remain outstanding.

**Family 7/30 migrated:** UWP Privacy Tweaks adds 19 reversible registry settings for the active background policy, app privacy policies, four file-system capabilities, and the UWP swap-file setting. `EnableUWPBackgroundApps` also maps to a separate user-scoped reset operation that captures and restores existing per-app `Disabled` and `DisabledByUser` values. The swap-file registry mapping is not documented by Microsoft; its operation links to the closest UWP lifecycle behavior reference and flags the mapping for review. Catalog validation passes. Pester could not run in the restricted execution session because its framework's temporary registry keys are denied; mocked checks and disposable Windows 11 VM checks remain outstanding.

**Family 8/30 active defaults migrated:** Security Tweaks adds the AutoShareServer and AutoShareWks settings, the current user's Windows Security account-protection warning, both 64-bit and 32-bit .NET strong-crypto values, and reversible BCDEdit operations for the F8 boot menu and DEP policy. The existing Windows Script Host operation covers `DisableScriptHost`. BCDEdit changes are recorded exactly and take effect after restart. AutoShareServer is supported on Windows Server 2025 and is not selected in the workstation profile; AutoShareWks is selected there. Catalog validation passes. Pester and disposable Windows VM checks remain outstanding; Pester is blocked in this session by denied temporary registry keys.

**Family 9/30 migrated:** Network Tweaks adds `windows.current-network-category`, which applies Private or Public to all reported non-domain profiles and captures the individual prior categories for exact restore. `windows.remote-assistance-policy` reversibly controls `fAllowToGetHelp`; Quick Assist removal remains a separate deferred operation because Windows 11 delivers it as a Store app and its lifecycle needs its own reliable reinstall behavior. Both defaults are selected in the workstation profile. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trips pass.

**Family 10/30 active defaults migrated with one deferral:** Service Tweaks adds `windows.microsoft-product-updates`, using the documented `AllowMUUpdateService` preference to opt in to Microsoft product updates; it is selected in the workstation default profile. `DisableUpdateRestart` remains deferred because the legacy implementation installs an experimental Image File Execution Options debugger for `MusNotification.exe`, and its exact effect and safe restoration need review before reproducing it. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trip passes.

**Family 14/30 active default migrated:** BitLocker adds `windows.bitlocker-encryption-method`, mapping the legacy AES-256 selector to the exact reversible `EncryptionMethod=4` policy value. The operation is Windows 11-only pending target-specific integration coverage and describes that it affects future encryption, not existing encrypted drives. Catalog validation and 53 mocked Pester tests pass; the Windows 11 disposable-VM round trip passes. Windows Server support remains undeclared.

**Family 15/30 reconciled, implementation incomplete:** The active Git default has passed install, repeat, local init/add/commit/HEAD and removal in Windows 11. 7-Zip, Notepad++, Sysmon and standalone Git LFS, Joplin, ShareX, WinDirStat and PowerShell 7 use the package lifecycle. The XML artifact remains download-only at an immutable commit; Sysmon installation uses its default configuration. All 53 selectors have an explicit disposition in [the ledger](migrations/install-programs-dispositions.md). Deferred selectors require the stated handler/source/licensing work before implementation; the current batch's acceptance is recorded in the session section above.

### Settings

#### Power Scheme Settings (power-scheme-settings)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetPowerSchemeBalanced`, `SetPowerSchemeHighPerf`, `SetPowerSchemeUltimate`, `SetPwrSchemeDesktopMenu`,
`RemovePwrSchemeDesktopMenu`, `SetLidCloseActionBattSleep`, `SetLidCloseActionBattDoNothing`,
`SetLidCloseActionPwrDoNothing`, `SetLidCloseActionPwrSleep`

**Partially migrated:** `SetLidCloseActionBattSleep` / `SetLidCloseActionBattDoNothing`
map to `windows.lid-close-action-dc`; the corresponding `Pwr` pair maps to
`windows.lid-close-action-ac`. The `PowerSetting` handler captures the active
scheme and literal AC/DC index for exact restore, and treats the initial value
as platform-defined rather than claiming a Windows default. Device/scheme
combinations that do not expose the setting report `Unavailable`; no power
setting is selected in the workstation profile. Catalog validation, mocked
handler lifecycle tests, and the Windows 11 VM integration suite pass, but the
VM had no lid-close control, so actual apply/restore on lid-capable hardware is
still required. The three named power-plan selectors and two desktop-context
menu selectors remain deferred because scheme creation/removal and dynamic
registry-tree rollback need separate designs.

#### Privacy configurations (privacy-configurations)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableInkingAndTypingData` **default**

#### Defender configuration (defender-configuration)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`ExcludeToolsDirDefender` **default**, `ExcludeBootstrapDirDefender` **default**, `RemoveToolsDirDefender`,
`RemoveBootstrapDirDefender`

#### Hardening Windows (hardening-windows)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableSSDPdiscovery` **default**, `DisableUniversalPlugAndPlay` **default**,
`DisableWinHttpAutoProxySvc` **default**, `EnableSSDPdiscovery`, `EnableUniversalPlugAndPlay`,
`EnableWinHttpAutoProxySvc`

#### Network Functions (network-functions)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableIEProxyAutoconfig` **default**, `DisableAutoconfigURL` **default**, `DisableMulticastDNS` **default**,
`EnableIEProxyAutoconfig`, `EnableAutoconfigURL`, `EnableMulticastDNS`, `GetNoTelemetryHostsFile`,
`SetDefaultHostsfile`

#### Privacy Tweaks (privacy-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableTelemetry` **default**, `DisableCortana` **default**, `DisableWiFiSense` **default**,
`DisableAppSuggestions` **default**, `DisableActivityHistory` **default**, `DisableLocation` **default**,
`DisableMapUpdates` **default**, `DisableFeedback` **default**, `DisableTailoredExperiences` **default**,
`DisableAdvertisingID` **default**, `DisableWebLangList` **default**, `DisableErrorReporting` **default**,
`DisableDiagTrack` **default**, `DisableWAPPush` **default**, `EnableTelemetry`, `EnableCortana`,
`EnableWiFiSense`, `DisableSmartScreen`, `EnableSmartScreen`, `DisableWebSearch`, `EnableWebSearch`,
`EnableAppSuggestions`, `EnableActivityHistory`, `DisableSensors`, `EnableSensors`, `EnableLocation`,
`EnableMapUpdates`, `EnableFeedback`, `EnableTailoredExperiences`, `EnableAdvertisingID`, `EnableWebLangList`,
`DisableBiometrics`, `EnableBiometrics`, `DisableCamera`, `EnableCamera`, `DisableMicrophone`,
`EnableMicrophone`, `EnableErrorReporting`, `SetP2PUpdateLocal`, `SetP2PUpdateInternet`, `SetP2PUpdateDisable`,
`EnableDiagTrack`, `EnableWAPPush`, `EnableClearRecentFiles`, `DisableClearRecentFiles`, `DisableRecentFiles`,
`EnableRecentFiles`

#### UWP Privacy Tweaks (uwp-privacy-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableUWPBackgroundApps` **default**, `EnableUWPBackgroundApps`, `DisableUWPVoiceActivation`,
`EnableUWPVoiceActivation`, `DisableUWPNotifications`, `EnableUWPNotifications`, `DisableUWPAccountInfo`,
`EnableUWPAccountInfo`, `DisableUWPContacts`, `EnableUWPContacts`, `DisableUWPCalendar`, `EnableUWPCalendar`,
`DisableUWPPhoneCalls`, `EnableUWPPhoneCalls`, `DisableUWPCallHistory`, `EnableUWPCallHistory`,
`DisableUWPEmail`, `EnableUWPEmail`, `DisableUWPTasks`, `EnableUWPTasks`, `DisableUWPMessaging`,
`EnableUWPMessaging`, `DisableUWPRadios`, `EnableUWPRadios`, `DisableUWPOtherDevices`, `EnableUWPOtherDevices`,
`DisableUWPDiagInfo`, `EnableUWPDiagInfo`, `DisableUWPFileSystem`, `EnableUWPFileSystem`, `DisableUWPSwapFile`,
`EnableUWPSwapFile`

#### Security Tweaks (security-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableAdminShares` **default**, `HideAccountProtectionWarn` **default**, `DisableScriptHost` **default**,
`EnableDotNetStrongCrypto` **default**, `EnableF8BootMenu` **default**, `SetDEPOptOut` **default**,
`SetUACLow`, `SetUACHigh`, `EnableSharingMappedDrives`, `DisableSharingMappedDrives`, `EnableAdminShares`,
`EnableBrowserServiceView`, `DisableFirewall`, `EnableFirewall`, `HideDefenderTrayIcon`,
`ShowDefenderTrayIcon`, `DisableDefender`, `EnableDefender`, `DisableDefenderCloud`, `EnableDefenderCloud`,
`EnableCtrldFolderAccess`, `DisableCtrldFolderAccess`, `EnableCIMemoryIntegrity`, `DisableCIMemoryIntegrity`,
`EnableDefenderAppGuard`, `DisableDefenderAppGuard`, `ShowAccountProtectionWarn`, `DisableDownloadBlocking`,
`EnableDownloadBlocking`, `EnableScriptHost`, `DisableDotNetStrongCrypto`, `EnableMeltdownCompatFlag`,
`DisableMeltdownCompatFlag`, `DisableF8BootMenu`, `DisableBootRecovery`, `EnableBootRecovery`,
`DisableRecoveryAndReset`, `EnableRecoveryAndReset`, `SetDEPOptIn`

#### Network Tweaks (network-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetCurrentNetworkPrivate` **default**, `DisableRemoteAssistance` **default**, `SetCurrentNetworkPublic`,
`SetUnknownNetworksPrivate`, `SetUnknownNetworksPublic`, `DisableNetDevicesAutoInst`,
`EnableNetDevicesAutoInst`, `DisableHomeGroups`, `EnableHomeGroups`, `DisableSMB1`, `EnableSMB1`,
`DisableSMBServer`, `EnableSMBServer`, `DisableNetBIOS`, `EnableNetBIOS`, `DisableLLMNR`, `EnableLLMNR`,
`DisableLLDP`, `EnableLLDP`, `DisableLLTD`, `EnableLLTD`, `DisableMSNetClient`, `EnableMSNetClient`,
`DisableQoS`, `EnableQoS`, `DisableIPv4`, `EnableIPv4`, `DisableIPv6`, `EnableIPv6`, `DisableNCSIProbe`,
`EnableNCSIProbe`, `DisableConnectionSharing`, `EnableConnectionSharing`, `EnableRemoteAssistance`,
`EnableRemoteDesktop`, `DisableRemoteDesktop`

#### Service Tweaks (service-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`EnableUpdateMSProducts` **default**, `DisableUpdateRestart` **default**,
`DisableMaintenanceWakeUp` **default**, `DisableSharedExperiences` **default**, `DisableAutoplay` **default**,
`DisableAutorun` **default**, `EnableNTFSLongPaths` **default**, `DisableUpdateMSRT`, `EnableUpdateMSRT`,
`DisableUpdateDriver`, `EnableUpdateDriver`, `DisableUpdateMSProducts`, `DisableUpdateAutoDownload`,
`EnableUpdateAutoDownload`, `EnableUpdateRestart`, `EnableMaintenanceWakeUp`, `DisableAutoRestartSignOn`,
`EnableAutoRestartSignOn`, `EnableSharedExperiences`, `EnableClipboardHistory`, `DisableClipboardHistory`,
`EnableAutoplay`, `EnableAutorun`, `DisableRestorePoints`, `EnableRestorePoints`, `EnableStorageSense`,
`DisableStorageSense`, `DisableDefragmentation`, `EnableDefragmentation`, `DisableSuperfetch`,
`EnableSuperfetch`, `DisableIndexing`, `EnableIndexing`, `DisableRecycleBin`, `EnableRecycleBin`,
`DisableNTFSLongPaths`, `DisableNTFSLastAccess`, `EnableNTFSLastAccess`, `SetBIOSTimeUTC`, `SetBIOSTimeLocal`,
`EnableHibernation`, `DisableHibernation`, `DisableSleepButton`, `EnableSleepButton`, `DisableSleepTimeout`,
`EnableSleepTimeout`, `DisableFastStartup`, `EnableFastStartup`, `DisableAutoRebootOnCrash`,
`EnableAutoRebootOnCrash`

#### UI Tweaks (ui-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`DisableActionCenter` **default**, `DisableLockScreenBlur` **default**, `DisableAccessibilityKeys` **default**,
`ShowTaskManagerDetails` **default**, `ShowFileOperationsDetails` **default**, `HideTaskbarSearch` **default**,
`HideTaskView` **default**, `SetTaskbarCombineWhenFull` **default**, `HideTaskbarPeopleIcon` **default**,
`ShowTrayIcons` **default**, `DisableSearchAppInStore` **default**, `DisableNewAppPrompt` **default**,
`DisableShortcutInName` **default**, `SetVisualFXPerformance` **default**, `SetSoundSchemeNone` **default**,
`DisableStartupSound` **default**, `EnableVerboseStatus` **default**, `DisableF1HelpKey` **default**,
`DisableTaskbarWidgets` **default**, `DisableTaskbarChat` **default**, `RemoveEdgeTabsFromAltTab` **default**,
`EnableActionCenter`, `DisableLockScreen`, `EnableLockScreen`, `DisableLockScreenRS1`, `EnableLockScreenRS1`,
`HideNetworkFromLockScreen`, `ShowNetworkOnLockScreen`, `HideShutdownFromLockScreen`,
`ShowShutdownOnLockScreen`, `EnableLockScreenBlur`, `DisableAeroShake`, `EnableAeroShake`,
`EnableAccessibilityKeys`, `HideTaskManagerDetails`, `HideFileOperationsDetails`, `EnableFileDeleteConfirm`,
`DisableFileDeleteConfirm`, `ShowTaskbarSearchIcon`, `ShowTaskbarSearchBox`, `ShowTaskView`,
`ShowSmallTaskbarIcons`, `ShowLargeTaskbarIcons`, `SetTaskbarCombineNever`, `SetTaskbarCombineAlways`,
`ShowTaskbarPeopleIcon`, `HideTrayIcons`, `ShowSecondsInTaskbar`, `HideSecondsFromTaskbar`,
`EnableSearchAppInStore`, `EnableNewAppPrompt`, `HideRecentlyAddedApps`, `ShowRecentlyAddedApps`,
`HideMostUsedApps`, `ShowMostUsedApps`, `SetWinXMenuPowerShell`, `SetWinXMenuCmd`, `SetControlPanelSmallIcons`,
`SetControlPanelLargeIcons`, `SetControlPanelCategories`, `EnableShortcutInName`, `HideShortcutArrow`,
`ShowShortcutArrow`, `SetVisualFXAppearance`, `EnableTitleBarColor`, `DisableTitleBarColor`, `SetAppsDarkMode`,
`SetAppsLightMode`, `SetSystemDarkMode`, `SetSystemLightMode`, `AddENKeyboard`, `RemoveENKeyboard`,
`EnableNumlock`, `DisableNumlock`, `DisableEnhPointerPrecision`, `EnableEnhPointerPrecision`,
`SetSoundSchemeDefault`, `EnableStartupSound`, `DisableChangingSoundScheme`, `EnableChangingSoundScheme`,
`DisableVerboseStatus`, `EnableF1HelpKey`, `DisableTaskbarDesktops`, `EnableTaskbarDesktops`,
`EnableTaskbarWidgets`, `EnableTaskbarChat`, `SetTaskbarAlignmentLeft`, `SetTaskbarAlignmentMiddle`,
`SetEdgeTabsWindowsAnd5tabs`, `SetEdgeTabsWindowsAnd3tabs`, `SetEdgeTabsWindowsAndAll`

#### Explorer UI Tweaks (explorer-ui-tweaks)

**Optional registry batch, 2026-10-09:** Seven further current-user folder
options map 14 legacy selectors to the existing `RegistryValue` lifecycle.
They remain outside the workstation default profile. Explicit on/off states
write a DWORD; `WindowsDefault` removes the override and is the declared
baseline. Removing an override is distinct from restoring the captured prior
value and registry type.

| Legacy selectors | Catalog operation |
| --- | --- |
| `ShowExplorerTitleFullPath`, `HideExplorerTitleFullPath` | `windows.explorer-title-full-path` |
| `ShowSuperHiddenFiles`, `HideSuperHiddenFiles` | `windows.protected-files-visibility` |
| `EnableFldrSeparateProcess`, `DisableFldrSeparateProcess` | `windows.explorer-separate-process` |
| `EnableRestoreFldrWindows`, `DisableRestoreFldrWindows` | `windows.restore-folder-windows` |
| `DisableSharingWizard`, `EnableSharingWizard` | `windows.sharing-wizard` |
| `HideSelectCheckboxes`, `ShowSelectCheckboxes` | `windows.item-selection-checkboxes` |
| `DisableThumbnails`, `EnableThumbnails` | `windows.thumbnail-display` |

The legacy reverse selectors for title paths, folder-window restoration and
Sharing Wizard removed a value. Their v3 explicit reverse states use zero or
one; use `WindowsDefault` to reproduce legacy override removal. Protected-file
visibility also depends on hidden-file visibility. Thumbnail display remains
separate from cache creation and network thumbnail database settings.

Microsoft's [folder option registry reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3c837e92-016e-4148-86e5-b4f0381a757f)
and [additional folder option reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/a6ca3a17-1971-4b22-bf3b-e1a5d5c50fca)
document six mappings. The checkbox operation links to
[Microsoft's user-visible option](https://support.microsoft.com/en-us/windows/experience/fileexplorer/file-explorer-in-windows);
its legacy `AutoCheckSelect` value is retained for review rather than claiming
that the folder-option specification documents that value (it names
`UseCheckBoxes`). No Explorer restart, logoff, share creation or cache deletion
is performed by these operations.

Native catalog/parser/generated-document validation and all 170 isolated tests
pass on Windows PowerShell 5.1 and PowerShell 7, including 35 new batch tests.
The existing live-registry test is excluded from workstation validation.
The VM suite includes apply, repeat, baseline and exact restore scenarios for
all seven operations. Their clean-profile literal defaults and visible Explorer
behavior still require disposable Windows 11 verification, including sign-in
and touch-related behavior; no Windows Server support is added by this batch.
Other optional Explorer selectors remain pending.

**Optional registry follow-up, 2026-10-09:** Three further current-user folder
options map six legacy selectors to the same exact-restore handler. They stay
outside the default profile and declare Windows 11 as their only target.

| Legacy selectors | Catalog operation | Explicit states |
| --- | --- | --- |
| `ShowEmptyDrives`, `HideEmptyDrives` | `windows.empty-drives-visibility` | `Visible=0`, `Hidden=1` |
| `ShowFolderMergeConflicts`, `HideFolderMergeConflicts` | `windows.folder-merge-conflicts` | `Shown=0`, `Hidden=1` |
| `ShowNavPaneAllFolders`, `HideNavPaneAllFolders` | `windows.navigation-pane-all-folders` | `Enabled=1`, `Disabled=0` |

All three legacy reverse selectors remove the value; use `WindowsDefault` or
`unset` for that behavior. The explicit reverse states now write a DWORD.
Folder merge prompts remain distinct from duplicate-file prompts, and the
navigation-pane option remains distinct from auto-expansion. The
[Microsoft settings reference](https://learn.microsoft.com/en-us/windows/apps/develop/settings/settings-common#file-explorer-classic)
documents these options rather than their precise registry mappings; the
catalog marks the retained legacy mappings for review. Clean-profile literal
defaults and visible behavior still need disposable Windows 11 verification.
The VM suite now includes registry round trips for all three.

Catalog/parser/generated-document validation, discovery and ID completion
checks pass. All 185 isolated tests pass on Windows PowerShell 5.1 and
PowerShell 7, including 50 Explorer tests; the existing live-registry test is
excluded from workstation validation. No state-changing VM run occurred for
this follow-up.

Other same-family candidates remain pending: per-icon desktop visibility,
desktop build-number display, and encrypted/compressed
file colors. The legacy file-color value is named
`ShowEncryptCompressedColor`, whereas Microsoft's older folder-option
specification names `ShowCompColor`; resolve that difference on the target
before choosing a mapping. Desktop icon selectors write two values and need
a coordinated restore contract. Namespace-key removals and context-menu
mutations remain separate from this scalar batch.

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`ShowKnownExtensions` **default**, `ShowHiddenFiles` **default**, `EnableNavPaneExpand` **default**,
`HideSyncNotifications` **default**, `HideRecentShortcuts` **default**, `SetExplorerThisPC` **default**,
`HideMusicFromThisPC` **default**, `HideVideosFromThisPC` **default**, `Hide3DObjectsFromThisPC` **default**,
`DisableThumbnailCache` **default**, `DisableThumbsDBOnNetwork` **default**, `ShowExplorerTitleFullPath`,
`HideExplorerTitleFullPath`, `HideKnownExtensions`, `HideHiddenFiles`, `ShowSuperHiddenFiles`,
`HideSuperHiddenFiles`, `ShowEmptyDrives`, `HideEmptyDrives`, `ShowFolderMergeConflicts`,
`HideFolderMergeConflicts`, `DisableNavPaneExpand`, `ShowNavPaneAllFolders`, `HideNavPaneAllFolders`,
`ShowNavPaneLibraries`, `HideNavPaneLibraries`, `EnableFldrSeparateProcess`, `DisableFldrSeparateProcess`,
`EnableRestoreFldrWindows`, `DisableRestoreFldrWindows`, `ShowEncCompFilesColor`, `HideEncCompFilesColor`,
`DisableSharingWizard`, `EnableSharingWizard`, `HideSelectCheckboxes`, `ShowSelectCheckboxes`,
`ShowSyncNotifications`, `ShowRecentShortcuts`, `SetExplorerQuickAccess`, `HideQuickAccess`, `ShowQuickAccess`,
`HideRecycleBinFromDesktop`, `ShowRecycleBinOnDesktop`, `ShowThisPCOnDesktop`, `HideThisPCFromDesktop`,
`ShowUserFolderOnDesktop`, `HideUserFolderFromDesktop`, `ShowControlPanelOnDesktop`,
`HideControlPanelFromDesktop`, `ShowNetworkOnDesktop`, `HideNetworkFromDesktop`, `HideDesktopIcons`,
`ShowDesktopIcons`, `ShowBuildNumberOnDesktop`, `HideBuildNumberFromDesktop`, `HideDesktopFromThisPC`,
`ShowDesktopInThisPC`, `HideDesktopFromExplorer`, `ShowDesktopInExplorer`, `HideDocumentsFromThisPC`,
`ShowDocumentsInThisPC`, `HideDocumentsFromExplorer`, `ShowDocumentsInExplorer`, `HideDownloadsFromThisPC`,
`ShowDownloadsInThisPC`, `HideDownloadsFromExplorer`, `ShowDownloadsInExplorer`, `ShowMusicInThisPC`,
`HideMusicFromExplorer`, `ShowMusicInExplorer`, `HidePicturesFromThisPC`, `ShowPicturesInThisPC`,
`HidePicturesFromExplorer`, `ShowPicturesInExplorer`, `ShowVideosInThisPC`, `HideVideosFromExplorer`,
`ShowVideosInExplorer`, `Show3DObjectsInThisPC`, `Hide3DObjectsFromExplorer`, `Show3DObjectsInExplorer`,
`HideNetworkFromExplorer`, `ShowNetworkInExplorer`, `HideIncludeInLibraryMenu`, `ShowIncludeInLibraryMenu`,
`HideGiveAccessToMenu`, `ShowGiveAccessToMenu`, `HideShareMenu`, `ShowShareMenu`, `DisableThumbnails`,
`EnableThumbnails`, `EnableThumbnailCache`, `EnableThumbsDBOnNetwork`

#### Server Specific Tweaks (server-specific-tweaks)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`HideServerManagerOnLogin`, `ShowServerManagerOnLogin`, `DisableShutdownTracker`, `EnableShutdownTracker`,
`DisablePasswordPolicy`, `EnablePasswordPolicy`, `DisableCtrlAltDelLogin`, `EnableCtrlAltDelLogin`,
`DisableIEEnhancedSecurity`, `EnableIEEnhancedSecurity`, `EnableAudio`, `DisableAudio`, `AudioMute`,
`AudioUnmute`

#### Bitlocker (bitlocker)

**Test demand:** Required per batch: Pester tests for state discovery, desired-state comparison, apply/restore, idempotence, WhatIf, and mocked failures. Defer complex Windows policy, service, network, and reboot scenarios to disposable-VM integration.

**Legacy selectors:**

`SetDefaultBitLockerAES256` **default**, `SetDefaultBitLockerAES128`, `PutBitlockerShortCutOnDesktop`,
`EnableLockOutThreshold`, `DisableLockOutThreshold`, `EnableEnhancedPIN`, `DisableEnhancedPIN`,
`EnableAdditionalAuthAtStart`, `EnableBitlockerTPMandPIN`, `EnableBitlocker`, `DisableBitlocker`,
`AddBitlockerRecoveryPswd`, `DisplayBitlockerRecoveryPwd`


### Packages

#### Install programs (install-programs)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`Install7Zip` **default**, `InstallGit4Win` **default**, `GetSysmonSwiftXML` **default**,
`InstallSysmon64` **default**, `Remove7Zip`, `InstallGitLFS`, `RemoveGitLFS`, `RemoveGit4Win`,
`InstallPSScriptTools`, `RemovePSScriptTools`, `InstallVSCode`, `RemoveVSCode`, `InstallGPGwin`,
`InstallNotepadPlusPlus`, `RemoveNotepadPlusPlus`, `GetSysmonOlafXML`, `RemoveSysmon64`,
`InstallVMwareWorkstation`, `RemoveVMwareWorkstation`, `SetVMDirUserhome`, `SetVMDirDocuments`,
`InstallThunderbird`, `InstallJoplin`, `InstallImageMagick`, `InstallImageMagickPortable`,
`RemoveImageMagickPortable`, `InstallSignal`, `InstallPython`, `InstallYara`, `RemoveYara`, `GetCyberChef`,
`RemoveCyberChef`, `InstallCaffeine`, `RemoveCaffeine`, `InstallPutty`, `RemovePutty`, `InstallWinSCP`,
`InstallKAPE`, `RemoveKAPE`, `InstallVeraCrypt`, `InstallVeraCryptPortable`, `InstallADReplStatus`,
`RemoveADReplStatus`, `InstallFirewallNotifier`, `RemoveFirewallNotifier`, `InstallWinDirStat`,
`RemoveWinDirStat`, `InstallShareX`, `RemoveShareX`, `InstallShareXportable`, `RemoveShareXportable`,
`InstallPowerShell`, `InstallAutomatedLab`

#### Office Apps (office-apps)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`DisableOneDrive` **default**, `UninstallOneDrive` **default**, `InstallOffice365` **default**,
`DisableTeamsAutoStart` **default**, `RemoveTeamsStoreApp` **default**, `EnableOneDrive`, `InstallOneDrive`,
`ResetTeamsAutoStart`, `RemoveTeamsWideInstaller`, `InstallVisioPro`

#### System Tools (system-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`GetSysinternalsSuite`, `RemoveSysinternalsSuite`, `InstallJoeWare`, `RemoveJoeWare`, `InstallCCleaner`,
`RemoveCCleaner`, `InstallMitec`, `RemoveMitec`, `InstallNtcore`, `RemoveNTCore`, `InstallTMOG`, `RemoveTMOG`,
`InstallWireshark`, `RemoveWireshark`, `InstallZimmermanTools`, `RemoveZimmermanTools`,
`InstallNirsoftLauncher`, `RemoveNirsoftLauncher`, `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64`,
`InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles`, `InstallArsenalRecon`, `InstallWinget`,
`InstallWingetAutoUpdate`

All 25 selectors have a current reconciliation in the [System Tools disposition ledger](migrations/system-tools-dispositions.md). None is yet represented by a v3 catalog operation.

**Defender and antivirus research (2026-10-09; investigation only):**

- **NirSoft:** Elevated alert risk is confirmed. NirSoft itself says alerts are
  common for some password-recovery utilities; its historical report includes
  password, credential, and key-recovery tools, though that report is no longer
  maintained. This supports a package-specific compatibility review, not a
  blanket exclusion or a claim that each current binary is safe. The selectors
  fetch a changing collection, so identify exact files and versions before
  considering any exception. [NirSoft antivirus report](https://www.nirsoft.net/false_positive_report.html)
- **JoeWare:** A Defender-related issue is confirmed for **AdFind**, not for
  every JoeWare utility. The publisher reports Defender blocking AdFind and
  attributes its reputation to legitimate Active Directory reconnaissance
  also being used by attackers. The legacy selector downloads the entire linked
  JoeWare tools collection, so inventory its contents before treating it as a
  single package or scoping an exception. [JoeWare report](https://blog.joeware.net/2023/02/22/6166/)
- **NTCore:** No source-confirmed Defender alert was found for the artifacts
  selected by the legacy function. That is unknown status, not evidence of a
  clean scan: the script crawls linked pages and collects multiple EXE/ZIP
  artifacts. Enumerate and pin the intended subset before migration.
- **Eric Zimmerman tools:** The publisher says all tools are digitally signed
  and characterizes antivirus hits as false positives after verifying the
  signature. Treat this as a publisher assertion that must be checked per
  artifact; the legacy function downloads and executes a mutable `master`
  PowerShell script before copying the resulting collection. Pin and verify
  that bootstrap script and record each resulting binary before any execution
  or exclusion decision. [Official tools and publisher guidance](https://ericzimmerman.github.io/)
- **Arsenal Recon:** The publisher documents antivirus compatibility steps for
  Arsenal Image Mounter (AIM), including possible exclusions for its folder or
  executables, and says AIM may need to allow a `utilman.exe` alert during VM
  boot. It also documents antivirus-evasion behavior in AIM's guest-VM tools.
  This establishes known AV interaction, not a confirmed Defender detection
  for every current artifact. The legacy selector downloads every MEGA link on
  the publisher page plus MEGAcmd, so resolve exact products, versions,
  licensing, drivers, and rollback before migration. [AIM walkthrough](https://arsenalrecon.com/arsenal-image-mounter-aim-walkthrough)

No tools were downloaded, executed, or scanned for this review, and no VM or
integration tests were run. Any Defender exclusion remains a separate,
package-scoped decision requiring exact artifact evidence and the verification
described in [Package-specific Defender exclusions](#package-specific-defender-exclusions).

#### Active Directory Tools (active-directory-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallRSAT`, `RemoveRSAT`, `InstallOpenJDK`, `InstallNeo4j`, `GetBloodhound`, `RemoveBloodhound`,
`GetSharphound`, `RemoveSharphound`, `GetAzurehound`, `RemoveAzurehound`, `GetImproHound`, `RemoveImprohound`,
`GetPingCastle`, `RemovePingCastle`

#### For Linux VMs (for-linux-vms)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallVirtIOGuestTool`, `InstallSpiceGuestTool`, `InstallSpiceWebDAV`

#### Browsers and Internet (browsers-and-internet)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`DisableEdgePagePrediction` **default**, `InstallFirefox` **default**,
`CreateFirefoxPreferenceFiles` **default**, `InstallChrome` **default**,
`CreateChromePreferenceFile` **default**, `RemoveFirefox`, `RemoveFirefoxPreferenceFiles`, `RemoveChrome`,
`RemoveChromePreferenceFile`, `InstallOpera`

#### Forensic Tools (forensic-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallAutopsy`, `InstallNetworkMiner`, `RemoveNetworkMiner`, `InstallAutorunner`, `RemoveAutorunner`,
`InstallChainsaw`, `RemoveChainsaw`, `GetChromeParser`, `RemoveChromeParser`, `InstallCyLR`, `RemoveCyLR`,
`InstallDejsonlz4`, `RemoveDejsonlz4`, `GetHex2text`, `RemoveHex2text`, `InstallHindsight`, `RemoveHindsight`,
`InstallSqlitebrowser`, `GetShimCacheParser`, `RemoveShimCacheParser`, `GetPSTViewer`, `GetOSTViewer`,
`InstallLoki`, `RemoveLoki`, `InstallSSView`, `RemoveSSView`, `InstallSrumMonkey`, `RemoveSrumMonkey`,
`InstallSrumDump`, `RemoveSrumDump`, `InstallThumbcacheviewer`, `RemoveThumbcacheviewer`,
`InstallSuperFetchTools2`, `RemoveSuperFetchTools2`, `InstallUserAssist`, `RemoveUserAssist`,
`InstallThumbsviewer`, `RemoveThumbsviewer`, `InstallRegRipper`, `RemoveRegRipper`, `InstallWinhex`,
`RemoveWinhex`, `InstallWinPmem`, `RemoveWinPmem`, `InstallVolatility2`, `RemoveVolatility2`,
`InstallVolatility3`, `InstallPartDiagParser`, `RemovePartDiagParser`, `InstallGglCookieCruncher`,
`RemoveGglCookieCruncher`, `InstallSigma`, `RemoveSigma`

#### Offensive Tools (offensive-tools)

**Test demand:** Required per batch: mocked Pester tests for detection, download resolution, installer/uninstaller invocation, idempotence, and failures. Defer live installer/version recovery checks to disposable VMs.

**Legacy selectors:**

`InstallHashcat`, `RemoveHashcat`, `InstallHashcatLauncher`, `RemoveHashcatLauncher`


### Windows components

#### Windows Subsystem for Linux (windows-subsystem-for-linux)

**Test demand:** Required per batch: mocked Pester tests for feature/app state, apply/remove calls, ShouldProcess, and failures. Defer OS-image, reboot, and broad component integration to disposable VMs.

**Legacy selectors:**

`EnableWSL`, `DisableWSL`, `InstallWSLubuntu`, `RemoveWSLubuntu`, `InstallWSLdebian`, `RemoveWSLdebian`,
`InstallWSLkali`, `RemoveWSLkali`, `InstallWSLFedora`

#### Application Tweaks (application-tweaks)

**Test demand:** Required per batch: mocked Pester tests for feature/app state, apply/remove calls, ShouldProcess, and failures. Defer OS-image, reboot, and broad component integration to disposable VMs.

**Legacy selectors:**

`UninstallMsftBloat` **default**, `UninstallThirdPartyBloat` **default**, `DisableXboxFeatures` **default**,
`DisableAdobeFlash` **default**, `DisableEdgePreload` **default**, `DisableEdgeShortcutCreation` **default**,
`DisableIEFirstRun` **default**, `DisableFirstLogonAnimation` **default**, `DisableMediaSharing` **default**,
`UninstallInternetExplorer` **default**, `SetPhotoViewerAssociation` **default**,
`AddPhotoViewerOpenWith` **default**, `UninstallXPSPrinter` **default**, `RemoveFaxPrinter` **default**,
`InstallMsftBloat`, `InstallThirdPartyBloat`, `UninstallWindowsStore`, `InstallWindowsStore`,
`EnableXboxFeatures`, `DisableFullscreenOptims`, `EnableFullscreenOptims`, `EnableAdobeFlash`,
`EnableEdgePreload`, `EnableEdgeShortcutCreation`, `EnableIEFirstRun`, `EnableFirstLogonAnimation`,
`EnableMediaSharing`, `DisableMediaOnlineAccess`, `EnableMediaOnlineAccess`, `EnableDeveloperMode`,
`DisableDeveloperMode`, `UninstallMediaPlayer`, `InstallMediaPlayer`, `InstallInternetExplorer`,
`UninstallWorkFolders`, `InstallWorkFolders`, `UninstallHelloFace`, `InstallHelloFace`,
`UninstallMathRecognizer`, `InstallMathRecognizer`, `UninstallPowerShellV2`, `InstallPowerShellV2`,
`UninstallPowerShellISE`, `InstallPowerShellISE`, `InstallLinuxSubsystem`, `UninstallLinuxSubsystem`,
`InstallHyperV`, `UninstallHyperV`, `UninstallSSHClient`, `InstallSSHClient`, `InstallSSHServer`,
`UninstallSSHServer`, `InstallTelnetClient`, `UninstallTelnetClient`, `InstallNET23`, `UninstallNET23`,
`UnsetPhotoViewerAssociation`, `RemovePhotoViewerOpenWith`, `UninstallPDFPrinter`, `InstallPDFPrinter`,
`InstallXPSPrinter`, `AddFaxPrinter`, `UninstallFaxAndScan`, `InstallFaxAndScan`, `InstallSandbox`,
`RemoveSandbox`


### Accounts and configuration

#### Windows configuration (windows-configuration)

**Current disposition:** The two registry-policy defaults for Edge URL copying
and Start's Run as different user command are migrated. Account creation,
administrator membership, built-in-account changes, language packs and copying
regional settings require account/locale handlers and multi-user recovery
coverage. `AddUserBinToPath` requires exact per-user environment capture and
restore; it is not represented as an installer or a machine PATH change.
The remaining optional selectors need their own component, credential/network,
activation or security-policy workflows before migration.

**Test demand:** Required per batch: mocked Pester tests for user/locale/configuration discovery, apply, restore or compensating behavior, and failures. Defer multi-user, locale, and machine-wide scenarios to disposable VMs.

**Legacy selectors:**

`CreateNewLocalAdmin` **default**, `DisableBuiltinAdministrator` **default**,
`DisableFriendlyURLFormat` **default**, `EnableRunAsInStartMenu` **default**,
`InstallLanguagePackGB` **default**, `SetRegionalSettings` **default**, `CopyRegionSettingsToAll` **default**,
`AddUserBinToPath` **default**, `ActivateWindows`, `ActivateWindowsOEM`, `MakeLoggedOnUserAdmin`,
`MakeLoggedOnUserNoAdmin`, `AddWiFi`, `DisableWindowsStoreApp`, `EnableWindowsStoreApp`,
`UnconfigureFriendlyURLFormat`, `DisableRunAsInStartMenu`, `EnableInternetPrinting`, `DisableInternetPrinting`,
`EnableMemoryIntegrity`, `DisableMemoryIntegrity`, `InstallLanguagePackDK`, `InstallLanguagePackCustom`,
`CopyRegionSettingsWelcome`, `CopyRegionSettingsNewUser`


### Files and assets

#### Customization (customization)

**Test demand:** Required per batch: isolated Pester tests using temporary paths or mocked file/registry calls for content, idempotence, WhatIf, and restore. Defer real shell/profile integration to disposable VMs.

**Legacy selectors:**

`InstallFonts` **default**, `ReplaceDefaultWallpapers` **default**, `SetLockScreen`, `SetDefaultLockScreen`,
`InstallLenovoVantage`, `RemoveLenovoVantage`


### System tasks

#### Unpinning (unpinning)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`CleanPublicDesktop` **default**, `UnpinStartMenuTiles`, `UnpinTaskbarIcons`

#### Operational Tasks (operational-tasks)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`GetWindowsUpdatesWithPwsh`, `CleanLocalWindowsUpdateCache`, `RunDiskCleanup`, `GetWindowsProductKey`,
`RunSysprepGeneralizeOOBE`

#### Other Functions (other-functions)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`SetHostname` **default**

#### Auxiliary Functions (auxiliary-functions)

**Test demand:** Required per batch: Pester tests for plan construction, ShouldProcess gating, and mocked command calls; assert no action occurs in WhatIf. Defer destructive, reboot, cleanup, and Sysprep end-to-end tests to disposable VMs.

**Legacy selectors:**

`WaitForKey` **default**, `Restart` **default**, `StopComputer`

## Preset references to reconcile

These selectors do not exactly match a function name in the legacy modules. Resolve or explicitly mark them unsupported before their family batch is migrated. Do not silently create catalog entries for misspelled or missing functions.

| Preset selector | Reconciliation |
| --- | --- |
| `DisableAdditionalAuthAtStart` | The library defines `DisableAdditionaAuthAtStart` (missing “l”); verify and correct the intended legacy behavior. |
| `DisableBrowserServiceView` | The library defines `DisableBrowserSvcView`; verify whether the shortened function is the intended implementation. |
| `EnableInkingAndTypingData` | No matching function is defined; preserve as unresolved until implementation or removal is decided. |
| `InstallNucleusKernelFATNFTS` | The library defines `InstallNucleusKernelFATNTFS`; reconcile the transposed letters. |
| `RemoveWinCSP` | The library defines `RemoveWinSCP`; reconcile the preset typo and keep the removal selector with the WinSCP package batch. |
| `RemoveWSLFedora` | No matching function is defined; the Fedora install selector has no matching removal implementation. |
| `RequireAdmin` | This is a preset prerequisite directive, not a function. Represent the privilege requirement in operation metadata and profile/run guidance rather than as an operation. |

## Library functions outside the preset inventory

The following 23 function names are defined in the legacy modules but are not selected by name in `default.preset`; keep them out of these batches and record them as a separate future-review backlog:

`DisableAdditionaAuthAtStart`, `DisableBrowserSvcView`, `DisableFirewallDomain`, `DisableFirewallPrivate`, `DisableFirewallPublic`, `DisableWSUS`, `EnableFirewallDomain`, `EnableFirewallPrivate`, `EnableFirewallPublic`, `EnableWSUS`, `Export-FunctionFromFile`, `Get-PackageInfo`, `Get-RideBootstrapFolder`, `Get-RideSoftwareFolder`, `Get-RIDEvars`, `Install-RideDownloadedExe`, `Install-RideDownloadedMsi`, `InstallEntraConnect`, `InstallNucleusKernelFATNTFS`, `RemoveWinSCP`, `Save-RideDownload`, `Test-FunctionName`, and `Test-RideDownloadOnly`.

Several items overlap with misspelled preset selectors listed above. Those functions remain outside the inventory until the selector mismatch is reconciled.

## Package download and artifact records

The current minimum is a working **download latest** path. Package operations must be able to resolve the current release, select the declared Windows artifact, download it without installing it, and report the version and file location. Installing the latest release uses the same resolver and acquisition path. A missing publisher checksum or signature must not prevent acquisition or ordinary package installation; report the available evidence and the locally observed hash accurately so users can make an informed choice. The first provider adapters are 7-Zip, Notepad++, and Git for Windows.

Each provider adapter returns structured release metadata: package ID, resolved version, architecture, filename, artifact URI, release/source URI, any provider-reported digest, and available checksum/signature sidecar URIs. Reject malformed URLs, ambiguous asset matches, and a provider digest mismatch. Do not discard a downloaded installer after a successful install; retain it in the configured artifact repository for reuse and record its observed SHA-256.

The shared, version-controlled `catalog/artifact-observations.json` is an append-only metadata library, not a binary repository or trust store. Each observation binds package ID, resolved version, filename, source URI, acquisition time, route/transport label, and observed SHA-256 to one exact file. It may also record a provider digest, signature/checksum evidence and result, Authenticode signer details, and file size. A hash computed only after download is an observation, not publisher authentication. Multiple observations for the same exact artifact are retained so later work can compare downloads made through independent internet paths. Do not claim independence solely because observations have different timestamps or users.

Maintain `docs/PACKAGE-VERIFICATION-MATRIX.md` from per-package source investigations. Record whether the official source resolves latest, provides exact versioned URLs, publishes checksums, offers detached signatures and a key identity, or supplies an Authenticode signature. Distinguish publisher-provided evidence from hosting-provider metadata and from hashes RIDE observes itself. The matrix informs a later policy decision; it does not block latest acquisition. The CLI `download` command acquires without installing; artifacts are retained by package and version, and observations are appended to `catalog/artifact-observations.json`.

Package presence remains separate from acquisition: downloading an installer does not make its operation `Present`. A later install-from-repository mode should install an already acquired artifact without network fallback. Download-only `Artifact` catalog entries are separate from packages and desired Windows state; the first is the user-selected SwiftOnSecurity Sysmon XML, resolved to an immutable Git commit URL and retained without applying it.

### Verification vocabulary and future policy decision

The earlier policy names `Bypass`, `Verified`, and `Strict` are provisional. `Verified` was intended to mean validation using provider/publisher evidence (for example a published checksum, detached signature, or Authenticode identity); a RIDE-computed SHA-256 alone is only an observed hash. Do not make `Verified` the default or require pinned exact versions until the package matrix shows which evidence is actually available. Keep download/install latest usable while collecting that evidence.

Any provider-reported digest that RIDE chooses to check must match the downloaded bytes; a mismatch is a hard failure. Record unavailable, invalid, or untrusted signature/checksum evidence without mislabeling the file. After the matrix is populated, decide which policies should gate installation, whether a trust exception is needed for checksum-only sources, and how machine-enforced minimums interact with user choices. Strict could later require exact version pinning, trusted publisher signatures, a signed repository manifest, and approved providers; those are decisions for the evidence review rather than prerequisites for this phase.

### Package-specific Defender exclusions

Before migrating additional packages that are known to trigger Microsoft Defender alerts, add package-level compatibility metadata and use it as the source for narrowly scoped directory exclusions. Dual-use forensic and security tools can exhibit behavior that overlaps with malicious activity; an observed alert is a reason to record and review the exception, not a blanket verdict that the package is safe.

- Record the package ID, affected exact version and artifact digest where known, Defender detection name or ID, affected file, observation date, evidence/source, rationale, and review status. Keep the record tied to the reviewed package artifact; require renewed review when the artifact changes.
- Install each package that needs an exception into an isolated, deterministic package directory under the configured `ToolsDirectory`. Metadata must identify the exclusion scope as that package directory. Do not derive a package exception by excluding the shared `ToolsDirectory` parent or a general Downloads directory.
- Generate exclusions only for packages selected for installation by the applicable analyst/tooling profile and whose metadata contains a reviewed exception. Show each package, exact resolved path, and recorded reason in the plan and run report; provide a readable grouped summary when several packages share a path.
- Preserve the existing repository-tools and bootstrap exclusions as separately documented compatibility decisions while this step is implemented. Do not silently remove or broaden them as a side effect of package metadata work. Review whether each remains needed against the repository functions and bootstrap workflow that prompted it.
- Capture pre-change exclusion state and restore only the state changed by the run. Deduplicate identical exact paths without broadening the resulting set.

**Verification required:** Add mocked Pester coverage proving that reviewed packages selected by the profile produce only their declared package-directory exclusions; unreviewed or unselected packages produce none; configured `ToolsDirectory` changes resolve correctly; duplicate paths are deduplicated without promoting them to a parent directory; `WhatIf` makes no change; existing exclusions are preserved; and restore removes only exclusions introduced by the run. In a disposable Windows 11 and Windows Server 2025 VM, inspect effective Defender exclusions and verify that a reviewed package's intended functions work while a neighboring, unexcluded directory remains scanned. Do not use live malware as a test fixture. The plan/report must make the longer exception list reviewable by package, path, version, evidence, and reason.

Expose the `download` command explicitly through the CLI and keep it separate from `RIDEVAR-Download-Only` and other legacy environment flags. Mock HTTP requests, digest comparison, and installer processes in Pester; verify that download-only never starts an installer and that installation uses the same acquisition path. Provider digests, when offered and checked, must match the downloaded bytes. Add installer failure, idempotence, and `WhatIf` cases. Future local-repository and signature-enforcement modes remain follow-up work informed by the source matrix.

7-Zip, Notepad++, and Git for Windows now resolve the latest GitHub release to a versioned asset. The release API endpoint remains mutable by design to satisfy the latest-download baseline; each resolved artifact URI and version are recorded in the observation library. Publisher signature verification and reproducible installation from the local artifact repository remain future work.

## Package variants and portable lifecycle

**Approved decision, 2026-10-09; implementation pending:** Support both installed
and portable distributions, with a recommended default per product and explicit
overrides. Offer only catalog-declared variants that have been implemented and
tested; supporting both does not require every product/provider combination.
The [README package table](../README.md#future-package-options) distinguishes
distribution (installed or portable), artifact format (MSI, EXE, ZIP or standalone
file), and provider (direct publisher download or WinGet). Scope remains a
separate constraint declared by each supported variant.

### Catalog and selection contract

- Keep one stable product ID, such as `package.sharex`, with variants in its
  catalog record or referenced manifest. Each variant declares acquisition,
  detection, supported Windows targets, scope, privileges, dependencies,
  install/removal behavior, and recovery limits. Provider adapters share the
  package lifecycle rather than duplicating it.
- Use installed editions by default for ordinary desktop applications where
  their integration is useful, and portable editions for portable-only products
  and suitable managed tools. Prefer MSI when features are equivalent and its
  lifecycle is tested; do not impose one artifact format on every product.
- Allow optional global distribution/provider preferences in the agreed local
  configuration. Explicit profile or command selections override preferences;
  unsupported explicit selections fail clearly. A preference may fall back to
  the product default when unavailable, with the reason shown in the plan.
- Resolve the selected variant, provider, scope, and destination during planning
  and record them with the artifact/version evidence in the saved run. Removal
  and restoration use that recorded selection rather than re-evaluating current
  preferences. Installation failures must not trigger a switch of variant or
  provider; the separate acquisition fallback rules below remain bounded to
  approved equivalent sources.
- Report an existing different edition instead of silently installing a second
  copy or replacing it. Changing installed to portable, or the reverse, requires
  an explicit migration that accounts for configuration and integration.
- Preserve existing IDs and profiles: entries without a variant retain their
  current catalog default. Version any required catalog/profile/state schema
  change and document its migration and recovery path. Final field/CLI names
  remain implementation work; new enumerable parameters require read-only
  completion and synchronized help.

### Managed portable lifecycle

- Install machine portable packages into isolated, deterministic product
  directories under the configurable `ToolsDirectory`. Any supported user
  variant must declare its user-scoped destination and state ownership.
- Record managed files, version, artifact evidence, shortcuts, and PATH changes.
  Detect presence from both the ownership manifest and actual files, reporting
  missing or modified files. Do not adopt arbitrary existing files implicitly.
- Preserve application settings and user-created files during upgrades and
  removal. Remove only owned package content and integration; never delete the
  shared tools root or overwrite modified/user files without an explicit policy.
- Participate in planning, `ShouldProcess`, pre-change capture, idempotence,
  status, and partial-failure reporting. Exact binary recovery requires retained
  verified artifacts and captured prior file state; application-data recovery
  must be declared separately. Otherwise report compensating recovery limits.
- Declare services, drivers, reboot requirements, and other system changes even
  for publisher-labelled portable products. Managed-file removal alone cannot
  recover those side effects. Defender exceptions remain governed by the
  separate package-specific exclusion decision above.

### Implementation order and acceptance

Implement direct managed-portable support alongside the existing EXE/MSI
handlers first, then add WinGet as an optional provider. Keep the standalone
bootstrap usable without requiring WinGet. Resume deferred portable selectors
from the [Install programs ledger](migrations/install-programs-dispositions.md)
and [System Tools ledger](migrations/system-tools-dispositions.md) only after
their package-specific source, ownership, dependencies, and recovery work is
complete.

Require mocked tests for variant/preference resolution, strict explicit choices,
existing-edition conflicts, safe extraction and ownership, modified/user-file
preservation, repeat installation, removal, recovery, `WhatIf`, and partial
failures. Exercise each offered variant/provider lifecycle in disposable Windows
VMs on its declared targets before claiming support, including upgrades with
preserved user data and cleanup of owned shortcuts/PATH changes. This decision
does not mark any deferred selector implemented or extend Windows support.

## Multiple package sources

Represent all approved acquisition/install providers for a package in its single package record or referenced manifest. For example, a package can describe both a direct GitHub release artifact and a WinGet source, with each provider's package identifier, exact version mapping, architecture, artifact metadata, and verification requirements. Provider adapters implement the mechanics; package-specific PSM1 files must not duplicate the package lifecycle or make implicit source choices.

Source selection should be deterministic and policy-driven: allow an explicit source choice and a configured preference among approved providers. An explicit provider choice must not fall back to another provider. Auto-selection may move to another provider only when it is approved for the same package/version, distribution, and scope and satisfies that provider's pinned artifact and trust metadata. An acquisition transport or availability failure may permit trying the next approved provider, with the resolved provider reported; an installation failure, version mismatch, hash mismatch, invalid signature, or unexpected publisher must stop the operation. Do not silently retry an integrity failure through a different source.

When providers supply different installers or materially different package builds, model them as distinct artifacts with provider-specific metadata and verification, even when they install the same logical package. Record the selected provider and artifact digest in the download manifest and run report so an installation can be reproduced and audited. Tests should cover provider preference, explicit source selection, approved transport fallback, and fail-closed verification errors.

**Agreed storage choices:** customizable values live in data-only, schema-versioned local configuration, split by scope: machine configuration under `%ProgramData%\RIDE\configuration.psd1` and user configuration under `%LocalAppData%\RIDE\configuration.psd1`. `ToolsDirectory` is machine-scoped and defaults to the system-drive `Tools` directory; it is not a catalog default or process environment variable. Package profiles currently resolve latest; exact-version selection and repository-backed reproducibility are later options, not prerequisites for acquisition.

## Acceptance and later integration

- For every batch, run catalog/profile validation and Pester coverage for planning, handler behavior through mocks, idempotence, `WhatIf`, and applicable restore or compensating behavior before accepting the batch.
- Keep package tests offline and deterministic by mocking download resolution and installer processes.
- Before accepting package migrations that use Defender exceptions, complete the package-specific exclusion metadata step and its mocked and disposable-VM verification above; ensure plans and reports identify every package-scoped exception.
- Defer complex disposable-VM scenarios—including reboot/Sysprep, broad Windows component changes, multi-user or machine-wide configuration, destructive cleanup, and live installer recovery—to a later integration phase.
- Add or retain Windows support declarations only after the affected operations pass their applicable disposable-VM checks on Windows 11 and Windows Server 2025.
