# Settings post-migration review

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
Cortana profile. First determine whether the current personalization UI is one
coherent operation requiring multiple values. Exact registry recovery does not
recover learned words if Windows clears them as a feature side effect.

## Review of other existing splits

The source review matched literal registry paths and values across the maintained
catalog and legacy function ASTs without importing or executing the legacy
module, then inspected the additional service, background-app and registry-tree
operations. These sixteen registry split families include both reverse selectors;
the following table records an explicit decision for each. It evaluates the
choice to split, not new proof of every feature's Windows integration acceptance.

| Legacy family | Current operations / boundary | Evaluation and remaining work |
| --- | --- | --- |
| DisableTelemetry / EnableTelemetry | `windows.diagnostic-data-policy`, `windows.linguistic-data-collection-policy` | Retain separate outcomes: diagnostic level and linguistic sample collection. Partial coverage; no promise of zero telemetry, task changes or Office controls. Off depends on edition. |
| DisableCortana / EnableCortana | Three preferences in the preceding section | Experimental; reject Cortana enablement terminology. Determine whether a single personalization operation is more appropriate. |
| DisableAppSuggestions / EnableAppSuggestions | Fifteen preferences in the preceding table | Experimental; numbered channels unresolved. Defer a user-facing bundle until feature evidence exists. |
| DisableActivityHistory / EnableActivityHistory | `windows.activity-history-feed-policy`, `windows.activity-history-publish-policy`, `windows.activity-history-upload-policy` | Three distinguishable policy stages, but coupled by the feed policy. Retain IDs; current app/OS relevance and dependency acceptance still required before presenting them as three independent privacy benefits. |
| DisableLocation / EnableLocation | `windows.location-service-policy`, `windows.location-scripting-policy` | Keep service-wide and scripting scopes distinct. Verify the scripting policy's current consumers; explain that service policy can dominate scripting access. |
| DisableUWPVoiceActivation / EnableUWPVoiceActivation | `windows.uwp-voice-activation`, `windows.uwp-voice-activation-above-lock` | Keep general and locked-device permissions distinct. Descriptions now state the dependency and covered-app scope; exact policy section links replace broad references. |
| DisableUWPFileSystem / EnableUWPFileSystem | `windows.uwp-documents-library-access`, `windows.uwp-pictures-library-access`, `windows.uwp-videos-library-access`, `windows.uwp-broad-file-system-access-access` | Library scopes are useful choices, but the legacy CapabilityAccessManager mapping has only feature documentation. Review current consent/UI effects, existing per-app decisions and broad-access dependencies; no universal filesystem block claim. |
| DisableAdminShares / EnableAdminShares | `windows.admin-share-server`, `windows.admin-share-workstation` | Valid platform split: only the target-appropriate operation applies. Preserve service-restart boundary and workstation mapping qualification. |
| EnableDotNetStrongCrypto / DisableDotNetStrongCrypto | `windows.dotnet-strong-crypto-64bit`, `windows.dotnet-strong-crypto-32bit` | Valid application registry-view split. An understood optional profile could select both; distinguish .NET Framework defaults and app/framework overrides. |
| DisableUpdateDriver / EnableUpdateDriver | `windows.update-driver-policy`, `windows.device-metadata-downloads` | Keep driver quality updates and device-associated app metadata separate. Partial coverage; DriverSearching/SearchOrderConfig is deferred, and metadata control is not a driver-installation block. |
| DisableMaintenanceWakeUp / EnableMaintenanceWakeUp | `windows.maintenance-wake-policy`, `windows.maintenance-wake-timer` | Two different mechanisms with one broad legacy goal. Further review required for modern update behavior, power/hardware prerequisites and WakeUp mapping. Do not promise to prevent every wake source. |
| DisableActionCenter / EnableActionCenter | `windows.action-center-policy`, `windows.toast-notifications-policy` | Valid distinction: center visibility versus transient banners. Corrected the center description, which previously claimed both. ToastEnabled mapping still needs current feature acceptance. |
| DisableAccessibilityKeys / EnableAccessibilityKeys | `windows.sticky-keys-prompts`, `windows.toggle-keys-prompts`, `windows.filter-keys-prompts` | Individual features are useful choices, but legacy Flags strings overwrite an entire bitfield. Review all changed bits; consider a focused masked update preserving unrelated preferences before describing these as prompt-only changes. |
| SetTaskbarCombineAlways / WhenFull / Never | `windows.taskbar-combine-primary`, `windows.taskbar-combine-secondary` | Valid primary/secondary display choice. A single-display VM cannot prove secondary-display effects; verify current taskbar UI and multi-monitor dependencies. |
| ShowSuperHiddenFiles / HideSuperHiddenFiles | `windows.protected-files-visibility`, `windows.hidden-files-visibility` | Valid distinct file classes with a dependency: hidden-files visibility also affects the protected-files outcome. Do not imply that protected visibility alone reproduces the legacy combined command. |
| HideRecentShortcuts / ShowRecentShortcuts | `windows.explorer-recent-shortcuts`, `windows.explorer-frequent-shortcuts` | Valid recent-file versus frequent-folder outcomes. These affect presentation, not history deletion; verify Explorer Home behavior separately from registry equality. |

Additional cases that do not appear as multiple scalar registry matches:

- Background apps: `windows.uwp-background-apps` and
  `windows.uwp-background-app-overrides` represent a policy and resetting existing
  per-app decisions. Reset is a different action, not an unconditional inverse
  of a broad disable. Keep both discoverable and explain their interaction.
- `windows.ssdp-discovery-service` and `windows.upnp-device-host-service` are
  separate services. A reviewed profile could express a combined discovery goal,
  with service dependencies and startup/running-state recovery visible.
- The Music, Videos and 3D Objects This PC operations use RegistryKeySet because
  multiple namespace keys implement one folder's visibility. This is the correct
  alternative to exposing one operation per registry write.
- AC and battery lid actions are independently useful power outcomes. Their
  migration does not implement selection or creation of a whole power scheme.

No existing profile is rewritten by this review. Some earlier mappings already
occur in profiles; the further-review dispositions above remain explicit
acceptance work, not an assertion that those settings are functionally approved.

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

This review changes presentation, references and migration acceptance guidance.
It preserves IDs, values, states, supported targets and saved-run schemas. It
does not run Windows changes, start a VM, request elevation or claim new UI tests.

Validation passes on Windows PowerShell 5.1 and PowerShell 7 for all 174
operations, 2 groups, 4 profiles and 52 maintained PowerShell files. Generated
documentation is current and the focused diff has no whitespace errors. A
comparison with the catalog staged for the successful forty-setting VM run
confirms that only names, descriptions and references changed in 22 entries;
all other operation metadata is identical. The unresolved channels remain
outside every profile. No additional lifecycle tests were needed for these
presentation changes; the unresolved feature checks remain outstanding.
