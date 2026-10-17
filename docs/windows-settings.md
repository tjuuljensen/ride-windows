# Windows settings

Use `show <id>`, `plan` and `status` to inspect the live and requested values
before changing a setting. The [operation catalog](OPERATIONS.md) declares
supported targets and actions; the guides below explain effects and recovery.

Image-dependent registry defaults appear as `<platform-defined>` in `status`;
their `MatchesDefault` field is unknown. See the
[default-value contract](setting-presentation.md#defaults-and-recovery).

Setting views distinguish scope, administrator requirements, preference/policy
behavior and GUI effects. See [setting presentation](setting-presentation.md)
for requirements, evidence gaps and user identity under elevation.
The [media and privacy comparison](setting-presentation.md#media-and-privacy-choices)
explains AutoPlay preferences versus drive policy, clipboard history versus sync,
and the separate location/advertising policy recovery boundaries.

Optional [PowerShell profile settings](powershell-profiles.md) provide separate
5.1/7 normal-session palettes and consistent administrator blue. Tab completes
Recommended, AdminBlue, Default and Baseline; unset/default remove only the managed
block. Accepted on Windows 11 and Server 2025 Desktop Experience; see the
[VM acceptance record](archive/migrations/powershell-profile-acceptance.md).
Inspect it with `list profile-settings` or use the optional
`profiles/powershell-colors.psd1` selection profile.

Coordinated settings such as `windows.mouse-pointer-precision` and
`windows.control-panel-view` expose one named state for several related values.
Tab completes those states. `unset` removes all declared overrides;
`restore -RunId <id>` recovers each captured value and type. Partial failures
retain the complete pre-change record. Inspect each operation in the [catalog](OPERATIONS.md) for its declared states.

Task, adapter, SMB, Defender, power-scheme, NetBIOS, firewall and sound settings
use explicit states and saved-run restore. Their native defaults can depend on
the device; `unset` is unavailable when removing an override has no meaning.
See the [catalog](OPERATIONS.md) for operation-specific dependencies and support.
Unaccepted settings remain candidates until their target checks pass.

Defender directory exclusions bind apply to the path and membership captured by
the engine. Changed configuration refuses the write; failed verification retains
the saved record for recovery. See the [exclusion recovery contract](setting-presentation.md#defender-exclusion-capture-and-recovery)
for versioned records, older records and directory/managed-visibility limits.

Power-plan indexes retain the full unsigned 32-bit value in inspection and saved
state. The [power recovery contract](setting-presentation.md#power-index-record-compatibility)
explains compatibility with older signed captures and the typed native reader's
pending target acceptance. Custom indexes are not rounded to catalog presets.

WAP Push and Windows Search offer startup-only and combined service presets;
Tab completes their catalog states. New delayed-start choices await VM acceptance.
See [service settings](service-settings.md) for runtime effects and recovery.

[Modern firewall profiles](firewall-profiles.md) provide pending Domain,
Private, Public and enable-all controls with local/effective inspection. Apply
targets remain unavailable until VM acceptance; Tab completes their states.

The pending [Windows Update notification policy](update-notifications.md)
coordinates display options and includes the manual active-hours/restart/deadline
workflow; suppression does not prevent restarts.

The pending [Windows CEIP policy](ceip-policies.md) keeps participation,
override removal and App-V reporting separate; current collection remains unverified.

Use the [Windows Security icon guide](security-icon-startup.md) for separate
machine policy and intended-user startup checks; GUI steps remain manual.

[Keyboard repeat delay](keyboard-repeat-delay.md) offers stored positions 0-3
with typed saved recovery. It retains registry-only behavior pending GUI/native
acceptance; Tab completes its catalog states.

[Owned power-plan copies](owned-power-plans.md) separate explicit creation
from existing-plan selection, with recorded ownership and recovery restricted
to unchanged inactive copies. These experimental candidates remain blocked
pending target acceptance; Tab completes `Create`.

[Conditional media policies](media-policies.md) keep user radio-preset and
machine WMDRM controls separate, with current component effects still pending.

[Server policies](server-policies.md) keep Server Manager automatic startup
separate from its console preference and Shutdown Event Tracker choices in one
paired policy. Server target acceptance remains pending.

[Windows Audio service](audio-service.md) offers guarded whole-device
Automatic/running or Manual/stopped choices. It stays separate from endpoint
mute and awaits target acceptance. For manual device-specific Mute/Unmute, use
the [native playback-device guide](audio-service.md#mute-a-selected-playback-device),
which preserves volume and default-device roles and explains manual recovery.
See [input and audio choices](setting-presentation.md#input-and-audio-choices)
for the different baseline, unset and saved-restore behavior of keyboard delay,
pointer precision, sound schemes and startup sound.

[Local maximum password age](local-password-policy.md) offers explicit
day choices and focused SAM field recovery. The candidate refuses domain
controllers and remains blocked pending target acceptance.

Use the [BitLocker recovery guide](bitlocker-recovery.md) for explicit
native backup and selected-key retrieval. Automated creation and secret handling
remain pending; no recovery secret belongs in RIDE state or reports.

Use [Windows recovery readiness](recovery-readiness.md) to prepare independent
media, backups and access before a deliberate Advanced startup entry. Windows RE
enable/disable lifecycle and boot acceptance remain pending.

The [Network discovery guide](network-discovery.md) separates connection
profiles, discovery and authenticated sharing. It preserves the retired Computer
Browser override and awaits peer/target evidence.

The [Storage Sense guide](storage-sense.md) preserves independent cleanup choices
and separates captured settings recovery from deleted files and offline content.
Current GUI/content evidence remains pending.

The [System protection guide](system-protection.md) keeps volume scope, storage
allowance and restore history explicit. Its native handoff adds no backend;
history loss cannot be reversed by restoring configuration.

Use the [Feedback frequency guide](feedback-frequency.md) for the intended-user
Settings choice. Machine request policy and scheduled tasks stay separate; the
paired interval backend remains pending type/unit and GUI evidence.
