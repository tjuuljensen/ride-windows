# Read-only desired-configuration reference

Export a selected RIDE profile for a separate observation/evaluation consumer.
RIDE remains the configuration owner under [ADR 0001](decisions/0001-configuration-ownership.md).
The reference describes requested configuration; it is not an apply plan, a
backup, a machine observation or evidence of compliance. LoggingBaseline consumer
integration is pending. Measurement thresholds remain owned by that consumer.

From the repository root in native Windows PowerShell 5.1 or PowerShell 7, provide
an explicit profile and independently known target details. No elevation or
network access is required. The output parent must already exist and the output
filename must be new. Source profiles should be reviewed declarative data.

```powershell
$reference = @{
    Profile = '.\profiles\default.psd1'
    Target = 'Windows 11'
    Build = 26100
    EditionId = 'Professional'
    InstallationType = 'Client'
    Role = 'Workstation'
    OutputPath = 'C:\Evidence\desired-reference.json'
}
.\tools\Export-RideDesiredConfiguration.ps1 @reference -WhatIf
.\tools\Export-RideDesiredConfiguration.ps1 @reference
Get-Help .\tools\Export-RideDesiredConfiguration.ps1 -Full
```

Use the actual target details, not the sample values. For Server, InstallationType
is `Server` for Desktop Experience or `Server Core`; use `Unknown` when it has not
been established. Role accepts Workstation, MemberServer, DomainController or
Unknown. These values are declared inputs and are not independently verified.
Tab completion lists repository profiles for `-Profile`, catalog supported and
candidate target names for `-Target`, and declared choices for installation/role.
Target suggestions include pending candidates and do not establish support.

WhatIf reads neither source nor live state and creates no file. Execution loads
the built-in catalog through its bounded data-only reader, validates the profile,
and binds both exact files by SHA-256. Source changes during generation refuse
output. Profiles are limited to 64 KiB; output is limited to 4 MiB. No operational
engine, installer, local configuration, saved run or private review store is read.
Custom libraries and external measurement-policy files are outside this version.

## Schema 1

`Kind = RideDesiredConfigurationReference` declares configuration owner RIDE and
consumer permission ObserveEvaluateReportOnly. The source identity records the
profile name and exact profile/catalog hashes. DeclaredTarget retains platform,
build, edition, installation type and role with Observed=false. Every selected
ID is retained in source order; duplicate or conflicting IDs are rejected.

| Field | Meaning |
| --- | --- |
| RequestedState / ResolvedState | Preserve the profile request; Baseline resolves only for kinds with the engine's declared baseline contract. It is not a Windows default or saved-state restore. |
| DeclaredTargetStatus | DeclaredSupported, NotApplicable, PendingAcceptance or Unknown. This compares catalog metadata with supplied inputs; edition/role/component/policy availability is not inferred. |
| ReferenceMode | DeclaredRegistryIntent for RegistryValue/RegistryValueSet; ReportOnly for other handlers and groups. |
| Mappings | Ordered registry path/name/type and SetValue, RemoveValue or KeepCurrent intent. Null removal, zero, empty string and arrays remain distinct. No environment expansion occurs. |
| RegistryView | NotSpecifiedByCatalog; consumers must establish the proper native/view mapping separately, preserving explicit Wow6432Node paths. |
| Members | Declared group membership order, retained for context. It is not expanded into configuration or reversed into an uninstall plan. |
| Variant / Scope | Explicit package variant request is retained; package scope/target remain unresolved. The exporter never chooses a destination or reads preferences. |
| CurrentState / Compliance | Always Unknown. No live observation or compliance comparison occurs. |

Pending/unsupported declarations remain visible; registry mapping presence does
not authorize execution or prove the setting's visible effect. A consumer must
validate schema/kind, confirm source identity, bind the intended machine/user and
registry view, and treat unsupported mappings or unavailable observations as
unknown/report-only. It must not execute registry instructions, silently omit
unknown selections, or conflate removal of an override with an effective default.
No credentials, installer arguments, private property stores or measurement
thresholds are exported. Review any separately authored profile/catalog content
before sharing an export.

ReadyForMutation and RecoverySupported remain false. This schema is separate from
existing saved-run/state schemas and cannot be imported as a restore record.
Unsupported future schema versions must be rejected rather than guessed. Keep
the pinned source files alongside a retained reference to reproduce its meaning;
GeneratedAtUtc is informational and not a stable content identifier.

## Verification and recovery

Inspect all selections, declared target statuses and unmapped ReportOnly items.
The source hash binds bytes but does not authenticate a publisher or prove a
trusted configuration. No setting changes occur, so no Windows restoration is
needed. Existing/racing outputs are preserved. On a write failure retain any
partial file for diagnosis and choose a new filename; do not treat partial JSON
as a valid reference. Actual consumer and native mapping acceptance remain in
the [migration evidence](migrations/settings-post-migration-review.md#b10-read-only-desired-configuration-reference-2026-10-17).
