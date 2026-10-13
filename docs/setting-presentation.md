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

Initial reviewed metadata covers file-name extensions, sound-scheme editing,
Edge startup boost and Defender cloud-delivered protection. Their feature/GUI
acceptance remains tracked in the
[post-migration review](migrations/settings-post-migration-review.md).

The Defender `Advanced` state retains its published value and recovery contract.
The catalog explains built-in protection versus separately licensed enterprise
services, required Antivirus availability/connectivity, and the inferred absence
of a separate account/onboarding step. Local-account VM acceptance remains pending.

## Remaining implementation and acceptance

Audit the remaining settings before filling their presentation fields. Add
observable effective-policy/source inspection per feature, not a generic registry
heuristic. Enforce and verify intended-user selection for mixed-scope elevation,
including alternate administrator credentials, before declaring execution safe
for the interactive user's profile. This first increment displays that gap; it
does not introduce a user selector or change HKCU execution semantics.

The first increment's focused Pester and catalog/reference checks passed on
native Windows PowerShell 5.1 and PowerShell 7 after the concurrent application
migration finished; the post-migration review records results and fixture retries.
GUI/sign-in/reboot, managed precedence and Windows Server acceptance remain
disposable-VM work.
