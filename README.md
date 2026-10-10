# RIDE-Windows

RIDE (Remove, Install, Disable, Enable) is a PowerShell engine for setting up and maintaining Windows workstations and servers. Profiles declare the requested state; a catalog describes each operation and its supported actions. RIDE is a personal automation project, not a complete security baseline. Review every profile and operation before applying it.

## Quick start

Run the default profile from a local checkout:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ride.ps1 plan
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ride.ps1 apply
```

The default profile shows file extensions, disables Autoplay, Autorun, and inking and typing data collection, and installs 7-Zip. Package and machine policy operations require an elevated PowerShell session. To download the repository and run the default profile on a new machine:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri https://raw.githubusercontent.com/tjuuljensen/ride-windows/master/docs/bootstrap.ps1 -OutFile $env:TEMP\ride-bootstrap.ps1; & $env:TEMP\ride-bootstrap.ps1 -Default"
```

Use `-NoRun` to download and inspect the files without applying anything, or `-Edit` to copy and edit the default profile before running it.

## Commands

Run `.\ride.ps1 -Help` for command usage, options, and examples.
When using PowerShell interactively, press Tab to complete commands, operation and group IDs, profile paths, saved run IDs, and the declared states of registry and desktop Shell folder settings.

| Command | Purpose |
| --- | --- |
| `list [view]` | Emit one consistent PowerShell object collection for catalog entries and profiles; views include `all`, `profiles`, `packages`, `windows`, `explorer`, `security`, `software`, `utilities`, `groups`, and `settings`. |
| `show <id>` | Show operation metadata and its current value; settings also show their baseline value. |
| `plan -Profile <file>` | Display each selected operation's current value beside its desired profile value. |
| `apply -Profile <file>` | Apply the profile's desired state and save prior state for changed operations. |
| `download <catalog-id>` | Download the latest package or standalone artifact without installing/applying it; retain it by item and version and record its observed SHA-256. |
| `install <package-id>` | Install one catalog package and save its prior state. |
| `set <setting-id> -State <state>` | Set one catalog setting to a declared state and save its prior value. |
| `unset <setting-id>` | Remove a setting value when the catalog declares an unset state, saving its prior value. |
| `status [view]` | Show target-specific defaults and live state, optionally filtered by a view such as `packages`, `windows`, `explorer`, or `security`. |
| `status [view] -Profile <file>` | Compare the selected operations' current values and states with the profile's desired values and states. |
| `restore -RunId <id>` | Restore settings captured before a prior run. Package restoration may require reinstalling the current upstream version. |
| `remove <package-id>` | Uninstall one catalog package and save its prior state. |
| `remove -Profile <file>` | Uninstall packages selected by a profile, in reverse group order. |

Image-dependent registry defaults appear as `<platform-defined>` in `status`;
their `MatchesDefault` field is unknown. See the
[migration/default contract](docs/MIGRATION-PLAN.md#optional-windows-settings-session-2026-10-09).

Use `download package.7zip -Destination <path>` to choose the artifact directory. Use `download artifact.sysmon-swift-config` to retain the latest SwiftOnSecurity XML at an immutable Git commit revision; RIDE does not apply this file automatically. Download records in `catalog/artifact-observations.json` are metadata only; a locally observed SHA-256 is not publisher authentication. See the [package verification matrix](docs/PACKAGE-VERIFICATION-MATRIX.md) for current source evidence. Append `-WhatIf` to a state-changing command to preview a change. An operation's supported actions, privilege needs, scope, and rollback limits are shown by `list`, `show`, and the generated [operation catalog](docs/OPERATIONS.md).

The optional God Mode desktop shortcut uses the current user's desktop,
including a redirected desktop. Preview it with
`.\ride.ps1 set windows.god-mode-shortcut Present -WhatIf`, then omit `-WhatIf`
to create it. Use `.\ride.ps1 unset windows.god-mode-shortcut` to remove it or
`restore -RunId <id>` to recover captured prior state. It creates the special
folder described in the [God Mode guide](https://www.tomshardware.com/how-to/enable-god-mode-windows-11).
Removal refuses nonempty folders. See the [folder workflow](docs/GOD-MODE.md)
for profile configuration and recovery details.

Packages and standalone artifacts include publisher license references in the
catalog and download records. Individual/company reviews stay in local,
exportable JSON. Use `tools/Manage-RideLicenseReviews.ps1 -Help` for Get, Set,
Export and Import; Tab completes commands, review statuses and catalog IDs.
See [Package licensing](docs/PACKAGE-LICENSING.md) for storage and examples.
Offline bundle creation and its redistribution review step are optional future work.

## Future package options

The approved v3 design supports installed and portable editions, with a
recommended default per product and explicit overrides for tested variants.
These selection options and general portable support are not implemented yet.

| Choice | Examples | What it determines |
| --- | --- | --- |
| Distribution | Installed, portable | How the application lives on the machine |
| Artifact format | MSI, EXE, ZIP, standalone file | How RIDE installs or extracts it |
| Provider | Direct publisher download, WinGet | Who acquires and manages the package |

WinGet is a provider that can install different distribution and artifact types.
Each product keeps one stable catalog ID; its variants declare supported scope
and lifecycle behavior. Portable packages will use dedicated directories and
managed-file records to preserve user data during upgrades and removal. Direct
portable support comes first; WinGet follows as an optional provider. See the
[package decision in the migration plan](docs/MIGRATION-PLAN.md#package-variants-and-portable-lifecycle)
for selection, recovery, and validation requirements.

## Profiles

Profiles are PowerShell data files under `profiles/`. They list operation IDs and desired states. For example:

```powershell
@{
  SchemaVersion = 1
  Name = 'Analyst workstation'
  Description = 'A small set of analyst utilities.'
  Operations = @(
    @{ Id = 'windows.show-known-extensions'; State = 'Enabled' }
    @{ Id = 'solution.analyst-basics'; State = 'Present' }
  )
}
```

Apply a profile with `.\ride.ps1 plan -Profile .\profiles\analyst-basics.psd1`, then `.\ride.ps1 apply -Profile .\profiles\analyst-basics.psd1`. Use `State = 'Baseline'` in a profile to select each operation's catalog-declared baseline. `restore` instead uses saved pre-change values.

## State and support

RIDE records versioned snapshots only for operations it changes. Machine records are stored under `%ProgramData%\RIDE\State`; user records are stored under `%LocalAppData%\RIDE\State`. Machine operations must run elevated. User operations run in the current user's context.

The catalog currently targets Windows 11 and Windows Server 2025. Support is declared per operation, and the engine rejects unsupported targets. More operating system versions should be added only after their relevant integration scenarios pass.

## Development

- `catalog/operations.psd1` defines the operation catalog and solution groups.
- `profiles/*.psd1` defines reusable selections.
- `modules/RIDE.Engine.psm1` plans and runs operations; focused handler modules implement registry settings, desktop folders, Defender exclusions, and packages.
- `docs/OPERATIONS.md` is generated from the catalog.
- `tools/validate.ps1` checks PowerShell syntax, catalog/profile references, and generated docs.
- `tests/` contains Pester tests. `tests/integration/` documents disposable VM checks.
- [Script model](docs/models/script-repository-model.md) defines
  headers, versioning, safety, and validation for maintained PowerShell scripts.
- Use `Get-Help .\ride.ps1 -Full` for native help or `-Help` for quick usage.
  Standalone maintained scripts expose `-Version` without operational work.
  See the [PowerShell walkthrough](docs/migrations/powershell-script-walkthrough.md)
  for per-file validation and retained legacy/upstream exceptions.

Run static and unit checks on Windows:

```powershell
.\tools\validate.ps1
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0 -MaximumVersion 5.99
$tests = New-PesterConfiguration
$tests.Run.Path = '.\tests'
$tests.Filter.ExcludeTag = 'WindowsIntegration'
$tests.TestRegistry.Enabled = $false
Invoke-Pester -Configuration $tests
```

The `WindowsIntegration` registry restoration test writes to HKCU and runs only
in a disposable Windows VM. The VM runner includes it; workstation checks exclude it.

For repeatable VM runs with host UAC enabled, see the opt-in
[AutomatedLab task controller](tests/integration/AUTOMATEDLAB-TASKS.md), including
on-demand execution, local edit watching, CI and the pilot acceptance checklist.
For additional OS images, use the [provisioning configuration and field guide](tests/integration/AUTOMATEDLAB.md).
The [verification matrix](docs/PACKAGE-VERIFICATION-MATRIX.md) explains artifact
retention and importing reviewed VM evidence into the shared metadata library.

The previous function-based implementation is retained as a migration reference under `legacy/v2/`; the new runner does not load it. The migration is incomplete, so the current catalog deliberately exposes only operations implemented by the new engine.

## License

RIDE is MIT. See [LICENSE](LICENSE). Downloaded third-party products retain
their own licenses; see the [publisher references](docs/OPERATIONS.md#publisher-licenses).
