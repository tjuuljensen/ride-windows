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
When using PowerShell interactively, press Tab to complete commands, operation and group IDs, profile paths, and saved run IDs.

| Command | Purpose |
| --- | --- |
| `list [view]` | Emit one consistent PowerShell object collection for catalog entries and profiles; views include `all`, `profiles`, `packages`, `windows`, `explorer`, `security`, `software`, `utilities`, `groups`, and `settings`. |
| `show <id>` | Show operation metadata and its current value; settings also show their baseline value. |
| `plan -Profile <file>` | Display each selected operation's current value beside its desired profile value. |
| `apply -Profile <file>` | Apply the profile's desired state and save prior state for changed operations. |
| `install <package-id>` | Install one catalog package and save its prior state. |
| `set <setting-id> -State <state>` | Set one catalog setting to a declared state and save its prior value. |
| `unset <setting-id>` | Remove a setting value when the catalog declares an unset state, saving its prior value. |
| `status [view]` | Show target-specific defaults and live state, optionally filtered by a view such as `packages`, `windows`, `explorer`, or `security`. |
| `status [view] -Profile <file>` | Compare the selected operations' current values and states with the profile's desired values and states. |
| `restore -RunId <id>` | Restore settings captured before a prior run. Package restoration may require reinstalling the current upstream version. |
| `remove <package-id>` | Uninstall one catalog package and save its prior state. |
| `remove -Profile <file>` | Uninstall packages selected by a profile, in reverse group order. |

Append `-WhatIf` to a state-changing command to preview a change. An operation's supported actions, privilege needs, scope, and rollback limits are shown by `list`, `show`, and the generated [operation catalog](docs/OPERATIONS.md).

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
- `modules/RIDE.Engine.psm1` plans and runs operations; focused handler modules implement registry settings, Defender exclusions, and packages.
- `docs/OPERATIONS.md` is generated from the catalog.
- `tools/validate.ps1` checks PowerShell syntax, catalog/profile references, and generated docs.
- `tests/` contains Pester tests. `tests/integration/` documents disposable VM checks.
- [Script model](docs/repository-portfolio/script-repository-model.md) defines
  headers, versioning, safety, and validation for maintained PowerShell scripts.

Run static and unit checks on Windows:

```powershell
.\tools\validate.ps1
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0 -MaximumVersion 5.99
Invoke-Pester .\tests
```

The previous function-based implementation is retained as a migration reference under `legacy/v2/`; the new runner does not load it. The migration is incomplete, so the current catalog deliberately exposes only operations implemented by the new engine.

## License

MIT. See [LICENSE](LICENSE).
