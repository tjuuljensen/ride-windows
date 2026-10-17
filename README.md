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

For a Windows installation that uses a local sign-in, see the
[Windows local-account setup guide](docs/windows-local-account-setup.md), which
tracks edition- and build-specific setup behavior.

## Commands

Run `.\ride.ps1 -Help` for command usage, options, and examples.
When using PowerShell interactively, press Tab to complete commands, operation and group IDs, profile paths, saved run IDs, declared setting states, package variants, and search fields/views.

For read-only audio review, the [endpoint inventory tool](docs/audio-service.md#read-only-endpoint-inventory)
captures explicit user/session observations. Its saved-data selector completes
endpoint IDs from the supplied inventory without querying or changing audio.
The [component inventory tool](docs/windows-component-inventory.md) keeps feature,
capability and Server role observations separate; names complete from saved data.
The [adapter inventory](docs/network-adapter-inventory.md) completes saved GUIDs
without selecting or changing a network device.
The [volume inventory](docs/volume-inventory.md) completes saved volume GUID paths
without using drive letters or labels as selection keys.
The [user proxy observation](docs/user-proxy-inventory.md) completes its explicit
default/LAN scope without querying Windows; capture performs no connectivity request.
Its in-memory edit preparation completes detection/setup choices and preserves
manual proxy settings; it cannot apply live changes.
Optional [PowerShell startup settings](docs/powershell-profiles.md) distinguish accepted
color presets from pending user-bin PATH candidates; declared states complete from
the catalog without inspecting or running profiles.
The [Terminal JSONC preparation API](docs/terminal-jsonc-preparation.md) completes
declared profile GUIDs from supplied bytes; it does not access live Terminal settings.
The [desired-configuration export](docs/desired-configuration-reference.md) creates
a read-only profile reference, with profile/target completion and no live-state query.

State-changing commands honor `-WhatIf` and the caller's `$WhatIfPreference`.
Optional Store registrations use the separate
[Store app/group tool](docs/store-app-groups.md#batch-1-commands); `list store-apps`
discovers its catalog entries. They are not package downloads or profile settings.
Use `-WhatIf:$false` to explicitly disable inherited preview for one invocation;
`-Confirm` requests confirmation for each supported change.

| Command | Purpose |
| --- | --- |
| `list [view]` | Emit one consistent PowerShell object collection for catalog entries and profiles; views include `all`, `profiles`, `packages`, `windows`, `explorer`, `security`, `software`, `utilities`, `groups`, and `settings`. |
| `search <query> [-Field <fields>] [-View <view>]` | Search catalog metadata using a case-insensitive literal phrase; return objects with the matching fields and values. |
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

Use `.\ride.ps1 search desktop-folder`, `.\ride.ps1 search 'File Explorer'`, or
`.\ride.ps1 search ThisPCPolicy -Field ValueName -View explorer` to find operations.
Search includes declared registry paths, including nested value sets. Quote paths;
backslashes need no doubling. See the [catalog search guide](docs/catalog-search.md)
for fields, completion and pipeline examples.

Packages may declare alternate distributions. Use `install`, `remove`,
`download` or `show` with `-Variant <name>`; profiles use a package-entry
`Variant`. See [application packages](docs/application-packages.md) for local
ToolsDirectory configuration, portable ownership and saved-selection recovery. Check the catalog for each distribution's supported targets.
The [offline adoption review](docs/application-packages.md#review-registrations-against-the-catalog)
compares supplied registrations with catalog variants and completes target labels
from that catalog; it does not adopt or replace installations.

See [Artcraft packages](docs/artcraft-packages.md) for the twelve standalone
creative apps, optional launcher and verified full MSI downloads.
The [offline bundle guide](docs/offline-bundles.md) describes local manifest
preflight, byte-bound package coverage and explicit local assembly. Assembly's
optional `-CatalogFileId` and `-CoverageProfileId` check selected package content
before completion; both parameters complete IDs from the manifest.
Automatic acquisition planning and offline install integration remain pending.

For explicit user-only settings, `-UserContext Desktop` starts a separate process
for the signed-in user in the current desktop session. See the
[intended-user handoff guide](docs/intended-user-handoff.md) for preview, child
results, user-owned recovery and pending native acceptance. Mixed profiles are refused.

See the [Windows settings guide](docs/windows-settings.md) for defaults,
scope, recovery and individual policy/service guides, including pending candidates.

Use `download package.7zip -Destination <path>` to choose the artifact directory. Use `download artifact.sysmon-swift-config` to retain the latest SwiftOnSecurity XML at an immutable Git commit revision; RIDE does not apply this file automatically. Download records in `catalog/artifact-observations.json` are metadata only; a locally observed SHA-256 is not publisher authentication. See the [package verification matrix](docs/package-verification-matrix.md) for current source evidence. Append `-WhatIf` to a state-changing command to preview a change. An operation's supported actions, privilege needs, scope, and rollback limits are shown by `list`, `show`, and the generated [operation catalog](docs/OPERATIONS.md).

GitHub latest-release lookups use [bounded freshness and shared quota backoff](docs/github-release-discovery.md).
Optional PAT discovery uses `-GitHubAuthentication PAT -GitHubCredentialReference <name>`
on download/install/apply/restore. Enroll through `tools/Manage-RideGitHubCredential.ps1`;
Tab completes nonsecret references without reading tokens. See the same guide for
DPAPI storage, explicit VM delivery and pending live authentication acceptance.

The optional God Mode desktop shortcut uses the current user's desktop,
including a redirected desktop. Preview it with
`.\ride.ps1 set windows.god-mode-shortcut Present -WhatIf`, then omit `-WhatIf`
to create it. Use `.\ride.ps1 unset windows.god-mode-shortcut` to remove it or
`restore -RunId <id>` to recover captured prior state. It creates the special
folder described in the [God Mode guide](https://www.tomshardware.com/how-to/enable-god-mode-windows-11).
Removal refuses nonempty folders. See the [folder workflow](docs/god-mode.md)
for profile configuration and recovery details.

Packages and standalone artifacts include publisher license references in the
catalog and download records. Individual/company reviews stay in local,
exportable JSON. Use `tools/Manage-RideLicenseReviews.ps1 -Help` for Get, Set,
Export and Import; Tab completes commands, review statuses and catalog IDs.
See [Important to review licensing](docs/package-licensing.md#important-to-review-licensing)
for Npcap, KAPE and other products whose free-use terms need assessment in
corporate or professional environments. The same guide explains local review records.
Offline bundle preparation is requested; shared publication retains the separate
redistribution review and omission contract.

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

## Mouse jigglers, Caffeine and lock blockers

The standalone full/light PowerShell helpers and native alternatives have
different prerequisites and input behavior. See the [screen-lock guide](docs/screen-lock-helpers.md)
for use and limitations, and the [impact evaluation](docs/screen-lock-impact.md)
for the measurement procedure and pending acceptance. No comparative memory/write
ranking is established; preventing sleep does not prove idle-lock prevention.

## Development

The `-Library` interface loads separate local catalogs and profiles using
built-in registry and package handlers, with completion and saved-run recovery
checks. Keep private catalogs and profiles outside the core repository. Custom-handler
registration and VM acceptance remain pending. See the
[authoring guide and starter library](docs/custom-libraries.md).
Create a library with `tools/New-RideLibrary.ps1 -Path .\my-library`; the guided
helper offers supported package/registry choices and generates validated files.
For packages, optional early URL/local-file inspection suggests installer details;
ZIP-contained EXE/MSI installers are supported. Samples are never executed.
If the installed-product name is unknown, the helper saves an unpublished draft;
resume it after a test installation in a disposable VM.
Use `tools/New-RideLibrary.ps1 -Path .\my-library -Add` to add operations to an
existing generated library, retaining its prior metadata for recovery. Custom
license links are optional and may use HTTP/HTTPS, including internal/localhost.
Registry authoring accepts HKCR paths with an explicit User/Machine destination,
unnamed default values and coordinated `RegistryValueSet` entries. See the
[Certutil context-menu example](examples/authoring/certutil-context-menu.psd1).
Start with the [combined example library](examples/library/README.md), with
separate starter, settings and package profiles. The [examples index](examples/README.md)
also links small authoring definitions and historical recovery snapshots.
See the [custom-library plan and release acceptance criteria](docs/MIGRATION-PLAN.md#custom-library-interface-v3-release-requirement).

- `catalog/operations.psd1` defines the operation catalog and solution groups.
- `profiles/*.psd1` defines reusable selections.
- `modules/RIDE.Engine.psm1` plans and runs operations; focused handler modules implement registry settings, desktop folders, Defender exclusions, and packages.
- `docs/OPERATIONS.md` is generated from the catalog.
- `tools/validate.ps1` checks PowerShell syntax, catalog/profile references, and generated docs.
- `tests/` contains Pester tests. `tests/integration/` documents disposable VM checks.
- [Script model](docs/models/script-repository-model.md) defines
  headers, versioning, safety, and validation for maintained PowerShell scripts.
- Use `Get-Help .\ride.ps1 -Full` for native help or `-Help` for quick usage.
  Standalone maintained scripts expose `-Version` without operational work;
  the intentionally parameterless caffeine-light fallback records its version in native help.
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
[AutomatedLab task controller](tests/integration/automatedlab-tasks.md), including
on-demand execution, local edit watching, CI and the pilot acceptance checklist.
For additional OS images, use the [provisioning configuration and field guide](tests/integration/automatedlab.md).
For a second AutomatedLab VM on the same host, use the guide's `NetworkMode
ExistingNat` workflow with explicit guest addressing. `NetworkMode` supports
tab completion; the shared-network path preserves the existing switch and NAT.
The [verification matrix](docs/package-verification-matrix.md) explains artifact
retention and importing reviewed VM evidence into the shared metadata library.

Historical source is retained under `legacy/v2/`; the engine does not load it.
For contributor work, see the [task list](TODO.md) and [migration plan](docs/MIGRATION-PLAN.md).
The [documentation index](docs/README.md) separates current guides, active
acceptance work and archived evidence. Follow the
[documentation naming and retention model](docs/models/documentation-model.md).

## Other reference sites

- [Ninite](https://ninite.com/) installs and updates a selection of Windows
  applications while declining optional bundled offers. See the
  [Ninite package comparison](docs/ninite-package-comparison.md) for its app list,
  overlap with RIDE's catalog and planned reviews, and the scope of its
  toolbar-avoidance claim.

## License

RIDE is MIT. See [LICENSE](LICENSE). Downloaded third-party products retain
their own licenses; see the [publisher references](docs/OPERATIONS.md#publisher-licenses)
and [corporate licensing review list](docs/package-licensing.md#important-to-review-licensing).
