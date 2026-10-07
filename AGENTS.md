# AGENTS.md

## Repository purpose and architecture

RIDE-Windows is a standalone PowerShell engine for Windows setup and
maintenance. Fresh-machine setup is the primary use; ongoing maintenance is
supported. The operation catalog and profiles define user-facing choices;
focused handler modules implement system changes.

- catalog/operations.psd1 is the source of truth for stable operation and
  group IDs, descriptions, supported targets, scope, privilege needs, actions,
  handlers, and setting or package metadata.
- profiles/*.psd1 are named, reviewable selections of desired states.
- modules/RIDE.Engine.psm1 owns catalog loading, planning, lifecycle, and state
  records. RIDE-Settings.psm1 and RIDE-Packages.psm1 own their focused handlers.
- tools/Export-RideCatalog.ps1 generates docs/OPERATIONS.md. Edit the catalog
  and generator instead of hand-editing generated catalog documentation.
- legacy/v2 is historical reference material. The new major version has no
  compatibility runner; do not reconnect the legacy library to the new engine.

Keep operation IDs stable after publication. If a catalog or profile schema
must change, document the migration and retain a recovery path. Prefer focused
changes over broad rewrites.

## Operation reference metadata

- Every `RegistryValue` operation in `catalog/operations.psd1` must include a
  `DocumentationUri` pointing to Microsoft documentation for the setting,
  policy, or user-visible behavior it controls. Prefer the exact policy or
  value reference. When Microsoft documents only the feature behavior, link
  that page and describe the registry mapping accurately without implying
  Microsoft documents the specific value.
- Every `Package` operation must include a `ProductUri` pointing to the
  product's official information page. Keep this separate from `DownloadUri`,
  which identifies the artifact source used by the installer.
- Use stable HTTPS URLs from Microsoft Learn or Microsoft Support for Windows
  settings, and from the software publisher or project for package information.
  Do not invent links; flag an undocumented setting for review and use the
  closest authoritative behavior reference when no direct reference exists.
- Render these references in generated `docs/OPERATIONS.md` and enforce their
  presence and URL form in catalog validation and tests.

## Command-line discoverability and completion

Tab completion is a default part of the RIDE command-line interface. Any
command-line parameter with a finite or discoverable set of valid values must
offer completion.

- Keep command names completable from their declared command set.
- Complete operation, package, and group IDs from the catalog, including
  positional values for show and the named -Id parameter.
- Complete profile paths from profiles/*.psd1 for -Profile.
- Complete saved run IDs from state manifests for -RunId.
- Source values from the same catalog, profile directory, or state store used
  by command execution. Do not maintain a second hard-coded suggestion list.
- Filter suggestions by the text already entered, ignore case where Windows
  identifiers are case-insensitive, and avoid duplicate suggestions.
- Completion must be read-only, must not invoke handlers or installers, and
  should fail quietly if optional completion data is unavailable.
- Update -Help and README command guidance when completion behavior changes.
- Add completion for future enumerable parameters as those parameters are
  introduced.

## Operation lifecycle and safety

Settings and packages have different lifecycle behavior and must remain
distinct in metadata, plans, reporting, and handlers.

- Settings support current-state inspection, desired-state checks, applying a
  declared value, and restoring the captured prior value.
- Profiles may request a documented baseline. Baseline application is not the
  same workflow as restoring a saved pre-change value.
- Package operations support presence checks, installation, and uninstall.
- Groups represent multi-component solutions and declare ordered dependencies.
  Removal follows the reverse dependency order.
- Store versioned pre-change state separately for machine and user scope.
- Make operations idempotent where practical. State-changing commands must
  support preview through ShouldProcess and report partial failures clearly.
- Declare supported Windows targets per operation. Do not infer support for a
  whole release from a few operations that happen to work.
- Machine operations require elevation; user operations run in the current
  user's context.
- One-off package and setting changes use catalog IDs and declared states via
  `install`, `remove <package-id>`, `set`, and `unset`; capture prior state just
  as profile-based changes do.
- Tab completion and discovery commands must not change Windows state.
- `list` emits a consistent object collection instead of separately formatted
  tables. Support useful views such as profiles, packages, Windows settings,
  and catalog categories; preserve pipeline-friendly objects.
- show displays a specific setting's live value and baseline value; package and
  group views display installed state and version where available.
- plan displays the effective desired value beside the live value.
- status without a profile reports each target-supported operation's literal
  and effective platform defaults beside its live value and interpreted state.
- status with a profile compares live values and states with the profile's
  desired values and states. Inspection remains read-only.
- status accepts catalog category/package/group views like list; select profiles
  for comparison with `-Profile <file>`.
- Declare literal and effective defaults per supported target in the catalog;
  do not substitute RIDE's BaselineState for a Windows default.

## Repository language and text

English is the canonical language for implementation, technical documentation,
operation metadata, profiles, identifiers, logs, help text, and tests.

- Write script headers and embedded comments in English.
- Use English for new repository-owned operation IDs, profile names, functions,
  modules, and test names. Keep published IDs stable unless an explicit
  migration is provided.
- Preserve official product names and externally owned identifiers.
- Preserve meaningful localized user-facing content when it is intentional;
  do not make active technical documents partially bilingual.
- Prefer readable ASCII punctuation in Markdown and scripts. Preserve
  meaningful Unicode.
- Follow .gitattributes and inspect git ls-files --eol before editing tracked
  text. The command launcher default.cmd uses CRLF; other repository text uses
  the applicable repository attributes. Do not change global Git EOL settings
  or run broad renormalization automatically.
- Keep README concise. Put detailed workflows in docs and link to them.

## PowerShell script model

Use the PowerShell conventions already established in the repository and
declare compatibility in user-facing documentation.

- Use CmdletBinding for reusable command-line scripts and
  $ErrorActionPreference = 'Stop' for operational paths unless a deliberate
  exception is documented.
- Quote paths and validate external input. Use literal-path parameters when
  treating input as a filesystem path.
- Keep completion code read-only and bounded; do not import the operational
  engine or query mutable machine configuration to provide suggestions.
- Put Windows changes behind focused handlers and ShouldProcess. Avoid
  unbounded destructive defaults.
- Keep command help, README usage, and parameter behavior in sync.
- Update script headers and documentation when flags, supported Windows
  targets, prerequisites, outputs, or side effects change.
- Preserve source attribution and license notices when adapting existing code.

## Validation model

Use Windows CI for PowerShell parser, catalog, profile, and Pester checks.
Pester unit tests should validate catalog and profile structure, lifecycle
behavior, and handlers through mocked installers and system calls.

Use disposable Windows VMs for system integration scenarios, including repeat
apply, status, exact restore, baseline application, grouped uninstall, and
reporting after partial failure. Run scenarios on Windows 11 and the declared
Windows Server targets. Add another Windows version to support declarations
only after applicable integration checks pass.

Keep tests isolated from the developer's machine. Prefer the narrowest useful
validation for a change, and state clearly when runtime behavior cannot be
verified in the available environment.

## Bootstrap and release model

The supported bootstrapper installs a tagged release or explicitly selected
source version for a standalone Windows setup. Keep source, download,
validation, execution, and recovery boundaries clear.

- A local Git checkout is the development source; a tagged release is the
  normal distribution unit for fresh-machine installation.
- Bootstrap scripts must make download-only, preview, and apply behavior
  explicit and must not silently apply a profile.
- Keep local configuration outside generated or release defaults.
- Document required elevation, package sources, state locations, and recovery
  behavior.
- Preserve prior major-version releases through Git tags. Do not make a new
  release depend on mutable legacy source files.
- DSC or Ansible integration may be considered later, but must not create a
  second source of truth for operation metadata or profiles.

## Windows-only development and validation

RIDE-Windows targets Windows. PowerShell or shell behavior observed on Linux
or WSL does not establish support for RIDE operations.

- Use Windows-native PowerShell and Git for Windows for repository workflows
  and Windows-specific validation.
- Use disposable Windows VMs for state-changing integration checks. Do not use
  a developer workstation as an integration-test target.
- Validate behavior on Windows 11 and the Windows Server releases declared by
  the affected operations. A new target is supported only after its applicable
  integration checks pass.
- Follow .gitattributes for line endings. The Windows command launcher
  default.cmd requires CRLF; do not change global Git EOL settings or run broad
  renormalization automatically.

## Git and workspace safety

- Check git status before broad edits and preserve unrelated user changes.
- Treat untracked files as intentional unless clearly generated by the current
  work.
- Do not use destructive Git commands or remove user data unless explicitly
  requested.
- Review the complete focused diff before finalizing meaningful changes.
