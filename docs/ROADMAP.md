# RIDE-Windows v3 roadmap

## Current state

The repository is cutting over from the v2 function runner to a purpose-built PowerShell engine. The v3 runner loads `.psd1` operation metadata and profiles. The initial catalog includes a reversible Explorer setting, direct installer/uninstaller operations for 7-Zip and Notepad++, and an ordered utility group. The previous function library, preset, and helper modules are under `legacy/v2/` as migration references and are not imported by the new runner.

The first implementation establishes the catalog, CLI, operation state store, focused handlers, and Windows CI checks. It does not migrate the full v2 library. The current supported targets are Windows 11 and Windows Server 2025, declared per operation.

## Architecture rules

- Keep user-facing actions in `catalog/operations.psd1`; keep shared implementation helpers out of the public operation catalog.
- Keep profiles declarative and versioned in `.psd1` files. Never evaluate a profile as a script.
- Each operation declares category, description, target OS, scope, privilege, actions, and rollback capability.
- Settings record the previous value and whether the value/key existed. Baseline states are explicit catalog values applied through profiles.
- Package uninstall is compensating when reinstalling a removed package cannot guarantee the same version. Expose that limit in catalog metadata and restore output.
- Add operations by category in small batches. Add catalog tests and applicable VM coverage before claiming new Windows support.

## Migration phases

The batch inventory, test demand, and preset/function reconciliation list are maintained in [MIGRATION-PLAN.md](MIGRATION-PLAN.md).

1. **Engine foundation** — catalog/profile validation, planning, state snapshots, status, exact settings restore, package lifecycle, generated operation documentation, Pester tests, and a disposable VM workflow.
2. **High-use setup operations** — migrate default-profile settings and installers from the v2 library. Keep IDs stable once released; record unsupported and one-way actions clearly.
3. **Grouped software solutions** — add package metadata and install/uninstall order for multi-component forensic and analyst toolsets. Track source verification, license acceptance, and version recovery per package.
4. **Settings families** — migrate Windows policies, privacy, services, network, UI, account, and Server-specific settings with explicit state discovery and baseline behavior.
5. **Major release** — publish v3 with new profiles and CLI; v2 remains available through prior release tags. Remove obsolete migration notes once a v2 operation family has been reviewed.

## Verification and support

- Windows CI runs PowerShell parsing, metadata/profile validation, generated-doc consistency, and Pester unit tests.
- A resettable Windows 11 VM and Windows Server 2025 VM exercise apply twice, status, saved-state restore, baseline application, group uninstall, and partial failure reporting.
- Add another Windows target only after its operation support declarations and integration checks are explicit.
- Run `tools/validate.ps1` and `Invoke-Pester .\tests` for each change. VM tests require a disposable VM; never use a daily workstation as the integration target.
