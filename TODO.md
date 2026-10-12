# RIDE-Windows v3 TODO

## Active priorities

### Engine correctness

- [ ] Review snapshot file ACLs and add safe cleanup/retention for old run records.
- [ ] Add package installer checksum/signature policy and retain installers needed for version-specific recovery.
- [ ] Handle partial failure across a multi-operation apply with per-operation completion reporting and a safe resume path.
- [ ] Add profile parameter validation and package dependency cycle detection.

### Migration

- [ ] Continue the accepted settings decisions from the [implementation handoff](docs/migrations/settings-implementation-handoff.md); complete the remaining metadata, handlers and acceptance before the final outstanding-issue walkthrough.
- [ ] Include **Rufus** as an optional v3 tool for bootable USB media creation; see the [requested additions](docs/CANDIDATE-TOOLS.md#requested-v3-additions-2026-10-11) for portable acquisition, publisher/license references and acceptance work.
- [ ] Include **HashCheck - idrassi fork** as an optional v3 app; see the [requested additions](docs/CANDIDATE-TOOLS.md#requested-v3-additions-2026-10-11) for publisher, license and acceptance work.
- [ ] Include the supplied **Hash value** submenu and corrected **SHA-256 with Certutil** context-menu setting as optional v3 solutions; see the [source and corrected registry example](examples/hash-context-menu/README.md).
- [ ] Inventory the v2 default profile and migrate its high-use settings and installers into v3 operation metadata.
- [ ] Migrate common forensic tools and their remove operations into package handlers and grouped profiles.
- [ ] Review user-scoped settings so elevated runs do not silently target the wrong user.
- [ ] Decide which legacy operations are unsupported, manual-only, or one-way and record that in the catalog.

### Verification

- [ ] Complete interactive Windows 11 and Server 2025 Desktop Experience memory/write and idle-lock measurements for full/light caffeine, Zhorn Caffeine and Arkane Mouse Jiggler. Pinned payloads and capture/snapshot/analysis tooling are ready. Two elevated PS5.1 Light pilots stayed unlocked for 600 seconds, exited after console Ctrl+C, and locked again; their raw memory figures and variation are recorded. A full-default pilot reported unlocked and exited with code 0, but post-exit input prevented resumed-lock acceptance. Native Zhorn x64 default also stayed unlocked, exited via -appexit and locked again; its steady private median was 5.375 MiB in this single pilot. Idle run 1 had a Terminal mismatch; idle run 2 matched Terminal but contained extra input. Idle run 3 had one startup reset followed by a quiet interval, allowing exploratory early-window arithmetic but no accepted ranking. Undisturbed matching controls, three clean repetitions, other cases/targets, write attribution and full cleanup/key-state acceptance remain pending. Manual guest sign-in is required after checkpoint restores. See the [impact report and reproducible procedure](docs/SCREEN-LOCK-IMPACT.md) and [decision record](docs/SCREEN-LOCK-HELPERS.md).
- [ ] Run the disposable VM suite on Windows 11 and Windows Server 2025.
- [ ] Add CI result publishing for Pester and test both Windows PowerShell 5.1 and PowerShell 7.
- [ ] Validate operation support declarations against the integration matrix before expanding targets.

## Down the road

- [ ] Once the CLI commands and operation lifecycle have stabilized, evaluate exposing a public, importable RIDE PowerShell module for interactive use and integration from other scripts. Keep `ride.ps1` as the standalone entry point; define a stable module API only if there is a clear use case.

Longer migration details live in [docs/ROADMAP.md](docs/ROADMAP.md). The old TODO and package modernization backlog were specific to v2 and will be reconsidered as operations migrate.
