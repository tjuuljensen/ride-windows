# RIDE-Windows v3 TODO

## Active priorities

### Engine correctness

- [ ] Review snapshot file ACLs and add safe cleanup/retention for old run records.
- [ ] Add package installer checksum/signature policy and retain installers needed for version-specific recovery.
- [ ] Handle partial failure across a multi-operation apply with per-operation completion reporting and a safe resume path.
- [ ] Add profile parameter validation and package dependency cycle detection.

### Migration

- [ ] Inventory the v2 default profile and migrate its high-use settings and installers into v3 operation metadata.
- [ ] Migrate common forensic tools and their remove operations into package handlers and grouped profiles.
- [ ] Review user-scoped settings so elevated runs do not silently target the wrong user.
- [ ] Decide which legacy operations are unsupported, manual-only, or one-way and record that in the catalog.

### Verification

- [ ] Run the disposable VM suite on Windows 11 and Windows Server 2025.
- [ ] Add CI result publishing for Pester and test both Windows PowerShell 5.1 and PowerShell 7.
- [ ] Validate operation support declarations against the integration matrix before expanding targets.

Longer migration details live in [docs/ROADMAP.md](docs/ROADMAP.md). The old TODO and package modernization backlog were specific to v2 and will be reconsidered as operations migrate.
