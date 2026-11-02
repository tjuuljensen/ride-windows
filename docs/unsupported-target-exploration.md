# Unsupported target exploration

`-AllowUnsupportedTarget` explicitly permits one invocation to pass the engine's
catalog OS, minimum-build and Desktop Experience restrictions. It does not change
`SupportedTargets`, establish Windows support or grant permission to a later
restore. Use a disposable Windows target with a verified recovery checkpoint.

From the repository root, preview the exact selection first:

```powershell
.\ride.ps1 set <setting-id> -State <declared-state> -AllowUnsupportedTarget -WhatIf
```

Omit `-WhatIf` only for the intended change. Machine operations still require
elevation; user operations retain their declared execution context. Pending
candidates additionally require `-AllowCandidate` for actual changes. The two
switches are independent, and PowerShell completes their parameter names.

The option is accepted by `apply`, `install`, `set`, `unset`, `remove` and
`restore`, including their previews. Read-only discovery and `plan` do not accept
it. `-UserContext Desktop` forwards the explicit choice in a schema-3 request;
schema-1/2 requests never grant target exploration. Preview launches no worker,
invokes no mutation handler and writes no audit or saved state.

Before a changed run, the engine saves a version-1 `TargetExploration` audit in
`_manifest.json`. It records the actual target classification, product, build,
update revision, edition, installation type, architecture observations, operation
ID, declared targets, candidate status and the restrictions being bypassed.
Warnings also identify the actual target. An already-desired selection creates
no run; its warnings are not durable execution evidence.

Recovery requires a fresh explicit switch:

```powershell
.\ride.ps1 restore -RunId <saved-run-id> -AllowUnsupportedTarget -WhatIf
```

Add `-AllowCandidate` when applicable. After all saved records pass validation,
each approved restore writes `.target-exploration-<id>.log` in its existing run
directory before invoking the handler. The file contains the same versioned JSON
audit; its `.log` extension keeps it outside recovery's `.json` snapshot set.
Existing saved-state schemas remain readable and do not grant either opt-in.

Architecture and artifact compatibility, integrity, privilege, dependency,
ownership, source identity, offline target matching, ShouldProcess and recovery
checks remain active. Handler-specific availability checks may still refuse an
operation; this switch cannot provide a missing Windows API or recovery source.
Follow the saved run and partial-failure report for recovery, and retain the
disposable checkpoint when a handler cannot recover the original state.

Focused mocked Windows tests establish the switch and audit behavior, not native
operation support on another Windows release. The intentional difference from
the shared fail-closed target contract is tracked in
[Fedora alignment](fedora-alignment.md#unsupported-target-exploration-2026-11-02).
