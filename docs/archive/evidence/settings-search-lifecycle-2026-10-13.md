# Windows Search focused lifecycle, 2026-10-13

Disposable Windows 11 request `53357a9252764c0fa543cd594f297de4` passed at
15:14:58 UTC through the pinned controller 0.4.6. Local source revision
`00e820f876f6c00f70750c732b3057f5e82f79bd` included the uncommitted fixture
implementation. All 277 retained source-file hashes match the preflight manifest.
Fixture SHA-256:
`9A3B07CD56FBC4F30397254A1EBFC536CDE181947DACB7F3EDC3B10AB25D30A6`.

Validation and 162 focused Pester checks passed; one WindowsIntegration check
was excluded. All seven real WSearch states, repeat apply, startup-only runtime
preservation, declared baseline and apply/restore previews passed. Exact captured
recovery restored Automatic/running, DelayedAutoStart DWORD 1 with its key present
and effective SCM delay true. Controller Error, CleanupError and CollectionError,
and guest StateCollectionError, Error and RecoveryError were null. Normal evidence
export completed. Independent postflight found both VMs Off, tasks Ready, queues
empty, locks available, no blocks and matching pinned checkpoint identities.

This establishes lifecycle behavior on Windows 11 build 26300 under Windows
PowerShell 5.1.26100.9444. Search results, indexing workload, Services GUI/session,
boot behavior, target defaults, managed precedence and deliberate native partial
failures remain pending. SupportedTargets remain unchanged; no Server support or
whole legacy outcome is claimed. Packages remain paused.

Protected evidence is retained under
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\53357a9252764c0fa543cd594f297de4`;
the preflight manifest, receipt and independent postflight are under
`.local/settings-validation/53357a9252764c0fa543cd594f297de4`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
