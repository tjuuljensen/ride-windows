# Modern Store app scope and reference preparation

Recorded: **2026-10-14**. The user approved option 3: reset active v3 scope to
reviewed current identities with live discovery and both explicit workflows.
Keep all apps until inventories have been reviewed; packages remain paused.

The [v2 coverage archive](../migrations/store-app-v2-historical-coverage-2026-10-14.md)
and adjacent JSON preserve all four original lists, 106 removal/102 registration
names, four reverse gaps and original source hash. Exact lists and source SHA-256
were independently compared against the earlier source evidence and unchanged
legacy/v2/lib-windows.psm1. Archive JSON SHA-256:
540E793FE1E654B6B271CF8BC380CA2D5836223635295A1ACC03819F24884BCA.
The prior 119-row template/history matrix is retained in that archive.

Active catalog review data now contains the 25 inspected static policy candidates.
Default comparison adds actually observed unknown apps; historical-only names are
loaded only with IncludeHistoricalCoverage. Every row remains unselected/unapproved.
Historical names impose no exhaustive v3 implementation requirement. The blanket
bulk remove/re-register behaviors are retired as requirements, not individual app
retirement or successful selected-app replacement. Original legacy source is not
connected to the engine. No supported target, operation or profile is expanded.

RIDE.StoreAppReview 0.2.0 adds separate online provisioning collection and archived
history comparison. Export-RideStoreProvisionedInventory 0.1.0 writes raw image
identities and a sibling DISM diagnostic log; it requires an already elevated
process and requests no elevation. Comparison 0.2.0 has an explicit historical
option. Provisioning evidence cannot pass as current-user registration evidence.

Fixture data 0.6.0/schema 4, native fixture 0.8.1 and guest runner 0.8.3 prepare
StoreReferenceInventory for exact configured guest identities. User and image
provisioning files/hashes stay separate; partial user evidence is retained if the
second collection fails. Provisioning subject and collecting account remain distinct.
Schemas 1/2 setting lifecycle and schema 3 user-only inventory remain valid.
The local submission preparation covers Windows 11 and Server 2025 serially with
known accepted guest identities and WinRM/idle/pin/hash guards. It was not submitted.

Native Windows PowerShell 5.1.26100.9711 and PowerShell 7.6.5 each passed **85/85**
focused Store review, fixture-data and CLI tests, zero failed/skipped. Appx, DISM,
identity, privilege and registry queries are mocked; TestRegistry is disabled.
Parser/catalog/profile/reference/generated-document validation passed on both:
318 operations, three groups, five profiles and 138 PowerShell files. Final
fixture changes preserving partial hash/provenance have fresh parser evidence;
native runtime remains pending. Local results/hashes are in
.local/store-app-scope-preparation-20261014.json and
.local/store-app-fixture-{5,7}/result.json.

No native inventory, VM submission, host service change, UAC/elevation request,
controller refresh, publisher/GitHub request or acquisition occurred in this run.
The earlier stopped-WinRM refusal remains the host prerequisite. Elevation work is
postponed; no new native acceptance is inferred from mocked tests or preparation.

The [active plan](../../migrations/store-app-inventory-plan.md) starts with available
representative Windows 11/Server references, not exhaustive release/edition/OEM
coverage. Additional variants become targeted acceptance work as needed. All five
estimates remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180:
historical replay requirements are retired, while selected-app implementations and
actual collection/removal/policy/recovery acceptance remain pending. No whole
legacy app outcome is resolved, retired or excluded by the archive row count.
