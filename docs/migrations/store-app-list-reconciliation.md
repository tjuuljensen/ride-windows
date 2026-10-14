# Current Store app review and optional historical comparison

V3 uses live inventories and small reviewed app selections. All apps are kept
until inventory review; packages remain paused. The current data file contains
25 inspected static policy candidates, not an approved removal list or an
exhaustive list of preinstalled Windows apps.

The [collected Windows 11/Server references](store-app-inventory-review.md) provide
separate user/provisioning counts and the next grouped Keep/Remove decisions.

The former 119-row v2/template reconciliation is preserved in the
[historical archive](../archive/migrations/store-app-v2-historical-coverage-2026-10-14.md).
Its four original lists and source hash are in the adjacent data-only JSON archive.
These names impose no requirement to implement every historical app in v3.

Default comparison includes current template candidates and unfamiliar packages
actually observed in the captured user inventory. Use `-IncludeHistoricalCoverage`
only when investigating historical matches, missing reverse entries or upgrade
history. Every comparison row remains Unselected and RemovalApproved=false.

Review exact package identities, publisher families, dependencies/protection and
user intent. Presence in provisioning is not a removal recommendation. An absent
historical app is not a completed uninstall or evidence that every older copy is
retired. Do not map replacement apps by friendly labels or replay v2 bulk scripts.

The inspected template omits XboxGamingOverlay, which appears in the Microsoft
feature guide. Its schema/identity capability remains pending; no PFN is guessed.
Follow the [reference inventory plan](store-app-inventory-plan.md),
[collection guide](../store-app-inventory.md) and
[separate policy/uninstall review](store-app-removal-review.md).
