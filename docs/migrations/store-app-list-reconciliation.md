# Current Store app review and optional historical comparison

## Reviewed selection static reconciliation, 2026-10-27 07:05 UTC

The existing reviewed selection is internally consistent: **22** exact Store
package identities appear in 22 catalog `StoreApp` operations, 5 accepted groups,
the group guide's exact-identity table and the read-only `ride.ps1 list store-apps`
view. The focused `StoreApps.Tests.ps1` and `StoreAppReview.Tests.ps1` suites
passed **59/59** after the workspace-local temp rerun. A new regression keeps the
documentation/catalog identity list and current policy crosswalk aligned.

Of the 22 selected identities, **21** map to the inspected static policy review
crosswalk. `Microsoft.XboxGamingOverlay` is the documented exception: it remains
in the reviewed gaming app group but has no policy selection ID because the
inspected template lacks a verified entry. Four other policy-review candidates
(`Microsoft.Copilot`, `Microsoft.MicrosoftOfficeHub`,
`Microsoft.WindowsFeedbackHub`, and `MSTeams`) are outside the accepted 22-app
selection. No names or PFNs were guessed, and dynamic discovery remains deferred.

This validates declarations and documentation only. It did not query an actual
user's Appx registrations or provisioning inventory, change an app, or authorize
removal. All 22 catalog operations remain pending acceptance with no published
targets; Store app lifecycle and acquisition-dependent reinstall remain paused
until their applicable disposable-target checks. See [structured evidence](../archive/evidence/store-app-selection-static-reconciliation-2026-10-27-0705.json)
and the [migration run record](../MIGRATION-PLAN.md#reviewed-store-app-selection-static-reconciliation-2026-10-27-0705-utc).

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
