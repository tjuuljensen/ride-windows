# Store app inventory and reconciliation batch

Recorded: **2026-10-14**. The user selected both separate sustained device policy
and intended-user one-time removal workflows, and requested updating/reconciling
v2 lists as app populations change. This batch implements their read-only identity
foundation, not either removal handler or an approved bulk list.

catalog/store-app-review.psd1 contains 119 review names: all 58 Microsoft and 48
third-party historical removal queries, plus 13 new names from the inspected
25-entry static policy template. Twelve static entries share a literal historical
name. Registration membership remains independent; AmazonVideo.PrimeVideo,
BytedancePte.Ltd.TikTok, Clipchamp.Clipchamp and Facebook.InstagramBeta retain their
missing reverse entries. No old name was guessed into a renamed app or declared
retired because it is absent from an inventory.

Current Microsoft feature documentation includes a static `XboxGamingOverlay`
payload entry that is absent from the inspected template. The recorded template
hash and its 25-entry source crosswalk remain authoritative for this local
declaration set. The documentation discrepancy is pending schema/servicing evidence,
not permission to invent a PFN or write an unsupported checkbox.

RIDE.StoreAppReview 0.1.0 and two tools implement expected-SID collection and saved
inventory comparison. The collector queries current-user Main/Framework/Bundle/
Resource/Optional registrations; absence and missing protection flags are retained.
Comparison includes unfamiliar current apps, exact policy PFNs, publisher-family
mismatches, framework/protected flags, utility/recovery caution and reverse gaps.
All rows remain unselected/unapproved. Export preview performs no query or write.
No executable v2 bulk preset, application registration, removal, provisioning or
acquisition was introduced. No operation or supported-target declaration changed.

Sixteen mocked/data-only tests passed on each native PowerShell edition, zero
failed or skipped. They cover exact historical membership, template
identities, wrong-user refusal, query failure, unknown flags, missing/renamed apps,
publisher mismatch/casing, unfamiliar current names, reverse gaps, frameworks,
saved CLI comparison and no-query/no-write export preview. Parser/catalog/profile/
reference validation passed on both editions: 318 operations, three groups, five
profiles and 137 PowerShell files. Final results are in the
dated migration ledger and .local/store-app-review-{5,7}/result.json. Live Appx
collection and interactive/device-policy behavior remain pending; no actual
installed-app inventory was collected on the developer workstation.

Current VM readiness remains deferred after denied CIM access. No disposable
request or elevation was submitted. Dependency bridge completion and historical
resource yield do not replace current idle/pin/hash checks. Native handoff
acceptance and mixed-profile recovery remain pending independently.

All five legacy ranges remain settings38-58/packages58-73/components20-25/
accounts-config-files25-35/maintenance8-12, total150-205/about180. The app outcomes
remain component-owned; rows and helper tools are not additional legacy closures.
Packages remain paused. Next work requires explicit app selection, actual template
capability and separate lifecycle/recovery contracts for the two workflows.
