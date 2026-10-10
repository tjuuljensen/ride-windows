# Package licensing and local reviews

RIDE keeps publisher references in its shared catalog and acquires packages and
standalone artifacts directly from the declared publisher sources. Current
providers use publisher-owned GitHub releases, immutable GitHub file revisions,
and Microsoft's Sysinternals hosting. GitHub asset resolution rejects an asset
URL outside the repository declared by the release API URI. Normal publisher
hosting redirects still apply. A download cache is for local acquisition and
recovery; it is not an approved redistribution bundle.

## Shared publisher metadata

Every package and standalone artifact declares:

- `ProductUri`: official product/project information.
- `DownloadUri`: the acquisition/discovery source used by the provider.
- `License`: a descriptive upstream license summary, including known exceptions.
  This is not a complete SPDX expression or a license inventory of bundled components.
- `LicenseUri`: official license/EULA reference, or the closest publisher
  reference when no separate agreement is available. Use `License = 'Unknown'`
  and explain missing terms in the description rather than inventing permission.
- `TermsUri`: optional separate publisher download/service terms when applicable.

These fields appear in `list` objects, `show`, generated `docs/OPERATIONS.md`,
download results, and new artifact observation records and `.ride.json` sidecars.
Download records bind the public references to the resolved version and artifact
hash. They do not archive the referenced web page or establish legal permission;
the license files supplied with the particular release remain relevant.

Preserve upstream license/notice files included in downloaded installers or
archives. RIDE retains the original payload and does not strip its notices.
It does not scrape websites for agreements or download a second license payload.
Additional rule packs, configurations, and datasets have their own terms: the
SwiftOnSecurity configuration's CC-BY-4.0 declaration is in its XML header and
is separate from the Microsoft Sysmon EULA.

## Local user/company reviews

`LicenseReviewStatus`, `DistributionNotes`, and `LicenseReviewedAt` are private
operational records, never shared catalog defaults. The standalone tool
`tools/Manage-RideLicenseReviews.ps1` stores them as UTF-8 JSON at:

```text
%LocalAppData%\RIDE\license-reviews.json
```

Select another local or access-controlled company file with `-StorePath` on
each invocation. The file uses the current user's filesystem permissions;
RIDE does not configure shared storage ACLs. `.local/` is ignored by Git when
you deliberately keep local configuration inside a development checkout.
Keep exports and review notes out of public Git history and release payloads.
Do not store license keys, credentials, or entitlement secrets in review notes.

Read metadata and local reviews without creating a store or inspecting Windows:

```powershell
.\tools\Manage-RideLicenseReviews.ps1 Get -Id package.7zip
```

Write a review after evaluating the applicable release terms. Substitute your
actual version, reviewer, and findings for the example values:

```powershell
.\tools\Manage-RideLicenseReviews.ps1 Set -Id package.7zip `
  -ReviewedVersion 26.04 -ReviewOwner 'Example company' `
  -LicenseReviewStatus Reviewed `
  -DistributionNotes 'Internal workstation installation reviewed.' -WhatIf
# Repeat without -WhatIf to save the record.
```

`Unknown`, `NeedsReview`, and `Reviewed` describe review progress. `Reviewed`
does not mean approved for every use, caching, or redistribution. Record the
intended use and findings in `DistributionNotes`. Missing records display
`Unknown`. Each record covers an exact `ReviewedVersion` and `ReviewOwner`;
the tool retains other versions and owners. Reviews are informational and do
not change package install eligibility or automatically apply to newer releases.

For `Reviewed`, `LicenseReviewedAt` defaults to the current UTC timestamp.
Use an explicit ISO 8601 timestamp with `Z` or an offset when recording a prior
review. Other statuses may leave this field null. The tool normalizes timestamps
to UTC and supports `-WhatIf`/`-Confirm` for all writes.

Export and import use the same versioned JSON format:

```powershell
.\tools\Manage-RideLicenseReviews.ps1 Export -Path C:\private\ride-reviews.json
.\tools\Manage-RideLicenseReviews.ps1 Import -Path C:\private\ride-reviews.json -WhatIf
# Repeat without -WhatIf to merge into the selected store.
```

Export refuses an existing destination unless `-Force` is supplied. Import
merges by ID/version/owner, preserves unrelated records, and rejects conflicting
records unless `-Force` explicitly selects the incoming record. Invalid input
leaves existing JSON intact. Export before updating an existing review with Set;
Set replaces the same ID/version/owner record. Writes use a lock file and an
atomic file replacement; concurrent writers fail rather than lose updates.
Imports retain records for retired IDs so historical reviews can still be
exported. Get includes them with empty current catalog references.

```json
{
  "SchemaVersion": 1,
  "Reviews": [
    {
      "Id": "package.7zip",
      "ReviewedVersion": "26.04",
      "ReviewOwner": "Example company",
      "LicenseReviewStatus": "Reviewed",
      "DistributionNotes": "Internal workstation installation reviewed.",
      "LicenseReviewedAt": "2026-10-10T10:00:00.0000000Z"
    }
  ]
}
```

Command and review status parameters use their declared value sets for Tab
completion. `-Id` completes package/artifact IDs from the same bounded catalog
reader used for execution, filters case-insensitively, and fails quietly when
optional data is unavailable. `-Help`, `-Version`, and Get perform no writes.

## Acceptance and migration boundaries

Adding reference metadata does not accept a license on anyone's behalf. Current
installer arguments remain visible in the catalog; Sysmon still uses the existing
`-accepteula -i` installation command. Selecting a local `Reviewed` record neither
sets that switch nor changes its behavior. Review the
[Microsoft Sysinternals terms](https://learn.microsoft.com/en-us/sysinternals/license-terms)
before choosing that installation workflow.

Catalog and artifact observation `SchemaVersion = 1` are retained: publisher
reference fields are additive. Existing observation records are not backfilled
with today's links and remain readable/importable. No operation IDs, profiles,
saved run snapshots, or package restore semantics change. The local review store
has its own independent schema version; unsupported versions are rejected without
rewriting the file. Exports provide a recovery copy for future schema migrations.

## Optional future offline bundles

Offline bundle creation and a redistribution review gate are deferred optional
development. A future exporter should check each selected payload's distribution
rights, consult the operator's local review records for the exact version and
intended audience, and include required licenses, attribution, notices, and
source/source offers where applicable. It should retain the applicable terms
and review evidence with the bundle and refuse unresolved distribution rights.
The present download command does not implement this exporter or its gate.
