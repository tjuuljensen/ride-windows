# Package licensing and local reviews

RIDE keeps publisher references in its shared catalog and acquires packages and
standalone artifacts directly from the declared publisher sources. Current
providers use publisher-owned GitHub releases, immutable GitHub file revisions,
and Microsoft's Sysinternals hosting. GitHub asset resolution rejects an asset
URL outside the repository declared by the release API URI. Normal publisher
hosting redirects still apply. A download cache is for local acquisition and
recovery; it is not an approved redistribution bundle.

## Important to review licensing

Review these products before organizational deployment or paid client work,
even when a download is free. "Free for individuals" is not a reliable blanket
rule: eligibility can depend on use, organization size, installation counts,
edition, automation and redistribution. This watchlist covers requested and
deferred products as well as catalog entries; inclusion does not mean RIDE can
install them. Publisher references checked **2026-10-13**.

| Product or component | Free-use context | Corporate or professional review trigger | Official references |
| --- | --- | --- | --- |
| Npcap, including the separate Wireshark capture driver | The standard license generally limits use to five copies/computers/users. It has exceptions for use solely with the official Nmap, Wireshark or Microsoft Defender for Identity distributions. | Check the exact exception and all consumers of a shared driver. Broader deployment, silent installation and redistribution need separate review; OEM internal-use and redistribution rights differ. Wireshark's license does not grant general Npcap rights. | [Npcap license](https://github.com/nmap/npcap/blob/master/LICENSE), [OEM options](https://npcap.com/oem/) |
| RegRipper 4.0, separate from the pending 3.0 candidate | Publisher README checked 2026-10-16 limits the free-use grant to personal and academic college/university use. | Publisher prohibits inclusion in vendor products, vendor training or distributions. Company/paid use and redistribution require an applicable grant; do not carry the 3.0 MIT metadata over to 4.0 or bundle it in a kit. The pinned 3.0 candidate retains its own license and bundled-runtime notices. | [RegRipper 4.0 terms](https://github.com/keydet89/RegRipper4.0#license), [RegRipper 3.0 license](https://github.com/keydet89/RegRipper3.0/blob/master/license.txt) |
| KAPE | Kroll lists government, education/research and internal company use as free. The EULA limits the grant to owned/controlled systems and internal business use; assess the intended individual use against those terms. | Kroll now says KAPE is no longer available for commercial use on third-party networks or paid engagements. Do not repeat the older assumption that buying an enterprise license automatically resolves this. Check any existing agreement directly with the publisher. Modules, targets and third-party tools can have separate terms. | [Current usage clarification](https://www.kroll.com/en/services/cyber/reactive-services/kroll-artifact-parser-and-extractor-kape), [EULA](https://www.kroll.com/en/end-user-license-agreement) |
| Docker Desktop, if selected for a container-based solution | Free for personal use, education, non-commercial open-source projects and eligible small businesses with fewer than 250 employees **and** less than USD 10 million annual revenue. | Larger-company professional use and government use require a paid subscription. Review the organization and selected subscription. Docker Desktop terms are separate from Docker Engine and the applications/images it runs. RIDE does not select or provision Desktop automatically. | [Desktop license](https://docs.docker.com/subscription-billing/desktop-license/), [Subscription FAQ](https://www.docker.com/pricing/faq/) |

This is a maintained review list, not a complete license inventory or a shared
approval. Add products when review finds personal-only terms, enterprise or
technician editions, restricted drivers, paid-engagement restrictions or
separately licensed dependencies. Record the exact version, edition, use case,
deployment scale and reviewing owner in the local store described below. Recheck
publisher terms before deployment and at release preparation; retain supplied
notices and assess redistribution independently from internal use.

## Shared publisher metadata

Every package and standalone artifact in the built-in catalog declares:

- `ProductUri`: official product/project information.
- `DownloadUri`: the acquisition/discovery source used by the provider.
- `License`: a descriptive upstream license summary, including known exceptions.
  This is not a complete SPDX expression or a license inventory of bundled components.
- `LicenseUri`: official license/EULA reference, or the closest publisher
  reference when no separate agreement is available. Use `License = 'Unknown'`
  and explain missing terms in the description rather than inventing permission.
- `TermsUri`: optional separate publisher download/service terms when applicable.

Custom libraries may omit `ProductUri`, `LicenseUri` and `TermsUri` when no online
reference is available. Custom license/terms links accept absolute HTTP or HTTPS
URLs, including internal servers and localhost with custom ports; embedded
credentials are rejected. A descriptive `License` remains required and defaults
to `Unknown` in the guided helper. Describe licenses shipped in the payload or a
local file there instead of inventing a URL. Built-in license references remain
official HTTPS links; installer downloads still require HTTPS. See
[Custom libraries](custom-libraries.md) for authoring and validation.

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

## Explicit unattended installation and shared-kit behavior

Accepted Q14 keeps review information visible while supporting an explicitly
selected unattended installation workflow. RIDE's pending internal review status
must not prompt, pause or by itself block that mode. Report unresolved reviews
and publisher notices without changing their recorded status. The existing store
is already informational; the complete unattended preflight/continuation workflow
still needs implementation and per-product evidence.

This does not supply missing credentials, entitlements, publisher agreement answers
or required interactive installer responses. Interactive account/Npcap and other
technical prerequisites remain distinct. Installation is separate from publication:
shared kits default to omitting unreviewed restricted members and reporting those
omissions. No override of that publication default was selected. See the accepted
[Q14 record](migrations/decision-session-2026-10-17.md#q14-visible-local-licensing-review-and-fast-unattended-deployment)
for scope; neither mode records a licensing assessment on the user's behalf.

## License acceptance and record compatibility

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

## Requested offline bundles

The [accepted offline preparation workflow](offline-bundles.md) includes
profile-selected and full external-package sets, reviewed installed/portable
variants for selected targets, pinned RIDE/profiles/payloads, and optional supplied
servicing sources. A local integrity preflight is source-ready; automatic assembly,
publication and offline installation are not yet implemented.

Keep distribution review separate from local download or installation. Retain
publisher licences, attribution, notices and applicable source/source offers.
Consult exact-version/owner local records when preparing shared content, without
copying private assessments or credentials into the manifest. Under Q14, shared
bundles default to omitting unreviewed restricted payloads and reporting omissions.
An incomplete bundle may serve a profile whose actual dependencies are complete;
missing selected content must stop deployment before changes with no network fallback.
Pending internal licence review alone is not an installation gate. Actual publisher
terms, entitlements and required responses remain separate. A hash match or local
Reviewed record does not establish redistribution rights.
