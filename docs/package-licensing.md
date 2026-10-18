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

Additional publisher checks on **2026-10-17**:

| Product or component | Review finding | Publisher reference |
| --- | --- | --- |
| JoeWare tools | The general licence permits personal/company system use but restricts distribution to other users or companies. Assess shared kits separately. The rdp-sec-check page identifies GPLv2 source, but its exact ZIP, compiled PerlApp binary, source and dependency notices remain uninspected; a source-repository reference also carries a tool-specific legal-use condition whose applicability to the JoeWare ZIP must be checked. | [General licence](https://www.joeware.net/freetools/warranty.htm), [rdp-sec-check](https://www.joeware.net/freetools/tools/rdp-sec-check/index.htm), [dated version/licence follow-up](archive/evidence/joeware-rdp-sec-check-version-license-follow-up-2026-10-17.json) |
| MiTeC standalone apps | Product pages distinguish licence tiers; the software EULA describes unregistered non-commercial use, evaluation conditions and purchased licences. Do not inherit the old site's freeware labels. Keep licence keys private and preserve activation; deployment, use and distribution assessments remain separate. | [Software EULA](https://www.mitec.cz/wp/support/), [JSON Viewer](https://www.mitec.cz/wp/mjsonv/), [XML Viewer](https://www.mitec.cz/wp/mxmlv/) |
| MiTeC historical standalone products | Reconcile each historical product statement with current terms. Internet History Browser, Icon Explorer and Windows File Analyzer restrict free use to private, educational and non-commercial purposes; the other ten reviewed historical pages state private/commercial free use. None establishes shared-kit distribution approval. SSView's bundled codec/source/sample require their own terms review; a ZLib name is insufficient. | [Dated reconciliation](archive/evidence/mitec-historical-reconciliation-2026-10-17.json), [SSView ownership review](archive/evidence/ssview-ownership-follow-up-2026-10-17.json) |
| NTCore Driver List and Rebel.NET | Neither inspected archive contains a licence file; no explicit use/distribution grant was located on the reviewed product pages. Keep admission pending a product-specific reference; do not inherit Explorer Suite terms or treat a C/C++ format header as a licence. | [Driver List](https://ntcore.com/driver-list/), [Rebel.NET](https://ntcore.com/rebel-net/), [Artifact evidence](archive/evidence/ntcore-member-source-follow-up-2026-10-17.json) |
| PhotoView and DDG bundled files | PhotoView includes a Microsoft GDI+ DLL plus language resources; DDG_IBFB includes a sample database/configuration and CSS. Publisher product terms alone do not establish all dependency/sample redistribution rights. Retain provenance and review exact selections before bundling. | [Utility evidence](archive/evidence/mitec-utility-artifact-review-2026-10-17.json), [Database evidence](archive/evidence/mitec-database-artifact-review-2026-10-17.json) |
| NTCore VirtualReg Manager and ScreenWriter | VirtualReg Manager's publisher permits inclusion in freeware; broader distribution remains to assess. ScreenWriter's bundled readme describes free software without warranty but supplies no explicit redistribution grant; preserve its attribution and review the two included samples separately. | [VirtualReg Manager](https://ntcore.com/virtualreg-manager/), [ScreenWriter](https://ntcore.com/screenwriter/), [Static artifact evidence](archive/evidence/ntcore-managed-utility-source-review-2026-10-17.json) |

The remaining MiTeC/NTCore source pass on **2026-10-17** adds these findings:

| Product or component | Review finding | Reference |
| --- | --- | --- |
| Remaining current MiTeC apps | Certificate Generator, Certificate Information, InfoBar, Mail Viewer, OLE/COM Explorer, System Information eXtra and UUID Generator explicitly limit free use to private/educational/non-commercial purposes. Other reviewed current pages list paid tiers. Review exact product terms and intended use; historical freeware labels do not establish organizational or distribution permission. | [Product-level observations](archive/evidence/mitec-remaining-source-review-2026-10-17.json), [Software EULA](https://www.mitec.cz/wp/support/) |
| DFM Editor and bundled SQLite components | DFM's Delphi 11/12 variants each ship eight matching BPLs; review the Embarcadero runtime notices separately. SQLite Query, Internet History Browser and ICQ/MSN History Browser contain SQLite-identified binaries, including renamed DLLs. Upstream SQLite deliverable code is public domain; that does not independently prove these exact binaries' provenance or license the surrounding MiTeC product. | [Artifact evidence](archive/evidence/mitec-remaining-source-review-2026-10-17.json), [SQLite copyright](https://www.sqlite.org/copyright.html) |
| NTCore Phoenix Protector | The retained MSI includes Phoenix License.rtf. Its limited personal, nontransferable single-user development/testing grant and restrictions on component separation, transfer and commercial hosting require exact intended-use review. The page's freeware label is insufficient; keep page 1.8.0.1, MSI 1.7.1 and executable 1.9.0.1 separate. No agreement or private owner assessment was recorded on the user's behalf. | [Publisher page](https://ntcore.com/phoenix-protector/), [MSI/EULA hash and observations](archive/evidence/ntcore-remaining-source-review-2026-10-17.json) |
| Remaining NTCore bundles | NETUnpack, DynLogger, NoDel, SNSRemover and WIM Installer retain product-specific grant/dependency gates. SNSRemover's nested older PE Detective is a separate pinned bundle; no inherited permission or automatic replacement of the reviewed standalone candidate. Explorer Suite's matching publisher hash does not resolve its opaque installer contents. | [Per-product evidence and exclusions](archive/evidence/ntcore-remaining-source-review-2026-10-17.json), [Collection coverage](archive/evidence/mitec-ntcore-source-coverage-2026-10-17.json) |

The later [static installer extraction](migrations/application-migration-review.md#six-installer-static-extraction-2026-10-17)
resolved all six outer payload inventories. Additional findings:

- Mail Checker includes three OpenSSL-identified **1.0.1e** DLLs; two SSL DLL
  names contain identical bytes. The [version-specific upstream terms](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_1e/LICENSE)
  include both OpenSSL and SSLeay conditions. Reconcile exact binary provenance,
  notices and acknowledgements; the product's freeware label is insufficient.
  No stand-alone licence file was found in its extracted file set; embedded
  installer agreements remain a separate review surface.
- Explorer Suite contains UPX **3.08**, its separate NTCore extension and a
  source ZIP with older build artifacts. The [UPX 3.08 licence](https://raw.githubusercontent.com/upx/upx/v3.08/LICENSE)
  is GPL-2.0-or-later with a compressed-executable exception; that exception does
  not supply a grant for the NTCore extension/SDK or remove UPX distribution
  obligations. Retain the source/MSI/templates/scripts as distinct reviewed
  components. The suite readme describes free software without warranty; no
  explicit redistribution grant was located there.
- Paradox Data Editor includes **BdeInst.dll 5.1.1.1**, **TUTIL32.DLL 5.0.0.38**
  and a temporary MiniReg helper. The subsequent nested review decoded all 29
  BDEFILES records, including core BDE **5.1.1.1** and DBCLIENT **5.0.1.32**.
  Exact distribution/registration terms remain unresolved. Extraction did not
  register a component or establish dependency compatibility.

Exact hashes, member inventories and helper/variant differences are in the
[extraction evidence](archive/evidence/installer-static-extraction-2026-10-17.json).
No local user/company review or shared distribution approval was created.

The [nested BDE/version/licence follow-up](migrations/application-migration-review.md#nested-bde-and-versionlicence-reconciliation-2026-10-17)
rehashes the retained MiTeC product pages and separates the software EULA from
the component/class licence. Named-user/build-machine, team and site scope must
match the applicable product agreement; component development rights are not
blanket app redistribution rights. Historical free-use statements and current
terms remain exact-product questions, not automatic permission for shared kits.

Embarcadero's [software licence requirements](https://docwiki.embarcadero.com/RADStudio/Sydney/en/Software_License_Requirements)
point to version-specific DEPLOY/README and product agreements, plus separate
vendor terms. Search-indexed official guidance was readable, but direct requests
to that page and two related BDE guides returned HTTP 403. It does not establish
rights for these exact BDE or DFM BPL bytes. Preserve that access limitation and
obtain the applicable publisher-supplied documents before distribution review.
Phoenix's fresh freeware page does not explicitly replace its retained EULA;
OpenSSL/UPX upstream references likewise do not resolve surrounding-product grants.

The [Phoenix/Explorer Suite follow-up](archive/evidence/ntcore-phoenix-suite-version-license-follow-up-2026-10-17.json)
confirms that NTCore's currently linked Explorer Suite download publishes the
same SHA-256 as the retained installer, whose embedded product label is IV; the
page still says III (18/11/2012), and the reviewed monthly archive pages contain
no later suite release clarification. The Suite page describes freeware, while
its retained readme says free software without warranty; neither reviewed source
states a separate redistribution grant. Phoenix's page describes the application
as freeware, but its bundled single-user development/testing EULA remains in the
retained MSI and no superseding notice was found. These findings are not an
individual or company use assessment, distribution approval, or license-key
review. Preserve the exact product/component terms and request clarification
before admitting either bundle to a shared distribution.

This is a maintained review list, not a complete license inventory or a shared
approval. Add products when review finds personal-only terms, enterprise or
technician editions, restricted drivers, paid-engagement restrictions or
separately licensed dependencies. Record the exact version, edition, use case,
deployment scale and reviewing owner in the local store described below. Recheck
publisher terms before deployment and at release preparation; retain supplied
notices and assess redistribution independently from internal use.

## Shared publisher metadata

The accepted [shared-installer rule](migrations/package-deployment-decisions.md#shared-installers-and-licence-tiers)
keeps one package when only entitlement changes. Installation and adoption must
preserve activation and settings; activation is a separate optional action.
Do not mistake this model for redistribution permission or evidence that all
publisher editions have identical artifacts.

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
