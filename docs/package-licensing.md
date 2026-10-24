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
| Microsoft Visual C++ v14 Redistributable (`package.vcredist-v14-x64`, version 14.51.36247.0) | Microsoft provides the redistributable for applications built with Visual Studio; use of the files and redistribution are governed by the applicable Visual Studio license terms. | Installing Microsoft's public installer for an application's runtime dependency is distinct from copying or redistributing the payload. Review the applicable Visual Studio license and the organization's redistribution role before including the installer in a shared offline bundle or other distribution. No redistribution entitlement is inferred. | [Latest supported downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist), [redistribution guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files), [license terms](https://visualstudio.microsoft.com/license-terms/) |
| Npcap, including the separate Wireshark capture driver | The standard license generally limits use to five copies/computers/users. It has exceptions for use solely with the official Nmap, Wireshark or Microsoft Defender for Identity distributions. | Check the exact exception and all consumers of a shared driver. Broader deployment, silent installation and redistribution need separate review; OEM internal-use and redistribution rights differ. Wireshark's license does not grant general Npcap rights. | [Npcap license](https://github.com/nmap/npcap/blob/master/LICENSE), [OEM options](https://npcap.com/oem/) |
| RegRipper 4.0, separate from the pending 3.0 candidate | Publisher README checked 2026-10-16 limits the free-use grant to personal and academic college/university use. | Publisher prohibits inclusion in vendor products, vendor training or distributions. Company/paid use and redistribution require an applicable grant; do not carry the 3.0 MIT metadata over to 4.0 or bundle it in a kit. The pinned 3.0 candidate retains its own license and bundled-runtime notices. | [RegRipper 4.0 terms](https://github.com/keydet89/RegRipper4.0#license), [RegRipper 3.0 license](https://github.com/keydet89/RegRipper3.0/blob/master/license.txt) |
| KAPE | Kroll lists government, education/research and internal company use as free. The EULA limits the grant to owned/controlled systems and internal business use; assess the intended individual use against those terms. | Kroll now says KAPE is no longer available for commercial use on third-party networks or paid engagements. Do not repeat the older assumption that buying an enterprise license automatically resolves this. Check any existing agreement directly with the publisher. Modules, targets and third-party tools can have separate terms. | [Current usage clarification](https://www.kroll.com/en/services/cyber/reactive-services/kroll-artifact-parser-and-extractor-kape), [EULA](https://www.kroll.com/en/end-user-license-agreement) |
| Docker Desktop (`package.docker-desktop`) | Free for personal use, education, non-commercial open-source projects and eligible small businesses with fewer than 250 employees **and** less than USD 10 million annual revenue. | Larger-company professional use and government use require a paid subscription. Review the organization and selected subscription. Docker Desktop terms are separate from Docker Engine and the applications/images it runs. Neither install variant accepts terms, selects/provisions a backend, or deploys containers. | [Desktop license](https://docs.docker.com/subscription-billing/desktop-license/), [Subscription Service Agreement](https://www.docker.com/legal/docker-subscription-service-agreement/), [Subscription FAQ](https://www.docker.com/pricing/faq/) |

Additional publisher checks on **2026-10-17**:

| Product or component | Review finding | Publisher reference |
| --- | --- | --- |
| JoeWare tools | The publisher clarified on 2024-06-06 that companies may download a copy and serve it to their internal users for internal corporate use. Distribution as part of a solution sold to others is a separate case. The internal-use clarification covers RIDE's direct download-and-install workflow; it is not a migration gate. AdFind has separate publisher-documented AV/PUP blocking, which remains a technical selection issue for that product only. The `rdp-sec-check` page identifies GPLv2 source included in its ZIP; exact source, compiled PerlApp binary and dependency notices remain uninspected, as does the applicability of a separate source-repository condition to those exact ZIP contents. | [JoeWare internal-use clarification](https://blog.joeware.net/2024/06/06/6216/), [general terms](https://www.joeware.net/freetools/warranty.htm), [AdFind AV/download notes](https://joeware.net/freetools/tools/adfind/index.htm), [rdp-sec-check](https://www.joeware.net/freetools/tools/rdp-sec-check/index.htm), [dated version/licence follow-up](archive/evidence/joeware-rdp-sec-check-version-license-follow-up-2026-10-17.json), [2026-10-23 review](archive/evidence/joeware-internal-use-current-version-review-2026-10-23.json) |
| MiTeC standalone apps | Product pages distinguish licence tiers; the software EULA describes unregistered non-commercial use, evaluation conditions and purchased licences. Do not inherit the old site's freeware labels. Keep licence keys private and preserve activation; deployment, use and distribution assessments remain separate. | [Software EULA](https://www.mitec.cz/wp/support/), [JSON Viewer](https://www.mitec.cz/wp/mjsonv/), [XML Viewer](https://www.mitec.cz/wp/mxmlv/) |
| MiTeC historical standalone products | Reconcile each historical product statement with current terms. Internet History Browser, Icon Explorer and Windows File Analyzer restrict free use to private, educational and non-commercial purposes; the other ten reviewed historical pages state private/commercial free use. None establishes shared-kit distribution approval. The Windows File Analyzer 2.10.0 and Icon Explorer 5.3.0 candidates have local `NeedsReview` records for owner-specific use administration; these markers do not block their RIDE direct-download/install migration. SSView's bundled codec/source/sample require their own terms review; a ZLib name is insufficient. | [Dated reconciliation](archive/evidence/mitec-historical-reconciliation-2026-10-17.json), [SSView ownership review](archive/evidence/ssview-ownership-follow-up-2026-10-17.json) |
| NTCore Driver List and Rebel.NET | Neither inspected archive contains a licence file; no explicit use/distribution grant was located on the reviewed product pages. Keep admission pending a product-specific reference; do not inherit Explorer Suite terms or treat a C/C++ format header as a licence. | [Driver List](https://ntcore.com/driver-list/), [Rebel.NET](https://ntcore.com/rebel-net/), [Artifact evidence](archive/evidence/ntcore-member-source-follow-up-2026-10-17.json) |
| PhotoView and DDG bundled files | PhotoView includes a Microsoft GDI+ DLL plus language resources; DDG_IBFB includes a sample database/configuration and CSS. Publisher product terms alone do not establish all dependency/sample redistribution rights. Retain provenance and review exact selections before bundling. | [Utility evidence](archive/evidence/mitec-utility-artifact-review-2026-10-17.json), [Database evidence](archive/evidence/mitec-database-artifact-review-2026-10-17.json) |
| NTCore VirtualReg Manager and ScreenWriter | VirtualReg Manager's publisher permits inclusion in freeware; broader distribution remains to assess. ScreenWriter's bundled readme describes free software without warranty but supplies no explicit redistribution grant; preserve its attribution and review the two included samples separately. | [VirtualReg Manager](https://ntcore.com/virtualreg-manager/), [ScreenWriter](https://ntcore.com/screenwriter/), [Static artifact evidence](archive/evidence/ntcore-managed-utility-source-review-2026-10-17.json) |

The remaining MiTeC/NTCore source pass on **2026-10-17** adds these findings:

| Product or component | Review finding | Reference |
| --- | --- | --- |
| Remaining current MiTeC apps | Certificate Generator, Certificate Information, InfoBar, Mail Viewer, OLE/COM Explorer, System Information eXtra and UUID Generator pages limit free use to private/educational/non-commercial purposes. Windows Registry Recovery and SMBIOS Explorer list paid license tiers; review their current terms and intended use. Exact-version local NeedsReview records for the new OLE/COM Explorer, Registry Recovery and SMBIOS candidates support owner-specific administration but do not block RIDE package migration. Historical freeware labels do not establish organizational or distribution permission. | [Product-level observations](archive/evidence/mitec-remaining-source-review-2026-10-17.json), [Software EULA](https://www.mitec.cz/wp/support/) |
| MiTeC System Information eXtra 16.0.0 and TAPI Monitor 1.2.0 | Both exact versions now have local `NeedsReview` records. System Information eXtra is freeware for private, educational and non-commercial purposes; it creates potentially sensitive system reports. TAPI Monitor lists the same non-commercial terms and a EUR 30 lifetime single-user commercial license; it can control calls. These markers do not block candidate planning and do not assert entitlement. | [System Information eXtra](https://www.mitec.cz/wp/msix/), [TAPI Monitor](https://www.mitec.cz/wp/mtapimon/), [source/member evidence](archive/evidence/mitec-system-information-tapi-static-review-2026-10-20.json), [candidate preparation](application-migration-review.md#mitec-system-information-extra-and-tapi-monitor-package-candidates-2026-10-23) |
| DFM Editor and bundled SQLite components | DFM Editor now has explicit, disjoint Delphi 11/12 package variants with eight matching BPLs each; the pinned package stages files without loading/registering them. Its exact versions have local `NeedsReview` markers for owner-specific administration, which do not block migration or install planning. SQLite Query, Internet History Browser and ICQ/MSN History Browser contain SQLite-identified binaries, including renamed DLLs. Upstream SQLite deliverable code is public domain; that does not independently prove these exact binaries' provenance or license the surrounding MiTeC product. | [DFM candidate and member hashes](archive/evidence/mitec-dfm-editor-candidate-2026-10-23.json), [artifact evidence](archive/evidence/mitec-remaining-source-review-2026-10-17.json), [SQLite copyright](https://www.sqlite.org/copyright.html) |
| MiTeC EXE Explorer and HexEdit | Both exact package versions have local `NeedsReview` markers for owner-specific license administration. Those records do not block candidate migration or install planning. EXE Explorer acceptance excludes VirusTotal/API-key/network behavior; HexEdit file tests use disposable copies and exclude live memory/raw-disk targets. | [Current EXE Explorer page](https://www.mitec.cz/exe.html), [HexEdit page](https://www.mitec.cz/wp/mhex/), [candidate evidence](archive/evidence/mitec-analysis-tools-candidates-2026-10-23.json), [support terms](https://www.mitec.cz/wp/support/) |
| MiTeC Mail Viewer and history viewers | Four exact candidate versions have local `NeedsReview` markers for owner-specific administration; these are informational and do not block package migration or install planning. Mail Viewer can expose message bodies and attachments; EHB, IHB and IMHB expose their documented history metadata. Later behavior checks use synthetic stores only. | [Current product pages](https://www.mitec.cz/wp/mmv/), [candidate evidence](archive/evidence/mitec-mail-history-viewer-candidates-2026-10-23.json), [support terms](https://www.mitec.cz/wp/support/) |
| MiTeC Structured Storage Viewer 4.1.2 | The pinned package candidate selects only `SSView.exe`; the optional codec, Delphi source and sample are excluded. Its exact-version `NeedsReview` record is informational and does not block direct-download package planning. Unregistered use is described as non-commercial and paid tiers are listed; owner-specific entitlement remains local. Codec/source/sample rights are not resolved by the viewer candidate. | [Publisher product page](https://www.mitec.cz/wp/mssv/), [terms](https://www.mitec.cz/wp/support/), [candidate evidence](archive/evidence/mitec-ssview-candidate-preparation-2026-10-23.json) |
| MiTeC Network Scanner 6.1.0 | The pinned x86/x64 candidate has an exact-version local `NeedsReview` record for owner-specific license administration. This marker is informational and does not block direct-download package planning. MiTeC lists paid tiers and describes unregistered use as non-commercial freeware; the local record does not determine entitlement. | [Publisher product page](https://www.mitec.cz/wp/mns/), [terms](https://www.mitec.cz/wp/support/), [candidate evidence](archive/evidence/mitec-network-scanner-candidate-preparation-2026-10-23-1623.json) |
| MiTeC Interbase Query 9.5.0 | The pinned x86/x64 candidate has an exact-version local `NeedsReview` record for owner-specific license administration. This marker is informational and does not block direct-download package planning. The publisher lists single-user, team and site license tiers; the local record does not determine entitlement. | [Publisher product page](https://www.mitec.cz/wp/mibq/), [terms](https://www.mitec.cz/wp/support/), [candidate evidence](archive/evidence/mitec-interbase-query-candidate-preparation-2026-10-23-1632.json) |
| MiTeC Task Manager DeLuxe 5.1.1 | The pinned x86/x64 candidate has an exact-version local `NeedsReview` record for owner-specific license administration. This marker is informational and does not block direct-download package planning. The publisher lists a lifetime single-user license; the local record does not determine owner-specific use. | [Publisher product page](https://www.mitec.cz/wp/tmx/), [terms](https://www.mitec.cz/wp/support/), [candidate evidence](archive/evidence/mitec-task-manager-deluxe-candidate-preparation-2026-10-23-1659.json) |
| NTCore Phoenix Protector (`package.phoenix-protector`) | The exact retained MSI 1.7.1 is now a Windows 11 package candidate pinned by SHA-256; its review record is `NeedsReview` with owner Unassigned. The MSI includes Phoenix License.rtf with a limited personal, nontransferable individual development/testing grant and restrictions on component separation, transfer and commercial hosting. The publisher's freeware label does not reconcile or replace those terms. Keep publisher page 1.8.0.1, MSI 1.7.1 and executable 1.9.0.1 separate; no user's or organization's entitlement or redistribution rights are inferred. | [Publisher page](https://ntcore.com/phoenix-protector/), [package usage and acceptance limits](application-packages.md#phoenix-protector-msi-candidate), [MSI/EULA hash and observations](archive/evidence/ntcore-remaining-source-review-2026-10-17.json) |
| NTCore 4GB Patch (`package.ntcore-4gb-patch`) | The publisher page and retained archive provide no product-specific license grant; executable copyright metadata says 2007 Daniel Pistelli, all rights reserved. Package candidacy and native acceptance proceed with the exact-version local status `NeedsReview`, per the user's migration priority. This does not assert internal entitlement or distribution permission. | [Publisher page](https://ntcore.com/4gb-patch/), [source/license findings](archive/evidence/ntcore-4gb-patch-page-follow-up-2026-10-21.json), [candidate and acceptance limits](application-packages.md#ntcore-4gb-patch-portable-candidate) |
| NTCore Driver List (`package.ntcore-driver-list`) | The exact archive and selected x64/x86 member versions are pinned from retained publisher bytes. The publisher page/archive provide no product-specific use or distribution grant. Candidate planning proceeds with an exact-version local `NeedsReview` marker; this review note is not an installation gate or an entitlement statement. | [Publisher page](https://ntcore.com/driver-list/), [source/member evidence](archive/evidence/ntcore-member-source-follow-up-2026-10-17.json), [candidate and report boundary](application-packages.md#ntcore-driver-list-and-rebelnet-portable-candidates) |
| NTCore Rebel.NET (`package.ntcore-rebelnet`) | The official guide says commercial use goes against the product terms; intended-use applicability and redistribution remain under review. Candidate planning proceeds with an exact-version local `NeedsReview` marker; this review note is not an installation gate or an entitlement statement. | [Publisher product page](https://ntcore.com/rebel-net/), [official guide](https://ntcore.com/files/rebelnet.htm), [source/member evidence](archive/evidence/ntcore-member-source-follow-up-2026-10-17.json), [candidate and synthetic-target boundary](application-packages.md#ntcore-driver-list-and-rebelnet-portable-candidates) |
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
The package-planning regression verifies this separation for Phoenix Protector,
NTCore 4GB Patch, Driver List, Rebel.NET, three MiTeC candidates, and Wireshark: each local `NeedsReview`
record remains visible while an install plan is still available. It does not execute
installers or clear their separate technical acceptance status.
See the [dated regression evidence](archive/evidence/license-review-package-plan-regression-2026-10-23.json).
The expanded catalog-wide regression then assigned synthetic version-matched
`NeedsReview` records to all 41 packages still marked `PendingAcceptance`; every
install plan remained available with technical acceptance pending. PowerShell 7
Pester passed 21/21. See the [expanded regression evidence](archive/evidence/pending-package-needsreview-plan-regression-2026-10-23.json).

## Sysinternals approval for RIDE download and install, 2026-10-22

The prior RIDE v2 license-specialist assessment approved Sysinternals for RIDE's
download-and-install workflow. RIDE acquires the tools directly from Microsoft's
download center and installs them on devices supported by the user; RIDE does not
publish or transfer Sysinternals copies. The user reconfirmed that approved scope
on 2026-10-22, so licensing is not a blocker for Sysinternals package migration.
On 2026-10-23, the user reaffirmed that there are no legal issues using
Sysinternals in RIDE and directed that license concerns must not block this
package migration.
The specialist approval and user's reaffirmation govern this migration
decision. Microsoft's [terms](https://learn.microsoft.com/en-us/sysinternals/license-terms)
and [licensing FAQ](https://learn.microsoft.com/en-us/sysinternals/license-faq)
are retained as product references, not as a separate license gate for RIDE's
approved workflow.

All ten exact Sysinternals suite/product versions are now `Reviewed` in the
checkout-local store, based on that prior specialist approval as reconfirmed by
the user. The reviewer identity and original approval date were not retained, so
the records say so rather than inventing them. See the [corrected
disposition evidence](archive/evidence/sysinternals-license-disposition-correction-2026-10-22.json);
the earlier [review-marker record](archive/evidence/sysinternals-license-review-2026-10-22.json)
is historical and superseded for RIDE download-and-install use.

On 2026-10-24 at 15:20 UTC, the user again emphasized that the v2 specialist
approval governs RIDE's direct download-and-install use. Do not apply strict or
generalized redistribution reasoning as a Sysinternals migration blocker. See
[latest disposition evidence](archive/evidence/sysinternals-license-disposition-reaffirmation-2026-10-24-1520.json).
The user most recently reaffirmed on 2026-10-23 that there are no legal issues using
Sysinternals in RIDE and that license concerns must not block package migration. Keep
the current disposition: approved for RIDE's direct download-and-install workflow;
no separate license review or distribution gate is required for this migration. See
the [original reaffirmation](archive/evidence/sysinternals-license-reaffirmation-2026-10-23.json)
and [latest scope record](archive/evidence/sysinternals-license-scope-reaffirmation-2026-10-23-1013.json).
The user reiterated on 2026-10-23 at 14:01 UTC that RIDE does not transfer or
publish Sysinternals, that the prior RIDE v2 specialist review approved the tool,
and that there are no legal issues for RIDE's download-and-install workflow. This
does not reopen licensing review or add an acceptance gate. See the [latest
decision evidence](archive/evidence/sysinternals-license-scope-reaffirmation-2026-10-23-1401.json).
On 2026-10-23 at 17:56 UTC, the user clarified that RIDE is a direct download-and-install tool: it obtains Sysinternals from Microsoft for installation on supported devices and does not transfer or publish copies. The prior RIDE v2 license-specialist assessment approved this workflow. The user states there are no legal issues using Sysinternals in RIDE and directs that generalized or strict redistribution reasoning must not block package migration. Licensing remains settled; no new license review or distribution gate applies. Defender-detected files remain excluded. Technical lifecycle, exact recovery and Windows target acceptance are still pending because VM/checkpoint access is unavailable. See the [latest decision evidence](archive/evidence/sysinternals-license-scope-reaffirmation-2026-10-23-1756.json).
On 2026-10-24, the user again directed that the prior specialist approval governs and that generalized redistribution reasoning must not block migration. No license blocker applies to Sysinternals in RIDE; Defender-detected files remain separately excluded. See the [latest approval reaffirmation](archive/evidence/sysinternals-approval-reaffirmation-2026-10-24-0350.json).
On 2026-10-24 at 05:03 UTC, the user reiterated that RIDE obtains Sysinternals directly from Microsoft for installation on supported devices, does not transfer or publish it, and is covered by the prior RIDE v2 specialist approval. The user's disposition is that there are no legal issues using Sysinternals in RIDE. Do not apply a generalized redistribution review or another licensing gate to this package migration. Defender detections remain a separate security exclusion; remaining acceptance work is technical. See the [current decision evidence](archive/evidence/sysinternals-approval-reaffirmation-2026-10-24-0503.json).
On 2026-10-24 at 08:42 UTC, the user again emphasized that migration reasoning must follow practical license administration: the prior RIDE v2 review by a license specialist approved Sysinternals for RIDE's download-and-install use. No legal blocker applies. RIDE obtains the tools from Microsoft for installation on supported devices and does not transfer or publish copies. Do not use generalized redistribution analysis to block migration or require a new license review. Defender-detected files remain separate exclusions; technical acceptance remains open. See the [latest decision evidence](archive/evidence/sysinternals-license-rationale-reaffirmation-2026-10-24-0842.json).

On 2026-10-24 at 12:37 UTC, the user reaffirmed that this prior specialist
approval governs RIDE's direct Microsoft download-and-install workflow. RIDE
does not transfer or publish Sysinternals copies, and the user confirms there
are no legal issues using Sysinternals in RIDE. Do not apply generalized
redistribution reasoning or require another license review as a package
migration gate. Defender-detected files remain separate security exclusions;
technical acceptance remains open. See the [latest decision evidence](archive/evidence/sysinternals-package-migration-disposition-2026-10-24-1237.json).

On 2026-10-24 at 16:35 UTC, the user corrected an overly strict interpretation:
RIDE is a direct download-and-install tool, not a publisher or transfer service
for Sysinternals. The prior RIDE v2 review by a license specialist approved the
tool for this workflow, and the user's disposition is that there are no legal
issues using it in RIDE. Do not turn general distribution language into a legal
hold, a new review requirement, or a package-migration blocker. Defender alerts
remain independent security exclusions; other open gates are technical. This
clarification changes no migration estimate. See the [current disposition
record](archive/evidence/sysinternals-license-practical-administration-correction-2026-10-24-1635.json).

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
technical prerequisites remain distinct. Shared-kit publication has a separate
default that omits unreviewed restricted members and reports those omissions. That
publication default does not apply to RIDE's direct publisher-download/install
workflow for Sysinternals, which is covered by the prior RIDE v2 specialist approval
and has no license migration gate. See the accepted
[Q14 record](migrations/decision-session-2026-10-17.md#q14-visible-local-licensing-review-and-fast-unattended-deployment)
for scope; neither mode records a licensing assessment on the user's behalf.

## License acceptance and record compatibility

User decision, 2026-10-22: candidate package implementation may proceed while
entitlement is unresolved when the package description clearly records the
known terms and uncertainty. A version-specific local `NeedsReview` record is
optional supporting context. Neither record establishes entitlement or
redistribution permission; native acceptance and shared publication remain
separate decisions.

Adding reference metadata does not accept a license on anyone's behalf. Current
installer arguments remain visible in the catalog; Sysmon still uses the existing
`-accepteula -i` installation command. Selecting a local `Reviewed` record neither
sets that switch nor changes its behavior. The prior RIDE v2 specialist approval
and the user's 2026-10-22 reconfirmation cover RIDE's direct Microsoft
download-and-install workflow. There are no legal issues or licensing blockers
for using Sysinternals in RIDE's package migration.

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

On 2026-10-23 at 18:18 UTC, the user corrected the migration rationale: the prior
RIDE v2 license-specialist review approved Sysinternals, and RIDE's workflow is
direct download from Microsoft followed by installation on supported devices.
RIDE does not publish Sysinternals or create a shared redistribution bundle. The
user states there are no legal issues for this workflow and directs that generalized
redistribution concerns must not block package migration. The ten exact version
records remain `Reviewed`; no additional license review or migration gate applies.
The four Defender-detected tools remain excluded for that separate security reason.
Only technical lifecycle, recovery and Windows target acceptance remain. See the
[dated decision evidence](archive/evidence/sysinternals-license-scope-clarification-2026-10-23-1818.json).
On 2026-10-24 at 03:03 UTC, the user reaffirmed that the prior RIDE v2
license-specialist approval covers RIDE's direct download-and-install workflow.
RIDE does not transfer or publish Sysinternals, and license concerns must not
block its package migration. Keep the ten exact versions Reviewed; Defender
alerts remain separate technical/security exclusions. No extra license gate
applies.

On 2026-10-24 at 15:05 UTC, the user corrected the rationale again: the prior
RIDE v2 specialist approval governs the ordinary direct-download-and-install
workflow, and generalized redistribution analysis is not a valid migration
gate for RIDE. Sysinternals package migration may proceed without another
license review. Defender-detected tools remain excluded for security reasons
only; technical lifecycle and Windows acceptance remain separate. See the
[latest decision evidence](archive/evidence/sysinternals-practical-license-administration-reaffirmation-2026-10-24-1505.json).

## CCleaner family owner-specific review

The publisher's current EULA identifies CCleaner Free as a Consumer Solution for
personal, noncommercial use and restricts resale/further distribution. The
publisher's builds page also labels advanced builds as not for distribution or
mirroring. Those distribution terms do not automatically block RIDE's direct
publisher-download/install migration. Record the exact version and owner as
`NeedsReview` when a catalog package identity exists; this is informational for
license administration, not a blanket package-planning gate. Resolve exact bytes,
archive contents, and applicable use terms for the selected device context before
runtime acceptance. The current source and version recheck is recorded in the
[dated evidence](archive/evidence/ccleaner-family-source-recheck-2026-10-24-0316.json).

## Sysinternals approval reaffirmed, 2026-10-24 04:05 UTC

The user reiterated that the prior RIDE v2 license-specialist review approved
Sysinternals and that RIDE's direct-download-and-install workflow has no legal
issues: RIDE downloads from Microsoft and installs on supported devices; it does
not transfer or publish Sysinternals. This specialist approval and user direction
settle licensing for this migration. Do not apply generalized redistribution
analysis as a package-migration gate or require another license review. Defender-
detected tools remain excluded on the separate security disposition; technical
lifecycle, recovery and Windows target acceptance remain separate work. See the
[dated decision record](archive/evidence/sysinternals-approval-reaffirmation-2026-10-24-0405.json).

## Sysinternals migration scope reaffirmed, 2026-10-24 04:19 UTC

The user reiterates that the prior RIDE v2 license-specialist assessment approved
Sysinternals for RIDE. RIDE is a direct download-and-install tool in this workflow;
it does not transfer or publish Sysinternals. Treat that specialist approval and
the user's determination that there are no legal issues as settled for package
migration. Do not impose redistribution-based license gates or require another
license review. Defender exclusions remain a separate security disposition. See
the [current decision record](archive/evidence/sysinternals-approval-reaffirmation-2026-10-24-0419.json).

On 2026-10-24 at 04:44 UTC, the user corrected the rationale again: generalized
redistribution analysis is not a practical or valid blocker for RIDE's direct
download-and-install package migration. The prior v2 specialist review approved
the tool, RIDE does not transfer or publish it, and the user states there are no
legal issues. Licensing is settled with no additional review or distribution
gate. Defender detections remain separately excluded. See the [latest decision
and acceptance status](archive/evidence/sysinternals-approval-reaffirmation-2026-10-24-0444.json).

On 2026-10-24 at 05:42 UTC, the user again directed that the prior RIDE v2
license-specialist approval is the practical and settled administration decision
for Sysinternals in RIDE's direct download-and-install workflow. Do not impose
additional license review or redistribution-based migration gates. The four
reported Defender-detected file groups remain separate security exclusions; they
do not create a Sysinternals license blocker.
The 2026-10-24 05:52 UTC migration run kept the user's Sysinternals disposition in force: the prior RIDE v2 specialist approval settles direct download/install, so no license review or redistribution gate blocks that package migration. Defender detections remain separate security exclusions.

## Sysinternals license rationale corrected, 2026-10-24 08:17 UTC

The user corrected the migration rationale again: it is too strict and not
grounded in practical license administration to treat the Sysinternals Suite as
requiring a new migration-time license review or to infer a blocker from general
redistribution analysis. The prior RIDE v2 license-specialist assessment approved
Sysinternals for RIDE's direct download-and-install workflow. RIDE downloads the
tools from Microsoft for installation on user-supported devices and does not
transfer or publish Sysinternals copies. The user's decision is that there are no
legal issues using Sysinternals in RIDE. This is settled for the existing scope;
do not reopen licensing or block package migration on that basis. Defender-alerted
tools remain separately excluded for security reasons. Remaining work is technical
package and Windows acceptance. See the [dated decision evidence](archive/evidence/sysinternals-license-rationale-correction-2026-10-24-0817.json).
On 2026-10-24 at 17:48 UTC, the user reaffirmed the RIDE v2 license-specialist
approval for RIDE's direct Microsoft download-and-install workflow. RIDE does not
transfer or publish Sysinternals copies, and the user states there are no legal
issues using Sysinternals in RIDE. No new review or redistribution gate applies
to package migration. Keep Defender-detected utilities excluded separately; the
remaining acceptance blockers are technical. See the [decision evidence](archive/evidence/sysinternals-direct-download-install-approval-reaffirmed-2026-10-24-1748.json).