# Custom RIDE library disposition review

Reviewed 2026-10-09 against the working trees of `custom-ride` and RIDE-Windows.
This is an evaluation and migration backlog, not package approval or runtime
acceptance. Product availability, a current download, and proven compatibility
are separate findings. An old release date alone does not establish obsolescence.

## Scope and evidence

Reviewed `lib-custom.psm1`, `custom-ride.preset`, `custom-ride.cmd`, README,
`.gitmodules`, supporting PowerShell scripts, BitLocker notes, bootstrap file
inventory and font attribution/license. Inspected the module through the
PowerShell AST without importing or executing it. ISL function bodies were
excluded from the function walkthrough; ISL receives no migration assessment.
The prohibited `custom-config.ini` was never opened, parsed, searched or copied.
No real serial numbers were used in this review.

The module defines 21 functions: 19 reviewed and two ISL exclusions. Every
selector in the custom preset is commented out; its presence is not evidence of
an active default. The `ride` directory is empty in this checkout, while
`.gitmodules` points to the upstream RIDE repository. Re-evaluating a second
upstream library is unnecessary; the current RIDE catalog and migration ledgers
are the overlap reference.

Bootstrap EXE/MSI/ZIP files were inventoried, not executed or validated as
authentic/current binaries. Desktop PDFs and the XLSX were inventoried by name;
their contents were not audited for technical accuracy or redistribution rights.
Two named PDF copies were hashed to confirm an exact duplicate. No analyst
assets or vendor payloads were copied into RIDE. Local inspection used native
Windows PowerShell on a Windows filesystem checkout.

## Overall implementation assessment

Retain useful capabilities and source attribution, rewrite their integration
through focused handlers. The custom module depends on the legacy runner's
process environment, exports every function, and has no declared operation
metadata, state records, installed-version inspection, ShouldProcess preview,
exact recovery or reliable partial-failure reporting. Most commands use a
drive-relative `\Tools` fallback and delete whole product directories, potentially
including user data. They do not satisfy the current RIDE lifecycle contract.

Specific static defects:

- `InstallMagnetDumpIt`, `InstallMagnetProcessCapture` and
  `InstallEncryptedDiskDetector` assign `$FileName` but construct the local path
  with unassigned `$LocalFileName`. Module-scope leakage could mask this defect.
- `GetRawCopy` performs target-directory flattening even in download-only mode,
  when the target variable may be unset. Its recursive move can also flatten
  unrelated levels and collide with file names. `GetEtl2pcapng` has the same
  out-of-branch target inspection; its lack of ZIP extraction happens to suit
  today's EXE, but is not a declared distribution contract.
- GitHub download functions take all `assets.browser_download_url` values,
  without exact file/architecture selection, digest/signature verification or
  fail-closed release validation. RawCopy's latest-release selection is wrong
  for modern Windows, as detailed below.
- FTK installation selects the first local EXE and uses `/S /v/qb /i` without
  checking the process exit code or installed state. The old argument string is
  not evidence for the current installer. Its download-only mode stages local
  files; it is not an acquisition resolver.
- `CopyFTKImagerInstall` uses wildcard-style `^*...*` as a regular expression
  rather than a bounded product-name match, reverses
  the conventional 32/64-bit uninstall-view labels, and copies assorted MFC/VC
  DLLs from the workstation. That is neither a reproducible portable package
  nor a verified dependency/redistribution contract.
- `SetCustomWallpapers` and `SetCustomLockScreen` check for their intended
  helpers but actually call `InstallFonts`. The corresponding wallpaper,
  lock-screen and pictures source directories are absent in this checkout.
- Recursive desktop/pictures copying has no ownership manifest, collision
  policy or recovery. Running under elevation may also select the wrong user's
  folders. Fonts and backgrounds depend on undeclared upstream functions.

PowerShell parsing succeeded for the module and the supporting script files,
including the `.ps1.win7`/`.ps1.win10` snapshots. This verifies syntax only;
none of these operational paths was run on the workstation.

## Module functions and bootstrap artifacts

Rows pair install/remove functions where they control the same product. Pending
package names are concepts, not newly published catalog IDs.

| Exact function(s) / component | Currency and disposition | Required migration or reason |
| --- | --- | --- |
| `GetRawCopy`, `RemoveRawCopy` | Conditional specialist tool; obsolete acquisition selection | The official [latest release](https://github.com/jschicht/RawCopy/releases) is 1.0.0.19, published 2017-08-01, explicitly for Windows 2000/NTFS 3.0. The [repository](https://github.com/jschicht/RawCopy) also contains modern binary files. Never use `releases/latest` for this product. Review an immutable revision, x64 member, license and modern-NTFS compatibility before managed deployment. Do not automatically run raw extraction. |
| `GetEtl2pcapng`, `RemoveEtl2pcapng` | Retain optional portable candidate | Microsoft's [release](https://github.com/microsoft/etl2pcapng/releases/tag/v1.11.0) is v1.11.0 (2023-10-25), with standalone `etl2pcapng.exe`. The [project](https://github.com/microsoft/etl2pcapng) documents additional conversion features over built-in pktmon. Use the built-in [pktmon conversion](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-pcapng-support) when adequate; retain this tool for its distinct supported ETL workflow. |
| `GetISL`, `RemoveISL` | Excluded immediately | User-directed exclusion. Do not migrate or investigate its private endpoint. |
| `InstallLocalFTKImager`; `bootstrap/FTKimager` | Retain product; replace stored 4.7.1 distribution | Current public vendor release is 8.3.0.27. Use the official release-page route below. Old installer, guide and release notes are historical artifacts, not RIDE payloads. Verify current install/uninstall and driver behavior in a VM. |
| `CopyFTKImagerInstall` | Discard implementation | Unreliable matching, copying installed files and broad system-DLL harvesting do not establish a portable lifecycle. A separately verified vendor-supported portable workflow may be considered later. |
| `InstallMagnetDumpIt`, `RemoveMagnetDumpIt`; `Comae-Toolkit-v20230117.zip` | Retain capability; refresh acquisition | [Magnet DumpIt for Windows](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/) is currently offered for x86, x64 and ARM64. The local 2023 toolkit name does not establish current version or trust. Vendor acquisition requires a form/email workflow; use a verified supplied artifact or approved private cache, with distribution rights recorded. |
| `InstallMagnetProcessCapture`, `RemoveMagnetProcessCapture`; `MagnetProcessCaptureV13.zip` | Conditional optional tool; not proven obsolete | The [publisher page](https://www.magnetforensics.com/resources/magnet-process-capture/) still lists version 1.3 (2020-01-15). The local name matches that series, but byte identity and modern Windows compatibility are unverified. Keep distinct from whole-memory capture; fix acquisition/path ownership through shared handlers. |
| `InstallMagnetRAMCapture`, `RemoveMagnetRAMCapture`; `MRCv120.exe` | Conditional fallback; old but still offered | The [publisher page](https://www.magnetforensics.com/resources/magnet-ram-capture/) lists v1.20 (2019-07-24) and old OS declarations. Do not infer Windows 11/Server 2025 support from availability. Prefer current DumpIt evaluation and require driver/VBS/HVCI coverage for any offered alternative. |
| `InstallEncryptedDiskDetector`, `RemoveEncryptedDiskDetector`; `EDDv310.zip` | Hold, not declared obsolete | [Magnet's earlier product explanation](https://www.magnetforensics.com/blog/free-digital-forensics-tools-every-investigator-needs/) documents the use case, but a current working dedicated download/version was not established. BitLocker inspection covers only part of the purpose, not all third-party encryption detection. Reconcile official access and current supported detection before admission. |
| `bootstrap/USBDetective/USB Detective.zip` | Candidate, no module function | [USB Detective](https://usbdetective.com/) still offers Community and Professional editions. The ZIP filename reveals neither edition nor version. Review license/access, current version and managed deployment; secrets/serials remain external. |
| `PutFilesOnDesktop`; `components/desktop` | Useful SOC capability; outside RIDE | Private content selection and current-user distribution belong to SOC/content management. All 29 files remain external; see inventory and ownership proposal below. |
| `PutPicsInMyPictures` | Exclude present implementation; external if needed | No pictures payload exists here. Use the same external managed-content workflow if later required, rather than a blanket copy into a user's directory. |
| `InstallCustomFonts`; Open Sauce Sans TTF tree | Reuse generic RIDE font work; external assets | Existing Customization family already plans `InstallFonts`. The local tree has an SIL OFL 1.1 license and attribution. Keep assets/licensing with organization branding or SOC releases and skip `.DS_Store`; add font presence, scope, ownership and removal tests to any generic handler. No new custom installer. |
| `SetCustomWallpapers`, `SetCustomLockScreen` | Discard broken wrappers; reuse existing family | Both invoke fonts instead of the named action. Background/lock-screen handlers are already migration items; supply organization assets externally, declare edition/policy support and exact prior settings recovery. |
| `bootstrap/CheckPointVPN/E86.80_CheckPointVPN.msi` and `sample_script_code_UNTESTED.ps` | Replace old artifact; discard sample | Current [E89.x vendor release notes](https://sc1.checkpoint.com/documents/E89.x/EN/Remote_Access_VPN_Clients_for_Windows_RN/Content/Topics-Remote_Access_VPN_Clients_for_Windows_RN/Remote-Access-Client-Upgrades.htm) show later clients required for Windows 11 24H2. Do not default to E86.80. Sample constructs SQLiteBrowser/GitHub URLs with undefined variables, not a VPN resolver. Tenant gateway settings and approved deployment belong to organization IT; a future generic package needs gateway/client compatibility and driver/reboot tests. |

Free product availability does not automatically authorize redistribution of
the stored installers. Preserve applicable publisher terms and adapted-code
attribution; the custom repository's MIT license is not a blanket license for
third-party products or reference PDFs.

## FTK Imager: public acquisition route found

The product marketing page's Download button still leads to a registration
form. A better discovery entry is the public
[Exterro FTK Downloads Library](https://www.exterro.com/ftk-downloads), which links
to the [FTK Imager 8.3 release page](https://www.exterro.com/ftk-downloads/ftk-imager-8-3).
That page exposes an Installer link directly to:

[FTK Imager 8.3.0.27 ZIP](https://d1kpmuwb7gvu1i.cloudfront.net/8.3/Imager/FTK%20Imager%208.3.0.27.zip)

Unauthenticated native HTTP HEAD on 2026-10-09 returned **200**,
`Content-Type: application/octet-stream` and `Content-Length: 405808295`.
The URL was extracted from the live vendor page, not guessed from a filename.
No registration, email submission or account was used. This establishes a
publicly discoverable source today, not guaranteed permanent CDN availability.

The linked [August 2026 release notes](https://d1kpmuwb7gvu1i.cloudfront.net/8.x/8.3.0/Exterro%20FTK%20Imager%208.3%20-%20Release%20Notes.pdf)
describe a malicious-UFDR-XML exfiltration fix and replacement/cleanup of an old
driver. Refreshing the old distribution is therefore substantive maintenance;
these notes do not prove which earlier version introduced each issue.

Recommended resolver contract:

1. Find the free Imager product entry in the official downloads library; follow
   its release page. Match the product exactly so FTK Suite/Imager Pro cannot
   be selected accidentally. Require one unambiguous expected installer link.
2. Validate HTTPS and the approved vendor/CDN source, record the resolved
   product/version, release page and artifact URL, and download once into the
   external package cache. Retain a supplied-artifact fallback for genuine
   source unavailability; never fall back after an integrity failure.
3. Inspect ZIP members safely and select the actual installer. Record archive
   and executable SHA-256, Authenticode evidence, publisher and version. A CDN
   multipart ETag is not a package checksum. Obtain independent publisher
   evidence where available; a locally computed hash alone establishes identity,
   not publisher authenticity.
4. Establish unattended arguments, exit/reboot behavior, installed detection,
   upgrades and uninstall in a disposable Windows VM. Keep recovery limits
   explicit. The release page's OS list is vendor information, not RIDE's
   tested support declaration. Do not run imaging or acquisition during setup.

Only release-page discovery and header reachability were verified here. The
405 MB ZIP was not downloaded, extracted, hashed, signature-checked or installed;
unattended deployment and archive/member layout remain implementation work.
No stable official WinGet package was established; it is unnecessary for the
direct-source approach and must not be invented as a dependency.

## Supporting scripts and documentation

| Source | Assessment | Disposition and follow-up |
| --- | --- | --- |
| `scripts/Set-PowerPlan.ps1`, `Set-PowerPlan2.ps1` | Current powercfg mechanism, fragile wrapper | Overlap with Power Scheme Settings, not the existing lid-close index operations. Regex uses unescaped input and localized scheme names; the second script duplicates a template but activates its original GUID instead of the returned newly created GUID. Reconcile into one operation using GUID discovery, exact prior active GUID, hardware availability, created-scheme ownership and read-only completion. [Microsoft powercfg contract](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options). |
| `scripts/Add-Wifi.ps1` | Current concept; not ready for migration | Overlap with `AddWiFi`. Plaintext PSK in temp XML, no finally cleanup or state capture, unescaped XML, character-based SSID hex instead of explicit byte encoding, all-user import and forced MAC-randomization disablement. Use validated secret input, XML construction, supported authentication choices, safe cleanup and prior-profile recovery; keep actual networks/keys in external secret storage. |
| `scripts/Get-AuditPolSetting.ps1` | Useful read-only collector, language-dependent | Parses localized CSV headings and subcategory names. Keep with LoggingBaseline/SOC reporting; prefer stable subcategory GUIDs and normalized objects. Align with the [proposed configuration-ownership ADR](../DECISIONS/0001-configuration-ownership.md); do not turn it into another policy writer. |
| `scripts/Get-SID.ps1`, `Get-UserFromSID.ps1` | Useful .NET identity helpers; not obsolete | SOC/admin utilities or private runbooks, not desired-state operations. Add parameter validation, unresolved-SID/account errors and help if maintained. No RIDE catalog duplication. |
| `scripts/Set-OutlookFolderPermissions.ps1` | Current Exchange cmdlet, wrong repository boundary | Changes tenant mailbox ACLs, installs/imports a module and connects implicitly. Despite its Set name it only calls [Add-MailboxFolderPermission](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/add-mailboxfolderpermission?view=exchange-ps), so repeat calls are not a set/update lifecycle. Move the use case to organization M365 administration with explicit connection, localized-folder discovery and permission read/update/recovery. |
| `bootstrap/OutlookSignatures/*` | Classic Outlook-era organization customization | ADSI/on-prem AD assumptions, legacy registry paths and ASCII output; no actual parameter/template parser despite header claims. Placeholder logo/group and `$ItStaff`/`$ITMember` mismatch remain. Keep templates in organization content management. Classic and new Outlook require separately verified workflows; use [Microsoft's current signature guidance](https://support.microsoft.com/en-us/office/create-and-add-an-email-signature-in-outlook-8ee5d4f4-68fd-464a-a1c1-0e1c80bb27f2). Do not claim local files/registry provision new Outlook signatures. |
| `docs/Enable-PrebootPIN.ps1` | Retain requirement; discard enrollment implementation | Broad all-volume selection and aggregate protector checks can mistake one volume's state for another; TPM+PIN is an OS-volume workflow. Adding a PIN protector does not remove a TPM-only protector, so PIN-only boot enforcement is not established. Prompt claims six numeric digits without validating them, exposes PIN strings through unmanaged buffers without freeing/zeroing them, lacks escrow checks and has fragile local/mapped-path elevation. Separate policy, OS-volume enrollment and approved recovery; never persist the PIN in RIDE state. [Microsoft protector semantics](https://learn.microsoft.com/en-us/powershell/module/bitlocker/add-bitlockerkeyprotector?view=windowsserver2025-ps). |
| `docs/BitlockerConfiguration.md` | Useful topics, uneven/old recovery advice | Reconcile with the existing BitLocker family. Rewrite recovery around verified AD DS/Entra escrow and an approved recovery runbook, not ad hoc alternate boot media or credentials. Event 789 should be presented as a possible observed event, not a guaranteed complete PIN-change history. Retain current [Microsoft operations guidance](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide). |
| `scripts/archive/Disable-Agents-Step1.ps1`, `Disable-Agents-Step2.ps1` | Discard from RIDE migration | Manual security-agent file/ACL/config deletion and reboot bypass supported removal/recovery. Use vendor/IT-approved agent management separately. Step 2's proxy URL write overlaps the existing `windows.proxy-autoconfig-url`; no second writer or combined agent-removal operation. |
| `AtomicRedTeamNuke/nuke.ps1`, `.ps1.win10`, `.ps1.win7` | Discard broad runner, retain lab concept externally | Executes mutable remote code and schedules nearly every technique elevated using a short denylist; cleanup does not ensure host restoration. Win7 snapshot also uses APIs unavailable there. [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) remains relevant, but SOC purple-team labs need pinned tools, explicit test allowlists, disposable targets/checkpoints and evidence capture. No broad attack execution in a RIDE setup profile. |
| `custom-ride.cmd`, `custom-ride.preset`, `.gitmodules` | Historical runner/composition, obsolete for v3 | Replace selections with declarative profiles referencing existing IDs. Do not reconnect the legacy `-include` engine or embedded RIDE submodule. The duplicate Sysinternals line has no independent capability. |

## README-only candidate reconciliation

These are unchecked intentions, not implemented installers. All proposed tools
are optional; deployment does not authorize automatic execution on evidence.

| Candidate(s) | Current assessment and migration disposition |
| --- | --- |
| [capa](https://github.com/mandiant/capa), [FLOSS](https://github.com/mandiant/flare-floss) | Current upstream projects; already in RIDE's supplemental candidates. Reuse those entries and portable lifecycle work. |
| [Detect It Easy](https://github.com/horsicq/Detect-It-Easy), [x64dbg](https://x64dbg.com/) | Current upstream offerings; add optional static-analysis/debugging candidates with exact release asset selection and architecture. |
| [peStudio](https://www.winitor.com/) | Retain for source/edition/commercial-use licensing review. Current publisher site was reachable, but usable download/licensing detail was not established; not ready for an automated package. |
| [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html), [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) | Still publisher-offered. Overlap with the legacy NirSoft package-list workflow; choose named products and modern browser-format/encryption test fixtures, not a whole suite. Cookie/cache/history support must be checked separately. Do not bypass browser encryption protections or modify source evidence implicitly. |
| HashCalc (Softonic link) | Disregard the third-party download route and default package proposal. Basic file hashing is available through native PowerShell `Get-FileHash`; add a GUI only if a distinct need is established with an official maintained source. No obsolete-version claim based solely on an aggregator. |
| [HxD](https://mh-nexus.de/en/downloads.php?product=Hx) | Publisher still offers installed and portable editions; useful optional hex editor. Choose variant/language and source verification explicitly. |
| [Volatility Workbench](https://www.osforensics.com/tools/volatility-workbench.html) | Current Volatility 3 GUI offering, not obsolete. Related to but distinct from planned Volatility CLI; evaluate packaging, bundled engine/symbol dependencies and offline-dump workflow separately. |
| [Hash Suite Free](https://hashsuite.openwall.net/) | Still offered; niche authorized password-audit candidate, held for edition/license and workflow need. Do not add by default or imply Free equals the Professional edition. |
| [Ophcrack](https://ophcrack.sourceforge.io/download.php?type=ophcrack) | Official download remains 3.8.0; legacy specialist/rainbow-table workflow. Defer from the first analyst bundle until a specific compatible use case justifies it; not evidence that all password auditing is obsolete. |
| [ExifTool](https://exiftool.org/history.html) | Current project with version history; add optional metadata-analysis package. Separate read-only inspection from metadata-writing commands and verify the Windows distribution/dependencies. |
| OfficeMalScanner (`reconstructer.org`) | Defer legacy source; current official download/support was not established. Evaluate [oletools/olevba](https://github.com/decalage2/oletools/wiki/olevba) for modern Office macro triage instead; not a promise of identical capability or a silently substituted installer. |
| [steghide](https://steghide.sourceforge.net/) | Historic Windows distribution; keep out of the first bundle. A format-specific extraction use case may justify a pinned lab tool, not a general current Windows deployment. Review newer maintained distributions separately. |
| [Thumbcache Viewer](https://thumbcacheviewer.github.io/) | Publisher documents Windows 11 and GUI/CLI editions; useful specialist candidate. Select the intended edition and verify modern fixtures; do not equate release age with obsolescence. |
| [SwitchyOmega](https://github.com/FelisCatus/SwitchyOmega) | Upstream explicitly says no longer maintained. Disregard original extension; review a maintained browser-compatible proxy tool only if needed. Organization proxy values remain external. |
| Check Point VPN; Outlook signatures | Already reconciled above; organization IT/content ownership, not duplicate analyst packages. |

Preset overlap also includes 7-Zip (`package.7zip` already implemented), YARA,
Sysinternals Suite, Eric Zimmerman tools, PuTTY and KAPE (existing deferred
families). `GetKAPE`/`GetPutty` names do not imply new implementations of the
existing products. `solution.analyst-basics` currently contains only 7-Zip and
Notepad++; its name does not imply it already delivers this forensic toolkit.

## Items disregarded from the RIDE migration

"Disregarded" here means no direct carryover into RIDE, not deletion from the
custom checkout. Valid external material and held candidates remain recoverable.

| Item | Why / alternative owner |
| --- | --- |
| ISL and its two functions | Explicit user exclusion, immediate and unconditional. |
| `custom-config.ini` | Explicitly prohibited review; contains real serial numbers. Secret/configuration storage outside source and release bundles. |
| Whole `lib-custom.psm1` and legacy CMD/preset/submodule runner | Obsolete integration contract; migrate metadata/capabilities through v3 rather than import old functions. |
| FTK 4.7.1 payload/docs and copied installed-tree/MFC workaround | Superseded acquisition source and unverifiable portable/dependency packaging; external cache for separately verified approved artifacts. |
| RawCopy latest-release strategy | Selects Windows 2000-only build; conditional product candidate needs a different source adapter. |
| Unverified local Magnet/EDD/USB/VPN binaries as release payloads | Local filenames are not trustworthy current package evidence; rights and verification belong to controlled acquisition/cache. Products have individual dispositions above. |
| Check Point sample script | Wrong upstream URLs/undefined variables; replace source design if organization IT requests a maintained package. |
| Custom wallpaper/lock-screen wrappers; absent pictures payload | Broken copy/paste code and no assets; reuse generic handlers with external content. |
| Analyst desktop PDFs/XLSX, broad copy-to-desktop function | Analyst-only material; private SOC/content ownership and managed current-user distribution. |
| Audit/SID helpers and tenant mailbox writers | Reporting/admin workflows, not workstation desired-state operations; LoggingBaseline/SOC/M365 owner. |
| Organization Outlook signature templates and old generator | Organization identity/branding plus client-specific provisioning; maintain externally. |
| Current PIN-enrollment implementation | Incorrect volume/protector reasoning, secret handling and recovery gaps; retain properly scoped BitLocker requirement only. |
| Archived agent-removal scripts | Unsupported destructive bypass and no recovery contract; vendor/organization IT process. |
| Atomic nuke runner and Win7/Win10 snapshots | Broad elevated test scheduling and mutable remote execution; replace with explicit SOC lab scenarios. |
| Original SwitchyOmega, HashCalc aggregator download | Unmaintained extension; unnecessary/unverified third-party hashing installer route. |
| OfficeMalScanner, steghide and Ophcrack in first bundle | Legacy/unverified or narrow specialist fit; held for explicit needs, not blanket product deletion. |
| Duplicate Sysinternals selector; duplicate PowerShell PDF; `.DS_Store` | No independent capability/content; deduplicate external releases and ignore OS metadata. |

## Analyst content ownership recommendation

Use a **private SOC repository for manifests, runbooks, reviewed scripts and
role selections**, with an **access-controlled document/artifact store for
content and binaries**. Keep RIDE responsible for generic host configuration
and tested public package metadata. SOC references stable RIDE operation IDs
for setup; it owns analyst resources, toolkit usage and lab scenarios. This is
a proposal, not a newly created SOC repository or storage integration.

Do not make SOC a second Windows configuration engine. The external content
publisher can manage its own files; it should delegate Windows policy/package
changes to RIDE's supported interfaces. Arbitrary external catalogs and composed
profiles are not currently an established RIDE extension contract.

Recommended content contract:

- Per asset: stable content ID, owner, title, publisher/source URI, revision,
  acquired/reviewed dates, SHA-256, access classification, distribution terms,
  expiry/review point and supersedes relationship. Version the manifest schema.
  Acquire gated assets through the authorized publisher workflow, not form
  automation or third-party mirrors.
- Prefer a current-user `Documents\SOC` library plus one optional Desktop
  shortcut. Resolve actual Windows known folders, including redirected/OneDrive
  paths. Offer a Desktop folder only as an explicit SOC preference.
- An opt-in publisher previews manifest changes, validates hashes/paths, avoids
  junction/path escapes, refuses to overwrite modified or user-created files,
  records owned files and removes only those files. Capture prior owned content
  or declare compensating restore. Tests use temporary folders/disposable VMs.
- Store case-filled trackers, personal data, licenses, recovery keys and other
  secrets outside Git and generic reference bundles. Separate a clean incident
  tracker template from real case records. Analyst-only access is enforced by
  storage/repository permissions and group assignment, not a folder name.

| Alternative | When it fits / tradeoff |
| --- | --- |
| Private SOC repository + controlled storage (recommended) | Separates reviewable automation from large/gated material, supports analyst ACLs and avoids binary Git history. Use existing storage, for example a protected document library, authenticated artifact service or managed share. |
| Private `analyst-resources` repository with Git LFS | Small team/offline versioned bundle where redistribution rights and repository ACLs are clear. Still has binary-history, quota and access-revocation costs; no secrets or real case files. Can later become a SOC component. |
| Organization document portal / endpoint content delivery | Best where IT already owns analyst group assignment and distribution. SOC can maintain the manifest/index; distribution requires an agreed current-user and ownership policy. |
| SOC link index without local payloads | Lowest maintenance and redistribution burden; weaker offline availability and less reproducible references. Suitable default for materials without clear redistribution permission. |

### External desktop inventory

All 29 existing files are excluded from RIDE payloads: 13 Cheat Sheets, 15 SANS
Posters and one DFIR workbook. The list below accounts for each filename; numeric
names have unresolved titles/revisions and need SOC metadata review. Older
2021/2022 names need content review against the publisher's
[current resource index](https://www.sans.org/posters), not automatic deletion
based on age. No claim is made that every old poster has a newer equivalent.

| External folder | Files |
| --- | --- |
| `Cheat Sheets` | `280.pdf`; `325.pdf`; `355.pdf`; `370.pdf`; `375.pdf`; `430.pdf`; `GoogleCheatSheet.pdf`; `RDP_DFIR.pdf`; `SANS SOC 2 Cheatsheet.pdf`; `SANS_DFIR_Cheat_Sheet_Booklet_v2.pdf`; `SANS_PowerShell-Enterprise-Cloud-Compliance-Cheatsheet-v1.0.2.pdf`; `SANS_PowerShell-Enterprise-Cloud-Compliance-Cheatsheet-v1.0.2-1.pdf`; `SANS_Tips_for_Reverse-Engineering_Malicious_Code.pdf` |
| `SANS Posters` | `130.pdf`; `145.pdf`; `150.pdf`; `165.pdf`; `195.pdf`; `65.pdf`; `70.pdf`; `CIS_Controls_v8_v1.3-0522.pdf`; `Digital-Poster_Purple-Team_Tools.pdf`; `SANS_CSPS_SEC540_v2.1_0422.pdf`; `SANS_DFIR_FOR509_Cloud_Forensics_Poster_v2.pdf`; `SANS_LDR_CISO_CSMM_v1.2_0922_WEB.pdf`; `SANS_Windows Third Party Forensics Poster-v1.1_11-21_WEB.pdf`; `SANS-DFPS_FOR500_v4.14_12-22.pdf`; `SOC Digital Poster_210915.pdf` |
| `DFIR` | `CrowdStrike-Incident-Response-Tracker-Template.xlsx` |

The two PowerShell cheat-sheet filenames have the same SHA-256:
`6122EBF1F07ECA91CE2877F6F7247E420A6312A9CC77588245CF7E7C49EA9408`.
Keep one canonical copy in the future external manifest. The workbook was not
opened; confirm it is a clean template before publishing it to analysts.

## Validation and next implementation gates

This review adds documentation only. Static parsing established source syntax;
live vendor pages and native public release metadata established the acquisition
findings. FTK's unauthenticated HEAD established reachability only. The ledger
was reconciled against every module function and desktop filename, with local
Markdown links and whitespace checked. No installer, handler, registry writer,
tenant operation, capture or Atomic test was executed.

Implementation order and the RIDE integration gates are in the
[migration plan](../MIGRATION-PLAN.md#custom-library-review-2026-10-09). Require
mocked lifecycle/source/ownership tests and disposable Windows integration
before catalog admission. VM tests must cover affected Windows 11 and declared
Server targets; driver-based tools also need representative VBS/HVCI/hardware
coverage. This review does not broaden any supported target.
