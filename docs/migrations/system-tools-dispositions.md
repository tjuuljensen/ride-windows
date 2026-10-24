# System Tools selector reconciliation

Source inventory reviewed 2026-10-09; dispositions updated 2026-10-24. The System Tools family contains 25 legacy selectors.
Some selectors have v3 catalog candidates or implemented operations. A listed
selector is not considered migrated until it has an explicit disposition,
source/artifact contract, and tested lifecycle. Do not run legacy installers as
part of this review.

| Legacy selector(s) | Current v3 disposition | Source behavior and remaining work |
| --- | --- | --- |
| `GetSysinternalsSuite`, `RemoveSysinternalsSuite` | Partially migrated: fixed Sysinternals Suite snapshot and nine independent products are implemented as candidates | The v2 selector downloaded Microsoft's mutable `SysinternalsSuite.zip`, copied it into a shared tools root, and removed that whole directory. V3 now has a pinned official snapshot and independently owned product candidates, with exact file ownership and recovery. The prior RIDE v2 license-specialist approval covers RIDE's direct download-and-install workflow; licensing is not a migration blocker. Remaining work is technical lifecycle/target acceptance and any additional legacy product grouping. Do not add automatic Defender exclusions or tool execution to staging. |
| `InstallJoeWare`, `RemoveJoeWare` | User selected the complete official collection, including AdFind, on 2026-10-23; dedicated package-directory Defender exclusion authorized | Replace the broad crawler with bounded per-product acquisition that resolves the latest publisher-offered version at download time. Preserve each observed source version and downloaded archive identity. The accepted `rdp-sec-check` page/version-list difference is documented in [JoeWare version discrepancies](../joeware-version-discrepancies.md); do not map the old `V01.00.00` digests to current `V02.00.00` bytes. Add a short description note for any page/archive mismatch found on acquisition. Exact payload and archive contents remain uninspected. AdFind remains excluded from selected batches because the publisher reports Defender blocking; this is not a threat classification or false-positive finding. Scope the authorized exclusion to the dedicated JoeWare install directory only. Defer individual-file exclusions to v3.1; do not exclude `ToolsDirectory`, `C:\Tools`, Downloads, or add per-file allow actions. Preserve and restore only the exact exclusion changed by the RIDE run. [Decision](decision-session-2026-10-17.md#package-and-profile-scope-decisions-2026-10-23); [JoeWare report](https://blog.joeware.net/2023/02/22/6166/); [current-source evidence](../archive/evidence/joeware-current-source-review-2026-10-24-0408.json) |
| `InstallCCleaner`, `RemoveCCleaner` | User selected installed/full and portable distributions for all four products on 2026-10-23 | Keep CCleaner, Defraggler, Recuva and Speccy independently selectable. Offer each publisher-verified portable distribution where available and report unavailable variants without substituting another distribution. Exact editions, artifacts, ownership and removal/recovery behavior remain to be reviewed. [Decision](decision-session-2026-10-17.md#package-and-profile-scope-decisions-2026-10-23). |
| `InstallMitec`, `RemoveMitec` | Deferred: dynamic collection | Scrapes the MiTeC site and follows multiple product pages before downloading tool archives into one shared directory. Select and pin intended tools; do not infer presence or remove ownership from a directory name alone. |
| `InstallNtcore`, `RemoveNTCore` | Deferred: dynamic collection; alert status unknown | Crawls NTCore tool pages and downloads multiple EXE/ZIP files into one shared directory. No source-confirmed Defender alert was identified in this review. Enumerate exact intended artifacts and check their publisher evidence before migration. |
| `InstallTMOG`, `RemoveTMOG` | Pinned Windows x64 free-edition package candidate; license status is informational `NeedsReview` | `package.tmog` pins official marketing version 1.0.1 (contained product version 1.0.1.0), matches the publisher release SHA-256, and verifies the publisher signature. The embedded license's personal-use scope and release-candidate notice are recorded for owner review and do not block direct-download/install planning. Installation, repeat, uninstallation, exact recovery and screensaver effects remain unaccepted on Windows 11; no supported target is declared. No PRO activation or screensaver selection is part of the package. See [candidate evidence](../archive/evidence/tmog-package-candidate-2026-10-24-0345.json) and [operator guidance](../application-packages.md#task-manager-tmog-free-edition-candidate). |
| `InstallWireshark`, `RemoveWireshark` | Deferred: installer/dependency lifecycle | Selects the first current 64-bit non-portable EXE from the download page. Define deterministic version/architecture resolution, signature checks, optional Npcap behavior, and removal/recovery semantics. |
| `InstallZimmermanTools`, `RemoveZimmermanTools` | Deferred: mutable executable bootstrap; alert status is artifact-specific | Downloads `Get-ZimmermanTools.ps1` from a mutable GitHub `master` URL and executes it, producing a changing forensic-tool collection. The publisher says tools are signed and antivirus hits are false positives after signature verification. Pin and verify the bootstrap script and record/verify each resulting artifact before execution or exception decisions. [Official publisher guidance](https://ericzimmerman.github.io/) |
| `InstallNirsoftLauncher`, `RemoveNirsoftLauncher` | Authorized v3 whole-collection package preparation; individual file handling deferred to v3.1 | Use the frozen collection source and current non-restrictive package rules. User-reported Defender alerts name `NirSoft/chromecookiesview.exe` and `NirSoft/bulletspassview.exe`; keep those members out of selected file-level review/acceptance batches pending the user's manual review. Do not restore/re-extract quarantined files, add per-file exclusions or allow actions. The 2026-10-24 decision permits a reviewed exclusion only for the selected package's RIDE-managed install directory, with exact prior-state capture and removal only of RIDE-added state; it still rejects the separate v2.x broad `C:\Tools` Defender exclusion. Safe archive lifecycle and target acceptance remain pending. [package exclusion lifecycle](decision-session-2026-10-17.md#package-scoped-defender-exclusions-and-deferred-yarasysmon-work-2026-10-24); [Frozen alert evidence](../archive/evidence/collection-continuation-blockers-2026-10-17.json); [NirSoft antivirus report](https://www.nirsoft.net/false_positive_report.html) |
| `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64` | Authorized v3 whole-collection package preparation; individual file handling deferred to v3.1 | Use the frozen collection source and current non-restrictive package rules. User-reported Defender alerts name `ProduKey.exe` and `WirelessKeyView.exe`; keep those members out of selected file-level review/acceptance batches pending the user's manual review. Do not restore/re-extract quarantined files, add per-file exclusions or allow actions. The 2026-10-24 decision permits a reviewed exclusion only for the selected package's RIDE-managed install directory, with exact prior-state capture and removal only of RIDE-added state; it still rejects the separate v2.x broad `C:\Tools` Defender exclusion. Safe archive lifecycle and target acceptance remain pending. [package exclusion lifecycle](decision-session-2026-10-17.md#package-scoped-defender-exclusions-and-deferred-yarasysmon-work-2026-10-24); [Frozen alert evidence](../archive/evidence/collection-continuation-blockers-2026-10-17.json); [NirSoft antivirus report](https://www.nirsoft.net/false_positive_report.html) |
| `InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles` | Deferred: launcher metadata and collection coupling | Downloads `.nlp` launcher package files and adds a repository-supplied Zimmerman language file. This is launcher configuration, not an independently installed software package; define its ownership and relationship to the launcher and bundled tools. |
| `InstallArsenalRecon` | v3 scope: individually selectable Arsenal publisher products with a free-use scenario; licensed-only products excluded | The original eight-product collection remains accepted; the 2026-10-24 decision expands v3 review to all publisher products for which the publisher offers a free-use scenario, including products that also have paid editions. Verify current product/version terms and exact artifacts per member. The legacy selector installs MEGAcmd and crawls every MEGA link; neither behavior is retained implicitly. Arsenal documents antivirus exclusions and a possible `utilman.exe` alert for Arsenal Image Mounter's VM features. Review driver, AV and recovery behavior per product. [AIM walkthrough](https://arsenalrecon.com/arsenal-image-mounter-aim-walkthrough) |
| `InstallWinget` | Deferred: Windows capability and dependency provisioning | Downloads an App Installer MSIX bundle plus VCLibs and WinUI dependencies, then registers packages. Determine supported Windows baselines and use the documented Windows package servicing model rather than ordinary EXE installer semantics. |
| `InstallWingetAutoUpdate` | Deferred: scheduled task/service behavior | Downloads the latest WAU ZIP from GitHub and runs its setup flow. Review task/service creation, update policy, persistence, and exact uninstall/restore behavior separately from WinGet itself. |

## Implementation constraints

- Package operations currently support EXE and MSI installers plus a dedicated
  Sysmon ZIP path. A portable collection needs managed-file installation,
  presence detection, version reporting, safe removal and exact rollback.
- The default workstation profile currently adds a broad Tools-directory
  Defender exclusion. That exclusion must not be mistaken for package-level
  alert evidence; a controlled alert scan must run with that exclusion absent
  from the disposable VM, inspect effective Defender exclusions, and scan exact
  versioned files without executing the tools.
- The user's 2026-10-24 decision authorizes reviewed, package/version-specific
  Defender exclusions only for selected NirSoft packages' RIDE-managed install
  directories, with exact prior-state capture and removal only of exclusions
  RIDE introduced. Do not exclude the shared `ToolsDirectory`, `C:\Tools`,
  Downloads or individual files. Per-file handling remains deferred to v3.1;
  known alerts require manual review. Do not restore/re-extract quarantined files
  or add allow actions. See the [decision ledger](decision-session-2026-10-17.md#package-scoped-defender-exclusions-and-deferred-yarasysmon-work-2026-10-24).
- No System Tools package was downloaded, executed or scanned for this
  reconciliation. The parallel AutomatedLab runbook test was not touched.

Application reconciliation, 2026-10-11: the managed portable lifecycle is now
available. Remaining System Tools outcomes still need their declared
product/source, collection, component, driver or policy evidence. The consolidated
[application ledger](application-migration-review.md) assigns these to the two
batches and counts CCleaner, Defraggler, Recuva and Speccy separately, together
with the omitted MEGAcmd helper from Arsenal Recon. No collection, licensed
product or Defender exclusion was silently admitted.

User decision, 2026-10-22: do not carry the legacy broad `C:\Tools` Defender
exclusion forward. The v3 whole-collection NirSoft preparation remains authorized;
individual file handling remains deferred to v3.1, and any file alerts require
manual user review. No Defender setting or allow action is authorized for NirSoft.


User decision, 2026-10-24: the user approved reviewed, package/version-specific
Defender exclusions only for selected packages' RIDE-managed install directories.
Capture exact prior-path membership and remove only exclusions introduced by RIDE.
Do not exclude shared roots, Downloads or individual files; NirSoft file-level
handling remains deferred to v3.1, and known alerts remain subject to manual
review. The broad v2.x `C:\Tools` exclusion remains rejected. See the [decision
ledger](decision-session-2026-10-17.md#package-scoped-defender-exclusions-and-deferred-yarasysmon-work-2026-10-24).

User decision, 2026-10-23: the complete JoeWare collection, including AdFind, is
selected. A Defender exclusion is authorized only for JoeWare's dedicated package
install directory, with individual-file exclusions deferred to v3.1. This is a
package-specific exception and does not restore the broad `C:\Tools` exclusion.

User decision, 2026-10-24: Zimmerman is the next collection for focused product
review. Its accepted 26-member inventory is unchanged; source/helper and artifact
provenance work remains. The Arsenal collection now covers all publisher products
with a free-use scenario, with licensed-only products excluded. This adds product
review scope but does not authorize MEGAcmd, drivers, AV exclusions or forensic
execution.

User decision, 2026-10-24: JoeWare is now the next family for focused product
review, superseding the Zimmerman review priority for ordering only. The existing
41-name JoeWare collection scope is unchanged. Refresh exact publisher versions
and artifact identities, including the recorded `rdp-sec-check` discrepancy.
Keep any Defender-blocked JoeWare binary an explicit acceptance blocker; a
collection selection or exclusion record does not establish that binary's
acceptance. This priority does not authorize acquisition, installation, tool
execution or a VM run.

User clarification, 2026-10-24: individual NirSoft file assessment is postponed
to v3.1 and is not part of v3. The earlier references above to manual review
describe the later v3.1 gate. The four reported alert files remain unclassified;
this clarification does not alter the authorized v3 whole-collection package
work or package-directory Defender exclusion rules. Windows VM acceptance stays
a separate technical gate.
