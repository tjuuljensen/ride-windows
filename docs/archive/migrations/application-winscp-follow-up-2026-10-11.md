# WinSCP migration and installed-application preparation

Archived run evidence. Counts, support and remaining-work statements below are
as recorded on the report date. Use the [current migration plan](../../MIGRATION-PLAN.md)
and [active application ledger](../../migrations/application-migration-review.md)
for current disposition; archiving does not close pending acceptance.


Reviewed 2026-10-11. This continuation preserves the exact legacy portable
WinSCP outcome while conventional installed candidates await individual choices
or dependency/license work. Published IDs, existing profiles and unrelated local
changes are preserved. No application is added to a recommended profile.

## Accepted WinSCP migration

`InstallWinSCP` / `RemoveWinSCP` map to one optional `package.winscp`, with the
`portable` variant. Deploy the complete official 6.5.7 ZIP beneath the configured
machine `ToolsDirectory`. The archive contains `WinSCP.exe`, `WinSCP.com`,
`license.txt` and `readme.txt`. Both binaries are x86, version 6.5.7.0, with valid
Martin Prikryl Authenticode signatures. The publisher's
[requirements](https://winscp.net/eng/docs/requirements) confirm its primary
release is 32-bit and works on x64 Windows; its 64-bit alternative is experimental.
Retaining the stable legacy distribution is the explicit architecture exception.
No experimental x64 substitution or Windows regional/language setting is made.
The exact legacy function selects a non-beta portable archive and does not read
regional or application-language variables. Its configured Tools-folder intent
is retained through v3 local configuration. The former recursive product-folder
replacement/removal becomes manifest ownership: unowned sessions are preserved,
and an existing unmanaged distribution is refused as a collision instead of
being erased or adopted silently.

The earlier SourceForge/wrapper attempts returned HTML. A focused shared
`WinSCPPortablePage` adapter now reads the durable
[versioned official page](https://winscp.net/download/WinSCP-6.5.7-Portable.zip/download),
extracts one SHA-256 and the matching fresh publisher CDN link, and rejects
ambiguous metadata, other versions, unexpected queries and undeclared hosts.
The catalog contains the durable page, never an expiring URL. Acquisition retains
the resolved URL, publisher digest and source reference with the artifact.
Hash disagreement blocks execution, including HTML accidentally returned as ZIP.

Official ZIP SHA-256:
`cbe76fc80695ac34d14e4ba81f7ff564beeb3f2033dae7490092e269016d7959`.
The inspected archive is 8,801,298 bytes. This is a publisher checksum, unlike a
locally inspected pin. Retain the complete GPL-3.0/icon-set notices;
[license reference](https://winscp.net/eng/docs/license).

Managed manifests own only the four distributed files. Preserve unowned
`WinSCP.ini`, other session/configuration files and existing registry settings.
Retained artifacts and captured owned-file state supply exact deployment recovery.
Do not launch the executable, create connections, import sessions or rewrite
configuration. The publisher's [portable guide](https://winscp.net/eng/docs/portable)
describes INI auto-selection and an explicit `/ini` path. Machine deployment does
not grant users write access or promise that every runtime file remains in Tools;
application configuration/storage choices remain user actions.

## Validation and VM acceptance

Before submission, Windows-native mocked checks passed on PowerShell 5.1 and 7:
255 passed, zero failed and one VM-only test excluded on each. Parser,
catalog/profile and generated-document validation passed for 287 operations,
two groups, four profiles and 85 PowerShell files. New source tests cover digest
binding, conflicting/missing checksums, unsafe or wrong-release URLs, ambiguous
payload links, oversized metadata and unsupported architecture selection.

Both disposable VM identities and clean checkpoint IDs matched, both VMs were
off, both controller tasks were Ready, and pending/running queues and blocked
markers were empty before submission. Final correlated `ApplicationsBatch2`
results passed on both targets. The suite includes installation/restore previews,
repeat installation, removal, preserved user files and retained-file recovery.
WinSCP also receives synthetic INI and registry-session preservation fixtures.
No Server Core runtime support is inferred from Desktop Experience acceptance.
The final publisher identity-field check also passed all 94 application/acquisition
tests on both PowerShell editions. WinSCP records its published SHA-256 and
checksum-page reference explicitly; hosting/provider evidence and local review
decisions remain separate.

Inspection found that portable manifests skipped `.com` signatures. The focused
follow-up now records them and rejects `HashMismatch` before product writes.
Its mocked signature/rejection regression passed with 256 native tests on each
PowerShell edition. The final VM suite retained valid signature evidence
for both WinSCP binaries, with exactly four owned files; initial runs without
this follow-up remain diagnostic evidence only.
The final suite also checks portable removal preview and repeated removal.
Read-only ID/variant completion passed on both PowerShell editions, with one
`portable` suggestion and no operational-engine import. The existing exporter
retains owned-file backups and acquisition metadata but excludes the download
cache; exact restoration is exercised in the guest before checkpoint reset.

## Final correlated acceptance

| Target | Actual image | Final run | Guest Pester | Portable lifecycles | Finished (UTC) |
| --- | --- | --- | ---: | ---: | --- |
| Windows 11 | Microsoft Windows 11 Enterprise Evaluation, build 26300 / Client | `06e454c9dcba455e9d9d0e81259453b5` | 230 passed | 12 passed | 2026-10-11T08:28:10.4500496Z |
| Windows Server 2025 | Microsoft Windows Server 2025 Standard Evaluation, build 26100 / Server | `6103ffaecca64224ab61874726bb814b` | 230 passed | 12 passed | 2026-10-11T08:13:28.6110765Z |

Both final requests passed parser/catalog/profile validation, all twelve portable
deployment lifecycles and 230 focused guest checks. WinSCP preview, repeat install,
removal preview, repeat removal, saved-selection restoration and original-absence
restoration passed. Both EXE/COM signatures are Valid, with thumbprint
`FD9BB1AE8DA14A218825FEC4A1BFB26DC8F005E7`; the four-file manifest, publisher
SHA-256 and exact member hashes agree with exported evidence. Synthetic unowned
INI and registry-session fixtures remained unchanged across removal and recovery.

All eight frozen catalog/module/test inputs matched their test-run hashes. Six
still matched the working tree before promotion; concurrent setting-presentation
metadata/validation changes were reviewed separately. Package/artifact metadata,
groups and acquisition/lifecycle handlers were unchanged. Concurrent engine/CLI
changes enrich display rows; they do not alter package mutation. Current native
validation/regression results are recorded below; VM acceptance refers to the
frozen revisions. Two schema-3 saved records per target retained
the exact portable/x86/Machine selection, version, source and configured Tools
destination. Exported owned-file backup bytes were independently rehashed;
the exporter deliberately excludes the download cache. Guest exact restore
completed before the controller reverted its clean checkpoint and shut down.
Both controllers are idle with empty queues and no blocked/cleanup/collection
error, and host UAC values are unchanged. No Server Core or application runtime,
file transfer, session import or connection behavior is claimed.

Twenty-four final-run observations were appended to the shared library, preserving
all 94 earlier records (118 total). WinSCP has one direct acquisition per target;
these same-publisher observations are not independent routes or local/company
license approval. Diagnostic initial requests were not imported or used for
support promotion. Published IDs and all four profile files remain unchanged.

Current-workspace native checks on both PowerShell editions passed 229
application/acquisition/catalog/controller cases, then all 65 library/search
cases after two isolated fixtures gained the new read-only presentation
dependency: 294 passing cases across the focused runs, with one VM-only case
excluded. The first rerun exposed those fixture dependencies and a
cross-runtime document-order difference; both are resolved. The generator now
orders setting IDs ordinally and omits empty reference links. Native parser,
catalog/profile and generated-reference validation passed on both editions for
287 operations, two groups, four profiles and 87 PowerShell files. The higher
file count includes the concurrent setting-presentation work; these checks do
not claim its separate GUI/setting acceptance.

## Installed candidates requiring review

- `GetPSTViewer`: exact official free PST Viewer 20.3 installer is signed by
  KernelApps Private Limited; SHA-256
  `4e2eb12620d5c06822913b82decc1c44d272082ce75a266e0ec3ab4e38c52ab9`.
- `GetOSTViewer`: exact official free OST Viewer 21.1 installer has the same
  valid publisher identity; SHA-256
  `f3ec61fe2f01c121e7436cfb6440e839795c280382409fd454f7814f99a20638`.

The [PST](https://www.nucleustechnologies.com/pst-viewer.html) and
[OST](https://www.nucleustechnologies.com/ost-viewer.html) product pages advertise
free editions, but their included product-specific `license.txt` and linked
[EULA](https://www.nucleustechnologies.com/eula.pdf) use licensed-copy/seat terms
without an explicit freeware grant. Resolve applicable terms instead of treating
marketing as local/company approval. Both x86 Inno installers also distribute
`sys\RICHTX32.OCX`; inspect shared-component registration/ownership and exact
recovery before installation. No installer was executed or evidence file opened.

`InstallAutomatedLab`: official release tag 5.61.0 has an 18,649,693-byte MSI with
GitHub release SHA-256
`60ffb72b56eafcb2001514dd09c696f90b5f9a9b2a43ba160f3b04f1d15edb84`.
Read-only MSI inspection found ProductVersion **5.61.18**, whereas its principal
module directories are **5.61.0**. Keep release, MSI and module versions distinct.
The machine MSI contains 1,289 files, including Pester 5.7.1, PSFramework,
SHiPS, PSFileTransfer, PSLog and DSC modules. Existing Gallery/manual modules
need per-file/version collision and ownership handling; ordinary uninstall
registration is insufficient for their recovery. Its only two custom actions
set directory properties, not host provisioning. Package-only intent and
LabSources/component ownership remain review items; do not invoke Hyper-V,
remoting, CredSSP, trust or lab creation commands. Exact
[installer source](https://github.com/AutomatedLab/AutomatedLab/blob/5.61.0/Installer/Product.wxs)
and [MIT license](https://github.com/AutomatedLab/AutomatedLab/blob/5.61.0/LICENSE)
were retained locally with the read-only inspection.

`InstallTMOG` / `RemoveTMOG`: a current Inno-format inspector can read the
previously checksummed/signed 1.0.1.0 installer (Inno 6.7.0). Its payload includes
the application, skins, `LICENSE.txt`, `THIRD_PARTY_NOTICES.md`, font notices and
`TMOG.scr` with application/system destinations. Establish unattended scope,
screen-saver/component controls and recovery without changing existing Windows
screen-saver selection. Preserve `%LOCALAPPDATA%\TMOG` entitlement/configuration
and user skins. A payload listing does not prove which conditional tasks run.
No application, screen saver or activation was executed.

Reading the exact included TMOG `LICENSE.txt` identified an additional blocker:
it grants personal free-edition evaluation/system-monitoring use, restricts public
redistribution and says the license is a release-candidate document requiring
publisher approval before public distribution. The marketing/store page does
not resolve that included-notice qualification or company-use scope. Establish
the applicable approved free-edition license/reference before catalog admission;
do not infer local owner/company license approval or redistribution permission.
All font/component notices were extracted for inspection and retained locally.

### Classic Teams cleanup

`RemoveTeamsWideInstaller` targets the exact historical `Teams Machine-Wide
Installer`; the legacy implementation uses `Win32_Product`, which should not be
reconnected to v3. Microsoft's
[classic-client availability record](https://learn.microsoft.com/en-us/microsoftteams/teams-classic-client-end-of-availability)
states desktop support ended on 2024-07-01 (VDI 2024-10-01) and availability ended
on 2025-07-01. This supports review of obsolete distribution behavior, but does
not decide whether old-installer cleanup remains useful. Choose a narrowly
identified historical cleanup action or retire this outcome; do not substitute
new Teams. Retained-artifact recovery and existing client/add-in ownership remain
unresolved. Microsoft also identifies possible Outlook meeting-add-in issues
after classic-client removal. `RemoveTeamsStoreApp` targets `MicrosoftTeams`
AppX in the calling-user context and requires its own component/scope decision.

### YARA binary availability recheck

The official latest-release API was rechecked at 2026-10-11T07:33:30Z: stable
`v4.5.8` still has zero published binary assets. Its
[release record](https://github.com/VirusTotal/yara/releases/tag/v4.5.8) lists parser
and bounds fixes, so selecting an earlier binary is a separate reviewed version
decision. Establish an official binary or explicit reproducible Windows build;
do not infer retirement or silently substitute YARA-X.

### ImproHound role and dependency reconciliation

`GetImproHound` / `RemoveImprohound` deploy and remove the publisher's release
payload under Tools; the legacy selector does not execute collection or database
setup. The official [v2.0.1 release](https://github.com/improsec/ImproHound/releases/tag/v2.0.1)
supplies one 169,999,605-byte `ImproHound.exe`, with no GitHub asset digest.
Release revision `8ec6de31b4043e025ce522773212b16cf225d65d` retains Apache-2.0
licensing. Its [README](https://github.com/improsec/ImproHound/blob/8ec6de31b4043e025ce522773212b16cf225d65d/README.md)
identifies a standalone x64 GUI and a tested legacy stack: BloodHound 4.2.0,
Neo4j 4.4.10, APOC 4.4.0.8 and JDK 11.0.16.1. It is an analysis client, not the
SharpHound collector. Decide retained legacy deployment versus an explicitly
reviewed current-stack replacement, then inspect executable identity, retained
license/component notices and user-data ownership. No binary was executed,
database configured, APOC permission changed or AD collection started.

### PSScriptTools repository and module boundary

`InstallPSScriptTools` / `RemovePSScriptTools` clone and copy the Git workspace
under Tools, including repository metadata. They do not install to a PowerShell
module path or import it. Current inspected revision
`549fa3e3d769532320054fc0b3c8f42df0452361` has an MIT-licensed
[3.2.0 manifest](https://github.com/jdhitsolutions/PSScriptTools/blob/549fa3e3d769532320054fc0b3c8f42df0452361/PSScriptTools.psd1)
declaring PowerShell 5.1/Desktop/Core, `Microsoft.PowerShell.Threadjob` and
`System.Drawing`. Its [README](https://github.com/jdhitsolutions/PSScriptTools/blob/549fa3e3d769532320054fc0b3c8f42df0452361/README.md)
recommends Gallery installation, which changes the legacy distribution/ownership
contract. Choose retained Git workspace or a pinned source archive, then define
dependency ownership and preservation of modified source/user files. Import also
loads functions, formatting and global customization variables; deployment must
not auto-import it or rewrite a PowerShell profile. Only static references were
read; no module, sample or installation command was executed.

### Opera exclusion by user decision

On 2026-10-11 the user instructed removal of Opera from this repository under
their trust policy. The legacy installer and preset entry have been removed;
Opera has no v3 package and is excluded from subsequent migration batches.
The ledger retains its historical selector solely to account for this decision.
This is a user-policy exclusion, not a publisher-source retirement or an
independent ownership/security assessment. No Opera installer was executed.
Windows-native checks on PowerShell 5.1 and 7 confirm the legacy module parses,
the installer function and preset selector are absent, no catalog entry exists,
and the preset retains CRLF. Repository validation also passed on both editions.
