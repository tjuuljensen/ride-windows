# Application review rounds, 2026-10-12

Current disposition update, 2026-10-17: Q17 and Q20 explicitly retire planned
Volatility 2 and ImproHound deployment, leaving existing installations/data alone.
This dated map retains all 79 original outcomes for traceability; 77 remain pending
or partial. See the [current ledger and estimate reconciliation](application-migration-review.md#accepted-volatility-2-and-improhound-retirements-2026-10-17).
Earlier unanswered/retirement-review wording below is historical, not a request
to reconsider these accepted dispositions.

This is a decision map for the 79 unresolved outcomes in the
[application review ledger](application-migration-review.md), not an approved
installation batch. The 29 accepted outcomes (ten earlier, nineteen newly
accepted) and Opera's user-policy exclusion remain unchanged. No installer,
handler, VM reset, configuration change or retirement was performed in this
review. Existing exact selectors and technical blockers remain authoritative in
the ledger; publisher observations dated 2026-10-11 are not all fresh checks.

The 79 outcomes include preferences, policies, components, helpers and bundle
members. They are not 79 independent application installs and cannot be compared
directly with the global packages/artifacts estimate. Grouping reduces repeated
decisions without combining unrelated ownership or recovery boundaries.

## Review method and preserved decisions

1. Decide whether the product/outcome is wanted, and whether to retain, explicitly
   replace, retire with evidence or defer it.
2. Choose distribution, edition, architecture, language, scope and integrations
   separately where they affect the product. Installed applications remain the
   first preparation priority; portable counterparts retain separate outcomes.
3. Verify publisher acquisition, licenses, dependency ownership, saved selection,
   user-data preservation and recovery. A confirmed preference does not establish
   technical acceptance or authorize unrelated bundle actions.
4. Prepare the applicable Windows 11 / Server 2025 scenarios before an install
   run. Matching hardware/hypervisor and driver/reboot tests remain explicit.

Installation scope is chosen per application. Existing published defaults and
recommended profiles are unchanged. The mixed Windows regional reference and
confirmed Office/Visio language bundle with future customization remain recorded
in the [earlier decisions](application-batch-decisions-2026-10-11.md); they are not
reopened by this grouping. Unsupported publisher choices remain blockers rather
than silent substitutions.

## Confirmed first-round choices

| Product | User decision, 2026-10-12 | Still to decide or verify |
| --- | --- | --- |
| ImageMagick | Keep both: x64 Q16 HDRI DLL installer for all users with machine PATH, and listed x64 Q16 static portable build | Optional installed integrations and portable scope/destination/PATH; verify actual portable feature set, machine environment recovery and safe 7z extraction |
| Gpg4win | Current-user scope; GnuPG command line and Kleopatra; no Explorer or Outlook integration | Verify current-user scope in both the outer and nested GnuPG installers, explicit exclusion of other optional components, dependency ownership and key/configuration preservation |
| Wireshark | Include live capture with a separate interactive Npcap step; no OEM rights assumed; capture restricted to administrators | Verify administrator-only capture; choose compatibility flags and Wireshark scope/associations; preserve shared runtime/driver ownership and handle reboot recovery; interactive completion must be detected before continuing |

Npcap adds requested capability beyond the legacy Wireshark silent installation.
It is not another resolved legacy outcome. No local/company license review was
marked approved. ImageMagick's edition pairing, machine scope and machine PATH,
Gpg4win's current-user scope, and Npcap's interactive deployment method with
administrator-only capture are confirmed from user replies. Other scope and
integration choices remain open. The interactive driver step cannot
be treated as an unattended successful installation or bypassed using OEM flags.

## R02 preparation review, 2026-10-12

The next discussion round is Python, Volatility 2/3, YARA and Loki. The unanswered
R01 questions about portable ImageMagick scope, Npcap compatibility mode and
Wireshark machine installation remain open; moving to this round does not answer
or discard them. User replies confirmed both Python deployment models as
selectable variants, Volatility 2 retirement review, and a managed pinned
Volatility 3 release with an isolated environment. Other choices remain open.

| Product | Confirmed choice, 2026-10-12 | Still to decide or verify |
| --- | --- | --- |
| Python | Both variants under one stable product ID; install manager default; traditional installer in machine scope with machine PATH unchanged and existing associations preserved; use bundled/validated pip without automatic upgrade | Manager deployment/command integration, compatible releases, architecture, runtime/update behavior, coexistence, installer flag verification and saved-selection recovery; managed runtimes remain per-user |
| Volatility 2 | Review for retirement; prepare Volatility 3 | Check historical plugin/sample needs and record a final retirement/replacement decision; not retired by this preparation choice |
| Volatility 3 | Managed pinned release with an isolated Python environment; core plus broader plugin dependencies | Verify exact interpreter and required/broader dependency compatibility; choose scope, symbols/caches, user plugins, updates and recovery; cloud/development extras remain separate |

Legacy `InstallPython` selects the first matching amd64 EXE on a mutable download
page, requests all-user installation, file associations and PATH, then upgrades
pip using the resolved `python.exe`. These are separate behavior choices. A v3
selection must identify the exact stable release/artifact and interpreter rather
than inherit a page-order selection or upgrade another installation's pip.

[Python's current Windows guide](https://docs.python.org/3/using/windows.html#advanced-installation)
recommends the install manager, but its runtimes are per-user even when the
manager MSI is machine-wide. Shared target extraction is a separate deployment
contract, not native per-machine managed runtime support. Manager removal leaves
runtimes, and automatic runtime acquisition is enabled by default unless
configured otherwise. The [3.14 release notice](https://www.python.org/downloads/release/python-3140/)
says traditional installers remain available through 3.14/3.15; exact selected
release availability and both-target acceptance still need verification. Both
models will be prepared as selectable variants. The user selected the install
manager as default and all-user machine scope for the traditional installer.
This does not make manager-managed runtimes machine-wide. Manager deployment,
architecture, release family, manager aliases/associations and runtime/update
policy remain undecided. Traditional-installer PATH/association and pip choices
are confirmed below; their exact installer behavior still needs verification.
Detect legacy-launcher/manager alias conflicts and use
the selected interpreter explicitly rather than selecting whichever Python is
first on PATH.

[Volatility 2's repository](https://github.com/volatilityfoundation/volatility)
is archived and its source requires Python 2 rather than Python 3. The legacy
standalone archive is a distinct distribution; retaining it does not implicitly
authorize installing a global Python 2 runtime. Historical plugins and sample
compatibility need individual acceptance before any replacement/retirement. The
user selected retirement review rather than retaining V2 for this preparation
batch; V2 remains unresolved until that review reaches an explicit disposition.

Legacy `InstallVolatility3` replaces a checkout, downloads symbols and invokes
`setup.py build/install` through PATH. The reviewed [v2.28.2 requirements](https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/pyproject.toml)
declare Python >=3.8 and distinguish required dependencies from optional plugin,
cloud and development dependencies. That lower bound does not establish
compatibility with every later interpreter. The user selected a managed pinned
release with an isolated environment and core plus broader plugin dependencies.
For the reviewed tag, the broader set is the publisher's `full` extra: YARA,
disassembly, cryptography, image and memory-access bindings. Confirm the exact
selected release's dependency set and wheels against the chosen interpreter;
cloud/development extras and any driver or acquisition execution remain separate.
Resolve interpreter/dependency
ownership, symbols, caches, user plugins and updates without modifying another
Python environment or discarding edits. The inspected tag is evidence, not an
automatic release selection.

YARA binary/build availability and Loki's scanner/signature update ownership stay
in individual review. Neither is admitted by a Python/Volatility choice, and no
scanner execution or Defender exclusion is implied. Three R02 preparation
questions have been answered: both Python model variants, Volatility 2 retirement
review and a pinned Volatility 3 release with an isolated environment. The user
also answered the follow-up choices as 1A/2A/3A: install-manager default,
traditional installer in machine scope and broader Volatility 3 dependencies.
Runtime compatibility, remaining environment behavior and symbol choices remain
open before implementation.

### Confirmed Python integration choices

The user answered the integration round **1A, 2A, 3A** on 2026-10-12: keep the
traditional installer's machine PATH unchanged, preserve existing Python file
associations, and use bundled/validated pip without an automatic installation-time
upgrade. This retains the earlier all-user machine scope while explicitly
changing three legacy behaviors. The association choice covers the traditional
installer; manager registration/aliases remain a separate review boundary.
Inspect the exact installer's PATH/association/launcher controls and capture prior
state for repeat install, removal and recovery. Do not reset existing user or
unowned PATH/association entries. Tool dependency installation must use its
recorded interpreter/environment; no global pip upgrade is implied by preparing
Volatility's isolated environment. Explicit later pip maintenance remains a
separate workflow.

The [publisher guide](https://docs.python.org/3/using/windows.html#installation)
warns that existing Python installations/PATH can affect commands; manager app
updates, runtime installation/update behavior and pip maintenance are separate.
The manager's automatic missing-runtime acquisition and its own update delivery
remain additional unresolved choices. No blanket automatic-update policy follows
from choosing the manager as the default variant.

## R03 preparation review, 2026-10-12

The user selected current BloodHound Community Edition with container deployment
reviewed separately, both SharpHound (AD) and AzureHound (Entra/Azure) as optional
collectors matched to the backend, and retirement review for ImproHound. These
are preparation choices: no container runtime, service, database, collector or
security exception was installed or executed. Existing data and earlier R01/R02
open choices remain separate review items.

| Product/outcome | Confirmed preparation | Still to decide or verify |
| --- | --- | --- |
| BloodHound | Current Community Edition; separate container deployment review | Supported host/runtime, versioned images and backend configuration, data migration, credentials, service/network ownership and recovery |
| SharpHound / AzureHound | Keep both optional tools; match versions to the selected backend | Exact stable distributions, compatibility, scope/destination, licenses/notices and saved-selection lifecycle; no collection or service setup |
| ImproHound | Review for retirement | Historical tiering-analysis needs, current-stack compatibility or explicit replacement/retirement decision; not retired yet |
| Microsoft OpenJDK / Neo4j/APOC | No standalone-product decision confirmed | Determine independently useful deployments before choosing Java majors, server/plugin versions and environment/service behavior |
| RSAT / ADReplStatus / PingCastle | Existing individual review retained | Exact component set/applicability, licensed binary/build or edition, runtime and applicable domain/lab acceptance |

The [current CE quickstart](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart)
uses a container backend and browser UI. The [Docker Windows requirements](https://docs.docker.com/desktop/setup/install/windows-install/)
exclude Windows Server from Docker Desktop support. Choose an applicable host
and deployment contract before implementation; a Windows CLI binary does not
prove backend applicability on both test targets. No Docker/WSL provisioning or
database-policy change follows automatically from the CE selection.

[SharpHound's publisher](https://github.com/SpecterOps/SharpHound)
directs users to the backend's collector selection for a compatible release.
[AzureHound's publisher](https://github.com/SpecterOps/AzureHound)
distinguishes release binaries from a potentially unstable rolling build. Both
choices need stable artifacts matched to the selected backend rather than
independent latest-version assumptions or an implicit replacement of legacy
PowerShell collectors. Deploying collectors does not run them or configure
collection services/credentials.

[ImproHound's documented tested stack](https://github.com/improsec/ImproHound)
remains BloodHound 4.2.0, Neo4j 4.4.10, APOC 4.4.0.8 and JDK 11.0.16.1. Current
CE compatibility is not established by that matrix. Its retirement review must
assess the wanted tiering-analysis outcome, not treat a container-backend choice
as proof that its functionality is replaced.

### Corrected Neo4j legacy contract

The previous ledger statement that APOC assets were used as the Neo4j installer
was incorrect. Re-reading `InstallNeo4j` in the [legacy source](../../legacy/v2/lib-windows.psm1)
shows a Neo4j Community Windows ZIP selected using the APOC major/minor version,
a separate pinned APOC JAR, extraction under Tools, replacement of an existing
destination, `apoc.*` unrestricted-procedure configuration, and service
installation/start when Java resolves on PATH. The database archive and plugin
are distinct sources. Selection, destructive directory replacement, database
files/credentials, broad procedure permission and service ownership each need
explicit reconciliation and recovery; none is admitted implicitly into v3.

Legacy OpenJDK selects Microsoft JDK 11 x64 MSI with PATH, JAVA_HOME and JAR
association features for that stack. The [publisher roadmap](https://learn.microsoft.com/en-us/java/openjdk/support)
still lists September 2027 as JDK 11's earliest end of support. Choosing CE does
not itself justify retiring JDK 11 or adding a general-purpose Java install to
profiles. Independently wanted Java/Neo4j uses remain a follow-up decision.

## Primary discussion groups

Each unresolved ledger outcome belongs to exactly one primary group. Cross-group
dependencies are handled below rather than counting an outcome twice.

| Group | Outcomes | Members | Shared decision | Individual boundaries |
| --- | ---: | --- | --- | --- |
| R01: General installed applications and their portable variants | 4 | ImageMagick installed/portable, Gpg4win, Wireshark/Npcap | Choose desired distributions/components first, then editions and scope per application. | Four legacy outcomes. Npcap live capture is newly requested additional scope; it was omitted by the legacy silent installer. |
| R02: Python, memory analysis and scanning | 5 | Python, Volatility 2/3, YARA, Loki | Choose the Python deployment model; retain historical Volatility separately or explicitly replace it; select scanner/rule update ownership. | Volatility 3 and historical tools need independent interpreter compatibility checks. Do not assume Loki/YARA require the same interpreter or substitute YARA-X. |
| R03: Java and AD analysis stack | 9 | Microsoft OpenJDK, Neo4j/APOC, BloodHound, ImproHound, SharpHound, AzureHound, PingCastle, ADReplStatus, RSAT | Choose retained legacy BloodHound/Neo4j versus a current deployment before selecting Java/APOC. | Collectors, desktop viewers, database/server roles and Windows AD components remain separate. RSAT is a Windows component, not an EXE package. |
| R04: Office, Visio and Teams | 6 | Office deployment, bundled Teams actions, Teams startup/Store/classic MSI cleanup, Visio | Choose licensed products, channel, architecture and activation; decide Teams inclusion and historical cleanup independently. | Keep the confirmed language bundle and future customization. Visio language applicability needs a supported product-specific choice; Office installation does not authorize Teams removal or forced application closure. |
| R05: Utility collections | 8 | Sysinternals, JoeWare, MiTeC, NTCore, Zimmerman, NirSoft launcher/x64/configuration | Choose a frozen complete inventory or named utilities, then identify actual wanted members. | One acquisition/ownership design can be reused, but versions, licenses and dependencies stay per collection/member. No mutable site crawl, bootstrap execution or automatic security exclusion. |
| R06: Source repositories, scripts and rules | 4 | PSScriptTools, PartDiagParser, GglCookieCruncher, Sigma | Choose pinned managed snapshots versus intentionally editable Git workspaces; define update ownership. | Source deployment, module import, script execution and rule application are separate actions. Preserve user edits and establish each runtime/license. |
| R07: Package management and maintenance policies | 4 | OneDrive package/sync policy, Winget, Winget AutoUpdate | Choose package deployment separately from sync and automatic-update behavior. | OneDrive data handling, AppX scope, scheduler/service changes and environment recovery need their own records. Installing Winget does not enable automatic updates. |
| R08: Virtualization, lab software and hardware-specific tools | 8 | VMware plus VM-directory preferences, AutomatedLab, VirtIO/SPICE/WebDAV, Lenovo Vantage | Choose wanted platforms/hardware and package-only versus lab-host provisioning. | VMware preferences can be one setting with alternative desired paths. AutomatedLab shared module collisions remain separate. Hyper-V does not validate QEMU/SPICE or Lenovo hardware behavior. |
| R09: Driver-dependent forensic and storage products | 5 | VeraCrypt installed/portable, Arsenal products and MEGAcmd helper, WinPmem | Choose exact products and whether to prepare driver/service lifecycle and reboot recovery. | A portable label does not imply driver-free operation. MEGAcmd is a distinct helper, not an implicit requirement for every Arsenal product. |
| R10: Hashcat and its launcher | 2 | Hashcat, HashcatLauncher | Keep the CLI alone or also a compatible launcher; define applicable GPU environments. | Bounded 7z extraction can be shared with other archives. GPU drivers, workload execution and launcher compatibility are separate acceptance. |
| R11: Monitoring and browser configuration | 4 | Olaf Sysmon XML, legacy Edge prediction, Firefox/Chrome preference files | Choose intended monitoring policy and supported browser preference/policy behavior. | These are settings/data outcomes. Do not replace a legacy mapping with a current policy without a decision; preserve existing profile data and distinguish policy application from artifact deployment. |
| R12: Products needing edition or entitlement decisions | 9 | KAPE, CCleaner/Defraggler/Recuva/Speccy, TMOG, PST/OST viewers, WinHex | Choose wanted products and editions, then establish applicable terms/artifacts. | CCleaner is four legacy outcomes, not one package. PST/OST shared OCX ownership needs a common solution. A free download is not owner/company license approval. |
| R13: Historical parsers and viewers | 11 | FirewallNotifier, Autorunner, ChromeParser, Hex2text, ShimCacheParser, SSView, Thumbcacheviewer, SuperFetchTools2, UserAssist, Thumbsviewer, RegRipper | Decide per product: retain a reviewed historical distribution, rebuild, explicitly replace, retire, or defer. | A missing latest-release endpoint is not retirement evidence. Modern format correctness is separate from extraction/install success; old runtimes and complete plugins/support files must be evaluated. |

## Connections that affect review order

- R02 Python/Volatility decisions affect interpreter-dependent parsers in R13;
  verify syntax and dependency compatibility rather than assigning one Python
  runtime to every tool. R06 repositories also need their own execution contracts.
- R03's AD deployment choice comes before its Java/Neo4j/APOC compatibility
  matrix. A current-stack decision does not replace each collector or retire
  ImproHound automatically.
- R05's member inventory determines whether R13's individually wanted MiTeC or
  other utilities overlap a collection. Reuse acquisition/ownership instead of
  installing the same member twice or sharing arbitrary directory ownership.
- Safe 7z support may serve ImageMagick portable, Hashcat and NirSoft launcher;
  a shared extractor does not settle product editions, licenses or GPU support.
- Npcap, VeraCrypt, WinPmem and relevant Arsenal/guest products share driver/reboot
  infrastructure needs, but not drivers, terms or applicability. Respect existing
  installations used by other products.
- Office choices precede Outlook integration if it is ever requested later.
  The current Gpg4win decision excludes that integration.

## Fresh publisher checks for the first rounds

- [ImageMagick Windows builds](https://imagemagick.org/download/#windows)
  recommend the x64 Q16 HDRI DLL installer and list a Q16 static portable 7z.
  The actual portable feature set must be verified; do not assume identical
  features or silently select one precision for both variants.
- [Python's current Windows guide](https://docs.python.org/3/using/windows.html)
  now identifies itself as Python 3.15 and recommends the install manager.
  Manager and runtime ownership are separate; manager removal leaves runtimes.
  The older ledger's traditional-installer option requires release-specific
  availability verification, not an inferred replacement or automatic latest major.
- [Gpg4win requirements](https://gpg4win.org/system-requirements.html)
  distinguish classic Outlook integration from experimental new-Outlook/web
  integration. Neither is included by the user's confirmed component choice.
- [Wireshark's Windows guide](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)
  confirms silent Wireshark installation omits Npcap. Live capture needs the
  separate capture driver; existing Npcap ownership must be preserved.
- [Npcap OEM](https://npcap.com/oem/) and its
  [user guide](https://npcap.com/guide/npcap-users-guide.html)
  reserve silent installation for OEM. Interactive installation, supplied OEM
  entitlement and an external prerequisite are distinct preparation choices.
  The confirmed administrator-only option restricts driver access and requests
  elevation for capture. WinPcap compatibility mode can remove existing WinPcap;
  that option remains a separate choice with conflict review, not an implicit
  effect of the live-capture decision. Raw Wi-Fi monitor-mode support needs
  applicable physical hardware and is still undecided.
- ImageMagick's [older Windows build repository](https://github.com/ImageMagick/ImageMagick-Windows)
  is archived and directs development to the [new Windows repository](https://github.com/ImageMagick/Windows).
  This is not product retirement evidence. Current installer task names and
  optional integrations still need exact-release inspection; historical setup
  examples do not establish their present contract.

## Exact outcome-to-group index

This index traces decisions to the existing ledger rather than replacing its
publisher evidence or blockers. Components of legacy bundles remain separate.

| Group | Batch | Exact ledger selectors / component |
| --- | --- | --- |
| R01 | 1 | `InstallGPGwin` |
| R01 | 1 | `InstallImageMagick` |
| R01 | 2 | `InstallImageMagickPortable`, `RemoveImageMagickPortable` |
| R01 | 1 | `InstallWireshark`, `RemoveWireshark` |
| R02 | 1 | `InstallPython` |
| R02 | 2 | `InstallYara`, `RemoveYara` |
| R02 | 2 | `InstallLoki`, `RemoveLoki` |
| R02 | 2 | `InstallVolatility2`, `RemoveVolatility2` |
| R02 | 2 | `InstallVolatility3` |
| R03 | 1 | `InstallADReplStatus`, `RemoveADReplStatus` |
| R03 | 1 | `InstallRSAT`, `RemoveRSAT` |
| R03 | 1 | `InstallOpenJDK` |
| R03 | 1 | `InstallNeo4j` |
| R03 | 2 | `GetBloodhound`, `RemoveBloodhound` |
| R03 | 2 | `GetSharphound`, `RemoveSharphound` |
| R03 | 2 | `GetAzurehound`, `RemoveAzurehound` |
| R03 | 2 | `GetImproHound`, `RemoveImprohound` |
| R03 | 2 | `GetPingCastle`, `RemovePingCastle` |
| R04 | 1 | `InstallOffice365` / Office deployment |
| R04 | 1 | `InstallOffice365` / Bundled Teams actions |
| R04 | 1 | `DisableTeamsAutoStart`, `ResetTeamsAutoStart` |
| R04 | 1 | `RemoveTeamsStoreApp` |
| R04 | 1 | `RemoveTeamsWideInstaller` |
| R04 | 1 | `InstallVisioPro` |
| R05 | 2 | `GetSysinternalsSuite`, `RemoveSysinternalsSuite` |
| R05 | 2 | `InstallJoeWare`, `RemoveJoeWare` |
| R05 | 2 | `InstallMitec`, `RemoveMitec` |
| R05 | 2 | `InstallNtcore`, `RemoveNTCore` |
| R05 | 2 | `InstallZimmermanTools`, `RemoveZimmermanTools` |
| R05 | 2 | `InstallNirsoftLauncher`, `RemoveNirsoftLauncher` |
| R05 | 2 | `InstallNirsoftToolsX64`, `RemoveNirsoftToolsX64` |
| R05 | 2 | `InstallNirsoftPkgFiles`, `RemoveNirsoftPkgFiles` |
| R06 | 2 | `InstallPSScriptTools`, `RemovePSScriptTools` |
| R06 | 2 | `InstallPartDiagParser`, `RemovePartDiagParser` |
| R06 | 2 | `InstallGglCookieCruncher`, `RemoveGglCookieCruncher` |
| R06 | 2 | `InstallSigma`, `RemoveSigma` |
| R07 | 1 | `DisableOneDrive`, `UninstallOneDrive`, `EnableOneDrive`, `InstallOneDrive` / OneDrive package |
| R07 | 1 | `DisableOneDrive`, `UninstallOneDrive`, `EnableOneDrive`, `InstallOneDrive` / OneDrive sync policy |
| R07 | 1 | `InstallWinget` |
| R07 | 1 | `InstallWingetAutoUpdate` |
| R08 | 1 | `InstallVMwareWorkstation`, `RemoveVMwareWorkstation` |
| R08 | 2 | `SetVMDirUserhome` |
| R08 | 2 | `SetVMDirDocuments` |
| R08 | 1 | `InstallAutomatedLab` |
| R08 | 1 | `InstallVirtIOGuestTool` |
| R08 | 1 | `InstallSpiceGuestTool` |
| R08 | 1 | `InstallSpiceWebDAV` |
| R08 | 1 | `InstallLenovoVantage`, `RemoveLenovoVantage` |
| R09 | 2 | `InstallVeraCrypt` |
| R09 | 2 | `InstallVeraCryptPortable` |
| R09 | 2 | `InstallArsenalRecon` / Arsenal products |
| R09 | 2 | `InstallArsenalRecon` / MEGAcmd helper |
| R09 | 2 | `InstallWinPmem`, `RemoveWinPmem` |
| R10 | 2 | `InstallHashcat`, `RemoveHashcat` |
| R10 | 2 | `InstallHashcatLauncher`, `RemoveHashcatLauncher` |
| R11 | 2 | `GetSysmonOlafXML` |
| R11 | 1 | `DisableEdgePagePrediction` |
| R11 | 2 | `CreateFirefoxPreferenceFiles`, `RemoveFirefoxPreferenceFiles` |
| R11 | 2 | `CreateChromePreferenceFile`, `RemoveChromePreferenceFile` |
| R12 | 2 | `InstallKAPE`, `RemoveKAPE` |
| R12 | 2 | `InstallCCleaner`, `RemoveCCleaner` / CCleaner portable |
| R12 | 2 | `InstallCCleaner`, `RemoveCCleaner` / Defraggler |
| R12 | 2 | `InstallCCleaner`, `RemoveCCleaner` / Recuva |
| R12 | 2 | `InstallCCleaner`, `RemoveCCleaner` / Speccy |
| R12 | 1 | `InstallTMOG`, `RemoveTMOG` |
| R12 | 1 | `GetPSTViewer` |
| R12 | 1 | `GetOSTViewer` |
| R12 | 2 | `InstallWinhex`, `RemoveWinhex` |
| R13 | 2 | `InstallFirewallNotifier`, `RemoveFirewallNotifier` |
| R13 | 2 | `InstallAutorunner`, `RemoveAutorunner` |
| R13 | 2 | `GetChromeParser`, `RemoveChromeParser` |
| R13 | 2 | `GetHex2text`, `RemoveHex2text` |
| R13 | 2 | `GetShimCacheParser`, `RemoveShimCacheParser` |
| R13 | 2 | `InstallSSView`, `RemoveSSView` |
| R13 | 2 | `InstallThumbcacheviewer`, `RemoveThumbcacheviewer` |
| R13 | 2 | `InstallSuperFetchTools2`, `RemoveSuperFetchTools2` |
| R13 | 2 | `InstallUserAssist`, `RemoveUserAssist` |
| R13 | 2 | `InstallThumbsviewer`, `RemoveThumbsviewer` |
| R13 | 2 | `InstallRegRipper`, `RemoveRegRipper` |

Coverage: 79 unresolved outcomes, each assigned once across 13 primary groups.
All remain pending implementation/acceptance or individual review. This review
resolves no legacy outcome, retires/excludes none, and changes no support claim.
R01 choices cover four legacy outcomes, R02 three (Python and Volatility 2/3), and
R03 four (BloodHound, two collectors and ImproHound). All eleven retain technical
acceptance or final disposition work. Global estimates remain 38-58 settings, 58-73 packages/artifacts,
20-25 components, 25-35 accounts/assets and 8-12 maintenance actions, rounded
150-205 / about 180; see the dated planning entry.
