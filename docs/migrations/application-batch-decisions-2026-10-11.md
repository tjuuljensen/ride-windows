# Application batch preparation decisions

Prepared 2026-10-11. The user requested a decision session before further
application installation work. This document records preparation proposals and
confirmed choices separately. No new installation, removal or VM mutation is
authorized by a pending proposal in this document.

The reported Server test completed successfully: correlated Full request
`6d6f9b37879e47eb94e94e1e76aec43e` ended at 05:45:03 UTC on 2026-10-11.
Before resuming, the actual `RIDE-S25-Test` VM was confirmed Off, with its
configured VM/checkpoint identity, no queued request, and no active controller
job. The user subsequently authorized further migrations until 13:00
Europe/Copenhagen (11:00 UTC), or an earlier stop instruction. This authorizes
clear outcomes and their disposable-VM tests; pending product choices remain
individual review items. Tasks requiring interactive elevation are skipped.

The [application review ledger](application-migration-review.md) remains the
outcome inventory and acceptance record. Selecting an edition for migration
does not establish source availability, licensing approval, runtime behavior or
Windows target support. Existing published defaults and recommended profiles
retain their current selections.

## Shared decisions

| Decision | Options presented | Confirmed choice |
| --- | --- | --- |
| Preparation scope | Installed applications and portable tools with driver-heavy/licensed deployments reviewed separately; conventional installed applications first; include driver-heavy/licensed deployments in preparation too | Confirmed: conventional installed applications first |
| New package scope default | Machine-wide where officially supported; per-user where officially supported; individual application decisions | Confirmed: choose scope separately for each application |
| New architecture/language default | Stable x64 and English UK with useful explicit legacy variants; stable x64 and English US with useful explicit legacy variants; individual architecture/language decisions | Confirmed preference: stable x64 and English UK. Conditional on meticulous review of legacy language/configuration behavior before discarding or replacing any part |
| Windows regional reference | Retain mixed legacy intent; revise values; keep undecided | Confirmed: retain mixed intent with Danish formats (`Culture = 'da-DK'`) instead of the legacy UK formats. UK English display language, Danish keyboard, Denmark location, Danish non-Unicode locale and Romance Standard Time remain the intended reference for separate review |
| Office/Visio language bundle | Preserve legacy bundle subject to current publisher support; make extra packs/proofing optional; review separately later | Confirmed: preserve the full legacy bundle as the migration requirement, subject to current publisher support, and prepare for future user customization to other languages |

The scope preference applies only where the publisher supports that mode.
Major runtime changes and product replacements require an individual decision.
Retaining a legacy variant requires an available, licensed distribution and
applicable validation; it is not an obligation to implement every historic build.

## Legacy language audit before changing defaults

The user explicitly requires careful review of legacy language configuration.
English UK is an application preference, not approval to replace Windows
regional settings or reduce multilingual application components. The following
is source inspection, not Windows runtime acceptance.

| Layer | Exact legacy behavior | Required reconciliation |
| --- | --- | --- |
| Declared configuration | Root `example.ini`, `[Language]`, defines LanguagePack and WinUserLanguage `en-GB`, Culture `en-GB`, Keyboard `0406:00000406`, Location `0x3d`, SystemLocale `da-DK`, TimeZone `Romance Standard Time` | Keep each field distinct. Configured language, keyboard, formats, location, legacy code-page behavior and time zone are separate choices |
| Language-pack installation | `InstallLanguagePackGB`, `InstallLanguagePackDK`, `InstallLanguagePackCustom` install UK, Danish or the process variable `RIDEVAR-Language-LanguagePack` | Assess prerequisites, availability, scope and recovery separately; do not imply an application installer installs the Windows pack |
| User language and keyboard | `SetRegionalSettings` reads `RIDEVAR-Language-*` overrides, clears the existing user language list and the first language's input methods, then adds one language and one keyboard | This replaces existing entries; preserve their order and input methods in captured state and review replacement versus addition explicitly |
| Formats and location | Sets language-list culture opt-out true, chosen culture and chosen home location | Capture the opt-out and culture separately; do not derive region or date/number formats from an application download locale |
| Non-Unicode locale | Sets chosen system locale, default `da-DK` | Separate machine setting; review restart and application compatibility before any implementation |
| Windows display language | Pack presence, installation, system preferred UI language and current-user UI override use `$DefaultWinUserLanguage` (`en-GB`), even if the configurable `$WinUserLanguage` differs | Observable inconsistency: decide whether fixed UK UI is intentional or the override should control UI too. Do not silently fix or reproduce it |
| Welcome screen and new users | `SetRegionalSettings` copies user international settings to welcome screen and new-user defaults on build >=22000. Separate CopyRegionSettingsToAll/Welcome/NewUser selectors repeat or narrow that copying | Build-number checks alone do not establish Server applicability. Review default-user and system-state recovery, not just current-user round trips |
| Secondary US keyboard | `AddENKeyboard` adds an `en-US` language entry; `RemoveENKeyboard` removes every `en-US` language entry | The source comments call this a keyboard operation but implementation changes the language list. Review that distinction and retain this independent outcome |
| Thunderbird payload | `InstallThunderbird` explicitly requests `os=win&lang=en-GB` | Preserve the UK-language requirement when deciding x64 versus legacy x86; channel and architecture remain independent choices |
| Firefox payload | `InstallFirefox` explicitly requests x64 MSI with `lang=en-US` | Published migrated default remains US English. A new UK preference is not approval to change it |
| Chrome and Signal payloads | Enterprise Chrome x64 MSI and Signal Desktop update distribution do not select an application UI locale in the legacy download/install arguments | Retain those distributions. Multilingual payload deployment does not prove UK English UI; application preferences and inherited Windows display language require separate review |
| Office and Visio | Product language `en-gb`; separate LanguagePack product requests `en-gb`, `da-dk`, `MatchOS`; ProofingTools requests `da-dk`, `en-us`, `en-gb` | User confirmed preservation of the full bundle with future customization. Keep product language, extra UI languages, OS-matching behavior and proofing separate; verify current product support and language order |
| Website language disclosure | `EnableWebLangList`/`DisableWebLangList` changes `HttpAcceptLanguageOptOut`, separately from installed languages | Preserve the published setting identity and semantics; application language preference does not select this privacy policy |

Audit anchors: [legacy regional setup](../../legacy/v2/lib-windows.psm1#L399),
[legacy sample configuration](../../example.ini#L20),
[default preset](../../legacy/v2/default.preset#L22),
[Thunderbird and Office](../../legacy/v2/lib-windows.psm1#L3969),
[Visio](../../legacy/v2/lib-windows.psm1#L4160),
[Firefox](../../legacy/v2/lib-windows.psm1#L5704), and
[secondary keyboard selectors](../../legacy/v2/lib-windows.psm1#L11570).
The legacy source was read, not imported or executed. The original INI loader
was also found in `ride.ps1` at Git commit
`ba7f8c9bb41c1c59b95cb6b7bb35a6176cfedcc7` (the parent of the v3 engine
introduction). Its input semantics are recorded below; v3 does not reconnect
that runner or inherit its process-environment configuration.

At the initial decision review, `MozillaVersionsJson` fixed artifact and checksum
member paths to `win64/en-US`. The subsequent authorized preparation now resolves
explicit x64/x86 architecture and optional `MozillaLocale` together with the exact
checksum member in [RIDE.PublisherSources.psm1](../../modules/RIDE.PublisherSources.psm1).
Existing Firefox retains x64/en-US. The user subsequently confirmed Thunderbird
Release x64/en-GB for current-user scope. The legacy literal UK-language intent
is retained; x86 is replaced by the explicitly chosen x64 distribution. See the
[implementation and acceptance record](application-thunderbird-follow-up-2026-10-11.md).
No regional setting is changed by this adapter.

The user confirmed the mixed Windows reference with Danish formats (`da-DK`),
replacing the historical `en-GB` culture preference for the future regional
review. The historical source table above remains an accurate record of the
legacy implementation. Windows UI language and regional formats remain distinct.
The user also confirmed the complete legacy Office/Visio language bundle with
preparation for future customization. These decisions do not start
regional-setting deployment.
Microsoft distinguishes international settings in its
[Windows international configuration guide](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-international-settings-in-windows).
Current ODT language ordering, MatchOS resolution and proofing configuration
must be checked against the
[Office Deployment Tool options](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/office-deployment-tool-configuration-options).

### Historical configuration input path

The historical runner accepts `-Ini`, resolves the path, then calls
`Get-IniFile`. A `[Language]` key becomes a process environment variable named
`RIDEVAR-Language-<key>` before selected functions run. This connects the sample
INI to the consumers above; it does not connect it to Office/Visio's hard-coded
XML languages or Firefox/Thunderbird's literal download locales.

| Input behavior inspected in the historical runner | Migration implication |
| --- | --- |
| Trims section names and values; accepts unsectioned values under `NO_SECTION` | Future local configuration needs a declared schema; arbitrary unsectioned keys do not become supported v3 options |
| Assigns each matching key in file order | Duplicate assignments are last-write wins; review explicit duplicate rejection rather than silently copying that behavior |
| Values remain strings; quotation marks and trailing inline comment text are not decoded or removed | Preserve intended locale identifiers, not accidental INI syntax; validate values before planning |
| Writes empty trimmed values to the process environment | On the historical Windows PowerShell/.NET Framework runtime, an empty value removes the variable, causing null-based consumers to use their fallback. Microsoft documents changed empty-value handling in .NET 9; distinguish omitted/default and explicit empty selections in the future schema instead of inheriting runtime-dependent behavior |
| Clears only `RIDEVAR-Download-Only` before reading the next file | Other omitted keys can retain an inherited or earlier process value. A v3 plan must resolve from explicit scope-specific configuration and save its effective selection, without stale legacy-variable inheritance |
| Regional consumers read configuration, but install the display pack and set UI overrides from fixed `DefaultWinUserLanguage` | The configured user-language list and fixed UK UI can diverge. This remains an explicit regional-review choice, not a language-adapter correction |

This is a static source audit. No historical runner, language installation,
regional command or process-environment mutation was executed. The user's
confirmed Danish formats supersede the sample's historical UK formats for
future review; the historical sample remains unchanged.
The empty-value interpretation follows Microsoft's
[SetEnvironmentVariable contract](https://learn.microsoft.com/en-us/dotnet/api/system.environment.setenvironmentvariable?view=netframework-4.8.1).

## Confirmed Office/Visio language preparation requirement

Preserve the following default requirements, subject to current publisher
support for the eventual licensed products:

- Product language: UK English (`en-gb`).
- Additional language packs: UK English (`en-gb`), Danish (`da-dk`) and
  OS-matching language selection (`MatchOS`).
- Proofing tools: Danish (`da-dk`), US English (`en-us`) and UK English (`en-gb`).

Prepare configuration so a future user can select other product languages,
additional language packs and proofing languages independently, with an explicit
choice about OS matching. Preserve language ordering where it affects behavior.
The precise configuration schema and command parameters remain implementation
design work; no configuration keys or runtime behavior were added in this session.

Future implementation must validate selections against the chosen product's
publisher-supported languages and expose discoverable choices through read-only
completion. Preview must show the requested languages and any resolved
OS-matching selection. Save the effective selection with deployment evidence so
removal and recovery do not recalculate languages from a later Windows locale.
Existing language components, user data and preferences require explicit
ownership and recovery handling; customization must not silently remove them.
Defaults remain reviewable and user customization must not rewrite shared
catalog or release defaults. An unavailable language remains a review item,
rather than being silently replaced by another language.

Licensed Office/Visio product IDs, channel, architecture, activation and bundled
Teams actions remain separate pending decisions. This preparation neither
accepts license terms nor starts an Office deployment. The former Server test
hold was verified complete before the newly authorized application runs.

### Current publisher constraints requiring individual review

Microsoft's [ODT language options](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/office-deployment-tool-configuration-options)
support `en-gb` for Microsoft 365 Apps but explicitly exclude that language for
Visio/Project. Legacy `InstallVisioPro` nevertheless declares `en-gb` on
`VisioProRetail`. Preserve the requested intent as an unresolved product-language
decision; do not substitute `en-us` or silently omit Visio. Verify the eventual
edition against [Visio's supported display languages](https://support.microsoft.com/en-us/visio/display-languages-supported-in-the-visio-desktop-app).

Language order determines the initial Shell UI culture. Microsoft documents
reinstallation to change that culture later. Future customization must distinguish
adding UI/proofing packs and selecting an application preference from changing the
initial installation culture. `MatchOS` needs a supported fallback, and
`MatchInstalled` is an existing-install action with download restrictions.
Requested/resolved languages, their order, source availability and fallback
must be visible in preview and retained in the saved selection. Unsupported
languages must block planning for the affected product.

Keep three independently customizable collections: ordered product languages,
additional language packs with explicit OS matching/fallback, and proofing
languages. Persist local selections outside shared defaults. Product licensing,
architecture/channel coexistence and existing language ownership must be
resolved before any executable deployment configuration is generated. Preserve
the full agreed bundle as the default requirement where supported.

Legacy XML also includes `RemoveMSI`, file-format AppSettings, automatic
activation, updates and `FORCEAPPSSHUTDOWN`. These are distinct deployment or
setting outcomes; language preparation does not authorize MSI removal, forcing
open applications closed, baseline preferences or activation. The legacy force
property's spelling differs from the current ODT `FORCEAPPSHUTDOWN` reference
and requires explicit reconciliation.

## Excluded product

On 2026-10-11 the user excluded Opera under their trust policy. Its legacy
installer and preset entry have been removed, and it is outside future migration
batches. No v3 ID was published. This records the user decision without making
an independent ownership or security assessment.

## Product decisions for subsequent rounds

These are candidates for discussion, not an approved batch membership list.
Technical source and lifecycle blockers remain separate from user choices.

| Outcome / exact legacy selector | Choice to resolve | Implementation or acceptance still needed |
| --- | --- | --- |
| Chrome: `InstallChrome`, `RemoveChrome` | Accepted: enterprise stable x64 machine MSI; adjacent browser configuration remains separate | Both-target profile-preserving lifecycle acceptance is recorded in the installed continuation |
| Signal: `InstallSignal` | Accepted: official stable x64 current-user Desktop distribution | Both-target SHA-512-bound acquisition, profile preservation and compensating recovery passed |
| Thunderbird: `InstallThunderbird` | Confirmed and accepted: Release x64/en-GB, current-user scope | Non-elevated deployment, repeat install/remove, profile preservation and saved-selection recovery passed on both targets; see [correlated acceptance](application-thunderbird-follow-up-2026-10-11.md#accepted-migration-after-resumed-validation) |
| ImageMagick installed: `InstallImageMagick` | Q16 HDRI x64 DLL versus another precision/HDRI edition; PATH and optional integrations | Exact revision/version, dependencies, uninstall detection and environment recovery |
| ImageMagick portable: `InstallImageMagickPortable`, `RemoveImageMagickPortable` | Include portable distribution; exact precision/HDRI edition | Current publisher portable distribution uses 7z; bounded extraction and runtime acceptance required |
| Python: `InstallPython` | Traditional runtime installer versus install manager; release family, scope, launcher and PATH | Manager/runtime ownership differs; dependency compatibility, environment recovery and existing-install conflicts |
| Gpg4win: `InstallGPGwin` | CLI and Kleopatra; Explorer integration; classic Outlook integration; experimental web integration separately | Verify current installer component controls, bind digest/signature and preserve key data; assess target applicability |
| Microsoft OpenJDK: `InstallOpenJDK` | Retain JDK 11 compatibility or select another explicitly declared major; JAVA_HOME/PATH behavior | Exact update MSI, coexistence and prior environment recovery; dependent applications constrain major choice |
| Wireshark: `InstallWireshark`, `RemoveWireshark` | Analysis application alone or capture capability with Npcap | Npcap is a separate driver/license/reboot decision; preserve existing capture-driver ownership |
| AutomatedLab: `InstallAutomatedLab` | Package installation only or separate lab-host provisioning work | Inspected MSI includes shared Pester/PSFramework/SHiPS/DSC modules; define collisions and component recovery. Release 5.61.0, MSI 5.61.18 and module versions differ; host provisioning remains separate |
| WinSCP: `InstallWinSCP`, `RemoveWinSCP` | Retain the explicit legacy stable portable outcome and publisher x86 distribution | Accepted on both targets: checked ZIP, four-file ownership, EXE/COM signatures, unowned sessions and exact deployment recovery. Installed edition remains a separate future choice |
| Volatility: `InstallVolatility3` and separate `InstallVolatility2`, `RemoveVolatility2` | Pinned v3 source archive versus maintained checkout; keep v2 as historical separate outcome or review retirement | Interpreter/environment ownership, plugins/notices and dependencies; no automatic v2 substitution |
| Tool collections: Sysinternals, Zimmerman, NirSoft, MiTeC, NTCore, JoeWare | Whole frozen inventory versus named utilities; identify actual wanted products | Exact per-member hashes/versions/licenses and notices; no changing-site crawl as one package |
| AD analysis: Neo4j, BloodHound, SharpHound, AzureHound, ImproHound, PingCastle | Legacy deployment versus current replacement; server/collector roles and runtime requirements | Product-specific dependencies, licensing and deployment/recovery; collector execution remains separate |
| Office, Visio and Teams | Licensed product/channel/architecture; Teams edition and included actions | Entitlement, supplied deployment configuration and edition-specific recovery |
| VMware, VeraCrypt, WinPmem, Arsenal and guest tools | Include driver/service work; intended product and matching test environment | Artifact/terms where applicable, driver signing, reboot and machine recovery; matching hardware/guest applicability |
| OneDrive and Winget maintenance | Package-only migration versus separately declared sync/update policy | Distinct package/configuration ownership and exact scope/recovery |
| Historical tools and dependencies | Retain a reviewed historical distribution, rebuild, replace explicitly or retire with evidence | License/runtime availability and current-format behavior; no inferred retirement from a missing latest-release endpoint |

## Authoritative references checked for the decision session

- [Thunderbird downloads](https://www.thunderbird.net/en-US/download/) offers
  Release and ESR channels. Release brings features monthly; ESR brings features
  annually with monthly stability/security fixes. Architecture, locale and
  installer type are independent selections.
- [ImageMagick Windows downloads](https://imagemagick.org/script/download.php/)
  recommends the x64 Q16 HDRI DLL build for 64-bit Windows and lists Q8/Q16,
  HDRI and static/DLL alternatives. Its listed portable distributions use 7z.
  Runtime dependencies and local image-processing policy remain acceptance work.
- [Python 3.14 Windows documentation](https://docs.python.org/3.14/using/windows.html)
  distinguishes the install manager from runtimes: removing the manager does not
  remove runtimes, and its managed runtimes are per-user. A machine-wide manager
  installation does not mean machine-wide runtime deployment. The
  [Python 3.14 release notice](https://www.python.org/downloads/release/python-3140/)
  says traditional installers remain available through the 3.14 and 3.15 releases.
- [Gpg4win requirements](https://gpg4win.org/system-requirements.html) describes
  current x64 requirements, classic Outlook compatibility and experimental
  GpgOL/Web integration. Current component controls must be verified against the
  actual selected release rather than assumed from older installer documentation.
- [Wireshark Windows installation](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)
  documents Npcap separately from application installation. Choosing file analysis
  versus live capture determines whether driver work belongs in this batch.

## Batch handoff

After the answers are confirmed, record exact editions, scopes, integrations,
runtime dependencies and batch membership here. Update the corresponding review
ledger entries with a link to the confirmed decisions while retaining technical
blockers. Prepare the implementation and Windows 11 / Server 2025 applicability
matrix before beginning the next install test run.
