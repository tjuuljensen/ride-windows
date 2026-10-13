# Application migration continuation, 2026-10-11

Archived run evidence. Counts, support and remaining-work statements below are
as recorded on the report date. Use the [current migration plan](../../MIGRATION-PLAN.md)
and [active application ledger](../../migrations/application-migration-review.md)
for current disposition; archiving does not close pending acceptance.


Two further legacy portable outcomes are accepted:
`InstallCaffeine`/`RemoveCaffeine` and
`InstallNetworkMiner`/`RemoveNetworkMiner`. Each keeps one product ID with the
`portable` default variant. Both are optional and no profile is changed.
Deployment support is declared for Windows 11 and Windows Server 2025 with
Desktop Experience after both disposable-VM lifecycle suites passed.

| Product | Exact distribution and integrity evidence | Deployment limits |
| --- | --- | --- |
| Caffeine | Publisher [version page](https://www.zhornsoftware.co.uk/caffeine/) identifies 1.98. The official ZIP contains only `caffeine32.exe` and `caffeine64.exe`; inspected SHA-256 is `4a259c348e59eb51bbb75aac7fdcc798705496d575892ee1e01fff6970d5ba1c`. [Publisher terms](https://www.zhornsoftware.co.uk/) state freeware including commercial use. | Both architectures are retained as the legacy archive did. No publisher checksum was found, so the inspected bytes are pinned and upstream changes fail acquisition. Deployment does not start the app or alter sleep/lock policy. |
| NetworkMiner | [Publisher product page](https://www.netresec.com/?page=NetworkMiner) identifies free edition 3.2 and its fixed-version ZIP. Downloaded SHA-256 matches the page: `daceec649fb4fe59b11e4a9e4ecd5f51c1dd37824280dfbeac67bec27b6b6d60`. [License reference](https://www.netresec.com/?page=NetworkMinerSourceCode) states GPLv2. | All 49 files in the nested archive are retained, including fingerprint data and its MIT notice. Running NetworkMiner requires .NET Framework 4.8 or later; runtime analysis, capture drivers and firewall rules are outside deployment acceptance. |

Research downloads were inspected without application execution. Native source
page snapshots, archive inventories and hashes are retained beneath
`.local/results/applications-followup-samples`. NetworkMiner's separate mutable
hash endpoint returned an older hash through web retrieval; the fresh native
product page and fixed-version payload agree on the hash above. No checksum
mismatch was overridden.

WinSCP remains an individual review item. Its official stable 6.5.7 portable
download page publishes SHA-256
`cbe76fc80695ac34d14e4ba81f7ff564beeb3f2033dae7490092e269016d7959`, but the
publisher download wrapper and its SourceForge route returned HTML during
inspection. A durable official artifact route is required before admission;
neither release candidates nor expiring download URLs are substituted.

Three earlier release-lookup failures received a source review. The
[ADReplStatus README](https://github.com/ryanries/ADReplStatus) identifies an early
personal rebuild with .NET Framework 4.8.1; it does not establish Microsoft
support or a licensed ready-to-deploy binary. The
[Autorunner README](https://github.com/woanware/autorunner) requires x64/.NET
Framework 4.7.2, describes privileged image access and a Sigcheck dependency.
The [WFN README](https://github.com/wokhan/WFN) offers beta/nightly versions,
GPLv3 and explicitly lacks official Server support. These remain review items
with concrete binary/license, dependency, target and recovery decisions. Their
source repositories remain accessible; missing latest-release endpoints are
not recorded as product retirement.

[Thumbcache Viewer](https://thumbcacheviewer.github.io/) and
[Thumbs Viewer](https://thumbsviewer.github.io/) have publisher binary links
despite the earlier release-endpoint failures. Their pages require Visual C++
2008 runtime. Microsoft's [runtime lifecycle FAQ](https://learn.microsoft.com/en-us/lifecycle/faq/visual-c-faq)
ends general v90 support on 2018-04-10; its exceptions concern specified
Microsoft products. Both outcomes remain for an individual runtime/license or
rebuild decision. No obsolete runtime is installed implicitly.

Further individual review evidence: [SSView](https://www.mitec.cz/ssv.html)
requires a commercial license outside private, educational and non-commercial
use and distinguishes Professional features. Its edition/terms remain a
decision, not a catalog license approval. The [UserAssist index](https://blog.didierstevens.com/my-software/#UserAssist)
identifies a fixed 2.6.0 ZIP/checksum alongside several older archives; member,
license, runtime and current-build parsing inspection remain required.
Microsoft's [OpenJDK roadmap](https://learn.microsoft.com/en-us/java/openjdk/support)
still lists JDK 11 LTS, with earliest end of support September 2027. The legacy
major is retained for review of update selection, PATH/JAVA_HOME and recovery;
no newer major is silently substituted.

[Volatility 3 release 2.28.2](https://github.com/volatilityfoundation/volatility3/releases/tag/v2.28.2)
declares Python >=3.8 and pefile >=2024.8.26, with additional optional plugin
dependencies, in its [release metadata](https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/pyproject.toml).
Its [VSL-1.0 notices](https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/LICENSE.txt)
must be retained. The source-checkout versus pinned-archive workflow and runtime
recovery remain an individual decision. A reviewed fixed archive can use the
existing bounded ZIP lifecycle; no dedicated provider is inherently required.

Native parser/catalog/profile validation and generated-document checks passed
on Windows PowerShell 5.1.26100.9549 and PowerShell 7.6.5: 284 operations, two
groups, four profiles and 85 maintained PowerShell files. Both runtimes passed
238 focused Pester checks, with one VM-only test excluded on the host. Read-only
PE inspection confirms Caffeine's native x86/x64 files and NetworkMiner's
IL-only managed executable. Both Caffeine files report version 1,9,8,0 and are
unsigned; this does not add a signature-authentication claim.
The native checks passed again after support promotion and observation import.

Both noninteractive disposable-VM controllers returned correlated success:

| Target | Correlated request | Result and recovery |
| --- | --- | --- |
| Windows 11 Enterprise Evaluation, build 26300 | `1c0a50092e904117b505e5d447b67f25` | 212 guest Pester checks and 11/11 portable scenarios passed; evidence collection, pinned checkpoint reset and shutdown succeeded. Finished 06:41:06 Europe/Copenhagen. |
| Windows Server 2025 Standard Evaluation with Desktop Experience, build 26100 | `3a426e31718b437c803959b44f31bcb2` | 212 guest Pester checks and 11/11 portable scenarios passed; evidence collection, pinned checkpoint reset and shutdown succeeded. Finished 06:38:13 Europe/Copenhagen. |

The requests used `ApplicationsBatch2`, rerunning its nine accepted portable
distributions alongside the two candidates. Caffeine 1.98 and NetworkMiner 3.2
both passed preview, installation, repeat installation, removal, preservation
of unowned files, exact owned-file restore and recovery of original absence.
All eleven scenarios reported successful recovery on each target. Both new
archive hashes match the inspected pins above. Guest PowerShell versions were
5.1.26100.9444 on Windows 11 and 5.1.26100.33438 on Server.

The existing controllers revalidated the pinned VM/checkpoint identities before
mutation. Windows 11 used VM `RIDE-Win11-Test`, ID
`6a5c9f91-91f9-44c5-924a-d1b5f863e16f`, checkpoint
`a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9`. Server used `RIDE-S25-Test`, ID
`06c2ae01-bf82-4634-9215-f240f3ea4147`, checkpoint
`4a5b49ba-0795-480a-8d01-6f4f670577c8`. Both queues were idle before submission
and after completion, with no recovery block. Actual guest edition/build and
Server installation type were recorded rather than inferred from the template.

Evidence is retained in
`C:\ProgramData\RIDE\TestAutomation\<controller>\results\<request>`. Work needing
interactive Windows administrator elevation is deferred while the user is AFK.
The recovery procedure captured evidence before restoring the pinned checkpoint
and shutting down each VM. Both parent results have null cleanup/collection
errors. Host UAC values before/after were unchanged: EnableLUA 1,
ConsentPromptBehaviorAdmin 5 and PromptOnSecureDesktop 1. No interactive host
elevation prompt was required.

Twenty-two new correlated acquisition observations were imported without
replacing existing records: four acquisitions for the two new products across
both guests, and eighteen for the portable regression reruns. Archive pins and
product/license references are in acquisition evidence; owned-file hashes,
available Authenticode status and recovery bytes are in the captured state.
No local license approval is copied into shared evidence. Server Core and
application/forensic behavior remain outside this deployment acceptance.

The application ledger now totals ten earlier migrations, fifteen accepted
batch/continuation outcomes and 84 individual review items. Ten review records
were refined with current publisher evidence. All five migration group ranges
were reviewed; the two resolved outcomes fit within the existing coarse ranges,
so packages remain 65-80 and the rounded total remains 160-215/about 190. Deferred
components and separate runtime acceptance remain counted where applicable.
