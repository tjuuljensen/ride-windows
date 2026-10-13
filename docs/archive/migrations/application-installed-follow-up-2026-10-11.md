# Installed application continuation, 2026-10-11

Archived run evidence. Counts, support and remaining-work statements below are
as recorded on the report date. Use the [current migration plan](../../MIGRATION-PLAN.md)
and [active application ledger](../../migrations/application-migration-review.md)
for current disposition; archiving does not close pending acceptance.


Chrome and Signal are accepted optional migrations for Windows 11 and Windows
Server 2025 with Desktop Experience. Published defaults, recommended profiles
and earlier accepted products remain unchanged.
The user's per-application scope and language requirements are recorded in the
[decision record](../../migrations/application-batch-decisions-2026-10-11.md).

| Product | Declared distribution | Source and integrity evidence | Accepted lifecycle |
| --- | --- | --- | --- |
| `package.chrome` | Legacy enterprise stable x64 MSI, all-user machine scope | Inspected MSI 155.0.8059.40, ALLUSERS=1, valid Google LLC signature, observed SHA-256 pin `32ba438dea18f0fed1ec621bfb274a2669adec67be2aa91d96b3cc6c64779276` | Preview, repeat installation/removal, existing profile preservation, recorded selection and compensating presence recovery passed on both targets |
| `package.signal` | Official stable x64 EXE, publisher-supported current-user scope | Official feed 8.30.0, matching release/file SHA-512, valid Signal Messenger LLC signature; observed SHA-256 `fb5cb6742e355df52e4375ad01d18adb671941c5e040e8dc9a81db852cfb43dd` | Same lifecycle passed, including protection against the upstream uninstaller's deletion of Roaming application data |

Chrome's hash is an inspected identity pin, not a publisher-published checksum.
The mutable endpoint must fail on changed bytes pending a reviewed update.
Signal's provider binds the feed version, stable x64 filename and canonical
SHA-512, then records the downloaded artifact's SHA-256. Checksums, available
signatures and product/licence references are retained independently of local
owner/company licence approval. No account linking or application UI validation
is claimed. Server applicability requires Desktop Experience.

Sources: [Chrome enterprise download](https://chromeenterprise.google/download/),
[Chrome executable terms](https://www.google.com/chrome/terms/),
[Signal official feed](https://updates.signal.org/desktop/latest.yml),
[Signal release licence](https://github.com/signalapp/Signal-Desktop/blob/v8.30.0/LICENSE),
and [Signal uninstall configuration](https://github.com/signalapp/Signal-Desktop/blob/v8.30.0/package.json).

## First correlated runs and correction

Server request `cb3abcd93ba74b4d996e0cc6b0af557e` passed validation and all 222
guest mocked checks. VS Code, Firefox, DB Browser, Autopsy and Chrome passed
their applicable lifecycle scenarios. Chrome additionally passed preservation
of an existing profile fixture and compensating removal recovery.

Signal's installer returned success but the initial exact `^Signal$` pattern did
not establish presence. Its installer framework defaults to a product name with
version in the registration. Detection now accepts stable names such as
`Signal 8.30.0` and excludes Beta. The regression check reads the actual catalog
pattern and tests registry-backed detection. Failure evidence now also exports
up to eight Signal registration entries, without unrelated registry data.
No product is promoted based on this failed request. Logs, state and acquisition
observations were collected; checkpoint recovery/shutdown passed and host UAC
values were unchanged.

Windows 11 request `e667dc52066742bf83d903f665c17d42` reproduced the same Signal
detection failure. Its other five scenarios and all 222 mocked checks passed;
collection, checkpoint recovery and shutdown succeeded with unchanged UAC.
Server retry
`3aec419bfefb4b43b93c322e999f1359` uses the corrected source and clean checkpoint.
The final correlated results below supersede these failed attempts for support
declarations while retaining the failure evidence.

The Server retry stopped before installation at one mocked detection test:
`Import-RideCatalogData` was not visible in the package module under the guest's
test-file order. Validation passed and the other 223 checks passed. The fixture
now explicitly imports its read-only reader into the local test scope; production
detection is unchanged. Evidence collection, checkpoint reset and shutdown
succeeded with unchanged UAC. The exact guest selection/order passed natively
before the final lifecycle requests. Windows 11 retry
`2a9d7a7f66ce40c9a6300daafcb0a7b3` reproduced the same fixture-only failure and
also recovered successfully. The corrected full focused suite passed 250 checks
on each native runtime; the exact guest file order passed 223 checks on both
PowerShell 5.1 and 7 with the one workstation integration test excluded.

## Final correlated acceptance

| Target | Correlated request | Guest checks | Installed lifecycle scenarios | Recovery and collection |
| --- | --- | ---: | --- | --- |
| Windows 11 Enterprise Evaluation, build 26300 | `0a58abbfedac42ab87e60c6a682b4968`, finished 2026-10-11 06:50:54 UTC | 224 passed, zero failed | All six passed; Chrome 155.0.8059.40 and Signal 8.30.0 passed profile preservation, removal preview/repeat and compensating removal recovery | Logs/state/observations collected; pinned checkpoint recovery and shutdown succeeded; UAC unchanged |
| Windows Server 2025 Standard Evaluation with Desktop Experience, build 26100 | `a68b43e9367148caba8f3fd173b5bdb6`, finished 2026-10-11 06:45:20 UTC | 224 passed, zero failed | All six passed, including the same two versions and preservation/recovery scenarios | Logs/state/observations collected; pinned checkpoint recovery and shutdown succeeded; UAC unchanged |

VS Code, Firefox, DB Browser and Autopsy were also rerun successfully. Parent
and guest summaries agree on each request ID and passing status. Tested catalog,
handler, publisher adapter, validation and regression-test hashes matched the
checkout before promotion. Only Chrome/Signal support metadata was promoted;
operation documentation was regenerated from the catalog.

Saved schema-3 runs retain the selected scope, variant, provider and acquisition
evidence. The two packages recover original absence, and recovering a removal
establishes presence using the recorded distribution. This remains compensating
EXE/MSI recovery: exact recovery of an arbitrary previously installed version is
unavailable. Profile fixtures prove retained bytes through these lifecycles,
not browser UI language, account linking, message synchronization or application
behavior. Server Core remains unavailable for these desktop packages.

Sixteen correlated acquisition observations were appended to the shared library:
one download for each of the six products and one Chrome/Signal cache read per
target. All 78 earlier observations were preserved, yielding 94 records. New
observations include valid executable/MSI signatures, hashes and product/license
references. Cache reads and same-origin downloads are not independent-route
verification. Signal's SHA-512 is retained in `ProviderDigest` and its feed in
`ChecksumUris`; the older publisher-SHA-256 fields remain unavailable rather
than mislabelling the SHA-512 result. No local owner/company licence approval
was added.

Result roots are the corresponding request directories beneath
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results` and
`C:\ProgramData\RIDE\TestAutomation\RIDESrv2025Test\results`. Each retains
`result.json`, `guest/summary.json`, `guest/applications-batch1.json`, Pester
output, transcripts, source snapshot/hashes, state and artifact observations.

## Native verification and review work

The final focused application/catalog/library/controller suite passed on Windows
PowerShell 5.1 and PowerShell 7: 250 passed, zero failed, one workstation
integration test excluded. The exact four-file guest selection/order passed
223 checks on each native runtime with that same exclusion. The 224-check guest
runs include the integration-tagged check. Native parser, catalog, four-profile
validation and generated operation documentation passed.

Mozilla preparation now supports explicit x64/x86 and locale selection with
the exact architecture/locale checksum member. Existing Firefox retains
x64/en-US. Thunderbird remains pending the user's channel/scope decisions;
no x86/en-GB behavior is discarded silently. Office/Visio retain the agreed
multilingual requirement and future customization intent; Windows Danish
formats remain a separate regional-settings review.

The [custom-library FTK review](../../migrations/custom-ride-dispositions.md#2026-10-11-payload-inspection-unresolved-prerequisites)
now records exact archive/member hashes, signatures and a separate CodeMeter
prerequisite. Unattended licence, driver/service ownership and exclusion controls
remain unresolved. No installer or exclusion was applied for FTK. Direct live
guest inspection required elevation and was skipped; the existing controller
provided correlated evidence and cleanup.

UserAssist 2.6.0 was also acquired from its exact publisher-linked HTTPS archive
and matched the published SHA-256. `Properties/AssemblyInfo.cs` states a
public-domain dedication; `UserAssist.csproj` targets .NET 2.0. Separate x64 and
AnyCPU Release binaries are mixed with Debug/development-host executables.
No package is admitted from that collection. Review a selected Release binary,
explicit .NET 3.5 dependency and modern registry-format behavior. Microsoft
documents a standalone prerequisite installer for Windows 11 build 28000 and
later; older Windows 11 builds use the optional-component route. These mechanisms
must not be conflated with the current build-26300 VM or Server applicability.
See the [Microsoft .NET 3.5 installation reference](https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11).

TMOG's publisher page loads a Windows release manifest; the static page's
`Not published` placeholders do not establish missing version/checksum evidence.
[That manifest](https://tmog.org/rtm/downloads/release-windows.json) declares
UNIVERSAL edition, x64, 1.0.1/build 0, versioned artifact
`TMOG-Task-Manager-Setup-1.0.1-0-x64-b4edf70fa040.exe`, and SHA-256
`b4edf70fa040968958c662ffb09feeeb0eeca07759e6ed7742606bcc39f29fc6`.
The inspected current installer matches the digest and has a valid David Plummer
signature; PE bootstrapper x86 is not the payload architecture. Product resources
report 1.0.1.0. Actual unattended scope, free-edition EULA/component controls,
registered removal and retained user/activation data remain review requirements.
No Pro licence, purchase, activation or application execution occurred. The
[Windows hotfix notes](https://tmog.org/rtm/release-notes.html) identify Server
startup improvements but do not establish RIDE target acceptance.

### Gpg4win component and dependency preparation

The exact [5.1.1 installer](https://files.gpg4win.org/gpg4win-5.1.1.exe)
matches the [publisher SHA-256](https://gpg4win.org/package-integrity.html),
`ed19c0c89ec42fe32c52a7abd6e3da5f491752700546b9eed7ddf82fd303cddf`,
and the declared 44,831,736-byte length. Authenticode is Valid, with g10 Code
GmbH and thumbprint `83CC4E382E5E4AF554C66E429E8F66FFE499910D`, matching the
publisher's current certificate reference. An available OpenPGP sidecar is
recorded as available, not cryptographically verified.

The [exact publisher source archive](https://files.gpg4win.org/gpg4win-5.1.1.tar.xz)
also matches its published SHA-256
`b486d80ae235dcc1aab72c276291a989bcc1ee947055565f5bae8842cfe8d907`.
Selected NSIS source files were read without executing the installer. Current
`src/nsis/inst-sections.nsi` retains explicit controls for `inst_kleopatra`,
`inst_okular`, `inst_gpgpass`, `inst_gpgoljs`, `inst_gpgol`, `inst_gpgex`,
`inst_paperkey` and `inst_browser`. The historical guide's GPA/Claws list is not
the current release's component contract. `/MINIMAL=1` and `/WITH_BROWSER=1`
have their own semantics; do not use minimal mode as a substitute for the user's
pending GUI/integration choice. The source supports multi-user installation and
remembers previous component choices, so scope and explicit component selection
must be resolved independently and recorded before deployment.

GnuPG is a required nested installer placed beside Gpg4win. The Gpg4win
uninstaller queries existing GnuPG registration, invokes its registered
uninstaller and checks both registry views. A single outer EXE presence record
cannot prove dependency ownership or recovery. Review coexistence with existing
GnuPG, selected integrations, process handling and key/configuration preservation
before a catalog entry or VM installation. No keys were generated/imported and
no Gpg4win application was run.

### Wireshark silent-install and unowned-content preparation

Legacy `InstallWireshark` passes `/S`. The
[publisher's current Windows installation guide](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html)
documents that silent installation skips Npcap; it does not confer live-capture
capability. The official x64 stable appcast currently identifies 4.6.9, exact
artifact `Wireshark-4.6.9-x64.exe`, minimum build 17763 and a SHA-256 comment.
A future resolver must bind one applicable stable item, exact filename/version,
publisher-host origin and digest without selecting the older stable item or a
development build. Appcast metadata is preparation evidence, not an acquired
or accepted installer.

The [4.6.9 NSIS source](https://gitlab.com/wireshark/wireshark/-/raw/v4.6.9/packaging/nsis/wireshark.nsi)
confirms silent Npcap/USBPcap skip paths, all-user installation and optional
Visual C++ redistributable execution. Personal settings and Npcap removal are
optional, but global plugins/profiles/settings are included in normal removal.
Unowned global content therefore needs an ownership/preservation contract before
admission. Review bundled runtime capture/recovery, existing capture drivers,
global customization and file associations. No capture driver, runtime or
Wireshark application was installed during this preparation.

The historical INI loader was located and reconciled in the
[language decision audit](../../migrations/application-batch-decisions-2026-10-11.md#historical-configuration-input-path).
It confirms that regional overrides do not control the hard-coded application
language choices and identifies stale process variables and empty-value fallback
behavior for explicit future review.
