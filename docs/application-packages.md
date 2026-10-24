# Application variants and portable recovery

RIDE keeps one product ID and declares supported distributions in `Variants`.
`DefaultVariant` preserves the existing default; old flat package entries use
`installed`. Additional products are optional. Check the
[application review ledger](migrations/application-migration-review.md) for
target acceptance and individual blockers before applying them.

```powershell
.\ride.ps1 show package.sharex -Variant portable
.\ride.ps1 download package.sharex -Variant portable -WhatIf
.\ride.ps1 install package.sharex -Variant portable -WhatIf
.\ride.ps1 remove package.sharex -WhatIf
```

Tab completes `-Variant` from the selected package's catalog metadata, including
custom libraries. Completion reads data only. An unsupported explicit choice
fails. A local preference may fall back to the catalog default with a planning
note. The current implementation refuses a different installed edition;
switching editions requires a reviewed edition change. `show`, default `status`
and removal use the recorded selection where available. An explicit profile
compares its requested edition.

## Slack and Discord current-user candidates

`package.slack` and `package.discord` are official x64 current-user EXE
packages accepted for Windows 11. ApplicationsBatch4 verified the pinned
publisher bytes and Authenticode signatures, then passed install, repeat,
vendor-uninstall, repeat-removal, recovery and byte-for-byte preservation of
pre-existing Roaming profile data for both packages. Discord's matching
manifest had a malformed 65-character digest; the exact publisher artifact was
measured independently and the verified SHA-256 is now pinned. Server support
is not inferred. See the [ApplicationsBatch4 acceptance
record](migrations/application-migration-review.md#slack-and-discord-applicationsbatch4-windows-11-acceptance-2026-10-22)
and [sanitized evidence](archive/evidence/applications-batch4-acceptance-2026-10-22.json).
Neither vendor's reviewed page publishes a checksum sidecar.

Slack currently recommends MSIX for managed deployment. Its direct-download EXE
is now under the legacy option, while its earlier deployment MSI was retired.
RIDE does not have an MSIX handler, so this candidate follows the selected
current-user EXE route. Discord's publisher documents the standard
`DiscordSetup.exe` download. Windows 11 acceptance confirmed the registered
uninstallers preserve existing current-user roaming app-data during removal.
They do not configure accounts, sign in, or apply organization policy.

## Phoenix Protector shared .NET prerequisite

The pinned Phoenix Protector 1.7.1 MSI declares a launch condition for
.NET Framework 2.0. RIDE records `PrerequisiteDotNetFramework35` and checks
the installed shared framework state before it acquires or launches the MSI.
Microsoft documents that .NET Framework 3.5 includes the CLR 2.0 layer used by
.NET Framework 2.0 applications. The package handler only reads the Windows
registry and fails closed when the prerequisite is absent or cannot be
inspected; it never enables .NET Framework or treats the shared feature as
Phoenix-owned uninstall state.

The failed Windows 11 acceptance run found that the test guest lacked the
prerequisite. Do not rerun the MSI until the prerequisite is explicitly
available in the disposable test image. RIDE has not verified the MSI launch
condition against an enabled feature, offline servicing behavior, installation
or recovery. The candidate declares no supported targets. See the
[acceptance and implementation record](migrations/application-migration-review.md#applicationsbatch1-windows-11-result-and-dependency-blockers-2026-10-24-1543-utc),
[Microsoft CLR/version mapping](https://learn.microsoft.com/en-us/dotnet/framework/install/versions-and-dependencies),
and [.NET Framework 3.5 on Windows 11](https://learn.microsoft.com/en-us/dotnet/framework/install/dotnet-35-windows-11).

## WinPmem signed production candidate

`package.winpmem` stages one pinned x64 executable in RIDE's machine tools
directory. Installing or removing the package only manages that owned file; it
does not run WinPmem, load its kernel driver, create a driver service or acquire
memory. The package remains a Windows 11 candidate with no supported targets.

The publisher's 4.1 development release marks its new drivers test-signed and
directs production users to the separate `go-winpmem_amd64_1.0-rc2_signed.exe`
asset with older signed drivers. The release asset page publishes the SHA-256
pin used by RIDE, but this workspace could not resolve `github.com`, so the
exact bytes and Authenticode signer have not yet been verified locally. Driver
loading, service cleanup, reboot recovery and capture require separate explicit
acceptance on a disposable Windows guest. Do not infer Windows support from the
publisher's historical OS claims. The publisher identifies the source and
signed binaries as Apache-2.0; retain upstream license and notice files.

See the [WinPmem migration record](migrations/application-migration-review.md#winpmem-production-asset-source-review-and-package-candidate-2026-10-24)
and the [publisher's release page](https://github.com/Velocidex/WinPmem/releases).

## MiTeC SQLite Query portable candidate

`package.mitec-sqlite-query` pins MiTeC SQLite Query 3.2.0 and the retained
three-file ZIP (`SQLiteQuery.exe`, `sqlite3.dll`, and `sqlite3.exe`). The app PE
is x86. Staging copies the selected files without opening a database or running
SQL. The candidate has no supported targets and remains pending Windows
acceptance.

The retained archive hash is local evidence, not a publisher checksum. The app
reports FileVersion 3.2.0.0 and ProductVersion 3.0.0.0; keep that distinction.
The bundled SQLite binaries identify release 3.35.5 and contain the official
source-ID string, but their different embedded compile options and the missing
source archive mean reproducible build provenance remains unverified. SQLite's
public-domain terms apply to its own deliverables; MiTeC's non-commercial EULA,
owner-specific entitlement and archive redistribution remain separate review
items. The retained ZIP has no license/notice file. Preserve applicable
[SQLite notices](https://www.sqlite.org/copyright.html) before redistribution;
the candidate does not claim permission.

Any later functional acceptance must use disposable copies of synthetic
databases, test SQL/edit/import/export/history and exact file recovery, and must
never open personal or production databases. See the dated
[source and candidate record](migrations/application-migration-review.md#mitec-sqlite-query-portable-candidate-preparation-2026-10-22).
The publisher documents an SQL Editor, Table Editor, Trigger Explorer, and SQL
History, with CSV/XML/SQL export and CSV/DataPacket 2.0 import. A prepared,
synthetic-only procedure exercises those claims and exact database-file recovery
in a disposable Windows VM; it is not acceptance evidence. See the
[fixture and run procedure](../tests/fixtures/mitec-sqlite-query/README.md) and
[latest static review](migrations/application-migration-review.md#mitec-sqlite-query-synthetic-gui-acceptance-preparation-2026-10-23).

## MiTeC Structured Storage Viewer portable candidate

`package.mitec-ssview` pins MiTeC Structured Storage Viewer 4.1.2 and selects
only `SSView.exe` from the retained publisher ZIP. The x86 viewer is staged
without launching it. The optional ZLib codec, Delphi source, and bundled
`test.ss` sample are excluded from the selected package files.

The archive SHA-256 is measured from the retained source, not publisher-provided.
The publisher documents Windows XP through 11 and Server 2003 through 2025, but
RIDE support remains unset pending Windows acceptance. The local exact-version
license record is informational for candidate planning. MiTeC's unregistered
terms describe non-commercial use and list paid tiers; package preparation does
not determine an individual or organization's entitlement.

The focused inert package lifecycle regression passes 2/2 in PowerShell 7. It
checks catalog metadata against the recorded archive/member pins and exercises
repeat staging, snapshot, removal and restore with a generated inert ZIP.
Windows PowerShell 5.1 parsing passes, but Pester cannot import on this host
because AuthorizationManager blocks its format data/module load. This is
static/lifecycle preparation, not VM acceptance.

Later behavior checks require a separately generated synthetic structured-
storage file, byte-exact recovery, an isolated viewer directory, and preservation
of unowned activation/configuration/plugins. Do not load or build the optional
codec or use the bundled sample in acceptance. See the [candidate preparation
record](migrations/application-migration-review.md#mitec-structured-storage-viewer-portable-candidate-preparation-2026-10-23).

## MiTeC Network Scanner portable candidate

`package.mitec-network-scanner` pins MiTeC Network Scanner 6.1.0 and offers
explicit `x64` and `x86` variants, defaulting to `x64`. Each variant stages only
its matching executable from the retained publisher ZIP. Staging does not launch
the scanner or send network traffic; Windows support remains unaccepted.

The retained archive and member hashes are locally measured, not publisher-
provided. The executables report FileVersion 6.1.0.0 and ProductVersion 6.0.0.0.
MiTeC lists paid tiers and describes unregistered use as non-commercial freeware.
The exact-version local `NeedsReview` record is informational and does not block
candidate planning.

The scanner can enumerate network hosts, services, shares and directory/system
details. Any behavior acceptance must use an isolated owned network, synthetic
endpoints and accounts, explicit port/traffic bounds, and disposable result
files. Do not scan the development host or a detected local range, query a real
directory/SAM, use production credentials, or open the VirusTotal link. See the
[candidate source and acceptance record](migrations/application-migration-review.md#mitec-network-scanner-portable-candidate-preparation-2026-10-23).

## MiTeC Interbase Query portable candidate

`package.mitec-interbase-query` pins MiTeC Interbase Query 9.5.0 with explicit
x64 and x86 variants, defaulting to x64. Each variant stages its matching
executable plus the same seven localization files from the retained publisher
ZIP. Staging does not launch the utility or connect to a database. The local
exact-version `NeedsReview` record is informational and does not block direct-
download package planning.

The executables report FileVersion 9.5.0.0 and ProductVersion 9.0.0.0. The
publisher page describes SQL/script execution, user and privilege management,
database validation, service controls, import/export, and index rebuilding.
Any behavior acceptance must use synthetic disposable databases with exact
backups and recovery. Do not use real database files, credentials, or live
services. The IBX client dependency version and bitness remain open; Windows
support is not established. See the [source and candidate record](migrations/application-migration-review.md#mitec-interbase-query-portable-candidate-preparation-2026-10-23-1632-utc).

## MiTeC Task Manager DeLuxe portable candidate

`package.mitec-task-manager-deluxe` pins version 5.1.1 and provides `x64` and
`x86` variants, defaulting to `x64`. Each stages the matching Task Manager
DeLuxe executable and Desktop Explorer executable from the retained publisher
ZIP. Staging does not launch either program. The exact-version local
`NeedsReview` record is informational and does not block direct-download
package planning.

The publisher describes live process, service, driver, account, session,
network and hardware views, with optional process/service control, minidumps,
CSV export, update checks and VirusTotal links. Later acceptance requires a
disposable Windows guest and synthetic process fixtures. Do not change
processes or services, create dumps, export account/session/journal data,
query VirusTotal, configure an API key, or enable update/network lookups.
Windows support remains unaccepted. See the [candidate source and acceptance
record](migrations/application-migration-review.md#mitec-task-manager-deluxe-portable-candidate-preparation-2026-10-23-1659-utc).

## MiTeC DFM Editor Delphi variants

`package.mitec-dfm-editor` pins the publisher's `DFMEdit.zip` and exposes two
explicit variants: `delphi-11` stages DFM Editor 8.3.1.0 with its eight Delphi
11 runtime packages, while `delphi-12` stages version 8.4.0.0 with its eight
Delphi 12 runtime packages. The default is `delphi-12`. Each variant selects
only its own nine archive members, so the 280 and 290 BPL families cannot be
mixed by package extraction. Switching variants follows the existing explicit
edition-change workflow.

This package stages files only. It does not launch the editor, open or extract
forms, load/register BPLs, or accept terms. Both versions have local
`NeedsReview` records for owner-specific license administration; those records
do not block package implementation or install planning. The candidate remains
unsupported pending Windows 11 lifecycle and synthetic DFM/PE acceptance. Use
only disposable text/binary DFM files, a synthetic PE, and a disposable package
fixture for functional tests. See the [candidate evidence](archive/evidence/mitec-dfm-editor-candidate-2026-10-23.json)
and the [dated migration review](migrations/application-migration-review.md#mitec-dfm-editor-delphi-variant-package-candidate-2026-10-23).

## MiTeC EXE Explorer and HexEdit candidates

`package.mitec-exe-explorer` pins MiTeC EXE Explorer 3.7.5 with its x86 and x64
executables. `package.mitec-hexedit` pins HexEdit 7.1.0's x86 executable. Both
stage only the exact reviewed archive members; neither candidate launches its
tool. EXE Explorer acceptance uses synthetic PE files and isolated export
paths, with VirusTotal/API-key/network behavior disabled. HexEdit acceptance
uses disposable file copies with exact backups and recovery; process-memory and
raw-disk features stay outside this file-lifecycle batch.

Both versions have local `NeedsReview` records for owner-specific license
administration. Those records do not block implementation or install planning.
Both candidates remain unsupported pending Windows 11 lifecycle and the
synthetic feature checks above. See the [candidate evidence](archive/evidence/mitec-analysis-tools-candidates-2026-10-23.json)
and [dated migration review](migrations/application-migration-review.md#mitec-exe-explorer-and-hexedit-candidate-packages-2026-10-23).

## MiTeC System Information eXtra and TAPI Monitor candidates

`package.mitec-system-information` pins MiTeC System Information eXtra 16.0.0
with both x86 and x64 report executables. `package.mitec-tapi-monitor` pins the
x86 TAPI Monitor 1.2.0 executable. These Windows 11 candidates have no supported
targets yet. Staging copies exact managed files without launching them.

System Information eXtra can report device, storage, process, service, event-log,
security and SMBIOS information and can save text, XML and structured-storage
reports. Do not create, load or retain reports from the development host or a
real user profile. Any later report acceptance must inventory fields and review
redaction, storage and cleanup with synthetic fixtures in a disposable VM.

TAPI Monitor can enumerate TAPI lines/providers, display active-call details and
control calls. Do not access real lines, telephones, providers, calls or call
history. Any later behavior acceptance requires a simulated non-production
provider, synthetic calls and unchanged line/provider configuration.

The current publisher pages list version 16.0.0 and 1.2.0, respectively, and
both list Windows 11. Exact archive and selected-member hashes are retained in
the [static review](archive/evidence/mitec-system-information-tapi-static-review-2026-10-20.json).
Both versions have local `NeedsReview` records. Those markers do not block
candidate planning and do not assert entitlement. See the [candidate-preparation
record](migrations/application-migration-review.md#mitec-system-information-extra-and-tapi-monitor-package-candidates-2026-10-23).

Portable architecture variants can share a product directory. Repeating an
installation or previewing removal validates that directory against the selected
variant's ownership manifest. A different installed variant still requires an
explicit reviewed migration; invalid ownership remains an error.

## Docker Desktop candidate for Windows 11

`package.docker-desktop` is a package candidate, not a supported RIDE target yet.
Its Windows 11 candidate target remains visible, while both variants await a
completed RIDE install, repeat, detection, removal and saved-run recovery test.
The current Hyper-V guest did not complete the installer scenarios, so do not
infer support from Docker Desktop's own Windows compatibility or a successful
installation outside RIDE. The package remains plannable for migration work;
its local `NeedsReview` marker is separate from this technical acceptance gate.

The default `per-user` variant installs for the current standard user without
elevation; the `all-users` variant installs machine-wide from elevated
PowerShell. Both use the official pinned Docker Desktop installer. RIDE does not
configure WSL or a backend, accept Docker's terms, start the application, or
create containers. Removal passes Docker's `--keep-data` option. Confirm Docker's
applicable license and Windows/WSL prerequisites before use. If Docker Desktop is
already installed, select its matching variant; RIDE detects it as present and
does not claim an earlier installation in a saved run.

Preview either variant without changing Windows state:

```powershell
.\ride.ps1 install package.docker-desktop -WhatIf
.\ride.ps1 install package.docker-desktop -Variant all-users -WhatIf
```

Do not apply the plan or remove `-WhatIf` until RIDE acceptance completes and the
catalog declares a supported target. Use the same variant when later checking
status or removing the package. The user reports that WinGet installed the latest
Docker Desktop on a physical computer; this is publisher-installer evidence only.
RIDE's state capture, repeat detection, saved-run recovery and keep-data uninstall
still need acceptance. The earlier disposable Hyper-V runs timed out and do not
establish a package failure on supported physical Windows hardware. See the
[acceptance record](migrations/application-migration-review.md#docker-desktop-focused-all-users-setup-and-interrupted-retry-2026-10-20).

The [approved deployment decision](migrations/package-deployment-decisions.md)
of 2026-10-14 allows future workstation installation, separate portable copies
and acquisition USB/toolkit assembly to coexist under one product ID, with
independent ownership and recovery. Explicit named selection and adoption/replacement
requirements were accepted on 2026-10-17; state migration, live lifecycle,
product conflict checks and kit acceptance remain pending. The examples in
this guide describe the current single-selection behavior. See the migration
ledger for current implementation authorization and pending acceptance.

Profiles select a distribution on the package entry:

```powershell
@{ SchemaVersion = 1; Name = 'Optional portable tools'; Operations = @(
  @{ Id = 'package.sharex'; State = 'Present'; Variant = 'portable' }
) }
```

Groups retain their catalog ordering and use package defaults. Select alternate
variants on individual package entries. Group removal reverses dependency order.

## Catalog package prerequisites

Install and profile plans expand declared `PrerequisitePackageId` chains before
their consumers, including packages that provide a required executable or a
versioned Windows system DLL. Preview shows each prerequisite's dependent
package and requirement. Shared prerequisites are deduplicated. A sufficient
installed prerequisite remains visible in the plan and is skipped as already
present. If its registration says it is installed but the declared file or
minimum version is missing, planning stops for review. Install confirmation and
saved-state capture remain per package; restore removes newly installed ordinary
prerequisites when possible and retains a newer in-place shared runtime when the
prior version cannot be restored exactly.

Removing a prerequisite is refused while an installed catalog-tracked dependent
remains. A profile that removes both orders dependents first. Offline plans use
the same declared package closure and ordering and require every needed package
payload to be present in the selected bundle, with no network fallback. Package
or DLL prerequisites without a declared package ID are rejected during catalog
validation.

## ImageMagick portable Q16

`package.imagemagick-portable-q16` selects the publisher's 7.1.2-34 Win64
static Q16 archive, documented as portable and requiring no installer or registry
changes. RIDE stages it under its owned tools directory without changing PATH,
running commands, or selecting optional integrations. The exact archive was
acquired from the official release URI and is pinned to SHA-256
`52cc6a441c7884f5ff4274b410c9b90c4b7d54245dcdf4d32988bb4e4df4e5d1`. The
publisher's detached signature was acquired but has not been independently
verified. The package is supported on Windows 11 after lifecycle, exact recovery
and bounded feature acceptance. Windows Server is not supported by that result.
The user/company license record is `NeedsReview` with owner Unassigned; this does
not assert entitlement. Keep the license text and attribution supplied in the
archive.

The package requires Microsoft's x64 Visual C++ v14 runtime (`vcomp140.dll`).
RIDE inserts [Microsoft Visual C++ v14 Redistributable
(x64)](#microsoft-visual-c-v14-redistributable-x64) before ImageMagick when the
catalog prerequisite closure is planned. If version 14.50.35710.0 or later is
already installed, the plan shows the prerequisite and skips its installation.
The RIDE-managed package passed install, repeat, removal and saved-run recovery
on Windows 11 build 26300; the catalog supports Windows 11. Recovery guarantees
runtime presence but cannot restore a previously installed older v14 version, so
RIDE does not attempt an unsafe downgrade. Windows Server acceptance remains
open. Removing ImageMagick does not remove the shared runtime. RIDE also refuses
to remove that runtime while ImageMagick remains installed. ImageMagick 7.1.2-34 Q16
lifecycle, exact recovery and bounded synthetic 1x1 PNG feature checks passed on
Windows 11 build 26300. No user image was opened.

## Microsoft Visual C++ v14 Redistributable (x64)

`package.vcredist-v14-x64` provides the current Microsoft Visual C++ v14 x64
shared runtime for applications built with Visual Studio 2017 through 2026. The
catalog pins version 14.51.36247.0 and its SHA-256, and uses Microsoft's stable
latest x64 link as the source. The pinned digest makes acquisition fail closed if
Microsoft changes the bytes at that link before RIDE's pin is refreshed.

The package is intended for dependency-driven use, not as a request to install
every historical VC++ package. ImageMagick declares it as a prerequisite, and
RIDE expands the dependency closure into normal install and profile plans.
ImageMagick needs at least 14.50.35710.0; RIDE considers a later registered v14
runtime sufficient.
Microsoft documents the v14 family as cumulative and in-place, while
redistributables from 2013 and earlier remain side by side. The x86 and ARM64
runtimes, and those older families, are outside this initial v3 package scope.

The RIDE-managed v14 x64 package passed two serialized Windows 11 lifecycle runs
on build 26300: install, minimum registered/runtime-DLL version, repeat install,
removal, repeat removal and saved-run recovery. Its remaining acceptance limit is exact
recovery of a previously installed older runtime version; RIDE restores presence
with the catalog-pinned current runtime instead of downgrading. Windows Server
support remains undeclared. See the [dated acceptance evidence](archive/evidence/vcredist-applicationsbatch5-win11-acceptance-2026-10-24-1642.json).

RIDE installs with `/install /quiet /norestart`. The package is marked pending
RIDE package lifecycle acceptance. Its installer and signature were verified in
the disposable Windows 11 ImageMagick acceptance run; a RIDE-managed runtime
install/remove/recovery cycle has not yet been accepted. Explicit removal can
affect other applications using the shared runtime. Keep a suitable v14 runtime
installed while any dependent application needs it. The focused RIDE lifecycle
batch is `ApplicationsBatch5`; it runs on the registered Windows 11 VM, preserves
an already adequate checkpoint runtime or installed catalog dependents, and
otherwise checks RIDE install, repeat, removal and saved-run recovery before
restoring the checkpoint. See the
batch procedure in [integration testing](../tests/integration/README.md#existing-application-suites).
See Microsoft's
[latest supported downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist),
[redistribution guidance](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files),
and [license terms](https://visualstudio.microsoft.com/license-terms/). See the
[approved v3 prerequisite work](migrations/application-migration-review.md#catalog-driven-package-prerequisites-approved-for-v3-2026-10-24).

Portable SevenZip packages use only the Microsoft-signed Windows inbox
`System32\tar.exe`. RIDE validates the full path listing and verbose file types
before extraction, rejects unsafe paths, links, duplicates and special files,
limits archives to 10,000 entries, 512 MiB per file and 2 GiB total, bounds each
tar process to five minutes, then verifies the staged file set and lengths before
writing to the package directory. The common portable manifest owns installed
files and supports exact saved-run recovery. Detached signature verification,
activation and Server acceptance remain open. See the dated
[candidate and extraction evidence](migrations/application-migration-review.md#imagemagick-portable-q16-sevenzip-lifecycle-implementation-2026-10-22)
and [Windows 11 acceptance evidence](migrations/application-migration-review.md#imagemagick-portable-q16-windows-11-acceptance-2026-10-23).

## Named deployment identity preparation

The optional metadata API in `modules/RIDE.DeploymentIdentity.psm1` prepares and
selects named identities without reading installed applications or state stores.
It is not wired into the install/remove commands above. It cannot reserve a name,
adopt files, create a kit or authorize a package change.

From the repository root in Windows PowerShell 5.1 or PowerShell 7, no elevation
is needed for this supplied-data example:

```powershell
Import-Module .\modules\RIDE.DeploymentIdentity.psm1
$resolved = @{ Id='package.sharex'; PackageId='sharex'; Kind='Package'
  SelectedVariant='portable'; Scope='Machine' }
$identity = New-RidePackageDeploymentIdentity -Operation $resolved -DeploymentId sharex-field
Get-RidePackageDeploymentIdentity -Records @($identity)
Resolve-RidePackageDeploymentIdentity -Records @($identity) -DeploymentId sharex-field
```

Use explicit already-resolved metadata; the API does not resolve a catalog default,
read preferences or verify that this example is deployable. User scope requires
the intended canonical numeric `-UserSid`; machine scope carries no user SID.
An optional library ID stays distinct from built-in identity. Names are lowercase
letters/digits/hyphens, start with a letter and have at most 64 characters;
reserved Windows device names are rejected. Names are identifiers, not paths.

Inspection retains every supplied deployment. Selection accepts a deployment ID
or an operation ID with exactly one match. Multiple copies, variants, scopes or
owners require an explicit deployment ID; a default distribution never resolves
that ambiguity. Both selectors together must agree. Unknown selections fail
without fallback. Operation/deployment completion uses only the supplied validated
collection, filters without case sensitivity and quietly returns nothing when
optional data is unavailable. The complete collection is limited to 4096 records;
duplicate names are rejected even across different products, owners or libraries.

Schema-1 `PackageDeploymentIdentity` objects always have `ReadyForMutation=false`.
They are preparation metadata, not ownership or recovery evidence. Existing
PackageSelections schema 1 and saved operation schemas 1/2/3 remain unchanged;
old records are refused by this new API rather than silently renamed. Future
integration must preserve those original records through an explicit versioned
mapping, collect all relevant stores, and refuse treating inaccessible stores as
empty. No recovery action is necessary for this in-memory API. See the
[implementation record](migrations/application-migration-review.md#b07-explicit-deployment-identity-preparation-2026-10-17)
for validation and remaining integration steps.

## Prepare a legacy selection mapping

`RIDE.LegacyDeploymentMapping.psm1` provides a data-only compatibility step for
an existing PackageSelections schema-1 record. Supply the parsed legacy record,
an explicit new deployment name, trusted expected base operation and expected
Machine/User store scope. User scope also requires its intended canonical SID.
No elevation, registry lookup or package execution occurs:

```powershell
Import-Module .\modules\RIDE.LegacyDeploymentMapping.psm1
$mapping = New-RideLegacyDeploymentMapping -Selection $oldSelection -DeploymentId example-workstation -ExpectedOperation $catalogPackage -ExpectedScope Machine
$originalLogicalRecord = Get-RideLegacyDeploymentSelection -Mapping $mapping
```

The expected operation checks stable product/library identity only. Its current
default variant, scope or destination does not replace the saved selection.
Retired saved variant IDs, original paths and unknown literal fields remain in
a deep copy. The reverse API checks identity consistency and returns a separate
copy; it does not write a state file or invoke the engine. Schema-3 run snapshots
are a separate format and are refused here.

This is a version-1 logical mapping with ReadyForMigration=false and
OriginalFileBytesPreserved=false. Keep the original file: this API does not read
or archive its bytes, authenticate the store/owner, reserve a unique name or
guarantee durable recovery. Parsed data must contain only bounded literal values;
unsupported objects are refused without altering the source. Before any actual
state migration, add strict byte-preserving input, complete store identity,
exclusive name reservation, journaling and interrupted-commit recovery. Existing
selection indexes and saved runs continue through the existing engine unchanged.
See the [compatibility evidence](migrations/application-migration-review.md#b07-legacy-selection-mapping-preparation-2026-10-17).

## Observe existing installation registrations

Use `tools/Export-RideInstalledRegistrationInventory.ps1` to prepare adoption
review data without running package detection handlers, installers or uninstallers.
From the repository root in native Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\tools\Export-RideInstalledRegistrationInventory.ps1 -Scope Machine,User -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -ExpectedUserSid '<intended-account-SID>' -ExpectedSessionId 1 -OutputPath C:\Evidence\registrations.json -WhatIf
```

Supply independently checked target/account/session values and an existing output
directory. Run as the intended interactive account with access to the selected
roots; no automatic elevation occurs. WhatIf collects nothing and writes nothing.
Remove WhatIf only for the intended read-only observation. Scope completes from
Machine/User; the current user is the executing account, not another loaded profile.

The JSON contains a separate source for each selected scope and native registry
view: Registry64 and Registry32 on a 64-bit OS, Registry32 on a 32-bit OS. This
view handling does not extend declared package target support. Each source is
Captured or Unavailable; a missing root is Captured with RootExists=false and an
empty Entries array. An inaccessible, malformed or interrupted source loses its
partial rows and remains Unavailable, while independent sources can complete.
Do not treat that source as evidence that a package is absent.

Each registration retains its literal key name plus DisplayName, DisplayVersion,
Publisher, InstallLocation, WindowsInstaller and SystemComponent, with explicit
presence/type/data. ExpandString paths stay unexpanded; unknown DWord bits remain
numeric. Up to 2048 entries per source and 4096 characters per string are retained.
Identical names in different views remain separate observations because shared or
reflected registrations need explicit reconciliation. No uninstall command is
captured or executed; no Win32_Product query, executable scan or repair occurs.

Check every source status and the complete machine/build/edition/user/session
context before review. Registrations can be stale, ambiguous or forged; a name,
publisher, version or path is not proof of product identity, installed health,
architecture or file ownership. This first slice does not discover other users,
portable trees, Store apps or service-only packages. Use the separate offline matching API below for catalog review; this inventory
itself is not an adoption plan. A schema-1 InstalledRegistrationObservation
always has ReadyForMutation=false and RecoverySupported=false.

The output is created exclusively; an existing/racing file is retained. On a
write failure preserve any partial output and choose a new name. Store the JSON
appropriately because it can contain user paths and installed-product metadata.
No Windows recovery is needed for observation. Before adoption, add complete
catalog matching, per-match ambiguity resolution, ownership and exact live
revalidation; replacement requires separate backups and recovery guarantees.
See the [batch record](migrations/application-migration-review.md#b07-installed-registration-inventory-2026-10-17).

## Review registrations against the catalog

After collecting an observation on the intended target, review its saved data
without querying Windows again. From the repository root, no elevation is needed:

```powershell
Import-Module .\modules\RIDE.CatalogData.psm1
Import-Module .\modules\RIDE.PackageAdoptionReview.psm1
$catalog = Import-RideCatalogData .\catalog\operations.psd1
$observed = Get-Content -LiteralPath C:\Evidence\registrations.json -Raw | ConvertFrom-Json
$review = Get-RidePackageAdoptionReview -Catalog $catalog -Inventory $observed -Target 'Windows 11'
$review.Rows | Select-Object OperationId,Variant,Scope,Status,ReadyForAdoption
```

Use a validated catalog and the intended target label. Target completes from that
catalog, including variant declarations. The explicit label is not proof that
the supplied observation came from a supported Windows target. All rows retain
ObservedTargetVerified=false and ReadyForAdoption=false.

| Review status | Meaning and next step |
| --- | --- |
| SingleCandidate | One provisional name match in complete scope/view observations. Verify product, version, architecture/channel, location and ownership before adoption. |
| Ambiguous | Multiple registrations match, or the registration also matches another distribution. Resolve this row individually; unrelated rows remain reviewable. |
| NoMatch | No name match in the supplied complete source views. This does not prove software is absent from the machine. |
| IncompleteSources | A required scope/view is missing or unavailable. Existing matches remain visible, but uniqueness and absence cannot be concluded. |
| TargetNotDeclared | The distribution does not declare the requested target; a matching name does not expand support. |
| NotCovered | Portable, service-only or other distributions need their own identity provider. |
| ReviewFailed | Invalid metadata or bounded matching failure; inspect the distribution before retrying. Other distributions still report results. |

The review uses the existing variant resolver's new `-MetadataOnly` switch to
avoid local preferences, destination expansion and configuration reads. Direct
resolver Variant completion uses the supplied operation. MetadataOnly results
must not be passed to an installer: they are not operational selections. Normal
resolver behavior and the main RIDE commands remain unchanged.

Matching is case-insensitive and culture-invariant, with a 50 ms regex timeout
and two-second scan budget per distribution. Saved observations are copied and
validated before matching; unavailable sources cannot retain partial rows.
Registry paths and values are never executed. Nothing is selected for adoption,
replacement or upgrade merely by generating this report. An adoption plan still
needs explicit operator selections, complete live revalidation and supported
ownership/recovery guarantees. Review requires no rollback; original observations
and existing RIDE state records are unchanged. See the
[implementation evidence](migrations/application-migration-review.md#b07-offline-package-adoption-review-2026-10-17).

## Prepare toolkit file-update decisions

`RIDE.ToolkitUpdatePreparation.psm1` implements the accepted staged-update file
rules in memory. It compares a prior ownership manifest, desired content and a
complete observation; it does not collect files, publish a toolkit or delete data.
From the repository root in native PowerShell, no elevation is needed:

```powershell
Import-Module .\modules\RIDE.ToolkitUpdatePreparation.psm1
$preparation = New-RideToolkitUpdatePreparation -KitId field-kit -Root C:\Kits\Field -PreviousManifest $previous -DesiredManifest $desired -Observation $observed
$preparation.Decisions | Select-Object RelativePath,Action,Reason,RequiresExplicitDecision
```

The two schema-1 ToolkitOwnedFiles inputs contain KitId and Files, with exact
RelativePath, Sha256 and Length for every managed file. Pass explicit null for
PreviousManifest only when preparing a first publication. These are owned-file
records, not complete product/artifact/license manifests or proof of provenance.

The schema-1 ToolkitFilesystemObservation must supply the same explicit Root,
Complete=true, CaseSensitive=false, RootIsReparsePoint=false and Entries with
RelativePath/Kind. File rows require Sha256/Length; Directory, ReparsePoint and
Unavailable rows carry null digest/length. A future collector must establish those
facts; setting the flags manually does not authenticate an observation. Both
manifests and observations are bounded to 32768 entries each.

| Action | Meaning |
| --- | --- |
| StageAdd | Desired path is unoccupied and unowned; stage and verify content before any commit. |
| StageReplace | Existing owned content still matches its prior digest/length; stage the replacement first. |
| Keep | Existing owned content already matches the desired content; no replacement. |
| RemoveOwnedUnchanged | Obsolete owned file still matches its prior digest/length; removal can only follow verified staging and live commit guards. |
| ForgetAbsent | Obsolete owned file is already absent; no filesystem deletion. |
| PreserveUnmanaged | Unrelated file or directory remains outside ownership. |
| Conflict | Requires a later explicit decision or corrected evidence; no implicit overwrite, deletion or adoption. |

Modified managed files, modified obsolete files, missing desired managed files,
unowned collisions and unsafe ancestors are conflicts. An unowned file with the
same desired hash is still not automatically adopted. Unrelated files and generated
data are retained. A file already at the desired content is kept, even if the old
manifest expected another version. All comparisons include byte length and digest.
Path checks reject traversal, absolute member paths, alternate streams, reserved
names, ambiguous trailing dots/spaces and case-colliding members. Reparse/unavailable
ancestors and observed descendants block replacement; no directory tree is owned
merely because a child file appears in a manifest. Case-only spelling changes do
not request a rename.

Root is a selected host subdirectory, including an eligible UNC subdirectory,
without USB enrollment or physical-volume tracking. ReadyForPublication and
RecoverySupported remain false even when ConflictCount is zero. Before a writer
uses these decisions it must authenticate ownership and exact artifact/source/
license notices, collect fresh complete filesystem evidence, verify staging and
implement journaled commit/interruption recovery. Modified-file answers cannot be
inferred from silence. Keep original manifests/observations; this API needs no
Windows rollback. See the [validation record](migrations/application-migration-review.md#b07-toolkit-owned-file-update-preparation-2026-10-17).

## Wireshark machine MSI candidate

`package.wireshark` offers the official pinned 4.6.9 x64 MSI as a pending installed
distribution. It has no supported targets and appears in no selection profile.
The user selected all-user installation while preserving capture-file associations;
choosing Wireshark as the default capture-file application remains a separate
explicit action. The candidate passes `/qn /norestart WIRESHARK_FILE_EXTENSIONS=0`
to the existing MSI handler, with compensating package recovery rather than an
exact backup of all application state.

The acquired 80,433,152-byte MSI matches the publisher's SHA-256 and carries a
Valid Wireshark Foundation Authenticode signature. Its read-only database declares
ALLUSERS=1, x64 architecture and product version 4.6.9.0. The 116 class-registration
rows belong to 29 components conditioned on WIRESHARK_FILE_EXTENSIONS being 1.
Disabling that property is a source-verified candidate; actual existing default
association preservation still requires native checks. The publisher's checksum
file includes a PGP signature, which was not verified in this run. Source/reference
and table evidence are [retained separately](archive/evidence/wireshark-msi-source-review-2026-10-17.json).

The MSI includes application notices and Visual C++ runtime merge-module files.
It contains no Npcap/USBPcap installer. Live capture remains the separately selected
interactive Npcap workflow, retaining administrator-only access. Q16 now selects
WinPcap compatibility off by default; enabling it needs explicit selection and
preview of replacement of any existing WinPcap installation. The Wireshark candidate
does not implement or execute that driver workflow.

The publisher labels its WiX installer experimental and warns about transitions
between NSIS and MSI installations. The inspected MSI launch conditions refuse
detected NSIS installations. Do not remove or convert an existing installation to
force eligibility. Existing MSI upgrades, global plugins/profiles, user settings,
shared runtime ownership, reboot reporting and uninstall/recovery all need their
own disposable evidence. Catalog discovery/download is preparation, not acceptance.

For review, start in the repository root in native PowerShell:

```powershell
.\ride.ps1 show package.wireshark
.\ride.ps1 download package.wireshark -WhatIf
```

Do not bypass the pending-target gate. Next acceptance must seed unrelated file
associations and global/user content, install/repeat/remove, verify those values
and files unchanged, retain MSI/recovery evidence and test partial failures. Test
Npcap separately with explicit interactive choices and captured prior driver state.
No installer or driver ran during this source batch. See the [dated record](migrations/application-migration-review.md#b08-wireshark-machine-msi-candidate-2026-10-17).

Official references: [Windows installation](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallWinInstall.html),
[WiX transition limitations](https://gitlab.com/wireshark/wireshark/-/blob/v4.6.9/packaging/wix/README.adoc),
[association conditions](https://gitlab.com/wireshark/wireshark/-/blob/v4.6.9/packaging/wix/ComponentGroups.wxi)
and [publisher checksums](https://www.wireshark.org/download/SIGNATURES-4.6.9.txt).

## Local configuration

Configuration is optional, data-only and never generated into release defaults.
Machine configuration is `%ProgramData%\RIDE\configuration.psd1`; current-user
configuration is `%LocalAppData%\RIDE\configuration.psd1`. Files are at most
64 KiB and unknown fields fail validation. Machine configuration may contain:

```powershell
@{
  SchemaVersion = 1
  ToolsDirectory = 'D:\Tools'
  PackageVariantPreference = 'portable'
}
```

The user file may contain `SchemaVersion` and `PackageVariantPreference`.
`ToolsDirectory` belongs to machine scope and defaults to
`$env:SystemDrive\Tools`. It must be an absolute local path below a drive root.
RIDE deploys each product beneath `<ToolsDirectory>\<PackageId>` and rejects
reparse-point paths. Portable deployments require elevation. Changing this
configuration does not move an existing installation: its saved selection
retains the original root. Conflicting saved scopes require individual review.

## Acquisition and ownership

Thunderbird's current-user Release x64/en-GB selection resolves to
`%LocalAppData%\Programs\Mozilla Thunderbird` during planning. Run its install,
remove and restore commands from non-elevated PowerShell: Mozilla's elevated
installer otherwise attempts machine registration. Preview remains available.
RIDE rejects conflicting editions and unowned destinations and preserves the
Roaming mail-profile directory during removal. See the
[Thunderbird validation record](archive/migrations/application-thunderbird-follow-up-2026-10-11.md)
for target acceptance and recovery limits.

Shared sources resolve one exact release asset from official HTTPS metadata.
VS Code binds its update response to the supplied SHA-256. Mozilla resolves a
versioned release path and its exact architecture/locale SHA-256 checksum entry.
Existing Firefox retains x64/en-US; optional `MozillaLocale` preparation does
not change that published default. Signal binds the official stable x64 update
feed's version, filename and matching file/release SHA-512 entries. PuTTY binds its
versioned standalone download to the publisher's architecture-specific checksum.
Publisher pages must select exactly one asset and
identify its version; GitHub assets remain bound to their declared repository.
Acquisition records retain product/license references, provider, variant,
version, SHA-256 and available publisher checksums/signatures. A published
digest mismatch stops installation. An observed hash alone is not publisher
authentication; see the [verification matrix](package-verification-matrix.md).
Published detached signature links are recorded; detached cryptographic
verification requires a separate trusted-key workflow. Publisher metadata calls
have a two-minute timeout and payload transfers have a thirty-minute timeout.
Failed transfers remove their temporary bytes rather than reuse a partial cache.
License approval remains in the independent local review store.

Pinned `DirectHttps` portable archives declare a version, artifact name and
`ExpectedSha256`. NetworkMiner 3.2 uses the checksum published beside its
fixed-version download. Caffeine 1.98 uses an inspected archive hash because
its publisher supplies a mutable ZIP without a published checksum. Changed
bytes stop acquisition and require catalog review; these entries do not claim
automatic latest-version discovery. `Architecture = 'neutral'` is supported
only for portable ZIP distributions, including managed assemblies and mixed
x86/x64 archives. It does not establish application runtime compatibility.

Portable payloads are copied, never run. ZIP and 7z extraction reject traversal,
absolute paths, streams, reserved device names, duplicate paths, links and
oversized archives. 7z extraction requires the Microsoft-signed Windows inbox
tar executable, rejects links and special file types, and is bounded by member,
unpacked-size and process-time limits. Whole-archive deployment retains all
supplied files, including notices.
Required files must exist before product writes. RIDE refuses unowned filename
collisions and never adopts an arbitrary pre-existing installation.

An optional `PortableMembers` array limits a pinned ZIP to exact reviewed file
paths. It requires `ExpectedSha256`, contains every `RequiredFiles` entry, and
cannot contain wildcards, directory entries or duplicate Windows paths. Every
selected file must exist before product writes. The handler still validates
unselected archive paths, links and declared size limits. Omitted files are not
staged or owned; packages without this field keep whole-archive behavior. Review
the generated [selected-member lists](OPERATIONS.md#selected-portable-zip-members)
and retain all notices applicable to the selected files. The complete original
archive remains in acquisition/recovery storage; selection does not remove its
other contents or establish permission to redistribute that archive. Exact
PortableMembers selection is currently limited to ZIP packages.

The pending NTCore candidates are independently owned portable copies: PE Detective
includes Signature Explorer and five signature databases; standalone x86 CFF Explorer
selects its executable and five databases, omitting SDK installers, example scripts
and the UPX extension. It does not replace the installed Explorer Suite. Publisher
pages describe freeware; the inspected archives contain no separate license file.
Embedded copyright is preserved, and shared-kit rights need their own assessment.
Neither candidate launches a tool, scans or patches files, refreshes signatures,
registers extensions, or changes PATH. Native acceptance is still pending, so no
supported apply target or profile selection is added.

The pending MiTeC JSON Viewer and XML Viewer candidates each use one pinned
publisher archive. The `portable` variant selects its x64 executable;
`portable-x86` selects its x86 executable. Both remain pending Windows 11
acceptance. Licence tiers are not separate package identities: these candidates
do not activate the software, inspect licence keys, open documents or launch
update checks. Unowned licence/configuration files are preserved by file ownership
rules; real activation preservation still needs disposable-target evidence.
Read the product's [MiTeC EULA](https://www.mitec.cz/wp/support/) and licence-tier
information before use. The archives contain no separate licence file; embedded
copyright remains intact. Structured Storage Viewer is separately under review
because codec plugins, samples and existing R13 ownership need reconciliation.

The product's `.ride-package.json` records owned relative paths and hashes,
version, variant and artifact evidence. Missing or modified owned files make
the installation unhealthy. Upgrades reject modified owned files. Removal
deletes matching owned bytes, preserves modified files, application data and
unowned content, and leaves the tools root intact. Preserved modifications are
reported; installing again over those files requires an individual decision.
An interrupted copy normally retains an `Installing` ownership journal and a saved
run. Manifest commit failures require the separate review below.

## Saved state and recovery

Package records now use schema 3 to retain the resolved operation, source,
scope, variant, destination and recovery contract. Schemas 1 and 2 remain
readable. A scope-local `State\PackageSelections` index preserves the selection
for subsequent removal/inspection and partial-failure handling. It is separate
from license reviews and acquisition observations.

Portable snapshots retain exact owned bytes and their captured hashes under
the saved run. Restore validates every backup and collision before writing,
uses the saved destination and preserves newer user changes. Missing recovery
bytes are an explicit failure; RIDE does not download a newer release and call
that exact recovery. Restoring original absence removes matching owned bytes
while preserving user files. Application data outside the ownership manifest
is not a backup and is never removed by this handler.

Ownership manifests use atomic replacement on success. Installation and restoration
write an incomplete ownership journal before copying files, so a partial copy
remains recognizable and can be retried from retained recovery bytes.

### Manifest commit failure

If committing `.ride-package.json` fails, stop further changes to that product.
Preserve the saved run, current product directory and any
`.ride-package-<id>.tmp` path reported in the warning. The staged file is evidence,
not an automatically accepted ownership manifest. It can describe a proposed
copy that never happened; Windows replacement failure can also leave the old
manifest absent. Compare both journals with actual file hashes and saved backup
bytes before choosing recovery. Do not rename a temporary journal into place,
delete retained evidence or reinstall to clear the error without that review.

The writer retries sharing/lock errors 32/33 and replacement error 1175 at most
twice, after 50 and 100 milliseconds. Each retry requires both files to remain
present, unchanged by SHA-256 and free of reparse-point paths. Other errors,
including partial-replacement errors 1176/1177, stop immediately. Remaining staged
bytes are retained on failure. This does not provide concurrent-writer isolation;
serialize operations for a product. See Microsoft's
[ReplaceFile failure states](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew).

Conventional EXE/MSI recovery remains compensating. Restoring original absence
uninstalls the selected product; recovering a previously installed product may
reinstall the declared source and reports that exact prior-version recovery is
unavailable. Driver, reboot, licensed and interactive workflows remain review
items until their separate scenarios are established.

`UninstallerType` optionally declares `Exe` or `Msi` when the registered removal
mechanism differs from the installer format. Firefox's MSI wraps its installer;
removal uses the registered `uninstall\helper.exe /S`, as documented by
[Mozilla](https://support.mozilla.org/en-US/kb/silently-install-uninstall-firefox-enterprise).
Packages without this override retain their existing removal behavior.

Signal's upstream installer declares deletion of application data on uninstall.
The current-user package therefore declares `PreserveRoamingDirectory = 'Signal'`
and `PreservationProcessName = 'Signal'`. RIDE refuses removal while Signal is
running. Before invoking its uninstaller, RIDE renames an existing Roaming
`Signal` directory to a unique sibling and writes a recovery journal. It restores
that entire directory, including unowned files, after success or failure. It
refuses reparse-point roots and never overwrites a newly created destination.
An absent profile is not created or adopted. This protects existing data during
package removal; it does not back up application data against other changes.

If interrupted or restoration fails, preserved data and its journal remain at
`%AppData%\.Signal.ride-preserved-<id>` and the corresponding `.json` path.
Another removal refuses these unfinished backups. Review `OriginalPath` and
`PreservedPath` in the journal, close Signal, and reconcile any destination
collision before restoring the directory. Do not delete either copy to clear
the blocker. Profile preservation is tested separately from account linking,
message synchronization and application UI behavior. The upstream behavior is
declared in [Signal's release configuration](https://github.com/signalapp/Signal-Desktop/blob/v8.30.0/package.json).

Chrome retains the legacy all-user enterprise x64 MSI distribution. Its current
mutable endpoint is pinned to inspected version 155.0.8059.40 and SHA-256; this
pin is observed identity evidence, not a publisher-published checksum. Different
bytes require review. Removal retains browser profile data in the lifecycle
scenario; browser language and policy configuration remain separate decisions.

## WinSCP portable acquisition

`package.winscp` retains the legacy stable portable distribution in the configured
machine tools directory. `WinSCPPortablePage` resolves its pinned, durable
publisher page to one fresh CDN URL and one SHA-256. The catalog never embeds an
expiring download link. Unexpected metadata or mismatching bytes stop acquisition.
The complete four-file archive retains its license/readme; the publisher's stable
build is x86 and supports x64 Windows. Experimental x64 releases are separate
choices. See [publisher requirements](https://winscp.net/eng/docs/requirements).

Ownership excludes `WinSCP.ini`, user session files and existing registry settings.
Removal/recovery preserve them. Deployment does not launch WinSCP, create
connections or change configuration storage. Users may select an explicit writable
INI path as described in the [portable guide](https://winscp.net/eng/docs/portable);
machine deployment does not grant write access to the tools directory.

## Pinned Python source candidates

`package.hex2text` and `package.chromeparser` are optional pending source-only
distributions. Each retains the complete three-file upstream archive: script,
README and license, under its commit-named root. RIDE stages files with the existing
portable handler; it does not execute Python, install an interpreter, add PATH or
file associations, or scan browser/evidence data. Both have Windows 11 candidate
targets only, empty supported targets and no recommended profile inclusion.

| Candidate | Source and observed archive SHA-256 | Runtime/function boundary |
| --- | --- | --- |
| Hex2text | gh05t-4/hex2text revision `9715c6c26824ef05039228f16e0c47620c52fe79`; `aa0083da094a3320db9a97eb22c499a420187c208ed92376a662243678f083c3` | A prompted converter with no imports: removes literal spaces and maps each complete four-digit hexadecimal group to one Unicode code point. Five synthetic-input probes confirmed incomplete-suffix loss, uncaught `ValueError`, U+0001 output and strict UTF-8 `UnicodeEncodeError` for an isolated surrogate. It is not a UTF-8 byte decoder. Windows console behavior and managed-file lifecycle remain pending. Retain GNU GPL v3 license and source. |
| ChromeSyncParser | marleyjaffe/ChromeSyncParser revision `0f59c5702ffd03102c550ecc373ab4fefa6f810c`; `8dff59a48d3d6ab41cf8d39154a0e05cfda5df36a1b76180a70692762854da46` | Historical Chrome SyncData/metas parser, using Python's standard library including sqlite3. Ordinary SQLite connections do not guarantee read-only forensic handling. Current Chrome schema, output correctness and input protection remain unverified. Retain MIT copyright/license. |

Both pinned scripts parse under Python 3.12.14. Hex2text was additionally run
with synthetic input only; this does not verify Windows console behavior or
managed-file lifecycle. Choose and validate an interpreter separately before
use. RIDE does not point these scripts at live profiles or evidence.
ChromeSyncParser can search historical user-profile paths and overwrite a
requested output file.
Static review of the pinned ChromeParser.py (SHA-256
7f8f8d7f4c29c9bd66f1645da47d2a449381896f48c3629a8c71e79e8b705384) found
additional blockers: its default Windows discovery branches only on platform
releases 7 and XP, so Windows 10/11 reaches glob.glob(databasePath) without
assigning databasePath; the README's Vista-or-later path also differs from the
code path. sqlite3.connect opens the selected database without read-only URI
mode. The -f output is opened with "w" before database discovery/open, which
truncates an existing output and can destroy the database if the same path is
supplied for both input and output. Do not execute this source against live
profiles or evidence. No parser/runtime, SQLite, browser-profile, or output-file
test was run. Future runtime acceptance must use disposable synthetic/copied
data and separately establish read-only input and non-overwriting output
behavior. A successful managed-file lifecycle cannot prove parser correctness
or modern application support.

All declared files are required before staging, so the legacy script-only payload
is rejected. The handler preserves unowned reports and operator files, refuses
replacement of modified owned scripts, and retains modified content during removal.
Saved-run restore requires retained backups and recovers only owned files. It cannot
undo code execution, data access or output changes. New revisions use a new nested
root; review any custom data migration instead of assuming it follows automatically.

See the [source observation](archive/evidence/python-script-source-review-2026-10-16.json)
and [batch record](migrations/application-migration-review.md#b08-pinned-python-source-candidates-2026-10-16)
for integrity, test and acceptance evidence. ShimCacheParser is still deferred:
the inspected publisher script uses Python 2 syntax and cStringIO. No Python 2
installation, unreviewed port, replacement parser or retirement is selected.

## Python install-manager runtime source review

The accepted `InstallPython` direction uses the Python install manager by default
and retains a traditional installer route. RIDE-managed runtimes must be selected
by exact version, implicit runtime downloads disabled, and updates kept separate.
The current official release sources expose manager 26.4 and PythonCore runtime
manifests for 3.15.1, 3.14.9 and 3.13.17. These are source candidates, not catalog package
IDs or supported-target claims. Publisher SHA-256 values, exact runtime tags and
URLs are retained in the [dated source evidence](archive/evidence/python-managed-runtime-source-review-2026-10-24-0355.json). The traditional full installer is deprecated since Python 3.14 and is scheduled to stop with 3.16.

The manager's documented per-user `pymanager.json` can set
`automatic_install` to `false`; the default is `true`. Its `py install --download`
command creates an offline index, and `py install --source=<local index>` installs
from that index without network access. The catalog candidate
`windows.python-manager-automatic-install` in [the generated operation catalog](OPERATIONS.md)
owns the environment-variable route; a managed JSON config file or generated
offline index would need its own lifecycle. The manager itself
automatically updates within a day of each release. The publisher MSIX is
recommended, while its MSI is machine-only, attempts a system PATH change, and
does not make managed runtimes machine-wide. The Store and python.org MSIX
variants cannot be installed together. The manager also owns `python`, `py` and
versioned global aliases, so existing launcher and command-resolution conflicts
must be previewed and preserved before activation.

The catalog now includes the pending setting candidate
`windows.python-manager-automatic-install`, which sets the current user's
`PYTHON_MANAGER_AUTOMATIC_INSTALL` environment value to `false` and restores the
prior literal value on saved-run recovery. It does not alter already-running
shells; Windows must propagate the updated user environment to new manager
processes. The setting has no supported targets until native acceptance. See the
[implementation evidence](archive/evidence/python-manager-auto-install-setting-implementation-2026-10-24-0404.json).
No Python manager or runtime package is registered yet.

No manager/runtime bytes were acquired or rehashed locally, and no candidate was
registered or run. Release branches, architecture, traditional-installer scope,
manager auto-update treatment and command-alias behavior remain implementation
choices. Windows 11/Server acceptance and recovery remain pending VM access.

## RegRipper 3.0 portable candidate

`package.regripper` retains the legacy RegRipper **3.0** product line as a pending
full-distribution candidate. It pins upstream revision
`ec96dd4a6a5c3ea70d8fece9b47a374f83582335` and the inspected archive hash. There are
no supported targets or profile entries; Windows 11 is the first disposable
acceptance candidate. Inspect from the repository root without elevation:

```powershell
.\ride.ps1 show package.regripper
.\ride.ps1 download package.regripper -WhatIf
```

The archive contains 282 files, including 266 plugin/profile files, x86 `rr.exe`
and `rip.exe`, the supplied `p2x5124.dll`, source, README and both license files.
RIDE retains the complete archive layout beneath
`<ToolsDirectory>\regripper\RegRipper3.0-<full revision>`. It does not flatten paths,
extract the nested `rip_bulk.zip`, or execute any included program, script or plugin.
The three inspected PE binaries are unsigned; the pinned hash establishes reviewed
byte identity, not cryptographic publisher authentication. The bundled interpreter
reports a 2011 build. Its current-build/runtime compatibility remains unverified.

The candidate uses manifest-owned file recovery. Unowned analyst reports and custom
plugins are preserved; changed bundled plugins block upgrades and survive removal.
Saved-run restore requires the retained files and refuses conflicting destinations.
A new revision has a different archive-root folder, so custom plugins are not
automatically copied into its folder. Review plugin compatibility explicitly before
moving them; neither pinned source acquisition nor successful extraction proves
forensic parsing quality or equivalence to an installed Perl environment.

Running the GUI/CLI later is separate from deployment. Use copies of authorized
input hives and an explicitly chosen output directory; RIDE does not acquire evidence,
run the `-uP` profile updater, install Perl/Python/YARA or merge transaction logs.
The publisher's [3.0 README](https://github.com/keydet89/RegRipper3.0#readme) describes
compiled Windows tools and notes that transaction logs are not automatically processed.
This observation is not a Windows 11 parser-support declaration.

The candidate does **not** substitute RegRipper 4.0. That line has different
[personal/academic and redistribution restrictions](package-licensing.md#important-to-review-licensing)
and a separate YARA integration. Retain the 3.0 MIT and contributor notices; review
bundled-runtime and distribution obligations independently. See the
[source record](migrations/application-migration-review.md#b08-regripper-30-distribution-candidate-2026-10-16)
for exact hashes, unresolved choices and native acceptance.

## Rufus portable candidate

`package.rufus` is a pending, optional x64 portable candidate pinned to official
Rufus 4.15. No Windows target is supported yet; Windows 11 is the first candidate
for disposable file-lifecycle acceptance. It is outside all profiles. From the
repository root, inspect it without elevation:

```powershell
.\ride.ps1 show package.rufus
.\ride.ps1 download package.rufus -WhatIf
```

Acquisition uses the official versioned `rufus-4.15p.exe` and the inspected SHA-256
pin. The reviewed bytes had a Valid Akeo Consulting Authenticode signature and file
version 4.15.2396. This is dated evidence, not a publisher-published checksum or
automatic latest-version discovery. See the [source review](archive/evidence/rufus-portable-source-review-2026-10-16.json).
The unmodified executable retains its embedded notices; publisher terms are linked
in the catalog. No redistribution or local/company license approval is implied.

After acceptance, the existing portable handler would own only `rufusp.exe` beneath
`<ToolsDirectory>\rufus` plus its RIDE ownership manifest. The stable filename keeps
the `p` that triggers Rufus portable mode. RIDE does not create or own `rufus.ini`,
logs, downloaded images or other user files; removal and exact owned-file restore
preserve them. Existing unowned executable collisions refuse adoption, and modified
owned executables are preserved rather than overwritten. Machine tools deployment
requires elevation and does not grant the user write access to that directory.

Staging never launches Rufus, creates a task/shortcut, changes PATH or touches USB
media. Running Rufus later is an explicit operator action: portable mode does not
promise an untouched registry, and its own updates, downloads, configuration and
media writes fall outside RIDE's file recovery. Saved-run restore cannot undo USB
formatting or recover media contents. The publisher explains the filename trigger,
INI behavior and registry effects in its
[portable FAQ](https://github.com/pbatard/rufus/wiki/FAQ#what-is-the-difference-between-the-portable-and-the-regular-version).

## PSScriptTools source candidate

`package.psscripttools` is an inert 3.2.0 source candidate, pinned to upstream
revision `549fa3e3d769532320054fc0b3c8f42df0452361`. It has no supported production
target and no profile selection. Windows 11 is a candidate for disposable file
lifecycle checks only. From the repository root, inspect and preview acquisition:

```powershell
.\ride.ps1 show package.psscripttools
.\ride.ps1 download package.psscripttools -WhatIf
```

The complete publisher archive retains 360 files, including 75 function files,
manifest, module, types/formats, samples, documentation and MIT notice. Its observed
SHA-256 pin is not a publisher signature or separately published checksum. See
[dated acquisition evidence](archive/evidence/psscripttools-source-review-2026-10-17.json).
Payload inspection parsed only the root manifest/module in both PowerShell
editions; no upstream code was imported or executed.

After acceptance, source would be owned beneath
`<ToolsDirectory>\psscripttools\PSScriptTools-<revision>` with the existing portable
manifest. Machine-scoped staging requires elevation. Repeat staging refuses to
overwrite modified owned files; removal preserves modified source and unowned
analyst files. Saved recovery restores owned captured bytes, not session/editor
state, external dependencies or an editable Git history. The archive has no Git
workspace metadata and no implicit update command.

The accepted Q15 model selects a pinned snapshot for normal deployment; editable
Git workspaces and the publisher's Gallery distribution are separate. It does not
register on PSModulePath, edit profiles, import/type-load anything, install
Microsoft.PowerShell.Threadjob or load System.Drawing. Those are separate runtime
requirements and ownership/compatibility work. A later upstream module import
dot-sources function files and loads types/formats, but also starts a background
CIM namespace-enumeration job, writes `%TEMP%\CimNamespaceList.txt`, registers
argument completers and sets global customization variables. VS Code/ISE
integration is conditional. This is outside inert file deployment and recovery.
Import tests must use a disposable VM with TEMP/TMP redirected to a unique
run-owned directory.
Keep the original source/modified files until recovery succeeds. The Windows 11
build 26300 rerun passed all 14 lifecycle checks across the complete archive,
collected saved-state ZIP evidence and restored the registered checkpoint. This
closes the file-lifecycle collection gate; production support remains pending.
Static review of all 75 functions located Start-ThreadJob in CimMember.ps1 and Utilities.ps1 and System.Drawing use in Convert-HTMLtoANSI.ps1. The manifest requires Microsoft.PowerShell.Threadjob and System.Drawing for import; RIDE installs neither dependency. Runtime/function behavior and dependency ownership remain
[acceptance gates](migrations/application-migration-review.md#psscripttools-runtime-dependency-static-review-2026-10-22).

## Phoenix Protector MSI candidate

`package.phoenix-protector` records the exact 1.7.1 MSI linked from the
[NTCore product page](https://ntcore.com/phoenix-protector/) with its observed
SHA-256. The page currently lists version 1.8.0.1, while the executable inside
the retained MSI is version 1.9.0.1; these are separate identities and RIDE does
not silently substitute one for another. Inspect or preview the pinned artifact
from the repository root:

```powershell
.\ride.ps1 show package.phoenix-protector
.\ride.ps1 download package.phoenix-protector -WhatIf
```

The package is a Windows 11 candidate with no supported production target while
native installation, removal, exact recovery, offline use and the MSI's
`.NET Framework 2.0.50727` launch condition remain untested. The MSI bundles an
individual on-premises development/testing license; the publisher page calls the
product freeware but does not say that it replaces the bundled terms. The exact
version remains `NeedsReview` in the checkout-local license store. That review
status documents uncertainty and neither grants nor denies an individual or
organization's rights. Check the terms that apply to the intended user and use;
do not treat downloadability as a rights determination. RIDE's offline bundle
path now supports a single MSI only when the manifest marks it `DeclaredNoNetwork`
and its accepted catalog package has no dependencies; this does not firewall the
installer or establish Phoenix's offline behavior. Do not run the installer on
the host. MSI execution and disconnected installation acceptance belong in a
disposable Windows guest using the existing checkpoint. See the [offline bundle
limits](offline-bundles.md#execute-an-explicitly-selected-offline-package-bundle).

## Task Manager TMOG free-edition candidate

`package.tmog` pins the official Windows x64 free-edition installer for marketing
version 1.0.1. The contained product file version is 1.0.1.0; the installer uses
Inno Setup 6.7.0 and contains the application, `TMOG.scr`, license text, and
third-party notices. The retained candidate matches the publisher release
manifest SHA-256 and has a verified David Plummer Authenticode signature. The
catalog declares Windows 11 as a candidate target, with no supported target until
installation, repeat, uninstall, exact recovery, and screensaver effects are
accepted in the disposable VM. See the [current publisher release notes](https://tmog.org/rtm/release-notes.html).

The installer embeds a free-edition license that describes personal evaluation
and ordinary system-monitoring use, restricts public redistribution, and calls
itself a release-candidate document requiring publisher approval before public
distribution. This is recorded for owner review in the checkout-local license
store as `NeedsReview`; it does not block RIDE's direct publisher-download/install
package planning. It is not an entitlement or redistribution determination.
Preview the operation with `.\ride.ps1 show package.tmog`. Do not launch TMOG,
activate PRO, select it as the Windows screensaver, or inspect live process data
during package lifecycle acceptance. Keep install/uninstall and screensaver
effects in the existing disposable Windows VM; do not run the installer on the
developer workstation.

## Artcraft machine-scope MSI candidates

The twelve apps in `solution.artcraft-apps` are pinned to individual publisher
GitHub releases and use machine-scope MSI installation. `ApplicationsBatch6`
selects only these twelve apps on Windows 11 for preview, install/repeat,
uninstall and saved-run recovery checks. `package.artcraft-launcher` is a separate
current-user MSI candidate routed to `ApplicationsBatch7`; that batch checks
launcher install/repeat/uninstall/recovery without launching it or downloading
apps. The twelve standalone apps passed full pinned-version install/uninstall and saved-run recovery on Windows 11 Enterprise build 26300 and now declare Windows 11 support. The separate ArtCraft Launcher remains a Windows 11 candidate: its first guest run accepted the MSI exit code but RIDE did not find an ARP entry. The handler now detects the current-user MSI from Windows Installer's per-user product registration, the vendor marker and expected executable, and uses the discovered ProductCode for uninstall. Five focused tests and repository validation passed; full Windows lifecycle retry `89f97d58ba1a493199f83654702c91ea` is queued after the current ImageMagick and settings batches.

The versions in the private review store are marked `NeedsReview` for
owner-specific bundled-asset and brand-term assessment. This record does not
gate technical package migration, grant entitlement or approve redistribution.
The batch does not launch an app or change the catalog's release pins. Keep these
checks in the disposable Windows 11 VM using the registered checkpoint; do not
run the machine installers on the developer workstation. See the [batch
procedure](../tests/integration/README.md#existing-application-suites) and
[migration review ledger](migrations/application-migration-review.md#artcraft-package-license-reviews-recorded-2026-10-22).

## Office and Visio configuration review

Office deployment remains pending. Microsoft 365 Apps for enterprise uses the
selected Monthly Enterprise default, with Current Channel explicit. Fresh installs
prefer 64-bit; adding products must match existing compatible Office architecture.
32-bit is explicit, and migrating an existing installation needs a separate choice.
Visio Professional 2016 Retail and Visio Plan 2 are separate choices, not proven
coinstallable products. Preserve existing 2016 licences/installations. Visio uses
the accepted en-US default or explicit da-DK; Office retains en-GB. Additional
language packs, MatchOS and proofing remain product-specific review work.

Standard subscription user sign-in is separate from unattended installation:
report activation pending and continue when installation succeeds without verified
activation. Keep specialized activation separate. Teams installation is optional;
startup and old-version cleanup require separate selections and data preservation.
OneDrive accounts, sync configuration and user files must be preserved; sync/folder
backup restrictions are separate choices. See the [accepted Q21/Q22 decisions](migrations/decision-session-2026-10-17.md#q21-guided-officevisio-selection-and-separate-teams-actions).

To inspect an operator-supplied ODT configuration, start at the repository root
in Windows PowerShell 5.1 or PowerShell 7. No elevation is needed for this in-memory
review; the caller needs read access to the explicitly selected local XML.

```powershell
Import-Module .\modules\RIDE.OfficeConfigurationReview.psm1
$configurationBytes = [IO.File]::ReadAllBytes('<reviewed-local-configuration.xml>')
$review = Get-RideOfficeConfigurationReview -Bytes $configurationBytes
$review | ConvertTo-Json -Depth 12
```

The schema-1 review binds exact bytes by SHA-256. It reports declared products,
languages, architecture/channel/version, removal selections/MSI exclusions, update
configuration and sensitive action requests. Omitted choices stay omitted.
Product keys, private property values, source paths and application-setting values
are not included. Unknown syntax is flagged, not corrected. Parsing is bounded to
1 MiB, 4096 nodes, depth 24 and 32 attributes; DTD/external resolution and processing
instructions are prohibited. XML parser errors omit source text.

This is neither an ODT schema validator nor installed-product, licence or
compatibility verification. ReadyForMutation and RecoverySupported remain false.
It does not write XML, fetch ODT, execute setup, activate Office, change Teams or
remove software. Keep the original XML for recovery/review and do not share it if
it contains secrets. The [dated evidence and next procedure](migrations/application-migration-review.md#b10-inert-office-configuration-review-2026-10-17)
explain the legacy configuration's unresolved actions and product-specific gates.

## Read-only Office metadata

Click-to-Run observation is available as a separate preparation tool. From the
repository root in native Windows PowerShell 5.1 or PowerShell 7, supply the
independently established target machine/build/edition and interactive account
SID/session. Registry read access and an existing writable output directory are
required; the command does not request elevation.

```powershell
$officeObservation = @{
    ExpectedComputerName = '<target>'
    ExpectedBuild = '<build>'
    ExpectedEditionId = '<edition>'
    ExpectedUserSid = 'S-1-5-21-1-2-3-1001'
    ExpectedSessionId = 1
    OutputPath = 'C:\Evidence\office-observation.json'
}
.\tools\Export-RideOfficeInventory.ps1 @officeObservation -WhatIf
.\tools\Export-RideOfficeInventory.ps1 @officeObservation
```

WhatIf performs no inventory or file creation. Execution creates one new JSON
file, refusing existing or racing output. Preserve partial output after a write
failure and use a new filename. No Office state needs restoration.

The schema-1 observation keeps Registry64 and Registry32 separate on 64-bit
Windows. It reads only eight machine Click-to-Run configuration fields; absent
keys/values remain distinguishable from unavailable sources. Failed, malformed or
partial source data is discarded. Context is checked before and after collection.
Raw strings are not expanded. Channel URLs are redacted; only a recognized
Microsoft CDN channel GUID is retained. No product key, account token, installation
path, MSI inventory or executable is queried.

Registration values may be shared, stale or incomplete. ProductReleaseIds and
ClientCulture do not prove installed product editions or each product's languages;
UpdateChannel and CDNBaseUrl do not alone establish the effective channel. The
tool does not resolve policy precedence, entitlements, activation or compatibility.
InstalledProductsVerified, EffectiveChannelVerified, ReadyForMutation and
RecoverySupported remain false. Native registry-view acceptance is pending. See
the [dated evidence and next procedure](migrations/application-migration-review.md#b10-click-to-run-observation-2026-10-17).

## Disposable-VM acceptance

New products and distributions declare `PendingAcceptance = $true`, explicit
`CandidateTargets` and an empty `SupportedTargets` collection until acceptance.
They remain inspectable and downloadable, but production execution rejects
them. The guarded suite enables each candidate target only in its test catalog.
Passing scenarios justify adding that target and clearing the pending marker;
an unavailable or failed scenario leaves the distribution pending for review.

`ApplicationsBatch1` and `ApplicationsBatch2` run through the existing VM runner
and task controller. Both run parser/catalog/profile validation and focused
mocked Pester checks for applications, catalog, acquisition and controller behavior
before live preview, install, repeat, remove and saved-run recovery. Related
library/schema regressions run on native Windows PowerShell 5.1 and PowerShell 7.
Portable scenarios also test preservation of user content and exact recovery
after removal. Candidate Server support is supplied in memory inside the
guarded test guest; it is added to production metadata only after acceptance.

The controller pins VM/checkpoint IDs, collects correlated logs, observations
and state before resetting, and records cleanup failure separately. See the
[VM runbook](../tests/integration/README.md) and
[controller recovery procedure](../tests/integration/automatedlab-tasks.md#recovery-and-teardown).
File lifecycle acceptance does not establish a forensic tool's parsing quality,
collector behavior, browser UI or hardware-driver compatibility.

The newer MiTeC JSON/XML Viewer and NTCore PE Detective/CFF Explorer candidates
use the [focused portable runner](../tests/integration/README.md#focused-reviewed-portable-packages),
with six architecture cases and retained pinned archives. They are outside the
older `ApplicationsBatch1`/`ApplicationsBatch2` selectors. Defender-blocked tools
are excluded. Check the [focused acceptance evidence](migrations/application-migration-review.md#focused-portable-vm-acceptance-rerun-2026-10-17)
for the latest lifecycle results and remaining blockers; lifecycle success alone
does not close functionality or activation acceptance.

Desktop products declare `RequiresDesktopExperience`; planning/execution and
saved-run preflight reject Server Core explicitly. The integration ledger reports
that applicability separately from failures. Detection follows Microsoft's
[InstallationType reference](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ee391629(v=vs.85)).

## Sysinternals reviewed Suite candidate

package.sysinternals-suite stages the full official portable snapshot captured on
2026-10-17. Its RIDE snapshot label is not a publisher Suite release version.
The source URL is mutable, so the expected SHA-256 must match exactly; a changed
upstream archive requires a separately reviewed snapshot instead of silent update.
All 164 names, including Eula.txt and help/readme material, are required. The
[source inventory](archive/evidence/sysinternals-suite-source-review-2026-10-17.json)
records file hashes, versions, PE machine fields and observed signatures.

This candidate has no supported apply targets and is absent from recommended
profiles. Whole-suite source staging is implemented. A fixed `SysinternalsSuite`
disposable-VM batch is prepared to check only the Suite's file lifecycle; it has not
run because VM access is blocked. Individual product selection, per-tool
dependencies/applicability and application behavior remain pending. The existing portable handler owns only recorded unchanged files
and preserves user-created/modified content. No tool is launched, EULA interaction
answered, driver/service installed, Sysmon configuration applied, PATH changed or
shortcut created. Mixed x86/x64 files do not imply support on every architecture.
The separately managed Sysmon service package remains independent.

The prior RIDE v2 license-specialist approval covers this direct-download-and-install
workflow. The exact snapshot and all nine product versions are `Reviewed`; licensing
is settled and is not a reason to defer their package migration. The remaining Suite
gate is technical Windows lifecycle, recovery and target acceptance.

Inspect the [batch procedure and recovery](migrations/application-migration-review.md#b11-sysinternals-reviewed-snapshot-candidate-2026-10-17)
before disposable-target acceptance. RIDE's direct-download-and-install workflow
has prior RIDE v2 license-specialist approval, reconfirmed by the user on
2026-10-22. The exact snapshot and all nine individual tool versions are marked
`Reviewed` in the checkout-local store; no licensing hold remains for their RIDE
package migration. Publishing or transferring copies is not part of this workflow.

## Individual Sysinternals portable packages

Nine independently selectable candidates accompany the whole-Suite snapshot:

| Catalog ID | Publisher version | Official archive inventory |
| --- | --- | --- |
| package.sysinternals-process-explorer | 17.2 | Four files; three signed executables and Eula.txt |
| package.sysinternals-autoruns | 14.3 | Seven files; six signed executables and Eula.txt |
| package.sysinternals-tcpview | 4.19 | Eight files; six signed executables, help and Eula.txt |
| package.sysinternals-procmon | 4.12 | Four files; three signed executables and Eula.txt |
| package.sysinternals-rammap | 1.63 | Four files; three signed executables and Eula.txt |
| package.sysinternals-disk2vhd | 2.02 | Five files; three signed executables, help and Eula.txt |
| package.sysinternals-sigcheck | 2.93 | Four files; three signed executables and Eula.txt |
| package.sysinternals-strings | 2.54 | Four files; three signed executables and Eula.txt |
| package.sysinternals-handle | 5.0 | Four files; three signed executables and Eula.txt |

Each has its own official ZIP SHA-256 pin, version and independent owned folder.
Selecting a product does not require Suite. Selecting both creates separate copies;
removing one does not own the other folder. The nine products passed install,
repeat, removal, repeat, saved-state restoration, digest/signature, collision and
modified-file preservation checks on Windows 11 build 26300; Windows 11 is now a
supported target for those package file lifecycles. Coexistence with the separate
Suite snapshot and Windows Server acceptance remain open. Product archives contain
x86, x64 and ARM64 members; neutral means the package retains mixed upstream files,
not that every utility architecture or runtime is accepted. These packages remain
absent from recommended profiles.

No process inspection/termination, autostart change, connection closure, driver
activation, EULA interaction or VirusTotal upload is performed by file staging.
Symbols, application preferences and tool execution are separate choices. Upstream
help inventory differs from the Suite; retain each archive's actual complete set
rather than silently borrowing files from another product. Utility runtime and
activation behavior have not been tested. Exact saved file recovery and
collision/modified-file refusal use the existing portable lifecycle. See the
[source review](migrations/application-migration-review.md#b11-independent-sysinternals-products-2026-10-17) for pins and
  remaining native acceptance. The prior RIDE v2 license-specialist approval,
  reconfirmed by the user, covers RIDE's download-and-install workflow. The user
  confirms there are no legal issues using Sysinternals in RIDE. Licensing is
  settled and must not block or defer these package migrations; proceed on the
  remaining technical acceptance work.

Process Monitor, RAMMap and Disk2vhd stage files only. Kernel-driver loading, boot
logging, trace capture, memory-list changes, imaging, VSS, virtual-disk attachment
and encrypted-volume handling require separate explicit workflows and acceptance.
RIDE does not decrypt volumes or infer imaging rights from this package selection.
The publisher's historical OS lists are not new RIDE support declarations. See the
[diagnostic/imaging review](migrations/application-migration-review.md#b11-sysinternals-diagnostic-and-imaging-candidates-2026-10-17).

Sigcheck, Strings and Handle also stage files only. File analysis, certificate-store
inspection, remote reputation lookups/uploads, handle enumeration/closure and driver
use require explicit tool execution. Optional external-service terms are considered
when selecting that service; package staging does not accept them. See the
[command-line product review](migrations/application-migration-review.md#b11-sysinternals-command-line-candidates-2026-10-17).

## NTCore 4GB Patch portable candidate

`package.ntcore-4gb-patch` stages the retained single-file x86 1.0.0.1 ZIP into
the managed portable package directory. The archive is pinned to its observed
SHA-256; this is a retained-file pin, not an independently publisher-verified
digest or a fresh confirmation of the mutable download URL. Changed bytes fail
closed and require a reviewed pin refresh. Installation and removal do not
launch the utility or open/modify any target executable.

The publisher says the utility sets the PE large-address-aware flag and creates
a backup, but Windows 11 testing found that direct invocation patches the target
when its `.Backup` path is occupied and does not create a recoverable original
copy. Do not invoke the upstream executable directly. Use the RIDE guarded
launcher at [tools/Invoke-Ride4GbPatch.ps1](../tools/Invoke-Ride4GbPatch.ps1).
It refuses a pre-existing backup, writes and flushes the exact original bytes to
`<target>.Backup` before launching the pinned tool, verifies that the backup
survived, and checks that only the PE large-address-aware flag changed. If
post-run checks fail, it attempts exact recovery and retains the adjacent backup
for manual recovery. Close the target application first.

The launcher is source-ready, but the guarded workflow has not yet passed its
Windows 11 VM acceptance. Keep supported targets empty until a disposable-VM
run verifies ordinary patching, exact backup creation, pre-existing backup
refusal without mutation, and exact recovery using only a synthetic x86 PE. Do
not patch a third-party or production executable.

The retained 2007 copyright metadata says all rights reserved; the reviewed
product page and archive contain no product-specific license grant. The package
is prepared as a candidate and its version-specific local license status is
`NeedsReview`, per the user's migration priority. This status does not assert
entitlement or redistribution permission. See the [source and pin evidence](archive/evidence/ntcore-4gb-patch-page-follow-up-2026-10-21.json),
[candidate preparation record](archive/evidence/ntcore-4gb-patch-candidate-preparation-2026-10-22.json),
[license review guidance](package-licensing.md#local-usercompany-reviews), and
[dated migration record](migrations/application-migration-review.md#ntcore-4gb-patch-candidate-preparation-2026-10-22).

## NTCore Driver List and Rebel.NET portable candidates

`package.ntcore-driver-list` stages the pinned x64 Driver List executable by
default; the `portable-x86` variant selects the verified x86 member. The retained
publisher ZIP contains an IA64 executable as well, but RIDE does not select it.
The publisher page advertises 1.0.2; both selected x86/x64 files carry file
version 1.0.2.1. The archive SHA-256 is measured from the retained publisher
archive, not an independently published digest. Staging does not inspect loaded
drivers or create a report. Keep target support empty until Windows lifecycle and
recovery acceptance pass. Do not retain a loaded-driver report from a test VM.

`package.ntcore-rebelnet` stages the pinned x86 Rebel.NET 1.6.0.1 executable and
its format header. The archive SHA-256 is measured from the retained publisher
archive, not an independently published digest. Package install/removal does not
open or rewrite assemblies. Keep target support empty. Any later functional
acceptance must use an owned synthetic .NET assembly, save to a separate output,
verify that the input remains unchanged, and test exact cleanup/recovery. Never
use a third-party or production assembly.

The Driver List product page and archive did not provide a product-specific use
or distribution grant. The [Rebel.NET guide](https://ntcore.com/files/rebelnet.htm)
says commercial use goes against its terms. These questions are recorded as
version-specific `NeedsReview` entries in the local review store; they do not
block package planning or candidate implementation and do not establish
entitlement or redistribution permission. See the [source review](archive/evidence/ntcore-member-source-follow-up-2026-10-17.json),
[candidate evidence](archive/evidence/ntcore-driver-list-rebelnet-candidate-2026-10-23-1045.json),
[license review guidance](package-licensing.md#local-usercompany-reviews), and
[dated migration record](migrations/application-migration-review.md#ntcore-driver-list-and-rebelnet-package-candidates-2026-10-23).

## MiTeC Windows File Analyzer and Icon Explorer candidates

`package.mitec-windows-file-analyzer` stages only the pinned `WFA.exe` from
version 2.10.0. It can display thumbnail databases, Prefetch records,
shortcuts, browser-history data and Recycle Bin records. Staging opens no files.
Any later behavior check must use narrow synthetic disposable artifacts, preserve
the inputs and verify exact output cleanup. Never scan or print a real profile or
host evidence.

`package.mitec-icon-explorer` stages only the pinned `IconExplorer.exe` from
version 5.3.0. Later checks must use a small synthetic icon-bearing directory
and a separate disposable output directory. Preserve inputs and test collisions,
overwrite behavior and cleanup before broader use.

Both publisher target lists end at Windows 10, so RIDE support remains empty
pending Windows 11 lifecycle and behavior acceptance. Their exact-version local
`NeedsReview` markers are for owner-specific administration and do not block
candidate planning, implementation or acceptance preparation. See the [retained
source evidence](archive/evidence/mitec-file-analyzer-icon-explorer-static-review-2026-10-21.json),
[candidate evidence](archive/evidence/mitec-file-analyzer-icon-explorer-candidates-2026-10-23-1230.json),
and [dated migration record](migrations/application-migration-review.md#mitec-windows-file-analyzer-and-icon-explorer-candidates-2026-10-23).

## MiTeC OLE/COM Explorer, Registry Recovery and SMBIOS candidates

`package.mitec-ole-com-explorer` stages only `OLExp.exe` (FileVersion
1.4.0.0). Staging activates no COM server and changes no registration. Keep
later checks limited to an inert synthetic object/type-library fixture; do not
activate arbitrary servers or alter COM registration.

`package.mitec-windows-registry-recovery` stages `WRR.exe` and `WRR64.exe` from
version 3.1.3. Staging opens no hive or backup. Hive contents can include product
keys, SIDs, user accounts, startup entries, services, drivers, network/firewall
settings and Outlook Express configuration. Any later check must use synthetic
offline hives and a disposable output directory; never inspect or export real
host or user hives.

`package.mitec-smbios-explorer` stages `SMBE.exe`, `SMBE64.exe` and its x86
`SMBIOS.exe` helper from version 1.8.0. Staging reads no firmware or system
information. SMBIOS data can contain serial numbers, asset tags, UUIDs and
hardware details. Later checks must use synthetic SMBIOS files and disable live
registry, WMI, ROM and API collection.

All three candidates remain unsupported pending RIDE Windows 11 lifecycle,
recovery and behavior acceptance. Their exact-version local `NeedsReview`
records support owner-specific administration and do not block package
migration or acceptance preparation. See the [retained source reviews](archive/evidence/mitec-olecom-project-maker-static-review-2026-10-21.json),
[registry/SMBIOS review](archive/evidence/mitec-registry-recovery-smbios-static-review-2026-10-21.json),
[candidate evidence](archive/evidence/mitec-review-data-tools-candidates-2026-10-23-1235.json),
and [dated migration record](migrations/application-migration-review.md#mitec-olecom-registry-recovery-and-smbios-explorer-candidates-2026-10-23).

## MiTeC Mail and History Viewer candidates

The unsupported Windows 11 candidates are `package.mitec-mail-viewer` 2.5.1.0,
`package.mitec-email-history-browser` 1.2.0, `package.mitec-internet-history-browser`
2.5.0 and `package.mitec-instant-messaging-history-browser` 1.2.1. Their retained
publisher archives and selected member hashes are pinned in the catalog and dated
evidence. Staging opens no personal mail, attachments, browser history, chats,
calls or transfers. Any future feature check must use synthetic disposable stores,
prove the inputs remain unchanged and verify output cleanup. The Mail Viewer may
expose message content and attachments; the history tools expose the metadata
listed on their publisher pages.

All four candidates keep `SupportedTargets` empty and `PendingAcceptance` true.
Their exact-version local `NeedsReview` records are owner-administration context;
they do not block implementation or install planning. Publisher-page claims and
general support-EULA language are retained as observations without treating the
local status as a migration gate. See the [candidate evidence](archive/evidence/mitec-mail-history-viewer-candidates-2026-10-23.json)
and [dated migration record](migrations/application-migration-review.md#mitec-mail-and-history-viewer-package-candidates-2026-10-23).

## Microsoft OpenJDK compatibility packages

The catalog provides Microsoft Build of OpenJDK 25.0.4.1 as the default Java
package and side-by-side compatibility choices 21.0.12.1, 17.0.20.1 and
11.0.32.1. Each candidate uses its exact Microsoft x64 MSI and validates the
publisher's version-matched SHA-256 sidecar before acquiring the installer.
The MSI installs only `FeatureMain` into a separate `C:\Program Files\Microsoft\RIDE\OpenJDK\jdk-<major>` directory; it leaves
`JAVA_HOME`, `PATH` and `.jar` associations unchanged. Selecting or installing
one version does not switch another application's runtime.

Microsoft lists these current LTS MSI versions and checksum files on the
[OpenJDK download page](https://learn.microsoft.com/en-us/java/openjdk/download).
Its [MSI instructions](https://learn.microsoft.com/en-us/java/openjdk/install)
document the optional environment, Java home and JAR association features; RIDE
does not select them. The packages are pending disposable Windows 11 and
Server 2025 lifecycle, repeat, uninstall and recovery acceptance, so they have
no supported target yet. Static metadata and mocked checksum checks do not
verify live Microsoft endpoints or MSI behavior.

## Volatility Workbench source-review status

PassMark lists Volatility Workbench 3.0.1017, based on Volatility 3 Framework
2.28.2. The ZIP includes the GUI, command-line executable and source. The
publisher says the program retrieves missing Windows symbols from Microsoft,
generates symbol tables and caches them. RIDE's offline bundle must pin symbol
inputs and prevent network fallback; the framework's CLI documentation
describes `--offline`, but that flag and its enforcement in the bundled 2.28.2
GUI/CLI have not yet been verified from the exact archive.

Workbench also reads and writes a `.CFG` alongside a memory dump, containing
platform and process-list metadata. Acceptance therefore needs a synthetic
memory image and disposable output location, with checks for image integrity,
sidecar contents, symbol/cache paths and network attempts. The 3.0.1017 archive
hash and member inventory are not available because the publisher host failed
DNS before transfer, so this remains source review only and is not cataloged or
supported. License review is not a migration gate. See the [offline-mode
source evidence](archive/evidence/volatility-workbench-offline-mode-source-review-2026-10-24-1515.json).

## Thumbcache Viewer source-review status

The publisher currently lists Thumbcache Viewer GUI x64 1.0.4.0 and command-line
x64 1.0.2.1 with exact GitHub release URLs. Both editions require the Visual C++
2008 runtime. Do not silently install an unpinned redistributable; confirm the
exact runtime package and architecture as part of package implementation.

Windows 11 mapping of Search `Windows.db` uses SQLite. The publisher says to run
the tool on Windows 11 or supply `sqlite3.dll`; GUI v1.0.4.0 source confirms it
tries `sqlite3.dll` first and falls back to Windows' `SearchIndexerCore.dll`.
This affects Windows Search mapping, not basic thumbnail-cache extraction, so
RIDE does not need to bundle a separate SQLite DLL for the basic workflow.
Mapping files from Windows Search is read-only, but exports can write extracted
thumbnails and reports; future acceptance must use synthetic databases and
disposable output folders.

The exact ZIPs could not be acquired because GitHub hostname resolution failed
before transfer. Their local hashes, members, and the command-line edition's
runtime details remain unverified, so neither candidate is cataloged or
supported yet. GPL-3.0-or-later is not a migration blocker. See the
[publisher and release source review](archive/evidence/thumbcache-viewer-dependency-source-recheck-2026-10-24-1514.json).

## ExifTool portable candidate

The catalog contains `package.exiftool` as an unsupported Windows 11 candidate
for publisher version 13.59 x64. The exact ZIP URL and reported SHA-256 are
pinned, but local acquisition and member/hash inspection are still required
before acceptance. The publisher labels 13.59 a development release; 13.55 is
its latest production release.

The candidate stages the publisher's complete folder and notices, keeping
`exiftool(-k).exe` beside `exiftool_files`. It creates `exiftool.exe` as an
owned copy of the launcher for command-line use. Uninstall and saved-run restore
must remove or recover only RIDE-owned files. No original media is read or
modified by package installation. Verify behavior with synthetic media fixtures
only. Windows 11 support is not declared until archive inspection, lifecycle,
recovery and guest acceptance pass.

See the [ExifTool source and version evidence](archive/evidence/exiftool-source-pin-2026-10-24-1458.json)
and [migration review](migrations/application-migration-review.md#exiftool-windows-artifact-source-pin-2026-10-24-1458-utc).

## Sysmon Modular configuration choices

Three explicit download-only artifact IDs provide the Balanced, Balanced with
FileDelete and Excludes only profiles from Olaf Hartong's signed
`configs-a45dedb13a43` release. All three are pinned to Sysmon 15.21 and checked
against that release's `SHA256SUMS` before the selected XML is downloaded. The
upstream identifies the unversioned filenames as the 15.21 aliases. The
Balanced profile excludes FileDelete archiving; Balanced with FileDelete
preserves deleted files and needs archive-disk planning; Excludes only is very
verbose and can produce substantial event volume. Review and tune a profile
for the endpoint before using it. RIDE's download operation does not install
Sysmon or apply the configuration. The separate configuration-apply workflow
is not part of these artifacts.

See the upstream [release description](https://github.com/olafhartong/sysmon-modular/releases/tag/configs-a45dedb13a43)
and [project guidance](https://github.com/olafhartong/sysmon-modular). The
artifacts are MIT-licensed; retain the upstream
[license](https://github.com/olafhartong/sysmon-modular/blob/master/license.md)
and configuration notices. The source archive documents the collection goals,
compatible Sysmon versions and release checksum manifest. See the [migration
record](migrations/application-migration-review.md#sysmon-modular-pinned-profile-artifacts-2026-10-23).

## JoeWare download-only source preparation

`tools/Download-JoeWareCollection.ps1` acquires the latest ZIP currently offered
on each selected product page from the fixed, reviewed 41-product collection.
It saves the page's current-version label, the resolved response URL, local
SHA-256, archive member names, inert version-string candidates, and the
publisher's current `versions.txt` row. It submits the publisher form with no
email address. It does not extract, install, execute or configure tools, and it
does not add Defender exclusions. AdFind's Defender-reported block remains a
separate selection/acceptance issue.

Run from the repository root in Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\tools\Download-JoeWareCollection.ps1 -Product rdp-sec-check -DestinationDirectory D:\staging\joeware
```

Omit `-Product` to select the full reviewed collection. The destination must
be new or empty; each ZIP and the JSON observation manifest are retained there.
Use `-WhatIf` to preview the publisher requests. The script does not claim a
publisher SHA-256: it records a local hash of the acquired bytes. Review any
page/list/archive differences in the
[JoeWare discrepancy record](joeware-version-discrepancies.md) before package
catalog admission or technical acceptance. In particular, do not associate the
older `rdp-sec-check` V01.00.00 digest with the page's V02.00.00 version unless
the acquired archive establishes the identity. The eventual package description
should use a short note such as: “The `rdp-sec-check` product page and publisher
version list disagree; see the [discrepancy record](joeware-version-discrepancies.md).”

### AccExp, ATSN and Auth source review, 2026-10-24 15:43 UTC

The publisher versions file lists AccExp 01.01.00 (2002-08-04), ATSN 01.00.00
(2004-03-27), and Auth 01.01.00 (2001-08-17). AccExp reads or changes account
expiration, not password expiration; setting expiration requires suitable
account permissions. ATSN queries Active Directory IP-to-site/subnet mapping,
can use a selected domain controller, and can write a report. Auth tests
credentials; do not use real user credentials or test against a live domain.
The publisher's platform lists are historical and do not establish Windows 11
support. The authorized download-only retry failed at local DNS before the
version list request completed; no form was submitted and no archive arrived.
No VM, directory, endpoint or Windows state was touched. Licensing is not a
migration gate. See [structured evidence](archive/evidence/joeware-accexp-atsn-auth-source-and-acquisition-review-2026-10-24-1543.json),
the [publisher version list](https://joeware.net/freetools/versions.txt),
[AccExp usage](https://joeware.net/freetools/tools/accexp/usage.htm),
[ATSN page](https://www.joeware.net/freetools/tools/atsn/index.htm),
[ATSN usage](https://joeware.net/freetools/tools/atsn/usage.htm), and
[Auth page](https://joeware.net/freetools/tools/auth/index.htm).
### Unlock source review, 2026-10-24

The publisher page lists Unlock 2.1.0 (version-list form `02.01.00`), released
2004-08-16; the product page and `versions.txt` row agree. The page lists Windows
2000, Windows Server 2003 and Windows XP, so it does not establish Windows 11
support. Unlock queries and can clear Active Directory account lockouts;
querying depends on caller rights, while unlocking requires write permission on
`lockoutTime`. The publisher says the C++ program was built with Borland Builder
6.0 and provides no source code. The version list supplies MD5/SHA-1, not SHA-256.
The product page uses an optional email download form; no form was submitted and
no ZIP was acquired. Do not register a package candidate until exact bytes and
members can be reviewed. Defer functional acceptance to an isolated synthetic
AD fixture; never target a live directory during migration tests. Licensing is
not a migration blocker under the publisher's internal-use clarification. See
[structured review evidence](archive/evidence/joeware-unlock-publisher-review-2026-10-24-1531.json),
[product page](https://www.joeware.net/freetools/tools/unlock/index.htm) and
[publisher versions file](https://joeware.net/freetools/versions.txt).
### AdQueueLoop, MemberOf and OldCmp source review, 2026-10-24

The publisher version list and corresponding product/usage pages match:
AdQueueLoop 2.00.00 (2006-03-23), MemberOf 2.03.00 (2006-06-10), and OldCmp
1.05.00 (2004-12-28). AdQueueLoop polls an Active Directory replication queue
and can write bounded file/CSV output. MemberOf queries membership for users,
groups or computers and adds primary-group data separately by default. OldCmp
can report and change old AD computer/user objects. Its documented safeguards
include a default change cap of 10, refusing deletion of objects that are not
already disabled, explicit unsafe/for-real switches, and never modifying domain
controllers. Use report-only first; any future mutation test belongs only in a
disposable AD with exact recovery. The publisher platform claims for these tools
are historical and do not establish Windows 11 support. No publisher form was
submitted and no ZIP/hash/member inventory was acquired. Package admission waits
for exact publisher bytes; licensing is not a migration blocker. See [structured
review](archive/evidence/joeware-adqueueloop-memberof-oldcmp-source-review-2026-10-24-1536.json),
[AdQueueLoop usage](https://joeware.net/freetools/tools/adqueueloop/usage.htm),
[MemberOf usage](https://joeware.net/freetools/tools/memberof/usage.htm),
[OldCmp product page](https://joeware.net/freetools/tools/oldcmp/index.htm), and
[publisher versions file](https://joeware.net/freetools/versions.txt).
### FindExpAcc, GCChk and UserName source review, 2026-10-24

The publisher's version list matches its product-page labels: FindExpAcc
01.01.00 (2005-06-19), GCChk 01.03.00 (2004-08-30), and UserName 01.00.00
(2002-10-08). FindExpAcc and GCChk query Active Directory/Global Catalog data;
insufficient read permissions can affect GCChk's missing-object findings.
UserName reads the current user's directory identity and can write optional
command/batch output. The publisher's platform claims stop at Windows XP/Server
2003 and do not establish Windows 11 support. No download form was submitted;
exact ZIPs, hashes and member inventory remain open. Later functional acceptance
should use a disposable synthetic directory and contained output paths. No
license blocker applies to RIDE's direct download/install workflow. See
[structured evidence](archive/evidence/joeware-findexpacc-gcchk-username-source-review-2026-10-24-1537.json),
[FindExpAcc page](https://joeware.net/freetools/tools/findexpacc/index.htm),
[GCChk page](https://joeware.net/freetools/tools/gcchk/index.htm),
[UserName page](https://joeware.net/freetools/tools/username/index.htm), and
[publisher versions list](https://joeware.net/freetools/versions.txt).
### FindPDC, SidToName and GetUserInfo source review, 2026-10-24

The publisher versions file and product/usage page agree on FindPDC 01.00.01
(2001-09-28) and SidToName 02.00.00 (March 2003; version-file date
2003-03-03). FindPDC checks name resolution and domain-controller NetLogon
responses; SidToName resolves a SID locally or against a selected computer.
The versions file lists GetUserInfo 02.07.00 (2003-09-27), and the publisher
index describes it as a remote user-information query, but the retrieved sources
do not confirm its product-page/version match. The publisher's support claims
are historical and do not establish Windows 11. Exact ZIPs, hashes, member lists
and per-product behavior remain open; no form was submitted and no endpoint or
AD was contacted. License is not a migration blocker. See [structured source
evidence](archive/evidence/joeware-findpdc-sidtoname-getuserinfo-source-review-2026-10-24-1539.json),
[FindPDC](https://joeware.net/freetools/tools/findpdc/index.htm),
[SidToName usage](https://joeware.net/freetools/tools/sidtoname/usage.htm),
[publisher index](https://joeware.net/freetools/), and
[versions file](https://joeware.net/freetools/versions.txt).
