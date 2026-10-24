# Offline installation bundles

The requested offline workflow prepares a transferable folder containing pinned
RIDE source, profiles, external package payloads and required notices. Preparation
and installation are separate. A full package library does not select every
package for installation. The [accepted decisions](migrations/decision-session-2026-10-17.md#offline-installation-follow-up-profile-selected-and-full-package-bundles)
define both profile-selected and full-set preparation, reviewed installed/portable
variants for selected targets, explicit omissions, new versions on refresh and
optional operator-supplied Windows servicing sources.

Currently available: local manifest integrity/dependency preflight and optional
byte-bound catalog/profile package coverage, plus explicit local-source assembly
with an optional selected-profile package-content gate. Explicit offline
`install`/`apply` enforce that gate for accepted portable packages and EXE/MSI
installers whose artifact is declared `DeclaredNoNetwork`, including catalog
prerequisites expanded into the same ordered plan. Each required package payload
must be present and accepted. A selected artifact dependency edge is accepted
only when it resolves to that consumer's earlier catalog prerequisite operation;
it does not create a separate installer action. Unmatched or multi-artifact
dependency actions remain unsupported.
Installer execution still requires catalog target acceptance.
Normal commands without offline options retain their online acquisition
behavior. Automatic acquisition planning, broader dependency/installer support
and engine packaging remain pending. The focused Caffeine portable scenario
passed disconnected Windows 11 build 26300 acceptance; broader native coverage
remains pending. Assembly or preflight alone does not establish an installable
air-gapped bundle.

## Execute an explicitly selected offline package bundle

Use a fresh native Windows PowerShell 5.1 or PowerShell 7 process from the bundled
RIDE directory. The manifest must include `ride.ps1`, `catalog/operations.psd1`
and every file beneath `modules/`, with the same relative layout and bytes as the
running checkout. The engine file paths share the root before
`catalog/operations.psd1`; for example `ride/`. Keep all prepared bundles and
saved runs. The engine checks source bytes, not the authenticity of the declared
Git commit or publisher provenance; those remain assembly review obligations.

Supply all three offline options, including during preview. For a reviewed
portable-only profile already included in the manifest:

```powershell
# Starting directory: C:\Offline\bundle-v1\ride
.\ride.ps1 apply -Profile .\profiles\portable-tools.psd1 -OfflineBundle ..\manifest.json -OfflineProfileId portable-tools -OfflineCatalogFileId catalog -WhatIf
# After reviewing the preview, repeat without -WhatIf to apply.
```

`install <package-id>` accepts the same options; the manifest profile must then
select exactly that package and variant. Use explicit `-Variant` when applicable.
`OfflineProfileId` and `OfflineCatalogFileId` complete from the supplied bounded
manifest, without loading the engine or inspecting machine state. An empty or
incomplete offline selection is an error, never an online fallback.

Before any state manifest, snapshot, selection index or handler write, the engine
verifies the selected profile/catalog bytes, selected payloads/notices, running
source, exact ordered package/variant plan and actual target/build/edition/
architecture. Missing, changed, omitted, wrong-source or unsupported requirements
fail the entire plan. Unrelated omitted artifacts remain permitted. Read leases
keep the manifest, selected bundle files and running source from being replaced
until execution completes or fails; failed preflight releases its leases.

Preflight recognizes catalog `neutral` archives as well as manifest `any`
content; explicitly architecture-specific payloads must still match the selected
profile. Catalog/manifest architecture declarations must agree. A neutral archive
does not establish that every included executable runs on every processor or
Windows release; native behavior and supported-target checks remain separate.

The offline execution path has these explicit limits:

- Every selection must be an already accepted `Portable`, `Exe` or `Msi` package
  in `Present` state, with exactly one payload and `DeclaredNoNetwork` capability.
  Catalog-declared prerequisites are expanded in dependency order and each must
  have a selected, accepted payload in the bundle. A manifest artifact edge
  must match the consumer's direct catalog prerequisite and the prerequisite
  operation must precede the consumer. Other artifact-level dependency actions
  are refused. The bound profile must use explicit variants where the
  catalog offers them; local preferences cannot silently change it.
- Other installer types, services/drivers, package removal, settings, servicing
  sources, library overlays and desktop-user handoff are not implemented for
  offline execution. Mixed plans fail before their first setting is changed.
- Network authentication options cannot accompany the CLI offline selection.
  No provider/discovery/download fallback is called. Portable extraction skips
  Authenticode provider inspection, which can contact certificate services, and
  records `NotInspectedOffline`. EXE/MSI payload signatures are not inspected by
  this offline path either. Exact SHA-256 checks and owned-file protections remain
  active. This is not a signature-verification claim.

Machine-scoped packages still require elevation. Use the normal saved Run ID for
portable exact-file recovery; unowned and modified files retain existing conflict
protections. A handler failure retains the saved-run error/reporting contract,
and all bundle read leases close in `finally`. There is no automatic resume,
bundle pruning, replacement of missing bytes or implicit profile composition.
Native no-network deployment and interruption/recovery acceptance remain pending;
the [implementation ledger](migrations/remaining-migrations-follow-up.md) records
the actual tested source and outstanding VM gate.

## Assemble prepared local files

From the repository root in native PowerShell, prepare a reviewed manifest and a
separate UTF-8 JSON source map: each key is a manifest File Id and each value is
an existing absolute local source file path. For example, a catalog record can
map to C:\Preparation\ride\catalog\operations.psd1. Every declared file needs
exactly one mapping; extra/unreferenced files are refused. Source paths are not
copied into transferable metadata. Review package acquisition provenance, rights
and pinned engine source separately; this tool does not generate those claims.

Create the destination parent explicitly, then preview and assemble a new version:

~~~powershell
.\tools\New-RideOfflineBundle.ps1 -ManifestPath 'C:\Preparation\manifest.json' -SourceMapPath 'C:\Preparation\sources.json' -DestinationPath 'C:\Offline\bundle-v2' -WhatIf
$result = .\tools\New-RideOfflineBundle.ps1 -ManifestPath 'C:\Preparation\manifest.json' -SourceMapPath 'C:\Preparation\sources.json' -DestinationPath 'C:\Offline\bundle-v2'
$result | Format-List
~~~

The source-map and manifest limits are each 4 MiB. All source files must be local
regular files with no reparse-point ancestry. The whole declared bundle shares the
128 GiB default/-MaximumBytes bound. No elevation or installer is invoked. Existing
destinations, even empty directories, are refused. A unique sibling .ride-staging-*
directory holds exclusively created files; each copy is hashed and the staged file
is verified again. After the last copy, the entire staged file set is rechecked so
an earlier file changed during later copying cannot pass on stale evidence.
Optional profile coverage runs before that final integrity pass.
Only after those checks are manifest.json and assembly.json
written and the directory moved to the absent destination. Those two root paths are
reserved. A competing destination makes the move fail without replacing it.

Check Status: Preview writes nothing; Completed means the copied bytes matched;
Failed reports FailureStage, FailedFileId, ErrorType and any retained StagingPath.
Interrupted/failed staging is never automatically resumed or deleted. Inspect it,
correct inputs and retry into a fresh destination. A completed copy may still be a
partial bundle with explicit omissions. It does not establish engine provenance,
redistribution approval, complete dependency coverage or installation readiness.
Use the following preflight for each selected deployment. Preserve prior versions.
The final pass is a point-in-time check, not a continuing filesystem lock. Keep the
bundle in a controlled directory and recheck it after transfer and before use.

## Check declared local content

Start from the repository root in native Windows PowerShell 5.1 or PowerShell 7.
Supply an explicitly reviewed manifest and a profile ID defined in it. The local
bundle root must be an existing drive subdirectory with read access; UNC/device
paths and reparse-point ancestry are refused. No elevation is requested.

```powershell
.\tools\Test-RideOfflineBundle.ps1 `
    -ManifestPath 'C:\Offline\bundle-v1\manifest.json' `
    -ProfileId 'workstation' -CatalogFileId 'catalog' |
    ConvertTo-Json -Depth 12
Get-Help .\tools\Test-RideOfflineBundle.ps1 -Full
```

The root defaults to the manifest's directory; `-Root` can explicitly identify a
copied folder. Manifest members use relative forward-slash paths, without binding
to the original host or a physical USB device. Profile ID completion reads only
the supplied bounded manifest, never payloads or Windows configuration. The module
API `Test-RideOfflineBundle -Manifest <object> -Root <path> -ProfileId <id>` also
completes IDs from its supplied metadata. Optional -CatalogFileId completes Engine
file IDs and enables package coverage using that catalog and the selected profile.
Only trusted checkout parsers are imported; bundled modules/scripts are never run.

The tool reads selected engine/profile/payload/notice/servicing files with shared
read access, compares exact lengths and SHA-256, and rejects missing, inaccessible,
changed, directory or reparse-point members. It neither imports bundled scripts nor
executes installers. There is no download or network fallback. Output is a pipeline
object; no report, bundle file, schedule or target state is written.

## Require selected-profile coverage during assembly

Add both `-CatalogFileId` and `-CoverageProfileId` to assembly when specified
profiles must have complete declared package content before the folder is committed:

~~~powershell
$result = .\tools\New-RideOfflineBundle.ps1 -ManifestPath 'C:\Preparation\manifest.json' -SourceMapPath 'C:\Preparation\sources.json' -DestinationPath 'C:\Offline\bundle-v3' -CatalogFileId 'catalog' -CoverageProfileId 'workstation','server'
$result | Format-List Status,CoverageStatus,FailedProfileId,FailureStage,StagingPath
$result.CoverageReports | ConvertTo-Json -Depth 16
~~~

Both ID parameters offer case-insensitive, read-only completion from the supplied
manifest. No host discovery, download or installer runs. Unknown/duplicate IDs,
an unpaired parameter, a catalog larger than 2 MiB or a profile larger than 64 KiB
are refused before staging. `-WhatIf` validates these inputs but performs no copy
or package coverage: CoverageStatus stays Pending and CoverageReports is empty.

Assembly compares the staged catalog/profile bytes and selected dependency files,
using the same preflight as `Test-RideOfflineBundle -CatalogFileId`. Every requested
profile must have SelectedPackageContentComplete true. Missing declarations,
selected omissions, mismatched catalog metadata or invalid declarative source
fail at CheckProfileCoverage. Inspect FailedProfileId and CoverageReports, retain
StagingPath, correct the inputs and retry to a new destination. No success metadata
or final directory is created on this failure. Unselected profiles and unrelated
omissions do not block the requested profiles; their content is still subject to
the complete assembly file-integrity check.

CoverageStatus is NotRequested without these options, Pending before checking,
Passed when every requested profile passes, or Failed when coverage fails.
The completed assembly.json records the selected IDs, catalog ID and coverage
status. Always also inspect the overall Status: later integrity or directory-commit
failure can fail assembly after coverage passed. Earlier schema-1 manifests and
integrity-only assembly remain supported; no retained bundle is rewritten.

This gate checks declared package content. Hidden installer dependencies,
non-package resources, engine provenance, target applicability and actual offline
behavior remain separate. OfflineGates and ReadyForMutation=false remain visible
in preparation reports. Explicit offline install/apply adds a whole-plan execution
gate above and rechecks files under read leases. It supports portable deployment
and MSI installers only when the selected artifact is marked
`DeclaredNoNetwork`, has exactly one payload and no declared/catalog dependency
actions, and the catalog target has already passed native acceptance. All other
installer types fail closed before mutation. This declaration does not prove an
EXE or MSI will avoid network access; test actual installer behavior on a
disconnected disposable Windows VM. Native acceptance and broader
installer/dependency coverage remain separate.

## Schema-1 manifest contract

The JSON root has exactly SchemaVersion=1, Kind=RideOfflineBundle, BundleId,
BundleVersion, Engine, Files, Artifacts, ServicingSources and Profiles. Unknown
fields and malformed/duplicate IDs, unsafe paths and unsupported versions are
rejected. This is a separate contract from package observations, toolkit ownership
and saved run/recovery manifests. A future assembler must generate it from pinned
reviewed source; hand-entered dependency lists are not proof of complete coverage.

| Section | Required content |
| --- | --- |
| Engine | Version, full SourceCommit, FileIds. Every referenced file has role Engine. The preflight does not verify commit provenance or whether every engine dependency is listed. |
| Files | Id, RelativePath, Role, Sha256 and nonnegative Length. Roles are Engine, Profile, Payload, Notice or ServicingSource. Case-insensitive duplicate paths, traversal, ADS, reserved names and file/descendant collisions are refused. |
| Artifacts | Id, PackageId (stable catalog operation ID, such as package.7zip), Variant, Version, Architecture, Targets, Status, OmissionCode, FileIds, DependencyIds, OfflineCapability, ProductUri, DownloadUri, License and LicenseUri; optional TermsUri. References are official HTTPS metadata supplied by assembly, not fetched or authenticated here. |
| ServicingSources | Id, Status, OmissionCode, FileIds, Target, Build, EditionId, Architecture and Compatibility=Unverified. This version never accepts a manifest claim of native servicing compatibility. |
| Profiles | Id, FileId, Target, Build, EditionId, Architecture, ArtifactIds and ServicingSourceIds. FileId must reference a Profile file; requirements include declared transitive artifact dependencies. |

Artifacts and servicing sources have Included or Omitted status. Included records
reference actual files and have a null OmissionCode; artifacts must include a
Payload, not just a notice. Omitted records have no file claims and use Missing,
Restricted or TechnicalPending. Required missing dependencies must have explicit
omission records; they cannot silently disappear. Cyclic/deep selected dependency
graphs are refused. Artifact and servicing identities must not collide.

OfflineCapability is Unverified, DeclaredNoNetwork or NetworkRequired. Even
DeclaredNoNetwork is a supplied assertion, not independently tested behavior.
Installer-internal downloads, activation, prompts, drivers and reboot behavior
remain product-specific gates. Offline execution enforces no network fallback;
it does not firewall an installer or guarantee its actions remain local. Preserve
upstream notices and agreements with the original payload; listing one notice
does not prove all required notices exist.
No credentials, private license-review records or organization assessment fields
belong in the shared manifest. Q14's pending local review must not become an
installation gate; publication omissions remain a distinct decision.

Bounds: 4 MiB UTF-8 JSON at the CLI, 32,768 file records, 4,096 artifacts, 256
profiles and servicing sources, 128 dependency levels, 1,024-character relative
paths and 128 GiB selected bytes by default. `-MaximumBytes` explicitly changes
the byte limit up to 1 TiB. Files whose declared/actual lengths differ are not
hashed. Only the selected profile and its declared requirements are hashed.

## Reading the result

SelectedDeclaredContentComplete is true only when the selected engine/profile,
artifact closure and servicing files match their hashes and their declared
target metadata matches. Unrelated omissions are listed in BundleOmissions and
make BundleDeclaredStatus Incomplete, but do not block complete selected content.
NoDeclaredOmissions is not a whole-bundle integrity certification: unselected files
are not hashed. OfflineGates separately reports unknown/network-required artifacts
and native servicing compatibility. A media build/edition/architecture mismatch
is reported, but matching those labels cannot prove FOD/language/image suitability.

ManifestCoverageVerified, EngineSourceCommitVerified, ProfileDependencyClosureVerified
and ActualTargetVerified remain false. With -CatalogFileId, preflight parses bounded catalog/profile data to discover
missing package declarations. It does not authenticate publisher hashes,
validate signatures or inspect the real target. ReadyForMutation and
RecoverySupported remain false. The result is a sequential read observation and
must not be reused as a durable authorization after files or target state change.

Package coverage compares an explicitly declared catalog DownloadUri with the
selected artifact's exact source string, including case-sensitive paths and query
parameters. A different source reports CatalogDownloadUriMismatch even when its
payload digest matches. CatalogDownloadUriComparison distinguishes Matched,
Mismatch, NotDeclared (provider-resolved source), and NotCompared (no unique
selected artifact). Matching metadata does not authenticate a download or its
redirect chain; DownloadSourceVerified stays false. Provider-resolved sources
still need separate pinned acquisition evidence.

The explicit offline installation path preflights the complete selected deployment
before **any** target change, verify its source coverage and native eligibility,
then execute locally without network fallback or version advancement. A partial
bundle may serve complete profiles; missing content unrelated to that profile
does not block it. The execution gate accepts portable, EXE and MSI packages only
under the declared no-network and dependency constraints above; unsupported
requirements fail before mutation.

## Comparing profile package declarations

Import modules/RIDE.OfflineBundle.psm1 and call Test-RideOfflineProfileCoverage
with a validated Catalog, effective Profile, Manifest, ProfileId, CatalogFileId and
the exact CatalogSha256/ProfileSha256. CatalogFileId identifies an Engine file;
the profile file comes from the manifest profile record. The supplied hashes must
match those records. This programmatic comparison reads no files or target state:
the caller must bind hashes to the parsed bytes before trusting the result.
The preflight -CatalogFileId option does this binding: it captures bounded UTF-8
bytes under read-sharing locks, verifies their exact manifest hashes, then uses
the same text with the declarative AST evaluator. Executable expressions, changed
digests and reparse paths are refused. Catalog/profile limits are 2 MiB/64 KiB.

The comparison expands ordinary package groups in order and follows catalog
PrerequisitePackageId links. It rejects unknown fields, cycles, overlapping
selections and Store workflows. A package with variants requires an explicit
variant in the effective profile; flatten groups when individual variants are
needed. Host preferences are never consulted. Only artifacts in the selected
manifest closure count, including dependencies. Missing, omitted or ambiguous
package/variant declarations remain visible. Catalog version, architecture,
product/licence references and single-payload digest pins are compared where
declared. No acquisition URL or publisher authenticity is inferred.

SelectedPackageDeclarationsComplete covers this package comparison only. Actual
file integrity, hidden installer dependencies, non-package resources, target
compatibility and removal/recovery source needs remain independent. A catalog
prerequisite adds a preparation requirement, not permission to install it. The
direct data API reports ParsedBytesBindingVerified=false. The byte-bound wrapper
sets that field true after captured-byte parsing. ProfileCoverageStatus is Compared,
SourceUnavailable or NotRequested. SelectedPackageContentComplete combines file
integrity and package declarations, and is null without requested coverage. Hidden
installer dependencies and non-package resources remain unverified. ReadyForMutation
is false for the standalone preparation report; install/apply with explicit offline
options adds the whole-plan execution gate described above. Conditional hardware profile
fields are currently refused, not ignored. The accepted Lenovo conditional scope
must include payloads regardless of the preparation computer's manufacturer once
its profile representation is implemented.

See the [coverage evidence](migrations/application-migration-review.md#b10-offline-profile-package-coverage-2026-10-17).

## Refresh and recovery

Prepare refreshes as new bundle versions with RIDE, effective profiles and
payloads pinned together. Reuse downloads only after identity/integrity verification.
Retain previous versions until the operator explicitly removes them; any later
shared storage must preserve retained versions' usability. This differs from the
separate toolkit update policy for unchanged owned files.

Read-only preflight needs no state recovery. Assembly creates only a new version
and retains failed staging; preserve its reported path for inspection. Preserve partial bundle content and
omission evidence; acquire or correct content in a new preparation version rather
than silently replacing a retained version. Do not delete user data or caches on
a failed check. See [dated implementation evidence](migrations/application-migration-review.md#b10-local-offline-bundle-preflight-2026-10-17)
for initial preflight boundaries, and [assembly evidence](migrations/application-migration-review.md#b10-explicit-local-offline-bundle-assembly-2026-10-17)
for local copy/recovery checks. The focused `OfflineCaffeine` disposable runner
passed 16 disconnected portable CLI install/apply, repeat, fail-closed preflight
and saved recovery checks on Windows 11 build 26300 through the registered task.
Broader installer/dependency/servicing, interruption and other-target acceptance
remain open. See the
[current acceptance record](migrations/application-migration-review.md#preregistered-acceptance-and-deferred-elevation-2026-10-17)
and [checkpoint-backed procedure](../tests/integration/README.md#focused-reviewed-portable-packages).
