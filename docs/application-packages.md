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
note. RIDE refuses a different installed edition; switching editions requires
a reviewed edition change. `show`, default `status` and removal use the recorded
selection where available. An explicit profile compares its requested edition.

Profiles select a distribution on the package entry:

```powershell
@{ SchemaVersion = 1; Name = 'Optional portable tools'; Operations = @(
  @{ Id = 'package.sharex'; State = 'Present'; Variant = 'portable' }
) }
```

Groups retain their catalog ordering and use package defaults. Select alternate
variants on individual package entries. Group removal reverses dependency order.

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

Portable payloads are copied, never run. ZIP extraction rejects traversal,
absolute paths, streams, reserved device names, duplicate paths, links and
oversized archives. All supplied files, including notices, are retained.
Required files must exist before product writes. RIDE refuses unowned filename
collisions and never adopts an arbitrary pre-existing installation.

The product's `.ride-package.json` records owned relative paths and hashes,
version, variant and artifact evidence. Missing or modified owned files make
the installation unhealthy. Upgrades reject modified owned files. Removal
deletes matching owned bytes, preserves modified files, application data and
unowned content, and leaves the tools root intact. Preserved modifications are
reported; installing again over those files requires an individual decision.
An interrupted write retains an `Installing` ownership journal and a saved run.

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

Ownership manifests are replaced atomically. Installation and restoration
write an incomplete ownership journal before copying files, so a partial copy
remains recognizable and can be retried from retained recovery bytes.

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
Desktop products declare `RequiresDesktopExperience`; planning/execution and
saved-run preflight reject Server Core explicitly. The integration ledger reports
that applicability separately from failures. Detection follows Microsoft's
[InstallationType reference](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ee391629(v=vs.85)).
