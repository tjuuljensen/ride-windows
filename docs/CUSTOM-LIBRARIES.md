# Custom libraries

The first v3 library milestone loads **explicit local metadata libraries**.
Maintainers can keep catalogs and profiles in another repository and reuse
RIDE's built-in `RegistryValue`, `RegistryValueSet` and `Package` handlers without
editing the engine.
Custom handler modules and profile inheritance are still pending release work.
Library API 1 is the initial contract; runtime VM acceptance remains pending.

## Create a library with the guided helper

Run from the RIDE checkout:

```powershell
.\tools\New-RideLibrary.ps1 -Path .\my-library
```

The helper offers numbered choices for **Package**, **RegistryValue** or
**RegistryValueSet** (several values implementing one setting), then
asks only for that kind's fields. For a package, it first offers an optional
test download URL or local sample, before the name, scope, targets and architecture
questions. Choose **Exe** or **Msi**, with direct or **Zip** packaging, a scope,
architecture, tested targets and download source. EXE silent arguments
come from the publisher; MSI suggests `/qn /norestart`. It asks for the name
shown in Windows installed apps and escapes it into an exact detection regex.
Choose targets you intend to validate; choosing a name does not prove support.
For registry entries it offers supported types, converts literal values and
asks for platform defaults rather than reading the author's machine.
It accepts HKCR paths and maps them to an explicit user/machine Classes root.
Enter a blank value name for the unnamed `(Default)` value.

Press Enter to omit documentation/product, license/terms and recovery-information links.
Type `:cancel` at any prompt to stop. You can add several operations in one
session. The helper writes a manifest, catalog and `profiles/custom.psd1`, and
validates the project with the normal resolver before publishing it. It never
installs anything or applies its generated profile. Creating a library requires a
new path; use `-Add` below to extend an existing generated library.

## Add another product to your library

Use the same wizard with `-Add`:

```powershell
.\tools\New-RideLibrary.ps1 -Path .\games-library -Add
```

It loads the existing namespace and suggests the next patch version, such as
`0.1.0` to `0.1.1`. Enter the new operation's local name and metadata as before.
Existing operation IDs, group membership and profile selections are preserved;
the new selection is appended to `profiles/custom.psd1`. You can add several
operations in one session. Duplicate operation/package IDs and a non-increasing
version are rejected. This command adds operations; it does not replace or rename
existing products, apply a profile or run an installer.

Preview with `-WhatIf` to avoid downloads and file changes. `-Definition` also
works with `-Add`: declare the existing library `Id`, a higher `Version`, and only
the new local `Operations`. The exported module function is
`Add-RideLibraryOperation -Path <directory> -Definition <hashtable>`.

Add mode supports the generated layout: `ride-library.psd1`,
`catalog/operations.psd1`, and a declared `profiles/custom.psd1`. Additional
declared profiles are preserved. Linked metadata files/directories are refused.
It validates staged metadata before updating the three managed files, and leaves
other files untouched. Generated catalogs/profiles are serialized again; their
metadata values are preserved, while embedded formatting/comments may change.

Each update retains the previous manifest, exact catalog bytes and all declared
profiles under `<library-directory>.history/<old-version>-<unique-id>/`.
The command returns `PreviousManifest`. Use that manifest with `-Library` to
restore a run saved with the prior catalog; the active updated manifest has a
different version/fingerprint. Keep these history directories with your library.
Unrelated assets are not archived by this metadata-only update.

During publication, `.ride-authoring.lock` blocks readers from loading mixed
versions. Concurrent helper updates are refused, and changes detected during
reading abort the update. A normal write failure restores the original metadata
and retains the backup. A process crash or failed rollback can leave the lock:
its contents identify the previous manifest. Recover that retained metadata
before removing a stale marker. No saved Windows state is discarded.

Inspect choices without starting the wizard:

```powershell
.\tools\New-RideLibrary.ps1 -ShowOptions
Get-Help .\tools\New-RideLibrary.ps1 -Full
```

Choices come from `RIDE.LibrarySchema.psm1`, also used by the library resolver;
target names come from the operation catalog. Path/definition parameters use
ordinary filesystem completion. The helper imports no operational engine.
Each run reloads the authoring schema and refreshes project-validation modules
before publishing, so an updated checkout works in an existing PowerShell console.
Missing choices or an unavailable default stop with a clear error instead of an
input loop. If a wizard was already running during an update, type `:cancel` and
start it again to load the current script and choices.

## Inspect an early installer sample

Select **Download URL** or **Local file** when the wizard offers sample inspection.
It reads content headers, hashes and version resources without executing the
installer. A single ZIP installer is inspected automatically; several candidates
require a numbered choice. Results supply editable defaults for installer format,
ZIP packaging/member, product name, resource version and local download filename.
The sample URL is offered as the installation source; confirm it is the publisher
source you intend to use. Failed inspection leaves manual authoring available.
`-WhatIf` prevents sample downloads, temporary extraction and project writes.

Inspection is also available independently:

```powershell
.\tools\Inspect-RideInstaller.ps1 -Uri 'https://win7games.com/download/Windows7Games_for_Windows_11_10_8.zip'
.\tools\Inspect-RideInstaller.ps1 -Path 'C:\Downloads\Windows7Games_for_Windows_11_10_8.zip'
```

Downloads are temporary, HTTPS only (including at most five redirects), limited
to 256 MiB and bounded by request/read timeouts and a 120-second streaming limit.
The helper sends the source origin as referrer for publishers that require one.
ZIP inspection accepts at most 128 entries, 1 GiB of declared expanded content
and a 512 MiB installer member. Temporary files are removed on success or failure;
local input files remain unchanged. ZIP member completion is available on
`Get-RideInstallerInspection -Path <file> -InstallerEntry <Tab>` and never downloads.

Resource names and versions need review: a bootstrapper version can differ from
the product version. `BinaryArchitecture` describes the launcher; a 32-bit launcher
can install 64-bit payloads. Architecture, targets, scope, installed-app detection,
license references and silent arguments remain explicit operator decisions. MSI
identification uses its container header and filename; it does not run Windows
Installer to interrogate the package. Observed hashes are never silently promoted
to expected publisher checksums.

### Windows 7 Games inspection example, 2026-10-10

The supplied ZIP was inspected successfully without executing its contents:

| Observed field | Result |
| --- | --- |
| Packaging / installer | ZIP / EXE |
| Installer member | `Windows 7 Games for Windows 11, 10 and 8-4.3-setup.exe` |
| Resource product / version | Windows 7 Games for Windows 11, 10 and 8 / `4.3` |
| Launcher architecture | `x86`; payload architecture still needs confirmation |
| Download SHA-256 | `b0db854664ba1b092e4f602dae9101130cb9a50cba103c9ef8b57362d7762b56` |
| Installer SHA-256 | `ae3ff402b459d4343d9fd0edf0d46186b9f604b2c989c9c8aa99adedfe4958ee` |

The archive also contains a `.sha256` file. The inner EXE hash matches the current
checksum on the [publisher page](https://win7games.com/); use that value for
`ExpectedInstallerSha256`, **not** `ExpectedSha256` of the ZIP. The publisher page
documents `/SP- /SILENT`, but its command still names version 4.0. Verify arguments,
actual installed-app name, scope, payload compatibility and removal in a disposable
Windows VM before applying a generated profile. Inspection does not establish
licensing terms, package lifecycle acceptance or Server support.

## Try a different package

The [KeePassXC authoring example](../examples/authoring/keepassxc.psd1) declares
a pinned MSI from the publisher's [download page](https://keepassxc.org/download/).
It intentionally omits the optional product URL. The publisher lists an MSVC
Redistributable prerequisite; prepare that in the disposable VM first. This
example has metadata validation only; installation, detection and removal still
need VM acceptance.

```powershell
.\tools\New-RideLibrary.ps1 -Path .\my-library -Definition .\examples\authoring\keepassxc.psd1 -WhatIf
.\tools\New-RideLibrary.ps1 -Path .\my-library -Definition .\examples\authoring\keepassxc.psd1
.\tools\validate.ps1 -Library .\my-library\ride-library.psd1
.\ride.ps1 list packages -Library .\my-library\ride-library.psd1
.\ride.ps1 apply -Library .\my-library\ride-library.psd1 -Profile .\my-library\profiles\custom.psd1 -WhatIf
```

`-Definition` is a repeatable alternative to console prompts and requires
`-Path`. It accepts a bounded declarative `.psd1` with `Id`, three-part `Version`
and an `Operations` array; no expressions are executed. Each operation has a
local `Id`, `Kind`, `Name`, `Description`, `Scope` and `SupportedTargets`.
The generator adds the namespace, handler, actions, elevation and rollback
metadata. Its per-kind fields use the catalog names shown below. Package IDs
default to the full namespaced operation ID. Registry definitions need `States`,
`BaselineState` and explicit `TargetDefaults`; the generated profile selects the
first non-baseline state alphabetically. Review it before applying.

## HKCR and coordinated registry entries

HKCR is a merged view. Microsoft recommends writing user-specific registrations
under `HKEY_CURRENT_USER\Software\Classes`, and machine defaults under
`HKEY_LOCAL_MACHINE\Software\Classes`; see
[HKEY_CLASSES_ROOT](https://learn.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key).
The helper accepts `HKCR:\...`, `HKEY_CLASSES_ROOT\...` or
`Registry::HKEY_CLASSES_ROOT\...` and displays the physical destination according
to the chosen scope. It also accepts long HKCU/HKLM root names from `.reg` files.
A path conflicting with the selected scope is refused. Generated catalog metadata
uses explicit HKCU/HKLM paths, so inspection and saved-run restore use that same
location. No HKCR drive is created and the merged view is not used for writes.

Choose `RegistryValue` for one value, or `RegistryValueSet` for 2-10 coordinated
values representing one setting. A value set uses `RegistryValues`, with one
unique `Key`, `RegistryPath`, `ValueName` and `ValueType` per component. Each state
maps every component key to its desired value. Supported component types are
`String` and `DWord`; single-value operations retain all listed registry types.
Custom documentation is optional. Literal value-set defaults remain
`PlatformDefined` until verified; the wizard asks for the effective behavior.

Enter a blank value name (or declare `ValueName = ''`) for `(Default)`, the `@`
value in a `.reg` file. An empty String **data value** writes an empty string;
`$null` removes the value. They are distinct states. `WindowsDefault` removes all
declared overrides. Saved-run restore recovers each value and original type in
reverse component order; newly created declared keys are removed only when empty,
and unrelated content is preserved. The operation does not delete a registry tree.

The [Certutil context-menu definition](../examples/authoring/certutil-context-menu.psd1)
declares the corrected two values as one setting: `Icon = 'shell32.dll,-152'`
and the unnamed command value `cmd.exe /k certutil -hashfile "%1" SHA256`.
Version 0.1.1 corrected the original empty value named `shell32.dll,-152`.
Version 0.1.2 uses the requested `SHA-256 with Certutil` verb key and display name;
Certutil's algorithm argument remains `SHA256`. The operation ID and component
keys remain stable, but the registry destination changes. Preserve generated
0.1.0/0.1.1 libraries and manifests for old-run recovery; restore earlier runs
with their original library before publishing this definition to a separate
library and applying it. The new definition leaves old verb keys untouched.
The [standalone registry example and attachment](../examples/hash-context-menu/README.md)
describe direct import and its recovery limits. The example selects User scope
and Windows 11 for pending VM acceptance. Change Scope to Machine for an elevated,
machine-wide registration. The [Shell documentation](https://learn.microsoft.com/en-us/windows/win32/shell/context-menu-handlers)
describes static verb registration and unnamed command values. This metadata
example does not establish menu visibility or hashing behavior on a target build.

Create and preview a separate library:

```powershell
.\tools\New-RideLibrary.ps1 -Path .\context-menu-library -Definition .\examples\authoring\certutil-context-menu.psd1
.\ride.ps1 apply -Library .\context-menu-library\ride-library.psd1 -Profile .\context-menu-library\profiles\custom.psd1 -WhatIf
```

To add it to an existing generated library, use the interactive `-Add` wizard and
choose `RegistryValueSet`. For noninteractive `-Add`, copy the definition, set
its `Id` to the existing library namespace and `Version` to a higher version,
and pass that copy with `-Definition`. Keep published operation IDs stable.

## Package fields and source choices

| Field | Valid values or meaning |
| --- | --- |
| `InstallerType` | `Exe` or `Msi`, including one self-contained installer inside a ZIP. Portable deployment and custom installers remain outside API 1. |
| `ArchiveType` | Optional `None` (default) or `Zip`. ZIP currently requires `DirectHttps`. |
| `InstallerEntry` | Required for ZIP: exact case-sensitive relative EXE/MSI member path using forward slashes. Spaces are allowed; traversal, absolute paths, links and duplicate case-insensitive matches are rejected. |
| `ExpectedInstallerSha256` | Optional publisher-provided hash of the selected installer inside ZIP, checked before execution. Only valid with ZIP packaging. |
| `Scope` | `User` or `Machine`; choose the actual installation context. Machine requires elevation. |
| `Architecture` | `x64`, `x86`, `arm64`; must match the selected installer. |
| `DownloadProvider` | `DirectHttps` for an explicit versioned installer, or `GitHubReleaseApi` for the publisher's latest release asset. |
| `DownloadUri` | Required HTTPS publisher source. GitHub API uses `https://api.github.com/repos/OWNER/REPO/releases/latest`. |
| `PackageVersion`, `AssetName` | Required for `DirectHttps`: safe version and local `.exe`/`.msi` filename matching installer type, or `.zip` for ZIP packaging. |
| `ExpectedSha256` | Optional 64-character publisher-provided hash of the download; use the ZIP hash for ZIP packaging. A mismatch stops before installation, including cached payloads. |
| `AssetPattern` | Required for `GitHubReleaseApi`: valid regex matching exactly one installer asset. |
| `DisplayNamePattern` | Valid nonblank regex matching the installed app's registered name. Wizard creates an escaped exact-name pattern; versioned names may need review. |
| `InstallerArguments`, `UninstallerArguments` | Publisher-documented silent switches. MSI requires `/qn /norestart` for installation. |
| `SuccessExitCodes` | Optional integer array; handler defaults to `0`. Wizard MSI includes `3010` for reboot-required success. |
| `License` | Required text summary; `Unknown` is the wizard default. Describe a license in the installer/archive or a local file here when no online reference exists. |
| `LicenseUri`, `TermsUri` | Optional absolute HTTP/HTTPS information links for custom packages. Internal hosts, localhost and non-default ports are accepted. Credentials and active-content schemes are rejected. Omit unavailable links instead of inventing a URL. |
| `ProductUri` | Optional HTTPS product/documentation link for custom packages. |
| `RecoveryUri` | Optional HTTPS recovery instructions, retained with saved state. Information only. |

Direct sources use the default HTTPS port without embedded credentials or
fragments. The declared version identifies the cache directory; it does not
make a mutable URL immutable. Prefer version-specific publisher URLs and supply
an expected digest when available. RIDE records the acquired hash/signature;
an observed local hash alone does not authenticate the publisher. GitHub assets
must still belong to the declared repository. An omitted `ProductUri` uses the
source origin for acquisition evidence.

ZIP packages retain the complete source archive and upstream notices in the
versioned cache. Acquisition evidence records the selected member's hash separately
from its parent archive. Installation extracts only that member to a new temporary
directory, verifies type and an optional member hash, waits for the installer process,
then removes staging even on failure. The source archive remains available. This
path supports a self-contained installer that completes before its process exits;
adjacent payloads, detached workers and portable apps need a different handler.
Removal and saved-run restore use the existing EXE/MSI compensating lifecycle.

## Try the starter library

Copy `examples/contoso/` to your own working directory or repository. Its
`ride-library.psd1` names an external catalog and a profile. The setting writes
an inert organization marker under `HKCU:\Software\RIDE\Examples\Contoso`;
it does not configure a Windows feature. The package group references
`package.7zip` from the built-in catalog rather than duplicating that product.

From the RIDE checkout, using the example in place:

```powershell
.\ride.ps1 list -Library .\examples\contoso\ride-library.psd1
.\ride.ps1 search PreferenceMarker -Library .\examples\contoso\ride-library.psd1
.\ride.ps1 list profiles -Library .\examples\contoso\ride-library.psd1
.\ride.ps1 plan -Library .\examples\contoso\ride-library.psd1 -Profile .\examples\contoso\profiles\workstation.psd1
.\ride.ps1 apply -Library .\examples\contoso\ride-library.psd1 -Profile .\examples\contoso\profiles\workstation.psd1 -WhatIf
```

Replace those paths with your external copy to use it outside the checkout.
Loading a library never selects or applies a profile automatically. Without
`-Profile`, profile commands keep their usual built-in default. Review the
profile before applying it; the example's 7-Zip installation requires elevation.
Use disposable Windows VMs for development lifecycle checks.

Tab completes manifest filesystem paths. Put `-Library` before the value being
completed to expose that selection's operation/group IDs, states, category
views and declared profile paths. Completion and search load data only, with
no engine, handlers, network access or state writes. Invalid optional completion
data fails quietly; an invalid library passed to a command fails explicitly.

## Manifest contract

```powershell
@{
  SchemaVersion = 1
  Id = 'example.contoso'
  Version = '0.1.0'
  EngineApiVersion = 1
  Catalog = 'catalog/operations.psd1'
  Profiles = @('profiles/workstation.psd1')
}
```

All six fields are required; additional fields are rejected. `Id` is a lowercase
library namespace; `Version` is a three-part numeric version. `EngineApiVersion`
identifies the library interface, separately from the engine's implementation
version. This implementation accepts schema 1 and API 1 only.

`Catalog` and every `Profiles` entry are literal relative `.psd1` paths inside
the manifest directory. Absolute paths and parent traversal are rejected.
The resolver reads only declared files; it does not scan for modules or
libraries. Files remain trusted local material; these path rules are not a
sandbox against filesystem links or untrusted PowerShell handlers.

Select multiple manifests with `-Library <first-path>,<second-path>`. The
resolver merges their data before validating references, so references may
use built-in IDs or IDs from other selected libraries. Each selected manifest
path and library ID must be unique. There is no remote dependency installation.
Limits are 32 selected libraries, 128 declared profiles per library, 256 KiB per
manifest/profile, and 2,000 total resolved catalog entries. Catalog files retain
the bounded reader's 2 MiB limit.

## Catalogs, profiles and ownership

Use the same schema-1 `Operations` and `Groups` structure as
`catalog/operations.psd1`. Every external operation and group ID starts with
the manifest ID plus a dot, such as `example.contoso.preference-marker`.
Keep published IDs stable. Duplicate IDs are errors, including operation/group
collisions; libraries cannot override built-in entries. `Library` metadata is
reserved for ownership assigned by the resolver.

API 1 accepts these external operation kinds:

| Kind | Implementation and required metadata |
| --- | --- |
| `RegistryValue` | Built-in registry lifecycle, declared states and value type, baseline, target defaults and scope/elevation. Documentation URL is optional for custom entries. User paths must use HKCU; machine paths must use HKLM. |
| `RegistryValueSet` | One setting with 2-10 String/DWord components, complete named states, baseline and target defaults. Blank ValueName selects the unnamed value. Paths use explicit scope roots; documentation URL is optional. |
| `Package` | Built-in EXE/MSI lifecycle with DirectHttps or GitHubReleaseApi acquisition, declared installer/detection metadata, target defaults, license references and compensating recovery limits. Product URL is optional; source and Download action remain required. |

Metadata uses the existing shared catalog validator, not a separate simplified
catalog format. Registry state values must match their declared registry type.
API 1 accepts String, ExpandString, Binary, DWord and QWord; MultiString lifecycle
support is deferred. DWord data uses signed 32-bit PowerShell integers (for
example `0xffffffff` for all bits set) to match the registry reader's representation.
Unsupported kinds or custom handlers are rejected before execution. A package
must have a filesystem-safe `PackageId`; two operations cannot own the same
PackageId. Reference an existing product's operation ID when it already exists.
Publisher/source review and disposable-VM acceptance remain the maintainer's
responsibility; schema validation does not establish product compatibility.

Optional custom `DocumentationUri`, `ProductUri` and `RecoveryUri` fields must
be valid HTTPS links when supplied; omit the field instead of using an empty
string. A custom registry link may describe organization-specific behavior.
The built-in catalog retains its required Microsoft/product references.
Custom license/terms references may use HTTP or HTTPS, or be omitted. They are
informational metadata and are not downloaded, executed or treated as approval
of licensing or distribution. The built-in catalog retains required official
HTTPS license references. Custom installer acquisition still requires HTTPS.

External groups contain ordered package operation IDs. Removal uses the normal
reverse member order. Profiles explicitly select operation/group IDs and states
using the existing profile format; declared external profiles are validated
against the merged catalog and appear in `list profiles`. External profile rows
include their absolute file path. General profile inheritance is not implemented.

## Validate and export references

```powershell
.\tools\validate.ps1 -Library .\examples\contoso\ride-library.psd1
.\tools\Export-RideCatalog.ps1 -Library .\examples\contoso\ride-library.psd1 -OutputPath .\examples\contoso\OPERATIONS.md
.\tools\Export-RideCatalog.ps1 -Library .\examples\contoso\ride-library.psd1 -OutputPath .\examples\contoso\OPERATIONS.md -Check
```

Validation includes the selected libraries and profiles while still checking
the built-in generated reference. External exports require a separate explicit
output file; they cannot replace the built-in `docs/OPERATIONS.md`. Exported
references include the selected library IDs and versions.

For direct module use, import `modules/RIDE.Engine.psm1`, then call
`Set-RideLibraryContext -Library <manifest-paths>` before the normal engine
commands. Selection validates and stores metadata in session memory. A failed
selection preserves the previous valid context; a call without `-Library`
clears the selection. Re-select after editing library data. The CLI establishes
a fresh selection on each invocation.

## Saved runs and upgrades

Applying external entries uses normal target/elevation checks, ShouldProcess,
per-scope snapshots and partial-failure reporting. Settings retain exact-value
recovery; packages retain their existing compensating version-recovery limits.
Preview does not save state or invoke writers/installers.

An optional `RecoveryUri` is copied into snapshots and shown when a missing or
changed library blocks recovery, or when package restoration can only reinstall
the declared installer. It can link to older releases or manual recovery
instructions. It is never fetched or executed, and does not enable automatic
downgrade or exact package-version restore.

An external operation snapshot uses saved-state schema 2 and includes the
library ID, exact version, catalog SHA-256, engine API, handler and snapshot
schema. Mixed-run manifests use schema 2 with library identities; built-in
operation snapshots remain schema 1. The engine still restores existing
built-in schema-1 runs. Older engines are not a supported recovery path for
external schema-2 records.

Restore checks every saved operation's identity and target before invoking the
first writer. A missing library, changed version or changed catalog causes an
actionable error and retains saved state. Select the original manifest with
`-Library` when restoring; moving an unchanged library to another directory is
allowed. Even a same-version catalog edit, including comments or line endings,
changes its fingerprint. This hash identifies recovery metadata; it is not
publisher authentication.

Retain tagged or archived original library versions and their exact catalog
bytes for outstanding saved runs. Restore with that original version before
upgrading, or keep it available for later recovery. API 1 requires an exact
match; cross-version snapshot migration is future work. RIDE does not fetch
replacement library code or discard snapshots when recovery is unavailable.

## Remaining release work

This foundation does not complete the
[v3 custom-library release requirement](MIGRATION-PLAN.md#custom-library-interface-v3-release-requirement).
Next: design and pilot custom handler registration/dispatch, expand metadata
support as needed, define tested cross-version recovery, and run external
lifecycles in disposable Windows VMs on each declared target. Local validation
and mocked tests do not establish Windows Server or new handler support.
