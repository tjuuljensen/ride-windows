# ride-windows Roadmap

This roadmap merges the previous `TODO.md`, `RIDEadditions2025.md`, and the current modernization assessment into one development path.

## Current State

`ride-windows` is a mature PowerShell bootstrap project for Windows 10/11 and Windows Server setup. Its strengths are the simple preset model, broad coverage, and years of accumulated practical installer and tweak functions.

The main maintenance pressure comes from scale:

- `lib-windows.psm1` is still a large monolithic module.
- Many installer functions repeat the same bootstrap-folder, download, and silent-install boilerplate.
- External downloads are dynamically resolved from GitHub, vendor pages, raw URLs, and scraped HTML with inconsistent verification.
- Some tooling is still exploratory, especially `docs/bootstrap.ps1`.
- Package requests and modernization tasks were split across multiple loose notes.

## Roadmap Principles

- Keep the preset/function-name contract stable while internals are modernized.
- Prefer shared helpers for repeated behavior, but do not force every installer into the same shape when special handling is needed.
- Prefer winget only where it reduces maintenance without weakening reproducibility, licensing clarity, or forensic workstation expectations.
- Add verification and validation before large module extraction.
- Keep roadmap files short enough to scan during maintenance.

## Phase 1: Guardrails

Status: mostly complete.

Completed:

- Added `tools/validate.ps1`.
- Added GitHub Actions validation on push and pull requests.
- Added local Markdown link validation, stale planning-note detection, and likely mojibake detection.
- Validates PowerShell parsing.
- Validates preset entries against available function names.
- Reports duplicate function definitions.
- Fixed `docs/bootstrap.ps1` parser errors and obvious typo.
- Replaced `Invoke-Expression` in `ride.ps1` with function lookup and direct invocation.
- Ignored local/private presets and install logs.

Remaining:

- Decide whether `docs/bootstrap.ps1` should become a supported one-line bootstrapper or be moved to an experimental area.
- Decide whether repository-local VS Code settings should be tracked or kept as operator-local setup notes.

## Documentation Maintenance

Documentation should be maintained as part of the same change that alters behavior:

- Update `README.md` when user-facing usage, supported Windows targets, command-line options, or contribution rules change.
- Update `TODO.md` for short actionable backlog items.
- Update `docs/ROADMAP.md` for modernization phases, package intake policy, and larger design decisions.
- Verify time-sensitive Windows release, lifecycle, package ID, and download-source information before committing it.
- Avoid creating new loose planning notes when an item belongs in `TODO.md` or `docs/ROADMAP.md`.

## Phase 2: Installer Helpers

Status: started.

Completed:

- Added shared helpers:
  - `Test-RideDownloadOnly`
  - `Get-RideBootstrapFolder`
  - `Get-RideSoftwareFolder`
  - `Save-RideDownload`
  - `Install-RideDownloadedExe`
  - `Install-RideDownloadedMsi`
- Converted initial installers:
  - `InstallGitLFS`
  - `InstallGit4Win`
  - `InstallNotepadPlusPlus`
  - `Install7Zip`
  - `InstallVSCode`
  - `InstallSignal`
  - `InstallPython`

Next steps:

- Convert common MSI installers to `Install-RideDownloadedMsi`.
- Convert simple EXE installers in small batches.
- Add helper support for:
  - optional expected SHA256
  - optional Authenticode requirement
  - cache/reuse existing installer
  - forced refresh
  - download-only reporting
- Keep special installers separate until there is a proven shared pattern for archives, portable tools, Git clones, and tools copied into `\Tools`.

## Phase 3: Supply Chain Verification

Goal: make download trust decisions visible and enforceable.

Work items:

- Inventory all external download sources by type:
  - GitHub release asset
  - raw GitHub file
  - vendor HTTPS direct link
  - vendor HTTP link
  - scraped vendor page
  - winget package
  - Git clone
- Add SHA256 verification where stable release assets are used.
- Add GPG/signature verification where upstream makes it practical.
- Add Authenticode verification for Windows installers where useful.
- Mark known unverified downloads explicitly in code comments or package metadata.
- Add an escape hatch such as `-AllowUnverified` only after the default path is clear.

## Phase 4: Module Extraction

Goal: reduce risk in `lib-windows.psm1` without breaking existing presets.

Suggested split:

- `modules/RIDE.Core.psm1`: runner helpers, logging, paths, validation support.
- `modules/RIDE.Installers.psm1`: shared download/install helpers.
- `modules/RIDE.WindowsConfig.psm1`: Windows settings, registry, policy, power, Defender, telemetry.
- `modules/RIDE.Browsers.psm1`: browser install and policy functions.
- `modules/RIDE.Forensics.psm1`: forensic and incident response tooling.
- `modules/RIDE.AD.psm1`: AD, domain-joined, Entra, RSAT, PingCastle, BloodHound related functions.
- `modules/RIDE.Customization.psm1`: fonts, wallpaper, lockscreen, UI customization.

Migration rule:

- Extract one category at a time.
- Keep current function names.
- Keep default preset behavior unchanged.
- Run `tools/validate.ps1` after each extraction.

## Phase 5: Package Intake

Package candidates should be triaged before implementation:

- `direct`: use upstream download because layout, licensing, or reproducibility matters.
- `winget`: use winget because it is stable enough and reduces maintenance.
- `manual`: document only, because licensing, prompts, or risk make automation unsuitable.
- `reject`: not useful enough or too fragile to maintain.

Current candidates from the 2025 note:

| Package | Candidate source | Initial disposition |
| --- | --- | --- |
| PDFgear | `PDFgear.PDFgear` from local note | verify current winget ID before implementation |
| yt-dlp | `yt-dlp.yt-dlp` or GitHub release | direct or winget candidate; verify current source |
| mpv | winget or upstream | candidate; verify source |
| HandBrake | `HandBrake.HandBrake` from local note | winget candidate; verify current ID |
| Beyond Compare | `ScooterSoftware.BeyondCompare.5` from local note | verify current ID and licensing behavior |
| Everything | `voidtools.Everything` from local note | winget candidate; verify current ID |
| Office Deployment Tool | `Microsoft.OfficeDeploymentTool` from local note | winget plus custom XML work; verify current ID |
| OpenSSH Preview | Windows optional feature / winget / Microsoft source | needs investigation |

Existing installers that may get optional winget alternatives:

- 7-Zip
- Git LFS
- Visual Studio Code
- Python
- Signal
- Notepad++

## Near-Term Release Target

A practical next release should include:

- Validation script committed and documented.
- Safer `ride.ps1` invocation.
- First batch of shared installer helpers.
- Initial converted installers.
- `TODO.md` and this roadmap as the single planning source.
- No duplicate active planning notes.
