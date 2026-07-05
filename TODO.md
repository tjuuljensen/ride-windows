# ride-windows TODO

This file is the short operational backlog. Longer planning, package intake, and modernization sequencing lives in `docs/ROADMAP.md`.

## Active Priorities

### A. Reliability and Safety

- [ ] Test running the default preset twice on a fresh Windows 11 VM and fix non-idempotent behavior.
- [ ] Add log overwrite or rotation behavior for `-log`.
- [ ] Add checksum verification for high-risk downloads.
- [ ] Add GPG/signature verification where upstreams publish usable signatures.
- [ ] Add a package download cache rule: if an installer already exists in the bootstrap folder, reuse it unless refresh is requested.
- [ ] Add a clear prompt before installing disk/filesystem recovery tools such as Nucleus on machines where target media could be affected.

### B. Installer Modernization

- [x] Add shared download/install helpers for repeated EXE/MSI installer boilerplate.
- [x] Convert initial EXE installers to shared helpers: Git LFS, Git for Windows, Notepad++, 7-Zip, VS Code, Signal, Python.
- [ ] Convert common MSI installers to `Install-RideDownloadedMsi`.
- [ ] Add optional winget-backed installers for packages where winget is good enough and does not reduce forensic reproducibility.
- [ ] Stage Office 365 deployment through the Office Deployment Tool so custom XML can be used.
- [ ] Add PingCastle license/config support through ini variables.

### C. Architecture

- [ ] Split `lib-windows.psm1` into focused modules once helper conversion has stabilized.
- [ ] Keep old function names as compatibility exports while modules are split.
- [ ] Normalize indentation in touched code as modules are extracted.
- [ ] Add one-line bootstrap/install entrypoint based on the Fedora RIDE pattern.
- [ ] Finish or retire `docs/bootstrap.ps1`; it currently parses, but still contains placeholder behavior.
- [ ] Add a documentation check to validation once the README/roadmap structure settles.

### D. Configuration and Workflows

- [ ] VS Code configuration: disable telemetry and install preferred Markdown extension.
- [ ] BitLocker recovery key export to AD.
- [ ] Install workflow functionality for WSL packages, probably through scheduled tasks rather than PowerShell 6+ workflows.
- [ ] Review OpenSSH Preview for modern cipher support and decide whether it belongs as a RIDE function.

## Package Candidates

Package IDs below are intake hints from local notes. Confirm the current winget ID or upstream release source before implementing a package function.

### General Utilities

- [ ] PDFgear (`PDFgear.PDFgear`, verify current winget ID)
- [ ] yt-dlp (`yt-dlp.yt-dlp`, verify current winget ID or use GitHub release)
- [ ] mpv
- [ ] HandBrake (`HandBrake.HandBrake`)
- [ ] Beyond Compare (`ScooterSoftware.BeyondCompare.5`, verify current winget ID and licensing behavior)
- [ ] Everything (`voidtools.Everything`)
- [ ] Rufus
- [ ] Balena Etcher
- [ ] Slack
- [ ] XMind
- [ ] PowerToys

### Already Implemented, Candidate for Winget Alternative

- [ ] 7-Zip (`7zip.7zip`)
- [ ] Git LFS (`GitHub.GitLFS`)
- [ ] Visual Studio Code (`Microsoft.VisualStudioCode`)
- [ ] Python (`Python.Python.3.x`)
- [ ] Signal (`OpenWhisperSystems.Signal`)
- [ ] Notepad++ (`Notepad++.Notepad++`)
- [ ] Office Deployment Tool (`Microsoft.OfficeDeploymentTool`)

### Forensics, Security, and Analysis

- [ ] Firefox forensic plugins
- [ ] Brim/Zui
- [ ] Scapy
- [ ] SCAP tooling
- [ ] Windows password cracking tooling
- [ ] Explorer default view with three timestamps

## Completed Historical Items

See Git history for the full legacy completed list. Notable completed items include VS Code, Signal, Python, YARA, Hashcat, CyberChef, Arsenal Image Mounter, Windows 11 taskbar tweaks, BitLocker prompt fixes, and firewall functions.
