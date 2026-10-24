# Install programs selector reconciliation

Reviewed 2026-10-11; original acceptance below is from 2026-10-08. All **53** selector names in this migration family have a
disposition below. A deferred selector is accounted for, not implemented or
tested. New packages remain optional; support is declared only after applicable
target tests pass. The portable batch passed Windows 11 and Server 2025 Desktop
Experience; see the [dated acceptance record](../archive/migrations/applications-batch-acceptance-2026-10-11.md).
Existing published IDs remain stable.

The five new packages passed install/repeat/remove in full Windows 11 request
`9744844940fd4ca498ef6486092ac831` (128 guest tests plus integration). PowerShell's
installed executable/version check also passed. Git functionality and Sysmon's
service lifecycle passed in that same suite. These results do not accept Server
targets or any deferred selector below.

| Exact legacy selector(s) | v3 disposition | Evidence or remaining work |
| --- | --- | --- |
| `Install7Zip`, `Remove7Zip` | `package.7zip` | Install, repeat and remove in disposable Windows 11 suite. |
| `InstallGit4Win`, `RemoveGit4Win` | `package.git-for-windows` | Latest patch-version filename fixed; local init/add/commit/HEAD, repeat and remove passed in run `20cb460af8be447dafcfc62662f99d35`. |
| `GetSysmonSwiftXML` | `artifact.sysmon-swift-config` | Download-only immutable commit; applying XML remains an explicit separate action. |
| `InstallSysmon64`, `RemoveSysmon64` | `package.sysmon64` | Archive/member evidence, service detection, repeat and uninstall. No implicit community XML. |
| `InstallNotepadPlusPlus`, `RemoveNotepadPlusPlus` | `package.notepadpp` | Existing EXE lifecycle; signature verification follow-ups in the matrix. |
| `InstallGitLFS`, `RemoveGitLFS` | `package.git-lfs` | Standalone installer needs machine Git; `solution.git-development` installs in dependency order and removes in reverse. Includes temporary process PATH handoff. VM acceptance tracked in migration plan. |
| `InstallJoplin` | `package.joplin` | Current-user NSIS install and compensating uninstall; preserve publisher-owned notebook data. VM acceptance tracked in migration plan. |
| `InstallShareX`, `RemoveShareX` | `package.sharex` | Machine x64 Inno installer and compensating uninstall. VM acceptance tracked in migration plan. |
| `InstallWinDirStat`, `RemoveWinDirStat` | `package.windirstat` | Versioned x64 MSI; `release/` tag prefix handled; quiet no-restart lifecycle. VM acceptance tracked in migration plan. |
| `InstallPowerShell` | `package.powershell` | PowerShell 7 x64 MSI; never replaces Windows PowerShell 5.1. Verify executable/version and remove in VM. |
| `InstallPSScriptTools`, `RemovePSScriptTools` | Deferred: repository acquisition | Managed file ownership is implemented; still need a pinned repository-archive provider, dependencies and notices. Do not substitute Install-Module. |
| `InstallVSCode`, `RemoveVSCode` | `package.vscode` (accepted on Windows 11 and Server 2025 Desktop Experience) | Retains legacy x64 User Setup; official version/SHA-256 feed. See the consolidated application ledger for both target results. |
| `InstallGPGwin` | Unsupported candidate: `package.gpg4win`; Windows acceptance pending | User confirmed current-user scope, GnuPG command line and Kleopatra only, without Explorer/Outlook integration (2026-10-12), and reaffirmed on 2026-10-23 that pre-existing `%APPDATA%/gnupg` keys/configuration must survive install, removal and recovery. Exact 5.1.1 installer/source hashes and signer are verified; mocked coverage exercises component configuration, nested-GnuPG ownership guards and preservation of the user-data directory. Verify outer and nested installer scope, selected components, coexistence and exact recovery on disposable Windows targets. No license blocker. See the [decision](application-review-rounds-2026-10-12.md#confirmed-first-round-choices), [recovery decision](decision-session-2026-10-17.md#gpg4win-user-data-recovery-boundary-confirmation-2026-10-23) and [source/implementation review](application-migration-review.md#gpg4win-5-1-1-current-user-package-candidate-implementation-2026-10-23-1742-utc). |
| `GetSysmonOlafXML` | User selected all three Sysmon Modular release profiles, 2026-10-23 | Offer Balanced, Balanced with FileDelete and Excludes only as separate choices. Pin a reviewed upstream release and target Sysmon version; preserve the distinction between acquiring a configuration and applying it. Excludes only is very verbose; FileDelete uses file archiving. No machine application is authorized by profile selection. [Decision](decision-session-2026-10-17.md#package-and-profile-scope-decisions-2026-10-23); [upstream profiles](https://github.com/olafhartong/sysmon-modular). |
| `InstallVMwareWorkstation`, `RemoveVMwareWorkstation` | Retired from v3 by user decision, 2026-10-24 | Do not implement the legacy VMware Workstation install/remove outcome or substitute another virtualizer. Preserve any existing installation; this decision does not authorize cleanup or runtime changes. |
| `SetVMDirUserhome`, `SetVMDirDocuments` | Deferred: application configuration | These are VMware preferences, not package installations. Need preference discovery, prior-value capture and exact restore under the current user. |
| `InstallThunderbird` | Accepted: `package.thunderbird` | Confirmed Release x64/en-GB, current-user scope. Non-elevated deployment, repeat install/remove, profile preservation and saved-selection recovery passed on both targets; see [correlated acceptance](../archive/migrations/application-thunderbird-follow-up-2026-10-11.md#accepted-migration-after-resumed-validation). Application/mail functionality and exact prior-version recovery remain separate. |
| `InstallImageMagick` | Deferred: variant and release adapter | Choose supported Q16/HDRI/architecture variant explicitly, then verify official checksum and installed detection/removal. |
| `InstallImageMagickPortable`, `RemoveImageMagickPortable` | Deferred: publisher edition/source | Managed ZIP ownership is implemented; exact HDRI/quantum-depth distribution and revision parsing remain unresolved. |
| `InstallSignal` | `package.signal` (accepted on Windows 11 and Server 2025 Desktop Experience) | Stable x64 current-user feed with checked SHA-512; repeat installation/removal, existing Roaming-profile preservation and compensating recovery passed on both targets. Account linking and prior-version recovery remain separate limits. See the [installed acceptance record](../archive/migrations/application-installed-follow-up-2026-10-11.md). |
| `InstallPython` | Partial: manager-default and traditional variants selected; RIDE-managed runtime policy decided | The declarative `windows.python-manager-automatic-install` user setting candidate implements `PYTHON_MANAGER_AUTOMATIC_INSTALL=false` with exact restore; its focused metadata/plan test passes 1/1. Prepare only explicitly selected pinned runtimes; keep runtime updates separate. Manager-managed runtimes remain per-user; preserve existing command resolution and associations by default. Current publisher evidence pins manager 26.4 and candidate PythonCore 3.15.1/3.14.9/3.13.17 manifests, but local bytes are not acquired or verified. Manager auto-updates itself, MSI attempts a machine PATH change, and `python`/`py` aliases require conflict-safe integration. Native environment propagation, exact supported releases, offline-index ownership, launcher coexistence, recovery and disposable Windows acceptance remain open. See the [runtime decision](decision-session-2026-10-17.md#python-ride-managed-runtime-selection-reaffirmed-2026-10-24), [source evidence](../archive/evidence/python-managed-runtime-source-review-2026-10-24-0355.json) and [setting implementation evidence](../archive/evidence/python-manager-auto-install-setting-implementation-2026-10-24-0404.json). |
| `InstallYara`, `RemoveYara` | Classic compatibility option deferred by user decision, 2026-10-22 | YARA-X remains the accepted default standalone engine, with classic YARA a distinct compatibility option. No older binary/build route or silent substitution; the reviewed classic release has no Windows binary assets. |
| `GetCyberChef`, `RemoveCyberChef` | `package.cyberchef` (accepted on Windows 11 and Server 2025 Desktop Experience) | Managed offline release ZIP; retain assets/notices and user recipes, without launching the browser. See the application ledger. |
| `InstallCaffeine`, `RemoveCaffeine` | `package.caffeine` (accepted on Windows 11 and Server 2025 Desktop Experience) | Retains the official 1.98 x86/x64 archive with an inspected hash pin and managed file recovery. No automatic execution/startup. See the application continuation evidence. |
| `InstallPutty`, `RemovePutty` | `package.putty` (accepted on Windows 11 and Server 2025 Desktop Experience) | Retains the legacy standalone x64 executable and resolves a versioned official URL; no MSI substitution. See the application ledger. |
| `InstallWinSCP`, `RemoveWinSCP` | Accepted: `package.winscp` / `portable` | Official stable x86 6.5.7 page/CDN acquisition matches publisher SHA-256. Twelve portable lifecycles and 230 guest checks passed per target, including owned-file recovery, valid EXE/COM signatures and unowned session preservation. Both VMs recovered; see [the acceptance record](../archive/migrations/application-winscp-follow-up-2026-10-11.md#final-correlated-acceptance). |
| `InstallKAPE`, `RemoveKAPE` | Deferred: package source and lifecycle; Defender policy decided | The user authorized an exclusion limited to KAPE's dedicated install directory, with prior-state capture and cleanup only of the exclusion RIDE adds. Defer individual-file exclusions to v3.1; no broad tools-directory exclusion or file allow action. CISA guidance documents antivirus/host-protection blocking for KAPE run from removable media; no KAPE-specific Defender detection or false positive was verified. Exact publisher source, pinned definition inventory, executable dependencies and Windows acceptance remain open; a pinned KapeFiles snapshot and separate refresh were already approved. See the [evidence and decision](application-migration-review.md#kape-defender-compatibility-and-exclusion-decision-2026-10-24-0401-utc). |
| `InstallVeraCrypt` | Deferred: driver/reboot recovery | Driver installation/removal and reboot-required outcomes need an orchestrated VM scenario and version recovery plan. |
| `InstallVeraCryptPortable` | Deferred: portable driver lifecycle | Managed-file ownership alone is insufficient; inspect driver side effects and reboot recovery. |
| `InstallADReplStatus`, `RemoveADReplStatus` | Deferred: upstream availability | Reconcile the legacy distribution's current availability/support and licensing before designing replacement semantics. |
| `InstallFirewallNotifier`, `RemoveFirewallNotifier` | Deferred: firewall policy recovery | Requires managed files plus exact capture/restore of firewall-policy changes; package presence alone cannot establish safe rollback. |
| `InstallShareXportable`, `RemoveShareXportable` | `package.sharex` / `portable` (accepted on Windows 11 and Server 2025 Desktop Experience) | Installed remains the default; ZIP ownership and exact retained-file recovery preserve user settings. See the application ledger. |
| `InstallAutomatedLab` | Deferred: lab-host setup | Installing a package does not provision Hyper-V, host remoting or trust policy. Keep elevated lab provisioning in the runbook; define package prerequisites and recovery independently. |

The managed portable lifecycle is implemented with the configurable machine tools
root and manifest ownership. Remaining product/source acceptance is tracked in the
[consolidated application ledger](application-migration-review.md). Defender exclusions remain separate explicit settings;
they are never added implicitly by a package installer. Deferred installers
need official source adapters and disposable-VM lifecycle evidence, rather
than execution of legacy scripts.

Use the optional `profiles/git-development.psd1` for the ordered Git solution:

```powershell
.\ride.ps1 plan -Profile .\profiles\git-development.psd1
.\ride.ps1 apply -Profile .\profiles\git-development.psd1 -WhatIf
.\ride.ps1 remove -Profile .\profiles\git-development.psd1 -WhatIf
```

Apply/remove require elevation. Direct package actions install only the named
package; the standalone LFS action reports a missing Git prerequisite instead
of silently installing it.
