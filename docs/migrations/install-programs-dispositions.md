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
| `InstallGPGwin` | Deferred: components, dependency ownership and lifecycle | Exact 5.1.1 installer/source match published hashes and current signer reference. Current component controls were inspected; pending component/scope choices and nested GnuPG coexistence/removal need explicit ownership and key/configuration recovery. See the installed continuation review. |
| `GetSysmonOlafXML` | Deferred: obsolete source reconciliation | Legacy root `sysmonconfig.xml` is no longer the selected current artifact. Upstream now supplies templates; select a specific configuration and immutable revision explicitly before adding an artifact. Do not silently substitute a different policy. [Upstream templates](https://github.com/olafhartong/sysmon-modular/tree/master/templates). |
| `InstallVMwareWorkstation`, `RemoveVMwareWorkstation` | Deferred: licensed distribution | Broadcom download access/license acceptance and driver/reboot lifecycle require a documented supplied-artifact workflow. No unattended credential or license assumption. |
| `SetVMDirUserhome`, `SetVMDirDocuments` | Deferred: application configuration | These are VMware preferences, not package installations. Need preference discovery, prior-value capture and exact restore under the current user. |
| `InstallThunderbird` | Accepted: `package.thunderbird` | Confirmed Release x64/en-GB, current-user scope. Non-elevated deployment, repeat install/remove, profile preservation and saved-selection recovery passed on both targets; see [correlated acceptance](../archive/migrations/application-thunderbird-follow-up-2026-10-11.md#accepted-migration-after-resumed-validation). Application/mail functionality and exact prior-version recovery remain separate. |
| `InstallImageMagick` | Deferred: variant and release adapter | Choose supported Q16/HDRI/architecture variant explicitly, then verify official checksum and installed detection/removal. |
| `InstallImageMagickPortable`, `RemoveImageMagickPortable` | Deferred: publisher edition/source | Managed ZIP ownership is implemented; exact HDRI/quantum-depth distribution and revision parsing remain unresolved. |
| `InstallSignal` | `package.signal` (accepted on Windows 11 and Server 2025 Desktop Experience) | Stable x64 current-user feed with checked SHA-512; repeat installation/removal, existing Roaming-profile preservation and compensating recovery passed on both targets. Account linking and prior-version recovery remain separate limits. See the [installed acceptance record](../archive/migrations/application-installed-follow-up-2026-10-11.md). |
| `InstallPython` | Deferred: version/launcher lifecycle | Define release family and scope, launcher coexistence, PATH behavior, uninstall and reboot outcomes before catalog admission. |
| `InstallYara`, `RemoveYara` | Deferred: current binary availability | Official latest release metadata has no binary assets; select a publisher-declared binary/build workflow and dependencies. |
| `GetCyberChef`, `RemoveCyberChef` | `package.cyberchef` (accepted on Windows 11 and Server 2025 Desktop Experience) | Managed offline release ZIP; retain assets/notices and user recipes, without launching the browser. See the application ledger. |
| `InstallCaffeine`, `RemoveCaffeine` | `package.caffeine` (accepted on Windows 11 and Server 2025 Desktop Experience) | Retains the official 1.98 x86/x64 archive with an inspected hash pin and managed file recovery. No automatic execution/startup. See the application continuation evidence. |
| `InstallPutty`, `RemovePutty` | `package.putty` (accepted on Windows 11 and Server 2025 Desktop Experience) | Retains the legacy standalone x64 executable and resolves a versioned official URL; no MSI substitution. See the application ledger. |
| `InstallWinSCP`, `RemoveWinSCP` | Accepted: `package.winscp` / `portable` | Official stable x86 6.5.7 page/CDN acquisition matches publisher SHA-256. Twelve portable lifecycles and 230 guest checks passed per target, including owned-file recovery, valid EXE/COM signatures and unowned session preservation. Both VMs recovered; see [the acceptance record](../archive/migrations/application-winscp-follow-up-2026-10-11.md#final-correlated-acceptance). |
| `InstallKAPE`, `RemoveKAPE` | Deferred: licensed forensic tools | Requires distribution/license review, managed files and explicit Defender-exclusion decision before execution. |
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
