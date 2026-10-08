# Install programs selector reconciliation

Reviewed 2026-10-08. All **53** selector names in this migration family have a
disposition below. A deferred selector is accounted for, not implemented or
tested. New packages are optional and Windows 11-only until target-specific
tests pass. Existing published IDs remain stable.

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
| `InstallPSScriptTools`, `RemovePSScriptTools` | Deferred: managed repository files | Legacy clones the project into a tools tree; replacing that with Install-Module would change the workflow. Need pinned revision, configurable tools root, manifest ownership and removal that preserves user files. |
| `InstallVSCode`, `RemoveVSCode` | Deferred: official update adapter | Need exact stable x64 artifact/version resolution, explicit machine/user edition choice and extension/settings-preserving uninstall tests. |
| `InstallGPGwin` | Deferred: publisher verification and lifecycle | Need current official installer resolution, checksum/signature trust-root review and installed-component/reboot tests. |
| `GetSysmonOlafXML` | Deferred: obsolete source reconciliation | Legacy root `sysmonconfig.xml` is no longer the selected current artifact. Upstream now supplies templates; select a specific configuration and immutable revision explicitly before adding an artifact. Do not silently substitute a different policy. [Upstream templates](https://github.com/olafhartong/sysmon-modular/tree/master/templates). |
| `InstallVMwareWorkstation`, `RemoveVMwareWorkstation` | Deferred: licensed distribution | Broadcom download access/license acceptance and driver/reboot lifecycle require a documented supplied-artifact workflow. No unattended credential or license assumption. |
| `SetVMDirUserhome`, `SetVMDirDocuments` | Deferred: application configuration | These are VMware preferences, not package installations. Need preference discovery, prior-value capture and exact restore under the current user. |
| `InstallThunderbird` | Deferred: official release adapter | Need exact x64 localized stable version/source, silent lifecycle and profile-preserving uninstall verification. |
| `InstallImageMagick` | Deferred: variant and release adapter | Choose supported Q16/HDRI/architecture variant explicitly, then verify official checksum and installed detection/removal. |
| `InstallImageMagickPortable`, `RemoveImageMagickPortable` | Deferred: portable ownership | Need managed-file handler and variant selection; never delete an arbitrary shared tools directory. |
| `InstallSignal` | Deferred: user installer lifecycle | Need official stable artifact resolution, unattended current-user install/removal and profile preservation tests. |
| `InstallPython` | Deferred: version/launcher lifecycle | Define release family and scope, launcher coexistence, PATH behavior, uninstall and reboot outcomes before catalog admission. |
| `InstallYara`, `RemoveYara` | Deferred: portable ownership | Pin official binary/version and dependencies; record managed files and validate removals. |
| `GetCyberChef`, `RemoveCyberChef` | Deferred: portable web artifact | Define offline artifact/extraction ownership and preserve user recipes/data. |
| `InstallCaffeine`, `RemoveCaffeine` | Deferred: portable ownership | Need publisher artifact adapter and managed-file lifecycle. |
| `InstallPutty`, `RemovePutty` | Deferred: selector semantics | Legacy portable executable and an installed MSI have different ownership/removal semantics. Select the intended form, retain SSH configuration and verify publisher evidence. |
| `InstallWinSCP` | Deferred: distribution choice | Distinguish portable versus installed distribution and preserve saved sessions; requires official adapter and VM lifecycle tests. |
| `InstallKAPE`, `RemoveKAPE` | Deferred: licensed forensic tools | Requires distribution/license review, managed files and explicit Defender-exclusion decision before execution. |
| `InstallVeraCrypt` | Deferred: driver/reboot recovery | Driver installation/removal and reboot-required outcomes need an orchestrated VM scenario and version recovery plan. |
| `InstallVeraCryptPortable` | Deferred: portable driver lifecycle | Managed-file ownership alone is insufficient; inspect driver side effects and reboot recovery. |
| `InstallADReplStatus`, `RemoveADReplStatus` | Deferred: upstream availability | Reconcile the legacy distribution's current availability/support and licensing before designing replacement semantics. |
| `InstallFirewallNotifier`, `RemoveFirewallNotifier` | Deferred: firewall policy recovery | Requires managed files plus exact capture/restore of firewall-policy changes; package presence alone cannot establish safe rollback. |
| `InstallShareXportable`, `RemoveShareXportable` | Deferred: portable ownership | Installed ShareX is available separately. Preserve portable settings and own only declared managed files. |
| `InstallAutomatedLab` | Deferred: lab-host setup | Installing a package does not provision Hyper-V, host remoting or trust policy. Keep elevated lab provisioning in the runbook; define package prerequisites and recovery independently. |

Portable work resumes with the agreed configurable machine tools root and
manifest ownership. Defender exclusions remain separate explicit settings;
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
