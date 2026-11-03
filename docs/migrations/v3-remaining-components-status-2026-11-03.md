# Remaining components towards RIDE v3, 2026-11-03

The fast track has produced useful Windows 11 acceptance evidence, but v3 is
not release-ready. The remaining estimate is **121-175 legacy outcomes**, rounded
to **120-175, about 150**. These are feature/product outcomes, not test cases or
catalog IDs. A passing test for an already-migrated candidate does not reduce
that estimate again.

This report consolidates the [Nov 3 reassessment](migration-completion-reassessment-2026-11-03.md),
the [product fast-track register](package-fast-track-register.md), the detailed
[Nov 2 component registers](migration-completion-reassessment-2026-11-02.md),
and the [active migration plan](../MIGRATION-PLAN.md). The linked ledgers retain
individual mappings and historical evidence; this report identifies the next
work and its acceptance boundary.

## Stop status

The user requested completion of the active Gpg4win test and its recovery,
repository status/report updates, then a stop. A local stop marker prevents
further admission. The waiting font diagnostic and InfoBar retry exited without
submitting a VM request. TMOG and System Information/TAPI remain unrun in the
correction queue. Gpg4win finished Failed at 13:20 Copenhagen: corrected NSIS
destination syntax still produced installer exit `0xC0000005`. All 76 guest
regression tests, Defender and checkpoint recovery passed; installation/startup
and product recovery did not. See [Gpg4win evidence](../archive/evidence/gpg4win-corrected-installer-failure-native-2026-11-03.json).

At 13:21 Copenhagen, the pinned VM was Off, both workers Ready, package queues
empty, and no recovery hold or retained request remained. Existing expiring tasks
remain registered and idle. No further test was admitted. The final usage
observation and correlated queue receipts are in [stop evidence](../archive/evidence/attended-requested-stop-2026-11-03.json).

## What the fast track achieved

- **31 MiTeC variants across 26 products** passed installation, bounded startup,
  removal and recovery in the guest. This includes Mail Checker and the latest
  Project Maker 1.9.0 run. Ten earlier viewer/development guest passes retain
  their failed outer-controller results; they are not rewritten as outer passes.
- Project Maker passed nine lifecycle checks, 464 guest regression tests,
  Defender and checkpoint recovery. Startup was an eight-second session-0
  observation. Recovery was compensating presence recovery; previous-version
  recovery and interactive UI are not claimed.
- PSScriptTools/ThreadJob passed package recovery and all four runtime probes:
  dependency present/missing in Windows PowerShell 5.1 and PowerShell 7.6.5.
- Rufus, RegRipper and WFN passed file lifecycles. Explorer Suite passed its
  installer lifecycle. These results do **not** establish executable startup.
- Three Sysmon configuration lifecycles completed one legacy outcome. The
  bounded disconnected Caffeine route passed 34 checks. Fonts and images have
  durable-state evidence, with remaining behavior checks described below.
- Windows-native shared-scenario, CLI and status tests now have evidence in both
  shells. One stale search rejection assertion was corrected; its complete
  38-case file passed in both shells. The separate 15-case status file also
  passed in both. Original failures remain in the
  [source evidence](../archive/evidence/shared-behavior-and-status-windows-pester-2026-11-03.json).

Since the Nov 2 morning estimate of 126-180, the numerical changes are three
product exclusions (Recuva, Speccy, Defraggler), one completed Sysmon outcome,
and one retired VMware preference outcome. VMware installation had already
been retired; it is not counted twice.

## Prepared follow-ups to resume first

These routes have source preparation. None is automatically restarted after
this stop. Before a future session, inspect the finite task expiry, pinned VM,
empty queues and recovery hold, then create fresh bounded requests with unique
receipts. Reuse the installed controller only if its registration is still valid.

| Component | Current result | Next test and completion criterion |
| --- | --- | --- |
| TMOG | Installation reached 1.0.1.0, but the old assertion expected release string 1.0.1. Tested mapping and pinned startup correction are ready. | Run the prepared focused lifecycle; require startup without observed errors, repeat install/remove and saved-state recovery. Preserve synthetic user data. |
| MiTeC System Information eXtra and TAPI Monitor | Original startup stopped at GetSys.exe exit 1. Earlier file lifecycle passed. Corrected selection is source-tested. | Run TAPI first and both MSIX primary applications. Require lifecycle/startup/recovery; keep GetSys/GetSys64 execution/report features on the v3.1 list. Original failure remains recorded. |
| InfoBar | Installation timed out after acquisition; 464 guest tests passed, four skipped. Checkpoint recovery passed. | Test the pending root-process completion selection with retained installer logging. Require actual installer completion, startup, removal and RIDE recovery. The timeout cause remains unproven. |
| Machine fonts | Durable recovery passed, but native font visibility and a fresh-child observation failed. Child reporting fix passed 52 tests per shell. | Run the prepared diagnostic with bounded child error capture. Require immediate native visibility and removal/restore behavior as well as file/registry recovery. A repeated name alone does not prove a process-reference cause. |
| Gpg4win | Corrected destination syntax still crashes with `0xC0000005`; 76 guest tests and checkpoint recovery passed. Startup was not reached. | Resolve any remaining installation failure before startup/lifecycle acceptance. Preserve the distinction between product recovery and clean-checkpoint recovery. |

Network Scanner x86 has reproduced APPCRASH `0x0eedfade`; x64 passed. Do not
spend another run on unchanged x86 inputs. Diagnose the failing variant or make
an explicit variant disposition before promotion.

## Remaining work by family

All five ranges were reviewed unchanged for this closeout. Native test progress
improves evidence but does not silently retire unresolved or partial scope.

| Family | Remaining legacy outcomes | What still needs implementation or acceptance |
| --- | ---: | --- |
| Settings | 37-57 | Current-user GUI/consumer proof, exact reverse-state meaning, mixed-profile ordering/recovery, remaining mappings and security/boot scenarios. |
| Packages | 34-49 | Failed/prepared lifecycles, startup gaps, target/variant acceptance, exact sources and ownership for unmigrated products. |
| Windows components | 19-24 | Native servicing/recovery, exact provider/build availability, and implementation of remaining component/resource families. |
| Files and assets | 23-33 | Font visibility, image/new-user behavior, synthetic Wi-Fi lifecycle, account/locale/configuration ownership and recovery. |
| Maintenance | 8-12 | Native maintenance lifecycle/recovery, explicit irreversible boundaries, broader offline/bootstrap delivery and final release checks. |
| **Total** | **121-175** | **120-175 rounded; about 150. Deferred/partial work remains counted.** |

### Settings and security

The [30-row settings register](migration-completion-reassessment-2026-11-02.md#settings-component-register-at-pause)
and [remaining settings plan](remaining-settings-plan.md) remain authoritative.
Priority gaps include desktop icons and context menus, intended-user handoff,
current-build Explorer/taskbar mappings, proxy consumers and policy precedence,
feedback/telemetry bundle meaning, power/NumLock behavior, Windows RE and System
Protection lifecycle, Storage Sense effects, and Server logon/shutdown controls.
Registry round trips alone do not close those behavior questions.

BitLocker remains a separate effective-policy, preboot and recovery workflow:
effective policy was not established, and TPM/PIN, recovery boot and off-device
key retrieval require their own evidence. No encryption acceptance is inferred.
Password complexity, IE ESC, Memory Integrity, and selected AI/passkey/presence,
Administrator protection and Smart App Control work retain their distinct
mapping, target and recovery requirements. Optional Store-app groups still need
their remaining intended-user, reinstall-source, interruption and group recovery
acceptance; a single app registration pass is insufficient.

### Packages beyond the prepared queue

| Package family | Remaining work |
| --- | --- |
| Rufus, RegRipper, WFN, Explorer Suite; earlier NTCore/Sysinternals file-only cases | Record a deliberately bounded startup criterion where appropriate. Startup is separate from media writes, firewall changes, driver use or utility features. Explorer Suite also lacks executable-based version readback. Keep existing scoped passes. |
| Paradox Data Editor / BDE | Prepare nested installer and shared-dependency ownership/coexistence/recovery before activation. |
| CCleaner and standard ImageMagick installer | Retain exact publisher bytes/hash/signature and define install/remove/recovery. CCleaner installer and portable variants are separate; standard ImageMagick is separate from its accepted portable image smoke test. |
| Microsoft OpenJDK 25/21/17/11 | Existing Server 2025 lifecycle evidence is not Windows 11 acceptance. Prepare the appropriate Windows 11 route and exact prior-version recovery, preserving shared JAVA_HOME/PATH/associations. |
| Python runtimes and preferences | Resolve runtime/manager/launcher coexistence, aliases/PATH, offline-index/cache ownership and recovery before native testing. |
| HashCheck and other shell integrations | Complete native lifecycle and intended-user Explorer behavior; preserve original files/registration and prove rollback. |
| JoeWare, remaining NTCore tools, Arsenal selections, BloodHound/SharpHound/AzureHound | Complete exact selected source acquisition, inventories and package-specific lifecycle/recovery where still missing. Do not substitute an unselected release or infer collection-wide acceptance. |
| Zimmerman tools, WinGet/WAU, NirSoft launcher content | Define immutable source/content ownership and safe update/registration/task recovery. Preserve existing exclusions for Defender-alerted tools. |

The [legacy package selector register](migration-completion-reassessment-2026-11-02.md#legacy-selectors-still-unmigrated-or-partially-represented)
contains remaining unmigrated/partial selectors. The fast-track rule does not
require testing every tool feature: install, bounded error-free startup and
uninstall/recovery suffice for an ordinary downloaded tool. Broader functionality
belongs in the v3.1 register. Driver, servicing and machine-policy effects retain
their separate acceptance boundaries.

### Windows components

OpenSSH Client and RSAT have source-ready catalog and queue routes, but the
native run stopped at a pending-servicing-restart preflight. Evidence was
recovered and the capability task removed. Resolve baseline readiness and prove
the corrected preflight route before reactivation. **Explicit Windows Update
acquisition is approved**; matching local media is not their only allowed source.
RSAT acquisition and lifecycle have not run.

OpenSSH Server capability, sshd service and inbound firewall rule need separate
native acceptance and exact preservation/recovery. Telnet still lacks validated
source identity. Hyper-V, Sandbox and WSL distributions require hardware,
dependency, reboot and resource-ownership design. Printer/fax queues, ports,
drivers and stored data must be handled as concrete resources.

ISE, optional Media Player, Work Folders, Hello Face, Math Recognizer, legacy
Flash/IE applicability, Store repair/removal and Xbox/shared dependencies remain
discovery or implementation gaps as detailed in the
[component register](migration-completion-reassessment-2026-11-02.md#windows-component-workstream-status-at-pause).
Absence on a supported build is a disposition to record, not a reason to invent
replacement payloads. PowerShell 2 is already retired.

### Files, images, wireless and accounts

- Supplied fonts/images in custom-ride are sufficient inputs. Fonts still need
  the diagnostic above; wallpaper/default lock-image durable checks passed,
  but visual and new-user behavior remain unproved. Current-user lock-screen
  modes are separate.
- Wi-Fi XML is generated from settings and uses a synthetic test profile.
  **Real credentials are not required.** The last preparation observed WlanSvc
  stopped and skipped interface/profile tests. This does not establish absence
  of hardware. Establish suitable service/interface prerequisites, then test
  generated XML, import/repeat/remove and guarded recovery without a real
  network connection.
- Locale/language ordering and new-user copying, browser/Python preferences,
  local administrator creation/membership, user-bin PATH and activation/key
  reporting need explicit ownership and recovery. Keep secrets out of normal
  profile/state/log files.
- Offline profile/full-set assembly, transfer and installation remain separate
  gates. The Caffeine result proves a bounded disconnected route, not every
  installer type or dependency. PowerShell appearance files already have
  Windows 11/Server evidence and need not be reopened as a missing legacy item.

### Maintenance and release acceptance

Public Desktop cleanup, Start/taskbar unpinning, selected Windows Update work,
update-cache cleanup, Disk Cleanup, Sysprep, hostname and secure key-display
actions retain implementation/effect/recovery gaps. Exact content restore is
not available for every cleanup action; state that boundary in the operation.
Standalone WaitForKey/Restart/StopComputer selectors remain retired.

Separate release gates remain:

1. Reconcile each supported target/variant against native evidence, including
   declared Windows Server targets. A Windows 11 fast-track pass does not promote
   Server support or all variants.
2. Complete native snapshot ACL, guest run-retention/task recovery and partial
   failure acceptance. Host controller recovery is different evidence.
3. Complete selected offline/bootstrap/source-authentication acceptance and
   final-source controller certification. Keep anonymous/PAT discovery and
   credential cleanup evidence scoped to their tested routes.
4. Finish or explicitly disposition the remaining shared-contract alignment,
   paired CI/output-contract work and immutable published contract reference.
   Today's Windows Pester results close a test-execution gap, not all alignment.
5. Reconcile operation defaults/profiles, generated documentation, notices and
   local licensing review, then perform the release-candidate checks. No push,
   tag, release or default-branch cutover occurred in this testing session.

See [release and remaining backlog](../../TODO.md#remaining-backlog-and-release-gates)
and [cross-platform alignment](../../TODO.md#cross-platform-alignment-for-final-v3).

## Retired, excluded and deliberately deferred scope

All VMware installation support **and** profile/path preferences are retired
from v3. Recuva, Speccy and Defraggler are excluded. Existing installations and
user VM files were not changed. ETL2PCAPNG retains its download-only acceptance;
Sysinternals licensing is settled under the user's earlier decision.

Product feature depth is deferred to v3.1 under the approved fast track. Docker,
Wireshark/Npcap, WFN firewall effects, WinPmem driver use, VeraCrypt reboot/driver
work, KAPE/collector activation, mutable Zimmerman sources and WinGet/WAU retain
their recorded deferrals. These should not quietly become new overnight work;
the final v3 scope must retain their explicit disposition. No new exclusion,
retirement or deferral is introduced by this report.

## Recommended next session

Resume the four prepared follow-ups first (TMOG, System Information/TAPI,
font diagnostic and InfoBar), using the preserved source fixes and fresh request
receipts. Resolve Gpg4win from its final evidence before any repeat. Then address
capability baseline readiness and the visual/WLAN prerequisites while the
operator is present. Prepare Paradox/BDE, CCleaner, Python and Windows 11 OpenJDK
as separate batches; do not mix them into an unreviewed general installer run.
Finally reconcile the remaining family registers and release gates. The current
queue being stopped or exhausted is not a v3 completion criterion.
