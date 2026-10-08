# Unattended migration results, 8 October 2026

The catalog now contains 98 operations, two ordered package groups and four
profiles. This session adds five optional Windows 11 packages and two default
user policies. The full legacy migration remains incomplete.

## Implementation

- Git for Windows handles four-part patch installer names. The exact publisher
  release-note checksum is checked independently of the GitHub provider digest.
- Standalone Git LFS, Joplin, ShareX, WinDirStat and PowerShell 7 use the engine's
  presence/install/remove lifecycle. The Git solution orders dependencies and
  reverses removal. MSI installation/removal is quiet and does not reboot.
- Git LFS receives the newly installed Git directory in the installer's process
  PATH; the calling environment is restored even when installation fails.
- Joplin detection uses the current user's uninstall registry. PowerShell's
  stable x64 MSI name is detected without matching preview or ARM64 editions.
- Edge copied-URL formatting and Start's Run as different user policy capture
  exact prior state, support WindowsDefault, and use documented user scope.
- A bounded data-only reader loads the growing catalog on PowerShell 5.1 and 7.
  Generation and completion use the same metadata; OS-name completion does not
  import AutomatedLab into an ordinary shell.
- Acquisition evidence records identity, route, cache/download distinction,
  hashes, publisher/provider metadata, certificates and timestamps. Sysmon's
  executable evidence is linked to its parent ZIP hash before execution.
  Imports preserve history, reject conflicts and use atomic file replacement.
- Provisioning accepts local PSD1 configuration and emits a controller seed
  containing discovered VM identity and explicit source/guest/checkpoint paths.
  The field guide explains overrides and downstream inheritance.

## Validation and VM evidence

Native Windows PowerShell 5.1 and PowerShell 7.6.5 each passed 127 isolated
tests; the live-registry test was excluded on the host. After the final atomic
metadata-replacement change, the 15 evidence/import tests passed on both
editions, and the four importer tests passed after path normalization.
Catalog/profile/parser/generated-document validation passed on both editions.
Source snapshot hashes and guest transcripts are retained with each VM request.

| Request | Result and interpretation |
| --- | --- |
| `994f01a75b3d4d8f9312103f9f31f56e` | Earlier 103-test suite; user confirmed successful locked-PC execution. |
| `20cb460af8be447dafcfc62662f99d35` | Passed 103 guest tests and integration, including Git init/add/commit/HEAD, repeat installation and removal. |
| `a2a2539763bf43e4a2981404d33a39e2` | Failed on Git LFS's missing Git prerequisite; acquisition evidence retained. |
| `e58d341c3b7d443e8807a34f3834972b` | Exposed use of a private uninstall helper in scenario cleanup; cleanup now uses engine plans. |
| `92e7d36ff7b34f94a5055441ad85fe4d`, `682536d978844fe798539063d8f5a15e`, `a18a681704714d78add94ecc2463a32c` | Failed explicitly while investigating PowerShell 5.1/Pester error handling over WinRM. Conflict rejection now exercises the child CLI boundary and captures its exit/error without nesting that failure stack. |
| `d1ce1d8e371241699e5d9d1d88f98c7c` | Passed 125 guest tests. Git LFS, Joplin, ShareX, WinDirStat and Sysmon scenarios completed; PowerShell MSI installed but its display-name detection failed. Pattern corrected and regression coverage added. |
| `9744844940fd4ca498ef6486092ac831` | Passed all 128 guest tests plus integration, including all five new package install/repeat/remove scenarios, installed PowerShell execution, Git functionality, Sysmon and both user-policy round trips. |

Failures were reported as failures. Collected request results show checkpoint
cleanup and evidence collection succeeded, with host UAC values unchanged:
EnableLUA=1, ConsentPromptBehaviorAdmin=5, PromptOnSecureDesktop=1.
Requests use the registered elevated controller from an ordinary signed-in
prompt. A locked session is supported; signing out is a different condition.

The accepted run started at 13:15:56 UTC and finished at 13:33:55 UTC. A native
Hyper-V read confirmed VM `6a5c9f91-91f9-44c5-924a-d1b5f863e16f` was Off;
the pinned clean checkpoint remained `a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9`.
The guest was Windows 11 Enterprise Evaluation build 26300 with Windows
PowerShell 5.1.26100.9444 and Pester 5.7.1. Final metadata replacement and
completion refinements made after that request's snapshot were checked through
isolated native host tests; no further installer behavior changed.

Results live under
`C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test\results\<request-id>`.
Installer bytes are not copied into the repository; reviewed metadata is in
`catalog/artifact-observations.json`. Failed requests supply acquisition
evidence, not package acceptance or independently routed verification.
The reviewed library contains 30 unique observations. Reimporting the final
request added zero records; all supplied provider digests and archive/member
links agree with the recorded hashes.

## Remaining work

All 53 Install programs selectors have explicit dispositions in
[the selector ledger](install-programs-dispositions.md). Deferred entries need
the stated source adapters, managed-file lifecycle, license decisions or
driver/reboot coverage. Other migration families remain in
[the migration plan](../MIGRATION-PLAN.md).

The Sysmon executable reports Valid with signer Microsoft Windows Publisher
and issuer Windows Production PCA 2023. 7-Zip and ShareX are unsigned.
[The verification matrix](../PACKAGE-VERIFICATION-MATRIX.md) records exact
hashes/certificates and open publisher-key, checksum, rotation and independent
route investigations. No mandatory signer trust gate was introduced.

Server 2025 creation and runtime acceptance await its ISO. Concurrent labs on
this host also need a shared NAT/switch and address-allocation design: the new
preflight blocks a second host NAT and preserves the existing Windows 11 lab.
Preparing a template does not establish Server or shared-network support.

The installed protected runner/collector remain their registered versions.
Repository versions use an explicit evidence handoff; the current suite also
supports the older runner's caller-scope handoff. Updating protected copies
requires the documented elevated registration workflow while idle.
Watcher/CI/overlap/timeout/interruption acceptance remains open in
[the controller runbook](../../tests/integration/AUTOMATEDLAB-TASKS.md).
Fallback sidecar collection after a shared-library write failure also remains
open; checkpoint reset would remove an uncollected cache sidecar.

Changes remain in the local working tree for review; no release was published.
