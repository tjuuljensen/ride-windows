# GitHub quota bridge pair gate complete, 2026-10-13

The current anonymous release-discovery bridge completed **two consecutive
Full passes on each target**, on one published CI/controller baseline.
The recurring bridge heartbeat is disabled (`PAUSED`), with no next bridge
run scheduled. The [active migration ledger](../../MIGRATION-PLAN.md#github-quota-bridge-two-target-pair-complete-2026-10-13)
retains the separate controller and cutover acceptance still open.

| Target | Accepted consecutive Full requests |
| --- | --- |
| Windows 11 | `2ceab6f49e6d408d86f713fc5ba4b28b`, `dbfd74b1bfca4e0a91c4f6b088f2ee23` |
| Server 2025 | `9f3c92ba97da41d4b88de8c86e380ab4`, `420c567aea0b44118862ecfcf1de35a5` |

All four used clean published CI source
`a15647590a1324681bbe4a69cbb55e498a623522` and reviewed installed controller
revision `55e97c00173885dad36918271a5a25bedbf9da37`, collector 0.4.1/module
0.4.3. Each passed validation, all 1,280 Pester tests, applicable Full
integration, all 217 snapshot/CI source hashes and checkpoint recovery.
The [Windows 11 pair](github-quota-bridge-windows-11-pair-2026-10-13.md)
retains real ProcessCache/payload cache reuse and publisher digest evidence;
the [first Server pass](github-quota-bridge-server-first-pass-2026-10-13.md)
retains that target's applicability and provenance.

One anonymous preflight at 11:48:08 UTC, after the recorded deadline, returned
HTTP 200, 7-Zip 26.04, 58 remaining and reset 12:44:35 UTC. Response Date
was 11:48:09 UTC, core limit 60, with no Age/Via/cache header or Retry-After.
Both controllers were idle with unchanged VM/checkpoint/account/ISO/repository
pins and all five installed hashes matching the reviewed baseline. CI source
was clean; competing settings work submitted no VM request. Newer controller
0.4.5, unfinished settings and staged documentation/ledger edits were excluded
and preserved. ArtCraft Launcher remained absent.

The installed registered client submitted only request
`420c567aea0b44118862ecfcf1de35a5`, Source CI, IntegrationSuite Full,
TimeoutMinutes 90. It passed 11:48:54-12:07:42 UTC. Guest Windows Server 2025
Standard Evaluation build 26100, Windows PowerShell 5.1.26100.33438 and
Pester 5.7.1 passed validation, all 1,280 tests and applicable integration.
Pester XML has zero failures/errors/skips/not-run; all 217 source hashes match.

| Publisher package | Version | Remaining at network metadata fetch |
| --- | --- | ---: |
| 7-Zip | 26.04 | 52 |
| Notepad++ | 8.9.8.1 | 51 |

Both observations retain matching publisher SHA-256 digests and five-minute
metadata freshness; payload observations occurred before expiry. Neither
Server run produced a ProcessCache observation. The Windows 11 pair supplies
real cache reuse evidence; mocked regression checks cover expiry/backoff
branches. Sysmon's separate publisher download is not counted as a GitHub
release/digest observation. The transcript skips the unsupported Windows 11
Explorer/Git/Git LFS/Joplin/ShareX/WinDirStat/PowerShell package scenarios;
those applicability skips do not expand Server support or skip Pester tests.
No expired metadata, automatic retry, token forwarding or authentication
fallback was used. The last saved quota was 51, so this run did not exhaust it.

Normal export/checkpoint cleanup had no collection or cleanup error, retaining
10 state JSON files including three manifests. UAC remained 1/5/1. Postflight
12:08:10 UTC verified both VMs Off, tasks Ready, queues empty, locks available,
no recovery blocks, unchanged pins/checkpoints and five installed hashes, clean
CI source and no launcher process. Failure collection was not invoked; the
[earlier real failure-path evidence](github-quota-bridge-launcher-diagnostic-2026-10-13.md)
remains separate. Local receipt/acceptance/postflight evidence uses the
`.local/quota-loop-server-20261013-1148-` prefix.

After the final audit, the same heartbeat was set to PAUSED. Shared VM
resources are yielded for other authorized work, which must recheck current
idle state before submission. No further bridge request or recurring automation
was created. The observed reset plus one second is retained as 12:44:36 UTC
(14:44:36 Europe/Copenhagen) for separate future publisher work; there is no
next scheduled bridge attempt.

This accepts the current anonymous bridge pair gate, not broader controller
certification. Newer controller 0.4.5 publication/acceptance, final controller
trigger/serialization/recovery coverage, default-branch cutover, optional
GitHub authentication implementation/acceptance and unrelated settings testing
remain separate. No registration status, master branch or support declaration
was changed. ArtCraft Launcher must not be restarted when testing stops.
