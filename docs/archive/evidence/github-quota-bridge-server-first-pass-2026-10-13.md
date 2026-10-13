# GitHub quota bridge Server 2025 first pass, 2026-10-13

Server 2025 completed consecutive Full pass **1/2**, following the accepted
[Windows 11 pair](github-quota-bridge-windows-11-pair-2026-10-13.md).
The [active migration ledger](../../MIGRATION-PLAN.md#server-2025-first-consecutive-full-pass-2026-10-13)
retains the remaining gate. These runs use published CI source
`a15647590a1324681bbe4a69cbb55e498a623522` and reviewed installed controller
revision `55e97c00173885dad36918271a5a25bedbf9da37`, collector 0.4.1/module
0.4.3. Newer unfinished settings, controller 0.4.5 and documentation renames
in the shared worktree are excluded and preserved.

After the recorded 10:44:07 UTC deadline, one anonymous publisher preflight
at 10:50:50 UTC returned HTTP 200, 7-Zip 26.04, 57 requests remaining and
reset 11:44:21 UTC. Response Date was 10:50:40 UTC, core limit 60, with no
Age/Via/cache header or Retry-After. Both VMs were Off, tasks Ready, pending/
running queues empty, locks available and recovery blocks absent. All five
installed controller hashes and VM/checkpoint/account/ISO/repository pins
matched the reviewed baseline. Registered tasks retained fixed hidden workers,
Interactive logon and Highest privilege. The CI checkout was clean and
ArtCraft Launcher absent. Competing settings work remained read-only and
submitted no VM request.

The installed registered client submitted one correlated request,
`9f3c92ba97da41d4b88de8c86e380ab4`, with Source CI, IntegrationSuite Full
and TimeoutMinutes 90. It passed 10:51:45-11:06:52 UTC. Windows Server 2025
Standard Evaluation build 26100, Windows PowerShell 5.1.26100.33438 and
Pester 5.7.1 passed validation, all 1,280 tests and applicable Full integration.
Pester XML has zero failures/errors/skips/not-run; all 217 snapshot/CI source
hashes matched.

| Publisher package | Version | Remaining quota at network metadata fetch |
| --- | --- | ---: |
| 7-Zip | 26.04 | 52 |
| Notepad++ | 8.9.8.1 | 51 |

Both release observations retained matching publisher SHA-256 digests and
five-minute retrieval/expiry provenance; payload observations occurred before
expiry. This Server suite produced no ProcessCache observation. Real cache
reuse remains covered by the Windows 11 pair and regression tests, rather
than being claimed from this Server run. Sysmon 15.22's separate publisher
download is not a GitHub release/digest observation.

The transcript explicitly skips the Windows 11-only Explorer baseline and
catalog-unsupported Git for Windows, Git LFS, Joplin, ShareX, WinDirStat and
PowerShell package scenarios. These integration applicability skips are
separate from Pester's zero skipped tests and do not expand Server support.
No expired metadata, automatic retry, host token forwarding or authentication
fallback was used; the last saved publisher lookup still had 51 remaining.

Normal guest export and checkpoint cleanup had no errors. Retained state
contains 10 JSON files including three manifests. UAC stayed 1/5/1. Postflight
at 11:07:18 UTC verified both VMs Off, tasks Ready, empty queues, available
worker locks, no recovery blocks, unchanged pinned checkpoints and five
installed hashes, clean CI source and no launcher process. Failure collection
was not invoked; earlier bounded-failure evidence remains separate. Local
preflight/readiness files use the `20261013-1051` suffix; receipt, acceptance
and postflight files use `.local/quota-loop-server-20261013-1051-`.

Progress is **Windows 11 2/2, Server 2025 1/2**. The same active heartbeat's
next attempt is **13:47 Europe/Copenhagen**, after the observed 13:44:21 reset
plus one second. This schedules a fresh quota window without claiming quota
exhaustion. One more consecutive Server Full pass remains, subject to a fresh
anonymous preflight and idle-resource/baseline checks. Disable this bridge
heartbeat after both pairs complete; broader controller certification,
default-branch cutover and unrelated settings acceptance remain open.
ArtCraft Launcher must not be restarted, including when testing stops.
