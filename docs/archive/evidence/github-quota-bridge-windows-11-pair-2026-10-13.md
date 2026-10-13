# GitHub quota bridge Windows 11 pair acceptance, 2026-10-13

Windows 11 completed **2/2 consecutive Full passes** on the same published
CI/controller baseline. Server 2025 remains **0/2**. The
[active migration ledger](../../MIGRATION-PLAN.md#windows-11-consecutive-full-pair-acceptance-2026-10-13)
retains remaining acceptance. The
[first pass](github-quota-bridge-launcher-closed-acceptance-2026-10-13.md)
and [tested release-discovery contract](https://github.com/tjuuljensen/ride-windows/blob/a15647590a1324681bbe4a69cbb55e498a623522/docs/GITHUB-RELEASE-DISCOVERY.md)
retain the earlier evidence and freshness/backoff requirements.

One anonymous preflight at 09:49:15 UTC returned HTTP 200, 7-Zip 26.04,
57 requests remaining and reset 10:44:06 UTC. Response Date matched the
observation; core limit was 60, with no Age/Via/cache header or Retry-After.
Both controllers were idle with unchanged VM/checkpoint/account/ISO/repository
pins. All five installed hashes matched the reviewed controller revision
`55e97c00173885dad36918271a5a25bedbf9da37`, collector 0.4.1/module 0.4.3.
The approved CI checkout was clean at
`a15647590a1324681bbe4a69cbb55e498a623522`. Unfinished settings and staged
documentation renames were excluded and preserved. ArtCraft Launcher remained
closed under the user's explicit instruction not to restart it.

Full Windows 11 CI-source request `dbfd74b1bfca4e0a91c4f6b088f2ee23`
passed 09:49:44-10:23:06 UTC through the installed registered client with
TimeoutMinutes 90. Windows 11 Enterprise Evaluation build 26300, Windows
PowerShell 5.1.26100.9444 and Pester 5.7.1 passed validation, all 1,280 guest
tests and Full integration. XML reports zero failures/errors/skips/not-run,
and all 217 snapshot/CI source hashes matched.

| Publisher package | Version | Remaining quota at network metadata fetch |
| --- | --- | ---: |
| 7-Zip | 26.04 | 50 |
| Notepad++ | 8.9.8.1 | 49 |
| Git for Windows | 2.56.0.windows.2 | 47 |
| Git LFS | 3.8.0 | 46 |
| Joplin | 3.7.21 | 45 |
| ShareX | 21.0.0 | 43 |
| WinDirStat | 2.9.3 | 41 |
| PowerShell | 7.6.6 | 40 |

Eight network release observations and three real ProcessCache/payload Cache
observations were retained. All 11 publisher SHA-256 digests matched. Cache
reuse for 7-Zip, Notepad++ and Git preserved original retrieval/expiry
timestamps and occurred before each five-minute expiry. No expired metadata,
host token forwarding or authentication fallback was used. Sysmon's separate
publisher download is not counted as a GitHub release/digest observation.

Normal guest export and checkpoint cleanup succeeded without collection or
cleanup errors. Retained state includes 838 JSON files and 413 manifests;
these counts do not claim that every file belongs to this request. UAC stayed
1/5/1. Both VMs ended Off, tasks Ready, queues empty, worker locks available,
no recovery blocks, and pinned checkpoints and five installed hashes unchanged.
The CI checkout remained clean, and the verified launcher had no process.
Failure collection was not invoked; its earlier bounded real-failure evidence
remains separate. Local receipt, acceptance and postflight evidence use the
`.local/quota-loop-win11-20261013-0949-` prefix.

Accepted Windows 11 pair: `2ceab6f49e6d408d86f713fc5ba4b28b` followed by
`dbfd74b1bfca4e0a91c4f6b088f2ee23`. The same heartbeat's next attempt is
**12:47 Europe/Copenhagen**, after the observed 12:44:06 reset plus one
second. This schedules a fresh quota window; the latest run did not exhaust
quota. Two consecutive Full Server 2025 passes remain, with a fresh anonymous
preflight and resource check before each. Disable the bridge heartbeat when
both pairs complete. Controller certification, default-branch cutover and
unrelated settings acceptance remain open. Do not restart ArtCraft Launcher.
