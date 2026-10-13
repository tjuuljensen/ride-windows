# GitHub quota bridge Windows 11 Full acceptance, 2026-10-13

This is Windows 11 consecutive Full pass **1/2**, with Server 2025 **0/2**.
The [migration ledger](../../MIGRATION-PLAN.md#launcher-closed-windows-11-full-acceptance-2026-10-13)
retains the open acceptance; the
[tested release-discovery contract](https://github.com/tjuuljensen/ride-windows/blob/a15647590a1324681bbe4a69cbb55e498a623522/docs/GITHUB-RELEASE-DISCOVERY.md)
defines freshness, cache and backoff behavior.

The user-approved ArtCraft Launcher closure remained in effect. One anonymous
preflight at 08:48:15 UTC returned HTTP 200, 7-Zip 26.04, 58 requests remaining,
reset 09:43:52 UTC. Response Date was 08:48:16 UTC, core limit 60, with no
Age/Via/cache header. Both controllers were idle with unchanged VM/checkpoint/
account/ISO/repository pins. Their five installed hashes matched the reviewed
baseline published in `55e97c00173885dad36918271a5a25bedbf9da37`, collector
0.4.1/controller module 0.4.3. Unfinished documentation-link changes in the
shared working copies were excluded. The approved CI checkout remained clean
at `a15647590a1324681bbe4a69cbb55e498a623522`.

Full Windows 11 CI-source request `2ceab6f49e6d408d86f713fc5ba4b28b`
passed 08:49:47-09:29:57 UTC. Guest Windows 11 Enterprise Evaluation build
26300, Windows PowerShell 5.1.26100.9444 and Pester 5.7.1 passed validation,
all 1,280 tests and Full integration. XML reports zero failures/errors/skips/
not-run, and all 217 snapshot/CI source hashes matched.

| Publisher package | Version | Remaining quota at network metadata fetch |
| --- | --- | ---: |
| 7-Zip | 26.04 | 49 |
| Notepad++ | 8.9.8.1 | 48 |
| Git for Windows | 2.56.0.windows.2 | 47 |
| Git LFS | 3.8.0 | 46 |
| Joplin | 3.7.21 | 44 |
| ShareX | 21.0.0 | 43 |
| WinDirStat | 2.9.3 | 42 |
| PowerShell | 7.6.6 | 41 |

Eight network release observations and three real ProcessCache/payload Cache
observations were retained. Cache reuse for 7-Zip, Notepad++ and Git preserved
the original retrieval/expiry timestamps; observed reuse occurred before each
five-minute expiry. All 11 SHA-256 values matched their declared publisher
digests. No expired metadata, token forwarding or authentication fallback was
used. The saved evidence is `.local/quota-loop-win11-20261013-0848-evidence.json`.

Normal guest export and checkpoint cleanup succeeded without errors, retaining
838 state JSON files including 413 manifests. Counts include available state,
not a claim of request ownership for every file. UAC remained 1/5/1. Both VMs
ended Off, tasks Ready, queues empty, worker locks available, no recovery blocks
and pinned checkpoint/installed hashes unchanged. CI checkout stayed clean.

The launcher-closed passive sample 08:56:43-09:06:43 UTC contained 29 repeated
TCP samples from two VS Code processes and no ArtCraft Launcher process.
Connections cannot establish request counts or exclusive quota ownership.
Success followed the launcher closure with positive quota at every saved lookup;
the diagnostic condition is kept for the next tests.

The next bridge continuation is **11:47 Europe/Copenhagen**, after the observed
11:43:52 reset. One more Windows 11 Full pass and two Server 2025 Full passes
remain. Controller certification, default-branch cutover and unrelated settings
acceptance remain separate.
