# GitHub quota bridge failure and launcher diagnostic, 2026-10-13

This completed run supports the unresolved acceptance in
[tested release-discovery contract](https://github.com/tjuuljensen/ride-windows/blob/a15647590a1324681bbe4a69cbb55e498a623522/docs/GITHUB-RELEASE-DISCOVERY.md) and the
[migration ledger](../../MIGRATION-PLAN.md#quota-failure-and-observed-launcher-client-2026-10-13).

One anonymous publisher preflight at 07:50:22 UTC returned HTTP 200, 7-Zip
26.04, 31 requests remaining and reset 08:43:43 UTC. Both controllers were
idle, all five installed hashes matched reviewed source and VM/checkpoint/
account/ISO/repository pins were unchanged. CI checkout was clean at
`a15647590a1324681bbe4a69cbb55e498a623522`. Full Windows 11 request
`21b380695758461ebe090c34f537a595` ran 07:51:53-08:20:39 UTC. Validation,
all 1,280 Pester tests and all 217 source hashes passed; XML reports zero
failures/errors/skips/not-run. Integration failed before 7-Zip acquisition on
quota zero, reset 08:43:43 UTC, earliest retry 08:43:44 UTC. No expired metadata,
automatic retry or successful release observation was used. Consecutive Full
passes remained zero.

Collector 0.4.1 completed inside its 90-second bound: copy markers
08:20:24.067-08:20:36.983 UTC, teardown ending 08:20:37.014 UTC. Collection
errors and omissions were empty. State export and checkpoint cleanup passed,
retaining 791 state JSON files including 395 manifests. UAC stayed 1/5/1.
Both VMs ended Off, tasks Ready, queues empty, locks available, no recovery
blocks and installed hashes/checkpoints unchanged.

The passive host sample 08:00:05-08:10:05 UTC recorded 465 repeated TCP
observations for ArtCraft Launcher PID 27136 against the once-resolved GitHub
API address 140.82.121.6, first 08:00:07.848 UTC, last 08:04:36.451 UTC.
These are connection samples, not 465 API requests or proof of all shared-IP
quota consumption. No obvious host proxy or Tailscale exit node was found.
The three additional published unit tests use mocked collector paths.

The user approved temporarily closing the observed launcher for bridge tests.
A graceful window close left the process running, so only the exact verified
launcher process was stopped. No launcher process remained at verification;
startup and network configuration stayed unchanged. Later acceptance must
establish whether this diagnostic condition improves guest acquisition.

Retained local evidence: `.local/quota-loop-win11-20261013-0750-evidence.json`,
the correlated receipt and preflight, and
`.local/quota-loop-host-connections-20261013-0800.json`. Full package acquisition,
consecutive two-target acceptance and controller certification remained open.
