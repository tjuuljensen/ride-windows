# Separate Store test desktop evidence, 2026-10-14

## Result and scope

The user explicitly authorized a separate UAC-enabled disposable Store desktop,
including elevation. Preparation and read-only desktop Plan passed. Both the
worker and Explorer were genuinely unelevated in the expected user's session.
Task cleanup and recovery to the separate clean checkpoint passed. All apps
remain kept; packages and downloads remain paused. No published target support
was changed, and no Store removal policy was applied.

This accepts the resource prerequisite and schema-7 read-only worker Plan only.
Full production launcher, alternate-administrator handoff, app uninstall/reinstall,
retained payload behavior, partial app failures and application-data recovery
remain pending. No Pester matrix or state-changing app lifecycle was run as part
of this preparation.

## Resource lineage

| Item | Recorded value |
| --- | --- |
| Original Windows 11 VM | `6a5c9f91-91f9-44c5-924a-d1b5f863e16f` |
| Exported original clean checkpoint | `a1d87bdd-4c98-4c4b-a6f7-a4f0c5bf21a9` |
| Independent new VM | `RIDE-Store-W11`, `ac29b689-f62d-4e5b-a4bc-25987f1fe843` |
| Owned resource root | `Z:\VMs\RIDE-StoreDesktop-20261014` |
| Separate clean checkpoint | `RIDE-store-uac-clean-20261014`, `35b4f659-f168-4c22-bfc4-b6e7651a09e2` |
| Guest UAC before / after reboot | `EnableLUA` 0 / 1; consent 5 and secure desktop 1 retained |
| Guest identity | `RIDE-WIN11-TEST\admin`, `S-1-5-21-3381495413-3650599264-2815280620-1000` |
| Network | No adapter; PowerShell Direct by new VM ID |
| Final state | Off; separate clean pin recovered |

The local checkpoint export/import created independent disks and a new VM ID.
All imported disk parents were checked under the owned resource root. An initial
Hyper-V dynamic-MAC assignment failed with an invalid zero address. The copy was
already disconnected; removing only its copied adapter completed isolation.
The failure and repair remain in the local preparation journal. No original
VM restore, boot, rename, disk write, UAC change or controller refresh occurred.

The cloned computer name, local user SID, existing sign-in configuration, installed
Pester and Store payloads were retained. No new automatic logon was configured,
and no password is included in the evidence. This is the existing Enterprise
Evaluation reference lineage, not fresh-install or Home/Pro edition coverage.

## Correlated desktop proof

Request `080d9d9404274f349857f1e06166fe80` ran from 13:57:42 to 13:59:40 UTC.
It staged the current checkout at source revision
`2b799873f0f95b7569945373ab576f00d13a5b40`, including uncommitted migration
implementation. All 362 original source files and the single isolated schema-7
selection matched the 363 guest file hashes. The checkout selection was not
created or replaced; published Store support stayed closed.

The consumer-group Plan reported all four operations refused by pending target
acceptance. News and Weather additionally refused stub/unavailable retained
payloads. Native runtime observations retained `IsPartOfSystem=null` and
`SystemProtectionObservation=Unknown`. No app removal/re-registration or new
removal record was attempted. Before/after registration observations matched.

The Interactive/Limited worker proved expected SID, session 1 and Explorer PID
5568; `CurrentElevated=false` and `ShellElevated=false`. The source-bound worker
Plan completed, and its owned transient task was removed. Guest execution exited
0, bounded evidence copies matched their hashes, and checkpoint recovery passed.

| Evidence | SHA-256 |
| --- | --- |
| Exported configuration | `2767B7CB2487E45C0E3A6D7FD57629DF2CD7A0E8ACF0465007ECBA77212EE9E6` |
| Original source manifest | `8691DF1CB8BBBEB20FC114537A5BD3412654E47B30E278AC66B11362BB659ECC` |
| Staged source manifest | `CE16A3FA10B28971487547CB0A0357972DE6017705FE044AC14BBA51DBC93D59` |
| Isolated fixture | `5C7E37766BFFD3F3D4213A3C1D578A86427CAFF9D01ABB5B1416F7309B48DE02` |
| Handoff source hash | `17137431ABE230C372ABD867CD33A967C80C413DD2DEE277676853B15B11E4A9` |
| Actor script | `FDA77845740789704373FF29412D595130D65588CE78834129E37E3906F5DD98` |
| Fixture result | `E9FCC9C3A49D45903A58DBFDEA1779BD890AA483BF2D9FA02CEFDBFD4B151332` |
| Actor result | `B409BC6184F356E03A4AAC84E77EE58DC11C907893136C6791BF8DD3C81FA7CF` |
| Actor console | `6221131F706561091236B0CA1B382C33EB40BBF8BC268FF980918CFECE8D1E6C` |

Local full source/manifests and bounded raw guest evidence are retained under
`.local/store-desktop-validation/080d9d9404274f349857f1e06166fe80/`.
Preparation/UAC journals and one-shot native helper scripts remain in `.local`;
the [machine-readable evidence](store-test-desktop-2026-10-14.json) records their
hashes and accepted original controller pins. No new controller or test schedule
was registered. Future runs must use the separate pin and serialized source/hash,
actor ownership, evidence collection and checkpoint recovery flow in the
[test desktop runbook](../../migrations/store-test-desktop.md).

## Original baselines and migration accounting

Postflight at 14:00:06 UTC found both original VMs Off, tasks Ready, queues empty,
locks available, no recovery blocks, unchanged VM/checkpoint pins and unchanged
five installed controller file hashes. CI remains clean at
`a15647590a1324681bbe4a69cbb55e498a623522`. ArtCraft Launcher remains closed.
The new VM is Off with zero network adapters and its separate clean pin present.

Resolved: separate desktop resource and native unelevated read-only worker proof.
Retired/excluded legacy outcomes: none. Partial/deferred: all app lifecycle,
production launcher, alternate administrator, policy applicability and additional
edition/Server desktop coverage. News and Weather sources remain deliberately
unavailable. No whole legacy feature/product outcome closes from preparation.
All five ranges remain settings 38-58, packages 58-73, components 20-25,
accounts/configuration/files 25-35 and maintenance 8-12; rounded 150-205/about 180.
