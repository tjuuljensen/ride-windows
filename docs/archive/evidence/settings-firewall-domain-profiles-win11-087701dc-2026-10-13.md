# Domain firewall profile Windows 11 lifecycle passed, 2026-10-13

Request: `087701dce1ba484795bf59765e980074`. Controller result: **Passed**, finished
`2026-10-13T16:35:37.5068445Z`. Local source revision: `00e820f876f6c00f70750c732b3057f5e82f79bd`
plus its retained uncommitted source. Retained manifest: 290 files;
preflight differences: 0. Fixture SHA-256:
`BB157B7E20F891DB99BAEF68B890D387653058BA32E57CE932BC6F1CAF58F708`. Source catalog SHA-256:
`18EF5EF5598577E7EFCE4960438A76BEA9BD7A3B601A2978BADF8D504AC9BD59`; private candidate catalog:
`4AD0F5DB92B94DA32822153C1207AAEA6890A54A8EFE1DCC49EFEC4C4C335DFB`. Published support declarations are unchanged.

All 290 retained snapshot files were independently checked against the
actual worker manifest; invalid hashes: 0. Reviewed preflight
delta paths: . Unreviewed differences:
0. The retained worker snapshot is the tested source authority.

Guest validation: True. Focused Pester: 142
passed, 0 failed, 143 discovered.
Fixture lifecycle: True; declared recovery mode:
Exact; recovery passed: True; exact recovery: True.
Completed states:
Off, On. Repeated apply is checked for each state;
apply/restore preview and any declared baseline are part of lifecycle acceptance.

Controller, cleanup, collection, guest, fixture and recovery errors were absent.

Controlled native-mutation failure evidence was not included in this snapshot.

Additional consumer/component observations were not included in this snapshot.

Independent native postflight found both VMs Off, tasks Ready, empty queues,
available locks, no recovery blocks and matching pinned checkpoint identities.
No package acquisition, GitHub request, host UAC change or developer-workstation
integration was performed. Packages remain paused.

This is bounded lifecycle evidence. Actual feature and GUI/session behavior,
component applicability, boot/workload, target defaults, managed precedence and
deliberately induced native partial failures remain pending. Missing components
do not become accepted features through registry round trips. No whole legacy
outcome or rounded estimate is closed by this run.

Protected evidence: `C:\ProgramData\RIDE\TestAutomation\RIDEWin11Test/results/087701dce1ba484795bf59765e980074`. The source snapshot/manifest,
guest summary, fixture report, transcript and final result retain the exact scope.
Local preflight receipt/manifest and postflight: `.local/settings-validation/087701dce1ba484795bf59765e980074`.
See the active [settings review](../../migrations/settings-post-migration-review.md).
