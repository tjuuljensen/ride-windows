# Store inventory context and refused native collection

Recorded: **2026-10-14**. User decision: both separate policy/user-uninstall
workflows, with **keep everything until current-user inventories are collected**.
Windows 10 historical entries stay preserved; absent apps on one release/edition
do not justify retirement or replacement-PFN guesses.

Store review module/exporter 0.1.1 retain observed edition ID, display version,
build/revision and process hints, with incomplete context explicit. Older schema-1
inventories remain readable. Twenty Store-review checks pass on each native
PowerShell edition. With fixture-data and CLI checks, **78/78 passed on each**,
zero failed/skipped. Validation passes 318 operations, three groups, five profiles,
137 PowerShell files. Pester TestRegistry is disabled; all Appx/registry collection
calls in these tests are mocked. Native app collection is not accepted by unit tests.

Schema-3 fixture/data module 0.5.0/fixture 0.8.0/guest runner 0.8.2 select bounded
read-only StoreInventory for an exact expected configured guest account/SID.
They accept no operation, states, app selection or widening keys. No Windows
mutation, lifecycle or app/data recovery is claimed. Existing schemas are retained.

The initial sandbox CIM denial was resolved using read-only status checks outside
the sandbox with the same Windows token, without UAC/elevation. Both disposable
controllers were idle with unchanged pins and installed 0.4.6 hashes, and the
GitHub bridge remained complete/yielded/paused. No controller refresh was made.

Request **3dfba9fd4b6f4e61bf24de7e8613777e**, Source Local, SettingsBatch60 routing,
was submitted at 06:57:11.9139471 UTC. It includes the current uncommitted source
in a retained **342-file preflight snapshot**, not the frozen CI checkout. Fixture
SHA-256: FDC659B975B6106788A18BB9399751AD56020B2DF0778E7BC33111B7EB0F4F20.
Expected configured guest identity came from accepted pinned request
6573f64481da4770b783f33e6d7a04ad and was not inferred to be another desktop user.

The controller refused it at 06:57:16.4853941 UTC:
`WinRM must already be running. Prepare the host in an elevated session; no services were started.`
There is no worker source-files seal or guest evidence: no VM scenario ran and no
Appx inventory was collected. The preflight snapshot is reproducibility evidence
for the proposed source only, not accepted native-test source. Null cleanup and
collection errors do not constitute successful checkpoint recovery.

At 06:58:33.5168876 UTC, independent native postflight verified both VMs Off,
tasks Ready, pending/running queues empty, locks available, no recovery blocks,
unchanged checkpoint pins and installed hashes. Host WinRM status was Stopped.
Only the refused request's unchanged hash-matched temporary selection was removed.
The service was not started; elevated host preparation is postponed per the user.
No application removal, publisher/GitHub request, package acquisition or UAC change.

Local evidence: .local/settings-validation/3dfba9fd4b6f4e61bf24de7e8613777e
(receipt, 342-file preflight manifest/snapshot, postflight); protected refusal:
C:/ProgramData/RIDE/TestAutomation/RIDEWin11Test/results/3dfba9fd4b6f4e61bf24de7e8613777e/result.json.
The [inventory collection plan](../../migrations/store-app-inventory-plan.md) owns
host prerequisite, Pro/Home/Education/Windows 10 reference questions and retirement
criteria. No selection question is pending before inventories.

All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205,
about 180. No whole legacy outcome is resolved, retired or excluded. Packages
remain paused; native handoff, mixed-profile recovery and actual app lifecycle
acceptance remain separate work.
