# Isolated Solitaire validation, 2026-10-14

## Current result

Repaired run `3899597cd74e477195a35b280b201308` passed at 14:53:26 UTC.
Uninstall/reinstall previews and real native operations, both repeats, retained
source and registration recovery, owned schema-1 records and unchanged unrelated
registrations passed. Task cleanup, evidence hashes and separate checkpoint
recovery passed. Both worker and Explorer remained unelevated in the expected
session. This accepts the basic Solitaire registration lifecycle on this exact
Windows 11 reference, not application data, GUI, interruption, full launcher,
alternate administrator or other target/edition acceptance. Published support
stays closed; no next app has started and packages remain paused.

## Scope

The user authorized Solitaire-only uninstall/reinstall validation on the separate
UAC-enabled offline desktop and required a result before moving to another app.
The original Windows 11 and Server pins/controllers remain unchanged. Packages,
downloads and all other app validation remain paused for this run.

The fixture uses production Store handlers in the actual unelevated expected
desktop. The original current-source snapshot is retained separately from a
private copy. Only `app.solitaire`'s empty target array becomes
`@('Windows 11')` in that private catalog; all identity, type, removability,
consumer, policy and local-source guards stay unchanged. The original catalog
and every other operation remain byte-identical. Published support stays closed.

The fixture checks preview, native removal and repeat, local-source survival,
reinstall preview, native registration and repeat, owned schema-1 Store records
and unrelated registrations. Registration recovery is best effort; checkpoint
cleanup, exact application/data recovery, GUI, interruption, full launcher and
alternate-administrator acceptance remain separate.

## First native run: partial removal, reinstall refused

Run `dfd6c2c94edd4eb09bd6457194f3bb82` completed **Failed** at 14:24:28 UTC.
The retained source revision is `e977b814bc0646d2fce3bf305752eab3a6344eb2`,
including the then-uncommitted Solitaire fixture. Concurrent commits were
preserved; testing used the actual hashed snapshot rather than frozen CI.

| Check | Result |
| --- | --- |
| Uninstall preview | NotApplied; unchanged registration and no new record |
| Native uninstall | Completed; absent readback |
| Repeat uninstall | AlreadyMatching; no extra record |
| Immediate unrelated registration comparison | Passed |
| Immediate local reinstall Plan | No refusals; manifest/dependencies found |
| Reinstall preview | Refused: source unavailable or changed |
| Native reinstall / repeat | Not run; no reinstall record |
| Full lifecycle / registration recovery | Failed / unverified |
| Owned transient task cleanup | Passed |
| Separate checkpoint recovery | Passed; VM Off |

Removal record `03da459cd8d24a49a4b503d0adab46c7` is schema 1, owned by
`RIDE-WIN11-TEST\admin` / `S-1-5-21-3381495413-3650599264-2815280620-1000`,
and completed for Solitaire only. The main payload was version `4.19.3190.0`.
The immediate source Plan captured a matching manifest and five dependencies,
but the subsequent preview guard refused. This first run alone does not
identify whether the manifest, its access, hash or dependency availability
changed. No acquisition fallback or native registration followed the refusal.

All 369 original source files and 371 staged private files were hash verified.
The two added files were the bounded request and original catalog sidecar.

| Evidence | SHA-256 |
| --- | --- |
| Original catalog | `CCADC1F33882D23CE1EC9832E32BCBAB6C06E638C8DCDEAA868EAE2A68FF91B7` |
| Private catalog | `FA4B0567C41292DC46046A1ACE6D2B7A87AC5BC5457DE0D31C8B27CD34DD799F` |
| Original manifest | `FDD2FC6EF73F0B8F26943FEE0B1A0EF74B0817D12F4166B50726A6AA32E5C09B` |
| Staged manifest | `47EEE4DAFACE207371C180A351679487D6BF95E50FA914DF927D2355E7BC31AA` |
| Request | `F01891BEE98FA43F8676119D8434E384AA7CCFE9227011E2A97524A175AAAC52` |
| Actor result | `B7E8D1B193899E2F73A229676F457BC650258D81B6299E2CEFB05A032EF9626B` |
| Fixture result | `5547AC2647D254CF92B2C51A379569D1AF156EFCBF4556A5E79F015E99488000` |
| Actor console | `656E518C5CB864AF3EC4262E44A5620A3B9D183C23F4869A4C425A5271547819` |

Raw source, private copy, manifests and bounded guest evidence are retained under
`.local/store-solitaire-validation/dfd6c2c94edd4eb09bd6457194f3bb82/`.
The host process exit observation was null; native task result 1, actor failure
and coordinator failure independently establish failure. No acceptance is based
on that missing process field. Task cleanup and checkpoint recovery passed.

## Diagnostic follow-up

Store handler 0.3.2 retains `SourceError` alongside the unchanged refusal reason.
Actor 0.1.1 records a bounded delayed source check, exact manifest/dependency
observations and unrelated-registration comparison on partial exits. The host
runner retains the child process handle before waiting, to capture its exit code.
The source/protection/session guards and schema-1 recovery records are unchanged.
Both native PowerShell editions passed all 36 focused mocked checks after this
diagnostic change; read-only source/catalog/profile checks passed.

Diagnostic run `10a640b3ab10400ba06eb99f0aefa3e5` completed Failed at 14:33:48 UTC
on source revision `006f5ab8cdd09f32711f2ea55f9a2666aaf52acc`, including the
uncommitted diagnostic changes. Preview/removal/repeat passed again, with removal
record `27f78e7617d342bc8b6c0127de861411`. Both immediate and five-second delayed
reinstall Plans passed, but reinstall preview was source-refused. At exit, the
manifest still existed and its original hash matched; all five dependencies
remained registered. Unrelated registrations matched after removal and at exit.
Source loss is therefore not established. Child exit code 1 was captured; task
cleanup and separate checkpoint recovery passed. No native reinstall ran.

The actual defect was a read-only dependency projection using
`ForEach-Object PackageFullName`. Both native PowerShell editions reproduced that
member projection being suppressed under inherited WhatIf. Handler 0.3.3 uses
`Select-Object -ExpandProperty PackageFullName`, preserving read-only inspection.
The added regression checks accepted available dependencies during preview and
still refused genuinely missing dependencies without registration or extra records.
All 37 focused checks passed on both editions. No identity, protection, policy,
source-hash or recovery guard was relaxed. A repaired same-app acceptance run
was prepared; no other app is selected.

## Repaired native rerun postponed after elevation cancellation

Windows canceled the elevation launch before the repaired runner started on
2026-10-14 at 14:40:57 UTC. No third native request or VM run was created.
The tested handler 0.3.3 fix remains implemented; native reinstall/repeat and
full lifecycle acceptance remain pending. The prior two failures are preserved,
with source retention and the preview defect distinguished from actual recovery.

The repaired handler SHA-256 is
`1BDC1D55229909F6A0EE672A8363485668F43F7FA613FF92AD31714BB75F27A7`;
actor 0.1.1 is
`1981BC0CAE0E25F27E61BF776DFBBCE6074C190EF98E372E2B295FD269776582`;
host runner is
`A5BFB04CC61945E50E1062DED0F9B20BDFF673232EA6748C4BEE26F48CF0F1BA`.
Existing user authorization remains recorded; the operational elevation step
still needs completion before a new run. Keep the same app and separate pin,
take a fresh current-source snapshot and retain success/failure recovery evidence.
No next app is started.

The [machine-readable run record](store-solitaire-validation-2026-10-14.json)
retains both failed runs, source/evidence hashes, partial actor observations and
the canceled launch. The [active follow-up](../../migrations/store-app-follow-up-decisions.md#solitaire-native-validation-follow-up)
owns the remaining acceptance step.

## Resource and accounting

The separate VM is `ac29b689-f62d-4e5b-a4bc-25987f1fe843`, with clean checkpoint
`35b4f659-f168-4c22-bfc4-b6e7651a09e2`. It has no network adapter. Actor/session
and guest UAC remain independently checked; the original resources are unchanged.
See the [desktop runbook](../../migrations/store-test-desktop.md).

The earlier failed attempts remain historical evidence. The repaired run accepts
focused uninstall/reinstall and best-effort retained registration recovery.
Interruption, GUI, application data, full launcher and further target/edition
acceptance remain pending; the whole legacy app-management outcome stays partial.
No whole legacy outcome resolves, retires or excludes. All five ranges remain
settings 38-58, packages 58-73, components 20-25, accounts/configuration/files
25-35 and maintenance 8-12; rounded 150-205/about 180. Published support and the
package pause remain unchanged.

## Repaired native acceptance and source evidence

The resumed user instruction completed elevation and ran handler 0.3.3 with actor
0.1.1 on the same separate clean pin. Source revision
`006f5ab8cdd09f32711f2ea55f9a2666aaf52acc` includes the uncommitted repaired
handler and migration changes. All 371 original source files and 373 isolated
guest files matched their manifests. The private catalog still changes only
Solitaire's target array; the published catalog remains unchanged and closed.

| Check | Result |
| --- | --- |
| Uninstall preview | NotApplied; no mutation or record |
| Native uninstall | Completed; absent readback |
| Repeat uninstall | AlreadyMatching; no extra record |
| Immediate/delayed source and dependencies | Available, matching manifest |
| Reinstall preview | NotApplied; no mutation or record |
| Native retained-source registration | Completed; present readback |
| Repeat reinstall | AlreadyMatching; no extra record |
| Unrelated current-user registrations | Unchanged after removal and at exit |
| Owned schema-1 records | Uninstall and Reinstall Completed; ExactRecovery=false |
| Actual desktop | Expected SID/session 1; worker and Explorer unelevated |
| Guest child / transient task | Exit 0; task cleanup verified |
| Separate clean checkpoint | Recovered; VM Off, no network adapter |

The removal record is `75a3c361b3de453188c6d7d5110caef1`; reinstall record is
`a67d72606707454c8122b122fb6a0fae`. The surviving main manifest still matches
`F5FF2A0F339EFAC089294F297EA46BB82F80F205D07DD4A581C42453E6D881D0`,
with all five dependencies present. Saved recovery owns this user's exact
Solitaire identity; no app-data or exact prior-version guarantee is inferred.

| Evidence | SHA-256 |
| --- | --- |
| Original source manifest | `07D00667A69D6D32847C46154A00643E2FA5C547EDE7C402FB0EBB17C269F7B1` |
| Staged source manifest | `E1A9CEDBED38B0222A7684FBF097A530C8A2F0350A42C71B99E82BF4232F94F2` |
| Request | `761F17F96FE3E3637D8F660E5418C2AC25954BC6FD58D50BABCE42DDF10C88BD` |
| Handoff source | `29489321A3749CDA4E397B23FF43322B4B8136A32DAB761168E6A98FA57ED0A4` |

Bounded actor/fixture/console hashes and raw records are retained in the
[machine-readable evidence](store-solitaire-validation-2026-10-14.json) and under
`.local/store-solitaire-validation/3899597cd74e477195a35b280b201308/`.
Postflight at 14:54:48 UTC verified both original VMs Off, controllers Ready,
empty queues, locks available, unchanged pins and five installed controller
hashes, clean frozen CI and closed launcher. The separate VM is Off with its
unchanged clean checkpoint and zero network adapters. No other app or package
was selected. The 37 focused mocked tests per native PowerShell edition remain
the regression evidence for the projection fix; this run adds native acceptance.
