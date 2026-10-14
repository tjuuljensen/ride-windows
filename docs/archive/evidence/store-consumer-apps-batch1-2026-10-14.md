# Consumer Store app candidate batch 1, 2026-10-14

Implemented app.clipchamp, app.news, app.weather, app.solitaire and the ordered
solution.store-consumer-apps group. StoreApps 0.1.0 and Invoke-RideStoreApps 0.1.0
provide explicit current-user planning and guarded actions; ordinary profile/package
routing refuses them. Published targets remain empty, with Windows 11/Server 2025
listed only as pending candidates. No default/recommended profile selects the apps.

The [group guide](../../store-app-groups.md#batch-1-commands) owns commands, flags,
scope and recovery. ID/action/command/saved Store-run completion reads the catalog
and bounded local directory names. Discovery distinguishes Store apps from settings
and downloadable packages. Generated OPERATIONS.md includes the declarations.

Removal captures intent before native mutation and retains all group results,
including absence/refusal/partial failure. Recovery reads only an owned schema-1
Store removal record; retained payload identity/manifest hash, available dependencies,
user/session, target and policy checks are repeated before registration. Interrupted
intent is not reported completed. Acquisition, AllUsers changes, deprovisioning,
policy writes and exact data/version restoration are absent from this contract.
Unknown protection/type/full-payload flags stay unknown; protected/shared consumers
and stub routes refuse. Source and state paths refuse escape/reparse points; manifest
XML disables DTD/entity resolution. Generic setting restore does not own these runs.

Local evidence on Windows PowerShell 5.1 and PowerShell 7:

- 165 passed focused Store/catalog/presentation/fixture/search checks per edition,
  zero failed, one state-changing registry WindowsIntegration case excluded.
- After final full-payload/stub safeguards, 22 updated Store-specific checks passed
  per edition, zero failed/skipped. These overlap the earlier run, not 187 unique tests.
- Parser/catalog/profile/generated-document validation passed on both editions:
  322 operations, four groups, five profiles and 141 PowerShell files.
- Initial 18 and then four regression failures per edition were corrected: completion
  path lookup, nested module test visibility, shared test-directory isolation and
  existing catalog assumptions about pending kinds/recovery labels. No native app
  mutation occurred in these failed mocked runs.

Local result metadata is in .local/store-consumer-unit-{5,7}/result.json. Native
Store preflight uses data module 0.7.0/schema 5, fixture 0.9.0 and guest runner 0.8.4.
It requires target refusal before invoking the guarded action and verifies every
result refused without state creation, then compares registration observations.
It claims no actual uninstall, retained-source recovery or desktop handoff acceptance.

## Native preflight

Pending serial Windows 11/Server 2025 runs from current Local source including
uncommitted changes, using installed controller 0.4.6/collector 0.4.1, unchanged
pins and frozen CI. Source hashes and checkpoint recovery must be verified per run.

No whole legacy outcome resolved or retired. App-specific protection/full payload,
unelevated desktop and alternate-admin Store handoff, actual removal/reinstall,
partial native failure, policy consumer/schema and later groups remain pending.
All five ranges stay 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180
because a guarded candidate is not accepted lifecycle behavior. Current apps are
kept; packages and acquisition-dependent reinstall remain paused.

## Later implementation and completed native preflights

All five optional groups/22 identities were implemented as guarded candidates.
StoreApps/tool 0.2.0 added same-session intended-user desktop handoff; its parent
reads selection/source metadata and its child owns inspection, records and app
confirmation. Native GUI/alternate-admin acceptance remains pending. The final
0.2.0 host mocked matrix passed 171 checks per edition, with one registry case
excluded. These overlap earlier totals.

| Run | Target / source module | Accepted scope | Source files / passed tests |
| --- | --- | --- | --- |
| 6019700fdc1b48bbab6ed91e8836994f | Windows 11 / 0.1.0 | Original guard/refusal only | 355 / 193 |
| b581ad67f44b4a87a5fb3a7307f96d6c | Windows 11 / 0.1.2 | Runtime/source inspection and refusal only | 355 / 194 |
| 8de2401ea49c49cfb82b47a1073d1904 | Server 2025 / 0.2.0 | Absence/refusal only; all four consumer apps absent | 356 / 198 |

Each run excluded one registry integration test, passed source/preflight byte/hash,
identity, XML, checkpoint recovery and final idle/pin/hash checks. No app changed
and no Store action record was created. Controller cleanup/collection errors were
empty. Installed controller 0.4.6/collector 0.4.1 and frozen CI stayed unchanged.

The revised Windows 11 snapshot verified runtime descriptors for all 11 rows.
Clipchamp and Solitaire have main-manifest proof. News and Weather each have two
stub rows and unavailable full source. SignatureKind=Store does not supply a
missing IsPartOfSystem; that flag remains null. WinRM has no current desktop.
Server retains managed-enrollment uncertainty rather than assuming no management.

| Run | Fixture SHA256 | Source-manifest SHA256 |
| --- | --- | --- |
| 6019700fdc1b48bbab6ed91e8836994f | 56525BF13808F033A09E113B82BB7871D6F0CC377C2AC3E980C97E00CC2DD7D8 | FA33C7269DEBB6794FD9F6251EBAF1D1248665E9776C927B28843318526FA087 |
| b581ad67f44b4a87a5fb3a7307f96d6c | 3315E13A06A116EE3ED017C265B1282F24735ADE1301A9B5FC3F43A5ED26DA4D | CB1E1CDD6EE00787C3238A0BBE012EB9064F7BCFAF7533F170B394658A9B146E |
| 8de2401ea49c49cfb82b47a1073d1904 | DAAC889E55A866227F199117DE12B8DB0DC6B2F4782332357B6FEE5E9243BF83 | 8635BDED9CC26EDB31CC46232655FF339F78E04E8E6284976E84CF76E260AA67 |

Retained receipts, summaries, XML and correlated guard-acceptance audits are in
.local/settings-validation/<RunId>; retained source snapshots are under each
installed controller's results/<RunId>/snapshot/ride-windows. These runs do not
include the later 0.3.0 protection-rule implementation.

## Reviewed protection/source decisions and later guard acceptance

The user approved exact reviewed identities plus known NonRemovable=false and
complete runtime type/stub checks, keeping IsPartOfSystem visibly unknown. The
user separately chose to wait for usable local reinstall source. News/Weather
therefore stay blocked; packages remain paused. StoreApps 0.3.0 and catalog
ReviewedIdentityRemovabilityV1 implement the first decision for exactly 22 apps.
Live observations and confirmation display Unknown explicitly without inventing
false system flags. Missing review metadata and known protected flags still refuse.

Windows 11 0341ac971c5a4c8ba7a12b15bd51b68e passed 201 guest checks with one registry
integration case excluded and native fixture 0.9.1 guard/reporting acceptance.
All 356 preflight/source entries and retained bytes matched. Fixture SHA256:
07FDE2B4B692DEE5E18496D911E97DE5ABF998382509DA8DF60F992DEC4F663C.
Source-manifest SHA256: FE2399CC69E9D2F8B5843010E29ADF645580F13662FC3C6D64F3FD0CB176A2AF.
Finished 11:18:23Z; source/identity/XML/checkpoint/idle/pin/hash audit passed at
11:20:20Z. All 11 rows retained null system flags and explicit Unknown observations,
with verified runtime descriptors. Clipchamp/Solitaire still refuse unavailable
current desktop and unpublished target. News/Weather also refuse stub/source.
No app changed, no Store record created; no desktop or app lifecycle accepted.

Later source review found that a runtime conflict could remain only diagnostic
when native fields were complete. StoreApps 0.3.1 now refuses any unverified or
conflicting runtime identity/type proof. Both editions passed all 31 focused
Store tests after this repair; PS7 repository validation passed. The earlier
174-check mocked matrix and both-edition parser/catalog validation passed before
that repair. The 31 checks overlap the broader matrix; do not sum their totals.
The completed native 0.3.0 snapshot does not include this later repair. Current
0.3.1 requires fresh native evidence in the next applicable desktop/lifecycle fixture.

All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180; no whole legacy outcome closed. Pending desktop/lifecycle/partial/recovery,
Server applicability and separate policy evidence are in the
[active follow-up document](../../migrations/store-app-follow-up-decisions.md).

## Desktop resource probe and actor diagnostics

Read-only Windows 11 probe 2f461c696aea46f18a36277740ab14af passed 203 guest
checks (one registry case excluded). One expected-SID Explorer candidate was
observed in session 1; caller session was 0. All 356 source/preflight hashes,
identity/XML/checkpoint and idle/pin checks passed. Fixture hash:
0344DB41A93958C2A237462F4444200490CF7BF10C44A345E699E90B9E3C4B82.
Source manifest: 7CD8422790EF30FF70072239E0BB9FB74B41ADCE94908F8CBB5A646CE4110235.
Shell presence alone did not accept a desktop worker.

Schema-7/fixture-0.11.0 Plan-only actor subsequently failed before worker evidence.
The bounded transcript repair (fixture 0.11.1/actor 0.1.1) isolated an initial
identity/session/admin-role refusal; actor 0.1.2 reported the exact observations.
Each native attempt passed 204 mocked guest checks with one registry case excluded,
then failed real actor acceptance. All 357 source/preflight bytes, owned-task cleanup,
controller collection/cleanup, checkpoint and idle/pin/hash checks were verified.
The failed selections were removed only after matching their receipt hashes.

| Run | Fixture SHA256 | Source-manifest SHA256 |
| --- | --- | --- |
| 99adcc9ee9df4f85953f37cf058ca9f7 | CF894B8320728A3F3ECC773264DB3E8B359E01CA2FBF983396FC47446203E5C5 | C3F740C9A4D20FD50106FFCF012A22A33234FA2B7AAF4722242D2D7AB53DBACA |
| b2615b9d390447dc906a3a50b490cf78 | 379319C1F22BF7062E0483A6A29B9EF76041559441CDF839B28E24F9FB6EC908 | 982217E678EB07C627AB0D60F9849FD93023508826761958951E296B91661EB6 |
| d62ee7a8b55c4c2aa0b2352147901e87 | C56726427B33E35C007873A9DF83CE1F46F91DD0B3DB686EEFA72B345CBD3614 | 0ED8737500063870F9AF6B44E5972CB2FE0AB0C10A47C4C43CE6DBEC9B48291C |

The final diagnostic proves matching expected/actual SID/account and session 1,
but AdministrativeToken=true. The guest reports EnableLUA=0, consent 5 and secure
desktop 1. The unelevated actor prerequisite is unavailable on this pinned guest;
the guard refused before app inspection. UAC and the pin were not changed.
Console hashes: b2615b9d A9747DA7B24176C41EF503A029589C46D66E3DA6FAED4508B5511F4D70383675;
d62ee7a8 484FEA918F831FB53A2B5B4748EFD79F1C5293C95F0ED07B999889A7A5867679.

A genuine unelevated desktop fixture resource is deferred while the user is AFK.
Keep the existing controller/pin/UAC unchanged and record any required interactive
resource preparation in the [follow-up document](../../migrations/store-app-follow-up-decisions.md#desktop-resource-decision---postponed-while-afk).
Native worker/full launcher/alternate-admin/app removal/reinstall remain pending.
No apps were removed; packages stay paused. All five estimate ranges remain
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about 180.
