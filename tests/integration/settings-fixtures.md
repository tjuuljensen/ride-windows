# Request-bound settings fixtures

Schema 2 also supports **MinimumAgeConflict** only for
`windows.local-password-maximum-age`, with exactly `States=@('Days1')` and explicit
pending-target approval. It requires captured minimum age zero and maximum above
one day. A test-only local
[level-1003 setter](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset)
seeds a one-day minimum; production maximum-age code retains its level-1002-only
ownership. Preview and attempted Days1 must preserve the seed, refuse the
minimum/maximum conflict and invoke the counted native maximum setter zero times.
The captured failed run is inspected/recovered while its unchanged seed remains.

Finally, only the fixture's minimum is returned to captured zero after SAM and
unrelated-field comparison; drift refuses replay. `RecoveryMode=ExactFixtureSeed`
and `MinimumSeedRecoveryPassed` describe this separate recovery. LifecyclePassed
and ExactRecovery remain false: refusal is not successful primary apply or a
whole policy lifecycle. Checkpoint cleanup remains independently required.
No user passwords, account flags, full security-policy replay, UAC or package
acquisition are involved. Published target declarations remain unchanged.

Schema 7 selects **StoreDesktopPlan**, with the same eight request/identity/group
keys as schema 5. It accepts no command/action switches and cannot widen targets.
The elevated disposable coordinator requires exactly one existing expected-SID
Explorer candidate and starts a RunId-owned Interactive/Limited guest task.
The worker verifies real current desktop SID/session/shell/elevation, fixture,
actor-script and catalog/module hashes before read-only Plan and the desktop
request worker. Registrations are compared before/after; all published app targets
remain blocked. It retains actor.json under the intended user's local fixture
directory and copies bounded/hash-checked evidence into guest results, including
available failures. No credentials, sign-in configuration, app actions or package
requests are used. No execution-policy setting is changed.

Only the exact owned task definition may be stopped/unregistered in finally;
cleanup failure invalidates Plan acceptance. The pinned checkpoint remains a
separate required cleanup boundary. DesktopPlanPassed covers the real worker's
read-only Plan, **not** the production shell launcher, alternate-administrator
route or uninstall/reinstall. Those acceptance flags remain false.

Schema 6 selects **StoreDesktopProbe**, with exactly SchemaVersion, RunId,
IntegrationSuite, Target, Scenario, ExpectedUserSid and ExpectedUserName. It
observes at most 32 existing Explorer processes and whether each owner matches
the configured disposable guest SID. It records caller/shell session IDs and
candidate count; no other owner's SID is retained. Missing or ambiguous shells
remain pending resources, not failed app lifecycle or successful handoff.
Shell presence does not verify active connection state, a real desktop, an
unelevated token or source-bound child completion. This probe starts no session,
process, task or app and changes no Windows configuration. Selection/action/state
keys are refused. Native lifecycle, DesktopHandoffPassed and ExactRecovery stay
false; ProbePassed accepts observation only. Packages remain paused.

Schema 5 selects **StoreAppPreflight** for an exact configured guest account/SID
and a declared Store app group. It preserves empty published target support and
requires every action to refuse without state records or native app changes.
It retains current registration/protection/source observations and compares them
after the refusal. No uninstall, reinstall, handoff, policy or recovery lifecycle
acceptance is implied. Packages/downloads remain forbidden. Other schemas retain
their existing contracts; extra action/state/package keys in schema 5 are refused.

Use the accepted pinned task controller with **Source Local** to validate one
setting from the current checkout, including its uncommitted implementation.
Never use the frozen CI checkout as evidence for those changes. Record the
actual source-file manifest and fixture hash, plus correlated guest evidence
and final checkpoint recovery.

The staged file `tests/integration/settings-validation.fixture.psd1` is an
explicit temporary request selection, not a release default or profile:

```powershell
@{
    SchemaVersion = 1
    RunId = '0123456789abcdef0123456789abcdef' # Replace with this request's exact ID.
    IntegrationSuite = 'SettingsBatch60'
    Target = 'Windows 11'
    OperationId = 'windows.wap-push-service'
    States = @('AutomaticRunning', 'AutomaticStartup', 'AutomaticDelayedStartup',
        'AutomaticDelayedRunning', 'ManualStartup', 'DisabledStartup', 'Disabled')
    AllowPendingCandidate = $false
}
```

The selected suite remains a known controller routing value. The fixture
**replaces** its batch: a Passed result means the operation/states in retained
`settings-fixture.json`, not acceptance of all sixty settings. Guest summary
includes `IntegrationFixture`; check it and the request/file hashes explicitly.
Full/application suites, mismatched request IDs, unknown keys/states, packages
and unsupported unapproved targets are refused before integration.

Fixture files are bounded to 16 KiB and sixteen unique declared states. The
schema-1 seven-key contract remains valid. Schema 2 adds required `Scenario`:
`Lifecycle`, `ActiveRefusal`, `SettingDrift` or `InterruptedCreation`. Schema-2 non-lifecycle
scenarios require an owned power-plan operation and keep the same target approval,
source/request binding and package exclusions. The data module supplies scenario
enumeration for validation and optional command completion.

Schema 3 is a separate **read-only Store inventory** contract. It has exactly
SchemaVersion, RunId, IntegrationSuite, Target, Scenario (`StoreInventory`),
ExpectedUserSid and ExpectedUserName. It accepts no operation, state, app selection
or candidate-widening keys. The guest verifies both expected account name and SID
before querying current-user Appx registrations. Use established pinned guest
identity evidence, never an inferred interactive desktop user. The current request
must still match the target, source hashes and installed controller pins.

It retains store-app-inventory.json, store-app-review.json and a correlated
settings-fixture.json with InventoryCollected and WindowsMutation=false. Lifecycle
and ExactRecovery remain false; RecoveryMode is NoWindowsMutation. The configured
guest execution account is labelled explicitly, including its session, and is
not proof of other users, an interactive desktop, an untouched inbox image, Home,
Pro or another release. Native inventory acceptance is distinct from app removal,
policy consumption and data recovery. Packages remain paused. Final checkpoint
recovery and current idle/hash checks remain required even for this read-only mode.

Schema 4 uses the same seven keys with Scenario `StoreReferenceInventory`. It
explicitly collects separate CurrentUser and online ProvisionedImage JSON files,
plus a local DISM diagnostic log and individual collection flags/hashes. No PFN
or user registration is inferred from provisioning. A second collection failure
retains the already collected user evidence as partial; it does not make the
combined reference successful. It accepts no app selection or removal keys.
Schema 3 remains user-only. Current review defaults exclude historical-only v2
names; optional history is data comparison, never a removal preset.

`ActiveRefusal` selects only its new owned copy through a separate engine-captured
selection run using an in-memory GUID state. On Server only, the existing selection
operation receives isolated guest-private fixture support/default metadata, recorded
in the private catalog hash. It verifies active-copy deletion refusal, restores the
captured selection, then performs normal owned-copy compensation. Published states
and target declarations are unchanged.

`SettingDrift` mutates the AC sleep timeout only on its inactive owned copy and
verifies native readback, changed logical fingerprint, deletion refusal and retained
ownership. `InterruptedCreation` injects a fault immediately after real successful
duplication and verifies Intent retention, saved-run deletion refusal and no naming,
export or delete continuation. Both declare **CheckpointOnly** cleanup: a passing
guard report is not accepted lifecycle recovery or RIDE compensation. Host final
checkpoint cleanup, clean collection and independent idle checks remain required.

The
current harness supports scalar/paired registry, primary-service, local firewall
profile and local maximum-password-age settings. Maximum-age fixtures unwind
their own changed runs
in reverse order, with a read-only preview at every step, so each run's expected
post-write value still guards against stale recovery. The native drift guard is
never bypassed to restore the initial run across intervening writes.
Enable-all firewall validation
seeds a mixed local state, verifies saved-run recovery to that seed and separately
recovers the seed. ActiveStore and network observations are retained as evidence;
only the owned PersistentStore flags define exact firewall recovery.
Owned power-plan fixtures require absent ownership and an available source. They
verify one inactive new identity, unchanged active selection and unrelated plan
identities, repeat apply and deletion through the saved run. Recovery is declared
**compensating**, not exact restoration of an edited existing plan. Proposed random
GUIDs in absent-state inspection are ignored; persistent ownership, full plan
inventory and active selection must return to the captured state. Incomplete
ownership or changed copies remain explicit failures requiring review.
Version 0.6.6 temporarily renames only its version-2 owned inactive copy, verifies
saved-run deletion refusal and retained ownership, then restores its known creation
label/description as a separate seed recovery. The logical fingerprint must return
to the captured value before normal saved-run compensation proceeds. This tests
real metadata drift without relaxing the changed-copy guard or editing another plan.
Version 0.6.3 also retains three consecutive native exports of the same inactive
copy under the guest result's `owned-plan-exports` directory, with lengths,
SHA-256 hashes and bounded byte-difference samples in `ExportObservation`.
This diagnoses export stability without an intervening plan change. It does not
mask bytes, relax the deletion guard or turn checkpoint recovery into successful
RIDE recovery. The diagnostic requires the same disposable-VM authorization.
It runs focused mocked handler/catalog/preview checks with WindowsIntegration
excluded and Pester TestRegistry disabled. Live native integration uses a fresh
PowerShell process so mock native types cannot leak from Pester into acceptance.

For an applicable pending candidate, set explicit approval in the fixture. The
harness changes only that operation's support/default fields in an owned
guest-private catalog copy, retaining original and fixture hashes. It does not
change published SupportedTargets, infer Windows defaults or add a recommended
profile. Inapplicable candidates stay unavailable; additional handler families
require their own fixture/recovery work before selection.

Keep the source unchanged until the worker's `source-files.json` confirms its
snapshot is sealed, and keep the temporary selection unchanged until execution
finishes. Verify retained `snapshot/ride-windows` bytes against that actual manifest.
Review any preflight/worker delta explicitly, including concurrent unrelated test
or documentation edits; record it rather than claiming every preflight hash matched.
Archive selection bytes with the retained snapshot. Remove only the
unchanged file owned by that request before another request; preserve concurrent
work and recheck both VMs/tasks, queues, worker locks, recovery blocks, pins and
installed hashes before each submission. Packages remain independently paused.

The harness checks apply/restore preview, repeated named-state apply, explicit
declared baseline and captured recovery, with original state retained even on
failure. GUI/session, boot/workload, managed precedence/defaults and deliberately
induced native partial failures remain separate evidence. Registry, primary-service
and maximum-age fixtures inject an interruption after a real focused native write.
Enable-all firewall fixtures interrupt before the second profile setter after the
first profile completes, and check per-profile partial reporting. These scenarios
retain the failed run and changed readback, then verify restore preview, exact
recovery and repeat recovery. Fixture seeds have a separate recovery boundary.
This establishes recovery from those controlled interruptions; it does not claim
a real access-denied or managed-policy failure. A recovered setting does not prove
the other outcomes. The pinned host checkpoint is the outer recovery
boundary; never execute this state-changing harness on the developer workstation.

See the [controller workflow](automatedlab-tasks.md) and active
[settings review](../../docs/migrations/settings-post-migration-review.md).
