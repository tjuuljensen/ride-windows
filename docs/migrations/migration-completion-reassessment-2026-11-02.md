# Migration completion reassessment, 2026-11-02

## Status

Migration execution is paused at the user's request. The next step is to reassess
how to close the remaining work before starting another implementation or test
batch.

## Why the completion approach is being reassessed

The user asked to fast-track the remaining tests because the migration appeared
unlikely to finish. Multiple source-test batches were run and committed, but the
overview stayed at **126-180 estimated legacy outcomes**. That estimate is not a
count of tests remaining. The batches established current-source behavior; most
did not resolve, retire, or exclude a legacy outcome. The work therefore needs
an outcome-oriented closure plan, rather than another unprioritized sweep of
passing source suites.

## Durable reporting and completion rules

For each requested workstream, report its concrete components one workstream at
a time. Label each component as one of:

- **Resolved**: the defined legacy outcome is implemented or otherwise met and
  its required acceptance evidence is complete.
- **Open**: implementation or mapping exists, but a stated acceptance or
  recovery requirement remains incomplete.
- **Unmigrated**: a legacy outcome still lacks an implementation or a recorded
  disposition.
- **Candidate**: optional or new work exists in candidate form and has not
  passed its declared acceptance gate. Candidates that are new features do not
  count as completed legacy outcomes.
- **Retired**: a durable decision removes the legacy outcome from the target
  platform scope.
- **Excluded**: a durable scope decision leaves an outcome out of this
  migration; retain its reason and any operational caveat.
- **Partial/deferred**: only some legacy behavior is covered or remaining work
  is intentionally postponed. Keep it visible and counted until reconciled.

Each status report should name the component, link its source-of-record entry,
state the remaining closure evidence, and identify blockers. Keep source
regression, artifact review, activation, and verified Windows behavior separate.

The five estimates in [MIGRATION-PLAN.md](../MIGRATION-PLAN.md#estimated-remaining-migration-work)
count legacy feature/product outcomes, not test cases or catalog IDs. A passing
source test updates validation evidence; it does not reduce an estimate unless
the linked ledger establishes that a legacy outcome was resolved, retired, or
excluded. Partial and deferred outcomes remain visible and counted according to
the migration model. Recalculate the ranges from the reconciled outcome ledger,
not from the number of tests passed.

## Checkpoint at pause

- **Settings:** presentation review is complete at 279/279. The estimate remains
  37-57 outcomes. The [remaining-settings plan](remaining-settings-plan.md) and
  [post-migration review](settings-post-migration-review.md) identify open
  mappings and candidate-only controls, including hibernation, modern BitLocker
  drive-method policies, Storage Sense policy, local password complexity,
  advanced WinHTTP proxy, desktop shortcuts, and File Explorer F1. Their source
  tests do not establish native acceptance. New controls such as Click to Do
  are candidates, not legacy closures.
- **Packages:** the estimate remains 37-52. Current-source package regressions
  cover many pins and file lifecycles. PSScriptTools' generated inert 360-member
  lifecycle passed 7/7; this does not establish package activation or close a
  legacy product outcome. The WFN 531-member case remains incomplete after a
  bounded attempt. Sysinternals licensing is settled under the prior RIDE v2
  specialist approval; Defender exclusions are independent of that decision.
- **Components:** the estimate remains 19-24. Source preparation and mocked
  lifecycle work do not establish Windows feature installation, service
  behavior, or recovery on declared targets.
- **Files/assets:** the estimate remains 25-35. Source checks do not establish
  Explorer menu, desktop, or other native shell behavior.
- **Maintenance:** the estimate remains 8-12. Source checks do not establish
  runtime ACL, scheduled-task, or screen-lock acceptance.

The exact ranges and dated test evidence remain in the migration plan. The
current Windows PowerShell 5.1 source batch passed 331/331; the PSScriptTools
suite passed 7/7; the WFN full synthetic suite did not finish its large case.
The broader 3,698-case aggregate remains incomplete. Native VM acceptance is
blocked because host CIM access fails before VM/checkpoint inspection. Keep
Defender-alerted NirSoft files excluded and do not materialize them during test
work. See the linked per-batch evidence in the [migration plan](../MIGRATION-PLAN.md).

## Resume criterion

Resume when the completion approach has been reviewed. Start with an explicit
legacy-outcome inventory for the workstream being discussed, separating
implemented-but-open outcomes from unmigrated outcomes, candidates, and accepted
or retired outcomes. Prioritize batches by the number of outcomes they can
actually close and the acceptance resources they require. Preserve the existing
authorization to run approved batches without pauses between them and commit
each completed batch separately; do not resume automatically while this
reassessment is pending.
