# Settings implementation handoff

Recorded: **2026-10-11**, before archiving the Windows-settings review chat.
This is a resume point, not a declaration that migration or acceptance is complete.

## Authoritative records

| Record | Purpose |
| --- | --- |
| [Post-migration review](settings-post-migration-review.md) | Detailed accepted decisions, mapping references, reverse semantics and feature acceptance requirements |
| [Remaining-settings ledger](remaining-settings-decisions.md#implementation-and-acceptance-queue) | Implementation order, deferred outcomes, resource gaps and final walkthrough milestone |
| [Migration plan](../MIGRATION-PLAN.md#estimated-remaining-migration-work) | Dated estimates by legacy outcome; refresh after every batch |
| [Setting presentation contract](../SETTING-PRESENTATION.md) | Implemented metadata/display contract and its compatibility and evidence limits |

Resume implementation from these accepted designs. The remaining-settings table
has accepted designs or retirement dispositions for 28 identified entries; its
29th entry, User .NET assemblies, still lacks source identification. These rows
are not counts of atomic settings or the entire migration backlog. Earlier
accepted decisions in the post-migration review remain applicable too. Do not
repeat approvals unless new evidence requires a material design change.

## Durable product decisions

- Prefer controls that match native GUI choices. Split legacy bundles only into
  independently useful, explainable controls; keep coordinated values together
  when they implement one feature. Preserve published IDs and saved recovery.
- Keep individual promotion controls plus optional **Reduce Windows promotions**
  guidance/composition. Undocumented numeric channels remain experimental and
  excluded from recommended profiles until their current meaning is established.
- Preserve the purpose of legacy bundles: guide users to complete outcomes when
  several controls are required. Explain dependencies, order, tradeoffs, recovery,
  prerequisites and missing coverage; do not present a universal security level.
- Scope, elevation, enforcement and GUI editability are separate dimensions.
  Display license/account/membership requirements explicitly. Configured values
  and declared defaults do not establish effective policy or protection.
- UAC must present all four native slider choices. The third position from the
  bottom is the proposed default choice; its value pair, GUI and prompt behavior
  still require independent Windows 11 and Server acceptance. Do not change
  EnableLUA or claim that the workstation's UAC was altered for migration.
- Prefer a Windows-native F1 solution. The accepted TypeLib investigation is
  conditional on evidence of the actual affected help behavior; no automatic
  third-party remapper or executable interception is approved as its replacement.
- Retain the user's early Windows 11 NumLock testing history. Registry-only
  startup controls must prove equivalence to the reliable legacy combined outcome;
  do not silently reintroduce simulated keypresses if current evidence disagrees.

The detailed accepted sections supersede this summary wherever more specific.
Task Manager's legacy view selector and Computer Browser visibility have accepted
retirement dispositions. Windows Update executable interception is also retired,
but supported interruption-management replacement work remains partial and counted.
Do not guess a replacement or silently close the unidentified .NET entry.

## Implementation checkpoint and next work

The first increment implements shared presentation in discovery/search, setting
and group-member details, profile previews and status, plus scalar registry
scope/root and metadata validation. Initial reviewed metadata covers file-name
extensions, sound-scheme editing, Edge startup boost and Defender cloud-delivered
protection. The Defender Advanced-state requirements are visible without changing
its value. Schema 1, IDs, states, handlers and saved-run contracts are preserved.

This is partial completion of queue item 1. Continue auditing the remaining
settings' scope, official applicability, GUI effects and prerequisites. Implement
feature-specific effective-policy/source inspection and protection against
targeting the wrong user under alternate-administrator elevation. Displaying an
execution account does not enforce the intended-user boundary.

Then follow the ledger's queue: coherent handlers and compatible exact recovery;
evidence for uncertain mappings; complete-outcome guidance; disposable target
acceptance. Open mapping work includes suggestions, input personalization,
feedback-frequency units/types, packed visual effects, NumLock, F1, shell/menu
controls and conditional CEIP/media components. Other accepted work includes
modern firewall profiles, owned power-plan creation, proxy configuration, Windows
RE, BitLocker enrollment/recovery, service delay/runtime and Server controls.

The requested final walkthrough starts only after the last retained setting is
implemented or has an explicit accepted replacement/retirement. That milestone
has not been reached. Review residual decisions, provenance, recovery and target
limitations together at that point.

## Recorded validation and reproducibility

Tests were held until the concurrent application migration and tests finished.
The presentation increment subsequently covered **149 passing checks per edition**
on Windows PowerShell 5.1.26100.9549 and PowerShell 7.6.5. Each initial run passed
147; two temporary-download fixture checks passed on targeted retry with
workspace-local scratch data. One state-changing WindowsIntegration test was
excluded. Parser/catalog/profile/reference validation passed for the then-current
287 operations, two groups, four profiles and 87 PowerShell files. These are
checkpoint results, not validation of later changes from other chats.

The mocked suite comprised `tests/SettingPresentation.Tests.ps1`,
`tests/Search.Tests.ps1`, `tests/Catalog.Tests.ps1` and `tests/Libraries.Tests.ps1`.
Use native Windows PowerShell and Pester 5.x. In its configuration, set
`Filter.ExcludeTag = @('WindowsIntegration')` and `TestRegistry.Enabled = $false`:
Pester otherwise attempts to create an automatic HKCU registry fixture even for
mocked tests. Keep temporary downloads in a dedicated writable scratch directory
when the sandbox restricts the default temporary location. The successful retry
set TEMP/TMP only in the child test process; no persistent environment or Windows
setting was changed, and no elevated Windows process was required.

Run `tools/validate.ps1` for parser/catalog/profile/generated-reference checks;
regenerate `docs/OPERATIONS.md` through `tools/Export-RideCatalog.ps1`. Hashtable
sorting in the generator must use property scriptblocks such as
`Sort-Object { $_.Id }` for identical PowerShell 5.1/7 output, and missing evidence
must not generate empty reference links.

Local detailed logs are under ignored `.local/setting-presentation-*`; they are
supplementary checkout evidence, not version-controlled artifacts. The durable
results and limitations are recorded above and in the post-migration review.
Unit and registry lifecycle checks do not prove GUI, sign-in/reboot, peer security,
managed precedence or Server behavior. State-changing acceptance belongs only in
disposable Windows VMs, with capture, exact recovery and checkpoint cleanup.

## Repository preservation

The implementation and decision documents include files that remain untracked
or uncommitted. Preserve them in reviewed commits before relying on a clean
checkout or release. Archiving the chat does not create those commits. Keep
concurrent application and other unrelated working-tree changes intact.
