# Intended-user handoff first batch

Recorded: **2026-10-14**. User decision D01 selects a separate process for the
signed-in user in the current desktop session; other sessions and no desktop are
refused. The implementation is explicit `-UserContext Desktop` for user-only
set/unset, apply/plan and saved-run restore. Current remains the default.

The parent freezes operation selections and contract hashes, captures desktop
SID/session/shell PID, and returns only a launch receipt. The worker requires the
actual unelevated desktop identity, unchanged source and validated user-only
operations. Recovery uses the target user's existing namespace and rejects mixed,
package, mismatched or unsupported saved records. No credential transfer,
execution-policy bypass in the worker, UAC adjustment or automatic mixed-profile
splitting is implemented. Catalog states, defaults and SupportedTargets remain
unchanged. Packages remain paused.

Focused handoff and CLI tests passed **65/65 on each native PowerShell edition**,
zero failed or skipped. They use mocked shell/context, launch and engine calls,
TestRegistry disabled and the existing Pester 5.7.1. Both editions compile
the native declarations without invoking their APIs. The test result files are
`.local/user-handoff-5/result.json` and `.local/user-handoff-7/result.json`.
Final counts and validation status are recorded in the dated migration ledger.
An initial test expected the desktop-specific authentication rejection even
though an earlier general CLI guard correctly rejected it; the corrected case
exercises apply, where the desktop-specific guard is reached. No product guard
was weakened. Earlier mock-visibility fixture retries are not native failures.

Dependency status is completed/idle. Local bridge evidence retains verified
Windows 11/Server Full pairs, explicit shared-resource yield and paused bridge.
The current readiness attempt through `.local/controller-046-readiness.ps1`
failed at Get-VM with denied CIM access. No VM/controller request, package
acquisition or developer-workstation setting change was submitted. Elevated
readiness and real interactive acceptance are deferred per the user's instruction
to postpone elevation. Historical idle records do not replace current checks.

Explorer COM broker behavior, actual cross-account launch, GUI/session behavior,
repeat apply and saved recovery remain pending disposable evidence. An ordinary
unattended session cannot establish a positive desktop launch. Mixed-profile
verified completion, cross-store correlation, ordering and interrupted recovery
need the next design batch. The concrete workflow and acceptance matrix are in
[the guide](../../intended-user-handoff.md).

No whole legacy outcome closes. All five ranges remain settings 38-58, packages
58-73, components 20-25, accounts/config/files 25-35, maintenance 8-12;
rounded total 150-205, about 180. Concurrent real Joplin observations in
catalog/artifact-observations.json were preserved and excluded from this batch's
implementation claims.
