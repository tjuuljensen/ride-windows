# Intended-user process handoff

`-UserContext Desktop` explicitly hands a user-only setting action to the signed-in
user in the caller's current desktop session. The default, `Current`, continues to
use the execution account. This first batch implements the separate-process route;
native interactive acceptance remains pending. Do not recommend mixed profiles
until their ordering and recovery batch is implemented and accepted.

The selected desktop must have a running, unelevated Explorer shell. RIDE refuses
another session, session zero, an absent shell or an elevated shell. It never falls
back to an administrator's HKCU, creates a logon session or asks for another user's
credentials. A different administrator's elevated console can prepare the request,
but the worker must run as the captured desktop user without elevation.

## First batch workflow

Preview an explicit user setting from a console in that desktop session:

```powershell
.\ride.ps1 set windows.show-known-extensions Enabled -UserContext Desktop -WhatIf
```

Preview prepares and checks the selection but starts no worker or handoff file.
It returns `NotLaunched`. To apply the same selection, omit `-WhatIf`:

```powershell
.\ride.ps1 set windows.show-known-extensions Enabled -UserContext Desktop
```

The desktop shell opens a visible Windows PowerShell 5.1 window. The caller's
`Launched` receipt includes the target SID, session and request ID, with
`CompletionVerified = false`. Read the child's actual operation output and saved
run ID. A launch receipt is neither successful application nor recovery evidence.
The window remains open on success or error. `-Confirm` requests launch confirmation
and is forwarded to the child engine for per-operation confirmation.

The worker rechecks SID, session, shell process, elevation, source hashes and all
operation contracts before engine changes. A changed checkout, inaccessible source,
changed desktop or incompatible selection fails visibly. Source checks include
uncommitted launcher, module and catalog files; linked source entries are refused.
The launcher sends encoded data rather than substituting IDs or paths into code.
It uses no execution-policy bypass. The desktop user's policy must permit the
worker; a policy failure remains pending work, rather than prompting for elevation.

Supported commands are `set`, `unset`, `apply`, `plan` and `restore`. `apply` and
`plan` require a user-only profile; the ordinary default profile includes machine
and package operations and will be refused. The selection must contain 1-100 user
settings with Set/Restore actions and fit the bounded launch command. Machine
operations, packages, artifacts, mixed profiles and package authentication options
are refused before launch. Explicit local libraries must be readable by the target
user and pass their existing catalog and recovery checks.

Saved capture and restore use the child's normal user state store. Keep the run ID
from the child window. To recover that user-only run:

```powershell
.\ride.ps1 restore -RunId <child-run-id> -UserContext Desktop
```

RIDE validates the user's manifest and every saved operation before invoking
restore. Mixed manifests, mismatched records and package records are refused.
It does not migrate the administrator's state store to the user. Run ID completion
is suppressed for `Desktop` in the administrator's console; use the saved output
or completion inside the actual user's console. Other catalog and state completion
continues to read the ordinary declared metadata.

## Acceptance and follow-up

The [first-batch evidence](archive/evidence/intended-user-handoff-batch1-2026-10-14.md)
records mocked identity, launch, source-drift, confirmation and recovery checks.
Native Explorer COM launch and an alternate administrator's actual desktop-user
process still need isolated acceptance. Obtain current controller readiness before
any VM submission; historical idle records are insufficient.

The next isolated VM acceptance needs a real signed-in unelevated desktop user
and a console in that same session. Cover same-user elevation and a different
administrator, preview, actual child SID/session, changed source/session refusal,
repeat apply, saved recovery, and partial-failure reporting. Capture the original
setting and the two accounts' user state roots; prove that only the target user's
state changes. Missing GUI/session evidence is pending, even if unattended
session-zero refusal passes. Run on pinned disposable targets with current source
hashes and checkpoint recovery; never on the developer workstation.

Before adding automatic handoff to mixed profiles, decide how the parent waits
for verified child completion, correlates both state stores, preserves operation
ordering, reports partial completion and resumes recovery after interruption.
The launch-only receipt deliberately provides no such guarantee in this batch.
Packages remain paused and are excluded from that settings work.

The launch design follows Microsoft's explanation of
[using Explorer to launch as its user](https://devblogs.microsoft.com/oldnewthing/20131118-00/?p=2643),
[desktop shell discovery](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getshellwindow)
and [FindWindowSW](https://learn.microsoft.com/en-us/windows/win32/api/exdisp/nf-exdisp-ishellwindows-findwindowsw).
These references explain the platform mechanism; local acceptance must still
establish the implemented process and recovery behavior.
