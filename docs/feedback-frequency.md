# Feedback frequency

Use the intended user's native Windows 11 **Feedback frequency** choice while
the paired preference backend awaits current-build mapping evidence. The
separate `windows.feedback-notifications-policy` is an advanced machine policy;
it is not an interchangeable dropdown preference or a complete telemetry control.

## Choose through Settings

In the intended user's session, open **Settings > Privacy & security > Diagnostics
& feedback**. Locate **Feedback frequency**, record the displayed prior choice,
then select only an option actually offered by that build. See Microsoft's
[diagnostics and feedback guidance](https://support.microsoft.com/en-us/windows/privacy/diagnostics-feedback-and-privacy-in-windows).
Do not sign in as a different administrator to set another user's preference.
This user preference requires no extra RIDE account or subscription.

Verify the selected label remains after reopening the page. If the control is
missing, disabled or managed, record that condition and use the organization's
support route where applicable. Do not remove policy overrides, modify other
users' hives or substitute a numeric interval for an unavailable GUI choice.
Leave unrelated diagnostic-data, personalization, inking/typing and history
choices at their prior values.

This handoff is manual and has no saved-run snapshot. A recorded GUI label can
help a user return to the previous choice, but it cannot preserve unknown
underlying custom/mixed values. It does not establish exact native recovery or
prove how often prompts will subsequently appear.

## Keep preference, policy and tasks separate

The catalog machine policy has its own scope, administrator and supported
edition requirements, explicit states and captured registry recovery. Consult
the [operation catalog](OPERATIONS.md) and Microsoft's
[feedback-notification policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-experience#donotshowfeedbacknotifications).
Configured local policy can differ from effective managed policy. Allowing
notifications does not force a prompt or override a user's frequency choice.

Neither this preference nor the request policy disables diagnostic-data
collection. Scheduled feedback tasks, services, Feedback Hub installation and
manual feedback submission are distinct actions; none is changed or executed
by the native preference handoff. No package/tool download is required.

## Paired backend and acceptance

The historical `NumberOfSIUFInPeriod` and `PeriodInNanoSeconds` pair is not a
verified finite-state mapping. Its literal types, large interval encoding/units
and current GUI choices need evidence before adding executable payloads. No
guessed QWORD conversion, truncation, one-value shortcut, recursive Rules cleanup
or automatic all-user enforcement is introduced.

A future focused handler must capture both values with their literal type,
data and absence before mutation; preserve unrelated Rules values; distinguish
explicit Automatically from removing both overrides; and recover mixed/custom
prior states while reporting partial failures. A manually chosen UI label does
not prove that contract.

Current Windows 11 dropdown/pair correspondence, GUI refresh, managed
precedence, actual prompt behavior and typed lifecycle/recovery remain pending.
Server applicability requires separate evidence. See the
[remaining settings ledger](migrations/remaining-settings-decisions.md) for the
partial legacy outcome; this native guidance adds no catalog candidate, support
declaration or recommended executable profile.
