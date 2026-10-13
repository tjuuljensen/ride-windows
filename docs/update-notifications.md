# Windows Update notifications and restart interruptions

The pending `windows.update-notification-display-policy` candidate coordinates
three machine DWORDs under `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`.
Changes require administrator rights. The columns below identify the policy gate
`SetUpdateNotificationLevel`, enum `UpdateNotificationLevel` and checkbox
`NoUpdateNotificationsDuringActiveHours`.

| State | Gate | Level | During active hours |
| --- | ---: | ---: | ---: |
| DefaultNotifications | 1 | 0 | 0 |
| KeepRestartWarnings | 1 | 1 | 0 |
| KeepRestartWarningsDuringActiveHours | 1 | 1 | 1 |
| HideIncludingRestartWarnings | 1 | 2 | 0 |
| HideIncludingRestartWarningsDuringActiveHours | 1 | 2 | 1 |
| PolicyDisabled | 0 | Removed | Removed |
| WindowsDefault / unset / Baseline | Removed | Removed | Removed |

These are distinct local configurations. PolicyDisabled's subordinate removal is
an explicit RIDE payload, not a claim about every Group Policy editor's behavior.
Saved restore recovers original types/data/independent absence, including mixed
custom values, rather than substituting a table row.

## Mapping and limits

Read-only WindowsUpdate.admx inspection on local Professional build 26200.9550
confirmed Machine scope, gate Enabled=1/Disabled=0, enum 0/1/2 and checkbox identity.
ADML defaults the checkbox unchecked. ADMX SHA-256:
`006425D1A5066D337A9DBC338743366F41C4623EB3533D2ADC3402B378457AC2`.
No Group Policy change occurred; this is not GUI/runtime acceptance.

Microsoft's [display-level reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#updatenotificationlevel)
names the gate in its Group Policy mapping, not the complete three-value payload.
The [active-hours reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#noupdatenotificationsduringactivehours)
documents checkbox 0/1 and Windows 11 22H2 availability. `MinimumBuild=22621` is
enforced independently of supported-target acceptance. Edition and Server
applicability require their own evidence; no extra RIDE subscription/account is needed.

Notification suppression does not prevent updates or restarts. Active-hours
variants constrain suppression without changing the schedule; deadline exceptions
can still produce notices. See [restart guidance](https://learn.microsoft.com/en-us/windows/deployment/update/waas-restart).
Configured registry values do not establish effective organization policy or its
source; that inspection and actual notification behavior remain acceptance gaps.

## Recovery and legacy conflicts

The engine captures all three maintained values before writing; a later failure
retains the complete record/run ID. Restore recovers typed values in reverse
order and preserves unrelated settings. Recovery cannot undo an intervening
update/reboot. A separate read-only `LegacyDebugger` observation reports a possible
old MusNotification.exe Debugger override. It is never executed, written, removed,
included in saved recovery or restored. Cleanup needs separate authorization.

No scan, download/install, task run, policy refresh, reboot probe, AUOptions edit
or IFEO cleanup is implicit. Review native Active hours and explicit restart
scheduling, plus applicable deadline/grace policies. Keep the personal restart-
notification preference separate from this machine policy. These guided user
steps are not captured RIDE actions and cannot promise prevention of restarts.

## Reduce Windows Update interruptions

This is the accepted guided replacement for the legacy restart-interception
intent. Follow it in the intended user's Windows 11 session. These native GUI
steps remain user actions: RIDE does not perform or capture them, and a completed
notification-policy write is not completion of this guide.

1. Open **Settings > Windows Update** and inspect whether a restart is already
   pending. Save work before choosing a restart time. Do not infer readiness from
   a notification disappearing.
2. Open **Advanced options > Active hours**. Choose **Automatically** to let
   Windows adjust from activity, or **Manually** to set the hours you normally
   need the machine. Check the displayed interval before leaving the page.
   [Microsoft's active-hours instructions](https://support.microsoft.com/en-us/windows/deployment/updates-lifecycle/keep-your-pc-up-to-date-with-active-hours)
   document both choices; this guide introduces no registry mapping or fixed
   RIDE schedule.
3. When Windows offers **Schedule the restart**, choose an available time that
   fits the work and any displayed organization deadline. Confirm the scheduled
   time in Windows Update. This is an explicit user choice, not an automatic
   restart initiated by RIDE. See the
   [Windows Update FAQ](https://support.microsoft.com/en-us/windows/deployment/updates-lifecycle/windows-update-faq).
4. Review **Advanced options > Notify me when a restart is required to finish
   updating** if that choice is available. It is a personal notification
   preference, separate from RIDE's advanced machine notification-display policy.
   Keep restart warnings visible when you need time to prepare; hiding notices
   does not extend a restart deadline.
5. On a managed device, inspect the deadline shown in Windows Update and ask the
   administrator for applicable quality/feature-update deadline and grace-period
   settings when they are not visible. RIDE does not derive effective management
   from registry values alone. Do not remove policies or enrollment to make a
   preference editable.

For Windows 11 22H2 and later, Microsoft's
[deadline guidance](https://learn.microsoft.com/en-us/windows/deployment/update/wufb-compliancedeadlines)
explains that the effective deadline uses the later of the discovery-based
deadline and the pending-restart-based grace period. A required restart can occur
at that deadline despite active hours. Exact notification timing and available
choices depend on the build and management policy; this guide does not assign
one universal schedule or default.

If an old MusNotification.exe Debugger override is reported, leave it untouched
and record the conflict for a separate cleanup review. Do not combine this guide
with interception, task/service disablement or an AUOptions rewrite. Update
installation, pause policies, managed maintenance windows and Server/Core restart
administration are separate workflows. No runnable profile is added: the guide
is a manual Windows 11 handoff, not a claim that RIDE prevents reboots.

Before claiming the outcome complete on a target, record the actual user choices,
applicable management, pending/scheduled restart presentation and observed
notification/restart behavior in disposable acceptance. Manual GUI changes have
no RIDE saved-run restore; recover them through the same Windows interface.

## Acceptance hold

SupportedTargets is empty and the candidate target is Windows 11. Normal apply
is blocked; metadata discovery/completion and explicit read-only local inspection
are available. No recommended profile selects suppression. The legacy
interruption-management outcome remains partial with estimates unchanged.

**Disposable VM testing is conditionally authorized only after the Github cache
chat verifies its VM tests and backs off/yields idle resources.** This guide run
starts no VM test. The scheduled validation follow-up retains that gate. Once ready,
verify GUI payloads, Disabled/default/removal, typed mixed recovery, repeat apply,
managed precedence, active-hours/deadline exceptions and real notifications/reboots
in disposable Windows 11 targets. Server installation modes and maintenance
windows need independent applicability/acceptance.

Local verification passed 43 selected mocked checks per PowerShell edition,
including 17 notification cases, with parser/catalog/profile/reference checks
passing. This proves the candidate contract, not effective policy or feature acceptance.
