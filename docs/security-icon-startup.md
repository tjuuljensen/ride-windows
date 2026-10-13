# Show the Windows Security notification icon

This is the accepted guided outcome for the legacy icon-startup remainder. It
keeps machine hiding policy, intended-user startup readiness, taskbar overflow
and visible appearance as separate checks. Icon visibility does not establish
antivirus effectiveness, and a missing icon does not establish disabled protection.

## Inspect and choose policy

```powershell
.\ride.ps1 show windows.security-notification-icon
.\ride.ps1 set windows.security-notification-icon -State Shown -WhatIf
```

The existing machine/admin policy keeps its stable ID and state meanings:
`Hidden=1`, `Shown=0`, `WindowsDefault`/unset removes the local override. Shown
permits display subject to startup/component readiness; it does not install or
repair a launcher. Managed policy can still hide the icon. RIDE reports configured
state, not an inspected organization-policy source or observed appearance.
Actual policy apply requires administrator rights and retains a saved policy
record. Use `restore -RunId <id>` for exact prior policy value/type/absence.

Microsoft's [tray-policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsdefendersecuritycenter#hidewindowssecuritynotificationareacontrol)
requires sign-out/sign-in or reboot for its effect. Choose that refresh yourself
at a suitable time after saving work. RIDE does not trigger it or mark the icon's
appearance verified merely because a registry value was applied.

## Check startup in the intended user's session

1. Check the notification-area overflow for the icon before changing startup.
2. In the intended user's session, review Settings > Apps > Startup or Task
   Manager > Startup apps. If the registered Windows Security notification entry
   is present, inspect its identity and current enabled/disabled state.
3. If it is the expected existing native entry and its control is available,
   choose the native startup state explicitly. A managed/unavailable toggle or a
   different administrator's session is not evidence of the intended-user state.
4. If the entry or component is absent/broken, record that gap for a separately
   reviewed Windows repair workflow. Historical Run commands, arbitrary shortcuts
   and old build-number branches are not a verified replacement.
5. After your chosen sign-in/reboot, observe actual icon appearance. Record
   startup choice, policy state, user identity, build and any remaining restriction.

Microsoft's [startup-app guide](https://support.microsoft.com/en-us/windows/experience/startup-boot/configure-startup-applications-in-windows)
documents these native controls generally; it does not verify a particular current
SecurityHealth command or approval-store mapping. This guide supplies no direct
startup backend. Exact per-user/all-users effect and current entry identity still
need target evidence. Machine policy rights are separate from GUI permissions.

## Reporting and recovery boundaries

Only RIDE policy changes have captured apply/restore records. Startup GUI choices,
overflow checks and refresh are **manual user steps**; completing this guide is
not a saved or automatically reversible RIDE startup action. Capture your original
GUI choice yourself if you want to return to it. Report absent components, managed
restrictions and appearance awaiting refresh as pending rather than success.

Defender/third-party protection, alerts, tamper protection and services remain
independent. This workflow includes no process launch/kill, service change, binary
permission edit, app reset or automatic startup repair. No extra RIDE account,
cloud subscription or membership is required for local icon configuration.

## Acceptance hold

The guide and catalog presentation are implemented; GUI/startup/appearance,
multi-user scope, custom/missing registrations, managed precedence and independent
Server evidence remain pending. Existing policy support declarations are retained;
this guide adds none and closes no legacy outcome.

**Disposable VM tests remain held until manual user confirmation after the GitHub
cache/backoff investigation.** No startup/policy or live protection change is
made while preparing the guide. Acceptance must check real appearance after
user-controlled refresh alongside unchanged protection/alerts and exact policy recovery.
