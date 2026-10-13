# Conditional server policies

## Server Manager startup

`windows.server-manager-startup-policy` is a pending machine/admin control for
the policy **Do not display Server Manager automatically at logon**. It keeps
the console's own startup preference separate:

| State | `DoNotOpenAtLogon` | Meaning |
| --- | --- | --- |
| `Suppressed` | DWORD 1 | Enable automatic-display suppression policy |
| `AutomaticStartup` | DWORD 0 | Explicitly disable that suppression policy |
| `WindowsDefault` | Remove value | Delegate to Windows, console preference and other applicable management |

The physical key is
`HKLM\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager`. The legacy
`ShowServerManagerOnLogin` removed this override; it did not write an explicit
startup policy. Saved restore preserves actual prior value/type/absence.
`WindowsDefault` does not clear the console preference. There is no console
launch/closure, scheduled-task change, forced policy refresh or component install.

Microsoft's [exact mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-servermanager#donotlaunchservermanager)
and [Server Manager guidance](https://learn.microsoft.com/en-us/windows-server/administration/server-manager/server-manager)
distinguish policy from the preference in Manage > Server Manager Properties.
The local build 26200.9550 `ServerManager.admx` confirms Machine class, policy
`DoNotLaunchServerManager`, value 1/0 and historical Server 2008 applicability.
Its SHA-256 is
`6EB8D580DA98AB0DA63122855556D8A2CD5A9853CE27B15CC2BE257CC6A50316`.
These mapping references and a client template do not prove current Server
desktop/Core or logon applicability.

Windows Server 2025 is a candidate only. Supported targets and target defaults
remain empty; normal apply is blocked, including preview. Effective managed
policy/source, console-preference precedence, administrator logon, manual
launch availability, exact restore and desktop/Core differences still require
target evidence. The operation is absent from recommended profiles. No extra
RIDE/cloud subscription or enrollment is required for local configuration;
Windows/component licensing is separate. Disposable VM tests remain held for
manual user confirmation.

## Shutdown Event Tracker

`windows.shutdown-event-tracker-policy` is one coordinated machine/admin policy
for Display Shutdown Event Tracker under Computer Configuration > Administrative
Templates > System. Its physical key is
`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability`.

| State | `ShutdownReasonOn` | `ShutdownReasonUI` |
| --- | --- | --- |
| `Disabled` | DWORD 0 | Preserve current value/type/absence |
| `Always` | DWORD 1 | DWORD 1 |
| `WorkstationOnly` | DWORD 1 | DWORD 2 |
| `ServerOnly` | DWORD 1 | DWORD 3 |
| `WindowsDefault` | Remove | Remove |

The [exact policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-reliability#shutdownreason)
describes the three display choices and their Server/client distinctions. Local
`Reliability.admx` confirms Machine class, enablement 1/0 and display values
1/2/3; SHA-256 on build 26200.9550 is
`420C9F48EFBE2551C0B8D0624B65692126B9228EE9CE308300EE75C49F7B3C06`.
Template presence is mapping evidence, not target feature acceptance.

The catalog's additive `@{ KeepCurrent = $true }` state component tells the
coordinated handler to leave the display choice untouched when disabling. It
requires a complete captured pair for inspection/matching and saved recovery,
but performs no write or desired-type comparison for that component. Invalid
markers or incomplete desired states fail before any component write. Existing
value-set states and saved snapshot formats remain compatible; ordinary null
still means remove, while WindowsDefault must contain only removal values.
The generator and plan/status text render this distinction as `<keep current>`.

The legacy disable wrote enablement 0; its reverse removed **only enablement**.
The new coherent WindowsDefault removes both declared policy overrides. That
broader removal is explicit; it is not claimed as identical legacy replay or as
the literal clean-image default. Exact saved-run recovery restores the captured
pair, including mismatched prior types, custom display data and absent values.
Enabled choices write the display selection before enablement. Multi-value writes
are not atomic; the engine saves both values before the first mutation and reports
partial failures. Restore follows reverse component order.

No command in this operation shuts down/restarts Windows, clears event logs,
changes timestamps, configures error-report upload or changes the separate
system-state-data policy. Effective source/management is not inspected. Server
2025 is a candidate only; desktop/Core behavior, prompt routes, managed
precedence, repeat apply, exact/partial recovery and client applicability remain
pending. No platform default or additional Windows target is asserted. Disposable
VM execution still requires manual user confirmation.
