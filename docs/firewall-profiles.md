# Modern Windows Firewall profile controls

| ID | Declared profiles | States |
| --- | --- | --- |
| `windows.firewall-domain-profiles` | Domain | On, advanced Off |
| `windows.firewall-private-profiles` | Private | On, advanced Off |
| `windows.firewall-public-profiles` | Public | On, advanced Off |
| `windows.firewall-all-profiles` | Domain, Private, Public | On only |

These implementation candidates apply to the whole device, with administrator
rights required for changes. Domain-profile configuration does not join a domain
or require a RIDE cloud account/subscription. Enable-all is one captured operation:
all three original local values are saved before the first write, in declared
Domain/Private/Public order. Native changes are not transactional; errors identify
the failed profile and completed profiles.

## Local configuration and effective protection

The handler reads explicit `PersistentStore` configuration separately from
`ActiveStore` resultant policy using Microsoft's
[Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile).
Concurrent active network categories come from
[Get-NetConnectionProfile](https://learn.microsoft.com/en-us/powershell/module/netconnection/get-netconnectionprofile).
Show, plan and profile status display local/effective Enabled flags, conflicts and
source when exposed. Missing source metadata stays unknown. `InDesiredState`
compares requested **local** configuration; it does not prove effective protection,
rule behavior, service readiness or allowed traffic.

Only declared local `Enabled` fields are written through
[Set-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile).
Rules, app exceptions, services, IPsec, logging, network categories and traffic
defaults are preserved. No GPO/MDM edits, policy reset, service repair or port
opening is performed. `NotConfigured` is GPO-only, so there is no generic local
default, unset or reset. An unrecoverable local representation refuses all writes.
Off stays explicit and advanced; no disable-all action or recommended profile is added.

The historical StandardProfile operation retains its original registry recovery
path. Inspection flags that legacy policy key's presence without assuming its
exact effective impact or automatically deleting/repairing overrides. See the
[accepted design](migrations/settings-post-migration-review.md#accepted-modern-firewall-replacement-decision-2026-10-11).

## Capture and recovery

Snapshot version 1 identifies `PersistentStore`, exact declared profile names,
original local flags and the requested local flags. It never uses resultant
managed values as restore targets. The engine saves the full record before
dispatch; the handler compares local state with that capture, rechecks before
each write and verifies local readback afterward.

Restore validates version, store, complete unique identities and typed restorable
enum strings before writing. Fields still at their original value need no write,
including profiles untouched by a partial failure. Changed fields recover their
own saved local value. Unexpected representation or visible drift stops recovery.
A Boolean flag cannot reveal every intervening write that returned to the same
value. Repeat restore is idempotent; managed policy can still disagree afterward.

## VM acceptance hold

All four records have `PendingAcceptance=$true`, **empty SupportedTargets** and
candidate Windows 11/Windows Server 2025 targets. Normal apply, including its
WhatIf path, is blocked by the existing target gate before inspection or mutation.
Metadata discovery/completion/planning are available. Explicit read-only show and
status can inspect candidates when the Windows cmdlets are present; completion
never invokes handlers.

**Do not start disposable VM tests until manual user confirmation after the GitHub
cache/backoff investigation.** No VM test is launched or scheduled by this work,
and no live workstation firewall change is made.

After confirmation, verify GUI/local/effective comparisons, unmanaged/managed
precedence, inactive/concurrent profiles, mixed-state recovery, partial failures
and benign allowed/blocked traffic in disposable targets with independent console
access. Check that rules and services remain unchanged. Server installation types
need independent applicability/acceptance before supported targets are declared.

Local verification passed 44 selected mocked checks per PowerShell edition,
including 20 firewall cases, with parser/catalog/profile/reference checks passing.
An unrelated Defender fixture was unavailable because its cmdlet is absent.
These results establish implementation contracts, not feature or target acceptance.
