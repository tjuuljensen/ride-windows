# Local-account password policy

`windows.local-password-maximum-age` is a pending advanced machine/admin
operation for the **local SAM account authority** on a workstation or
standalone/member server. Domain controllers and unknown/inconsistent computer
roles are refused before native policy inspection. Domain accounts, per-account
never-expire flags, Windows Hello/PIN and Microsoft-account password settings
are separate. No recommended profile selects this operation.

## Explicit choices and inspection

`NoExpiry` means **Never expires**. `Days1` through `Days999` select an explicit
number of days, including `Days42` only when that is the user's choice. There
is no universal 42-day preset or expiration recommendation. Microsoft's
[Maximum password age reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-password-age)
documents the 0/1-999 day choices and minimum-age relationship. Choose a value
appropriate to the account authority and requirements; this operation does not
compose a complete account-security outcome or change passwords.

The catalog stores `StateRange = @{ Prefix = 'Days'; Minimum = 1; Maximum = 999 }`
and `States = @{ NoExpiry = 0 }`. The data-only reader expands the bounded range
for discovery, command execution, profile validation and read-only completion.
The CLI does not maintain a second suggestion list or query Windows for Tab.
This additive schema-1 field requires catalog reader 0.2.0 / engine 0.19.0 or
later; old operation IDs/states and saved snapshots retain their prior meaning.
Older engines do not support this new handler. Generated documentation summarizes
the range rather than printing 1,000 individual state names.

For example, after target acceptance:

```powershell
.\ride.ps1 show windows.local-password-maximum-age
.\ride.ps1 set windows.local-password-maximum-age Days90 -WhatIf
.\ride.ps1 restore -RunId <captured-run-id> -WhatIf
```

Currently normal apply remains blocked because supported targets are empty.
The operation has no baseline, unset or Not defined state: Never expires is
an explicit applied value, not removal of a local/managed policy definition.

The native reader uses local `NetUserModalsGet` levels 0 and 2 to report
currently applied SAM maximum/minimum-age seconds, minimum length, password
history length, forced-logoff seconds and the SAM domain SID. These are nonsecret
policy/authority fields. No user/password enumeration or secret capture occurs.
It does not inspect local GPO definitions, effective managed provenance or a
particular account's expiration flags; policy reapplication can change the field.
Inspection labels valid non-day/custom seconds explicitly instead of rounding.

## Focused writes and exact field recovery

[NetUserModalsSet](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netusermodalsset)
level **1002** changes only maximum password age. RIDE passes a null server
parameter for the local computer and exposes no remote-server/domain option.
One day is 86,400 seconds; Never expires uses `TIMEQ_FOREVER` (`0xffffffff`),
as documented by
[USER_MODALS_INFO_1002](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_modals_info_1002).
No full modal record or exported security template is replayed.

The engine saves exact raw prior seconds, SAM identity, related modal context
and the expected new seconds before mutation. Apply refuses authority/context
drift and explicit day choices less than or equal to the current minimum age,
matching the documented GUI choice. A minimum age outside the documented GUI
range requires separate review; it is never repaired implicitly. Native errors
and readback drift remain explicit failures with the saved run retained.

Restore uses snapshot version 1, the same local-authority/DC checks, and only
the captured maximum-age field. A different SAM SID, independently changed
maximum age or changed related modal context blocks stale recovery. Already
restored maximum age requires no new write. Valid prior custom seconds can be
recovered without converting them to a day preset. Native prior recovery permits
the API's greater-than-or-equal minimum-age relation; new GUI day choices use
the stricter documented greater-than relation. Unsupported prior native values
that cannot be represented safely by the API fail before mutation.

Recovery changes no passwords and cannot undo password changes or consequences
that occurred while the policy was applied. Minimum age/length, complexity,
history, logoff, lockout and per-account flags are unowned and untouched. They
are captured only as nonsecret context for conflict detection. No policy refresh,
account weakening, domain-controller fallback or password expiration action is
implicit. Password complexity remains a separate pending migration.

## Acceptance boundary

Windows 11 and Windows Server 2025 are candidates only; target defaults remain
undeclared until evidenced. Local mocked tests and native type compilation prove
control flow/structure, not native SAM or Local Security Policy GUI behavior.
Required acceptance includes native field-only effects, real local SID/role
mapping, standalone/member/DC refusal, minimum-age constraints, repeat apply,
custom/forever/partial recovery, managed reapplication and per-account exceptions.
Current installed edition and local security GUI availability need target evidence.
No extra RIDE/cloud subscription or domain join is required for local configuration.
Packages remain paused. VM tests remain held at the Github cache verification
and resource-backoff gate; this implementation uses no anonymous GitHub quota.
