# Keyboard repeat delay

`windows.keyboard-repeat-delay` is an optional current-user registry preference.
It selects the stored delay before a held key begins repeating; repeat rate,
Filter Keys, keyboard layout and visual effects are separate settings. No
administrator rights are needed. Run in the intended user's context; RIDE's
broader alternate-administrator identity protections remain acceptance work.

| State | Stored String value | Presentation |
| --- | --- | --- |
| `Shortest` | `0` | Position 0, shortest |
| `LegacyAppearance` | `1` | Position 1, retained legacy alias |
| `Position2` | `2` | Position 2 |
| `Longest` | `3` | Position 3, longest |
| `WindowsDefault` | Value removed | Delegate stored preference to Windows |

Microsoft's [SystemParametersInfo reference](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow)
documents the native 0-3 range and hardware-dependent timing. It does not
document this registry mapping. Intermediate positions have no guaranteed
millisecond timing. Control Panel > Keyboard > Speed > Repeat delay mapping
and actual behavior still require target verification.

The existing `RegistryValue` handler and snapshot contract remain in use. This
increment adds positions 2/3 without silently switching the published ID to a
native setter. `show`, `plan` and `status` inspect **stored registry state**;
they do not query the effective interactive-session delay. Apply writes a String
preference or removes it, without native API calls, change notification, simulated
keys, process restart, sign-out or reboot. No immediate runtime effect is claimed.

```powershell
.\ride.ps1 show windows.keyboard-repeat-delay
.\ride.ps1 set windows.keyboard-repeat-delay -State Position2 -WhatIf
.\ride.ps1 set windows.keyboard-repeat-delay -State Longest -WhatIf
```

Press Tab after `-State` for catalog-derived choices. `unset` selects
`WindowsDefault`; it removes the override without inventing a Windows default.
`restore -RunId <id>` restores the saved literal value, type and absence, including
legacy DWORD, String and unexpected prior representations. Literal recovery does
not establish recovery of an interactive setting that was never captured.

## Acceptance and native-backend follow-up

Both added positions are implementation candidates within the existing Windows 11
target boundary. No recommended profile or Server support is added. Packed
visual-effect presets remain deferred and the legacy visual-effects outcome stays
partial.

The focused keyboard and service follow-up passed 51 selected mocked tests on
each of Windows PowerShell 5.1 and PowerShell 7.6.5. Parser/catalog/profile and
generated-reference validation also passed on both editions. These results
establish the stored-state contract, not GUI/native feature acceptance.

The accepted native-backend direction requires independently captured effective
delay and exact stored state, versioned compatibility with existing registry-only
run records, and a tested sequence that restores effective state without
normalizing away prior data/type or recreating an absent value. That switch is
deferred until persistence, user/session ownership and recovery evidence is proven.

**All disposable VM tests remain held until the user manually confirms that they
may start after the GitHub cache/backoff investigation.** This continuation
launches or schedules no VM tests. Cache freshness, quota reset or elapsed time
does not release the hold.

After confirmation, verify all four GUI positions, native effective readback,
later-sign-in persistence, actual held-key behavior and unchanged repeat rate,
Filter Keys and other UI effects in disposable Windows 11 VMs. Exercise old typed,
absent and unexpected snapshots, repeated apply and partial failures. Server
GUI/session applicability requires independent evidence before support is added.
