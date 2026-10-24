# Windows Terminal default profile

This is an intended-user workflow for an already installed Terminal instance.
RIDE has a candidate [read-only packaged-instance inventory and guarded settings-file writer](terminal-jsonc-preparation.md).
The inventory lists current-user Stable, Preview and Canary package identities
with their separate settings paths; the user still chooses the instance/profile.
Unpackaged and portable installations require an explicit path. Native VM and GUI
acceptance remain pending; discovery does not prove profile launchability.

The default profile chooses the shell for a new tab when no profile is specified.
It is represented by the root `defaultProfile` property, which can identify a
profile by GUID or name. The default terminal application chooses the Windows
console host and is a separate OS setting. See Microsoft's
[startup settings](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/startup#default-profile).

## Choose and verify

1. Open the existing Terminal instance as the intended signed-in desktop user.
   To inventory packaged instances without changing them, run
   `Get-RideTerminalInstalledInstances` from the repository root after importing
   `modules/RIDE.TerminalJsonc.psm1`. Choose the exact package name for the
   intended instance; `Set-RideTerminalInstalledInstanceDefaultProfile` will
   requery current-user AppX registrations before using that package's settings
   path. For unpackaged/portable editions, supply the documented settings path
   to the explicit-path writer. Record the instance and user for later recovery.
2. Open Terminal Settings and select Startup. Record the current Default profile
   before making a change. Select a profile already available in that instance.
3. Save the selection. Leave the separate Default terminal application choice
   alone for this workflow.
4. Open a new tab with `Ctrl+Shift+T` or the plus button. Check that the expected
   shell opens; explicitly selected tabs and restored window layouts may use
   other profiles. Record the observed result rather than treating a saved
   dropdown as GUI acceptance.

Microsoft describes the Settings UI selection in its
[default-profile workflow](https://learn.microsoft.com/en-us/windows/terminal/install#set-your-default-terminal-profile)
and the new-tab behavior in the
[startup reference](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/startup#default-profile).
An unavailable instance or profile stays a prerequisite; this workflow acquires
no Terminal, shell or WSL component.

## Recovery and pending automation

For manual recovery, return to the same user's same Terminal instance and select
the recorded prior profile, then verify a new tab again. If that profile has
disappeared, retain the unresolved recovery instead of guessing another identity.
This guide creates no RIDE saved run or captured file recovery.

The candidate writer captures original/expected bytes before changing only the
root `defaultProfile`, checks current computer/SID, locks the selected file,
verifies readback and refuses owned-value restore conflicts. It leaves file ACLs
unchanged and does not prove that a declared/generated profile is available. File
round trips, real profile availability and new-tab GUI behavior need disposable
acceptance before a catalog operation or supported target can be published. No
default profile, terminal-host choice or installation is selected by this document.

For a packaged instance, first capture the intended current user and run a
preview with the exact package and already verified profile GUID:

```powershell
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
Set-RideTerminalInstalledInstanceDefaultProfile `
  -PackageName 'Microsoft.WindowsTerminal' `
  -ExpectedComputerName $env:COMPUTERNAME `
  -ExpectedUserSid $sid `
  -ProfileId '{00000000-0000-0000-0000-000000000000}' `
  -WhatIf
```

Replace the example GUID with one visible in the selected instance. Remove
`-WhatIf` only after the preview identifies the intended existing settings file;
the command prompts through `ShouldProcess` and returns a recovery snapshot path.
It refuses to create a missing settings file. Restore with
`Restore-RideTerminalDefaultProfileFile`, using that same path, computer, SID and
snapshot. This workflow needs no elevation and does not launch Terminal or a
profile.

The packaged-instance paths come from Microsoft's [Terminal FAQ](https://learn.microsoft.com/en-us/windows/terminal/faq);
portable distribution stores settings beside the application under its `settings`
directory, as described in Microsoft's [distribution guide](https://learn.microsoft.com/en-us/windows/terminal/distributions).

The optional [core utility app group](store-app-groups.md#accepted-groups) owns
Terminal registration actions separately. Its removal/reinstall acceptance does
not establish default-profile editing or recover the user's Terminal settings.
