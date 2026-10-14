# Windows Terminal default profile

Reviewed: **2026-10-14**. This is an intended-user native UI workflow for an
already installed Terminal instance. RIDE's automatic profile-file editor and
native GUI acceptance remain pending. Packages remain paused.

The default profile chooses the shell for a new tab when no profile is specified.
It is represented by the root `defaultProfile` property, which can identify a
profile by GUID or name. The default terminal application chooses the Windows
console host and is a separate OS setting. See Microsoft's
[startup settings](https://learn.microsoft.com/en-us/windows/terminal/customize-settings/startup#default-profile).

## Choose and verify

1. Open the existing Terminal instance as the intended signed-in desktop user.
   If several instances are installed, choose the one whose settings you intend
   to change. Record the instance and user for later recovery.
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

The later automatic editor must discover the applicable settings file and existing
profile identities, preserve comments/unknown fields and unrelated edits, and
capture the original `defaultProfile` value or absence. It must refuse disappeared
profiles and restore conflicts. File round trips and new-tab GUI behavior need
separate disposable acceptance before a catalog operation or supported target
can be published. No default profile, terminal-host choice or installation is
selected by this document.

The optional [core utility app group](store-app-groups.md#accepted-groups) owns
Terminal registration actions separately. Its removal/reinstall acceptance does
not establish default-profile editing or recover the user's Terminal settings.
