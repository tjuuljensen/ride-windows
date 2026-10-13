# Windows recovery readiness

Prepare a Windows 11 recovery route and enter native recovery interfaces
deliberately. Windows RE enable/disable lifecycle remains pending; this guide
does not execute recovery actions.

## Establish an independent route

Before any future advanced Windows RE Disable operation, record the intended
device and running Windows installation and establish a usable recovery route
that does not depend on that installation's registered Windows RE image. A file
or USB device merely existing is not verification. Record the route as pending
until its boot/access evidence is available for that device and configuration.

Use an appropriate recovery drive, installation media or organization-provided
recovery environment. Review the manufacturer's boot instructions and applicable
Secure Boot/media servicing guidance. Do not assume media from a different PC or
an older configuration will boot or contain the required recovery tools/drivers.
Keep OEM instructions and custom recovery arrangements available independently.
Microsoft's [Recovery Drive guidance](https://support.microsoft.com/en-us/windows/experience/backup-recovery/recovery-drive)
describes creation in the native utility: explicitly choose an empty USB device;
creation erases its contents. A recovery drive does not back up personal files.
Media creation remains a deliberate manual action outside this migration run.

Keep a separately accessible backup of important files and evidence that needed
files can be retrieved. RIDE saved setting records are neither a system image
nor a replacement for file backups. A recovery interface opening does not prove
that a backup is complete or restorable.

## Credentials, encryption and access

Identify the account or organizational support route needed by the selected
recovery tool. Avoid assuming a Windows Hello PIN, current sign-in session or
local elevation supplies every recovery credential. Retain credentials through
the user's approved secure mechanism; do not put passwords in the migration
ledger, saved setting state or reports.

For encrypted volumes, use the [BitLocker recovery handoff](bitlocker-recovery.md)
to establish accessible recovery information for the exact volume and key ID.
Access must remain possible when the Windows installation or ordinary session
is unavailable. A backup submission alone does not establish retrieval. Do not
suspend protection, remove protectors, trigger recovery or decrypt a volume as
part of readiness documentation.

Some recovery tools require networking or organization-specific authorization.
Check the selected tool's current requirements and available drivers/network
route; do not assume ordinary Windows connectivity or stored Wi-Fi credentials
work in the recovery environment. Windows RE itself requires no additional RIDE
account or subscription. Particular tools and backup services have independent
requirements.

## Inspect and enter recovery separately

An optional native read-only inspection in an elevated Windows terminal is:

```powershell
reagentc.exe /info
```

Microsoft's [REAgentC reference](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11)
documents this as inspection of the running installation when no offline target
is supplied. Review the returned status and association in the intended OS.
Localized output, errors, absent details or an unexpected installation remain
unknown; none should be interpreted automatically as Disabled. This is manual
inspection, with no parser or catalog handler.

For a deliberate Windows 11 entry action, save work and open **Settings > System
> Recovery > Advanced startup > Restart now**. Selecting Restart now restarts
the PC; schedule that action with the user and any organization managing the
device. Shift while selecting Restart is another native entry route. See
Microsoft's [Windows recovery environment guide](https://support.microsoft.com/en-us/windows/experience/backup-recovery/windows-recovery-environment).
This guide neither issues a reboot command nor schedules Windows RE boot.

Entering the environment, enabling its registered image, automatic boot-failure
recovery and Reset this PC are separate outcomes. Do not interrupt boot or force
power loss to demonstrate readiness. In an authorized disposable acceptance
scenario, verify that the expected recovery interface opens and that returning
to the intended Windows installation works without choosing repair/reset tools.
Encrypted access and credentials require their own evidence.

## Choose a recovery tool deliberately

Microsoft's [recovery options](https://support.microsoft.com/en-us/windows/experience/backup-recovery/recovery-options-in-windows)
explain the different repair, restore and reinstall routes. Identify the problem
and affected device before selecting one. Reset, reinstall and image recovery
can remove data, apps or configuration. Opening Advanced startup does not
authorize these actions or turn them into reversible RIDE setting changes.
System Restore depends on available restore points; changing System protection
configuration cannot recreate deleted history. No tool is launched by this guide.

## Evidence and remaining migration

Readiness records should contain device/OS identity, independent-route identity,
media verification date/configuration, backup retrieval status, nonsecret
BitLocker volume/key identity and a credentials/support-access status. Each stage
can be pending, verified or unavailable; leave unknowns explicit. No credential,
recovery password or secret backup content belongs in those records.

The legacy Windows RE outcome remains partial. Its future backend must capture
the current OS/boot identity, native recovery association, image/staged location
and stable partition identity before mutation. It must preserve OEM/custom
configuration, avoid cycling satisfied states, refuse identity/servicing drift
and report partial recovery. Opposite enable/disable commands alone do not prove
exact recovery; image downloads, deletion, partition repair and broad BCD repair
are outside that focused setting.

Windows 11 boot, encrypted access, independent media and nondestructive return
remain pending acceptance. Windows Server 2025 and Server Core need separate
applicability/tool evidence; this client guide does not declare their support.
See the [remaining settings ledger](migrations/remaining-settings-decisions.md)
for native lifecycle and acceptance work. No supported target or recommended
executable profile is added by this handoff.
