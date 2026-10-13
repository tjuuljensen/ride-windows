# System protection

Review traditional Windows 11 System protection in its native interface, with
explicit affected-volume scope. A maintained RIDE On/Off backend remains pending
inspection, coupling and recovery evidence. No Server port or recommended
executable profile is declared by this handoff.

## Select a volume and preserve its allocation

Search Start for **Create a restore point** and open the **System Protection**
tab. Identify the intended volume and its current protection state before
selecting **Configure**. This is a machine setting; use an authorized
administrator and recognize that changes affect other users of that machine.
Unavailable or managed controls remain pending, not an invitation to bypass
policy. No additional RIDE account or subscription is required.

Microsoft's [System Protection guide](https://support.microsoft.com/en-us/windows/experience/backup-recovery/system-protection)
documents native configuration and separate manual restore-point creation.
Record the selected volume, protection choice and current storage allowance.
For a deliberate On choice, select **Turn on system protection**, preserving
the existing allowance unless resizing was separately requested, then Apply.
Review the resulting state and wait for the native operation to finish; opening
the dialog or clicking Apply alone is not verification of success.

Do not infer a drive from the letter C: alone or change every listed volume.
Drive letters can differ between installations/recovery environments. A future
backend needs stable volume identity and must expose any system-drive coupling.
Microsoft's [Disable-ComputerRestore reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/disable-computerrestore?view=powershell-5.1)
requires System Restore to be disabled on the system drive before or concurrently
with disabling it on another drive.
Do not substitute a presumed independent per-volume command for GUI selection.
No ComputerRestore command is executed by this guide.

## Treat Off and history deletion as advanced actions

The accepted Off choice is advanced and potentially destructive. Before changing
it, review the selected volume, any affected coupled volumes and the native
warning about retained restore history. Stop if the scope or history effect
cannot be established. A disable operation can lose the recovery history the
user may need; turning protection back On cannot recreate deleted restore points.
Do not select the separate **Delete** history action as part of enablement or
configuration recovery.

Increasing/decreasing the allowance, manual point creation and applying a point
are distinct actions. Shrinking an allowance may discard history; preserve it
for a focused On/Off operation. A configuration snapshot can record prior state
and allocation, but it cannot promise exact restoration of deleted history.
No wildcard drive selection, storage-area cleanup or shadow-copy deletion is
included in this handoff.

## Keep recovery tools distinct

Traditional [System Restore](https://support.microsoft.com/en-us/windows/experience/backup-recovery/system-restore)
rolls back system configuration and installed programs without restoring personal
files. It is not a file backup. Maintain an independently accessible backup and
recovery route; see [recovery readiness](recovery-readiness.md).

Where available, the separately documented
[point-in-time restore feature](https://support.microsoft.com/en-us/windows/experience/backup-recovery/point-time-restore-for-windows)
can also roll back personal-file changes on the Windows drive. Its Settings
control, availability and recovery semantics differ. Do not map the legacy
System protection selectors onto that newer feature or promise that its restore
leaves personal files untouched. This handoff configures neither feature
automatically and launches no restore.

## Remaining acceptance

Windows 11 enabled-volume inspection, GUI correspondence, system-drive coupling,
asynchronous completion, actual defaults, point retention/deletion and bounded
configuration recovery remain pending. Use disposable fixtures with expendable
restore history; establish the whole affected scope before the advanced Off
scenario. Repeated On must not recreate/delete history or alter allocation.
Missing components or unverified history effects remain explicit failures or
pending evidence. Server applicability is outside this accepted client scope.

The [remaining settings ledger](migrations/remaining-settings-decisions.md)
retains the partial legacy outcome. Native guidance does not establish handler
acceptance or turn compensating configuration recovery into exact history restore.
