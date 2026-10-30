# BitLocker recovery backup and retrieval

The v3 catalog now contains source-ready workflows for OS-volume enrollment,
explicit decryption, adding a recovery-password protector and revealing a selected
key. They remain unavailable for application while disposable Windows acceptance
is pending. Recovery creation and reveal use a local dialog and return only
nonsecret IDs/status; they do not use generic snapshots, pipeline output, logs or
transcripts. Encryption/decryption are staged system actions, not exact RIDE
restore operations. This guide covers the manual destination, backup and retrieval
steps that remain under user control.

The dedicated entry point is `tools/Invoke-RideBitLockerWorkflow.ps1`. It reads
the workflow ID, action, encryption choices and target gate from the catalog.
Each state-changing or secret-revealing handler also checks the catalog gate, so
calling the module function directly cannot bypass pending acceptance. The gate
stops before BitLocker volume inspection while an operation is pending; read-only
status remains available. Add, Backup and Show previews also stop before volume
inspection, since the native volume object may contain recovery passwords. The
workflow order is: add a recovery protector, store
and verify its key from another device, then enroll encryption. Choose TPM-only
startup or TPM plus a BitLocker
startup PIN, and choose full-volume or used-space-only scope after considering the
drive's prior use. The PIN is prompted as a SecureString only after preview
approval; it is never a command-line parameter. The hardware test remains enabled;
RIDE does not reboot, modify firmware, skip checks or change managed policy.

Use `.\ride.ps1 show windows.bitlocker-enrollment` for read-only current
volume state, all protector IDs/types and a whitelisted snapshot of FVE and
PolicyManager startup-authentication values. The PolicyManager snapshot includes
the startup-authentication choice, enhanced-PIN and minimum-PIN settings, the
preboot-PIN exception for InstantGo/HSTI-capable devices, and preboot input
policy for slates. Microsoft's [BitLocker CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/bitlocker-csp)
documents these device-policy names and supported editions. The snapshot is
explicitly raw: it does not determine which GPO/MDM source wins or prove an
effective boot route. Do not treat the absence of these values as Windows boot
acceptance.

The status view labels a `TpmCertificate` protector as a *potential* Network
Unlock route. Microsoft identifies Network Unlock as a TPM-plus-network-key
route requiring managed policy, certificate distribution, a Windows Deployment
Services server and suitable UEFI networking. The label alone does not prove
that the route is provisioned or used. Enrollment preserves and refuses this
protector until its policy and actual boot behavior have been reviewed; see
Microsoft's [Network Unlock requirements](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/network-unlock).

RIDE's `windows.bitlocker-wizard-shortcut` is a source-ready, pending Windows 11
operation. Once disposable-target acceptance passes, it will add a reversible
current-user desktop shortcut and be selected by the default workstation profile.
It opens the Windows wizard only; it does not enable encryption or handle keys.

## Identify the volume and existing recovery protector

Choose the protected volume explicitly. OS-volume startup recovery is different
from unlocking a data/removable drive. A recovery password is a 48-digit secret;
its protector/key **ID** identifies it and is not the password. Match by
`RecoveryPassword` type and exact ID, never by array position or merely the first
item returned.

If the BitLocker PowerShell module and required local rights are available, this
optional read-only example lists **only nonsecret IDs/types** for one chosen
volume. Replace `C:` with the intended volume; RIDE does not run it automatically:

```powershell
Get-BitLockerVolume -MountPoint 'C:' |
    ForEach-Object { $_.KeyProtector } |
    Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } |
    Select-Object KeyProtectorId, KeyProtectorType
```

Do not format or serialize the full volume/protector object: it can contain a
recovery password. Microsoft's
[operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
documents protector listing/backup and notes that protector listing is not
available in Control Panel. With zero recovery passwords, stop at the separate
creation decision. With several, select the exact ID; if the native backup GUI
does not establish which one it uses, keep that selected-key action pending.
Do not guess, rotate or delete a protector to simplify selection.

## Back up an existing recovery key

1. From Start, open **Manage BitLocker**. Confirm the intended volume and choose
   **Back up your recovery key** when the native interface makes it available.
   Device Encryption and the full BitLocker management UI have different edition/
   hardware surfaces; a missing interface is not permission to install, enable
   encryption or silently select a different backend.
2. Choose an explicit destination accessible **from another device** if this
   volume becomes locked. Use the appropriate native file/account/organization
   route below, retaining the existing selected protector. This guide does not
   create a new recovery password as part of backup.
3. Complete the native backup and verify that the saved ID matches the intended
   recovery password. If the interface cannot prove the selected-ID mapping,
   record the step as pending rather than claim success.
4. Check retrieval from another device through the chosen destination. A local
   success message, encrypted percentage or cloud metadata row is not proof of
   usable recovery access.

| Destination | Required access and boundary |
| --- | --- |
| File or USB | An explicitly chosen protected storage location that remains accessible independently of the locked volume/device. The exported file can contain the plaintext recovery password; keep it outside this repository, RIDE state, transcripts and routine reports |
| Personal Microsoft account | The account that owns the saved recovery key; it may be the account of the person who originally set up the device. Local administrator rights do not grant access to that account |
| Microsoft Entra/work or school account | Correct organization/device association and permitted self-service or an authorized helpdesk/admin role. Follow tenant access/audit requirements; an arbitrary work account or local administrator is insufficient |
| AD DS | Applicable domain environment, recovery-object storage and directory permissions, with authorized helpdesk retrieval. Use a separately verified selected-ID backup workflow; this guide does not run AD DS commands or assume domain membership alone proves escrow |
| Print | An explicit user choice through the native interface, stored securely away from the device. RIDE does not print automatically |

Microsoft's [backup instructions](https://support.microsoft.com/en-us/windows/security/encryption/back-up-your-bitlocker-recovery-key)
describe native destination choices. The RIDE handoff requires independent access
rather than treating another location on the same unavailable machine as enough.
Do not store the only backup on the protected volume or keep an unprotected USB/
printout with the computer. Offline backup needs no RIDE/cloud subscription;
account/directory routes retain their own access and licensing requirements.

The source operation `windows.bitlocker-backup-recovery-password` opens the native
BitLocker Drive Encryption Control Panel after `ShouldProcess` approves. It
requires an exact existing protector ID and a catalog destination choice:
`FileOrUsb`, `PersonalMicrosoftAccount`, or `Print`. For example, after target
acceptance, the script syntax is:

```powershell
.\tools\Invoke-RideBitLockerWorkflow.ps1 -OperationId windows.bitlocker-backup-recovery-password -MountPoint C: -KeyProtectorId '{id}' -BackupDestination FileOrUsb
```

The selected category is an instruction for the native UI, not evidence that the
same route was used. Entra ID and AD DS escrow are separate organization-managed
backend workflows and are not options in this Control Panel handoff. It returns
`BackupVerified = false`;
the user must match that ID in the chosen destination and verify retrieval from
another device. The operation is still pending disposable Windows acceptance and
cannot currently run through RIDE.

## Show the selected recovery key

Use the explicit key ID to select the corresponding entry in the native account,
organization, file or paper interface. On a recovery screen, the first eight
characters of its key ID help identify the matching saved entry. Microsoft's
[retrieval instructions](https://support.microsoft.com/en-us/windows/security/encryption/find-your-bitlocker-recovery-key)
link the personal and work/school account routes and explain ID matching. Use
that native interface for secret presentation; do not paste the password into
this chat or a RIDE diagnostic record.
The explicit Show workflow offers only local reveal and close; it does not claim
that a backup was made. Use the separate native backup handoff for an existing
protector and independently verify retrieval from another device.

For organization recovery, follow the
[BitLocker recovery process](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-use-bitlocker-recovery-password-viewer).
Self-service availability, delegated directory permission and audit are distinct
from local Windows elevation. No Graph permission request, unattended tenant
retrieval, automatic clipboard copy or custom secret viewer is introduced.

## Additional creation and complete acceptance

**Create an additional recovery key** is implemented in source as
`windows.bitlocker-add-recovery-password`, but remains pending disposable Windows
acceptance. Native protector-add commands can return recovery passwords in their
output. The handler captures the object privately, shows the key only in a local
masked dialog, and returns a nonsecret protector ID with `BackupVerified = false`.
Create never claims that a destination was used or that recovery access was
verified. After closing the dialog, use the separate
`windows.bitlocker-backup-recovery-password` workflow with that exact protector
ID and an explicit destination; verify retrieval from another device before
relying on the key or enabling encryption. If presentation fails, the protector
is retained and the partial result must be inspected before any retry. No
implicit rotation, backup cleanup, suspend, decryption, reboot or forced recovery
test is included here.

The source workflows map `EnableBitlocker`, `DisableBitlocker`,
`AddBitlockerRecoveryPswd` and `DisplayBitlockerRecoveryPwd` to separate catalog
IDs. Enablement is gated on a supported Windows Pro/Enterprise/Education edition,
a ready TPM, Windows RE verified enabled, no configured local FVE policy values,
a fully decrypted OS volume and an exact recovery-protector ID whose off-device
backup was verified. The source offers TPM-only and TPM+PIN, but managed/effective
startup policy and alternate boot-route analysis remain incomplete; catalog
activation therefore stays gated. Enrollment also fails closed inside the handler
until effective policy and boot-route compatibility can be established; a catalog
target declaration alone cannot release that guard. `Disable-BitLocker` removes every protector on
the selected OS volume and starts decryption; it is never a restore action. Secret
display is selected by exact protector ID and never by array position. Each
operation remains blocked until Windows acceptance verifies zero/one/multiple
protectors, secure PIN input, secret redaction, preview, repeat behavior, failed
backup, conversion states and recovery.

Routine progress should contain only the selected volume, protector/key ID,
destination category and stages such as identified, backup submitted/saved,
retrieval verified, or pending. Never include a recovery password, PIN, raw object
dump or secret export contents in status/state/logs. Manual backup/display is not
automatically reversible; existing protectors/backups remain unowned by RIDE.

The whole legacy recovery outcome remains partial. Secure custom creation/display,
zero/multiple/reordered protectors, exact-ID backup selection, failed destinations,
off-device retrieval and real recovery-screen unlock require disposable encrypted
target/lab-account acceptance. Server and backend-specific GUI/permission evidence
remain separate. No keys or accounts were accessed while implementing this guide.
VM execution retains the Github cache verification/resource-backoff gate; packages
remain paused and no anonymous GitHub quota is used.
