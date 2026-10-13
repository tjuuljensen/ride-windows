# BitLocker recovery backup and retrieval

This implements the accepted guided recovery area through Windows and the
account/organization's native recovery interface. It does not add an executable
RIDE recovery-key handler, retrieve a key, create a protector or change encryption.
Manual steps are not captured RIDE apply/restore actions.

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

## Show the selected recovery key

Use the explicit key ID to select the corresponding entry in the native account,
organization, file or paper interface. On a recovery screen, the first eight
characters of its key ID help identify the matching saved entry. Microsoft's
[retrieval instructions](https://support.microsoft.com/en-us/windows/security/encryption/find-your-bitlocker-recovery-key)
link the personal and work/school account routes and explain ID matching. Use
that native interface for secret presentation; do not paste the password into
this chat or a RIDE diagnostic record.

For organization recovery, follow the
[BitLocker recovery process](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-use-bitlocker-recovery-password-viewer).
Self-service availability, delegated directory permission and audit are distinct
from local Windows elevation. No Graph permission request, unattended tenant
retrieval, automatic clipboard copy or custom secret viewer is introduced.

## Additional creation and complete acceptance

**Create an additional recovery key** remains a separate advanced pending
implementation. Native protector-add commands can return recovery passwords in
their output, so this guide does not wrap them or claim secure creation through
routine logs. A future backend must record nonsecret protector ownership and
stages, preserve all existing unlock methods and prove redaction/partial recovery
before availability. No create/delete, implicit rotation, backup cleanup, suspend,
decryption, reboot or forced recovery test is included here.

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
