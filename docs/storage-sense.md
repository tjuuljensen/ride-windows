# Storage Sense choices and recovery

The stable `windows.storage-sense` operation changes only the intended user's
legacy enablement value. It preserves other cleanup preferences. Its Microsoft
reference explains feature behavior; the current-build GUI mapping and effective
content behavior remain pending review. A stored value matching a requested
state is not proof that cleanup occurred or that every GUI option matches it.

## Review the intended user's cleanup choices

In that user's Windows 11 session, open **Settings > System > Storage > Storage
Sense**. Review current enablement and available choices before changing them.
Microsoft's [Storage Sense guidance](https://support.microsoft.com/en-us/windows/experience/storage-filemanagement/manage-drive-space-with-storage-sense)
describes per-user preferences and system-drive cleanup. Other users' choices
and other drives are separate scope; no all-user enforcement is implied.

Record the displayed schedule, temporary-file choice, Recycle Bin retention,
Downloads retention and each available cloud-content choice. Preserve values
that were not explicitly selected for change. Missing or managed options remain
pending/unavailable; do not bypass policy or write guessed registry channels.

Enabling permits later automatic cleanup under the configured conditions.
Review and back up needed content before enabling it. Downloads and Recycle Bin
retention can delete files; cloud-content dehydration makes selected content
online-only instead. Restoring local availability depends on the provider,
connectivity and free disk space. Cloud controls also depend on the signed-in
provider account. Check actual displayed options; do not apply one assumed
default to every build, provider or existing profile.

Changing enablement does not authorize **Run Storage Sense now**, Temporary
files removal, Windows.old removal, an account sign-in or a cloud-content change.
Keep each immediate cleanup or additional preference a separate deliberate
choice. No cleanup is invoked by the RIDE enablement handler.

## Stored state and feature state

The catalog's explicit enable/disable states change one declared value.
`WindowsDefault` removes that value; it does not recursively reset the preference
tree, recover factory choices or clear notification history. Exact saved-run
restore recovers the captured value/type/absence; it does not infer omitted
preferences from a different user or snapshot.

The legacy reverse's recursive preference deletion is excluded from maintained
disable behavior. The unverified `StoragePoliciesNotified` marker is untouched.
No extra cleanup-value mappings, default-profile selection is introduced by this guide. A separate advanced machine-policy candidate is documented below and remains unsupported pending Windows 11 acceptance. Read-only `show`/`status` inspection of
the catalog setting remains distinct from the native Settings screen.

Turning Off or restoring configuration cannot recover files already deleted by
Windows. A prior registry record is not a file backup. Making cloud content
online-only also changes offline availability; restoring the setting does not
automatically download that content.

## Separate advanced machine policy candidate

The catalog includes `windows.storage-sense-global-policy` as an advanced machine
policy candidate separate from the current-user `windows.storage-sense`
preference. Microsoft documents `AllowStorageSenseGlobal`: Enabled forces Storage
Sense on and prevents users from disabling it; Disabled forces it off and prevents
users from enabling it. Removing the local override returns control to Windows
and user behavior, including possible low-storage activation. The policy does not
set cadence or per-cleanup choices and RIDE does not run cleanup.

Microsoft lists Pro, Enterprise, Education and IoT Enterprise editions for this
policy. The RIDE candidate remains unsupported pending Windows 11 edition-specific
acceptance of UI enforcement, effective policy precedence, exact restore and the
cleanup boundary. Windows Home and Server are outside this candidate. See the
[Microsoft Storage Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-storage#allowstoragesenseglobal).

## Remaining acceptance

Current Windows 11 GUI/value correspondence, literal/effective defaults,
managed precedence and actual content effects remain pending. Acceptance must
use an isolated disposable fixture with explicitly expendable files, distinct
users and independently checked cloud/offline behavior when applicable. Capture
unrelated cleanup choices before and after repeated enable/disable/default and
saved-state recovery. Do not use the developer workstation or real user content
as the fixture. Server applicability requires separate evidence.

See the [remaining settings ledger](migrations/remaining-settings-decisions.md)
for the partial legacy outcome and the [operation catalog](OPERATIONS.md) for
current target/action declarations. This guide adds native user guidance without
claiming content recovery or closing feature acceptance.
