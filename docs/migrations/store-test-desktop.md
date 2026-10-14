# Separate disposable Store test desktop

## Purpose and boundaries

The existing Windows 11 clean guest has UAC disabled. Its Limited interactive
task still received an administrative token, so the Store desktop guard refused
the earlier Plan fixture. On 2026-10-14 the user authorized a separate
UAC-enabled disposable desktop and any elevation needed to prepare it.

Preparation uses only a local export of the existing clean checkpoint. Hyper-V
[exports checkpoints](https://learn.microsoft.com/en-us/powershell/module/hyper-v/export-vmsnapshot?view=windowsserver2025-ps)
and [imports a copy with a new VM identity](https://learn.microsoft.com/en-us/powershell/module/hyper-v/import-vm?view=windowsserver2025-ps).
The copy owns independent disks and has no network adapter. PowerShell Direct
addresses its VM ID without guest networking. The original Windows 11 and Server
VMs, checkpoint pins, installed controllers and CI checkout remain unchanged.

Only the new guest's `EnableLUA` changes from 0 to 1, followed by a reboot.
Administrator consent and secure desktop settings remain 5 and 1 respectively,
consistent with [Microsoft's UAC configuration reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration).
The guest retains the cloned local account and existing sign-in configuration;
no credentials are published, and no new automatic sign-in is configured.
The cloned computer name and user SID are lineage, not a new reference inventory
for another Windows edition or installation image.

Packages and downloads remain paused. No app is removed, registered or selected
for default removal during preparation. Published `SupportedTargets` stay closed.

## Validation flow

1. Check both original controllers are idle, their pins and installed file hashes
   match the accepted baseline, and no other VM is running or queued.
2. Export the exact original clean checkpoint without restoring or booting the
   original. Import a new VM ID under a dedicated resource directory. Verify
   every imported disk and parent belongs to that directory before boot.
3. Boot the disconnected copy using PowerShell Direct and the existing local lab
   credential privately. Verify the guest identity, enable UAC only there, reboot,
   and observe the expected signed-in shell. Shut down gracefully and capture
   a new clean checkpoint scoped to this VM.
4. Restore the new pin and stage a hash-verified snapshot of the current checkout,
   including relevant uncommitted implementation. Add schema-7 Plan selection
   only to that isolated snapshot; do not replace a checkout fixture or open
   catalog target support.
5. Run the existing read-only Store desktop Plan fixture. Its Interactive/Limited
   worker must prove actual SID, same desktop session, source/fixture/script
   hashes and an unelevated shell and worker. Collect bounded actor evidence and
   verify transient task cleanup separately from a task-launch receipt.
6. Recover the separate clean checkpoint, leave the copy Off, and verify the two
   original controller baselines again. Retain correlated evidence even on failure.

A passing Plan proves this desktop prerequisite only. Full production launcher,
alternate-administrator handoff, app uninstall/reinstall, payload retention,
partial failure and application-data limitations remain separate acceptance.
The first intended lifecycle candidate is Solitaire; News and Weather continue
to wait for usable local reinstall sources. See the
[follow-up decisions](store-app-follow-up-decisions.md).

## Resource and evidence

Preparation and source-bound read-only Plan passed on 2026-10-14. VM
`RIDE-Store-W11` (`ac29b689-f62d-4e5b-a4bc-25987f1fe843`) has the separate clean
checkpoint `RIDE-store-uac-clean-20261014`
(`35b4f659-f168-4c22-bfc4-b6e7651a09e2`). It is Off, with no network adapter,
under `Z:\VMs\RIDE-StoreDesktop-20261014`. Both actor and Explorer were
unelevated in session 1 for the expected cloned user. Read-only Plan request
`080d9d9404274f349857f1e06166fe80` passed task cleanup and checkpoint recovery.
See the [dated completion evidence](../archive/evidence/store-test-desktop-2026-10-14.md)
for source manifests, hashes and exact acceptance boundaries.
There is no new registered controller or scheduled test loop at this stage.
Do not repoint either existing controller to this copy.
