# Image input preparation and pending personalization acceptance

RIDE can validate the selected local static PNG inputs. Image installation,
default wallpaper and lock-screen apply/restore commands are not implemented
yet. A successful source check is not a Windows personalization acceptance pass.

## Validate an input

Start in the repository root using native Windows PowerShell 5.1 or PowerShell 7
on Windows. No elevation is needed. Select a local `.png` and obtain its expected
SHA-256 from the reviewed input manifest, independently of this validation call:

```powershell
Import-Module ./modules/RIDE.ImageFiles.psm1
Get-RidePngSource -Path 'C:\Inputs\wallpaper.png' -ExpectedSha256 $selectedHash
```

The command reads a stable snapshot and checks its hash before decoding. It
accepts static PNGs up to 16 MiB, 8192 pixels on either axis and 32 million total
pixels. It checks the signature, critical chunk envelope, CRCs, dimensions,
compressed-data header, bounded scanlines and inflated-data checksum, then asks
Windows GDI+ to decode the snapshot. Animated PNGs, alternate streams, network
paths and reparse paths refuse. This is a bounded source gate, not a complete PNG
conformance test or a claim that Windows will use the image for a given policy.

The result contains the hash, byte count and dimensions. `-IncludeContent` also
returns the exact validated `Content` byte array for a future lifecycle writer.
That writer must use the returned bytes instead of reopening an input that may
have changed. Validation does not edit the source, create an installed asset or
change personalization. There is no system change to restore.

## Three separate acceptance workflows

| Requested workflow | Implementation and acceptance required |
| --- | --- |
| Machine/default wallpaper | Establish supported default-user behavior and an owned asset location; preserve default-profile state and verify a newly created disposable user's visible desktop. A forced wallpaper policy or current-user preference does not establish this outcome. |
| User lock-screen image | Run in the intended interactive user's context. Capture the original image and selection mode; static-image byte recovery alone does not recover Spotlight or slideshow behavior. Verify the actual lock screen and repeat/restore. |
| Machine default lock-screen image | Use the documented `LockScreenImage` policy on a suitable edition, an owned public-readable asset and private machine recovery state. Preserve prior policy type/value/absence and unrelated values. Verify the signed-out/default image and recovery. Do not add a policy preventing user changes implicitly. |

Microsoft's detailed [default lock-screen policy documentation](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_forcedefaultlockscreen)
limits that policy to Enterprise, Education and Server editions. A Windows 11 Pro
registry round trip must not be reported as a successful default-image test.
Windows Server support also requires its own native acceptance evidence.

The legacy `SetDefaultLockScreen` removes old overrides; it is a reset action,
not an existing second-image setter. Keep that mapping separate from the newly
requested default-image workflow. The legacy wallpaper ownership changes and
inbox-file overwrites, and the Pro lock-screen CSP registry workaround, are not
approved replacements for documented behavior and captured recovery.

Each future disposable-guest scenario must preview without changes, apply,
verify the visible effect, repeat without new mutations, restore the captured
state and verify recovery. Refuse conflicting policy/file changes and retain
incomplete-run evidence. Do not delete or overwrite Windows inbox images,
shared source images or unrelated user assets. Image refresh/caching and
sign-out requirements need native evidence; registry equality alone is not
visual verification.

## Current evidence

The three [selected inputs](archive/evidence/custom-ride-image-inputs-2026-11-02.json)
remain hash-pinned copies of the user-supplied images. The
[source-validation evidence](archive/evidence/image-source-validation-2026-11-02.json)
records both PowerShell versions, malformed-input checks and real input decoding.
All three selected images are 3840 by 2160. No image was applied to Windows.
The [remaining-test assessment](migrations/migration-completion-reassessment-2026-11-02.md)
owns the broader component status and test strategy.
