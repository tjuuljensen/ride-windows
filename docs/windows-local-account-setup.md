# Windows setup with a local account

Windows setup behavior depends on edition, installation media, and build. This
guide records ways to finish setup with a device-local account and tracks which
methods have been observed to work. Recheck the steps against each new ISO;
OOBE commands and screens can change between releases.

Microsoft currently documents an internet connection as required to finish
Windows Home and Pro setup. That is the supported setup requirement. The
workarounds below are version-dependent and are not a Microsoft-supported
promise that every Home or Pro image will allow an offline local account.
Connecting after setup lets Windows Update obtain current security updates and
drivers. A local Windows sign-in does not prevent separately signing into
Microsoft Store or other apps later.

## Choose a method

### 1. Use an offline-account choice if OOBE offers one

Some installation flows show an option such as **I don't have internet** or
**Continue with limited setup**. If it appears, keep the device offline, choose
that option, and create the local account in OOBE. The option is not present in
every edition or build, so do not assume it will be available.

### 2. Disconnect networking and open local account creation

This is the method reported successful on a Windows 11 Pro VM. In Hyper-V,
disconnect the VM's virtual network adapter before or during OOBE. On physical
hardware, unplug Ethernet and turn off Wi-Fi using the setup UI or the device's
hardware control. Then, at the Microsoft account sign-in page:

1. Press **Shift+F10** to open Command Prompt. Some laptops require
   **Fn+Shift+F10**.
2. Enter:

   ```text
   start ms-cxh:localonly
   ```

3. If a local-user dialog opens, create the account and finish OOBE while the
   device remains disconnected.
4. Reconnect networking after reaching the desktop, then run Windows Update
   and install any missing drivers.

`ms-cxh:localonly` is an internal OOBE entry point, not a stable documented
Windows command. If it is not recognized or does not open a local-user dialog,
record the edition and build and use another method rather than assuming the
same command works on that image. Tom's Hardware documents this path as a
version-dependent workaround; the RIDE VM result below is the repository's
field evidence.

For a Hyper-V test VM, disconnect only the guest adapter. Restore it after
setup; integration tests need network access for package downloads and updates.

### 3. Use Rufus-created installation media

Rufus offers a Windows User Experience option to remove the online Microsoft
account requirement when creating Windows installation media. This changes
the installation media and still requires networking to be unavailable at
the account-creation stage. Creating the media erases the selected USB drive:
verify the target carefully, use only official Windows ISO files, and review
each selected Rufus option. Do not select unrelated hardware-requirement
bypasses for this purpose. Rufus documents that its account option depends on
installer behavior Microsoft may change.

### 4. Treat `OOBE\BYPASSNRO` as a legacy fallback

Older Windows 11 builds included `OOBE\BYPASSNRO` to restart OOBE with a
network-bypass choice. Microsoft announced removal of `bypassnro.cmd` from an
Insider build in March 2025. It may still exist in some older or customized
media, but it is not a reliable current instruction. If testing it, use the
sign-in page's **Shift+F10** prompt, record the exact build, and do not treat a
successful result on one ISO as proof for another.

### 5. Add a local account after setup

If setup has already completed with another account, Windows supports adding a
local user through **Settings > Accounts > Other users > Add account > I don't
have this person's sign-in information > Add a user without a Microsoft
account**. Choose its standard-user or administrator role deliberately. This
does not replace the account used to finish OOBE.

## Edition notes

- **Home and Pro:** Microsoft's current support article says internet is
  required to finish setup. The offline methods above are workarounds, and
  Pro's behavior must be checked on the exact ISO/build in use.
- **Enterprise and Education:** Their setup flows can differ from consumer
  Home/Pro OOBE. The Enterprise Evaluation VM used for the RIDE pilot completed
  setup without requiring a Microsoft account. Treat that as tested evidence
  for that image, not a guarantee for all Enterprise media or deployments.
- **Managed, domain-joined, or organization-provisioned devices:** Follow the
  organization's deployment process; this guide is for interactive personal
  installs and disposable test VMs.

Microsoft accounts and local accounts have different service and sync behavior.
Microsoft recommends a Microsoft account for its service integration; choose
the account type that fits the device's use. For a test VM, use a dedicated
local test account, keep the VM isolated from production identities, and use a
nonblank password.

## Behavior tracking

Record results against the exact ISO and build. A method's status applies only
to that row. Recheck when the installation media changes, when a major Windows
release is adopted, or when OOBE no longer matches these steps.

| Date observed | Edition and image/build | Method | Result | Evidence |
| --- | --- | --- | --- | --- |
| October 2026 (exact day not recorded) | Windows 11 Pro; exact build and ISO not recorded | Network adapter disabled; `start ms-cxh:localonly` | Successful, user-reported | User confirmed this was the Pro VM; record the exact image/build on the next reproduction |
| October 2026 (exact day not recorded) | Windows 11 Enterprise Evaluation, OS `10.0.26300.9457`; ISO `26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso` | Standard interactive setup; no local-account workaround required | Setup completed without requiring a Microsoft account, user-reported | Existing RIDE-Win11-Test VM setup; this is a separate observation from the Pro workaround |

For each new observation, include the exact edition, OS build, ISO filename or
source, whether networking was connected, the steps used, whether OOBE reached
the desktop, and any failure text. Mark results as **user-reported**,
**reproduced**, or **not tested** so anecdotes do not become blanket claims.

## References

- [Microsoft: Get connected when setting up your Windows device](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/get-connected-when-setting-up-your-windows-device)
- [Microsoft: Windows 11 Insider Preview Build 26200.5516](https://blogs.windows.com/windows-insider/2025/03/28/announcing-windows-11-insider-preview-build-26200-5516-dev-channel/)
- [Microsoft: Manage user accounts in Windows](https://support.microsoft.com/en-gb/windows/security/identity-signin/manage-user-accounts-in-windows)
- [Tom's Hardware: How to install Windows 11 without a Microsoft account](https://www.tomshardware.com/how-to/install-windows-11-without-microsoft-account) (secondary reference for build-dependent OOBE workarounds)
- [Rufus FAQ: online Microsoft account option](https://github.com/pbatard/rufus/wiki/FAQ#help-i-dont-see-the-option-to-bypass-the-need-for-a-microsoft-account-with-windows-11)
