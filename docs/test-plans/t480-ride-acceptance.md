# T480 RIDE acceptance plan

## Purpose and target

This plan qualifies selected RIDE behavior on the physical Lenovo T480. It is
limited to this device and its recorded Windows build; it does not establish
support for other Windows releases or hardware.

Target details reported by the user:

- Windows 11 Pro installed and fully updated.
- BitLocker is not currently in use.
- One Windows system restore point exists.
- 32 GB RAM and approximately 932 GB storage.
- CPU reported as "Intel Core i/-8650 1.9GHz"; confirm the exact model with the
  read-only preflight because this may be a transcription error.

The restore point is useful for some Windows recovery scenarios, but it does
not provide BitLocker recovery or guarantee rollback of firmware, boot, or
encryption changes. Keep BitLocker enrollment, protectors, suspension, and
boot-recovery mutations out of scope until their separate recovery gate passes.

## Execution boundaries

- Do not install ChatGPT or Codex on the T480 for this test. They are not
  prerequisites. No non-default software is required: use built-in Windows
  PowerShell 5.1 and a reviewed copy of the RIDE source. Do not install Git,
  Pester, PowerShell 7, or other tools on the T480 for this plan. Return the
  generated Markdown report and test observations in this chat.
- Use the T480 only for the physical-hardware observations and explicitly
  selected, low-risk RIDE acceptance below. Keep broad lifecycle tests in
  Windows CI/Pester and disposable VMs.
- Do not run the all-settings integration runner, a default profile, or package
  acquisition/installers on the T480 as part of this plan.
- The F1 Help operation is implemented as an experimental Windows 11 candidate
  with published support still pending. The T480 acceptance script temporarily
  enables it in memory for this process only; it does not change catalog
  support. The user-visible mapping remains unverified until the physical test
  report passes. Do not edit registry values manually.
- The automated T480 preflight is read-only. It records OS/build, model, CPU,
  memory, disk capacity, TPM, Secure Boot, firmware virtualization/SLAT,
  WSL/Virtual Machine Platform feature states, BitLocker status, and restore-point
  availability where the Windows APIs permit. It does not enable BitLocker,
  create a restore point, change firmware, press F1, or run RIDE handlers.

## Test cases and pass gates

| ID | Overall goal | Tests required | Pass gate |
| --- | --- | --- | --- |
| T480-00 | Confirm the physical target and virtualization capabilities before choosing cases. | Run `tests/integration/Invoke-RideT480Preflight.ps1`; review Windows edition/build, exact Lenovo model and CPU, memory, system-drive capacity, TPM, Secure Boot, firmware virtualization/SLAT, WSL/Virtual Machine Platform feature states, BitLocker, and restore-point observations. | Report identifies Windows 11 Pro and the T480. Unknown or unavailable fields remain unknown, never inferred. Report contains no serial number, recovery secret, or account name. |
| T480-01 | Establish a safe, reproducible starting point and identify the exact source under test. | Confirm the restore point is still listed; ensure personal data has a separate backup; record the source revision and manifest supplied with the reviewed source copy, plus the built-in PowerShell version. Run `tools/validate.ps1` and focused mocked Pester tests on the development machine before preparing the copy; do not install or run Pester on the T480. | The source identity and validation results accompany the copy. The T480 needs no Git, Pester, or other installed tool. Development-machine mocked tests do not prove live T480 behavior. No package install or Windows setting change occurs. |
| T480-02 | Verify RIDE discovery and inspection are read-only on this target. | In PowerShell 5.1, import the RIDE engine from the checkout; list settings; show each selected operation; inspect plan and status; inspect command completion. Capture the before state, then repeat status/plan and compare. | Selected IDs resolve, descriptions/states are understandable, and platform/scope are accurate. Inspection and completion do not change the captured state. Do not select a machine operation unless its target guard and elevation requirement are clear. |
| T480-03 | Establish actual F1 behavior before evaluating a RIDE change. | With no F1 override installed, record whether F1 in File Explorer and on the desktop opens Help on this exact Windows build. Also record F1 behavior in one unrelated application where the expected result is known. Record application/build and observed result; do not use a potentially destructive document or action. | Baseline is repeatable and documented. If Explorer/Desktop F1 does not invoke Help, mark the user-visible issue absent on this build; do not enable a workaround just to force a result. |
| T480-04 | Qualify the experimental F1 Help Blocked/WindowsDefault lifecycle without collateral effects. | Run `tests/integration/Invoke-RideF1HelpAcceptance.ps1` in the normal T480 user session. Record baseline; allow the script's preview and explicit confirmation; observe Explorer/Desktop and unrelated-app behavior under Blocked and WindowsDefault; review its sanitized report. | The script's final exact registry state matches the pre-test snapshot; no restore errors; repeat/idempotence checks pass. Record visible F1 outcomes even if the override has no effect. This remains candidate-only evidence; it does not declare Windows 11 support. |
| T480-05 | Characterize TPM/boot readiness without changing protection state. | From the preflight report, review TPM readiness, Secure Boot state, WinRE availability if separately checked, and current BitLocker status. Use read-only Windows inspection only. Confirm recovery access arrangements before planning any encrypted-boot test. | Readiness facts are known and internally consistent. Since BitLocker is currently off, this case can qualify only read-only platform detection; it cannot qualify encrypted boot, recovery-screen, protector, or BitLocker restore behavior. |
| T480-06 | Qualify a future BitLocker/TPM/boot recovery lifecycle, if separately approved. | Before any mutation, make a current backup and confirm the recovery key is saved and retrievable (USB or password manager are both acceptable). Review the exact RIDE operation, target scope, expected reboot, recovery route, and rollback. Then use a separately approved test procedure to capture pre-state, apply one change, reboot and observe, restore the captured state, reboot and verify. Never include the key in output. | This case remains **not ready** while BitLocker is off and the recovery procedure is not approved. A system restore point alone does not pass this gate. Do not start enrollment, protector changes, suspension, or boot-policy changes under this plan. |
| T480-07 | Produce evidence sufficient to decide whether each tested RIDE function qualifies. | Complete the report template below for every case; attach the sanitized preflight report and development-machine validation/Pester results; record operation ID, source revision, before/after observations, run ID, reboots, restore result, and deviations. | Each claim has evidence for the named case and T480 build. Mark pass, fail, blocked, or not run explicitly. A blocked or unrun case is not a pass and does not widen target support. |
| T480-08 | Resolve whether Docker Desktop's prior VM failures were caused by the VM test environment and qualify RIDE's package lifecycle on native Windows. | After reviewing Docker's current terms and prerequisites, verify the T480 satisfies the package's Windows build, WSL 2, hardware virtualization, SLAT, and memory requirements. Use a physical-test-only candidate acceptance build/harness; preview, install one selected variant, repeat, inspect status/version, exercise captured-run recovery, then uninstall and verify the result. Run per-user first. Test all-users only as a separate elevated case if that variant is required. | A complete RIDE lifecycle passes on physical Windows with no unexplained installer hang; repeat detects the same install; recovery/uninstall acts only on the selected variant. Do not claim Docker data preservation unless a safe test resource existed and was separately approved for runtime testing. Catalog currently has no supported Windows target for this pending candidate, so ordinary apply remains blocked until a test-only candidate path is prepared; do not widen published support to bypass the gate. |
| T480-09 | Test native WSL 2 and Docker engine startup separately from RIDE package lifecycle, if Docker runtime behavior is in scope. | First record the default Windows feature state. With a separately approved procedure, enable/install the required WSL 2 components and a disposable Linux distribution, reboot if required, verify WSL reports version 2, launch Docker Desktop with the WSL 2 backend, run a minimal publisher-provided smoke container, verify engine shutdown/restart, then remove only the test distribution/resources. Do not use credentials, private source trees, or production data. | The WSL distribution and engine work on bare-metal T480 Windows without an outer VM layer. Record any WSL kernel/version, feature, boot, or engine error separately. This qualifies the native runtime path only; it is outside the current RIDE package's install/remove scope. If enabling Windows features or installing a distribution is not desired, mark this case not run. |

## Step-by-step procedure

### 1. Prepare the checkout on the T480

1. Do not install ChatGPT/Codex, Git, Pester, PowerShell 7, or any other tool.
   Obtain a reviewed source copy and its source revision/hash manifest through
   the repository's normal trusted channel, or copy them from the test
   workstation using an approved removable drive. Windows File Explorer can
   extract an archive if needed.
2. Place the source copy in a user-writable working directory. Verify the
   supplied manifest using built-in PowerShell `Get-FileHash` if it lists file
   hashes. Do not change execution policy; if Windows blocks a script, stop and
   report the block rather than weakening policy.
3. Open **Windows PowerShell** (5.1) as the normal test user. Use elevation only
   if a specific selected operation requires it and its test case calls for it.
4. From the repository root, run:

   ```powershell
   .\tests\integration\Invoke-RideT480Preflight.ps1
   ```

5. Open the report path printed by the script. Check the reported values and
   correct the CPU description from the device's actual reported model. Share
   the report back only after confirming it contains no sensitive data.

### 2. Establish source and automated-test evidence

1. Record the source revision/hash manifest supplied with the reviewed copy and
   `$PSVersionTable.PSVersion`. Git is not needed on the T480.
2. The development machine prepares validation evidence before the copy is
   transferred, using the repository's static validation and focused mocked
   suite:

   ```powershell
   .\tools\validate.ps1
   Invoke-Pester .\tests\RemainingSettings.Tests.ps1
   ```

   Run Pester only where it is already available on the development machine;
   do not install it on the T480 for this plan. These tests use mocked system
   handlers and do not prove T480 runtime behavior.
3. On the T480, review the supplied validation evidence and identify the exact
   operation IDs selected for read-only checks. Do not use broad integration
   scripts on this laptop.

### 3. Perform read-only RIDE checks

1. Import the engine as described in the repository README.
2. Run only `list`, `show`, `plan`, `status`, and completion for selected IDs.
3. Save the relevant output in the report. Repeat `status` and `plan` and
   confirm no machine state changed.
4. Stop if an operation is pending acceptance, has unclear scope, requires
   unexplained elevation, or would acquire/install a package.

### 4. Run the experimental F1 candidate lifecycle

1. Run `tests/integration/Invoke-RideF1HelpAcceptance.ps1` from the reviewed
   source copy in the normal, unelevated T480 desktop session. It enables the
   pending candidate only in its own process; catalog support remains pending.
2. Confirm the baseline results before the script applies `Blocked`. Observe
   Explorer, desktop, and a known unrelated application's F1 behavior under
   both `Blocked` and `WindowsDefault`, then allow the script to restore the
   exact starting state.
3. Review the generated sanitized Markdown report and confirm no restore error.
   Do not perform manual registry edits or use the legacy recursive-delete
   behavior. If a visible test step fails, report it and use the run IDs for
   recovery; do not claim target support.

### 5. Leave BitLocker/boot mutation deferred

1. Record T480-05 read-only TPM/Secure Boot/BitLocker facts.
2. Mark T480-06 **not ready** until a separate recovery-changing procedure is
   reviewed, a current backup exists, and the recovery key is confirmed saved
   and retrievable. Do not treat the restore point as that confirmation.
3. Stop before any command that turns on BitLocker, adds/removes protectors,
   suspends/resumes protection, changes Secure Boot/TPM settings, or alters
   boot configuration.

### 6. Decide whether to add Docker/WSL cases

1. Review T480-00's firmware virtualization, SLAT, WSL feature, Windows build,
   and memory observations against the package's declared prerequisites.
2. The T480 is the appropriate physical target for Docker Desktop's RIDE
   installer lifecycle because the prior Hyper-V guest attempts timed out and
   the repository records that VM/VDI setup as outside the supported Docker
   test configuration. The old VM results are inconclusive; they do not prove
   hypervisor layering was the cause.
3. Keep T480-08 limited to the package lifecycle. RIDE does not install/update
   WSL, enable Windows features, choose a backend, start Docker Desktop, or
   provision containers. The catalog currently leaves Docker Desktop pending
   with no supported target, so first prepare an isolated physical-candidate
   test path; do not edit published support just to run it.
4. Treat T480-09 as an optional, separate runtime investigation. It requires
   non-default Windows features and a test Linux distribution. Proceed only if
   native WSL/Docker runtime behavior is something the user wants qualified;
   record installed components and reverse/cleanup steps first.

### 7. Return the results

Fill in the report template below in a Markdown file, attach the generated
preflight report, and send both back in this chat. Include failures and blocked
gates, not just successful cases. Do not include recovery keys, serial numbers,
personal file paths, or account names.

## Report-back template

```markdown
# T480 RIDE test report

- Date/time and time zone:
- Windows edition/build:
- Lenovo model / CPU (as reported by Windows):
- PowerShell version:
- RIDE commit/source revision:
- Elevated session used? For which case and why:
- Preflight report attached:

| Test ID | Pass / Fail / Blocked / Not run | Evidence and observations | RIDE run ID | Recovery/restore result |
| --- | --- | --- | --- | --- |
| T480-00 | | | | |
| T480-01 | | | | |
| T480-02 | | | | |
| T480-03 | | | | |
| T480-04 | | | | |
| T480-05 | | | | |
| T480-06 | | | | |
| T480-07 | | | | |
| T480-08 | | | | |
| T480-09 | | | | |

## Deviations, failures, and follow-up

```

## Repository basis

The laptop's TPM/boot role and recovery-key condition are recorded in the
[remaining settings plan](../migrations/remaining-settings-plan.md#mixed-scope-profiles-and-acceptance-resources-2026-10-24)
and [migration follow-up](../migrations/remaining-migrations-follow-up.md#mixed-scope-profiles-and-tpm-boot-acceptance-2026-10-24).
The F1 candidate's current evidence and pending implementation/behavior gates
are recorded in the [settings post-migration review](../migrations/settings-post-migration-review.md#f1-help-windows-native-preference-and-source-comparison-2026-10-11).
The Docker candidate's package-only boundary and pending physical lifecycle are
recorded in the [application package guide](../application-packages.md#docker-desktop-candidate-for-windows-11)
and [dated review](../migrations/application-migration-review.md#docker-desktop-ready-for-physical-ride-review-2026-10-22). Current Docker
prerequisites and the VM/VDI boundary are described in [Docker's Windows install
requirements](https://docs.docker.com/desktop/setup/install/windows-install/)
and [VM/VDI guidance](https://docs.docker.com/desktop/setup/vm-vdi/).
