# Windows edition support decisions, 2026-11-04

## Decisions

- Treat Windows release/build and Windows edition as separate support dimensions.
  A `Windows 11` target declaration does not imply that every edition supports
  every operation.
- Reuse shared handler tests across editions. Add focused native acceptance only
  where the backend or Windows behavior is edition-specific; keep Server, Home
  and ARM64 acceptance independent.
- The default wallpaper and machine default lock-screen image remain separate
  features. Pro evidence for one does not establish the other.
- The machine default lock-screen handler supports the documented
  `LockScreenImage` policy route on Enterprise/Education editions. Windows 11 Pro
  is refused. On the Pro 26300 test VM, the attempted `PersonalizationCSP`
  registry tuple did not change the signed-out sign-in image even though the
  registry/file lifecycle applied. Exact native restore passed.
- Do not enable Shared PC mode or create MDM/Boot to Cloud policy as an implicit
  prerequisite to ordinary RIDE image configuration. Reconsider Pro only as a
  separately designed workflow with explicit management-mode requirements and
  focused visual/recovery acceptance.
- For RSAT, OpenSSH and Store app operations, inventory the exact target before
  mutation. Treat an absent capability or app as unavailable on that image, not
  as successful installation. A Pro acceptance result does not establish Server,
  Home, ARM64 or another Windows build.

## Component scope and remaining acceptance

The catalog component areas comprise 22 RSAT capabilities, OpenSSH Client and
Server capabilities, 23 user-scoped Store app registrations, and the two default
image settings. The RSAT group composes its 22 catalog identities. Read-only
component inventory can also observe optional Windows features and Server
roles/features; that observation does not provide a catalog install/remove
operation for every observed item.

- **Default wallpaper:** keep its current Enterprise/Education target gate.
  Microsoft documents the first-logon theme policy on Pro, but that path differs
  from setting a current user's wallpaper. Test and decide it independently on
  Pro.
- **Default lock screen:** ordinary Pro is unsupported by the current machine
  policy operation. EnterpriseEval 26300.9711 has accepted sign-in image
  behavior. Other Enterprise/Education builds need candidate acceptance.
- **RSAT:** use Pro/Enterprise x64 as candidate client editions. Inventory all
  catalog identities on the Pro image and use the prepared group lifecycle route
  when servicing availability permits. Do not claim Server roles from client
  RSAT testing.
- **OpenSSH:** test Client capability lifecycle separately from Server
  capability, service activation and firewall exposure. Keep Windows Server
  acceptance separate.
- **Store apps:** inventory per intended user. Run lifecycle acceptance for
  available apps; keep absent, protected, non-removable or source-unavailable
  apps as explicit per-app outcomes. Apply the approved fast-track criterion:
  install/registration succeeds, the app launches without error, and uninstall
  succeeds; deeper product behavior is deferred to v3.1.

## Evidence and recovery

The Pro lock-screen run used the retained AutomatedLab guest `RIDE-W11P-Test`
in lab `RIDEWin11ProTest`, Windows 11 Pro build 26300. Apply returned
`AwaitingVisualVerification`; the user observed the original blue sign-in image.
Restore returned `LifecyclePassedVisualPending`, and a screenshot confirmed the
original image was back. Collect returned `Collected` with a verified export of
13 files. Reset returned `ResetAndOff`, `Stage=Released`,
`RecoveryRequired=False`, and no reported error. The guest was restored to its
pinned checkpoint.

Microsoft's [Personalization CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/personalization-csp)
limits Pro use to documented Shared PC or Boot to Cloud policy conditions. The
[background configuration overview](https://learn.microsoft.com/en-us/windows/configuration/background/)
does not make a direct registry tuple an accepted substitute for those
preconditions. RIDE does not enable those management modes.

For client RSAT, Microsoft's [installation guidance](https://learn.microsoft.com/en-us/windows-server/administration/install-remote-server-administration-tools)
lists Windows 11 Pro and Enterprise editions. Feature availability and servicing
source remain image-specific; Microsoft documents DISM capability inventory and
servicing in [Features on Demand](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/features-on-demand-v2--capabilities?view=windows-11).
