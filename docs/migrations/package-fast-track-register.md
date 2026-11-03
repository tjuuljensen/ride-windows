# Package fast-track acceptance register

## Decision and acceptance boundary

On 2026-11-03 the user selected install, startup without observed errors and
uninstall as the fast-track gate for downloaded ordinary user-mode tools,
including MiTeC Mail Checker. Product functionality is not a v3 acceptance gate
for this selection. Keep deeper feature scenarios for v3.1. Exact package
identity, repeat behavior, declared recovery and active/no-alert Defender remain
part of the existing lifecycle route.

A bounded startup check records the executable, execution context, observation
period, exit/error evidence and closure. Copying an executable or detecting
installation is not startup acceptance. Noninteractive startup does not establish
interactive UI behavior. No real mail accounts, credentials, send or delete
actions are needed for Mail Checker fast-track acceptance.

Driver loading, disk writes, firewall changes, encryption and shared dependency
recovery retain their explicit boundaries. Preserve separate download-only
decisions. Do not relabel earlier file-only passes as having launched a tool.

## Product evidence

The MiTeC portable and Mail Checker guest scenarios now include bounded startup
checks. Eight startup tests plus 18 existing selection tests passed in both
PowerShell editions. JSON/XML Viewer x64/x86 native startup passed; the old
controller rejected the new execution flag, so its failed outer result remains
recorded alongside the passing guest evidence. Failed startup
retains executable/process/error evidence. See [source checks](../archive/evidence/fast-track-startup-and-capability-preflight-source-2026-11-03.json).

| Products | Lifecycle evidence | Startup evidence | v3.1 follow-up |
| --- | --- | --- | --- |
| Twelve MiTeC products in the Nov 3 reassessment | Passed, 12 cases | Not run in those file-only cases | Synthetic feature scenarios; startup remains for revised fast track. |
| NTCore PE Detective, CFF Explorer, 4GB Patch, Driver List x64/x86, Rebel.NET | Passed, six cases / five products | No general startup proof; 4GB Patch has separate synthetic PE behavior evidence | Product feature coverage. |
| Sysinternals Suite and nine individual packages | Passed, ten cases | Not launched; retain prior scoped package acceptance | Optional utility coverage, without a new licensing gate. |
| WinPmem | Passed file-only lifecycle | Deliberately not launched; driver/memory acquisition remains separate | Explicit driver/collection acceptance if selected. |
| MiTeC JSON Viewer and XML Viewer, x64/x86 | Four cases passed 15 checks, exact recovery and Defender; outer controller classification failed | Eight-second owned-process observation passed in session 0; no interactive UI claim. [Evidence](../archive/evidence/mitec-viewers-fast-track-native-2026-11-03.json). | Synthetic feature scenarios and interactive UI coverage. |
| MiTeC development batch | Six cases passed 15 checks, exact recovery and Defender; outer controller classification failed | Bounded startup passed in session 0. [Exact products/variants](../archive/evidence/mitec-development-fast-track-native-2026-11-03.json). | Synthetic feature scenarios and interactive UI coverage. |
| MiTeC Mail Checker | Passed nine lifecycle checks, 63 guest regression tests, Defender and checkpoint recovery. Exact executable identity verified before startup and after compensating reinstall; ARP version remains absent. [Evidence](../archive/evidence/mail-checker-fast-track-native-2026-11-03.json). | Eight-second session-0 startup passed without observed errors; no accounts or mail actions | Synthetic mail features and interactive UI in v3.1 if selected. |
| MiTeC Network Scanner | x64 passed 15 lifecycle/startup checks. x86 startup failed; checkpoint recovery and Defender passed. | x86 produced APPCRASH `0x0eedfade` in session 0. [Evidence](../archive/evidence/mitec-network-fast-track-native-2026-11-03.json). | Diagnose x86 startup separately; features remain deferred. |
| MiTeC OLE/COM Explorer, Windows Registry Recovery, SMBIOS Explorer, Windows File Analyzer, Icon Explorer, Structured Storage Viewer | Six cases passed 15 checks each, with successful outer controller result, recovery and Defender | Bounded startup passed in session 0. [Evidence](../archive/evidence/mitec-system-viewers-fast-track-native-2026-11-03.json). | Focused features and interactive UI deferred to v3.1. |
| MiTeC DirList and Network Meter | Not reached after Scanner x86 failure; reordered follow-up prepared | Native startup pending | Focused features deferred to v3.1. |
| Rufus | Nov 3 native lifecycle passed 14 checks with recovery and Defender; [evidence](../archive/evidence/attended-routes-activation-and-rufus-native-2026-11-03.json) | Not launched; no media operation | Scoped startup separate from media actions. |
| RegRipper | Passed native file lifecycle, recovery and Defender. [Evidence](../archive/evidence/regripper-native-file-lifecycle-2026-11-03.json). | Not launched; no hive analysis | Scoped startup separate from product actions. |
| WFN | Passed 14 native file lifecycle checks for the selected 531-member payload, Defender and checkpoint recovery. [Evidence](../archive/evidence/wfn-native-file-lifecycle-2026-11-03.json). | Not launched; no firewall actions | Scoped startup separate from firewall actions. |
| InfoBar | Guest regression gate failed before install/startup; checkpoint recovered. [Native evidence](../archive/evidence/infobar-regression-gate-native-2026-11-03.json). Stale assertions corrected: 138 application tests passed, three skipped per shell. | Pinned startup prepared; corrected native retry pending | Synthetic features deferred to v3.1. |
| Project Maker | Earlier snapshot stopped at the same three stale runner-version assertions before installation; checkpoint recovered. [Evidence](../archive/evidence/project-maker-regression-gate-native-2026-11-03.json). Corrected retry queued. | Pinned startup prepared. [Source evidence](../archive/evidence/infobar-project-maker-startup-source-2026-11-03.json). Native startup pending. | Synthetic features deferred to v3.1. |
| Gpg4win | Native installer failed again with `0xC0000005`; 73 guest regression tests and separate checkpoint recovery passed. [Evidence](../archive/evidence/gpg4win-installer-failure-native-2026-11-03.json). | Not reached | Diagnose installer failure before startup or feature acceptance. |
| TMOG | Installed, then exact version assertion failed: release 1.0.1 registers 1.0.1.0. Checkpoint recovery passed. [Evidence](../archive/evidence/tmog-version-assertion-native-2026-11-03.json). Corrected native retry pending. | Pinned eight-second startup prepared; 50 tests passed per shell. [Source evidence](../archive/evidence/tmog-fast-track-startup-source-2026-11-03.json). Native pending. | Establish startup for v3 fast track; feature coverage in v3.1. |
| NTCore Explorer Suite | Prepared focused route; earlier partial evidence retained | Native startup still to be established | Features after lifecycle/startup acceptance. |

The [Nov 3 status](migration-completion-reassessment-2026-11-03.md) and
[overnight case index](../archive/evidence/overnight-closeout-2026-11-03.json)
provide exact products, variants and evidence. Update this register with native
results rather than inferring acceptance from prepared routes.
