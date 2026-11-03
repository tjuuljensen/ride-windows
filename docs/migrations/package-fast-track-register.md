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
PowerShell editions; native startup results are still pending. Failed startup
retains executable/process/error evidence. See [source checks](../archive/evidence/fast-track-startup-and-capability-preflight-source-2026-11-03.json).

| Products | Lifecycle evidence | Startup evidence | v3.1 follow-up |
| --- | --- | --- | --- |
| Twelve MiTeC products in the Nov 3 reassessment | Passed, 12 cases | Not run in those file-only cases | Synthetic feature scenarios; startup remains for revised fast track. |
| NTCore PE Detective, CFF Explorer, 4GB Patch, Driver List x64/x86, Rebel.NET | Passed, six cases / five products | No general startup proof; 4GB Patch has separate synthetic PE behavior evidence | Product feature coverage. |
| Sysinternals Suite and nine individual packages | Passed, ten cases | Not launched; retain prior scoped package acceptance | Optional utility coverage, without a new licensing gate. |
| WinPmem | Passed file-only lifecycle | Deliberately not launched; driver/memory acquisition remains separate | Explicit driver/collection acceptance if selected. |
| MiTeC Mail Checker | Prepared ApplicationsBatch13 route; native result pending | Bounded startup required, without mail account setup | Synthetic mail features only in v3.1 if selected. |
| Remaining MiTeC viewers/development/network/system batches | Prepared 14 products / 20 variants; native results pending | Record per-product startup separately | Focused features deferred to v3.1. |
| Rufus | Nov 3 native lifecycle passed 14 checks with recovery and Defender; [evidence](../archive/evidence/attended-routes-activation-and-rufus-native-2026-11-03.json) | Not launched; no media operation | Scoped startup separate from media actions. |
| RegRipper, WFN | Prepared native file lifecycle routes | Existing routes do not launch; no implicit evidence/firewall actions | Scoped startup separate from product actions. |
| InfoBar, Project Maker, NTCore Explorer Suite, Gpg4win, TMOG | Prepared focused routes; earlier partial evidence retained | Native startup still to be established | Features after lifecycle/startup acceptance. |

The [Nov 3 status](migration-completion-reassessment-2026-11-03.md) and
[overnight case index](../archive/evidence/overnight-closeout-2026-11-03.json)
provide exact products, variants and evidence. Update this register with native
results rather than inferring acceptance from prepared routes.
