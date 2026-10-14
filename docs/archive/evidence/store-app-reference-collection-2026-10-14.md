# Store app reference collection, 2026-10-14

The user directly authorized UAC and continued collection. The fixed host action
started existing WinRM at 08:15:13 UTC; status changed Stopped to Running while
startup type remained Manual. No service configuration, listener or firewall
change was made. All apps remain kept; packages remain paused.

## Windows 11 reference

Run: **cdfee696816b4ce480cfce9371832b98**, finished **08:21:55 UTC**.
Source Local at HEAD 2b799873f0f95b7569945373ab576f00d13a5b40 includes current
uncommitted collection changes. All **347** retained snapshot hashes match both
actual bytes and the preflight manifest. Installed controller **0.4.6**, collector
**0.4.1**, pinned VM/checkpoint and frozen CI revision remain unchanged.

- Configured user: RIDE-WIN11-TEST\admin, SID ending 1000; exact identity verified.
- CIM: Microsoft Windows 11 Enterprise Evaluation, 10.0.26300.
- Registry observation: EnterpriseEval, 26H2, build **26300.9457**. Raw ProductName
  is Windows 10 Enterprise Evaluation; it is retained as an observation.
- **170 current-user registered-package rows**, including resource/framework rows;
  **47 online provisioned-package rows**, captured separately.
- Default comparison: 104 review rows, 23 exact policy family matches, two template
  candidates not observed, 79 unfamiliar current names. None selected or approved.
- Guest parser/catalog/profile/generated-document validation passed. Pester:
  **155 passed, zero failed**, one registry WindowsIntegration case excluded by
  the focused read-only selection. Native inventory ran in a separate process.
- Controller, guest and fixture passed; collection, cleanup and state-collection
  errors empty. Both VMs Off, tasks Ready, queues empty, locks available, no
  recovery blocks, checkpoints match; installed controller hashes/pins unchanged.

Fixture SHA-256: 29E86E6B1C9F70696ECDB7A0C23595F7F175A0F98407E98488F6975F0E4B4CC8.
Source manifest: 9EB39317D395D40FC834BA5542A46E98AD9E7ACEB88CAC3FD7CF2C35BF5248ED.
User inventory: 38C4F505F2B541DAB22BBB093F866C1F2483841993DC154F126ACD34B298CC00.
Provisioning inventory: 2AF426777BA230E2D798D4E7D72765A4569D26C387C5AF6531F7AA632ECD2F62.

Raw evidence remains in the protected controller result directory for this RunId;
local receipt, source manifest, postflight and reference-acceptance.json are in
.local/settings-validation/cdfee696816b4ce480cfce9371832b98. The hash-matched
temporary selection was removed only after acceptance checks passed.

This accepts read-only collection for the configured reference user/image. It
does not establish an untouched inbox baseline, interactive desktop handoff,
other users/editions, app-removal/reinstall recovery or policy effectiveness.
No supported operation target is expanded and no legacy outcome closes.
All five ranges remain 38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded 150-205/about
180, because selected-app implementation and consumer/recovery evidence stay open.

## Windows Server 2025 reference

Run: **c1a950c3c611407d845efdf31aea1fb8**, finished **08:28:52 UTC**.
Source Local at the same HEAD includes current uncommitted changes and the dated
Windows 11 collection report. All **348** retained snapshot hashes match their
actual bytes and preflight entries; the additional report explains the count.

- Configured user: RIDE-S25-TEST\bob, SID ending 1000; exact identity verified.
- CIM: Microsoft Windows Server 2025 Standard Evaluation, 10.0.26100.
- Registry observation: ServerStandardEval, 24H2, build **26100.33438**.
- **57 registered-package rows / 52 distinct names**, captured separately from
  **five provisioned-package rows / five distinct names**.
- Default comparison: 75 review rows, two exact template family matches
  (Feedback Hub and Terminal), 23 candidates not observed and 50 unfamiliar names.
- Guest validation passed; Pester **155 passed, zero failed**, one registry
  WindowsIntegration case intentionally excluded. Native collection ran separately.
- Controller, guest, fixture and source audit passed; cleanup/collection/state
  errors empty. Both controllers Off/Ready, queues empty, locks available, no
  blocks, matching checkpoints and unchanged installed hashes/pins at postflight.

Fixture SHA-256: 850137D9240DD0DBF48305D970AFBD70B53AEA31BEC14E84ACF87606E739AC75.
Source manifest: 060B939AAF082EBD1FB5B7AC2A42F3455DDD0E09F1310FB42914480ECFC9E0F9.
User inventory: 7D6AC8C6E6AF4EA2ED57BF435E3EE9D8C8606B82A984789568463019E17881AC.
Provisioning inventory: 6E137E3CAE4E8CAD6039AD3EBA5E88CE22699D5CAFFB8DFB80C9EBF9CE9ED37F.
Local receipt, manifest, postflight and acceptance are under this RunId in
.local/settings-validation; raw collected files were copied there and hashes
verified against protected controller evidence. Only the hash-matched temporary
selection was removed after acceptance.

## Review handoff

The [inventory review](../../migrations/store-app-inventory-review.md) lists all
110 observed/candidate names across the two references, with user/provisioning
counts kept separate. All remain Keep and RemovalApproved=false. The complete
aggregate, including exact captured families, versions, dependencies and unknown
flags, remains in .local/store-reference-review-20261014.json. Original comparison
rows remain Unselected; the review's Keep reflects the user's explicit hold.

Windows 11 has 11 distinct framework names and 51 names with NonRemovable=true;
Server has eight and 44 respectively, with overlap between those categories.
IsPartOfSystem is unavailable for **all 170/57 registration rows**. Unknown flags
are retained as null, not rewritten as false or treated as removal approval.
App-specific protection and consumer checks remain required before uninstall.

The first decision group is Clipchamp, News, Weather and Solitaire. This is a
proposed review group only: no app was selected, removed or reinstalled, no
provisioning/policy was changed, and no GitHub or package request was made.
Intended-user desktop handoff, actual serviced policy capability/effects,
partial removal and data/reinstall recovery remain separate acceptance work.
All five migration ranges and the rounded total remain unchanged.
