# Store app inventory and reviewed migration scope

Decision accepted: **reset v3 scope to current reviewed app identities, use live
inventories, and retain separate user-uninstall and device-policy workflows**.
October 2026 is the reference capture period, not a permanent universal inbox list.
**Keep every app until the inventories have been reviewed. Packages remain paused.**

## Active scope and historical coverage

Start with the available pinned Windows 11 and Windows Server 2025 references.
Collect actual user registrations and image provisioning separately. Record exact
edition/build and provenance; Server does not establish client-edition coverage.
Home, Pro, Education, OEM/region variants and additional releases become explicit
acceptance work when relevant apps or resources require them. An exhaustive matrix
of all Windows installations is not a prerequisite for implementation.

The [v2 lists are archived as historical coverage](../archive/migrations/store-app-v2-historical-coverage-2026-10-14.md).
They retain 106 removal and 102 registration names, source hash and four reverse
gaps. Original legacy source stays unchanged. Historical-only names impose no v3
implementation requirement. The blanket bulk removal/re-registration behaviors
are retired as migration requirements; they are not reconnected to the engine.
No installed legacy app is declared absent or safe to remove by this decision.

Default review data contains the inspected template's 25 candidate identities,
plus unfamiliar packages actually observed in an inventory. These are not selected
apps or an exhaustive inbox list. Historical comparisons are optional through
`-IncludeHistoricalCoverage`. Maintain small reviewed selections with exact identities
and protection/dependency checks instead of growing another universal bulk list.

## Two future removal workflows

| Workflow | Intended scope | Acceptance and recovery boundary |
| --- | --- | --- |
| One-time selected-app uninstall | Explicit intended-user registration; target acceptance per applicable operation | Current identities, dependencies/protection and partial results; no exact app-data/version recovery promise |
| Sustained selected-app policy | Compatible Windows 11 Enterprise/Education device policy, initially static template choices | Actual edition/servicing/template capability and effective policy; configuration restore does not reinstall apps or recover data |

Neither workflow silently substitutes for the other. Unknown apps remain visible
for review. Absent approved selections report Not installed/Not applicable; they do
not trigger replacement-name guesses. Additional dynamic PFNs, AllUsers removal,
deprovisioning and acquisition-dependent reinstall remain separate decisions.
No blanket reinstall reverse action is planned. All selection and app changes wait
for inventory review and subsequent matching implementation/acceptance batches.

## Reference collection package

| File/tool | Evidence collected | Scope |
| --- | --- | --- |
| Export-RideStoreAppInventory.ps1 | Observed edition/build, expected SID, package families/full names, versions, available flags and dependencies | CurrentUser; no AllUsers inference |
| Export-RideStoreProvisionedInventory.ps1 | Observed edition/build, raw package names, versions, architecture/resource/region fields and local DISM log | ProvisionedImage, OnlineOperatingSystem; no existing-user registration inference |
| Compare-RideStoreAppInventory.ps1 | Current template candidates and observed packages, exact family matches/mismatches and pending choices | Data-only user review; optional archived-history overlay |
| Schema-4 StoreReferenceInventory fixture | Separate user/provisioning JSON and hashes, current-user comparison, exact configured guest identity and partial collection status | Pinned disposable reference; no operation/state/app selection or Windows mutation |

Use the [collection commands and scope guide](../store-app-inventory.md). The
provisioning tool requires an already elevated process and never asks for elevation;
its preview queries nothing and writes no inventory or DISM log. The disposable
controller already provides an elevated guest, after the existing host prerequisites
are satisfied. Preserve schema-3 user-only collection and schema-1/2 setting fixtures.

For each capture, retain time, edition, release/build/revision, actual user identity,
image/setup provenance, fresh versus upgrade, language/region and known OEM/management
or servicing changes. Process culture/architecture hints do not prove installation
region or image provenance. Keep raw identities locally and publish reviewed
aggregates. A checkpoint reference is not automatically an untouched OEM baseline.

## Evidence with different authority

- [Get-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage?view=windowsserver2025-ps)
  establishes that user's registered packages at capture time.
- [Get-AppxProvisionedPackage](https://learn.microsoft.com/en-us/powershell/module/dism/get-appxprovisionedpackage?view=windowsserver2025-ps)
  identifies packages configured in an image for new profiles.
- Actual serviced ADMX/ADML and consumer evidence establish policy capabilities,
  not the installed-app population. The [policy guide](https://learn.microsoft.com/en-us/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal)
  governs applicability and sign-in/reinstall behavior.
- [Official lifecycle notices](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)
  inform historical classification. Deprecation, distribution retirement and
  absence from a specific inventory remain different evidence.

Use representative versioned snapshots as reference evidence. Select apps because
of reviewed user intent and actual identities, not simply because they appear in
provisioning. Archive retention does not require testing every Windows 10-era app.

## Next review and implementation steps

1. Implement the accepted optional consumer group first: Clipchamp, News, Weather
   and Solitaire. The [group contract](../store-app-groups.md) records the five
   uninstall/reinstall compositions; current installed apps remain kept.
2. Follow with core utilities (2A), multimedia including Media Player/Sound
   Recorder (2B), assistance/productivity (2C) and Xbox/gaming (3). Exact
   captured families, versions, other-package references and unknown flags remain
   visible; an absent historical name is not a universal retirement. Shared and
   protected gaming dependencies stay guarded rather than automatically removed.
3. Implement only the selected app identities in matching small batches. Keep
   intended-user one-time uninstall separate from sustained device policy; verify
   actual serviced policy capability and intended-user desktop behavior first.
4. Collect another relevant user/edition only when it affects those choices.
   No Home/Pro/Education or Windows 10 capture is required merely to complete this
   representative collection phase; their support/coverage is not inferred.

The prior user-only request 3dfba9fd4b6f4e61bf24de7e8613777e was refused before VM
use because host WinRM was stopped; [dated refusal evidence](../archive/evidence/store-app-inventory-refusal-2026-10-14.md)
remains intact. Direct user authorization subsequently allowed the fixed host
WinRM start. Startup type remains Manual; configuration was unchanged.

## Current collection status

Both read-only StoreReferenceInventory runs passed:
Windows 11 cdfee696816b4ce480cfce9371832b98, 170 registrations/102 distinct names
and 47 provisioning rows; Server c1a950c3c611407d845efdf31aea1fb8, 57 registrations/
52 names and five provisioning rows. The configured accounts/SIDs, separate scopes,
current Local source including uncommitted changes, all 347/348 snapshot hashes
and checkpoint recovery were verified. Both controllers are idle with unchanged
pins/installed hashes. See [dated evidence](../archive/evidence/store-app-reference-collection-2026-10-14.md).

These are Enterprise Evaluation and Server Standard Evaluation references, not
untouched OEM/inbox baselines or other edition/user coverage. IsPartOfSystem is
unavailable on all captured registration rows; unknown flags remain null. No
app-selection question was needed before collection. User review now establishes
five optional groups with uninstall/reinstall composition and a separate linked
policy workflow. All five groups now have guarded candidate implementations;
the reviewed identity/removability rule is approved and missing local reinstall
sources remain blocking. Policy effectiveness, native interactive handoff and
app/data recovery acceptance remain pending. See the
[active acceptance tasks](store-app-follow-up-decisions.md). Every app
stays kept; packages remain paused. The GitHub bridge stays paused and installed
controllers/pins/CI remain unchanged.
