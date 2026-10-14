# Store app removal policy and v2 migration review

Reviewed: **2026-10-14**. Recommendation: include the policy as a candidate in
the built-in app management migration, alongside explicit Appx uninstall work.
Keep device policy, user uninstall and image provisioning as distinct actions.
The user selected a modern v3 scope with live discovery and both separate workflows.
V2 lists are archived as optional historical coverage; they impose no requirement
to implement every entry. User and provisioning references were collected separately;
the [inventory review](store-app-inventory-review.md) owns grouped app choices.
The user accepted [five optional uninstall/reinstall groups](../store-app-groups.md).
The device policy remains its own workflow with independent configuration and
acceptance. The explicit app handlers are implemented as guarded candidates; app-specific
native lifecycle and the separate policy handler/acceptance remain pending.
Packages remain paused; this review changes no Windows state or support targets.

## Policy and applicability

Microsoft's [current feature guide](https://learn.microsoft.com/en-us/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal)
describes Windows 11 24H2 or newer Enterprise/Education support, device-wide removal
at provisioning/sign-in, blocked reinstallation while selected, and loss of local
app data. Clearing selection permits subsequent reinstallation; it does not
reinstall apps. Multi-session environments are unsupported. The guide describes
both a static app list and a newer dynamic PFN list, whose schema needs compatible
servicing. Its prerequisite text mentions managed deployment, while its GPO steps
also describe Local Group Policy. Standalone local-policy acceptance needs testing.

The [ApplicationManagement CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationmanagement#removedefaultmicrosoftstorepackages)
maps `RemoveDefaultMicrosoftStorePackages` to Computer Configuration, Windows
Components, App Package Deployment, in `AppxPackageManager.admx`. It identifies
`HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx\RemoveDefaultMicrosoftStorePackages`
and the `Enabled` value. Its applicability table still says Insider Preview
26100 and includes IoT, unlike the narrower feature guide. Do not turn those
inconsistent tables into a blanket build-number or IoT support declaration.
No Pro, Home or Server support is proposed.

Read-only inspection of the local ADMX found the policy and support identifier
`SUPPORTED_Windows_11_0_24H2_NOSERVER_ENTERPRISE_EDUCATION`, with Enabled 1/0,
25 per-app `RemovePackage` booleans and a `DynamicRemovalList` multi-text field.
Both installed English and Danish ADML presentations preselect seven checkboxes.
Template presence proves the mapping, not that a particular OS consumer applies
it. RIDE should require an explicit app selection rather than inherit UI defaults.

## What the v2 functions actually do

The active v2 preset selects `UninstallMsftBloat` and `UninstallThirdPartyBloat`.
Their source is in [lib-windows.psm1](../../legacy/v2/lib-windows.psm1).

| Legacy function | Literal app-name queries | Actual source behavior |
| --- | ---: | --- |
| UninstallMsftBloat | 58 | Get-AppxPackage by name, piped to Remove-AppxPackage, without User or AllUsers selection |
| InstallMsftBloat | 58 | Enumerate matching packages with AllUsers; register each existing InstallLocation manifest in the execution user's context |
| UninstallThirdPartyBloat | 48 | Same user-context removal pattern, using a separate historical list |
| InstallThirdPartyBloat | 44 | Same existing-manifest re-registration pattern; four removal entries have no matching reverse entry |

The missing third-party reverse entries are `AmazonVideo.PrimeVideo`,
`BytedancePte.Ltd.TikTok`, `Clipchamp.Clipchamp` and `Facebook.InstagramBeta`.
Neither removal function deprovisions the Windows image. Neither install function
captures prior registrations, versions or app data. Enumerating AllUsers is not
restoring every user's registration. Under alternate-administrator execution, the
execution account can differ from the intended desktop user.

Microsoft documents [Remove-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage?view=windowsserver2025-ps)
as user-account removal, with separate User and AllUsers scopes. The ordinary data
preservation option applies only to development/loose-file registration, so it
cannot supply a general backup contract for Store apps.
[Add-AppxPackage registration](https://learn.microsoft.com/en-us/powershell/module/appx/add-appxpackage?view=windowsserver2025-ps)
uses an existing package/manifest. V2's reverse therefore cannot guarantee recovery
when payloads, dependencies or registration prerequisites are missing.

## Coverage is only partial

Of the 25 static policy entries in the inspected template, 12 have a package-name
stem matching a v2 removal query. Eleven are in the Microsoft list; Clipchamp is
in v2's third-party list. This is a literal name comparison, not verified runtime
identity, publisher, availability or removal equivalence.

| Static policy entries with a matching legacy name stem | Entries requiring separate mapping or new coverage |
| --- | --- |
| Feedback Hub, Microsoft 365/Office Hub, News, Photos, Solitaire, Sticky Notes, To Do, Weather, Camera, Media Player, Sound Recorder, Clipchamp | Copilot, MSTeams, new Outlook, Paint, Quick Assist, Snipping Tool, Calculator, Notepad, Terminal, Gaming App, Xbox Identity Provider, Xbox Speech to Text Overlay, Xbox TCUI |

For example, v2's `Microsoft.MSPaint` is not the template's `Microsoft.Paint`.
Do not map renamed or replaced apps by a friendly label alone. The dynamic list
offers a candidate route for additional PFNs, but it does not justify converting
every old query into a current removal target. V2 also removes WinJS and
Advertising.Xaml framework/dependency entries; those need dependency review rather
than inclusion in a consumer-app preset.

The retained [read-only comparison data](../archive/evidence/store-app-removal-source-review-2026-10-14.json)
contains all literal source lists, the 25-entry PFN crosswalk, template hashes,
default selections and reverse-list gaps. Counts are query entries, not new legacy
outcomes.

## Proposed RIDE workflows

| Workflow | Proposed contract | Recovery boundary |
| --- | --- | --- |
| Remove selected Store apps by device policy | One coordinated policy with explicit reviewed app selections and a separately gated dynamic PFN list. Machine/admin scope. No silent fallback on unsupported editions or schemas | Restore captured policy values/types/absence and only owned keys. Report any resulting app/data removal separately; policy restore is not app restore |
| Uninstall selected apps now | Separate explicit intended-user action, with identity, package version, dependencies, removability and current registration shown before apply. All-user removal would be a separate scope | Record actual completion and reinstall requirements per app. No Exact claim for app data or versions without an evidenced recovery route |
| Remove provisioning for new profiles | Separate image/component action if requested. Do not bundle it into user uninstall | Own image/provisioning identity and declared recovery media/dependencies; existing-user registration remains a separate concern |
| Reinstall or re-register an app | Separate selected-app action after checking policy and available source | Refuse or explain an active removal policy. Do not clear the policy, fetch payloads or run broad re-registration automatically |

Uninstall/reinstall composition follows the [accepted app groups](../store-app-groups.md):
consumer apps, core utilities, multimedia, assistance/personal productivity and
Xbox/gaming. Those groups do not automatically configure the policy. Policy
coverage depends on its actual template/schema; share app identities while retaining
independent user actions and device selections. Both documents link to the other
workflow. Reinstall/source refusal and per-app partial results are required; app
data and previous versions are not guaranteed recovery.

The [DISM provisioning command](https://learn.microsoft.com/en-us/powershell/module/dism/remove-appxprovisionedpackage?view=windowsserver2025-ps)
changes image provisioning for new accounts, which differs from ordinary existing
user removal. Keep the selected API's exact scope visible in planning and reports.

For the policy, Enabled, explicit Disabled and Not configured must remain distinct.
Capture the complete owned selection before mutation, including mixed/custom prior
values. Preserve unrelated policy keys and external management. Do not overwrite
domain/MDM policy or promise that a raw registry write establishes effective GPO
configuration. Show configured selection, effective source, pending sign-in and
observed per-user app state separately. A configured policy is not completed removal.

Use a shared app identity model across workflows, but retain their different
lifecycles. Completion should come from the reviewed selection data and bounded
installed-app inventory. Do not create an executable bulk list from v2 or add
removal to recommended profiles. Keep tools needed by RIDE and file/protocol
handlers visible when reviewing the eventual list.

## Implementation and acceptance sequence

1. Collect representative Windows 11/Server 2025 user and provisioning references.
   Review actual identities, publishers and protection/dependencies. Consult v2
   history only when relevant; no exhaustive historical reconciliation is required.
2. Establish static versus dynamic schema capability on the actual serviced
   Enterprise/Education targets. Resolve standalone Local Group Policy behavior;
   record external management and unsupported targets explicitly.
3. Design the coordinated policy capture/restore contract and current-user Appx
   lifecycle separately. Keep the broad built-in app work owned by the components
   migration; link its policy portion from settings without counting it twice.
4. Add mocked preview, capture, unknown app, conflict, partial-failure and completion
   checks. No package acquisition or application removal on the workstation.
5. Later, use explicitly selected sacrificial apps in the established disposable
   VM flow. Test existing and new profiles, pending sign-in, repeat application,
   per-app partial results, policy-conflict refusal and policy restore. Checkpoint
   cleanup must not be reported as application/data restoration. Any reinstall or
   Store/sideload blocking test needing acquisition stays deferred while packages
   are paused. Interactive elevation or unavailable credentials are deferred.

## Accepted decisions and remaining implementation

**D11:** Both distinct workflows are selected. Five optional uninstall/reinstall
groups are accepted, including Media Player and Sound Recorder in multimedia.
Actual executions remain explicit; no profile selects them by default.
The [historical archive](../archive/migrations/store-app-v2-historical-coverage-2026-10-14.md)
retains all 106 removal names and their registration gaps. The active comparison
contains current template candidates and observed apps; archived names are optional.
The read-only comparison tools include
unfamiliar installed apps rather than treating the historical lists as complete.
The group choices add optional functionality, not permission to uninstall apps
on the workstation. Notepad, Terminal and recovery/file/protocol tools need their
own preservation and consumer checks before their later isolated fixture batch.

Both configured disposable reference inventories passed after authorized host
WinRM preparation; the [inventory review](store-app-inventory-review.md) records
the accepted groups. Keep current apps installed while implementing choices and
their guards. Follow the [inventory plan](store-app-inventory-plan.md); the previous
stopped-WinRM refusal remains historical evidence. Reinstall requiring acquisition
stays deferred while packages are paused. No absent app is inferred retired.

This review resolves no legacy uninstall outcome and retires no app. Built-in app
management was already counted in the components estimate. The new policy is an
additional implementation option within that work; all five rounded ranges remain
unchanged pending app-by-app design and acceptance.
