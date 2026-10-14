# Store app inventory and reconciliation

Use read-only inventory before selecting either the device removal policy or a
one-time intended-user uninstall. App names and installed packages change over
time. The [active review definitions](../catalog/store-app-review.psd1) contain
inspected policy candidates. The [archived v2 lists](archive/migrations/store-app-v2-historical-coverage-2026-10-14.md)
retain historical queries for optional comparison. Neither is a removal preset.
Keep all apps until inventory review; packages remain paused.

Run collection inside the intended user's own Windows console. Use `whoami /user`
to verify that account and obtain its SID, then supply it explicitly:

```powershell
.\tools\Export-RideStoreAppInventory.ps1 -ExpectedUserSid <intended-user-SID> -OutputPath .\apps.json -WhatIf
.\tools\Export-RideStoreAppInventory.ps1 -ExpectedUserSid <intended-user-SID> -OutputPath .\apps.json
.\tools\Compare-RideStoreAppInventory.ps1 -InventoryPath .\apps.json |
    Select-Object Name, MappingStatus, StaticPolicyId, ReviewClass, PendingReview
```

Preview performs neither collection nor output writing. Collection queries only
the execution user's Appx registrations, including main, framework, bundle,
resource and optional packages. An SID mismatch or query failure stops the export.
No AllUsers query, provisioning inspection, app registration, removal or download
occurs. Retain the JSON locally: it includes installed app identities, versions,
publisher, dependencies and protection flags for the captured user. Re-export
after servicing or Store updates when reviewing a changed target.

Each export also retains observed edition ID, release, build/revision and process
culture/architecture hints. Keep the raw ProductName label separate from the build;
it is not used to infer target support. Missing edition/build observations remain
explicitly incomplete, including older schema-1 inventories without this additive
context. One user's snapshot cannot establish coverage for another edition,
release, OEM image or language. See the [inventory collection plan](migrations/store-app-inventory-plan.md).

Comparison reads saved data only and returns pipeline-friendly objects. Default
output includes current candidates and unfamiliar observed names, and distinguishes
an exact policy PFN from a name-only match or different publisher family. Missing
protection/type flags remain unknown. Multiple registrations remain visible.
Every row is `Unselected` with `RemovalApproved = false`; a match approves no removal.
An absent registration establishes neither retirement nor successful uninstall.

Historical absent names are included only on explicit request:

```powershell
.\tools\Compare-RideStoreAppInventory.ps1 -InventoryPath .\apps.json -IncludeHistoricalCoverage
```

## Separate provisioning reference

Use an already elevated console for online image provisioning; postpone this
task if elevation is unavailable. Preview performs no DISM query or log/output write:

```powershell
.\tools\Export-RideStoreProvisionedInventory.ps1 -OutputPath .\provisioned-apps.json -WhatIf
.\tools\Export-RideStoreProvisionedInventory.ps1 -OutputPath .\provisioned-apps.json
```

Provisioning is saved as `ProvisionedImage`, separately from `CurrentUser`.
Raw DISM names/version/architecture/resource/region fields are preserved without
guessing package-family identities or current-user registrations. Diagnostics
are written to the explicit sibling `provisioned-apps.json.dism.log`.
The current-user comparison command refuses provisioning data instead of merging
the two scopes. These exports do not remove apps or change image provisioning.

`Microsoft.MSPaint` and the template's `Microsoft.Paint` remain separate. Historical
registration commands are not complete recovery: four v2 third-party removal
entries have no reverse entry, and available manifests do not restore app data.
Dependency/framework, protected/system and utility/recovery entries require
deliberate review before a removal fixture is prepared.

The [current review and historical comparison](migrations/store-app-list-reconciliation.md) and
[joint policy/uninstall review](migrations/store-app-removal-review.md) own pending
template capability. The [accepted app groups](store-app-groups.md) own optional
uninstall/reinstall membership and source/recovery limits. Static policy declarations depend on the
actual serviced template; do not infer a newer schema from a friendly name.
Live inventory, effective policy and actual app lifecycle need applicable native
acceptance. Packages remain paused; reinstall requiring acquisition stays deferred.

Microsoft documents [Get-AppxPackage user scope and package types](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage?view=windowsserver2025-ps).
RIDE queries current-user registrations and does not infer other users or image
provisioning from this result.
