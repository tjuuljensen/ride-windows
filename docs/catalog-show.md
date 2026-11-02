# Catalog inspection

Run these commands from the repository root in Windows PowerShell 5.1 or
PowerShell 7 on Windows. `show` reads catalog metadata and live state through
the relevant handler. It does not install, apply, download or save recovery
state. No recovery step is needed. Access to some observations depends on the
current user's permissions; errors are reported rather than requesting elevation.
Inspection does not establish target support or runtime acceptance.

## Selecting entries

Use a full catalog operation or group ID. Both existing forms remain supported:

```powershell
.\ride.ps1 show package.autopsy
.\ride.ps1 show -Id windows.show-known-extensions
```

Pipeline input can be ID strings or objects with a nonblank string `Id` property:

```powershell
'package.autopsy', 'package.firefox' | .\ride.ps1 show
.\ride.ps1 search autopsy | .\ride.ps1 show
.\ride.ps1 list packages | Where-Object Name -like '*Firefox*' | .\ride.ps1 show
```

`-InputObject <item>` also accepts one such input. Do not combine pipeline input
or `-InputObject` with a positional or named `-Id`, or pipe into an invocation
that already supplies `-InputObject`. Other RIDE commands reject
pipeline input. IDs use the existing case-insensitive catalog lookup; product
shorthand such as `autopsy` is not an alias for `package.autopsy`.

Each input is inspected in order; repeated IDs produce repeated observations.
Empty pipelines return nothing. A missing ID without a pipeline, null/blank
input, an object without a string `Id`, or an unknown ID is an error. Processing
stops at the first error; results already emitted remain available. This is
sequential inspection, not an atomic snapshot of multiple operations.

`-Variant` applies to every selected package; non-package entries reject it.
Use the same `-Library` selection on both discovery and show when inspecting
external library entries. Input objects supply only their ID; show resolves
metadata afresh from its selected catalog. `list profiles` results cannot be
shown because profiles are not operation/group IDs.

Tab completes positional IDs, `-Id`, and string values for `-InputObject` from
the selected catalog, including libraries. Completion remains read-only.

## Output contract: schema 1

Starting with CLI 0.18.0 / engine 0.32.0, each successful selection returns one
PowerShell object with type name `RIDE.ShowResult`, instead of formatting
records. PowerShell displays its properties interactively. Consumers can
select/filter/export before applying `Format-List` or `Format-Table`.

| Stable field | Meaning |
| --- | --- |
| `SchemaVersion` | Integer `1`, identifying this Windows show result contract. |
| `Id`, `Name` | Catalog ID and display name, both strings. |
| `Kind` | Catalog operation kind; groups use `Group`. |
| `CurrentValue`, `CurrentValueType` | Operation-only display strings describing the live observation and its type; the type may be null when unavailable. Display values are not raw registry or installer data. |
| `BaselineValue` | Present where the existing handler declares/projects a baseline. A display string or handler-specific value, not a platform default or saved pre-change state. |
| `Installed` | Boolean package presence observation for package results. |
| `Members` | Group-only ordered array of catalog member ID strings. |
| `MemberStates` | Group-only array of observed members, in declared order. Each row has string `Id`, `Name`, `CurrentValue`, `CurrentValueType`, plus applicable setting presentation metadata. |

Additional catalog and handler-specific properties remain available, including
scope, privilege requirements and policy descriptions. They vary by operation;
they are not a universal machine-readable schema. Ignore unknown properties.
Fields defined above retain their meanings within schema 1; breaking changes
require a new schema version and documented transition. Group rows omit members
that cannot be found in the selected catalog, as the previous display did.
Nested observations do not grant installation or target acceptance.

For groups, inspect the summary or expand the member observations:

```powershell
$group = .\ride.ps1 show solution.rsat-client-tools
$group | Format-List *
$group.MemberStates | Format-List *
```

Choose other group IDs with `.\ride.ps1 list groups`.
Earlier callers that parsed formatting records should consume these properties
instead. The former `ForEach-Object { .\ride.ps1 show $_.Id }` calling syntax
continues to work. Other commands' output contracts are unchanged.

## Filtering and exporting

```powershell
.\ride.ps1 show package.autopsy | Select-Object Id, Name, Installed
.\ride.ps1 list packages | .\ride.ps1 show |
    Where-Object Installed | Select-Object Id, Name, Installed |
    Export-Csv .\installed-packages.csv -NoTypeInformation
.\ride.ps1 show package.autopsy | ConvertTo-Json -Depth 20
```

Only the explicit `Export-Csv` command writes a file. Choose an output path you
intend to create or replace. Select scalar fields for CSV; JSON can preserve
nested group observations. This is a native PowerShell result contract, not a
shared Windows/Fedora JSON schema.
