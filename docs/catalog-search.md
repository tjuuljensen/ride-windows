# Search the operation library

`search` discovers catalog operations, packages, standalone artifacts and groups.
It reads metadata without loading the operational engine, querying live Windows
state, requiring elevation, downloading payloads or creating state records.
Use `show <id>` to inspect a result's current state.

```powershell
.\ride.ps1 search desktop-folder
.\ride.ps1 search 'File Explorer'
.\ride.ps1 search 'Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\'
.\ride.ps1 search -Query ThisPCPolicy -Field ValueName -View explorer
.\ride.ps1 search desktop -Field Name,Description -View settings
```

Matching uses a case-insensitive literal substring with ordinal comparison.
A query is one phrase, including its spaces; quote phrases and paths. Backslashes
need no doubling. Wildcards and regex punctuation are literal. Regex support is
planned in the [roadmap](../TODO.md), and `-Regex` is not currently supported.
Missing, empty or whitespace-only queries are errors. No matches returns an empty
object collection. Supply either a positional query or `-Query`, not both.

## Fields and views

By default, search examines all fields below. `-Field` accepts one or more names,
ignores field-name case and duplicates, and matches when any selected field
contains the query. Values are searched separately; phrases never span fields
or adjacent registry locations.

| Field | Catalog metadata searched |
| --- | --- |
| `Id` | Published operation or group ID. |
| `Name` | User-facing name. |
| `Description` | Explanation, limitations and side effects. |
| `Category` | Catalog category. |
| `RegistryPath` | `RegistryPath`, each `RegistryPaths` entry and each nested `RegistryValues[].RegistryPath`. |
| `ValueName` | `ValueName`, each `ValueNames` entry and each nested `RegistryValues[].ValueName`. |
| `ResourceId` | `PackageId`, `ArtifactId`, `ServiceName`, `PowerSettingGuid`, `PowerSubgroupGuid`, `BcdElement`, `FolderName`, `TaskPath`, `TaskName`, `ComponentId`, `ComponentIds`, `PreferenceName`, `Preference`, `Protocol`, `SchemeGuid`. |

The field map in `modules/RIDE.Discovery.psm1` is shared by matching, validation
and field completion. URLs, installer arguments, defaults, migration notes,
legacy selectors and profile contents are outside this search contract.

`-View` defaults to `all`. It shares list's catalog view selection: `packages`,
`artifacts`, `groups`, `settings` and catalog categories such as `windows`,
`explorer`, `security` or `software`. Category names containing spaces are also
accepted with hyphens, such as `windows-settings`. Search excludes profile files
and rejects the `profiles` view. Valid views with no matches return no objects;
unknown fields or views are errors.

Search covers the catalog independently of the current Windows target. Results
retain `SupportedTargets`, full descriptions and experimental wording. Discovery
does not establish that an operation is suitable or verified for your machine.

Press Tab to complete `search`, positional or named query ID suggestions, field
names, and views/categories. Completion reads bounded catalog data and fails
quietly if optional data is unavailable.

## Results and pipelines

Interactive results display `Id`, `Name`, `Kind` and `MatchedFields`. Each result
is a PowerShell object with the same catalog properties used by `list`, plus:

- `MatchedFields`: canonical fields that matched, in field-contract order.
- `Matches`: objects containing `Field`, `Source` and the full matching `Value`.
  For example, `Source` can be `RegistryValues[1].RegistryPath`.

Each entry appears once even if several fields or values match. Results sort by
type, category, name and ID. Full values remain available without display
truncation or formatting records in the pipeline:

```powershell
.\ride.ps1 search desktop-folder | Select-Object Id,Name,SupportedTargets
.\ride.ps1 search ThisPCPolicy -Field ValueName | ForEach-Object { $_.Matches }
.\ride.ps1 search 'File Explorer' | Format-List *
.\ride.ps1 search Explorer -View settings | Export-Csv .\matches.csv -NoTypeInformation
```

`-Query`, `-Field` and `-View` belong to search. Search rejects profile and action
parameters (`-Profile`, `-State`, `-RunId`, `-Destination`, `-WhatIf`, `-Confirm`)
instead of silently ignoring them. Existing commands retain positional ID and
state binding. The data-only module also exports `Find-RideCatalog` for callers
that need a custom literal `-CatalogPath`.
