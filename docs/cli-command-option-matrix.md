# CLI command and option matrix

Reviewed: 2026-11-01. This matrix describes the current PowerShell CLI in
`ride.ps1`; it does not grant new behavior or change published syntax. See
`docs/models/ride-behavior-contract.md` RB-01, RB-02, RB-03, RB-04, RB-05,
RB-06 and RB-08 for the shared v3 target.

## Commands

| Command | Current selector and default | Current behavior |
| --- | --- | --- |
| `list` | Optional positional `Id` as a view; defaults to `all` | Read-only catalog discovery. |
| `search` | Positional query through `Id`, or `-Query`; not both | `-Field` and `-View` narrow literal search. Rejects profile, state, run ID, destination and ShouldProcess switches. |
| `show` | Required operation/group ID | Displays live metadata/state. `-Variant` is accepted for packages. |
| `plan` | `-Profile`, default profile if omitted | Read-only plan for the selected profile. |
| `apply` | `-Profile`, default profile if omitted | Applies the selected profile. |
| `download` | Required package/artifact ID | Acquires the declared payload without installing. `-Variant`, `-Destination` and GitHub authentication are supported. |
| `install` | Required package/component ID | Installs one package or Windows capability. `-Variant` and GitHub authentication are supported. |
| `set` | Required setting ID and `-State` | Applies one declared setting state. `-Profile` is rejected. |
| `unset` | Required setting ID | Uses the operation's declared override-removal semantics. `-Profile` is rejected. |
| `status` | Optional positional `Id` as a view; defaults to `all` | Shows defaults/live state, or profile comparison only when `-Profile` is explicit. |
| `restore` | Required `-RunId` | Restores captured prior state. GitHub authentication may be supplied for release discovery. |
| `remove` | Optional package/component ID; otherwise uses `-Profile` or the default profile | Direct ID and explicit profile are mutually exclusive. Profile removal includes packages, Windows capabilities and Defender exclusions; it does not reset ordinary settings. Direct Defender exclusion removal is rejected by the engine; use `unset <id>`. A bare `remove` still falls back to the default profile for compatibility. |
| `prune-state` | Optional `-StateScope` and `-OlderThanDays` | Previews/removes old completed recovery records. Other selectors are rejected. |

## Option gates

| Option | Accepted commands / requirements | Current guard or known gap |
| --- | --- | --- |
| `-Id` | View for `list`/`status`; query for positional `search`; required selector for direct actions | `remove` without ID falls back to a profile. Other irrelevant `-Id` uses are not uniformly rejected. |
| `-Query`, `-Field`, `-View` | `search` | Rejected on other commands; named and positional search query cannot be combined. |
| `-Profile` | `plan`, `apply`, `status`, profile-based `remove`; profile defaults apply to `plan`, `apply` and `remove` | Direct install/download/set/unset reject it; remove rejects combining it with an ID. It is currently ignored on some other commands. |
| `-State` | `set`; required by `set` | It is currently ignored on some other commands. |
| `-RunId` | `restore`; required by `restore` | It is currently ignored on some other commands. |
| `-Variant` | `install`, `remove`, `download`, `show`; requires an ID | Rejected elsewhere. The engine checks that the ID is a package and that the variant is declared. |
| `-Destination` | `download` | Search and desktop handoff reject it; other irrelevant uses are not uniformly rejected. |
| `-AllowCandidate` | `apply`, `install`, `set`, `unset`, `remove`, `restore` | Rejected on discovery, `plan`, `status`, `download` and `prune-state`. It does not widen target, privilege or support. |
| `-StateScope`, `-OlderThanDays` | `prune-state` | Rejected elsewhere. Machine records require elevation. |
| `-UserContext Desktop` | `set`, `unset`, `apply`, `plan`, `restore` | Requires the supported user-only handoff shape. Direct set/unset reject profile; GitHub auth, destination and variant are rejected. |
| GitHub authentication options | `download`, `install`, `apply`, `restore` | `PAT` requires `-GitHubCredentialReference`; `Anonymous` forbids it. |
| Offline bundle options | `install`, `apply`; `-OfflineBundle`, `-OfflineProfileId`, `-OfflineCatalogFileId` are required together | Rejects libraries, desktop handoff and GitHub authentication. No network fallback. |
| `-WhatIf`, `-Confirm` | Automatic `CmdletBinding` options | Search rejects both. Read-only commands currently accept them without a meaningful preview contract. |
| `-Help`, `-Version` | Early-return switches | They return before operational work; irrelevant options supplied with them are not validated. |
| `-Library` | Catalog-consuming commands | Selects explicit local metadata libraries. Offline execution and desktop handoff have narrower rules. |

## ALIGN-03 current gap

The existing focused tests cover several early refusals and ShouldProcess
forwarding. The parser does not yet reject every irrelevant option before
catalog/handler access. The default-profile fallback for bare `remove` remains
published compatibility behavior and needs a declared transition before it can
be removed. Help must describe that profile removal includes Defender exclusions,
and direct exclusion removal must continue to use `unset` unless the catalog and
engine contract change together.

No runtime validation or removal semantics change in this review batch.
