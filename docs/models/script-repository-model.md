# RIDE-Windows Script Model

## Purpose and scope

This model defines how maintained PowerShell scripts in RIDE-Windows are
authored, documented, versioned, validated, and operated. It applies to the
command-line runner, tools, bootstrap and maintenance scripts, and scripts used
for tests or disposable VM integration. Repository-specific instructions may
add narrower requirements.

This is the RIDE-specific implementation of the
[shared script model](https://github.com/tjuuljensen/network-devices/blob/master/docs/repository-portfolio/script-repository-model.md).
The shared model is authoritative for portfolio policy; this document owns
RIDE-specific requirements. Repository models belong in `docs/models/`.
`docs/repository-portfolio/` is reserved for portfolio governance in
network-devices.

Generated files identify their generator, and vendor or legacy scripts retain
their applicable upstream metadata and license notices. Scratch files are not
maintained scripts and should remain outside the repository or clearly marked
as temporary.

## Ownership and source of truth

- Every maintained script has one authoritative repository path.
- The owning repository is responsible for behavior, versioning, validation,
  and operational documentation.
- Scripts that call another repository, runtime, or service must identify that
  boundary in the header or a linked runbook.
- Do not edit generated or copied release outputs directly when a source and
  generation or publication workflow exists.

## Header contract

Each maintained `.ps1` script begins with English PowerShell comment-based
help in a `<# ... #>` block. Use recognized help keywords so `Get-Help` can
discover the content. A generic `Purpose:`, `Usage:`, or shell-style banner
does not satisfy this contract.

Map the required information to native help sections:

- `.SYNOPSIS`: purpose.
- `.DESCRIPTION`: behavior, safety, and material side effects.
- `.PARAMETER <name>`: each declared parameter, defaults, and constraints.
- `.EXAMPLE`: actual supported commands and important options.
- `.INPUTS` and `.OUTPUTS`: pipeline input and returned object types; these
  sections do not describe arbitrary files or environment variables.
- `.NOTES`: compatibility, prerequisites, file/environment inputs, ownership,
  upstream attribution and license where applicable, version, and changelog.
- `.LINK`: related authoritative documentation or runbooks where useful.

The following is an illustrative header template. Replace the explanatory
text with verified behavior and parameter names before using it in a script.

```powershell
<#
.SYNOPSIS
  Describe the script's purpose.

.DESCRIPTION
  Describe its behavior, safety boundaries, and material side effects.

.PARAMETER Path
  Describe the actual parameter, its default, and validation constraints.

.EXAMPLE
  .\Example.ps1 -Path .
  Explain what this supported invocation does.

.INPUTS
  None. Replace with the accepted pipeline types when applicable.

.OUTPUTS
  Describe the returned object types, or None when no objects are returned.

.NOTES
  Compatibility: Verified PowerShell editions/versions and Windows targets.
  Prerequisites: Required tools, permissions, and host assumptions.
  File/environment inputs: Required files, variables, and credential sources.
  Recovery: Relevant state restore or disposable VM checkpoint boundary.
  Author: Known first-party author or RIDE-Windows maintainers.
  Version: Current semantic version from the script's version constant.
  Changelog: Concise entries for established versions and contract changes.

.LINK
  docs/models/script-repository-model.md
#>
```

Put adapted-code source and license notes in `.NOTES` and preserve existing
notices. Do not invent author names, version history, or compatibility claims.
Use blank lines between help sections. Script help precedes executable code;
if a function declaration is the first statement, leave at least two blank
lines after the script help to avoid associating it with that function.

Modules (`.psm1`) have a top-level overview and native comment-based help on
exported commands. Data files (`.psd1`) retain valid data-file syntax and a
concise ownership/purpose comment; do not invent a CLI or script help for them.
Generated, vendored, and historical files retain applicable source notices and
have explicit exceptions recorded during review.

Follow Microsoft's
[comment-based help reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_comment_based_help)
for keyword semantics and placement. Keep headers readable and concise without
decorative banners or stale dates.

Headers must describe the current implementation. Update them when parameters,
compatibility, prerequisites, output, or side effects change. Put detailed
procedures in a runbook and link to it.

## Versioning

Maintained scripts use semantic versions (`MAJOR.MINOR.PATCH`). Use `0.x.y`
while the interface or behavior is experimental, and `1.0.0` when its first
supported contract is established.

- Keep one script-level version constant in the implementation and repeat it
  in the header and changelog.
- Standalone command-line scripts expose a `-Version` switch whose output uses
  that same constant. Do not add a version command to sourced snippets or
  scripts that are only consumed by another script.
- Increment the version when behavior, inputs, outputs, compatibility, or
  operational contracts change. Header-only corrections do not require an
  increment unless they record a meaningful contract change.
- Keep any synchronized script copies on the same version.

## Language and style

- Write headers, comments, help text, identifiers, and technical documentation
  in English. Preserve official product names and external identifiers.
- Use `[CmdletBinding()]` for reusable command-line scripts and set
  `$ErrorActionPreference = 'Stop'` for operational paths unless an exception
  is deliberate and documented.
- Quote paths, validate external input, and use `-LiteralPath` when a value is
  a filesystem path.
- Keep completion and discovery code read-only; do not load the operational
  engine or inspect mutable Windows state to generate suggestions.
- Follow `.gitattributes` and inspect `git ls-files --eol` before changing
  tracked text. Preserve the repository's line-ending policy.

## Safety and operational behavior

- Prefer read-only inspection by default. State-changing scripts must make
  their target and effects clear and support `ShouldProcess` when applicable.
- Validate paths and targets before writing or deleting. Avoid broad or
  unresolved destructive targets.
- Prefer idempotent operations and report partial failures clearly.
- Keep credentials out of arguments, logs, source, and generated reports.
- Scripts that change Windows state run only on declared supported Windows
  targets. Integration scripts require disposable VMs; do not use a developer
  workstation as an integration-test target.
- Document recovery boundaries, such as RIDE state restore or a clean VM
  checkpoint, in the header or linked runbook.

## Validation

Use Windows PowerShell or PowerShell 7 on Windows for RIDE runtime checks.
Run the narrowest relevant validation for a script change:

- Parse edited PowerShell scripts with the PowerShell language parser.
- Run `-Help` and `-Version` smoke checks for standalone command-line scripts
  when they can be run safely without changing system state.
- Inspect `Get-Help <script-path> -Full` and `-Examples` to verify that native
  help exposes the synopsis, parameters, examples, and notes correctly. For
  modules, use an isolated session or mocked harness if importing them could
  change state; inspect each exported command's help there.
- Use Pester for mocked behavior and disposable Windows VMs for real system
  integration. Never infer Windows support from Linux or WSL results.
- Use `git diff --check` for whitespace and encoding-related issues.

Static checks do not prove runtime availability, permissions, network access,
or Windows state behavior. State those limits clearly.

## Exceptions and review

An exception must state its reason and intended replacement or review point
when it is temporary. Generated files identify their generator; upstream files
retain their source attribution and license. Legacy scripts may be addressed
as focused maintenance work rather than receiving unrelated changes.

For each new or materially changed script, review whether its purpose, usage,
compatibility, inputs, effects, prerequisites, ownership, version, and
validation are clear and current.
