# RIDE-Windows Script Model

## Purpose and scope

This model defines how maintained PowerShell scripts in RIDE-Windows are
authored, documented, versioned, validated, and operated. It applies to the
command-line runner, tools, bootstrap and maintenance scripts, and scripts used
for tests or disposable VM integration. Repository-specific instructions may
add narrower requirements.

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

Each maintained script begins with a concise English header. Include the
following sections, using spaced comment blocks and the syntax native to the
script:

```text
Purpose:
  Short description of the script's job.

Behavior:
  - Important normal operation and safety behavior.

Compatibility:
  - Supported PowerShell edition/version and Windows targets or constraints.

Usage:
  command [options]

Inputs / environment:
  - Parameters, files, environment variables, and credentials.

Outputs / side effects:
  - Output, files, network calls, Windows changes, and exit behavior.

Prerequisites:
  - Required tools, versions, permissions, and host assumptions.

Author:
  RIDE-Windows maintainers or known first-party author.

Version:
  0.1.0

Changelog:
  - 0.1.0: Initial version.
```

Use PowerShell comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`,
`.EXAMPLE`, and `.NOTES`) where it improves command discovery. Keep the
metadata readable from the top of the file without requiring the reader to
infer the script's target, effects, or prerequisites. Do not add decorative
banners or stale dates.

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
