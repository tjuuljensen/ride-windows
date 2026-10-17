# Documentation model

This is the RIDE-specific application of the shared
[repository documentation model](https://github.com/tjuuljensen/network-devices/blob/master/docs/repository-portfolio/repository-documentation-model.md).
The shared model owns portfolio policy; this document owns RIDE-specific
application and exceptions. It complements the [local script model](script-repository-model.md)
and the shared [language](https://github.com/tjuuljensen/network-devices/blob/master/docs/repository-portfolio/repository-language-model.md)
and [deployment](https://github.com/tjuuljensen/network-devices/blob/master/docs/repository-portfolio/deployment-model.md)
models. Keep these local additions in `docs/models/`; do not copy portfolio
governance into another `docs/repository-portfolio/` tree.

Alignment baseline: network-devices [`f0e118b`](https://github.com/tjuuljensen/network-devices/commit/f0e118bf3b33df5ef474c608a2490af8f843481b),
reviewed 2026-10-15. This incorporates the October 13 phased-migration contract
and October 15 audience and reusable-header refinements. Shared policy links
above remain canonical for subsequent reviews.

## Audience and supported behavior

Apply the shared [audience rule](https://github.com/tjuuljensen/network-devices/blob/master/docs/repository-portfolio/repository-documentation-model.md#separate-user-guidance-from-maintainer-guidance)
to root and component READMEs, installation guides, examples and reusable
script/configuration headers. Explain what users can install or operate,
requirements, configuration, supported commands, limitations and material
effects. Do not assume the reader knows a development conversation.

Keep editing ownership, publication/synchronization procedures, repository
organization explanations and development history in maintainer guidance,
architecture, decisions, registers, runbooks or migration ledgers. A concise
README link can direct contributors there. Renaming an internal checkout to
"the source repository" does not make unnecessary maintenance prose relevant
to users; omit it rather than anonymizing it.

Preserve RIDE's identity, working public release/download/import links, useful
dependency links, known authors and required upstream attribution or license
notices. Include maintenance constraints when they affect the reader's task.
For example, elevation and state-record locations affect an operator; where
future source fixes belong is a maintainer concern. Describe resulting behavior
and retain meaningful user-facing changelog entries without session narratives.
Do not apply blanket replacements to URLs, commands or external identifiers.

Update generated or copied headers at their authoritative source and use the
existing generator or release workflow. Before publication, review the audience
relevance of docs and embedded headers for every selected entry, including
standalone tools and examples. Retain applicable secret/protected-content
checks and upstream notices; a wording review does not replace them.

## Names and locations

| Document role | Convention |
| --- | --- |
| Repository or directory entry point | `README.md` |
| Contributor/automation instructions | `AGENTS.md`, `CONTRIBUTING.md` |
| Standard repository documents, when needed | `ARCHITECTURE.md`, `CHANGELOG.md`, `SECURITY.md`, `LICENSE` |
| Existing root task list | `TODO.md`; one backlog, without a duplicate roadmap |
| Topic guides | Lowercase kebab-case, such as `package-licensing.md`, `service-settings.md` |
| Directories and decisions | Lowercase, such as `docs/models/` and `docs/decisions/0001-configuration-ownership.md` |
| Dated evidence | Descriptive lowercase name with a date under `docs/archive/`; keep original report names when moving existing evidence |

Reserved names describe a document's role, not its importance. Do not create
empty standard documents just to fill the list. Keep README concise and link to
the [documentation index](../README.md) for detailed guides.

Existing topic guides may remain directly under `docs/`. When grouping new
material improves navigation, use `docs/architecture/` for system boundaries,
`docs/reference/` for technical reference, `docs/runbooks/` for procedures and
`docs/registers/` for current ownership/provenance/lifecycle records. Keep
decisions in `docs/decisions/`, active migration work in `docs/migrations/` and
local models in `docs/models/`. Use component-local READMEs for independently
usable components. Introduce only directories with useful content; avoid
cosmetic moves or a parallel document for an already-owned subject.

Two existing path contracts are explicit exceptions: `docs/MIGRATION-PLAN.md`
is referenced by migration tracking instructions, and `docs/OPERATIONS.md` is
the generated catalog used by validation and its LF attribute. Keep these paths
until their instructions, generator, validation, attributes and inbound links
can be changed together. These exceptions do not set a pattern for new guides.
Externally owned files and historical source under `legacy/` retain their names.

For a rename, inspect inbound links and script consumers, update exact casing,
and check local links. Use an intermediate filename for case-only renames on
Windows. External bookmarks cannot be updated by a repository edit; list moved
paths in the change description. Do not change Git's global line-ending settings.

## Paths, examples and operational procedures

Use forward slashes and exact filename casing in repository-relative prose and
Markdown links. Prefer relative links within RIDE and canonical HTTPS links to
external sources. Avoid personal checkout paths; define placeholders such as
`<repo-root>` and `<version>`. Use native Windows paths and shell-specific
quoting in commands and runtime paths, with accurate `powershell` or `cmd`
fence labels. State the required working directory and execution host.

An installation, update, maintenance or recovery procedure must state:

- its task, scope, supported Windows targets and PowerShell versions;
- prerequisites, inputs, credentials boundary, elevation and current-user context;
- artifact source, selected version and integrity checks where applicable;
- effects on files, packages, settings and saved state before mutating commands;
- expected state, verification and checks requiring a disposable Windows VM;
- removal and recovery, including any unsupported or manual lifecycle steps.

Show read-only inspection, plan or `-WhatIf` before application where supported.
Do not invent commands to complete a procedure. Keep secrets and personal
identifiers out of examples, label conceptual commands and illustrative output,
and link to authoritative script help rather than repeating parameter tables.

RIDE operations target Windows. Record support per operation and distinguish
Windows 11 from declared Windows Server targets and applicable PowerShell
editions. Linux/WSL syntax results do not establish support. Link dated runtime
evidence and retain pending acceptance explicitly; parser and mocked tests do
not prove installation, permissions or user-visible behavior.

Keep download, installation, publication, activation and maintenance distinct.
For bootstrap/release workflows, identify source, transport, validation,
activation, trigger, health check, secrets boundary and recovery using the
existing RIDE workflow. Downloading a tagged release is not applying a profile.
Restoring captured state, applying a documented baseline and uninstalling a
package are different operations; describe their actual recovery limits.

## Text and accessibility

Use English technical prose and UTF-8 by default. Preserve meaningful Unicode,
official names, localized content and upstream notices; fix actual corruption
without stripping valid characters. Prefer ASCII punctuation in new technical
prose. Document encoding exceptions required by consumers and follow
`.gitattributes` independently for line endings. Inspect `git ls-files --eol`
before editing; do not change global Git settings or broadly renormalize files.

Pair status icons with text and provide useful alternative text or an adjacent
explanation for diagrams and images.

## One authoritative document per subject

Put supported behavior, prerequisites, commands, recovery and current limitations
in topic guides. Use present-tense, task-oriented headings. A guide may identify
pending acceptance and link to evidence, but should not repeat session narratives,
old test totals, estimate changes or claims about the agent's current VM state.
Keep schema/data migration instructions when they are needed for real recovery;
the word "migration" is appropriate there.

`TODO.md` owns actionable priorities. `MIGRATION-PLAN.md` owns legacy outcome
counts, release requirements and the current migration overview. Active
`docs/migrations/` ledgers own unresolved decisions and acceptance. Do not count
new documents or catalog IDs as completed legacy outcomes.

Archive completed or superseded run reports under `docs/archive/migrations/`,
and measurement history under `docs/archive/evidence/`. Preserve dates, failed
results, scope limits, source links and recovery evidence. Add an archive index
and update inbound and relative links. Archiving a report does not close an
open acceptance item: leave a pointer in the active ledger or evaluation guide.
Do not archive an active decision ledger merely because it is long or dated.

Before release, refresh the corporate licensing review list, verify that README
links to it, reconcile active acceptance, and archive further evidence only once
its remaining work has an explicit current owner/document. Keep the licensing
list public and descriptive; organization-specific approvals stay in the local
license review store.

## Phased migration delivery

Apply the [shared batch contract](https://github.com/tjuuljensen/network-devices/blob/master/docs/repository-portfolio/repository-documentation-model.md#multi-step-migration-delivery)
to work spanning multiple batches or verification windows. Ordinary isolated
edits outside an active migration do not require a new migration plan. Existing
migration runs still follow the tracking requirements in `AGENTS.md`.

Use [MIGRATION-PLAN.md](../MIGRATION-PLAN.md) and its existing linked ledgers as
the persistent handoff. Provide a plain-language operator procedure alongside
the technical mapping; a backlog alone is insufficient:

1. Select named legacy outcomes or one related feature, with scope, dependencies
   and deferred work. Prefer a small pilot before broader batches.
2. Assess the authoritative source, current/proposed mapping, consumers,
   compatibility, state to preserve and recovery. Identify missing evidence.
3. Implement and validate a focused source patch and necessary consumer updates.
   Review the diff and record source readiness and activation requirements.
4. Activate only within the authorized scope and through the existing workflow.
   Record the target/revision and recovery path. Real Windows integration work
   requires a disposable VM, never the developer workstation.
5. Verify explicit acceptance criteria, including user-visible behavior,
   idempotence, preserved state and recovery as applicable. Record dated results
   and owner observations still needed, separately from static validation.
6. Close verified outcomes or record failure and authorized recovery. Refresh the
   migration overview and ledgers as required by [AGENTS.md](../../AGENTS.md#migration-progress-tracking),
   and provide a concrete next action with any necessary owner steps.

Each batch record identifies source/owner, mappings, consumers, state constraints,
acceptance, recovery, status, revision when available, dated evidence and the
next action. Preserve established status vocabulary while distinguishing source
readiness, activation awaiting verification and verified behavior. Exceptions
need an owner, reason and review condition. Preserve recovery material while
consumers or pending checks still depend on it. For work without a runtime, use
artifact or consumer acceptance instead of inventing deployment steps.

Continue authorized work without mandatory approval pauses between stages.
Prepare a concrete reviewable result before seeking missing authorization;
explain the applicable boundary and do not ask again for unchanged scope.
Design approval does not authorize every future runtime mutation or deletion.
If ownership, consumers or recovery are unclear, keep that object at read-only
assessment and continue independent authorized work. The handoff must name
what can happen next and what evidence is missing, not require another prompt
for work already authorized.

## Review checklist

Before finalizing a documentation change, check audience and authoritative
ownership, exact paths and link fragments, shell syntax and starting directory,
supported-target evidence, prerequisites and effects, recovery, Unicode and line
endings. Update docs with the behavior they describe, remove duplicate guidance
or label it historical, and review the complete focused diff. Use local link
checks and `git diff --check` for documentation-only edits; runtime checks are
needed when behavior changes, not to validate prose.

Document exceptions with reason, scope, owner and a review/replacement condition
when temporary. The RIDE maintainers own the existing path exceptions above;
their replacement condition is coordinated migration of all consumers.
