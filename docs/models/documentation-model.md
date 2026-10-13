# Documentation model

This is the RIDE-specific application of the shared
[repository documentation model](https://github.com/tjuuljensen/network-devices/blob/master/docs/repository-portfolio/repository-documentation-model.md).
That model recommends lowercase kebab-case for topic filenames; it does not
require uppercase names for all documentation.

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
