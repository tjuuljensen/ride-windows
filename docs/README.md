# Documentation

Start with the repository [README](../README.md) for setup and commands. The
[operation catalog](OPERATIONS.md) is generated from catalog metadata and
declares each operation's support, actions, references and recovery limits.

## User and authoring guides

| Subject | Guide |
| --- | --- |
| License review before corporate deployment or paid work | [Important to review licensing](package-licensing.md#important-to-review-licensing), including Npcap and KAPE; [local review records](package-licensing.md#local-usercompany-reviews) |
| Finding operations | [Catalog search](catalog-search.md) |
| Settings and their individual guides | [Windows settings](windows-settings.md), [scope, defaults and recovery](setting-presentation.md) |
| Explicit current-desktop user actions | [Intended-user handoff](intended-user-handoff.md), including pending native acceptance and mixed-profile recovery |
| Existing Terminal default-profile selection | [Native profile workflow](windows-terminal-profile.md), with manual recovery and pending file-editor/GUI acceptance |
| Reviewing built-in Store apps | [Accepted uninstall/reinstall groups](store-app-groups.md), [separate policy workflow](migrations/store-app-removal-review.md), [collected references](migrations/store-app-inventory-review.md), [user/provisioning inventory](store-app-inventory.md) |
| Windows installation with a local account | [Local-account setup](windows-local-account-setup.md) |
| Installed/portable packages and recovery | [Application packages](application-packages.md), [Artcraft packages](artcraft-packages.md) |
| Downloads and provenance | [Package verification](package-verification-matrix.md), [GitHub release discovery](github-release-discovery.md) |
| Custom catalogs and profiles | [Custom libraries](custom-libraries.md), [examples](../examples/README.md) |
| Desktop helpers | [God Mode folder](god-mode.md), [screen-lock helpers](screen-lock-helpers.md) |
| Disposable Windows validation | [Integration scenarios](../tests/integration/README.md), [AutomatedLab provisioning](../tests/integration/automatedlab.md), [task controller](../tests/integration/automatedlab-tasks.md) |
| Workflow diagrams | [Controller workflow](../tests/integration/automatedlab-tasks.md#controller-workflow), [GitHub cache and backoff](github-release-discovery.md#cache-and-backoff-flow) |
| Maintainer conventions | [Script model](models/script-repository-model.md), [documentation model](models/documentation-model.md), [configuration ownership](decisions/0001-configuration-ownership.md) |

## Active work and evidence

- [Task list](../TODO.md): priorities and future work.
- [Migration plan](MIGRATION-PLAN.md): current legacy outcome estimates and
  release acceptance, including documentation and licensing requirements.
- [Controller and GitHub bridge RC resumption](migrations/controller-certification.md#resume-near-v3-release-candidate): accepted source boundaries, deferred certification and safe restart procedure.
- [Settings implementation handoff](migrations/settings-implementation-handoff.md),
  [remaining decisions](migrations/remaining-settings-decisions.md) and
  [settings review ledger](migrations/settings-post-migration-review.md): open
  decisions and feature acceptance.
- [Remaining settings plan and questions](migrations/remaining-settings-plan.md):
  complete remainder triage, recommended first batch, decision IDs and deferred
  interactive or test-resource work.
- [Application review](migrations/application-migration-review.md) and
  [review rounds](migrations/application-review-rounds-2026-10-12.md): product
  choices and outstanding deployment/runtime acceptance.
- [Candidate tools](candidate-tools.md): proposals, not an installation promise.
- [Screen-lock evaluation](screen-lock-impact.md): current findings, procedure
  and unresolved measurement acceptance.
- [Archive](archive/README.md): dated evidence and superseded planning context.
  Archive placement does not change an operation's acceptance or support.
