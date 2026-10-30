# Documentation

Start with the repository [README](../README.md) for setup and commands. The
[operation catalog](OPERATIONS.md) is generated from catalog metadata and
declares each operation's support, actions, references and recovery limits.

## User and authoring guides

| Subject | Guide |
| --- | --- |
| License review before corporate deployment or paid work | [Important to review licensing](package-licensing.md#important-to-review-licensing), including Npcap and KAPE; [local review records](package-licensing.md#local-usercompany-reviews) |
| Finding operations | [Catalog search](catalog-search.md) |
| Read-only profile reference for observation consumers | [Desired-configuration export](desired-configuration-reference.md), with explicit target inputs and pending consumer acceptance |
| Offline installation source preparation | [Offline bundle preflight](offline-bundles.md), accepted version/omission rules and pending assembly/install integration |
| Settings and their individual guides | [Windows settings](windows-settings.md), [scope, defaults and recovery](setting-presentation.md) |
| Explicit current-desktop user actions | [Intended-user handoff](intended-user-handoff.md), including pending native acceptance and mixed-profile recovery |
| Existing Terminal default-profile selection | [Native profile workflow](windows-terminal-profile.md), with manual recovery and pending writer/GUI acceptance; [JSONC preparation API](terminal-jsonc-preparation.md) for supplied bytes only |
| BitLocker enrollment and recovery | [Enrollment, decryption, recovery-key backup and retrieval](bitlocker-recovery.md); catalog workflows and the desktop shortcut remain pending Windows 11 disposable-target acceptance |
| Reviewing built-in Store apps | [Accepted uninstall/reinstall groups](store-app-groups.md), [separate policy workflow](migrations/store-app-removal-review.md), [collected references](migrations/store-app-inventory-review.md), [user/provisioning inventory](store-app-inventory.md) |
| Inspecting Windows component availability | [Read-only feature, capability and Server role inventory](windows-component-inventory.md), with explicit target identity and pending native acceptance |
| Inspecting network adapter identities | [Read-only adapter inventory](network-adapter-inventory.md), with GUID-only saved lookup and pending native collection acceptance |
| Inspecting stored Wi-Fi profile identities | [Read-only wireless profile inventory](wireless-profile-inventory.md), with interface GUIDs, exact names/order/flags and no XML/key retrieval |
| Inspecting volume identities | [Read-only volume inventory](volume-inventory.md), with saved GUID-path lookup and pending native collection acceptance |
| Inspecting local account identities | [Read-only local user inventory](local-user-inventory.md), with saved SID lookup; membership, credentials and account changes remain separate |
| Inspecting the intended user's language list and regional state | [Read-only ordered language inventory](user-language-inventory.md), separate display/input overrides and [explicit regional providers](user-language-inventory.md#observe-regional-providers-separately) with process/user/machine scope |
| Inspecting and preparing intended-user proxy options | [Default/LAN observation and in-memory edit preparation](user-proxy-inventory.md), preserving manual/PAC values with conflict-aware recovery; live writes remain unimplemented |
| Windows installation with a local account | [Local-account setup](windows-local-account-setup.md) |
| Installed/portable packages and recovery | [Application packages](application-packages.md), [Artcraft packages](artcraft-packages.md) |
| Other Windows app installers | [Ninite package comparison](ninite-package-comparison.md), including catalog overlap, pending reviews and optional bundled offers |
| Downloads and provenance | [Package verification](package-verification-matrix.md), [GitHub release discovery](github-release-discovery.md) |
| Custom catalogs and profiles | [Custom libraries](custom-libraries.md), [examples](../examples/README.md) |
| Desktop helpers | [God Mode folder](god-mode.md), [screen-lock helpers](screen-lock-helpers.md) |
| Disposable Windows validation | [Integration scenarios](../tests/integration/README.md), [AutomatedLab provisioning](../tests/integration/automatedlab.md), [task controller](../tests/integration/automatedlab-tasks.md) |
| Physical Lenovo T480 acceptance | [T480 RIDE test plan](test-plans/t480-ride-acceptance.md) and [read-only preflight script](../tests/integration/Invoke-RideT480Preflight.ps1) |
| Workflow diagrams | [Controller workflow](../tests/integration/automatedlab-tasks.md#controller-workflow), [GitHub cache and backoff](github-release-discovery.md#anonymous-cache-and-backoff-flow) |
| Maintainer conventions | [Script model](models/script-repository-model.md), [documentation model](models/documentation-model.md), [configuration ownership](decisions/0001-configuration-ownership.md) |

## Active work and evidence

- [Task list](../TODO.md): priorities and future work.
- [Migration plan](MIGRATION-PLAN.md): current legacy outcome estimates and
  release acceptance, including documentation and licensing requirements.
- [Full remaining migration analysis and decisions](migrations/remaining-migrations-follow-up.md):
  all five groups, matching implementation batches, questions for the user's
  return and postponed elevation; includes the source coverage audit.
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
