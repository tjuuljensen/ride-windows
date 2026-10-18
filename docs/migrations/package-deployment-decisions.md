# Package deployment and acquisition toolkit decisions

Approved by the user on 2026-10-14. Design approved; deployment coexistence and
host-folder toolkit publication remain unimplemented. Package implementation
continues under the direct continuation instruction; the expired overnight
automation remains paused. See the [current handoff](remaining-migrations-follow-up.md#archive-handoff-and-closure-order-2026-10-17).
Q01-Q04 are accepted; durable integration and runtime acceptance remain open.

The [full migration follow-up](remaining-migrations-follow-up.md#questions-for-the-users-return)
records accepted Q01-Q04 deployment, adoption and host-folder publication choices.
This document remains the authority for the approved coexistence model.

## Approved deployment model

Analysts may need an application installed on their workstation and a portable
edition of the same product for forensic acquisition USBs or similar kits.
Keep one stable product ID with supported distributions beneath it. Offer these
independent workflows where product-specific validation permits them:

| Workflow | Purpose |
| --- | --- |
| Install on this machine | Workstation use with the application's declared Windows integration. |
| Deploy portable copy | Maintain a separate portable edition in a chosen directory. |
| Build acquisition USB/toolkit | Assemble selected reviewed portable tools into a reproducible kit. |

An installed application, a local portable copy and multiple kits may coexist.
Each deployment retains separate ownership, distribution, scope, destination,
version, artifact evidence and recovery records. Updating or removing one
deployment affects only that deployment. Existing product defaults remain;
choosing a portable deployment does not implicitly replace an installed edition.

This supersedes the general design rule that installed and portable editions
must be mutually exclusive. Conflict checks still apply to paths, registrations,
services, drivers and shared configuration. Products need explicit coexistence
review before this capability is enabled. Replacing an existing deployment
remains an explicit migration with configuration and integration accounted for.

The current implementation still refuses conflicting editions and uses its
existing saved selection. The [application guide](../application-packages.md)
describes that behavior; this decision adds no command, catalog entry, target
support or automatic selection.

## Shared installers and licence tiers

Accepted 2026-10-17: model one package when free, paid or feature-tier editions
use the same installer and installed application. Licence keys, subscriptions
and accounts that unlock features do not alone justify separate variants.
Create variants only for verified differences in artifacts, installed components
or deployment behavior. Distinct products and reviewed installed/portable choices
remain distinct where their deployment differs.

Installation, adoption, updates and removal are separate from optional explicit
activation through publisher-supported methods. Preserve existing settings and
activation; do not require tier selection for shared installation, initiate a
trial, or upgrade a subscription implicitly. Startup and integrations remain
independent choices. Per-product artifact equivalence and activation preservation
need evidence. This supersedes earlier mandatory entitlement-selection wording;
see the [accepted rule](decision-session-2026-10-17.md#shared-installers-and-licence-tiers)
and [local licensing/publication boundaries](../package-licensing.md).

## Explicit identity and adoption decisions, 2026-10-17

The [decision session](decision-session-2026-10-17.md) records the user's acceptance:
each deployment has an explicit stable name/ID, and ambiguous product-only changes
must require that selection. Inspection shows separate copies. Names discussed
were examples; final main-command/profile spelling and kit-member schema remain
implementation work. The in-memory [identity API](../application-packages.md#named-deployment-identity-preparation)
now prepares/inspects/selects those identities; it has no live state-store integration.

Existing installations must be adoptable for supported future management without
requiring removal or replacement first. Also offer explicit replacement of selected
existing content/installations. First-run discovery should present supported
existing installations for bulk adoption selection; ambiguous matches are resolved
individually without blocking unrelated identified selections. Adoption preserves
the installation and does not implicitly update or replace it. Blanket collision
refusal without a future adoption/replacement route does not meet this requirement.

Detailed ownership, inventory presentation, backup/recovery guarantees and product
exceptions require implementation/validation. Recognizing one executable cannot
establish ownership of an entire shared folder. Adoption cannot reconstruct
pre-installation state or undo historical installation changes. Current collision
refusal stays in effect until the separate workflows are delivered. These are
capability/design decisions, not authorization to adopt, replace or uninstall
anything on the developer workstation. Q03-Q04 are now accepted below.

The [registration inventory](../application-packages.md#observe-existing-installation-registrations)
is now source-ready for Q02: separate machine/current-user registry views, literal
metadata and unavailable-source reporting. The [offline matching report](../application-packages.md#review-registrations-against-the-catalog)
now compares declared distributions and exposes per-row ambiguity. It does not
resolve those copies, prove ownership or perform adoption/replacement.

## Host-folder toolkit publication decision, 2026-10-17

Q03 accepts a standard per-product/distribution layout beneath an operator-chosen
root and kit name, with content selected by a profile. Publish into a host folder
and retain managed files, exact versions/hashes and required licenses/notices.
The user transfers that folder manually to portable storage or other computers.
The kit identifies named published content, not a tracked USB stick. Do not require
physical-media enrollment or persistent volume-ID binding for this workflow.
Explicit destination/path ownership checks remain necessary. Transferred copies
are not automatically enrolled as managed deployments. No formatting or tool
execution is implied. This supersedes the earlier physical-volume proposal for Q03.

The related air-gap installation workflow remains separate from publishing deployed
portable tools. Its [later accepted scope](#offline-installation-bundles-2026-10-17)
now includes profile-selected/full reviewed variants, RIDE/profiles, explicit
omissions, retained versions and optional supplied servicing sources. Dependency
coverage, installer offline capability and native acceptance still need evidence.
Neither workflow approves all products, redistribution or runtime installation.

## Staged publication update decision, 2026-10-17

Q04 accepts building and verifying replacement content before updating the host
publication, retaining the existing folder during preparation. Replace managed
files and remove unchanged managed files that the profile no longer selects.
Preserve unrelated files and tool-generated data. Ask before replacing locally
modified managed files; modified obsolete files are not silently deleted either.
Noninteractive processing must report those conflicts for a later answer, never
treat silence as approval. The user accepts staging's temporary disk-space cost.

This governs the Q03 host publication, not automatic synchronization of transferred
copies. Concrete commit/journal/recovery, hash/member checks and conflict presentation
still require implementation and validation; design approval does not prove atomic
replacement or authorize changing actual content. See the [accepted decision](decision-session-2026-10-17.md#q04-staged-toolkit-updates-with-explicit-modified-file-decisions).

The [owned-file update preparation API](../application-packages.md#prepare-toolkit-file-update-decisions)
now implements these comparison rules against supplied data. It produces explicit
staging/removal/keep/conflict decisions while retaining ReadyForPublication=false.
Live collection, full artifact/notices manifest, staging, durable commit/recovery
and actual publication remain unimplemented.

## Acquisition kit requirements

Build kits from reviewed portable distributions. Retain a manifest with product
identities, distributions, versions, hashes, included files and upstream notices.
Kit assembly does not implicitly execute acquisition tools.

Validate acquisition suitability separately from portable file deployment.
A publisher's portable label does not establish operation on another machine,
driver/service prerequisites, privileges or absence of source-system changes.
Retain product-specific evidence and recovery limits. Redistribution review
remains separate from download-cache ownership and technical acceptance; local
individual/company license decisions remain in the existing license review
store described in [package licensing](../package-licensing.md).

## Remaining design and implementation work

| Work item | Decision or acceptance still required |
| --- | --- |
| Deployment identity and selection | Q01 accepted explicit names and ambiguity refusal. Schema-1 in-memory identity API and supplied-record completion implemented; main commands/profiles and durable selection remain pending. |
| State compatibility | Version-1 logical legacy selection mapping is source-ready, preserving retired variants/original paths/unknown fields. Original-byte archive, authenticated store identity, unique-name reservation, durable index/run migration and interrupted recovery remain required. |
| Independent lifecycle | Q02 accepts existing-installation adoption, explicit replacement and bulk review with per-match ambiguity resolution. Implement inventory, ownership, backup/recovery and partial-failure boundaries separately; preserve unrelated deployments and data. |
| Product coexistence | Review each installed/portable pairing for path, registration, service, driver and configuration conflicts; do not enable coexistence for every product automatically. |
| Kit layout and ownership | Q03 accepts named profile-driven publication to a chosen host root with product/distribution directories and manifest/notices. No physical-media tracking. Implement exact path/file ownership; Q04 accepts verified staging, unchanged-owned-file cleanup and explicit modified-file decisions. |
| Kit licensing | Review applicable redistribution terms and retain notices before distributing kits; a retained download is not distribution approval. |
| Acquisition suitability | Validate supported target environments, elevation, dependencies and source-system effects per tool. File lifecycle acceptance alone is insufficient. |
| Validation | Add focused mocked checks and disposable-VM lifecycle acceptance for applicable products/targets before normal use; include coexistence, independent recovery and partial failures. |

Q01-Q04 capability choices are resolved; detailed identity, ownership, staging,
durable state and recovery work remain. The overnight authorization
permits independent package batches while those workflow decisions remain open.
Implementation estimates need a separate review once the workflow and schema
are specified; this design records no completed legacy product outcome.

## Source-provider knowledge retained

Repository inspection on 2026-10-14 found implemented GitHub release, immutable
GitHub file, direct HTTPS and publisher-specific API/page download adapters.
Each selected package/variant currently declares its download provider.

The existing [multiple-source design](../MIGRATION-PLAN.md#multiple-package-sources)
plans approved alternative providers beneath one product ID, explicit selection,
preferences and bounded fallback for equivalent artifacts after availability or
transport failures. Installation or integrity failures stop the operation.

WinGet remains a future provider. No PSGallery adapter or specific PSGallery
design was found in the maintained implementation/guidance. This discussion
approved deployment coexistence, not implementation of either provider or a
GitHub-to-WinGet-to-PSGallery fallback chain. Provider, distribution, artifact
format and scope remain separate dimensions for every deployment.

## Offline installation bundles, 2026-10-17

The [offline decision follow-ups](decision-session-2026-10-17.md#offline-installation-follow-up-profile-selected-and-full-package-bundles)
accept both profile-selected downloads and a full external-package set. Include
reviewed available installed and portable variants for explicitly selected Windows
targets; keep RIDE, effective profiles and exact payload versions/hashes/notices
pinned together. The folder is transferable without original-host or USB identity.
Full preparation does not select all packages for installation. Optional matching
operator-supplied servicing sources may accompany packages; component selection
and native media compatibility are independent.

Keep partial bundles with clear missing/restricted/technical omissions. Before
any deployment changes, check the entire selected profile and dependency/source
requirements. Unrelated omissions do not block complete profiles; missing selected
content stops the deployment, with no network fallback. Internal pending licence
review alone is not an install gate; Q14 publication omissions remain applicable.
No private assessments or credentials are copied into shared metadata.

Refresh creates a new version and reuses only verified matching downloads. Retain
previous versions until explicit removal; shared storage must not invalidate them.
This does not alter Q04's owned-file toolkit update policy. Current [offline
preparation](../offline-bundles.md) includes local integrity preflight, optional
byte-bound profile/catalog package coverage and explicit-source local assembly
with a final staged-file integrity pass. Mandatory install/apply integration,
complete dependency discovery, engine provenance, offline installer behavior and
servicing compatibility remain pending. Source readiness is not air-gap readiness.
