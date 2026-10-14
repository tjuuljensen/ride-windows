# Package deployment and acquisition toolkit decisions

Approved by the user on 2026-10-14. Design approved; deployment coexistence and
USB toolkit assembly remain unimplemented. Packages remain paused.

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
| Deployment identity and selection | Define how commands and profiles identify a particular deployment and how inspection handles multiple deployments. CLI/schema names remain undecided; add read-only completion for enumerable choices. |
| State compatibility | Extend selection indexes, manifests and saved runs for separate deployments; preserve existing product IDs, profiles and schema-versioned recovery records through an explicit migration. |
| Independent lifecycle | Define update, removal and recovery selection, including ambiguous product-only requests, partial failures, modified files and shared dependencies. Preserve unrelated deployments and user data. |
| Product coexistence | Review each installed/portable pairing for path, registration, service, driver and configuration conflicts; do not enable coexistence for every product automatically. |
| Kit layout and ownership | Define destination/media identity, file ownership, offline use, update/rebuild and removal behavior, and whether assembly copies retained verified artifacts. |
| Kit licensing | Review applicable redistribution terms and retain notices before distributing kits; a retained download is not distribution approval. |
| Acquisition suitability | Validate supported target environments, elevation, dependencies and source-system effects per tool. File lifecycle acceptance alone is insufficient. |
| Validation | Add focused mocked checks and disposable-VM lifecycle acceptance for applicable products/targets before normal use; include coexistence, independent recovery and partial failures. |

These are follow-up requirements, not authorization to resume package work.
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
