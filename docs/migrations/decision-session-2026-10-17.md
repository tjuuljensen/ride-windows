# Migration decision session, 2026-10-17

This session records user-approved answers while implementation continues in a
separate chat sharing this checkout. Reconcile accepted answers into the existing
subject ledgers; do not overwrite concurrent implementation or estimate updates.
The [question register](remaining-migrations-follow-up.md#questions-for-the-users-return)
and [approved deployment model](package-deployment-decisions.md) retain context.
Unanswered recommendations remain proposals.

Archive reconciliation, 2026-10-17: the broad policy pass is complete; later
entries supersede earlier remaining-choice snapshots. Profile composition and
BitLocker/recovery test setup are explicitly deferred. No new general approval
question arose from the final artifact review. The [current handoff](remaining-migrations-follow-up.md#archive-handoff-and-closure-order-2026-10-17)
and [application dispositions](application-review-rounds-2026-10-12.md#current-dispositions-2026-10-17)
identify implementation and acceptance work. Continue this ledger for concrete
exceptions and new explicit user answers; do not reopen accepted Q01-Q31 policy.

The [shared-installer and licence-tier rule](#shared-installers-and-licence-tiers)
clarifies earlier edition-selection decisions, including TMOG and other products:
a feature entitlement alone does not create a separate deployment variant.

## Q01: Explicit deployment identity

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "this model is good",
in response to the recommended explicit naming model.

Give each independent deployment a stable name/ID. Examples discussed were
`imagemagick-workstation`, `imagemagick-portable` and `field-kit`; these illustrate
identification, not finalized command syntax or a complete kit-member schema.
Update and removal target the identified deployment. When several deployments
of a product exist, a product-only mutation must require explicit selection,
rather than automatically targeting a designated default deployment. Inspection
must expose the separate deployments so the operator can select the intended one.

Rationale: a little naming overhead makes the affected copy clear and supports
independent installed, portable and kit lifecycles already approved in the
deployment model.

Acceptance boundaries: this approves the identity/selection behavior, not runtime
activation, a particular destination, collision adoption, kit membership or
redistribution. Preserve existing product IDs and records through a versioned
compatibility path. Exact CLI/schema spelling and product-specific coexistence
validation remain implementation work. Q02-Q04 are answered below.

No implementation, installer, Windows setting or existing ledger was changed by
this decision record. This is design acceptance, not native lifecycle acceptance
or a completed legacy outcome; estimates are left to the implementation ledger.

## Q02: Adopt existing installations and offer explicit replacement

Accepted requirement, 2026-10-17 (Europe/Copenhagen). The user wants to run RIDE
v3 on an existing system and manage packages already installed there: "I want a
way to 'adopt' my existing install." The user also explicitly requested the
option to take ownership and replace existing content.

Existing installation alone must not be a universal blocking collision. Provide
an adoption workflow that associates an identified existing installation with a
stable RIDE deployment identity and enables its supported future management.
Adoption preserves the existing installation; it does not require replacement
merely to register it. Also provide an explicit replacement workflow for selected
existing content/installations. Blanket refusal with no adoption or replacement
route does not satisfy this decision.

Rationale: RIDE supports maintenance and migration of existing machines as well
as fresh setup. Requiring every existing package to be removed or relocated
before RIDE can manage it would undermine that use case.

Proposed implementation safeguards, not separately approved detailed choices:
discover product/version/distribution/scope/location; distinguish installed
package registration from portable file ownership; preview the deployment being
adopted and any ambiguous identities; keep adoption separate from updating or
replacing files. For replacement, preview affected files/configuration and retain
recoverable prior content where possible. Do not infer ownership of an entire
shared folder or unrelated application data from a recognized executable.

Acceptance boundaries: this is approval of capabilities and workflow intent, not
permission to adopt, overwrite or uninstall anything on the developer workstation
during this decision session. Detailed inventory presentation,
ownership boundaries, backup/recovery guarantees and product-specific unsupported
cases still require design and validation. Adoption cannot recreate pre-install
state or promise reversal of installation changes made before RIDE observed them.
Current portable collision refusal remains implemented behavior until this new
workflow is delivered; no runtime acceptance is claimed here.

### Q02 follow-up: Bulk adoption review

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Let me select several
existing installations to adopt together, and handle ambiguous matches
individually."

The first-run adoption workflow scans supported packages and presents one
reviewable list. The operator can select multiple identified existing
installations for adoption together. Ambiguous matches require individual
resolution rather than a guessed match or blocking all unrelated selections.
Selection for adoption preserves those installations; it does not implicitly
select replacement or upgrade. Detailed UI/CLI presentation remains implementation
work. This accepts the bulk-selection behavior proposed above without approving
unresolved ownership/recovery mechanics or actual workstation mutation.

## Q03: Profile-driven toolkit publication to a host folder

Accepted by the user on 2026-10-17 (Europe/Copenhagen): standard layout, with an
operator-chosen kit name and root folder. A profile selects the content to publish
into that host folder. Retain separate product/distribution directories, a manifest
of versions/hashes/managed files, and required upstream licenses/notices.

The user explicitly does not require RIDE to track particular USB sticks. Manual
copying from the published folder to portable storage or one or more computers is
the operator's workflow. Kit identity belongs to the named published content, not
a particular physical medium. Do not require enrollment or persistent volume-ID
binding for this workflow. Normal explicit-path and ownership checks still apply;
no formatting or automatic execution is implied. Transferred copies are not
automatically enrolled as managed deployments on their destination computers.

This supersedes the proposed Q03 physical-volume tracking requirement for toolkit
publication. Rationale: build once into a predictable host directory and let the
operator transfer it freely, without managing an inventory of removable devices.
Q04 below records the accepted publication update/removal behavior.

### Related offline installation scenario

The user also described downloading the full "external packages" set, transferring
it, then running RIDE on an air-gapped computer using portable storage or a copied
local folder as its package source. Preserve this as a distinct desired use case:
toolkit publication assembles deployed portable tools; an offline installation
source supplies payloads and metadata for RIDE to install selected packages later.
They can share acquisition evidence without becoming the same operation.

Current documentation describes offline bundle creation as optional future work
and installation from an acquired local repository without network fallback as a
planned mode. Do not present the complete air-gap workflow as already implemented.
The exact meaning of the full external-package set, included variants/targets,
dependency completeness, installer offline capability, bundle delivery priority
and engine/profile inclusion remain to be specified. No blanket product selection,
distribution-rights approval, network acquisition or installation is authorized by
this discussion. Existing local license-review ownership remains unchanged.

See [planned local-repository acquisition](../MIGRATION-PLAN.md) and
[offline bundle status](../package-licensing.md#requested-offline-bundles).
This records workflow intent only; no kit was built and no native acceptance or
legacy-outcome closure is claimed.

## Q04: Staged toolkit updates with explicit modified-file decisions

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes, that update model
works for me. Preserve unrelated files and tool-generated data, and ask before
replacing locally modified files."

Build and verify replacement content before updating the published toolkit folder.
Keep the existing publication intact during preparation; a failed download or
verification must not leave it partially updated. Replace managed files and remove
unchanged managed files no longer selected by the profile. Preserve unrelated
files and tool-generated data. Ask before replacing locally modified managed
files; do not silently overwrite them. Modified obsolete files must likewise not
be silently deleted under the unchanged-file removal rule.

Rationale: retain a usable publication during preparation and protect local
customizations and generated data. The user accepts the temporary additional disk
space required by staging. This applies to the published host folder from Q03,
not automatic synchronization of manually transferred copies.

Acceptance boundaries: concrete staging/commit and interrupted-update recovery,
hash/member checks, conflict presentation and noninteractive conflict reporting
remain implementation and validation work. No claim of atomic replacement or
complete recovery is established by design approval. A required conflict answer
must not be inferred from silence. No toolkit content was changed in this session.

## Q05: OpenSSH Client and Telnet Client first

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Start with OpenSSH Client
and Telnet Client, individually selectable and neither enabled by default."

Prioritize those two client components where applicable and available. Keep them
independent choices with no automatic selection in default profiles. Larger
components (OpenSSH Server, RSAT, Hyper-V, Windows Sandbox and WSL) follow as
separate choices with their own dependencies and configuration.

Rationale: the user accepted the proposed delivery order and optional selection
model. Acceptance covers implementation priority and selection behavior; it does
not authorize enabling either component on the developer workstation, select
servicing sources, activate server services or establish Windows target support.
Source policy is accepted in Q06 below; native servicing and recovery require
their own evidence.

## Q06: Explicit online and offline Windows servicing modes

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Offer both modes. Online
should respect the configured servicing sources, and offline should use a matching
local source without network fallback."

Offer explicit online and offline source modes for Windows component servicing.
Online mode may obtain missing payloads through the configured servicing sources,
respecting organizational policy; it must not silently override those sources.
Offline mode uses an explicitly supplied matching local source with no network
fallback. Missing or incompatible source content must be reported clearly.
Windows component servicing sources remain distinct from application-package
download/source folders.

Rationale: support ordinary connected setup and the user's air-gap workflow.
This supersedes the proposed local-source-only initial restriction in Q06; neither
mode is selected implicitly by this answer. Matching-build/source validation,
source-policy preservation, pending-reboot reporting, failure/recovery behavior
and native acceptance remain implementation work. This approves supported workflow
design, not immediate component acquisition or activation on the workstation.

## Q07: Interactive local administrator enrollment

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use secure interactive
password entry, handle existing accounts separately, and protect the last usable
administrator."

The operator chooses the new account name and enters its password securely during
execution. Passwords must not be written to profiles, logs or saved recovery
records. An existing account with the requested name requires a separate explicit
choice; creation must not silently adopt the account or reset its password.
Disabling another administrator or removing administrator membership remains a
separate action, guarded against losing the last usable administrator access.

Rationale: the user accepted interactive enrollment and explicit existing-account
handling. Unattended account creation was not selected. Exact SID ownership,
proof of viable administrator access, credential handling, enrollment failure
recovery and protection of any subsequently created user data require implementation
and native acceptance. Design approval does not authorize creating accounts,
changing passwords or changing memberships on the developer workstation.

## Q08: Separate PowerShell startup and persistent user PATH choices

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Offer both options, with
PowerShell startup only as the initial migration and persistent user PATH as a
separate choice. Preserve the folder and its contents when removing either
setting."

Migrate the legacy user-bin PowerShell startup behavior first, independently
selectable for the applicable PowerShell runtime. Offer persistent user PATH as
a separate explicit setting for the intended user. Selecting one does not
implicitly select the other. Removing either setting must preserve the bin folder
and its contents; PATH management does not imply directory or tool ownership.

Rationale: retain the legacy scoped behavior while allowing broader user-level
command discovery when wanted. Machine PATH changes are not included. Exact
entry ownership, duplicate handling, coexistence with inherited PATH and existing
profile snippets, environment refresh and conflict-safe recovery remain subject
to implementation and validation. Directory provisioning remains separate.
No live PATH or profile was changed by this design decision.

## Q09: Select an existing Terminal profile and preserve other settings

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Let me choose an existing
Terminal profile and preserve the other settings. If it is missing on another
computer, ask me to select another."

Discover available profiles in the selected Windows Terminal instance and let
the operator choose an existing profile. Own only the root defaultProfile field;
preserve unrelated Terminal settings. Resolve the selected profile by its actual
identity rather than guessing an executable or substituting a shell by name.
If that profile is missing on another computer, require another explicit selection.
An unattended run must report the unresolved selection rather than invent an answer.

Rationale: respect each computer's existing Terminal setup and the operator's
shell preference. This does not install Terminal, create profiles or automatically
install the selected shell. Live instance/file binding, profile availability,
field-level persistence and exact conflict-safe recovery still require validation.
No Terminal setting was changed by this decision.

## Q10: Separate browser preferences and enforced policies

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Offer both user
preferences and enforced policies, with enforced policies always an explicit
choice. Preview individual changes and preserve unrelated browser settings."

Offer supported user preferences for a selected browser profile and separately
selectable enforced policies. Policies must always be an explicit choice with
scope and control-locking behavior visible. Do not silently substitute policy for
a user preference. Preview individual owned fields and preserve unrelated browser
settings; do not replace a whole preferences file with a legacy template.

Rationale: support both personal customization and deliberate managed settings
without confusing their effects. Concrete browser/version mappings, profile
identity, managed precedence, file locking/refresh and conflict-safe recovery
remain implementation and acceptance work. No particular browser setting or
policy value is selected by this answer, and no live browser configuration changed.

## Q11: Explicit asset sources and separate deployment/application scopes

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use per-user deployment
where supported, offer machine-wide and new-user defaults separately, and ask
before replacing conflicting assets. Keep copying and applying images separate."

Use a reviewable asset list of operator-supplied files or declared official
downloads, retaining source/license information. Deploy fonts, wallpapers and
lock-screen assets per user where supported. Offer machine-wide and new-user
default deployment separately rather than silently expanding scope. Ask before
replacing conflicting existing assets. Copying an image and selecting it as a
wallpaper or lock-screen background are independent actions.

Rationale: support personal configuration and deliberate wider deployment while
preserving existing assets and preferences. Actual files/sources, applicable
rights, target-specific support, exact ownership and registration, prior-content
capture and conflict-safe recovery remain to be specified and validated. This
does not select particular assets or authorize overwriting shared OS-owned files.
No font, image or Windows preference was changed by this decision.

## Q12: Per-user Wi-Fi import with separate connection and all-user choices

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use per-user Wi-Fi
profiles, offer all-user provisioning separately, and keep import and connection
separate. Handle credentials securely and ask before replacing existing profiles."

Select the Wi-Fi adapter and profile explicitly. Use intended-user profile scope
and offer all-user provisioning as a separate choice. Importing a profile does
not implicitly connect or enable automatic connection; connection behavior is
selected explicitly. Handle credentials securely and ask before replacing an
existing profile, with recoverable prior profile content as a prerequisite.

Rationale: allow network preparation without unexpectedly changing connectivity
or configuring other users. Secure credential input/storage, exact profile-content
and ACL ownership, managed-profile restrictions, automatic-connection semantics
and recovery require implementation and native hardware acceptance. A basic saved
profile-name inventory is not a recoverable profile backup. No network, adapter,
credential or live Wi-Fi profile was changed by this decision.

## Q13: Curated, individually selectable tool collections

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use curated collections
with individual selection and an option to select the whole reviewed collection.
Propose new upstream additions rather than adding them automatically."

Define each collection through a reviewable, versioned list of named members.
Allow individual member selection and selection of the whole reviewed collection.
New upstream members are proposed additions, not automatic changes to an existing
selection. Launcher/configuration setup remains separate from collection content.

Rationale: retain convenient group selection while keeping membership deliberate
and reproducible. The actual member lists for each collection are still pending;
this approves their selection model, not any unreviewed tool, version, license or
installer behavior. Q13 is therefore partially resolved: membership policy is
accepted, concrete collection membership requires review. Q14 separately covers
personal/company license-review handling. No collection was acquired or deployed.

## Q14: Visible local licensing review and fast unattended deployment

Accepted by the user on 2026-10-17 (Europe/Copenhagen): keep tools visible with
clear review requirements, record licensing assessments locally, and omit
unreviewed restricted tools from shared kits with reported omissions as the
default behavior. The user also explicitly requested an option for a full
unattended RIDE installation on a clean machine, without interrupting a fast-paced
deployment for RIDE compliance-review prompts.

Keep product/license references visible and individual/company assessments in the
existing local review store, tied to the applicable product/version/review owner.
Do not hide restricted tools solely because review is pending. Shared toolkit
publication defaults to omitting unreviewed restricted members and reporting the
omissions. This answer does not select an override of that publication default.

Offer an explicit unattended installation mode for the operator's selected
deployment/profile. RIDE's own pending licensing-review status or reminder must
not prompt, pause or by itself block that installation mode. Report outstanding
reviews and relevant licensing notices in the deployment results, retaining their
actual unresolved status. Do not silently mark reviews as approved or turn the
installation-mode choice into a redistribution assessment.

Rationale: RIDE serves experienced operators preparing forensic and developer
machines quickly; review information should remain available without making
internal compliance bookkeeping an interactive deployment bottleneck. Shared-kit
publication and installation on a selected machine have different default review
behavior.

Acceptance boundaries: unattended mode does not invent credentials, entitlements,
publisher agreement answers, product selections or required interactive installer
responses. Existing interactive account enrollment (Q07), driver workflows and
technical prerequisites remain distinct. Exact flags, preflight requirements,
per-item failure/skip reporting and continuation behavior need implementation;
do not describe all selected products as unattended-capable without evidence.
No actual license assessment, acquisition, installation or publication occurred in
this session. This accepts workflow behavior, not legal eligibility for any tool.

## Q15: Pinned normal deployments and separate editable checkouts

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use pinned releases or
source revisions for normal deployments, with editable Git checkouts offered
separately. Keep downloading, updating, importing and executing as distinct
actions."

Normal source-based deployments use a pinned release or immutable source revision.
Offer editable Git checkouts as a separate development option. Download, update,
module import and execution remain independently selected actions; acquisition
alone does not authorize import or execution. A deployment profile may explicitly
compose its required actions without making them inseparable.

Rationale: reproducible normal deployments alongside an intentional development
workflow. Exact product revisions, dependency sets and checkout/update conflict
handling still require product-specific implementation and review. No source was
downloaded, imported or executed by this decision.

## Q16: Wireshark installation scope and file associations

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Install Wireshark for all
users and preserve existing file associations. Offer making it the default for
capture files as a separate option."

Use all-user installation scope for Wireshark. Preserve existing file associations
during installation and offer capture-file default association as a separate
explicit option. Retain earlier accepted live capture, separate interactive
Npcap enrollment and administrator-only capture decisions.

Rationale: make the application available across the machine without taking over
existing capture-file defaults. Exact installer flags, supported association
workflow, existing driver/runtime ownership and native acceptance remain technical
work. Q16 is partially resolved: Npcap compatibility flags and other products'
unresolved integrations still need review. No installation or association changed.

### Q16 follow-up: WinPcap compatibility is explicit and off by default

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Default WinPcap
compatibility mode off and offer it as an explicit option. Preview replacement
of any existing WinPcap installation before enabling it."

RIDE's Npcap workflow must explicitly select compatibility mode off by default,
rather than inherit the publisher's current enabled default. Offer enabling it
as a separate explicit option. Detect and preview replacement of any existing
WinPcap installation before enabling compatibility mode; do not silently replace
it during ordinary Npcap installation. Earlier administrator-only capture and
separate interactive Npcap enrollment choices remain unchanged.

The [publisher guide](https://npcap.com/guide/npcap-users-guide.html), checked
2026-10-17, documents that winpcap_mode defaults to yes and removes an existing
WinPcap installation when enabled. Exact selected-release behavior, existing
consumer detection, recovery and installer-result validation still require
implementation/acceptance. This records the default and preview requirement,
not authorization to replace a workstation driver. Other Q16 product integrations
remain pending.

## Q17: Retire planned Volatility 2 deployment; retain Volatility 3

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Retire Volatility 2 from
RIDE's planned deployment catalog and leave existing installations untouched.
Continue with Volatility 3."

Retire the planned Volatility 2 deployment outcome instead of implementing it as
an optional specialist package. Preserve its historical migration mapping and
record this explicit user retirement; do not silently substitute or erase the
legacy selector. Do not uninstall, modify or adopt existing Volatility 2 copies
as a consequence. Continue the previously selected Volatility 3 work with its
pinned release and isolated environment.

Rationale: the user selected retirement of RIDE's planned Volatility 2 offering
after the earlier retirement review. This is not a claim that Volatility 3
replaces every historical plugin or workflow. Volatility 3 dependency, runtime,
functional and recovery acceptance remain open. The implementation chat should
reconcile this retired legacy outcome and its estimate effect in the authoritative
ledgers; this session does not edit concurrent estimates or implementation.

## Q18: Pinned dependencies and separately selected rule/plugin updates

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Pin reviewed dependencies,
offer extra rules and plugins explicitly, and keep updates separate. Preserve
custom content and ask before replacing modified files."

Pin each tool's reviewed dependency set. Offer additional rule/plugin collections
through explicit selection. Keep updates separate from installation, while allowing
a profile to explicitly compose both actions. Preserve custom rules/plugins and
ask before replacing locally modified managed files. Retain the earlier selected
broader Volatility 3 plugin dependencies; this decision does not narrow that
selection to core-only.

Rationale: reproducible installations with deliberate maintenance and protection
of analyst customizations. Exact dependency versions, rule/plugin membership,
sources, compatibility and recovery remain product-specific review work. Q18's
management model is accepted; it does not approve unspecified extras or network
execution, and it does not complete the concrete dependency manifests. No package,
rule or plugin was acquired, updated or executed by this decision.

## Q19: Collectors first; separately managed BloodHound CE backend

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Manage the collectors
and keep the backend separately managed. Leave optional backend deployment as
a later addition."

Initial RIDE delivery manages the selected SharpHound and AzureHound collectors.
The BloodHound CE backend remains separately managed. Collector installation must
not implicitly install Docker/WSL, create a backend or take ownership of an
existing backend. Optional backend deployment is deferred as a later addition,
not retired or accepted as implemented.

Rationale: deliver workstation collector management without coupling it to backend
infrastructure lifecycle. Collector versions must still be matched to the selected
external backend; its actual version and compatibility evidence remain unresolved.
Collector deployment does not authorize running collection or enrolling backend
credentials. No container environment, backend or collector was changed here.

## Q20: Defer standalone Neo4j/APOC and retire planned ImproHound deployment

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Defer standalone
Neo4j/APOC until there is an independent use case, and retire ImproHound from
RIDE's planned deployment catalog. Leave existing installations and data untouched."

Keep standalone Neo4j/APOC deployment deferred pending an independently identified
use case. This is not retirement of that outcome and does not choose database,
plugin or Java versions. Retire ImproHound from the planned deployment catalog,
preserving its historical selector/migration mapping with this explicit user
disposition. Do not uninstall, modify or delete any existing installation or data
as a consequence of either choice.

Rationale: the user selected distinct dispositions after the earlier independent
deployment and retirement reviews. BloodHound CE selection does not establish
functional replacement of ImproHound. The implementation chat should reconcile
the retired outcome and retained deferred scope in authoritative ledgers and
estimates; this session leaves concurrent implementation and estimates untouched.

## Q21: Guided Office/Visio selection and separate Teams actions

Accepted direction, 2026-10-17 (Europe/Copenhagen): the user wants to choose
Office/Visio products and channel together in this session, retain the previously
approved language requirements, and handle Teams installation, startup and cleanup
separately. No existing deployment configuration was selected.

Retain the approved full language intent, subject to actual product support:
product language en-gb; additional LanguagePack requests en-gb, da-dk and MatchOS;
ProofingTools requests da-dk, en-us and en-gb. Do not silently substitute an
unsupported Visio language or omit it. Teams installation, startup configuration
and cleanup of older editions are independent explicit actions; Office installation
does not authorize them implicitly.

Q21 remains partially answered. Licensed products/editions, channel, architecture,
activation method and exact supported language mapping still need selection and
verification. This records the guided selection request, not an inferred license,
product selection or permission to install/remove software.

### Q21 follow-up: Microsoft 365 Apps for enterprise selected

On 2026-10-17 (Europe/Copenhagen), the user selected Microsoft 365 Apps for
enterprise, retained the approved language requirements, and referred to the
"Visio suggestion from side chat" for Visio. Record the Office product selection;
the exact referenced Visio choice was initially unresolved and is now specified
in the follow-up below. No update channel was selected by that reference.
Channel and architecture remain unanswered, and no license entitlement or actual
installation is verified by the product choice.

### Q21 follow-up: Separate Visio Professional 2016 Retail and Plan 2 choices

Accepted direction, 2026-10-17 (Europe/Copenhagen): offer separate choices for
Visio Professional 2016 Retail and Visio Plan 2. Deploy Plan 2 through Microsoft's
Office Deployment Tool; the operator supplies an assigned subscription and
completes sign-in. Check compatibility with existing Office/Visio installations
before making changes. Never automatically replace the existing 2016 installation
or switch its licence. Retain the approved language requirements, subject to
explicit resolution of product-specific language support.

Rationale: support the user's existing perpetual installation and a separately
selected subscription route without silently converting either. Separate choices
do not establish that both products can coexist on the same machine. Exact
publisher acquisition/deployment routes, product IDs, architecture/channel
compatibility, lifecycle/support status, supported languages and recovery remain
technical review items. Unsupported combinations must be reported before mutation;
do not remove an existing product to make the selected combination fit implicitly.
Plan 2 sign-in is explicit and is not fabricated by unattended mode. No subscription
assignment, entitlement, sign-in, licence conversion or installation occurred here.
The Microsoft 365 Apps update channel is selected in the follow-up below.

### Q21 follow-up: Monthly Enterprise default and explicit Current alternative

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use Monthly Enterprise
as the default, with Current Channel available as an explicit alternative."

Use Monthly Enterprise as the default channel for the Microsoft 365 Apps for
enterprise deployment choice and expose Current Channel as an explicit alternative.
Resolve any coinstalled subscription Visio channel requirements through the
compatibility review. This channel preference does not authorize silently changing
an existing managed channel, replacing Visio Professional 2016 Retail or overriding
organizational update policy. Pin/record the selected deployment version separately
from its channel; maintenance behavior remains distinct from initial installation.

Rationale: predictable monthly updates with an optional earlier-feature channel.
Architecture, activation details and exact supported language mapping remain open.
No Office channel or installation was changed in this session.

### Q21 follow-up: Architecture selection and explicit migration

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use 64-bit for fresh
installs, match existing Office architecture when adding products, and offer
32-bit explicitly. Ask before migrating an existing 32-bit installation to 64-bit."

Default fresh Office/Visio deployments to 64-bit where supported. When adding a
compatible product to an existing Office installation, match its architecture.
Expose 32-bit as an explicit choice. Migration of an existing 32-bit installation
to 64-bit requires a separate operator decision; do not silently enable migration
or uninstall existing products to satisfy the fresh-install default.

Rationale: a consistent fresh-install default with preservation of existing
compatibility requirements. Product/version/channel/add-in compatibility and
migration recovery still require preflight and validation. Architecture matching
alone does not prove that a particular Office/Visio combination is supported.
No existing Office installation or architecture was changed here.

### Q21 follow-up: Standard user sign-in without blocking deployment

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use standard user sign-in
initially. Let unattended installation finish and report activation pending
without interrupting deployment. Keep specialized activation modes separate."

Initial Microsoft 365 Apps activation uses an assigned user subscription and user
sign-in, consistent with the selected Visio Plan 2 approach. Allow unattended
installation to complete and continue the deployment while reporting activation
pending where activation has not been verified. Do not store account passwords
or report successful activation merely because installation succeeded. Keep
shared-computer and other specialized activation modes as separate configuration.

Rationale: prepare machines without waiting for user sign-in, while accurately
distinguishing installed software from activated software. No account entitlement,
credentials or activation was verified or changed in this session. This does not
change the separate Visio Professional 2016 Retail licence or its activation route.

Language evidence, references checked 2026-10-17: Microsoft's
[deployment language table](https://learn.microsoft.com/en-us/microsoft-365-apps/deploy/overview-deploying-languages-microsoft-365-apps#languages-culture-codes-and-companion-proofing-languages)
explicitly excludes en-GB from Visio (including the subscription scope described
by that guide). The [Visio desktop language list](https://support.microsoft.com/en-us/visio/display-languages-supported-in-the-visio-desktop-app),
which includes Visio Professional 2016, lists en-US and da-DK. The user accepted
the product-specific resolution below.

### Q21 follow-up: Visio en-US default with explicit Danish alternative

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use US English for Visio,
with Danish as an explicit alternative. Keep UK English for Office and the approved
additional-language and proofing requirements."

Use en-US as the selected Visio display-language default and expose da-DK as an
explicit alternative for the Visio choices. Retain en-GB for Microsoft 365 Apps
for enterprise and the approved additional-language and proofing intent. This is
an explicit product-specific exception to the earlier uniform en-GB request, not
a change to Windows regional settings or permission to force a language change on
the existing Visio 2016 installation.

Rationale: preserve the preferred English interface using a documented Visio
language while retaining optional Danish. Additional LanguagePack/MatchOS and
ProofingTools requests still require product-specific validation; do not reinsert
unsupported en-GB Visio resources through those paths or silently discard an
unsupported request. No product language was changed on this workstation.

### Q21 follow-up: Optional Teams installation and separate cleanup

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep Teams installation
optional, preserve existing startup behaviour, and offer older-version cleanup
separately with a preview and user data preserved."

Teams installation is optional and not automatically selected with Office.
Preserve existing Teams startup behavior unless the operator explicitly selects
a startup change. Offer older-version cleanup as a separate action with a preview
of the exact detected installations and preservation of user data. Office setup
does not implicitly remove Store, classic machine-wide or other Teams variants.

Rationale: install Office without taking over Teams choices or historical data.
Exact supported Teams distribution/scope, old-version identities, data ownership,
process handling and recovery require product-specific implementation and review.
If data preservation cannot be established, report the affected cleanup as blocked
rather than silently deleting data. No Teams package, startup setting or data was
changed by this decision.

## Q22: OneDrive preservation and separate synchronization settings

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Preserve OneDrive
accounts, sync settings and files; keep sync restrictions and folder-backup
changes explicit, and never delete files during app removal."

Keep OneDrive application management separate from synchronization policy.
Preserve existing accounts, sync configuration and user files during adoption
and update. Sync restrictions and folder-backup changes require explicit choices.
Application removal must not delete local or cloud user files; ordinary removal
of application-owned program binaries is distinct from deletion of user content.

Rationale: manage the application without silently changing synchronization or
data ownership. Exact package scope, account/configuration preservation and
uninstall effects require native validation. If preservation cannot be established,
do not claim the operation meets this contract. No account, sync configuration,
OneDrive installation or user data was changed here. WinGet AutoUpdate decisions
under Q22 are recorded in the follow-up below.

### Q22 follow-up: Selected-package updates by default, broad mode explicit

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use selected packages
by default, and offer all eligible packages except exclusions as an explicit
option. Respect pins, keep scheduling separate, and never reboot or force-close
apps automatically."

Automatic updating is opt-in. Default update selection is an explicit package list;
offer all eligible packages except an exclusion list as an additional explicit
mode. Use approved sources and respect existing pins. Scheduling is independently
selected rather than implicitly activated by installing the updater. Never reboot
or force-close applications automatically; report updates that need intervention.

Rationale: support controlled maintenance and a deliberate broad-update option
without disrupting active work. Exact eligibility rules, selected/excluded package
identity and source matching, schedule values, existing scheduler ownership,
upstream updater capabilities and per-package non-disruptive installer behavior
still need design and verification. Do not claim the requested behavior is already
provided by an unreviewed upstream default. No updater, schedule or package changed.

## Q23: VMware workstation installation first; guest drivers separately

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Start with VMware
workstation installation, preserving existing VMs and preferences. Keep
VM-directory settings separate, then address guest drivers for a specified
virtual platform."

Prioritize VMware workstation application installation. Preserve existing VMs
and application preferences. VM-directory configuration remains a separate
explicit setting, with no implicit relocation of existing VMs. Address guest
drivers afterward against an explicitly specified virtual platform, separately
from host provisioning.

Rationale: deliver the requested workstation application before platform-specific
guest components. Q23 priority and scope separation are accepted; VMware edition,
version, source/access, integration flags, driver/reboot behavior and native
acceptance still need review. The guest platform and exact drivers are not yet
selected. Other hardware/GPU and AutomatedLab roles remain unresolved. This does
not authorize changing the developer host, running VMs or protected test controllers.

## Q24: FTK Imager then KAPE; Arsenal product selection deferred

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Start with FTK Imager,
then KAPE. Leave the specific Arsenal product choice open until we review the
options."

Prioritize preparation of FTK Imager, followed by KAPE. Keep selection of any
specific Arsenal product unresolved until its options are reviewed. Review exact
editions, official acquisition routes, deployment requirements and applicable
terms for each product independently. If access or required technical resources
are unavailable, retain that blocker and continue independent work rather than
substitute a different product silently.

Rationale: the user selected preparation order, not a specific release, licence
assessment or runtime execution. Q24 remains partial: Arsenal and other gated
product/edition choices are still open. No payload was acquired, installed or
executed by this decision.

## Q25: RIDE owns configuration; LoggingBaseline remains read-only

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Accept RIDE as the
configuration owner and keep LoggingBaseline read-only for observation,
evaluation and reporting. Keep downloading Sysmon configuration separate from
applying it."

Accept the ownership boundary proposed in
[ADR 0001](../decisions/0001-configuration-ownership.md): RIDE applies explicitly
selected Windows configuration, including supported logging/audit/Sysmon settings,
with preview and recovery. LoggingBaseline observes, evaluates and reports, using
exported RIDE desired configuration as its reference. Each mutable control has
one writer. Keep LoggingBaseline's own measurement thresholds distinct from
desired Windows configuration values. Downloading a Sysmon configuration and
applying it are independently selected actions.

Rationale: avoid competing configuration and recovery paths. Reconciliation of
the ADR status, versioned export contract and affected plans remains follow-up;
this decision session edits no other repository or concurrent implementation.
No particular audit/security values are selected and no host policy, Sysmon
configuration or LoggingBaseline runtime behavior changed here.

## Q26: Validate reviewed Store selection before a separate dynamic extension

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Defer dynamic-list
support until the existing reviewed app selection is validated. Keep the optional
uninstall/reinstall groups unchanged and add dynamic-list support later as a
separate extension."

Finish validation of the existing reviewed Store-app selection first. Preserve
the accepted optional uninstall/reinstall group membership and separate device
policy workflow. Defer dynamic-list support to a later, independently validated
extension; do not expand selected app identities or supported targets implicitly.

Rationale: establish the current workflow before adding broader policy scope.
The [Microsoft policy guide](https://learn.microsoft.com/en-us/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal),
checked 2026-10-17, describes dynamic Package Family Name selection and schema
compatibility requirements. Actual local template/CSP and consumer acceptance
remain prerequisites for that future extension. No apps, group membership or
device removal policy changed in this decision session.

## Q27: Explicit destructive maintenance with a disposable-cache exception

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Accept that recovery
contract, but allow explicitly selected disposable-cache cleanup without a backup.
Keep previews and recovery limits clear, and require backups for destructive
actions such as Sysprep."

Destructive maintenance requires explicit selection and a preview of affected
data. Distinguish restoration of settings from recovery of deleted content and
state recovery limits plainly. Require an external backup or checkpoint for
destructive actions RIDE cannot undo, including Sysprep. Reboot and shutdown remain
explicit choices. Such maintenance is outside an ordinary unattended installation
unless separately configured.

Exception: explicitly selected disposable-cache cleanup may run without a backup.
Define and preview the actual disposable cache/data class; do not treat arbitrary
files or user content as disposable merely because they are in a cache-like path.
Deletion is not represented as exactly restorable through a settings snapshot.

Rationale: permit practical cache maintenance while retaining recovery requirements
for destructive transitions. Exact cache classes, busy-operation guards, backup
verification and action-specific recovery remain implementation/acceptance work.
This does not select any cleanup target, authorize running Sysprep or permit
workstation deletion during this decision session.

## Q28: Explorer/input, Server behavior, then application/hardware acceptance

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Start with Explorer,
desktop icons and keyboard/input, then Server behaviour, then application and
hardware-dependent checks. Defer unavailable resources."

Prioritize disposable-target hands-on acceptance in that order. The Server phase
covers sign-in, shutdown and related prompts. Application-dependent settings
precede audio, network-peer and other hardware-dependent scenarios where applicable.
Defer unavailable resources and continue independent checks; absence is not a pass.

Rationale: the user accepted the proposed validation sequence. This resolves Q28's
ordering and the corresponding D02/D03 priority direction; exact D04-D06 resource,
historical behavior and recovery arrangements remain open. It does not authorize
integration changes on the working machine or accept any GUI/boot/hardware result.
Existing disposable-target source pinning, serialization and recovery rules remain.

## Q29 / D07: Keep unsafe-to-restore menu controls visible but unavailable

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep those controls
visible but unavailable until reliable recovery is implemented. Explain the
limitation and provide manual guidance where possible."

When a menu control cannot reliably restore the original registry content and
permissions, retain it as a visible unavailable requirement rather than retiring
it or weakening the recovery contract. Explain the specific limitation and offer
accurate manual guidance where possible. Implementation may resume once reliable
recovery is demonstrated; do not substitute guessed fixed registry reconstruction.

Rationale: preserve the desired capability while making its current limits clear.
This resolves the Q29/D07 disposition, not any particular control's runtime
acceptance. No menu binding or registry permissions were changed in this session.

## Q30 / D08 / D10: Explicit resource identity with captured default-audio option

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use explicit device
selection by default, with current-default audio selection as a separate option
that captures the device identity. If a device disappears, report it rather than
switching targets."

For targeted audio, adapter and volume changes, present friendly names and details
for explicit operator selection and retain the stable underlying identity.
Current-default audio selection is an additional explicit option that resolves
and captures the actual device identity before mutation. Recovery targets that
same captured device. A missing/disappeared device is reported; never switch to
a replacement or newly default device implicitly.

Rationale: make selection usable while preventing changes or recovery from drifting
to a different resource. This accepts Q30's selection behavior and D08/D10 direction;
existing published all-visible adapter compatibility scope remains explicit and
unchanged until a documented migration. Saved named local selections, detailed
identity/conflict guards and hardware acceptance remain implementation work.
This does not introduce physical-USB tracking for Q03 toolkit publication or select
any actual device in this session.

## Q31 / D09: Close unsubstantiated User .NET assemblies bookkeeping entry

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Close it as an
unsubstantiated bookkeeping entry, retain the audit, and reopen it if a source
or use case appears."

Close the unidentified User .NET assemblies entry as unsubstantiated bookkeeping,
not an implemented feature or a claim that all possible historical sources have
been exhausted. Retain the existing source audit and its bounded conclusions in
the [settings ledger](settings-post-migration-review.md#unidentified-entry-source-audit-and-closure-path-2026-10-11).
Reopen if an actual source or independently defined use case is identified.
Do not add a guessed assembly deployment/cache action or remove any .NET feature,
runtime, assembly or existing user content.

Rationale: no corresponding deployment outcome was identified in the recorded
legacy/tag/history searches. This resolves Q31/D09's disposition. The implementation
chat should reconcile R29, the authoritative ledgers and estimate accounting;
this session does not modify concurrent estimates or claim runtime completion.

## Remaining choices snapshot after Q31, 2026-10-17

All 31 top-level questions have now been discussed. Accepted workflow policies
above must not be reopened because a concurrently maintained register still shows
an older question. Several questions remain partial at concrete product/resource
level; technical API/schema/version validation is implementation work, not an
additional user approval gate by itself.

| Area | Remaining user choice or input |
| --- | --- |
| Q13/Q18 collection and rule membership | Exact named members of Sysinternals/JoeWare/MiTeC/NTCore/Zimmerman/NirSoft collections and optional rule/plugin sets. Volatility 3 scope and symbols/cache locations; Python manager command integration and runtime-acquisition/update preferences remain in the application rounds. Compatibility versions are researched by implementation. |
| Q16/Q24 product-specific options | ImageMagick optional integrations and portable scope/PATH; exact Arsenal product; retained scope/editions for other gated utilities and historical parsers/viewers. FTK Imager then KAPE priority is settled. Existing approved Gpg4win/Wireshark choices remain settled. Independent OpenJDK use still needs a requirement; it is not automatically retired with the old graph stack. |
| Q23 platform and hardware roles | The actual guest platform and selected VirtIO/SPICE/WebDAV components; whether AutomatedLab, Lenovo-specific tools, GPU roles and HashcatLauncher are wanted. VMware-first priority is settled; exact native resources/requirements remain to be supplied. |
| Q19 collector compatibility input | Version of the separately managed BloodHound CE backend to match collectors against. Backend deployment automation is deliberately deferred. |
| Q03 offline installation scope | Meaning of the full external-package set versus a selected profile, included distributions/targets, whether RIDE engine/profiles travel with it, and delivery priority. Dependency completeness and offline behavior need implementation evidence. Toolkit host-folder publication is already accepted. |
| Deployment-specific configuration | Actual updater package/exclusion lists, allowed sources and schedule; asset files and browser setting values; selected local accounts, Terminal/device/Wi-Fi identities and destinations. These are profile/runtime inputs, not reasons to stop generic source implementation. |
| D04-D06 acceptance resources/history | Available application/hardware/peer fixtures; historical NumLock conditions and precise F1 intent; disposable TPM/boot recovery setup, off-device recovery destination and responsible recovery verifier. Validation order and deferral of unavailable resources are settled. |

Intentionally deferred rather than awaiting immediate approval: standalone
Neo4j/APOC pending an independent use case; optional BloodHound backend deployment;
dynamic Store policy until existing selection validation; specialized Office
activation modes. Retired: planned Volatility 2 and ImproHound deployments.
Closed as unsubstantiated bookkeeping: User .NET assemblies, with audit retained.

Office/Visio/Teams product, channel, architecture, activation and language policies
are now selected. Remaining product compatibility, availability, preservation,
recovery and native acceptance are technical work; unsupported combinations must
be reported before changes, not silently substituted. No full migration or runtime
acceptance is implied by completing this decision discussion.

## Offline installation follow-up: Profile-selected and full package bundles

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "I want both
profile-selected downloads and the full external-package set, with RIDE and
profiles included so I can copy the folder to an air-gapped machine and install
from it."

Make both preparation modes part of the requested offline-installation scope:

- Profile-selected: acquire the external packages and required dependencies for
  the explicitly selected profile(s).
- Full external-package set: prepare the complete applicable external-package
  set, independently of a particular installation profile. Exact variant/target
  coverage and the treatment of unavailable or technically unaccepted entries
  still need an explicit assembly definition.

Include the RIDE engine and profiles in the prepared folder, together with the
package payloads and metadata needed for local installation. The operator can
copy that folder to removable storage or another location on the air-gapped
machine and run RIDE against it. Do not bind it to the original host path or a
particular USB device. Keep source preparation separate from installation: a full
source bundle does not select all its packages for installation.

The offline contract requires local resolution without network fallback. Validate
the selected deployment's source completeness before changing the target and
report missing/incompatible artifacts or dependencies explicitly. Include pinned
source/engine identity, hashes, upstream notices and effective profile selections
in the bundle evidence. Do not claim air-gap readiness merely because a download
cache exists. Installer-internal downloads, activation, interactive prerequisites
and Windows servicing media need their own applicability checks; no credentials
or private license-review records should be silently copied with profiles.

Rationale: the user wants one transferable folder supporting both focused setup
and a broader offline package library. This promotes offline bundle preparation
from a merely optional future idea to explicitly requested functionality, while
keeping toolkit publication and actual installation distinct. Existing Q14 shared
publication/licensing defaults and unattended-install behavior remain in force;
report any resulting omissions instead of describing an incomplete set as complete.
No bundle was acquired, built, published or installed during this decision session.

### Full-set variants and target coverage

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Include both installer
and portable variants where reviewed and available for the selected Windows
targets. Report missing or restricted payloads clearly."

The full external-package bundle includes both reviewed installer and portable
variants where available and applicable to the explicitly selected Windows
targets. Do not silently reduce the full set to one default distribution per
product or expand it to unselected targets. Record requested and included
variants, and clearly report missing or restricted payloads and their reasons.
Reviewed variant eligibility does not invent a local licensing assessment or
override Q14's publication defaults and unattended-install behavior.

This settles variant coverage in the preceding assembly definition. Concrete
target selections remain preparation inputs; availability, dependency closure
and offline compatibility require implementation evidence. How to finalize a
bundle with unavailable requested payloads is the next workflow choice. No
payload acquisition or runtime action was performed here.

### Incomplete bundles and selected-profile preflight

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep partial bundles
with clear omissions, allow profiles with complete payloads, and stop before
changes if the selected profile needs missing payloads."

Retain successfully prepared content when requested payloads are unavailable.
Mark the overall bundle incomplete and list omissions and their reasons. A
profile whose required payloads and dependencies are complete can still be
installed from that bundle. Missing content unrelated to the selected deployment
does not block it.

Before any target changes, check the complete selected profile's required local
payloads and dependencies. If any are missing, stop that deployment before
changes and report what must be acquired. Do not silently skip selected packages
or attempt network fallback. This payload-completeness check does not turn a
pending local licensing assessment into an installation gate contrary to Q14;
publication omissions and unavailable payloads remain explicitly reported.

This settles finalization of partial bundles and the selected-profile missing
payload behavior. Source preparation, integrity validation and Windows-native
acceptance remain implementation work; no bundle or installation was executed
in this decision session.

### Offline bundle refresh and version retention

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Prepare a new bundle
version, reuse verified downloads, and preserve the previous version until I
remove it. Keep RIDE, profiles and package versions pinned together."

Refreshing an offline bundle is an explicit preparation action that produces a
new bundle version. Reuse downloads whose identity and integrity have been
verified against the requested pinned artifacts. Pin the RIDE engine, effective
profiles and package versions together in each bundle's manifest so the source
set remains reproducible. Do not silently advance versions during installation.

Preserve the previous bundle version until the operator explicitly removes it;
refresh must not overwrite or automatically prune it. Any shared payload storage
must preserve the usability of retained versions when another version is removed.
Apply the accepted completeness and omission reporting to each new version.
Preparing a newer version does not install or update anything on a target.

This accepts the offline bundle refresh and retention policy. It does not change
Q04's separate toolkit-publication update policy. No bundle was prepared, removed
or installed during this decision session.

### Optional operator-supplied Windows servicing sources

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Accept optional
inclusion of matching Windows servicing sources that I supply. Check
compatibility before changes and never fall back to the network."

Offer optional inclusion of operator-supplied Windows servicing sources alongside
external package payloads in the offline bundle. Record their identity and
applicability, and check compatibility with the selected target and requested
components before target changes. Do not assume any supplied Windows media can
service every component or Windows target.

Apply the accepted selected-profile preflight to required servicing content:
report missing or incompatible sources before changes, without network fallback.
Supplying sources does not select or enable components. OpenSSH Client and
Telnet Client remain individually selectable and disabled by default under Q05.
Q06's separate online mode still respects configured servicing sources; offline
bundle installation cannot silently switch to that mode.

This settles optional servicing-source inclusion. Actual source paths and target
selections are preparation inputs; compatibility checks and native acceptance
remain implementation work. No media was acquired or copied and no component
was enabled in this decision session.

## Q23 follow-up: Windows guest platforms and individual components

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Support VMware,
Hyper-V and KVM/QEMU, with guest components individually selectable and kept
separate from host installation. Expected hypervisors to be used: Proxmox,
Gnome Boxes (KVM), VMware, Hyper-V."

The requested Windows guest-component scope covers VMware, Hyper-V and KVM/QEMU,
including the expected Proxmox and GNOME Boxes environments. Keep guest
components individually selectable and separate from host hypervisor installation
and configuration. Selecting a guest component does not install or enable a host
hypervisor, move VMs, or alter host preferences.

Treat this as approved product scope, not verified runtime support. Determine
applicable built-in versus separately supplied components for each Windows target
and virtual platform; do not assume the same driver, agent or integration package
is required everywhere. Retain declared publisher sources, integrity and licensing
metadata, focused recovery, and platform-specific acceptance requirements.
Exact component choices and platform-detection behavior remain to be resolved.

This settles the previously unspecified guest-platform scope in Q23. It does not
authorize changes to the developer workstation or protected VM infrastructure.
No guest tools or drivers were acquired, installed or tested in this session.

### Guest-platform detection and unattended selection

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Detect the platform
and suggest matching components, use explicit profile selections for unattended
deployment, and report ambiguity or conflicts before driver changes."

Use platform detection to suggest applicable guest components. Detection is not
authorization to install suggested components. Unattended deployment uses the
operator's explicit profile selections rather than silently selecting components
from detected hardware. Before driver changes, report ambiguous detection or
conflicts between the detected platform and selected profile; do not guess a
platform or substitute another driver set. Leave affected driver changes pending
until the ambiguity or conflict is resolved.

Keep detection and suggestions read-only. Exact detection signals, applicability
checks and test coverage are implementation work; no hypervisor or driver behavior
was validated by this decision. Optional guest convenience integrations remain
a separate choice.

### Guest convenience integrations

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep convenience
integrations individually selectable and never enable them automatically.
Preserve existing settings and report required host-side configuration."

Keep clipboard sharing, drag-and-drop and shared-folder/WebDAV integrations
individually selectable where supported. Installing guest components must not
implicitly enable these convenience integrations. Preserve existing integration
settings unless the operator explicitly selects a change; an unselected option
does not authorize disabling an existing integration either.

Report any host-side configuration required for a selected integration separately
from guest installation. Do not silently change the host or treat installation of
a guest package as evidence that the complete integration works. Availability,
independent configurability, preservation and recovery need evidence for each
platform; report limitations rather than promise unsupported controls.

This settles the convenience-integration policy under Q23. No host or guest
configuration was changed or verified in this decision session.

### AutomatedLab module installation scope

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Include AutomatedLab
module installation, preserving existing modules and lab definitions. Keep host
provisioning and creating or removing labs as separate, explicit workflows."

Include AutomatedLab PowerShell module installation in the requested migration
scope. Preserve existing modules and lab definitions. Resolve dependency and
shared-module collisions explicitly rather than silently replacing, removing or
upgrading existing modules; report incompatible requirements before changes.

Keep host provisioning, lab creation and lab removal as separate, explicitly
selected workflows. Module installation must not implicitly provision the host,
create or remove VMs/labs, or change existing lab definitions. This decision sets
their separation and does not select any provisioning or lab operation to run.

Exact module versions, dependency compatibility, installation scope, recovery and
Windows-native acceptance remain implementation work. Existing protected lab
infrastructure remains untouched. No module was installed or lab changed in this
decision session.

### Lenovo Vantage scope and update separation

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep Lenovo Vantage
optional for compatible Lenovo hardware. Separate app installation from driver,
firmware and BIOS updates, and never trigger those updates automatically."

Retain Lenovo Vantage as an optional application for compatible Lenovo hardware.
Check hardware and package applicability before installation. Keep application
installation separate from driver, firmware and BIOS update workflows; RIDE must
never automatically trigger those updates as part of installing or managing the
application. Unattended app installation does not select an update workflow.

Do not silently alter existing update preferences. Review installer/service
defaults and report any limitations affecting the requested separation rather
than claim that app installation proves updates cannot occur. Exact package
identity, dependencies, supported hardware, recovery and native acceptance remain
implementation work. No application or update was run in this decision session.

### Lenovo Vantage conditional hardware selection

Accepted by the user on 2026-10-17 (Europe/Copenhagen), following the proposal
to add an autodetect-and-install option: "Add this to the decisions logged."

Offer an explicit conditional selection: install Lenovo Vantage when compatible
Lenovo hardware is detected. Detect hardware on the installation target, not on
the computer preparing an offline bundle. Install on confirmed compatible Lenovo
hardware; skip other hardware with a "not applicable" result. If hardware identity
or compatibility is unknown or ambiguous, skip with an explanation rather than
guess. A manufacturer match alone does not establish package compatibility.

Keep ordinary explicit package selection available. Prefer the same stable package
ID with a conditional selection; introduce another package ID only if it denotes
a distinct Vantage product or distribution, not merely detection behavior. Reuse
the accepted adoption workflow for existing installations rather than implicitly
replacing them.

When this conditional option is selected for offline preparation, include its
required payloads and dependencies regardless of the preparation host's hardware.
Retain the existing omission reporting and offline completeness contract; target
applicability determines whether the conditional package is required for that
deployment. Detection does not authorize driver, firmware or BIOS updates, which
remain separate and must never be triggered automatically by RIDE.

This records the conditional-installation decision only. Detection evidence,
profile representation, package compatibility and Windows-native validation remain
implementation work. No package or system configuration was changed here.

## Q23 / R10 follow-up: Hashcat CLI and optional launcher

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Include the CLI and
optional HashcatLauncher, subject to verified availability and compatibility.
Keep GPU driver installation and running workloads separate and explicit."

Include the Hashcat CLI and a separately selectable optional HashcatLauncher in
the requested migration scope. Verify declared-source availability and launcher
compatibility with the selected pinned Hashcat version before admitting the
launcher combination. If those checks cannot be satisfied, report the launcher
as unavailable or pending review; do not substitute an unreviewed launcher or
silently omit it from an explicitly selected deployment.

Keep GPU driver installation and workload execution separate, explicitly selected
actions. Installing or acquiring Hashcat or its launcher does not authorize
driver changes, benchmarks or workload execution. Preserve existing custom
content and apply the accepted ownership/adoption and recovery contracts.

This settles inclusion of both CLI and optional launcher. GPU vendor/hardware
coverage, runtime applicability, exact versions and native acceptance remain to
be established. No package was acquired or installed, driver changed, or workload
run in this decision session.

### GPU vendor coverage and runtime applicability

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Cover NVIDIA, AMD
and Intel, with compatibility checks for each hardware/runtime combination.
Keep driver installation explicit and separate."

Include NVIDIA, AMD and Intel in the requested GPU applicability scope. Check
each actual hardware/runtime combination against the selected pinned tool
version; vendor inclusion alone does not establish compatibility for every GPU,
driver, runtime or virtualized environment. Report unsupported or unverified
combinations without claiming successful hardware acceptance.

Keep driver installation an explicit, separate action. Detection, compatibility
inspection, package installation and optional launcher installation must not
silently install or replace drivers. Workload execution remains separate under
the preceding decision; selecting GPU vendor coverage does not authorize a
benchmark or workload.

This settles requested vendor coverage. Exact hardware fixtures, runtime versions
and Windows-native acceptance remain implementation and validation work. No GPU
driver or runtime was changed and no workload was executed in this session.

## Q18 follow-up: Volatility 3 scope and persistent content

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Default to per-user
isolation, offer machine-wide installation separately, and make symbol/cache
locations configurable. Preserve symbols, caches and custom plugins during
updates or removal."

Default Volatility 3 deployment to a per-user isolated environment. Offer
machine-wide installation as a separate explicit selection with its own scope,
privilege and recovery requirements. Retain the previously accepted pinned
release and reviewed broader plugin dependencies; do not modify another tool's
Python environment or infer that Python manager runtimes support machine scope.
Validate the interpreter deployment needed for each offered installation scope.

Make symbol and cache locations configurable. Preserve symbols, caches and
custom plugins during tool updates and removal, including content at operator-
selected locations. Do not treat preserved content as disposable because it is
called a cache. Any separately selected cleanup remains outside ordinary update
or removal, under the accepted explicit-cleanup contract.

This settles Volatility 3 installation scope and persistent-content policy.
Exact paths are deployment inputs; compatibility, ownership boundaries and
Windows-native lifecycle acceptance remain implementation work. No tool,
environment, symbol, cache or plugin was changed in this decision session.

## R02 follow-up: Python install-manager command integration

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Preserve existing
python/py behavior and file associations, offer changes explicitly after a
conflict preview, and have RIDE use the selected interpreter directly."

For the Python install-manager variant, preserve existing python/py command
resolution and file associations. Offer integration changes only as explicit
choices after previewing conflicts and effects on existing installations.
Installing the manager does not authorize silently replacing another launcher,
claiming command aliases or changing associations. Validate installer behavior
and report any preservation limitation before applying the affected changes.

RIDE must invoke the explicitly selected interpreter directly rather than rely
on whichever Python executable resolves first through PATH or a default alias.
Retain versioned prior-state capture and recovery for selected integration changes.
The previously accepted traditional-installer PATH, association and pip policies
remain unchanged.

This settles command integration for the manager variant. Automatic acquisition
of missing runtimes remains a separate choice; exact compatibility, installer
controls and native acceptance remain implementation work. No manager, command
alias, association or interpreter was changed in this decision session.

### Python runtime acquisition and updates

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Disable automatic
runtime downloads, acquire selected pinned runtimes during preparation, and
offer automatic acquisition only as an explicit online option. Keep updates
separate."

Default RIDE-managed Python runtime acquisition to explicit preparation of the
selected pinned runtimes. Disable implicit downloads triggered by invoking a
missing Python version. Offer automatic acquisition only as an explicit online
option, with its configuration effects previewed and recoverable. Keep runtime
updates separate from preparation, installation and ordinary interpreter use.

Offline deployment must resolve required runtimes from the prepared local bundle,
without network fallback. Apply the accepted selected-profile completeness check
before target changes when a required runtime is missing. Preserve other Python
installations and do not silently change unrelated existing manager configuration;
surface conflicts with the requested acquisition policy before applying changes.

This settles the runtime-acquisition policy. Exact manager controls, pinned
interpreter compatibility and Windows-native acceptance remain implementation
work. No runtime was downloaded, installed, updated or configured in this session.

## Q16 / R01 follow-up: Portable ImageMagick scope and PATH

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use a chosen
destination and per-user scope by default, with shared deployment and PATH
changes explicit after conflict previews. Keep the approved installer behavior
unchanged."

For portable ImageMagick, let the operator choose the destination and default to
per-user deployment without PATH changes. Offer shared deployment and user or
machine PATH integration as separate explicit choices after previewing conflicts,
scope and command-resolution effects. Do not silently shadow an existing
ImageMagick deployment or overwrite conflicting destination content. Use the
accepted adoption/replacement and saved-state recovery contracts.

Keep the approved installed distribution unchanged: x64 Q16 HDRI DLL installer,
all-user machine scope and machine PATH. Portable choices do not replace that
selection or claim parity with all installed-distribution features.

This settles portable scope, destination selection and PATH policy. Concrete
paths are deployment inputs; distribution compatibility, extraction, environment
recovery and native acceptance remain implementation work. Optional installed
integrations remain a separate decision. No files or PATH settings were changed
on a deployment target in this session.

### ImageMagick optional installed integrations

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Leave optional
integrations unselected on fresh installs, preserve existing choices on adoption
or upgrades, and preview requested changes. Keep machine PATH enabled."

For fresh ImageMagick installer deployments, leave optional integrations
unselected, except the already approved machine PATH integration, which remains
enabled. During adoption or upgrades, preserve existing integration choices;
unselected fresh-install defaults do not authorize resetting existing choices.
Offer supported optional integration changes explicitly and preview their effects,
including any requested file-association changes, before application.

Preserve unrelated environment and association state, capture prior values for
selected changes, and report conflicts or installer preservation limitations.
Verify the actual optional controls of the pinned installer rather than assuming
an upstream default or unsupported flag implements this policy.

This settles the remaining ImageMagick installer-integration policy while keeping
the approved distribution, all-user scope and machine PATH behavior. Exact flags,
state recovery and Windows-native acceptance remain implementation work. No
installer or system integration was changed in this decision session.

## R03 follow-up: Independently selectable Microsoft OpenJDK

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep Microsoft
OpenJDK independently selectable for Java development and other applications,
preserving existing Java installations."

Retain Microsoft OpenJDK as an independently selectable product for Java
development and other applications. Do not limit it to dependencies of the
previous graph stack or retire it because standalone Neo4j/APOC is deferred and
ImproHound deployment is retired.

Preserve existing Java installations. Product selection alone does not authorize
removal, replacement, migration between installer methods, or changes to an
existing installation's environment and associations. Use the accepted explicit
adoption/replacement model where applicable and report compatibility conflicts.

This establishes an independent use case and settles product retention. Java
major versions, coexistence and environment-integration choices remain separate;
publisher availability, exact pins, installer behavior, recovery and native
acceptance remain implementation work. No Java installation was acquired or
changed in this decision session.

### Java coexistence and environment integration

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Allow side-by-side
JDK versions and use explicit runtime paths. Preserve JAVA_HOME, PATH and .jar
associations by default, with changes explicit after conflict previews."

Allow separately selected JDK major versions side by side, subject to verified
installer and runtime compatibility. Use explicit runtime paths for managed
applications rather than relying on the global Java default. Preserve existing
JAVA_HOME, PATH and .jar associations by default. Offer changes individually as
explicit selections after previewing conflicts and command-resolution effects,
with captured prior state and recovery.

Do not silently migrate existing Java installations or change an application's
selected runtime when adding another JDK. Distinguish major-version coexistence
from update or replacement of an existing installation of the same major; the
latter retains the accepted ownership, preview and preservation requirements.

This settles coexistence and integration policy. JDK major-version selection is
the next product choice; exact artifacts, installer-method constraints and native
acceptance remain implementation work. No Java or environment changes were made
in this session.

### Microsoft OpenJDK major-version policy

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes" to the proposed
JDK 25 LTS default for new standalone deployments, with JDK 21, 17 and 11
explicitly selectable for application compatibility, reviewed patch releases
pinned, and no automatic application migration between majors.

Default new standalone Microsoft OpenJDK selections to JDK 25 LTS. Offer 21,
17 and 11 as explicit compatibility selections. Pin reviewed patch releases for
each selected major; do not silently advance existing applications to another
major or overwrite their explicit runtime paths. Preserve the accepted
side-by-side and environment-integration policies.

The [Microsoft support roadmap](https://learn.microsoft.com/en-us/java/openjdk/support)
was checked on 2026-10-17 and lists all four LTS majors. Publisher servicing
status does not establish application compatibility or RIDE native acceptance.
Review support and artifact availability when preparing future pins; do not
silently substitute another major when a requested version is unavailable.

This settles the major-version policy. Exact patch/artifact pins, application
compatibility and Windows-native acceptance remain implementation work. No JDK
was acquired, installed or migrated in this decision session.

## Q24 / R09 follow-up: Reviewed Arsenal collection

Accepted by the user on 2026-10-17 (Europe/Copenhagen): option 2, "A reviewed
Arsenal collection, with each product individually selectable and an option to
select the whole collection."

Prepare a curated, versioned Arsenal collection with individually selectable
products and an explicit whole-reviewed-collection selection. Do not restrict
the requested scope to Image Mounter alone. Exact initial product membership is
the next decision; selecting this collection model does not automatically admit
every publisher product or future addition.

Retain Q13's reviewed-member and proposed-upstream-addition policy. Keep licensing
and activation, driver installation, and actual forensic operations separate from
collection selection and acquisition. Apply Q14's existing local-review,
unattended-install and shared-kit omission contracts without creating another
licensing gate. Do not acquire entitlements, activate products, install drivers,
mount evidence or run forensic workloads through this decision alone.

The [publisher product catalog](https://arsenalrecon.com/products) was reviewed
on 2026-10-17 to present the choice. Exact artifacts, compatibility, dependencies,
preservation, recovery and native acceptance remain implementation work. MEGAcmd
is still a separately assessed helper, not an implicit collection dependency.
No Arsenal product was acquired, installed or executed in this decision session.

### Initial Arsenal collection membership

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes" to the proposed
eight-product initial scope, subject to acquisition and compatibility review:

- Arsenal Image Mounter
- Hibernation Recon
- Registry Recon
- HBIN Recon
- Hive Recon
- ODC Recon
- Swap Recon
- LevelDB Recon

Keep these products individually selectable and offer selection of the whole
reviewed collection. This approves the intended member list; it does not assert
that each member already has an accepted artifact or supported deployment.
Report unavailable, restricted or incompatible members using the accepted
omission and selected-profile completeness contracts. Do not silently substitute
products or include new publisher additions automatically.

Treat Arsenal's open-source utilities as a separate future collection, outside
this initial member list. Keep licensing/activation, driver installation and
forensic execution separate under the preceding decision. MEGAcmd helper scope
remains the next independent choice.

Membership is based on the publisher catalog linked above. Exact pins,
acquisition, compatibility and native lifecycle acceptance remain implementation
work. No collection payload was acquired, installed or executed here.

### MEGAcmd helper disposition

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes" to deferring
MEGAcmd deployment unless a reviewed acquisition source requires it or the
operator wants it independently, preserving existing installations and never
installing it implicitly with Arsenal products.

Defer the legacy MEGAcmd helper deployment. Reconsider it only for an evidenced
requirement of a reviewed acquisition source or an independently selected use
case. Such a requirement must be declared and reviewed; it does not authorize
silently installing MEGAcmd with an Arsenal product or whole-collection selection.
Keep existing MEGAcmd installations and their data untouched.

This is a conditional deferral, not retirement or a claim that all future Arsenal
sources can be acquired without a helper. Source selection and compatibility
remain implementation work, with missing payloads reported under the accepted
bundle contracts. No helper was installed, removed or executed in this session.

## Q19 follow-up: Backend-version compatibility decision deferred

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Defer this decision.
Continue with other decisions" in response to choosing the BloodHound CE backend
version for SharpHound and AzureHound compatibility.

Leave the exact external BloodHound CE backend version and matched collector
versions pending. Do not infer a latest backend, select a compatibility pair on
the user's behalf, or claim backend acceptance from this deferral. Keep the
accepted collectors-first scope and separately managed backend unchanged.

Continue independent migration preparation and unrelated decisions. Resolve the
backend version and obtain compatibility evidence before claiming a matched
collector deployment is ready for that backend. This defers the version input,
not the whole collector product scope, and authorizes no collection execution,
credentials or backend changes.

## Q13 / R05 follow-up: Initial Sysinternals collection scope

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes" to the full
official Sysinternals Suite as the initial scope, frozen to a reviewed inventory
with recorded versions and hashes, individual and whole-collection selection,
and explicit review of future additions.

Use the complete official Sysinternals Suite as the intended initial collection
scope. Inventory and pin its exact members, versions and hashes before admission;
do not resolve membership through a mutable download at deployment time. Retain
upstream notices and apply the accepted per-target applicability and omission
contracts. A suite membership decision does not expand supported Windows targets
or declare every member technically accepted.

Keep tools individually selectable, offer the whole reviewed collection, and
propose future upstream additions for review instead of silently adding them.
Copying or acquiring tools does not execute them, accept interactive terms on the
operator's behalf, install drivers, or activate services such as Sysmon. Preserve
the accepted RIDE configuration-ownership and separate Sysmon application model.

The [official suite page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
was reviewed on 2026-10-17. Exact payload inventory, integrity, dependencies,
recovery and native acceptance remain implementation work. No suite payload was
acquired, installed or executed in this decision session.

## Q13 / R05 follow-up: Zimmerman forensic collection and updater review

Accepted by the user on 2026-10-17 (Europe/Copenhagen): include the forensic
tools collection, keep KAPE separate, and use reviewed artifacts without
automatically running the updater. The user additionally requested validation
of existing v2 acquisition/update scripts and newer upstream replacements to
determine whether they are obsolete or still relevant. Do not discard useful
update capabilities merely because normal deployment uses pinned artifacts.

The initial collection is the publisher's [Forensic tools section](https://ericzimmerman.github.io/#forensic-tools),
reviewed on 2026-10-17: AmcacheParser, AppCompatCacheParser, bstrings, EvtxECmd,
EZViewer, Hasher, JLECmd, JumpList Explorer, LECmd, MFTECmd, MFTExplorer, PECmd,
RBCmd, RecentFileCacheParser, RECmd, Registry Explorer, RLA, SDB Explorer,
SBECmd, ShellBags Explorer, SQLECmd, SrumECmd, SumECmd, Timeline Explorer,
VSCMount and WxTCmd. Freeze the exact artifacts, versions and hashes following
review; offer individual and whole-reviewed-collection selection. Keep KAPE
separately managed and other helper utilities outside this initial collection.
Future additions remain proposals. Apply the established applicability,
licensing, preservation and omission contracts per member.

### Acquisition/update source review, 2026-10-17

Review scope here is static inspection, not execution or deployment acceptance.
Windows-native PowerShell parsing of `legacy/v2/lib-windows.psm1` returned zero
parser errors. That does not establish correct downloads or safe updates.

- The v2 `InstallZimmermanTools` wrapper (line 8456) downloads mutable GitHub
  `master`, invokes it using `Invoke-Expression` with all runtime variants before
  checking download-only mode, and deletes an existing destination before copying.
  Its syntax parses, but this execution/replacement model is unsuitable for v3.
  Preserve useful acquisition intent and replace the wrapper rather than reconnect
  the legacy library or discard updater functionality.
- The [current upstream source](https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1)
  remains relevant: it discovers downloads, compares ETags for incremental refresh,
  supports runtime variants and offers optional ancillary-file synchronization.
  It is not ready for unmodified v3 execution. Discovery is mutable; ETag values
  stored in a SHA1-labelled field do not validate downloaded bytes. Extraction
  overwrites destination files. The initial suspected endless HEAD retry was
  corrected by the bounded control-flow review below: the duplicate-URL guard
  advances on the next iteration, so the failed candidate is skipped. The optional Sync
  path executes downloaded tools. Pin and inspect an immutable revision, enforce
  bounded retries, staged extraction, allowed membership, integrity and separate
  synchronization before integration. The publisher's linked ZIP could not be
  inspected through the web reader; equivalence to GitHub source is unverified.
- Initial adjacent-v2 triage: Sysinternals obtains a mutable suite ZIP; JoeWare
  discovers forms through HTTP pages; MiTeC crawls HTTP HTML links; NTCore relies
  on page/link shapes; NirSoft scrapes download links and archive-password HTML.
  These remain useful records of acquisition intent, but cannot define immutable
  v3 collection membership. Endpoint failure or old markup alone does not prove
  the underlying product is obsolete.

Continue the requested per-script review during each collection migration:
compare legacy behavior with publisher-maintained replacements; classify retain,
adapt, replace or obsolete with evidence; validate syntax and bounded mocked
network/failure behavior, integrity, extraction, membership, preservation and
recovery. Preserve authorship/notices. Only explicit preparation/update workflows
may run an admitted pinned helper; installation must not implicitly execute a
mutable updater. No acquisition helper or downloaded tool was executed here.
The adjacent scripts have only preliminary triage, not completed validation.

### Zimmerman maps and batch definitions

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes - continue" to
including reviewed upstream maps and batch definitions alongside the tools,
refreshing them separately, preserving custom files and asking before replacing
local modifications.

Include reviewed, pinned upstream maps and batch definitions applicable to the
selected Zimmerman tools. Record their source revision, integrity and compatible
tool versions; retain required notices. Their inclusion does not authorize
running a batch definition, processing evidence or executing a tool's sync command.

Make refresh a separate explicit action. Preserve custom files and require an
explicit choice before replacing locally modified managed files. Stage and
validate refreshed content before applying it, using the accepted ownership and
recovery patterns. Do not let an upstream synchronization helper bypass these
preservation rules or silently expand the selected content set.

Include selected ancillary content in offline completeness checks and pinned
bundle evidence, without network fallback. Exact inventories, compatibility and
helper validation remain implementation work. No maps were fetched, replaced or
executed in this decision session.

## R02 follow-up: Standalone YARA engine selection

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to
YARA-X for new standalone deployments and classic YARA as an explicit
compatibility option, separately selectable, subject to verified Windows
artifacts, with no silent engine substitution.

Default new standalone engine selections to YARA-X. Retain classic YARA as an
explicit compatibility selection with distinct version, artifact and dependency
identity. Do not silently replace an application's requested engine or infer
complete rule/API compatibility between engines. Pin reviewed releases and
validate applicable Windows artifacts and selected rule compatibility.

The [classic YARA project](https://github.com/VirusTotal/yara) states that it is
in maintenance mode; [YARA-X](https://github.com/VirusTotal/yara-x) is separately
maintained. This product decision does not resolve the existing classic-YARA
Windows binary/build gate or authorize substituting an older binary. Acquisition,
updates, rule selection and scanning retain their separate boundaries.

Exact artifact/build provenance, licensing metadata, native validation and
recovery remain implementation work. No engine was acquired or installed and no
scan was run in this decision session.

## Q13 / R05 follow-up: NirSoft collection and optional launcher

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Approved" to a
frozen, reviewed collection based on the NirLauncher package and x64 tools,
individual and whole-collection selection, an optional launcher, preservation of
existing launcher configuration, and per-tool licensing and compatibility review.

Use the [NirLauncher package](https://launcher.nirsoft.net/) and
[x64 tools package](https://www.nirsoft.net/x64_download_package.html) as the
initial inventory sources. Freeze exact members, versions, architectures and
hashes after review; resolve overlapping members explicitly without silently
overwriting a selected variant. Keep individual tool selection and an explicit
whole-reviewed-collection option. Future upstream additions remain proposals.

Keep NirLauncher separately selectable. Preserve existing launcher configuration
and custom entries; changes to managed package/configuration files follow the
accepted preview, local-modification and recovery contracts. Tool selection does
not authorize running a tool or changing its operational settings.

Assess licensing and target compatibility per utility, retaining notices and
applying Q14's local-review and shared-kit omission rules. Do not treat the
collection's general description as blanket licensing or platform acceptance.
The publisher pages were reviewed on 2026-10-17; exact payload inventories,
bounded extraction, acquisition-helper validation and Windows-native acceptance
remain implementation work. No package was acquired or tool executed here.

## Q13 / R05 follow-up: JoeWare collection scope

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to
using the full official JoeWare tools catalog as the initial review inventory,
individual and whole-reviewed-collection selection, per-tool current Windows
compatibility assessment, and clear unavailable/unsupported-member reporting.

Use the [official tools catalog](https://www.joeware.net/freetools/index.htm)
as the initial review inventory. Freeze named members, versions, artifacts and
hashes before admission rather than crawling the changing site at deployment.
Offer individual selection and the whole reviewed collection. Apply the accepted
new-addition, licensing, preservation and offline omission contracts per member.

Assess older tools individually against the declared Windows targets and relevant
directory/service environments. Historical publisher compatibility labels do not
prove current support, and age alone does not establish obsolescence. Clearly
report unsupported or unavailable members; do not silently substitute another
utility or represent unresolved members as accepted.

This approves review scope, not execution of administrative tools or changes to
accounts, directory objects, credentials, services or domain membership. Exact
inventory, acquisition-script modernization, recovery and native acceptance
remain implementation work. No JoeWare payload was acquired or executed here.

## Q13 / R05 follow-up: MiTeC collection scope

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to a
reviewed collection of MiTeC standalone applications and tools, individual and
whole-collection selection, exclusion of developer component libraries and demos
from this collection, and per-product edition/licensing distinctions.

Use the publisher's [Apps & Tools catalog](https://www.mitec.cz/wp/apps/) and
official linked product pages to establish an explicit reviewed inventory of
standalone applications and tools. Keep developer component libraries and demos
outside this initial collection. Offer individual members and an explicit
whole-reviewed-collection selection; propose future additions separately.

Identify editions and applicable licensing per product and version. Do not infer
eligibility from a freeware label, an older page or a filename-based trial/demo
filter. Preserve Q14's local assessment, unattended-install and shared-kit
omission behavior. Reconcile products already tracked separately, including
Structured Storage Viewer, without duplicate deployment ownership.

The publisher is transitioning its website and links to older pages; inspect
current authoritative downloads rather than treating the legacy HTML crawler as
validated. Exact membership, pins, acquisition-helper modernization, preservation,
recovery and target acceptance remain implementation work. No MiTeC payload was
acquired or executed in this decision session.

## Q13 / R05 follow-up: NTCore collection scope

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to
reviewing NTCore standalone utilities as a collection, including Explorer
Suite/CFF Explorer, PE Detective and 4GB Patch, with individual and whole-reviewed-
collection selection, Cerbero Suite separate, and source-code examples excluded.

Use the [official download catalog](https://ntcore.com/download/) as the initial
review inventory of standalone utilities. Keep Cerbero Suite separately assessed
and source-code examples outside the collection. Freeze exact reviewed members,
versions, artifacts and hashes; propose future additions separately.

Assess older utilities individually for supported-target compatibility and
applicable licensing before admission. Neither age nor presence on the current
download page establishes obsolescence or native acceptance. Apply the accepted
omission, preservation, adoption and recovery contracts. Collection selection and
file acquisition do not execute tools, patch binaries or change Windows settings.

This settles the requested collection scope. Exact membership, acquisition-script
modernization, compatibility and Windows-native validation remain implementation
work. No NTCore payload was acquired or executed in this decision session.

## R02: LOKI RS beta approved; older Python Loki handling excluded

Fresh publisher review found that [Python Loki](https://github.com/Neo23x0/Loki)
is explicitly deprecated and points to [LOKI RS](https://github.com/Neo23x0/Loki-RS).
The latter describes itself as beta, uses YARA-X and defaults to YARA Forge Core
signatures. This prompted a product-scope decision before signature selection.

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Do not consider
handling of older python loki installations. Loki rs as beta is approved."

Include LOKI RS as a separately identified, explicitly selected beta option.
Keep its beta status visible; pin a reviewed release and validate Windows
behavior, runtime requirements and rule compatibility before native acceptance.
Product approval alone does not establish completed implementation or validation.

Exclude handling of older Python Loki installations from this migration scope.
Do not design Loki-specific discovery, adoption, upgrade, conversion, migration
of old rules/reports, or uninstall workflows for them. This supersedes the
preceding proposal to handle legacy-installation preservation as transition work;
it does not authorize modifying or deleting older installations or data.

Standalone YARA versus YARA-X remains an independent product decision. Signature
selection is the next choice. Acquisition, updates and scanning remain separate;
no scanner or updater was acquired or run in this decision session.

### LOKI RS signature collection

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to
YARA Forge Core as the default LOKI RS signature set, Extended and Full as explicit
options, reviewed snapshots pinned, refresh separate, and custom rules preserved.

Default selected LOKI RS deployments to a reviewed, pinned YARA Forge Core
snapshot. Offer Extended and Full as explicit alternatives. Record the selected
set, source revision, integrity, notices and compatibility with the pinned scanner
release in acquisition and offline bundle evidence. Do not silently change sets
or treat broader coverage as a reason to enable an unselected alternative.

Keep signature refresh separate from scanner installation and scanning. Preserve
custom rules and apply the accepted preview/confirmation contract before replacing
locally modified managed content. Do not let upstream update commands bypass
these rules or introduce a network fallback during offline installation.

The [upstream signature documentation](https://github.com/Neo23x0/Loki-RS#signatures)
informs the set names; exact snapshots, rule compilation compatibility, update
helper validation and Windows-native acceptance remain implementation work.
Older Python Loki handling stays excluded. No signatures were acquired or scan
executed in this decision session.

## R09 follow-up: VeraCrypt installed and portable scope

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to
retaining installed and portable VeraCrypt variants, preserving existing settings,
containers and keyfiles, and keeping mounting, encryption, decryption and
system-encryption setup separate from deployment.

Offer both installed and portable variants with explicit distribution identity
and ownership. Preserve existing settings, containers and keyfiles during
deployment, update and removal. Do not infer permission to overwrite data or
configuration from selecting either variant; use the accepted conflict preview,
adoption and recovery contracts.

Keep mounting, encryption, decryption and system-encryption setup as separate
explicit workflows. Deployment does not select or execute these operations.
The [publisher's portable-mode documentation](https://veracrypt.io/en/Portable%20Mode.html)
confirms administrator and driver-lifecycle requirements; portable file presence
is not evidence of successful driver load, unload or recovery. Validate each
variant's driver ownership, retained-version recovery and reboot reporting on
declared Windows targets without automatic reboot or forced dismount.

Exact release pins, installer behavior and Windows-native acceptance remain
implementation work. No payload was acquired, driver loaded, volume mounted or
encrypted data changed in this decision session.

## R09 follow-up: WinPmem preparation and capture separation

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to
including a pinned WinPmem acquisition executable, keeping driver loading and
memory capture explicit, checking driver signing and target compatibility first,
requiring a chosen output location, and preserving existing captures during
updates or removal.

Include the reviewed, pinned acquisition executable as a deployable tool. Tool
preparation and file deployment must not implicitly load its driver or acquire
memory. Driver loading and memory capture require explicit selection of the
applicable action; a selected capture workflow may declare its required driver
lifecycle, with compatibility and signing checked before activation.

Require an operator-chosen capture output location and preserve existing captures
during tool updates or removal. Do not overwrite a prior capture implicitly.
Validate driver cleanup, partial-failure reporting and recovery on the declared
Windows targets. Do not claim current-target support solely from historical
[publisher documentation](https://github.com/Velocidex/WinPmem).

Exact artifact provenance, signing/current-build compatibility and native
acceptance remain implementation work. No driver was loaded and no memory was
captured in this decision session.

## Q24 / R12 follow-up: KAPE Targets and Modules

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Yes. Proceed" to
including a reviewed, pinned KapeFiles snapshot, separate refresh, preservation
of custom definitions, and individual review of referenced third-party executable
dependencies without automatically downloading or running them when definitions
are copied.

Include the reviewed Targets and Modules definitions from a pinned
[KapeFiles revision](https://github.com/EricZimmerman/KapeFiles). Record the
revision, content hashes, notices and compatibility with the selected KAPE
release. Keep definition refresh separate from installation and execution;
preserve custom definitions and ask before replacing locally modified managed
files under the existing update contract.

Treat referenced third-party executables as separately declared, reviewed
dependencies with exact sources, versions, integrity and licensing metadata.
Copying a definition does not acquire or execute its referenced binary. Explicit
preparation can include dependencies for selected workflows; report missing
dependencies and distinguish definitions present from a runnable, complete
workflow. Retain offline preflight and no-network-fallback requirements.

This does not authorize collection or processing of evidence, implicit security
exclusions or upstream sync execution. KAPE remains separately managed from the
Zimmerman collection. Exact inventories, dependency checks, helper review and
native acceptance remain implementation work. No definition or dependency was
downloaded and no KAPE workflow was executed in this decision session.

## R12 follow-up: Retain four separate CCleaner-family products

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep all four
individually selectable, preserving existing installations. Review editions and
available distributions separately."

Retain CCleaner, Defraggler, Recuva and Speccy as four independently selectable
products. Do not bundle-install the other three when one is selected. Preserve
existing installations and use the accepted explicit adoption/replacement model.
This retention decision does not choose editions, distribution variants, activation,
automatic maintenance or operational use.

Review editions and declared publisher distributions separately for each product,
with per-version integrity, licensing and target compatibility evidence. Product
retention is not a claim that every historical portable artifact remains available.

Read-only publisher-page check, 2026-10-17: the
[CCleaner builds page](https://www.ccleaner.com/ccleaner/builds) lists online,
offline and portable downloads; its advanced-build notice restricts distribution
and mirroring. The [Recuva](https://www.ccleaner.com/recuva/builds) and
[Speccy](https://www.ccleaner.com/speccy/builds) builds pages each list an installer.
The Defraggler builds URL redirects to a JavaScript-dependent product page, so
its artifact availability was not established by this reader. These observations
do not prove artifact freshness, complete edition availability or disappearance
of historical alternatives. Apply the existing shared-kit review/omission policy.

Exact edition/distribution selections are pending. Artifact validation,
preservation, recovery and native acceptance remain implementation work. No
product was acquired, installed, removed or executed in this decision session.

## R12 follow-up: Installed and portable distribution preference

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Use installed versions
as primary choices, offer reviewed official portable builds separately, and
report unavailable variants without substitution."

For CCleaner, Defraggler, Recuva and Speccy, present installed distributions as
the primary choices. Offer an official portable build as a separate selection
only where its availability, provenance, licensing and target compatibility have
been reviewed. Preserve existing installations under the accepted adoption and
replacement contract.

Report unavailable requested variants explicitly. Do not silently substitute an
installer for a portable build, another edition, or another product. This
preference does not establish that every product has a current portable build.
Apply the existing offline completeness and omission rules to selected variants.

This resolves distribution preference; edition selection remains open. Exact
artifact review and native acceptance remain implementation work. No payload
was downloaded and no installation or system setting was changed.

## R12 follow-up: Explicit edition selection

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Let profiles explicitly
select the edition, preserve existing editions and activation by default, and
never start trials or paid upgrades automatically."

For CCleaner, Defraggler, Recuva and Speccy, profiles explicitly select the
reviewed edition. Preserve existing editions and activation by default during
adoption and maintenance. Never initiate a trial or paid upgrade automatically,
and do not substitute an available edition for an unavailable requested edition.
There is no universal Free-edition default. Review each publisher offering and
its applicable terms separately under the existing local licensing-review and
unattended-deployment contract.

This resolves the edition-selection policy. Exact available editions, artifact
metadata, activation-preservation behavior and Windows-native acceptance remain
implementation work. No product was installed or activated in this session.

## R12 follow-up: Optional TMOG and separate integrations

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep TMOG optional with
explicit edition selection, preserve settings and activation, and keep startup
and screensaver changes separate and off by default."

Retain TMOG as an optional package with explicit edition selection. Preserve
existing settings and activation during adoption and maintenance. Treat startup
integration and screensaver configuration as separate choices, both unselected
by default. Installing the application must not implicitly enable either choice
or disable an existing user-selected configuration.

The [publisher product page](https://tmog.org/) lists Free and optional Pro
editions. Exact current artifacts, applicable edition terms, unattended installer
behavior and configuration/activation recovery still require review and native
acceptance. The historical installer/license observations remain audit evidence;
this scope decision does not establish that current artifacts have identical
behavior or terms. No installation, activation, startup or screensaver change
was performed in this decision session.

## R12 follow-up: Separate PST and OST viewers

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep PST Viewer and
OST Viewer individually selectable, preserve existing installations and mailbox
files, and leave paid repair/conversion products outside the initial scope."

Retain Kernel PST Viewer and Kernel OST Viewer as two individually selectable
packages. Preserve existing installations and mailbox files during adoption,
updates and removal. Selecting either viewer does not select the other product
or a paid repair/conversion product. Paid repair/conversion products remain
outside the initial scope.

The publisher lists the [PST Viewer](https://www.nucleustechnologies.com/pst-viewer.html)
and [OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html) as free
viewers. Exact artifact/terms review and shared RICHTX32.OCX registration,
ownership and recovery remain implementation work under the existing licensing
and lifecycle contracts. Validate coexistence and removal without breaking the
other viewer or unrelated applications. No installer was executed and no mailbox
file was opened or changed in this decision session.

## R12 follow-up: Optional WinHex and explicit licence selection

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep WinHex optional
with explicit licence selection, preserve existing licences and settings, and
make evaluation explicit. Leave the other X-Ways products outside the initial
scope."

Retain WinHex as an optional package with explicit licence-type selection.
Preserve existing licences and settings during adoption and maintenance. Offer
evaluation only when explicitly selected; do not substitute evaluation for a
requested licensed deployment or automatically change the licence type.

X-Ways Forensics, X-Ways Investigator and X-Ways Imager remain outside this
initial scope. The [publisher comparison](https://www.x-ways.net/comparison.html)
distinguishes WinHex licence types and related products. Exact official HTTPS
artifacts, applicable terms, configuration/licence preservation and native
acceptance remain implementation work under the existing licensing contract.
No product was downloaded, installed, activated or executed in this session.

## R13 follow-up: Retain historical tools with individual review

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Keep them individually
selectable, preserve existing installations, and defer unverified tools without
substitution. Bring back concrete exceptions for review."

Retain FirewallNotifier, Autorunner, ChromeParser, Hex2text, ShimCacheParser,
SSView, ThumbcacheViewer, SuperFetchTools2, UserAssist, ThumbsViewer and RegRipper
as individually selectable candidates. Use reviewed pinned artifacts, preserve
existing installations and report tested Windows versions and supported data
formats accurately. Successful file deployment alone does not establish parser
correctness or current-format compatibility.

Defer tools whose provenance or compatibility cannot be established, without
silently replacing them. Bring concrete exceptions back for user review when
the investigation establishes a product decision is needed. Routine source,
dependency, integrity and native acceptance work proceeds under existing
authorization without reopening this retention policy. Reconcile collection
overlaps through shared product identity and ownership, not duplicate deployment.

This is retention-policy acceptance, not a claim that all eleven products have
passed artifact or native validation. No tool was acquired, installed or run,
and no existing installation was changed in this decision session.

## Shared installers and licence tiers

Accepted by the user on 2026-10-17 (Europe/Copenhagen), explicitly applying to
"TMOG and others": when free, paid or feature-tier editions use the same
installer and installed application, model them as one package. Do not create
separate installation variants solely because a licence key, subscription or
account unlocks additional features.

Separate installation, adoption, update and removal from licensing and activation.
Preserve existing settings and activation during adoption and updates. Activation
or licence changes are explicit, optional actions using publisher-supported
methods. Installing or adopting the shared application does not require selecting
or changing its licence tier, and must not implicitly initiate a trial or paid
upgrade.

Create separate deployment variants only where artifacts, installed components
or deployment behavior materially differ. Review those differences from publisher
evidence; marketing edition names alone are insufficient. Keep startup,
integrations and other optional configuration independently selectable.

This rule clarifies and supersedes any earlier wording in this record that could
require licence-tier selection as an installation prerequisite or imply separate
packages for entitlement-only differences. In particular, apply it to the TMOG,
CCleaner-family and WinHex decisions where publisher evidence establishes shared
installation behavior. A profile may separately request a supported activation
or licence change; omission preserves the existing activation state. Retain
distinct products and materially different deployment variants, including the
previously selected installed/portable choices where applicable.

Exact per-product artifact equivalence and activation-preservation checks remain
implementation work. This records the common model; it does not claim that every
named product uses identical artifacts across all editions or that activation
has been tested. No package, licence or system configuration was changed.

## D06 follow-up: Defer BitLocker and recovery test setup

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Defer the BitLocker and
recovery test setup for now."

Defer selection and preparation of the disposable TPM/boot test environment,
off-device recovery-information destination and retrieval/unlock verifier.
Dependent BitLocker and Windows recovery acceptance remains pending; this
deferral is neither test acceptance nor permission to use the developer
workstation or assume a recovery destination.

Continue independent migration and review work under existing authorization.
Retain the accepted recovery contract and outstanding technical evidence; reopen
this setup when the user chooses to arrange the required resources. No recovery
secret was requested or recorded and no boot, encryption or recovery state was
changed in this session.

## Deployment profile selection deferred

Accepted by the user on 2026-10-17 (Europe/Copenhagen): "Defer deployment
profiles for now."

Defer choosing and composing the first forensic analyst or developer workstation
deployment profile, including its default package selections and setting values.
The suggested forensic-first order was not accepted. Preserve existing profiles;
this deferral does not select new defaults or revise their contents.

Generic package, setting, collection and offline-bundle preparation can continue
under the accepted contracts without waiting for a new deployment profile.
Deployment-specific identities, destinations, exclusions and schedules remain
inputs to supply when those workflows are configured. Bring back concrete product
exceptions when technical review identifies a material unresolved choice rather
than treating routine validation as another approval gate.

The broad product/workflow decision pass is covered by the accepted entries in
this record. Remaining work includes technical evidence, explicit deferrals and
test/profile-specific inputs; this is not a declaration of migration completion.
No profile or system configuration was changed in this session.

## Artifact, compatibility and updater review continuation, 2026-10-17

The user authorized continued review under the accepted decisions, keeping
deferrals closed and returning only concrete exceptions needing a decision.
This pass inspected eight legacy acquisition functions and the Zimmerman CMD/NLP
helpers, compared publisher sources, and ran nine bounded in-memory fixtures in
Windows-native PowerShell 7.6.5. It did not import or execute the legacy library,
upstream updater, installer or application. No executable payload was acquired.
The decision record is the only repository file changed by this pass; concurrent
implementation and its ledgers remain independently owned.

### Updater classification and implementation consequences

| Source | Disposition | Verified source finding and next implementation step |
| --- | --- | --- |
| `GetSysinternalsSuite`, line 2111 | Replace wrapper; retain official archive acquisition | Deletes the destination before deployment and lacks its own digest verification. The existing [pinned Suite inventory](../archive/evidence/sysinternals-suite-source-review-2026-10-17.json) already records 164 members; reuse that evidence and the owned-file lifecycle rather than reacquire or rerun passed tests. Microsoft's [Suite page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) still supplies separate regular, Nano and ARM64 distributions; their existence does not expand selected targets. |
| `InstallNirsoftLauncher`, line 2192, and `InstallNirsoftToolsX64`, line 2482 | Replace wrappers; retain publisher sources | Both delete the destination before checking/executing 7-Zip and report installation without checking its exit code. Password parsing is unchecked and URL construction assumes a particular relative-link form. Use reviewed archive metadata, explicit architecture, bounded extraction and verified staging before changing an existing deployment. |
| `InstallNirsoftPkgFiles`, line 2300 | Replace blanket config updater; retain optional launcher integration | Downloads every matching NLP file, force-writes configuration, and its CCleaner copy uses the loop's `$NLPFileFullName` rather than the selected `$SourceFile`. A destination Join-Path also occurs outside the download-only guard although `$ToolsFolder` is assigned inside it. Generate or merge only selected reviewed launcher entries, preserving custom entries; do not copy all upstream integration files automatically. |
| `InstallJoeWare`, line 2588 | Replace broad scraper; retain per-product acquisition intent | Discovers all tool pages over HTTP, derives output names from form fields and POSTs to a shared download endpoint. It then clears the destination before extraction. Review exact product pages, HTTPS routes, form response identity and bounded output names; stop treating every form result as a verified ZIP. |
| `InstallMitec`, line 2806 | Replace HTML crawler; retain selected products | Uses HTTP and takes the first qualifying artifact without architecture selection. Download existence drives its retry/success check; extraction deploys ZIPs although acquisition also accepts EXEs. The publisher's [new apps page](https://www.mitec.cz/wp/apps/) links old pages during migration. Resolve each reviewed product route and distribution; neither a missing old selector nor an EXE left uninstalled means the product is obsolete. |
| `InstallNtcore`, line 2920 | Replace old-page crawler; retain selected utilities | Requires old relative `/?page_id*` links and concatenates hostnames; can return before processing direct downloads. It also includes source-file transformations outside the accepted standalone-utility scope. Use the [current download index](https://ntcore.com/download/) and exact member pages. Filter Monitor's publisher description limits historical testing to Vista/Windows 7 and warns about future internals: current-target compatibility stays deferred, without replacement or retirement. |
| `InstallZimmermanTools`, line 8456 | Replace v2 execution/deployment wrapper; adapt useful upstream discovery logic | Mutable script execution precedes the download-only guard; destination replacement deletes existing content. Preserve updater functionality through separately selected, pinned preparation with verified members and recovery. Do not reconnect the wrapper. |
| `components/files/Get-ZimmermanTools.cmd` and `zimmermantools.nlp` | Replace or adapt as reviewed launcher integration | CMD runs the adjacent script with all runtime variants and an unquoted destination; NLP exposes updater entries and mutable URLs. Reconcile these with explicit runtime selection and the separate preparation/update action, including space-containing destinations. Do not publish the existing shortcuts as a safe managed updater. |

All eight inspected legacy function bodies lack their own SHA-256 verification.
This is a bounded function-body observation, not a claim about every helper in
the repository. Existing Sysinternals evidence identifies the same legacy source
SHA-256, `4827a032607e96a2eb49bd53bb02bdeab860a5481a1ab68954480452a3f4cdea`.

The [NirLauncher page](https://launcher.nirsoft.net/downloads/index.html) publishes
version 1.30.26, size 41,961,437 bytes and SHA-256
`6cfd973d0f2d34ec2fe5c7cfdcc0bdbcb56a8fad329fb4683f6446602769f1b2`.
These are publisher-page observations, not a downloaded-byte verification.
It also requests avoiding multi-connection aggressive downloaders. The separate
[x64 package page](https://www.nirsoft.net/x64_download_package.html) specifies x64
executables and archive extraction information. Preserve those distinct sources
and archive requirements; do not infer a frozen member inventory from either page.
No maintained replacement updater was established for the adjacent collections
in this bounded review; their publisher indexes remain useful discovery sources.

### Zimmerman correction and bounded failure fixtures

The [upstream source](https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1)
records a URL before issuing HEAD. On failure, its next iteration hits the
duplicate guard and advances. The earlier endless-retry suspicion is withdrawn.
However, an empty download queue can report all files current after discovery
failures, and returns before optional Sync. Cached ETags are not proof that local
payloads still exist; the final merge matches ETags without URL identity.

Five isolated control-flow/predicate fixtures passed: a failed first URL followed
by success takes three loop iterations and two mock requests; two failures take
four iterations and produce no candidates; duplicate links request each unique
URL once; matching ETag queues nothing without consulting local payload presence;
and a different URL with the same ETag matches the final merge predicate. These
fixtures reproduce inspected decisions, not a full upstream execution or live
network test. Add explicit failure/omission state and local integrity checks in
the managed implementation.

Four additional in-memory fixtures passed: old NTCore selectors omit absolute
modern links; blindly prefixing `https:` corrupts an already absolute URL;
PowerShell's failed `-match` retains earlier named captures; and MiTeC's first-link
predicate selects by page order rather than architecture. Synthetic inputs prove
those failure modes, not that every current publisher response triggers them.

The Windows shell could not resolve GitHub's API during source-pin retrieval.
The web reader exposed current source and history identifying abbreviated commit
`d808d1d`, but immutable source retrieval failed. No verified full commit pin or
script byte digest is claimed. Exact pinned-source mocked tests, ZIP/script
equivalence, staging/preservation tests and native acceptance remain open. Do not
execute the mutable source as a workaround.

### Shared-package and compatibility evidence

The [TMOG store](https://store.tmog.org/licenses) explicitly describes Pro as an
unlock inside the existing app. Apply one application package, with optional
activation. Its [publisher activation documentation](https://tmog.org/rtm/privacy.html)
describes interactive registration, a machine-bound local entitlement at
`%LOCALAPPDATA%/TMOG/license.json`, and offline verification after activation.
That file contains licence material: preserve it locally, keep it out of generic
shared kits and ordinary logs, and do not treat copying it to another computer
as activation. First activation still needs the publisher-supported workflow;
no offline activation method was established here. No licence file was read.

[CCleaner support](https://support.ccleaner.com/s/article/how-to-register-and-activate-ccleaner-professional?language=en_US)
also documents registration within the application. This supports separating
activation from installation, but does not establish byte-identical installers
across every consumer/business distribution. The [WinHex comparison](https://www.x-ways.net/comparison.html)
lists architecture availability differences by licence type; inspect actual
artifacts before treating those differences as entitlement-only. Existing
settings/licence preservation and explicit optional activation remain binding.

No finding in this pass requires a new user decision. Retention, deferral,
explicit updates, reviewed membership and preservation policies already cover
the required adaptations. No legacy outcome is newly migrated or retired and no
native acceptance is claimed. Profile composition and BitLocker/recovery setup
remain deferred. Next technical work is exact source pinning and isolated
acquisition/extraction contract validation, followed by per-member compatibility
evidence; unresolved runtime checks must stay visibly pending.

