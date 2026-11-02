# Wireless profile generation, lifecycle and inventory

## Generate XML from supplied settings

RIDE generates the profile file; an existing production XML file is not a
prerequisite. From the repository root in native Windows PowerShell 5.1 or
PowerShell 7, use an existing local directory and a new `.xml` filename:

```powershell
Import-Module .\modules\RIDE.WirelessProfile.psm1
$key = Read-Host 'Wi-Fi key' -AsSecureString
try {
    New-RideWirelessProfileFile -ProfileName 'Office profile' -Ssid 'Office' `
        -Security WPA2Personal -Key $key -ConnectionMode manual `
        -OutputPath 'C:\Private\wifi.xml' -WhatIf
} finally {
    $key.Dispose()
}
```

Repeat with a fresh secure key and without `-WhatIf` to generate the file. This
requires no elevation or WLAN adapter. Profile generation does not import,
connect, scan, change a service or select an interface. The output object reports
file-generation status only; it contains no XML, password or password digest.
`Security` and `ConnectionMode` complete from their declared valid values.

The implemented security choices are `WPA2Personal` (WPA2PSK/AES) and `Open`
(open/none, with no key). A WPA2 key is an 8-63 printable ASCII passphrase or a
64-digit hexadecimal network key. Enterprise/EAP, WPA3, WEP and WPA are not
implemented. `manual` is the default; automatic connection is an explicit profile
preference and can take effect only after a later import. `-HiddenNetwork` sets
the non-broadcast flag. MAC randomization is not overridden by this generator.

`-Ssid` uses strict UTF-8 without normalization, limited to 1-32 bytes. Use
`-SsidBytes` instead for an exact binary SSID. XML contains the authoritative hex
SSID; profile identity is supplied separately through `-ProfileName`. An XML
writer escapes text rather than interpolating it into markup.

The file is created exclusively with a protected DACL for the current user and
SYSTEM, and those permissions are checked through the open handle before any
profile bytes are written. Existing files are never overwritten; parent reparse
points, UNC/device/alternate-stream paths and mapped network drives are refused.
The filesystem must support the requested permissions. A failure can leave a new
empty or private partial file; inspect it and choose a new filename for a retry.

WLAN import XML contains **unencrypted key material** (`protected=false`). File
permissions protect access; they do not encrypt the key. Keep real output out of
Git, ordinary logs, transcripts and shared evidence, and remove it after its
intended use. SecureString input avoids a plaintext command argument; generation
necessarily creates plaintext in process memory and does not promise complete
memory erasure. Real credentials belong in an interactive secure prompt or local
secret source, never in committed settings or a chat message.

The implementation follows Microsoft's [WLAN v1 schema](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpwl/34054c93-cfcd-44df-89d8-5f2ba7532b67),
[SSID byte semantics](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-ssid-ssidconfig-element)
and [shared-key rules](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-sharedkey-security-element).
The XML namespace is the literal `http://www.microsoft.com/networking/WLAN/profile/v1`
identifier from the protocol schema, not an HTTP acquisition URL.

### Synthetic testing

`tests/fixtures/wireless-profile.synthetic.psd1` supplies a clearly synthetic SSID,
profile name and public test-only key. `tests/WirelessProfile.Tests.ps1` generates
files from those settings and exercises private output, invalid settings, byte
identity, escaping, preview and collision handling. No real network or credential
is needed. For an explicit synthetic output, from the repository root:

```powershell
Import-Module .\modules\RIDE.WirelessProfile.psm1
$fixture = Import-PowerShellDataFile .\tests\fixtures\wireless-profile.synthetic.psd1
$key = ConvertTo-SecureString $fixture.SyntheticKey -AsPlainText -Force
try {
    New-RideWirelessProfileFile -ProfileName $fixture.ProfileName -Ssid $fixture.Ssid `
        -Security $fixture.Security -Key $key -ConnectionMode $fixture.ConnectionMode `
        -HiddenNetwork:$fixture.HiddenNetwork -OutputPath 'C:\Private\synthetic-wifi.xml'
} finally {
    $key.Dispose()
}
```

Native import/repeat/remove/restore remains pending. That scenario must use the
synthetic profile in manual mode, a disposable target with suitable WLAN support,
an explicit interface and the selected machine/all-user scope. Verify exact
profile settings and scope, preserve existing profiles, and prove recovery before
checkpoint cleanup. Do not connect to a real network. No adapter is needed for
generation tests; no suitable adapter means native import is untested, not passed.

The isolated `RIDE.WirelessNative.psm1` provider now supplies bounded profile
list/read/set/delete/order calls for the candidate lifecycle handler. Its fake-API
tests verify call arguments, error reporting and allocation/handle cleanup in
both PowerShell editions. Loading it performs no WLAN calls. It does not expose
an independently recoverable import command or establish native acceptance.

Recovery must distinguish replacement from deletion: `WlanSetProfile` with a null
security descriptor preserves permissions on an existing all-user profile,
whereas deletion/recreation needs the original permissions as well as XML and
order. `WlanGetProfile` returns granted access flags, not the complete per-profile
security descriptor. Do not label an XML-only delete/recreate round trip exact
recovery. The synthetic fixture can establish explicit known permissions; native
lifecycle acceptance remains required. Source ownership/conflict checks are
implemented in the candidate below.
See Microsoft's [profile set semantics](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofile)
and [profile retrieval semantics](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofile).

## Candidate all-user profile lifecycle

`RIDE.WirelessLifecycle.psm1` supplies import, owned removal and saved-run restore
for Windows 11 x64. Native acceptance is pending. Use an already elevated native
PowerShell process on the explicitly selected disposable target, an available
WLAN service/interface, and an existing local state directory. The commands do
not start a service, elevate, scan or call a connection API. Importing an
automatic profile can nevertheless cause Windows to connect; it requires the
separate `-AllowAutoConnect` switch. Synthetic tests use manual mode.

After generating the private synthetic XML above, preview and then apply:

```powershell
Import-Module .\modules\RIDE.WirelessLifecycle.psm1
$wireless = @{
    ProfilePath = 'C:\Private\synthetic-wifi.xml'
    InterfaceId = '<observed-wlan-interface-guid>'
    StateDirectory = 'C:\Private\State'
    ExpectedComputerName = '<disposable-target>'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Install-RideWirelessProfile @wireless -WhatIf
$install = Install-RideWirelessProfile @wireless -AllowCandidate -Confirm:$false
$repeat = Install-RideWirelessProfile @wireless -AllowCandidate -Confirm:$false
$remove = Remove-RideWirelessProfile -OwnerRunId $install.RunId `
    -StateDirectory $wireless.StateDirectory -AllowCandidate -Confirm:$false
Restore-RideWirelessProfileRun -RunId $remove.RunId `
    -StateDirectory $wireless.StateDirectory -AllowCandidate -Confirm:$false
Restore-RideWirelessProfileRun -RunId $install.RunId `
    -StateDirectory $wireless.StateDirectory -AllowCandidate -Confirm:$false
```

Use a fixture identity absent before the test. A repeated matching import returns
`AlreadyDesired` without another run or writer. Removing the created profile
records a new run; restoring that removal recreates the profile, then restoring
the original import recovers absence. Check results and native readback before
advancing; do not continue this sequence after a failed command. Run completion
reads only filenames in an explicitly bound `StateDirectory`; it never decrypts
records or queries WLAN. Interface selection comes from the read-only inventory.

Import requires XML with the generator's supported fields and private file
permissions. Existing profiles are preserved unless `-ReplaceExisting` explicitly
permits a supported all-user replacement. The handler captures prior XML/order
and uses a null native security descriptor to retain existing permissions.
Policy, per-user, unknown-flag and unavailable-plaintext profiles refuse.

Before a native writer, the handler creates a private immutable intent record,
sealed with current-user Windows DPAPI, and rechecks target and observed state.
After successful readback it creates a separate private applied record. The
original account and its DPAPI material are required to read either record;
copying the files alone does not provide portable recovery. Public schema-1
results contain `Status` and `RunId`, never XML, keys or key digests. Successful
mutation results additionally identify action/scope and no explicit connection
attempt. `NativeAcceptancePassed=false` does not change through candidate use.

Recovery refuses target/build/revision/account, profile XML, flags or preference
order drift. Matching settings tolerate native-added defaults during apply;
restore compares the captured XML and complete observed order. Removing an
existing profile is refused because its full original DACL is unavailable.
Deletion is limited to a completed RIDE creation with the recorded explicit
security descriptor. Permission preservation depends on no intervening external
per-profile DACL change: this API does not expose that complete descriptor for
drift detection. No universal exact-permission recovery is claimed.

Readback comparison treats omitted `autoSwitch` as false on these Windows
targets, following Microsoft's [profile switching default](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-wlanprofile-element#autoswitch).
Invalid booleans and automatic switching on a manual profile refuse before import.

If a writer or verification fails, the error exposes a run ID and retains its
private intent. Without a completed applied record, automatic restore refuses;
inspect the target and retained record under the original account before choosing
recovery. A partial restore likewise retains both original records and makes no
exact-recovery claim. A VM checkpoint reset is emergency cleanup, not proof of
RIDE restore. Do not discard private records before verified recovery.

`tests/WirelessLifecycle.Tests.ps1` mocks every WLAN call and target identity while
testing real private-file ACLs and DPAPI in TestDrive. Together with generation,
33/33 tests pass in PowerShell 7.6.5 and Windows PowerShell 5.1.26100.9818. This is
source evidence only; native hardware/service prerequisites,
permission behavior and exact synthetic round trip remain open. See
[dated evidence](archive/evidence/wireless-lifecycle-source-2026-11-02.json).

### Disposable-target acceptance entry point

`tests/integration/Invoke-RideWirelessAcceptance.ps1` now supplies the guarded
guest scenario. Its orchestration and independent XML readback have 12/12 mocked
tests passing in each PowerShell edition; this is not a native WLAN result.
The direct retained host route below is source-prepared. An already elevated
permitted VM coordinator must provide the staged source,
the exact target/interface, a retained checkpoint and correlated guest markers
`RIDE_TEST_GUEST=1`, `RIDE_INTEGRATION_VM=1` and `RIDE_TEST_RUN_ID`. Do not set
these on the workstation to bypass the guest guard. No new UAC prompt is used.

From the staged repository inside that attested guest, with an existing local
evidence root and the request's independently observed interface GUID:

```powershell
.\tests\integration\Invoke-RideWirelessAcceptance.ps1 `
    -RunId $env:RIDE_TEST_RUN_ID -InterfaceId '<guest-wlan-interface-guid>' `
    -ExpectedComputerName '<guest>' -ExpectedBuild '26300' `
    -ExpectedEditionId EnterpriseEval -EvidenceRoot 'C:\RIDE\WirelessAcceptance' `
    -DisposableVm -WhatIf
```

After a successful preview, use the same arguments without `-WhatIf` and with
`-Confirm:$false`. A new request directory receives private synthetic XML,
DPAPI lifecycle records and `result.json`. The fixture name includes the request
prefix; any collision refuses rather than adopting or deleting an existing
profile. The run verifies preview, import with native readback, repeat without a
new run, replacement with a second synthetic SSID, recovery of the prior profile,
owned removal, recovery of the removed profile, recovery of initial absence and
the complete observed list/flags/order, and repeated restore. It never connects.

Inspect the schema-1 result before any checkpoint cleanup. `Passed` requires all
nine checks; `Preview` makes no change; `NotRun` identifies missing elevation,
service, interface or a fixture collision. `Failed` identifies the last stage,
sets `RecoveryRequired=true` and retains completed lifecycle IDs plus all saved
intent IDs in `StateRunIds`, including incomplete operations. It stops rather
than attempting blind cleanup. Follow the lifecycle recovery limits above;
verify recovery before treating checkpoint cleanup as routine. Do not publish
private state. The entry point makes no connection or universal DACL-recovery
claim, and its success does not promote other targets or profiles.

The latest [acceptance preparation evidence](archive/evidence/wireless-acceptance-preparation-2026-11-02.json)
records an idle host controller, no elevated token and no native guest run.

### Retained host dispatch

Start in the registered repository checkout in an already elevated native Windows
PowerShell 5.1 x64 host session. Import
`tests/integration/RIDE.WirelessVm.psm1` and use the installed controller
configuration. The AutomatedLab credential, exact disposable VM/checkpoint and
[retained reservation requirements](image-personalization.md#retained-host-coordination)
apply. This is direct phased dispatch, separate from the generic reset-per-request
queue. It does not request UAC, refresh the controller or change scheduled tasks.

Prepare reserves the idle Off VM, restores the pinned checkpoint, starts it and
stages exactly six modules and `wireless-profile.synthetic.psd1`. The fixture
supplies public synthetic settings; no real network key or supplied XML is needed.
Both ends verify the fixed source paths and hashes. No legacy/component directory
is traversed. Guest name, Hyper-V manufacturer/model, exact Windows 11 build,
selected Enterprise/Education edition, x64 architecture and elevation must match.
Lifecycle also requires the prepared build revision to remain unchanged.

Prepare observes the WLAN service and interfaces without starting a service,
installing a component, scanning networks or connecting. The bounded inventory
provider reads interface/profile-list metadata; the preparation result retains
only interface GUIDs and literal states. Profile names and adapter descriptions
are discarded, and no profile XML or key is requested by discovery. Missing
service/API or zero interfaces returns `NotRun`, with a reason and no acceptance
pass. Hardware availability on the selected VM remains unverified until this
native observation runs.

```powershell
Import-Module .\tests\integration\RIDE.WirelessVm.psm1
$session = @{
    ConfigurationPath = '<installed-controller-configuration.json>'
    RunId = [guid]::NewGuid().ToString('N')
}
$prepare = @{
    Phase = 'Prepare'
    ExpectedBuild = '26300'
    ExpectedEditionId = 'EnterpriseEval'
}
Invoke-RideWirelessVmPhase @session @prepare -WhatIf
$prepared = Invoke-RideWirelessVmPhase @session @prepare -Confirm:$false
$prepared.GuestResult.Availability
# Continue only if Prepared; select a GUID from this request's observation.
$interface = '<observed-guest-wlan-interface-guid>'
Invoke-RideWirelessVmPhase @session -Phase Lifecycle -InterfaceId $interface -WhatIf
$lifecycle = Invoke-RideWirelessVmPhase @session -Phase Lifecycle -InterfaceId $interface -Confirm:$false
Invoke-RideWirelessVmPhase @session -Phase Collect -Confirm:$false
# Inspect exported results and any outstanding recovery before explicit cleanup.
Invoke-RideWirelessVmPhase @session -Phase Reset -Confirm:$false
```

Review each result before proceeding. On Prepare `NotRun`, skip Lifecycle,
collect the prerequisite evidence and explicitly reset the retained VM. Do not
invent a GUID to force a run. Lifecycle accepts InterfaceId only from the saved,
correlated Prepare observation; both host and guest enforce that selection.
The guest runner rechecks the actual WLAN service/interface and synthetic-name
collision, so an interface disappearing later is `NotRun`, not a pass. A failed
phase retains the guest and its state for inspection.

Lifecycle generates private XML from the supplied synthetic settings, then runs
the nine import/repeat/replace/remove/recovery checks described above in one
PowerShell Direct invocation. The host requires the selected interface, all nine
checks, three distinct restored Import/Replace/Remove runs and a verified evidence
export before setting `ProfileLifecycleAcceptancePassed=true`. The guest's
`NativeAcceptancePassed` covers only its documented synthetic lifecycle. The
host's broader `NativeAcceptancePassed`, `ConnectionVerified` and
`FullDaclRecoveryVerified` stay false; no connection or general DACL recovery is
inferred from this scenario.

Host reports use schema 1 and include Phase, InterfaceId, Stage, Status,
GuestResult, EvidenceExport, Store, RecoveryRequired and those acceptance fields.
After session validation, SourceManifest lists retained source/input paths,
sizes and hashes without publishing profile contents or credentials.
Statuses include Preview, Prepared, NotRun, Passed, Collected, ResetAndOff and
Failed. Keep the original Lifecycle report: Collect/Reset do not carry its pass
forward. RecoveryRequired also describes the retained VM/hold, so even an unrun
scenario requires explicit checkpoint cleanup before releasing the reservation.

Every phase exports the retained guest directory to a fresh private host export
under `retained.<lease-id>`. It includes the exact source snapshot, interface
observation, generated synthetic XML, private DPAPI state and reports that exist.
Ordinary phase results contain no XML or key material. The export itself is
private evidence and must not be published. DPAPI records remain tied to their
recorded guest/account; copying them is not portable recovery or proof they can
be restored after checkpoint rollback. Recover and verify completed lifecycle
runs in the original guest before cleanup whenever possible.

Export checks paths, hashes, byte counts and host readback, with limits of 512
entries, 16 MiB per file and 32 MiB total. Failed guest phases attempt a partial
export without automatic profile deletion or VM reset. Explicit Reset exports
first, restores the pinned checkpoint, verifies Off and releases only the matching
hold. Reset is cleanup or deliberate abandonment after failure inspection; it is
never a RIDE profile-restore pass. Retrying Reset from Off requires a prior reset
intent and unchanged verified export. Early preparation failures without a usable
session/intent require controller inspection. Remote jobs have a 180-second limit
and readiness a separate three-minute limit. A local timeout does not prove guest
work stopped; existing host Hyper-V/dependency calls have no added watchdog.

Phase, edition, retained run IDs and saved interface GUIDs offer completion.
Interface completion reads only this request's saved local observation, filters
case-insensitively and fails quietly if private data is unavailable. It makes no
VM/WLAN call or hold change. All phases support `-WhatIf`; host previews do not
query the guest and cannot certify its WLAN prerequisites.

The [dispatch evidence](archive/evidence/wireless-vm-source-2026-11-02.json)
records 37 host-route and 18 guest-runner source cases passing in each shell,
independent dependency/generation checks and the installed Prepare preview.
Native interface discovery, DPAPI/remoting behavior and the actual nine-check
profile lifecycle remain unrun.

## Read-only wireless profile inventory

Capture basic stored Wi-Fi profile metadata visible to an explicitly identified
user. The tool records enabled WLAN interface GUIDs, descriptions, literal state,
profile names, preference order and flags. It does not retrieve profile XML, keys,
EAP user data or active SSIDs, scan networks, connect, import or remove profiles.
Native service, user-visibility and hardware acceptance remain pending.

## Capture and inspect

Start in the repository root in native Windows PowerShell 5.1 or PowerShell 7,
in the intended user's interactive session. Supply machine/build/edition and
SID/session independently. Create a private local evidence directory first.
No elevation prompt, WLAN service start or component installation is performed.

```powershell
.\tools\Export-RideWirelessProfileInventory.ps1 `
  -ExpectedComputerName '<target>' -ExpectedBuild '<build>' `
  -ExpectedEditionId '<edition>' -ExpectedUserSid '<intended-user-sid>' `
  -ExpectedSessionId 1 -OutputPath 'C:\Evidence\wireless-profiles.json' -WhatIf
```

Remove WhatIf only to perform the read-only query and create new JSON. Preview
queries nothing. Existing output or a file created during collection refuses;
retain partial output on failure and choose a new filename. Profile names can
disclose private network names even though secrets are not requested. Keep the
evidence local with appropriate access controls; the exporter does not set ACLs.

The version-1 observation distinguishes Captured with zero interfaces/profiles
from Unavailable. Any provider, bounds, malformed-data or cleanup failure discards
all partial rows. Only error type and an available native numeric code are retained.
Pre/post machine/build/edition/update/SID/session/native/interactive drift refuses
the whole observation. This does not verify ownership of the desktop.

The reader uses [WlanEnumInterfaces](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanenuminterfaces)
and [WlanGetProfileList](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofilelist),
with a version-2 client handle and explicit allocation/handle cleanup. RIDE limits
capture to 64 interfaces and 256 profiles each; native calls have no hard timeout.
Missing service/API/access is an unavailable prerequisite, not permission to
install, start or repair anything. Enabled-interface coverage does not enumerate
every disabled adapter or profiles belonging to other accounts.

## Identity, order and scope

| Field | Meaning |
| --- | --- |
| Interface Id | Observed WLAN interface GUID; a description or adapter index is not a substitute. |
| Profile Name | Exact, case-sensitive stored profile identity, not guaranteed to equal an SSID. Renames require fresh review. |
| Position | Zero-based preference position returned by the API; not the currently connected profile. |
| Flags | Complete unsigned bitmask, retaining unknown bits. |
| GroupPolicyFlag | The documented group-policy bit; those profiles are read-only. |
| PerUserFlag | The documented per-user bit; when clear the API describes an all-user profile. |
| UnknownFlagBits | Bits outside the two reviewed flags; no new meaning is invented. |

Microsoft defines [profile-name and flag semantics](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/ns-wlanapi-wlan_profile_info).
The list header's dwIndex is application bookkeeping, not active connection state.
Neither a missing policy flag nor a returned profile establishes permission to
change it. Basic metadata contains no complete content or credentials for recovery.
`ReadyForMutation`, `RecoverySupported` and `ConnectionVerified` remain false.

Import the module and use saved metadata without a new native query:

```powershell
Import-Module .\modules\RIDE.WirelessInventory.psm1
$saved = Get-Content -LiteralPath 'C:\Evidence\wireless-profiles.json' -Raw |
  ConvertFrom-Json
Find-RideWirelessProfileObservation -Inventory $saved `
  -InterfaceId '<reviewed-interface-guid>' -ProfileName 'Reviewed profile'
```

InterfaceId and ProfileName completion read only supplied saved rows, filter by
prefix and never connect. Names complete only for the explicitly selected interface;
case variants remain distinct and quotes are escaped. Control-character names
remain literal observations but are omitted from completion. Lookup distinguishes
missing interface, missing exact profile and unavailable capture. It revalidates
row bounds, order, GUIDs and duplicate names after JSON roundtrip.

## Acceptance and next work

`tests/WirelessInventory.Tests.ps1` uses fake allocated native buffers and mocked
identity, plus temporary evidence files. It proves field handling and cleanup,
not an actual service/API, permissions or hardware result. Interface/profile
membership can change during or after the sequential calls; no atomic snapshot
or current connection is claimed.

On a disposable target with suitable WLAN hardware and an already available
service, compare observed GUIDs and profile preference order with the intended
user's native UI. Include no-profile, per-user, all-user, policy, missing-service,
disappearance and alternate-user cases. Do not create networks, expose keys or
enable components just to obtain a green inventory result.

Q12 still owns native profile scope/connection behavior and exact restore before
promotion of the candidate importer. Generated XML supplies the selected input; the tests
use synthetic settings. Q30 still owns interface selection. Inventory metadata
alone does not establish recoverable profile content or import acceptance.
Generation and inventory alone need no network recovery. If the candidate
lifecycle changed a profile, restore that run before reverting its source;
retain the matching reader and private state while recovery remains unfinished.
The [migration record](migrations/remaining-migrations-follow-up.md#b02-wireless-profile-identity-inventory-2026-10-17)
retains implementation and native-acceptance status.
