# ADR 0001: Ownership of Windows configuration and logging baselines

- Status: Proposed
- Date: 2026-10-07

## Context

RIDE-Windows is a state-changing Windows setup and maintenance engine. It has a
catalog, desired-state profiles, preview/apply, captured prior state, and
restore behavior. LoggingBaseline currently collects and reports Windows
logging state without changing the host. Its first-release plan adds a
desired-state policy for compliance and proposes preview/apply for logging and
audit settings.

The planned LoggingBaseline controls include event-channel enablement and size,
advanced audit policy, SACLs, PowerShell logging, firewall/DNS/WMI logging,
AppLocker audit mode, and LSASS audit mode. A second implementation of these
writers, with a separate apply and recovery path, would create competing
policies and unclear ownership. These LoggingBaseline controls are not in the
current RIDE operation catalog, so this decision establishes the boundary
before the planned configuration work is implemented. There is no competing
LoggingBaseline writer today: it collects and compares state read-only. RIDE
already mutates other settings, including Defender exclusions, while
LoggingBaseline can observe some of those same settings; observation plus
mutation is intentional and is not duplicate ownership by itself.

## Proposed decision

Make RIDE-Windows the only tool that applies Windows configuration. Make
LoggingBaseline a read-only collector, compliance evaluator, and storage/growth
reporter. LoggingBaseline may produce recommendations and a machine-readable
plan, but it must not write host policy or configuration.

Use RIDE's catalog and profiles as the source of desired configuration. Give
LoggingBaseline a versioned, read-only desired-state input generated from a
RIDE profile or another explicit RIDE export. Do not maintain a second
independently edited set of expected values in
`LoggingBaseline/Policies/Workstation.v1.json`. Keep LoggingBaseline-owned
measurement targets, such as minimum log retention or storage-growth
thresholds, separate from desired Windows setting values.

No control may have two owners that can apply it. Stable RIDE operation IDs
identify mutable controls; LoggingBaseline control IDs may refer to those
operation IDs for collection and compliance. If a control is outside RIDE's
supported targets or handlers, report it as `Unknown` or `ReportOnly` until
RIDE implements it. Do not silently apply a similar setting from
LoggingBaseline.

### Ownership examples

| Control | Configuration owner | LoggingBaseline responsibility |
| --- | --- | --- |
| Security, System, Application, PowerShell, Defender, Firewall, DNS, WMI, and Sysmon event channels | RIDE | Collect enabled state, sizes, retention/overwrite behavior, and growth |
| Advanced audit policy, PowerShell logging, firewall/DNS/WMI logging, SACLs, and AppLocker audit mode | RIDE | Collect actual state and compare it with the selected RIDE profile |
| Defender protection and exclusions | RIDE | Report observed Defender state and relevant collection limits |
| Firewall enforcement (profiles, inbound defaults, and rules) | RIDE | Collect/report separately from Firewall log settings |
| Credential protections and SMB protocol policy | RIDE | Report compliance-relevant state where collectors can verify it |
| Event retention and storage-growth targets | RIDE profile for requested host values; LoggingBaseline policy for measurement thresholds | Measure and report estimated or unknown retention with its basis |

## Alternatives considered

1. **LoggingBaseline applies logging/audit controls; RIDE applies all other
   settings.** This preserves LoggingBaseline's planned `-Apply` workflow, but
   creates two apply/recovery engines and leaves boundary cases (for example,
   Firewall logging versus Firewall enforcement) to maintain. Use this only if
   the user explicitly prefers LoggingBaseline as a specialized configuration
   owner and RIDE excludes every control assigned to it.
2. **Both tools can apply overlapping controls.** Rejected. Desired values,
   state capture, rollback, reporting, and policy precedence would diverge.
3. **Create a third shared policy repository or package now.** Deferred. A
   RIDE profile export is a smaller first contract. Revisit a shared policy
   package only if another consumer needs independent versioning or multiple
   RIDE profiles cannot provide the required input.

## Consequences and follow-up

- Revise LoggingBaseline's first-release plan before it implements
  configuration commands: keep its preview/report flow read-only and export
  recommendations or desired-state comparisons for RIDE.
- Add audit/logging configuration operations to RIDE only when the handler can
  plan, apply through `ShouldProcess`, capture prior state or declare recovery
  limits, verify after changes, and report pending reboot or partial failure.
- Define a versioned RIDE-to-LoggingBaseline export contract with stable
  operation IDs, target OS/build/edition/role, desired state, applicability,
  and source profile. Preserve unknown and not-applicable states.
- Keep the LoggingBaseline repository's current uncommitted changes untouched
  until this boundary is accepted. This ADR documents a proposal; it does not
  change that repository or its plan.

## Proposed security controls for RIDE

These are catalog/profile candidates, not blanket instructions to force every
setting on every Windows image. Prefer status collection first, preserve
per-operation Windows support declarations, and test changes on representative
Windows 11 and Windows Server 2025 roles.

### 4. Credential and virtualization protections

Add a read-only security posture view, then explicit reversible/configurable
operations only where useful:

- Report Secure Boot, TPM presence/readiness, VBS state, Credential Guard
  running/configured state, LSA protection state, HVCI (Memory Integrity) state,
  and pending reboot. Prefer Microsoft's documented WMI/System Information
  verification over inferring runtime state from one registry value.
- Treat Credential Guard as a target-dependent baseline. Windows 11 22H2 and
  later, and Windows Server 2025, enable it by default only on eligible devices;
  Server 2025's default applies to domain-joined non-domain-controllers, not
  domain controllers. Preserve that role distinction in catalog support and
  status.
- For a managed rollout, first audit hardware, drivers, credential-dependent
  applications, virtual machine roles, RDP/VPN/802.1X SSO, and Server live
  migration dependencies. Enable VBS/Credential Guard and LSA protection in a
  test ring, then deploy by profile. Avoid UEFI-locking or irreversible boot
  changes without documented recovery steps and a tested recovery path.
- Treat HVCI as a separate compatibility-tested control; do not assume
  Credential Guard status proves Memory Integrity is enabled.

Microsoft notes default-enable eligibility and application/role compatibility
limits in its [Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
and [known issues](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-considerations).
See also [added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
and [Memory Integrity deployment](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity).

### 5. Audit and forensic telemetry profile

Add a separate, opt-in `audit-workstation` profile and role-specific server
profiles. Keep local audit telemetry distinct from optional Windows diagnostic
data sent to Microsoft. Candidate controls:

- Enable successful and failed process-creation auditing and include process
  command lines (Security event 4688). Warn that command-line arguments may
  contain passwords, tokens, or other secrets; restrict access and forward
  records to a protected collector.
- Enable PowerShell Script Block Logging. Add Module Logging for selected
  security-relevant modules. Enable transcription only with a protected,
  access-controlled destination; local transcripts can expose sensitive input.
- Configure channel enablement, maximum size, overwrite/retention behavior,
  and minimum useful retention for Security, System, Application, PowerShell,
  Defender, Firewall, SMB, and Sysmon channels. Set sizes based on measured
  event volume and disk budget rather than one universal cap.
- Add policy/audit for Defender configuration changes, account/logon events,
  firewall rule changes, PowerShell, and selected object-access auditing where
  investigation needs justify the collection and storage cost.
- Use Sysmon as a separate opt-in collector/configuration choice; select a
  reviewed configuration and measure event volume before broad rollout.
- Keep policy application and compliance evaluation distinct. A missing or
  inaccessible channel is `Unknown`, not compliant. LoggingBaseline owns
  collection completeness, measured growth, retention estimates, and reporting.

Microsoft documents [command-line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
and [PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging).
The PowerShell documentation warns that script logging can capture sensitive
data; use protected event logging where appropriate.

### 6. SMB hardening

Add a status view for SMB client and server settings and a role-specific profile
for supported settings:

- Confirm SMBv1 is absent/disabled on Windows 11 and Windows Server 2025. It is
  not installed by default on Windows 11 or Server 2019 and later; report state
  rather than forcing a redundant change. Do not re-enable SMBv1 to support an
  old device; replace or update that endpoint where possible.
- Report client outbound and server inbound SMB signing separately. Windows
  11 24H2 Pro/Enterprise/Education requires both directions by default;
  Windows Server 2025 requires outbound signing by default. Preserve supported
  defaults and avoid a global signing bypass for legacy NAS/guest access.
- Disable insecure guest logons. Audit dependencies before blocking NTLM over
  SMB or tightening other legacy authentication paths.
- Offer SMB encryption for selected sensitive shares or trusted network
  boundaries, rather than forcing it globally without compatibility and
  throughput testing.
- On workstations that do not serve files, scope inbound TCP 445 through
  Windows Firewall to the networks that require it, or block it when no inbound
  SMB use is intended. On file servers and domain controllers, model role,
  share, replication, and management dependencies before changing inbound
  access.

See Microsoft's [SMB security hardening](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening),
[SMB signing behavior](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing),
and [SMBv1 defaults and lifecycle](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3).
