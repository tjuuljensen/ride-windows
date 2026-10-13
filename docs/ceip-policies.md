# Windows and App-V CEIP participation policies

The pending `windows.ceip-participation-policy` candidate configures the Windows
Customer Experience Improvement Program policy for the whole device. It requires
administrator rights for changes and remains outside recommended profiles.

| State | Local DWORD CEIPEnable | Windows Group Policy wording |
| --- | ---: | --- |
| OptedOut | 0 | Turn off Windows CEIP: Enabled |
| OptedIn | 1 | Turn off Windows CEIP: Disabled |
| WindowsDefault / unset / Baseline | Removed | Local override removed |

The target is `HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows`, value
`CEIPEnable`. Microsoft's [exact policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-icm#ceipenable)
documents the Windows policy and inversion. It lists Pro, Enterprise, Education
and IoT Enterprise; that is not evidence of current collection on every build,
Home applicability or Server acceptance. No RIDE account, subscription, domain
join or Intune enrollment is needed merely to configure local policy.

Read-only local ICM.admx inspection on Professional build 26200.9550 confirms
Machine scope, policy Enabled=0/Disabled=1. Source SHA-256:
`96441AA74A539F8AE8688F31BA2D61B460D87A4159765B546B1BC39BFA905C5D`.
This is mapping evidence, not a feature test. The old Control Panel wording in
Microsoft's reference is not presented as a verified Windows 11 checkbox.

## Literal state and recovery

Legacy EnableTelemetry removed this override; it did not explicitly opt in.
Removal delegates to applicable Windows preference/policy decisions and is
different from writing 1. Saved-run restore returns exact captured value/type/
absence, including unexpected prior representations. Existing registry snapshots
and the stable generic handler are reused; no effective state is inferred from
a local value and no collected data can be recovered by restoring configuration.

Show/plan/profile status report configured registry state. Effective managed
policy/source and current consumer behavior remain unverified. This control does
not provide a universal telemetry-off switch, change diagnostic-data policies or
tasks, write native/Wow6432Node AllowTelemetry mirrors, invoke collectors or modify
another product's reporting.

## App-V is separate

App-V's positively named CEIP policy uses the opposite Group Policy orientation:
Enabled=1/Disabled=0 at its own AppV policy key. A relevant installed/enabled client
and verified policy-to-client consumption/precedence are required. The accepted
App-V design remains deferred until those prerequisites and mappings can be
established. This Windows policy never configures or activates App-V, acquires
licenses or claims that a policy write proves an App-V opt-out.

## Acceptance hold

The Windows record has empty SupportedTargets, a Windows 11 candidate target and
`PendingAcceptance=$true`. Normal apply is blocked; metadata discovery and
completion remain available. No support or legacy-outcome closure is claimed.

**Disposable VM tests remain held until manual user confirmation after the GitHub
cache/backoff investigation.** No VM test, privacy change, package acquisition or
collection probe is launched here. After confirmation, verify applicable editions,
both explicit states and removal, typed saved recovery, managed precedence and
actual current CEIP consumers. Lack of network activity alone cannot prove opt-out.
Server and App-V applicability/acceptance remain independent.

Local verification passed 22 selected mocked checks per PowerShell edition,
including four CEIP cases, with parser/catalog/profile/reference checks passing.
These results prove the local candidate contract, not current collection behavior.
