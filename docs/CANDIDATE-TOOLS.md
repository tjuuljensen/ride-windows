# Supplemental tool candidates

Reviewed 2026-10-07. This is a research shortlist, not a set of approved packages or a promise of support. Candidates were compared with the current package catalog and the historical tool selectors in `docs/MIGRATION-PLAN.md` and `components/files/`. Tools already represented there, such as KAPE, Sysinternals, Chainsaw, Autopsy, Volatility, and Eric Zimmerman's tools, are intentionally omitted from the new-package shortlist.

Here, "stealthy" means minimizing unnecessary changes to evidence and limiting exposure during authorized analysis. It does not mean hiding activity from owners, endpoint security, or monitoring. No live-system collection is footprint-free: reading volatile state and running collectors can change memory, files, and logs. Follow the incident plan and evidence-handling requirements, document actions, and use offline copies where possible.

## Recommended candidates

| Priority | Tool | Audience and useful capability | Access and licensing | Fit and review notes |
| --- | --- | --- | --- | --- |
| 1 | [FTK Imager](https://www.exterro.com/ftk-downloads/ftk-imager-8-3) | Investigators: acquire and preview forensic images, with hash verification; also useful for validating and browsing image files. | Exterro states FTK Imager is free and requires no product license; no license key required. | A practical gap-filler for evidence acquisition and review. Use a hardware write blocker where applicable, independently record and verify hashes, and check current download access and unattended deployment before adding it. An imager does not make live acquisition non-invasive. |
| 2 | [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Investigators and technical Windows users: fast Windows Event Log hunting and timeline generation, including Sigma rules and output suitable for downstream analysis. | Free to use; no license key required. Hayabusa is AGPLv3; its detection rules use the separate DRL 1.1 license. | Strong, focused complement to the existing artifact parsers. Keep the program and detection-rule licenses visible when packaging or redistributing rules. |
| 3 | [MemProcFS](https://github.com/ufrisk/MemProcFS) | Memory investigators: examine Windows memory dumps through a mounted, queryable file-system view and run forensic plugins/YARA scans. | AGPLv3; no license key required. | Adds a distinct workflow alongside the legacy Volatility 2/3 selectors. Prefer read-only analysis of a verified offline dump; the project also supports live memory and read/write-capable devices, which need a separate authorization and handling review. Windows use requires Dokany for mounting. |
| 4 | [Velociraptor](https://docs.velociraptor.app/docs/overview/) | Forensic investigators: remote artifact collection, endpoint triage, fleet hunts, and live monitoring through VQL artifacts. Complements one-host collection utilities with a client/server workflow. | Open source; no license key required. | Highest-value investigation addition. Consider documenting both standalone collection and managed deployment; the server/client setup is substantially more involved than a normal workstation utility. |
| 5 | [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10) | Technical users and administrators: compare, edit, test, and apply Microsoft's Windows security baselines using Policy Analyzer and LGPO. | Microsoft-distributed; no license key required. | High-value host-hardening addition, with baselines for Windows 11 and Windows Server 2025. Start with comparison and review; applying a baseline changes system policy and should be tested against the user's role and existing policy. |
| 6 | [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) | Technical Windows users and investigators: inspect crash dumps, debug live user or kernel code, and examine memory/register state. | Microsoft-distributed; no license key required. | Broad Windows troubleshooting value as well as forensic value. Microsoft documents Windows Package Manager installation (`Microsoft.WinDbg`); confirm Server support and package detection before cataloging it. |
| 7 | [YARA-X](https://github.com/VirusTotal/yara-x) | Investigators and malware analysts: scan files with reusable text/binary pattern rules and perform local, repeatable triage. | BSD-3-Clause; no license key required. | Prefer evaluating YARA-X as the forward-looking choice: its maintainers declared it stable and the original YARA is in maintenance mode. Rule packs have their own licenses and update cadence. |
| 8 | [capa](https://github.com/mandiant/capa) | Malware analysts: identify likely capabilities in suspicious executables, .NET files, shellcode, or supported sandbox reports. | Apache-2.0; no license key required. | Excellent portable static-triage utility; its output supports analyst investigation and is not a verdict that a file is malicious. |
| 9 | [FLOSS](https://github.com/mandiant/flare-floss) | Malware analysts: recover ordinary, stack, and obfuscated strings from binaries where basic string extraction is insufficient. | Public standalone releases; no license key required. | Pairs well with capa for portable first-pass triage. Verify the current release artifact, upstream license, and update behavior when implementing. |
| 10 | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Advanced Windows users and investigators: disassemble and decompile compiled software, automate analysis, and inspect unfamiliar binaries. | Apache-2.0; no license key required. | High-quality reverse-engineering suite, but a larger specialist install than the other candidates. Current upstream instructions require a 64-bit JDK; account for that prerequisite and its update lifecycle. |

## Suggested order

For investigation coverage, prioritize **FTK Imager** for disk-image work, **Hayabusa** for event-log analysis, and **MemProcFS** for offline memory-dump analysis. Add **Velociraptor** as a separate investigation solution when the repository is ready to document its server/client deployment model. For everyday Windows security, prioritize **Security Compliance Toolkit** and **WinDbg**. Treat **YARA-X**, **capa**, **FLOSS**, and **Ghidra** as optional analyst-profile tools rather than default workstation software.

## Investigator workflow and low-impact use

Experienced investigators select tools by task and evidence source rather than installing one giant suite on a subject system. NIST describes a forensic process spanning collection, examination, analysis, and reporting; CISA guidance emphasizes preserving volatile evidence. CISA's incident playbooks also call for detailed evidence logs. A practical Windows flow is:

1. **Scope and preserve.** Follow the incident plan and authority for collection. Record host identity, time, operator, tool versions, commands, and any containment decision. Prioritize volatile information when the case needs it; running tools or shutting down can change or destroy evidence.
2. **Acquire deliberately.** For offline storage, use a suitable write blocker when applicable. Preserve the original, record hashes and acquisition details, and work from verified copies. For live response, use the smallest authorized collector that answers the question and document its expected effects.
3. **Analyze copies.** Use the existing KAPE, Zimmerman, Autopsy, Chainsaw, and Volatility candidates alongside additions such as Hayabusa, FTK Imager, and MemProcFS. Correlate host artifacts with Windows event logs and relevant network or centralized logs; no one tool establishes a finding by itself.
4. **Keep the analysis environment separate.** Use a dedicated, patched analysis workstation or disposable VM. Keep storage encrypted and access-limited. For untrusted files, Windows Sandbox can be useful on supported editions, but its networking and clipboard are enabled by default; disable networking, disable clipboard sharing, and expose only a read-only sample folder when that matches the task. Use an isolated malware lab for behavior requiring networking. Sandbox isolation is not a guarantee that malware cannot detect or escape the environment.
5. **Harden without destroying evidence.** On an everyday workstation, use Microsoft's reviewed baselines as a starting point and retain Defender, firewall, update, and security logging protections. Do not apply hardening changes to a suspected evidence host before collection unless the response plan calls for it.

Low-impact collection and concealment are different goals. Do not market collectors as invisible: endpoint controls may record them, and preventing those records would undermine the evidence trail. For a high-stakes investigation, validate the chosen tools and workflow against representative test images before relying on them; NIST's tool catalog is a discovery aid, not a certification or endorsement.

## Existing repository tools worth migrating

These useful capabilities already appear in legacy selectors, so they are migration work rather than new candidate packages:

- **Sysmon and its configurations** for opt-in endpoint telemetry. The repo already references Sysmon plus SwiftOnSecurity and Olaf Hartong configurations. Keep configuration selection explicit; increasing event collection affects storage, privacy, and system behavior.
- **Windows Sandbox** for disposable testing on supported Windows editions. The repo already has legacy install/remove selectors. Prefer a reviewed `.wsb` template with networking and clipboard disabled and sample folders read-only for untrusted-file inspection.
- **Volatility 2/3** for memory analysis. MemProcFS is supplemental because it offers a different mounted-filesystem workflow, not because it replaces the existing tools.

## Repository implementation notes

- The existing `RIDE-Packages.psm1` handler currently accepts `InstallerType = 'Exe'`. Several candidates are portable releases or archives, so add and validate archive extraction, version detection, and removal behavior before representing them as ordinary package operations.
- Prefer upstream release pages or official Microsoft distribution channels. Pin or resolve versions deliberately, verify downloaded artifacts where upstream publishes hashes/signatures, and retain license and rule-pack attribution.
- Keep acquisition, examination, and live-response tools opt-in in profiles. Their presence does not configure logging, deploy an endpoint service, or establish evidence-handling procedures by itself.
- Confirm target support and behavior on the repository's declared Windows 11 and Windows Server targets before adding catalog entries. In particular, verify elevated operation needs, unattended install/removal, update semantics, and whether a tool is appropriate for server images.

## Primary references

- [Velociraptor overview](https://docs.velociraptor.app/docs/overview/)
- [Hayabusa project and license](https://github.com/Yamato-Security/hayabusa)
- [WinDbg installation and support](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/)
- [YARA-X project](https://github.com/VirusTotal/yara-x) and [Windows installation](https://virustotal.github.io/yara-x/docs/intro/installation/)
- [capa project](https://github.com/mandiant/capa)
- [FLOSS project and releases](https://github.com/mandiant/flare-floss)
- [Ghidra project and installation](https://github.com/NationalSecurityAgency/ghidra)
- [FTK Imager product page and license FAQ](https://www.exterro.com/digital-forensics-software)
- [MemProcFS project, examples, and license](https://github.com/ufrisk/MemProcFS)
- [Microsoft Security Compliance Toolkit](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)
- [NIST Computer Forensics Tools & Techniques Catalog](https://toolcatalog.nist.gov/)
- [CISA guidance on preserving forensic data](https://www.cisa.gov/sites/default/files/FactSheets/NCCIC%20ICS_FactSheet_AreYouCompromised_S508C.pdf)
- [CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks](https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf)
- [Windows Sandbox overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)
- [Windows Sandbox configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
