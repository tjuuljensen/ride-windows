# Six control presentation batch 1

Recorded: **2026-10-14**. Added explicit SettingPresentation metadata for
windows.hidden-files-visibility, windows.protected-files-visibility,
windows.explorer-recent-shortcuts, windows.explorer-frequent-shortcuts,
windows.control-panel-view and application.edge-background-mode. Generated
OPERATIONS.md through its source generator.

Before/after canonical data comparison of all six operation records, excluding
only SettingPresentation, passed. IDs, states, values, paths, supported targets,
scope, elevation, baseline/default declarations and recovery contracts are unchanged.
The catalog contains 28 explicit presentation records, up from 22. This is not six
new legacy outcomes or proof of effective GUI behavior.

PowerShell 7.6.5: SettingPresentation.Tests.ps1, Catalog.Tests.ps1 and
Search.Tests.ps1 completed with **122 passing, zero failing**, and one
WindowsIntegration test excluded. TestRegistry was disabled. The first attempt's
NUnit export failed because sandboxed Pester could not query CIM environment
metadata after all assertions passed. The retry disabled that export and completed
successfully, retaining the console and compact JSON result instead.

PowerShell 7 parser/catalog/profile/reference/generated-document validation passed:
318 operations, three groups, five profiles, 131 PowerShell files.
Windows PowerShell 5.1.26100.9711 also passed all 122 tests, zero failed, one
integration test excluded. Initial direct script attempts stopped at
AuthorizationManager and read-only execution-policy inspection was denied.
The subsequent attempt used README's established process-only `-ExecutionPolicy
Bypass` launch and succeeded. No elevation or persistent policy change was made.
Full validation passed on both editions; after adding the next handoff module/test
it checked 133 PowerShell files. Both editions used the already-installed Pester
5.7.1 by explicit path; no dependency was downloaded.

The references for all six controls were read from Microsoft Learn/Support.
Feature-only references remain labelled as such. Existing Explorer Visible
override-removal semantics, coordinated Control Panel choices and Edge mandatory
policy scope remain explicit. Current GUI, managed precedence and intended-user
execution need independent acceptance.

No Windows setting, VM, package or GitHub publisher request was changed or started.
No supported target or recommended profile was expanded. Local supplementary
evidence is in .local/presentation-batch1-before.clixml,
.local/presentation-batch1-contract.json and
.local/presentation-batch1-7/result.json and .local/presentation-batch1-5/result.json.
All five legacy estimate ranges remain
38-58 / 58-73 / 20-25 / 25-35 / 8-12, rounded total 150-205, about 180.

The user chose a separate intended-user process handoff for the next batch,
initially limited to the current signed-in desktop session. This decision does
not itself establish a working handoff or mixed-scope recovery.
