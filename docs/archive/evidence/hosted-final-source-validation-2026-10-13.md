# Hosted final-source validation, 2026-10-13

Full hosted validation **passed** for published candidate
`f5e32180faf96508c35534ba46677bc78d0fe889`. This closes the hosted source
validation gate for that candidate. Broader controller certification and
manual-dispatch/master-push acceptance remain deferred until v3 reaches release
candidate state and publication/activation is agreed.

## Source and trigger

Review branch `codex/ride-v3-hosted-validation-20261013` was published with trigger
`cc5481f2bdff02015f939d1b9d631fca135737e7`. The trigger changed no content: both
commits reference tree `29999e7a2f4e7e2dab74c35e3993782ca0cd025c`. Its commit
message omitted the skip-CI instruction so the candidate's existing Validate
workflow could run. No checkout switch, ordinary-index staging or PR was needed.

[Validate run 38413683226](https://github.com/tjuuljensen/ride-windows/actions/runs/38413683226)
ran on GitHub-hosted windows-latest with pinned Pester 5.7.1. Both jobs checked
out the actual trigger revision and passed catalog/profile/syntax/generated-
document validation: 318 operations, three groups, five profiles and 120
PowerShell files. The full tests directory ran in both declared editions.

## Completed results

| Edition | Job ID | Passed | Failed | Skipped | Inconclusive / NotRun | Conclusion |
| --- | --- | ---: | ---: | ---: | --- | --- |
| Windows PowerShell 5.1 | 115352321943 | 1,455 | 0 | 0 | 0 / 0 | Success |
| PowerShell 7 | 115352322372 | 1,453 | 0 | 2 | 0 / 0 | Success |

The two PowerShell 7 skips are the Windows PowerShell-only controller host
preflight checks: prepared elevated-host validation and non-elevated refusal.
Both passed in the Windows PowerShell 5.1 job. They are intentional edition
exclusions, not unexamined missing coverage. PowerShell 7 finished Pester at
14:35:23 UTC in 367.33 seconds; Windows PowerShell 5.1 finished at 14:40:12 UTC
in 582 seconds. Completed job steps and full decoded logs were retained locally
and audited at 14:42:11 UTC.

| Retained local log | SHA-256 |
| --- | --- |
| powershell-job.log | 60EB037E23D996C2477356020B8F4258340F461AA33EAFE4739101A6859AE3A1 |
| pwsh-job.log | 16571AF4681510CCD0D3570E6A4DD441BFC564581A4CAA8DEAA8A1DDB772DE30 |

Local evidence is `.local/hosted-validation-20261013/{state,jobs}.json` and
the two logs. These hashes identify the retained decoded log files.

## Scope and remaining gates

The disposable VM workflow's push filter excludes the review branch; this
publication triggered hosted Validate only. No Hyper-V controller request,
self-hosted run, activation-variable change or master publication occurred.
The frozen CI checkout remained clean at `a156475`; local master remained
`ba7f8c9`. Shared checkout branch and index were unchanged by trigger publication.
Unfinished settings/service fixture edits and other migration work were excluded
and preserved. ArtCraft Launcher was not restarted.

Hosted regression does not establish new settings' GUI/effective-state/target
acceptance or advance the installed guest baseline. Existing anonymous bridge
pairs and controller 0.4.6 scoped normal/timeout/refusal/record acceptance retain
their original evidence. The [active matrix](../../migrations/controller-certification.md)
owns deferred delivery gates. New implementation changes and the eventual RC
source require their own applicable validation; this result names the actual
tested tree rather than claiming future source is accepted.
