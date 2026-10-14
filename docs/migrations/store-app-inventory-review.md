# Store app inventory review and next decisions

Reviewed: **2026-10-14**. Both pinned disposable references have verified read-only
user and provisioning captures. **Keep every app; packages remain paused.**
The user accepted optional app-group membership below. Executable uninstall,
reinstall and policy acceptance remain pending; adding choices removes no apps.

## Captured references

| Reference | Edition/release/build observed | User rows / distinct names | Provisioned rows / distinct names |
| --- | --- | ---: | ---: |
| Windows 11 | EnterpriseEval, 26H2, 26300.9457 | 170 / 102 | 47 / 47 |
| Windows Server 2025 | ServerStandardEval, 24H2, 26100.33438 | 57 / 52 | 5 / 5 |

User rows include main/bundle/resource/framework registrations; counts are not
counts of distinct removable apps. Provisioning describes the online image for
new profiles, separately from this configured user. The references do not prove
an untouched inbox baseline, Home/Pro/Education/OEM/region coverage or another
user's registrations. Raw ProductName is retained separately from CIM/build.

[Dated collection evidence](../archive/evidence/store-app-reference-collection-2026-10-14.md)
retains run IDs, hashes, test results and checkpoint checks. Full local review data
is .local/store-reference-review-20261014.json; hash-verified copies of raw JSON
are retained under each .local/settings-validation/RunId. No historical alias or
provisioned name is converted into a package-family identity.

## Current static policy candidates

Every row is currently Keep. U/P means observed user/provisioning row counts.
Exact is a comparison against the inspected template PFN, not effective-policy
or uninstall acceptance. The template's inclusion is not a reason to remove an app.

| Exact app name | Windows 11 U/P | Server 2025 U/P | PFN comparison W11 / Server |
| --- | ---: | ---: | --- |
| Clipchamp.Clipchamp | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.BingNews | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.BingWeather | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.Copilot | 0/0 | 0/0 | NotObserved / NotObserved |
| Microsoft.GamingApp | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.MicrosoftOfficeHub | 0/0 | 0/0 | NotObserved / NotObserved |
| Microsoft.MicrosoftSolitaireCollection | 2/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.MicrosoftStickyNotes | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.OutlookForWindows | 1/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.Paint | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.ScreenSketch | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.Todos | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.Windows.Photos | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.WindowsCalculator | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.WindowsCamera | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.WindowsFeedbackHub | 3/1 | 3/1 | ExactPolicyFamilyObserved / ExactPolicyFamilyObserved |
| Microsoft.WindowsNotepad | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.WindowsSoundRecorder | 2/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.WindowsTerminal | 2/1 | 2/1 | ExactPolicyFamilyObserved / ExactPolicyFamilyObserved |
| Microsoft.Xbox.TCUI | 2/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.XboxIdentityProvider | 2/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.XboxSpeechToTextOverlay | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| Microsoft.ZuneMusic | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| MicrosoftCorporationII.QuickAssist | 3/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |
| MSTeams | 1/1 | 0/0 | ExactPolicyFamilyObserved / NotObserved |

## Other observed names

These names have no static entry in the inspected policy template. Their presence
requires review rather than a guessed replacement or policy choice. Guarded means
at least one captured registration is framework, non-removable or marked system;
it is not a complete dependency assessment. Unknown IsPartOfSystem stays unknown.
All rows remain kept, including entries with no observed protection flag.
IsPartOfSystem was unavailable for every registration in both captures. It stays
null; no positive guard observed must not be interpreted as safe to remove.

| Observed name | Windows 11 U/P | Server 2025 U/P | Captured guard flag |
| --- | ---: | ---: | --- |
| 1527c705-839a-4832-9118-54d4Bd6a0c89 | 1/0 | 1/0 | Guarded |
| c5e2524a-ea46-4f67-841f-6a9465d9d515 | 1/0 | 1/0 | Guarded |
| E2A4F912-2574-4A75-9BB0-0D023378592B | 1/0 | 1/0 | Guarded |
| F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE | 1/0 | 1/0 | Guarded |
| Microsoft.AccountsControl | 1/0 | 1/0 | Guarded |
| Microsoft.AIFabric.CBS.1.6 | 1/0 | 0/0 | Guarded |
| Microsoft.ApplicationCompatibilityEnhancements | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.AsyncTextService | 1/0 | 1/0 | Guarded |
| Microsoft.AV1VideoExtension | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.AVCEncoderVideoExtension | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.BingSearch | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.BioEnrollment | 1/0 | 1/0 | Guarded |
| Microsoft.CredDialogHost | 1/0 | 1/0 | Guarded |
| Microsoft.DesktopAppInstaller | 2/1 | 3/1 | Guarded |
| Microsoft.ECApp | 1/0 | 1/0 | Guarded |
| Microsoft.GetHelp | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.HEIFImageExtension | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.HEVCVideoExtension | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.LockApp | 1/0 | 1/0 | Guarded |
| Microsoft.MicrosoftEdge.Stable | 1/1 | 1/1 | No positive guard observed; review pending |
| Microsoft.MicrosoftEdgeDevToolsClient | 1/0 | 1/0 | Guarded |
| Microsoft.MPEG2VideoExtension | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.NET.Native.Framework.2.2 | 1/0 | 1/0 | Guarded |
| Microsoft.NET.Native.Runtime.2.2 | 1/0 | 1/0 | Guarded |
| Microsoft.PowerAutomateDesktop | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.RawImageExtension | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.SecHealthUI | 1/1 | 1/1 | Guarded |
| Microsoft.StorePurchaseApp | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.UI.Xaml.2.8 | 1/0 | 1/0 | Guarded |
| Microsoft.UI.Xaml.CBS | 1/0 | 1/0 | Guarded |
| Microsoft.VCLibs.140.00 | 1/0 | 1/0 | Guarded |
| Microsoft.VCLibs.140.00.UWPDesktop | 1/0 | 1/0 | Guarded |
| Microsoft.VP9VideoExtensions | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.WebMediaExtensions | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.WebpImageExtension | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.Win32WebViewHost | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.Apprep.ChxApp | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.AssignedAccessLockApp | 1/0 | 0/0 | Guarded |
| Microsoft.Windows.AugLoop.CBS | 1/0 | 0/0 | Guarded |
| Microsoft.Windows.CapturePicker | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.CloudExperienceHost | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.ContentDeliveryManager | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.DevHome | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.Windows.NarratorQuickStart | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.OOBENetworkCaptivePortal | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.OOBENetworkConnectionFlow | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.ParentalControls | 1/0 | 0/0 | Guarded |
| Microsoft.Windows.PeopleExperienceHost | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.PinningConfirmationDialog | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.PrintQueueActionCenter | 1/0 | 0/0 | Guarded |
| Microsoft.Windows.SecureAssessmentBrowser | 1/0 | 0/0 | Guarded |
| Microsoft.Windows.ShellExperienceHost | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.StartMenuExperienceHost | 1/0 | 1/0 | Guarded |
| Microsoft.Windows.XGpuEjectDialog | 1/0 | 1/0 | Guarded |
| Microsoft.WindowsAlarms | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.WindowsAppRuntime.1.3 | 1/0 | 0/0 | Guarded |
| Microsoft.WindowsAppRuntime.CBS.1.6 | 1/0 | 1/0 | Guarded |
| Microsoft.WindowsAppRuntime.CBS.1.8 | 0/0 | 1/0 | Guarded |
| Microsoft.WindowsAppRuntime.CBS.2 | 1/0 | 0/0 | Guarded |
| Microsoft.WindowsStore | 2/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.XboxGameCallableUI | 1/0 | 0/0 | Guarded |
| Microsoft.XboxGamingOverlay | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.YourPhone | 3/1 | 0/0 | No positive guard observed; review pending |
| Microsoft.AAD.BrokerPlugin | 1/0 | 1/0 | Guarded |
| MicrosoftWindows.57242383.Tasbar | 0/0 | 1/0 | Guarded |
| MicrosoftWindows.59336768.Speion | 0/0 | 1/0 | Guarded |
| MicrosoftWindows.59337133.Voiess | 0/0 | 1/0 | Guarded |
| MicrosoftWindows.59337145.Livtop | 0/0 | 1/0 | Guarded |
| MicrosoftWindows.59379618.InpApp | 0/0 | 1/0 | Guarded |
| MicrosoftWindows.61869720.Voiess | 1/0 | 0/0 | Guarded |
| MicrosoftWindows.61869721.Livtop | 1/0 | 0/0 | Guarded |
| MicrosoftWindows.61869722.Speion | 1/0 | 0/0 | Guarded |
| MicrosoftWindows.61869836.InpApp | 1/0 | 0/0 | Guarded |
| MicrosoftWindows.Client.CBS | 1/0 | 1/0 | Guarded |
| MicrosoftWindows.Client.Core | 1/0 | 1/0 | Guarded |
| MicrosoftWindows.Client.CoreAI | 1/0 | 0/0 | Guarded |
| MicrosoftWindows.Client.FileExp | 1/0 | 1/0 | Guarded |
| MicrosoftWindows.Client.OOBE | 1/0 | 1/0 | Guarded |
| MicrosoftWindows.Client.Photon | 1/0 | 1/0 | Guarded |
| MicrosoftWindows.Client.WebExperience | 2/1 | 0/0 | No positive guard observed; review pending |
| MicrosoftWindows.CrossDevice | 3/1 | 0/0 | No positive guard observed; review pending |
| MicrosoftWindows.UndockedDevKit | 1/0 | 1/0 | Guarded |
| Windows.CBSPreview | 1/0 | 1/0 | Guarded |
| windows.immersivecontrolpanel | 1/0 | 1/0 | Guarded |
| Windows.PrintDialog | 1/0 | 1/0 | Guarded |

## Accepted group decisions

The user approved these optional uninstall/reinstall groups, with the sustained
device policy kept as its own workflow. Their documentation links both ways.

| Batch | Group | Accepted membership |
| --- | --- | --- |
| 1 | Consumer apps | Clipchamp, News, Weather, Solitaire |
| 2A | Core utilities | Calculator, Notepad, Snipping Tool, Terminal |
| 2B | Multimedia | Photos, Paint, Camera, Media Player, Sound Recorder |
| 2C | Assistance and personal productivity | Quick Assist, Sticky Notes, Outlook, To Do |
| 3 | Xbox and gaming | Xbox app, Game Bar, TCUI, Identity Provider, Speech to Text Overlay; dependencies reviewed together |

The [group contract and exact identities](../store-app-groups.md) records all
22 app choices, reinstall/source limits, protected/shared dependencies and batch
order. No current registration is changed by adding these choices. Media Player
and Sound Recorder are included in 2B by the user's follow-up; codecs/extensions
and legacy media components remain outside the group. Historical-only apps and
unlisted current candidates remain outside accepted membership.

Other editions/users can be collected when a selected target needs them. Existing
references do not establish Home/Pro coverage or universal app retirement.

Before an uninstall batch: complete same-desktop intended-user handoff acceptance,
refresh live exact identities, preserve unknown protection flags, inspect other
package consumers, and define refusal/partial reporting plus reinstall/data limits.
Before a policy batch: verify template/schema/edition/servicing, managed precedence
and actual sign-in effects, with configuration recovery distinct from restoring
apps or data. Image deprovisioning, AllUsers removal and blanket re-registration
remain separate unapproved scope.

Group membership and workflow separation are decided. All five groups and the
explicit same-session Store handoff are implemented as candidates. The user
approved the reviewed identity/removability rule while retaining visibly unknown
IsPartOfSystem, and chose to wait for usable local reinstall sources. Native
handoff, app-specific lifecycle and policy acceptance remain pending. See the
[active acceptance tasks](store-app-follow-up-decisions.md). No supported target
or default/recommended profile is changed.
