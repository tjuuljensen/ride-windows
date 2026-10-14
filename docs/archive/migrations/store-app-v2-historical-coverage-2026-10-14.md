# V2 Store app historical coverage

Archived: **2026-10-14**. The user selected a modern v3 scope with live inventories and reviewed app choices. These lists preserve Windows 10/v2 history; they impose no requirement to implement every historical entry in v3.

The [data-only archive](store-app-v2-historical-coverage-2026-10-14.json) retains all four literal function lists, source SHA-256, 106 removal names, 102 registration names and four reverse gaps. Original [v2 source](../../../legacy/v2/lib-windows.psm1) remains unchanged. No compatibility runner or executable preset is connected to v3.

The 119-row comparison below retains the earlier 25-entry inspected-template overlay. Its 13 additional names and twelve literal overlaps are reference evidence, not accepted current inventories or removal selections. Current decisions belong in the [active inventory plan](../../migrations/store-app-inventory-plan.md). Both explicit v3 workflows remain pending review/acceptance; all apps are kept and packages are paused.

Missing reverse entries are AmazonVideo.PrimeVideo, BytedancePte.Ltd.TikTok, Clipchamp.Clipchamp and Facebook.InstagramBeta. V2 re-registration is not captured version/app-data recovery. The blanket bulk remove/register workflows are retired as v3 implementation requirements; selected-app lifecycle replaces them when accepted.

## Historical comparison matrix

M = Microsoft v2 removal; T = third-party v2 removal; P = static policy declaration.
A missing reverse means the historical removal had no matching register entry.
Dependency and Keep classifications are review cautions, not approved selections.

| Exact package Name | Source | Template PFN | Missing legacy reverse | Review class |
| --- | --- | --- | --- | --- |
| 2414FC7A.Viber | T | Unmapped historical name | No | AppReview |
| 41038Axilesoft.ACGMediaPlayer | T | Unmapped historical name | No | AppReview |
| 46928bounde.EclipseManager | T | Unmapped historical name | No | AppReview |
| 4DF9E0F8.Netflix | T | Unmapped historical name | No | AppReview |
| 64885BlueEdge.OneCalendar | T | Unmapped historical name | No | AppReview |
| 7EE7776C.LinkedInforWindows | T | Unmapped historical name | No | AppReview |
| 828B5831.HiddenCityMysteryofShadows | T | Unmapped historical name | No | AppReview |
| 89006A2E.AutodeskSketchBook | T | Unmapped historical name | No | AppReview |
| 9E2F88E3.Twitter | T | Unmapped historical name | No | AppReview |
| A278AB0D.DisneyMagicKingdoms | T | Unmapped historical name | No | AppReview |
| A278AB0D.DragonManiaLegends | T | Unmapped historical name | No | AppReview |
| A278AB0D.MarchofEmpires | T | Unmapped historical name | No | AppReview |
| ActiproSoftwareLLC.562882FEEB491 | T | Unmapped historical name | No | AppReview |
| AD2F1837.GettingStartedwithWindows8 | T | Unmapped historical name | No | AppReview |
| AD2F1837.HPJumpStart | T | Unmapped historical name | No | AppReview |
| AD2F1837.HPRegistration | T | Unmapped historical name | No | AppReview |
| AdobeSystemsIncorporated.AdobePhotoshopExpress | T | Unmapped historical name | No | AppReview |
| Amazon.com.Amazon | T | Unmapped historical name | No | AppReview |
| AmazonVideo.PrimeVideo | T | Unmapped historical name | Yes | AppReview |
| BytedancePte.Ltd.TikTok | T | Unmapped historical name | Yes | AppReview |
| C27EB4BA.DropboxOEM | T | Unmapped historical name | No | AppReview |
| CAF9E577.Plex | T | Unmapped historical name | No | AppReview |
| Clipchamp.Clipchamp | T, P | Clipchamp.Clipchamp_yxz26nhyzhsrt | Yes | AppReview |
| CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC | T | Unmapped historical name | No | AppReview |
| D52A8D61.FarmVille2CountryEscape | T | Unmapped historical name | No | AppReview |
| D5EA27B7.Duolingo-LearnLanguagesforFree | T | Unmapped historical name | No | AppReview |
| DB6EA5DB.CyberLinkMediaSuiteEssentials | T | Unmapped historical name | No | AppReview |
| Disney.37853FC22B2CE | T | Unmapped historical name | No | AppReview |
| DolbyLaboratories.DolbyAccess | T | Unmapped historical name | No | AppReview |
| Drawboard.DrawboardPDF | T | Unmapped historical name | No | AppReview |
| Facebook.Facebook | T | Unmapped historical name | No | AppReview |
| Facebook.InstagramBeta | T | Unmapped historical name | Yes | AppReview |
| Fitbit.FitbitCoach | T | Unmapped historical name | No | AppReview |
| flaregamesGmbH.RoyalRevolt2 | T | Unmapped historical name | No | AppReview |
| GAMELOFTSA.Asphalt8Airborne | T | Unmapped historical name | No | AppReview |
| KeeperSecurityInc.Keeper | T | Unmapped historical name | No | AppReview |
| king.com.BubbleWitch3Saga | T | Unmapped historical name | No | AppReview |
| king.com.CandyCrushFriends | T | Unmapped historical name | No | AppReview |
| king.com.CandyCrushSaga | T | Unmapped historical name | No | AppReview |
| king.com.CandyCrushSodaSaga | T | Unmapped historical name | No | AppReview |
| king.com.FarmHeroesSaga | T | Unmapped historical name | No | AppReview |
| Microsoft.3DBuilder | M | Unmapped historical name | No | AppReview |
| Microsoft.Advertising.Xaml | M | Unmapped historical name | No | DependencyReview |
| Microsoft.AppConnector | M | Unmapped historical name | No | AppReview |
| Microsoft.BingFinance | M | Unmapped historical name | No | AppReview |
| Microsoft.BingFoodAndDrink | M | Unmapped historical name | No | AppReview |
| Microsoft.BingHealthAndFitness | M | Unmapped historical name | No | AppReview |
| Microsoft.BingMaps | M | Unmapped historical name | No | AppReview |
| Microsoft.BingNews | M, P | Microsoft.BingNews_8wekyb3d8bbwe | No | AppReview |
| Microsoft.BingSports | M | Unmapped historical name | No | AppReview |
| Microsoft.BingTranslator | M | Unmapped historical name | No | AppReview |
| Microsoft.BingTravel | M | Unmapped historical name | No | AppReview |
| Microsoft.BingWeather | M, P | Microsoft.BingWeather_8wekyb3d8bbwe | No | AppReview |
| Microsoft.CommsPhone | M | Unmapped historical name | No | AppReview |
| Microsoft.ConnectivityStore | M | Unmapped historical name | No | AppReview |
| Microsoft.Copilot | P | Microsoft.Copilot_8wekyb3d8bbwe | No | AppReview |
| Microsoft.FreshPaint | M | Unmapped historical name | No | AppReview |
| Microsoft.GamingApp | P | Microsoft.GamingApp_8wekyb3d8bbwe | No | AppReview |
| Microsoft.GetHelp | M | Unmapped historical name | No | AppReview |
| Microsoft.Getstarted | M | Unmapped historical name | No | AppReview |
| Microsoft.HelpAndTips | M | Unmapped historical name | No | AppReview |
| Microsoft.Media.PlayReadyClient.2 | M | Unmapped historical name | No | DependencyReview |
| Microsoft.Messaging | M | Unmapped historical name | No | AppReview |
| Microsoft.Microsoft3DViewer | M | Unmapped historical name | No | AppReview |
| Microsoft.MicrosoftOfficeHub | M, P | Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe | No | AppReview |
| Microsoft.MicrosoftPowerBIForWindows | M | Unmapped historical name | No | AppReview |
| Microsoft.MicrosoftSolitaireCollection | M, P | Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe | No | AppReview |
| Microsoft.MicrosoftStickyNotes | M, P | Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe | No | AppReview |
| Microsoft.MinecraftUWP | M | Unmapped historical name | No | AppReview |
| Microsoft.MixedReality.Portal | M | Unmapped historical name | No | AppReview |
| Microsoft.MoCamera | M | Unmapped historical name | No | AppReview |
| Microsoft.MSPaint | M | Unmapped historical name | No | AppReview |
| Microsoft.NetworkSpeedTest | M | Unmapped historical name | No | AppReview |
| Microsoft.Office.OneNote | M | Unmapped historical name | No | AppReview |
| Microsoft.Office.Sway | M | Unmapped historical name | No | AppReview |
| Microsoft.OfficeLens | M | Unmapped historical name | No | AppReview |
| Microsoft.OneConnect | M | Unmapped historical name | No | AppReview |
| Microsoft.OutlookForWindows | P | Microsoft.OutlookForWindows_8wekyb3d8bbwe | No | AppReview |
| Microsoft.Paint | P | Microsoft.Paint_8wekyb3d8bbwe | No | AppReview |
| Microsoft.People | M | Unmapped historical name | No | AppReview |
| Microsoft.Print3D | M | Unmapped historical name | No | AppReview |
| Microsoft.Reader | M | Unmapped historical name | No | AppReview |
| Microsoft.RemoteDesktop | M | Unmapped historical name | No | AppReview |
| Microsoft.ScreenSketch | P | Microsoft.ScreenSketch_8wekyb3d8bbwe | No | KeepReview |
| Microsoft.SkypeApp | M | Unmapped historical name | No | AppReview |
| Microsoft.Todos | M, P | Microsoft.Todos_8wekyb3d8bbwe | No | AppReview |
| Microsoft.Wallet | M | Unmapped historical name | No | AppReview |
| Microsoft.WebMediaExtensions | M | Unmapped historical name | No | AppReview |
| Microsoft.Whiteboard | M | Unmapped historical name | No | AppReview |
| Microsoft.Windows.Photos | M, P | Microsoft.Windows.Photos_8wekyb3d8bbwe | No | AppReview |
| Microsoft.WindowsAlarms | M | Unmapped historical name | No | AppReview |
| Microsoft.WindowsCalculator | P | Microsoft.WindowsCalculator_8wekyb3d8bbwe | No | KeepReview |
| Microsoft.WindowsCamera | M, P | Microsoft.WindowsCamera_8wekyb3d8bbwe | No | AppReview |
| microsoft.windowscommunicationsapps | M | Unmapped historical name | No | AppReview |
| Microsoft.WindowsFeedbackHub | M, P | Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe | No | AppReview |
| Microsoft.WindowsMaps | M | Unmapped historical name | No | AppReview |
| Microsoft.WindowsNotepad | P | Microsoft.WindowsNotepad_8wekyb3d8bbwe | No | KeepReview |
| Microsoft.WindowsPhone | M | Unmapped historical name | No | AppReview |
| Microsoft.WindowsReadingList | M | Unmapped historical name | No | AppReview |
| Microsoft.WindowsScan | M | Unmapped historical name | No | AppReview |
| Microsoft.WindowsSoundRecorder | M, P | Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe | No | AppReview |
| Microsoft.WindowsTerminal | P | Microsoft.WindowsTerminal_8wekyb3d8bbwe | No | KeepReview |
| Microsoft.WinJS.1.0 | M | Unmapped historical name | No | DependencyReview |
| Microsoft.WinJS.2.0 | M | Unmapped historical name | No | DependencyReview |
| Microsoft.Xbox.TCUI | P | Microsoft.Xbox.TCUI_8wekyb3d8bbwe | No | AppReview |
| Microsoft.XboxIdentityProvider | P | Microsoft.XboxIdentityProvider_8wekyb3d8bbwe | No | AppReview |
| Microsoft.XboxSpeechToTextOverlay | P | Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe | No | AppReview |
| Microsoft.YourPhone | M | Unmapped historical name | No | AppReview |
| Microsoft.ZuneMusic | M, P | Microsoft.ZuneMusic_8wekyb3d8bbwe | No | AppReview |
| Microsoft.ZuneVideo | M | Unmapped historical name | No | AppReview |
| MicrosoftCorporationII.QuickAssist | P | MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe | No | KeepReview |
| MSTeams | P | MSTeams_8wekyb3d8bbwe | No | AppReview |
| Nordcurrent.CookingFever | T | Unmapped historical name | No | AppReview |
| PandoraMediaInc.29680B314EFC2 | T | Unmapped historical name | No | AppReview |
| PricelinePartnerNetwork.Booking.comBigsavingsonhot | T | Unmapped historical name | No | AppReview |
| SpotifyAB.SpotifyMusic | T | Unmapped historical name | No | AppReview |
| ThumbmunkeysLtd.PhototasticCollage | T | Unmapped historical name | No | AppReview |
| WinZipComputing.WinZipUniversal | T | Unmapped historical name | No | AppReview |
| XINGAG.XING | T | Unmapped historical name | No | AppReview |
