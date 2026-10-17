<#
.SYNOPSIS
  Verify inert ODT XML review, bounds, action visibility and sensitive-data omission.
.DESCRIPTION
  Uses synthetic configuration bytes and extracts XML text from historical source.
  Does not execute legacy code, ODT, native providers, external entities or installers.
.EXAMPLE
  Invoke-Pester .\tests\OfficeConfigurationReview.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5, Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Version: Repository fixture; no actual Office deployment or activation acceptance.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $Root 'modules/RIDE.OfficeConfigurationReview.psm1') -Force
  function ConvertTo-OfficeTestBytes([string]$Text){,[Text.UTF8Encoding]::new($false,$true).GetBytes($Text)}
  $script:BasicXml='<Configuration><Add OfficeClientEdition="64" Channel="MonthlyEnterprise" Version="16.0.12345.12345"><Product ID="O365ProPlusRetail"><Language ID="en-gb"/></Product></Add></Configuration>'
}
Describe 'Inert Office configuration review' {
  It 'reports explicit product intent without making mutation or activation claims' {
    $bytes=ConvertTo-OfficeTestBytes $BasicXml
    $before=[Convert]::ToBase64String($bytes)
    $r=Get-RideOfficeConfigurationReview -Bytes $bytes
    $r.Kind | Should -BeExactly OfficeConfigurationReview
    $r.SchemaVersion | Should -Be 1
    $r.Additions.Count | Should -Be 1
    $r.Additions[0].Architecture | Should -BeExactly '64'
    $r.Additions[0].Channel | Should -BeExactly MonthlyEnterprise
    $r.Additions[0].Version | Should -BeExactly '16.0.12345.12345'
    $r.Additions[0].Products[0].Id | Should -BeExactly O365ProPlusRetail
    $r.Additions[0].Products[0].Languages[0].Id | Should -BeExactly en-gb
    $r.ReviewItems | Should -Contain ExistingInstallationCompatibilityNotVerified
    $r.ReviewItems | Should -Not -Contain DeploymentVersionNotPinned
    $r.ReadyForMutation | Should -BeFalse
    $r.RecoverySupported | Should -BeFalse
    $r.ActivationStatus | Should -BeExactly NotObserved
    [Convert]::ToBase64String($bytes) | Should -BeExactly $before
  }
  It 'binds review to the exact input bytes including comments' {
    $a=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $BasicXml)
    $b=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes ('<!-- preserved -->'+$BasicXml))
    $a.ConfigurationSha256 | Should -Match '^[a-f0-9]{64}$'
    $b.ConfigurationSha256 | Should -Not -Be $a.ConfigurationSha256
  }
  It 'does not silently supply architecture, channel or a deployment version' {
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes '<Configuration><Add><Product ID="O365ProPlusRetail"><Language ID="en-gb"/></Product></Add></Configuration>')
    $r.Additions[0].Architecture | Should -BeNullOrEmpty
    $r.Additions[0].Channel | Should -BeNullOrEmpty
    $r.Additions[0].Version | Should -BeNullOrEmpty
    $r.ReviewItems | Should -Contain ArchitectureNotExplicitlyResolved
    $r.ReviewItems | Should -Contain ChannelOutsideSelectedChoices
    $r.ReviewItems | Should -Contain DeploymentVersionNotPinned
  }
  It 'does not treat MatchInstalled as an immutable deployment pin' {
    $xml=$BasicXml.Replace('16.0.12345.12345','MatchInstalled')
    (Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)).ReviewItems | Should -Contain DeploymentVersionNotPinned
  }
  It 'retains both selected channels and explicit architecture without choosing compatibility' -ForEach @(
    @{Channel='Current';Architecture='32'},@{Channel='MonthlyEnterprise';Architecture='64'}
  ) {
    $xml=$BasicXml.Replace('MonthlyEnterprise',$Channel).Replace('OfficeClientEdition="64"',('OfficeClientEdition="'+$Architecture+'"'))
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.ReviewItems | Should -Not -Contain ChannelOutsideSelectedChoices
    $r.Additions[0].Architecture | Should -BeExactly $Architecture
    $r.ReadyForMutation | Should -BeFalse
  }
  It 'flags architecture migration and CDN fallback without authorizing them' {
    $xml=$BasicXml.Replace('<Add ','<Add MigrateArch="TRUE" AllowCdnFallback="True" ')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.ReviewItems | Should -Contain ArchitectureMigrationRequiresSeparateDecision
    $r.ReviewItems | Should -Contain CdnFallbackRequestedOrUnrecognized
  }
  It 'does not call explicit false migration or fallback requests true' {
    $xml=$BasicXml.Replace('<Add ','<Add MigrateArch="FALSE" AllowCdnFallback="false" ')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.ReviewItems | Should -Not -Contain ArchitectureMigrationRequiresSeparateDecision
    $r.ReviewItems | Should -Not -Contain CdnFallbackRequestedOrUnrecognized
  }
  It 'preserves ordered language intent and reports unsupported Visio UK English' {
    $xml='<Configuration><Add><Product ID="VisioProRetail"><Language ID="en-gb"/><Language ID="da-dk"/><Language ID="MatchOS"/></Product><Product ID="ProofingTools"><Language ID="da-dk"/><Language ID="en-us"/><Language ID="en-gb"/></Product></Add></Configuration>'
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    ($r.Additions[0].Products[0].Languages.Id -join ',') | Should -BeExactly 'en-gb,da-dk,MatchOS'
    ($r.Additions[0].Products[1].Languages.Id -join ',') | Should -BeExactly 'da-dk,en-us,en-gb'
    $r.ReviewItems | Should -Contain VisioEnglishUkUnsupported
    $r.ReviewItems | Should -Contain MatchOsFallbackUnspecified
    $r.ReviewItems | Should -Contain DynamicLanguageResolutionRequired
  }
  It 'retains a supplied fallback and target without inventing their resolution' {
    $xml=$BasicXml.Replace('<Language ID="en-gb"/>','<Language ID="MatchOS" Fallback="da-dk"/><Language ID="MatchInstalled" TargetProduct="All"/>')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.Additions[0].Products[0].Languages[0].Fallback | Should -BeExactly da-dk
    $r.Additions[0].Products[0].Languages[1].TargetProduct | Should -BeExactly All
    $r.ReviewItems | Should -Not -Contain MatchOsFallbackUnspecified
    $r.ReviewItems | Should -Contain DynamicLanguageResolutionRequired
  }
  It 'reports application exclusions separately' {
    $xml=$BasicXml.Replace('</Product>','<ExcludeApp ID="Teams"/><ExcludeApp ID="OneDrive"/></Product>')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    ($r.Additions[0].Products[0].ExcludedApps -join ',') | Should -BeExactly 'Teams,OneDrive'
    $r.ReviewItems | Should -Contain ApplicationExclusionsRequireReview
  }
  It 'reports removal, settings, updates, terms and activation as independent requests' {
    $extra='<Remove All="TRUE"/><RemoveMSI/><AppSettings><User Key="private-path" Value="private-data"/></AppSettings><Updates Enabled="TRUE" Channel="Current" UpdatePath="private-server" Deadline="private-date"/><Display Level="None" AcceptEULA="TRUE"/><Property Name="AUTOACTIVATE" Value="1"/><Property Name="SharedComputerLicensing" Value="1"/>'
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $BasicXml.Replace('</Configuration>',$extra+'</Configuration>'))
    $r.RemoveElements | Should -Be 1
    $r.Removals[0].All | Should -BeExactly TRUE
    $r.RemoveMsiElements | Should -Be 1
    $r.AppSettingsElements | Should -Be 1
    foreach($issue in @('ProductRemovalRequiresSeparateDecision','MsiRemovalRequiresSeparateDecision','ApplicationSettingsRequireSeparateReview','UpdateMaintenanceRequiresSeparateReview','PublisherTermsAcceptanceRequestedOrUnrecognized','AutomaticActivationConfigurationRequiresReview','SpecializedActivationRequiresSeparateDecision')){$r.ReviewItems | Should -Contain $issue}
    ($r|ConvertTo-Json -Depth 12) | Should -Not -Match 'private-path|private-data|private-server|private-date'
  }
  It 'omits product keys, secret property values and source paths' {
    $xml=$BasicXml.Replace('<Add ','<Add SourcePath="private-source" DownloadPath="private-download" ').Replace('ID="O365ProPlusRetail"','ID="O365ProPlusRetail" PIDKEY="FAKE-SECRET-KEY"').Replace('</Configuration>','<Property Name="TenantAssociationKey" Value="FAKE-TENANT-SECRET"/><!-- FAKE-COMMENT-SECRET --></Configuration>')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.SensitiveConfigurationPresent | Should -BeTrue
    $r.Additions[0].Products[0].ProductKeyPresent | Should -BeTrue
    $r.Properties[0].Value | Should -BeNullOrEmpty
    $r.Properties[0].ValueOmitted | Should -BeTrue
    ($r|ConvertTo-Json -Depth 12) | Should -Not -Match 'FAKE-SECRET-KEY|FAKE-TENANT-SECRET|FAKE-COMMENT-SECRET|private-source|private-download'
  }
  It 'reports exact removal selections and MSI exclusions without executing them' {
    $xml='<Configuration><Remove All="FALSE"><Product ID="VisioProRetail"><Language ID="da-dk"/></Product></Remove><RemoveMSI><IgnoreProduct ID="VisPro"/><IgnoreProduct ID="PrjPro"/></RemoveMSI></Configuration>'
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.Removals[0].All | Should -BeExactly FALSE
    $r.Removals[0].Products[0].Id | Should -BeExactly VisioProRetail
    $r.Removals[0].Products[0].LanguageIds | Should -Contain da-dk
    ($r.MsiRemovalExclusions[0].IgnoreProductIds -join ',') | Should -BeExactly 'VisPro,PrjPro'
    $r.ReadyForMutation | Should -BeFalse
  }
  It 'does not infer a removal target from an omitted All attribute' {
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes '<Configuration><Remove/></Configuration>')
    $r.Removals[0].All | Should -BeNullOrEmpty
    $r.Removals[0].Products.Count | Should -Be 0
    $r.ReviewItems | Should -Contain ProductRemovalRequiresSeparateDecision
  }
  It 'does not equate parse success with bundled-app or language acceptance' {
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $BasicXml)
    $r.ReviewItems | Should -Contain BundledApplicationsAndLanguageSupportNotFullyVerified
  }
  It 'detects the legacy misspelled property without silently repairing it' {
    $xml=$BasicXml.Replace('</Configuration>','<Property Name="FORCEAPPSSHUTDOWN" Value="TRUE"/></Configuration>')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.Properties[0].Name | Should -BeExactly FORCEAPPSSHUTDOWN
    $r.Properties[0].Value | Should -BeNullOrEmpty
    $r.UnreviewedSyntax | Should -Contain 'Configuration/Property/FORCEAPPSSHUTDOWN'
    $r.ReviewItems | Should -Contain UnreviewedProperty
    $r.ReviewItems | Should -Not -Contain ForcedApplicationShutdownRequiresSeparateDecision
  }
  It 'flags the actual forced-close property for <Value>' -ForEach @(@{Value='TRUE'},@{Value='unknown'}) {
    $xml=$BasicXml.Replace('</Configuration>',('<Property Name="FORCEAPPSHUTDOWN" Value="'+$Value+'"/></Configuration>'))
    (Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)).ReviewItems | Should -Contain ForcedApplicationShutdownRequiresSeparateDecision
  }
  It 'keeps explicit false forced-close behavior distinct' {
    $xml=$BasicXml.Replace('</Configuration>','<Property Name="FORCEAPPSHUTDOWN" Value="FALSE"/></Configuration>')
    (Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)).ReviewItems | Should -Not -Contain ForcedApplicationShutdownRequiresSeparateDecision
  }
  It 'does not treat unknown syntax as reviewed or expose attribute data' {
    $xml=$BasicXml.Replace('<Add ','<Add FutureFlag="private-unknown-value" ').Replace('</Configuration>','<FutureAction Password="private-password">private-text</FutureAction></Configuration>')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.ReviewItems | Should -Contain UnreviewedXmlSyntax
    $r.ReviewItems | Should -Contain UnreviewedTextContent
    $r.SensitiveConfigurationPresent | Should -BeTrue
    ($r|ConvertTo-Json -Depth 12) | Should -Not -Match 'private-unknown-value|private-password|private-text'
  }
  It 'flags repeated top-level elements while retaining both declarations' {
    $xml=$BasicXml.Replace('</Configuration>','<Add Channel="Current"/></Configuration>')
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.Additions.Count | Should -Be 2
    $r.ReviewItems | Should -Contain RepeatedTopLevelElement
  }
  It 'reports missing product and language IDs without choosing replacements' {
    $xml='<Configuration><Add><Product><Language/></Product></Add></Configuration>'
    $r=Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)
    $r.ReviewItems | Should -Contain MissingProductIdentity
    $r.ReviewItems | Should -Contain MissingLanguageIdentity
  }
  It 'reads the actual two historical XML blocks as text and exposes their unresolved actions' {
    $legacy=Get-Content -LiteralPath (Join-Path $Root 'legacy/v2/lib-windows.psm1') -Raw
    $matches=[regex]::Matches($legacy,'(?s)<Configuration>.*?</Configuration>')
    $matches.Count | Should -Be 2
    $reviews=@(foreach($match in $matches){Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $match.Value)})
    foreach($r in $reviews){
      $r.RemoveMsiElements | Should -Be 1
      $r.ReviewItems | Should -Contain DeploymentVersionNotPinned
      $r.ReviewItems | Should -Contain MatchOsFallbackUnspecified
      $r.ReviewItems | Should -Contain PublisherTermsAcceptanceRequestedOrUnrecognized
      $r.UnreviewedSyntax | Should -Contain 'Configuration/Property/FORCEAPPSSHUTDOWN'
      $r.ReadyForMutation | Should -BeFalse
    }
    $reviews[0].AppSettingsElements | Should -Be 1
    $reviews[1].ReviewItems | Should -Contain VisioEnglishUkUnsupported
  }
}

Describe 'Office XML parser boundaries' {
  It 'refuses <Case> without leaking source data' -ForEach @(
    @{Case='external DTD';Xml='<!DOCTYPE Configuration SYSTEM "file:///private-secret.xml"><Configuration/>'},
    @{Case='internal entity';Xml='<!DOCTYPE Configuration [<!ENTITY x "private-secret">]><Configuration>&x;</Configuration>'},
    @{Case='processing instruction';Xml='<?private-secret value?><Configuration/>'},
    @{Case='namespace';Xml='<Configuration xmlns="urn:private-secret"/>'},
    @{Case='namespace attribute';Xml='<Configuration xmlns:x="urn:private-secret" x:flag="1"/>'},
    @{Case='wrong root';Xml='<private-secret/>'},
    @{Case='broken XML';Xml='<Configuration private-secret>'},
    @{Case='duplicate attribute';Xml='<Configuration X="private-secret" X="private-secret"/>'}
  ) {
    try {Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $Xml);throw 'Expected rejection'}
    catch {$_.Exception.Message | Should -BeExactly 'Office XML is malformed, exceeds inspection limits, or uses prohibited XML features.'}
  }
  It 'rejects excessive <Bound>' -ForEach @(@{Bound='Bytes'},@{Bound='Depth'},@{Bound='Nodes'},@{Bound='Attributes'},@{Bound='AttributeValue'}) {
    $bytes=switch($Bound){
      Bytes {[byte[]]::new(1048577)}
      Depth {ConvertTo-OfficeTestBytes ('<Configuration>'+('<X>'*25)+('</X>'*25)+'</Configuration>')}
      Nodes {ConvertTo-OfficeTestBytes ('<Configuration>'+('<X/>'*4097)+'</Configuration>')}
      Attributes {ConvertTo-OfficeTestBytes ('<Configuration '+((1..33|ForEach-Object {'A'+$_+'="x"'}) -join ' ')+'/>')}
      AttributeValue {ConvertTo-OfficeTestBytes ('<Configuration X="'+('x'*4097)+'"/>')}
    }
    {Get-RideOfficeConfigurationReview -Bytes $bytes} | Should -Throw
  }
  It 'rejects empty bytes' {{Get-RideOfficeConfigurationReview -Bytes ([byte[]]@())} | Should -Throw}
  It 'refuses a review token containing a path without echoing it' {
    $xml=$BasicXml.Replace('O365ProPlusRetail','C:\private-secret')
    {Get-RideOfficeConfigurationReview -Bytes (ConvertTo-OfficeTestBytes $xml)} | Should -Throw 'Office XML contains an invalid or excessive review token.'
  }
  It 'supports XML-declared UTF-16 bytes without modifying them' {
    $text='<?xml version="1.0" encoding="utf-16"?>'+$BasicXml
    $bytes=[Text.Encoding]::Unicode.GetPreamble()+[Text.Encoding]::Unicode.GetBytes($text)
    (Get-RideOfficeConfigurationReview -Bytes $bytes).Additions[0].Products[0].Id | Should -BeExactly O365ProPlusRetail
  }
}
