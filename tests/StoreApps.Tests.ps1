<#
.SYNOPSIS
  Validate Store registration guards, intent records and partial group behavior.
.NOTES
  Windows PowerShell 5.1/PowerShell 7; Pester 5.7.1. All Appx/native calls mocked.
  Version: 0.2.0. Reviewed identity/removability guards; no workstation mutation.
#>
BeforeAll {
  $script:Root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $script:Root 'modules/RIDE.StoreApps.psm1') -Force
  Import-Module (Join-Path $script:Root 'modules/RIDE.CatalogData.psm1') -Force
  $script:Catalog=Import-RideCatalogData (Join-Path $script:Root 'catalog/operations.psd1')
  $script:Sid='S-1-5-21-1-2-3-1001'
  function New-StoreTestPackage($Operation) {
    [pscustomobject]@{Name=$Operation.AppxName;PackageFamilyName=$Operation.PackageFamilyName;PackageFullName=($Operation.AppxName+'_1.0.0.0_x64__'+($Operation.PackageFamilyName -split '_')[-1]);Version='1.0.0.0';Publisher='CN=Fixture';Status='Ok';InstallLocation=('C:\Program Files\WindowsApps\'+$Operation.AppxName+'_1.0.0.0_x64__fixture');Dependencies=@();IsFramework=$false;IsResourcePackage=$false;IsBundle=$false;IsPartOfSystem=$false;NonRemovable=$false;IsStub=$false}
  }
}
Describe 'Store catalog and discovery boundaries' {
  It 'declares the consumer batch independently from packages/settings and default profiles' {
    $apps=@($script:Catalog.Operations|Where-Object MigrationBatch -eq StoreConsumerApps20261014)
    $apps.Count|Should -Be 4
    @($apps|Where-Object {$_.SupportedTargets.Count -or -not $_.PendingAcceptance -or $_.Scope -ne 'User' -or $_.RequiresAdmin -or $_.Rollback -ne 'BestEffort'}).Count|Should -Be 0
    $g=$script:Catalog.Groups|Where-Object Id -eq solution.store-consumer-apps
    $g.Members|Should -Be @('app.clipchamp','app.news','app.weather','app.solitaire')
    foreach($p in Get-ChildItem (Join-Path $script:Root 'profiles') -Filter '*.psd1'){
      @((Import-PowerShellDataFile $p.FullName).Operations|Where-Object {$_.Id -in $apps.Id -or $_.Id -eq $g.Id}).Count|Should -Be 0
    }
  }
  It 'keeps all approved groups exact, pending and outside shared framework removal' {
    $apps=@($script:Catalog.Operations|Where-Object Kind -eq StoreApp)
    $groups=@($script:Catalog.Groups|Where-Object Workflow -eq StoreApps)
    $apps.Count|Should -Be 22;$groups.Count|Should -Be 5
    @($groups.Members|Sort-Object -Unique).Count|Should -Be 22
    @($apps|Where-Object {$_.SupportedTargets.Count -or -not $_.PendingAcceptance -or $_.RequiresAdmin -or $_.Scope -ne 'User' -or -not $_.RequireKnownProtectionFlags -or $_.ProtectionRule -cne 'ReviewedIdentityRemovabilityV1'}).Count|Should -Be 0
    @($apps|Where-Object {$_.AppxName -match 'VCLibs|\.NET.Native|UI.Xaml|WindowsAppRuntime|XboxGameCallableUI'}).Count|Should -Be 0
    ($apps|Where-Object AppxName -eq Microsoft.XboxGamingOverlay).PolicySelectionId|Should -BeNullOrEmpty
    foreach($g in $groups){@($g.Members|Where-Object {$_ -notin $apps.Id}).Count|Should -Be 0}
  }
  It 'keeps the documented reviewed list aligned with catalog identities and the policy crosswalk' {
    $apps=@($script:Catalog.Operations|Where-Object Kind -eq StoreApp)
    $review=Import-PowerShellDataFile (Join-Path $script:Root 'catalog/store-app-review.psd1')
    $guide=Get-Content (Join-Path $script:Root 'docs/store-app-groups.md') -Raw
    $section=[regex]::Match($guide,'(?s)## Exact identities to implement(?<body>.*?)(?:\r?\n## |\z)').Groups['body'].Value
    $documentedNames=@([regex]::Matches($section,'(?m)^\| [^|]+ \| [^|]+ \| ([^|]+) \|$')|ForEach-Object {$_.Groups[1].Value.Trim()}|Where-Object {$_ -ne 'Package name' -and $_ -notmatch '^[-| ]+$'})
    $catalogNames=@($apps.AppxName|Sort-Object)
    $documentedNames|Should -HaveCount 22
    @(Compare-Object $catalogNames @($documentedNames|Sort-Object)).Count|Should -Be 0

    $policyMapped=@($apps|Where-Object PolicySelectionId)
    $policyMapped|Should -HaveCount 21
    foreach($operation in $policyMapped){
      $definition=@($review.Apps|Where-Object StaticPolicyId -ceq $operation.PolicySelectionId)
      $definition|Should -HaveCount 1
      $definition[0].Name|Should -BeExactly $operation.AppxName
      $definition[0].PolicyFamilyName|Should -BeExactly $operation.PackageFamilyName
    }

    ($apps|Where-Object AppxName -eq 'Microsoft.XboxGamingOverlay').PolicySelectionId|Should -BeNullOrEmpty
    $unselectedReviewNames=@('MSTeams','Microsoft.Copilot','Microsoft.MicrosoftOfficeHub','Microsoft.WindowsFeedbackHub')
    @(Compare-Object @($review.Apps|Where-Object Name -notin $catalogNames|ForEach-Object Name|Sort-Object) @($unselectedReviewNames|Sort-Object)).Count|Should -Be 0
  }
  It 'discovers Store apps without invoking any Appx handler' {
    Import-Module (Join-Path $script:Root 'modules/RIDE.Discovery.psm1') -Force
    $rows=@(Get-RideCatalogRows $script:Catalog)
    @(Select-RideCatalogView -Catalog $script:Catalog -Rows $rows -View store-apps).Count|Should -Be @($script:Catalog.Operations|Where-Object Kind -eq StoreApp).Count
    @((Select-RideCatalogView -Catalog $script:Catalog -Rows $rows -View settings)|Where-Object Kind -eq StoreApp).Count|Should -Be 0
  }
  It 'completes declared group and app IDs through the read-only tool' {
    $tool=Join-Path $script:Root 'tools/Invoke-RideStoreApps.ps1'
    $text="& '$tool' Plan solution.store-"
    $result=[Management.Automation.CommandCompletion]::CompleteInput($text,$text.Length,$null)
    $result.CompletionMatches.CompletionText|Should -Contain 'solution.store-consumer-apps'
  }
  It 'refuses implicit profile routing in the existing engine' {
    Import-Module (Join-Path $script:Root 'modules/RIDE.Engine.psm1') -Force
    $m=Get-Module RIDE.Engine
    {& $m {Expand-RideProfileOperations @{Operations=@(@{Id='solution.store-consumer-apps';State='Absent'})}}}|Should -Throw '*explicit Store group*'
  }
}
Describe 'Guarded Store lifecycle' {
  BeforeEach {
    Import-Module (Join-Path $script:Root 'modules/RIDE.StoreApps.psm1') -Force
    $script:operations=@($script:Catalog.Operations|Where-Object MigrationBatch -eq StoreConsumerApps20261014|ForEach-Object {$c=$_.Clone();$c.SupportedTargets=@('Windows 11');$c.PendingAcceptance=$false;$c})
    $script:live=@{};$script:original=@{}
    foreach($o in $script:operations){$p=New-StoreTestPackage $o;$script:live[$o.Id]=$p;$script:original[$o.Id]=$p}
    $script:stateRoot=Join-Path $TestDrive ('StoreApps-'+[guid]::NewGuid().ToString('N'))
    Mock Get-RideStoreStateRoot -ModuleName RIDE.StoreApps {$script:stateRoot}
    Mock Get-RideStoreSelection -ModuleName RIDE.StoreApps {param($Id) if($Id -eq 'solution.store-consumer-apps'){$script:operations}else{$script:operations|Where-Object Id -eq $Id}}
    Mock Get-RideStoreIdentity -ModuleName RIDE.StoreApps {[pscustomobject]@{Sid=$script:Sid;Elevated=$false}}
    Mock Get-RideStoreDesktop -ModuleName RIDE.StoreApps {[pscustomobject]@{CurrentSid=$script:Sid;TargetSid=$script:Sid;CurrentElevated=$false;ShellElevated=$false;SessionId=2;CurrentSessionId=2;ShellProcessId=200}}
    Mock Get-RideStoreTarget -ModuleName RIDE.StoreApps {'Windows 11'}
    Mock Get-RideStorePolicyGuard -ModuleName RIDE.StoreApps {$null}
    Mock Get-RideStoreNativePackages -ModuleName RIDE.StoreApps {param($Operation) if($script:live.ContainsKey($Operation.Id)){$script:live[$Operation.Id]}}
    Mock Get-RideStoreRuntimePackage -ModuleName RIDE.StoreApps {param($Sid,$FullName) $p=$script:live.Values|Where-Object PackageFullName -ceq $FullName|Select-Object -First 1;[pscustomobject]@{Name=$p.Name;Family=$p.PackageFamilyName;FullName=$p.PackageFullName;IsFramework=$p.IsFramework;IsResourcePackage=$p.IsResourcePackage;IsBundle=$p.IsBundle;IsStub=$p.IsStub;SignatureKind='Store'}}
    Mock Get-RideStoreRegisteredPackages -ModuleName RIDE.StoreApps {@()}
    Mock Get-RideStoreManifestProof -ModuleName RIDE.StoreApps {param($Package) [pscustomobject]@{Path=(Join-Path $Package.InstallLocation 'AppxManifest.xml');SHA256=('A'*64);Name=$Package.Name;Publisher=$Package.Publisher;Version=$Package.Version;Dependencies=@()}}
    Mock Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps {param($FullName) foreach($key in @($script:live.Keys)){if($script:live[$key].PackageFullName -ceq $FullName){[void]$script:live.Remove($key)}}}
    Mock Invoke-RideStoreNativeRegister -ModuleName RIDE.StoreApps {param($Path) foreach($key in $script:original.Keys){if((Join-Path $script:original[$key].InstallLocation 'AppxManifest.xml') -ceq $Path){$script:live[$key]=$script:original[$key]}}}
  }
  It 'checks intended SID before native inspection or state creation' {
    {Get-RideStoreAppPlan app.news Uninstall S-1-5-21-1-2-3-1002}|Should -Throw '*SID mismatch*'
    Should -Invoke Get-RideStoreNativePackages -ModuleName RIDE.StoreApps -Exactly 0
    Test-Path $script:stateRoot|Should -BeFalse
  }
  It 'keeps target candidates blocked before any mutation' {
    Mock Get-RideStoreTarget -ModuleName RIDE.StoreApps {'Windows Server 2025'}
    $r=@(Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false)
    $r[0].Status|Should -Be Refused;$r[0].Error|Should -Match 'Target acceptance'
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
  }
  It 'refuses another administrator or unavailable desktop without a fallback' {
    Mock Get-RideStoreDesktop -ModuleName RIDE.StoreApps {throw 'No desktop'}
    $r=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $r.Status|Should -Be Refused;$r.Error|Should -Match 'desktop identity unavailable'
    Test-Path $script:stateRoot|Should -BeFalse
  }
  It 'preserves unknown system flags for a reviewed identity with complete removability and type evidence' {
    $script:live['app.news'].IsPartOfSystem=$null
    $state=Get-RideStoreAppState ($script:operations|Where-Object Id -eq app.news)
    $state.Packages[0].SignatureKind|Should -Be Store
    $state.Packages[0].IsPartOfSystem|Should -BeNullOrEmpty
    $state.Packages[0].SystemProtectionObservation|Should -Be Unknown
    $r=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $r.Status|Should -Be Completed
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 1
    $record=Get-Content -LiteralPath (Join-Path $script:stateRoot "$($r.RunId)/manifest.json") -Raw|ConvertFrom-Json
    $record.Items[0].Before.Packages[0].IsPartOfSystem|Should -BeNullOrEmpty
    $record.Items[0].Before.Packages[0].SystemProtectionObservation|Should -Be Unknown
  }
  It 'refuses missing review metadata even with otherwise complete evidence' {
    $script:operations[0].Remove('ProtectionRule')
    $r=Invoke-RideStoreAppAction $script:operations[0].Id Uninstall $script:Sid -Confirm:$false
    $r.Status|Should -Be Refused;$r.Error|Should -Match 'Reviewed identity/removability rule required'
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
    Test-Path $script:stateRoot|Should -BeFalse
  }
  It 'refuses every incomplete removability or package-type flag with an unknown system flag' {
    foreach($flag in @('NonRemovable','IsFramework','IsResourcePackage','IsBundle','IsStub')){
      $p=$script:live['app.news'];$p.IsPartOfSystem=$null;$p.$flag=$null
      (Get-RideStoreAppPlan app.news Uninstall $script:Sid).Refusals|Should -Contain 'Protection/type flags incomplete'
      $p.$flag=$false
    }
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
    Test-Path $script:stateRoot|Should -BeFalse
  }
  It 'refuses a known system flag even for a reviewed removable identity' {
    $script:live['app.news'].IsPartOfSystem=$true
    (Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false).Status|Should -Be Refused
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
    Test-Path $script:stateRoot|Should -BeFalse
  }
  It 'refuses runtime type conflicts even when all native provider flags are populated' {
    Mock Get-RideStoreRuntimePackage -ModuleName RIDE.StoreApps {param($Sid,$FullName) $p=$script:live['app.news'];[pscustomobject]@{Name=$p.Name;Family=$p.PackageFamilyName;FullName=$p.PackageFullName;IsFramework=$true;IsResourcePackage=$false;IsBundle=$false;IsStub=$false;SignatureKind='Store'}}
    $r=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $r.Status|Should -Be Refused;$r.Error|Should -Match 'Runtime package identity/type evidence unavailable or conflicting'
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
    Test-Path $script:stateRoot|Should -BeFalse
  }
  It 'refuses stub packages instead of starting an acquisition route' {
    $script:live['app.news'].IsStub=$true
    (Get-RideStoreAppPlan app.news Uninstall $script:Sid).Refusals|Should -Contain 'Stub package source requires separate acquisition review'
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
  }
  It 'refuses framework/protected registrations and unexpected publisher families' {
    $script:live['app.news'].NonRemovable=$true
    (Get-RideStoreAppPlan app.news Uninstall $script:Sid).Refusals|Should -Contain 'Protected/system/framework registration'
    $script:live['app.news'].NonRemovable=$false;$script:live['app.news'].PackageFamilyName='Microsoft.BingNews_aaaaaaaaaaaaa'
    (Get-RideStoreAppPlan app.news Uninstall $script:Sid).Refusals|Should -Contain 'Unexpected publisher family or app identity'
  }
  It 'refuses unreadable/active policy rather than altering policy' {
    Mock Get-RideStorePolicyGuard -ModuleName RIDE.StoreApps {'Active device removal policy'}
    (Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false).Status|Should -Be Refused
    Mock Get-RideStorePolicyGuard -ModuleName RIDE.StoreApps {throw 'Denied'}
    (Get-RideStoreAppPlan app.news Uninstall $script:Sid).Refusals|Should -Contain 'Device policy source unavailable; no app change allowed'
  }
  It 'refuses removal of an app referenced by another current registration' {
    Mock Get-RideStoreRegisteredPackages -ModuleName RIDE.StoreApps {@([pscustomobject]@{Name='Fixture.Consumer';Dependencies=@([pscustomobject]@{PackageFullName=$script:live['app.news'].PackageFullName})})}
    (Get-RideStoreAppPlan app.news Uninstall $script:Sid).Refusals|Should -Contain 'Other registered apps depend on this app; review consumers separately'
  }
  It 'preview invokes no mutation and creates no state directory' {
    $r=@(Invoke-RideStoreAppAction solution.store-consumer-apps Uninstall $script:Sid -WhatIf)
    $r.OperationId|Should -Be @('app.solitaire','app.weather','app.news','app.clipchamp')
    @($r|Where-Object Status -ne NotApplied).Count|Should -Be 0
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
    Test-Path $script:stateRoot|Should -BeFalse
  }
  It 'stores intent before mutation and captures partial group completion' {
    Mock Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps {
      param($FullName)
      $record=Get-ChildItem -LiteralPath $script:stateRoot -Filter manifest.json -Recurse|ForEach-Object {Get-Content $_.FullName -Raw|ConvertFrom-Json}
      @($record.Items|Where-Object Status -eq Intent).Count|Should -Be 1
      foreach($key in @($script:live.Keys)){if($script:live[$key].PackageFullName -ceq $FullName){if($key -eq 'app.weather'){throw 'Controlled Appx failure'};[void]$script:live.Remove($key)}}
    }
    $r=@(Invoke-RideStoreAppAction solution.store-consumer-apps Uninstall $script:Sid -Confirm:$false)
    @($r|Where-Object Status -eq Completed).Count|Should -Be 3
    @($r|Where-Object Status -eq Failed).Count|Should -Be 1
    @($r.RunId|Sort-Object -Unique).Count|Should -Be 1
    $saved=Get-Content (Join-Path $script:stateRoot ($r[0].RunId+'/manifest.json')) -Raw|ConvertFrom-Json
    $saved.Status|Should -Be Partial;$saved.Items.Count|Should -Be 4;$saved.ExactRecovery|Should -BeFalse
  }
  It 'repeat removal skips absent registrations and creates no second record' {
    $first=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $first.Status|Should -Be Completed
    (Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false).Status|Should -Be AlreadyMatching
    @(Get-ChildItem $script:stateRoot -Directory).Count|Should -Be 1
  }
  It 're-registers only the owned retained payload and reports best effort' {
    $removed=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $restored=Invoke-RideStoreAppAction app.news Reinstall $script:Sid -RemovalRunId $removed.RunId -Confirm:$false
    $restored.Status|Should -Be Completed;$restored.ExactRecovery|Should -BeFalse
    Should -Invoke Invoke-RideStoreNativeRegister -ModuleName RIDE.StoreApps -Exactly 1
    (Invoke-RideStoreAppAction app.news Reinstall $script:Sid -RemovalRunId $removed.RunId -Confirm:$false).Status|Should -Be AlreadyMatching
  }
  It 'allows explicit recovery of an owned interrupted removal intent' {
    $r=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $path=Join-Path $script:stateRoot ($r.RunId+'/manifest.json');$data=Get-Content $path -Raw|ConvertFrom-Json
    $data.Items[0].Status='Intent';$data.Status='InProgress';$data|ConvertTo-Json -Depth 20|Set-Content $path
    (Invoke-RideStoreAppAction app.news Reinstall $script:Sid -RemovalRunId $r.RunId -Confirm:$false).Status|Should -Be Completed
  }
  It 'refuses missing/changed retained payload without download fallback' {
    $r=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    Mock Get-RideStoreManifestProof -ModuleName RIDE.StoreApps {throw 'Missing'}
    $p=Get-RideStoreAppPlan app.news Reinstall $script:Sid -RemovalRunId $r.RunId
    $p.Refusals|Should -Contain 'Source unavailable or changed; acquisition remains paused'
    $p.SourceError|Should -BeExactly 'Missing'
    (Invoke-RideStoreAppAction app.news Reinstall $script:Sid -RemovalRunId $r.RunId -Confirm:$false).Status|Should -Be Refused
    Should -Invoke Invoke-RideStoreNativeRegister -ModuleName RIDE.StoreApps -Exactly 0
  }
  It 'keeps real dependency projection active during reinstall preview without extra records' {
    Mock Get-RideStoreManifestProof -ModuleName RIDE.StoreApps {param($Package) [pscustomobject]@{Path=(Join-Path $Package.InstallLocation 'AppxManifest.xml');SHA256=('A'*64);Name=$Package.Name;Publisher=$Package.Publisher;Version=$Package.Version;Dependencies=@('Fixture.Dependency_1.0.0.0_x64__fixture')}}
    Mock Get-RideStoreRegisteredPackages -ModuleName RIDE.StoreApps {@([pscustomobject]@{Name='Fixture.Dependency';PackageFullName='Fixture.Dependency_1.0.0.0_x64__fixture';Dependencies=@()})}
    $removed=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $preview=Invoke-RideStoreAppAction app.news Reinstall $script:Sid -RemovalRunId $removed.RunId -WhatIf
    $preview.Status|Should -BeExactly 'NotApplied'
    $preview.RecordCreated|Should -BeFalse
    @(Get-ChildItem $script:stateRoot -Directory).Count|Should -Be 1
    Should -Invoke Invoke-RideStoreNativeRegister -ModuleName RIDE.StoreApps -Exactly 0
    Mock Get-RideStoreRegisteredPackages -ModuleName RIDE.StoreApps {@()}
    $refused=Invoke-RideStoreAppAction app.news Reinstall $script:Sid -RemovalRunId $removed.RunId -WhatIf
    $refused.Status|Should -BeExactly 'Refused'
    Should -Invoke Invoke-RideStoreNativeRegister -ModuleName RIDE.StoreApps -Exactly 0
  }
  It 'refuses recovery records owned by another SID' {
    $r=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $path=Join-Path $script:stateRoot ($r.RunId+'/manifest.json');$data=Get-Content $path -Raw|ConvertFrom-Json
    $data.UserSid='S-1-5-21-1-2-3-1002';$data|ConvertTo-Json -Depth 20|Set-Content $path
    {Get-RideStoreAppPlan app.news Reinstall $script:Sid -RemovalRunId $r.RunId}|Should -Throw '*different user owner*'
  }
  It 'rechecks policy after confirmation and before saving intent' {
    Mock Get-RideStorePolicyGuard -ModuleName RIDE.StoreApps {
      $script:policyCalls++;if($script:policyCalls -gt 1){'Policy changed'}else{$null}
    }
    $script:policyCalls=0
    $r=Invoke-RideStoreAppAction app.news Uninstall $script:Sid -Confirm:$false
    $r.Status|Should -Be Failed
    Should -Invoke Invoke-RideStoreNativeRemove -ModuleName RIDE.StoreApps -Exactly 0
    Test-Path $script:stateRoot|Should -BeFalse
  }
}
Describe 'Retained manifest proof and state path safety' {
  BeforeEach {Import-Module (Join-Path $script:Root 'modules/RIDE.StoreApps.psm1') -Force}
  It 'refuses state/source paths outside their literal root' {
    $m=Get-Module RIDE.StoreApps
    {& $m {Assert-RideStorePath -Path 'C:\outside\manifest.json' -Root 'C:\owned'}}|Should -Throw '*escapes*'
  }
  It 'parses identity with DTD disabled and hashes exact manifest bytes' {
    $script:proofRoot=Join-Path $TestDrive 'payload';$null=New-Item -ItemType Directory -Path $script:proofRoot
    $manifest=Join-Path $script:proofRoot 'AppxManifest.xml'
    [IO.File]::WriteAllText($manifest,'<Package><Identity Name="Microsoft.BingNews" Publisher="CN=Fixture" Version="1.0.0.0" /></Package>')
    Mock Assert-RideStorePath -ModuleName RIDE.StoreApps {param($Path,$Root) $Path}
    $m=Get-Module RIDE.StoreApps
    $proof=& $m {param($directory) Get-RideStoreManifestProof ([pscustomobject]@{Name='Microsoft.BingNews';Publisher='CN=Fixture';Version='1.0.0.0';InstallLocation=$directory;Dependencies=@();IsStub=$false})} $script:proofRoot
    $proof.SHA256|Should -Be (Get-FileHash $manifest).Hash
    [IO.File]::WriteAllText($manifest,'<!DOCTYPE Package [<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">]><Package><Identity Name="Microsoft.BingNews" Publisher="CN=Fixture" Version="1.0.0.0" /></Package>')
    {& $m {param($directory) Get-RideStoreManifestProof ([pscustomobject]@{Name='Microsoft.BingNews';Publisher='CN=Fixture';Version='1.0.0.0';InstallLocation=$directory;Dependencies=@();IsStub=$false})} $script:proofRoot}|Should -Throw
  }
}
Describe 'Explicit Store desktop handoff' {
  BeforeEach {
    Import-Module (Join-Path $script:Root 'modules/RIDE.StoreApps.psm1') -Force
    Mock Get-RideStoreDesktop -ModuleName RIDE.StoreApps {[pscustomobject]@{TargetSid=$script:Sid;CurrentSid='S-1-5-21-1-2-3-1002';CurrentElevated=$true;ShellElevated=$false;SessionId=2;CurrentSessionId=2;ShellProcessId=200}}
    Mock Get-RideStoreHandoffSourceHash -ModuleName RIDE.StoreApps {('B'*64)}
    Mock Start-RideStoreShellProcess -ModuleName RIDE.StoreApps {}
    Mock Get-RideStoreNativePackages -ModuleName RIDE.StoreApps {throw 'Parent must not inspect apps'}
    Mock Read-RideStoreRemovalRun -ModuleName RIDE.StoreApps {throw 'Parent must not read another user record'}
  }
  It 'previews an alternate-admin launch without app queries, process launch or records' {
    $r=Start-RideStoreDesktopHandoff Plan solution.store-consumer-apps -ExpectedUserSid $script:Sid -WhatIf
    $r.Status|Should -Be NotLaunched;$r.CompletionVerified|Should -BeFalse
    Should -Invoke Start-RideStoreShellProcess -ModuleName RIDE.StoreApps -Exactly 0
    Should -Invoke Get-RideStoreNativePackages -ModuleName RIDE.StoreApps -Exactly 0
  }
  It 'launches only the validated desktop route and never reads target recovery in the parent' {
    $r=Start-RideStoreDesktopHandoff Reinstall app.news -ExpectedUserSid $script:Sid -RemovalRunId ('1'*32) -Confirm:$false
    $r.Status|Should -Be Launched;$r.CompletionVerified|Should -BeFalse
    Should -Invoke Start-RideStoreShellProcess -ModuleName RIDE.StoreApps -Exactly 1
    Should -Invoke Read-RideStoreRemovalRun -ModuleName RIDE.StoreApps -Exactly 0
  }
  It 'refuses another session or an elevated desktop shell before launch' {
    Mock Get-RideStoreDesktop -ModuleName RIDE.StoreApps {[pscustomobject]@{TargetSid=$script:Sid;ShellElevated=$false;SessionId=3;CurrentSessionId=2;ShellProcessId=200}}
    {Start-RideStoreDesktopHandoff Plan app.news -ExpectedUserSid $script:Sid -Confirm:$false}|Should -Throw '*current session*'
    Should -Invoke Start-RideStoreShellProcess -ModuleName RIDE.StoreApps -Exactly 0
  }
  It 'revalidates child source and ownership before app inspection' {
    Mock Get-RideStoreIdentity -ModuleName RIDE.StoreApps {[pscustomobject]@{Sid=$script:Sid;Elevated=$false}}
    Mock Get-RideStoreDesktop -ModuleName RIDE.StoreApps {[pscustomobject]@{TargetSid=$script:Sid;CurrentSid=$script:Sid;CurrentElevated=$false;ShellElevated=$false;SessionId=2;CurrentSessionId=2;ShellProcessId=200}}
    $request=[pscustomobject]@{SchemaVersion=1;Workflow='StoreDesktopHandoff';RequestId=('2'*32);Root=$script:Root;SourceHash=('C'*64);TargetSid=$script:Sid;SessionId=2;ShellProcessId=200;Command='Plan';Id='app.news';Action='Uninstall';RemovalRunId=$null}
    {Invoke-RideStoreDesktopRequest $request}|Should -Throw '*source changed*'
    Should -Invoke Get-RideStoreNativePackages -ModuleName RIDE.StoreApps -Exactly 0
    $request.SourceHash='B'*64;$request.TargetSid='S-1-5-21-1-2-3-1002'
    {Invoke-RideStoreDesktopRequest $request}|Should -Throw '*owner/session/shell changed*'
  }
}
