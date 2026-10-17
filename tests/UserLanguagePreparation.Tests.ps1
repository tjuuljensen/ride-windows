<#
.SYNOPSIS
  Verify order-only language preparation and conflict-aware recovery in memory.
.DESCRIPTION
  Uses supplied synthetic observations. No native account, language, keyboard,
  registry, file or network provider is invoked. Tests preserve unowned metadata.
.EXAMPLE
  Invoke-Pester .\tests\UserLanguagePreparation.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester results.
.NOTES
  Compatibility: Pester 5 on native Windows PowerShell 5.1 and PowerShell 7.
  Version: Repository test fixture; native writer/acceptance remains pending.
#>
BeforeAll {
  Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'modules/RIDE.UserLanguagePreparation.psm1') -Force
  function New-PriorityObservation {
    param([string[]]$Order=@('fr-FR','en-GB','da-DK'))
    $index=0
    [pscustomobject]@{
      SchemaVersion=1;Kind='UserLanguageObservation';Status='Captured'
      WindowsContext=[pscustomobject]@{ComputerName='TEST-VM';Build='26100';EditionId='Professional';UpdateBuildRevision=1;NativeProcess=$true;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;UserInteractive=$true}
      Languages=@(foreach($tag in $Order){[pscustomobject]@{Position=$index;LanguageTag=$tag;IdentityStatus='Identified';InputMethodTips=@('fixture-input');Handwriting=$false;Spellchecking=$true;Selected=$false};$index++})
      ReadyForMutation=$false;RecoverySupported=$false
    }
  }
}
Describe 'Existing user language priority preparation' {
  It 'moves the requested existing tag first while preserving all other relative order' {
    $observation=New-PriorityObservation;$before=$observation|ConvertTo-Json -Depth 8 -Compress
    $patch=New-RideUserLanguagePriorityPatch $observation 'EN-gb'
    ($patch.DesiredOrder -join ',') | Should -BeExactly 'en-GB,fr-FR,da-DK'
    ($patch.Snapshot.OriginalOrder -join ',') | Should -BeExactly 'fr-FR,en-GB,da-DK'
    $patch.ChangeRequired | Should -BeTrue
    $patch.Snapshot.OwnsOrder | Should -BeTrue
    $patch.MutationAuthorized | Should -BeFalse
    $patch.ReadyForMutation | Should -BeFalse
    ($observation|ConvertTo-Json -Depth 8 -Compress) | Should -BeExactly $before
    ($patch.Snapshot|ConvertTo-Json -Depth 8) | Should -Not -Match 'InputMethodTips|Handwriting|Spellchecking'
  }
  It 'keeps an already-first or sole language as an unowned no-op' {
    foreach($order in @(@('en-GB'),@('en-GB','da-DK'))){
      $patch=New-RideUserLanguagePriorityPatch (New-PriorityObservation $order) 'en-GB'
      $patch.ChangeRequired | Should -BeFalse
      $patch.Snapshot.OwnsOrder | Should -BeFalse
      $patch.DesiredOrder.Count | Should -Be $order.Count
    }
  }
  It 'never invents or installs an absent selected language' {
    {New-RideUserLanguagePriorityPatch (New-PriorityObservation) 'de-DE'} | Should -Throw '*existing observed*'
  }
  It 'rejects unavailable, empty, missing identity, duplicate and invalid-order inputs' {
    $observation=New-PriorityObservation;$observation.Status='Unavailable';$observation.Languages=$null
    {New-RideUserLanguagePriorityPatch $observation 'en-GB'} | Should -Throw '*captured*'
    {New-RideUserLanguagePriorityPatch (New-PriorityObservation @()) 'en-GB'} | Should -Throw '*nonempty*'
    $observation=New-PriorityObservation;$observation.Languages[0].LanguageTag=$null
    {New-RideUserLanguagePriorityPatch $observation 'en-GB'} | Should -Throw '*missing*'
    {New-RideUserLanguagePriorityPatch (New-PriorityObservation @('en-GB','EN-gb')) 'en-GB'} | Should -Throw '*duplicate*'
    $observation=New-PriorityObservation;$observation.Languages[0].Position=1
    {New-RideUserLanguagePriorityPatch $observation 'en-GB'} | Should -Throw '*order*'
  }
  It 'refuses invalid context field <Field>' -ForEach @(
    @{Field='UserInteractive';Value=$false},@{Field='NativeProcess';Value=$false},
    @{Field='SessionId';Value=0},@{Field='SessionId';Value=1.5},@{Field='UpdateBuildRevision';Value=$null},
    @{Field='UserSid';Value='someone'},@{Field='ComputerName';Value="bad`nname"}
  ) {
    $observation=New-PriorityObservation;$observation.WindowsContext.$Field=$Value
    {New-RideUserLanguagePriorityPatch $observation 'en-GB'} | Should -Throw
  }
  It 'completes identified supplied tags without live discovery' {
    $observation=New-PriorityObservation
    $attr=(Get-Command New-RideUserLanguagePriorityPatch).Parameters.LanguageTag.Attributes|Where-Object {$_ -is [Management.Automation.ArgumentCompleterAttribute]}
    $matches=@(& $attr.ScriptBlock '' '' 'EN' $null @{Inventory=$observation})
    $matches.Count | Should -Be 1
    $matches[0].CompletionText | Should -BeExactly "'en-GB'"
    @(& $attr.ScriptBlock '' '' 'de' $null @{Inventory=$observation}).Count | Should -Be 0
    @(& $attr.ScriptBlock '' '' '' $null @{}).Count | Should -Be 0
  }
}
Describe 'Language priority recovery preparation' {
  BeforeEach {$script:Patch=New-RideUserLanguagePriorityPatch (New-PriorityObservation) 'en-GB'}
  It 'restores order after JSON roundtrip without owning newer keyboard or handwriting edits' {
    $snapshot=$Patch.Snapshot|ConvertTo-Json -Depth 8|ConvertFrom-Json
    $current=New-PriorityObservation $Patch.DesiredOrder
    $current.Languages[0].InputMethodTips=@('new-external-input');$current.Languages[0].Handwriting=$true
    $before=$current|ConvertTo-Json -Depth 8 -Compress
    $restore=Restore-RideUserLanguagePriorityPatch $current $snapshot
    ($restore.DesiredOrder -join ',') | Should -BeExactly 'fr-FR,en-GB,da-DK'
    $restore.ChangeRequired | Should -BeTrue
    $restore.ReadyForMutation | Should -BeFalse
    ($current|ConvertTo-Json -Depth 8 -Compress) | Should -BeExactly $before
    ($restore|ConvertTo-Json -Depth 8) | Should -Not -Match 'InputMethodTips|Handwriting|Spellchecking'
  }
  It 'reports no-op when the original order has already been restored' {
    $r=Restore-RideUserLanguagePriorityPatch (New-PriorityObservation) $Patch.Snapshot
    $r.ChangeRequired | Should -BeFalse
  }
  It 'refuses external reorder, added language or removed language for owned order' -ForEach @(
    @{Order=@('da-DK','fr-FR','en-GB')},@{Order=@('en-GB','fr-FR','da-DK','de-DE')},@{Order=@('en-GB','da-DK')}
  ) {
    {Restore-RideUserLanguagePriorityPatch (New-PriorityObservation $Order) $Patch.Snapshot} | Should -Throw '*conflicts*'
  }
  It 'does not undo later ordering or membership after an unchanged proposal' {
    $noop=New-RideUserLanguagePriorityPatch (New-PriorityObservation) 'fr-FR'
    $r=Restore-RideUserLanguagePriorityPatch (New-PriorityObservation @('da-DK','en-GB','fr-FR','de-DE')) $noop.Snapshot
    $r.ChangeRequired | Should -BeFalse
    ($r.DesiredOrder -join ',') | Should -BeExactly 'da-DK,en-GB,fr-FR,de-DE'
  }
  It 'refuses changed identity field <Field>' -ForEach @(
    @{Field='ComputerName';Value='OTHER'},@{Field='Build';Value='26101'},@{Field='EditionId';Value='Enterprise'},
    @{Field='UpdateBuildRevision';Value=2},@{Field='UserSid';Value='S-1-5-21-1-2-3-1002'},@{Field='SessionId';Value=2}
  ) {
    $current=New-PriorityObservation $Patch.DesiredOrder;$current.WindowsContext.$Field=$Value
    {Restore-RideUserLanguagePriorityPatch $current $Patch.Snapshot} | Should -Throw '*identity differs*'
  }
  It 'rejects snapshot version, ownership, order and selected-tag inconsistencies' {
    foreach($field in @('SchemaVersion','OwnsOrder','ExpectedOrder','LanguageTag')){
      $s=$Patch.Snapshot|ConvertTo-Json -Depth 8|ConvertFrom-Json
      switch($field){SchemaVersion{$s.SchemaVersion=2}OwnsOrder{$s.OwnsOrder=$false}ExpectedOrder{$s.ExpectedOrder=@('en-GB','da-DK','fr-FR')}LanguageTag{$s.LanguageTag='de-DE'}}
      {Restore-RideUserLanguagePriorityPatch (New-PriorityObservation $Patch.DesiredOrder) $s} | Should -Throw
    }
  }
}
