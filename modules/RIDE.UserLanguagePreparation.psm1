<#
.SYNOPSIS
  Prepare reversible priority changes among existing user-language declarations.
.DESCRIPTION
  Operates only on supplied observations. Moves one existing language to the front
  while retaining the relative order of all others. Owns list order only, never
  input methods or flags. No language installation, native query, setter or writer.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; native acceptance pending.
  File/environment inputs: Supplied schema-1 language observations and snapshots.
  Recovery: In-memory proposal only, with identity and order conflict checks.
  Version: 0.1.0.
  Changelog: 0.1.0: Add existing-language priority preparation and order-only recovery.
.LINK
  ../docs/user-language-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.UserLanguageInventory.psm1') -ErrorAction Stop

function ConvertTo-RideLanguageOrder {
  param($Order)
  if($null -eq $Order -or $Order -is [string] -or $Order -isnot [Collections.IEnumerable]){throw 'Language order must be an explicit collection.'}
  $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $items=[Collections.Generic.List[string]]::new()
  foreach($tag in $Order){
    if($items.Count -ge 128 -or $tag -isnot [string] -or $tag.Length -gt 128 -or $tag -cnotmatch '^[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*$' -or -not $seen.Add($tag)){throw 'Invalid, missing or duplicate language in priority order.'}
    $items.Add($tag)
  }
  if(-not $items.Count){throw 'Language priority requires an existing nonempty list.'}
  ,@($items.ToArray())
}

function ConvertTo-RideLanguagePreparationIdentity {
  param($Context)
  foreach($name in @('ComputerName','Build','EditionId','UserSid')){
    if($Context.$name -isnot [string] -or [string]::IsNullOrWhiteSpace($Context.$name) -or $Context.$name.Length -gt 255 -or $Context.$name -match '[\x00-\x1f]'){throw 'Invalid language preparation identity.'}
  }
  if($Context.Build -cnotmatch '^[0-9]{4,8}$' -or $Context.UserSid -cnotmatch '^S-1-[0-9]+(?:-[0-9]+)+$' -or $Context.SessionId -is [string] -or $Context.SessionId -is [bool] -or $null -eq $Context.SessionId -or $Context.SessionId -lt 1 -or $Context.SessionId -gt [int]::MaxValue -or [decimal]$Context.SessionId -ne [int]$Context.SessionId -or $Context.NativeProcess -isnot [bool] -or -not $Context.NativeProcess -or $Context.UserInteractive -isnot [bool] -or -not $Context.UserInteractive){throw 'Language preparation requires an explicit native interactive identity.'}
  $ubr=$Context.UpdateBuildRevision
  if($null -eq $ubr -or $ubr -is [string] -or $ubr -is [bool] -or $ubr -lt 0 -or $ubr -gt [uint32]::MaxValue -or [decimal]$ubr -ne [uint32]$ubr){throw 'Invalid language preparation update revision.'}
  [pscustomobject]@{ComputerName=$Context.ComputerName;Build=$Context.Build;EditionId=$Context.EditionId;UpdateBuildRevision=[uint32]$ubr;UserSid=$Context.UserSid;SessionId=[int]$Context.SessionId;NativeProcess=$true;UserInteractive=$true}
}

function Get-RideLanguagePreparationInput {
  param($Inventory)
  if($Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'UserLanguageObservation' -or $Inventory.Status -cne 'Captured'){throw 'Language preparation requires a captured schema-1 observation.'}
  $identity=ConvertTo-RideLanguagePreparationIdentity $Inventory.WindowsContext
  $order=ConvertTo-RideLanguageOrder @($Inventory.Languages|ForEach-Object {$_.LanguageTag})
  # Shared lookup validates all saved positions and identity status without discovery.
  $null=Find-RideUserLanguageObservation -Inventory $Inventory -LanguageTag $order[0]
  [pscustomobject]@{Identity=$identity;Order=$order}
}

function Get-RideLanguagePriorityOrder {
  param([string[]]$Order,[string]$LanguageTag)
  $selected=@($Order|Where-Object {$_ -ieq $LanguageTag})
  if($selected.Count -ne 1){throw 'Select exactly one existing observed language tag; language creation is separate.'}
  $selected[0]
  foreach($tag in $Order){if($tag -ine $LanguageTag){$tag}}
}

function New-RideUserLanguagePriorityPatch {
  <#
  .SYNOPSIS
    Propose moving an existing language to first position, without applying it.
  .PARAMETER Inventory
    Complete identified schema-1 ordered observation from the intended user/session.
  .PARAMETER LanguageTag
    Explicit existing tag. Completion reads supplied identified rows only.
  .EXAMPLE
    New-RideUserLanguagePriorityPatch -Inventory $saved -LanguageTag en-GB
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. DesiredOrder, change flag and version-1 order snapshot.
  .NOTES
    This changes neither display override nor default input. No automatic en-GB
    selection or language-pack installation. ReadyForMutation remains false.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try{
        $data=$fakeBoundParameters.Inventory
        if($data.SchemaVersion -ne 1 -or $data.Kind -cne 'UserLanguageObservation' -or $data.Status -cne 'Captured' -or @($data.Languages).Count -gt 128){return}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $prefix=([string]$wordToComplete).Trim("'",'"')
        foreach($row in @($data.Languages)){
          $tag=[string]$row.LanguageTag
          if($row.IdentityStatus -ceq 'Identified' -and $tag.Length -le 128 -and $tag -cmatch '^[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*$' -and $tag.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($tag)){
            [Management.Automation.CompletionResult]::new(("'"+$tag+"'"),$tag,'ParameterValue',$tag)
          }
        }
      }catch{return}
    })][string]$LanguageTag)
  $inputData=Get-RideLanguagePreparationInput $Inventory
  $desired=@(Get-RideLanguagePriorityOrder -Order $inputData.Order -LanguageTag $LanguageTag)
  $changed=($inputData.Order -join '|') -ine ($desired -join '|')
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserLanguagePriorityPreparation';DesiredOrder=$desired;ChangeRequired=$changed
    Snapshot=[pscustomobject]@{SchemaVersion=1;Kind='UserLanguagePrioritySnapshot';Identity=$inputData.Identity;OriginalOrder=@($inputData.Order);LanguageTag=$desired[0];ExpectedOrder=$desired;OwnsOrder=$changed}
    ReadyForMutation=$false;MutationAuthorized=$false
    Limitation='Order proposal only; no native list reconstruction, setter, durable state or display/input verification'
  }
}

function Restore-RideUserLanguagePriorityPatch {
  <#
  .SYNOPSIS
    Propose restoring owned list order while leaving all per-language metadata alone.
  .PARAMETER Inventory
    Current supplied observation for the same machine/build/edition/user/session.
  .PARAMETER Snapshot
    Version-1 priority snapshot returned by New-RideUserLanguagePriorityPatch.
  .EXAMPLE
    Restore-RideUserLanguagePriorityPatch -Inventory $current -Snapshot $patch.Snapshot
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Recovery DesiredOrder and change flag, never native mutation.
  .NOTES
    Added/removed languages or a third ordering conflict if the original proposal
    owned order. An already restored order is a no-op; an unchanged proposal owns
    nothing. Input methods/flags are not in the snapshot and must be preserved.
    Schema consistency does not authenticate operator-supplied snapshots.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,[Parameter(Mandatory)]$Snapshot)
  $current=Get-RideLanguagePreparationInput $Inventory
  if($Snapshot.SchemaVersion -ne 1 -or $Snapshot.Kind -cne 'UserLanguagePrioritySnapshot' -or $Snapshot.OwnsOrder -isnot [bool] -or $Snapshot.LanguageTag -isnot [string]){throw 'Invalid language priority snapshot schema.'}
  $identity=ConvertTo-RideLanguagePreparationIdentity $Snapshot.Identity
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','UserSid','SessionId','NativeProcess','UserInteractive')){
    if($current.Identity.$field -ine $identity.$field){throw 'Language recovery identity differs from the original target/user/session.'}
  }
  $original=ConvertTo-RideLanguageOrder $Snapshot.OriginalOrder
  $expected=ConvertTo-RideLanguageOrder $Snapshot.ExpectedOrder
  $reconstructed=@(Get-RideLanguagePriorityOrder -Order $original -LanguageTag $Snapshot.LanguageTag)
  $owns=($original -join '|') -ine ($reconstructed -join '|')
  if(($expected -join '|') -cne ($reconstructed -join '|') -or $Snapshot.OwnsOrder -ne $owns){throw 'Language priority snapshot disagrees with its reconstructed edit.'}
  $desired=@($current.Order)
  if($owns){
    if(($current.Order -join '|') -ieq ($expected -join '|')){$desired=@($original)}
    elseif(($current.Order -join '|') -ine ($original -join '|')){throw 'Current language membership or order conflicts with recovery.'}
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='UserLanguagePriorityRecoveryPreparation';DesiredOrder=$desired
    ChangeRequired=(($current.Order -join '|') -ine ($desired -join '|'))
    ReadyForMutation=$false;MutationAuthorized=$false
    Limitation='Restore order only against current rows; retain every current input-method string, flag and unowned field'
  }
}

Export-ModuleMember -Function New-RideUserLanguagePriorityPatch,Restore-RideUserLanguagePriorityPatch
