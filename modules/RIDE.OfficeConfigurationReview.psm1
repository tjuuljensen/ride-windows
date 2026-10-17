<#
.SYNOPSIS
  Review supplied Office Deployment Tool XML without executing or rewriting it.
.DESCRIPTION
  Parses bounded XML with DTD/external resolution prohibited. Summarizes declared
  products, languages, architecture, channels and actions without exposing product
  keys, property secrets, source paths or application-setting values. Unknown syntax
  remains an explicit review item. This is not an ODT schema or compatibility validator.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; .NET XML APIs.
  Inputs: Supplied XML bytes, at most 1 MiB. No file, registry, network or ODT access.
  Recovery: Pure inspection; original bytes are unchanged and remain authoritative.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded inert configuration review with redacted action flags.
.LINK
  ../docs/application-packages.md
#>
$ErrorActionPreference='Stop'

function Read-RideOfficeXmlDocument {
  param([byte[]]$Bytes)
  if(-not $Bytes.Length -or $Bytes.Length -gt 1048576){throw 'Office XML must contain 1 to 1048576 bytes.'}
  $settings=[Xml.XmlReaderSettings]::new()
  $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
  $settings.XmlResolver=$null
  $settings.MaxCharactersInDocument=1048576
  $settings.MaxCharactersFromEntities=1024
  $settings.IgnoreComments=$false
  $settings.IgnoreProcessingInstructions=$false
  $stream=$null;$reader=$null
  try {
    $stream=[IO.MemoryStream]::new($Bytes,$false)
    $reader=[Xml.XmlReader]::Create($stream,$settings)
    $nodes=0
    while($reader.Read()){
      $nodes++
      if($nodes -gt 4096 -or $reader.Depth -gt 24 -or $reader.AttributeCount -gt 32){throw 'XML bounds exceeded.'}
      if($reader.NodeType -eq [Xml.XmlNodeType]::Element){
        if($reader.NamespaceURI -or $reader.Prefix){throw 'Namespaces are not reviewed.'}
        if($reader.Name.Length -gt 128){throw 'Excessive XML name.'}
        if($reader.MoveToFirstAttribute()){
          do {if($reader.Name.Length -gt 128 -or $reader.Value.Length -gt 4096 -or $reader.NamespaceURI -or $reader.Prefix){throw 'Unreviewed or excessive attribute.'}}while($reader.MoveToNextAttribute())
          $null=$reader.MoveToElement()
        }
      }
      if($reader.NodeType -in @([Xml.XmlNodeType]::ProcessingInstruction,[Xml.XmlNodeType]::EntityReference)){throw 'XML instructions/entities are not reviewed.'}
    }
    $reader.Dispose();$reader=$null;$stream.Dispose();$stream=$null
    $stream=[IO.MemoryStream]::new($Bytes,$false)
    $reader=[Xml.XmlReader]::Create($stream,$settings)
    $document=[Xml.XmlDocument]::new();$document.XmlResolver=$null
    $document.Load($reader)
    if($document.DocumentElement.Name -cne 'Configuration'){throw 'Wrong root.'}
    return ,$document
  }catch{
    # XML exception messages can quote input data: do not forward them.
    throw 'Office XML is malformed, exceeds inspection limits, or uses prohibited XML features.'
  }finally{if($reader){$reader.Dispose()};if($stream){$stream.Dispose()}}
}

function Get-RideOfficeToken {
  param([Xml.XmlElement]$Element,[string]$Attribute)
  if(-not $Element.HasAttribute($Attribute)){return $null}
  $value=$Element.GetAttribute($Attribute)
  if($value -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$'){throw 'Office XML contains an invalid or excessive review token.'}
  $value
}

function Get-RideOfficeConfigurationReview {
  <#
  .SYNOPSIS
    Inspect supplied ODT configuration bytes and list unresolved effects.
  .PARAMETER Bytes
    Exact XML bytes. At most 1 MiB, 4096 XML nodes, depth 24 and 32 attributes
    per element. Do not send credentials or product keys to a shared report.
  .EXAMPLE
    $bytes=[IO.File]::ReadAllBytes('<reviewed-local-configuration.xml>')
    Get-RideOfficeConfigurationReview -Bytes $bytes
  .INPUTS
    Byte[]. Explicit input only; the module reads no file or external entity.
  .OUTPUTS
    PSCustomObject. Schema-1 OfficeConfigurationReview with redacted summaries.
  .NOTES
    Omitted values remain null; no publisher default is silently selected. Product
    identifiers do not prove licence edition, entitlement, compatibility or language
    support. Installation, activation and update maintenance are separate. The
    returned record never authorizes mutation, removes products or accepts terms.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
  $document=Read-RideOfficeXmlDocument $Bytes
  $issues=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $null=$issues.Add('ExistingInstallationCompatibilityNotVerified')
  $null=$issues.Add('EntitlementAndActivationNotVerified')
  $null=$issues.Add('PublisherPayloadAndVersionNotVerified')
  $null=$issues.Add('BundledApplicationsAndLanguageSupportNotFullyVerified')
  $null=$issues.Add('RecoveryNotImplemented')
  $unknown=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  $secretPresent=$false
  $schema=@{
    Configuration=@();Add=@('OfficeClientEdition','Channel','Version','MigrateArch','AllowCdnFallback','SourcePath','DownloadPath','OfficeMgmtCOM')
    Product=@('ID','PIDKEY');Language=@('ID','Fallback','TargetProduct');ExcludeApp=@('ID')
    Remove=@('All');RemoveMSI=@();IgnoreProduct=@('ID')
    Updates=@('Enabled','Channel','TargetVersion','Deadline','UpdatePath');Display=@('Level','AcceptEULA')
    Property=@('Name','Value');AppSettings=@()
  }
  $paths=@('Configuration','Configuration/Add','Configuration/Add/Product','Configuration/Add/Product/Language','Configuration/Add/Product/ExcludeApp',
    'Configuration/Remove','Configuration/Remove/Product','Configuration/Remove/Product/Language','Configuration/RemoveMSI','Configuration/RemoveMSI/IgnoreProduct',
    'Configuration/Updates','Configuration/Display','Configuration/Property','Configuration/AppSettings')
  $stack=[Collections.Generic.Stack[object]]::new()
  $stack.Push([pscustomobject]@{Node=$document.DocumentElement;Path='Configuration'})
  while($stack.Count){
    $entry=$stack.Pop();$element=$entry.Node;$path=$entry.Path
    if($path -cnotin $paths){$null=$unknown.Add($path)}
    foreach($attribute in $element.Attributes){
      if($attribute.Name -ieq 'PIDKEY' -or $attribute.Name -match '(?i)password|secret|token|tenantassociationkey'){$secretPresent=$true}
      if(-not $schema.ContainsKey($element.Name) -or $attribute.Name -cnotin $schema[$element.Name]){$null=$unknown.Add($path+'/@'+$attribute.Name)}
    }
    foreach($child in $element.ChildNodes){
      if($child.NodeType -eq [Xml.XmlNodeType]::Element){$stack.Push([pscustomobject]@{Node=$child;Path=$path+'/'+$child.Name})}
      elseif($child.NodeType -in @([Xml.XmlNodeType]::Text,[Xml.XmlNodeType]::CDATA) -and -not [string]::IsNullOrWhiteSpace($child.Value)){$null=$issues.Add('UnreviewedTextContent')}
    }
  }
  $additions=@(foreach($add in $document.DocumentElement.SelectNodes('./Add')){
    $products=@(foreach($product in $add.SelectNodes('./Product')){
      $id=Get-RideOfficeToken $product 'ID'
      if(-not $id){$null=$issues.Add('MissingProductIdentity')}
      $languages=@(foreach($language in $product.SelectNodes('./Language')){
        $languageId=Get-RideOfficeToken $language 'ID'
        if(-not $languageId){$null=$issues.Add('MissingLanguageIdentity')}
        $fallback=Get-RideOfficeToken $language 'Fallback'
        if($languageId -in @('MatchOS','MatchInstalled','MatchPreviousMSI')){$null=$issues.Add('DynamicLanguageResolutionRequired')}
        if($languageId -eq 'MatchOS' -and -not $fallback){$null=$issues.Add('MatchOsFallbackUnspecified')}
        if($id -like 'Visio*' -and $languageId -ieq 'en-gb'){$null=$issues.Add('VisioEnglishUkUnsupported')}
        [pscustomobject]@{Id=$languageId;Fallback=$fallback;TargetProduct=Get-RideOfficeToken $language 'TargetProduct'}
      })
      if(-not $languages.Count){$null=$issues.Add('LanguageSelectionUnspecified')}
      $exclusions=@(foreach($excluded in $product.SelectNodes('./ExcludeApp')){Get-RideOfficeToken $excluded 'ID'})
      if($exclusions.Count){$null=$issues.Add('ApplicationExclusionsRequireReview')}
      [pscustomobject]@{Id=$id;Languages=$languages;ExcludedApps=$exclusions;ProductKeyPresent=$product.HasAttribute('PIDKEY')}
    })
    $version=Get-RideOfficeToken $add 'Version'
    if(-not $version -or $version -cnotmatch '^16\.0\.[0-9]{1,5}\.[0-9]{1,5}$'){$null=$issues.Add('DeploymentVersionNotPinned')}
    $architecture=Get-RideOfficeToken $add 'OfficeClientEdition'
    if($architecture -notin @('32','64')){$null=$issues.Add('ArchitectureNotExplicitlyResolved')}
    $channel=Get-RideOfficeToken $add 'Channel'
    if($channel -notin @('MonthlyEnterprise','Current')){$null=$issues.Add('ChannelOutsideSelectedChoices')}
    $migration=Get-RideOfficeToken $add 'MigrateArch'
    if($null -ne $migration -and $migration -ine 'FALSE'){$null=$issues.Add('ArchitectureMigrationRequiresSeparateDecision')}
    $cdn=Get-RideOfficeToken $add 'AllowCdnFallback'
    if($null -ne $cdn -and $cdn -ine 'FALSE'){$null=$issues.Add('CdnFallbackRequestedOrUnrecognized')}
    if(-not $products.Count){$null=$issues.Add('NoProductSelection')}
    [pscustomobject]@{Architecture=$architecture;Channel=$channel;Version=$version;MigrateArch=$migration;AllowCdnFallback=$cdn
      SourcePathPresent=$add.HasAttribute('SourcePath');DownloadPathPresent=$add.HasAttribute('DownloadPath')
      OfficeMgmtCOM=Get-RideOfficeToken $add 'OfficeMgmtCOM';Products=$products}
  })
  $root=$document.DocumentElement
  $removeCount=$root.SelectNodes('./Remove').Count
  $removeMsiCount=$root.SelectNodes('./RemoveMSI').Count
  $removals=@(foreach($remove in $root.SelectNodes('./Remove')){
    [pscustomobject]@{All=Get-RideOfficeToken $remove 'All';Products=@(foreach($product in $remove.SelectNodes('./Product')){
      [pscustomobject]@{Id=Get-RideOfficeToken $product 'ID';LanguageIds=@(foreach($language in $product.SelectNodes('./Language')){Get-RideOfficeToken $language 'ID'})}
    })}
  })
  $msiExclusions=@(foreach($remove in $root.SelectNodes('./RemoveMSI')){
    [pscustomobject]@{IgnoreProductIds=@(foreach($product in $remove.SelectNodes('./IgnoreProduct')){Get-RideOfficeToken $product 'ID'})}
  })
  if($removeCount){$null=$issues.Add('ProductRemovalRequiresSeparateDecision')}
  if($removeMsiCount){$null=$issues.Add('MsiRemovalRequiresSeparateDecision')}
  if($root.SelectNodes('./AppSettings').Count){$null=$issues.Add('ApplicationSettingsRequireSeparateReview')}
  $updates=@(foreach($update in $root.SelectNodes('./Updates')){
    $null=$issues.Add('UpdateMaintenanceRequiresSeparateReview')
    [pscustomobject]@{Enabled=Get-RideOfficeToken $update 'Enabled';Channel=Get-RideOfficeToken $update 'Channel'
      TargetVersion=Get-RideOfficeToken $update 'TargetVersion';UpdatePathPresent=$update.HasAttribute('UpdatePath');DeadlinePresent=$update.HasAttribute('Deadline')}
  })
  $displays=@(foreach($display in $root.SelectNodes('./Display')){
    $accept=Get-RideOfficeToken $display 'AcceptEULA'
    if($null -ne $accept -and $accept -ine 'FALSE'){$null=$issues.Add('PublisherTermsAcceptanceRequestedOrUnrecognized')}
    [pscustomobject]@{Level=Get-RideOfficeToken $display 'Level';AcceptEula=$accept}
  })
  $properties=@(foreach($property in $root.SelectNodes('./Property')){
    $name=Get-RideOfficeToken $property 'Name';$value=$null
    switch -CaseSensitive ($name){
      FORCEAPPSHUTDOWN {
        $value=Get-RideOfficeToken $property 'Value'
        if($value -ine 'FALSE'){$null=$issues.Add('ForcedApplicationShutdownRequiresSeparateDecision')}
      }
      AUTOACTIVATE {$value=Get-RideOfficeToken $property 'Value';$null=$issues.Add('AutomaticActivationConfigurationRequiresReview')}
      SharedComputerLicensing {$value=Get-RideOfficeToken $property 'Value';$null=$issues.Add('SpecializedActivationRequiresSeparateDecision')}
      DeviceBasedLicensing {$value=Get-RideOfficeToken $property 'Value';$null=$issues.Add('SpecializedActivationRequiresSeparateDecision')}
      default {
        $null=$issues.Add('UnreviewedProperty');$null=$unknown.Add('Configuration/Property/'+$name)
        if($name -match '(?i)password|secret|token|key|SCLCache'){$secretPresent=$true}
      }
    }
    [pscustomobject]@{Name=$name;Value=$value;ValueOmitted=($null -eq $value)}
  })
  foreach($single in @('Add','Updates','Display','Remove','RemoveMSI','AppSettings')){
    if($root.SelectNodes('./'+$single).Count -gt 1){$null=$issues.Add('RepeatedTopLevelElement')}
  }
  if($unknown.Count){$null=$issues.Add('UnreviewedXmlSyntax')}
  if($secretPresent){$null=$issues.Add('SensitiveConfigurationPresent')}
  $hasher=[Security.Cryptography.SHA256]::Create()
  try{$hash=([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$hasher.Dispose()}
  [pscustomobject]@{
    SchemaVersion=1;Kind='OfficeConfigurationReview';ConfigurationSha256=$hash;ByteLength=$Bytes.Length
    Additions=$additions;Updates=$updates;Display=$displays;Properties=$properties
    Removals=$removals;MsiRemovalExclusions=$msiExclusions
    RemoveElements=$removeCount;RemoveMsiElements=$removeMsiCount;AppSettingsElements=$root.SelectNodes('./AppSettings').Count
    SensitiveConfigurationPresent=$secretPresent;UnreviewedSyntax=@($unknown|Sort-Object);ReviewItems=@($issues|Sort-Object)
    Scope='Supplied configuration only; no installed-product, publisher-schema, licence, activation or compatibility verification'
    ActivationStatus='NotObserved';ReadyForMutation=$false;RecoverySupported=$false
  }
}
Export-ModuleMember -Function Get-RideOfficeConfigurationReview
