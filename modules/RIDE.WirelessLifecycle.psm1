<#
.SYNOPSIS
  Import, remove and restore explicitly selected all-user WLAN profiles.
.DESCRIPTION
  Captures private, DPAPI-protected intent before every profile mutation and a
  verified result after it. Recovery checks target, exact XML, scope and order.
  Existing profile replacement preserves its permissions; deletion is limited
  to profiles created by a completed RIDE import with known security settings.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7, Windows 11 x64.
  Prerequisites: Existing elevation and WLAN service/interface; no UAC or service start.
  Recovery: Conditional exact profile XML/order recovery within the recorded scope.
  Incomplete operations retain intent for inspection; no checkpoint reset is a restore.
  Secrets: XML is read privately and sealed using current-user DPAPI before storage.
  Run results/errors contain no XML, key or key digest. Keep state local and private.
  Version: 0.1.0.
  Changelog: 0.1.0: Add candidate all-user import, owned removal and guarded recovery.
.LINK
  ../docs/wireless-profile-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'RIDE.WirelessNative.psm1') -ErrorAction Stop
$script:WirelessProfileSddl='D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;BU)'

function Get-RideWirelessLifecycleContext {
  $version=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  $product=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions'
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  try {
    [pscustomobject]@{ComputerName=[Environment]::MachineName;Build=[string]$version.CurrentBuildNumber;EditionId=[string]$version.EditionID;Revision=$version.UBR;ProductType=[string]$product.ProductType;InstallationType=[string]$version.InstallationType;UserSid=$identity.User.Value;NativeProcess=[Environment]::Is64BitProcess;Architecture=$env:PROCESSOR_ARCHITECTURE;Administrator=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
  } finally { $identity.Dispose() }
}

function Assert-RideWirelessLifecycleContext {
  param($Context,$Expected,[bool]$Mutation)
  if($Context.ProductType -cne 'WinNT' -or $Context.InstallationType -cne 'Client' -or $Context.Build -cnotmatch '^\d{5,8}$' -or [int]$Context.Build -lt 22000 -or -not $Context.NativeProcess -or $Context.Architecture -cne 'AMD64'){throw 'Wireless lifecycle requires a native Windows 11 x64 client.'}
  if($Mutation -and -not $Context.Administrator){throw 'All-user WLAN changes require existing elevation; no elevation prompt is launched.'}
  if($Expected){foreach($field in @('ComputerName','Build','EditionId','Revision','ProductType','InstallationType','UserSid','NativeProcess','Architecture')){if($Context.$field -cne $Expected.$field){throw "Wireless target identity drift ($field); saved state retained."}}}
}

function Read-RideWirelessLifecycleXml {
  param([string]$Xml,[switch]$GeneratedInput)
  if([string]::IsNullOrEmpty($Xml) -or $Xml.Length -gt 262144){throw 'Wireless XML is empty or exceeds its bound.'}
  $reader=$null
  try {
    $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=262144
    $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($Xml),$settings)
    $doc=[Xml.XmlDocument]::new();$doc.PreserveWhitespace=$true;$doc.XmlResolver=$null;$doc.Load($reader)
    if($doc.DocumentElement.LocalName -cne 'WLANProfile' -or $doc.DocumentElement.NamespaceURI -cne 'http://www.microsoft.com/networking/WLAN/profile/v1'){throw 'Invalid profile root.'}
    $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('w',$doc.DocumentElement.NamespaceURI)
    $name=$doc.SelectNodes('/w:WLANProfile/w:name',$ns)
    if($name.Count -ne 1 -or [string]::IsNullOrEmpty($name[0].InnerText) -or $name[0].InnerText.Length -gt 255 -or $name[0].InnerText -match '[\x00-\x1f]'){throw 'Invalid profile identity.'}
    $auth=$doc.SelectNodes('/w:WLANProfile/w:MSM/w:security/w:authEncryption',$ns)
    if($auth.Count -ne 1 -or $auth[0].useOneX -cne 'false' -or -not (($auth[0].authentication -ceq 'WPA2PSK' -and $auth[0].encryption -ceq 'AES') -or ($auth[0].authentication -ceq 'open' -and $auth[0].encryption -ceq 'none'))){throw 'Unsupported authentication.'}
    if($doc.SelectNodes('//*[local-name()="EAPConfig" or local-name()="OneX"]',$ns).Count){throw 'EAP content is not supported.'}
    if($doc.SelectSingleNode('/w:WLANProfile/w:connectionType',$ns).InnerText -cne 'ESS'){throw 'Infrastructure profiles only.'}
    $mode=$doc.SelectSingleNode('/w:WLANProfile/w:connectionMode',$ns)
    if($null -eq $mode -or $mode.InnerText -cnotin @('manual','auto')){throw 'Explicit connection mode required.'}
    foreach($booleanPath in @('/w:WLANProfile/w:SSIDConfig/w:nonBroadcast','/w:WLANProfile/w:autoSwitch')){
      $values=$doc.SelectNodes($booleanPath,$ns)
      if($values.Count -gt 1 -or ($values.Count -eq 1 -and $values[0].InnerText -cnotin @('true','false','1','0'))){throw 'Invalid profile boolean.'}
    }
    $autoSwitch=$doc.SelectSingleNode('/w:WLANProfile/w:autoSwitch',$ns)
    if($mode.InnerText -ceq 'manual' -and $autoSwitch -and $autoSwitch.InnerText -cin @('true','1')){throw 'Manual profiles cannot request automatic switching.'}
    $ssids=$doc.SelectNodes('/w:WLANProfile/w:SSIDConfig/w:SSID',$ns)
    if($ssids.Count -ne 1 -or $doc.SelectNodes('/w:WLANProfile/w:SSIDConfig',$ns).Count -ne 1 -or $ssids[0].hex -cnotmatch '^(?:[0-9A-Fa-f]{2}){1,32}$'){throw 'One exact hexadecimal SSID is required.'}
    $shared=$doc.SelectNodes('/w:WLANProfile/w:MSM/w:security/w:sharedKey',$ns)
    if($auth[0].authentication -ceq 'WPA2PSK'){
      if($shared.Count -ne 1 -or $shared[0].protected -cne 'false'){throw 'An available plaintext key is required inside private recovery capture.'}
      $material=$shared[0].SelectSingleNode('w:keyMaterial',$ns).InnerText
      if($shared[0].keyType -ceq 'passPhrase'){
        if($material.Length -lt 8 -or $material.Length -gt 63 -or $material -cmatch '[^\x20-\x7e]'){throw 'Invalid personal passphrase.'}
      }elseif($shared[0].keyType -ceq 'networkKey'){
        if($material -cnotmatch '^[0-9a-fA-F]{64}$'){throw 'Invalid network key.'}
      }else{throw 'Unsupported key type.'}
    }elseif($shared.Count){throw 'Open profile contains an unexpected key.'}
    if($GeneratedInput){
      $allowed=@('WLANProfile','WLANProfile/name','WLANProfile/SSIDConfig','WLANProfile/SSIDConfig/SSID','WLANProfile/SSIDConfig/SSID/hex','WLANProfile/SSIDConfig/nonBroadcast','WLANProfile/connectionType','WLANProfile/connectionMode','WLANProfile/autoSwitch','WLANProfile/MSM','WLANProfile/MSM/security','WLANProfile/MSM/security/authEncryption','WLANProfile/MSM/security/authEncryption/authentication','WLANProfile/MSM/security/authEncryption/encryption','WLANProfile/MSM/security/authEncryption/useOneX','WLANProfile/MSM/security/sharedKey','WLANProfile/MSM/security/sharedKey/keyType','WLANProfile/MSM/security/sharedKey/protected','WLANProfile/MSM/security/sharedKey/keyMaterial')
      $seen=@{}
      foreach($element in @($doc.SelectNodes('//*'))){$parts=[Collections.Generic.List[string]]::new();for($p=$element;$p -is [Xml.XmlElement];$p=$p.ParentNode){$parts.Insert(0,$p.LocalName)};$path=$parts -join '/'
        if($path -cnotin $allowed -or $seen.ContainsKey($path) -or $element.NamespaceURI -cne $doc.DocumentElement.NamespaceURI){throw 'Input contains unsupported or duplicate settings.'};$seen[$path]=$true
        foreach($attribute in $element.Attributes){if($attribute.NamespaceURI -cne 'http://www.w3.org/2000/xmlns/'){throw 'Input contains unsupported attributes.'}}
      }
    }
    # Preserve leaf whitespace (including a space-only key); remove only indentation
    # surrounding child elements. Native XML formatting is not a state difference.
    foreach($node in @($doc.SelectNodes('//text()[normalize-space(.)=""]'))){if(@($node.ParentNode.ChildNodes|Where-Object NodeType -eq ([Xml.XmlNodeType]::Element)).Count){$null=$node.ParentNode.RemoveChild($node)}}
    [pscustomobject]@{Name=$name[0].InnerText;Mode=$mode.InnerText;Canonical=$doc.DocumentElement.OuterXml;Document=$doc;Namespaces=$ns}
  } catch { throw 'Wireless XML is invalid or outside the supported personal/open infrastructure profile schema.' }
  finally { if($reader){$reader.Dispose()} }
}

function Test-RideWirelessDesiredEqual {
  param([string]$ActualXml,[string]$DesiredXml)
  $signatures=@(foreach($text in @($ActualXml,$DesiredXml)){
    $parsed=Read-RideWirelessLifecycleXml $text;$doc=$parsed.Document;$ns=$parsed.Namespaces
    $hidden=$doc.SelectSingleNode('/w:WLANProfile/w:SSIDConfig/w:nonBroadcast',$ns)
    $auto=$doc.SelectSingleNode('/w:WLANProfile/w:autoSwitch',$ns)
    $auth=$doc.SelectSingleNode('/w:WLANProfile/w:MSM/w:security/w:authEncryption',$ns)
    $key=$doc.SelectSingleNode('/w:WLANProfile/w:MSM/w:security/w:sharedKey',$ns)
    $material=if($key){$key.SelectSingleNode('w:keyMaterial',$ns).InnerText}else{$null}
    # Windows 7 and later default an omitted autoSwitch to false.
    [ordered]@{Name=$parsed.Name;Ssid=$doc.SelectSingleNode('/w:WLANProfile/w:SSIDConfig/w:SSID/w:hex',$ns).InnerText.ToUpperInvariant();Mode=$parsed.Mode;Hidden=($null -ne $hidden -and $hidden.InnerText -in @('true','1'));AutoSwitch=($parsed.Mode -ceq 'auto' -and $null -ne $auto -and $auto.InnerText -in @('true','1'));Authentication=$auth.authentication;Encryption=$auth.encryption;KeyType=if($key){$key.keyType}else{$null};Key=if($key){if($key.keyType -ceq 'networkKey'){$material.ToUpperInvariant()}else{$material}}else{$null}}|ConvertTo-Json -Compress
  })
  $signatures[0] -ceq $signatures[1]
}

function Get-RideWirelessLifecycleRows { param([guid]$InterfaceId);Initialize-RideWirelessProfileNative;[Ride.WirelessProfileV1.Client]::List($InterfaceId) }
function Get-RideWirelessLifecycleContent { param([guid]$InterfaceId,[string]$Name);Initialize-RideWirelessProfileNative;[Ride.WirelessProfileV1.Client]::Read($InterfaceId,$Name,$true) }
function Set-RideWirelessLifecycleContent {
  param([guid]$InterfaceId,[string]$Xml,[AllowNull()][string]$SecurityDescriptor,[bool]$Overwrite)
  Initialize-RideWirelessProfileNative
  $sddl=if([string]::IsNullOrEmpty($SecurityDescriptor)){[System.Management.Automation.Language.NullString]::Value}else{$SecurityDescriptor}
  [Ride.WirelessProfileV1.Client]::Set($InterfaceId,$Xml,$sddl,$Overwrite)
}
function Remove-RideWirelessLifecycleContent { param([guid]$InterfaceId,[string]$Name);Initialize-RideWirelessProfileNative;[Ride.WirelessProfileV1.Client]::Delete($InterfaceId,$Name) }
function Set-RideWirelessLifecyclePosition { param([guid]$InterfaceId,[string]$Name,[uint32]$Position);Initialize-RideWirelessProfileNative;[Ride.WirelessProfileV1.Client]::Position($InterfaceId,$Name,$Position) }

function Get-RideWirelessLifecycleSnapshot {
  param([guid]$InterfaceId,[string]$Name)
  if($InterfaceId -eq [guid]::Empty){throw 'An explicit nonempty WLAN interface GUID is required.'}
  $rows=@(Get-RideWirelessLifecycleRows $InterfaceId)
  $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  if($rows.Count -gt 256){throw 'Wireless profile inventory exceeds its bound.'}
  for($i=0;$i -lt $rows.Count;$i++){if($rows[$i].Position -ne $i -or -not $names.Add($rows[$i].Name)){throw 'Wireless profile inventory is inconsistent.'}}
  $matches=@($rows|Where-Object Name -CEQ $Name)
  $xml=$null;$position=-1
  if($matches.Count){
    if($matches.Count -ne 1 -or $matches[0].Flags -ne 0){throw 'Only an exact all-user profile without policy or unknown flags can be changed.'}
    $content=Get-RideWirelessLifecycleContent $InterfaceId $Name
    if(-not $content.Present -or $content.Flags -ne 0 -or ($content.GrantedAccess -band 0x70023) -ne 0x70023){throw 'Profile scope, presence or write access changed during capture.'}
    $parsed=Read-RideWirelessLifecycleXml $content.Xml
    if($parsed.Name -cne $Name){throw 'Native profile XML identity differs from its list entry.'}
    $xml=$content.Xml;$position=[int]$matches[0].Position
  }
  [pscustomobject]@{Present=($matches.Count -eq 1);Xml=$xml;Position=$position;Order=@($rows|ForEach-Object {[pscustomobject]@{Name=$_.Name;Flags=[uint32]$_.Flags;Position=[int]$_.Position}})}
}

function Test-RideWirelessSnapshotEqual {
  param($Left,$Right)
  if([bool]$Left.Present -ne [bool]$Right.Present -or [int]$Left.Position -ne [int]$Right.Position -or (ConvertTo-Json -InputObject @($Left.Order) -Depth 5 -Compress) -cne (ConvertTo-Json -InputObject @($Right.Order) -Depth 5 -Compress)){return $false}
  if($Left.Present){return (Read-RideWirelessLifecycleXml $Left.Xml).Canonical -ceq (Read-RideWirelessLifecycleXml $Right.Xml).Canonical}
  return $true
}

function Assert-RideWirelessOtherProfiles {
  param($Before,$After,[string]$Name)
  $left=@($Before.Order|Where-Object Name -CNE $Name|ForEach-Object {[pscustomobject]@{Name=$_.Name;Flags=$_.Flags}})
  $right=@($After.Order|Where-Object Name -CNE $Name|ForEach-Object {[pscustomobject]@{Name=$_.Name;Flags=$_.Flags}})
  if((ConvertTo-Json -InputObject $left -Compress) -cne (ConvertTo-Json -InputObject $right -Compress)){throw 'Unrelated WLAN profile membership, flags or relative order changed; retain the run for inspection.'}
}

function Get-RideWirelessRunPath {
  param([string]$StateDirectory,[string]$RunId,[ValidateSet('intent','applied')][string]$Part)
  if($RunId -cnotmatch '^[a-f0-9]{32}$'){throw 'Wireless run ID must be 32 lowercase hexadecimal characters.'}
  Join-Path $StateDirectory ($RunId+'.'+$Part+'.dat')
}

function Save-RideWirelessRunPart {
  param([string]$StateDirectory,[string]$RunId,[string]$Part,$Record)
  $plain=$null;$cipher=$null;$stream=$null
  try {
    Add-Type -AssemblyName System.Security
    $plain=[Text.UTF8Encoding]::new($false,$true).GetBytes(($Record|ConvertTo-Json -Depth 16 -Compress))
    if($plain.Length -gt 2097152){throw 'Wireless recovery record exceeds its bound.'}
    $cipher=[Security.Cryptography.ProtectedData]::Protect($plain,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $stream=New-RidePrivateFileStream -Path (Get-RideWirelessRunPath $StateDirectory $RunId $Part)
    $stream.Write($cipher,0,$cipher.Length);$stream.Flush($true)
  } finally {if($stream){$stream.Dispose()};if($plain){[Array]::Clear($plain,0,$plain.Length)};if($cipher){[Array]::Clear($cipher,0,$cipher.Length)}}
}

function Read-RideWirelessRunPart {
  param([string]$StateDirectory,[string]$RunId,[string]$Part)
  $cipher=$null;$plain=$null
  try {
    Add-Type -AssemblyName System.Security
    $cipher=Read-RidePrivateFileBytes -Path (Get-RideWirelessRunPath $StateDirectory $RunId $Part) -MaximumBytes 3145728
    $plain=[Security.Cryptography.ProtectedData]::Unprotect($cipher,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    if($plain.Length -gt 2097152){throw 'Wireless record exceeds its bound.'}
    $record=[Text.UTF8Encoding]::new($false,$true).GetString($plain)|ConvertFrom-Json
    if($record.SchemaVersion -ne 1 -or $record.Kind -cne 'WirelessLifecycle' -or $record.RunId -cne $RunId -or $record.Part -cne $Part){throw 'Wireless record identity differs.'}
    $record
  } catch {throw 'Private wireless recovery record is missing, damaged, inaccessible or belongs to another account.'}
  finally {if($plain){[Array]::Clear($plain,0,$plain.Length)};if($cipher){[Array]::Clear($cipher,0,$cipher.Length)}}
}

function New-RideWirelessRunIntent {
  param([string]$Action,$Context,[guid]$InterfaceId,[string]$Name,$Before,[string]$DesiredXml,[bool]$CreatedByRun,[AllowNull()][string]$SecurityDescriptor)
  [pscustomobject]@{SchemaVersion=1;Kind='WirelessLifecycle';Part='intent';RunId=[guid]::NewGuid().ToString('N');CreatedAtUtc=[DateTime]::UtcNow.ToString('o');Action=$Action;Context=$Context;InterfaceId=$InterfaceId.ToString('D');Name=$Name;Before=$Before;DesiredXml=$DesiredXml;CreatedByRun=$CreatedByRun;SecurityDescriptor=$SecurityDescriptor}
}

function Complete-RideWirelessRun {
  param([string]$StateDirectory,$Intent,$After)
  Save-RideWirelessRunPart $StateDirectory $Intent.RunId applied ([pscustomobject]@{SchemaVersion=1;Kind='WirelessLifecycle';Part='applied';RunId=$Intent.RunId;After=$After})
  [pscustomobject]@{SchemaVersion=1;Status='Applied';RunId=$Intent.RunId;Action=$Intent.Action;Scope='Machine/AllUser';ConnectionAttempted=$false;NativeAcceptancePassed=$false}
}

function Install-RideWirelessProfile {
  <#
  .SYNOPSIS
    Import a generated all-user profile after durable private state capture.
  .PARAMETER ProfilePath
    Private XML produced from supplied settings; no ordinary plaintext argument.
  .PARAMETER InterfaceId
    Explicit WLAN interface GUID. Descriptions and adapter indexes are not accepted.
  .PARAMETER StateDirectory
    Existing local recovery directory. Individual records are private and DPAPI sealed.
  .PARAMETER ExpectedComputerName
    Independently identified disposable target name.
  .PARAMETER ExpectedBuild
    Exact expected Windows build number.
  .PARAMETER ExpectedEditionId
    Exact expected edition identity.
  .PARAMETER ReplaceExisting
    Explicitly permit XML replacement of an existing supported all-user profile.
    Its existing permissions are preserved and its prior XML/order are captured.
  .PARAMETER AllowAutoConnect
    Permit an auto-mode profile; Windows may connect after import. Synthetic tests omit it.
  .PARAMETER AllowCandidate
    Fresh opt-in for pending native acceptance. Does not bypass other guards.
  .EXAMPLE
    Install-RideWirelessProfile -ProfilePath C:\Private\synthetic.xml -InterfaceId '<guid>' -StateDirectory C:\Private\State -ExpectedComputerName '<vm>' -ExpectedBuild '26300' -ExpectedEditionId EnterpriseEval -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 result with run ID; no profile content or credentials.
  .NOTES
    Candidate Windows 11 x64; existing elevation is required for actual all-user changes.
    No explicit network connect call is made. Incomplete runs retain private intent.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$ProfilePath,[Parameter(Mandatory)][guid]$InterfaceId,
    [Parameter(Mandatory)][string]$StateDirectory,[Parameter(Mandatory)][string]$ExpectedComputerName,
    [Parameter(Mandatory)][string]$ExpectedBuild,[Parameter(Mandatory)][string]$ExpectedEditionId,
    [switch]$ReplaceExisting,[switch]$AllowAutoConnect,[switch]$AllowCandidate)
  $context=Get-RideWirelessLifecycleContext
  Assert-RideWirelessLifecycleContext $context $null (-not $WhatIfPreference)
  if($context.ComputerName -cne $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -cne $ExpectedEditionId){throw 'Expected wireless target differs; no profile was changed.'}
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Wireless lifecycle acceptance is pending; actual changes require -AllowCandidate.'}
  $bytes=$null
  try {$bytes=Read-RidePrivateFileBytes -Path $ProfilePath -MaximumBytes 1048576;$xml=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)}finally{if($bytes){[Array]::Clear($bytes,0,$bytes.Length)}}
  $parsed=Read-RideWirelessLifecycleXml $xml -GeneratedInput
  if($parsed.Mode -ceq 'auto' -and -not $AllowAutoConnect){throw 'Automatic connection mode requires explicit -AllowAutoConnect; use manual mode for synthetic tests.'}
  $before=Get-RideWirelessLifecycleSnapshot $InterfaceId $parsed.Name
  if($before.Present -and (Test-RideWirelessDesiredEqual $before.Xml $xml)){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyDesired';RunId=$null;Scope='Machine/AllUser';ConnectionAttempted=$false}}
  if($before.Present -and -not $ReplaceExisting){throw 'An existing profile requires explicit -ReplaceExisting; no profile was changed.'}
  $sddl=if($before.Present){$null}else{$script:WirelessProfileSddl}
  $intent=New-RideWirelessRunIntent Install $context $InterfaceId $parsed.Name $before $xml (-not $before.Present) $sddl
  if($PSCmdlet.ShouldProcess($InterfaceId,'Import selected all-user WLAN profile after private recovery capture')){
    Save-RideWirelessRunPart $StateDirectory $intent.RunId intent $intent
    try {
      Assert-RideWirelessLifecycleContext (Get-RideWirelessLifecycleContext) $context $true
      if(-not (Test-RideWirelessSnapshotEqual $before (Get-RideWirelessLifecycleSnapshot $InterfaceId $parsed.Name))){throw 'Profile changed after capture.'}
      Set-RideWirelessLifecycleContent $InterfaceId $xml $sddl ([bool]$before.Present)
      $after=Get-RideWirelessLifecycleSnapshot $InterfaceId $parsed.Name
      Assert-RideWirelessOtherProfiles $before $after $parsed.Name
      if(-not $after.Present -or -not (Test-RideWirelessDesiredEqual $after.Xml $xml)){throw 'Native profile differs from the requested settings; acceptance is incomplete.'}
      if($before.Present -and $after.Position -ne $before.Position){throw 'Profile replacement changed preference position.'}
      Complete-RideWirelessRun $StateDirectory $intent $after
    } catch {throw "Wireless import did not complete. Run ID: $($intent.RunId). Private intent retained; inspect native state before recovery."}
  }
}

function Remove-RideWirelessProfile {
  <#
  .SYNOPSIS
    Remove a profile created by a completed RIDE import, retaining recovery.
  .PARAMETER OwnerRunId
    Completed install run that created this profile from absence with known permissions.
  .PARAMETER StateDirectory
    Existing private recovery directory for the original and new run records.
  .PARAMETER AllowCandidate
    Fresh opt-in for the pending native lifecycle candidate.
  .EXAMPLE
    Remove-RideWirelessProfile -OwnerRunId '<install-run-id>' -StateDirectory C:\Private\State -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 result with the removal run ID; restore that run to reinstall.
  .NOTES
    Refuses deletion of pre-existing profiles whose original permissions were not captured.
    XML replacement of those profiles can instead be undone through their install run.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$OwnerRunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $owner=Read-RideWirelessRunPart $StateDirectory $OwnerRunId intent
  $applied=Read-RideWirelessRunPart $StateDirectory $OwnerRunId applied
  if($owner.Action -cne 'Install' -or -not $owner.CreatedByRun -or $owner.Before.Present -or $owner.SecurityDescriptor -cne $script:WirelessProfileSddl){throw 'Removal requires a RIDE-created profile with recorded permissions; restore a replacement run instead.'}
  $context=Get-RideWirelessLifecycleContext;Assert-RideWirelessLifecycleContext $context $owner.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Wireless removal requires -AllowCandidate.'}
  $before=Get-RideWirelessLifecycleSnapshot ([guid]$owner.InterfaceId) $owner.Name
  if(-not $before.Present){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyAbsent';RunId=$null}}
  if(-not (Test-RideWirelessSnapshotEqual $before $applied.After)){throw 'Wireless state or order changed since installation; refusing removal.'}
  $intent=New-RideWirelessRunIntent Remove $context ([guid]$owner.InterfaceId) $owner.Name $before $null $false $owner.SecurityDescriptor
  if($PSCmdlet.ShouldProcess($owner.InterfaceId,'Remove the exact RIDE-created all-user WLAN profile after private capture')){
    Save-RideWirelessRunPart $StateDirectory $intent.RunId intent $intent
    try {
      Assert-RideWirelessLifecycleContext (Get-RideWirelessLifecycleContext) $context $true
      if(-not (Test-RideWirelessSnapshotEqual $before (Get-RideWirelessLifecycleSnapshot ([guid]$owner.InterfaceId) $owner.Name))){throw 'Profile changed after capture.'}
      Remove-RideWirelessLifecycleContent ([guid]$owner.InterfaceId) $owner.Name
      $after=Get-RideWirelessLifecycleSnapshot ([guid]$owner.InterfaceId) $owner.Name
      Assert-RideWirelessOtherProfiles $before $after $owner.Name
      if($after.Present){throw 'Profile remained after removal.'}
      Complete-RideWirelessRun $StateDirectory $intent $after
    } catch {throw "Wireless removal did not complete. Run ID: $($intent.RunId). Private intent retained; inspect native state before recovery."}
  }
}

function Restore-RideWirelessProfileRun {
  <#
  .SYNOPSIS
    Restore a completed wireless run's captured XML, scope and preference order.
  .PARAMETER RunId
    Completed install or removal run to undo. Incomplete records refuse automatic recovery.
  .PARAMETER StateDirectory
    Private local recovery directory; DPAPI requires the original Windows account.
  .PARAMETER AllowCandidate
    Fresh opt-in for candidate recovery; previous run approval is not reused.
  .EXAMPLE
    Restore-RideWirelessProfileRun -RunId '<run-id>' -StateDirectory C:\Private\State -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 Restored or AlreadyRestored result without secrets.
  .NOTES
    Refuses target/state/order drift. Partial native restore failures retain the original
    records and require inspection; no unrelated profile or permission is repaired.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
  param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$StateDirectory,[switch]$AllowCandidate)
  $intent=Read-RideWirelessRunPart $StateDirectory $RunId intent
  $applied=Read-RideWirelessRunPart $StateDirectory $RunId applied
  if($intent.Action -cnotin @('Install','Remove')){throw 'Unknown wireless recovery action.'}
  $context=Get-RideWirelessLifecycleContext;Assert-RideWirelessLifecycleContext $context $intent.Context (-not $WhatIfPreference)
  if(-not $WhatIfPreference -and -not $AllowCandidate){throw 'Wireless recovery requires fresh -AllowCandidate.'}
  $current=Get-RideWirelessLifecycleSnapshot ([guid]$intent.InterfaceId) $intent.Name
  if(Test-RideWirelessSnapshotEqual $current $intent.Before){return [pscustomobject]@{SchemaVersion=1;Status='AlreadyRestored';RunId=$RunId}}
  if(-not (Test-RideWirelessSnapshotEqual $current $applied.After)){throw 'Wireless recovery conflict: native XML, scope or order changed; saved state retained.'}
  if($intent.Action -ceq 'Remove' -and $intent.SecurityDescriptor -cne $script:WirelessProfileSddl){throw 'Original profile permissions are unavailable; refusing recreation.'}
  if($PSCmdlet.ShouldProcess($intent.InterfaceId,'Restore captured WLAN profile content and preference order')){
    try {
      Assert-RideWirelessLifecycleContext (Get-RideWirelessLifecycleContext) $intent.Context $true
      if(-not (Test-RideWirelessSnapshotEqual $current (Get-RideWirelessLifecycleSnapshot ([guid]$intent.InterfaceId) $intent.Name))){throw 'Wireless state drifted during recovery preflight.'}
      if($intent.Before.Present){
        $sddl=if($current.Present){$null}else{$intent.SecurityDescriptor}
        Set-RideWirelessLifecycleContent ([guid]$intent.InterfaceId) $intent.Before.Xml $sddl ([bool]$current.Present)
        Set-RideWirelessLifecyclePosition ([guid]$intent.InterfaceId) $intent.Name ([uint32]$intent.Before.Position)
      } else {Remove-RideWirelessLifecycleContent ([guid]$intent.InterfaceId) $intent.Name}
      $after=Get-RideWirelessLifecycleSnapshot ([guid]$intent.InterfaceId) $intent.Name
      if(-not (Test-RideWirelessSnapshotEqual $after $intent.Before)){throw 'Wireless recovery readback differs from captured state.'}
      [pscustomobject]@{SchemaVersion=1;Status='Restored';RunId=$RunId;Scope='Machine/AllUser';ConnectionAttempted=$false}
    } catch {throw "Wireless recovery did not complete. Run ID: $RunId. Retain private records and inspect native state; no exact recovery is claimed."}
  }
}

$script:WirelessRunCompleter={param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try{if(-not $fakeBoundParameters.ContainsKey('StateDirectory')){return};$directory=[string]$fakeBoundParameters.StateDirectory
    Get-ChildItem -LiteralPath $directory -Filter '*.applied.dat' -File -ErrorAction Stop|Select-Object -First 1000|ForEach-Object {if($_.Name -cmatch '^([a-f0-9]{32})\.applied\.dat$'){$id=$Matches[1];if($id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase)){[Management.Automation.CompletionResult]::new($id,$id,'ParameterValue','Saved wireless run')}}}
  }catch{}
}
Register-ArgumentCompleter -CommandName Remove-RideWirelessProfile -ParameterName OwnerRunId -ScriptBlock $script:WirelessRunCompleter
Register-ArgumentCompleter -CommandName Restore-RideWirelessProfileRun -ParameterName RunId -ScriptBlock $script:WirelessRunCompleter
Export-ModuleMember -Function Install-RideWirelessProfile,Remove-RideWirelessProfile,Restore-RideWirelessProfileRun
