<#
.SYNOPSIS
  Generate a protected WLAN profile file from explicit settings.
.DESCRIPTION
  Prepares WPA2-Personal/AES or open infrastructure profiles without querying
  adapters, importing a profile, connecting or changing Windows configuration.
  Writes a new file with an explicit current-user/SYSTEM DACL at creation.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Inputs: Explicit settings, SecureString key and a new local XML path.
  Recovery: No WLAN state changes. Remove the generated sensitive file after use.
  Partial files remain private on failure; existing files are never overwritten.
  Version: 0.2.0.
  Changelog: 0.2.0: Share verified private-file persistence with wireless lifecycle state.
  0.1.0: Generate escaped profiles with exact SSID bytes and private output.
.LINK
  ../docs/wireless-profile-inventory.md
#>
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'RIDE.PrivateFiles.psm1') -ErrorAction Stop

function ConvertTo-RideWirelessProfileXml {
  param([string]$ProfileName,[byte[]]$SsidBytes,[string]$Security,
    [Security.SecureString]$Key,[string]$ConnectionMode,[bool]$HiddenNetwork)
  if ([string]::IsNullOrEmpty($ProfileName) -or $ProfileName.Length -gt 255 -or $ProfileName -match '[\x00-\x1f]') { throw 'ProfileName must contain 1-255 characters without control characters.' }
  try { $null=[Xml.XmlConvert]::VerifyXmlChars($ProfileName) } catch { throw 'ProfileName contains invalid XML characters.' }
  if ($SsidBytes.Count -lt 1 -or $SsidBytes.Count -gt 32) { throw 'SSID must contain 1-32 bytes.' }
  $material=$null;$pointer=[IntPtr]::Zero;$memory=$null;$writer=$null
  try {
    if ($Security -eq 'WPA2Personal') {
      if ($null -eq $Key -or $Key.Length -lt 8 -or $Key.Length -gt 64) { throw 'WPA2Personal requires an 8-63 ASCII passphrase or a 64-digit hexadecimal key.' }
      $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
      $material=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
      if ($material.Length -eq 64) {
        if ($material -cnotmatch '^[0-9A-Fa-f]{64}$') { throw 'A 64-character WPA2 key must be hexadecimal.' }
        $keyType='networkKey'
      } else {
        if ($material -cmatch '[^\x20-\x7e]') { throw 'A WPA2 passphrase must contain only printable ASCII characters.' }
        $keyType='passPhrase'
      }
    } elseif ($Security -eq 'Open') {
      if ($null -ne $Key) { throw 'Open security does not accept a key.' }
    } else { throw 'Unsupported wireless security selection.' }
    if ($ConnectionMode -notin @('manual','auto')) { throw 'Unsupported connection mode.' }
    $memory=[IO.MemoryStream]::new()
    $settings=[Xml.XmlWriterSettings]::new()
    $settings.Encoding=[Text.UTF8Encoding]::new($false)
    $settings.Indent=$true;$settings.NewLineChars="`n";$settings.CloseOutput=$false
    $writer=[Xml.XmlWriter]::Create($memory,$settings)
    $writer.WriteStartDocument()
    # This is an XML namespace identifier, not a network endpoint. Preserve http.
    $writer.WriteStartElement('WLANProfile','http://www.microsoft.com/networking/WLAN/profile/v1')
    $writer.WriteElementString('name',$ProfileName)
    $writer.WriteStartElement('SSIDConfig');$writer.WriteStartElement('SSID')
    $writer.WriteElementString('hex',([BitConverter]::ToString($SsidBytes).Replace('-','')))
    $writer.WriteEndElement()
    $writer.WriteElementString('nonBroadcast',$HiddenNetwork.ToString().ToLowerInvariant())
    $writer.WriteEndElement()
    $writer.WriteElementString('connectionType','ESS')
    $writer.WriteElementString('connectionMode',$ConnectionMode)
    $writer.WriteElementString('autoSwitch','false')
    $writer.WriteStartElement('MSM');$writer.WriteStartElement('security');$writer.WriteStartElement('authEncryption')
    $writer.WriteElementString('authentication',$(if ($Security -eq 'WPA2Personal') {'WPA2PSK'}else{'open'}))
    $writer.WriteElementString('encryption',$(if ($Security -eq 'WPA2Personal') {'AES'}else{'none'}))
    $writer.WriteElementString('useOneX','false');$writer.WriteEndElement()
    if ($Security -eq 'WPA2Personal') {
      $writer.WriteStartElement('sharedKey');$writer.WriteElementString('keyType',$keyType)
      $writer.WriteElementString('protected','false');$writer.WriteElementString('keyMaterial',$material)
      $writer.WriteEndElement()
    }
    $writer.WriteEndElement();$writer.WriteEndElement();$writer.WriteEndElement()
    $writer.WriteEndDocument();$writer.Flush()
    ,$memory.ToArray()
  } finally {
    if ($writer) { $writer.Dispose() }
    if ($memory) { $buffer=$memory.GetBuffer();[Array]::Clear($buffer,0,$buffer.Length);$memory.Dispose() }
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    # Managed strings cannot be reliably zeroed; no claim of secret-free process memory.
    $material=$null
  }
}

function New-RideWirelessPrivateStream {
  param([string]$Path)
  New-RidePrivateFileStream -Path $Path
}

function New-RideWirelessProfileFile {
  <#
  .SYNOPSIS
    Generate a new private WLAN XML file from supplied settings.
  .PARAMETER ProfileName
    Exact profile identity, distinct from the network SSID. Maximum 255 characters.
  .PARAMETER Ssid
    SSID encoded as strict UTF-8, with a 1-32 byte limit. No character normalization.
  .PARAMETER SsidBytes
    Exact SSID bytes when UTF-8 text is not appropriate. Alternative to Ssid.
  .PARAMETER Security
    WPA2Personal uses AES with a supplied key; Open uses no encryption or key.
    Enterprise/EAP, WEP, WPA and WPA3 are not implemented by this generator.
  .PARAMETER Key
    SecureString containing an 8-63 printable ASCII passphrase or 64 hex digits.
    Obtain real values through Read-Host -AsSecureString or a local secret source.
  .PARAMETER ConnectionMode
    Manual by default; auto is explicit. Generation never connects or imports.
  .PARAMETER HiddenNetwork
    Write nonBroadcast true; default false. Does not initiate scanning.
  .PARAMETER OutputPath
    New .xml file under an existing local directory. No overwrite or shared path.
  .EXAMPLE
    New-RideWirelessProfileFile -ProfileName 'Office profile' -Ssid 'Office' -Key (Read-Host 'Wi-Fi key' -AsSecureString) -OutputPath C:\Private\wifi.xml
  .INPUTS
    None. Supply settings explicitly; no existing XML is required.
  .OUTPUTS
    PSCustomObject. Schema-1 file-generation result, without key, XML or key digest.
  .NOTES
    File DACL allows only the current user and SYSTEM, set at creation. XML contains
    an unencrypted key as required for import; ACL protection is not encryption.
    WhatIf creates no file. Native import, interface/scope selection and recovery
    are separate pending work; generation needs no WLAN adapter or elevation.
  #>
  [CmdletBinding(SupportsShouldProcess=$true,DefaultParameterSetName='Text')]
  param(
    [Parameter(Mandatory)][string]$ProfileName,
    [Parameter(Mandatory,ParameterSetName='Text')][string]$Ssid,
    [Parameter(Mandatory,ParameterSetName='Bytes')][byte[]]$SsidBytes,
    [ValidateSet('WPA2Personal','Open')][string]$Security='WPA2Personal',
    [Security.SecureString]$Key,
    [ValidateSet('manual','auto')][string]$ConnectionMode='manual',
    [switch]$HiddenNetwork,
    [Parameter(Mandatory)][string]$OutputPath
  )
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'WLAN profile generation is supported only on Windows.' }
  $path=[IO.Path]::GetFullPath($OutputPath)
  if ($path -notmatch '^[A-Za-z]:\\' -or $path.Substring(2).Contains(':') -or [IO.Path]::GetExtension($path) -ine '.xml') { throw 'Use a local drive path to a new .xml file; UNC, device and alternate-stream paths are not supported.' }
  if ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($path)).DriveType -eq [IO.DriveType]::Network) { throw 'Mapped network drives are not supported for private WLAN output.' }
  $parent=[IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($path))
  if (-not $parent.Exists) { throw 'Create the output parent directory explicitly.' }
  for ($node=$parent;$null -ne $node;$node=$node.Parent) {
    if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Output ancestors must not be reparse points.' }
  }
  if ([IO.File]::Exists($path) -or [IO.Directory]::Exists($path)) { throw 'Output already exists; choose a new file.' }
  if ($PSCmdlet.ParameterSetName -eq 'Text') {
    try { $SsidBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($Ssid) } catch { throw 'SSID is not valid Unicode text; use exact SsidBytes if appropriate.' }
  }
  $bytes=$null;$stream=$null
  try {
    $bytes=ConvertTo-RideWirelessProfileXml -ProfileName $ProfileName -SsidBytes $SsidBytes -Security $Security -Key $Key -ConnectionMode $ConnectionMode -HiddenNetwork ([bool]$HiddenNetwork)
    if ($PSCmdlet.ShouldProcess($path,'Create a private WLAN XML file from supplied settings; no import or connection')) {
      try { $stream=New-RideWirelessPrivateStream -Path $path;$stream.Write($bytes,0,$bytes.Length);$stream.Flush() }
      catch { throw 'Private WLAN file creation failed. Existing files are not overwritten. Review any new empty or private partial output before reuse.' }
      finally { if ($stream) { $stream.Dispose();$stream=$null } }
      [pscustomobject]@{SchemaVersion=1;Kind='WirelessProfileFile';Status='Generated';Path=$path;Security=$Security;ConnectionMode=$ConnectionMode;ContainsKey=($Security -eq 'WPA2Personal');Imported=$false;ConnectionVerified=$false;RecoverySupported=$false}
    }
  } finally { if ($null -ne $bytes) { [Array]::Clear($bytes,0,$bytes.Length) } }
}

Export-ModuleMember -Function New-RideWirelessProfileFile
