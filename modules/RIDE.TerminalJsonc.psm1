<#
.SYNOPSIS
  Inspect, apply and restore reversible default-profile edits in Terminal JSONC.
.DESCRIPTION
  Bounded JSONC preparation and guarded exact-file apply/restore. File operations require
  an explicit settings path and matching current computer/SID, hold an exclusive handle,
  save recovery bytes before mutation, honor ShouldProcess and verify readback. Recovery
  preserves unrelated text or refuses conflicts. Declared profile identities do not
  prove generated or launchable profiles. Current-user packaged-instance inventory is
  read-only; unpackaged/portable instances still require explicit paths. This remains
  outside the catalog pending native GUI and disposable-Windows acceptance.
.EXAMPLE
  Import-Module .\modules\RIDE.TerminalJsonc.psm1
  Get-Help New-RideTerminalDefaultProfilePatch -Full
.INPUTS
  None on import.
.OUTPUTS
  None on import. Exported functions return inspection or proposed byte records.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; UTF-8 with optional BOM.
  Prerequisites: Explicit supplied bytes, at most 1 MiB; explicit visible profile GUID.
  Recovery: Patch snapshot version 1 plus identity-bound file snapshot version 1; file ACLs are not captured.
  Version: 0.4.0.
  Changelog: 0.4.0: Connect verified packaged-instance selection to the guarded writer.
  0.3.0: Add read-only current-user packaged instance/path inventory.
  0.2.0: Add identity-bound exclusive file apply/restore with saved bytes.
  0.1.0: Add bounded JSONC inspection and pure field-edit/recovery proof.
.LINK
  ../docs/windows-terminal-profile.md
#>


$ErrorActionPreference = 'Stop'

function Initialize-RideTerminalJsoncParser {
  if ('Ride.TerminalJsonc.V1.Parser' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
namespace Ride.TerminalJsonc.V1 {
  public sealed class Node {
    public string Kind;
    public int Start, End;
    public string Value;
    public List<Property> Properties = new List<Property>();
    public List<Node> Items = new List<Node>();
  }
  public sealed class Property {
    public string Key;
    public int Start;
    public Node Value;
  }
  public sealed class Parser {
    private readonly string text;
    private int position, nodes;
    private Parser(string source) { text = source; }
    private Exception Invalid() { return new FormatException("Invalid or unsupported Terminal JSONC at character " + position + "."); }
    private void Trivia() {
      while (position < text.Length) {
        char c = text[position];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { position++; continue; }
        if (c != '/' || position + 1 >= text.Length) { return; }
        if (text[position + 1] == '/') {
          position += 2;
          while (position < text.Length && text[position] != '\r' && text[position] != '\n') { position++; }
        } else if (text[position + 1] == '*') {
          int end = text.IndexOf("*/", position + 2, StringComparison.Ordinal);
          if (end < 0) { throw Invalid(); }
          position = end + 2;
        } else { return; }
      }
    }
    private string Quoted() {
      if (position >= text.Length || text[position++] != '"') { throw Invalid(); }
      StringBuilder value = new StringBuilder();
      bool closed = false;
      while (position < text.Length) {
        char c = text[position++];
        if (c == '"') { closed = true; break; }
        if (c < 32) { throw Invalid(); }
        if (c != '\\') { value.Append(c); continue; }
        if (position >= text.Length) { throw Invalid(); }
        char escape = text[position++];
        switch (escape) {
          case '"': value.Append('"'); break;
          case '\\': value.Append('\\'); break;
          case '/': value.Append('/'); break;
          case 'b': value.Append('\b'); break;
          case 'f': value.Append('\f'); break;
          case 'n': value.Append('\n'); break;
          case 'r': value.Append('\r'); break;
          case 't': value.Append('\t'); break;
          case 'u':
            if (position + 4 > text.Length) { throw Invalid(); }
            string hex = text.Substring(position, 4);
            if (!Regex.IsMatch(hex, "\\A[0-9a-fA-F]{4}\\z")) { throw Invalid(); }
            value.Append((char)Convert.ToUInt16(hex, 16)); position += 4; break;
          default: throw Invalid();
        }
      }
      if (!closed) { throw Invalid(); }
      string result = value.ToString();
      for (int i = 0; i < result.Length; i++) {
        if (Char.IsHighSurrogate(result[i])) {
          if (i + 1 >= result.Length || !Char.IsLowSurrogate(result[++i])) { throw Invalid(); }
        } else if (Char.IsLowSurrogate(result[i])) { throw Invalid(); }
      }
      return result;
    }
    private Node Read(int depth) {
      if (depth > 64 || ++nodes > 32768) { throw new FormatException("Terminal JSONC nesting or node limit exceeded."); }
      Trivia();
      if (position >= text.Length) { throw Invalid(); }
      Node node = new Node(); node.Start = position;
      char c = text[position];
      if (c == '{') {
        node.Kind = "Object"; position++; Trivia();
        HashSet<string> keys = new HashSet<string>(StringComparer.Ordinal);
        if (position < text.Length && text[position] == '}') { position++; }
        else {
          while (true) {
            Trivia(); Property property = new Property(); property.Start = position; property.Key = Quoted();
            if (!keys.Add(property.Key)) { throw new FormatException("Duplicate JSONC property; refusing ambiguous edits."); }
            Trivia(); if (position >= text.Length || text[position++] != ':') { throw Invalid(); }
            property.Value = Read(depth + 1); node.Properties.Add(property); Trivia();
            if (position >= text.Length) { throw Invalid(); }
            if (text[position] == '}') { position++; break; }
            if (text[position++] != ',') { throw Invalid(); }
            Trivia(); if (position < text.Length && text[position] == '}') { position++; break; }
          }
        }
      } else if (c == '[') {
        node.Kind = "Array"; position++; Trivia();
        if (position < text.Length && text[position] == ']') { position++; }
        else {
          while (true) {
            node.Items.Add(Read(depth + 1)); Trivia();
            if (position >= text.Length) { throw Invalid(); }
            if (text[position] == ']') { position++; break; }
            if (text[position++] != ',') { throw Invalid(); }
            Trivia(); if (position < text.Length && text[position] == ']') { position++; break; }
          }
        }
      } else if (c == '"') { node.Kind = "String"; node.Value = Quoted(); }
      else {
        int start = position;
        while (position < text.Length && ",]} \t\r\n/".IndexOf(text[position]) < 0) { position++; }
        string token = text.Substring(start, position - start);
        if (token == "true" || token == "false") { node.Kind = "Boolean"; node.Value = token; }
        else if (token == "null") { node.Kind = "Null"; }
        else if (Regex.IsMatch(token, "\\A-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\\z")) { node.Kind = "Number"; node.Value = token; }
        else { throw Invalid(); }
      }
      node.End = position; return node;
    }
    public static Node Parse(string source) {
      if (source == null || source.Length > 1048576) { throw new FormatException("Terminal JSONC size limit exceeded."); }
      Parser parser = new Parser(source); Node root = parser.Read(0); parser.Trivia();
      if (parser.position != source.Length || root.Kind != "Object") { throw parser.Invalid(); }
      return root;
    }
  }
}
'@
}

function Read-RideTerminalJsoncBytes {
  param([byte[]] $Bytes)
  if (-not $Bytes -or $Bytes.Length -gt 1MB) { throw 'Terminal JSONC must contain 1 byte through 1 MiB.' }
  $offset = if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 239 -and $Bytes[1] -eq 187 -and $Bytes[2] -eq 191) { 3 } else { 0 }
  $codec = [Text.UTF8Encoding]::new($false, $true)
  try { $text = $codec.GetString($Bytes, $offset, $Bytes.Length - $offset) }
  catch { throw 'Terminal JSONC requires valid UTF-8; unsupported encodings are preserved without edits.' }
  Initialize-RideTerminalJsoncParser
  $root = [Ride.TerminalJsonc.V1.Parser]::Parse($text)
  [pscustomobject]@{ Text = $text; Root = $root; Bom = ($offset -eq 3); Codec = $codec }
}

function Get-RideTerminalJsoncProperty {
  param($Node, [string] $Name)
  if ($Node -and $Node.Kind -eq 'Object') { $Node.Properties | Where-Object { $_.Key -ceq $Name } }
}

function Get-RideTerminalDeclaredProfiles {
  param($Document)
  $profiles = Get-RideTerminalJsoncProperty $Document.Root 'profiles'
  if (-not $profiles) { return }
  if ($profiles.Value.Kind -notin @('Array','Object')) { throw 'Terminal profiles must be an object or legacy array.' }
  # Older direct arrays are inspected; no schema conversion is performed.
  $list = if ($profiles.Value.Kind -eq 'Array') { $profiles.Value } else { (Get-RideTerminalJsoncProperty $profiles.Value 'list').Value }
  if (-not $list) { return }
  if ($list.Kind -ne 'Array' -or $list.Items.Count -gt 4096) { throw 'Terminal declared profiles must be a bounded array.' }
  $defaults = Get-RideTerminalJsoncProperty $profiles.Value 'defaults'
  if ($defaults -and $defaults.Value.Kind -ne 'Object') { throw 'Terminal profile defaults must be an object.' }
  $defaultHidden = if ($defaults) { Get-RideTerminalJsoncProperty $defaults.Value 'hidden' } else { $null }
  if ($defaultHidden -and $defaultHidden.Value.Kind -ne 'Boolean') { throw 'Terminal default hidden flag must be Boolean.' }
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($item in $list.Items) {
    if ($item.Kind -ne 'Object') { throw 'Terminal profile entry must be an object.' }
    $guidProperty = Get-RideTerminalJsoncProperty $item 'guid'
    $nameProperty = Get-RideTerminalJsoncProperty $item 'name'
    $hiddenProperty = Get-RideTerminalJsoncProperty $item 'hidden'
    $sourceProperty = Get-RideTerminalJsoncProperty $item 'source'
    $id = $null
    if ($guidProperty) {
      if ($guidProperty.Value.Kind -ne 'String' -or $guidProperty.Value.Value -notmatch '^\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$') { throw 'Terminal declared profile has an unsupported GUID.' }
      $id = ([guid]$guidProperty.Value.Value).ToString('B')
      if (-not $seen.Add($id)) { throw 'Duplicate declared Terminal profile GUID; refusing ambiguous selection.' }
    }
    if ($nameProperty -and $nameProperty.Value.Kind -ne 'String') { throw 'Terminal profile name must be a string.' }
    if ($hiddenProperty -and $hiddenProperty.Value.Kind -ne 'Boolean') { throw 'Terminal profile hidden flag must be Boolean.' }
    if ($sourceProperty -and $sourceProperty.Value.Kind -ne 'String') { throw 'Terminal profile source must be a string.' }
    $hidden = if ($hiddenProperty) { $hiddenProperty.Value.Value -eq 'true' } else { [bool]($defaultHidden -and $defaultHidden.Value.Value -eq 'true') }
    [pscustomobject]@{ Id = $id; Name = $(if ($nameProperty) { $nameProperty.Value.Value } else { $null }); Hidden = $hidden; Source = $(if ($sourceProperty) { $sourceProperty.Value.Value } else { $null }); AvailabilityVerified = $false }
  }
}

function ConvertTo-RideTerminalJsoncBytes {
  param($Document, [string] $Text)
  $payload = $Document.Codec.GetBytes($Text)
  $result = if ($Document.Bom) { [byte[]](@(239,187,191) + @($payload)) } else { $payload }
  if ($result.Length -gt 1MB) { throw 'Proposed Terminal JSONC exceeds the 1 MiB limit.' }
  ,([byte[]]$result)
}

function Assert-RideTerminalPriorProfile {
  param($Profiles, [string] $Value)
  $match = @($Profiles | Where-Object { -not $_.Hidden -and (($_.Id -and [string]::Equals($_.Id, $Value, [StringComparison]::OrdinalIgnoreCase)) -or [string]::Equals($_.Name, $Value, [StringComparison]::Ordinal)) })
  if ($match.Count -ne 1) { throw 'Prior default profile is missing, hidden or ambiguous in the supplied declarations; recovery requires review.' }
}

function Get-RideTerminalDefaultProfileDocument {
  <#
  .SYNOPSIS
    Inspect supplied JSONC bytes without discovering or accessing a Terminal instance.
  .PARAMETER Bytes
    Explicit UTF-8 settings bytes, with optional BOM, at most 1 MiB.
  .EXAMPLE
    Get-RideTerminalDefaultProfileDocument -Bytes $copiedSettingsBytes
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Declared default/profile observations.
  .NOTES
    Declared profiles are not proof of installed/dynamic/launchable profiles. No writes.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][byte[]] $Bytes)
  $document = Read-RideTerminalJsoncBytes $Bytes
  $property = Get-RideTerminalJsoncProperty $document.Root 'defaultProfile'
  if ($property -and $property.Value.Kind -ne 'String') { throw 'Terminal root defaultProfile must be a string.' }
  [pscustomobject]@{
    SchemaVersion = 1; DefaultProfilePresent = [bool]$property
    DefaultProfile = $(if ($property) { $property.Value.Value } else { $null })
    Profiles = @(Get-RideTerminalDeclaredProfiles $document)
    AvailabilityVerified = $false; InstanceVerified = $false; MutationAuthorized = $false
  }
}

function Get-RideTerminalInstalledInstances {
  <#
  .SYNOPSIS
    Find current-user packaged Windows Terminal instances and inspect their settings paths.
  .DESCRIPTION
    Queries only packages registered to the current user for the documented Stable,
    Preview and Canary package names. It derives each package's own LocalState path,
    reads an existing settings.json if present and reports declared profiles only.
    It does not inspect other users, unpackaged/portable installations, dynamic profile
    availability, or launchability, and it never changes a file or package.
  .PARAMETER LocalAppDataPath
    Current user's LocalAppData root. Defaults to the current token's known folder.
  .PARAMETER AppxPackages
    Optional unverified package records for offline inspection/tests. Supplying records
    never reports an installed instance as verified. When omitted, Get-AppxPackage is
    queried for Microsoft.WindowsTerminal* in the current user's context.
  .EXAMPLE
    Get-RideTerminalInstalledInstances | Format-Table PackageName, Version, SettingsPath, SettingsFilePresent
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject records with package identity, exact settings path and declared profiles.
  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows. Read-only.
    Unpackaged and portable installations continue to use explicit operator-supplied paths.
  #>
  [CmdletBinding()]
  param(
    [string] $LocalAppDataPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData),
    [object[]] $AppxPackages
  )
  if ([string]::IsNullOrWhiteSpace($LocalAppDataPath)) { throw 'The current user LocalAppData path is unavailable.' }
  $localRoot = [IO.Path]::GetFullPath($LocalAppDataPath)
  if (-not (Test-Path -LiteralPath $localRoot -PathType Container)) { throw 'The current user LocalAppData directory does not exist.' }

  $liveInventory = -not $PSBoundParameters.ContainsKey('AppxPackages')
  if (-not $liveInventory) { $packages = @($AppxPackages) }
  else {
    if (-not (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) { throw 'Get-AppxPackage is unavailable; no packaged Terminal inventory was collected.' }
    $packages = @(Get-AppxPackage -Name 'Microsoft.WindowsTerminal*' -ErrorAction Stop)
  }

  $knownPackages = @{
    'Microsoft.WindowsTerminal' = 'Microsoft.WindowsTerminal_8wekyb3d8bbwe'
    'Microsoft.WindowsTerminalPreview' = 'Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe'
    'Microsoft.WindowsTerminalCanary' = 'Microsoft.WindowsTerminalCanary_8wekyb3d8bbwe'
  }
  $seenFamilies = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach ($package in $packages) {
    if (-not $package) { continue }
    $name = [string]$package.Name
    if (-not $knownPackages.ContainsKey($name)) { continue }
    $family = [string]$package.PackageFamilyName
    if (-not [string]::Equals($family, $knownPackages[$name], [StringComparison]::OrdinalIgnoreCase)) { throw "The registered package family for $name does not match the documented Windows Terminal identity." }
    if (-not $seenFamilies.Add($family)) { throw "More than one current-user package record was returned for $family." }

    $settingsPath = [IO.Path]::GetFullPath((Join-Path $localRoot (Join-Path (Join-Path 'Packages' $family) 'LocalState/settings.json')))
    $profiles = @(); $defaultProfile = $null; $settingsPresent = Test-Path -LiteralPath $settingsPath -PathType Leaf
    if ($settingsPresent) {
      $item = Get-Item -LiteralPath $settingsPath -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt 1MB) { throw "The settings file for $family is a reparse point or exceeds the 1 MiB inspection limit." }
      $document = Get-RideTerminalDefaultProfileDocument -Bytes ([IO.File]::ReadAllBytes($settingsPath))
      $profiles = @($document.Profiles)
      $defaultProfile = $document.DefaultProfile
    }
    [pscustomobject]@{
      PackageName = $name
      PackageFamilyName = $family
      PackageFullName = [string]$package.PackageFullName
      Version = [string]$package.Version
      SettingsPath = $settingsPath
      SettingsFilePresent = [bool]$settingsPresent
      DefaultProfile = $defaultProfile
      Profiles = $profiles
      InventorySource = if ($liveInventory) { 'CurrentUserAppx' } else { 'InjectedUnverified' }
      InstanceVerified = [bool]$liveInventory
      ProfileAvailabilityVerified = $false
      MutationAuthorized = $false
    }
  }
}

function New-RideTerminalDefaultProfilePatch {
  <#
  .SYNOPSIS
    Propose a narrow defaultProfile edit in memory with a reversible snapshot.
  .PARAMETER Bytes
    Explicit UTF-8 source bytes. No file is read or written.
  .PARAMETER ProfileId
    GUID of one explicitly declared, non-hidden profile in the supplied bytes.
    Completion uses those declarations only, not installed/dynamic profile discovery.
  .EXAMPLE
    New-RideTerminalDefaultProfilePatch -Bytes $copiedSettingsBytes -ProfileId $selectedGuid
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Proposed bytes and snapshot version 1.
  .NOTES
    Preparation only. An operational writer must independently bind instance/user/file,
    validate actual profile availability and detect concurrent edits before activation.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][byte[]] $Bytes, [Parameter(Mandatory)][string] $ProfileId)
  if ($ProfileId -notmatch '^\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}$') { throw 'Select a declared profile GUID in braces.' }
  $id = ([guid]$ProfileId).ToString('B')
  $document = Read-RideTerminalJsoncBytes $Bytes
  $profiles = @(Get-RideTerminalDeclaredProfiles $document)
  if (@($profiles | Where-Object { $_.Id -eq $id -and -not $_.Hidden }).Count -ne 1) { throw 'Selected profile GUID is not a visible declaration in these bytes.' }
  $property = Get-RideTerminalJsoncProperty $document.Root 'defaultProfile'
  $literal = '"' + $id + '"'
  $originalLiteral = $null; $fragment = $null; $prefixLength = 0
  if ($property) {
    if ($property.Value.Kind -ne 'String') { throw 'Terminal root defaultProfile must be a string.' }
    Assert-RideTerminalPriorProfile $profiles $property.Value.Value
    $originalLiteral = $document.Text.Substring($property.Value.Start, $property.Value.End - $property.Value.Start)
    if ([string]::Equals($property.Value.Value, $id, [StringComparison]::OrdinalIgnoreCase)) { $mode = 'NoChange'; $proposed = $document.Text }
    else { $mode = 'Replace'; $proposed = $document.Text.Substring(0, $property.Value.Start) + $literal + $document.Text.Substring($property.Value.End) }
  }
  else {
    $mode = 'Insert'
    $newline = if ($document.Text.Contains("`r`n")) { "`r`n" } elseif ($document.Text.Contains("`r")) { "`r" } else { "`n" }
    $prefix = $newline + '  '; $prefixLength = $prefix.Length
    $comma = if ($document.Root.Properties.Count) { ',' } else { '' }
    $fragment = $prefix + '"defaultProfile": ' + $literal + $comma + $newline
    $index = $document.Root.Start + 1
    $proposed = $document.Text.Substring(0, $index) + $fragment + $document.Text.Substring($index)
  }
  $proposedBytes = ConvertTo-RideTerminalJsoncBytes $document $proposed
  $null = Read-RideTerminalJsoncBytes $proposedBytes
  [pscustomobject]@{
    Changed = ($mode -ne 'NoChange'); Bytes = $proposedBytes; MutationAuthorized = $false
    Snapshot = [pscustomobject]@{
      SchemaVersion = 1; Mode = $mode; ProfileId = $id
      OriginalBase64 = [Convert]::ToBase64String($Bytes); ExpectedBase64 = [Convert]::ToBase64String($proposedBytes)
      OriginalLiteral = $originalLiteral; ExpectedLiteral = $literal; InsertedFragment = $fragment; PrefixLength = $prefixLength
    }
  }
}

function Restore-RideTerminalDefaultProfilePatch {
  <#
  .SYNOPSIS
    Propose recovery bytes for one prior in-memory patch, preserving unrelated edits.
  .PARAMETER Bytes
    Current supplied UTF-8 bytes. No live file is read or changed.
  .PARAMETER Snapshot
    Snapshot version 1 returned by New-RideTerminalDefaultProfilePatch.
  .EXAMPLE
    Restore-RideTerminalDefaultProfilePatch -Bytes $editedCopy -Snapshot $patch.Snapshot
  .INPUTS
    None.
  .OUTPUTS
    System.Management.Automation.PSCustomObject. Proposed recovered bytes only.
  .NOTES
    Validates original/expected byte relationships. Edited owned text, disappeared
    prior profiles and changed encoding refuse recovery; retain the snapshot for review.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][byte[]] $Bytes, [Parameter(Mandatory)] $Snapshot)
  if ($Snapshot.SchemaVersion -ne 1 -or $Snapshot.OriginalBase64.Length -gt 1398104 -or $Snapshot.ExpectedBase64.Length -gt 1398104) { throw 'Invalid Terminal patch snapshot.' }
  $original = [Convert]::FromBase64String([string]$Snapshot.OriginalBase64)
  $verified = New-RideTerminalDefaultProfilePatch $original ([string]$Snapshot.ProfileId)
  foreach ($name in @('Mode','ProfileId','OriginalBase64','ExpectedBase64','OriginalLiteral','ExpectedLiteral','InsertedFragment','PrefixLength')) {
    if ([string]$Snapshot.$name -cne [string]$verified.Snapshot.$name) { throw 'Terminal patch snapshot content mismatch.' }
  }
  $document = Read-RideTerminalJsoncBytes $Bytes
  $prior = Read-RideTerminalJsoncBytes $original
  if ($document.Bom -ne $prior.Bom) { throw 'Terminal JSONC encoding/BOM changed; review recovery.' }
  if ($Snapshot.Mode -eq 'NoChange') { return [pscustomobject]@{Changed=$false; Bytes=[byte[]]$Bytes.Clone(); MutationAuthorized=$false} }
  $property = Get-RideTerminalJsoncProperty $document.Root 'defaultProfile'
  if ($Snapshot.Mode -eq 'Replace') {
    $priorProperty = Get-RideTerminalJsoncProperty $prior.Root 'defaultProfile'
    Assert-RideTerminalPriorProfile @(Get-RideTerminalDeclaredProfiles $document) $priorProperty.Value.Value
    if (-not $property -or $property.Value.Kind -ne 'String') { throw 'Terminal defaultProfile was removed or changed; recovery conflict.' }
    $literal = $document.Text.Substring($property.Value.Start, $property.Value.End - $property.Value.Start)
    if ($literal -ceq $Snapshot.OriginalLiteral) { return [pscustomobject]@{Changed=$false; Bytes=[byte[]]$Bytes.Clone(); MutationAuthorized=$false} }
    if ($literal -cne $Snapshot.ExpectedLiteral) { throw 'Terminal defaultProfile was edited; recovery conflict.' }
    $text = $document.Text.Substring(0,$property.Value.Start) + $Snapshot.OriginalLiteral + $document.Text.Substring($property.Value.End)
  }
  else {
    if (-not $property) { return [pscustomobject]@{Changed=$false; Bytes=[byte[]]$Bytes.Clone(); MutationAuthorized=$false} }
    $start = $property.Start - [int]$Snapshot.PrefixLength
    $length = ([string]$Snapshot.InsertedFragment).Length
    if ($start -lt 0 -or $start + $length -gt $document.Text.Length -or $document.Text.Substring($start,$length) -cne $Snapshot.InsertedFragment) { throw 'Inserted Terminal property was edited; recovery conflict.' }
    $text = $document.Text.Remove($start,$length)
  }
  $restored = ConvertTo-RideTerminalJsoncBytes $document $text
  $null = Read-RideTerminalJsoncBytes $restored
  [pscustomobject]@{Changed=$true; Bytes=$restored; MutationAuthorized=$false}
}

function Get-RideTerminalFileIdentity {
  param([string] $ExpectedComputerName, [string] $ExpectedUserSid, [string] $SettingsPath)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Terminal settings file operations are supported only on Windows.' }
  if ([string]::IsNullOrWhiteSpace($ExpectedComputerName) -or $ExpectedComputerName -ine $env:COMPUTERNAME) { throw 'Expected computer name does not match the current computer.' }
  $actualSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ([string]::IsNullOrWhiteSpace($ExpectedUserSid) -or $ExpectedUserSid -cne $actualSid) { throw 'Expected SID does not match the current user.' }
  if ([string]::IsNullOrWhiteSpace($SettingsPath) -or -not [IO.Path]::IsPathRooted($SettingsPath)) { throw 'Supply an exact absolute Terminal settings.json path.' }
  $path = [IO.Path]::GetFullPath($SettingsPath)
  if ([IO.Path]::GetFileName($path) -cne 'settings.json') { throw 'The selected file must be named settings.json.' }
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (-not $item -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Terminal settings path must be an existing regular file, not a reparse point.' }
  [pscustomobject]@{ComputerName=$env:COMPUTERNAME;UserSid=$actualSid;Path=$path;Length=[long]$item.Length}
}

function Read-RideTerminalLockedBytes {
  param([IO.FileStream] $Stream)
  if ($Stream.Length -lt 1 -or $Stream.Length -gt 1MB) { throw 'Terminal settings file must contain 1 byte through 1 MiB.' }
  $Stream.Position = 0
  $bytes = [byte[]]::new([int]$Stream.Length)
  $offset = 0
  while ($offset -lt $bytes.Length) {
    $read = $Stream.Read($bytes, $offset, $bytes.Length - $offset)
    if ($read -le 0) { throw 'Terminal settings file changed during the exclusive read.' }
    $offset += $read
  }
  ,$bytes
}

function Write-RideTerminalLockedBytes {
  param([IO.FileStream] $Stream, [byte[]] $Bytes, [byte[]] $RollbackBytes)
  try {
    $Stream.Position = 0
    $Stream.SetLength(0)
    $Stream.Write($Bytes, 0, $Bytes.Length)
    $Stream.Flush($true)
    $actual = Read-RideTerminalLockedBytes $Stream
    if ([Convert]::ToBase64String($actual) -cne [Convert]::ToBase64String($Bytes)) { throw 'Terminal settings readback did not match the proposed bytes.' }
  } catch {
    $writeError = $_
    try {
      $Stream.Position = 0
      $Stream.SetLength(0)
      $Stream.Write($RollbackBytes, 0, $RollbackBytes.Length)
      $Stream.Flush($true)
      $actualRollback = Read-RideTerminalLockedBytes $Stream
      if ([Convert]::ToBase64String($actualRollback) -cne [Convert]::ToBase64String($RollbackBytes)) { throw 'Rollback readback mismatch.' }
    } catch { throw "Terminal settings write failed and automatic byte rollback also failed; retain the saved snapshot. Write error: $($writeError.Exception.Message) Rollback error: $($_.Exception.Message)" }
    throw "Terminal settings write failed; original bytes were restored. $($writeError.Exception.Message)"
  }
}

function Get-RideTerminalSnapshotPath {
  param([string] $RequestedPath)
  if ($RequestedPath) {
    if (-not [IO.Path]::IsPathRooted($RequestedPath)) { throw 'Snapshot path must be absolute.' }
    $path = [IO.Path]::GetFullPath($RequestedPath)
    $parent = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Snapshot parent directory must already exist.' }
    if (Test-Path -LiteralPath $path) { throw 'Snapshot path already exists; refusing to overwrite recovery data.' }
    return $path
  }
  $root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'RIDE/State/TerminalProfiles'
  New-Item -ItemType Directory -Path $root -Force | Out-Null
  Join-Path $root ([guid]::NewGuid().ToString('N') + '.json')
}

function Save-RideTerminalFileSnapshot {
  param([string] $Path, $Record)
  $json = ConvertTo-Json -InputObject $Record -Depth 12 -Compress
  $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json)
  if ($bytes.Length -gt 4MB) { throw 'Terminal recovery snapshot exceeds 4 MiB.' }
  $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
  finally { $stream.Dispose() }
}

function Read-RideTerminalFileSnapshot {
  param([string] $Path)
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
  try {
    if ($stream.Length -lt 1 -or $stream.Length -gt 4MB) { throw 'Terminal recovery snapshot size is invalid.' }
    $bytes = [byte[]]::new([int]$stream.Length)
    $offset = 0
    while ($offset -lt $bytes.Length) {
      $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
      if ($read -le 0) { throw 'Terminal recovery snapshot changed during read.' }
      $offset += $read
    }
    ,$bytes
  } finally { $stream.Dispose() }
}

function Set-RideTerminalDefaultProfileFile {
  <#
  .SYNOPSIS
    Apply a guarded Terminal default-profile edit to one explicitly selected file.
  .DESCRIPTION
    Binds the path to the current computer and user, takes an exclusive file handle,
    persists original/expected bytes before writing, and verifies durable readback.
    Static declarations do not prove that a generated profile is available or launchable.
  .PARAMETER SettingsPath
    Exact absolute settings.json path for the Terminal instance selected by the operator.
  .PARAMETER ExpectedComputerName
    Computer identity recorded by a prior current-context observation.
  .PARAMETER ExpectedUserSid
    SID of the intended signed-in user; it must be the current token's SID.
  .PARAMETER ProfileId
    GUID of a visible profile declared in the locked settings bytes.
  .PARAMETER SnapshotPath
    Optional new snapshot path for isolated tests. The production default is the
    current user's RIDE state directory; existing snapshot files are never overwritten.
  .EXAMPLE
    Set-RideTerminalDefaultProfileFile -SettingsPath $selectedPath -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -ProfileId $profileId -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Changed state, snapshot identity and readback status; no settings bytes.
  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Recovery: Restore-RideTerminalDefaultProfileFile uses the recorded patch and refuses conflicts.
    File ACLs are not changed or captured. A disposable VM must prove profile launch behavior.
  #>
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param([Parameter(Mandatory)][string] $SettingsPath,
    [Parameter(Mandatory)][string] $ExpectedComputerName,
    [Parameter(Mandatory)][string] $ExpectedUserSid,
    [Parameter(Mandatory)][string] $ProfileId,
    [string] $SnapshotPath)
  $context = Get-RideTerminalFileIdentity $ExpectedComputerName $ExpectedUserSid $SettingsPath
  $stream = [IO.File]::Open($context.Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    $before = Read-RideTerminalLockedBytes $stream
    $patch = New-RideTerminalDefaultProfilePatch -Bytes $before -ProfileId $ProfileId
    if (-not $patch.Changed) { return [pscustomobject]@{Applied=$false;Changed=$false;SnapshotPath=$null;ComputerName=$context.ComputerName;UserSid=$context.UserSid;SettingsPath=$context.Path;ReadbackVerified=$true;ProfileAvailabilityVerified=$false} }
    if (-not $PSCmdlet.ShouldProcess($context.Path, "Set Terminal default profile to $ProfileId")) { return [pscustomobject]@{Applied=$false;Changed=$true;SnapshotPath=$null;ComputerName=$context.ComputerName;UserSid=$context.UserSid;SettingsPath=$context.Path;ReadbackVerified=$false;ProfileAvailabilityVerified=$false} }
    $snapshotPathResolved = Get-RideTerminalSnapshotPath $SnapshotPath
    $snapshot = [pscustomobject]@{SchemaVersion=1;CreatedAtUtc=[DateTime]::UtcNow.ToString('o');ComputerName=$context.ComputerName;UserSid=$context.UserSid;SettingsPath=$context.Path;OriginalSha256=(Get-RideTerminalByteHash $before);ExpectedSha256=(Get-RideTerminalByteHash $patch.Bytes);Patch=$patch.Snapshot}
    Save-RideTerminalFileSnapshot $snapshotPathResolved $snapshot
    Write-RideTerminalLockedBytes $stream $patch.Bytes $before
    [pscustomobject]@{Applied=$true;Changed=$true;SnapshotPath=$snapshotPathResolved;ComputerName=$context.ComputerName;UserSid=$context.UserSid;SettingsPath=$context.Path;ReadbackVerified=$true;ProfileAvailabilityVerified=$false}
  } finally { $stream.Dispose() }
}

function Set-RideTerminalInstalledInstanceDefaultProfile {
  <#
  .SYNOPSIS
    Apply a guarded default-profile edit to one live current-user packaged Terminal instance.
  .DESCRIPTION
    Requeries current-user AppX registrations, selects exactly one documented Stable,
    Preview or Canary instance by package name, and passes its derived existing settings
    path to the identity-bound file writer. Synthetic package records cannot authorize
    a write. A declared profile is not evidence that it is currently available or
    launchable; disposable Windows acceptance remains required.
  .PARAMETER PackageName
    Exact documented package identity: Stable, Preview or Canary.
  .PARAMETER ExpectedComputerName
    Computer identity recorded by a prior current-context observation.
  .PARAMETER ExpectedUserSid
    SID of the intended signed-in user; it must be the current token's SID.
  .PARAMETER ProfileId
    GUID of a visible profile declared in the selected instance's settings file.
  .PARAMETER SnapshotPath
    Optional new snapshot path for isolated tests. Existing snapshots are never overwritten.
  .PARAMETER LocalAppDataPath
    Optional LocalAppData root used for packaged-path resolution; defaults to the current user.
  .EXAMPLE
    Set-RideTerminalInstalledInstanceDefaultProfile -PackageName Microsoft.WindowsTerminal -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -ProfileId $profileId -WhatIf
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Selected package identity, file mutation and recovery status.
  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows. Uses the current user's live AppX registrations.
    Recovery: Restore-RideTerminalDefaultProfileFile with the returned SnapshotPath.
  #>
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param(
    [Parameter(Mandatory)][ValidateSet('Microsoft.WindowsTerminal','Microsoft.WindowsTerminalPreview','Microsoft.WindowsTerminalCanary')][string] $PackageName,
    [Parameter(Mandatory)][string] $ExpectedComputerName,
    [Parameter(Mandatory)][string] $ExpectedUserSid,
    [Parameter(Mandatory)][string] $ProfileId,
    [string] $SnapshotPath,
    [string] $LocalAppDataPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
  )

  $matches = @(Get-RideTerminalInstalledInstances -LocalAppDataPath $LocalAppDataPath | Where-Object { [string]::Equals([string]$_.PackageName, $PackageName, [StringComparison]::Ordinal) })
  if ($matches.Count -ne 1) { throw "Expected exactly one current-user $PackageName registration; found $($matches.Count)." }
  $instance = $matches[0]
  if ($instance.InventorySource -cne 'CurrentUserAppx' -or -not $instance.InstanceVerified) { throw 'Only a live current-user AppX inventory can authorize packaged-instance selection.' }
  if (-not $instance.SettingsFilePresent -or -not (Test-Path -LiteralPath $instance.SettingsPath -PathType Leaf)) { throw "The selected $PackageName instance has no existing settings.json file; this command does not create it." }
  $context = Get-RideTerminalFileIdentity $ExpectedComputerName $ExpectedUserSid $instance.SettingsPath

  # Validate the selected profile against current bytes before prompting; the guarded
  # writer repeats validation while holding its exclusive handle before committing.
  $currentBytes = [IO.File]::ReadAllBytes($context.Path)
  $proposal = New-RideTerminalDefaultProfilePatch -Bytes $currentBytes -ProfileId $ProfileId
  if (-not $proposal.Changed) {
    $result = Set-RideTerminalDefaultProfileFile -SettingsPath $context.Path -ExpectedComputerName $ExpectedComputerName -ExpectedUserSid $ExpectedUserSid -ProfileId $ProfileId -SnapshotPath $SnapshotPath -Confirm:$false
  } elseif ($PSCmdlet.ShouldProcess($context.Path, "Set $PackageName default profile to $ProfileId")) {
    $result = Set-RideTerminalDefaultProfileFile -SettingsPath $context.Path -ExpectedComputerName $ExpectedComputerName -ExpectedUserSid $ExpectedUserSid -ProfileId $ProfileId -SnapshotPath $SnapshotPath -Confirm:$false
  } else {
    return [pscustomobject]@{
      PackageName = $instance.PackageName; PackageFullName = $instance.PackageFullName
      InstanceVerified = $true; ProfileAvailabilityVerified = $false
      Applied = $false; Changed = $true; SnapshotPath = $null
      ComputerName = $env:COMPUTERNAME; UserSid = $ExpectedUserSid
      SettingsPath = $context.Path; ReadbackVerified = $false
    }
  }
  [pscustomobject]@{
    PackageName = $instance.PackageName; PackageFullName = $instance.PackageFullName
    InstanceVerified = $true; ProfileAvailabilityVerified = $false
    Applied = $result.Applied; Changed = $result.Changed; SnapshotPath = $result.SnapshotPath
    ComputerName = $result.ComputerName; UserSid = $result.UserSid
    SettingsPath = $result.SettingsPath; ReadbackVerified = $result.ReadbackVerified
  }
}

function Get-RideTerminalByteHash {
  param([byte[]] $Bytes)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
  finally { $sha.Dispose() }
}

function Restore-RideTerminalDefaultProfileFile {
  <#
  .SYNOPSIS
    Restore one saved Terminal default-profile edit under an exclusive file lock.
  .DESCRIPTION
    Reconstructs and validates the original patch from the snapshot, preserves unrelated
    edits, refuses identity/path/owned-value conflicts and verifies readback.
  .PARAMETER SettingsPath
    Exact settings.json path recorded by Set-RideTerminalDefaultProfileFile.
  .PARAMETER ExpectedComputerName
    Expected current computer identity from a fresh observation.
  .PARAMETER ExpectedUserSid
    Expected current user SID from a fresh observation.
  .PARAMETER SnapshotPath
    Existing recovery snapshot created by the apply command.
  .EXAMPLE
    Restore-RideTerminalDefaultProfileFile -SettingsPath $selectedPath -ExpectedComputerName $env:COMPUTERNAME -ExpectedUserSid $sid -SnapshotPath $snapshot
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Change and readback status; no settings bytes.
  .NOTES
    Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows. Snapshot is retained after restore.
  #>
  [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
  param([Parameter(Mandatory)][string] $SettingsPath,
    [Parameter(Mandatory)][string] $ExpectedComputerName,
    [Parameter(Mandatory)][string] $ExpectedUserSid,
    [Parameter(Mandatory)][string] $SnapshotPath)
  $context = Get-RideTerminalFileIdentity $ExpectedComputerName $ExpectedUserSid $SettingsPath
  $snapshotFullPath = [IO.Path]::GetFullPath($SnapshotPath)
  if (-not (Test-Path -LiteralPath $snapshotFullPath -PathType Leaf)) { throw 'Terminal recovery snapshot is missing.' }
  $snapshotItem = Get-Item -LiteralPath $snapshotFullPath -Force
  if (($snapshotItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $snapshotItem.Length -gt 4MB) { throw 'Terminal recovery snapshot path or size is invalid.' }
  $record = [Text.Encoding]::UTF8.GetString((Read-RideTerminalFileSnapshot $snapshotFullPath)) | ConvertFrom-Json -ErrorAction Stop
  if ($record.SchemaVersion -ne 1 -or $record.ComputerName -ine $context.ComputerName -or $record.UserSid -cne $context.UserSid -or -not [string]::Equals([string]$record.SettingsPath, $context.Path, [StringComparison]::OrdinalIgnoreCase)) { throw 'Terminal recovery snapshot belongs to another identity or settings path.' }
  $stream = [IO.File]::Open($context.Path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
  try {
    $current = Read-RideTerminalLockedBytes $stream
    $snapshotOriginal = [Convert]::FromBase64String([string]$record.Patch.OriginalBase64)
    $snapshotExpected = [Convert]::FromBase64String([string]$record.Patch.ExpectedBase64)
    if ((Get-RideTerminalByteHash $snapshotOriginal) -cne $record.OriginalSha256 -or (Get-RideTerminalByteHash $snapshotExpected) -cne $record.ExpectedSha256) { throw 'Terminal recovery snapshot byte hash is invalid.' }
    $proposal = Restore-RideTerminalDefaultProfilePatch -Bytes $current -Snapshot $record.Patch
    if (-not $proposal.Changed) { return [pscustomobject]@{Restored=$false;Changed=$false;SnapshotPath=$snapshotFullPath;SettingsPath=$context.Path;ReadbackVerified=$true} }
    if (-not $PSCmdlet.ShouldProcess($context.Path, 'Restore captured Terminal default profile')) { return [pscustomobject]@{Restored=$false;Changed=$true;SnapshotPath=$snapshotFullPath;SettingsPath=$context.Path;ReadbackVerified=$false} }
    Write-RideTerminalLockedBytes $stream $proposal.Bytes $current
    [pscustomobject]@{Restored=$true;Changed=$true;SnapshotPath=$snapshotFullPath;SettingsPath=$context.Path;ReadbackVerified=$true}
  } finally { $stream.Dispose() }
}

Register-ArgumentCompleter -CommandName New-RideTerminalDefaultProfilePatch -ParameterName ProfileId -ScriptBlock {
  param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
  try {
    if ($fakeBoundParameters.Bytes -isnot [byte[]]) { return }
    $document = Get-RideTerminalDefaultProfileDocument -Bytes $fakeBoundParameters.Bytes
    $prefix = ([string]$wordToComplete).Trim("'",'"')
    foreach ($profile in $document.Profiles | Where-Object { $_.Id -and -not $_.Hidden } | Sort-Object Id -Unique) {
      if ($profile.Id.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { [Management.Automation.CompletionResult]::new(("'"+$profile.Id+"'"),$profile.Id,'ParameterValue',($profile.Name+' (declared only)')) }
    }
  } catch { }
}

Export-ModuleMember -Function Get-RideTerminalDefaultProfileDocument, Get-RideTerminalInstalledInstances, New-RideTerminalDefaultProfilePatch, Restore-RideTerminalDefaultProfilePatch, Set-RideTerminalDefaultProfileFile, Set-RideTerminalInstalledInstanceDefaultProfile, Restore-RideTerminalDefaultProfileFile
