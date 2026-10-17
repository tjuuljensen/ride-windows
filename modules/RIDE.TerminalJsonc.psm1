<#
.SYNOPSIS
  Inspect and prepare reversible default-profile edits in supplied Terminal JSONC bytes.
.DESCRIPTION
  Pure in-memory preparation: reads no settings file, discovers no Terminal instance,
  launches nothing and writes nothing. A bounded parser retains source spans so only
  the root defaultProfile string or a new owned property fragment changes. Recovery
  preserves unrelated text or refuses conflicts. Declared profile identities do not
  prove installed, generated or launchable profiles. No operational handler uses this
  preparation contract yet; identity, file locking and native acceptance remain separate.
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
  Recovery: Supplied snapshot version 1; no file, account or instance binding is implied.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded JSONC inspection and pure field-edit/recovery proof.
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

Export-ModuleMember -Function Get-RideTerminalDefaultProfileDocument, New-RideTerminalDefaultProfilePatch, Restore-RideTerminalDefaultProfilePatch
