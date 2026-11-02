<#
.SYNOPSIS
  Inspect bounded single-face TrueType source identities without loading fonts.
.DESCRIPTION
  Reads the OpenType name table and SHA-256 from one stable file read. It does
  not register, load, render or install fonts. Collection/CFF fonts are refused.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7.
  Input: Local .ttf file, at most 16 MiB, with unambiguous Windows English names.
  This is metadata validation, not verification of every glyph/table or a license review.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded TrueType naming/source identity for machine-font lifecycle.
.LINK
  https://learn.microsoft.com/en-us/typography/opentype/spec/name
#>
$ErrorActionPreference='Stop'

function Initialize-RideTrueTypeReader {
  if('Ride.FontFilesV1.Metadata' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Text;
namespace Ride.FontFilesV1 {
  public sealed class Metadata {
    public string Family {get;private set;} public string Subfamily {get;private set;}
    public string FullName {get;private set;} public string PostScriptName {get;private set;}
    static void Bound(byte[] b,long o,long n) {if(o<0||n<0||o>b.Length||n>b.Length-o)throw new InvalidOperationException("TrueType range is outside the file.");}
    static ushort U16(byte[] b,long o) {Bound(b,o,2);return (ushort)((b[(int)o]<<8)|b[(int)o+1]);}
    static uint U32(byte[] b,long o) {Bound(b,o,4);return ((uint)b[(int)o]<<24)|((uint)b[(int)o+1]<<16)|((uint)b[(int)o+2]<<8)|b[(int)o+3];}
    public static Metadata Read(byte[] b) {
      if(b==null||b.Length<12||b.Length>16777216||U32(b,0)!=0x00010000)throw new InvalidOperationException("A bounded single-face TrueType font is required.");
      int count=U16(b,4);if(count<1||count>256)throw new InvalidOperationException("Invalid TrueType table count.");
      Bound(b,12,count*16L);long name=-1,length=0;var tags=new HashSet<string>(StringComparer.Ordinal);
      for(int i=0;i<count;i++) {long row=12+i*16L;string tag=Encoding.ASCII.GetString(b,(int)row,4);if(!tags.Add(tag))throw new InvalidOperationException("Duplicate TrueType table.");
        long offset=U32(b,row+8),size=U32(b,row+12);Bound(b,offset,size);
        if(size>0&&offset<12+count*16L)throw new InvalidOperationException("TrueType table overlaps its directory.");
        if(tag=="name"){name=offset;length=size;}
      }
      if(name<0||length<6)throw new InvalidOperationException("TrueType naming table is missing.");
      int format=U16(b,name),records=U16(b,name+2),storage=U16(b,name+4);
      if(format!=0||records<1||records>4096||6+records*12L>length||storage<6+records*12L||storage>length)throw new InvalidOperationException("Unsupported or malformed TrueType naming table.");
      var names=new Dictionary<int,string>();var decoder=new UnicodeEncoding(true,false,true);
      for(int i=0;i<records;i++){long row=name+6+i*12L;int platform=U16(b,row),encoding=U16(b,row+2),language=U16(b,row+4),id=U16(b,row+6),size=U16(b,row+8),offset=U16(b,row+10);
        if(storage+(long)offset+size>length)throw new InvalidOperationException("TrueType name string exceeds its table.");
        if(platform!=3||(encoding!=1&&encoding!=10)||language!=0x0409||(id!=1&&id!=2&&id!=4&&id!=6))continue;
        if(size<2||size>1024||size%2!=0)throw new InvalidOperationException("Invalid Windows font name size.");
        string value=decoder.GetString(b,(int)(name+storage+offset),size);
        if(String.IsNullOrWhiteSpace(value)||value.Length>255||value.IndexOf('\0')>=0)throw new InvalidOperationException("Invalid Windows font identity.");
        foreach(char c in value)if(Char.IsControl(c))throw new InvalidOperationException("Font identity contains control characters.");
        string previous;if(names.TryGetValue(id,out previous)&&previous!=value)throw new InvalidOperationException("Ambiguous Windows English font identity.");names[id]=value;
      }
      foreach(int id in new[]{1,2,4,6})if(!names.ContainsKey(id))throw new InvalidOperationException("Required Windows English font identity is missing.");
      return new Metadata{Family=names[1],Subfamily=names[2],FullName=names[4],PostScriptName=names[6]};
    }
  }
}
'@ -ErrorAction Stop
}

function Read-RideFontSourceBytes {
  <#
  .SYNOPSIS
    Read a bounded local font/manifest/license source without changing it.
  .PARAMETER Path
    Existing ordinary local file; network paths and reparse ancestors refuse.
  .PARAMETER MaximumBytes
    Caller-selected bound, at most 16 MiB.
  .OUTPUTS
    Byte array for metadata validation or recovery capture, not an installed font.
  .NOTES
    Source reader shared by font metadata and lifecycle commands; no native font calls.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path,[ValidateRange(1,16777216)][int]$MaximumBytes=16777216)
  if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Font sources require native Windows.'}
  $full=[IO.Path]::GetFullPath($Path)
  if($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':') -or [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)).DriveType -eq [IO.DriveType]::Network){throw 'Font sources require a local path without alternate streams.'}
  $item=[IO.FileInfo]::new($full)
  if(-not $item.Exists -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Font source must be an existing ordinary file.'}
  for($node=$item.Directory;$null -ne $node;$node=$node.Parent){if($node.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Font source ancestors must not be reparse points.'}}
  $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    if($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes){throw 'Font source is empty or exceeds its size bound.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$n=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -eq 0){throw 'Font source ended during reading.'};$offset+=$n}
    ,$bytes
  }finally{$stream.Dispose()}
}

function Get-RideTrueTypeMetadata {
  <#
  .SYNOPSIS
    Return a font's exact source hash and Windows naming-table identities.
  .PARAMETER Path
    Explicit local single-face .ttf path. No glob, reparse or network source.
  .PARAMETER ExpectedSha256
    Optional exact expected SHA-256; mismatch refuses before metadata is returned.
  .EXAMPLE
    Get-RideTrueTypeMetadata -Path C:\Fonts\Example-Regular.ttf
  .INPUTS
    None.
  .OUTPUTS
    Schema-1 source metadata, without payload bytes or system font changes.
  .NOTES
    Read-only. Names come from Windows English records, never the filename.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path,[ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256)
  if([IO.Path]::GetExtension($Path) -ine '.ttf'){throw 'Only single-face .ttf input is currently implemented.'}
  $bytes=Read-RideFontSourceBytes $Path
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')}finally{$sha.Dispose()}
  if($ExpectedSha256 -and $hash -ine $ExpectedSha256){throw 'Font source hash differs from the selected input.'}
  Initialize-RideTrueTypeReader
  $metadata=[Ride.FontFilesV1.Metadata]::Read($bytes)
  [pscustomobject]@{SchemaVersion=1;Path=[IO.Path]::GetFullPath($Path);FileName=[IO.Path]::GetFileName($Path);Bytes=$bytes.Length;Sha256=$hash;Family=$metadata.Family;Subfamily=$metadata.Subfamily;FullName=$metadata.FullName;PostScriptName=$metadata.PostScriptName;RegistryName=$metadata.FullName+' (TrueType)';FontLoadPerformed=$false;InstallationPerformed=$false}
}

Export-ModuleMember -Function Get-RideTrueTypeMetadata,Read-RideFontSourceBytes
