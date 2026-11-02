<#
.SYNOPSIS
  Validate bounded local PNG inputs without changing images or Windows settings.
.DESCRIPTION
  Reads one stable byte snapshot, checks its expected SHA-256, static PNG envelope
  and dimensions, then validates decoding with Windows GDI+. No file is rewritten.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7.
  Limits: Static PNG only; 16 MiB, 8192 pixels per axis, 32 million pixels.
  This source gate does not establish wallpaper or lock-screen policy acceptance.
  Version: 0.1.0.
  Changelog: 0.1.0: Add bounded image inputs for disposable image lifecycle tests.
.LINK
  https://www.w3.org/TR/png-3/
#>
$ErrorActionPreference='Stop'

function Initialize-RidePngEnvelopeReader {
  if('Ride.ImageFilesV1.Envelope' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Text;
namespace Ride.ImageFilesV1 {
  public sealed class Envelope {
    public int Width {get;private set;} public int Height {get;private set;}
    static uint U32(byte[] b,int o) {return ((uint)b[o]<<24)|((uint)b[o+1]<<16)|((uint)b[o+2]<<8)|b[o+3];}
    static uint Crc(byte[] b,int start,int count) {
      uint crc=0xffffffff;
      for(int i=start;i<start+count;i++) {crc^=b[i];for(int bit=0;bit<8;bit++)crc=(crc&1)!=0 ? (crc>>1)^0xedb88320 : crc>>1;}
      return crc^0xffffffff;
    }
    static void ValidateData(byte[] data,int width,int height,int depth,int color,int interlace) {
      if(data.Length<6||(data[0]&15)!=8||(data[0]>>4)>7||((data[0]<<8)|data[1])%31!=0||(data[1]&32)!=0)
        throw new InvalidOperationException("PNG compressed data header is invalid.");
      int channels=color==2?3:color==4?2:color==6?4:1;
      var rows=new List<int>();
      int[] xs={0,4,0,2,0,1,0},ys={0,0,4,0,2,0,1},dx={8,8,4,4,2,2,1},dy={8,8,8,4,4,2,2};
      for(int pass=0;pass<(interlace==0?1:7);pass++) {
        int w=interlace==0?width:Math.Max(0,(width-xs[pass]+dx[pass]-1)/dx[pass]);
        int h=interlace==0?height:Math.Max(0,(height-ys[pass]+dy[pass]-1)/dy[pass]);
        if(w==0||h==0)continue;
        int size=(w*channels*depth+7)/8+1;
        for(int row=0;row<h;row++)rows.Add(size);
      }
      int rowIndex=0,column=0;uint a=1,b=0;byte[] buffer=new byte[16384];
      using(var input=new MemoryStream(data,2,data.Length-6,false))
      using(var inflater=new DeflateStream(input,CompressionMode.Decompress)) {
        int count;
        while((count=inflater.Read(buffer,0,buffer.Length))>0) {
          for(int i=0;i<count;i++) {
            if(rowIndex>=rows.Count)throw new InvalidOperationException("PNG inflated data exceeds its dimensions.");
            if(column==0&&buffer[i]>4)throw new InvalidOperationException("PNG scanline filter is invalid.");
            a=(a+buffer[i])%65521;b=(b+a)%65521;
            if(++column==rows[rowIndex]){rowIndex++;column=0;}
          }
        }
      }
      if(rowIndex!=rows.Count||column!=0)throw new InvalidOperationException("PNG inflated data is incomplete.");
      if(((b<<16)|a)!=U32(data,data.Length-4))throw new InvalidOperationException("PNG inflated data checksum differs.");
    }
    public static Envelope Read(byte[] b) {
      byte[] signature={137,80,78,71,13,10,26,10};
      if(b==null||b.Length<57||b.Length>16777216)throw new InvalidOperationException("PNG byte length is outside the supported bound.");
      for(int i=0;i<8;i++)if(b[i]!=signature[i])throw new InvalidOperationException("PNG signature is invalid.");
      int offset=8,width=0,height=0,depth=0,color=0,interlace=0,chunks=0;bool data=false,dataEnded=false,palette=false;
      using(var compressed=new MemoryStream()) {
      while(offset<b.Length) {
        if(++chunks>65536||b.Length-offset<12)throw new InvalidOperationException("PNG chunk envelope is incomplete or excessive.");
        uint rawLength=U32(b,offset);
        if(rawLength>(uint)(b.Length-offset-12))throw new InvalidOperationException("PNG chunk exceeds the file.");
        int length=(int)rawLength;
        for(int i=offset+4;i<offset+8;i++)if(!((b[i]>=65&&b[i]<=90)||(b[i]>=97&&b[i]<=122)))throw new InvalidOperationException("PNG chunk type is invalid.");
        if((b[offset+6]&32)!=0)throw new InvalidOperationException("PNG reserved chunk bit is invalid.");
        string type=Encoding.ASCII.GetString(b,offset+4,4);
        if(Crc(b,offset+4,length+4)!=U32(b,offset+8+length))throw new InvalidOperationException("PNG chunk CRC differs.");
        if(chunks==1&&type!="IHDR")throw new InvalidOperationException("PNG header must be first.");
        if(type=="IHDR") {
          if(chunks!=1||length!=13)throw new InvalidOperationException("PNG header is duplicated or malformed.");
          uint w=U32(b,offset+8),h=U32(b,offset+12);
          if(w==0||h==0||w>8192||h>8192||(ulong)w*h>32000000)throw new InvalidOperationException("PNG dimensions exceed the supported bound.");
          width=(int)w;height=(int)h;depth=b[offset+16];color=b[offset+17];
          bool validDepth=(color==0&&(depth==1||depth==2||depth==4||depth==8||depth==16))||
            (color==3&&(depth==1||depth==2||depth==4||depth==8))||
            ((color==2||color==4||color==6)&&(depth==8||depth==16));
          if(!validDepth||b[offset+18]!=0||b[offset+19]!=0||b[offset+20]>1)throw new InvalidOperationException("PNG header encoding is unsupported.");
          interlace=b[offset+20];
        } else if(type=="PLTE") {
          if(palette||data||length==0||length>768||length%3!=0||color==0||color==4||(color==3&&length/3>(1<<depth)))throw new InvalidOperationException("PNG palette is malformed or out of order.");
          palette=true;
        } else if(type=="IDAT") {
          if(dataEnded||(color==3&&!palette))throw new InvalidOperationException("PNG image data is out of order.");
          data=true;
          compressed.Write(b,offset+8,length);
        } else if(type=="IEND") {
          if(length!=0||!data||offset+12!=b.Length)throw new InvalidOperationException("PNG trailer or image data is invalid.");
          ValidateData(compressed.ToArray(),width,height,depth,color,interlace);
          return new Envelope{Width=width,Height=height};
        } else {
          if(type=="acTL"||type=="fcTL"||type=="fdAT")throw new InvalidOperationException("Animated PNG input is not supported.");
          if((b[offset+4]&32)==0)throw new InvalidOperationException("PNG has an unknown critical chunk.");
        }
        if(data&&type!="IDAT")dataEnded=true;
        offset+=length+12;
      }
      throw new InvalidOperationException("PNG trailer is missing.");
      }
    }
  }
}
'@ -ErrorAction Stop
}

function Read-RideImageSourceBytes {
  param([string]$Path)
  if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Image sources require native Windows.'}
  try{$full=[IO.Path]::GetFullPath($Path)}catch{throw 'Image sources require a local path without alternate streams.'}
  if($full -notmatch '^[A-Za-z]:\\' -or $full.Substring(2).Contains(':') -or [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)).DriveType -eq [IO.DriveType]::Network){throw 'Image sources require a local path without alternate streams.'}
  $item=[IO.FileInfo]::new($full)
  if(-not $item.Exists -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Image source must be an existing ordinary file.'}
  for($node=$item.Directory;$null -ne $node;$node=$node.Parent){if($node.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Image source ancestors must not be reparse points.'}}
  $stream=[IO.File]::Open($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    if($stream.Length -lt 57 -or $stream.Length -gt 16777216){throw 'Image source is empty, truncated or exceeds its size bound.'}
    $bytes=New-Object byte[] ([int]$stream.Length);$offset=0
    while($offset -lt $bytes.Length){$n=$stream.Read($bytes,$offset,$bytes.Length-$offset);if($n -eq 0){throw 'Image source ended during reading.'};$offset+=$n}
    ,$bytes
  }finally{$stream.Dispose()}
}

function Get-RidePngSource {
  <#
  .SYNOPSIS
    Return the hash and dimensions of a validated local static PNG snapshot.
  .PARAMETER Path
    Existing local .png file. Reparse paths, network sources and streams refuse.
  .PARAMETER ExpectedSha256
    Required exact SHA-256 of the selected input; mismatch refuses before decoding.
  .PARAMETER IncludeContent
    Include the exact validated bytes for a lifecycle writer. The writer must use
    these bytes rather than reopening the source after validation.
  .EXAMPLE
    Get-RidePngSource -Path C:\Inputs\wallpaper.png -ExpectedSha256 $selectedHash
  .INPUTS
    None.
  .OUTPUTS
    Source identity and dimensions, optionally with Content as a byte array.
  .NOTES
    Read-only; no elevation or Windows personalization calls. GDI+ decoding does
    not prove that Windows will display this image for a particular user/policy.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,[switch]$IncludeContent)
  if([IO.Path]::GetExtension($Path) -ine '.png'){throw 'Only static .png input is currently implemented.'}
  $bytes=Read-RideImageSourceBytes $Path
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$hash=[BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','')}finally{$sha.Dispose()}
  if($hash -ine $ExpectedSha256){throw 'Image source hash differs from the selected input.'}
  Initialize-RidePngEnvelopeReader
  $envelope=[Ride.ImageFilesV1.Envelope]::Read($bytes)
  Add-Type -AssemblyName System.Drawing
  $memory=[IO.MemoryStream]::new($bytes,$false);$decoded=$null
  try {
    $decoded=[Drawing.Image]::FromStream($memory,$false,$true)
    if($decoded.RawFormat.Guid -ne [Drawing.Imaging.ImageFormat]::Png.Guid -or $decoded.Width -ne $envelope.Width -or $decoded.Height -ne $envelope.Height){throw 'Decoded PNG identity differs from its envelope.'}
  }finally{if($decoded){$decoded.Dispose()};$memory.Dispose()}
  $result=[ordered]@{SchemaVersion=1;Path=[IO.Path]::GetFullPath($Path);FileName=[IO.Path]::GetFileName($Path);Bytes=$bytes.Length;Sha256=$hash;Format='PNG';Width=$envelope.Width;Height=$envelope.Height;DecodeValidated=$true;PersonalizationChanged=$false}
  if($IncludeContent){$result.Content=$bytes}
  [pscustomobject]$result
}

Export-ModuleMember -Function Get-RidePngSource
