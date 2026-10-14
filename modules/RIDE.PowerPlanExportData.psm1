<#
.SYNOPSIS
  Fingerprint logical data in a native power-plan export application hive.
.DESCRIPTION
  Reads only an existing bounded file through a private read-only application-hive
  handle. No HKLM/HKU mount, registry setter or power-plan command is used. Includes
  the complete key hierarchy, classes, raw named value types/data and owner/group/
  DACL. Transport headers, timestamps and SACL are outside this data contract.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Read access to the file and its embedded key security descriptor.
  Native definitions load lazily; import performs no file or Windows inspection.
  Owner: RIDE-Windows maintainers. Version: 0.1.0.
  Changelog: 0.1.0: Add bounded LogicalExportV1 comparison; no byte masking.
.LINK
  https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadappkeyw
#>
$ErrorActionPreference='Stop'
function Initialize-RidePowerPlanExportApi {
  if('Ride.PowerPlanExportDataV1' -as [type]){return}
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
namespace Ride {
 public static class PowerPlanExportDataV1 {
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegLoadAppKeyW(string file,out IntPtr key,uint access,uint options,uint reserved);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegOpenKeyExW(IntPtr key,string name,uint options,uint access,out IntPtr child);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryValueExW(IntPtr key,string name,IntPtr reserved,out uint type,byte[] data,ref uint size);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryInfoKeyW(IntPtr key,StringBuilder keyClass,ref uint classLength,IntPtr reserved,out uint children,out uint childNameLength,out uint childClassLength,out uint values,out uint valueNameLength,out uint valueLength,out uint securityLength,out long timestamp);
  [DllImport("advapi32.dll")] static extern int RegGetKeySecurity(IntPtr key,uint info,byte[] data,ref uint size);
  static void Check(int status){if(status!=0)throw new System.ComponentModel.Win32Exception(status);}
  static void Text(BinaryWriter writer,string value){writer.Write(value.Length);foreach(char c in value)writer.Write((ushort)c);}
  static void Walk(RegistryKey key,string name,BinaryWriter writer,int depth,ref int count){
   if(depth>64 || ++count>4096)throw new InvalidDataException("Export key bounds exceeded.");
   IntPtr handle=key.Handle.DangerousGetHandle();uint length=0,children,childName,childClass,values,valueName,valueSize,securitySize;long time;
   Check(RegQueryInfoKeyW(handle,null,ref length,IntPtr.Zero,out children,out childName,out childClass,out values,out valueName,out valueSize,out securitySize,out time));
   if(length>32767 || children>4096 || values>16384 || valueSize>1048576)throw new InvalidDataException("Export metadata bounds exceeded.");
   var keyClass=new StringBuilder((int)length+1);length++;
   Check(RegQueryInfoKeyW(handle,keyClass,ref length,IntPtr.Zero,out children,out childName,out childClass,out values,out valueName,out valueSize,out securitySize,out time));
   Text(writer,name);Text(writer,keyClass.ToString());
   uint size=0;int status=RegGetKeySecurity(handle,7,null,ref size);
   if(status!=122 || size==0 || size>65536)throw new InvalidDataException("Export key security query failed.");
   byte[] security=new byte[size];Check(RegGetKeySecurity(handle,7,security,ref size));writer.Write(size);writer.Write(security,0,(int)size);
   string[] names=key.GetValueNames();Array.Sort(names,StringComparer.Ordinal);if(names.Length!=values)throw new InvalidDataException("Export values changed during inspection.");writer.Write(names.Length);
   foreach(string value in names){
    uint type;size=0;Check(RegQueryValueExW(handle,value,IntPtr.Zero,out type,null,ref size));if(size>1048576)throw new InvalidDataException("Export value bounds exceeded.");
    byte[] data=new byte[size];uint originalType=type;Check(RegQueryValueExW(handle,value,IntPtr.Zero,out type,data,ref size));if(type!=originalType)throw new InvalidDataException("Export value type changed.");
    Text(writer,value);writer.Write(type);writer.Write(size);writer.Write(data,0,(int)size);
   }
   names=key.GetSubKeyNames();Array.Sort(names,StringComparer.Ordinal);if(names.Length!=children)throw new InvalidDataException("Export keys changed during inspection.");writer.Write(names.Length);
   foreach(string childNameText in names){
    IntPtr child;Check(RegOpenKeyExW(handle,childNameText,8,0x20019,out child));
    using(var safe=new SafeRegistryHandle(child,true))using(var childKey=RegistryKey.FromHandle(safe)){Walk(childKey,childNameText,writer,depth+1,ref count);}
   }
   if(writer.BaseStream.Length>8388608)throw new InvalidDataException("Export representation bounds exceeded.");
  }
  public static string Read(string file){
   var info=new FileInfo(file);if(!info.Exists || info.Length<1 || info.Length>1048576 || (info.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Export must be an existing bounded regular file.");
   IntPtr handle;Check(RegLoadAppKeyW(file,out handle,0x20019,1,0));
   using(var safe=new SafeRegistryHandle(handle,true))using(var key=RegistryKey.FromHandle(safe))using(var stream=new MemoryStream())using(var writer=new BinaryWriter(stream)){
    Text(writer,"RIDE.LogicalExportV1");int count=0;Walk(key,"",writer,0,ref count);writer.Flush();using(var sha=SHA256.Create()){return BitConverter.ToString(sha.ComputeHash(stream.ToArray())).Replace("-","").ToLowerInvariant();}
   }
  }
 }
}
'@ -ErrorAction Stop
}
function Get-RidePowerPlanExportFingerprint {
  <#
  .SYNOPSIS
    Return the LogicalExportV1 SHA-256 of an existing native export file.
  .PARAMETER LiteralPath
    Existing bounded file; the caller owns path trust and temporary-file cleanup.
  .OUTPUTS
    String. Lowercase SHA-256 over typed logical export data, not its file header.
  .NOTES
    Read-only private application hive; no machine/user registry namespace mount.
    Key timestamps and transport metadata are not settings. SACL/OS policy source
    and effective inherited/hardware behavior are outside this comparison.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$LiteralPath)
  if(-not [IO.Path]::IsPathRooted($LiteralPath)){throw 'Export path must be absolute.'}
  if(-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)){throw 'Export file does not exist.'}
  Initialize-RidePowerPlanExportApi
  [Ride.PowerPlanExportDataV1]::Read([IO.Path]::GetFullPath($LiteralPath))
}
Export-ModuleMember -Function Get-RidePowerPlanExportFingerprint
