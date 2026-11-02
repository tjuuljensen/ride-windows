<#
.SYNOPSIS
  Construct inert name-table-only bytes for font source unit tests.
.DESCRIPTION
  This is not a renderable font. Never pass it to GDI or a native acceptance run.
  The function returns bytes only and performs no filesystem/system writes.
.NOTES
  Native PowerShell 5.1/7 test helper. Version: 0.1.0.
#>
function New-RideSyntheticTrueTypeBytes {
  param([string]$Name='RIDE Synthetic Test',[switch]$Ambiguous)
  $records=@(@{Id=1;Value=$Name},@{Id=2;Value='Regular'},@{Id=4;Value=$Name},@{Id=6;Value=$Name.Replace(' ','')})
  if($Ambiguous){$records+=@{Id=4;Value='Different synthetic identity'}}
  $encoded=@($records|ForEach-Object {,[Text.Encoding]::BigEndianUnicode.GetBytes($_.Value)})
  $storage=6+12*$records.Count;$length=$storage+($encoded|ForEach-Object Length|Measure-Object -Sum).Sum
  $memory=[IO.MemoryStream]::new();$writer=[IO.BinaryWriter]::new($memory)
  function Write-U16([int]$Value){$writer.Write([byte](($Value -shr 8) -band 255));$writer.Write([byte]($Value -band 255))}
  function Write-U32([long]$Value){foreach($shift in @(24,16,8,0)){$writer.Write([byte](($Value -shr $shift) -band 255))}}
  try{
    Write-U32 65536;Write-U16 1;Write-U16 16;Write-U16 0;Write-U16 0
    $writer.Write([Text.Encoding]::ASCII.GetBytes('name'));Write-U32 0;Write-U32 28;Write-U32 $length
    Write-U16 0;Write-U16 $records.Count;Write-U16 $storage
    $offset=0
    for($i=0;$i -lt $records.Count;$i++){Write-U16 3;Write-U16 1;Write-U16 1033;Write-U16 $records[$i].Id;Write-U16 $encoded[$i].Length;Write-U16 $offset;$offset+=$encoded[$i].Length}
    foreach($bytes in $encoded){$writer.Write([byte[]]$bytes)}
    $writer.Flush();,$memory.ToArray()
  }finally{$writer.Dispose();$memory.Dispose()}
}
