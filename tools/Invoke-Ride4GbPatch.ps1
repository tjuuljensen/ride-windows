<#
.SYNOPSIS
  Safely run the pinned NTCore 4GB Patch tool against one x86 executable.

.DESCRIPTION
  Creates and flushes an exact adjacent .Backup file before invoking the tool,
  refuses an existing backup, and verifies that only the PE large-address-aware
  bit and recomputed PE checksum changed. Keeps original bytes in memory as a
  second recovery source.
  Do not invoke the upstream executable directly; use this guarded launcher.

.PARAMETER ToolPath
  Path to the RIDE-managed 4gb_patch.exe.

.PARAMETER TargetPath
  Path to the x86 PE32 executable to patch. The target must not be running.

.PARAMETER ExpectedToolSha256
  Catalog-pinned SHA-256 for the installed upstream utility.

.PARAMETER Help
  Display this help and return without reading target files.

.PARAMETER Version
  Print the launcher version without reading target files.

.EXAMPLE
  .\tools\Invoke-Ride4GbPatch.ps1 -ToolPath 'C:\Tools\NTCore\4GB Patch\4gb_patch.exe' -TargetPath 'C:\Apps\Legacy\app.exe' -ExpectedToolSha256 '<catalog SHA-256>'

.INPUTS
  None. Paths and the expected tool hash are supplied explicitly.

.OUTPUTS
  A result object containing target, backup and SHA-256 evidence.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Elevated session when modifying protected files; close the target application.
  Effects: Creates <TargetPath>.Backup, runs the hash-pinned patcher, and sets the PE large-address-aware flag and checksum.
  Recovery: Restore the exact original bytes from the adjacent .Backup file.
  Author: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog: 0.2.0: Validate the expected PE checksum update.
    0.1.0: Add exact-backup guarded invocation for NTCore 4GB Patch.
#>
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
  [string]$ToolPath,
  [string]$TargetPath,
  [ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedToolSha256,
  [switch]$Help,
  [switch]$Version
)
$ErrorActionPreference='Stop'
if($Version){'0.2.0';return}
if($Help){Get-Help -Name $PSCommandPath -Full;return}
if(-not $ToolPath -or -not $TargetPath -or -not $ExpectedToolSha256){throw 'ToolPath, TargetPath and ExpectedToolSha256 are required.'}

function Get-RidePe32X86Characteristics {
  param([byte[]]$Bytes)
  if($Bytes.Length -lt 0x100 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a){throw 'Target is not a valid MZ executable.'}
  $peOffset=[BitConverter]::ToUInt32($Bytes,0x3c)
  if($peOffset -gt ($Bytes.Length-24) -or $Bytes[$peOffset] -ne 0x50 -or $Bytes[$peOffset+1] -ne 0x45 -or $Bytes[$peOffset+2] -ne 0 -or $Bytes[$peOffset+3] -ne 0){throw 'Target has no valid PE signature.'}
  if([BitConverter]::ToUInt16($Bytes,$peOffset+4) -ne 0x14c -or [BitConverter]::ToUInt16($Bytes,$peOffset+24) -ne 0x10b){throw 'Target must be a PE32 x86 executable.'}
  [pscustomobject]@{Offset=([int]$peOffset+22);ChecksumOffset=([int]$peOffset+24+64);Characteristics=[BitConverter]::ToUInt16($Bytes,[int]$peOffset+22)}
}

function Get-RidePeChecksum {
  param([byte[]]$Bytes,[int]$ChecksumOffset)
  if($ChecksumOffset -lt 0 -or ($ChecksumOffset+4) -gt $Bytes.Length){throw 'PE checksum field is outside the target file.'}
  [uint64]$sum=0
  for($offset=0;$offset -lt $Bytes.Length;$offset+=2){
    if($offset -ge $ChecksumOffset -and $offset -lt ($ChecksumOffset+4)){continue}
    [uint64]$word=0
    if(($offset+1) -lt $Bytes.Length){$word=[BitConverter]::ToUInt16($Bytes,$offset)}else{$word=$Bytes[$offset]}
    $sum+=$word
    $sum=($sum -band 0xffff)+($sum -shr 16)
  }
  $sum+=$Bytes.Length
  $sum=($sum -band 0xffff)+($sum -shr 16)
  [uint32]$sum
}

function Restore-RideExactTarget {
  param([string]$Path,[byte[]]$Bytes)
  $temporary=$Path+'.ride-restore-'+[guid]::NewGuid().ToString('N')+'.tmp'
  $stream=$null
  try{
    $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true);$stream.Dispose();$stream=$null
    [IO.File]::Replace($temporary,$Path,$null)
  }finally{
    if($stream){$stream.Dispose()}
    if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}
  }
}

$tool=[IO.Path]::GetFullPath($ToolPath)
$target=[IO.Path]::GetFullPath($TargetPath)
if($tool -notmatch '^[A-Za-z]:\\' -or $target -notmatch '^[A-Za-z]:\\'){throw 'Tool and target must use local drive paths.'}
if($tool -ieq $target){throw 'The tool cannot be its own target.'}
$toolItem=Get-Item -LiteralPath $tool -ErrorAction Stop
if($toolItem.PSIsContainer -or (Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash -ine $ExpectedToolSha256){throw 'The installed 4GB Patch utility does not match the expected SHA-256.'}
$targetItem=Get-Item -LiteralPath $target -ErrorAction Stop
if($targetItem.PSIsContainer -or ($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Target must be a regular file and cannot be a reparse point.'}
if($targetItem.Length -gt 512MB){throw 'Target exceeds the 512 MiB safety limit.'}
$backup=$target+'.Backup'
if([IO.File]::Exists($backup) -or [IO.Directory]::Exists($backup)){throw "Backup path already exists; no changes made: $backup"}

$original=$null
$backupStream=$null
$createdBackup=$false
$toolStarted=$false
try{
  $targetStream=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  try{
    if($targetStream.Length -gt 512MB){throw 'Target exceeds the 512 MiB safety limit.'}
    $original=[byte[]]::new([int]$targetStream.Length)
    $readOffset=0
    while($readOffset -lt $original.Length){$read=$targetStream.Read($original,$readOffset,$original.Length-$readOffset);if(-not $read){throw 'Target changed during the guarded read.'};$readOffset+=$read}
  }finally{$targetStream.Dispose()}
  $pe=Get-RidePe32X86Characteristics $original
  if($pe.Characteristics -band 0x20){throw 'Target already has the large-address-aware flag set.'}
  $sha=[Security.Cryptography.SHA256]::Create()
  try{$originalHash=([BitConverter]::ToString($sha.ComputeHash($original))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  if(-not $PSCmdlet.ShouldProcess($target,'Create exact backup and run the pinned NTCore 4GB Patch utility')){return}

  $backupStream=[IO.File]::Open($backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  $backupStream.Write($original,0,$original.Length);$backupStream.Flush($true);$backupStream.Dispose();$backupStream=$null;$createdBackup=$true
  if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ine $originalHash){throw 'Target changed after backup creation; utility was not started. The exact original backup was retained.'}

  $start=[Diagnostics.ProcessStartInfo]::new()
  $start.FileName=$tool
  $start.Arguments='"'+$target+'"'
  $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
  $process=[Diagnostics.Process]::Start($start);$toolStarted=$true
  if(-not $process.WaitForExit(60000)){$process.Kill();$process.WaitForExit();throw 'The 4GB Patch utility exceeded 60 seconds.'}
  $process.Refresh()
  if($process.ExitCode -ne 0){throw "The 4GB Patch utility returned exit code $($process.ExitCode). The exact original backup was retained."}

  $patched=[IO.File]::ReadAllBytes($target)
  $patchedPe=Get-RidePe32X86Characteristics $patched
  if($patched.Length -ne $original.Length -or -not ($patchedPe.Characteristics -band 0x20)){throw 'The utility did not produce the expected x86 large-address-aware target.'}
  $expected=[byte[]]$original.Clone()
  $expected[$pe.Offset]=[byte](($expected[$pe.Offset] -bor 0x20) -band 0xff)
  $expectedChecksum=Get-RidePeChecksum -Bytes $expected -ChecksumOffset $pe.ChecksumOffset
  [Array]::Copy([BitConverter]::GetBytes($expectedChecksum),0,$expected,$pe.ChecksumOffset,4)
  if([Convert]::ToBase64String($patched) -cne [Convert]::ToBase64String($expected)){throw 'The utility changed bytes other than the PE large-address-aware flag.'}
  if((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ine $originalHash){throw 'The adjacent backup no longer matches the exact original bytes.'}
  [pscustomobject]@{TargetPath=$target;BackupPath=$backup;OriginalSha256=$originalHash;PatchedSha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant();PeChecksum=('0x{0:X8}' -f $expectedChecksum);ToolSha256=$ExpectedToolSha256.ToLowerInvariant();ExitCode=$process.ExitCode;Status='Patched'}
}catch{
  $failure=$_.Exception.Message
  if($toolStarted -and $createdBackup -and $original){
    try{
      $current=[IO.File]::ReadAllBytes($target)
      if($current.Length -eq $original.Length){
        $currentPe=Get-RidePe32X86Characteristics $current
        $expectedPatched=[byte[]]$original.Clone();$expectedPatched[$currentPe.Offset]=[byte](($expectedPatched[$currentPe.Offset] -bor 0x20) -band 0xff)
        $expectedChecksum=Get-RidePeChecksum -Bytes $expectedPatched -ChecksumOffset $currentPe.ChecksumOffset
        [Array]::Copy([BitConverter]::GetBytes($expectedChecksum),0,$expectedPatched,$currentPe.ChecksumOffset,4)
        if([Convert]::ToBase64String($current) -ceq [Convert]::ToBase64String($expectedPatched)){Restore-RideExactTarget -Path $target -Bytes $original}
      }
    }catch{$failure+=" Recovery attempt failed: $($_.Exception.Message). Restore from '$backup'."}
  }
  throw $failure
}finally{if($backupStream){$backupStream.Dispose()}}
