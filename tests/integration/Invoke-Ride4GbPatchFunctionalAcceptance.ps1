<#
.SYNOPSIS
  Verify NTCore 4GB Patch against an owned synthetic x86 PE in a disposable guest.
.DESCRIPTION
  Runs only the hash-pinned tool supplied by the portable acceptance runner and
  only against a generated fixture under the correlated evidence directory. It
  verifies the large-address-aware flag, exact backup bytes, guarded refusal
  when a user backup exists, safe launcher invocation, and exact recovery. No
  user executable or installed application is opened or changed.
.PARAMETER ExpectedComputerName
  Exact guest identity supplied by the host runner.
.PARAMETER ToolPath
  Installed package copy of 4gb_patch.exe.
.PARAMETER ExpectedSha256
  Catalog-pinned SHA-256 for the tool.
.PARAMETER EvidencePath
  Fresh functional-evidence directory below the correlated guest evidence root.
.PARAMETER DisposableVm
  Required explicit guest attestation in addition to identity/model/elevation checks.
.PARAMETER Version
  Print the version without querying Windows or running the utility.
.EXAMPLE
  .\Invoke-Ride4GbPatchFunctionalAcceptance.ps1 -Version
.INPUTS
  Hash-pinned installed tool path and correlated evidence directory.
.OUTPUTS
  result.json with functional checks and collision/recovery results.
.NOTES
  Compatibility: Windows PowerShell 5.1 on a disposable Windows 11 x64 guest.
  Prerequisites: Elevated attested guest and installed NTCore 4GB Patch candidate.
  Effects: Executes the utility only on a generated, non-runnable x86 PE fixture.
  Recovery: Confirms the exact original bytes are retained in the backup and restores
    the synthetic target from those bytes. Temporary fixture files are then removed.
  Author: RIDE-Windows maintainers. Version: 0.4.0.
  Changelog: 0.4.0: Run only through the RIDE guarded launcher and verify PE checksum changes.
    0.3.0: Verify the RIDE guarded launcher and exact pre-created backup.
    0.2.0: Record unsafe collisions and recover the synthetic target before failure.
    0.1.0: Add bounded synthetic x86 PE, backup, collision and recovery checks.
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [string]$ExpectedComputerName,
  [string]$ToolPath,
  [ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
  [string]$EvidencePath,
  [switch]$DisposableVm,
  [switch]$Version
)
if($Version){'0.4.0';return}
$ErrorActionPreference='Stop'
if(-not $ExpectedComputerName -or -not $ToolPath -or -not $ExpectedSha256 -or -not $EvidencePath){throw 'ExpectedComputerName, ToolPath, ExpectedSha256 and EvidencePath are required.'}
if(-not $DisposableVm -or $env:RIDE_INTEGRATION_VM -ne '1' -or
   $env:COMPUTERNAME -ine $ExpectedComputerName){throw 'Use the attested disposable guest runner; no workstation integration is permitted.'}
if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine' -or
   (Get-CimInstance Win32_OperatingSystem).Caption -notmatch 'Windows 11'){
  throw 'A Windows 11 virtual machine is required.'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
  throw 'Guest elevation is required.'
}
$evidence=[IO.Path]::GetFullPath($EvidencePath)
if($evidence -notmatch '^C:\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\evidence\\4gb-patch-functional$'){
  throw 'Invalid correlated functional-evidence directory.'
}
$tool=(Get-Item -LiteralPath $ToolPath -ErrorAction Stop).FullName
$repositoryRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$launcher=Join-Path $repositoryRoot 'tools/Invoke-Ride4GbPatch.ps1'
if(-not (Test-Path -LiteralPath $launcher -PathType Leaf)){throw 'RIDE guarded 4GB Patch launcher is missing from the bound source.'}
if((Get-Item -LiteralPath $tool).PSIsContainer -or (Get-FileHash -LiteralPath $tool).Hash -ine $ExpectedSha256){
  throw 'Installed 4GB Patch tool does not match the catalog pin.'
}
if(-not $PSCmdlet.ShouldProcess($ExpectedComputerName,'Run NTCore 4GB Patch against an owned synthetic PE fixture')){return}
$null=New-Item -ItemType Directory -Path $evidence -Force
$work=Join-Path $evidence ('work-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $work
$fixture=Join-Path $work 'synthetic-x86.exe'
$result=[ordered]@{
  Status='Failed';ToolSha256=$ExpectedSha256.ToLowerInvariant();Fixture='synthetic-x86.exe'
  OriginalSha256=$null;PatchedSha256=$null;BackupName=$null;BackupSha256=$null
  CollisionBehavior=$null;CollisionExitCode=$null;CollisionTargetSha256=$null
  CollisionSentinelPreserved=$false;CollisionBackupFiles=@();CollisionRefusal=$null;RecoveryAfterRejectedBehavior=$null
  GuardedLauncherStatus=$null;GuardedLauncherError=$null;GuardedLauncherBackupSha256=$null;ChangedByteOffsets=@()
  Checks=@();ToolExecuted=$false;Error=$null
}
function Set-U16([byte[]]$Bytes,[int]$Offset,[uint16]$Value){[Array]::Copy([BitConverter]::GetBytes($Value),0,$Bytes,$Offset,2)}
function Set-U32([byte[]]$Bytes,[int]$Offset,[uint32]$Value){[Array]::Copy([BitConverter]::GetBytes($Value),0,$Bytes,$Offset,4)}
function New-SyntheticX86Pe {
  $bytes=New-Object byte[] 1024
  $bytes[0]=0x4d;$bytes[1]=0x5a
  Set-U32 $bytes 0x3c 0x80
  $bytes[0x80]=0x50;$bytes[0x81]=0x45;$bytes[0x82]=0;$bytes[0x83]=0
  $coff=0x84;$optional=$coff+20;$section=$optional+0xe0
  Set-U16 $bytes $coff 0x14c
  Set-U16 $bytes ($coff+2) 1
  Set-U16 $bytes ($coff+16) 0xe0
  Set-U16 $bytes ($coff+18) 0x0102
  Set-U16 $bytes $optional 0x10b
  Set-U32 $bytes ($optional+4) 0x200
  Set-U32 $bytes ($optional+16) 0x1000
  Set-U32 $bytes ($optional+20) 0x1000
  Set-U32 $bytes ($optional+24) 0x1000
  Set-U32 $bytes ($optional+28) 0x400000
  Set-U32 $bytes ($optional+32) 0x1000
  Set-U32 $bytes ($optional+36) 0x200
  Set-U16 $bytes ($optional+40) 6
  Set-U16 $bytes ($optional+48) 6
  Set-U32 $bytes ($optional+56) 0x2000
  Set-U32 $bytes ($optional+60) 0x200
  Set-U16 $bytes ($optional+68) 3
  Set-U32 $bytes ($optional+72) 0x100000
  Set-U32 $bytes ($optional+76) 0x1000
  Set-U32 $bytes ($optional+80) 0x100000
  Set-U32 $bytes ($optional+84) 0x1000
  Set-U32 $bytes ($optional+92) 16
  [Text.Encoding]::ASCII.GetBytes('.text').CopyTo($bytes,$section)
  Set-U32 $bytes ($section+8) 0x10
  Set-U32 $bytes ($section+12) 0x1000
  Set-U32 $bytes ($section+16) 0x200
  Set-U32 $bytes ($section+20) 0x200
  Set-U32 $bytes ($section+36) 0x60000020
  for($i=0x200;$i -lt $bytes.Length;$i++){$bytes[$i]=[byte](($i*31) -band 0xff)}
  return ,$bytes
}
function Get-PeCharacteristics([byte[]]$Bytes){
  if($Bytes.Length -lt 0x100 -or $Bytes[0] -ne 0x4d -or $Bytes[1] -ne 0x5a){throw 'Fixture is not an MZ image.'}
  $pe=[BitConverter]::ToUInt32($Bytes,0x3c)
  if($pe -gt ($Bytes.Length-24) -or $Bytes[$pe] -ne 0x50 -or $Bytes[$pe+1] -ne 0x45 -or
     $Bytes[$pe+2] -ne 0 -or $Bytes[$pe+3] -ne 0){throw 'Fixture has no valid PE signature.'}
  if([BitConverter]::ToUInt16($Bytes,$pe+4) -ne 0x14c -or [BitConverter]::ToUInt16($Bytes,$pe+24) -ne 0x10b){
    throw 'Fixture is not a PE32 x86 image.'
  }
  [BitConverter]::ToUInt16($Bytes,$pe+22)
}
function Get-SyntheticPeChecksum([byte[]]$Bytes){
  $peOffset=[BitConverter]::ToUInt32($Bytes,0x3c)
  $checksumOffset=[int]$peOffset+24+64
  [uint64]$sum=0
  for($offset=0;$offset -lt $Bytes.Length;$offset+=2){
    if($offset -ge $checksumOffset -and $offset -lt ($checksumOffset+4)){continue}
    [uint64]$word=0
    if(($offset+1) -lt $Bytes.Length){$word=[BitConverter]::ToUInt16($Bytes,$offset)}else{$word=$Bytes[$offset]}
    $sum+=$word
    $sum=($sum -band 0xffff)+($sum -shr 16)
  }
  $sum+=$Bytes.Length
  $sum=($sum -band 0xffff)+($sum -shr 16)
  [uint32]$sum
}
try{
  $original=New-SyntheticX86Pe
  if((Get-PeCharacteristics $original) -band 0x20){throw 'Synthetic PE starts with the large-address-aware flag set.'}
  [IO.File]::WriteAllBytes($fixture,$original)
  $result.OriginalSha256=(Get-FileHash -LiteralPath $fixture).Hash.ToLowerInvariant()
  $result.Checks+=@('SyntheticPe32X86','InitialFlagClear')
  $backupPath=$fixture+'.Backup'

  # A pre-existing user backup must stop the RIDE launcher before utility execution.
  $sentinel=[Text.Encoding]::UTF8.GetBytes('RIDE synthetic backup collision sentinel')
  [IO.File]::WriteAllBytes($backupPath,$sentinel)
  $collisionBytes=[IO.File]::ReadAllBytes($backupPath)
  $result.CollisionSentinelPreserved=([Convert]::ToBase64String($collisionBytes) -ceq [Convert]::ToBase64String($sentinel))
  $afterCollision=[IO.File]::ReadAllBytes($fixture)
  $result.CollisionTargetSha256=(Get-FileHash -LiteralPath $fixture).Hash.ToLowerInvariant()
  if(-not $result.CollisionSentinelPreserved -or (Get-PeCharacteristics $afterCollision) -band 0x20 -or
     [Convert]::ToBase64String($afterCollision) -cne [Convert]::ToBase64String($original)){
    throw 'Synthetic collision precondition was not preserved.'
  }
  try{
    & $launcher -ToolPath $tool -TargetPath $fixture -ExpectedToolSha256 $ExpectedSha256 -Confirm:$false | Out-Null
    throw 'Guarded launcher unexpectedly accepted a pre-existing backup path.'
  }catch{
    if($_.Exception.Message -notlike '*Backup path already exists; no changes made*'){throw}
    $result.CollisionRefusal=$_.Exception.Message
  }
  $result.CollisionBehavior='GuardedLauncherRefusedExistingBackupWithoutMutation'
  $result.Checks+=@('GuardedLauncherRefusesExistingBackup','CollisionTargetPreserved','CollisionSentinelPreserved')
  [IO.File]::Delete($backupPath)
  $result.ToolExecuted=$true
  try{
    $safeResult=& $launcher -ToolPath $tool -TargetPath $fixture -ExpectedToolSha256 $ExpectedSha256 -Confirm:$false
  }catch{
    $result.GuardedLauncherError=$_.Exception.Message
    $failedBytes=[IO.File]::ReadAllBytes($fixture)
    for($offset=0;$offset -lt [Math]::Min($original.Length,$failedBytes.Length);$offset++){
      if($original[$offset] -ne $failedBytes[$offset]){
        $result.ChangedByteOffsets+=@([pscustomobject]@{Offset=$offset;Original=('{0:X2}' -f $original[$offset]);Observed=('{0:X2}' -f $failedBytes[$offset])})
      }
    }
    if($original.Length -ne $failedBytes.Length){$result.ChangedByteOffsets+=@([pscustomobject]@{Offset='Length';Original=$original.Length;Observed=$failedBytes.Length})}
    if([IO.File]::Exists($backupPath)){$result.GuardedLauncherBackupSha256=(Get-FileHash -LiteralPath $backupPath).Hash.ToLowerInvariant()}
    throw ('Guarded launcher rejected the synthetic result after retaining its backup. Changed byte offsets: '+(($result.ChangedByteOffsets|ForEach-Object{$_.Offset}) -join ','))
  }
  $result.GuardedLauncherError=$null
  if($safeResult.Status -cne 'Patched' -or $safeResult.OriginalSha256 -ine $result.OriginalSha256){throw 'Guarded launcher did not report a successful exact-backup patch.'}
  $result.GuardedLauncherStatus=$safeResult.Status
  $result.GuardedLauncherBackupSha256=(Get-FileHash -LiteralPath $backupPath).Hash.ToLowerInvariant()
  $result.BackupName=[IO.Path]::GetFileName($backupPath)
  $result.BackupSha256=$result.GuardedLauncherBackupSha256
  $backupBytes=[IO.File]::ReadAllBytes($backupPath)
  $afterSafePatch=[IO.File]::ReadAllBytes($fixture)
  $expectedSafe=[byte[]]$original.Clone();$peOffset=[BitConverter]::ToUInt32($original,0x3c)
  Set-U16 $expectedSafe ([int]$peOffset+22) ([uint16]((Get-PeCharacteristics $original) -bor 0x20))
  $expectedChecksum=Get-SyntheticPeChecksum $expectedSafe
  Set-U32 $expectedSafe ([int]$peOffset+24+64) $expectedChecksum
  $result.PatchedSha256=$safeResult.PatchedSha256
  if(-not ((Get-PeCharacteristics $afterSafePatch) -band 0x20)){throw 'The large-address-aware flag was not set.'}
  if($safeResult.PeChecksum -cne ('0x{0:X8}' -f $expectedChecksum)){throw 'Guarded launcher reported an unexpected PE checksum.'}
  if([Convert]::ToBase64String($backupBytes) -cne [Convert]::ToBase64String($original) -or
     [Convert]::ToBase64String($afterSafePatch) -cne [Convert]::ToBase64String($expectedSafe)){
    throw 'Guarded launcher did not retain the exact backup and expected flag-plus-checksum target.'
  }
  $result.Checks+=@('GuardedLauncherCreatesExactBackup','GuardedLauncherSetsLargeAddressAwareFlag','GuardedLauncherRecomputesPeChecksum')
  [IO.File]::WriteAllBytes($fixture,$backupBytes)
  $recovered=[IO.File]::ReadAllBytes($fixture)
  if([Convert]::ToBase64String($recovered) -cne [Convert]::ToBase64String($original) -or (Get-PeCharacteristics $recovered) -band 0x20){
    throw 'Recovery did not restore the exact original PE with its flag clear.'
  }
  $result.Checks+=@('ExactSyntheticRecoveryFromAdjacentBackup')
  $result.Status='Passed'
}catch{$result.Error=$_.Exception.Message}
finally{
  if(Test-Path -LiteralPath $work){
    $resolvedWork=[IO.Path]::GetFullPath($work).TrimEnd('\')
    $resolvedEvidence=$evidence.TrimEnd('\')
    if(-not $resolvedWork.StartsWith($resolvedEvidence+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Refusing cleanup outside the functional-evidence directory.'}
    Remove-Item -LiteralPath $resolvedWork -Recurse -Force
  }
  $result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding UTF8
}
[pscustomobject]$result
if($result.Status -ne 'Passed'){throw ('4GB Patch functional acceptance failed: '+$result.Error)}
