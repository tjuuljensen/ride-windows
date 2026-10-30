<#
.SYNOPSIS
  Verify pinned RawCopy file extraction using only a generated synthetic file.
.DESCRIPTION
  Runs the pinned x64 RawCopy candidate against one uniquely generated fixture in
  the disposable Windows guest. It disables network sending, metadata output and
  directory listing, directs output to a unique temporary directory, and checks
  exact content hashes and cleanup. It never scans a directory or accepts an
  operator-supplied source path. The guest must already be elevated; no UAC prompt
  is requested.
.PARAMETER ExecutablePath
  Literal path to the staged RawCopy64.exe from package.rawcopy.
.PARAMETER ExpectedComputerName
  Exact disposable guest identity to prevent running on an unintended computer.
.PARAMETER EvidencePath
  New JSON evidence file path in an existing evidence directory.
.PARAMETER TimeoutSeconds
  Maximum RawCopy process duration.
.EXAMPLE
  .\Invoke-RideRawCopySyntheticAcceptance.ps1 -ExecutablePath 'C:\Tools\RawCopy\RawCopy64.exe' -ExpectedComputerName 'RIDE-Win11-Test' -EvidencePath 'C:\RIDE-Evidence\rawcopy.json'
.INPUTS
  None.
.OUTPUTS
  PSCustomObject describing the synthetic extraction acceptance result.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows 11.
  Prerequisites: Existing elevated session in the disposable guest, staged pinned
  RawCopy 1.0.0.22, and an existing evidence directory.
  Side effects: Creates one generated source file, one output file and one JSON
  evidence file. On success it removes only its two synthetic files and their
  unique directories. On failure it preserves the unique fixture directory.
  Does not attach a disk, mount an image, invoke network output, read user/evidence
  data, change Defender, or publish Windows support.
  Version: 1.0.0.
  Changelog: 1.0.0: Add guarded synthetic file extraction acceptance for RawCopy.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExecutablePath,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$EvidencePath,
  [ValidateRange(5,300)][int]$TimeoutSeconds=60
)

$ErrorActionPreference='Stop'
$expectedExecutableSha256='619795AA357E1EB36FEBF45B398CCCCB289CB27B547814BFB422EFB3E8F98E3D'
$expectedComputerName=$ExpectedComputerName.Trim()
if([Environment]::MachineName -cne $expectedComputerName){throw "Expected disposable guest '$expectedComputerName', found '$([Environment]::MachineName)' instead."}
$computer=Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
if($computer.Model -notmatch 'Virtual Machine'){throw 'RawCopy synthetic acceptance requires a disposable virtual-machine guest.'}
$os=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
if([int]$os.ProductType -ne 1 -or [int]$os.BuildNumber -lt 22000){throw 'RawCopy candidate acceptance is limited to Windows 11 client guests; Server and older Windows targets are not declared.'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'The disposable guest session must already be elevated. This runner does not request UAC.'}

$exe=[IO.Path]::GetFullPath($ExecutablePath)
if(-not (Test-Path -LiteralPath $exe -PathType Leaf)){throw 'The staged RawCopy executable does not exist.'}
$exeItem=Get-Item -LiteralPath $exe -Force
if($exeItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'The staged RawCopy executable cannot be a reparse point.'}
$exeHash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
if($exeHash -cne $expectedExecutableSha256){throw 'The staged RawCopy executable does not match the pinned 1.0.0.22 member digest.'}

$evidence=[IO.Path]::GetFullPath($EvidencePath)
$evidenceParent=[IO.Path]::GetDirectoryName($evidence)
if(-not (Test-Path -LiteralPath $evidenceParent -PathType Container)){throw 'Evidence parent directory must already exist.'}
if(Test-Path -LiteralPath $evidence){throw 'EvidencePath already exists; choose a new path.'}
if(-not $PSCmdlet.ShouldProcess($expectedComputerName,'Read one generated RawCopy fixture and write its matching output/evidence')){
  return [pscustomobject]@{Status='WhatIf';ComputerName=$expectedComputerName;PackageVersion='1.0.0.22';ExecutableSha256=$exeHash;ToolExecuted=$false;WindowsSupportPromoted=$false}
}

$runId=[guid]::NewGuid().ToString('N')
$machineTemp=Join-Path $env:windir 'Temp'
if(-not (Test-Path -LiteralPath $machineTemp -PathType Container)){throw 'Windows machine temp directory is unavailable.'}
$machineTempItem=Get-Item -LiteralPath $machineTemp -Force
if($machineTempItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Windows machine temp directory cannot be a reparse point.'}
$fixtureRoot=Join-Path $machineTemp ('RIDE-RawCopy-'+$runId)
$sourceDirectory=Join-Path $fixtureRoot 'source'
$outputDirectory=Join-Path $fixtureRoot 'output'
$sourcePath=Join-Path $sourceDirectory 'synthetic-fixture.bin'
$outputName='synthetic-copy.bin'
$outputPath=Join-Path $outputDirectory $outputName
$process=$null
$stdout=''
$stderr=''
$processExitCode=$null
$toolExecuted=$false
$sourceHash=$null
$outputHash=$null
$sourceUnchanged=$false
$outputMatchesSource=$false
$status='Failed'
$failure=$null
$cleaned=$false

try {
  New-Item -ItemType Directory -Path $sourceDirectory -ErrorAction Stop | Out-Null
  New-Item -ItemType Directory -Path $outputDirectory -ErrorAction Stop | Out-Null
  foreach($directoryPath in @($fixtureRoot,$sourceDirectory,$outputDirectory)){
    $directoryItem=Get-Item -LiteralPath $directoryPath -Force
    if($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Synthetic fixture directories cannot be reparse points.'}
  }
  $driveLetter=[IO.Path]::GetPathRoot($sourcePath).Substring(0,1)
  $volume=Get-Volume -DriveLetter $driveLetter -ErrorAction Stop
  if($volume.FileSystem -cne 'NTFS'){throw 'Synthetic fixture volume must use NTFS.'}

  [byte[]]$fixtureBytes=New-Object byte[] 4096
  for($i=0;$i -lt $fixtureBytes.Length;$i++){$fixtureBytes[$i]=[byte](($i*37+11)%256)}
  [IO.File]::WriteAllBytes($sourcePath,$fixtureBytes)
  $sourceHash=(Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToUpperInvariant()

  $arguments=@(
    '/FileNamePath:"'+$sourcePath+'"',
    '/OutputPath:"'+$outputDirectory+'"',
    '/OutputName:"'+$outputName+'"',
    '/AllAttr:0',
    '/RawDirMode:0',
    '/WriteFSInfo:0',
    '/TcpSend:0'
  ) -join ' '
  $startInfo=[Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName=$exe
  $startInfo.Arguments=$arguments
  $startInfo.WorkingDirectory=$outputDirectory
  $startInfo.UseShellExecute=$false
  $startInfo.CreateNoWindow=$true
  $startInfo.RedirectStandardOutput=$true
  $startInfo.RedirectStandardError=$true
  $process=[Diagnostics.Process]::new()
  $process.StartInfo=$startInfo
  if(-not $process.Start()){throw 'RawCopy process did not start.'}
  $toolExecuted=$true
  $stdoutTask=$process.StandardOutput.ReadToEndAsync()
  $stderrTask=$process.StandardError.ReadToEndAsync()
  if(-not $process.WaitForExit($TimeoutSeconds*1000)){
    try{$process.Kill()}catch{}
    throw "RawCopy exceeded the $TimeoutSeconds second timeout."
  }
  $process.WaitForExit()
  $stdout=$stdoutTask.Result
  $stderr=$stderrTask.Result
  $processExitCode=$process.ExitCode
  if($processExitCode -ne 0){throw "RawCopy returned exit code $processExitCode."}
  if(-not (Test-Path -LiteralPath $outputPath -PathType Leaf)){throw 'RawCopy did not create the expected synthetic output file.'}
  $outputs=@(Get-ChildItem -LiteralPath $outputDirectory -Force -File)
  if($outputs.Count -ne 1 -or $outputs[0].Name -cne $outputName){throw 'RawCopy created unexpected output files.'}
  $outputHash=(Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash.ToUpperInvariant()
  $outputMatchesSource=($outputHash -ceq $sourceHash)
  if(-not $outputMatchesSource){throw 'RawCopy output bytes do not match the generated synthetic source.'}
  $sourceUnchanged=((Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToUpperInvariant() -ceq $sourceHash)
  if(-not $sourceUnchanged){throw 'RawCopy changed the synthetic source file.'}
  $status='Passed'
}
catch {
  $failure=$_.Exception.Message
}
finally {
  if($process){$process.Dispose()}
  if($status -eq 'Passed'){
    Remove-Item -LiteralPath $outputPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $sourcePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $outputDirectory -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $sourceDirectory -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $fixtureRoot -Force -ErrorAction SilentlyContinue
    $cleaned=(-not (Test-Path -LiteralPath $fixtureRoot))
    if(-not $cleaned){$status='Failed';$failure='Successful extraction completed, but unique synthetic fixture cleanup did not finish.'}
  }
}

$record=[ordered]@{
  schemaVersion=1
  recordedAtUtc=[DateTime]::UtcNow.ToString('o')
  package='package.rawcopy'
  packageVersion='1.0.0.22'
  computerName=$expectedComputerName
  windowsBuild=[string]$os.BuildNumber
  executableSha256=$exeHash
  status=$status
  toolExecuted=$toolExecuted
  syntheticOnly=$true
  sourceSha256=$sourceHash
  outputSha256=$outputHash
  sourceUnchanged=$sourceUnchanged
  outputMatchesSource=$outputMatchesSource
  networkSendEnabled=$false
  fileSystemInfoOutputEnabled=$false
  rawDirectoryListingEnabled=$false
  processExitCode=$processExitCode
  fixtureCleaned=$cleaned
  failure=$failure
  output='One generated 4096-byte fixture copied to one uniquely named output, with exact SHA-256 match required.'
  sideEffects=@{
    userOrEvidenceDataRead=$false
    imageOrDiskAttached=$false
    windowsOrDefenderStateChanged=$false
    elevationPromptRequested=$false
    windowsSupportPromoted=$false
  }
}
$json=ConvertTo-Json -InputObject $record -Depth 8
[IO.File]::WriteAllText($evidence,$json,[Text.UTF8Encoding]::new($false))
$result=[pscustomobject]@{Status=$status;ComputerName=$expectedComputerName;PackageVersion='1.0.0.22';ExecutableSha256=$exeHash;SourceSha256=$sourceHash;OutputSha256=$outputHash;ProcessExitCode=$processExitCode;FixtureCleaned=$cleaned;EvidencePath=$evidence;WindowsSupportPromoted=$false;Failure=$failure}
if($status -ne 'Passed'){throw "RawCopy synthetic acceptance failed. Evidence: '$evidence'. $failure"}
$result
