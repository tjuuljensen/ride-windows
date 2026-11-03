<#
.SYNOPSIS
  Prepare the retained PowerShell 7.6.5 runtime inside a disposable test run.
.DESCRIPTION
  Uses one exact publisher ZIP, preserving licenses and notices. No installer,
  PATH edit, module registration or network fallback. The existing checkpoint
  runner owns recovery of the run-local fixture directory.
.NOTES
  Windows PowerShell 5.1/7. Version: 0.1.0. Disposable Windows guest only.
  Source: https://github.com/PowerShell/PowerShell/releases/download/v7.6.5/PowerShell-7.6.5-win-x64.zip
#>
function Get-RidePowerShellRuntimeFixturePin {
  [pscustomobject]@{Name='PowerShell-7.6.5-win-x64.zip';Version='7.6.5';Bytes=106319290;Sha256='32EB8F6CDCE08F86E987D625A2733E54AC3E289AE7E1621B14C0B5BCEC2434EA';Entries=661;ExpandedBytes=256592846}
}
function Expand-RidePowerShellRuntimeFixture {
  <#
  .SYNOPSIS
    Expand a fixed runtime ZIP into a fresh, run-owned guest directory.
  .PARAMETER ArchivePath
    Retained ZIP staged with the test source; never downloaded implicitly.
  .PARAMETER Destination
    Fresh core-runtime directory below the attested portable run.
  .OUTPUTS
    Executable identity and fixture source evidence; does not launch PowerShell.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ArchivePath,[Parameter(Mandatory)][string]$Destination)
  $ErrorActionPreference='Stop'
  if($env:RIDE_INTEGRATION_VM -cne '1'){throw 'Runtime fixture requires an attested disposable guest.'}
  $target=[IO.Path]::GetFullPath($Destination).TrimEnd('\')
  if($target -cnotmatch '^C:\\RIDE\\PortableAcceptance\\[0-9a-f]{32}\\core-runtime$'){throw 'Runtime fixture destination is not a bounded guest run.'}
  foreach($path in @($target,[IO.Path]::GetFullPath($ArchivePath))){
    for($node=[IO.FileInfo]::new($path);$null -ne $node;$node=$(if($node -is [IO.FileInfo]){$node.Directory}else{$node.Parent})){
      if($node.Exists -and ($node.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Runtime fixture path has a reparse point.'}
    }
  }
  if(Test-Path -LiteralPath $target){throw 'Runtime fixture destination already exists.'}
  $pin=Get-RidePowerShellRuntimeFixturePin
  $file=Get-Item -LiteralPath $ArchivePath -Force
  if($file.PSIsContainer -or $file.Name -cne $pin.Name -or $file.Length -ne $pin.Bytes -or (Get-FileHash -LiteralPath $file.FullName).Hash -cne $pin.Sha256){throw 'Runtime archive does not match the retained publisher pin.'}
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip=[IO.Compression.ZipFile]::OpenRead($file.FullName)
  try {
    if($zip.Entries.Count -ne $pin.Entries -or ($zip.Entries|Measure-Object Length -Sum).Sum -ne $pin.ExpandedBytes){throw 'Runtime ZIP inventory differs.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($entry in $zip.Entries){
      $name=$entry.FullName.Replace('\','/')
      if($name -match '(^/|:|(^|/)\.\.(/|$))' -or -not $seen.Add($name) -or (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000){throw 'Unsafe runtime ZIP member.'}
      $candidate=[IO.Path]::GetFullPath((Join-Path $target $name))
      if(-not $candidate.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Runtime ZIP member escapes its directory.'}
    }
  } finally {$zip.Dispose()}
  [IO.Compression.ZipFile]::ExtractToDirectory($file.FullName,$target)
  foreach($name in @('LICENSE.txt','ThirdPartyNotices.txt','pwsh.exe')){if(-not(Test-Path -LiteralPath (Join-Path $target $name) -PathType Leaf)){throw 'Runtime executable or upstream notice is missing.'}}
  $executable=Join-Path $target 'pwsh.exe'
  $signature=Get-AuthenticodeSignature -LiteralPath $executable
  if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'Runtime executable publisher signature is not valid.'}
  $version=(Get-Item -LiteralPath $executable).VersionInfo.ProductVersion
  if($version -notmatch '^7\.6\.5(?:\D|$)'){throw 'Runtime executable version differs.'}
  [pscustomobject]@{Version=$pin.Version;ArchiveSha256=$pin.Sha256;ArchiveBytes=$pin.Bytes;Executable=$executable;ExecutableSha256=(Get-FileHash -LiteralPath $executable).Hash;SignatureStatus=[string]$signature.Status;SignerSubject=$signature.SignerCertificate.Subject;Entries=$pin.Entries;ExpandedBytes=$pin.ExpandedBytes;Scope='Run-local test fixture; no installation or PATH changes'}
}
Export-ModuleMember -Function Expand-RidePowerShellRuntimeFixture
