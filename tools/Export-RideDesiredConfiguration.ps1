<#
.SYNOPSIS
  Export a selected profile as a read-only configuration reference.
.DESCRIPTION
  Reads the built-in catalog and an explicit profile without importing operational
  handlers or inspecting Windows. Binds exact source hashes and a declared target.
  Only registry-value intent is mapped; other handlers/groups remain ReportOnly.
  Creates a new JSON file without replacement. WhatIf reads no source or live state.
.PARAMETER Profile
  Explicit local schema-1 profile. Completion lists repository profiles.
.PARAMETER Target
  Declared target name. Completion uses catalog supported/candidate target names.
.PARAMETER Build
  Declared target build number, not a current-machine observation.
.PARAMETER EditionId
  Declared Windows EditionID; no edition support is inferred.
.PARAMETER InstallationType
  Declared Client, Server, Server Core or Unknown installation type.
.PARAMETER Role
  Declared Workstation, MemberServer, DomainController or Unknown role.
.PARAMETER OutputPath
  New local JSON path in an existing directory. Existing/racing output is preserved.
.EXAMPLE
  .\tools\Export-RideDesiredConfiguration.ps1 -Profile .\profiles\default.psd1 -Target 'Windows 11' -Build 26100 -EditionId Professional -InstallationType Client -Role Workstation -OutputPath C:\Evidence\desired-reference.json -WhatIf
.INPUTS
  None.
.OUTPUTS
  String. Created JSON path. All compliance/current state fields remain Unknown.
.NOTES
  Compatibility: Native Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: Read access to reviewed source files and write access to output parent.
  No elevation, secrets, network, custom library, local configuration or state store.
  Recovery: No Windows mutation. Preserve a partial output and retry with a new name.
  This reference cannot be passed to an apply/restore command. Consumer acceptance
  and native observation mappings remain separate from source validation.
  Version: 0.1.0.
  Changelog: 0.1.0: Add source-bound schema-1 export and read-only completions.
.LINK
  ../docs/desired-configuration-reference.md
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory)]
  [ArgumentCompleter({
    param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $invocationPath=$commandAst.CommandElements[0].Value
      $scriptPath=if($invocationPath -and [IO.File]::Exists($invocationPath)){[IO.Path]::GetFullPath($invocationPath)}else{(Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Path}
      $root=Split-Path -Parent (Split-Path -Parent $scriptPath)
      $prefix=[IO.Path]::GetFileName($wordToComplete.Trim("'",'"'))
      Get-ChildItem -LiteralPath (Join-Path $root 'profiles') -Filter '*.psd1' -File -ErrorAction Stop |
        Where-Object {$_.Name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)} | Sort-Object Name -Unique | ForEach-Object {
          [Management.Automation.CompletionResult]::new(("'"+$_.FullName.Replace("'","''")+"'"),$_.Name,'ParameterValue',$_.Name)
        }
    }catch{}
  })]
  [ValidateNotNullOrEmpty()][string]$Profile,
  [Parameter(Mandatory)]
  [ArgumentCompleter({
    param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
    try{
      $invocationPath=$commandAst.CommandElements[0].Value
      $scriptPath=if($invocationPath -and [IO.File]::Exists($invocationPath)){[IO.Path]::GetFullPath($invocationPath)}else{(Get-Command -Name $commandName -CommandType ExternalScript -ErrorAction Stop).Path}
      $root=Split-Path -Parent (Split-Path -Parent $scriptPath)
      Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -ErrorAction Stop
      $data=Import-RideCatalogData -Path (Join-Path $root 'catalog/operations.psd1')
      @($data.Operations|ForEach-Object {$_.SupportedTargets;$_.CandidateTargets}) | Sort-Object -Unique |
        Where-Object {$_ -and $_.StartsWith($wordToComplete.Trim("'",'"'),[StringComparison]::OrdinalIgnoreCase)} | ForEach-Object {
          [Management.Automation.CompletionResult]::new(("'"+$_.Replace("'","''")+"'"),$_,'ParameterValue',$_)
        }
    }catch{}
  })]
  [ValidateLength(1,255)][string]$Target,
  [Parameter(Mandatory)][ValidateRange(1000,99999999)][int]$Build,
  [Parameter(Mandatory)][ValidateLength(1,255)][string]$EditionId,
  [Parameter(Mandatory)][ValidateSet('Client','Server','Server Core','Unknown')][string]$InstallationType,
  [Parameter(Mandatory)][ValidateSet('Workstation','MemberServer','DomainController','Unknown')][string]$Role,
  [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath
)
$ErrorActionPreference='Stop'
$destination=[IO.Path]::GetFullPath($OutputPath)
if(-not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($destination))){throw 'Create the output parent directory explicitly.'}
if([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)){throw 'Reference output already exists; choose a new filename.'}
if($PSCmdlet.ShouldProcess($destination,'Export a read-only desired-configuration reference')){
  $root=Split-Path -Parent $PSScriptRoot
  Import-Module (Join-Path $root 'modules/RIDE.CatalogData.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.CatalogValidation.psm1') -Force
  Import-Module (Join-Path $root 'modules/RIDE.DesiredConfiguration.psm1') -Force
  $catalogPath=Join-Path $root 'catalog/operations.psd1'
  $profileFile=Get-Item -LiteralPath $Profile -ErrorAction Stop
  if($profileFile -isnot [IO.FileInfo] -or $profileFile.Length -gt 65536){throw 'Profile must be a file no larger than 64 KiB.'}
  $catalogHash=(Get-FileHash -LiteralPath $catalogPath).Hash
  $profileHash=(Get-FileHash -LiteralPath $profileFile.FullName).Hash
  $catalog=Import-RideCatalogData -Path $catalogPath
  $errors=@(Get-RideCatalogValidationErrors -Catalog $catalog -ProfilePaths @($profileFile))
  if($errors.Count){throw 'Catalog/profile validation failed; validate the selected source before exporting.'}
  $profileData=Import-PowerShellDataFile -LiteralPath $profileFile.FullName
  $result=ConvertTo-RideDesiredConfiguration -Catalog $catalog -Profile $profileData -CatalogSha256 $catalogHash -ProfileSha256 $profileHash -Target $Target -Build $Build -EditionId $EditionId -InstallationType $InstallationType -Role $Role
  if((Get-FileHash -LiteralPath $catalogPath).Hash -cne $catalogHash -or (Get-FileHash -LiteralPath $profileFile.FullName).Hash -cne $profileHash){throw 'Source changed during export; discard the reference.'}
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 15)+"`n")
  if($bytes.Length -gt 4MB){throw 'Desired reference exceeds 4 MiB.'}
  $stream=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
  $destination
}
