<#
.SYNOPSIS
  Guide an author through creating or extending a custom library with API 1 choices.
.DESCRIPTION
  Prompts for package or registry metadata, then generates a validated manifest,
  catalog and profile in a new directory, or adds operations with Add. Offers
  supported EXE/MSI installers, download providers, scopes, targets and registry
  types, including coordinated RegistryValueSet entries. HKCR paths are mapped
  to the selected user/machine Software\Classes root before publication. Enter
  an empty value name for (Default). Documentation/product and recovery-information
  URLs are optional for custom entries. Package source
  remains required; license summaries are required, but license/terms links are
  optional HTTP/HTTPS references. Offers an early optional HTTPS sample
  download or local-file inspection before scope, targets and architecture. Never
  executes samples or installs anything; ZIP packaging is separate from EXE/MSI.
  Unknown package detection saves an unpublished draft for later ResumeDraft.
.PARAMETER Path
  New output directory, or existing generated library directory with Add. Prompts
  when omitted in interactive mode. WhatIf writes no files or downloads.
.PARAMETER Add
  Add operations to an existing generated library. Retain prior metadata in a
  sibling history directory and require a higher library version. No installs.
.PARAMETER Definition
  Optional literal .psd1 authoring definition for repeatable, noninteractive use.
  Requires Path. See docs/CUSTOM-LIBRARIES.md for its fields and examples.
.PARAMETER ResumeDraft
  With Definition, prompt for missing installed-product names in a saved draft,
  then publish when every package has confirmed detection metadata.
.PARAMETER ShowOptions
  Return supported authoring choices without prompting or writing.
.PARAMETER Help
  Display native help and return.
.PARAMETER Version
  Print the script version and return.
.EXAMPLE
  .\tools\New-RideLibrary.ps1 -Path .\my-library
  Start the guided helper. Type :cancel at any prompt to stop without publishing.
.EXAMPLE
  .\tools\New-RideLibrary.ps1 -Path .\my-library -Definition .\my-definition.psd1 -WhatIf
  Preview project creation using reviewed authoring data.
.EXAMPLE
  .\tools\New-RideLibrary.ps1 -ShowOptions
.EXAMPLE
  .\tools\New-RideLibrary.ps1 -Path .\my-library -Add
  Add another operation; accept the suggested patch version and retain prior metadata.
.EXAMPLE
  .\tools\New-RideLibrary.ps1 -Path .\my-library -Definition .\my-library.draft.psd1 -ResumeDraft
  Finish a draft after checking its product registration in a disposable VM.
.INPUTS
  None.
.OUTPUTS
  System.Management.Automation.PSCustomObject. Project paths/operation IDs or
  choice rows. An incomplete interactive package definition saves a draft file.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: RIDE checkout; existing writable output parent for generation.
  File inputs: Built-in catalog and optional bounded, declarative authoring data.
  Recovery: New mode refuses existing output. Add mode retains prior metadata in
  a sibling history directory and rolls back failed writes. Validation failure
  removes only this run's staging. Package recovery remains compensating.
  Owner: RIDE-Windows maintainers. Version: 0.5.0.
  Changelog: 0.5.0: Save unknown package detection as a draft and resume after VM verification.
    0.4.1: Explain installed-product detection and where to verify its name.
    0.4.0: Add coordinated/default registry values and scope-explicit HKCR paths.
    0.3.0: Add to existing libraries; allow optional HTTP/HTTPS license links.
    0.2.1: Refresh cached metadata modules and reject empty choice prompts.
    0.2.0: Inspect optional early samples and author ZIP-contained installers.
    0.1.0: Add guided choices and validated custom-library generation.
.LINK
  ../docs/CUSTOM-LIBRARIES.md
#>


[CmdletBinding(SupportsShouldProcess)]
param(
  [string] $Path = '',
  [string] $Definition = '',
  [switch] $Add,
  [switch] $ResumeDraft,
  [switch] $ShowOptions,
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.5.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# A long-lived console can retain an earlier schema after a checkout update.
Import-Module (Join-Path $root 'modules/RIDE.LibrarySchema.psm1') -Force -ErrorAction Stop
$options = Get-RideLibraryAuthoringOptions -Root $root
if ($ShowOptions) {
  foreach ($name in $options.Keys | Sort-Object) { [pscustomobject]@{ Field = $name; Choices = $options[$name] } }
  return
}
if ($ResumeDraft -and -not $Definition) { throw '-ResumeDraft requires -Definition with an existing draft.' }

function Read-AuthoringText {
  param([string] $Label, [string] $Default = '', [switch] $Optional, [scriptblock] $Validate)
  while ($true) {
    $suffix = if ($Default) { " [$Default]" } elseif ($Optional) { ' [optional; Enter to skip]' } else { '' }
    $value = [string](Read-Host ($Label + $suffix))
    if ($value -eq ':cancel') { throw [OperationCanceledException]::new('Authoring cancelled; no project was published.') }
    if (-not $value -and $Default) { $value = $Default }
    if ([string]::IsNullOrWhiteSpace($value) -and -not $Optional) { Write-Host 'Enter a value, or type :cancel.'; continue }
    if ($value -and $Validate -and -not (& $Validate $value)) { Write-Host 'Invalid value; try again, or type :cancel.'; continue }
    return $value
  }
}

function Read-AuthoringChoice {
  param([string] $Label, [string[]] $Choices, [switch] $Multiple, [string] $Default = '')
  if (-not $Choices.Count -or @($Choices | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count) {
    throw "No valid choices were loaded for '$Label'. Check the authoring schema; no project was published."
  }
  if ($Default -and $Default -notin $Choices) { throw "Default '$Default' is not available for '$Label'. Check the authoring schema; no project was published." }
  Write-Host $Label
  for ($index = 0; $index -lt $Choices.Count; $index++) { Write-Host ('  {0}. {1}' -f ($index + 1), $Choices[$index]) }
  while ($true) {
    $inputText = Read-AuthoringText $(if ($Multiple) { 'Choose numbers or names, separated by commas' } else { 'Choose a number or name' }) -Default $Default
    $selected = @(); $valid = $true
    foreach ($part in $inputText.Split(',')) {
      $part = $part.Trim(); $number = 0
      if ([int]::TryParse($part, [ref]$number) -and $number -ge 1 -and $number -le $Choices.Count) { $selected += $Choices[$number - 1] }
      elseif ($part -in $Choices) { $selected += @($Choices | Where-Object { $_ -eq $part })[0] }
      else { $valid = $false }
    }
    if ($valid -and ($Multiple -or $selected.Count -eq 1)) { return ($selected | Select-Object -Unique) }
    Write-Host 'Choose from the listed values.'
  }
}

function Read-AuthoringUri {
  param([string] $Label, [switch] $Optional, [string] $Default = '', [switch] $AllowHttp)
  Read-AuthoringText -Label $Label -Optional:$Optional -Default $Default -Validate {
    param($value)
    $schemes = if ($AllowHttp) { @('http', 'https') } else { @('https') }
    [Uri]::IsWellFormedUriString($value, [UriKind]::Absolute) -and ([Uri]$value).Scheme -in $schemes -and -not ([Uri]$value).UserInfo
  }
}

function Read-RegistryData {
  param([string] $Label, [string] $Type)
  while ($true) {
    $value = Read-AuthoringText -Label "$Label ($Type; literal text/numbers, not PowerShell code)" -Optional:($Type -in @('String', 'ExpandString'))
    try {
      switch ($Type) {
        { $_ -in @('String', 'ExpandString') } { return $value }
        DWord {
          $number = if ($value -match '^0x[0-9a-fA-F]+$') { [Convert]::ToInt64($value.Substring(2), 16) } else { [long]::Parse($value, [Globalization.CultureInfo]::InvariantCulture) }
          if ($number -gt [int]::MaxValue -and $number -le [uint32]::MaxValue) { $number -= 4294967296 }
          return [int]$number
        }
        QWord { return $(if ($value -match '^0x[0-9a-fA-F]+$') { [Convert]::ToInt64($value.Substring(2), 16) } else { [long]::Parse($value, [Globalization.CultureInfo]::InvariantCulture) }) }
        Binary {
          $bytes = @($value.Split(',') | ForEach-Object {
            $part = $_.Trim()
            $number = if ($part -match '^0x[0-9a-fA-F]+$') { [Convert]::ToInt32($part.Substring(2), 16) } else { [int]::Parse($part, [Globalization.CultureInfo]::InvariantCulture) }
            if ($number -lt 0 -or $number -gt 255) { throw 'A byte must be between 0 and 255.' }
            $number
          })
          Write-Output -NoEnumerate $bytes
          return
        }
      }
    } catch { Write-Host 'Enter a value of the selected type. Binary uses comma-separated bytes; integers accept decimal or 0x hexadecimal.' }
  }
}

function Read-RegistryPath {
  param([string] $Scope)
  $hive = if ($Scope -eq 'User') { 'HKCU' } else { 'HKLM' }
  $entered = Read-AuthoringText "Registry key path (${hive}:\ or HKCR; long .reg roots accepted)" -Validate {
    param($value)
    try { $null = ConvertTo-RideLibraryRegistryPath -Path $value -Scope $Scope; $true } catch { Write-Host $_.Exception.Message; $false }
  }
  $normalized = ConvertTo-RideLibraryRegistryPath -Path $entered -Scope $Scope
  Write-Host ("Registry destination: $normalized")
  $normalized
}

if ($Definition) {
  if (-not $Path) { throw '-Definition requires -Path; no interactive prompts are used.' }
  $file = Get-Item -LiteralPath $Definition -ErrorAction Stop
  if ($file.PSIsContainer -or $file.Extension -ne '.psd1' -or $file.Length -gt 256KB) { throw 'Definition must be a .psd1 file of at most 256 KiB.' }
  $tokens = $null; $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors.Count -or $ast.ParamBlock -or $ast.BeginBlock -or $ast.ProcessBlock -or $ast.EndBlock.Statements.Count -ne 1) { throw 'Definition must contain a single declarative hashtable.' }
  $statement = $ast.EndBlock.Statements[0]
  if ($statement -isnot [Management.Automation.Language.PipelineAst] -or $statement.PipelineElements.Count -ne 1 -or $statement.PipelineElements[0].Expression -isnot [Management.Automation.Language.HashtableAst]) { throw 'Definition must contain a single declarative hashtable.' }
  $data = $statement.PipelineElements[0].Expression.SafeGetValue()
  if ($ResumeDraft) {
    foreach ($operation in @($data.Operations)) {
      if ($operation.Kind -eq 'Package' -and $operation.ContainsKey('DetectionDisplayName') -and [string]::IsNullOrWhiteSpace($operation.DetectionDisplayName)) {
        Write-Host ("Confirm the registered Windows product name for {0} after a test installation in a disposable VM." -f $operation.Name)
        $operation.DetectionDisplayName = Read-AuthoringText 'Installed product name shown in Windows Installed apps'
      }
    }
  }
} else {
  Write-Host 'Author a custom RIDE library. Optional sample inspection downloads files; no installers or Windows changes run.'
  Write-Host 'Type :cancel at any prompt to stop. Test installation and rollback in a disposable Windows VM.'
  if (-not $Path) { $Path = Read-AuthoringText $(if ($Add) { 'Existing generated library directory' } else { 'New library directory (parent must exist)' }) }
  if ($Add) {
    foreach ($moduleName in @('RIDE.CatalogData', 'RIDE.LibrarySchema', 'RIDE.CatalogValidation', 'RIDE.Libraries')) {
      Import-Module (Join-Path $root ('modules/' + $moduleName + '.psm1')) -Force -ErrorAction Stop
    }
    $context = Get-RideCatalogContext -Root $root -Library (Join-Path $Path 'ride-library.psd1')
    $existing = $context.Libraries[0]
    $oldVersion = [version]$existing.Version
    $nextVersion = '{0}.{1}.{2}' -f $oldVersion.Major, $oldVersion.Minor, ($oldVersion.Build + 1)
    Write-Host ("Add to library {0}, currently {1}. Original metadata will be retained for recovery." -f $existing.Id, $existing.Version)
    $data = @{
      Id = $existing.Id
      Version = Read-AuthoringText 'New library version' -Default $nextVersion -Validate { param($value) $value -match '^\d+\.\d+\.\d+$' -and [version]$value -gt $oldVersion }
      Operations = @()
    }
  } else {
    if (Test-Path -LiteralPath $Path) { throw 'Output already exists; use -Add for a generated library or choose a new directory.' }
    $data = @{
      Id = Read-AuthoringText 'Library namespace, such as mycompany.tools' -Validate { param($value) $value -cmatch '^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$' }
      Version = Read-AuthoringText 'Library version' -Default '0.1.0' -Validate { param($value) $value -match '^\d+\.\d+\.\d+$' }
      Operations = @()
    }
  }
  do {
    $kind = Read-AuthoringChoice 'What do you want to add?' $options.Kinds
    $sample = $null; $sampleUri = ''
    if ($kind -eq 'Package') {
      Import-Module (Join-Path $root 'modules/RIDE.InstallerInspection.psm1') -ErrorAction Stop
      $sampleSource = Read-AuthoringChoice 'Inspect an early sample before answering package questions?' @('Skip', 'Download URL', 'Local file')
      if ($sampleSource -ne 'Skip') {
        $sampleParameters = @{ WhatIf = $WhatIfPreference; Confirm = $false }
        if ($sampleSource -eq 'Download URL') {
          $sampleUri = Read-AuthoringUri 'Early test download URL (downloads a temporary sample; never executes it)'
          $sampleParameters.Uri = $sampleUri
        } else { $sampleParameters.Path = Read-AuthoringText 'Existing local sample path' }
        try {
          $sample = Get-RideInstallerInspection @sampleParameters
          if ($sample -and $sample.ArchiveType -eq 'Zip' -and -not $sample.InstallerType) {
            if (-not $sample.Candidates.Count) { throw 'ZIP contains no supported installer candidates.' }
            $sampleParameters.InstallerEntry = Read-AuthoringChoice 'Select the self-contained ZIP installer' $sample.Candidates
            $sample = Get-RideInstallerInspection @sampleParameters
          }
          if ($sample) {
            $sample | Format-List AssetName, ArchiveType, InstallerEntry, InstallerType, ProductName, ProductVersion, BinaryArchitecture, Sha256, InstallerSha256 | Out-Host
            Write-Host 'Review resource hints. BinaryArchitecture describes the launcher, not the installed payload. Observed hashes are not publisher verification.'
          }
        } catch [OperationCanceledException] { throw }
        catch { Write-Warning ('Sample inspection failed; continue with manual metadata: ' + $_.Exception.Message); $sample = $null }
      }
    }
    $operation = @{
      Kind = $kind
      Id = Read-AuthoringText 'Local operation name, such as my-app (library prefix is added)' -Validate { param($value) $value -cmatch '^[a-z][a-z0-9.-]*$' }
      Name = Read-AuthoringText 'Display name' -Default $(if ($sample) { $sample.ProductName } else { '' })
      Description = Read-AuthoringText 'What does this operation do?'
      Scope = Read-AuthoringChoice 'Which installation/registry scope?' $options.Scopes
      SupportedTargets = @(Read-AuthoringChoice 'Choose targets you will test in disposable VMs' $options.SupportedTargets -Multiple)
    }
    if ($kind -eq 'Package') {
      $operation.InstallerType = Read-AuthoringChoice 'Installer format' $options.InstallerTypes -Default $(if ($sample) { $sample.InstallerType } else { '' })
      $archiveType = Read-AuthoringChoice 'Download packaging (ZIP supports one self-contained installer)' $options.ArchiveTypes -Default $(if ($sample) { $sample.ArchiveType } else { 'None' })
      if ($archiveType -eq 'Zip') {
        $operation.ArchiveType = 'Zip'
        $operation.InstallerEntry = Read-AuthoringText 'Exact installer member path inside ZIP (forward slashes)' -Default $(if ($sample) { $sample.InstallerEntry } else { '' })
        $memberHash = Read-AuthoringText 'Publisher-provided SHA-256 of the inner installer (not the ZIP)' -Optional -Validate { param($value) $value -match '^[a-fA-F0-9]{64}$' }
        if ($memberHash) { $operation.ExpectedInstallerSha256 = $memberHash }
      }
      $operation.Architecture = Read-AuthoringChoice 'Package architecture (confirm payload support; do not rely only on launcher architecture)' $options.Architectures
      $providers = if ($archiveType -eq 'Zip') { @('DirectHttps') } else { $options.DownloadProviders }
      $operation.DownloadProvider = Read-AuthoringChoice 'Source: DirectHttps pins a version; GitHubReleaseApi selects a release asset' $providers -Default $(if ($sampleUri) { 'DirectHttps' } else { '' })
      $operation.DownloadUri = Read-AuthoringUri 'Official publisher installer URL (or GitHub latest-release API URL)' -Default $sampleUri
      if ($operation.DownloadProvider -eq 'DirectHttps') {
        $versionHint = if ($sample -and $sample.ProductVersion -match '^[0-9A-Za-z][0-9A-Za-z.+_-]*$') { $sample.ProductVersion } else { '' }
        $operation.PackageVersion = Read-AuthoringText 'Package version (review resource hint; separate from library version)' -Default $versionHint -Validate { param($value) $value -match '^[0-9A-Za-z][0-9A-Za-z.+_-]*$' }
        $extension = if ($archiveType -eq 'Zip') { '.zip' } else { '.' + $operation.InstallerType.ToLowerInvariant() }
        $nameHint = if ($sample -and [IO.Path]::GetExtension($sample.AssetName) -eq $extension) { $sample.AssetName -replace '[^a-zA-Z0-9._-]', '_' } else { '' }
        $operation.AssetName = Read-AuthoringText "Local download filename ending in $extension" -Default $nameHint -Validate { param($value) $value -match '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.(exe|msi|zip)$' -and [IO.Path]::GetExtension($value) -eq $extension }
        $checksum = Read-AuthoringText 'Publisher-provided SHA-256 of the download (ZIP hash for ZIP packaging)' -Optional -Validate { param($value) $value -match '^[a-fA-F0-9]{64}$' }
        if ($checksum) { $operation.ExpectedSha256 = $checksum }
      } else {
        $operation.AssetPattern = Read-AuthoringText 'Regex matching exactly one release installer filename' -Validate { param($value) try { $null = [regex]::new($value); $true } catch { $false } }
      }
      Write-Host 'Package detection uses the product name registered in Windows Installed apps (or Programs and Features).'
      Write-Host 'For a games bundle, enter its full installed product name, not an included game such as Solitaire.'
      Write-Host 'If it is already installed, check its entry in Installed apps. Otherwise press Enter; the helper saves a draft to finish after a test installation in a disposable VM.'
      Write-Host 'No installable library is published until the detection name is supplied. An incorrect name makes show/install/remove treat an installed package as absent.'
      if ($sample -and $sample.ProductName) { Write-Host ("Installer resource name (hint only; verify registration): {0}" -f $sample.ProductName) }
      $operation.DetectionDisplayName = Read-AuthoringText 'Installed product name (Enter to defer; not an included app)' -Optional
      $arguments = if ($operation.InstallerType -eq 'Msi') { '/qn /norestart' } else { '' }
      $operation.InstallerArguments = Read-AuthoringText 'Silent installer arguments from the publisher' -Default $arguments
      $operation.UninstallerArguments = Read-AuthoringText 'Silent uninstaller arguments from the publisher' -Default $arguments
      if ($operation.InstallerType -eq 'Msi') { $operation.SuccessExitCodes = @(0, 3010) }
      $operation.License = Read-AuthoringText 'License summary (or describe where the local/payload license is found)' -Default 'Unknown'
      $licenseUri = Read-AuthoringUri 'License information URL (HTTP/HTTPS, including internal/localhost)' -Optional -AllowHttp
      if ($licenseUri) { $operation.LicenseUri = $licenseUri }
      $productUri = Read-AuthoringUri 'Product/documentation URL' -Optional
      if ($productUri) { $operation.ProductUri = $productUri }
      $termsUri = Read-AuthoringUri 'Separate applicable terms URL (HTTP/HTTPS)' -Optional -AllowHttp
      if ($termsUri) { $operation.TermsUri = $termsUri }
      $operation.TargetDefaults = @{}
      foreach ($target in $operation.SupportedTargets) {
        $default = Read-AuthoringChoice "Package presence in the standard $target image" @('Absent', 'Present')
        $operation.TargetDefaults[$target] = @{ DefaultValue = $default; EffectiveDefault = "Author-declared package default: $default; verify the target image" }
      }
      Write-Host 'Package rollback is compensating. Removing a new installation is supported; recovering a previous version is not guaranteed.'
    } else {
      if ($kind -eq 'RegistryValue') {
        $operation.RegistryPath = Read-RegistryPath -Scope $operation.Scope
        $operation.ValueName = Read-AuthoringText 'Registry value name (Enter for unnamed Default value)' -Optional
        $operation.ValueType = Read-AuthoringChoice 'Registry data type' $options.RegistryValueTypes
      }
      $stateName = Read-AuthoringText 'Desired state name' -Default 'Enabled' -Validate { param($value) $value -ne 'WindowsDefault' }
      if ($kind -eq 'RegistryValueSet') {
        Write-Host 'Declare 2-10 coordinated values for one setting. Enter an empty String value to write empty data; WindowsDefault removes values.'
        $operation.RegistryValues = @(); $desired = @{}; $unset = @{}
        do {
          $member = @{
            Key = Read-AuthoringText 'Component name (unique local label, such as Menu or Command)' -Validate { param($value) $value -cmatch '^[a-zA-Z][a-zA-Z0-9_-]*$' -and $value -notin $desired.Keys }
            RegistryPath = Read-RegistryPath -Scope $operation.Scope
            ValueName = Read-AuthoringText 'Registry value name (Enter for unnamed Default value)' -Optional
            ValueType = Read-AuthoringChoice 'Registry data type' $options.RegistryValueSetTypes
          }
          $desired[$member.Key] = Read-RegistryData 'Desired value' $member.ValueType
          $unset[$member.Key] = $null
          $operation.RegistryValues += $member
          $anotherValue = if ($operation.RegistryValues.Count -lt 2) { 'Yes' } elseif ($operation.RegistryValues.Count -ge 10) { 'No' }
            else { Read-AuthoringChoice 'Add another value to this setting?' @('No', 'Yes') }
        } while ($anotherValue -eq 'Yes')
        $operation.States = @{ WindowsDefault = $unset }
      } else {
        $desired = Read-RegistryData 'Desired value' $operation.ValueType
        $operation.States = @{ WindowsDefault = $null }
      }
      $operation.States[$stateName] = $desired
      $operation.BaselineState = 'WindowsDefault'
      $operation.TargetDefaults = @{}
      foreach ($target in $operation.SupportedTargets) {
        if ($kind -eq 'RegistryValueSet') {
          $operation.TargetDefaults[$target] = @{ DefaultValue = 'PlatformDefined'; EffectiveDefault = Read-AuthoringText "Effective $target behavior without these overrides (literal defaults remain unverified)" }
          continue
        }
        $existence = Read-AuthoringChoice "Literal registry value in the standard $target image" @('Absent', 'Present', 'Platform-defined')
        $defaultValue = if ($existence -eq 'Present') { Read-RegistryData 'Literal default value' $operation.ValueType } else { $null }
        $operation.TargetDefaults[$target] = @{
          DefaultValueExists = $(if ($existence -eq 'Platform-defined') { $null } else { $existence -eq 'Present' })
          DefaultValue = $defaultValue
          EffectiveDefault = Read-AuthoringText 'Effective platform behavior when no override is applied'
        }
      }
      $documentationUri = Read-AuthoringUri 'Documentation URL' -Optional
      if ($documentationUri) { $operation.DocumentationUri = $documentationUri }
      Write-Host 'WindowsDefault removes the override. Saved-run restore recovers the captured value and type.'
    }
    $recoveryUri = Read-AuthoringUri 'Recovery instructions URL (information only; optional rollback aid)' -Optional
    if ($recoveryUri) { $operation.RecoveryUri = $recoveryUri }
    $data.Operations += $operation
    $more = Read-AuthoringChoice 'Add another operation?' @('No', 'Yes')
  } while ($more -eq 'Yes')
}

# Refresh metadata dependencies before publishing, including an older ZIP validator.
foreach ($moduleName in @('RIDE.CatalogData', 'RIDE.LibrarySchema', 'RIDE.CatalogValidation', 'RIDE.Libraries', 'RIDE.LibraryAuthoring')) {
  Import-Module (Join-Path $root ('modules/' + $moduleName + '.psm1')) -Force -ErrorAction Stop
}
if (@($data.Operations | Where-Object { $_.Kind -eq 'Package' -and $_.ContainsKey('DetectionDisplayName') -and [string]::IsNullOrWhiteSpace($_.DetectionDisplayName) }).Count) {
  if ($Definition) { throw 'The draft still has an unknown installed-product name. Use -ResumeDraft after a test installation.' }
  $draftPath = [IO.Path]::GetFullPath($Path + '.draft.psd1')
  $draftParameters = @{ Path = $draftPath; Definition = $data; WhatIf = [bool]$WhatIfPreference }
  if ($PSBoundParameters.ContainsKey('Confirm')) { $draftParameters.Confirm = $PSBoundParameters.Confirm }
  $saved = Save-RideLibraryAuthoringDraft @draftParameters
  if ($saved) {
    Write-Host "Draft saved: $saved"
    Write-Host 'After installing the sample in a disposable VM, run this helper with -Path, -Definition <draft path> and -ResumeDraft to publish.'
    if ($Add) { Write-Host 'Keep -Add when resuming this draft.' }
  }
  return
}
Write-Host 'Review the generated profile before applying it. No profile is applied by this helper.'
$creationParameters = @{ Path = $Path; Definition = $data; Root = $root; WhatIf = $WhatIfPreference }
if ($PSBoundParameters.ContainsKey('Confirm')) { $creationParameters.Confirm = $PSBoundParameters.Confirm }
if ($Add) { Add-RideLibraryOperation @creationParameters } else { New-RideLibraryProject @creationParameters }
