<#
.SYNOPSIS
  Share read-only catalog and profile validation with external library loading.
.DESCRIPTION
  Checks the built-in operation schemas and declarative profile references.
  Returns diagnostic strings without importing handlers or inspecting Windows.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Owner: RIDE-Windows maintainers. Version: 0.23.0.
  Changelog: 0.23.0: Validate pinned exact portable ZIP member selections.
    0.22.0: Validate the fixed user-bin startup PATH profile renderer.
    0.21.0: Require explicit reviewed Store identity/removability metadata.
    0.20.0: Validate separate pending Store app actions and refuse profile routing.
    0.19.0: Validate pending local password-age range and focused lifecycle.
    0.18.0: Validate pending service candidates and dependency refusal metadata.
    0.17.0: Validate exact KeepCurrent markers in coordinated registry states.
    0.16.0: Validate pending owned power-plan creation and compensating recovery.
    0.15.0: Allow explicitly pending scalar registry policy candidates.
    0.14.0: Validate pending value sets, minimum build and read-only observations.
    0.13.0: Validate pending firewall profiles and local enablement states.
    0.12.0: Validate exact service identity and optional runtime/explicit delayed-start choices.
    0.11.0: Validate managed profile settings and candidate targets.
    0.10.0: Validate current-user destination and execution contracts.
    0.9.0: Validate setting presentation evidence and scalar registry scope.
    0.8.0: Validate pinned WinSCP portable publisher sources.
    0.7.0: Validate Signal feeds, user-data preservation and Mozilla locales.
    0.6.1: Allow architecture-neutral managed or mixed portable ZIP distributions.
    0.6.0: Validate variants, portable metadata, publisher sources and pending acceptance.
    0.5.0: Validate custom coordinated registry values and unnamed default values.
    0.4.0: Allow optional HTTP/HTTPS license and terms links for custom packages.
    0.3.0: Validate optional ZIP packaging, member paths and member hashes.
    0.2.0: Allow optional custom references and validated direct HTTPS installers.
    0.1.0: Extract the existing validator for shared library validation.
#>

$script:ModuleVersion = '0.21.0'


function Get-RideCatalogValidationErrors {
  <#
  .SYNOPSIS
    Return catalog and profile schema diagnostics without changing state.
  .PARAMETER Catalog
    Resolved SchemaVersion 1 catalog data.
  .PARAMETER ProfilePaths
    Explicit profile FileInfo objects to validate against this catalog.
  .PARAMETER CustomOperationIds
    Resolver-owned custom IDs whose information references are optional; custom
    license/terms links accept HTTP or HTTPS when supplied.
  .EXAMPLE
    Get-RideCatalogValidationErrors -Catalog $catalog
  .INPUTS
    None.
  .OUTPUTS
    System.String. One diagnostic per invalid field or reference.
  .NOTES
    Read-only. Version and compatibility follow the module overview.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][hashtable] $Catalog, [IO.FileInfo[]] $ProfilePaths = @(), [string[]] $CustomOperationIds = @())
  $errors = New-Object System.Collections.Generic.List[string]
  function Add-Error([string] $Message) { $errors.Add($Message) }
  if ($Catalog.SchemaVersion -ne 1) { Add-Error 'Catalog must declare SchemaVersion 1.' }
  $ids = @{}
  foreach ($operation in $catalog.Operations) {
    $isCustom = $operation.Id -in $CustomOperationIds
    if ($operation.ContainsKey('Variants')) {
      if ($operation.Kind -ne 'Package' -or $operation.Variants -isnot [hashtable] -or $operation.Variants.Count -gt 16 -or -not $operation.DefaultVariant -or -not $operation.Variants.ContainsKey($operation.DefaultVariant)) { Add-Error "Invalid package variants/default: $($operation.Id)" }
      else {
        foreach ($variantName in $operation.Variants.Keys) {
          if ($variantName -notmatch '^[a-z][a-z0-9-]*$' -or $operation.Variants[$variantName] -isnot [hashtable]) { Add-Error "Invalid variant key/data: $($operation.Id)"; continue }
          $flat = $operation.Clone(); $flat.Remove('Variants'); $flat.Remove('DefaultVariant')
          foreach ($key in $operation.Variants[$variantName].Keys) {
            if ($key -in @('Id', 'PackageId', 'Kind', 'Handler', 'Library', 'Variants', 'DefaultVariant', 'SelectedVariant', 'ResolvedToolsDirectory', 'InstallDirectory', 'LicenseReviewStatus', 'DistributionNotes', 'LicenseReviewedAt')) { Add-Error "Variant cannot override identity/review/runtime fields: $($operation.Id) / $key"; continue }
            $flat[$key] = $operation.Variants[$variantName][$key]
          }
          if ($flat.PrerequisitePackageId -and $flat.PrerequisitePackageId -notin @($catalog.Operations | Where-Object Kind -eq 'Package' | ForEach-Object Id)) { Add-Error "Unknown variant package prerequisite: $($operation.Id) / $variantName" }
          foreach ($problem in Get-RideCatalogValidationErrors -Catalog @{ SchemaVersion=1; Operations=@($flat); Groups=@() } -CustomOperationIds $CustomOperationIds) {
            if ($problem -notlike '*Unknown package prerequisite*') { Add-Error "Variant $variantName : $problem" }
          }
        }
      }
    }
    if ($operation.ContainsKey('RecoveryUri') -and (-not [Uri]::IsWellFormedUriString([string]$operation.RecoveryUri, [UriKind]::Absolute) -or ([Uri]$operation.RecoveryUri).Scheme -ne 'https')) {
      Add-Error "Recovery information must use an absolute HTTPS URI: $($operation.Id)"
    }
    foreach ($localField in @('LicenseReviewStatus', 'DistributionNotes', 'LicenseReviewedAt', 'ReviewOwner', 'ReviewedVersion')) {
      if ($operation.ContainsKey($localField)) { Add-Error "User/company license reviews belong in local storage, not the catalog: $($operation.Id) / $localField" }
    }
    if ($operation.Kind -in @('Package', 'Artifact')) {
      if ([string]::IsNullOrWhiteSpace([string]$operation.License)) { Add-Error "Download operation requires a license summary (Unknown when unavailable): $($operation.Id)" }
      if ($isCustom) {
        foreach ($field in @('LicenseUri', 'TermsUri')) {
          if ($operation.ContainsKey($field) -and (-not [Uri]::IsWellFormedUriString([string]$operation[$field], [UriKind]::Absolute) -or
              ([Uri]$operation[$field]).Scheme -notin @('http', 'https') -or ([Uri]$operation[$field]).UserInfo)) {
            Add-Error "Custom $field must be an absolute HTTP/HTTPS URI without credentials; omit unavailable links: $($operation.Id)"
          }
        }
      } elseif (-not [Uri]::IsWellFormedUriString([string]$operation.LicenseUri, [UriKind]::Absolute) -or ([Uri]$operation.LicenseUri).Scheme -ne 'https') {
        Add-Error "Download operation requires an absolute HTTPS license URI: $($operation.Id)"
      }
      if (-not $isCustom -and $operation.ContainsKey('TermsUri') -and (-not [Uri]::IsWellFormedUriString([string]$operation.TermsUri, [UriKind]::Absolute) -or ([Uri]$operation.TermsUri).Scheme -ne 'https')) {
        Add-Error "Additional terms must use an absolute HTTPS URI: $($operation.Id)"
      }
    }
    foreach ($field in @('Id', 'Name', 'Kind', 'Category', 'Description', 'SupportedTargets', 'Scope', 'RequiresAdmin', 'Actions', 'Handler', 'Rollback')) {
      if (-not $operation.ContainsKey($field)) { Add-Error "Operation is missing required field '$field': $($operation.Id)" }
    }
    if ($operation.Id -notmatch '^[a-z][a-z0-9.-]+$') { Add-Error "Invalid operation ID: $($operation.Id)" }
    if ($ids.ContainsKey($operation.Id)) { Add-Error "Duplicate catalog ID: $($operation.Id)" }
    $ids[$operation.Id] = $true
    if ($operation.Scope -notin @('Machine', 'User')) { Add-Error "Invalid scope for $($operation.Id): $($operation.Scope)" }
    if ($operation.RequiresAdmin -isnot [bool]) { Add-Error "RequiresAdmin must be Boolean: $($operation.Id)" }
    if ($operation.Kind -notin @('Package', 'Artifact') -and $operation.Scope -eq 'Machine' -and $operation.RequiresAdmin -ne $true) {
      Add-Error "Machine settings require elevation: $($operation.Id)"
    }
    if ($operation.ContainsKey('SettingPresentation')) {
      $presentation = $operation.SettingPresentation
      if ($operation.Kind -in @('Package', 'Artifact') -or $presentation -isnot [hashtable]) {
        Add-Error "Setting presentation requires a setting and a metadata table: $($operation.Id)"
      }
      else {
        $allowedPresentationFields = @('AppliesTo', 'Behavior', 'GuiEffect', 'GuiPath', 'Requirements', 'OtherSupportedChoices', 'ReferenceUris')
        foreach ($field in $presentation.Keys) {
          if ($field -notin $allowedPresentationFields) { Add-Error "Unknown setting presentation field: $($operation.Id) / $field" }
        }
        foreach ($field in @('AppliesTo', 'GuiEffect', 'GuiPath')) {
          if ($presentation.ContainsKey($field) -and ($presentation[$field] -isnot [string] -or [string]::IsNullOrWhiteSpace($presentation[$field]))) { Add-Error "Setting presentation requires nonblank text: $($operation.Id) / $field" }
        }
        if ($presentation.Behavior -notin @('Preference', 'EnforcedPolicy', 'RecommendedPolicy', 'Configuration', 'Unverified')) { Add-Error "Invalid setting behavior: $($operation.Id)" }
        foreach ($field in @('Requirements', 'OtherSupportedChoices', 'ReferenceUris')) {
          if (-not $presentation.ContainsKey($field) -or @($presentation[$field]).Count -eq 0) { Add-Error "Setting presentation requires $field evidence: $($operation.Id)" }
          foreach ($value in @($presentation[$field])) {
            if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { Add-Error "Setting presentation requires nonblank entries: $($operation.Id) / $field" }
          }
        }
        foreach ($reference in @($presentation.ReferenceUris)) {
          if (-not [Uri]::IsWellFormedUriString([string]$reference, [UriKind]::Absolute) -or ([Uri]$reference).Scheme -ne 'https' -or ([Uri]$reference).UserInfo -or (-not $isCustom -and ([Uri]$reference).Host -notin @('learn.microsoft.com', 'support.microsoft.com'))) { Add-Error "Setting presentation requires authoritative HTTPS references: $($operation.Id)" }
        }
      }
    }
    if ($operation.ContainsKey('MinimumBuild') -and ($operation.MinimumBuild -isnot [int] -or $operation.MinimumBuild -lt 1)) { Add-Error "MinimumBuild must be a positive integer: $($operation.Id)" }
    $pendingPackage = $operation.Kind -in @('Package', 'StoreApp', 'ProfileSetting', 'FirewallProfile', 'RegistryValueSet', 'RegistryValue', 'OwnedPowerPlan', 'WindowsService', 'LocalPasswordMaximumAge') -and $operation.PendingAcceptance -eq $true -and @($operation.SupportedTargets).Count -eq 0
    if ($operation.ContainsKey('PendingAcceptance') -and ($operation.PendingAcceptance -isnot [bool] -or ($operation.PendingAcceptance -and -not $pendingPackage))) { Add-Error "Pending acceptance requires a supported candidate kind with no supported targets: $($operation.Id)" }
    if ($pendingPackage -and (-not $operation.CandidateTargets -or @($operation.CandidateTargets | Where-Object { $_ -notin @('Windows 11', 'Windows Server 2025') }).Count)) { Add-Error "Pending operation requires explicit candidate targets: $($operation.Id)" }
    if (@($operation.SupportedTargets).Count -eq 0 -and -not $pendingPackage) { Add-Error "No supported target declared for $($operation.Id)" }
    if (-not $operation.ContainsKey('TargetDefaults')) {
      Add-Error "Operation is missing target defaults: $($operation.Id)"
      $targetDefaults = @{}
    }
    else {
      $targetDefaults = $operation.TargetDefaults
    }
    foreach ($target in $operation.SupportedTargets) {
      if (-not $targetDefaults.ContainsKey($target)) {
        Add-Error "Operation '$($operation.Id)' is missing defaults for '$target'."
        continue
      }
      $defaults = $targetDefaults[$target]
      if (-not $defaults.ContainsKey('EffectiveDefault')) { Add-Error "Operation '$($operation.Id)' is missing an effective default for '$target'." }
      if ($operation.Kind -eq 'RegistryValue' -and -not $defaults.ContainsKey('DefaultValueExists')) {
        Add-Error "Operation '$($operation.Id)' is missing literal default existence for '$target'."
      }
      if ($operation.Kind -eq 'RegistryValue' -and $defaults.ContainsKey('DefaultValueExists')) {
        if ($null -ne $defaults.DefaultValueExists -and $defaults.DefaultValueExists -isnot [bool]) {
          Add-Error "Registry default existence must be a Boolean or null: $($operation.Id) ($target)."
        }
        if (-not $defaults.ContainsKey('DefaultValue') -or ($null -eq $defaults.DefaultValueExists -and $null -ne $defaults.DefaultValue)) {
          Add-Error "Registry defaults require DefaultValue; platform-defined defaults must use null: $($operation.Id) ($target)."
        }
      }
    if ($operation.Kind -in @('Package', 'Artifact', 'DefenderExclusion') -and -not $defaults.ContainsKey('DefaultValue')) {
        Add-Error "Operation '$($operation.Id)' is missing a literal default for '$target'."
      }
      if ($operation.Kind -eq 'RegistryKeySet' -and -not $defaults.ContainsKey('DefaultValue')) {
        Add-Error "Registry key-set operation '$($operation.Id)' is missing a literal default for '$target'."
      }
      if ($operation.Kind -eq 'WindowsService' -and -not $defaults.ContainsKey('DefaultValue')) {
        Add-Error "Operation '$($operation.Id)' is missing a literal service default for '$target'."
      }
      if ($operation.Kind -eq 'BackgroundAppOverrides' -and -not $defaults.ContainsKey('DefaultValue')) {
        Add-Error "Operation '$($operation.Id)' is missing a literal override default for '$target'."
      }
      if ($operation.Kind -eq 'BootConfiguration' -and -not $defaults.ContainsKey('DefaultValue')) {
        Add-Error "Operation '$($operation.Id)' is missing a literal boot configuration default for '$target'."
      }
      if ($operation.Kind -eq 'NetworkProfile' -and -not $defaults.ContainsKey('DefaultValue')) {
        Add-Error "Operation '$($operation.Id)' is missing a network-profile default for '$target'."
      }
      if ($operation.Kind -eq 'PowerSetting' -and -not $defaults.ContainsKey('DefaultValue')) {
        Add-Error "Operation '$($operation.Id)' is missing a power-setting default for '$target'."
      }
    }
    if ($operation.Kind -eq 'StoreApp') {
      if($operation.Handler -ne 'StoreApp' -or $operation.Scope -ne 'User' -or $operation.RequiresAdmin -ne $false -or $operation.Rollback -ne 'BestEffort' -or $operation.RequireKnownProtectionFlags -ne $true -or $operation.ProtectionRule -cne 'ReviewedIdentityRemovabilityV1' -or $operation.ReinstallSource -cne 'RetainedManifestOnly'){Add-Error "Invalid guarded Store lifecycle/scope: $($operation.Id)"}
      if($operation.AppxName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$' -or $operation.PackageFamilyName -cnotmatch ('^'+[regex]::Escape([string]$operation.AppxName)+'_[a-z0-9]{13}$')){Add-Error "Invalid exact Store app identity: $($operation.Id)"}
      if(@(Compare-Object @('Get','Test','Uninstall','Reinstall') @($operation.Actions)).Count -or $operation.ContainsKey('BaselineState') -or $operation.ContainsKey('States')){Add-Error "Store app requires distinct uninstall/reinstall actions without setting defaults: $($operation.Id)"}
      if(-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri,[UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com'){Add-Error "Store app requires Microsoft HTTPS documentation: $($operation.Id)"}
    }
    elseif ($operation.Kind -eq 'RegistryValue') {
      $expectedRoot = if ($operation.Scope -eq 'User') { 'HKCU:\' } else { 'HKLM:\' }
      if (-not ([string]$operation.RegistryPath).StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) { Add-Error "Registry path conflicts with declared scope: $($operation.Id)" }
      foreach ($field in @('RegistryPath', 'ValueName', 'ValueType', 'States', 'BaselineState')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Registry operation is missing '$field': $($operation.Id)" }
      }
      if (-not $operation.ContainsKey('DocumentationUri') -and -not $isCustom) { Add-Error "Registry operation is missing Microsoft documentation URI: $($operation.Id)" }
      elseif ($operation.ContainsKey('DocumentationUri') -and (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or (-not $isCustom -and ([Uri]$operation.DocumentationUri).Host -notin @('learn.microsoft.com', 'support.microsoft.com')))) {
        Add-Error "Registry operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
      }
      if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
      if ($operation.Handler -ne 'RegistryValue') { Add-Error "No matching handler for $($operation.Id)" }
    }
    elseif ($operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'DefenderPreference', 'SmbProtocol', 'PowerScheme', 'NetBios', 'RemoteDesktopFirewall', 'SoundScheme')) {
      $expectedScope = if ($operation.Kind -eq 'SoundScheme') { 'User' } else { 'Machine' }
      if ($operation.Handler -ne $operation.Kind -or $operation.Scope -ne $expectedScope -or $operation.RequiresAdmin -ne ($expectedScope -eq 'Machine')) { Add-Error "Invalid managed-setting handler/scope: $($operation.Id)" }
      if (@(@('Get', 'Test', 'Set', 'Restore') | Where-Object { $_ -notin $operation.Actions }).Count) { Add-Error "Incomplete managed-setting lifecycle: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -notin @('learn.microsoft.com', 'support.microsoft.com')) { Add-Error "Managed settings require Microsoft HTTPS documentation: $($operation.Id)" }
      if (-not $operation.States -or $operation.ContainsKey('BaselineState')) { Add-Error "Managed settings require explicit states without an invented baseline: $($operation.Id)" }
      foreach ($target in $operation.SupportedTargets) { if ($operation.TargetDefaults[$target].DefaultValue -ne 'PlatformDefined') { Add-Error "Managed-setting defaults must remain platform-defined: $($operation.Id)" } }
      if ($operation.Kind -eq 'ScheduledTask') {
        if ($operation.TaskPath -notmatch '^\\Microsoft\\(Windows\\[^*?\r\n]+|Office)\\$' -or -not $operation.TaskName -or $operation.TaskName -match '[\\*?\r\n]') { Add-Error "Invalid exact scheduled-task identity: $($operation.Id)" }
      }
      if ($operation.Kind -eq 'AdapterBinding') {
        if (-not $operation.ComponentIds -or @($operation.ComponentIds | Select-Object -Unique).Count -ne @($operation.ComponentIds).Count -or @($operation.ComponentIds | Where-Object { $_ -notin @('ms_lldp', 'ms_lltdio', 'ms_rspndr', 'ms_msclient', 'ms_pacer', 'ms_tcpip', 'ms_tcpip6', 'ms_server') }).Count) { Add-Error "Invalid adapter component allowlist: $($operation.Id)" }
      }
      if ($operation.Kind -eq 'SmbProtocol' -and $operation.Preference -notin @('EnableSMB1Protocol', 'EnableSMB2Protocol')) { Add-Error "Unsupported SMB preference: $($operation.Id)" }
      if ($operation.Kind -eq 'DefenderPreference' -and $operation.Preference -ne 'EnableControlledFolderAccess') { Add-Error "Unsupported Defender preference: $($operation.Id)" }
      foreach ($value in $operation.States.Values) {
        if ($operation.Kind -in @('ScheduledTask', 'AdapterBinding', 'SmbProtocol') -and $value -isnot [bool]) { Add-Error "Managed flag must be Boolean: $($operation.Id)" }
        if ($operation.Kind -eq 'DefenderPreference' -and ($value -isnot [int] -or $value -notin @(0, 1, 2))) { Add-Error "Invalid Controlled Folder Access mode: $($operation.Id)" }
        if ($operation.Kind -eq 'NetBios' -and ($value -isnot [int] -or $value -notin @(0, 1, 2))) { Add-Error "Invalid NetBIOS option: $($operation.Id)" }
        if ($operation.Kind -eq 'SoundScheme' -and $value -notin @('.None', '.Default')) { Add-Error "Invalid sound preset: $($operation.Id)" }
        if ($operation.Kind -eq 'RemoteDesktopFirewall' -and $value -notin @('True', 'False')) { Add-Error "Invalid Remote Desktop firewall flag: $($operation.Id)" }
        if ($operation.Kind -eq 'PowerScheme' -and [string]$value -notmatch '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { Add-Error "Invalid power-scheme GUID: $($operation.Id)" }
      }
    }
    elseif ($operation.Kind -eq 'Package') {
      if ($operation.ContainsKey('RequiresDesktopExperience') -and $operation.RequiresDesktopExperience -isnot [bool]) { Add-Error "RequiresDesktopExperience must be Boolean: $($operation.Id)" }
      if ($operation.ContainsKey('RequiresUnelevatedUser') -and ($operation.RequiresUnelevatedUser -isnot [bool] -or $operation.Scope -ne 'User' -or $operation.RequiresAdmin -or $operation.InstallerType -ne 'Exe')) { Add-Error "Invalid unelevated user execution contract: $($operation.Id)" }
      if ($operation.ContainsKey('LocalAppDataInstallDirectory')) {
        $directory=[string]$operation.LocalAppDataInstallDirectory
        if ($operation.Scope -ne 'User' -or $operation.InstallerType -ne 'Exe' -or -not $operation.RequiresUnelevatedUser -or $directory -notmatch '^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,79}$' -or $directory.EndsWith('.') -or $directory.EndsWith(' ') -or $directory -match '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)' -or $operation.InstallerArguments -notlike '*{InstallDirectory}*') { Add-Error "Invalid current-user install directory contract: $($operation.Id)" }
      }
      if ($operation.ConflictingDisplayNamePattern) {
        try { $null=[regex]::new([string]$operation.ConflictingDisplayNamePattern) } catch { Add-Error "Invalid conflicting edition pattern: $($operation.Id)" }
        if ($operation.Scope -ne 'User' -or -not $operation.LocalAppDataInstallDirectory) { Add-Error "Conflicting edition detection requires an explicit user destination: $($operation.Id)" }
      }
      if ($operation.ContainsKey('PreserveRoamingDirectory')) {
        $preserved=[string]$operation.PreserveRoamingDirectory
        if ($operation.Scope -ne 'User' -or $operation.InstallerType -ne 'Exe' -or $preserved -notmatch '^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,79}$' -or $preserved.EndsWith('.') -or $preserved.EndsWith(' ') -or $preserved -match '^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)' -or $operation.PreservationProcessName -notmatch '^[a-zA-Z0-9_-]+$') { Add-Error "Invalid user-data preservation contract: $($operation.Id)" }
      } elseif ($operation.ContainsKey('PreservationProcessName')) { Add-Error "Preservation process requires a declared user-data directory: $($operation.Id)" }
      if ($operation.Scope -eq 'Machine' -and -not $operation.RequiresAdmin) { Add-Error "Machine packages require elevation: $($operation.Id)" }
      if ($operation.InstallerType -notin @('Exe', 'Msi', 'SysmonZip', 'Portable')) { Add-Error "Unsupported installer type: $($operation.Id)" }
      if ($operation.ContainsKey('UninstallerType') -and ($operation.UninstallerType -notin @('Exe', 'Msi') -or $operation.InstallerType -notin @('Exe', 'Msi'))) { Add-Error "Unsupported uninstaller type: $($operation.Id)" }
      if ($operation.ContainsKey('ArchiveType') -and $operation.ArchiveType -notin @('None', 'Zip')) { Add-Error "Unsupported ArchiveType: $($operation.Id)" }
      if ($operation.ArchiveType -eq 'Zip' -and $operation.InstallerType -ne 'Portable') {
        if ($operation.DownloadProvider -ne 'DirectHttps' -or $operation.InstallerType -notin @('Exe', 'Msi')) { Add-Error "ZIP installer requires DirectHttps and Exe/Msi: $($operation.Id)" }
        $entry = [string]$operation.InstallerEntry
        if (-not $entry -or $entry.Length -gt 240 -or $entry -match '[\\\x00-\x1f:"*?<>|]|^/|(^|/)\.{1,2}(/|$)|[. ](/|$)|//|/$' -or
            [IO.Path]::GetExtension($entry) -ne ('.' + ([string]$operation.InstallerType).ToLowerInvariant())) { Add-Error "ZIP requires a safe matching EXE/MSI InstallerEntry: $($operation.Id)" }
        if ($operation.ContainsKey('ExpectedInstallerSha256') -and $operation.ExpectedInstallerSha256 -notmatch '^[a-fA-F0-9]{64}$') { Add-Error "ExpectedInstallerSha256 must contain 64 hexadecimal characters: $($operation.Id)" }
      } elseif ($operation.ContainsKey('InstallerEntry') -or $operation.ContainsKey('ExpectedInstallerSha256')) { Add-Error "InstallerEntry and ExpectedInstallerSha256 require ArchiveType Zip: $($operation.Id)" }
      if ($operation.InstallerType -eq 'Portable') {
        if ($operation.Scope -ne 'Machine' -or $operation.PortableFormat -notin @('Zip', 'File') -or -not $operation.RequiredFiles) { Add-Error "Portable packages require machine scope, Zip/File and RequiredFiles: $($operation.Id)" }
        foreach ($member in @($operation.RequiredFiles) + @($operation.PortableFileName) | Where-Object { $_ }) {
          if ($member -match '[\\\x00-\x1f:"*?<>|]|^/|(^|/)\.{1,2}(/|$)|[. ](/|$)|//|/$' -or $member -eq '.ride-package.json') { Add-Error "Unsafe portable member: $($operation.Id)" }
        }
        if ($operation.PortableFormat -eq 'File' -and -not $operation.PortableFileName) { Add-Error "Standalone portable requires PortableFileName: $($operation.Id)" }
      }
      if ($operation.ContainsKey('PortableMembers')) {
        if ($operation.InstallerType -ne 'Portable' -or $operation.PortableFormat -ne 'Zip' -or
            $operation.PortableMembers -isnot [array] -or $operation.PortableMembers.Count -lt 1 -or
            $operation.PortableMembers.Count -gt 10000 -or $operation.ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') {
          Add-Error "PortableMembers requires a nonempty exact member array and pinned portable ZIP: $($operation.Id)"
        }
        $selectedMembers = @{}
        foreach ($member in @($operation.PortableMembers)) {
          if ($member -isnot [string] -or [string]::IsNullOrWhiteSpace($member) -or $member.Length -gt 240 -or
              $member -match '[\\\x00-\x1f:"*?<>|]|^/|(^|/)\.{1,2}(/|$)|[. ](/|$)|//|/$|(^|/)(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|/|$)' -or $member -ieq '.ride-package.json') {
            Add-Error "Unsafe PortableMembers file: $($operation.Id)"; continue
          }
          if ($selectedMembers.ContainsKey($member)) { Add-Error "Duplicate PortableMembers file: $($operation.Id)" }
          $selectedMembers[$member] = $true
        }
        foreach ($required in @($operation.RequiredFiles)) {
          if (-not $selectedMembers.ContainsKey([string]$required)) { Add-Error "RequiredFiles must be included in PortableMembers: $($operation.Id)" }
        }
      }
      if ($operation.InstallerType -eq 'Msi' -and ($operation.InstallerArguments -notmatch '/qn' -or $operation.InstallerArguments -notmatch '/norestart')) { Add-Error "MSI packages require quiet, no-restart arguments: $($operation.Id)" }
      if ($operation.PrerequisitePackageId) {
        if ($operation.PrerequisitePackageId -notin @($catalog.Operations | Where-Object Kind -eq 'Package' | ForEach-Object Id)) { Add-Error "Unknown package prerequisite: $($operation.Id)" }
        if (-not $operation.PrerequisiteProgramFilesExecutable -or [IO.Path]::IsPathRooted($operation.PrerequisiteProgramFilesExecutable) -or $operation.PrerequisiteProgramFilesExecutable -match '(^|[\\/])\.\.([\\/]|$)|["\r\n:*?]') { Add-Error "Invalid prerequisite executable: $($operation.Id)" }
      }
      if ($operation.Handler -ne 'Package') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('PackageId', 'InstallerType', 'DownloadUri', 'InstallerArguments', 'UninstallerArguments', 'DisplayNamePattern')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Package operation is missing '$field': $($operation.Id)" }
      }
      if ([string]::IsNullOrWhiteSpace([string]$operation.DisplayNamePattern)) { Add-Error "Package detection requires a nonblank DisplayNamePattern: $($operation.Id)" }
      else {
        try { $null = [regex]::new([string]$operation.DisplayNamePattern) }
        catch { Add-Error "Package DisplayNamePattern must be a valid regex: $($operation.Id)" }
      }
      if (-not $operation.ContainsKey('ProductUri') -and -not $isCustom) { Add-Error "Package operation is missing product information URI: $($operation.Id)" }
      elseif ($operation.ContainsKey('ProductUri') -and (-not [Uri]::IsWellFormedUriString([string]$operation.ProductUri, [UriKind]::Absolute) -or ([Uri]$operation.ProductUri).Scheme -ne 'https')) {
        Add-Error "Package operation must use an absolute HTTPS product URI: $($operation.Id)"
      }
      if ('Install' -notin $operation.Actions -or 'Uninstall' -notin $operation.Actions) { Add-Error "Package lifecycle must include install and uninstall: $($operation.Id)" }
      if ('Download' -in $operation.Actions) {
        foreach ($field in @('DownloadProvider', 'Architecture')) {
          if (-not $operation.ContainsKey($field)) { Add-Error "Downloadable package is missing '$field': $($operation.Id)" }
        }
        if (-not [Uri]::IsWellFormedUriString([string]$operation.DownloadUri, [UriKind]::Absolute) -or ([Uri]$operation.DownloadUri).Scheme -ne 'https') {
          Add-Error "Downloadable package must use an absolute HTTPS source URI: $($operation.Id)"
        }
        if ($operation.DownloadProvider -eq 'GitHubReleaseApi') {
          if (-not $operation.AssetPattern) { Add-Error "GitHub release packages require an asset pattern: $($operation.Id)" }
          else {
            try { $null = [regex]::new([string]$operation.AssetPattern) }
            catch { Add-Error "GitHub AssetPattern must be a valid regex: $($operation.Id)" }
          }
          if ([Uri]::IsWellFormedUriString([string]$operation.DownloadUri, [UriKind]::Absolute) -and ([Uri]$operation.DownloadUri).Host -ne 'api.github.com') { Add-Error "GitHub release API provider must use api.github.com: $($operation.Id)" }
        }
        elseif ($operation.DownloadProvider -eq 'DirectHttps') {
          $assetExtension = if ($operation.PortableFormat -eq 'File') { [IO.Path]::GetExtension([string]$operation.AssetName) } elseif ($operation.ArchiveType -eq 'Zip' -or $operation.PortableFormat -eq 'Zip') { '.zip' } else { '.' + ([string]$operation.InstallerType).ToLowerInvariant() }
          if ($operation.PackageVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]*$' -or
              $operation.AssetName -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*\.(exe|msi|zip)$' -or
              [IO.Path]::GetExtension([string]$operation.AssetName) -ne $assetExtension) { Add-Error "Direct HTTPS packages require a safe PackageVersion and matching EXE/MSI or ZIP AssetName: $($operation.Id)" }
          if (-not [Uri]::IsWellFormedUriString([string]$operation.DownloadUri, [UriKind]::Absolute) -or
              -not ([Uri]$operation.DownloadUri).IsDefaultPort -or ([Uri]$operation.DownloadUri).UserInfo -or ([Uri]$operation.DownloadUri).Fragment) { Add-Error "Direct HTTPS sources must use the default port without credentials or fragments: $($operation.Id)" }
          if ($operation.ContainsKey('ExpectedSha256') -and $operation.ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') { Add-Error "ExpectedSha256 must contain 64 hexadecimal characters: $($operation.Id)" }
        }
        elseif ($operation.DownloadProvider -in @('VSCodeUpdateApi', 'MozillaVersionsJson', 'PublisherLinkPage', 'SignalDesktopFeed', 'WinSCPPortablePage')) {
          if (-not $operation.AllowedDownloadHosts -or @($operation.AllowedDownloadHosts | Where-Object { $_ -notmatch '^[a-zA-Z0-9.-]+$' }).Count) { Add-Error "Publisher providers require declared download hosts: $($operation.Id)" }
          if ($operation.DownloadProvider -eq 'MozillaVersionsJson' -and ($operation.MozillaProduct -notin @('firefox', 'thunderbird') -or -not $operation.VersionKey)) { Add-Error "Invalid Mozilla metadata: $($operation.Id)" }
          if ($operation.ContainsKey('MozillaChannel') -and ($operation.DownloadProvider -ne 'MozillaVersionsJson' -or $operation.MozillaChannel -notin @('release','esr'))) { Add-Error "Invalid Mozilla update channel: $($operation.Id)" }
          if ($operation.DownloadProvider -eq 'MozillaVersionsJson' -and ($operation.Architecture -notin @('x64','x86') -or ($operation.ContainsKey('MozillaLocale') -and $operation.MozillaLocale -notmatch '^[a-z]{2,3}(?:-[a-zA-Z0-9]{2,8})*$'))) { Add-Error "Invalid Mozilla architecture/locale: $($operation.Id)" }
          if ($operation.DownloadProvider -eq 'SignalDesktopFeed' -and ($operation.DownloadUri -cne 'https://updates.signal.org/desktop/latest.yml' -or $operation.Architecture -ne 'x64' -or $operation.Scope -ne 'User' -or $operation.InstallerType -ne 'Exe' -or @($operation.AllowedDownloadHosts).Count -ne 1 -or $operation.AllowedDownloadHosts[0] -ne 'updates.signal.org')) { Add-Error "Signal feed requires official stable x64 EXE in user scope: $($operation.Id)" }
          if ($operation.DownloadProvider -eq 'WinSCPPortablePage' -and ($operation.PackageVersion -notmatch '^\d+\.\d+\.\d+$' -or $operation.DownloadUri -cne "https://winscp.net/download/WinSCP-$($operation.PackageVersion)-Portable.zip/download" -or $operation.Architecture -ne 'x86' -or $operation.InstallerType -ne 'Portable' -or $operation.PortableFormat -ne 'Zip' -or @($operation.AllowedDownloadHosts).Count -ne 1 -or $operation.AllowedDownloadHosts[0] -ne 'cdn.winscp.net')) { Add-Error "WinSCP requires a pinned official x86 portable ZIP page and CDN: $($operation.Id)" }
          if ($operation.DownloadProvider -eq 'PublisherLinkPage' -and (-not $operation.AssetPattern -or -not $operation.VersionPattern)) { Add-Error "Publisher page requires artifact/version patterns: $($operation.Id)" }
          if ($operation.ContainsKey('ChecksumAssetPattern') -or $operation.ContainsKey('ChecksumMember')) {
            if ($operation.DownloadProvider -ne 'PublisherLinkPage' -or -not $operation.ChecksumAssetPattern -or -not $operation.ChecksumMember -or
                $operation.ChecksumMember.Length -gt 240 -or $operation.ChecksumMember -match '[\\\x00-\x1f:]|^/|(^|/)\.{1,2}(/|$)') { Add-Error "Publisher checksum requires a pattern and safe relative member: $($operation.Id)" }
            try { $null = [regex]::new([string]$operation.ChecksumAssetPattern) } catch { Add-Error "Invalid publisher checksum pattern: $($operation.Id)" }
          }
        }
        elseif ($operation.DownloadProvider -eq 'SysinternalsSysmonPage') {
          if (-not $operation.ContainsKey('VersionUri') -or -not [Uri]::IsWellFormedUriString([string]$operation.VersionUri, [UriKind]::Absolute) -or ([Uri]$operation.VersionUri).Host -ne 'learn.microsoft.com') { Add-Error "Sysmon latest provider must resolve the version from Microsoft Learn: $($operation.Id)" }
          if (([Uri]$operation.DownloadUri).Host -ne 'download.sysinternals.com' -or $operation.AssetName -ne 'Sysmon.zip' -or $operation.InstallerType -ne 'SysmonZip') { Add-Error "Invalid Microsoft Sysmon archive metadata: $($operation.Id)" }
        }
        else { Add-Error "Unsupported package download provider '$($operation.DownloadProvider)': $($operation.Id)" }
        $neutralPortableZip = $operation.Architecture -eq 'neutral' -and $operation.InstallerType -eq 'Portable' -and $operation.PortableFormat -eq 'Zip'
        if ($operation.Architecture -notin @('x64', 'x86', 'arm64') -and -not $neutralPortableZip) { Add-Error "Invalid package architecture: $($operation.Id)" }
      }
    }
    elseif ($operation.Kind -eq 'Artifact') {
      if ($operation.Handler -ne 'Artifact') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('ArtifactId', 'DownloadUri', 'DownloadProvider', 'Repository', 'AssetPath', 'Architecture', 'ProductUri')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Download-only artifact is missing '$field': $($operation.Id)" }
      }
      if (@($operation.Actions).Count -ne 1 -or 'Download' -notin $operation.Actions) { Add-Error "Download-only artifact must expose only Download: $($operation.Id)" }
      if ($operation.DownloadProvider -ne 'GitHubFileCommitApi' -or ([Uri]$operation.DownloadUri).Host -ne 'api.github.com') { Add-Error "Unsupported download-only artifact provider or URI: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.ProductUri, [UriKind]::Absolute) -or ([Uri]$operation.ProductUri).Scheme -ne 'https') { Add-Error "Artifact product URI must be an absolute HTTPS URI: $($operation.Id)" }
      if ($operation.Architecture -notin @('neutral', 'x64', 'x86', 'arm64')) { Add-Error "Invalid artifact architecture: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'DefenderExclusion') {
      if ($operation.Handler -ne 'DefenderExclusion') { Add-Error "No matching handler for $($operation.Id)" }
      if ($operation.PathResolver -notin @('ToolsDirectory', 'BootstrapDirectory')) { Add-Error "Invalid Defender exclusion path resolver: $($operation.Id)" }
      if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Defender exclusion lifecycle is incomplete: $($operation.Id)" }
      foreach ($target in $operation.SupportedTargets) {
        if ($operation.TargetDefaults[$target].DefaultValue -notin @('Present', 'Absent')) { Add-Error "Invalid Defender exclusion default for $($operation.Id) on '$target'." }
      }
    }
    elseif ($operation.Kind -eq 'WindowsService') {
      if ($operation.ContainsKey('RefuseDependencyChanges') -and $operation.RefuseDependencyChanges -isnot [bool]) { Add-Error "Service dependency refusal must be Boolean: $($operation.Id)" }
      if ($operation.Handler -ne 'WindowsService') { Add-Error "No matching handler for $($operation.Id)" }
      if ([string]$operation.ServiceName -notmatch '^[A-Za-z0-9_.-]+$') { Add-Error "Invalid exact service identity: $($operation.Id)" }
      foreach ($field in @('ServiceName', 'States', 'DocumentationUri')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Windows service operation is missing '$field': $($operation.Id)" }
      }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
        Add-Error "Windows service operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
      }
      foreach ($stateName in $operation.States.Keys) {
        $state = $operation.States[$stateName]
        if ($state -isnot [hashtable]) { Add-Error "Invalid service state '$stateName': $($operation.Id)"; continue }
        if ($state.StartupType -notin @('Automatic', 'Manual', 'Disabled') -or
            ($state.ContainsKey('Status') -and $state.Status -notin @('Running', 'Stopped'))) {
          Add-Error "Invalid startup type or running state for '$($operation.Id)' state '$stateName'."
        }
        if ($state.ContainsKey('DelayedAutoStart') -and
            ($state.DelayedAutoStart -isnot [bool] -or $state.StartupType -ne 'Automatic' -or $operation.PreserveDelayedAutoStart -ne $true)) {
          Add-Error "Explicit service delay requires Automatic startup, a Boolean and delayed-start capture: $($operation.Id) / $stateName"
        }
        foreach ($key in $state.Keys) {
          if ($key -notin @('StartupType', 'Status', 'DelayedAutoStart')) { Add-Error "Unknown service state field '$key': $($operation.Id) / $stateName" }
        }
      }
      if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Windows service lifecycle is incomplete: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'BackgroundAppOverrides') {
      if ($operation.Handler -ne 'BackgroundAppOverrides') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('RegistryPath', 'ValueNames', 'States', 'DocumentationUri')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Background app override operation is missing '$field': $($operation.Id)" }
      }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
        Add-Error "Background app override operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
      }
      if ('Reset' -notin $operation.States.Keys) { Add-Error "Background app override operation must declare Reset: $($operation.Id)" }
      if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Background app override lifecycle is incomplete: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'BootConfiguration') {
      if ($operation.Handler -ne 'BootConfiguration') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('BcdElement', 'States', 'BaselineState', 'RestartRequired', 'DocumentationUri')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Boot configuration operation is missing '$field': $($operation.Id)" }
      }
      if ($operation.BcdElement -notin @('bootmenupolicy', 'nx', 'bootstatuspolicy')) { Add-Error "Unsupported BCD element for '$($operation.Id)'." }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
        Add-Error "Boot configuration operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
      }
      if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
      if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Boot configuration lifecycle is incomplete: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'NetworkProfile') {
      if ($operation.Handler -ne 'NetworkProfile') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('States', 'BaselineState', 'DocumentationUri')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Network profile operation is missing '$field': $($operation.Id)" }
      }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
        Add-Error "Network profile operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
      }
      if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
      foreach ($stateName in $operation.States.Keys) {
        if ($operation.States[$stateName] -notin @('Private', 'Public')) { Add-Error "Invalid network category in '$($operation.Id)' state '$stateName'." }
      }
      if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Network profile lifecycle is incomplete: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'LocalPasswordMaximumAge') {
      if ($operation.Handler -ne $operation.Kind -or $operation.Scope -ne 'Machine' -or $operation.RequiresAdmin -ne $true) { Add-Error "Local password age requires the machine/admin focused handler: $($operation.Id)" }
      $range = $operation.StateRange
      if ($range -isnot [hashtable] -or $range.Count -ne 3 -or $range.Prefix -cne 'Days' -or $range.Minimum -ne 1 -or $range.Maximum -ne 999) { Add-Error "Local password age requires bounded Days1..Days999 metadata: $($operation.Id)" }
      if ($operation.States -isnot [hashtable] -or $operation.States.Count -ne 1000 -or $operation.States.NoExpiry -isnot [int] -or $operation.States.NoExpiry -ne 0) { Add-Error "Local password age states must resolve the complete declared range: $($operation.Id)" }
      foreach ($day in 1..999) { if ($operation.States['Days'+$day] -isnot [int] -or $operation.States['Days'+$day] -ne $day) { Add-Error "Invalid explicit password-age day state: $($operation.Id) / Days$day"; break } }
      if ($operation.ContainsKey('BaselineState') -or $operation.ContainsKey('UnsetState') -or $operation.Rollback -ne 'Exact') { Add-Error "Local password age requires captured field recovery without an invented definition-removal state: $($operation.Id)" }
      if (@(@('Get','Test','Set','Restore') | Where-Object { $_ -notin $operation.Actions }).Count) { Add-Error "Local password-age lifecycle is incomplete: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri,[UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') { Add-Error "Local password age requires Microsoft HTTPS documentation: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'OwnedPowerPlan') {
      if ($operation.Handler -ne 'OwnedPowerPlan' -or $operation.Scope -ne 'Machine' -or $operation.RequiresAdmin -ne $true -or $operation.Id -notmatch '^windows\.[a-z0-9-]+$') { Add-Error "Owned power plans require a machine/admin focused handler and stable safe ID: $($operation.Id)" }
      if ($operation.SourcePowerPlanGuid -notmatch '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { Add-Error "Owned power plans require an exact source GUID: $($operation.Id)" }
      if ($operation.States -isnot [hashtable] -or $operation.States.Count -ne 1 -or $operation.States.Create -isnot [bool] -or $operation.States.Create -ne $true) { Add-Error "Owned power plans allow explicit Create only: $($operation.Id)" }
      if ($operation.ContainsKey('BaselineState') -or $operation.ContainsKey('UnsetState') -or $operation.Rollback -ne 'Compensating') { Add-Error "Owned-copy recovery is compensating, with no implicit removal/default state: $($operation.Id)" }
      if (@(@('Get', 'Test', 'Set', 'Restore') | Where-Object { $_ -notin $operation.Actions }).Count) { Add-Error "Owned power plans require capture and restore actions: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') { Add-Error "Owned power plans require Microsoft HTTPS documentation: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'FirewallProfile') {
      if ($operation.Handler -ne 'FirewallProfile' -or $operation.Scope -ne 'Machine' -or $operation.RequiresAdmin -ne $true) { Add-Error "Firewall profiles require the machine/admin focused handler: $($operation.Id)" }
      $names = @($operation.FirewallProfiles)
      if ($names.Count -notin @(1, 3) -or @($names | Where-Object { $_ -notin @('Domain', 'Private', 'Public') }).Count -or @($names | Sort-Object -Unique).Count -ne $names.Count) { Add-Error "Firewall profiles require one exact profile or all three unique profiles: $($operation.Id)" }
      if ($operation.States -isnot [hashtable] -or $operation.States.On -isnot [string] -or $operation.States.On -cne 'True' -or
          ($names.Count -eq 1 -and ($operation.States.Off -isnot [string] -or $operation.States.Off -cne 'False' -or $operation.States.Count -ne 2)) -or
          ($names.Count -eq 3 -and $operation.States.Count -ne 1)) { Add-Error "Firewall profile states are On/Off, or On only for all profiles: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') { Add-Error "Firewall profiles require Microsoft HTTPS documentation: $($operation.Id)" }
      if ($operation.ContainsKey('BaselineState') -or $operation.ContainsKey('UnsetState')) { Add-Error "Firewall local default/removal states are not declared: $($operation.Id)" }
      foreach ($target in $operation.SupportedTargets) { if (-not $operation.TargetDefaults[$target].ContainsKey('DefaultValue')) { Add-Error "Firewall profiles require literal target defaults: $($operation.Id)" } }
      if ($operation.Rollback -ne 'Exact' -or @(@('Get', 'Test', 'Set', 'Restore') | Where-Object { $_ -notin $operation.Actions }).Count) { Add-Error "Firewall profile lifecycle must support exact saved configuration recovery: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'RegistryValueSet') {
      if ($operation.Handler -ne 'RegistryValueSet') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('RegistryValues', 'States', 'BaselineState')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Registry value-set operation is missing '$field': $($operation.Id)" }
      }
      $members = @($operation.RegistryValues)
      if ($members.Count -lt 2 -or $members.Count -gt 10) { Add-Error "Registry value sets require 2-10 components: $($operation.Id)" }
      $expectedRoot = if ($operation.Scope -eq 'User') { 'HKCU:\' } else { 'HKLM:\' }
      foreach ($member in $members) {
        if (-not $member.Key -or $member.ValueName -isnot [string] -or -not ([string]$member.RegistryPath).StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) { Add-Error "Invalid registry component or scope: $($operation.Id)" }
        if ($member.ValueType -notin @('DWord', 'String')) { Add-Error "Unsupported value-set registry type: $($operation.Id)" }
      }
      if (@($members.Key | Select-Object -Unique).Count -ne $members.Count) { Add-Error "Duplicate value-set component names: $($operation.Id)" }
      if (@($members | ForEach-Object { $_.RegistryPath + '|' + $_.ValueName } | Select-Object -Unique).Count -ne $members.Count) { Add-Error "Duplicate registry values: $($operation.Id)" }
      if ($operation.ContainsKey('ReadOnlyRegistryValues')) {
        $observations = @($operation.ReadOnlyRegistryValues)
        if ($observations.Count -lt 1 -or $observations.Count -gt 5 -or @($observations.Key | Sort-Object -Unique).Count -ne $observations.Count) { Add-Error "Read-only registry observations must have 1-5 unique keys: $($operation.Id)" }
        foreach ($observation in $observations) {
          if ($observation.Key -isnot [string] -or [string]::IsNullOrWhiteSpace($observation.Key) -or
              $observation.ValueName -isnot [string] -or [string]::IsNullOrWhiteSpace($observation.ValueName) -or
              -not ([string]$observation.RegistryPath).StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
              $observation.ValueType -notin @('DWord', 'String') -or $observation.Key -in $members.Key) { Add-Error "Invalid read-only registry observation: $($operation.Id)" }
          if (@($members | Where-Object { $_.RegistryPath -eq $observation.RegistryPath -and $_.ValueName -eq $observation.ValueName }).Count) { Add-Error "Read-only registry observation overlaps a writable value: $($operation.Id)" }
        }
      }
      foreach ($stateName in $operation.States.Keys) {
        $values = $operation.States[$stateName]
        if ($values -isnot [hashtable] -or $values.Count -ne $members.Count -or @($members | Where-Object { -not $values.ContainsKey($_.Key) }).Count) { Add-Error "Incomplete registry value-set state: $($operation.Id) / $stateName" }
        foreach ($member in $members) {
          $value = $values[$member.Key]
          if ($value -is [hashtable] -and $value.Count -eq 1 -and $value.KeepCurrent -is [bool] -and $value.KeepCurrent -eq $true) { continue }
          if ($null -ne $value -and (($member.ValueType -eq 'DWord' -and $value -isnot [int]) -or ($member.ValueType -eq 'String' -and $value -isnot [string]))) { Add-Error "Invalid component value type: $($operation.Id) / $stateName" }
        }
      }
      if (-not $operation.States.ContainsKey($operation.BaselineState) -or -not $operation.States.ContainsKey('WindowsDefault') -or @($operation.States.WindowsDefault.Values | Where-Object { $null -ne $_ }).Count) { Add-Error "Invalid registry value-set baseline/unset states: $($operation.Id)" }
      if (-not $operation.ContainsKey('DocumentationUri') -and -not $isCustom) { Add-Error "Registry value-set reference must be Microsoft HTTPS: $($operation.Id)" }
      elseif ($operation.ContainsKey('DocumentationUri') -and (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or (-not $isCustom -and ([Uri]$operation.DocumentationUri).Host -notin @('learn.microsoft.com', 'support.microsoft.com')))) { Add-Error "Registry value-set reference must be Microsoft HTTPS: $($operation.Id)" }
      foreach ($target in $operation.SupportedTargets) { if ($operation.TargetDefaults[$target].DefaultValue -ne 'PlatformDefined') { Add-Error "Value-set defaults must be platform-defined until observed: $($operation.Id)" } }
      if (@(@('Get', 'Test', 'Set', 'Restore') | Where-Object { $_ -notin $operation.Actions }).Count) { Add-Error "Registry value-set lifecycle is incomplete: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'RegistryKeySet') {
      if ($operation.Handler -ne 'RegistryKeySet') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('RegistryPaths', 'States', 'BaselineState', 'DocumentationUri')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Registry key-set operation is missing '$field': $($operation.Id)" }
      }
      if (@($operation.RegistryPaths).Count -eq 0) { Add-Error "Registry key-set operation has no paths: $($operation.Id)" }
      foreach ($path in $operation.RegistryPaths) {
        if ([string]$path -notmatch '^HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MyComputer\\NameSpace\\\{[0-9A-Fa-f-]{36}\}$') {
          Add-Error "Registry key-set path is outside the supported This PC Shell namespace roots: $($operation.Id)"
        }
      }
      if (@($operation.RegistryPaths | Select-Object -Unique).Count -ne @($operation.RegistryPaths).Count) { Add-Error "Registry key-set paths must be unique: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
        Add-Error "Registry key-set operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
      }
      if (-not $operation.States.ContainsKey($operation.BaselineState)) { Add-Error "Invalid baseline state for $($operation.Id)" }
      foreach ($stateName in $operation.States.Keys) {
        if ($operation.States[$stateName] -notin @('Present', 'Absent')) { Add-Error "Invalid registry key-set value in '$($operation.Id)' state '$stateName'." }
      }
      if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Registry key-set lifecycle is incomplete: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'PowerSetting') {
      if ($operation.Handler -ne 'PowerSetting') { Add-Error "No matching handler for $($operation.Id)" }
      foreach ($field in @('PowerSubgroupGuid', 'PowerSettingGuid', 'PowerIndex', 'States', 'DocumentationUri')) {
        if (-not $operation.ContainsKey($field)) { Add-Error "Power setting operation is missing '$field': $($operation.Id)" }
      }
      foreach ($field in @('PowerSubgroupGuid', 'PowerSettingGuid')) {
        if ([string]$operation.$field -notmatch '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { Add-Error "Invalid power setting GUID '$field': $($operation.Id)" }
      }
      if ($operation.PowerIndex -notin @('AC', 'DC')) { Add-Error "Power setting index must be AC or DC: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') {
        Add-Error "Power setting operation must use an absolute Microsoft HTTPS documentation URI: $($operation.Id)"
      }
      if (@($operation.States.Keys).Count -lt 2 -or @($operation.States.Values | Select-Object -Unique).Count -ne @($operation.States.Values).Count) { Add-Error "Power setting states must map to unique values: $($operation.Id)" }
      foreach ($value in $operation.States.Values) {
        if ($value -isnot [int] -or $value -lt 0 -or $value -gt 86400) { Add-Error "Unsupported power index in '$($operation.Id)': $value" }
        if ($operation.PowerSubgroupGuid -eq '4f971e89-eebd-4455-a8de-9e59040e7347' -and $value -notin @(0, 1)) { Add-Error "Unsupported button/lid index in '$($operation.Id)': $value" }
      }
      foreach ($target in $operation.SupportedTargets) { if ($operation.TargetDefaults[$target].DefaultValue -ne 'Platform-defined') { Add-Error "Power setting default must remain platform-defined: $($operation.Id)" } }
      if ('Get' -notin $operation.Actions -or 'Test' -notin $operation.Actions -or 'Set' -notin $operation.Actions -or 'Restore' -notin $operation.Actions) { Add-Error "Power setting lifecycle is incomplete: $($operation.Id)" }
      if ($operation.ContainsKey('BaselineState')) { Add-Error "Power setting must not invent a RIDE baseline: $($operation.Id)" }
    }
    elseif ($operation.Kind -eq 'ProfileSetting') {
      if ($operation.Handler -ne 'ProfileSetting' -or $operation.Scope -ne 'User' -or $operation.RequiresAdmin -ne $false) { Add-Error "Profile setting requires its user-scoped handler: $($operation.Id)" }
      if ($operation.ProfileRuntime -notin @('WindowsPowerShell51', 'PowerShell7') -or $operation.ProfileSetting -notin @('TerminalColors', 'UserBinPath')) { Add-Error "Unsupported profile runtime or setting: $($operation.Id)" }
      if ($operation.ProfileSetting -eq 'TerminalColors') {
        if ($operation.States -isnot [hashtable] -or $operation.States.Count -ne 3 -or $operation.States.Recommended -cne 'Recommended' -or $operation.States.AdminBlue -cne 'AdminBlue' -or -not $operation.States.ContainsKey('Default') -or $null -ne $operation.States.Default -or $operation.BaselineState -cne 'Default' -or $operation.UnsetState -cne 'Default') { Add-Error "Profile setting requires Recommended/AdminBlue/Default with explicit removal and baseline: $($operation.Id)" }
        $palettes = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot '../components/profiles/terminal-color-schemes.psd1')
        if (-not $palettes.ContainsKey([string]$operation.NormalColorScheme) -or -not $palettes.ContainsKey([string]$operation.AdminColorScheme)) { Add-Error "Profile setting requires reviewed color schemes: $($operation.Id)" }
        foreach ($palette in $palettes.Values) { if ($palette.Count -ne 19 -or @($palette.Values | Where-Object { $_ -cnotmatch '^#[0-9A-Fa-f]{6}$' }).Count) { Add-Error 'Invalid profile color palette data.' } }
      }
      elseif ($operation.ProfileSetting -eq 'UserBinPath') {
        if ($operation.States -isnot [hashtable] -or $operation.States.Count -ne 2 -or $operation.States.Enabled -cne 'Enabled' -or -not $operation.States.ContainsKey('Default') -or $null -ne $operation.States.Default -or $operation.BaselineState -cne 'Default' -or $operation.UnsetState -cne 'Default') { Add-Error "User-bin profile setting requires Enabled/Default with explicit removal and baseline: $($operation.Id)" }
        if ($operation.ContainsKey('NormalColorScheme') -or $operation.ContainsKey('AdminColorScheme')) { Add-Error "User-bin profile setting cannot declare color palettes: $($operation.Id)" }
      }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') { Add-Error "Profile setting requires Microsoft documentation: $($operation.Id)" }
      foreach ($action in @('Get', 'Test', 'Set', 'Restore')) { if ($action -notin $operation.Actions) { Add-Error "Profile setting lifecycle is missing '$action': $($operation.Id)" } }
      if ($operation.Rollback -ne 'Exact') { Add-Error "Profile setting requires exact managed-content restore: $($operation.Id)" }
      foreach ($target in $operation.SupportedTargets) { if (-not $operation.TargetDefaults[$target] -or -not $operation.TargetDefaults[$target].ContainsKey('DefaultValue') -or $operation.TargetDefaults[$target].DefaultValue -cne 'Default') { Add-Error "Profile setting default must describe absent RIDE customization: $($operation.Id)" } }
    }
    elseif ($operation.Kind -eq 'ShellFolder') {
      if ($operation.Handler -ne 'ShellFolder') { Add-Error "No matching handler for $($operation.Id)" }
      if ($operation.Scope -ne 'User' -or $operation.RequiresAdmin -ne $false -or $operation.PathResolver -ne 'CurrentUserDesktop') { Add-Error "Shell folder must use the current-user desktop: $($operation.Id)" }
      if ($operation.FolderName -cne 'GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}') { Add-Error "Unsupported Shell folder name: $($operation.Id)" }
      if (-not $operation.States -or @($operation.States.Keys).Count -ne 2 -or $operation.States.Present -cne 'Present' -or $operation.States.Absent -cne 'Absent' -or $operation.BaselineState -cne 'Absent') { Add-Error "Shell folder must declare Present/Absent and baseline Absent: $($operation.Id)" }
      if (-not [Uri]::IsWellFormedUriString([string]$operation.DocumentationUri, [UriKind]::Absolute) -or ([Uri]$operation.DocumentationUri).Scheme -ne 'https' -or ([Uri]$operation.DocumentationUri).Host -ne 'learn.microsoft.com') { Add-Error "Shell folder requires Microsoft documentation: $($operation.Id)" }
      foreach ($target in $operation.SupportedTargets) { if ($operation.TargetDefaults[$target].DefaultValue -cne 'Absent') { Add-Error "Shell folder default must be Absent: $($operation.Id)" } }
      foreach ($action in @('Get', 'Test', 'Set', 'Restore')) { if ($action -notin $operation.Actions) { Add-Error "Shell folder lifecycle is missing '$action': $($operation.Id)" } }
      if ($operation.Rollback -ne 'Exact') { Add-Error "Shell folder requires exact restore: $($operation.Id)" }
    }
    else { Add-Error "Unknown operation kind '$($operation.Kind)': $($operation.Id)" }
  }

  foreach ($group in $catalog.Groups) {
    if ($ids.ContainsKey($group.Id)) { Add-Error "Duplicate catalog ID: $($group.Id)" }
    $ids[$group.Id] = $true
    if (@($group.Members).Count -eq 0) { Add-Error "Group has no members: $($group.Id)" }
    $storeMembers=@($catalog.Operations|Where-Object {$_.Id -in $group.Members -and $_.Kind -eq 'StoreApp'})
    if($storeMembers.Count -and ($group.Workflow -cne 'StoreApps' -or $storeMembers.Count -ne @($group.Members).Count -or @($group.Members|Sort-Object -Unique).Count -ne @($group.Members).Count -or @($group.Members).Count -gt 32 -or @($group.Actions).Count -ne 2 -or 'Uninstall' -notin $group.Actions -or 'Reinstall' -notin $group.Actions -or $group.Rollback -ne 'BestEffort')){Add-Error "Store group requires a separate bounded app workflow: $($group.Id)"}
    foreach ($member in $group.Members) {
      if (-not ($catalog.Operations | Where-Object { $_.Id -eq $member })) { Add-Error "Unknown member '$member' in group '$($group.Id)'" }
    }
  }

  foreach ($profileFile in $profilePaths) {
    $profile = Import-PowerShellDataFile -LiteralPath $profileFile.FullName
    if ($profile.SchemaVersion -ne 1) { Add-Error "$($profileFile.Name) must declare SchemaVersion 1." }
    if (-not $profile.Operations) { Add-Error "$($profileFile.Name) has no selected operations." }
    $profileIds = @{}
    foreach ($selection in $profile.Operations) {
      if ($profileIds.ContainsKey($selection.Id)) { Add-Error "$($profileFile.Name) selects '$($selection.Id)' more than once." }
      $profileIds[$selection.Id] = $true
      if (-not $ids.ContainsKey($selection.Id)) { Add-Error "$($profileFile.Name) references unknown ID '$($selection.Id)'"; continue }
      $operation = $catalog.Operations | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1
      $group = $catalog.Groups | Where-Object { $_.Id -eq $selection.Id } | Select-Object -First 1
      if(($operation -and $operation.Kind -eq 'StoreApp') -or ($group -and $group.Workflow -eq 'StoreApps')){Add-Error "$($profileFile.Name) cannot route Store apps through setting/package profiles; use the explicit Store workflow."}
      if ($operation -and $operation.Kind -eq 'RegistryValue' -and $selection.State -ne 'Baseline' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid state for '$($selection.Id)'" }
      if ($selection.Variant -and (-not $operation -or $operation.Kind -ne 'Package' -or ($operation.Variants -and -not $operation.Variants.ContainsKey($selection.Variant)) -or (-not $operation.Variants -and $selection.Variant -ne 'installed'))) { Add-Error "Invalid profile package variant: $($selection.Id)" }
      if ($operation -and $operation.Kind -eq 'Artifact') { Add-Error "$($profileFile.Name) cannot select download-only artifact '$($selection.Id)' as a desired Windows state." }
      if ($operation -and $operation.Kind -eq 'WindowsService' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid service state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -in @('FirewallProfile', 'OwnedPowerPlan', 'LocalPasswordMaximumAge') -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid focused setting state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'BackgroundAppOverrides' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid background app state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'BootConfiguration' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid boot configuration state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'NetworkProfile' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid network-profile state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'RegistryKeySet' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid registry key-set state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'RegistryValueSet' -and $selection.State -ne 'Baseline' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid registry value-set state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'PowerSetting' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid power-setting state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'ShellFolder' -and $selection.State -ne 'Baseline' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid Shell folder state for '$($selection.Id)'" }
      if ($operation -and $operation.Kind -eq 'ProfileSetting' -and $selection.State -ne 'Baseline' -and $selection.State -notin $operation.States.Keys) { Add-Error "$($profileFile.Name) has invalid profile setting state for '$($selection.Id)'" }
      if ((($operation -and $operation.Kind -in @('Package', 'DefenderExclusion')) -or $group) -and $selection.State -notin @('Present', 'Absent')) { Add-Error "$($profileFile.Name) must use Present or Absent for '$($selection.Id)'" }
    }
  }

  $errors.ToArray()
}

Export-ModuleMember -Function Get-RideCatalogValidationErrors
