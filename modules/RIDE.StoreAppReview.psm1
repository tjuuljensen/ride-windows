<#
.SYNOPSIS
  Collect separate user and provisioning inventories with current app review data.
.DESCRIPTION
  Keeps historical names, observed package identities and policy declarations
  separate. No removal, registration, provisioning or acquisition is performed.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7; live Appx query on Windows.
  Prerequisites: Appx cmdlets and the intended user's actual console for collection.
  File/environment inputs: catalog/store-app-review.psd1 and optional saved inventory.
  Owner: RIDE-Windows maintainers. Version: 0.2.0.
  Changelog: 0.2.0: Archive historical coverage behind an explicit comparison option;
    prepare separate online provisioning collection with local DISM evidence logs.
    0.1.1: Retain edition/build context without inferring cross-release coverage.
    0.1.0: Add explicit-user inventory and exact-identity reconciliation.
#>
$ErrorActionPreference = 'Stop'

function Get-RideStoreAppDefinition {
  <#
  .SYNOPSIS
    Read app review definitions without importing handlers or querying Windows.
  .DESCRIPTION
    Defaults to the inspected current template candidates. Historical coverage
    is loaded only when explicitly requested; it is never an executable preset.
  .PARAMETER IncludeHistoricalCoverage
    Annotate and include archived v2 names for optional historical comparison.
  .EXAMPLE
    Get-RideStoreAppDefinition | Where-Object StaticPolicyId
  .INPUTS
    None.
  .OUTPUTS
    Hashtable. Validated review definitions.
  .NOTES
    Version and compatibility follow the module overview.
  #>
  [CmdletBinding()]
  param([switch] $IncludeHistoricalCoverage)
  $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'catalog/store-app-review.psd1'
  if ((Get-Item -LiteralPath $path).Length -gt 262144) { throw 'App review definitions exceed the data bound.' }
  $data = Import-PowerShellDataFile -LiteralPath $path
  if ($data.SchemaVersion -ne 1 -or -not @($data.Apps).Count -or @($data.Apps).Count -gt 500) { throw 'Invalid app review definitions.' }
  $names = @{}
  $policyIds = @{}
  $validated = @()
  foreach ($app in $data.Apps) {
    if ($app -isnot [hashtable] -or $app.Name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$' -or $names.ContainsKey($app.Name) -or $app.ReviewClass -notin @('AppReview','DependencyReview','KeepReview')) { throw 'Invalid or duplicate app review name.' }
    $names[$app.Name] = $true
    if ($app.StaticPolicyId) {
      if ($app.PolicyFamilyName -cne ($app.Name + '_' + ($app.PolicyFamilyName -split '_')[-1]) -or $app.PolicyFamilyName -notmatch '^[a-zA-Z0-9.-]+_[a-z0-9]{13}$' -or $policyIds.ContainsKey($app.StaticPolicyId)) { throw 'Invalid or duplicate app policy identity.' }
      $policyIds[$app.StaticPolicyId] = $true
    } elseif ($app.PolicyFamilyName) { throw 'A policy family needs its static template identity.' }
    foreach ($family in @($app.LegacyRemoval) + @($app.LegacyRegistration)) {
      if ($family -notin @('Microsoft','ThirdParty')) { throw 'Invalid historical app family.' }
    }
    $validated += @($app)
  }
  $definitions = @{}
  foreach ($app in $validated) { $definitions[$app.Name] = $app }
  if ($IncludeHistoricalCoverage) {
    $archivePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'docs/archive/migrations/store-app-v2-historical-coverage-2026-10-14.json'
    if ((Get-Item -LiteralPath $archivePath).Length -gt 262144) { throw 'Historical coverage exceeds its data bound.' }
    $history = Get-Content -LiteralPath $archivePath -Raw | ConvertFrom-Json
    if ($history.SchemaVersion -ne 1 -or $history.Status -cne 'HistoricalCoverageOnly' -or @($history.Definitions).Count -gt 500) { throw 'Invalid historical coverage.' }
    $historicalNames = @{}
    foreach ($entry in $history.Definitions) {
      if ($entry.Name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$' -or $historicalNames.ContainsKey($entry.Name) -or $entry.ReviewClass -notin @('AppReview','DependencyReview','KeepReview')) { throw 'Invalid historical app identity.' }
      $historicalNames[$entry.Name] = $true
      foreach ($family in @($entry.LegacyRemoval) + @($entry.LegacyRegistration)) {
        if ($family -notin @('Microsoft','ThirdParty')) { throw 'Invalid historical app family.' }
      }
      if (-not $definitions.ContainsKey($entry.Name)) {
        $definitions[$entry.Name] = @{Name=$entry.Name;PolicyFamilyName='';StaticPolicyId='';ReviewClass=$entry.ReviewClass}
      }
      $definitions[$entry.Name].LegacyRemoval = @($entry.LegacyRemoval)
      $definitions[$entry.Name].LegacyRegistration = @($entry.LegacyRegistration)
    }
  }
  foreach ($name in @($definitions.Keys | Sort-Object)) { $definitions[$name] }
}

function Get-RideStoreInventoryUserSid {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { $identity.User.Value } finally { $identity.Dispose() }
}

function Get-RideStoreCurrentAppx {
  # Include dependency/resource types so they cannot disappear from the review.
  @(Get-AppxPackage -PackageTypeFilter Main,Framework,Bundle,Resource,Optional -ErrorAction Stop)
}

function Test-RideStoreInventoryAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
  finally { $identity.Dispose() }
}

function Get-RideStoreProvisionedPackages([string] $LogPath) {
  @(Get-AppxProvisionedPackage -Online -LogPath $LogPath -ErrorAction Stop)
}

function Get-RideStoreProvisionedAppInventory {
  <#
  .SYNOPSIS
    Collect online image provisioning separately from existing user registrations.
  .DESCRIPTION
    Requires an already elevated process; never requests elevation. Reads DISM
    provisioning and retains raw package identities without inventing PFNs.
  .PARAMETER LogPath
    Explicit evidence log path with an existing parent directory. DISM writes
    its diagnostic log here instead of the default Windows log location.
  .EXAMPLE
    Get-RideStoreProvisionedAppInventory -LogPath C:\Evidence\provisioning-dism.log
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 ProvisionedImage inventory; no removal approval.
  .NOTES
    Online image only; no mount, deprovisioning, registration or acquisition.
    Already elevated guest collection is separate from interactive host elevation.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string] $LogPath)
  if (-not (Test-RideStoreInventoryAdministrator)) { throw 'Provisioning inventory requires an already elevated process; postpone elevation.' }
  $log = [IO.Path]::GetFullPath($LogPath)
  if (-not (Test-Path -LiteralPath (Split-Path -Parent $log) -PathType Container)) { throw 'Create the provisioning evidence directory explicitly.' }
  $packages = @(Get-RideStoreProvisionedPackages -LogPath $log)
  if ($packages.Count -gt 5000) { throw 'Provisioning inventory exceeds its package bound.' }
  $rows = @(foreach ($package in $packages) {
    if (-not $package.DisplayName -or -not $package.PackageName) { throw 'Incomplete provisioned package identity.' }
    [pscustomobject][ordered]@{
      DisplayName=[string]$package.DisplayName;PackageName=[string]$package.PackageName
      Version=[string]$package.Version;Architecture=[string]$package.Architecture
      ResourceId=[string]$package.ResourceId;Regions=@($package.Regions)
    }
  })
  [pscustomobject][ordered]@{SchemaVersion=1;Scope='ProvisionedImage';ImageSource='OnlineOperatingSystem';CapturedAtUtc=[DateTime]::UtcNow.ToString('o');WindowsContext=Get-RideStoreWindowsContext;Packages=$rows;RegistrationEvidence=$false;RemovalApproved=$false}
}

function Get-RideStoreWindowsContext {
  try {
    $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $complete = $version.EditionID -and $version.DisplayVersion -and $version.CurrentBuildNumber
    [pscustomobject][ordered]@{
      Status = $(if ($complete) { 'Captured' } else { 'Partial' })
      Source = 'CurrentVersion registry observation; not a support declaration'
      EditionId = [string]$version.EditionID
      DisplayVersion = [string]$version.DisplayVersion
      CurrentBuild = [string]$version.CurrentBuildNumber
      UpdateBuildRevision = $version.UBR
      ProductNameObserved = [string]$version.ProductName
      ProcessArchitectureHint = [string]$env:PROCESSOR_ARCHITECTURE
      ProcessUiCulture = [Globalization.CultureInfo]::CurrentUICulture.Name
    }
  } catch {
    [pscustomobject]@{Status='Unavailable';Source='CurrentVersion registry observation unavailable'}
  }
}

function Get-RideStoreAppInventory {
  <#
  .SYNOPSIS
    Collect packages for the explicitly expected execution user, without changes.
  .DESCRIPTION
    Refuses an account mismatch before querying Appx. Queries this user only.
    Missing protection flags remain unknown; presence never approves removal.
  .PARAMETER ExpectedUserSid
    SID of the intended user, supplied explicitly to prevent administrator confusion.
  .EXAMPLE
    Get-RideStoreAppInventory -ExpectedUserSid 'S-1-5-21-1-2-3-1001'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 current-user inventory with package identity and flags.
  .NOTES
    No AllUsers query or user impersonation. Native Appx acceptance remains pending.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidatePattern('^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$')][string] $ExpectedUserSid)
  $actualSid = Get-RideStoreInventoryUserSid
  if ($actualSid -cne $ExpectedUserSid) { throw 'Inventory account differs from the intended user; nothing queried.' }
  $windowsContext = Get-RideStoreWindowsContext
  $packages = @(Get-RideStoreCurrentAppx)
  if ($packages.Count -gt 5000) { throw 'App inventory exceeds the package bound.' }
  $rows = @(foreach ($package in $packages) {
    $flags = @{}
    foreach ($flag in @('IsFramework','IsResourcePackage','NonRemovable','IsPartOfSystem')) {
      $flags[$flag] = if ($package.$flag -is [bool]) { $package.$flag } else { $null }
    }
    [pscustomobject][ordered]@{
      Name = [string]$package.Name
      PackageFamilyName = [string]$package.PackageFamilyName
      PackageFullName = [string]$package.PackageFullName
      Publisher = [string]$package.Publisher
      Version = [string]$package.Version
      Architecture = [string]$package.Architecture
      Status = [string]$package.Status
      IsFramework = $flags.IsFramework
      IsResourcePackage = $flags.IsResourcePackage
      NonRemovable = $flags.NonRemovable
      IsPartOfSystem = $flags.IsPartOfSystem
      Dependencies = @($package.Dependencies | ForEach-Object {
        [pscustomobject]@{Name=[string]$_.Name;PackageFamilyName=[string]$_.PackageFamilyName;PackageFullName=[string]$_.PackageFullName}
      })
    }
  })
  [pscustomobject][ordered]@{SchemaVersion=1;UserSid=$actualSid;Scope='CurrentUser';CapturedAtUtc=[DateTime]::UtcNow.ToString('o');WindowsContext=$windowsContext;Packages=$rows}
}

function Compare-RideStoreAppInventory {
  <#
  .SYNOPSIS
    Reconcile a saved inventory against historical and current policy identities.
  .DESCRIPTION
    Emits definitions even when absent, and includes unfamiliar installed names.
    Exact PFN matching is separate from a historical name or publisher mismatch.
    Every row remains unselected and unapproved for removal.
  .PARAMETER Inventory
    Schema-1 CurrentUser data produced by Get-RideStoreAppInventory.
  .PARAMETER IncludeHistoricalCoverage
    Explicitly include archived names; default output covers current candidates
    and actually observed packages rather than every historical absent app.
  .EXAMPLE
    Compare-RideStoreAppInventory -Inventory $savedInventory
  .INPUTS
    None. Inventory is supplied explicitly.
  .OUTPUTS
    PSCustomObject. Per-app reconciliation with observed registrations and review gaps.
  .NOTES
    No Windows query or mutation; module version and compatibility apply.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)] $Inventory, [switch] $IncludeHistoricalCoverage)
  if ($Inventory.SchemaVersion -ne 1 -or $Inventory.Scope -cne 'CurrentUser' -or $Inventory.UserSid -notmatch '^S-1-(?:5-21|12-1)-(?:\d+-){3}\d+$' -or @($Inventory.Packages).Count -gt 5000) { throw 'Invalid current-user inventory.' }
  $byName = @{}
  foreach ($package in $Inventory.Packages) {
    if ($package.Name -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]+$' -or $package.PackageFamilyName -notmatch '^[a-zA-Z0-9.-]+_[a-z0-9]{13}$' -or -not $package.PackageFullName -or $package.PackageFamilyName -ine ($package.Name + '_' + ($package.PackageFamilyName -split '_')[-1])) { throw 'Invalid observed package identity.' }
    foreach ($flag in @('IsFramework','IsResourcePackage','NonRemovable','IsPartOfSystem')) {
      if ($null -ne $package.$flag -and $package.$flag -isnot [bool]) { throw 'Invalid observed protection flag.' }
    }
    if (-not $byName.ContainsKey($package.Name)) { $byName[$package.Name] = @() }
    $byName[$package.Name] += @($package)
  }
  $definitions = @(Get-RideStoreAppDefinition -IncludeHistoricalCoverage:$IncludeHistoricalCoverage)
  $known = @{}
  foreach ($definition in $definitions) { $known[$definition.Name] = $definition }
  $names = @(@($known.Keys) + @($byName.Keys) | Sort-Object -Unique)
  foreach ($name in $names) {
    $definition = $known[$name]
    $observed = @($byName[$name] | Where-Object { $null -ne $_ })
    $families = @($observed.PackageFamilyName | Sort-Object -Unique)
    $mapping = if (-not $observed.Count) { 'NotObserved' }
      elseif (-not $definition) { 'UnreviewedCurrentName' }
      elseif (-not $definition.PolicyFamilyName) { 'HistoricalNameOnly' }
      elseif ($families.Count -eq 1 -and $families[0] -ieq $definition.PolicyFamilyName) { 'ExactPolicyFamilyObserved' }
      else { 'PolicyFamilyMismatch' }
    $reasons = @('Explicit keep/remove decision required','App data and exact reinstall recovery not established')
    if ($Inventory.WindowsContext.Status -ne 'Captured') { $reasons += 'Edition/build context incomplete; no cross-release coverage inferred' }
    if ($definition.ReviewClass -eq 'DependencyReview' -or @($observed | Where-Object { $_.IsFramework -or $_.IsResourcePackage }).Count) { $reasons += 'Dependency/resource review required' }
    if (@($observed | Where-Object { $_.NonRemovable -or $_.IsPartOfSystem }).Count) { $reasons += 'Observed protected/system package; no automatic removal' }
    if (@($observed | Where-Object { $null -eq $_.NonRemovable -or $null -eq $_.IsPartOfSystem -or $null -eq $_.IsFramework -or $null -eq $_.IsResourcePackage }).Count) { $reasons += 'Protection/type flags incomplete' }
    if ($definition.ReviewClass -eq 'KeepReview') { $reasons += 'Utility/recovery consumer: retain unless deliberately reviewed' }
    if ($definition -and @($definition.LegacyRemoval | Where-Object { $_ -notin $definition.LegacyRegistration }).Count) { $reasons += 'Historical removal has no matching registration entry' }
    [pscustomobject][ordered]@{
      Name=$name;UserSid=$Inventory.UserSid;WindowsContext=$Inventory.WindowsContext;MappingStatus=$mapping;StaticPolicyId=$definition.StaticPolicyId
      PolicyFamilyName=$definition.PolicyFamilyName;ObservedFamilies=$families;ObservedPackages=$observed
      LegacyRemoval=@($definition.LegacyRemoval | Where-Object { $_ });LegacyRegistration=@($definition.LegacyRegistration | Where-Object { $_ })
      ReviewClass=$(if($definition){$definition.ReviewClass}else{'Unreviewed'})
      HistoricalCoverageIncluded=[bool]$IncludeHistoricalCoverage
      Selection='Unselected';RemovalApproved=$false;PendingReview=$reasons
    }
  }
}

Export-ModuleMember -Function Get-RideStoreAppDefinition,Get-RideStoreAppInventory,Get-RideStoreProvisionedAppInventory,Compare-RideStoreAppInventory
