<#
.SYNOPSIS
  Observe local Windows component identities and literal servicing states.
.DESCRIPTION
  Keeps DISM foundation features, capabilities and Server Manager features separate.
  Queries only explicitly selected providers in an already elevated process. Import
  and completion never query Windows. No servicing, acquisition or reboot occurs.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; native
  provider acceptance is target-specific and remains pending.
  Prerequisites: Already elevated native process, available selected Windows modules,
  and an existing local evidence directory for uniquely named DISM diagnostic logs.
  File/environment inputs: Explicit expected machine/build/edition and log directory.
  Recovery: Observation only; retain diagnostic files. Not an engine recovery record.
  Version: 0.1.0
  Changelog: 0.1.0: Add separate, bounded component observation and saved-data lookup.
.LINK
  ../docs/windows-component-inventory.md
#>
$ErrorActionPreference = 'Stop'

function Get-RideComponentWindowsContext {
  $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
  $product = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions' -ErrorAction Stop
  [pscustomobject]@{
    ComputerName=[Environment]::MachineName; Build=[string]$version.CurrentBuildNumber
    EditionId=[string]$version.EditionID; UpdateBuildRevision=$version.UBR
    InstallationType=[string]$version.InstallationType; ProductType=[string]$product.ProductType
    NativeProcess=([Environment]::Is64BitProcess -or -not [Environment]::Is64BitOperatingSystem)
    Source='Local registry and process observation; not a support declaration'
  }
}

function Test-RideComponentInventoryAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  try { ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
  finally { $identity.Dispose() }
}

function Get-RideComponentProviderRows {
  param([string]$Kind,[string]$LogPath,[string]$ScratchDirectory)
  switch ($Kind) {
    'OptionalFeature' { Dism\Get-WindowsOptionalFeature -Online -LogPath $LogPath -ScratchDirectory $ScratchDirectory -ErrorAction Stop }
    'Capability' { Dism\Get-WindowsCapability -Online -LogPath $LogPath -ScratchDirectory $ScratchDirectory -ErrorAction Stop }
    'ServerFeature' { ServerManager\Get-WindowsFeature -ErrorAction Stop }
    default { throw 'Unknown component provider.' }
  }
}

function Assert-RideComponentIdentity {
  param($Name)
  if ($Name -isnot [string] -or [string]::IsNullOrWhiteSpace($Name) -or $Name.Length -gt 1024 -or $Name -match '[\x00-\x1f]') { throw 'Invalid component identity.' }
}

function Get-RideWindowsComponentInventory {
  <#
  .SYNOPSIS
    Capture selected component providers on an explicitly identified local OS.
  .DESCRIPTION
    Refuses a machine/build/edition mismatch before querying servicing providers.
    Each provider either completes or is Unavailable with no partial rows. Missing
    names and unavailable providers remain different. No source availability is inferred.
  .PARAMETER Kind
    One or more distinct provider kinds; no provider is queried implicitly.
  .PARAMETER ExpectedComputerName
    Intended local computer name. Remote collection is not supported.
  .PARAMETER ExpectedBuild
    Exact observed OS build number, supplied independently from the intended target.
  .PARAMETER ExpectedEditionId
    Intended OS EditionID from the CurrentVersion registry key.
  .PARAMETER LogDirectory
    Existing local evidence directory. DISM uses unique log paths here and its own
    scratch subdirectories. Server Manager does not use a DISM log.
  .EXAMPLE
    Get-RideWindowsComponentInventory -Kind OptionalFeature,Capability -ExpectedComputerName '<target>' -ExpectedBuild '<build>' -ExpectedEditionId '<edition>' -LogDirectory C:\Evidence
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Schema-1 observation with independent provider results.
  .NOTES
    Requires existing elevation; never prompts. No mutation-ready or recovery claim.
    Maximum 4096 rows per provider; native query duration is not hard-time-limited.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('OptionalFeature','Capability','ServerFeature')][string[]]$Kind,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedComputerName,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]{4,8}$')][string]$ExpectedBuild,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedEditionId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$LogDirectory
  )
  if (-not (Test-RideComponentInventoryAdministrator)) { throw 'Component inventory needs existing elevation; postpone this collection until available.' }
  $selectedKinds=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  foreach($item in $Kind) { if (-not $selectedKinds.Add($item)) { throw 'Select each component provider only once.' } }
  $context=Get-RideComponentWindowsContext
  if (-not $context.NativeProcess -or $context.ComputerName -ine $ExpectedComputerName -or $context.Build -cne $ExpectedBuild -or $context.EditionId -ine $ExpectedEditionId -or $context.ProductType -cnotin @('WinNT','ServerNT','LanmanNT')) { throw 'Component inventory target differs from the expected native machine/build/edition.' }
  $logRoot=[IO.Path]::GetFullPath($LogDirectory)
  if ($logRoot.StartsWith('\\') -or -not [IO.Directory]::Exists($logRoot)) { throw 'Component evidence requires an existing local directory.' }
  $started=[DateTime]::UtcNow.ToString('o')
  $providers=@(foreach($providerKind in $Kind) {
    $providerKind=switch($providerKind){'OptionalFeature'{'OptionalFeature'} 'Capability'{'Capability'} 'ServerFeature'{'ServerFeature'}}
    $result=[pscustomobject]@{Kind=$providerKind;Status='Unavailable';Rows=$null;ErrorId=$null;LogPath=$null;Coverage=$null}
    if ($providerKind -eq 'ServerFeature' -and $context.ProductType -ceq 'WinNT') {
      $result.Status='NotApplicable'; $result.Coverage='Server Manager roles/features are not queried on a client OS.'; $result
      continue
    }
    $result.Coverage=switch($providerKind) {
      'OptionalFeature' {'Windows Foundation Package features; not every feature in every package.'}
      'Capability' {'Capabilities reported by the current online image.'}
      'ServerFeature' {'Local Server Manager roles/features; not client capabilities.'}
    }
    if ($providerKind -ne 'ServerFeature') { $result.LogPath=Join-Path $logRoot ('components-'+[Guid]::NewGuid().ToString('N')+'.log') }
    try {
      $rows=[Collections.Generic.List[object]]::new()
      $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      Get-RideComponentProviderRows -Kind $providerKind -LogPath $result.LogPath -ScratchDirectory $logRoot | ForEach-Object {
        if ($rows.Count -ge 4096) { throw 'Component provider exceeds the row bound.' }
        $name=if($providerKind -eq 'OptionalFeature'){$_.FeatureName}else{$_.Name}
        Assert-RideComponentIdentity $name
        if (-not $names.Add($name)) { throw 'Duplicate component identity.' }
        $state=if($providerKind -eq 'ServerFeature'){[string]$_.InstallState}else{[string]$_.State}
        if ([string]::IsNullOrWhiteSpace($state) -or $state.Length -gt 128 -or $state -match '[\x00-\x1f]') { throw 'Missing or invalid literal component state.' }
        $rows.Add([pscustomobject]@{Name=$name;StateObserved=$state;DependenciesVerified=$false;SourceAvailability='Unknown';Selected=$false})
      }
      $result.Rows=@($rows.ToArray()); $result.Status='Captured'
    } catch {
      # Do not promote partial enumeration to absence or embed arbitrary provider text.
      $result.Rows=$null; $result.ErrorId=$_.Exception.GetType().FullName
    }
    $result
  })
  $after=Get-RideComponentWindowsContext
  foreach($field in @('ComputerName','Build','EditionId','UpdateBuildRevision','ProductType','NativeProcess')) {
    if ($after.$field -cne $context.$field) { throw 'Component target changed during collection; retain logs but discard the observation.' }
  }
  [pscustomobject]@{
    SchemaVersion=1;Kind='WindowsComponentObservation';WindowsContext=$context
    StartedAtUtc=$started;CompletedAtUtc=[DateTime]::UtcNow.ToString('o');Providers=$providers
    Consistency='Sequential provider observations; not atomic';ReadyForMutation=$false;RecoverySupported=$false
  }
}

function Find-RideWindowsComponentObservation {
  <#
  .SYNOPSIS
    Look up one exact name in a selected provider's saved observation.
  .PARAMETER Inventory
    Observation from Get-RideWindowsComponentInventory or its JSON representation.
  .PARAMETER Kind
    Provider namespace; similar names in different namespaces are independent.
  .PARAMETER Name
    Exact observed identifier; prefix completion uses supplied data only.
  .EXAMPLE
    Find-RideWindowsComponentObservation -Inventory $inventory -Kind Capability -Name 'OpenSSH.Client~~~~0.0.1.0'
  .INPUTS
    None.
  .OUTPUTS
    PSCustomObject. Observed, NotObserved, Unavailable, NotApplicable or NotCollected.
  .NOTES
    NotObserved is limited to a completed provider's declared coverage; it is not
    proof that the component cannot be installed. Never searches a different provider.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory,
    [Parameter(Mandatory)][ValidateSet('OptionalFeature','Capability','ServerFeature')][string]$Kind,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()]
    [ArgumentCompleter({
      param($commandName,$parameterName,$wordToComplete,$commandAst,$fakeBoundParameters)
      try {
        $data=$fakeBoundParameters['Inventory'];$kindValue=$fakeBoundParameters['Kind']
        if ($null -eq $data -or @($data.Providers).Count -gt 3) { return }
        $providers=@($data.Providers | Where-Object {$_.Kind -ieq $kindValue -and $_.Status -ceq 'Captured'})
        if ($providers.Count -ne 1 -or @($providers[0].Rows).Count -gt 4096) { return }
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach($row in @($providers[0].Rows)) {
          $id=[string]$row.Name
          if (-not [string]::IsNullOrWhiteSpace($id) -and $id.Length -le 1024 -and $id -notmatch '[\x00-\x1f]' -and $id.StartsWith($wordToComplete,[StringComparison]::OrdinalIgnoreCase) -and $seen.Add($id)) {
            [Management.Automation.CompletionResult]::new(("'"+$id.Replace("'","''")+"'"),$id,'ParameterValue',$id)
          }
        }
      } catch { return }
    })][string]$Name)
  Assert-RideComponentIdentity $Name
  if ($Inventory.SchemaVersion -ne 1 -or $Inventory.Kind -cne 'WindowsComponentObservation' -or @($Inventory.Providers).Count -gt 3) { throw 'Invalid component observation schema.' }
  $seen=@{}
  foreach($provider in @($Inventory.Providers)) {
    if ($provider.Kind -cnotin @('OptionalFeature','Capability','ServerFeature') -or $seen.ContainsKey($provider.Kind) -or $provider.Status -cnotin @('Captured','Unavailable','NotApplicable')) { throw 'Invalid or duplicate component provider.' }
    $seen[$provider.Kind]=$true
    if ($provider.Status -ceq 'Captured') {
      if ($null -eq $provider.Rows -or @($provider.Rows).Count -gt 4096) { throw 'Invalid captured provider row collection.' }
      $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach($row in @($provider.Rows)) {
        Assert-RideComponentIdentity $row.Name
        if (-not $names.Add($row.Name) -or $row.StateObserved -isnot [string] -or [string]::IsNullOrWhiteSpace($row.StateObserved) -or $row.StateObserved.Length -gt 128 -or $row.StateObserved -match '[\x00-\x1f]') { throw 'Invalid or duplicate captured component row.' }
      }
    } elseif ($null -ne $provider.Rows) { throw 'An unavailable provider cannot contain captured rows.' }
  }
  $selected=@($Inventory.Providers | Where-Object {$_.Kind -ieq $Kind})
  $row=$null; $coverage=$null; $status='NotCollected'
  if ($selected.Count -eq 1) {
    $provider=$selected[0]; $status=$provider.Status; $coverage=$provider.Coverage
    if ($status -ceq 'Captured') {
      $matches=@($provider.Rows | Where-Object {[string]::Equals($_.Name,$Name,[StringComparison]::Ordinal)})
      $status='NotObserved'
      if ($matches.Count -eq 1) { $status='Observed'; $row=$matches[0] }
    }
  }
  [pscustomobject]@{Kind=$Kind;Name=$Name;Status=$status;Observation=$row;Coverage=$coverage;ReadyForMutation=$false;RecoverySupported=$false}
}

Export-ModuleMember -Function Get-RideWindowsComponentInventory,Find-RideWindowsComponentObservation
