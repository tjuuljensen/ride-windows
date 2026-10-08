<#
.SYNOPSIS
  Capture and restore declared registry subtrees and their security descriptors.

.DESCRIPTION
  Recursively captures typed values and owner/group/access security. Hidden removes catalog roots;
  Visible creates missing roots. Restore replaces current roots and reconstructs saved trees. Import
  may compile the RIDE.RegistrySecurityNative P/Invoke helper, but does not query or change registry
  state.

.EXAMPLE
  Import-Module .\modules\RIDE-RegistryKeySet.psm1
  Import definitions; inspect exported commands with Get-Help before use.

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None on import. Exported commands return the types documented in their individual help.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows registry APIs, Add-Type, and sufficient registry/ACL rights; elevation for
  machine keys.
  File/environment inputs: Catalog RegistryPaths and saved typed tree/security records.
  Recovery: State-changing handlers are engine-internal: use ride.ps1 preview and captured-run
  restoration. Direct calls bypass ShouldProcess and snapshot capture.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Initial reversible registry key-set handler (existing header version retained; module
    constant added).
  Supported targets are declared per operation in catalog/operations.psd1. This walkthrough
  validates syntax/help, not Windows state transitions.

.LINK
  docs/models/script-repository-model.md

.LINK
  docs/OPERATIONS.md

#>


$script:ModuleVersion = '0.1.0'

if (-not ('RIDE.RegistrySecurityNative' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RIDE {
  public static class RegistrySecurityNative {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegSetKeySecurity(SafeRegistryHandle key, uint securityInformation, byte[] securityDescriptor);
  }
}
'@
}

function Get-RideRegistryKeyTreeNode {
  param(
    [Parameter(Mandatory = $true)][string] $LiteralPath,
    [Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey] $RegistryKey,
    [Parameter(Mandatory = $true)][AllowEmptyString()][string] $RelativePath
  )

  $values = foreach ($name in ($RegistryKey.GetValueNames() | Sort-Object)) {
    $kind = $RegistryKey.GetValueKind($name).ToString()
    $value = $RegistryKey.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($kind -notin @('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord', 'None')) {
      throw "Registry value '$name' at '$LiteralPath' has unsupported type '$kind'; refusing an inexact snapshot."
    }
    $encoding = if ($kind -in @('Binary', 'None')) { 'Base64' } else { 'Native' }
    if ($encoding -eq 'Base64') { $value = [Convert]::ToBase64String([byte[]]$value) }
    [ordered]@{ Name = $name; Kind = $kind; Encoding = $encoding; Value = $value }
  }

  $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group -bor [System.Security.AccessControl.AccessControlSections]::Access
  $acl = $RegistryKey.GetAccessControl($sections)
  $children = foreach ($childName in ($RegistryKey.GetSubKeyNames() | Sort-Object)) {
    $childRelativePath = if ($RelativePath) { $RelativePath + '\' + $childName } else { $childName }
    $childPath = $LiteralPath + '\' + $childName
    $childKey = $RegistryKey.OpenSubKey($childName, $false)
    if ($null -eq $childKey) { throw "Registry subkey disappeared during snapshot: '$childPath'." }
    try {
      Get-RideRegistryKeyTreeNode -LiteralPath $childPath -RegistryKey $childKey -RelativePath $childRelativePath
    }
    finally {
      $childKey.Dispose()
    }
  }

  [ordered]@{
    RelativePath = $RelativePath
    SecurityDescriptor = $acl.GetSecurityDescriptorSddlForm($sections)
    Values = @($values)
    Children = @($children)
  }
}

function Get-RideRegistryKeyTreeState {
  <#
  .SYNOPSIS
    Capture declared registry trees, typed values, and security descriptors.

  .DESCRIPTION
    Reads each HKLM/HKCU root recursively. Preserves owner/group/access SDDL and Base64 binary data;
    refuses unsupported value kinds or disappearing subkeys. No registry writes occur.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .EXAMPLE
    Get-Help Get-RideRegistryKeyTreeState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    System.Management.Automation.PSCustomObject. Trees, PresentCount, and TotalCount.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param([Parameter(Mandatory = $true)][hashtable] $Operation)

  $trees = foreach ($path in $Operation.RegistryPaths) {
    $key = Open-RideRegistryKey -LiteralPath $path
    if ($null -eq $key) {
      [ordered]@{ Path = $path; Exists = $false; Root = $null }
    }
    else {
      try {
        $root = Get-RideRegistryKeyTreeNode -LiteralPath $path -RegistryKey $key -RelativePath ''
        [ordered]@{ Path = $path; Exists = $true; Root = $root }
      }
      finally {
        $key.Dispose()
      }
    }
  }

  [pscustomobject]@{ Trees = @($trees); PresentCount = @($trees | Where-Object Exists).Count; TotalCount = @($Operation.RegistryPaths).Count }
}

function Open-RideRegistryKey {
  param(
    [Parameter(Mandatory = $true)][string] $LiteralPath,
    [switch] $Writable
  )

  if ($LiteralPath -notmatch '^(?<Hive>HKLM|HKCU):\\(?<SubKey>.+)$') {
    throw "Registry key path is outside the supported HKLM/HKCU hives: '$LiteralPath'."
  }
  $hive = if ($matches.Hive -eq 'HKLM') { [Microsoft.Win32.RegistryHive]::LocalMachine } else { [Microsoft.Win32.RegistryHive]::CurrentUser }
  $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, [Microsoft.Win32.RegistryView]::Default)
  try {
    if ($Writable) {
      $rights = [System.Security.AccessControl.RegistryRights]::ReadKey -bor [System.Security.AccessControl.RegistryRights]::SetValue -bor [System.Security.AccessControl.RegistryRights]::CreateSubKey -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions -bor [System.Security.AccessControl.RegistryRights]::TakeOwnership
      $key = $baseKey.OpenSubKey($matches.SubKey, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
    }
    else {
      $key = $baseKey.OpenSubKey($matches.SubKey, $false)
    }
    return $key
  }
  finally {
    $baseKey.Dispose()
  }
}

function Open-RideWritableRegistryKey {
  param([Parameter(Mandatory = $true)][string] $LiteralPath)
  $key = Open-RideRegistryKey -LiteralPath $LiteralPath -Writable
  if ($null -eq $key) { throw "Could not open registry key for writing: '$LiteralPath'." }
  $key
}

function Set-RideRegistryKeySetState {
  <#
  .SYNOPSIS
    Create or remove the declared registry roots.

  .DESCRIPTION
    Hidden recursively deletes the catalog roots. Visible creates missing empty roots; it does not
    recreate deleted subtree contents. Use the engine to capture exact prior trees and preview
    changes.

  .PARAMETER Operation
    Catalog operation metadata for this focused handler; use the engine to select and validate it.

  .PARAMETER State
    Declared desired state for the selected catalog operation.

  .EXAMPLE
    Get-Help Set-RideRegistryKeySetState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][hashtable] $Operation,
    [Parameter(Mandatory = $true)][ValidateSet('Visible', 'Hidden')][string] $State
  )

  foreach ($path in $Operation.RegistryPaths) {
    if ($State -eq 'Hidden') {
      if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop }
    }
    elseif (-not (Test-Path -LiteralPath $path)) {
      New-Item -Path $path -Force -ErrorAction Stop | Out-Null
    }
  }
}

function Restore-RideRegistryKeySetState {
  <#
  .SYNOPSIS
    Replace current roots with the captured registry trees.

  .DESCRIPTION
    Deletes current roots, recreates saved nodes/typed values, then restores saved security
    descriptors through the Windows API. Destructive direct calls bypass engine checks; use
    Restore-RideRun.

  .PARAMETER Trees
    Saved tree records containing Path, Exists, Root, typed Values, Children, and SecurityDescriptor
    from a matching pre-change snapshot.

  .EXAMPLE
    Get-Help Restore-RideRegistryKeySetState -Full
    Inspect this command's contract without invoking its implementation.

  .INPUTS
    None. Parameters are supplied explicitly.

  .OUTPUTS
    None.

  .NOTES
    Ownership: RIDE-Windows maintainers. Version and compatibility follow the module overview.

  #>

  param(
    [Parameter(Mandatory = $true)][object[]] $Trees
  )

  foreach ($tree in $Trees) {
    if (Test-Path -LiteralPath $tree.Path) { Remove-Item -LiteralPath $tree.Path -Recurse -Force -ErrorAction Stop }
    if (-not $tree.Exists) { continue }

    $nodes = New-Object System.Collections.Generic.List[object]
    $pending = New-Object System.Collections.Generic.Stack[object]
    $pending.Push($tree.Root)
    while ($pending.Count -gt 0) {
      $node = $pending.Pop()
      $nodes.Add($node)
      foreach ($child in @($node.Children)) {
        $pending.Push($child)
      }
    }

    foreach ($node in $nodes) {
      $path = if ($node.RelativePath) { Join-Path $tree.Path $node.RelativePath } else { [string]$tree.Path }
      if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force -ErrorAction Stop | Out-Null }
      foreach ($value in @($node.Values)) {
        $data = switch ([string]$value.Kind) {
          'Binary' { ,([Convert]::FromBase64String([string]$value.Value)); break }
          'None' { ,([Convert]::FromBase64String([string]$value.Value)); break }
          'DWord' { [int]$value.Value; break }
          'QWord' { [long]$value.Value; break }
          'MultiString' { ,([string[]]@($value.Value)); break }
          default { [string]$value.Value }
        }
        $key = Open-RideWritableRegistryKey -LiteralPath $path
        $kind = [System.Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$value.Kind)
        $valueName = if ([string]$value.Name) { [string]$value.Name } else { $null }
        try {
          $key.SetValue($valueName, $data, $kind)
          $key.Flush()
        }
        finally {
          $key.Dispose()
        }
      }
    }

    for ($index = $nodes.Count - 1; $index -ge 0; $index--) {
      $node = $nodes[$index]
      $path = if ($node.RelativePath) { Join-Path $tree.Path $node.RelativePath } else { [string]$tree.Path }
      $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group -bor [System.Security.AccessControl.AccessControlSections]::Access
      $key = Open-RideWritableRegistryKey -LiteralPath $path
      try {
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        $acl.SetSecurityDescriptorSddlForm([string]$node.SecurityDescriptor, $sections)
        $securityDescriptor = $acl.GetSecurityDescriptorBinaryForm()
        $result = [RIDE.RegistrySecurityNative]::RegSetKeySecurity($key.Handle, 0x7, $securityDescriptor)
        if ($result -ne 0) { throw (New-Object System.ComponentModel.Win32Exception($result)) }
        $key.Flush()
      }
      finally {
        $key.Dispose()
      }
    }
  }
}

Export-ModuleMember -Function Get-RideRegistryKeyTreeState, Set-RideRegistryKeySetState, Restore-RideRegistryKeySetState
