<#
.SYNOPSIS
  Show selected cryptographic hash values for one file.
.DESCRIPTION
  Computes only the requested algorithm or the complete legacy submenu set from
  the exact literal path passed by Windows Shell, then shows the values in one
  short-lived message box. It does not change the file or write a report.
.PARAMETER LiteralPath
  Exact file path supplied by the Shell context-menu verb.
.PARAMETER Algorithm
  MD5, SHA1, SHA256, SHA384, SHA512, MACTripleDES, RIPEMD160, or ShowAll.
.EXAMPLE
  powershell.exe -NoProfile -STA -File .\tools\Get-RideHashValue.ps1 -LiteralPath 'C:\Example\sample.bin' -Algorithm SHA256
.INPUTS
  None. Parameters are supplied explicitly.
.OUTPUTS
  None when invoked as a script. Internal calculation returns hash objects.
.NOTES
  Compatibility: Windows PowerShell 5.1 on Windows.
  Prerequisites: Windows Forms; the selected file must be readable.
  Attribution: Original RIDE-Windows helper; based on the built-in Get-FileHash cmdlet.
  Version: 1.0.0.
  Changelog: 1.0.0: Add argument-based literal-path hashing for the RIDE context menu.
#>
#requires -version 5.1
[CmdletBinding()]
param(
  [string] $LiteralPath,
  [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'RIPEMD160', 'ShowAll')]
  [string] $Algorithm
)

$ErrorActionPreference = 'Stop'

function Get-RideHashValueRows {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string] $LiteralPath,
    [Parameter(Mandatory)][ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'RIPEMD160', 'ShowAll')]
    [string] $Algorithm
  )

  $algorithms = if ($Algorithm -eq 'ShowAll') {
    @('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'MACTripleDES', 'RIPEMD160')
  }
  else { @($Algorithm) }

  foreach ($name in $algorithms) {
    $result = Get-FileHash -LiteralPath $LiteralPath -Algorithm $name -ErrorAction Stop
    [pscustomobject]@{ Algorithm = $name; Hash = [string]$result.Hash }
  }
}

function Format-RideHashValueRows {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object[]] $Rows)

  @($Rows | ForEach-Object { '{0}: {1}' -f $_.Algorithm, $_.Hash }) -join [Environment]::NewLine
}

function Show-RideHashValueMessage {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string] $Message,
    [Parameter(Mandatory)][string] $Title,
    [switch] $ErrorMessage
  )

  Add-Type -AssemblyName System.Windows.Forms
  $icon = if ($ErrorMessage) { [System.Windows.Forms.MessageBoxIcon]::Error } else { [System.Windows.Forms.MessageBoxIcon]::Information }
  [void][System.Windows.Forms.MessageBox]::Show($Message, $Title, [System.Windows.Forms.MessageBoxButtons]::OK, $icon)
}

if ($MyInvocation.InvocationName -ne '.') {
  if ([string]::IsNullOrWhiteSpace($LiteralPath) -or [string]::IsNullOrWhiteSpace($Algorithm)) {
    throw 'Both LiteralPath and Algorithm are required.'
  }

  try {
    $rows = @(Get-RideHashValueRows -LiteralPath $LiteralPath -Algorithm $Algorithm)
    $body = Format-RideHashValueRows -Rows $rows
    Show-RideHashValueMessage -Message $body -Title (Split-Path -Leaf -LiteralPath $LiteralPath)
  }
  catch {
    Show-RideHashValueMessage -Message $_.Exception.Message -Title 'Hash calculation failed' -ErrorMessage
  }
}
