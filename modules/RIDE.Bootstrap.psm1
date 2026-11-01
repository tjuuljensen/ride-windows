<#
.SYNOPSIS
  Build correctly quoted Windows process argument strings.
.DESCRIPTION
  Quotes arguments according to the Windows command-line parsing convention used
  by the PowerShell executable. This is required by Start-Process, whose
  ArgumentList parameter joins its input into one command-line string.
.PARAMETER Argument
  One argument to quote. Empty strings are retained as an explicit empty argument.
.PARAMETER Arguments
  Ordered arguments to join into one Windows command line.
.EXAMPLE
  ConvertTo-RideWindowsCommandLineArgument 'C:\Program Files\RIDE\ride.ps1'
.EXAMPLE
  Join-RideWindowsCommandLine @('-File', 'C:\Program Files\RIDE\ride.ps1', 'plan')
.INPUTS
  System.String or System.String[].
.OUTPUTS
  System.String.
.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows.
  Prerequisites: None.
  Version: 0.1.0.
#>

function ConvertTo-RideWindowsCommandLineArgument {
  [CmdletBinding()]
  param([AllowNull()][AllowEmptyString()][Parameter(Mandatory)][string] $Argument)

  if ($null -eq $Argument) { $Argument = '' }
  if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }

  $builder = [Text.StringBuilder]::new()
  [void]$builder.Append('"')
  $backslashCount = 0
  foreach ($character in $Argument.ToCharArray()) {
    if ($character -eq [char]92) {
      $backslashCount++
      continue
    }
    if ($character -eq [char]34) {
      [void]$builder.Append([string]::new([char]92, (2 * $backslashCount) + 1))
      [void]$builder.Append('"')
      $backslashCount = 0
      continue
    }
    if ($backslashCount -gt 0) {
      [void]$builder.Append([string]::new([char]92, $backslashCount))
      $backslashCount = 0
    }
    [void]$builder.Append($character)
  }
  if ($backslashCount -gt 0) {
    [void]$builder.Append([string]::new([char]92, 2 * $backslashCount))
  }
  [void]$builder.Append('"')
  $builder.ToString()
}

function Join-RideWindowsCommandLine {
  [CmdletBinding()]
  param([AllowEmptyCollection()][Parameter(Mandatory)][string[]] $Arguments)

  (@($Arguments | ForEach-Object { ConvertTo-RideWindowsCommandLineArgument -Argument $_ }) -join ' ')
}

Export-ModuleMember -Function ConvertTo-RideWindowsCommandLineArgument, Join-RideWindowsCommandLine
