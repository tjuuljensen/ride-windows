<#
.SYNOPSIS
	Windows setup automation runner for the RIDE tweak library.
.DESCRIPTION
	RIDE (Remove - Install - Disable - Enable) loads one or more PowerShell
	modules, selects tweak functions from preset files and command-line
	arguments, and then invokes the selected functions.

	The script is intended for routine post-installation configuration on
	supported Windows client and Windows Server systems. It is not a complete
	hardening baseline and it can make invasive system changes. Read the selected
	preset and tweak functions before running them.
.PARAMETER Include
	One or more PowerShell modules containing RIDE tweak functions. The standard
	repository module is lib-windows.psm1. Include files are resolved before
	importing, so relative paths are accepted.
.PARAMETER Preset
	One or more preset files containing tweak function names, one per line.
	Comments beginning with # are ignored. A function name prefixed with ! removes
	that tweak from the current selection.
.PARAMETER Ini
	Optional INI file used to populate RIDEVAR-* process environment variables
	consumed by selected tweak functions.
.PARAMETER DownloadOnly
	Set download-only mode for installer functions that support it. This sets the
	RIDEVAR-Download-Only process environment variable.
.PARAMETER Log
	Optional transcript log path. The path may be relative or absolute.
.PARAMETER Tweak
	Additional tweak function names to apply. Prefix a name with ! to remove it
	from the current selection. This parameter also captures remaining positional
	arguments so legacy calls such as `ride.ps1 -include lib-windows.psm1 Restart`
	continue to work.
.NOTES
	This script is for Windows only. Though many features might work in 32-bit
	environments, the script is made for and tested on x64 installations.
.LINK
	https://github.com/tjuuljensen/ride-windows/blob/master/README.md
.EXAMPLE
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ride.ps1 -Include .\lib-windows.psm1 -Preset .\default.preset
.EXAMPLE
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ride.ps1 -Include .\lib-windows.psm1 -Preset .\default.preset -DownloadOnly
.EXAMPLE
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ride.ps1 -Include .\lib-windows.psm1 -Preset .\default.preset -Ini .\example.ini -Log .\install-log.log
.EXAMPLE
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ride.ps1 -Include .\lib-windows.psm1 ShowKnownExtensions !HideKnownExtensions
#>

[CmdletBinding(PositionalBinding = $false)]
param(
	[Parameter()]
	[string[]] $Include = @(),

	[Parameter()]
	[string[]] $Preset = @(),

	[Parameter()]
	[string] $Ini = "",

	[Parameter()]
	[switch] $DownloadOnly,

	[Parameter()]
	[string] $Log = "",

	[Parameter(ValueFromRemainingArguments = $true)]
	[string[]] $Tweak = @()
)

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}

$tweaks = @()
$ModulesIncluded = @()
$PSCommandArgs = @()

Function Add-PSCommandArgument {
	param(
		[string] $Name,
		[string] $Value = ""
	)

	If ($Value -eq "") {
		$script:PSCommandArgs += $Name
	} Else {
		$script:PSCommandArgs += "$Name `"$Value`""
	}
}

Function AddOrRemoveTweak($tweak) {
	If ($tweak -eq "") {
		return
	}

	If ($tweak[0] -eq "!") {
		# If the name starts with exclamation mark (!), exclude the tweak from selection
		$script:tweaks = $script:tweaks | Where-Object { $_ -ne $tweak.Substring(1) }
	} Else {
		# Otherwise add the tweak
		$script:tweaks += $tweak
	}
}

Function Invoke-Tweak($tweak) {
	$command = Get-Command -Name $tweak -CommandType Function -ErrorAction SilentlyContinue
	if (-not $command) {
		throw "Tweak function not found: $tweak"
	}

	& $command
}

function Get-IniFile {
# Inspired by: https://stackoverflow.com/a/422529
# Read contents of ini file into a variable
# Inspired by https://stackoverflow.com/questions/43690336/powershell-to-read-single-value-from-simple-ini-file
    param(
        [parameter(Mandatory = $true)] [string] $filePath
	)

    # Create a default section if none exist in the file. Like a java prop file.
    $section = "NO_SECTION"

    switch -regex -file $filePath {
        "^\[(.+)\]$" {
            $section = $matches[1].Trim()
        }
        "^\s*([^#].+?)\s*=\s*(.*)" {
            $name,$value = $matches[1..2]
            # skip comments that start with semicolon:
            if (!($name.StartsWith(";"))) {
                [Environment]::SetEnvironmentVariable("RIDEVAR-$section-$name", $value.Trim(), "Process")
            }
        }
    }
}

# Clean up env from potentially earlier execution
Remove-Item -Path env:RIDEVAR-Download-Only -ErrorAction SilentlyContinue

# Resolve and import included tweak modules
foreach ($includePath in $Include) {
	$resolvedInclude = Resolve-Path $includePath -ErrorAction Stop
	Add-PSCommandArgument -Name "-Include" -Value $resolvedInclude
	Import-Module -Name $resolvedInclude -ErrorAction Stop
	$ModulesIncluded += [System.IO.Path]::GetFileNameWithoutExtension("$resolvedInclude")
}

# Resolve preset files and load selected tweak names
foreach ($presetPath in $Preset) {
	$resolvedPreset = Resolve-Path $presetPath -ErrorAction Stop
	Add-PSCommandArgument -Name "-Preset" -Value $resolvedPreset
	Get-Content $resolvedPreset -ErrorAction Stop | ForEach-Object { AddOrRemoveTweak($_.Split("#")[0].Trim()) }
}

If ($Ini) {
	$resolvedIni = Resolve-Path $Ini -ErrorAction Stop
	Add-PSCommandArgument -Name "-Ini" -Value $resolvedIni
	Get-IniFile $resolvedIni
}

If ($DownloadOnly) {
	[Environment]::SetEnvironmentVariable("RIDEVAR-Download-Only", $true, "Process")
	Add-PSCommandArgument -Name "-DownloadOnly"
}

If ($Log) {
	$resolvedLog = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Log)
	Add-PSCommandArgument -Name "-Log" -Value $resolvedLog
	Start-Transcript $resolvedLog
}

foreach ($tweakName in $Tweak) {
	Add-PSCommandArgument -Name $tweakName
	AddOrRemoveTweak($tweakName)
}

# Call the desired tweak functions
$tweaks | ForEach-Object { Invoke-Tweak $_ }

# Unload loaded modules after execution of tweaks
if ($ModulesIncluded.Length -gt 0 ) { $ModulesIncluded | ForEach-Object { Remove-Module -Name $_ -Force -ErrorAction Stop } }
