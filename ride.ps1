##########
# Win 10 / 11 / Server 2016 / Server 2019 Bootstrap Script - Main execution loop
# Author: Torsten Juul-Jensen
# Version: v4.00, 2022-02-11
# Source: https://github.com/tjuuljensen/ride-windows
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}

$tweaks = @()
$PSCommandArgs = @()

Function AddOrRemoveTweak($tweak) {
	If ($tweak[0] -eq "!") {
		# If the name starts with exclamation mark (!), exclude the tweak from selection
		$script:tweaks = $script:tweaks | Where-Object { $_ -ne $tweak.Substring(1) }
	} ElseIf ($tweak -ne "") {
		# Otherwise add the tweak
		$script:tweaks += $tweak
	}
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

# Parse and resolve paths in passed arguments
$i = 0
While ($i -lt $args.Length) {
	If ($args[$i].ToLower() -eq "-include") {
		# Resolve full path to the included file
		$include = Resolve-Path $args[++$i] -ErrorAction Stop
		$PSCommandArgs += "-include `"$include`""
		# Import the included file as a module
		Import-Module -Name $include -ErrorAction Stop
	} ElseIf ($args[$i].ToLower() -eq "-preset") {
		# Resolve full path to the preset file
		$preset = Resolve-Path $args[++$i] -ErrorAction Stop
		$PSCommandArgs += "-preset `"$preset`""
		# Load tweak names from the preset file
		Get-Content $preset -ErrorAction Stop | ForEach-Object { AddOrRemoveTweak($_.Split("#")[0].Trim()) }
	} ElseIf ($args[$i].ToLower() -eq "-ini") {
		# Resolve full path to the ini file
		$ini = Resolve-Path $args[++$i] -ErrorAction Stop
		$PSCommandArgs += "-ini `"$ini`""
		# Load valuesfrom the ini file
        Get-IniFile $ini
	} ElseIf ($args[$i].ToLower() -eq "-downloadonly") {
		[Environment]::SetEnvironmentVariable("RIDEVAR-Download-Only", $true, "Process")
		$PSCommandArgs += "-downloadonly"
	} ElseIf ($args[$i].ToLower() -eq "-log") {
		# Resolve full path to the output file
		$log = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($args[++$i])
		$PSCommandArgs += "-log `"$log`""
		# Record session to the output file
		Start-Transcript $log
	} Else {
		$PSCommandArgs += $args[$i]
		# Load tweak names from command line
		AddOrRemoveTweak($args[$i])
	}
	$i++
}

# Call the desired tweak functions
$tweaks | ForEach-Object { Invoke-Expression $_ }
