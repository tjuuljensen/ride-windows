##########
# Win 10 / 11 / Server 2016 / Server 2019 Bootstrap Script - Main execution loop
# Author: Torsten Juul-Jensen
# Version: v4.00, 2022-02-11
# Source: https://github.com/tjuuljensen/bootstrap-windows
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
# Read contents of ini file into a variable
# Inspired by https://stackoverflow.com/questions/43690336/powershell-to-read-single-value-from-simple-ini-file
    param(
        [parameter(Mandatory = $true)] [string] $filePath
			  )
    $anonymous = "NoSection"
    $ini = @{}
    switch -regex -file $filePath
    {
        "^\[(.+)\]$" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^([#;].*)$" # Comment - ; or # at beginning of line
        {
            if (!($section))
            {
                $section = $anonymous
                $ini[$section] = @{}
            }
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=\s*(.*)(#.*$)" # Key - break at any # (linux style)
        {
            if (!($section))
            {
                $section = $anonymous
                $ini[$section] = @{}
            }
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }

    return $ini
}

# Clean up env from potentially earlier execution
Remove-Item -Path env:BOOTSTRAP_DOWNLOAD_ONLY -ErrorAction SilentlyContinue

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
		$config = Get-IniFile $ini
	} ElseIf ($args[$i].ToLower() -eq "-downloadonly") {
		$env:BOOTSTRAP_DOWNLOAD_ONLY = $true
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
