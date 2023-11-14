<# 
# Bootstrap loader to ride-windows repo
#
# Torsten Juul-Jensen
# November 10, 2023
#>

$author="tjuuljensen"
$repo="ride-windows"

Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}


function ShowSyntaxHelp()
{
  $ScriptName=$MyInvocation.MyCommand.Name
  Write-Output "normal usage:     $ScriptName [-ride <options...>] [-default] [-stop] [-edit | -notepad ]"
  Write-Output "specific release: $ScriptName -release v1.337"
  exit 1
}

function New-TemporaryDirectory {
  $parent = [System.IO.Path]::GetTempPath()
  [string] $name = [System.Guid]::NewGuid()
  New-Item -ItemType Directory -Path (Join-Path $parent $name) | Out-Null
}


function DownloadFile()
{
  param([String] $release)
  if ( $release ){
    $BootstrapArchive="https://github.com/${author}/${repo}/archive/refs/tags/$release.zip"  
    #$Url=https://api.github.com/repos/${author}/${repo}/zipball/refs/tags/$release
    #$Archive=$release
  }
  else {
    # Direct URL to bootstrap master archive on github
    $BootstrapArchive="https://github.com/${author}/${repo}/heads/master.zip"
  }

  # Downloading file
  $TempDir=New-TemporaryDirectory
  Write-Output "Downloading $BootstrapArchive => $TempDir"
  $FileName = ([System.IO.Path]::GetFileName($BootstrapArchive).Replace("%20"," "))
  $FileFullName = Join-Path -Path $TempDir -ChildPath $FileName
  Start-BitsTransfer -Source $BootstrapArchive -Destination $FileFullName

  # Unzipping
	Expand-Archive $FileFullName -DestinationPath $TempDir
	Remove-Item -Path $FileFullName -ErrorAction Ignore
	Write-Output "Unzipped to: $TempDir"

  # If directory is nested, move contents one directory up
  $SubPath = Get-ChildItem $TempDir -Name 
  if ($SubPath.count -eq 1) {
    $FullSubPath =Join-Path -Path $TempDir -ChildPath $SubPath
    $FolderIsNested = (Get-ChildItem -Path "$TempDir" -Directory).count -eq (Get-ChildItem -Path "$TempDir" ).count
    if ($FolderIsNested) {
      Get-ChildItem -Path "$FullSubPath" -Recurse | Move-Item -Destination $TempDir
      Remove-Item -Path $FullSubPath -ErrorAction SilentlyContinue -Recurse -Force
    }  

  #INSTALLDIR=$(realpath "$TEMPDIR")
  }
}

<#
# If this file does not exist it's probably because we're bootstrapping a fresh
# system.  So we download the Git repository and bootstrap from there
if [[ ! -f "$SCRIPTDIR/${repo}/ride.sh" ]] && [[ ! -f "$SCRIPTDIR/../ride.sh" ]]; then #the ride script does NOT exist in a subdir or one level up (run from repo directory)
  DownloadFile $@
elif [[ -f "$SCRIPTDIR/${repo}/ride.sh" ]] ; then
  INSTALLDIR=$(realpath "$SCRIPTDIR/${repo}/")
elif [[ -f "$SCRIPTDIR/../ride.sh" ]] ; then
  INSTALLDIR=$(realpath "$SCRIPTDIR/../")
fi


elif [[ "--default" == *"$1"* ]] ; then
  # Start the installation of the default preset
  cd $INSTALLDIR
  ./ride.sh --include lib-fedora.sh --preset default.preset

elif [[  "--edit | --vi | -e" == *"$1"* ]] ; then
  cd $INSTALLDIR
  cp default.preset custom.preset
  vi custom.preset
  ./ride.sh --include lib-fedora.sh --preset custom.preset
elif [[ "--ride" == *"$1"* ]] ; then
  # Start the RIDE installation with remaining parameters
  cd $INSTALLDIR
  shift
  ./ride.sh $@

#>

If (($args[0].ToLower() -eq "-help") -or ($args.Length -eq 0 )) {
  ShowSyntaxHelp
  break
}

$i = 0
While ($i -lt $args.Length) {
  # if -help is put anywhere on command line, the script will display help and exit
	If ($args[$i].ToLower() -eq "-help") {
    ShowSyntaxHelp
	} 
  ElseIf ($args[$i].ToLower() -eq "-default") {
    RequireAdmin
    DownloadFile
    Write-Output "Running default Installation..."
    # Do stuff (preset + include)
	} 
  ElseIf ($args[$i].ToLower() -eq "-ride") {
    RequireAdmin
    DownloadFile
    Write-Output "Running RIDE installation with custom parameters..."
    # Do stuff (preset + include ALLARGS)
	} 
  ElseIf ($args[$i].ToLower() -eq "-release") {
    RequireAdmin
    DownloadFile $args[++$i]
    # do stuff
	} 
  ElseIf ($args[$i].ToLower() -eq "-stop") {
    Write-Output "No installation tasks performed. It is up to you now to do the magic."
    if (($TempDir) -and (!( Test-Path $PSScriptRoot/${repo}/ ))) {
      $Repodir = Join-Path -Path $PSScriptRoot -ChildPath "${repo}"
      Move-Item –Path $TempDir -Destination $Repodir
      Write-Output "Files can be found in: $Repodir"
      return
    }
	} 
  ElseIf ($args[$i].ToLower() -eq "-edit") {
    RequireAdmins
    DownloadFile 
    Write-Output "Edit preset file in Notepad before running installation..."
    # Do stuff (notepad presetfile + ride preset + include)
	} 
  Else {
		ShowSyntaxHelp
    return
	}
	$i++
}