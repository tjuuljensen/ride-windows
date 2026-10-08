<#
.SYNOPSIS
  Resize an image into the helper's Windows wallpaper filename variants.

.DESCRIPTION
  Reads image dimensions, selects landscape or portrait presets, and invokes ImageMagick resize for
  each output in the working directory. Resize preserves aspect ratio; target dimensions are bounds
  rather than guaranteed exact crops. Existing output filenames can be overwritten; native exit
  codes are not checked.

.PARAMETER imageFile
  Input image filename; defaults to img0.jpg in the current working directory. Use a local relative
  filename for this legacy helper.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\components\wallpaper\make-wallpaper-files.ps1 -Help

.EXAMPLE
  .\components\wallpaper\make-wallpaper-files.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  None. Host messages and img0_<width>x<height>.jpg files in the current directory.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: magick.exe in PATH, System.Drawing, readable source image, and writable output
  directory.
  File/environment inputs: The selected image file and current directory.
  Recovery: Back up output filenames before generating; restore those backups if replaced.
  Error-handling exception: Existing operational error policy is retained; globally enabling Stop
  requires a separate tested change.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.
  Behavior reference: https://ccmexec.com/2015/08/replacing-default-wallpaper-in-windows-10-using-scriptmdtsccm/ (retained from the original header).

.LINK
  https://imagemagick.org/index.php

.LINK
  https://ccmexec.com/2015/08/replacing-default-wallpaper-in-windows-10-using-scriptmdtsccm/

#>


[CmdletBinding()]
param($imageFile="img0.jpg",
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

# check if magick is in path
if ($null -eq (Get-Command "magick.exe" -ErrorAction SilentlyContinue)) 
{ 
   Write-Host "Unable to find magick.exe in your PATH"
   Write-Host "Download it free here: https://imagemagick.org/index.php"
   exit 1
} elseif ( ! (Test-Path $imageFile)) {
   Write-Host "Image file not found: $imageFile"
   exit 1
}

Add-Type -AssemblyName System.Drawing
$image = New-Object System.Drawing.Bitmap $imageFile
$imageWidth = $image.Width
$imageHeight = $image.Height

if ($imageWidth -ge $imageHeight)
{
   Write-Host "Processing landscape formats"
   # Landscape formats
   magick .\$imageFile -resize 1024x768 img0_1024x768.jpg
   magick .\$imageFile -resize 1366x768 img0_1366x768.jpg
   magick .\$imageFile -resize 2560x1600 img0_2560x1600.jpg
   magick .\$imageFile -resize 3840x2160 img0_3840x2160.jpg
} else {
   # Portrait formats
   Write-Host "Processing portrait formats"
   magick .\$imageFile -resize 768x1024 img0_768x1024.jpg
   magick .\$imageFile -resize 768x1366 img0_768x1366.jpg
   magick .\$imageFile -resize 1200x1920 img0_1200x1920.jpg
   magick .\$imageFile -resize 1600x2560 img0_1600x2560.jpg
   magick .\$imageFile -resize 2160x3840 img0_2160x3840.jpg
}

