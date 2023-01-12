# Script to resize a windows wallpaper to the default windows wallpaper sizes
# Look for more info here:
# https://ccmexec.com/2015/08/replacing-default-wallpaper-in-windows-10-using-scriptmdtsccm/
#
# Landscape modes: 1024 x 768, 1366 x 768, 2560 x 1600, 3840 x 2160
# Portrait modes : 768 x 1024, 768 x 1366, 1200 x 1920, 1600 x 2560, 2160 x 3840
#
# Conversion is done using Open Source tool Imagemagick
# https://imagemagick.org/index.php

param($imageFile="img0.jpg") 

# check if magick is in path
if ($null -eq (Get-Command "magick.exe" -ErrorAction SilentlyContinue)) 
{ 
   Write-Host "Unable to find magick.exe in your PATH"
   Write-Host "Download it free here: https://imagemagick.org/index.php"
   exit 1
}

# Check if image exists and if syntax below works

add-type -AssemblyName System.Drawing
$image = New-Object System.Drawing.Bitmap $imageFile
$imageWidth = $image.Width
$imageHeight = $image.Height

if ($imageWidth -ge $imageHeight)
{
   # Landscape formats
   magick .\$image -resize 1024x768 img0_1024x768.jpg
   magick .\$image -resize 1366x768 img0_1366x768.jpg
   magick .\$image -resize 2560x1600 img0_2560x1600.jpg
   magick .\$image -resize 3840x2160 img0_3840x2160.jpg
} else {
   # Portrait formats
   magick .\$image -resize 768x1024 img0_768x1024.jpg
   magick .\$image -resize 768x1366 img0_768x1366.jpg
   magick .\$image -resize 1200x1920 img0_1200x1920.jpg
   magick .\$image -resize 1600x2560 img0_1600x2560.jpg
   magick .\$image -resize 2160x3840 img0_2160x3840.jpg
}

