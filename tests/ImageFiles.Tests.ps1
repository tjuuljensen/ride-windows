<#
.SYNOPSIS
  Test PNG source validation using small generated images and malformed fixtures.
.DESCRIPTION
  Writes only TestDrive fixtures. Does not call personalization APIs or change
  registry values, machine files, policies or source image content.
.EXAMPLE
  Invoke-Pester ./tests/ImageFiles.Tests.ps1
.NOTES
  Pester 5, native Windows PowerShell 5.1/7. Version: 0.1.0.
#>
BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../modules/RIDE.ImageFiles.psm1') -Force
  Add-Type -AssemblyName System.Drawing
  function New-TestPng {
    $bitmap=[Drawing.Bitmap]::new(2,3);$memory=[IO.MemoryStream]::new()
    try{$bitmap.Save($memory,[Drawing.Imaging.ImageFormat]::Png);,$memory.ToArray()}finally{$memory.Dispose();$bitmap.Dispose()}
  }
  function Set-TestChunkCrc([byte[]]$Bytes,[int]$Offset,[int]$Length){
    [uint32]$crc=[uint32]::MaxValue
    for($i=$Offset+4;$i -lt $Offset+8+$Length;$i++){
      $crc=$crc -bxor $Bytes[$i]
      for($bit=0;$bit -lt 8;$bit++){if($crc -band 1){$crc=($crc -shr 1) -bxor [uint32]3988292384}else{$crc=$crc -shr 1}}
    }
    $crc=$crc -bxor [uint32]::MaxValue
    for($i=0;$i -lt 4;$i++){$Bytes[$Offset+8+$Length+$i]=[byte](($crc -shr (24-8*$i)) -band 255)}
  }
  function Write-TestPng([byte[]]$Bytes){
    [IO.File]::WriteAllBytes($script:source,$Bytes)
    (Get-FileHash -LiteralPath $script:source -Algorithm SHA256).Hash
  }
  function Find-TestChunk([byte[]]$Bytes,[string]$Type){
    $offset=8
    while($offset -lt $Bytes.Length){
      $size=([int]$Bytes[$offset] -shl 24) -bor ([int]$Bytes[$offset+1] -shl 16) -bor ([int]$Bytes[$offset+2] -shl 8) -bor [int]$Bytes[$offset+3]
      if([Text.Encoding]::ASCII.GetString($Bytes,$offset+4,4) -ceq $Type){return @{Offset=$offset;Length=$size}}
      $offset+=$size+12
    }
    throw 'Missing test chunk.'
  }
}
Describe 'Bounded static PNG source validation' {
  BeforeEach {$script:source=Join-Path $TestDrive 'source.png';$script:bytes=New-TestPng}
  It 'returns source identity without rewriting input or changing personalization' {
    $hash=Write-TestPng $bytes;$stamp=[IO.File]::GetLastWriteTimeUtc($source)
    $result=Get-RidePngSource -Path $source -ExpectedSha256 $hash
    $result.Width|Should -Be 2;$result.Height|Should -Be 3
    $result.Sha256|Should -BeExactly $hash;$result.DecodeValidated|Should -BeTrue
    $result.PersonalizationChanged|Should -BeFalse
    $result.PSObject.Properties.Name|Should -Not -Contain 'Content'
    (Get-FileHash -LiteralPath $source).Hash|Should -BeExactly $hash
    [IO.File]::GetLastWriteTimeUtc($source)|Should -Be $stamp
  }
  It 'returns the exact validated bytes when a caller requests content' {
    $hash=Write-TestPng $bytes
    $result=Get-RidePngSource -Path $source -ExpectedSha256 $hash -IncludeContent
    $result.Content.GetType().FullName|Should -Be 'System.Byte[]'
    [Convert]::ToBase64String($result.Content)|Should -BeExactly ([Convert]::ToBase64String($bytes))
    [IO.File]::WriteAllText($source,'changed after validation')
    $result.Content.Length|Should -Be $bytes.Length
  }
  It 'refuses changed content before interpreting the image' {
    $hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 ('0'*64)}|Should -Throw '*hash differs*'
  }
  It 'refuses a non-PNG extension' {
    {Get-RidePngSource -Path (Join-Path $TestDrive 'source.jpg') -ExpectedSha256 ('0'*64)}|Should -Throw '*Only static*'
  }
  It 'refuses network and alternate-stream paths' {
    {Get-RidePngSource -Path '\\server\share\image.png' -ExpectedSha256 ('0'*64)}|Should -Throw '*local path*'
    {Get-RidePngSource -Path ($source+':stream.png') -ExpectedSha256 ('0'*64)}|Should -Throw '*local path*'
  }
  It 'refuses a file beyond the byte bound before reading it' {
    $stream=[IO.File]::Create($source);try{$stream.SetLength(16777217)}finally{$stream.Dispose()}
    {Get-RidePngSource -Path $source -ExpectedSha256 ('0'*64)}|Should -Throw '*size bound*'
  }
  It 'refuses a renamed non-PNG payload' {
    $bytes[0]=0;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*signature*'
  }
  It 'refuses corrupted chunk data even when its file hash matches' {
    $bytes[16]=1;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*CRC*'
  }
  It 'refuses excessive dimensions before asking GDI to allocate pixels' {
    $bytes[16]=0;$bytes[17]=0;$bytes[18]=32;$bytes[19]=1
    Set-TestChunkCrc $bytes 8 13;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*dimensions*'
  }
  It 'refuses excessive pixel area even when each axis is within its bound' {
    foreach($offset in @(16,20)){$bytes[$offset]=0;$bytes[$offset+1]=0;$bytes[$offset+2]=32;$bytes[$offset+3]=0}
    Set-TestChunkCrc $bytes 8 13;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*dimensions*'
  }
  It 'refuses truncation and appended data' {
    $hash=Write-TestPng $bytes[0..($bytes.Length-2)]
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*incomplete*'
    $hash=Write-TestPng ($bytes+[byte]0)
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*trailer*'
  }
  It 'refuses animation chunks rather than silently accepting only a first frame' {
    $chunk=New-Object byte[] 20;$chunk[3]=8
    [Array]::Copy([Text.Encoding]::ASCII.GetBytes('acTL'),0,$chunk,4,4);$chunk[11]=1
    Set-TestChunkCrc $chunk 0 8
    $hash=Write-TestPng ($bytes[0..32]+$chunk+$bytes[33..($bytes.Length-1)])
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*Animated PNG*'
  }
  It 'rejects undecodable image data even with a valid envelope and CRC' {
    $chunk=Find-TestChunk $bytes 'IDAT';$offset=$chunk.Offset;$size=$chunk.Length
    for($i=0;$i -lt $size;$i++){$bytes[$offset+8+$i]=0}
    Set-TestChunkCrc $bytes $offset $size;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*compressed data header*'
  }
  It 'checks the inflated-data checksum independently of the PNG chunk CRC' {
    $chunk=Find-TestChunk $bytes 'IDAT';$offset=$chunk.Offset;$size=$chunk.Length
    $bytes[$offset+8+$size-1]=$bytes[$offset+8+$size-1] -bxor 1
    Set-TestChunkCrc $bytes $offset $size;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*inflated data checksum*'
  }
  It 'rejects incomplete inflated scanlines' {
    $bytes[23]=4;Set-TestChunkCrc $bytes 8 13;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*inflated data is incomplete*'
  }
  It 'stops excess decompressed data at the declared image boundary' {
    $bytes[23]=2;Set-TestChunkCrc $bytes 8 13;$hash=Write-TestPng $bytes
    {Get-RidePngSource -Path $source -ExpectedSha256 $hash}|Should -Throw '*inflated data exceeds*'
  }
}
