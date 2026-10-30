<#
.SYNOPSIS
  Verify download-only preview boundaries for the JoeWare acquisition tool.
.DESCRIPTION
  Mocks publisher requests and confirms WhatIf neither contacts the publisher
  nor creates the selected output directory.
.EXAMPLE
  Invoke-Pester .\tests\Download-JoeWareCollection.Tests.ps1
.INPUTS
  None.
.OUTPUTS
  Pester test results.
.NOTES
  Compatibility: Pester 5 on Windows PowerShell 5.1 and PowerShell 7.
  Recovery: TestDrive owns the temporary output path; no publisher or Windows state is changed.
#>

BeforeAll {
  $script:DownloadTool = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools/Download-JoeWareCollection.ps1'
  $script:DownloadTokens = $null
  $script:DownloadParseErrors = $null
  $script:DownloadAst = [Management.Automation.Language.Parser]::ParseFile($script:DownloadTool, [ref]$script:DownloadTokens, [ref]$script:DownloadParseErrors)
  if (@($script:DownloadParseErrors).Count) { throw 'The JoeWare acquisition script does not parse.' }
  $script:DownloadFunctions = @($script:DownloadAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-JoeWarePageVersion'
  }, $true))
  $script:DownloadFunctions += @($script:DownloadAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Assert-JoeWareHttpsUri','Get-JoeWareResponseUri')
  }, $true))
  if ($script:DownloadFunctions.Count -ne 3) { throw 'A JoeWare page/response URI helper is missing or ambiguous.' }
  foreach ($function in $script:DownloadFunctions) { . ([scriptblock]::Create($function.Extent.Text)) }
}

Describe 'JoeWare download-only source preview' {
  BeforeEach {
    $priorArchiveBytes = Get-Variable -Name MockJoeWareArchiveBytes -Scope Global -ErrorAction SilentlyContinue
    $script:HadPriorJoeWareArchiveBytes = $null -ne $priorArchiveBytes
    $script:PriorJoeWareArchiveBytes = if ($priorArchiveBytes) { $priorArchiveBytes.Value } else { $null }
  }

  AfterEach {
    if ($script:HadPriorJoeWareArchiveBytes) {
      Set-Variable -Name MockJoeWareArchiveBytes -Scope Global -Value $script:PriorJoeWareArchiveBytes
    } else {
      Remove-Variable -Name MockJoeWareArchiveBytes -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'decodes the current-page version label as one HTML-decoded string' {
    $html = '<html><div>Current Version</div><p>Version&nbsp;1.29.00 - June 8, 2026</p><h2>Version History</h2></html>'

    $result = Get-JoeWarePageVersion -Html $html

    $result.Version | Should -BeExactly '1.29.00'
    $result.Label | Should -BeExactly 'Version 1.29.00 - June 8, 2026'
  }

  It 'accepts final response URI shapes used by Windows PowerShell 5.1 and PowerShell 7' {
    $windowsPowerShellResponse = [pscustomobject]@{ BaseResponse = [pscustomobject]@{ ResponseUri = [uri]'https://joeware.net/downloads/admod.zip' } }
    $powerShell7Response = [pscustomobject]@{ BaseResponse = [pscustomobject]@{ RequestMessage = [pscustomobject]@{ RequestUri = [uri]'https://www.joeware.net/downloads/admod.zip' } } }

    (Get-JoeWareResponseUri -Response $windowsPowerShellResponse) | Should -BeExactly 'https://joeware.net/downloads/admod.zip'
    (Get-JoeWareResponseUri -Response $powerShell7Response) | Should -BeExactly 'https://www.joeware.net/downloads/admod.zip'
  }

  It 'refuses response URIs outside the official JoeWare HTTPS origin' {
    $response = [pscustomobject]@{ BaseResponse = [pscustomobject]@{ ResponseUri = [uri]'https://example.invalid/admod.zip' } }

    { Get-JoeWareResponseUri -Response $response } | Should -Throw '*outside its official HTTPS origin*'
  }

  It 'records hash and member observations for one mocked selected-product archive' {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $destination = Join-Path $TestDrive 'joeware-admod-positive'
    $archivePath = Join-Path $TestDrive 'inert-admod.zip'
    $archive = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Create)
    try {
      foreach ($fixture in @(
        @{ Name = 'AdMod.exe'; Content = 'inert test fixture, never executed' },
        @{ Name = 'readme.txt'; Content = 'Version 1.29.00' }
      )) {
        $entry = $archive.CreateEntry($fixture.Name)
        $writer = [IO.StreamWriter]::new($entry.Open())
        try { $writer.Write($fixture.Content) } finally { $writer.Dispose() }
      }
    } finally { $archive.Dispose() }

    $global:MockJoeWareArchiveBytes = [IO.File]::ReadAllBytes($archivePath)
    Mock Invoke-WebRequest {
      if ($Uri -like '*/versions.txt') {
        return [pscustomobject]@{ Content = "admod,1.29.00,2026.06.08,,`n" }
      }
      if ($OutFile) {
        [IO.File]::WriteAllBytes($OutFile, $global:MockJoeWareArchiveBytes)
        return [pscustomobject]@{ BaseResponse = [pscustomobject]@{ ResponseUri = [uri]'https://www.joeware.net/downloads/AdMod.zip' } }
      }
      [pscustomobject]@{
        Content = '<div>Current Version</div><p>Version 1.29.00 - June 8, 2026</p><h2>Version History</h2>'
        InputFields = @(
          [pscustomobject]@{ name = 'download'; value = 'AdMod.zip' },
          [pscustomobject]@{ name = 'B1'; value = 'Download' }
        )
      }
    }

    $output = @(& $script:DownloadTool -Product AdMod -DestinationDirectory $destination)

    Should -Invoke Invoke-WebRequest -Times 3 -Exactly
    (Test-Path -LiteralPath (Join-Path $destination 'AdMod.zip') -PathType Leaf) | Should -BeTrue
    (Test-Path -LiteralPath (Join-Path $destination 'joeware-download-observations.json') -PathType Leaf) | Should -BeTrue
    @(Get-ChildItem -LiteralPath $destination -Force -Filter '*.download').Count | Should -Be 0
    $manifest = Get-Content -LiteralPath (Join-Path $destination 'joeware-download-observations.json') -Raw | ConvertFrom-Json
    $product = @($manifest.Products)[0]
    $product.Product | Should -BeExactly 'AdMod'
    $product.PageVersion | Should -BeExactly '1.29.00'
    $product.VersionListObservation.Version | Should -BeExactly '1.29.00'
    $product.ResponseUri | Should -BeExactly 'https://www.joeware.net/downloads/AdMod.zip'
    $product.Sha256 | Should -BeExactly (Get-FileHash -LiteralPath (Join-Path $destination 'AdMod.zip') -Algorithm SHA256).Hash.ToLowerInvariant()
    $product.Members | Should -Be @('AdMod.exe', 'readme.txt')
    @($output | Where-Object { $_.ProductCount -eq 1 }).Count | Should -Be 1
  }

  It 'does not request publisher pages or create the output directory under WhatIf' {
    $destination = Join-Path $TestDrive 'joeware-preview'
    Mock Invoke-WebRequest { throw 'Publisher requests must not run during WhatIf.' }

    & $script:DownloadTool -Product @('AccExp', 'ATSN') -DestinationDirectory $destination -WhatIf

    Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    Test-Path -LiteralPath $destination | Should -BeFalse
  }

  It 'excludes Defender-blocked AdFind from the default preview' {
    $destination = Join-Path $TestDrive 'joeware-default-preview'
    Mock Invoke-WebRequest { throw 'Publisher requests must not run during WhatIf.' }

    $preview = (& $script:DownloadTool -DestinationDirectory $destination -WhatIf 6>&1 | Out-String)

    $preview | Should -Not -Match 'AdFind'
    Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    Test-Path -LiteralPath $destination | Should -BeFalse
  }

  It 'refuses explicitly selected Defender-blocked AdFind before any request or directory creation' {
    $destination = Join-Path $TestDrive 'joeware-adfind-blocked'
    Mock Invoke-WebRequest { throw 'Publisher requests must not run for Defender-blocked products.' }

    { & $script:DownloadTool -Product AdFind -DestinationDirectory $destination -WhatIf } |
      Should -Throw '*Defender-blocked JoeWare product*'

    Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    Test-Path -LiteralPath $destination | Should -BeFalse
  }

  It 'completes reviewed Product values from the inventory and shared exclusion policy' {
    Push-Location (Split-Path -Parent $PSScriptRoot)
    try {
      $line = '.\tools\Download-JoeWareCollection.ps1 -Product '
      $result = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    } finally { Pop-Location }
    $values = @($result.CompletionMatches | ForEach-Object { $_.CompletionText })

    $values | Should -Contain 'AdMod'
    $values | Should -Not -Contain 'AdFind'
    $values.Count | Should -Be 40
  }

  It 'completes a quoted absolute tool path from another location' {
    Push-Location $TestDrive
    try {
      $line = "& '" + $script:DownloadTool.Replace("'", "''") + "' -Product AdM"
      $result = TabExpansion2 -inputScript $line -cursorColumn $line.Length
    } finally { Pop-Location }
    @($result.CompletionMatches | ForEach-Object { $_.CompletionText }) | Should -Be @('AdMod')
  }
}
