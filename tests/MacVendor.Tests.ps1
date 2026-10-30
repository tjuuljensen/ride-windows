<#
.SYNOPSIS
  Check standalone MAC vendor lookup without network or Windows state changes.

.DESCRIPTION
  Uses an IEEE-style TSV cache to check prefix selection, input and output modes,
  validation, and offline/preview boundaries.

.EXAMPLE
  Invoke-Pester .\tests\MacVendor.Tests.ps1

.INPUTS
  None.

.OUTPUTS
  Pester results.

.NOTES
  Compatibility: Pester 5; intended for Windows PowerShell 5.1 and PowerShell 7.
  Prerequisites: No network connection or elevation.
  Version: Repository test fixture.
#>

BeforeAll {
    $utility = Join-Path (Split-Path -Parent $PSScriptRoot) 'components/scripts/mac-vendor.ps1'
}

Describe 'MAC vendor lookup' {
    BeforeEach {
        $cacheDirectory = Join-Path $TestDrive 'mac-vendor'
        [void][IO.Directory]::CreateDirectory($cacheDirectory)
        $lines = @(
            "prefix`tbits`tregistry`torganization`taddress"
            "001A2B`t24`tMA-L`tLarge Co`tLarge Street"
            "001A2B3`t28`tMA-M`tMedium Co`tMedium Street"
            ('001A2B334' + "`t36`tMA-S`tSmall Co`t" + '"Line 1' + "`t" + 'Suite 2"')
            "020000`t24`tMA-L`tLocal Co`t"
            "030000`t24`tMA-L`tGroup Co`t"
        )
        [IO.File]::WriteAllText(
            (Join-Path $cacheDirectory 'ieee-mac-vendors.tsv'),
            ($lines -join "`n"),
            [Text.UTF8Encoding]::new($false)
        )
    }

    It 'selects the longest available prefix and reads quoted TSV fields' {
        $result = @(& $utility -Offline -CacheDir $cacheDirectory -ShowAddress 00:1A:2B:33:44:55)
        $result[0] | Should -BeExactly '00:1A:2B:33:44:55 -> Small Co [MA-S, 001A2B334/36]'
        $result[1] | Should -BeExactly "  Line 1`tSuite 2"
        (& $utility -Offline -CacheDir $cacheDirectory 00:1A:2B:3) |
            Should -BeExactly '00:1A:2B:3 -> Medium Co [MA-M, 001A2B3/28]'
        (& $utility -Offline -CacheDir $cacheDirectory 00-1A-2B) |
            Should -BeExactly '00-1A-2B -> Large Co [MA-L, 001A2B/24]'
    }

    It 'accepts pipeline input and returns Unknown for an unmatched prefix' {
        $result = @('00:1A:2B:33:44:55', 'FF:FF:FF:FF:FF:FF' |
            & $utility -Offline -CacheDir $cacheDirectory -Quiet)
        $result.Count | Should -Be 2
        $result[0] | Should -BeExactly 'Small Co'
        $result[1] | Should -BeExactly 'Unknown'
    }

    It 'emits one JSON array with flags and supports quiet JSON' {
        $result = & $utility -Offline -CacheDir $cacheDirectory -Json 02:00:00,03:00:00 |
            ConvertFrom-Json
        $result.Count | Should -Be 2
        $result[0].locally_administered | Should -BeTrue
        $result[0].multicast | Should -BeFalse
        $result[1].multicast | Should -BeTrue

        $quietResult = & $utility -Offline -CacheDir $cacheDirectory -Quiet -Json 00:1A:2B,FF:FF:FF |
            ConvertFrom-Json
        $quietResult[0].organization | Should -BeExactly 'Large Co'
        $quietResult[1].organization | Should -BeNullOrEmpty
        @($quietResult[0].PSObject.Properties.Name).Count | Should -Be 1
        $quietResult[0].PSObject.Properties.Name | Should -BeExactly 'organization'
    }

    It 'rejects a batch containing an invalid query' {
        { & $utility -Offline -CacheDir $cacheDirectory 00:1A:2B,AB } | Should -Throw
    }

    It 'keeps offline mode and preview read-only' {
        $missing = Join-Path $TestDrive 'missing'
        { & $utility -Offline -CacheDir $missing 00:1A:2B } | Should -Throw
        & $utility -CacheDir $missing -Update -WhatIf | Out-Null
        (Test-Path -LiteralPath $missing) | Should -BeFalse
        { & $utility -CacheDir $cacheDirectory -Offline -Update 00:1A:2B } | Should -Throw
    }
}
