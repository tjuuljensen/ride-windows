<#
.SYNOPSIS
  Decode the registry DigitalProductId using the bundled C# decoder.

.DESCRIPTION
  Compiles the adapted decoder and reads HKLM DigitalProductId, then returns the decoded string. The
  existing OS-version branch is retained. Output may contain a sensitive product key. This script
  does not activate Windows or change licensing.

.PARAMETER Help
  Display help and return before operational work.

.PARAMETER Version
  Print the script version and return before operational work.

.EXAMPLE
  .\components\scripts\Get-WindowsProductKey.ps1 -Help

.EXAMPLE
  .\components\scripts\Get-WindowsProductKey.ps1 -Version

.INPUTS
  None. Parameters are supplied explicitly.

.OUTPUTS
  System.String. Decoded product key; treat operational output as sensitive.

.NOTES
  Compatibility: Windows PowerShell 5.1 and PowerShell 7 on Windows; system integration remains
  unverified in this walkthrough.
  Prerequisites: Windows registry read access and Add-Type C# compilation.
  File/environment inputs: HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion DigitalProductId.
  Recovery: No Windows state changes. Use an isolated session to discard the loaded Decoder type.
  Error-handling exception: Existing operational error policy is retained; globally enabling Stop
  requires a separate tested change.
  Author: RIDE-Windows maintainers.
  Version: 0.1.0
  Changelog:
    0.1.0: Establish the versioned PowerShell help contract during the 2026-10-08 walkthrough.
  Based on: https://github.com/mrpeardotnet/WinProdKeyFinder (embedded attribution retained). Upstream license provenance needs separate verification before redistribution changes.

.LINK
  https://github.com/mrpeardotnet/WinProdKeyFinder

#>


[CmdletBinding()]
param(
  [switch] $Help,
  [switch] $Version
)

$script:ScriptVersion = '0.1.0'
if ($Version) { Write-Output $script:ScriptVersion; return }
if ($Help) { Get-Help -Name $PSCommandPath -Full; return }

function Get-WindowsProductKey
{
  # The retained predicate selects the legacy decoder for every reported OS major version <= 6.
  function Test-Win7
  {
    $OSVersion = [System.Environment]::OSVersion.Version
    ($OSVersion.Major -eq 6 -and $OSVersion.Minor -lt 2) -or
    $OSVersion.Major -le 6
  }

  # implement decoder
  $code = @'
// original implementation: https://github.com/mrpeardotnet/WinProdKeyFinder
using System;
using System.Collections;

  public static class Decoder
  {
        public static string DecodeProductKeyWin7(byte[] digitalProductId)
        {
            const int keyStartIndex = 52;
            const int keyEndIndex = keyStartIndex + 15;
            var digits = new[]
            {
                'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R',
                'T', 'V', 'W', 'X', 'Y', '2', '3', '4', '6', '7', '8', '9',
            };
            const int decodeLength = 29;
            const int decodeStringLength = 15;
            var decodedChars = new char[decodeLength];
            var hexPid = new ArrayList();
            for (var i = keyStartIndex; i <= keyEndIndex; i++)
            {
                hexPid.Add(digitalProductId[i]);
            }
            for (var i = decodeLength - 1; i >= 0; i--)
            {
                // Every sixth char is a separator.
                if ((i + 1) % 6 == 0)
                {
                    decodedChars[i] = '-';
                }
                else
                {
                    // Do the actual decoding.
                    var digitMapIndex = 0;
                    for (var j = decodeStringLength - 1; j >= 0; j--)
                    {
                        var byteValue = (digitMapIndex << 8) | (byte)hexPid[j];
                        hexPid[j] = (byte)(byteValue / 24);
                        digitMapIndex = byteValue % 24;
                        decodedChars[i] = digits[digitMapIndex];
                    }
                }
            }
            return new string(decodedChars);
        }

        public static string DecodeProductKey(byte[] digitalProductId)
        {
            var key = String.Empty;
            const int keyOffset = 52;
            var isWin8 = (byte)((digitalProductId[66] / 6) & 1);
            digitalProductId[66] = (byte)((digitalProductId[66] & 0xf7) | (isWin8 & 2) * 4);

            const string digits = "BCDFGHJKMPQRTVWXY2346789";
            var last = 0;
            for (var i = 24; i >= 0; i--)
            {
                var current = 0;
                for (var j = 14; j >= 0; j--)
                {
                    current = current*256;
                    current = digitalProductId[j + keyOffset] + current;
                    digitalProductId[j + keyOffset] = (byte)(current/24);
                    current = current%24;
                    last = current;
                }
                key = digits[current] + key;
            }

            var keypart1 = key.Substring(1, last);
            var keypart2 = key.Substring(last + 1, key.Length - (last + 1));
            key = keypart1 + "N" + keypart2;

            for (var i = 5; i < key.Length; i += 6)
            {
                key = key.Insert(i, "-");
            }

            return key;
        }
   }
'@
  # compile c#:
  Add-Type -TypeDefinition $code
 
  # get raw product key:
  $digitalId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DigitalProductId).DigitalProductId
  
  $isWin7 = Test-Win7
  if ($isWin7)
  {
    # use static c# method:
    [Decoder]::DecodeProductKeyWin7($digitalId)
  }
  else
  {
    # use static c# method:
    [Decoder]::DecodeProductKey($digitalId)
  }
}

return Get-WindowsProductKey
