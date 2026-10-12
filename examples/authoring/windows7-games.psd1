# Reconciled operator-created example, 2026-10-12. VM acceptance is pending.
# Retains the original authoring namespace; see ../library/README.md for choices.
# LicenseUri is intentionally omitted because the original URL was a placeholder.
# Version 0.1.2 matches the read-only registered product name observed on 2026-10-12.
@{
  Id = 'custom.games'
  Version = '0.1.2'
  Operations = @(
    @{
      Id = 'classic-msgames'
      Kind = 'Package'
      Name = 'Windows 7 Games for Windows 11, 10 and 8'
      Description = 'Installs Solitaire, Spider Solitaire, Minesweeper, FreeCell, Hearts, Chess Titans, Mahjong Titans, Purble Place, Internet Spades, Internet Checkers, and Internet Backgammon'
      Category = 'Software / Custom library'
      Scope = 'Machine'
      SupportedTargets = @('Windows 11')
      PackageId = 'custom.games.classic-msgames'
      InstallerType = 'Exe'
      ArchiveType = 'Zip'
      Architecture = 'x86'
      DownloadProvider = 'DirectHttps'
      DownloadUri = 'https://win7games.com/download/Windows7Games_for_Windows_11_10_8.zip'
      PackageVersion = '4.3'
      AssetName = 'Windows7Games_for_Windows_11_10_8.zip'
      ExpectedSha256 = 'b0db854664ba1b092e4f602dae9101130cb9a50cba103c9ef8b57362d7762b56'
      InstallerEntry = 'Windows 7 Games for Windows 11, 10 and 8-4.3-setup.exe'
      ExpectedInstallerSha256 = 'ae3ff402b459d4343d9fd0edf0d46186b9f604b2c989c9c8aa99adedfe4958ee'
      DisplayNamePattern = '^Windows 7 Games for Windows 11, 10 and 8$'
      InstallerArguments = ' /SP- /SILENT'
      UninstallerArguments = '/SILENT'
      License = 'Unknown'
      ProductUri = 'https://winaero.com/download-windows-7-games-for-windows-11/'
      TargetDefaults = @{
        'Windows 11' = @{ DefaultValue = 'Absent'; EffectiveDefault = 'Author-declared package default: Absent; verify the target image' }
      }
    }
  )
}
