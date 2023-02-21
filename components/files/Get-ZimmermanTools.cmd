@echo off
rem Created to update Zimmerman Tools using Get-ZimmermanTools.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dpn0.ps1" -Dest %~dp0

